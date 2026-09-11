//! C7.1 matrix and B12 flat-source composition. No complete Gemma credit.

mod codec;
#[cfg(feature = "c71-b12-pcs")]
#[macro_use]
mod wire;
mod census;
mod diagnostic;
#[cfg(feature = "c71-b12-pcs")]
mod b12;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Internal component seam; no admitted Gemma runner yet.
mod linear;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Internal same-W range caller, no full Gemma runner.
mod range;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Public byte functions; returned original source MAC still needs the shared PCS.
mod byte_function;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // RNE component; full Gemma producer and source routing remain explicit.
mod rne;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Exact RMS GKR component; canonical P/S/Y producer routes remain explicit.
mod rms;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Lookup component; canonical histogram and producer routes remain explicit.
mod lookup;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Joint Q30 RoPE; original raw/Y source closures remain explicit.
mod rope;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Raw attention component; source, integer and KV-history closures stay explicit.
mod attention;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // P0 caller; input/output openings remain explicit.
mod p0;
#[cfg(feature = "c71-b12-pcs")]
#[allow(dead_code)] // Native pinned W layout and P0 routes; full Gemma runtime remains open.
mod gemma;
pub use diagnostic::{preflight, run};
#[cfg(feature = "c71-work-census")]
pub use census::self_check;

use crate::c61_whir_reference::C61Commitment;
#[cfg(not(feature = "c71-b12-pcs"))]
use crate::c61_whir_reference::{c61_reference_mmcs, C61Mmcs};
#[cfg(feature = "c71-b12-pcs")]
use b12::{mmcs as matrix_mmcs, HidingMmcs as MatrixMmcs, PrivateRng as MatrixRng};
#[cfg(not(feature = "c71-b12-pcs"))]
type MatrixMmcs = C61Mmcs;
#[cfg(not(feature = "c71-b12-pcs"))]
type MatrixRng = StdRng;
type MatrixMultiProof = <MatrixMmcs as p3_commit::Mmcs<Goldilocks>>::MultiProof;

#[cfg(not(feature = "c71-b12-pcs"))]
fn matrix_mmcs(_seed: [u8; 32]) -> MatrixMmcs {
    c61_reference_mmcs()
}
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_multilinear_util::{point::Point, poly::Poly};
use p3_whir_c61::pcs::zk::{
    HidingWhirProver, HidingWhirProverData, HidingWhirVerifier, MaskCodeShape, ZkWhirProof,
};
use p3_whir_c61::pcs::zk::{ZkParameters, ZkWhirConfig};
use p3_whir_c61::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use rand::RngCore;
use rand_010::SeedableRng;
#[cfg(not(feature = "c71-b12-pcs"))]
use rand_010::rngs::StdRng;
use volta_field::{Fp, Fp3};
use volta_mac::c7_fp3::{
    c7_fp3_transfer_prover, c7_fp3_transfer_verifier, C7Fp3ProverAuthed as Auth,
    C7Fp3TransferCorrection, C7Fp3VerifierKey as Key,
};

type E = CubicTrinomialExtensionField<Goldilocks>;

// Plonky3 uses v^3=v+1; C7.1 wire/MAC values use u^3=2. Columns are 1,u,u²
// in the v basis. Checking u³=2 and inverse matrices suffices for the field
// homomorphism; tests also compare products with VOLTA's independent arithmetic.
const U: [u64; 3] = [10352974269065334650, 17378948687159909735, 2917282665816582346];
const U2: [u64; 3] = [11322695156155957973, 16204988691673636767, 10686073369887939522];
const FROM_P3: [[u64; 3]; 3] = [
    [1, 0, 6148914689804861441],
    [0, 10744699582168515350, 12364293176282353495],
    [0, 13400538918433122525, 3889521287166635039],
];

fn to_p3(x: Fp3) -> E {
    E::new(std::array::from_fn(|i| {
        Goldilocks::new(
            (if i == 0 { x.c0 } else { Fp::ZERO } + x.c1 * Fp::new(U[i]) + x.c2 * Fp::new(U2[i]))
                .value(),
        )
    }))
}

fn from_p3(x: E) -> Fp3 {
    let coefficients: &[Goldilocks] = x.as_basis_coefficients_slice();
    let limbs: [Fp; 3] = std::array::from_fn(|i| {
        (0..3).fold(Fp::ZERO, |sum, j| {
            sum + Fp::new(FROM_P3[i][j]) * Fp::new(coefficients[j].as_canonical_u64())
        })
    });
    Fp3::new(limbs[0], limbs[1], limbs[2])
}

/// C71FS-v1 framing for the bounded matrix profile. `phase` names the
/// component, and each request has its own ordered slot inside that phase.
/// The slot counts native draw requests. B12 uses one XOF tape for consecutive
/// draws until a new prover choice. Authenticated openings are fixed by their
/// roots and stay in the hash without restarting the tape.
/// Exhaustion panics across P3's infallible challenger API; the outer runner
/// must catch this and burn the attempt, never retry with a substitute value.
#[derive(Clone)]
struct FsState {
    hash: blake3::Hasher,
    events: u64,
    requests: usize,
    request_limit: usize,
    phase: u16,
    #[cfg(feature = "c71-b12-pcs")]
    coin_tape: Option<blake3::OutputReader>,
}

#[derive(Clone)]
struct Fs(std::sync::Arc<std::sync::Mutex<FsState>>);

impl FsState {
    fn record(&mut self, kind: u16, bytes: &[u8]) {
        self.hash.update(&self.events.to_le_bytes());
        self.hash.update(&self.phase.to_le_bytes());
        self.hash.update(&kind.to_le_bytes());
        self.hash.update(&(bytes.len() as u64).to_le_bytes());
        self.hash.update(bytes);
        self.events = self.events.checked_add(1).expect("C71FS event counter exhausted");
    }
}

impl Fs {
    fn new(profile_and_statement: &[u8], request_limit: usize) -> Self {
        let mut result = FsState {
            hash: blake3::Hasher::new(),
            events: 0,
            requests: 0,
            request_limit,
            phase: 0,
            #[cfg(feature = "c71-b12-pcs")]
            coin_tape: None,
        };
        result.hash.update(b"volta-zk/c7.1/fs/v1");
        result.record(0, profile_and_statement);
        Self(std::sync::Arc::new(std::sync::Mutex::new(result)))
    }

    fn record(&mut self, kind: u16, bytes: &[u8]) {
        let mut state = self.0.lock().unwrap();
        #[cfg(feature = "c71-b12-pcs")]
        if kind != 0x2100 {
            state.coin_tape = None; // fresh prover message; verified openings are determined
        }
        state.record(kind, bytes);
    }

    fn set_phase(&mut self, phase: u16) {
        self.0.lock().unwrap().phase = phase;
    }
    fn digest(&self) -> blake3::Hash {
        self.0.lock().unwrap().hash.finalize()
    }
    #[cfg(test)]
    fn requests(&self) -> usize {
        self.0.lock().unwrap().requests
    }
    #[cfg(test)]
    fn fork(&self) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(self.0.lock().unwrap().clone())))
    }

    fn request(&mut self, kind: u16, width: u32) -> blake3::OutputReader {
        let mut state = self.0.lock().unwrap();
        assert!(state.requests < state.request_limit, "C71FS request reservation exhausted");
        let mut request = Vec::new();
        request.extend_from_slice(&(state.requests as u64).to_le_bytes());
        request.extend_from_slice(&kind.to_le_bytes());
        request.extend_from_slice(&width.to_le_bytes());
        request.extend_from_slice(&8u32.to_le_bytes());
        state.record(0xff00, &request);
        state.requests += 1;
        #[cfg(feature = "c71-b12-pcs")]
        if let Some(reader) = state.coin_tape.take() {
            return reader;
        }
        state.hash.finalize_xof()
    }

    fn finish_request(&mut self, reader: blake3::OutputReader, bytes: &[u8]) {
        let mut state = self.0.lock().unwrap();
        state.record(0xff01, bytes); // verifier's own draw, not a new prover message
        #[cfg(feature = "c71-b12-pcs")]
        {
            state.coin_tape = Some(reader);
        }
        #[cfg(not(feature = "c71-b12-pcs"))]
        let _ = reader;
    }

    fn fields(&mut self, count: usize) -> Vec<Fp> {
        assert!(count == 1 || count == 3, "C71FS unsupported field dimension");
        let mut reader = self.request(1, count as u32);
        let result: Vec<_> = (0..count)
            .map(|_| {
                (0..8)
                    .find_map(|_| {
                        let mut bytes = [0; 8];
                        reader.fill(&mut bytes);
                        let word = u64::from_le_bytes(bytes);
                        (word < volta_field::P).then(|| Fp::new(word))
                    })
                    .expect("C71FS coordinate rejection budget exhausted")
            })
            .collect();
        let bytes: Vec<_> = result.iter().flat_map(|x| x.value().to_le_bytes()).collect();
        self.finish_request(reader, &bytes);
        result
    }

    fn fp3(&mut self) -> Fp3 {
        let values = self.fields(3);
        Fp3::new(values[0], values[1], values[2])
    }
}

impl CanObserve<Goldilocks> for Fs {
    fn observe(&mut self, x: Goldilocks) {
        self.record(1, &x.as_canonical_u64().to_le_bytes());
    }
}

impl CanObserve<C61Commitment> for Fs {
    fn observe(&mut self, root: C61Commitment) {
        assert_eq!(root.num_roots(), 1, "C71FS only admits one-root caps");
        self.record(2, &root.roots()[0]);
    }
}

impl CanSample<Goldilocks> for Fs {
    fn sample(&mut self) -> Goldilocks {
        Goldilocks::new(self.fields(1)[0].value())
    }
}

impl CanSampleBits<usize> for Fs {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C71FS index domain exceeds profile");
        let mut reader = self.request(2, bits as u32);
        let mut bytes = [0; 8];
        reader.fill(&mut bytes);
        // All admitted index domains are powers of two, so every u64 is
        // below floor(2^64/D)*D. There is no biased modular reduction.
        let result = u64::from_le_bytes(bytes) & ((1u64 << bits) - 1);
        self.finish_request(reader, &result.to_le_bytes());
        result as usize
    }
}

impl CanSampleUniformBits<Goldilocks> for Fs {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for Fs {
    type Witness = Goldilocks;
    fn grind(&mut self, bits: usize) -> Goldilocks {
        assert_eq!(bits, 0, "C71 matrix profile forbids grinding");
        Goldilocks::ZERO
    }
    fn check_witness(&mut self, bits: usize, witness: Goldilocks) -> bool {
        bits == 0 && witness == Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for Fs {
    fn observe_algebra_element<A: BasedVectorSpace<Goldilocks>>(&mut self, value: A) {
        let limbs = value.as_basis_coefficients_slice();
        match limbs.len() {
            1 => self.observe(limbs[0]),
            3 => self.record(3, &from_p3(E::new([limbs[0], limbs[1], limbs[2]])).to_bytes()),
            _ => panic!("C71FS unsupported algebra dimension"),
        }
    }
    fn sample_algebra_element<A: BasedVectorSpace<Goldilocks>>(&mut self) -> A {
        match A::DIMENSION {
            1 => A::from_basis_coefficients_slice(&[self.sample()]).unwrap(),
            3 => {
                let value = to_p3(self.fp3());
                A::from_basis_coefficients_slice(value.as_basis_coefficients_slice()).unwrap()
            }
            _ => panic!("C71FS unsupported algebra dimension"),
        }
    }
}

fn config(h: usize) -> Result<ZkWhirConfig<E, Goldilocks, Fs>, String> {
    if !(10..=14).contains(&h) {
        return Err("C71 CPU domain must be D10..D14".into());
    }
    #[cfg(feature = "c71-b12-pcs")]
    {
        b12::config(h)
    }
    #[cfg(not(feature = "c71-b12-pcs"))]
    {
        ZkWhirConfig::new(
            h,
            ProtocolParameters {
                security_level: 128, // nominal PCS parameter, no complete/lifetime security credit
                pow_bits: 0,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::ConstantFromSecondRound(1, 2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            ZkParameters { ell_zk: 16, mask_log_inv_rate: 1 },
        )
        .map_err(|e| e.to_string())
    }
}

/// P3's ordinary challenger omits authenticated Merkle opening payloads.
/// Bind those payloads at the actual open/verify calls before later draws.
/// This changes only the C71 transcript; the pinned fork and legacy paths
/// retain their algorithms and bytes. Extension leaf preimages are base-field
/// words in P3's v basis, exactly as consumed by the Merkle hash.
#[derive(Clone)]
struct ObservedMmcs {
    fs: Fs,
    inner: MatrixMmcs,
}

impl ObservedMmcs {
    fn new(fs: Fs, seed: [u8; 32]) -> Self {
        Self { fs, inner: matrix_mmcs(seed) }
    }

    fn bind<R: AsRef<[Goldilocks]>>(
        &self,
        indices: &[usize],
        rows: &[Vec<R>],
        proof: &MatrixMultiProof,
    ) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(indices.len() as u32).to_le_bytes());
        for (&index, matrices) in indices.iter().zip(rows) {
            bytes.extend_from_slice(&(index as u32).to_le_bytes());
            bytes.extend_from_slice(&(matrices.len() as u32).to_le_bytes());
            for row in matrices {
                bytes.extend_from_slice(&(row.as_ref().len() as u32).to_le_bytes());
                for value in row.as_ref() {
                    bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
                }
            }
        }
        #[cfg(feature = "c71-b12-pcs")]
        let proof = {
            b12::bind_salts(&mut bytes, &proof.0);
            &proof.1
        };
        bytes.extend_from_slice(&(proof.sibling_hashes.len() as u32).to_le_bytes());
        for hash in &proof.sibling_hashes {
            bytes.extend_from_slice(hash);
        }
        self.fs.clone().record(0x2100, &bytes);
    }
}

impl p3_commit::Mmcs<Goldilocks> for ObservedMmcs {
    type ProverData<M> = <MatrixMmcs as p3_commit::Mmcs<Goldilocks>>::ProverData<M>;
    type Commitment = C61Commitment;
    type Proof = <MatrixMmcs as p3_commit::Mmcs<Goldilocks>>::Proof;
    type MultiProof = MatrixMultiProof;
    type Error = <MatrixMmcs as p3_commit::Mmcs<Goldilocks>>::Error;
    fn commit<M: p3_matrix::Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        self.inner.commit(inputs)
    }
    fn get_matrices<'a, M: p3_matrix::Matrix<Goldilocks>>(
        &self,
        data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner.get_matrices(data)
    }
    fn open_batch<M: p3_matrix::Matrix<Goldilocks>>(
        &self,
        _index: usize,
        _data: &Self::ProverData<M>,
    ) -> p3_commit::BatchOpening<Goldilocks, Self> {
        panic!("C71 requires multiproofs");
    }
    fn verify_batch(
        &self,
        _commit: &Self::Commitment,
        _dimensions: &[p3_matrix::Dimensions],
        _index: usize,
        _opening: p3_commit::BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        panic!("C71 requires multiproofs");
    }
    fn open_multi_batch<M: p3_matrix::Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let (rows, proof) = self.inner.open_multi_batch(indices, data);
        self.bind(indices, &rows, &proof);
        (rows, proof)
    }
    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[p3_matrix::Dimensions],
        indices: &[usize],
        rows: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(commit, dimensions, indices, rows, proof)?;
        self.bind(indices, rows, proof);
        Ok(())
    }
}

fn request_limit(config: &ZkWhirConfig<E, Goldilocks, Fs>) -> usize {
    // For each next distinct query, acceptance >= (D-t+1)/D. If each of
    // t positions gets 256*ceil(D/(D-t+1)) draws, a union bound on honest
    // uniform tapes gives <= t*exp(-256) exhaustion. This global cap is at
    // least that sum. It does not bound adversarial ROM queries.
    let queries = |domain: usize, requested: usize| {
        let t = domain.min(requested);
        t * 256 * domain.div_ceil(domain - t + 1)
    };
    let mut bound = 3 + 3 * config.n_rounds() + config.num_variables;
    for batch in 0..=config.n_rounds() {
        bound += config.round_folding_factor(batch);
    }
    for (round, parameters) in config.round_parameters.iter().enumerate() {
        bound += parameters.ood_samples;
        bound += queries(
            parameters.domain_size >> config.round_folding_factor(round),
            parameters.num_queries,
        );
    }
    let final_round = config.final_round_config();
    bound += queries(final_round.domain_size >> final_round.folding_factor, config.final_queries);
    for group in config.mask_groups() {
        bound += queries(group.shape.domain_size, config.mask_queries);
    }
    bound
}

fn signed(x: i64) -> Fp3 {
    let magnitude = Fp::new(x.unsigned_abs());
    Fp3::from_base(if x < 0 { -magnitude } else { magnitude })
}

fn fold(values: &mut Vec<Fp3>, r: Fp3) {
    let half = values.len() / 2;
    for i in 0..half {
        let next = values[i] + r * (values[i + half] - values[i]);
        values[i] = next;
    }
    values.truncate(half);
}

fn eq(point: &[Fp3]) -> Vec<Fp3> {
    let mut weights = vec![Fp3::ONE];
    for &r in point {
        weights = weights.into_iter().flat_map(|x| [x * (Fp3::ONE - r), x * r]).collect();
    }
    weights
}

#[derive(Clone)]
struct Model {
    domain: Domain,
    weights: Vec<i16>,
    seed: [u8; 32],
    salt_seed: [u8; 32],
    root: C61Commitment,
    // Immutable across clones; the caller still owns the exposure/attempt budget.
    retained: Option<std::sync::Arc<HidingWhirProverData<Goldilocks, E, ObservedMmcs>>>,
}

#[derive(Clone, Copy)]
enum Domain {
    Matrix(usize),
    #[cfg(feature = "c71-b12-pcs")]
    Flat(usize),
    #[cfg(all(test, feature = "c71-b12-pcs"))]
    JointTest {
        bits: usize,
        exposures: usize,
        first: usize,
    },
}

impl From<usize> for Domain {
    fn from(n: usize) -> Self {
        Self::Matrix(n)
    }
}

impl Domain {
    fn config(self) -> Result<ZkWhirConfig<E, Goldilocks, Fs>, String> {
        match self {
            Self::Matrix(n) => matrix_config(n),
            #[cfg(feature = "c71-b12-pcs")]
            Self::Flat(bits) => b12::config(bits),
            #[cfg(all(test, feature = "c71-b12-pcs"))]
            Self::JointTest { bits, exposures, first } => {
                if !(12..=13).contains(&bits)
                    || !(1..=2).contains(&exposures)
                    || !(4..=5).contains(&first)
                {
                    return Err("joint-state test profile outside bounded scope".into());
                }
                Ok(codec::tuning::parameters(bits, exposures, first))
            }
        }
    }

    // Preserve the legacy side word. Its reserved high bit distinguishes a
    // flat Boolean domain, including odd dimensions D11/D35, without aliasing.
    fn identity(self) -> u32 {
        match self {
            Self::Matrix(n) => n as u32,
            #[cfg(feature = "c71-b12-pcs")]
            Self::Flat(bits) => (1 << 31) | bits as u32,
            #[cfg(all(test, feature = "c71-b12-pcs"))]
            Self::JointTest { bits, exposures, first } => {
                (1 << 30) | ((exposures as u32) << 16) | ((first as u32) << 8) | bits as u32
            }
        }
    }
}

fn matrix_config(n: usize) -> Result<ZkWhirConfig<E, Goldilocks, Fs>, String> {
    if !(1..=128).contains(&n) {
        return Err("C71 matrix side must be 1..128".into());
    }
    let side = n.next_power_of_two().max(32);
    #[cfg(feature = "c71-b12-pcs")]
    {
        config(2 * side.ilog2() as usize)
    }
    #[cfg(not(feature = "c71-b12-pcs"))]
    {
        let mut result = config(2 * side.ilog2() as usize)?;
        // A model root is admitted for only three attempted openings. Its first
        // oracle needs the aggregate query budget; every other mask is fresh.
        // This capacity adjustment is not a multi-session ZK composition proof.
        result.oracle_randomness[0] *= 3;
        let rows = side * side >> result.round_folding_factor(0);
        if result.oracle_randomness[0] > rows * ((1 << result.starting_log_inv_rate) - 1) {
            return Err("C71 three-slot initial-mask capacity exceeds oracle slack".into());
        }
        result.switch_masks[0] = MaskCodeShape::new(
            result.oracle_randomness[0] + result.round_parameters[0].ood_samples,
            result.mask_queries,
            result.zk.mask_log_inv_rate,
        );
        Ok(result)
    }
}

impl Model {
    fn new(n: usize, weights: Vec<i16>) -> Result<Self, String> {
        Self::new_in(Domain::Matrix(n), weights)
    }

    fn new_in(domain: Domain, weights: Vec<i16>) -> Result<Self, String> {
        Self::new_with_retention(domain, weights, false)
    }

    fn new_with_retention(domain: Domain, weights: Vec<i16>, retain: bool) -> Result<Self, String> {
        let config = domain.config()?;
        let valid = match domain {
            Domain::Matrix(n) => weights.len() == n * n,
            #[cfg(feature = "c71-b12-pcs")]
            Domain::Flat(bits) => !weights.is_empty() && weights.len() <= 1usize << bits,
            #[cfg(all(test, feature = "c71-b12-pcs"))]
            Domain::JointTest { bits, .. } => {
                !weights.is_empty() && weights.len() <= 1usize << bits
            }
        };
        if !valid {
            return Err("C71 weight dimensions differ".into());
        }
        let mut seed = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut seed).map_err(|e| e.to_string())?;
        let mut salt_seed = [0; 32];
        rand::rngs::OsRng.try_fill_bytes(&mut salt_seed).map_err(|e| e.to_string())?;
        let mut model = Self {
            domain,
            weights,
            seed,
            salt_seed,
            root: C61Commitment::new(vec![[0; 32]]),
            retained: None,
        };
        let mut fs = Fs::new(b"C71 model setup, Delta independent", 0);
        let mmcs = ObservedMmcs::new(fs.clone(), salt_seed);
        let dft = Radix2DFTSmallBatch::default();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);
        let (root, data) =
            prover.commit(model.polynomial(), &mut fs, &mut MatrixRng::from_seed(seed));
        model.root = root;
        model.retained = if retain { Some(std::sync::Arc::new(data)) } else { None };
        Ok(model)
    }

    fn polynomial(&self) -> Poly<Goldilocks> {
        let size = match self.domain {
            Domain::Matrix(n) => n.next_power_of_two().max(32).pow(2),
            #[cfg(feature = "c71-b12-pcs")]
            Domain::Flat(bits) => 1usize << bits,
            #[cfg(all(test, feature = "c71-b12-pcs"))]
            Domain::JointTest { bits, .. } => 1usize << bits,
        };
        let mut values = vec![Goldilocks::ZERO; size];
        for (i, &weight) in self.weights.iter().enumerate() {
            let index = match self.domain {
                Domain::Matrix(n) => (i / n) * n.next_power_of_two().max(32) + i % n,
                #[cfg(feature = "c71-b12-pcs")]
                Domain::Flat(_) => i,
                #[cfg(all(test, feature = "c71-b12-pcs"))]
                Domain::JointTest { .. } => i,
            };
            values[index] = Goldilocks::new(signed(i64::from(weight)).c0.value());
        }
        Poly::new(values)
    }
}

struct MatrixProof {
    rounds: Vec<[Fp3; 4]>, // three transfer corrections and a zero-MAC tag
    terminal: [Fp3; 2],
    pcs: ZkWhirProof<Goldilocks, E, ObservedMmcs>,
    close_tag: Fp3,
}

#[derive(Clone, Copy)]
struct AttemptContext {
    session: [u8; 32],
    capacity: [u8; 32],
    slot: u8,
    predecessor: [u8; 32],
    nonce: [u8; 32],
}

impl AttemptContext {
    fn valid(self) -> bool {
        self.slot < 3
            && self.session != [0; 32]
            && self.capacity != [0; 32]
            && self.nonce != [0; 32]
    }
    fn encode(self) -> Vec<u8> {
        let mut bytes = vec![u8::from(self.predecessor != [0; 32]), self.slot];
        bytes.extend_from_slice(&self.session);
        bytes.extend_from_slice(&self.capacity);
        bytes.extend_from_slice(&self.predecessor);
        bytes.extend_from_slice(&self.nonce);
        bytes
    }
}

fn matrix_statement(
    n: usize,
    root: &C61Commitment,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
) -> Result<Fs, String> {
    if input.len() != n || output.len() != n || !attempt.valid() || root.num_roots() != 1 {
        return Err("C71 matrix statement shape or attempt mismatch".into());
    }
    if output.iter().any(|x| x.unsigned_abs() > n as u64 * 32768 * 32768) {
        return Err("C71 integer output exceeds the no-wrap relation range".into());
    }
    let mut statement = gamma(config);
    statement.extend_from_slice(&(n as u32).to_le_bytes());
    statement.extend_from_slice(&root.roots()[0]);
    statement.extend_from_slice(&attempt.encode());
    for x in input {
        statement.extend_from_slice(&x.to_le_bytes());
    }
    for y in output {
        statement.extend_from_slice(&y.to_le_bytes());
    }
    Ok(Fs::new(&statement, request_limit(config)))
}

// Explicit derived geometry makes the profile independent of Debug formatting.
// Variable lists have their counts; every integer is a little-endian u64.
fn gamma(c: &ZkWhirConfig<E, Goldilocks, Fs>) -> Vec<u8> {
    #[cfg(not(feature = "c71-b12-pcs"))]
    let mut bytes = b"C71-matrix-v1;codec1;Fp3-u3-2;P3-v3-v-1;BLAKE3-XOF;Johnson128;PoW0;AES128-MMO;LPN64,512,8,4;setup16,128,4;checks2;pool3;lift9sVOLE48;no-security;slots3;draw8;distinct256;cap8MiB".to_vec();
    #[cfg(feature = "c71-b12-pcs")]
    let mut bytes = b"C71-matrix-B12-unique-v1;codec2;Fp3-u3-2;P3-v3-v-1;BLAKE3-XOF-coin-block1-fixed-openings;CFW9.10+8.1;radius1/4;queries512;ell2048;OOD1;PoW0;B11-AES256-finite;post-bootstrap-capacity32;rows3;salts4Fp;private-coins-v1-cap2^40;no-security;slots3;draw8;distinct256;".to_vec();
    #[cfg(feature = "c71-b12-pcs")]
    bytes.extend_from_slice(if codec::max_bytes(c.num_variables) > codec::MAX_BYTES {
        b"cap16MiB"
    } else {
        b"cap8MiB"
    });
    let mut words = vec![
        volta_field::P,
        c.zk.ell_zk as u64,
        c.zk.mask_log_inv_rate as u64,
        c.num_variables as u64,
        c.n_rounds() as u64,
        c.final_queries as u64,
        c.final_sumcheck_rounds as u64,
        c.mask_queries as u64,
        request_limit(c) as u64,
    ];
    for list in [&c.folding_schedule, &c.oracle_randomness] {
        words.push(list.len() as u64);
        words.extend(list.iter().map(|&x| x as u64));
    }
    for r in c.round_parameters.iter().chain(std::iter::once(&c.final_round_config())) {
        words.extend(
            [
                r.pow_bits,
                r.folding_pow_bits,
                r.num_queries,
                r.ood_samples,
                r.num_variables,
                r.folding_factor,
                r.log_inv_rate,
                r.domain_size,
            ]
            .map(|x| x as u64),
        );
        words.push(r.folded_domain_gen.as_canonical_u64());
    }
    let groups = c.mask_groups();
    words.push(groups.len() as u64);
    for g in groups {
        words.extend(
            [g.width, g.shape.message_len, g.shape.randomness_len, g.shape.domain_size]
                .map(|x| x as u64),
        );
    }
    words.extend(U);
    words.extend(U2);
    words.extend(FROM_P3.into_iter().flatten());
    bytes.extend(words.into_iter().flat_map(u64::to_le_bytes));
    bytes
}

fn record_values(fs: &mut Fs, kind: u16, values: &[Fp3]) {
    fs.record(kind, &values.iter().flat_map(|x| x.to_bytes()).collect::<Vec<_>>());
}

// Shared blind product sumcheck: matrix and arbitrary public linear forms
// use the same transfers, zero-MAC checks and transcript order.
fn prove_product(
    mut a: Vec<Fp3>,
    mut b: Vec<Fp3>,
    mut target: Auth,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> (Vec<[Fp3; 4]>, Vec<Fp3>, Auth, Fp3, Fp3) {
    assert_eq!(a.len(), b.len());
    assert!(a.len().is_power_of_two());
    let h = a.len().ilog2() as usize;
    let mut point = Vec::new();
    let mut rounds = Vec::new();
    for round in 0..h {
        fs.set_phase(1 + round as u16);
        let half = a.len() / 2;
        let mut coefficients = [Fp3::ZERO; 3];
        for i in 0..half {
            let da = a[i + half] - a[i];
            let db = b[i + half] - b[i];
            coefficients[0] += a[i] * b[i];
            coefficients[1] += da * b[i] + a[i] * db;
            coefficients[2] += da * db;
        }
        let mut authenticated = [Auth::ZERO; 3];
        let mut wire = [Fp3::ZERO; 4];
        for i in 0..3 {
            let (correction, value) =
                c7_fp3_transfer_prover(correlations.next().unwrap(), coefficients[i]);
            wire[i] = correction.value();
            authenticated[i] = value;
        }
        wire[3] = authenticated[0].m + authenticated[0].m + authenticated[1].m + authenticated[2].m
            - target.m;
        record_values(fs, 0x10, &wire);
        let r = fs.fp3();
        target = authenticated[0].add(authenticated[1].scale(r)).add(authenticated[2].scale(r * r));
        fold(&mut a, r);
        fold(&mut b, r);
        point.push(r);
        rounds.push(wire);
    }
    (rounds, point, target, a[0], b[0])
}

fn prove_pcs(
    model: &Model,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    point: Point<E>,
    terminal: Auth,
    mask: Auth,
    fs: &mut Fs,
) -> Result<(ZkWhirProof<Goldilocks, E, ObservedMmcs>, Fp3), String> {
    fs.set_phase(0x200);
    let dft = Radix2DFTSmallBatch::default();
    let data = if model.retained.is_some() {
        fs.observe(model.root.clone());
        None
    } else {
        census::mark("prover_commit_rematerialization")?;
        let mmcs = ObservedMmcs::new(fs.clone(), model.salt_seed);
        let prover = HidingWhirProver::new(config, &dft, &mmcs);
        // Re-materialization is charged to this attempt; only initial coins repeat.
        let (root, data) =
            prover.commit(model.polynomial(), fs, &mut MatrixRng::from_seed(model.seed));
        if root != model.root {
            return Err("C71 prover changed the installed model root".into());
        }
        Some(data)
    };
    census::mark("prover_pcs")?;
    let mut seed = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut seed).map_err(|e| e.to_string())?;
    // A new MMCS instance is essential: rematerializing the fixed root must
    // not restart the salt stream used for the fresh proof commitments.
    let mut proof_salt_seed = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut proof_salt_seed).map_err(|e| e.to_string())?;
    let proof_mmcs = ObservedMmcs::new(fs.clone(), proof_salt_seed);
    let prover = HidingWhirProver::new(config, &dft, &proof_mmcs);
    let claims = [(point, to_p3(terminal.x))];
    let mut rng = MatrixRng::from_seed(seed);
    let proved = match data {
        Some(data) => prover.prove_claimless(data, &claims, to_p3(mask.x), fs, &mut rng),
        None => prover.prove_claimless_retained(
            model.retained.as_ref().unwrap(),
            &claims,
            to_p3(mask.x),
            fs,
            &mut rng,
        ),
    };
    let close_tag =
        mask.m - from_p3(proved.base_case.gamma * proved.target.coefficient) * terminal.m;
    record_values(fs, 0x12, &[close_tag]);
    Ok((proved.proof, close_tag))
}

fn verify_product(
    rounds: &[[Fp3; 4]],
    mut target: Key,
    delta: Fp3,
    fs: &mut Fs,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<(Key, Vec<Fp3>), String> {
    let mut point = Vec::new();
    for (round, wire) in rounds.iter().enumerate() {
        fs.set_phase(1 + round as u16);
        let keys: [Key; 3] = std::array::from_fn(|i| {
            c7_fp3_transfer_verifier(
                correlations.next().unwrap(),
                delta,
                C7Fp3TransferCorrection::new(wire[i]),
            )
        });
        if keys[0].k + keys[0].k + keys[1].k + keys[2].k - target.k != wire[3] {
            return Err("C71 matrix sumcheck MAC rejected".into());
        }
        record_values(fs, 0x10, wire);
        let r = fs.fp3();
        target = keys[0].add(keys[1].scale(r)).add(keys[2].scale(r * r));
        point.push(r);
    }
    Ok((target, point))
}

#[allow(clippy::too_many_arguments)]
fn verify_pcs(
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    root: &C61Commitment,
    point: Point<E>,
    pcs: &ZkWhirProof<Goldilocks, E, ObservedMmcs>,
    close_tag: Fp3,
    terminal: Key,
    mask: Key,
    delta: Fp3,
    fs: &mut Fs,
) -> Result<(), String> {
    fs.set_phase(0x200);
    census::mark("verifier_pcs")?;
    fs.observe(root.clone());
    // Verification never commits or uses this dummy salt RNG.
    let mmcs = ObservedMmcs::new(fs.clone(), [0; 32]);
    let verifier = HidingWhirVerifier::new(config, &mmcs);
    let checked = verifier
        .verify_claimless(pcs, root, &[point], fs)
        .map_err(|e| e.to_string())?;
    let key = mask.k
        + delta * from_p3(checked.base_case.combined - checked.base_case.shifted_masked_claim)
        - from_p3(checked.base_case.gamma)
            * (from_p3(checked.target.coefficient) * terminal.k
                + delta * from_p3(checked.target.constant));
    if key != close_tag {
        return Err("C71 matrix PCS terminal MAC rejected".into());
    }
    record_values(fs, 0x12, &[close_tag]);
    Ok(())
}

fn matrix_prove(
    model: &Model,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
    correlations: &mut std::vec::IntoIter<Auth>,
) -> Result<(MatrixProof, blake3::Hash), String> {
    census::mark("prover_reduction")?;
    let n = match model.domain {
        Domain::Matrix(n) => n,
        #[cfg(feature = "c71-b12-pcs")]
        Domain::Flat(_) => return Err("C71 matrix caller needs a matrix source".into()),
        #[cfg(all(test, feature = "c71-b12-pcs"))]
        Domain::JointTest { .. } => return Err("C71 matrix caller needs a matrix source".into()),
    };
    let config = matrix_config(n)?;
    let h = config.num_variables / 2;
    let required = 3 * h + 2;
    if correlations.len() < required {
        return Err(format!(
            "matrix prover correlations: required {required}, available {}",
            correlations.len()
        ));
    }
    // The caller must durably burn this entire attempt before any emission.
    let mut reserved: std::vec::IntoIter<_> =
        correlations.by_ref().take(required).collect::<Vec<_>>().into_iter();
    let mut fs = matrix_statement(n, &model.root, input, output, attempt, &config)?;
    let side = 1 << h;
    let row_point: Vec<_> = (0..h).map(|_| fs.fp3()).collect();
    let row_weights = eq(&row_point);
    let public_sum =
        output.iter().zip(&row_weights).fold(Fp3::ZERO, |s, (&y, &r)| s + signed(y) * r);
    let target = Auth::new(public_sum, Fp3::ZERO);
    let mut a = vec![Fp3::ZERO; side];
    for i in 0..n {
        for j in 0..n {
            a[j] += row_weights[i] * signed(model.weights[i * n + j] as i64);
        }
    }
    let mut b: Vec<_> = input.iter().map(|&x| signed(x as i64)).collect();
    b.resize(side, Fp3::ZERO);
    let (rounds, col_point, target, a, b) =
        prove_product(a, b, target, &mut fs, &mut reserved);
    fs.set_phase(0x100);
    let (correction, terminal) = c7_fp3_transfer_prover(reserved.next().unwrap(), a);
    let terminal_wire = [correction.value(), target.m - b * terminal.m];
    record_values(&mut fs, 0x11, &terminal_wire);
    let mask = reserved.next().unwrap();
    let point = Point::new(row_point.into_iter().chain(col_point).map(to_p3).collect());
    let (pcs, close_tag) = prove_pcs(model, &config, point, terminal, mask, &mut fs)?;
    Ok((MatrixProof { rounds, terminal: terminal_wire, pcs, close_tag }, fs.digest()))
}

// The verifier receives only the installed root, public integers, fresh keys
// and proof. There is no provider-local witness/evaluation metadata in its API.
fn matrix_verify(
    n: usize,
    root: &C61Commitment,
    input: &[i16],
    output: &[i64],
    attempt: AttemptContext,
    proof: &MatrixProof,
    delta: Fp3,
    correlations: &mut std::vec::IntoIter<Key>,
) -> Result<blake3::Hash, String> {
    census::mark("verifier_reduction")?;
    let config = matrix_config(n)?;
    let h = config.num_variables / 2;
    let required = 3 * h + 2;
    if correlations.len() < required {
        return Err(format!(
            "matrix verifier correlations: required {required}, available {}",
            correlations.len()
        ));
    }
    let mut reserved = correlations.by_ref().take(required).collect::<Vec<_>>().into_iter();
    let mut fs = matrix_statement(n, root, input, output, attempt, &config)?;
    if proof.rounds.len() != h {
        return Err("C71 matrix round count mismatch".into());
    }
    let row_point: Vec<_> = (0..h).map(|_| fs.fp3()).collect();
    let row_weights = eq(&row_point);
    let public_sum =
        output.iter().zip(&row_weights).fold(Fp3::ZERO, |s, (&y, &r)| s + signed(y) * r);
    let target = Key::new(delta * public_sum);
    let mut b: Vec<_> = input.iter().map(|&x| signed(x as i64)).collect();
    b.resize(1 << h, Fp3::ZERO);
    let (target, col_point) =
        verify_product(&proof.rounds, target, delta, &mut fs, &mut reserved)?;
    for &r in &col_point {
        fold(&mut b, r);
    }
    fs.set_phase(0x100);
    let terminal = c7_fp3_transfer_verifier(
        reserved.next().unwrap(),
        delta,
        C7Fp3TransferCorrection::new(proof.terminal[0]),
    );
    if target.k - b[0] * terminal.k != proof.terminal[1] {
        return Err("C71 matrix terminal MAC rejected".into());
    }
    record_values(&mut fs, 0x11, &proof.terminal);
    let mask = reserved.next().unwrap();
    let point = Point::new(row_point.into_iter().chain(col_point).map(to_p3).collect());
    verify_pcs(&config, root, point, &proof.pcs, proof.close_tag, terminal, mask, delta, &mut fs)?;
    Ok(fs.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_bytes_match_independent_flat_reference() {
        // Reference rebuilds the complete byte string; it does not call any
        // Fs framing/request helper or depend on its incremental hash state.
        fn frame(bytes: &mut Vec<u8>, seq: u64, phase: u16, kind: u16, body: &[u8]) {
            bytes.extend(seq.to_le_bytes());
            bytes.extend(phase.to_le_bytes());
            bytes.extend(kind.to_le_bytes());
            bytes.extend((body.len() as u64).to_le_bytes());
            bytes.extend(body);
        }
        let mut bytes = b"volta-zk/c7.1/fs/v1".to_vec();
        frame(&mut bytes, 0, 0, 0, b"C71-public-KAT-v1");
        frame(&mut bytes, 1, 0, 2, &[0x71; 32]);
        let request = [
            0u64.to_le_bytes().as_slice(),
            &1u16.to_le_bytes(),
            &3u32.to_le_bytes(),
            &8u32.to_le_bytes(),
        ]
        .concat();
        frame(&mut bytes, 2, 1, 0xff00, &request);
        let mut expected = [0; 24];
        let mut hash = blake3::Hasher::new();
        hash.update(&bytes);
        hash.finalize_xof().fill(&mut expected);
        let expected = Fp3::from_bytes(&expected).unwrap(); // this fixed vector has no rejection
        frame(&mut bytes, 3, 1, 0xff01, &expected.to_bytes());
        frame(&mut bytes, 4, 1, 1, &7u64.to_le_bytes());
        let request = [
            1u64.to_le_bytes().as_slice(),
            &2u16.to_le_bytes(),
            &11u32.to_le_bytes(),
            &8u32.to_le_bytes(),
        ]
        .concat();
        frame(&mut bytes, 5, 1, 0xff00, &request);
        let mut word = [0; 8];
        let mut hash = blake3::Hasher::new();
        hash.update(&bytes);
        hash.finalize_xof().fill(&mut word);
        let index = u64::from_le_bytes(word) & 2047;
        frame(&mut bytes, 6, 1, 0xff01, &index.to_le_bytes());
        let mut fs = Fs::new(b"C71-public-KAT-v1", 2);
        fs.observe(C61Commitment::new(vec![[0x71; 32]]));
        fs.set_phase(1);
        assert_eq!(fs.fp3(), expected);
        fs.observe(Goldilocks::new(7));
        assert_eq!(fs.sample_bits(11), index as usize);
        assert_eq!(fs.digest(), blake3::hash(&bytes));
        assert_eq!(
            expected,
            Fp3::new(
                Fp::new(12407007333001977886),
                Fp::new(18119134539298759906),
                Fp::new(17958922495321283941)
            )
        );
        assert_eq!(index, 1319);
        assert_eq!(
            fs.digest().to_hex().as_str(),
            "2eafb615a0bdaf51cf300a197c97d491a225f2ecbb3c64689c2773bfffa2fab4"
        );
        #[cfg(not(feature = "c71-b12-pcs"))]
        for (n, digest) in [
            (48, "913f74d7b4317b71d098c55c79e2ffddc1a906859ff1e65912592448bd0e77ba"),
            (128, "e96896ada45f227b313dc5f2008c2cb38d2fbc19283e4b179c8eb20d0c70e55d"),
        ] {
            assert_eq!(blake3::hash(&gamma(&matrix_config(n).unwrap())).to_hex().as_str(), digest);
        }
    }

    #[test]
    fn cubic_basis_map_preserves_the_c71_field_and_codec() {
        let u = E::new(U.map(Goldilocks::new));
        assert_eq!(u * u, E::new(U2.map(Goldilocks::new)));
        assert_eq!(u * u * u, E::from(Goldilocks::TWO));
        let basis = [
            Fp3::ONE,
            Fp3::new(Fp::ZERO, Fp::ONE, Fp::ZERO),
            Fp3::new(Fp::ZERO, Fp::ZERO, Fp::ONE),
        ];
        for x in basis {
            assert_eq!(from_p3(to_p3(x)), x);
        }
        for i in 0..3 {
            let v = E::new(std::array::from_fn(|j| Goldilocks::from_bool(i == j)));
            assert_eq!(to_p3(from_p3(v)), v);
        }
        for n in 1..33 {
            let x = Fp3::new(Fp::new(n), Fp::new(3 * n + 1), Fp::new(5 * n + 2));
            let y = Fp3::new(-Fp::new(n + 3), Fp::new(7 * n + 4), -Fp::new(n + 5));
            assert_eq!(from_p3(to_p3(x) + to_p3(y)), x + y);
            assert_eq!(from_p3(to_p3(x) * to_p3(y)), x * y);
            assert_eq!(from_p3(to_p3(x.inv())) * x, Fp3::ONE);
            assert_eq!(Fp3::from_bytes(&from_p3(to_p3(x)).to_bytes()), Ok(x));
        }
    }

    #[test]
    fn fp3_fs_replays_native_whir_and_rejects_changes() {
        use crate::c61_whir_reference::c61_reference_mmcs;
        use p3_dft::Radix2DFTSmallBatch;
        use p3_multilinear_util::{point::Point, poly::Poly};
        use p3_whir_c61::pcs::zk::{HidingWhirProver, HidingWhirVerifier};
        use rand_010::{rngs::StdRng, SeedableRng};
        // Component diagnostic only: codec, matrix relation and lifecycle
        // are deliberately not claimed by this in-memory PCS replay.
        let config = config(14).unwrap();
        let limit = request_limit(&config);
        let mmcs = c61_reference_mmcs();
        let dft = Radix2DFTSmallBatch::default();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);
        let verifier = HidingWhirVerifier::new(&config, &mmcs);
        let witness =
            Poly::new((0..1 << 14).map(|i| Goldilocks::new((i % 32768) as u64)).collect());
        let mut fs = Fs::new(b"C71 matrix component test; D14/Fp3/128/Johnson/1,2/16/1", limit);
        let mut rng = StdRng::seed_from_u64(71);
        let (root, data) = prover.commit(witness.clone(), &mut fs, &mut rng);
        let point = Point::new((0..14).map(|_| to_p3(fs.fp3())).collect());
        let value = witness.eval_base(&point);
        let mask = to_p3(Fp3::new(Fp::new(17), Fp::new(19), Fp::new(23)));
        let output =
            prover.prove_claimless(data, &[(point.clone(), value)], mask, &mut fs, &mut rng);
        let mut replay = Fs::new(b"C71 matrix component test; D14/Fp3/128/Johnson/1,2/16/1", limit);
        replay.observe(root.clone());
        let replay_point = Point::new((0..14).map(|_| to_p3(replay.fp3())).collect());
        assert_eq!(point, replay_point);
        let before_proof = replay.fork();
        let checked =
            verifier.verify_claimless(&output.proof, &root, &[replay_point], &mut replay).unwrap();
        assert_eq!(fs.digest(), replay.digest());
        assert_eq!(fs.requests(), replay.requests());
        assert_eq!(output.target, checked.target);
        assert_eq!(output.base_case, checked.base_case);
        assert_eq!(
            checked.base_case.combined
                - checked.base_case.shifted_masked_claim
                - checked.base_case.gamma * checked.target.evaluate(value),
            -mask
        );
        let mut changed = output.proof.clone();
        changed.base_case.blinded_message[0] += E::ONE;
        assert!(verifier
            .verify_claimless(&changed, &root, &[point.clone()], &mut before_proof.fork())
            .is_err());
        let wrong_root = C61Commitment::new(vec![[0x71; 32]]);
        assert!(verifier
            .verify_claimless(&output.proof, &wrong_root, &[point], &mut before_proof.fork())
            .is_err());
        let mut exhausted = Fs::new(b"cap", 0);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exhausted.fp3())).is_err());
        assert!(super::config(27).is_err());
    }

    #[cfg(not(feature = "c71-b12-pcs"))]
    #[test]
    fn matrix_outputs_reach_the_same_root_with_real_aes_mac_targets() {
        use volta_mac::c7_fp3::{c7_fp3_lift_prover, c7_fp3_lift_verifier};
        use volta_pcg::{
            expand_phase_b_production, GgmPrg, PhaseAParams, ResponseAuthorizationStore,
            SessionBinding,
        };
        let n = 48; // non-power-of-two padding; three openings fit this initial-mask geometry
        let weights: Vec<i16> =
            (0..n * n).map(|i| ((i * 31 % 65536) as i32 - 32768) as i16).collect();
        let model = Model::new(n, weights).unwrap();
        let h = matrix_config(n).unwrap().num_variables / 2;
        let per_attempt = 3 * h + 2;
        let count = 3 * per_attempt;
        let directory = std::env::temp_dir().join(format!(
            "volta-c71-matrix-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = ResponseAuthorizationStore::new(&directory).unwrap();
        let mut pools: Vec<_> = (0..3)
            .map(|lane| {
                let binding = SessionBinding::new([0x71; 32], [0x72; 32], [lane + 1; 32]).unwrap();
                let setup = expand_phase_b_production(
                    &store,
                    binding,
                    3 * count,
                    0,
                    PhaseAParams::tiny_for_test(3 * count),
                )
                .unwrap();
                assert!(setup.expansion.consistency.ok);
                assert_eq!(setup.expansion.setup.params.ggm_prg, GgmPrg::Aes128Mmo);
                setup.expansion
            })
            .collect();
        let delta = Fp3::new(
            pools[0].verifier_delta.c0,
            pools[1].verifier_delta.c0,
            pools[2].verifier_delta.c0,
        );
        let mut auths = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..count {
            let rows = std::array::from_fn(|_| {
                std::array::from_fn(|lane| pools[lane].prover.subs.pop().unwrap())
            });
            let key_rows = std::array::from_fn(|_| {
                std::array::from_fn(|lane| pools[lane].verifier.sub_keys.pop().unwrap())
            });
            let (wire, auth) = c7_fp3_lift_prover(rows);
            auths.push(auth);
            keys.push(c7_fp3_lift_verifier(key_rows, delta, wire));
        }
        assert!(pools.iter().all(|p| p.prover.subs.is_empty() && p.verifier.sub_keys.is_empty()));
        let mut prover_pool = auths.into_iter();
        let mut verifier_pool = keys.into_iter();
        let mut predecessor = [0; 32];
        for slot in 0..3 {
            let attempt = AttemptContext {
                session: [0x71; 32],
                capacity: [0x73; 32],
                slot,
                predecessor,
                nonce: [0xa0 + slot; 32],
            };
            let binding = SessionBinding::new([0x71; 32], [0x72; 32], attempt.nonce).unwrap();
            store.reserve(&binding).unwrap();
            assert!(store.reserve(&binding).is_err());
            if slot == 1 {
                assert_eq!(prover_pool.by_ref().take(per_attempt).count(), per_attempt);
                assert_eq!(verifier_pool.by_ref().take(per_attempt).count(), per_attempt);
                continue; // deliberately aborted after burning all reserved masks
            }
            let input: Vec<i16> = (0..n).map(|j| (j as i16 - 24) * slot as i16).collect();
            let output: Vec<i64> = model
                .weights
                .chunks_exact(n)
                .map(|row| row.iter().zip(&input).map(|(&w, &x)| i64::from(w) * i64::from(x)).sum())
                .collect();
            let fixture_keys = verifier_pool.clone();
            let fixture_auths = prover_pool.clone();
            let (proof, prover_digest) =
                matrix_prove(&model, &input, &output, attempt, &mut prover_pool).unwrap();
            let encoded = codec::encode(n, &model.root, &input, &output, attempt, &proof).unwrap();
            let mut proof =
                codec::decode(n, &model.root, &input, &output, attempt, &encoded).unwrap();
            assert_eq!(
                codec::encode(n, &model.root, &input, &output, attempt, &proof).unwrap(),
                encoded
            );
            for end in [0, 75, encoded.len() / 2, encoded.len() - 1] {
                assert!(codec::decode(n, &model.root, &input, &output, attempt, &encoded[..end])
                    .is_err());
            }
            let mut bad = encoded.clone();
            bad.push(0);
            assert!(codec::decode(n, &model.root, &input, &output, attempt, &bad).is_err());
            bad = encoded.clone();
            bad[codec::header(n, &model.root, &input, &output, attempt).unwrap().bytes.len()
                ..codec::header(n, &model.root, &input, &output, attempt).unwrap().bytes.len() + 8]
                .copy_from_slice(&volta_field::P.to_le_bytes());
            assert!(codec::decode(n, &model.root, &input, &output, attempt, &bad).is_err());
            let verifier_digest = matrix_verify(
                n,
                &model.root,
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut verifier_pool,
            )
            .unwrap();
            assert_eq!(prover_digest, verifier_digest);
            predecessor = *verifier_digest.as_bytes();
            if slot == 0 {
                let mut wrong_w = model.clone();
                wrong_w.weights[0] += 1;
                assert!(matrix_prove(
                    &wrong_w,
                    &input,
                    &output,
                    attempt,
                    &mut fixture_auths.clone()
                )
                .err()
                .unwrap()
                .contains("installed model root"));
                let mut wrong_input = input.clone();
                wrong_input[0] += 1;
                assert!(matrix_verify(
                    n,
                    &model.root,
                    &wrong_input,
                    &output,
                    attempt,
                    &proof,
                    delta,
                    &mut fixture_keys.clone()
                )
                .is_err());
                // Each altered context also changes the derived row/column points;
                // a valid proof cannot supply or override those challenge points.
                for changed in [
                    AttemptContext { session: [9; 32], ..attempt },
                    AttemptContext { capacity: [9; 32], ..attempt },
                    AttemptContext { slot: 2, ..attempt },
                    AttemptContext { predecessor: [9; 32], ..attempt },
                    AttemptContext { nonce: [9; 32], ..attempt },
                ] {
                    assert!(
                        codec::decode(n, &model.root, &input, &output, changed, &encoded).is_err()
                    );
                    assert!(matrix_verify(
                        n,
                        &model.root,
                        &input,
                        &output,
                        changed,
                        &proof,
                        delta,
                        &mut fixture_keys.clone()
                    )
                    .is_err());
                }
            }
            proof.rounds[0][3] += Fp3::ONE;
            assert!(matrix_verify(
                n,
                &model.root,
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut fixture_keys.clone()
            )
            .is_err());
            proof.rounds[0][3] = proof.rounds[0][3] - Fp3::ONE;
            proof.rounds.swap(0, 1);
            assert!(matrix_verify(
                n,
                &model.root,
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut fixture_keys.clone()
            )
            .is_err());
            proof.rounds.swap(0, 1);
            // Replays below mutate one fixed fixture; they are not new session attempts.
            let mut wrong_output = output.clone();
            wrong_output[0] += 1;
            assert!(matrix_verify(
                n,
                &model.root,
                &input,
                &wrong_output,
                attempt,
                &proof,
                delta,
                &mut fixture_keys.clone()
            )
            .is_err());
            assert!(matrix_verify(
                n,
                &C61Commitment::new(vec![[7; 32]]),
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut fixture_keys.clone()
            )
            .is_err());
            proof.terminal[0] += Fp3::ONE;
            assert!(matrix_verify(
                n,
                &model.root,
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut fixture_keys.clone()
            )
            .is_err());
            assert!(matrix_verify(
                n,
                &model.root,
                &input,
                &output,
                attempt,
                &proof,
                delta,
                &mut Vec::new().into_iter()
            )
            .unwrap_err()
            .contains("required"));
        }
        assert_eq!(prover_pool.len(), 0);
        assert_eq!(verifier_pool.len(), 0);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
