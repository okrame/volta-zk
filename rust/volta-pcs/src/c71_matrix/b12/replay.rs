//! Bounded end-to-end sourcewise WHIR refinement against the native transcript.
use super::*;
use super::{
    replay_tree::Tree,
    sourcewise::{Getter, Lease, State},
};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::{dense::DenseMatrix, extension::FlatMatrixView, Matrix};
use p3_sumcheck_c61::strategy::ResidualSumcheckProver;
use p3_whir_c61::pcs::{
    proof::{QueryOpenings, SharedProofOpening},
    zk::{
        BaseCaseZkProof, ZkRoundProof, ZkWhirInitialMessage, ZkWhirOracleCommitter,
        ZkWhirReplayHandle,
    },
};
use rand_010::RngExt;
use std::sync::{Arc, Mutex};
fn limbs(x: &E) -> &[Goldilocks] {
    <E as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(x)
}
enum Pads {
    Base(Arc<[Goldilocks]>),
    Extension(Vec<E>),
}
impl Pads {
    fn len(&self) -> usize {
        match self {
            Self::Base(v) => v.len(),
            Self::Extension(v) => v.len(),
        }
    }
    fn get(&self, i: usize) -> E {
        match self {
            Self::Base(v) => E::from(v[i]),
            Self::Extension(v) => v[i],
        }
    }
}
struct Code {
    get: Getter,
    len: usize,
    width: usize,
    height: usize,
    pads: Pads,
}

fn multiply_polynomials(
    mut left: Vec<Goldilocks>,
    mut right: Vec<Goldilocks>,
    dft: &Radix2DFTSmallBatch<Goldilocks>,
) -> Vec<Goldilocks> {
    let length = left.len() + right.len() - 1;
    let size = length.next_power_of_two();
    left.resize(size, Goldilocks::ZERO);
    right.resize(size, Goldilocks::ZERO);
    let mut spectrum = dft.dft(left);
    for (value, factor) in spectrum.iter_mut().zip(dft.dft(right)) {
        *value *= factor;
    }
    let mut product = dft.idft(spectrum);
    product.truncate(length);
    product
}

struct QueryFactors {
    inverse: Vec<Goldilocks>,
    modulus: Vec<Goldilocks>,
}

fn query_tree(
    points: &[Goldilocks],
    dft: &Radix2DFTSmallBatch<Goldilocks>,
) -> Vec<Vec<QueryFactors>> {
    assert!(points.len().is_power_of_two());
    let mut level: Vec<_> = points.iter().map(|&point| vec![-point, Goldilocks::ONE]).collect();
    let mut factors = Vec::new();
    loop {
        factors.push(level.iter().map(|modulus| QueryFactors::new(modulus.clone(), dft)).collect());
        if level.len() == 1 {
            return factors;
        }
        let mut children = level.into_iter();
        level = Vec::with_capacity(children.len() / 2);
        while let Some(left) = children.next() {
            level.push(multiply_polynomials(left, children.next().unwrap(), dft));
        }
    }
}

impl QueryFactors {
    fn new(mut modulus: Vec<Goldilocks>, dft: &Radix2DFTSmallBatch<Goldilocks>) -> Self {
        let cap = modulus.len() - 1;
        let reverse: Vec<_> = modulus.iter().rev().copied().collect();
        let mut inverse = vec![Goldilocks::ONE];
        while inverse.len() < cap {
            let next = 2 * inverse.len();
            let mut correction =
                multiply_polynomials(reverse[..next].to_vec(), inverse.clone(), dft);
            correction.truncate(next);
            for value in &mut correction {
                *value = -*value;
            }
            correction[0] += Goldilocks::ONE + Goldilocks::ONE;
            inverse = multiply_polynomials(inverse, correction, dft);
            inverse.truncate(next);
        }
        inverse.resize(2 * cap, Goldilocks::ZERO);
        modulus.resize(2 * cap, Goldilocks::ZERO);
        Self { inverse: dft.dft(inverse), modulus: dft.dft(modulus) }
    }

    fn remainder(
        &self,
        high: &[E],
        low: impl Fn(usize) -> E,
        dft: &Radix2DFTSmallBatch<Goldilocks>,
    ) -> Vec<E> {
        let cap = self.inverse.len() / 2;
        assert_eq!(high.len(), cap);
        let mut reversed: Vec<_> = high.iter().rev().copied().collect();
        reversed.resize(2 * cap, E::ZERO);
        let mut spectrum = dft.dft_algebra(reversed);
        for (value, &factor) in spectrum.iter_mut().zip(&self.inverse) {
            *value *= factor;
        }
        let mut quotient = dft.idft_algebra(spectrum);
        quotient.truncate(cap);
        quotient.reverse();
        quotient.resize(2 * cap, E::ZERO);
        let mut spectrum = dft.dft_algebra(quotient);
        for (value, &factor) in spectrum.iter_mut().zip(&self.modulus) {
            *value *= factor;
        }
        let product = dft.idft_algebra(spectrum);
        (0..cap).map(|offset| low(offset) - product[offset]).collect()
    }
}

impl Code {
    fn base(&self) -> bool {
        matches!(self.pads, Pads::Base(_))
    }
    fn columns(&self) -> usize {
        self.width * if self.base() { 1 } else { 3 }
    }
    fn coefficient(&self, b: usize, j: usize) -> E {
        let n = self.len / self.width;
        let pad = self.pads.len() / self.width;
        if j < n {
            (self.get)(b * n + j)
        } else {
            assert!(j < n + pad);
            self.pads.get(b * pad + j - n)
        }
    }
    fn coset(&self, c: usize, rows: usize) -> Result<Vec<u64>, String> {
        let z = Goldilocks::two_adic_generator(self.height.ilog2() as usize).exp_u64(c as u64);
        let mut values = vec![E::ZERO; rows * self.width];
        for b in 0..self.width {
            let mut power = Goldilocks::ONE;
            for j in 0..(self.len + self.pads.len()) / self.width {
                values[(j % rows) * self.width + b] += self.coefficient(b, j) * power;
                power *= z;
            }
        }
        let encoded = Radix2DFTSmallBatch::<Goldilocks>::default()
            .dft_algebra_batch(DenseMatrix::new(values, self.width))
            .to_row_major_matrix();
        let mut cells = vec![0; rows * self.columns().max(4)];
        for j in 0..rows {
            for b in 0..self.width {
                let x = encoded.values[j * self.width + b];
                if self.base() {
                    assert_eq!(&limbs(&x)[1..], &[Goldilocks::ZERO; 2]);
                    cells[b * rows + j] = limbs(&x)[0].as_canonical_u64();
                } else {
                    for (k, v) in limbs(&x).iter().enumerate() {
                        cells[(3 * b + k) * rows + j] = v.as_canonical_u64();
                    }
                }
            }
        }
        Ok(cells)
    }
    fn rows(&self, indices: &[usize]) -> Result<Vec<Vec<Goldilocks>>, String> {
        if indices.len() > 1024 || indices.iter().any(|&index| index >= self.height) {
            return Err("code query outside domain or reference batch cap".into());
        }
        if indices.is_empty() {
            return Ok(Vec::new());
        }
        let root = Goldilocks::two_adic_generator(self.height.ilog2() as usize);
        let cap = indices.len().next_power_of_two();
        let mut points: Vec<_> = indices.iter().map(|&index| root.exp_u64(index as u64)).collect();
        points.resize(cap, Goldilocks::ZERO);
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        let factors = query_tree(&points, &dft);
        let root_factors = &factors.last().unwrap()[0];
        let coefficients = (self.len + self.pads.len()) / self.width;
        let mut values = vec![E::ZERO; indices.len() * self.width];
        for column in 0..self.width {
            let mut remainder = vec![E::ZERO; cap];
            for block in (0..coefficients.div_ceil(cap)).rev() {
                remainder = root_factors.remainder(
                    &remainder,
                    |offset| {
                        let index = block * cap + offset;
                        if index < coefficients {
                            self.coefficient(column, index)
                        } else {
                            E::ZERO
                        }
                    },
                    &dft,
                );
            }
            let mut remainders = vec![remainder];
            for level in factors[..factors.len() - 1].iter().rev() {
                let mut children = Vec::with_capacity(level.len());
                for (parent, pair) in remainders.into_iter().zip(level.chunks_exact(2)) {
                    let half = parent.len() / 2;
                    for factor in pair {
                        children.push(factor.remainder(
                            &parent[half..],
                            |offset| parent[offset],
                            &dft,
                        ));
                    }
                }
                remainders = children;
            }
            for (row, value) in remainders.into_iter().take(indices.len()).enumerate() {
                values[row * self.width + column] = value[0];
            }
        }
        Ok(values
            .chunks_exact(self.width)
            .map(|row| {
                let mut output = Vec::with_capacity(self.columns());
                for v in row {
                    if self.base() {
                        output.push(limbs(v)[0]);
                    } else {
                        output.extend_from_slice(limbs(v));
                    }
                }
                output
            })
            .collect())
    }
    fn commit(
        self,
        mmcs: &HidingMmcs,
        state: Option<&State>,
    ) -> Result<(replay_tree::Commitment, ZkWhirReplayHandle), String> {
        let base = self.base();
        let code = Arc::new(self);
        let rowcode = code.clone();
        let rows = 256.min(code.height);
        let (root, tree) = Tree::commit(
            mmcs,
            code.height,
            code.columns(),
            rows,
            (code.height / rows).max(16),
            |c| code.coset(c, rows),
            Arc::new(move |indices| rowcode.rows(indices)),
        )?;
        let lease = state.map(State::replay_lease).transpose()?.flatten();
        Ok((root, ZkWhirReplayHandle::new(Oracle { tree, base, lease })))
    }
}

/// Immutable base-field source behind one already committed flat oracle.
///
/// The caller owns the getter's storage and must keep its answers immutable
/// for the root's lifetime. Construction replays the installation coins and
/// rejects a root mismatch before this handle can be used by a proof.
pub(in crate::c71_matrix) struct ReplayModel {
    domain: Domain,
    root: C61Commitment,
    seed: [u8; 32],
    salt_seed: [u8; 32],
    source: Getter,
}

impl ReplayModel {
    pub(in crate::c71_matrix) fn new(
        domain: Domain,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
    ) -> Result<Self, String> {
        let mut model =
            Self { domain, root: C61Commitment::new(vec![[0; 32]]), seed, salt_seed, source };
        let mut setup = Fs::new(b"C71 model setup, Delta independent", 0);
        let (root, handle, _) = model.commit_initial(&mut setup)?;
        drop(handle);
        model.root = root;
        Ok(model)
    }

    pub(in crate::c71_matrix) fn new_checked(
        domain: Domain,
        root: C61Commitment,
        seed: [u8; 32],
        salt_seed: [u8; 32],
        source: Getter,
    ) -> Result<Self, String> {
        let model = Self::new(domain, seed, salt_seed, source)?;
        if root != model.root {
            return Err("C71 replay source changed the installed model root".into());
        }
        Ok(model)
    }

    pub(in crate::c71_matrix) fn domain(&self) -> Domain {
        self.domain
    }

    pub(in crate::c71_matrix) fn root(&self) -> &C61Commitment {
        &self.root
    }

    pub(in crate::c71_matrix) fn source(&self) -> Getter {
        self.source.clone()
    }

    pub(in crate::c71_matrix) fn value(&self, index: usize) -> Fp3 {
        from_p3((self.source)(index))
    }

    fn commit_initial(
        &self,
        fs: &mut Fs,
    ) -> Result<(C61Commitment, ZkWhirReplayHandle, Arc<[Goldilocks]>), String> {
        let config = self.domain.config()?;
        let first = config.round_folding_factor(0);
        let mut rng = PrivateRng::from_seed(self.seed);
        let pads: Arc<[Goldilocks]> =
            (0..config.oracle_randomness[0] << first).map(|_| rng.random()).collect();
        let len = 1usize << config.num_variables;
        let height = (len >> first) << config.starting_log_inv_rate;
        let mmcs = ObservedMmcs::new(fs.clone(), self.salt_seed);
        // Match `HidingWhirProver::new`: cloning forks the extension salt
        // stream by consuming one seed from the base stream before its commit.
        let _extension = mmcs.clone();
        let (root, handle) = Code {
            get: self.source.clone(),
            len,
            width: 1 << first,
            height,
            pads: Pads::Base(pads.clone()),
        }
        .commit(&mmcs.inner, None)?;
        Ok((root, handle, pads))
    }
}

pub(in crate::c71_matrix) fn prove_pcs_sourcewise(
    model: &ReplayModel,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    point: Point<E>,
    terminal: Auth,
    mask: Auth,
    fs: &mut Fs,
) -> Result<(ZkWhirProof<Goldilocks, E, ObservedMmcs>, Fp3), String> {
    prove_pcs_sourcewise_with_coins(model, config, point, terminal, mask, fs, fresh_pcs_coins()?)
}

pub(in crate::c71_matrix) fn prove_pcs_sourcewise_with_coins(
    model: &ReplayModel,
    config: &ZkWhirConfig<E, Goldilocks, Fs>,
    point: Point<E>,
    terminal: Auth,
    mask: Auth,
    fs: &mut Fs,
    coins: PcsCoins,
) -> Result<(ZkWhirProof<Goldilocks, E, ObservedMmcs>, Fp3), String> {
    if model.domain.config()?.num_variables != config.num_variables {
        return Err("C71 replay source and PCS domains differ".into());
    }
    fs.set_phase(0x200);
    census::mark("prover_commit_rematerialization")?;
    let (root, handle, pads) = model.commit_initial(fs)?;
    if root != model.root {
        return Err("C71 replay source changed the installed model root".into());
    }
    fs.observe(root);
    census::mark("prover_pcs")?;
    let dft = Radix2DFTSmallBatch::default();
    let base = ObservedMmcs::new(fs.clone(), coins.salt_seed);
    let extension = base.clone();
    let base_ref = &base;
    let prover = HidingWhirProver {
        config,
        dft: &dft,
        mmcs: &base_ref,
        extension_mmcs: ExtensionMmcs::new(&extension),
    };
    let claims = [(point, to_p3(terminal.x))];
    let backend = Backend {
        base: &base,
        extension: &extension,
        source: Mutex::new(Some(model.source.clone())),
        first: config.round_folding_factor(0),
        retain_first: false,
    };
    let mut rng = PrivateRng::from_seed(coins.seed);
    let proved = prover.prove_claimless_replay_with_oracle(
        1 << config.num_variables,
        &pads,
        handle,
        &claims,
        to_p3(mask.x),
        &backend,
        fs,
        &mut rng,
    )?;
    let close_tag =
        mask.m - from_p3(proved.base_case.gamma * proved.target.coefficient) * terminal.m;
    record_values(fs, 0x12, &[close_tag]);
    Ok((owned_proof(proved.proof), close_tag))
}

// `&ObservedMmcs` and `ObservedMmcs` have identical commitment/proof associated
// types. Move the payload between their nominal WHIR wrappers without a codec
// round trip or a second copy of any proof vector.
fn owned_proof(
    proof: ZkWhirProof<Goldilocks, E, &ObservedMmcs>,
) -> ZkWhirProof<Goldilocks, E, ObservedMmcs> {
    let ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case } = proof;
    let rounds = rounds
        .into_iter()
        .map(|round| {
            let ZkRoundProof { commitment, mask_commitment, ood_answers, pow_witness, openings } =
                round;
            ZkRoundProof { commitment, mask_commitment, ood_answers, pow_witness, openings }
        })
        .collect();
    let BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness,
        source_openings,
        fresh_main_openings,
        mask_openings,
    } = base_case;
    let base_case = BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness,
        source_openings,
        fresh_main_openings,
        mask_openings,
    };
    ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case }
}
struct Oracle {
    tree: Tree,
    base: bool,
    lease: Option<Lease>,
}
struct Backend<'a> {
    base: &'a ObservedMmcs,
    extension: &'a ObservedMmcs,
    source: Mutex<Option<Getter>>,
    first: usize,
    retain_first: bool,
}
impl<'a> ZkWhirOracleCommitter<Goldilocks, E, &'a ObservedMmcs> for Backend<'a> {
    type Error = String;
    type SumcheckState = State;
    fn initialize_sumcheck(
        &self,
        message: ZkWhirInitialMessage<'_, Goldilocks>,
        claims: &[(Point<E>, E)],
        coefficients: &[E],
        target: E,
    ) -> Result<State, String> {
        if claims.len() != 1
            || coefficients != [E::ONE]
            || message.len() != 1 << claims[0].0.num_variables()
        {
            return Err("bounded singleton sourcewise claim".into());
        }
        let mut source = self.source.lock().map_err(|_| "source lock poisoned")?;
        let state = State::new(
            source.as_ref().ok_or("source already consumed")?.clone(),
            claims[0].0.as_slice(),
            self.first,
            target,
            self.retain_first,
        )?;
        source.take(); // transfer ownership only after geometry and claim validation
        Ok(state)
    }
    fn commit_initial(
        &self,
        _: ZkWhirInitialMessage<'_, Goldilocks>,
        _: &[Goldilocks],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<DenseMatrix<Goldilocks>>,
        ),
        String,
    > {
        Err("dense initial commit forbidden".into())
    }
    fn commit_extension(
        &self,
        _: &[E],
        _: &[E],
        _: usize,
        _: usize,
    ) -> Result<
        (
            replay_tree::Commitment,
            <HidingMmcs as Mmcs<Goldilocks>>::ProverData<
                FlatMatrixView<Goldilocks, E, DenseMatrix<E>>,
            >,
        ),
        String,
    > {
        Err("dense extension commit forbidden".into())
    }
    fn commit_extension_replay_from_sumcheck(
        &self,
        state: &State,
        randomness: &[E],
        folding: usize,
        height: usize,
    ) -> Result<Option<(replay_tree::Commitment, ZkWhirReplayHandle)>, String> {
        let get = state.getter();
        Code {
            get,
            len: 1 << state.num_variables(),
            width: 1 << folding,
            height,
            pads: Pads::Extension(randomness.to_vec()),
        }
        .commit(&self.extension.inner, Some(state))
        .map(Some)
    }
    fn evaluate_padded_ood_from_sumcheck(
        &self,
        state: &State,
        point: E,
        suffix: &[E],
    ) -> Result<Option<E>, String> {
        let get = state.getter();
        let mut v = suffix.iter().rev().fold(E::ZERO, |v, &x| v * point + x);
        for i in (0..1 << state.num_variables()).rev() {
            v = v * point + get(i);
        }
        Ok(Some(v))
    }
    fn accumulate_round_claim_from_sumcheck(
        &self,
        state: &mut State,
        domain: usize,
        indices: &[usize],
        points: &[E],
        ood: &[E],
        queries: &[E],
    ) -> Result<bool, String> {
        let root = Goldilocks::two_adic_generator(domain.ilog2() as usize);
        let mut terms: Vec<_> = points.iter().copied().zip(ood.iter().copied()).collect();
        terms.extend(
            indices.iter().zip(queries).map(|(&i, &c)| (E::from(root.exp_u64(i as u64)), c)),
        );
        state.add_powers(&terms)?;
        Ok(true)
    }
    fn release_replay(&self, handle: ZkWhirReplayHandle) -> Result<(), String> {
        let oracle = handle.downcast::<Oracle>().map_err(|_| "replay handle type")?;
        let Oracle { tree, lease, .. } = *oracle;
        drop(tree); // no opening callback survives when the generation is released
        if let Some(lease) = lease {
            lease.release()?;
        }
        Ok(())
    }
    fn open_replay(
        &self,
        handle: &ZkWhirReplayHandle,
        indices: &[usize],
        randomness: &Point<E>,
    ) -> Result<Option<(QueryOpenings<Goldilocks, E, replay_tree::MultiProof>, Vec<E>)>, String>
    {
        let oracle = handle.downcast_ref::<Oracle>().ok_or("replay handle type")?;
        let (rows, proof) = oracle.tree.open(indices)?;
        // The C7.1 wrapper binds original rows/salts/frontier into FS before
        // the next coin, including extension rows in their native base layout.
        let mmcs = if oracle.base { self.base } else { self.extension };
        mmcs.bind(indices, &rows, &proof);
        let rows: Vec<_> = rows.into_iter().map(|mut v| v.remove(0)).collect();
        if oracle.base {
            let folded = rows.iter().map(|v| Poly::new(v.clone()).eval_base(randomness)).collect();
            Ok(Some((QueryOpenings::Base(SharedProofOpening { rows, proof }), folded)))
        } else {
            let rows: Vec<Vec<E>> = rows
                .iter()
                .map(|v| v.chunks_exact(3).map(|c| E::new(c.try_into().unwrap())).collect())
                .collect();
            let folded = rows
                .iter()
                .map(|v| Poly::new(v.clone()).eval_ext::<Goldilocks>(randomness))
                .collect();
            Ok(Some((QueryOpenings::Extension(SharedProofOpening { rows, proof }), folded)))
        }
    }
}
#[cfg(test)]
pub(in crate::c71_matrix) fn compare_source(
    dimension: usize,
    source: Getter,
    values: Vec<Goldilocks>,
    original: Option<&Model>,
) {
    use rand_010::RngExt;
    assert!((10..=12).contains(&dimension));
    assert_eq!(values.len(), 1 << dimension);
    census::start().unwrap();
    let config = config(dimension).unwrap();
    let dft = Radix2DFTSmallBatch::default();
    let salt_seed = original.map_or([73; 32], |m| m.salt_seed);
    let root_seed = original.map_or([91; 32], |m| m.seed);
    let witness = Poly::new(values);
    let point = Point::new(
        (0..dimension)
            .map(|i| {
                E::new([Goldilocks::new(i as u64 + 3), Goldilocks::new(7), Goldilocks::new(11)])
            })
            .collect(),
    );
    let value = witness.eval_base(&point);
    // Original endpoint fixed before the proof. Ideal MACs here, as in the
    // bounded composed runner; no reauthentication after challenges.
    let delta =
        Fp3::new(volta_field::Fp::new(7), volta_field::Fp::new(11), volta_field::Fp::new(13));
    let terminal_key = Key { k: Fp3::ONE };
    let terminal = Auth { x: from_p3(value), m: terminal_key.k - delta * from_p3(value) };
    let mask_key = Key { k: Fp3::ONE + Fp3::ONE };
    let mask = Auth { x: Fp3::ONE, m: mask_key.k - delta };
    let claims = [(point.clone(), value)];
    let mut fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    fs.set_phase(0x200);
    let root_mmcs = ObservedMmcs::new(fs.clone(), salt_seed);
    let root_prover = HidingWhirProver::new(&config, &dft, &root_mmcs);
    let mut root_rng = PrivateRng::from_seed(root_seed);
    let (root, data) = root_prover.commit(witness, &mut fs, &mut root_rng);
    if let Some(original) = original {
        assert_eq!(root, original.root);
    }
    // Actual C7.1 discipline: fresh proof coins/MMCS, independent of root replay.
    let proof_mmcs = ObservedMmcs::new(fs.clone(), [83; 32]);
    let reference = HidingWhirProver::new(&config, &dft, &proof_mmcs);
    let mut rng = PrivateRng::from_seed([101; 32]);
    let result = reference.prove_claimless(data, &claims, to_p3(mask.x), &mut fs, &mut rng);

    census::mark("sourcewise_initial_commit").unwrap();
    let mut replay_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    replay_fs.set_phase(0x200);
    let original_mmcs = ObservedMmcs::new(replay_fs.clone(), salt_seed);
    let _original_extension = original_mmcs.clone(); // the native initial-construction fork
    let mut initial_rng = PrivateRng::from_seed(root_seed);
    let first = config.round_folding_factor(0);
    let pads: Arc<[Goldilocks]> =
        (0..config.oracle_randomness[0] << first).map(|_| initial_rng.random()).collect();
    let height = ((1 << dimension) >> first) << config.starting_log_inv_rate;
    let (replay_root, handle) = Code {
        get: source.clone(),
        len: 1 << dimension,
        width: 1 << first,
        height,
        pads: Pads::Base(pads.clone()),
    }
    .commit(&original_mmcs.inner, None)
    .unwrap();
    assert_eq!(root, replay_root);
    assert_eq!(root_rng.position(), initial_rng.position());
    replay_fs.observe(replay_root.clone());
    let base = ObservedMmcs::new(replay_fs.clone(), [83; 32]);
    let extension = base.clone();
    let base_ref = &base;
    let engine = HidingWhirProver {
        config: &config,
        dft: &dft,
        mmcs: &base_ref,
        extension_mmcs: ExtensionMmcs::new(&extension),
    };
    let mut replay_rng = PrivateRng::from_seed([101; 32]);
    census::mark("sourcewise_open_all_rounds").unwrap();
    let backend = Backend {
        base: &base,
        extension: &extension,
        source: Mutex::new(Some(source)),
        first,
        retain_first: original.is_some(),
    };
    let output = engine
        .prove_claimless_replay_with_oracle(
            1 << dimension,
            &pads,
            handle,
            &claims,
            to_p3(mask.x),
            &backend,
            &mut replay_fs,
            &mut replay_rng,
        )
        .unwrap();
    census::mark("codec_and_native_verifier").unwrap();
    assert_eq!(
        serde_json::to_vec(&result.proof).unwrap(),
        serde_json::to_vec(&output.proof).unwrap()
    );
    let close_tag =
        mask.m - from_p3(output.base_case.gamma * output.target.coefficient) * terminal.m;
    assert_eq!(
        close_tag,
        mask.m - from_p3(result.base_case.gamma * result.target.coefficient) * terminal.m
    );
    let canonical = |value| {
        let matrix = MatrixProof {
            rounds: vec![[Fp3::ZERO; 4]; dimension],
            terminal: [Fp3::ZERO; 2],
            pcs: serde_json::from_value(value).unwrap(),
            close_tag,
        };
        codec::encode_linear(Domain::Flat(dimension), &matrix).unwrap()
    };
    let bytes = canonical(serde_json::to_value(&result.proof).unwrap());
    assert_eq!(bytes, canonical(serde_json::to_value(&output.proof).unwrap()));
    eprintln!("sourcewise observed D{dimension} canonical_bytes={}", bytes.len());
    assert_eq!(fs.digest(), replay_fs.digest());
    assert_eq!(rng.position(), replay_rng.position());
    assert_eq!(result.target, output.target);
    assert_eq!(result.base_case, output.base_case);
    record_values(&mut fs, 0x12, &[close_tag]);
    record_values(&mut replay_fs, 0x12, &[close_tag]);
    let owned_proof: ZkWhirProof<Goldilocks, E, ObservedMmcs> =
        serde_json::from_value(serde_json::to_value(&output.proof).unwrap()).unwrap();
    let mut verifier_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    verify_pcs(
        &config,
        &root,
        point.clone(),
        &owned_proof,
        close_tag,
        terminal_key,
        mask_key,
        delta,
        &mut verifier_fs,
    )
    .unwrap();
    assert_eq!(verifier_fs.digest(), fs.digest());
    // A coherently encoded proof cannot be closed on a different endpoint MAC.
    let mut wrong_fs = Fs::new(b"sourcewise C71 observed refinement", request_limit(&config));
    assert!(verify_pcs(
        &config,
        &root,
        point,
        &owned_proof,
        close_tag,
        Key { k: terminal_key.k + Fp3::ONE },
        mask_key,
        delta,
        &mut wrong_fs
    )
    .is_err());
    eprintln!("sourcewise_allocator={}", census::finish().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c71_b12_query_factors_balanced_product_and_newton_match_direct_oracle() {
        let dft = Radix2DFTSmallBatch::<Goldilocks>::default();
        for cap in [1_usize, 2, 4, 8, 32, 128, 1024] {
            let points: Vec<_> = (0..cap)
                .map(|index| Goldilocks::new(((index * index + 7 * index) % 19) as u64))
                .collect();
            let mut expected = vec![Goldilocks::ONE];
            for &point in &points {
                let mut next = vec![Goldilocks::ZERO; expected.len() + 1];
                for (degree, &coefficient) in expected.iter().enumerate() {
                    next[degree] -= coefficient * point;
                    next[degree + 1] += coefficient;
                }
                expected = next;
            }
            let factors = query_tree(&points, &dft);
            assert_eq!(factors.len(), cap.ilog2() as usize + 1);
            for (depth, level) in factors.iter().enumerate() {
                assert_eq!(level.len(), cap >> depth);
                assert!(level.iter().all(|factor| factor.inverse.len() == 2usize << depth));
            }
            let root = &factors.last().unwrap()[0];
            let (inverse, modulus) = (root.inverse.clone(), root.modulus.clone());
            assert_eq!(inverse.len(), 2 * cap);
            assert_eq!(modulus.len(), 2 * cap);
            let inverse = dft.idft(inverse);
            let modulus = dft.idft(modulus);
            assert_eq!(&modulus[..cap + 1], expected);
            assert!(modulus[cap + 1..].iter().all(|&value| value == Goldilocks::ZERO));
            assert!(inverse[cap..].iter().all(|&value| value == Goldilocks::ZERO));
            for degree in 0..cap {
                let coefficient: Goldilocks = (0..=degree)
                    .map(|offset| expected[cap - offset] * inverse[degree - offset])
                    .sum();
                assert_eq!(
                    coefficient,
                    if degree == 0 { Goldilocks::ONE } else { Goldilocks::ZERO }
                );
            }
        }
    }

    #[test]
    fn c71_b12_query_remainder_matches_original_base_and_extension_rows() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for extension in [false, true] {
            let reads = Arc::new(AtomicUsize::new(0));
            let counter = reads.clone();
            let original = move |index: usize| {
                E::new(std::array::from_fn(|limb| {
                    if limb == 0 || extension {
                        Goldilocks::new((index * index + 17 * index + 23 + limb) as u64)
                    } else {
                        Goldilocks::ZERO
                    }
                }))
            };
            let pads: Vec<_> = (0..6).map(|index| -original(index + 131)).collect();
            let code = Code {
                get: Arc::new(move |index| {
                    counter.fetch_add(1, Ordering::Relaxed);
                    original(index)
                }),
                len: 130,
                width: 2,
                height: 1024,
                pads: if extension {
                    Pads::Extension(pads.clone())
                } else {
                    Pads::Base(pads.iter().map(|value| limbs(value)[0]).collect())
                },
            };
            let root = Goldilocks::two_adic_generator(10);
            for indices in [
                vec![],
                vec![0],
                vec![1023, 0, 31],
                vec![1, 1, 1, 7, 127],
                (0..1024).rev().collect(),
            ] {
                let expected: Vec<Vec<_>> = indices
                    .iter()
                    .map(|&index| {
                        let point = root.exp_u64(index as u64);
                        (0..2)
                            .flat_map(|column| {
                                let value = (0..68).rev().fold(E::ZERO, |value, offset| {
                                    value * point
                                        + if offset < 65 {
                                            original(column * 65 + offset)
                                        } else {
                                            pads[column * 3 + offset - 65]
                                        }
                                });
                                limbs(&value)[..if extension { 3 } else { 1 }].to_vec()
                            })
                            .collect()
                    })
                    .collect();
                reads.store(0, Ordering::Relaxed);
                assert_eq!(code.rows(&indices).unwrap(), expected);
                assert_eq!(reads.load(Ordering::Relaxed), if indices.is_empty() { 0 } else { 130 });
            }
            reads.store(0, Ordering::Relaxed);
            assert!(code.rows(&[1024]).is_err());
            assert!(code.rows(&vec![0; 1025]).is_err());
            assert_eq!(reads.load(Ordering::Relaxed), 0);
        }
        println!("C71_QUERY_REMAINDER base_and_extension=true original_pads=true one_source_read_per_batch=true canonical_credit=false");
    }

    #[test]
    fn c71_b12_full_sourcewise_chain_matches_native_bytes() {
        let source: Getter = Arc::new(|i| E::from(Goldilocks::new((i * i + 17 * i + 23) as u64)));
        let values = (0..1024).map(|i| limbs(&source(i))[0]).collect();
        compare_source(10, source, values, None);
    }
}
