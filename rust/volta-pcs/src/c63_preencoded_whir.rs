//! CPU reference for C6.3's pre-encoded initial WHIR oracle.
//!
//! This freezes the deterministic `A * rho` layout and a CPU-only, opt-in
//! first-round link against the existing C6.2 cached-base seam. It is not a
//! production adapter, a privacy proof, the systematic `D' -> m` link, or
//! evidence for paired queries.

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use p3_blake3::Blake3;
use p3_challenger::{
    CanFinalizeDigest, CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError, SerializingChallenger64,
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_matrix::extension::FlatMatrixView;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeError;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck_c61::zk::ZkSumcheckData;
use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir_c61::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir_c61::pcs::zk::{
    BaseCaseZkProof, BlindedMask, ClaimlessWhirVerifierClosure, HidingWhirVerifier,
    MaskOpeningPair, ZkParameters, ZkRoundProof, ZkWhirConfig, ZkWhirInitialMessage,
    ZkWhirInitialOracleLink, ZkWhirOracleCommitter, ZkWhirProof,
};
use rayon::prelude::*;
use volta_field::Fp2;
use volta_mac::{Transcript, VerifierCtx, VerifierKey};
use volta_proto::C6ClientAttempt;

use crate::c61_authenticated_whir::{
    verify_c63_authenticated_whir_limb_pair, C61AuthenticatedWhirAffineClaim,
    C61AuthenticatedWhirBaseProof, C63AuthenticatedWhirLane, C63AuthenticatedWhirMaskRange,
    C63AuthenticatedWhirNormalizedLimb,
};
use crate::c61_whir_reference::{
    c61_max_pruned_binary_siblings, c61_p3_fp2_from_volta, c61_reference_mmcs,
    c61_volta_fp2_from_p3, C61Commitment, C61Mmcs, C61MultiProof, C61P3Fp2, C61Reader,
    C61SizingChallenger, C61WhirStructuralBudget, C61Writer, C61_WHIRA1_DIGEST_BYTES,
    C61_WHIRA1_ELL_ZK, C61_WHIRA1_FP2_BYTES, C61_WHIRA1_FP_BYTES, C61_WHIRA1_HEADER_BYTES,
    C61_WHIRA1_MULTIPROOF_COUNT_BYTES,
};
use crate::c62_gpu_whir::{
    C62GpuMmcs, C62GpuProverData, C62GpuSumcheckState, C62GpuWhirCommitter, C62GpuWhirError,
};
use crate::c63_authenticated_sketch::{
    c63_verify_correction_rows_by_tape_reference, C63CorrectionRowsOpeningReference,
    C63SparseSketchReference, C63_BOLT_COLUMNS, C63_SYSTEMATIC_SPOT_QUERIES,
};
#[cfg(test)]
use crate::c63_authenticated_sketch::{C63CorrectionAppendFrontier, C63_BOLT_ROWS_PER_POSITION};
use crate::c63_gpu_owner::C63GpuStateOwner;
use crate::c63_public_argument::{C63PublicArgument, C63VerifierSketchState};
use crate::c63_sparse_h_closure::{
    begin_verify_c63_sparse_h_tape_closure_reference, C63SparseHClosureProof,
    C63SparseHClosureStatement, C63SparseHTapeClosureReferenceAudit, C63SparseHTapeVerifierPending,
    C63TapeSystematicSpot,
};
use crate::c6_authenticated_output_link::C63ResidualSourceFunctionalsVerifiedLink;

pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2: usize = 19;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROWS: usize = 1 << C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2;
pub const C63_ENCODED_SKETCH_FOLDED_POSITIONS: usize = 2;
pub const C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH: usize =
    C63_BOLT_COLUMNS * C63_ENCODED_SKETCH_FOLDED_POSITIONS;
pub const C63_ENCODED_SKETCH_INDEPENDENT_A_QUERIES: usize = 490;
pub const C63_WHIR_MAGIC: [u8; 8] = *b"C63WIR1\0";
pub const C63_WHIR_VERSION: u16 = 1;
pub const C63_WHIR_SECURITY_BITS: usize = 105;
pub const C63_POW_SEARCH_CAP_PER_PHASE: u64 = 1 << 26;
const C63_H_POW_CONTEXT: &str = "volta-zk/c63/H_pow/v1";
const C63_SYSTEMATIC_QUERY_PHASE_TAG: u64 = 0x6330_6358_5152_5931;

/// Draw sorted unique systematic rows after both state roots and `rho` have
/// already entered the caller's transcript. Duplicate draws are rejected,
/// which is uniform sampling without replacement over this power-of-two
/// domain. The cap fails closed instead of permitting an adversarial sampler
/// to stall verification.
pub fn c63_sample_systematic_query_rows<Challenger>(
    challenger: &mut Challenger,
    num_variables: usize,
    queries: usize,
) -> Result<Vec<u32>, String>
where
    Challenger: CanObserve<Goldilocks> + CanSampleBits<usize>,
{
    let domain = 1usize
        .checked_shl(num_variables as u32)
        .ok_or_else(|| "C6.3 systematic query dimension overflows".to_owned())?;
    if num_variables == 0 || num_variables > 32 || queries == 0 || queries > domain {
        return Err("C6.3 systematic query geometry differs".to_owned());
    }
    challenger.observe(Goldilocks::new(C63_SYSTEMATIC_QUERY_PHASE_TAG));
    let draw_cap = queries
        .checked_mul(2)
        .ok_or_else(|| "C6.3 systematic query draw cap overflows".to_owned())?;
    let mut rows = BTreeSet::new();
    for _ in 0..draw_cap {
        rows.insert(challenger.sample_bits(num_variables) as u32);
        if rows.len() == queries {
            return Ok(rows.into_iter().collect());
        }
    }
    Err("C6.3 systematic query duplicate-draw cap reached".to_owned())
}

/// Fiat--Shamir delegates to `inner`; grinding uses an independent keyed hash.
#[derive(Clone)]
pub struct C63SeparatedChallenger<F, Inner> {
    inner: Inner,
    role: [u8; 16],
    pow_phase: u64,
    marker: PhantomData<F>,
}

impl<F, Inner> C63SeparatedChallenger<F, Inner> {
    pub fn new(inner: Inner, role: [u8; 16]) -> Result<Self, String> {
        if role == [0; 16] {
            return Err("C6.3 separated challenger role is zero".to_owned());
        }
        Ok(Self { inner, role, pow_phase: 0, marker: PhantomData })
    }
}

impl<T, F, Inner> CanObserve<T> for C63SeparatedChallenger<F, Inner>
where
    Inner: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.inner.observe(value);
    }
}

impl<T, F, Inner> CanSample<T> for C63SeparatedChallenger<F, Inner>
where
    Inner: CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
}

impl<F, Inner> CanSampleBits<usize> for C63SeparatedChallenger<F, Inner>
where
    Inner: CanSampleBits<usize>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}

impl<F, Inner> CanSampleUniformBits<F> for C63SeparatedChallenger<F, Inner>
where
    Inner: CanSampleUniformBits<F>,
{
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        self.inner.sample_uniform_bits::<RESAMPLE>(bits)
    }
}

impl<F, Inner> FieldChallenger<F> for C63SeparatedChallenger<F, Inner>
where
    F: Field + Sync,
    Inner: CanObserve<F> + CanSample<F> + CanSampleBits<usize> + Sync,
{
}

impl<F, Inner> GrindingChallenger for C63SeparatedChallenger<F, Inner>
where
    F: PrimeField64 + Sync,
    Inner: CanFinalizeDigest<Digest = [u8; 32]>
        + CanObserve<F>
        + CanSample<F>
        + CanSampleBits<usize>
        + Clone
        + Sync,
{
    type Witness = F;

    fn grind(&mut self, bits: usize) -> F {
        assert!(bits < 64 && (1u64 << bits) < F::ORDER_U64);
        if bits == 0 {
            return F::ZERO;
        }
        let snapshot = self.inner.clone().finalize();
        let witness = (0..C63_POW_SEARCH_CAP_PER_PHASE.min(F::ORDER_U64))
            .into_par_iter()
            .find_any(|&candidate| {
                c63_pow_accepts(self.role, self.pow_phase, bits, snapshot, candidate)
            })
            .map(|candidate| unsafe { F::from_canonical_unchecked(candidate) })
            .expect("C6.3 separated PoW witness search hit its fail-closed cap");
        assert!(self.check_witness(bits, witness));
        witness
    }

    fn check_witness(&mut self, bits: usize, witness: F) -> bool {
        if bits == 0 {
            return true;
        }
        if bits >= 64 || (1u64 << bits) >= F::ORDER_U64 {
            return false;
        }
        let snapshot = self.inner.clone().finalize();
        if !c63_pow_accepts(self.role, self.pow_phase, bits, snapshot, witness.to_unique_u64()) {
            return false;
        }
        self.inner.observe(witness);
        self.pow_phase += 1;
        true
    }
}

fn c63_pow_accepts(
    role: [u8; 16],
    phase: u64,
    bits: usize,
    snapshot: [u8; 32],
    witness: u64,
) -> bool {
    let mut hasher = blake3::Hasher::new_derive_key(C63_H_POW_CONTEXT);
    hasher.update(&role);
    hasher.update(&phase.to_le_bytes());
    hasher.update(&(bits as u64).to_le_bytes());
    hasher.update(&snapshot);
    hasher.update(&witness.to_le_bytes());
    let digest = hasher.finalize();
    u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("fixed PoW digest"))
        & ((1u64 << bits) - 1)
        == 0
}

pub type C63SeparatedSizingChallenger = C63SeparatedChallenger<Goldilocks, C61SizingChallenger>;
pub type C63WhirConfig = ZkWhirConfig<C61P3Fp2, Goldilocks, C63SeparatedSizingChallenger>;
pub type C63OrdinaryWhirProof = ZkWhirProof<Goldilocks, C61P3Fp2, C61Mmcs>;

const C63_TRANSCRIPT_BINDING_CONTEXT: &str = "volta-zk/c63/transcript-binding/v2";
const C63_TRANSCRIPT_LANE_CONTEXT: &str = "volta-zk/c63/transcript-lane/v1";
const C63_TRANSCRIPT_QUERY_CONTEXT: &str = "volta-zk/c63/transcript-query/v1";
const C63_TRANSCRIPT_SPOT_CONTEXT: &str = "volta-zk/c63/transcript-spots/v1";
const C63_TRANSCRIPT_SPARSE_CONTEXT: &str = "volta-zk/c63/transcript-sparse/v1";
const C63_TRANSCRIPT_TERMINAL_CONTEXT: &str = "volta-zk/c63/transcript-terminal/v1";
const C63_TRANSCRIPT_SOURCE_FUNCTIONAL_CONTEXT: &str =
    "volta-zk/c63/transcript-source-functional/v1";
const C63_TRANSCRIPT_OUTPUT_POINT_CONTEXT: &str = "volta-zk/c63/transcript-output-point/v1";
const C63_PROJECTED_CACHE_CONTENT_CONTEXT: &str = "volta-zk/c63/projected-cache-content/v1";

/// Minimal C6.3 Fiat--Shamir schedule. The immutable request/model bindings
/// fix `rho` and the eight lane contexts; all eight initial roots then fix the
/// systematic/sparse context; only the complete public and sparse bodies fix
/// the four terminal contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C63TranscriptBinding {
    digest: [u8; 32],
}

impl C63TranscriptBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        attempt: C6ClientAttempt,
        statement_digest: [u8; 32],
        profile_digest: [u8; 32],
        predecessor_correction_root: [u8; 32],
        predecessor_encoded_sketch_root: [u8; 32],
        correction_root: [u8; 32],
        encoded_sketch_root: [u8; 32],
        epoch: u64,
        old_len: u16,
        accepted_len: u16,
    ) -> Result<Self, String> {
        if [
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_encoded_sketch_root,
            correction_root,
            encoded_sketch_root,
        ]
        .contains(&[0; 32])
            || epoch == 0
            || old_len >= accepted_len
            || attempt.workload.old_context != u32::from(old_len)
            || attempt.workload.new_context != u32::from(accepted_len)
        {
            return Err("C6.3 transcript binding contains an empty field".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_BINDING_CONTEXT);
        hasher.update(b"C63TX2");
        hasher.update(&crate::c61_interactive_driver::c61_interactive_attempt_digest(attempt)?);
        hasher.update(&statement_digest);
        hasher.update(&profile_digest);
        hasher.update(&predecessor_correction_root);
        hasher.update(&predecessor_encoded_sketch_root);
        hasher.update(&correction_root);
        hasher.update(&encoded_sketch_root);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&old_len.to_le_bytes());
        hasher.update(&accepted_len.to_le_bytes());
        Ok(Self { digest: *hasher.finalize().as_bytes() })
    }

    pub(crate) fn rho_seed(self) -> [u8; 32] {
        self.digest
    }

    pub(crate) fn output_point(self) -> Vec<Fp2> {
        let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_OUTPUT_POINT_CONTEXT);
        hasher.update(&self.digest);
        let mut transcript = Transcript::new(*hasher.finalize().as_bytes());
        (0..C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2).map(|_| transcript.challenge_fp2()).collect()
    }

    pub(crate) fn projected_cache_content_digest(
        self,
        rho: &[Fp2; C63_BOLT_COLUMNS],
        tape: usize,
        limb: usize,
    ) -> Result<[u8; 32], String> {
        if tape >= 2 || limb >= 2 {
            return Err("C6.3 projected cache coordinate differs".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key(C63_PROJECTED_CACHE_CONTENT_CONTEXT);
        hasher.update(&self.digest);
        c63_hash_rho(&mut hasher, rho);
        hasher.update(&[tape as u8, limb as u8]);
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn lane_seed(
        self,
        rho: &[Fp2; C63_BOLT_COLUMNS],
        lane: C63AuthenticatedWhirLane,
        tape: usize,
        limb: usize,
    ) -> Result<[u8; 32], String> {
        if tape >= 2 || limb >= 2 {
            return Err("C6.3 transcript lane coordinate differs".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_LANE_CONTEXT);
        hasher.update(&self.digest);
        c63_hash_rho(&mut hasher, rho);
        hasher.update(&[lane as u8, tape as u8, limb as u8]);
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn query_seed(
        self,
        rho: &[Fp2; C63_BOLT_COLUMNS],
        initial_roots: &[[u8; 32]; 8],
    ) -> Result<[u8; 32], String> {
        if initial_roots.contains(&[0; 32]) {
            return Err("C6.3 transcript contains an empty WHIR root".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_QUERY_CONTEXT);
        hasher.update(&self.digest);
        c63_hash_rho(&mut hasher, rho);
        for root in initial_roots {
            hasher.update(root);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn spot_seed(self, query_seed: [u8; 32]) -> Result<[u8; 32], String> {
        c63_phase_seed(C63_TRANSCRIPT_SPOT_CONTEXT, self.digest, query_seed)
    }

    pub(crate) fn sparse_seed(self, query_seed: [u8; 32]) -> Result<[u8; 32], String> {
        c63_phase_seed(C63_TRANSCRIPT_SPARSE_CONTEXT, self.digest, query_seed)
    }

    pub(crate) fn source_functional_context(
        self,
        query_seed: [u8; 32],
        sparse_prefix_digest: [u8; 32],
    ) -> Result<[u8; 32], String> {
        if query_seed == [0; 32] || sparse_prefix_digest == [0; 32] {
            return Err("C6.3 source-functional transcript input is empty".to_owned());
        }
        let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_SOURCE_FUNCTIONAL_CONTEXT);
        hasher.update(&self.digest);
        hasher.update(&query_seed);
        hasher.update(&sparse_prefix_digest);
        Ok(*hasher.finalize().as_bytes())
    }

    pub(crate) fn terminal_contexts(
        self,
        query_seed: [u8; 32],
        public_argument: &[u8],
        sparse_proof: &[u8],
    ) -> Result<[[[u8; 32]; 2]; 2], String> {
        if query_seed == [0; 32] || public_argument.is_empty() || sparse_proof.is_empty() {
            return Err("C6.3 terminal transcript input is empty".to_owned());
        }
        Ok(std::array::from_fn(|lane| {
            std::array::from_fn(|tape| {
                let mut hasher = blake3::Hasher::new_derive_key(C63_TRANSCRIPT_TERMINAL_CONTEXT);
                hasher.update(&self.digest);
                hasher.update(&query_seed);
                hasher.update(&(public_argument.len() as u64).to_le_bytes());
                hasher.update(public_argument);
                hasher.update(&(sparse_proof.len() as u64).to_le_bytes());
                hasher.update(sparse_proof);
                hasher.update(&[lane as u8, tape as u8]);
                *hasher.finalize().as_bytes()
            })
        }))
    }
}

fn c63_phase_seed(
    context: &'static str,
    binding: [u8; 32],
    query_seed: [u8; 32],
) -> Result<[u8; 32], String> {
    if query_seed == [0; 32] {
        return Err("C6.3 phase transcript input is empty".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&binding);
    hasher.update(&query_seed);
    Ok(*hasher.finalize().as_bytes())
}

fn c63_hash_rho(hasher: &mut blake3::Hasher, rho: &[Fp2; C63_BOLT_COLUMNS]) {
    for value in rho {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C63ClaimlessWhirVerifierClosure {
    pub(crate) claim_weight: Fp2,
    pub(crate) target: C61AuthenticatedWhirAffineClaim,
    pub(crate) combined: Fp2,
    pub(crate) shifted_masked_claim: Fp2,
    pub(crate) gamma: Fp2,
}

pub(crate) fn c63_challenger(
    context_digest: [u8; 32],
) -> Result<C63SeparatedSizingChallenger, String> {
    if context_digest == [0; 32] {
        return Err("C6.3 WHIR transcript context is zero".to_owned());
    }
    C63SeparatedChallenger::new(
        SerializingChallenger64::new(HashChallenger::<u8, Blake3, 32>::new(
            context_digest.to_vec(),
            Blake3 {},
        )),
        [0x63; 16],
    )
}

fn c63_convert_verifier_closure(
    closure: ClaimlessWhirVerifierClosure<C61P3Fp2>,
) -> Result<C63ClaimlessWhirVerifierClosure, String> {
    let [claim_weight]: [C61P3Fp2; 1] = closure
        .claim_weights
        .try_into()
        .map_err(|_| "C6.3 WHIR claim-weight census differs".to_owned())?;
    Ok(C63ClaimlessWhirVerifierClosure {
        claim_weight: c61_volta_fp2_from_p3(claim_weight),
        target: C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(closure.target.coefficient),
            constant: c61_volta_fp2_from_p3(closure.target.constant),
        },
        combined: c61_volta_fp2_from_p3(closure.base_case.combined),
        shifted_masked_claim: c61_volta_fp2_from_p3(closure.base_case.shifted_masked_claim),
        gamma: c61_volta_fp2_from_p3(closure.base_case.gamma),
    })
}

#[cfg(feature = "cuda")]
pub(crate) struct C63ResidentWhirLimbProof {
    pub(crate) artifact: Vec<u8>,
    pub(crate) normalized: C63AuthenticatedWhirNormalizedLimb,
}

#[cfg(feature = "cuda")]
fn c63_normalize_prover_limb<MT>(
    output: &p3_whir_c61::pcs::zk::ClaimlessWhirProverOutput<Goldilocks, C61P3Fp2, MT>,
) -> Result<C63AuthenticatedWhirNormalizedLimb, String>
where
    MT: Mmcs<Goldilocks>,
{
    let [claim_weight]: [C61P3Fp2; 1] = output
        .claim_weights
        .clone()
        .try_into()
        .map_err(|_| "C6.3 resident WHIR claim-weight census differs".to_owned())?;
    Ok(C63AuthenticatedWhirNormalizedLimb {
        combined: c61_volta_fp2_from_p3(output.base_case.combined),
        shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
        gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
        affine: C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(output.target.coefficient),
            constant: c61_volta_fp2_from_p3(output.target.constant),
        },
        claim_weight: c61_volta_fp2_from_p3(claim_weight),
    })
}

#[cfg(feature = "cuda")]
pub(crate) struct C63ResidentSystematicPrepared {
    mmcs: C62GpuMmcs,
    config: C63WhirConfig,
    committer: C62GpuWhirCommitter,
    commitment: C61Commitment,
    data: p3_whir_c61::pcs::zk::HidingWhirProverData<Goldilocks, C61P3Fp2, C62GpuMmcs>,
    challenger: C63SeparatedSizingChallenger,
}

#[cfg(feature = "cuda")]
impl C63ResidentSystematicPrepared {
    pub(crate) fn root(&self) -> [u8; 32] {
        self.commitment.roots()[0]
    }

    pub(crate) fn evaluate(&self, point: &[Fp2]) -> Result<Fp2, String> {
        self.committer.evaluate_pending_initial(point).map_err(|error| error.to_string())
    }

    pub(crate) fn finish<R: rand_010::Rng>(
        self,
        point: &[Fp2],
        evaluation: Fp2,
        mask: Fp2,
        rng: &mut R,
    ) -> Result<C63ResidentWhirLimbProof, String> {
        if self.config.num_variables != point.len() {
            return Err("C6.3 resident systematic opening geometry differs".to_owned());
        }
        let dft = p3_dft::Radix2DFTSmallBatch::default();
        let prover = p3_whir_c61::pcs::zk::HidingWhirProver::new(&self.config, &dft, &self.mmcs);
        let point = Point::new(point.iter().rev().copied().map(c61_p3_fp2_from_volta).collect());
        let mut challenger = self.challenger;
        challenger.observe_algebra_slice(point.as_slice());
        let output = prover
            .prove_claimless_with_oracle(
                self.data,
                &[(point, c61_p3_fp2_from_volta(evaluation))],
                c61_p3_fp2_from_volta(mask),
                &self.committer,
                &mut challenger,
                rng,
            )
            .map_err(|error| error.to_string())?;
        let artifact = encode_c63_whir_ordinary_artifact_with_config(
            self.config.num_variables,
            &self.config,
            &self.commitment,
            &output.proof,
        )?;
        Ok(C63ResidentWhirLimbProof { artifact, normalized: c63_normalize_prover_limb(&output)? })
    }
}

/// Commit one D22 systematic limb before the sparse point is drawn. The
/// existing GPU WHIR committer performs the fresh code switch; no host-sized
/// message or second proof engine is introduced.
#[cfg(feature = "cuda")]
pub(crate) fn prepare_c63_resident_systematic_limb<R: rand_010::Rng>(
    mmcs: C62GpuMmcs,
    config: &C63WhirConfig,
    message: volta_accel::DeviceBuffer<u64>,
    context_digest: [u8; 32],
    rng: &mut R,
) -> Result<C63ResidentSystematicPrepared, String> {
    if message.len() != 1usize << config.num_variables {
        return Err("C6.3 resident systematic lane geometry differs".to_owned());
    }
    let committer = C62GpuWhirCommitter::fresh_resident(mmcs.clone(), message)
        .map_err(|error| error.to_string())?;
    let dft = p3_dft::Radix2DFTSmallBatch::default();
    let prover = p3_whir_c61::pcs::zk::HidingWhirProver::new(config, &dft, &mmcs);
    let mut challenger = c63_challenger(context_digest)?;
    let (commitment, data) = prover
        .commit_resident_with_oracle(
            1usize << config.num_variables,
            &committer,
            &mut challenger,
            rng,
        )
        .map_err(|error| error.to_string())?;
    Ok(C63ResidentSystematicPrepared {
        mmcs,
        config: config.clone(),
        committer,
        commitment,
        data,
        challenger,
    })
}

#[cfg(feature = "cuda")]
pub(crate) struct C63ResidentProjectedPrepared {
    config: C63WhirConfig,
    mmcs: C63ProjectedGpuMmcs,
    committer: C62GpuWhirCommitter,
    commitment: C61Commitment,
    data: p3_whir_c61::pcs::zk::HidingWhirProverData<Goldilocks, C61P3Fp2, C63ProjectedGpuMmcs>,
    challenger: C63SeparatedSizingChallenger,
}

#[cfg(feature = "cuda")]
impl C63ResidentProjectedPrepared {
    pub(crate) fn root(&self) -> [u8; 32] {
        self.commitment.roots()[0]
    }

    pub(crate) fn evaluate(&self, point: &[Fp2]) -> Result<Fp2, String> {
        self.committer.evaluate_pending_initial(point).map_err(|error| error.to_string())
    }

    pub(crate) fn finish<R: rand_010::Rng>(
        self,
        point: &[Fp2],
        evaluation: Fp2,
        mask: Fp2,
        rng: &mut R,
    ) -> Result<C63ResidentWhirLimbProof, String> {
        if self.config.num_variables != point.len() {
            return Err("C6.3 resident projected opening geometry differs".to_owned());
        }
        let link = self.mmcs.link();
        let dft = p3_dft::Radix2DFTSmallBatch::default();
        let prover = p3_whir_c61::pcs::zk::HidingWhirProver::new(&self.config, &dft, &self.mmcs);
        let point = Point::new(point.iter().rev().copied().map(c61_p3_fp2_from_volta).collect());
        let mut challenger = self.challenger;
        challenger.observe_algebra_slice(point.as_slice());
        let output = prover
            .prove_claimless_with_oracle_and_initial_link(
                self.data,
                &[(point, c61_p3_fp2_from_volta(evaluation))],
                c61_p3_fp2_from_volta(mask),
                &self.committer,
                &link,
                &mut challenger,
                rng,
            )
            .map_err(|error| error.to_string())?;
        let artifact = encode_c63_whir_projected_artifact_with_config(
            self.config.num_variables,
            &self.config,
            &self.commitment,
            &output.proof,
        )?;
        Ok(C63ResidentWhirLimbProof { artifact, normalized: c63_normalize_prover_limb(&output)? })
    }
}

/// Commit one D19 sketch limb and attach the accepted `A` transition before
/// the sparse point is drawn.
#[cfg(feature = "cuda")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_c63_resident_projected_limb<R: rand_010::Rng>(
    mmcs: C62GpuMmcs,
    config: &C63WhirConfig,
    key: crate::c62_gpu_whir::C62ProviderCacheKey,
    message: volta_accel::DeviceBuffer<u64>,
    encoded: volta_accel::DeviceBuffer<u64>,
    context: C63EncodedSketchAtoYContext,
    predecessor: Option<Arc<C63GpuStateOwner>>,
    successor: Arc<C63GpuStateOwner>,
    context_digest: [u8; 32],
    rng: &mut R,
) -> Result<C63ResidentProjectedPrepared, String> {
    if message.len() != 1usize << config.num_variables
        || key.num_variables as usize != config.num_variables
    {
        return Err("C6.3 resident projected lane geometry differs".to_owned());
    }
    let cache = mmcs
        .prepare_linked_fixed_base_resident(key, message, encoded)
        .map_err(|error| error.to_string())?;
    let projected_mmcs = C63ProjectedGpuMmcs::new(mmcs.clone(), context);
    let committer = C62GpuWhirCommitter::provider_cached(mmcs, cache);
    let dft = p3_dft::Radix2DFTSmallBatch::default();
    let prover = p3_whir_c61::pcs::zk::HidingWhirProver::new(config, &dft, &projected_mmcs);
    let mut challenger = c63_challenger(context_digest)?;
    let (commitment, mut data) = prover
        .commit_resident_with_oracle(
            1usize << config.num_variables,
            &committer,
            &mut challenger,
            rng,
        )
        .map_err(|error| error.to_string())?;
    projected_mmcs
        .attach_encoded_sketch_a(&mut data.merkle, predecessor, successor)
        .map_err(|error| error.to_string())?;
    Ok(C63ResidentProjectedPrepared {
        config: config.clone(),
        mmcs: projected_mmcs,
        committer,
        commitment,
        data,
        challenger,
    })
}

pub(crate) fn verify_c63_claimless_whir_limb_pair(
    closures: [C63ClaimlessWhirVerifierClosure; 2],
    opening_target_key: VerifierKey,
    proof: C61AuthenticatedWhirBaseProof,
    context: &mut VerifierCtx,
    lane: C63AuthenticatedWhirLane,
    mask_range: C63AuthenticatedWhirMaskRange,
    transcript_context: [u8; 32],
) -> Result<(), String> {
    let inputs = std::array::from_fn(|limb| C63AuthenticatedWhirNormalizedLimb {
        combined: closures[limb].combined,
        shifted_masked_claim: closures[limb].shifted_masked_claim,
        gamma: closures[limb].gamma,
        affine: closures[limb].target,
        claim_weight: closures[limb].claim_weight,
    });
    let mut transcript = Transcript::new_fiat_shamir(transcript_context)?;
    verify_c63_authenticated_whir_limb_pair(
        inputs,
        opening_target_key,
        proof,
        context,
        lane,
        mask_range,
        &mut transcript,
    )
    .map_err(|error| error.to_string())
}

fn encode_c63_fp_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<Goldilocks, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> Result<(), String> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err("C6.3 WHIR base opening shape differs".to_owned());
    }
    for row in &opening.rows {
        for value in row {
            writer.fp(*value);
        }
    }
    writer
        .multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
        .map_err(|error| error.to_string())
}

fn encode_c63_fp2_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<C61P3Fp2, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> Result<(), String> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err("C6.3 WHIR extension opening shape differs".to_owned());
    }
    for row in &opening.rows {
        for value in row {
            writer.fp2(*value);
        }
    }
    writer
        .multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
        .map_err(|error| error.to_string())
}

fn decode_c63_fp_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> Result<SharedProofOpening<Goldilocks, C61MultiProof>, String> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp().map_err(|error| error.to_string())?);
        }
        rows.push(row);
    }
    let proof = reader
        .multiproof(c61_max_pruned_binary_siblings(leaves, queries))
        .map_err(|error| error.to_string())?;
    Ok(SharedProofOpening { rows, proof })
}

fn decode_c63_fp2_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> Result<SharedProofOpening<C61P3Fp2, C61MultiProof>, String> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp2().map_err(|error| error.to_string())?);
        }
        rows.push(row);
    }
    let proof = reader
        .multiproof(c61_max_pruned_binary_siblings(leaves, queries))
        .map_err(|error| error.to_string())?;
    Ok(SharedProofOpening { rows, proof })
}

fn c63_whir_profile(num_variables: usize) -> Result<(usize, Vec<usize>, Vec<usize>), String> {
    match num_variables {
        22 => Ok((18, vec![1, 2, 3, 3, 4, 5, 6, 7], vec![1, 2, 2, 2, 2, 2, 2, 2, 2])),
        19 => Ok((17, vec![1, 2, 3, 4, 5, 6], vec![1, 2, 2, 2, 2, 2, 2])),
        _ => Err("C6.3 WHIR admits only D22 or D19".to_owned()),
    }
}

/// Exact registered D22/D19 Hiding-WHIR configuration, including native PoW.
pub fn c63_whir_config(num_variables: usize) -> Result<C63WhirConfig, String> {
    let (pow_bits, rates, folding) = c63_whir_profile(num_variables)?;
    ZkWhirConfig::new_with_query_security_level(
        num_variables,
        ProtocolParameters {
            security_level: C63_WHIR_SECURITY_BITS,
            pow_bits,
            round_log_inv_rates: rates,
            folding_factor: FoldingFactor::PerRound(folding),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        ZkParameters { ell_zk: 16, mask_log_inv_rate: 1 },
        C63_WHIR_SECURITY_BITS,
    )
    .map_err(|error| format!("C6.3 WHIR configuration failed: {error}"))
}

pub fn c63_whir_structural_budget(num_variables: usize) -> Result<C61WhirStructuralBudget, String> {
    let config = c63_whir_config(num_variables)?;
    c63_whir_structural_budget_for_config(&config)
}

pub(crate) fn c63_whir_structural_budget_for_config(
    config: &C63WhirConfig,
) -> Result<C61WhirStructuralBudget, String> {
    let num_variables = config.num_variables;
    let opening_bytes = |leaves: usize, queries: usize, width: usize, element_bytes: usize| {
        queries
            .checked_mul(width)
            .and_then(|count| count.checked_mul(element_bytes))
            .and_then(|rows| {
                c61_max_pruned_binary_siblings(leaves, queries)
                    .checked_mul(C61_WHIRA1_DIGEST_BYTES)
                    .and_then(|frontier| rows.checked_add(frontier))
            })
            .and_then(|bytes| bytes.checked_add(C61_WHIRA1_MULTIPROOF_COUNT_BYTES))
            .ok_or_else(|| "C6.3 WHIR structural opening count overflows".to_owned())
    };

    let mut round_opening_bytes = 0usize;
    let mut rounds_bytes = 0usize;
    for (index, round) in config.round_parameters.iter().enumerate() {
        let fold = config.round_folding_factor(index);
        let opening = opening_bytes(
            round.domain_size >> fold,
            round.num_queries,
            1 << fold,
            if index == 0 { C61_WHIRA1_FP_BYTES } else { C61_WHIRA1_FP2_BYTES },
        )?;
        round_opening_bytes += opening;
        rounds_bytes += 2 * C61_WHIRA1_DIGEST_BYTES
            + round.ood_samples * C61_WHIRA1_FP2_BYTES
            + usize::from(round.pow_bits > 0) * C61_WHIRA1_FP_BYTES
            + opening;
    }

    let groups = config.mask_groups();
    let mut base_mask_opening_bytes = 0usize;
    let mut blinded_mask_bytes = 0usize;
    for group in &groups {
        let one = opening_bytes(
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            C61_WHIRA1_FP2_BYTES,
        )?;
        base_mask_opening_bytes += 2 * one;
        blinded_mask_bytes += group.width
            * (group.shape.message_len + group.shape.randomness_len)
            * C61_WHIRA1_FP2_BYTES;
    }

    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;
    let source_opening = opening_bytes(
        final_domain,
        config.final_queries,
        1 << final_round.folding_factor,
        C61_WHIRA1_FP2_BYTES,
    )?;
    let fresh_main_opening =
        opening_bytes(final_domain, config.final_queries, 1, C61_WHIRA1_FP2_BYTES)?;
    let base_case_bytes = (1 + groups.len()) * C61_WHIRA1_DIGEST_BYTES
        + C61_WHIRA1_FP2_BYTES
        + (1 << final_round.num_variables) * C61_WHIRA1_FP2_BYTES
        + config.oracle_randomness[config.n_rounds()] * C61_WHIRA1_FP2_BYTES
        + blinded_mask_bytes
        + usize::from(config.final_pow_bits > 0) * C61_WHIRA1_FP_BYTES
        + source_opening
        + fresh_main_opening
        + base_mask_opening_bytes;

    let batches = config.n_rounds() + 1;
    let sumcheck_rounds: usize = (0..batches).map(|batch| config.round_folding_factor(batch)).sum();
    let sumcheck_bytes =
        (batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES;
    let sumcheck_pow: usize = (0..batches)
        .map(|batch| {
            let bits = if batch == 0 {
                config.starting_folding_pow_bits
            } else {
                config.round_parameters[batch - 1].folding_pow_bits
            };
            usize::from(bits > 0) * config.round_folding_factor(batch)
        })
        .sum();
    let strict_chain_bytes = C61_WHIRA1_HEADER_BYTES
        + C61_WHIRA1_DIGEST_BYTES
        + sumcheck_bytes
        + sumcheck_pow * C61_WHIRA1_FP_BYTES
        + batches * C61_WHIRA1_DIGEST_BYTES
        + rounds_bytes
        + base_case_bytes;
    Ok(C61WhirStructuralBudget {
        num_variables,
        rounds: config.n_rounds(),
        mask_queries: config.mask_queries,
        round_opening_bytes,
        base_mask_opening_bytes,
        blinded_mask_bytes,
        base_case_bytes,
        strict_chain_bytes,
    })
}

/// Canonical claimless C6.3 WHIR codec. The terminal value stays authenticated.
pub fn encode_c63_whir_ordinary_artifact(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &C63OrdinaryWhirProof,
) -> Result<Vec<u8>, String> {
    let config = c63_whir_config(num_variables)?;
    encode_c63_whir_ordinary_artifact_with_config(num_variables, &config, commitment, proof)
}

pub(crate) fn encode_c63_whir_ordinary_artifact_with_config<MT>(
    num_variables: usize,
    config: &C63WhirConfig,
    commitment: &C61Commitment,
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
) -> Result<Vec<u8>, String>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>,
{
    if config.num_variables != num_variables {
        return Err("C6.3 WHIR codec dimension differs".to_owned());
    }
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;
    let mut body = C61Writer::default();
    body.commitment(commitment).map_err(|error| error.to_string())?;

    if proof.sumchecks.len() != batches || proof.sumcheck_mask_commitments.len() != batches {
        return Err("C6.3 WHIR sumcheck batch count differs".to_owned());
    }
    for (batch, sumcheck) in proof.sumchecks.iter().enumerate() {
        let rounds = config.round_folding_factor(batch);
        let pow_count = usize::from(c63_sumcheck_pow_bits(&config, batch) > 0) * rounds;
        if sumcheck.ell_zk != config.zk.ell_zk
            || sumcheck.round_coefficients.len() != rounds
            || sumcheck
                .round_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != config.zk.ell_zk - 1)
            || sumcheck.pow_witnesses.len() != pow_count
        {
            return Err("C6.3 WHIR sumcheck shape differs".to_owned());
        }
        body.fp2(sumcheck.mu_tilde);
        for coefficients in &sumcheck.round_coefficients {
            for coefficient in coefficients {
                body.fp2(*coefficient);
            }
        }
        for witness in &sumcheck.pow_witnesses {
            body.fp(*witness);
        }
    }
    for commitment in &proof.sumcheck_mask_commitments {
        body.commitment(commitment).map_err(|error| error.to_string())?;
    }

    if proof.rounds.len() != config.n_rounds() {
        return Err("C6.3 WHIR round count differs".to_owned());
    }
    for (index, (round_proof, round)) in
        proof.rounds.iter().zip(&config.round_parameters).enumerate()
    {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        body.commitment(&round_proof.commitment).map_err(|error| error.to_string())?;
        body.commitment(&round_proof.mask_commitment).map_err(|error| error.to_string())?;
        if round_proof.ood_answers.len() != round.ood_samples
            || (round.pow_bits == 0 && round_proof.pow_witness != Goldilocks::ZERO)
        {
            return Err("C6.3 WHIR round scalar shape differs".to_owned());
        }
        for answer in &round_proof.ood_answers {
            body.fp2(*answer);
        }
        if round.pow_bits > 0 {
            body.fp(round_proof.pow_witness);
        }
        match (&round_proof.openings, index) {
            (QueryOpenings::Base(opening), 0) => {
                encode_c63_fp_opening(&mut body, opening, round.num_queries, 1 << fold, leaves)
            }
            (QueryOpenings::Extension(opening), index) if index > 0 => {
                encode_c63_fp2_opening(&mut body, opening, round.num_queries, 1 << fold, leaves)
            }
            _ => return Err("C6.3 WHIR round opening field differs".to_owned()),
        }
        .map_err(|error| error.to_string())?;
    }

    let base = &proof.base_case;
    body.commitment(&base.fresh_main_commitment).map_err(|error| error.to_string())?;
    if base.fresh_mask_commitments.len() != groups.len() {
        return Err("C6.3 WHIR fresh-mask root count differs".to_owned());
    }
    for commitment in &base.fresh_mask_commitments {
        body.commitment(commitment).map_err(|error| error.to_string())?;
    }
    body.fp2(base.masked_claim);
    if base.blinded_message.len() != 1 << final_round.num_variables
        || base.blinded_randomness.len() != config.oracle_randomness[config.n_rounds()]
    {
        return Err("C6.3 WHIR base source reveal shape differs".to_owned());
    }
    for value in &base.blinded_message {
        body.fp2(*value);
    }
    for value in &base.blinded_randomness {
        body.fp2(*value);
    }
    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    if base.blinded_masks.len() != flat_masks {
        return Err("C6.3 WHIR blinded-mask count differs".to_owned());
    }
    let mut mask_index = 0;
    for group in &groups {
        for _ in 0..group.width {
            let mask = &base.blinded_masks[mask_index];
            mask_index += 1;
            if mask.message.len() != group.shape.message_len
                || mask.randomness.len() != group.shape.randomness_len
            {
                return Err("C6.3 WHIR blinded-mask shape differs".to_owned());
            }
            for value in &mask.message {
                body.fp2(*value);
            }
            for value in &mask.randomness {
                body.fp2(*value);
            }
        }
    }
    if config.final_pow_bits == 0 && base.pow_witness != Goldilocks::ZERO {
        return Err("C6.3 WHIR unexpected base PoW witness".to_owned());
    }
    if config.final_pow_bits > 0 {
        body.fp(base.pow_witness);
    }
    match &base.source_openings {
        QueryOpenings::Extension(opening) => encode_c63_fp2_opening(
            &mut body,
            opening,
            config.final_queries,
            1 << final_round.folding_factor,
            final_domain,
        ),
        QueryOpenings::Base(_) => return Err("C6.3 WHIR final source field differs".to_owned()),
    }
    .map_err(|error| error.to_string())?;
    encode_c63_fp2_opening(
        &mut body,
        &base.fresh_main_openings,
        config.final_queries,
        1,
        final_domain,
    )
    .map_err(|error| error.to_string())?;
    if base.mask_openings.len() != groups.len() {
        return Err("C6.3 WHIR mask-opening group count differs".to_owned());
    }
    for (opening, group) in base.mask_openings.iter().zip(&groups) {
        encode_c63_fp2_opening(
            &mut body,
            &opening.carried,
            config.mask_queries,
            group.width,
            group.shape.domain_size,
        )
        .and_then(|_| {
            encode_c63_fp2_opening(
                &mut body,
                &opening.fresh,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )
        })
        .map_err(|error| error.to_string())?;
    }

    let mut artifact = C61Writer::default();
    artifact.bytes.extend_from_slice(&C63_WHIR_MAGIC);
    artifact.u16(C63_WHIR_VERSION);
    artifact.u8(num_variables as u8);
    artifact.u8(0);
    artifact.u32(body.bytes.len()).map_err(|error| error.to_string())?;
    artifact.bytes.extend_from_slice(&body.bytes);
    if artifact.bytes.len() > c63_whir_structural_budget_for_config(config)?.strict_chain_bytes {
        return Err("C6.3 WHIR artifact exceeds its structural maximum".to_owned());
    }
    Ok(artifact.bytes)
}

pub fn decode_c63_whir_ordinary_artifact(
    bytes: &[u8],
    num_variables: usize,
) -> Result<(C61Commitment, C63OrdinaryWhirProof), String> {
    let config = c63_whir_config(num_variables)?;
    decode_c63_whir_ordinary_artifact_with_config(bytes, num_variables, &config)
}

pub(crate) fn decode_c63_whir_ordinary_artifact_with_config(
    bytes: &[u8],
    num_variables: usize,
    config: &C63WhirConfig,
) -> Result<(C61Commitment, C63OrdinaryWhirProof), String> {
    if config.num_variables != num_variables {
        return Err("C6.3 WHIR codec dimension differs".to_owned());
    }
    if bytes.len() > c63_whir_structural_budget_for_config(config)?.strict_chain_bytes {
        return Err("C6.3 WHIR artifact exceeds its structural maximum".to_owned());
    }
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;
    let mut reader = C61Reader::new(bytes);
    if reader.take(8).map_err(|error| error.to_string())? != C63_WHIR_MAGIC
        || reader.u16().map_err(|error| error.to_string())? != C63_WHIR_VERSION
        || reader.u8().map_err(|error| error.to_string())? as usize != num_variables
        || reader.u8().map_err(|error| error.to_string())? != 0
    {
        return Err("C6.3 WHIR artifact header differs".to_owned());
    }
    let body_len = reader.u32().map_err(|error| error.to_string())?;
    if body_len != bytes.len().saturating_sub(C61_WHIRA1_HEADER_BYTES) {
        return Err("C6.3 WHIR artifact body length differs".to_owned());
    }
    let commitment = reader.commitment().map_err(|error| error.to_string())?;
    let batches = config.n_rounds() + 1;
    let mut sumchecks = Vec::with_capacity(batches);
    for batch in 0..batches {
        let rounds = config.round_folding_factor(batch);
        let mu_tilde = reader.fp2().map_err(|error| error.to_string())?;
        let mut round_coefficients = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let mut coefficients = Vec::with_capacity(config.zk.ell_zk - 1);
            for _ in 0..config.zk.ell_zk - 1 {
                coefficients.push(reader.fp2().map_err(|error| error.to_string())?);
            }
            round_coefficients.push(coefficients);
        }
        let pow_count = usize::from(c63_sumcheck_pow_bits(&config, batch) > 0) * rounds;
        let mut pow_witnesses = Vec::with_capacity(pow_count);
        for _ in 0..pow_count {
            pow_witnesses.push(reader.fp().map_err(|error| error.to_string())?);
        }
        sumchecks.push(ZkSumcheckData {
            mu_tilde,
            ell_zk: config.zk.ell_zk,
            round_coefficients,
            pow_witnesses,
        });
    }
    let mut sumcheck_mask_commitments = Vec::with_capacity(batches);
    for _ in 0..batches {
        sumcheck_mask_commitments.push(reader.commitment().map_err(|error| error.to_string())?);
    }
    let mut rounds = Vec::with_capacity(config.n_rounds());
    for (index, round) in config.round_parameters.iter().enumerate() {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let round_commitment = reader.commitment().map_err(|error| error.to_string())?;
        let mask_commitment = reader.commitment().map_err(|error| error.to_string())?;
        let mut ood_answers = Vec::with_capacity(round.ood_samples);
        for _ in 0..round.ood_samples {
            ood_answers.push(reader.fp2().map_err(|error| error.to_string())?);
        }
        let pow_witness = if round.pow_bits > 0 {
            reader.fp().map_err(|error| error.to_string())?
        } else {
            Goldilocks::ZERO
        };
        let openings = if index == 0 {
            QueryOpenings::Base(decode_c63_fp_opening(
                &mut reader,
                round.num_queries,
                1 << fold,
                leaves,
            )?)
        } else {
            QueryOpenings::Extension(decode_c63_fp2_opening(
                &mut reader,
                round.num_queries,
                1 << fold,
                leaves,
            )?)
        };
        rounds.push(ZkRoundProof {
            commitment: round_commitment,
            mask_commitment,
            ood_answers,
            pow_witness,
            openings,
        });
    }

    let fresh_main_commitment = reader.commitment().map_err(|error| error.to_string())?;
    let mut fresh_mask_commitments = Vec::with_capacity(groups.len());
    for _ in 0..groups.len() {
        fresh_mask_commitments.push(reader.commitment().map_err(|error| error.to_string())?);
    }
    let masked_claim = reader.fp2().map_err(|error| error.to_string())?;
    let mut blinded_message = Vec::with_capacity(1 << final_round.num_variables);
    for _ in 0..1 << final_round.num_variables {
        blinded_message.push(reader.fp2().map_err(|error| error.to_string())?);
    }
    let randomness = config.oracle_randomness[config.n_rounds()];
    let mut blinded_randomness = Vec::with_capacity(randomness);
    for _ in 0..randomness {
        blinded_randomness.push(reader.fp2().map_err(|error| error.to_string())?);
    }
    let mut blinded_masks = Vec::new();
    for group in &groups {
        for _ in 0..group.width {
            let mut message = Vec::with_capacity(group.shape.message_len);
            for _ in 0..group.shape.message_len {
                message.push(reader.fp2().map_err(|error| error.to_string())?);
            }
            let mut randomness = Vec::with_capacity(group.shape.randomness_len);
            for _ in 0..group.shape.randomness_len {
                randomness.push(reader.fp2().map_err(|error| error.to_string())?);
            }
            blinded_masks.push(BlindedMask { message, randomness });
        }
    }
    let pow_witness = if config.final_pow_bits > 0 {
        reader.fp().map_err(|error| error.to_string())?
    } else {
        Goldilocks::ZERO
    };
    let source_openings = QueryOpenings::Extension(decode_c63_fp2_opening(
        &mut reader,
        config.final_queries,
        1 << final_round.folding_factor,
        final_domain,
    )?);
    let fresh_main_openings =
        decode_c63_fp2_opening(&mut reader, config.final_queries, 1, final_domain)?;
    let mut mask_openings = Vec::with_capacity(groups.len());
    for group in &groups {
        mask_openings.push(MaskOpeningPair {
            carried: decode_c63_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
            fresh: decode_c63_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
        });
    }
    reader.finish().map_err(|error| error.to_string())?;
    Ok((
        commitment,
        ZkWhirProof {
            sumchecks,
            sumcheck_mask_commitments,
            rounds,
            base_case: BaseCaseZkProof {
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
            },
        },
    ))
}

pub(crate) fn verify_c63_whir_ordinary_artifact_with_config_at_point(
    bytes: &[u8],
    num_variables: usize,
    config: &C63WhirConfig,
    point: &[Fp2],
    context_digest: [u8; 32],
) -> Result<C63ClaimlessWhirVerifierClosure, String> {
    if point.len() != num_variables || config.num_variables != num_variables {
        return Err("C6.3 WHIR opening point geometry differs".to_owned());
    }
    let (commitment, proof) =
        decode_c63_whir_ordinary_artifact_with_config(bytes, num_variables, config)?;
    let point = Point::new(point.iter().rev().copied().map(c61_p3_fp2_from_volta).collect());
    let mut challenger = c63_challenger(context_digest)?;
    challenger.observe(commitment.clone());
    challenger.observe_algebra_slice(point.as_slice());
    let mmcs = c61_reference_mmcs();
    let verifier = HidingWhirVerifier::new(config, &mmcs);
    let closure = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(
            &proof,
            &commitment,
            std::slice::from_ref(&point),
            &mut challenger,
        )
    }))
    .map_err(|_| "C6.3 ordinary WHIR verifier panicked".to_owned())?
    .map_err(|error| format!("C6.3 ordinary WHIR verification failed: {error}"))?;
    c63_convert_verifier_closure(closure)
}

fn c63_sumcheck_pow_bits(config: &C63WhirConfig, batch: usize) -> usize {
    if batch == 0 {
        config.starting_folding_pow_bits
    } else {
        config.round_parameters[batch - 1].folding_pow_bits
    }
}

pub(crate) fn c63_projected_whir_structural_bytes_for_config(
    config: &C63WhirConfig,
) -> Result<usize, String> {
    let queries = config.round_parameters[0].num_queries;
    let fold = config.round_folding_factor(0);
    let leaves = config.round_parameters[0].domain_size >> fold;
    let a_opening = queries * C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH * C61_WHIRA1_FP_BYTES
        + C61_WHIRA1_MULTIPROOF_COUNT_BYTES
        + c61_max_pruned_binary_siblings(leaves, queries) * C61_WHIRA1_DIGEST_BYTES;
    Ok(C61_WHIRA1_HEADER_BYTES
        + C61_WHIRA1_MULTIPROOF_COUNT_BYTES
        + c63_whir_structural_budget_for_config(config)?.strict_chain_bytes
        + 1
        + 2 * a_opening)
}

fn c63_projected_whir_structural_bytes() -> Result<usize, String> {
    c63_projected_whir_structural_bytes_for_config(&c63_whir_config(19)?)
}

type C63InnerProof = <C61Mmcs as Mmcs<Goldilocks>>::Proof;
type C63AProverData = <C61Mmcs as Mmcs<Goldilocks>>::ProverData<DenseMatrix<Goldilocks>>;

/// Prover data for the ordinary C6.1 MMCS plus, only on the first randomized
/// `y` oracle, the separately rooted D19-by-32 tensor `A`.
pub(crate) struct C63ProjectedProverData<M> {
    inner: <C61Mmcs as Mmcs<Goldilocks>>::ProverData<M>,
    predecessor_a: Option<Arc<C63AProverData>>,
    successor_a: Option<Arc<C63AProverData>>,
}

/// The extra tuple member is present only for the opt-in `A -> y` opening.
/// Keeping the ordinary proof first lets no-link commits and openings delegate
/// without changing their values or transcript observations.
type C63LinkedAProof<P> = (Option<(Vec<Vec<Goldilocks>>, P)>, (Vec<Vec<Goldilocks>>, P));
type C63ProjectedProof = (C63InnerProof, Option<C63LinkedAProof<C63InnerProof>>);
type C63ProjectedMultiProof = (C61MultiProof, Option<C63LinkedAProof<C61MultiProof>>);

/// Verifier-known context for one base-field limb of `y=A*rho`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct C63EncodedSketchAtoYContext {
    predecessor_d: C61Commitment,
    predecessor_a: C61Commitment,
    successor_d: C61Commitment,
    successor_a: C61Commitment,
    old_len: u16,
    dimensions: Dimensions,
    coefficients: [Goldilocks; C63_BOLT_COLUMNS],
    tape: Option<usize>,
    limb: usize,
}

impl C63EncodedSketchAtoYContext {
    /// Bind both deterministic roots, then draw one verifier-owned
    /// `rho in Fp2^16` and build the two limb contexts from that same draw.
    pub(crate) fn sample_pair_after_roots<Challenger>(
        predecessor_d: C61Commitment,
        predecessor_a: C61Commitment,
        successor_d: C61Commitment,
        successor_a: C61Commitment,
        old_len: u16,
        rows: usize,
        challenger: &mut Challenger,
    ) -> Result<([Fp2; C63_BOLT_COLUMNS], [Self; 2]), String>
    where
        Challenger: FieldChallenger<Goldilocks> + CanObserve<C61Commitment>,
    {
        if rows == 0 || !rows.is_power_of_two() {
            return Err("C6.3 A-to-y context geometry differs".to_owned());
        }
        challenger.observe(predecessor_d.clone());
        challenger.observe(predecessor_a.clone());
        challenger.observe(successor_d.clone());
        challenger.observe(successor_a.clone());
        let rho = std::array::from_fn(|_| {
            let value: C61P3Fp2 = challenger.sample_algebra_element();
            c61_volta_fp2_from_p3(value)
        });
        let contexts = std::array::from_fn(|limb| Self {
            predecessor_d: predecessor_d.clone(),
            predecessor_a: predecessor_a.clone(),
            successor_d: successor_d.clone(),
            successor_a: successor_a.clone(),
            old_len,
            dimensions: Dimensions { width: C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH, height: rows },
            coefficients: rho.map(|value| {
                Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() })
            }),
            tape: None,
            limb,
        });
        Ok((rho, contexts))
    }

    pub(crate) fn sample_tape_limb_after_roots<Challenger>(
        predecessor_d: C61Commitment,
        predecessor_a: C61Commitment,
        successor_d: C61Commitment,
        successor_a: C61Commitment,
        old_len: u16,
        rows: usize,
        challenger: &mut Challenger,
    ) -> Result<([Fp2; C63_BOLT_COLUMNS], [[Self; 2]; 2]), String>
    where
        Challenger: FieldChallenger<Goldilocks> + CanObserve<C61Commitment>,
    {
        if rows == 0 || !rows.is_power_of_two() {
            return Err("C6.3 A-to-y context geometry differs".to_owned());
        }
        challenger.observe(predecessor_d.clone());
        challenger.observe(predecessor_a.clone());
        challenger.observe(successor_d.clone());
        challenger.observe(successor_a.clone());
        let rho = std::array::from_fn(|_| {
            let value: C61P3Fp2 = challenger.sample_algebra_element();
            c61_volta_fp2_from_p3(value)
        });
        let contexts = std::array::from_fn(|tape| {
            std::array::from_fn(|limb| Self {
                predecessor_d: predecessor_d.clone(),
                predecessor_a: predecessor_a.clone(),
                successor_d: successor_d.clone(),
                successor_a: successor_a.clone(),
                old_len,
                dimensions: Dimensions {
                    width: C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
                    height: rows,
                },
                coefficients: std::array::from_fn(|column| {
                    if column & 1 != tape {
                        Goldilocks::ZERO
                    } else if limb == 0 {
                        Goldilocks::new(rho[column].c0.value())
                    } else {
                        Goldilocks::new(rho[column].c1.value())
                    }
                }),
                tape: Some(tape),
                limb,
            })
        });
        Ok((rho, contexts))
    }
}

/// CPU MMCS seam which opens the fresh randomized `y` row and the accepted
/// `A` row at the same verifier-derived first-round WHIR positions.
///
/// Later WHIR commitments and the default/no-link path delegate to C6.1.
#[derive(Clone)]
pub(crate) struct C63ProjectedMmcs {
    inner: C61Mmcs,
    context: Arc<C63EncodedSketchAtoYContext>,
}

impl C63ProjectedMmcs {
    pub(crate) fn new(context: C63EncodedSketchAtoYContext) -> Self {
        Self { inner: c61_reference_mmcs(), context: Arc::new(context) }
    }

    pub(crate) fn link(&self) -> C63EncodedSketchAtoYLink {
        C63EncodedSketchAtoYLink { context: Arc::clone(&self.context) }
    }

    /// Marks exactly one already-committed WHIR oracle as the projected
    /// `A -> y` initial oracle. The accepted root is checked before attaching
    /// its prover data.
    pub(crate) fn attach_encoded_sketch_a<M>(
        &self,
        prover_data: &mut C63ProjectedProverData<M>,
        predecessor: Option<(&C61Commitment, C63AProverData)>,
        successor_commitment: &C61Commitment,
        successor_data: C63AProverData,
    ) -> Result<(), String> {
        if successor_commitment != &self.context.successor_a
            || predecessor.as_ref().map(|(root, _)| *root)
                != (self.context.old_len != 0).then_some(&self.context.predecessor_a)
        {
            return Err("C6.3 attached A roots differ from the transition".to_owned());
        }
        if prover_data.predecessor_a.is_some() || prover_data.successor_a.is_some() {
            return Err("C6.3 A prover data already attached".to_owned());
        }
        prover_data.predecessor_a = predecessor.map(|(_, data)| Arc::new(data));
        prover_data.successor_a = Some(Arc::new(successor_data));
        Ok(())
    }
}

impl Mmcs<Goldilocks> for C63ProjectedMmcs {
    type ProverData<M> = C63ProjectedProverData<M>;
    type Commitment = C61Commitment;
    type Proof = C63ProjectedProof;
    type MultiProof = C63ProjectedMultiProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, inner) = self.inner.commit(inputs);
        (commitment, C63ProjectedProverData { inner, predecessor_a: None, successor_a: None })
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
        let ordinary = self.inner.open_batch(index, &prover_data.inner);
        let linked = prover_data.successor_a.as_ref().map(|successor| {
            let predecessor = prover_data.predecessor_a.as_ref().map(|data| {
                let opening = self.inner.open_batch(index, data);
                let (rows, proof) = opening.unpack();
                (rows, proof)
            });
            let opening = self.inner.open_batch(index, successor);
            let (rows, proof) = opening.unpack();
            (predecessor, (rows, proof))
        });
        BatchOpening::new(ordinary.opened_values, (ordinary.opening_proof, linked))
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner.get_matrices(&prover_data.inner)
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        let (ordinary_proof, linked) = batch_opening.opening_proof;
        self.inner.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::new(batch_opening.opened_values, ordinary_proof),
        )?;
        if let Some((predecessor, (a_rows, a_proof))) = linked {
            if let Some((rows, proof)) = predecessor {
                self.inner.verify_batch(
                    &self.context.predecessor_a,
                    std::slice::from_ref(&self.context.dimensions),
                    index,
                    BatchOpeningRef::new(rows, proof),
                )?;
            } else if self.context.old_len != 0 {
                return Err(MerkleTreeError::WrongBatchSize);
            }
            self.inner.verify_batch(
                &self.context.successor_a,
                std::slice::from_ref(&self.context.dimensions),
                index,
                BatchOpeningRef::new(a_rows, a_proof),
            )?;
        }
        Ok(())
    }

    fn open_multi_batch<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let (ordinary_rows, ordinary_proof) =
            self.inner.open_multi_batch(indices, &prover_data.inner);
        let linked = prover_data.successor_a.as_ref().map(|successor| {
            let predecessor = prover_data.predecessor_a.as_ref().map(|data| {
                let (rows, proof) = self.inner.open_multi_batch(indices, data);
                let rows = rows
                    .into_iter()
                    .map(|mut per_matrix| {
                        assert_eq!(per_matrix.len(), 1, "C6.3 predecessor A root holds one matrix");
                        per_matrix.swap_remove(0)
                    })
                    .collect();
                (rows, proof)
            });
            let (rows, proof) = self.inner.open_multi_batch(indices, successor);
            let rows = rows
                .into_iter()
                .map(|mut per_matrix| {
                    assert_eq!(per_matrix.len(), 1, "C6.3 A root holds one matrix");
                    per_matrix.swap_remove(0)
                })
                .collect();
            (predecessor, (rows, proof))
        });
        (ordinary_rows, (ordinary_proof, linked))
    }

    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(commit, dimensions, indices, opened_values, &proof.0)?;
        if let Some((predecessor, (a_rows, a_proof))) = &proof.1 {
            if let Some((rows, old_proof)) = predecessor {
                let opened = rows.iter().map(|row| vec![row.as_slice()]).collect::<Vec<_>>();
                self.inner.verify_multi_batch(
                    &self.context.predecessor_a,
                    std::slice::from_ref(&self.context.dimensions),
                    indices,
                    &opened,
                    old_proof,
                )?;
            } else if self.context.old_len != 0 {
                return Err(MerkleTreeError::WrongBatchSize);
            }
            let opened_a = a_rows.iter().map(|row| vec![row.as_slice()]).collect::<Vec<_>>();
            self.inner.verify_multi_batch(
                &self.context.successor_a,
                std::slice::from_ref(&self.context.dimensions),
                indices,
                &opened_a,
                a_proof,
            )?;
        }
        Ok(())
    }
}

/// GPU-resident counterpart of `C63ProjectedMmcs`. Ordinary WHIR openings
/// stay on the C6.2 path; only the first linked opening also reads accepted A.
#[derive(Clone)]
pub(crate) struct C63ProjectedGpuMmcs {
    inner: C62GpuMmcs,
    context: Arc<C63EncodedSketchAtoYContext>,
}

pub(crate) struct C63ProjectedGpuProverData<M> {
    inner: C62GpuProverData<M>,
    predecessor_a: Option<Arc<C63GpuStateOwner>>,
    successor_a: Option<Arc<C63GpuStateOwner>>,
}

impl C63ProjectedGpuMmcs {
    pub(crate) fn new(inner: C62GpuMmcs, context: C63EncodedSketchAtoYContext) -> Self {
        Self { inner, context: Arc::new(context) }
    }

    pub(crate) fn link(&self) -> C63EncodedSketchAtoYLink {
        C63EncodedSketchAtoYLink { context: Arc::clone(&self.context) }
    }

    pub(crate) fn attach_encoded_sketch_a<M>(
        &self,
        prover_data: &mut C63ProjectedGpuProverData<M>,
        predecessor: Option<Arc<C63GpuStateOwner>>,
        successor: Arc<C63GpuStateOwner>,
    ) -> Result<(), String> {
        let successor_root = C61Commitment::new(vec![successor.encoded_sketch_root()]);
        let predecessor_root =
            predecessor.as_ref().map(|state| C61Commitment::new(vec![state.encoded_sketch_root()]));
        if successor_root != self.context.successor_a
            || predecessor_root.as_ref()
                != (self.context.old_len != 0).then_some(&self.context.predecessor_a)
        {
            return Err("C6.3 resident A roots differ from the transition".to_owned());
        }
        if prover_data.predecessor_a.is_some() || prover_data.successor_a.is_some() {
            return Err("C6.3 resident A owner already attached".to_owned());
        }
        prover_data.predecessor_a = predecessor;
        prover_data.successor_a = Some(successor);
        Ok(())
    }
}

impl Mmcs<Goldilocks> for C63ProjectedGpuMmcs {
    type ProverData<M> = C63ProjectedGpuProverData<M>;
    type Commitment = C61Commitment;
    type Proof = C63ProjectedProof;
    type MultiProof = C63ProjectedMultiProof;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, inner) = self.inner.commit(inputs);
        (commitment, C63ProjectedGpuProverData { inner, predecessor_a: None, successor_a: None })
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
        let ordinary = self.inner.open_batch(index, &prover_data.inner);
        let linked = prover_data.successor_a.as_ref().map(|state| {
            let predecessor = prover_data.predecessor_a.as_ref().map(|old| {
                let (mut rows, proof) =
                    old.open_encoded_sketch_rows(&[index]).unwrap_or_else(|error| {
                        panic!("C6.3 resident predecessor A opening failed: {error}")
                    });
                assert_eq!(rows.len(), 1, "C6.3 resident predecessor A batch opening count");
                (vec![rows.swap_remove(0)], proof.sibling_hashes)
            });
            let (mut rows, proof) = state
                .open_encoded_sketch_rows(&[index])
                .unwrap_or_else(|error| panic!("C6.3 resident A opening failed: {error}"));
            assert_eq!(rows.len(), 1, "C6.3 resident A batch opening count");
            (predecessor, (vec![rows.swap_remove(0)], proof.sibling_hashes))
        });
        BatchOpening::new(ordinary.opened_values, (ordinary.opening_proof, linked))
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        self.inner.get_matrices(&prover_data.inner)
    }

    fn verify_batch(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, Goldilocks, Self>,
    ) -> Result<(), Self::Error> {
        let (ordinary_proof, linked) = opening.opening_proof;
        self.inner.verify_batch(
            commitment,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, ordinary_proof),
        )?;
        if let Some((predecessor, (a_rows, a_proof))) = linked {
            if let Some((rows, proof)) = predecessor {
                self.inner.verify_batch(
                    &self.context.predecessor_a,
                    std::slice::from_ref(&self.context.dimensions),
                    index,
                    BatchOpeningRef::new(rows, proof),
                )?;
            } else if self.context.old_len != 0 {
                return Err(MerkleTreeError::WrongBatchSize);
            }
            self.inner.verify_batch(
                &self.context.successor_a,
                std::slice::from_ref(&self.context.dimensions),
                index,
                BatchOpeningRef::new(a_rows, a_proof),
            )?;
        }
        Ok(())
    }

    fn open_multi_batch<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<Goldilocks>>>, Self::MultiProof) {
        let (ordinary_rows, ordinary_proof) =
            self.inner.open_multi_batch(indices, &prover_data.inner);
        let linked = prover_data.successor_a.as_ref().map(|state| {
            let predecessor = prover_data.predecessor_a.as_ref().map(|old| {
                old.open_encoded_sketch_rows(indices).unwrap_or_else(|error| {
                    panic!("C6.3 resident predecessor A opening failed: {error}")
                })
            });
            let successor = state
                .open_encoded_sketch_rows(indices)
                .unwrap_or_else(|error| panic!("C6.3 resident A opening failed: {error}"));
            (predecessor, successor)
        });
        (ordinary_rows, (ordinary_proof, linked))
    }

    fn verify_multi_batch<R: AsRef<[Goldilocks]> + PartialEq>(
        &self,
        commitment: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner.verify_multi_batch(commitment, dimensions, indices, opened_values, &proof.0)?;
        if let Some((predecessor, (a_rows, a_proof))) = &proof.1 {
            if let Some((rows, old_proof)) = predecessor {
                let opened = rows.iter().map(|row| vec![row.as_slice()]).collect::<Vec<_>>();
                self.inner.verify_multi_batch(
                    &self.context.predecessor_a,
                    std::slice::from_ref(&self.context.dimensions),
                    indices,
                    &opened,
                    old_proof,
                )?;
            } else if self.context.old_len != 0 {
                return Err(MerkleTreeError::WrongBatchSize);
            }
            let opened_a = a_rows.iter().map(|row| vec![row.as_slice()]).collect::<Vec<_>>();
            self.inner.verify_multi_batch(
                &self.context.successor_a,
                std::slice::from_ref(&self.context.dimensions),
                indices,
                &opened_a,
                a_proof,
            )?;
        }
        Ok(())
    }
}

impl ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C63ProjectedGpuMmcs> for C62GpuWhirCommitter {
    type Error = C62GpuWhirError;
    type SumcheckState = C62GpuSumcheckState;

    fn initialize_sumcheck(
        &self,
        message: ZkWhirInitialMessage<'_, Goldilocks>,
        claims: &[(Point<C61P3Fp2>, C61P3Fp2)],
        coefficients: &[C61P3Fp2],
        batched_target: C61P3Fp2,
    ) -> Result<Self::SumcheckState, Self::Error> {
        <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::initialize_sumcheck(
            self,
            message,
            claims,
            coefficients,
            batched_target,
        )
    }

    fn commit_initial(
        &self,
        message: ZkWhirInitialMessage<'_, Goldilocks>,
        randomness: &[Goldilocks],
        folding: usize,
        height: usize,
    ) -> Result<(C61Commitment, C63ProjectedGpuProverData<DenseMatrix<Goldilocks>>), Self::Error>
    {
        let (commitment, inner) =
            <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::commit_initial(
                self, message, randomness, folding, height,
            )?;
        Ok((
            commitment,
            C63ProjectedGpuProverData { inner, predecessor_a: None, successor_a: None },
        ))
    }

    fn commit_extension(
        &self,
        message: &[C61P3Fp2],
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> Result<
        (
            C61Commitment,
            C63ProjectedGpuProverData<FlatMatrixView<Goldilocks, C61P3Fp2, DenseMatrix<C61P3Fp2>>>,
        ),
        Self::Error,
    > {
        let (commitment, inner) =
            <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::commit_extension(
                self, message, randomness, folding, height,
            )?;
        Ok((
            commitment,
            C63ProjectedGpuProverData { inner, predecessor_a: None, successor_a: None },
        ))
    }

    fn commit_extension_from_sumcheck(
        &self,
        state: &Self::SumcheckState,
        randomness: &[C61P3Fp2],
        folding: usize,
        height: usize,
    ) -> Result<
        Option<(
            C61Commitment,
            C63ProjectedGpuProverData<FlatMatrixView<Goldilocks, C61P3Fp2, DenseMatrix<C61P3Fp2>>>,
        )>,
        Self::Error,
    > {
        <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::commit_extension_from_sumcheck(
            self, state, randomness, folding, height,
        )
        .map(|result| {
            result.map(|(commitment, inner)| {
                (commitment, C63ProjectedGpuProverData { inner, predecessor_a: None, successor_a: None })
            })
        })
    }

    fn evaluate_padded_ood_from_sumcheck(
        &self,
        state: &Self::SumcheckState,
        point: C61P3Fp2,
        suffix: &[C61P3Fp2],
    ) -> Result<Option<C61P3Fp2>, Self::Error> {
        <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::evaluate_padded_ood_from_sumcheck(
            self, state, point, suffix,
        )
    }

    fn accumulate_round_claim_from_sumcheck(
        &self,
        state: &mut Self::SumcheckState,
        folded_domain_size: usize,
        stir_indices: &[usize],
        ood_points: &[C61P3Fp2],
        ood_coeffs: &[C61P3Fp2],
        query_coeffs: &[C61P3Fp2],
    ) -> Result<bool, Self::Error> {
        <Self as ZkWhirOracleCommitter<Goldilocks, C61P3Fp2, C62GpuMmcs>>::accumulate_round_claim_from_sumcheck(
            self,
            state,
            folded_domain_size,
            stir_indices,
            ood_points,
            ood_coeffs,
            query_coeffs,
        )
    }
}

pub(crate) type C63ProjectedWhirProof = ZkWhirProof<Goldilocks, C61P3Fp2, C63ProjectedMmcs>;

fn strip_c63_opening<T: Clone>(
    opening: &SharedProofOpening<T, C63ProjectedMultiProof>,
) -> (
    SharedProofOpening<T, C61MultiProof>,
    Option<(
        Option<SharedProofOpening<Goldilocks, C61MultiProof>>,
        SharedProofOpening<Goldilocks, C61MultiProof>,
    )>,
) {
    let linked = opening.proof.1.clone().map(|(predecessor, (rows, proof))| {
        (
            predecessor.map(|(rows, proof)| SharedProofOpening { rows, proof }),
            SharedProofOpening { rows, proof },
        )
    });
    (SharedProofOpening { rows: opening.rows.clone(), proof: opening.proof.0.clone() }, linked)
}

fn lift_c63_opening<T>(
    opening: SharedProofOpening<T, C61MultiProof>,
    linked: Option<(
        Option<SharedProofOpening<Goldilocks, C61MultiProof>>,
        SharedProofOpening<Goldilocks, C61MultiProof>,
    )>,
) -> SharedProofOpening<T, C63ProjectedMultiProof> {
    SharedProofOpening {
        rows: opening.rows,
        proof: (
            opening.proof,
            linked.map(|(predecessor, successor)| {
                (
                    predecessor.map(|opening| (opening.rows, opening.proof)),
                    (successor.rows, successor.proof),
                )
            }),
        ),
    }
}

fn strip_c63_projected_proof<MT>(
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
) -> Result<
    (
        C63OrdinaryWhirProof,
        (
            Option<SharedProofOpening<Goldilocks, C61MultiProof>>,
            SharedProofOpening<Goldilocks, C61MultiProof>,
        ),
    ),
    String,
>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C63ProjectedMultiProof>,
{
    let mut linked_a = None;
    let mut rounds = Vec::with_capacity(proof.rounds.len());
    for (index, round) in proof.rounds.iter().enumerate() {
        let openings = match (&round.openings, index) {
            (QueryOpenings::Base(opening), 0) => {
                let (ordinary, linked) = strip_c63_opening(opening);
                linked_a = linked;
                QueryOpenings::Base(ordinary)
            }
            (QueryOpenings::Extension(opening), index) if index > 0 => {
                let (ordinary, linked) = strip_c63_opening(opening);
                if linked.is_some() {
                    return Err("C6.3 projected A opening appears after the first round".to_owned());
                }
                QueryOpenings::Extension(ordinary)
            }
            _ => return Err("C6.3 projected WHIR opening field differs".to_owned()),
        };
        rounds.push(ZkRoundProof {
            commitment: round.commitment.clone(),
            mask_commitment: round.mask_commitment.clone(),
            ood_answers: round.ood_answers.clone(),
            pow_witness: round.pow_witness,
            openings,
        });
    }
    let linked_a = linked_a.ok_or_else(|| "C6.3 projected A opening is missing".to_owned())?;
    let base = &proof.base_case;
    let source_openings = match &base.source_openings {
        QueryOpenings::Extension(opening) => {
            let (ordinary, linked) = strip_c63_opening(opening);
            if linked.is_some() {
                return Err("C6.3 projected A opening appears in the base source".to_owned());
            }
            QueryOpenings::Extension(ordinary)
        }
        QueryOpenings::Base(_) => return Err("C6.3 projected base source field differs".to_owned()),
    };
    let (fresh_main_openings, fresh_link) = strip_c63_opening(&base.fresh_main_openings);
    if fresh_link.is_some() {
        return Err("C6.3 projected A opening appears in the fresh main oracle".to_owned());
    }
    let mut mask_openings = Vec::with_capacity(base.mask_openings.len());
    for opening in &base.mask_openings {
        let (carried, carried_link) = strip_c63_opening(&opening.carried);
        let (fresh, fresh_link) = strip_c63_opening(&opening.fresh);
        if carried_link.is_some() || fresh_link.is_some() {
            return Err("C6.3 projected A opening appears in a mask oracle".to_owned());
        }
        mask_openings.push(MaskOpeningPair { carried, fresh });
    }
    Ok((
        ZkWhirProof {
            sumchecks: proof.sumchecks.clone(),
            sumcheck_mask_commitments: proof.sumcheck_mask_commitments.clone(),
            rounds,
            base_case: BaseCaseZkProof {
                fresh_main_commitment: base.fresh_main_commitment.clone(),
                fresh_mask_commitments: base.fresh_mask_commitments.clone(),
                masked_claim: base.masked_claim,
                blinded_message: base.blinded_message.clone(),
                blinded_randomness: base.blinded_randomness.clone(),
                blinded_masks: base.blinded_masks.clone(),
                pow_witness: base.pow_witness,
                source_openings,
                fresh_main_openings,
                mask_openings,
            },
        },
        linked_a,
    ))
}

fn lift_c63_projected_proof(
    proof: C63OrdinaryWhirProof,
    linked_a: (
        Option<SharedProofOpening<Goldilocks, C61MultiProof>>,
        SharedProofOpening<Goldilocks, C61MultiProof>,
    ),
) -> Result<C63ProjectedWhirProof, String> {
    let mut rounds = Vec::with_capacity(proof.rounds.len());
    for (index, round) in proof.rounds.into_iter().enumerate() {
        let openings = match (round.openings, index) {
            (QueryOpenings::Base(opening), 0) => {
                QueryOpenings::Base(lift_c63_opening(opening, Some(linked_a.clone())))
            }
            (QueryOpenings::Extension(opening), index) if index > 0 => {
                QueryOpenings::Extension(lift_c63_opening(opening, None))
            }
            _ => return Err("C6.3 ordinary WHIR opening field differs".to_owned()),
        };
        rounds.push(ZkRoundProof {
            commitment: round.commitment,
            mask_commitment: round.mask_commitment,
            ood_answers: round.ood_answers,
            pow_witness: round.pow_witness,
            openings,
        });
    }
    let base = proof.base_case;
    let source_openings = match base.source_openings {
        QueryOpenings::Extension(opening) => {
            QueryOpenings::Extension(lift_c63_opening(opening, None))
        }
        QueryOpenings::Base(_) => return Err("C6.3 ordinary base source field differs".to_owned()),
    };
    Ok(ZkWhirProof {
        sumchecks: proof.sumchecks,
        sumcheck_mask_commitments: proof.sumcheck_mask_commitments,
        rounds,
        base_case: BaseCaseZkProof {
            fresh_main_commitment: base.fresh_main_commitment,
            fresh_mask_commitments: base.fresh_mask_commitments,
            masked_claim: base.masked_claim,
            blinded_message: base.blinded_message,
            blinded_randomness: base.blinded_randomness,
            blinded_masks: base.blinded_masks,
            pow_witness: base.pow_witness,
            source_openings,
            fresh_main_openings: lift_c63_opening(base.fresh_main_openings, None),
            mask_openings: base
                .mask_openings
                .into_iter()
                .map(|opening| MaskOpeningPair {
                    carried: lift_c63_opening(opening.carried, None),
                    fresh: lift_c63_opening(opening.fresh, None),
                })
                .collect(),
        },
    })
}

pub(crate) fn encode_c63_whir_projected_artifact<MT>(
    commitment: &C61Commitment,
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
) -> Result<Vec<u8>, String>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C63ProjectedMultiProof>,
{
    encode_c63_whir_projected_artifact_with_config(19, &c63_whir_config(19)?, commitment, proof)
}

pub(crate) fn encode_c63_whir_projected_artifact_with_config<MT>(
    num_variables: usize,
    config: &C63WhirConfig,
    commitment: &C61Commitment,
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
) -> Result<Vec<u8>, String>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C63ProjectedMultiProof>,
{
    if config.num_variables != num_variables {
        return Err("C6.3 projected WHIR codec dimension differs".to_owned());
    }
    let (ordinary, linked_a) = strip_c63_projected_proof(proof)?;
    let ordinary = encode_c63_whir_ordinary_artifact_with_config(
        num_variables,
        config,
        commitment,
        &ordinary,
    )?;
    let queries = config.round_parameters[0].num_queries;
    let fold = config.round_folding_factor(0);
    let leaves = config.round_parameters[0].domain_size >> fold;
    let mut body = C61Writer::default();
    body.u32(ordinary.len()).map_err(|error| error.to_string())?;
    body.bytes.extend_from_slice(&ordinary);
    body.u8(linked_a.0.is_some() as u8);
    if let Some(predecessor) = &linked_a.0 {
        encode_c63_fp_opening(
            &mut body,
            predecessor,
            queries,
            C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
            leaves,
        )?;
    }
    encode_c63_fp_opening(
        &mut body,
        &linked_a.1,
        queries,
        C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
        leaves,
    )?;
    let mut artifact = C61Writer::default();
    artifact.bytes.extend_from_slice(&C63_WHIR_MAGIC);
    artifact.u16(C63_WHIR_VERSION);
    artifact.u8(num_variables as u8);
    artifact.u8(1);
    artifact.u32(body.bytes.len()).map_err(|error| error.to_string())?;
    artifact.bytes.extend_from_slice(&body.bytes);
    if artifact.bytes.len() > c63_projected_whir_structural_bytes_for_config(config)? {
        return Err("C6.3 projected WHIR artifact exceeds its structural maximum".to_owned());
    }
    Ok(artifact.bytes)
}

pub(crate) fn decode_c63_whir_projected_artifact(
    bytes: &[u8],
) -> Result<(C61Commitment, C63ProjectedWhirProof), String> {
    decode_c63_whir_projected_artifact_with_config(bytes, 19, &c63_whir_config(19)?)
}

pub(crate) fn decode_c63_whir_projected_artifact_with_config(
    bytes: &[u8],
    num_variables: usize,
    config: &C63WhirConfig,
) -> Result<(C61Commitment, C63ProjectedWhirProof), String> {
    if config.num_variables != num_variables {
        return Err("C6.3 projected WHIR codec dimension differs".to_owned());
    }
    if bytes.len() > c63_projected_whir_structural_bytes_for_config(config)? {
        return Err("C6.3 projected WHIR artifact exceeds its structural maximum".to_owned());
    }
    let mut reader = C61Reader::new(bytes);
    if reader.take(8).map_err(|error| error.to_string())? != C63_WHIR_MAGIC
        || reader.u16().map_err(|error| error.to_string())? != C63_WHIR_VERSION
        || reader.u8().map_err(|error| error.to_string())? as usize != num_variables
        || reader.u8().map_err(|error| error.to_string())? != 1
    {
        return Err("C6.3 projected WHIR artifact header differs".to_owned());
    }
    let body_len = reader.u32().map_err(|error| error.to_string())?;
    if body_len != bytes.len().saturating_sub(C61_WHIRA1_HEADER_BYTES) {
        return Err("C6.3 projected WHIR artifact body length differs".to_owned());
    }
    let ordinary_len = reader.u32().map_err(|error| error.to_string())?;
    let ordinary = reader.take(ordinary_len).map_err(|error| error.to_string())?;
    let (commitment, proof) =
        decode_c63_whir_ordinary_artifact_with_config(ordinary, num_variables, config)?;
    let queries = config.round_parameters[0].num_queries;
    let fold = config.round_folding_factor(0);
    let leaves = config.round_parameters[0].domain_size >> fold;
    let predecessor = match reader.u8().map_err(|error| error.to_string())? {
        0 => None,
        1 => Some(decode_c63_fp_opening(
            &mut reader,
            queries,
            C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
            leaves,
        )?),
        _ => return Err("C6.3 predecessor A opening flag differs".to_owned()),
    };
    let successor =
        decode_c63_fp_opening(&mut reader, queries, C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH, leaves)?;
    let linked_a = (predecessor, successor);
    reader.finish().map_err(|error| error.to_string())?;
    Ok((commitment, lift_c63_projected_proof(proof, linked_a)?))
}

/// Extracts `randomized_y - project(A,rho,limb)` from the authenticated rows.
/// WHIR's opt-in first-round equation constrains these values to
/// `Enc(0,zeta)`; this type does not claim the separate Bolt `D' -> m` link.
#[derive(Clone)]
pub(crate) struct C63EncodedSketchAtoYLink {
    context: Arc<C63EncodedSketchAtoYContext>,
}

impl<EF, MT> ZkWhirInitialOracleLink<Goldilocks, EF, MT> for C63EncodedSketchAtoYLink
where
    EF: p3_field::ExtensionField<Goldilocks>,
    MT: Mmcs<Goldilocks, MultiProof = C63ProjectedMultiProof>,
{
    fn required(&self) -> bool {
        true
    }

    fn folded_mask_values(
        &self,
        opening: &QueryOpenings<Goldilocks, EF, C63ProjectedMultiProof>,
        indices: &[usize],
        randomness: &Point<EF>,
    ) -> Option<Vec<EF>> {
        let QueryOpenings::Base(opening) = opening else {
            return None;
        };
        let (_, Some((predecessor, (successor_rows, _)))) = &opening.proof else {
            return None;
        };
        let predecessor_rows = predecessor.as_ref().map(|(rows, _)| rows);
        if opening.rows.len() != indices.len()
            || successor_rows.len() != indices.len()
            || predecessor_rows.is_some_and(|rows| rows.len() != indices.len())
            || (self.context.old_len == 0) != predecessor_rows.is_none()
            || opening.rows.iter().any(|row| row.len() != C63_ENCODED_SKETCH_FOLDED_POSITIONS)
            || successor_rows.iter().any(|row| row.len() != C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH)
            || predecessor_rows.is_some_and(|rows| {
                rows.iter().any(|row| row.len() != C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH)
            })
        {
            return None;
        }

        opening
            .rows
            .iter()
            .zip(successor_rows)
            .enumerate()
            .map(|(row_index, (randomized, successor_row))| {
                let mut difference = randomized.clone();
                for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
                    let successor = (0..C63_BOLT_COLUMNS)
                        .map(|column| {
                            successor_row
                                [column * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position]
                                * self.context.coefficients[column]
                        })
                        .sum::<Goldilocks>();
                    let predecessor = predecessor_rows.map_or(Goldilocks::ZERO, |rows| {
                        (0..C63_BOLT_COLUMNS)
                            .map(|column| {
                                rows[row_index]
                                    [column * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position]
                                    * self.context.coefficients[column]
                            })
                            .sum()
                    });
                    difference[folded_position] -= successor - predecessor;
                }
                Some(Poly::new(difference).eval_base(randomness))
            })
            .collect()
    }
}

pub(crate) fn verify_c63_whir_projected_artifact_with_config_at_point(
    bytes: &[u8],
    num_variables: usize,
    config: &C63WhirConfig,
    point: &[Fp2],
    context: C63EncodedSketchAtoYContext,
    context_digest: [u8; 32],
) -> Result<C63ClaimlessWhirVerifierClosure, String> {
    if point.len() != num_variables
        || config.num_variables != num_variables
        || context.dimensions.height != 1usize << num_variables
    {
        return Err("C6.3 projected WHIR opening point geometry differs".to_owned());
    }
    let (commitment, proof) =
        decode_c63_whir_projected_artifact_with_config(bytes, num_variables, config)?;
    let point = Point::new(point.iter().rev().copied().map(c61_p3_fp2_from_volta).collect());
    let mmcs = C63ProjectedMmcs::new(context);
    let link = mmcs.link();
    let mut challenger = c63_challenger(context_digest)?;
    challenger.observe(commitment.clone());
    challenger.observe_algebra_slice(point.as_slice());
    let verifier = HidingWhirVerifier::new(config, &mmcs);
    let closure = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless_with_initial_link(
            &proof,
            &commitment,
            std::slice::from_ref(&point),
            &link,
            &mut challenger,
        )
    }))
    .map_err(|_| "C6.3 projected WHIR verifier panicked".to_owned())?
    .map_err(|error| format!("C6.3 projected WHIR verification failed: {error}"))?;
    c63_convert_verifier_closure(closure)
}

/// Read only the initial root needed to derive post-commit challenges. Full
/// canonical decoding and proof verification still happen before acceptance.
fn c63_whir_initial_root(
    bytes: &[u8],
    num_variables: usize,
    projected: bool,
) -> Result<[u8; 32], String> {
    let mut reader = C61Reader::new(bytes);
    if reader.take(8).map_err(|error| error.to_string())? != C63_WHIR_MAGIC
        || reader.u16().map_err(|error| error.to_string())? != C63_WHIR_VERSION
        || reader.u8().map_err(|error| error.to_string())? as usize != num_variables
        || reader.u8().map_err(|error| error.to_string())? != projected as u8
    {
        return Err("C6.3 WHIR root prefix differs".to_owned());
    }
    let body_len = reader.u32().map_err(|error| error.to_string())?;
    if body_len != bytes.len().saturating_sub(C61_WHIRA1_HEADER_BYTES) {
        return Err("C6.3 WHIR root prefix length differs".to_owned());
    }
    if projected {
        let ordinary_len = reader.u32().map_err(|error| error.to_string())?;
        let ordinary = reader.take(ordinary_len).map_err(|error| error.to_string())?;
        return c63_whir_initial_root(ordinary, num_variables, false);
    }
    let commitment = reader.commitment().map_err(|error| error.to_string())?;
    if commitment.roots().len() != 1 {
        return Err("C6.3 WHIR initial root cap differs".to_owned());
    }
    Ok(commitment.roots()[0])
}

pub(crate) fn c63_whir_initial_roots(
    d22_artifacts: &[[Vec<u8>; 2]; 2],
    d19_artifacts: &[[Vec<u8>; 2]; 2],
    input_variables: usize,
    output_variables: usize,
) -> Result<[[u8; 32]; 8], String> {
    let mut roots = [[0u8; 32]; 8];
    for tape in 0..2 {
        for limb in 0..2 {
            roots[tape * 2 + limb] =
                c63_whir_initial_root(&d22_artifacts[tape][limb], input_variables, false)?;
            roots[4 + tape * 2 + limb] =
                c63_whir_initial_root(&d19_artifacts[tape][limb], output_variables, true)?;
        }
    }
    Ok(roots)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_c63_sketch_suffix(
    public_argument_bytes: &[u8],
    attempt: C6ClientAttempt,
    h: &C63SparseSketchReference,
    sparse_proof: &C63SparseHClosureProof,
    predecessor_state: &C63VerifierSketchState,
    source_link: C63ResidualSourceFunctionalsVerifiedLink,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    verifier_contexts: &mut [VerifierCtx; 2],
) -> Result<(C63SparseHTapeClosureReferenceAudit, C63VerifierSketchState), String> {
    begin_verify_c63_sketch_suffix(
        public_argument_bytes,
        attempt,
        h,
        sparse_proof,
        predecessor_state,
        verifier_contexts,
    )?
    .finish(source_link, terminal_proofs, mask_range, verifier_contexts)
}

/// CPU-verifier state after the sparse proof has fixed the source-functional
/// point but before the authenticated output link and eight WHIR bodies close.
pub struct C63SketchSuffixVerifierPending {
    argument: C63PublicArgument,
    rho: [Fp2; C63_BOLT_COLUMNS],
    projected_contexts: [[C63EncodedSketchAtoYContext; 2]; 2],
    statement: C63SparseHClosureStatement,
    source_functional_context_digest: [u8; 32],
    successor_state: C63VerifierSketchState,
    inner: C63EightBodyVerifierPending,
}

impl C63SketchSuffixVerifierPending {
    pub fn sumcheck_point(&self) -> &[Fp2] {
        self.inner.sparse.sumcheck_point()
    }

    pub fn rho(&self) -> &[Fp2; C63_BOLT_COLUMNS] {
        &self.rho
    }

    pub fn source_functional_context_digest(&self) -> [u8; 32] {
        self.source_functional_context_digest
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.argument.statement_digest()
    }

    pub fn accepted_len(&self) -> u16 {
        self.argument.accepted_len()
    }

    pub fn finish(
        self,
        source_link: C63ResidualSourceFunctionalsVerifiedLink,
        terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
        mask_range: C63AuthenticatedWhirMaskRange,
        verifier_contexts: &mut [VerifierCtx; 2],
    ) -> Result<(C63SparseHTapeClosureReferenceAudit, C63VerifierSketchState), String> {
        let input_config = c63_whir_config(22)?;
        let output_config = c63_whir_config(19)?;
        let audit = finish_verify_c63_eight_body_terminal_join_with_configs(
            self.inner,
            &self.statement,
            self.argument.d22_whir(),
            self.argument.d19_projected_whir(),
            22,
            &input_config,
            19,
            &output_config,
            &self.projected_contexts,
            source_link,
            terminal_proofs,
            mask_range,
            verifier_contexts,
        )?;
        Ok((audit, self.successor_state))
    }
}

pub fn begin_verify_c63_sketch_suffix(
    public_argument_bytes: &[u8],
    attempt: C6ClientAttempt,
    h: &C63SparseSketchReference,
    sparse_proof: &C63SparseHClosureProof,
    predecessor_state: &C63VerifierSketchState,
    verifier_contexts: &mut [VerifierCtx; 2],
) -> Result<C63SketchSuffixVerifierPending, String> {
    let input_config = c63_whir_config(22)?;
    let output_config = c63_whir_config(19)?;
    let (decoded, statement, spots, successor_state) = prepare_c63_sketch_suffix_inputs(
        public_argument_bytes,
        attempt,
        None,
        C63_SYSTEMATIC_SPOT_QUERIES,
        22,
        &input_config,
        19,
        &output_config,
        predecessor_state,
    )?;
    let inner = begin_verify_c63_eight_body_terminal_join_with_configs(
        h,
        &statement,
        &spots,
        sparse_proof,
        decoded.argument.d22_whir(),
        decoded.argument.d19_projected_whir(),
        22,
        19,
        decoded.binding,
        &decoded.rho,
        public_argument_bytes,
        verifier_contexts,
    )?;
    let source_functional_context_digest = decoded.binding.source_functional_context(
        inner.query_seed,
        sparse_proof.source_functional_prefix_digest().map_err(|error| error.to_string())?,
    )?;
    Ok(C63SketchSuffixVerifierPending {
        argument: decoded.argument,
        rho: decoded.rho,
        projected_contexts: decoded.projected_contexts,
        statement,
        source_functional_context_digest,
        successor_state,
        inner,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c63_sketch_suffix_with_configs(
    public_argument_bytes: &[u8],
    attempt: C6ClientAttempt,
    h: &C63SparseSketchReference,
    output_point: &[Fp2],
    sparse_proof: &C63SparseHClosureProof,
    predecessor_state: &C63VerifierSketchState,
    source_link: C63ResidualSourceFunctionalsVerifiedLink,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    verifier_contexts: &mut [VerifierCtx; 2],
    spot_queries: usize,
    input_variables: usize,
    input_config: &C63WhirConfig,
    output_variables: usize,
    output_config: &C63WhirConfig,
) -> Result<(C63SparseHTapeClosureReferenceAudit, C63VerifierSketchState), String> {
    let (decoded, statement, spots, successor_state) = prepare_c63_sketch_suffix_inputs(
        public_argument_bytes,
        attempt,
        Some(output_point),
        spot_queries,
        input_variables,
        input_config,
        output_variables,
        output_config,
        predecessor_state,
    )?;
    let pending = begin_verify_c63_eight_body_terminal_join_with_configs(
        h,
        &statement,
        &spots,
        sparse_proof,
        decoded.argument.d22_whir(),
        decoded.argument.d19_projected_whir(),
        input_variables,
        output_variables,
        decoded.binding,
        &decoded.rho,
        public_argument_bytes,
        verifier_contexts,
    )?;
    let audit = finish_verify_c63_eight_body_terminal_join_with_configs(
        pending,
        &statement,
        decoded.argument.d22_whir(),
        decoded.argument.d19_projected_whir(),
        input_variables,
        input_config,
        output_variables,
        output_config,
        &decoded.projected_contexts,
        source_link,
        terminal_proofs,
        mask_range,
        verifier_contexts,
    )?;
    Ok((audit, successor_state))
}

#[allow(clippy::too_many_arguments)]
fn prepare_c63_sketch_suffix_inputs(
    public_argument_bytes: &[u8],
    attempt: C6ClientAttempt,
    supplied_output_point: Option<&[Fp2]>,
    spot_queries: usize,
    input_variables: usize,
    input_config: &C63WhirConfig,
    output_variables: usize,
    output_config: &C63WhirConfig,
    predecessor_state: &C63VerifierSketchState,
) -> Result<
    (
        crate::c63_public_argument::C63TranscriptPublicArgument,
        C63SparseHClosureStatement,
        Vec<C63TapeSystematicSpot>,
        C63VerifierSketchState,
    ),
    String,
> {
    let decoded = C63PublicArgument::decode_in_attempt_with_configs(
        public_argument_bytes,
        attempt,
        spot_queries,
        input_variables,
        input_config,
        output_variables,
        output_config,
    )?;
    let derived_output_point;
    let output_point = match supplied_output_point {
        Some(point) => point,
        None if output_variables == C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2 => {
            derived_output_point = decoded.binding.output_point();
            &derived_output_point
        }
        None => return Err("C6.3 production output-point geometry differs".to_owned()),
    };
    let argument = &decoded.argument;
    let opening = C63CorrectionRowsOpeningReference::decode(
        argument.correction_opening(),
        argument.old_len(),
        argument.accepted_len(),
        &decoded.queried_rows,
    )?;
    let (spots, successor_frontier) = c63_verify_correction_rows_by_tape_reference(
        argument.predecessor_correction_root(),
        argument.correction_root(),
        predecessor_state.correction_frontier(),
        argument.profile_digest(),
        argument.epoch(),
        argument.old_len(),
        argument.accepted_len(),
        &decoded.queried_rows,
        &decoded.rho,
        &opening,
    )?;
    let successor_state = predecessor_state.accept(argument, successor_frontier)?;
    let spots = spots
        .into_iter()
        .map(|(row, values)| C63TapeSystematicSpot { row, values })
        .collect::<Vec<_>>();
    let statement =
        C63SparseHClosureStatement::new(argument.correction_root(), output_point.to_vec())
            .map_err(|error| error.to_string())?;
    Ok((decoded, statement, spots, successor_state))
}

/// Verify the C6.3-specific cryptographic suffix in protocol order. Terminal
/// proofs are object-major: systematic tape 0/1, then sketch tape 0/1.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_c63_eight_body_terminal_join_with_configs(
    h: &C63SparseSketchReference,
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    sparse_proof: &C63SparseHClosureProof,
    d22_artifacts: &[[Vec<u8>; 2]; 2],
    d19_artifacts: &[[Vec<u8>; 2]; 2],
    input_variables: usize,
    input_config: &C63WhirConfig,
    output_variables: usize,
    output_config: &C63WhirConfig,
    transcript_binding: C63TranscriptBinding,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    public_argument_bytes: &[u8],
    projected_contexts: &[[C63EncodedSketchAtoYContext; 2]; 2],
    source_link: C63ResidualSourceFunctionalsVerifiedLink,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    verifier_contexts: &mut [VerifierCtx; 2],
) -> Result<C63SparseHTapeClosureReferenceAudit, String> {
    let pending = begin_verify_c63_eight_body_terminal_join_with_configs(
        h,
        statement,
        spots,
        sparse_proof,
        d22_artifacts,
        d19_artifacts,
        input_variables,
        output_variables,
        transcript_binding,
        rho,
        public_argument_bytes,
        verifier_contexts,
    )?;
    finish_verify_c63_eight_body_terminal_join_with_configs(
        pending,
        statement,
        d22_artifacts,
        d19_artifacts,
        input_variables,
        input_config,
        output_variables,
        output_config,
        projected_contexts,
        source_link,
        terminal_proofs,
        mask_range,
        verifier_contexts,
    )
}

struct C63EightBodyVerifierPending {
    sparse: C63SparseHTapeVerifierPending,
    lane_contexts: [[[[u8; 32]; 2]; 2]; 2],
    terminal_contexts: [[[u8; 32]; 2]; 2],
    query_seed: [u8; 32],
}

#[allow(clippy::too_many_arguments)]
fn begin_verify_c63_eight_body_terminal_join_with_configs(
    h: &C63SparseSketchReference,
    statement: &C63SparseHClosureStatement,
    spots: &[C63TapeSystematicSpot],
    sparse_proof: &C63SparseHClosureProof,
    d22_artifacts: &[[Vec<u8>; 2]; 2],
    d19_artifacts: &[[Vec<u8>; 2]; 2],
    input_variables: usize,
    output_variables: usize,
    transcript_binding: C63TranscriptBinding,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    public_argument_bytes: &[u8],
    verifier_contexts: &mut [VerifierCtx; 2],
) -> Result<C63EightBodyVerifierPending, String> {
    let initial_roots =
        c63_whir_initial_roots(d22_artifacts, d19_artifacts, input_variables, output_variables)?;
    let query_seed = transcript_binding.query_seed(rho, &initial_roots)?;
    let mut spot_challenger = c63_challenger(transcript_binding.spot_seed(query_seed)?)?;
    let expected_rows =
        c63_sample_systematic_query_rows(&mut spot_challenger, input_variables, spots.len())?;
    if spots.iter().map(|spot| spot.row).ne(expected_rows) {
        return Err("C6.3 systematic rows differ from the post-root transcript".to_owned());
    }
    let mut lane_contexts = [[[[0u8; 32]; 2]; 2]; 2];
    for (lane, lane_context) in lane_contexts.iter_mut().enumerate() {
        for (tape, tape_context) in lane_context.iter_mut().enumerate() {
            for (limb, context) in tape_context.iter_mut().enumerate() {
                *context = transcript_binding.lane_seed(
                    rho,
                    if lane == 0 {
                        C63AuthenticatedWhirLane::Systematic
                    } else {
                        C63AuthenticatedWhirLane::Sketch
                    },
                    tape,
                    limb,
                )?;
            }
        }
    }
    let sparse_bytes = sparse_proof.encode().map_err(|error| error.to_string())?;
    let terminal_contexts =
        transcript_binding.terminal_contexts(query_seed, public_argument_bytes, &sparse_bytes)?;
    let mut sparse_transcript = Transcript::new(transcript_binding.sparse_seed(query_seed)?);
    let pending = begin_verify_c63_sparse_h_tape_closure_reference(
        h,
        statement,
        spots,
        sparse_proof,
        verifier_contexts,
        &mut sparse_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok(C63EightBodyVerifierPending {
        sparse: pending,
        lane_contexts,
        terminal_contexts,
        query_seed,
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_verify_c63_eight_body_terminal_join_with_configs(
    pending: C63EightBodyVerifierPending,
    statement: &C63SparseHClosureStatement,
    d22_artifacts: &[[Vec<u8>; 2]; 2],
    d19_artifacts: &[[Vec<u8>; 2]; 2],
    input_variables: usize,
    input_config: &C63WhirConfig,
    output_variables: usize,
    output_config: &C63WhirConfig,
    projected_contexts: &[[C63EncodedSketchAtoYContext; 2]; 2],
    source_link: C63ResidualSourceFunctionalsVerifiedLink,
    terminal_proofs: [C61AuthenticatedWhirBaseProof; 4],
    mask_range: C63AuthenticatedWhirMaskRange,
    verifier_contexts: &mut [VerifierCtx; 2],
) -> Result<C63SparseHTapeClosureReferenceAudit, String> {
    let m_keys = source_link.terminal_m_keys();

    for tape in 0..2 {
        let closures = [
            verify_c63_whir_ordinary_artifact_with_config_at_point(
                &d22_artifacts[tape][0],
                input_variables,
                input_config,
                pending.sparse.sumcheck_point(),
                pending.lane_contexts[0][tape][0],
            )?,
            verify_c63_whir_ordinary_artifact_with_config_at_point(
                &d22_artifacts[tape][1],
                input_variables,
                input_config,
                pending.sparse.sumcheck_point(),
                pending.lane_contexts[0][tape][1],
            )?,
        ];
        verify_c63_claimless_whir_limb_pair(
            closures,
            m_keys[tape],
            terminal_proofs[tape],
            &mut verifier_contexts[tape],
            C63AuthenticatedWhirLane::Systematic,
            mask_range,
            pending.terminal_contexts[0][tape],
        )?;
    }

    let u_keys = pending.sparse.derive_u_opening_keys(m_keys).map_err(|error| error.to_string())?;
    for tape in 0..2 {
        let closures = [
            verify_c63_whir_projected_artifact_with_config_at_point(
                &d19_artifacts[tape][0],
                output_variables,
                output_config,
                statement.output_point(),
                projected_contexts[tape][0].clone(),
                pending.lane_contexts[1][tape][0],
            )?,
            verify_c63_whir_projected_artifact_with_config_at_point(
                &d19_artifacts[tape][1],
                output_variables,
                output_config,
                statement.output_point(),
                projected_contexts[tape][1].clone(),
                pending.lane_contexts[1][tape][1],
            )?,
        ];
        verify_c63_claimless_whir_limb_pair(
            closures,
            u_keys[tape],
            terminal_proofs[2 + tape],
            &mut verifier_contexts[tape],
            C63AuthenticatedWhirLane::Sketch,
            mask_range,
            pending.terminal_contexts[1][tape],
        )?;
    }
    pending.sparse.finish(u_keys, m_keys).map_err(|error| error.to_string())
}

/// Pack the sixteen deterministic scalar codewords into WHIR's first-fold
/// leaf order. Each physical row is
/// `[column_0/fold_0, column_0/fold_1, ..., column_15/fold_1]`.
pub fn c63_pack_encoded_sketch_rows_reference(
    encoded_columns: &[DenseMatrix<Goldilocks>],
) -> Result<DenseMatrix<Goldilocks>, String> {
    if encoded_columns.len() != C63_BOLT_COLUMNS {
        return Err("C6.3 encoded sketch needs sixteen tensor columns".to_owned());
    }
    let values_per_column = encoded_columns[0].values.len();
    if encoded_columns[0].width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
        || values_per_column == 0
        || !values_per_column
            .checked_div(C63_ENCODED_SKETCH_FOLDED_POSITIONS)
            .is_some_and(usize::is_power_of_two)
        || encoded_columns.iter().any(|column| {
            column.width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
                || column.values.len() != values_per_column
        })
    {
        return Err("C6.3 encoded sketch column geometry differs".to_owned());
    }

    let rows = values_per_column / C63_ENCODED_SKETCH_FOLDED_POSITIONS;
    let mut packed = Vec::with_capacity(rows * C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH);
    for row in 0..rows {
        for column in encoded_columns {
            let start = row * C63_ENCODED_SKETCH_FOLDED_POSITIONS;
            packed.extend_from_slice(
                &column.values[start..start + C63_ENCODED_SKETCH_FOLDED_POSITIONS],
            );
        }
    }
    Ok(DenseMatrix::new(packed, C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH))
}

/// Project a paired `A` row by one base-field limb of `rho in Fp2^16`.
/// The result has exactly the width-two layout consumed by
/// `commit_c62_cached_fixed_base`.
pub fn c63_project_encoded_sketch_limb_reference(
    paired_rows: &DenseMatrix<Goldilocks>,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    limb: usize,
) -> Result<DenseMatrix<Goldilocks>, String> {
    c63_project_encoded_sketch_tape_limb(paired_rows, rho, None, limb)
}

pub fn c63_project_encoded_sketch_tape_limb_reference(
    paired_rows: &DenseMatrix<Goldilocks>,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    tape: usize,
    limb: usize,
) -> Result<DenseMatrix<Goldilocks>, String> {
    c63_project_encoded_sketch_tape_limb(paired_rows, rho, Some(tape), limb)
}

fn c63_project_encoded_sketch_tape_limb(
    paired_rows: &DenseMatrix<Goldilocks>,
    rho: &[Fp2; C63_BOLT_COLUMNS],
    tape: Option<usize>,
    limb: usize,
) -> Result<DenseMatrix<Goldilocks>, String> {
    if limb >= 2
        || tape.is_some_and(|value| value >= 2)
        || paired_rows.width != C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH
        || paired_rows.values.is_empty()
        || paired_rows.values.len() % C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH != 0
        || !(paired_rows.values.len() / C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH).is_power_of_two()
    {
        return Err("C6.3 encoded sketch projection geometry differs".to_owned());
    }
    let coefficients = rho
        .map(|value| Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() }));
    let mut projected = Vec::with_capacity(paired_rows.values.len() / C63_BOLT_COLUMNS);
    for row in paired_rows.values.chunks_exact(C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH) {
        for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
            let mut value = Goldilocks::ZERO;
            for column in 0..C63_BOLT_COLUMNS {
                if tape.is_some_and(|selected| column & 1 != selected) {
                    continue;
                }
                value += row[column * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position]
                    * coefficients[column];
            }
            projected.push(value);
        }
    }
    Ok(DenseMatrix::new(projected, C63_ENCODED_SKETCH_FOLDED_POSITIONS))
}

/// Project the decoded D19 tensor message by the same limb and column order.
pub fn c63_project_decoded_sketch_limb_reference(
    columns: &[Poly<Goldilocks>],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    limb: usize,
) -> Result<Poly<Goldilocks>, String> {
    c63_project_decoded_sketch_tape_limb(columns, rho, None, limb)
}

pub fn c63_project_decoded_sketch_tape_limb_reference(
    columns: &[Poly<Goldilocks>],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    tape: usize,
    limb: usize,
) -> Result<Poly<Goldilocks>, String> {
    c63_project_decoded_sketch_tape_limb(columns, rho, Some(tape), limb)
}

fn c63_project_decoded_sketch_tape_limb(
    columns: &[Poly<Goldilocks>],
    rho: &[Fp2; C63_BOLT_COLUMNS],
    tape: Option<usize>,
    limb: usize,
) -> Result<Poly<Goldilocks>, String> {
    if columns.len() != C63_BOLT_COLUMNS || limb >= 2 || tape.is_some_and(|value| value >= 2) {
        return Err("C6.3 decoded sketch projection geometry differs".to_owned());
    }
    let len = columns[0].as_slice().len();
    if len == 0
        || !len.is_power_of_two()
        || columns.iter().any(|column| column.as_slice().len() != len)
    {
        return Err("C6.3 decoded sketch column geometry differs".to_owned());
    }
    let coefficients = rho
        .map(|value| Goldilocks::new(if limb == 0 { value.c0.value() } else { value.c1.value() }));
    let mut projected = Goldilocks::zero_vec(len);
    for (column_index, (column, coefficient)) in columns.iter().zip(coefficients).enumerate() {
        if tape.is_some_and(|selected| column_index & 1 != selected) {
            continue;
        }
        for (target, &value) in projected.iter_mut().zip(column.as_slice()) {
            *target += value * coefficient;
        }
    }
    Ok(Poly::new(projected))
}

/// Reference-only equality check for the decoded-message/pre-encoded-oracle
/// link. A production prover must establish this relation without re-encoding.
pub fn c63_check_preencoded_link_reference(
    projected: &DenseMatrix<Goldilocks>,
    ordinary_encoding: &DenseMatrix<Goldilocks>,
) -> Result<(), String> {
    if projected == ordinary_encoding {
        Ok(())
    } else {
        Err("C6.3 pre-encoded initial oracle is not the decoded message encoding".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    #[cfg(feature = "cuda")]
    use std::sync::Arc;
    #[cfg(feature = "cuda")]
    use std::time::Instant;

    use p3_blake3::Blake3;
    use p3_challenger::{
        CanObserve, FieldChallenger, GrindingChallenger, HashChallenger, SerializingChallenger64,
    };
    use p3_commit::Mmcs;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::Dimensions;
    use p3_multilinear_util::point::Point;
    use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    use p3_whir_c61::pcs::zk::{
        ClaimlessWhirProverOutput, ClaimlessWhirVerifierClosure, HidingWhirProver,
        HidingWhirVerifier, ZkParameters, ZkWhirConfig,
    };
    use rand_010::rngs::StdRng;
    use rand_010::SeedableRng;
    #[cfg(feature = "cuda")]
    use volta_accel::{Backend, DeviceSlice};
    use volta_field::{Fp, Fp2};
    use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
    use volta_proto::{C6CorrelationRange, C6PairedCorrelationRanges, C6Workload};

    use super::*;
    use crate::c61_authenticated_whir::{
        finish_c61_authenticated_whir_base, finish_c63_authenticated_whir_limb_pair,
        prepare_c61_authenticated_whir_mask, prepare_c63_authenticated_whir_limb_pair,
        verify_c61_authenticated_whir_base, C61AuthenticatedWhirAffineClaim,
        C61AuthenticatedWhirMaskRange, C61AuthenticatedWhirProverFinishInput,
        C61AuthenticatedWhirVerifierInput, C63AuthenticatedWhirLane, C63AuthenticatedWhirMaskRange,
        C63AuthenticatedWhirPreparedLimbPair,
    };
    use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};
    use crate::c61_whir_reference::{
        c61_p3_fp2_from_volta, c61_reference_mmcs, c61_volta_fp2_from_p3, C61P3Fp2,
    };
    #[cfg(feature = "cuda")]
    use crate::c62_gpu_whir::{
        C62GpuResourceGuard, C62ProviderCacheKey, C62_GPU_WHIR_EXECUTOR_VERSION,
        C62_GPU_WHIR_FIELD_TAG,
    };
    #[cfg(feature = "cuda")]
    use crate::c63_authenticated_sketch::c63_verify_correction_rows_reference;
    use crate::c63_authenticated_sketch::{
        c63_authenticated_correction_functional_prover_reference,
        c63_authenticated_correction_functional_verifier_reference, c63_bolt_correction_index,
        c63_correction_state_root_reference, c63_correction_tile_root_reference,
        c63_open_correction_rows_reference, c63_verify_correction_rows_by_tape_reference,
        C63AuthenticatedCorrectionProverCell, C63AuthenticatedCorrectionVerifierCell,
        C63CorrectionRowReference, C63SparseSketchEdge, C63SparseSketchReference,
        C63_BOLT_LIVE_ROWS_PER_POSITION,
    };
    #[cfg(feature = "cuda")]
    use crate::c63_authenticated_sketch::{
        C63SparseSetupReference, C63_BOLT_LDPC_CHECK_DEGREE, C63_BOLT_LDPC_COLUMN_DEGREE,
        C63_BOLT_ROWS, C63_BOLT_ROW_LOG2, C63_BOLT_SKETCH_ROWS, C63_PRODUCTION_SETUP_SEED,
        C63_SYSTEMATIC_SPOT_QUERIES,
    };
    #[cfg(feature = "cuda")]
    use crate::c63_gpu_owner::{C63GpuSetupOwner, C63GpuStateOwner, C63GpuTileMetadata};
    #[cfg(feature = "cuda")]
    use crate::c63_sparse_h_closure::prove_c63_sparse_h_closure_with_spots_resident;
    use crate::c63_sparse_h_closure::{
        begin_verify_c63_sparse_h_tape_closure_reference,
        prove_c63_sparse_h_tape_closure_with_spots_reference,
        verify_c63_sparse_h_tape_closure_from_whir_openings_reference, C63SparseHClosureError,
        C63SparseHClosureStatement, C63TapeSystematicSpot,
    };
    #[cfg(feature = "cuda")]
    use crate::c63_sparse_h_closure::{
        verify_c63_sparse_h_closure_from_whir_openings_reference, C63SystematicSpot,
    };
    use crate::c6_persistent_cache::{expected_c6_cache_append_cells, C6PersistentCacheLayout};

    const TEST_NUM_VARIABLES: usize = 12;

    fn config_for<Challenger>(
        num_variables: usize,
    ) -> ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>
    where
        Challenger: p3_challenger::FieldChallenger<Goldilocks>
            + p3_challenger::GrindingChallenger<Witness = Goldilocks>,
    {
        ZkWhirConfig::new(
            num_variables,
            ProtocolParameters {
                security_level: 32,
                pow_bits: 0,
                round_log_inv_rates: Vec::new(),
                folding_factor: FoldingFactor::ConstantFromSecondRound(1, 2),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            ZkParameters { ell_zk: 4, mask_log_inv_rate: 1 },
        )
        .unwrap()
    }

    fn synthetic_commitment(byte: u8) -> C61Commitment {
        C61Commitment::new(vec![[byte; 32]])
    }

    fn synthetic_fp_opening(
        queries: usize,
        width: usize,
        leaves: usize,
    ) -> SharedProofOpening<Goldilocks, C61MultiProof> {
        SharedProofOpening {
            rows: vec![vec![Goldilocks::ZERO; width]; queries],
            proof: C61MultiProof {
                sibling_hashes: vec![[0x41; 32]; c61_max_pruned_binary_siblings(leaves, queries)],
            },
        }
    }

    fn synthetic_fp2_opening(
        queries: usize,
        width: usize,
        leaves: usize,
    ) -> SharedProofOpening<C61P3Fp2, C61MultiProof> {
        SharedProofOpening {
            rows: vec![vec![C61P3Fp2::ZERO; width]; queries],
            proof: C61MultiProof {
                sibling_hashes: vec![[0x42; 32]; c61_max_pruned_binary_siblings(leaves, queries)],
            },
        }
    }

    fn synthetic_production_proof(config: &C63WhirConfig) -> C63OrdinaryWhirProof {
        let batches = config.n_rounds() + 1;
        let sumchecks = (0..batches)
            .map(|batch| {
                let rounds = config.round_folding_factor(batch);
                let pow_count = usize::from(c63_sumcheck_pow_bits(config, batch) > 0) * rounds;
                ZkSumcheckData {
                    mu_tilde: C61P3Fp2::ZERO,
                    ell_zk: config.zk.ell_zk,
                    round_coefficients: vec![vec![C61P3Fp2::ZERO; config.zk.ell_zk - 1]; rounds],
                    pow_witnesses: vec![Goldilocks::ONE; pow_count],
                }
            })
            .collect();
        let rounds = config
            .round_parameters
            .iter()
            .enumerate()
            .map(|(index, round)| {
                let fold = config.round_folding_factor(index);
                let leaves = round.domain_size >> fold;
                ZkRoundProof {
                    commitment: synthetic_commitment(0x51 + index as u8),
                    mask_commitment: synthetic_commitment(0x61 + index as u8),
                    ood_answers: vec![C61P3Fp2::ZERO; round.ood_samples],
                    pow_witness: if round.pow_bits > 0 {
                        Goldilocks::ONE
                    } else {
                        Goldilocks::ZERO
                    },
                    openings: if index == 0 {
                        QueryOpenings::Base(synthetic_fp_opening(
                            round.num_queries,
                            1 << fold,
                            leaves,
                        ))
                    } else {
                        QueryOpenings::Extension(synthetic_fp2_opening(
                            round.num_queries,
                            1 << fold,
                            leaves,
                        ))
                    },
                }
            })
            .collect();
        let groups = config.mask_groups();
        let final_round = config.final_round_config();
        let final_domain = final_round.domain_size >> final_round.folding_factor;
        let blinded_masks = groups
            .iter()
            .flat_map(|group| {
                (0..group.width).map(|_| BlindedMask {
                    message: vec![C61P3Fp2::ZERO; group.shape.message_len],
                    randomness: vec![C61P3Fp2::ZERO; group.shape.randomness_len],
                })
            })
            .collect();
        let mask_openings = groups
            .iter()
            .map(|group| MaskOpeningPair {
                carried: synthetic_fp2_opening(
                    config.mask_queries,
                    group.width,
                    group.shape.domain_size,
                ),
                fresh: synthetic_fp2_opening(
                    config.mask_queries,
                    group.width,
                    group.shape.domain_size,
                ),
            })
            .collect();
        ZkWhirProof {
            sumchecks,
            sumcheck_mask_commitments: (0..batches)
                .map(|index| synthetic_commitment(0x71 + index as u8))
                .collect(),
            rounds,
            base_case: BaseCaseZkProof {
                fresh_main_commitment: synthetic_commitment(0x81),
                fresh_mask_commitments: (0..groups.len())
                    .map(|index| synthetic_commitment(0x91 + index as u8))
                    .collect(),
                masked_claim: C61P3Fp2::ZERO,
                blinded_message: vec![C61P3Fp2::ZERO; 1 << final_round.num_variables],
                blinded_randomness: vec![
                    C61P3Fp2::ZERO;
                    config.oracle_randomness[config.n_rounds()]
                ],
                blinded_masks,
                pow_witness: if config.final_pow_bits > 0 {
                    Goldilocks::ONE
                } else {
                    Goldilocks::ZERO
                },
                source_openings: QueryOpenings::Extension(synthetic_fp2_opening(
                    config.final_queries,
                    1 << final_round.folding_factor,
                    final_domain,
                )),
                fresh_main_openings: synthetic_fp2_opening(config.final_queries, 1, final_domain),
                mask_openings,
            },
        }
    }

    #[test]
    fn production_profiles_include_every_registered_pow_witness_and_byte() {
        let cases = [
            (22, vec![245, 245, 113, 74, 74, 55, 44, 36], 31, 257, 17, 1_289_080),
            (19, vec![245, 245, 113, 74, 55, 44], 36, 254, 13, 970_752),
        ];
        for (variables, queries, final_queries, mask_queries, witnesses, bytes) in cases {
            let config = c63_whir_config(variables).unwrap();
            assert_eq!(
                config.round_parameters.iter().map(|round| round.num_queries).collect::<Vec<_>>(),
                queries,
            );
            assert_eq!(config.final_queries, final_queries);
            assert_eq!(config.mask_queries, mask_queries);
            let sumcheck_pow: usize = (0..=config.n_rounds())
                .map(|batch| {
                    let bits = if batch == 0 {
                        config.starting_folding_pow_bits
                    } else {
                        config.round_parameters[batch - 1].folding_pow_bits
                    };
                    usize::from(bits > 0) * config.round_folding_factor(batch)
                })
                .sum();
            let round_pow =
                config.round_parameters.iter().filter(|round| round.pow_bits > 0).count();
            assert_eq!(
                sumcheck_pow + round_pow + usize::from(config.final_pow_bits > 0),
                witnesses
            );
            assert_eq!(c63_whir_structural_budget(variables).unwrap().strict_chain_bytes, bytes);
        }
        assert!(c63_whir_config(20).is_err());
    }

    #[test]
    fn transcript_derives_the_output_point_and_projected_cache_identity() {
        let attempt = C6ClientAttempt {
            slot: 7,
            nonce: [0x11; 32],
            setup_manifest_digest: [0x12; 32],
            old_head_digest: [0x13; 32],
            predecessor_certificate_digest: [0x14; 32],
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    C6CorrelationRange { stage: 1, start: 1_000, count: 1_000 },
                    C6CorrelationRange { stage: 1, start: 2_000, count: 1_000 },
                ],
            },
            workload: C6Workload {
                prompt_tokens: 1,
                decode_tokens: 0,
                old_context: 1,
                new_context: 2,
            },
        };
        let binding = C63TranscriptBinding::new(
            attempt, [0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32], 2, 1,
            2,
        )
        .unwrap();
        let mut changed_attempt = attempt;
        changed_attempt.nonce[0] ^= 1;
        let changed_binding = C63TranscriptBinding::new(
            changed_attempt,
            [0x21; 32],
            [0x22; 32],
            [0x23; 32],
            [0x24; 32],
            [0x25; 32],
            [0x26; 32],
            2,
            1,
            2,
        )
        .unwrap();
        assert_eq!(binding.output_point().len(), C63_ENCODED_SKETCH_PHYSICAL_ROW_LOG2);
        assert_ne!(binding.output_point(), changed_binding.output_point());

        let rho = std::array::from_fn(|index| {
            Fp2::new(Fp::new(31 + index as u64), Fp::new(47 + index as u64))
        });
        let key = binding.projected_cache_content_digest(&rho, 0, 0).unwrap();
        assert_ne!(key, binding.projected_cache_content_digest(&rho, 0, 1).unwrap());
        assert_ne!(key, binding.projected_cache_content_digest(&rho, 1, 0).unwrap());
        assert_ne!(key, changed_binding.projected_cache_content_digest(&rho, 0, 0).unwrap());
        assert!(binding.projected_cache_content_digest(&rho, 2, 0).is_err());
    }

    #[test]
    fn production_claimless_codec_counts_pow_and_rejects_bad_framing() {
        for variables in [22, 19] {
            let config = c63_whir_config(variables).unwrap();
            let commitment = synthetic_commitment(0x31);
            let proof = synthetic_production_proof(&config);
            let encoded =
                encode_c63_whir_ordinary_artifact(variables, &commitment, &proof).unwrap();
            assert_eq!(
                encoded.len(),
                c63_whir_structural_budget(variables).unwrap().strict_chain_bytes
            );
            let (decoded_commitment, decoded) =
                decode_c63_whir_ordinary_artifact(&encoded, variables).unwrap();
            assert_eq!(decoded_commitment, commitment);
            assert_eq!(
                encode_c63_whir_ordinary_artifact(variables, &decoded_commitment, &decoded)
                    .unwrap(),
                encoded,
            );

            let mut bad_header = encoded.clone();
            bad_header[0] ^= 1;
            assert!(decode_c63_whir_ordinary_artifact(&bad_header, variables).is_err());
            let mut noncanonical = encoded.clone();
            noncanonical[48..56].copy_from_slice(&volta_field::P.to_le_bytes());
            assert!(decode_c63_whir_ordinary_artifact(&noncanonical, variables).is_err());
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(decode_c63_whir_ordinary_artifact(&trailing, variables).is_err());
            assert!(decode_c63_whir_ordinary_artifact(&encoded[..encoded.len() - 1], variables,)
                .is_err());
        }
    }

    #[test]
    fn production_projected_codec_places_a_opening_once() {
        let config = c63_whir_config(19).unwrap();
        let commitment = synthetic_commitment(0x31);
        let ordinary = synthetic_production_proof(&config);
        let queries = config.round_parameters[0].num_queries;
        let linked = synthetic_fp_opening(
            queries,
            C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
            C63_ENCODED_SKETCH_PHYSICAL_ROWS,
        );
        let projected =
            lift_c63_projected_proof(ordinary, (Some(linked.clone()), linked.clone())).unwrap();
        let encoded = encode_c63_whir_projected_artifact(&commitment, &projected).unwrap();
        assert_eq!(encoded.len(), c63_projected_whir_structural_bytes().unwrap());
        let (decoded_commitment, decoded) = decode_c63_whir_projected_artifact(&encoded).unwrap();
        assert_eq!(decoded_commitment, commitment);
        assert_eq!(
            encode_c63_whir_projected_artifact(&decoded_commitment, &decoded).unwrap(),
            encoded,
        );

        let mut missing = decoded.clone();
        let QueryOpenings::Base(first) = &mut missing.rounds[0].openings else {
            panic!("first C6.3 projected round must be base-field");
        };
        first.proof.1 = None;
        assert!(encode_c63_whir_projected_artifact(&commitment, &missing).is_err());

        let (_, mut trailing_link) = decode_c63_whir_projected_artifact(&encoded).unwrap();
        let QueryOpenings::Extension(second) = &mut trailing_link.rounds[1].openings else {
            panic!("second C6.3 projected round must be extension-field");
        };
        second.proof.1 =
            Some((Some((linked.rows.clone(), linked.proof.clone())), (linked.rows, linked.proof)));
        assert!(encode_c63_whir_projected_artifact(&commitment, &trailing_link).is_err());

        let mut bad_flag = encoded.clone();
        bad_flag[11] = 0;
        assert!(decode_c63_whir_projected_artifact(&bad_flag).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_c63_whir_projected_artifact(&trailing).is_err());
    }

    fn config<Challenger>() -> ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>
    where
        Challenger: p3_challenger::FieldChallenger<Goldilocks>
            + p3_challenger::GrindingChallenger<Witness = Goldilocks>,
    {
        config_for(TEST_NUM_VARIABLES)
    }

    fn challenger(seed: [u8; 32]) -> C63SeparatedSizingChallenger {
        C63SeparatedChallenger::new(
            SerializingChallenger64::new(HashChallenger::<u8, Blake3, 32>::new(
                seed.to_vec(),
                Blake3 {},
            )),
            [0x63; 16],
        )
        .unwrap()
    }

    #[test]
    fn separated_pow_does_not_consume_fiat_shamir_samples() {
        let seed = [0x51; 32];
        let observed = Goldilocks::from_u64(0x1234);
        let mut prover = challenger(seed);
        let mut verifier = challenger(seed);
        prover.observe(observed);
        verifier.observe(observed);

        let witness = prover.grind(10);
        assert!(verifier.check_witness(10, witness));
        let first_prover_sample: Goldilocks = prover.sample();
        let first_verifier_sample: Goldilocks = verifier.sample();
        assert_eq!(first_prover_sample, first_verifier_sample);

        let mut direct = SerializingChallenger64::new(HashChallenger::<u8, Blake3, 32>::new(
            seed.to_vec(),
            Blake3 {},
        ));
        direct.observe(observed);
        direct.observe(witness);
        let first_direct_sample: Goldilocks = direct.sample();
        assert_eq!(first_prover_sample, first_direct_sample);

        let snapshot = {
            let mut transcript = SerializingChallenger64::new(
                HashChallenger::<u8, Blake3, 32>::new(seed.to_vec(), Blake3 {}),
            );
            transcript.observe(observed);
            transcript.finalize()
        };
        let changed_role = (1u8..=u8::MAX)
            .map(|byte| [byte; 16])
            .find(|candidate| {
                !c63_pow_accepts(*candidate, 0, 10, snapshot, witness.to_unique_u64())
            })
            .expect("a domain-separated role must reject this 10-bit witness");
        let mut wrong_role = C63SeparatedChallenger::new(
            SerializingChallenger64::new(HashChallenger::<u8, Blake3, 32>::new(
                seed.to_vec(),
                Blake3 {},
            )),
            changed_role,
        )
        .unwrap();
        wrong_role.observe(observed);
        assert!(!wrong_role.check_witness(10, witness));
    }

    #[test]
    fn systematic_query_rows_are_replayable_sorted_and_unique() {
        let mut prover = challenger([0x62; 32]);
        let mut verifier = challenger([0x62; 32]);
        let prover_rows = c63_sample_systematic_query_rows(&mut prover, 12, 257).unwrap();
        let verifier_rows = c63_sample_systematic_query_rows(&mut verifier, 12, 257).unwrap();
        assert_eq!(prover_rows, verifier_rows);
        assert_eq!(prover_rows.len(), 257);
        assert!(prover_rows.windows(2).all(|pair| pair[0] < pair[1]));
        let prover_next: Goldilocks = prover.sample();
        let verifier_next: Goldilocks = verifier.sample();
        assert_eq!(prover_next, verifier_next);
        assert!(c63_sample_systematic_query_rows(&mut challenger([0x62; 32]), 0, 1).is_err());
    }

    fn verify_claimless(
        commitment: &crate::c61_whir_reference::C61Commitment,
        proof: &p3_whir_c61::pcs::zk::ZkWhirProof<
            Goldilocks,
            BinomialExtensionField<Goldilocks, 2>,
            crate::c61_whir_reference::C61Mmcs,
        >,
        point: &Point<C61P3Fp2>,
        verifier_seed: [u8; 32],
    ) -> bool {
        replay_claimless(commitment, proof, point, verifier_seed).is_some()
    }

    fn replay_claimless(
        commitment: &crate::c61_whir_reference::C61Commitment,
        proof: &p3_whir_c61::pcs::zk::ZkWhirProof<
            Goldilocks,
            BinomialExtensionField<Goldilocks, 2>,
            crate::c61_whir_reference::C61Mmcs,
        >,
        point: &Point<C61P3Fp2>,
        verifier_seed: [u8; 32],
    ) -> Option<ClaimlessWhirVerifierClosure<C61P3Fp2>> {
        let mut challenger = challenger(verifier_seed);
        let config = config_for::<C63SeparatedSizingChallenger>(point.num_variables());
        let mmcs = c61_reference_mmcs();
        challenger.observe(commitment.clone());
        challenger.observe_algebra_slice(point.as_slice());
        let verifier = HidingWhirVerifier::new(&config, &mmcs);
        catch_unwind(AssertUnwindSafe(|| {
            verifier.verify_claimless(
                proof,
                commitment,
                std::slice::from_ref(point),
                &mut challenger,
            )
        }))
        .ok()?
        .ok()
    }

    #[allow(clippy::too_many_arguments)]
    fn close_authenticated_limb_pair<MT>(
        prepared: C63AuthenticatedWhirPreparedLimbPair,
        outputs: [&ClaimlessWhirProverOutput<Goldilocks, C61P3Fp2, MT>; 2],
        closures: [&C63ClaimlessWhirVerifierClosure; 2],
        target_values: [Fp2; 2],
        target_tags: [Fp2; 2],
        context: &mut VerifierCtx,
        lane: C63AuthenticatedWhirLane,
        mask_range: C63AuthenticatedWhirMaskRange,
        transcript_seed: [u8; 32],
    ) -> Result<(ProverAuthed, VerifierKey, C61AuthenticatedWhirBaseProof), String>
    where
        MT: Mmcs<Goldilocks>,
    {
        for limb in 0..2 {
            if outputs[limb].claim_weights.len() != 1
                || c61_volta_fp2_from_p3(outputs[limb].claim_weights[0])
                    != closures[limb].claim_weight
                || c61_volta_fp2_from_p3(outputs[limb].target.coefficient)
                    != closures[limb].target.coefficient
                || c61_volta_fp2_from_p3(outputs[limb].target.constant)
                    != closures[limb].target.constant
                || c61_volta_fp2_from_p3(outputs[limb].base_case.combined)
                    != closures[limb].combined
                || c61_volta_fp2_from_p3(outputs[limb].base_case.shifted_masked_claim)
                    != closures[limb].shifted_masked_claim
                || c61_volta_fp2_from_p3(outputs[limb].base_case.gamma) != closures[limb].gamma
            {
                return Err("C6.3 WHIR limb prover/verifier closure differs".to_owned());
            }
        }
        let targets: [ProverAuthed; 2] =
            std::array::from_fn(|limb| ProverAuthed::new(target_values[limb], target_tags[limb]));
        let basis = Fp2::new(Fp::ZERO, Fp::ONE);
        let target = targets[0].add(targets[1].scale(basis));
        let mut prover_transcript = Transcript::new_fiat_shamir(transcript_seed)?;
        let provider_closure = finish_c63_authenticated_whir_limb_pair(
            prepared,
            std::array::from_fn(|limb| C63AuthenticatedWhirNormalizedLimb {
                combined: c61_volta_fp2_from_p3(outputs[limb].base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(
                    outputs[limb].base_case.shifted_masked_claim,
                ),
                gamma: c61_volta_fp2_from_p3(outputs[limb].base_case.gamma),
                affine: C61AuthenticatedWhirAffineClaim {
                    coefficient: c61_volta_fp2_from_p3(outputs[limb].target.coefficient),
                    constant: c61_volta_fp2_from_p3(outputs[limb].target.constant),
                },
                claim_weight: c61_volta_fp2_from_p3(outputs[limb].claim_weights[0]),
            }),
            target,
            &mut prover_transcript,
        )
        .map_err(|error| error.to_string())?;

        let target_keys: [VerifierKey; 2] = std::array::from_fn(|limb| {
            VerifierKey::new(target_tags[limb] + context.delta * target_values[limb])
        });
        let target_key = target_keys[0].add(target_keys[1].scale(basis));
        verify_c63_claimless_whir_limb_pair(
            [*closures[0], *closures[1]],
            target_key,
            provider_closure.proof,
            context,
            lane,
            mask_range,
            transcript_seed,
        )?;
        Ok((target, target_key, provider_closure.proof))
    }

    fn replay_projected_claimless(
        mmcs: &C63ProjectedMmcs,
        link: Option<&C63EncodedSketchAtoYLink>,
        commitment: &crate::c61_whir_reference::C61Commitment,
        proof: &p3_whir_c61::pcs::zk::ZkWhirProof<
            Goldilocks,
            BinomialExtensionField<Goldilocks, 2>,
            C63ProjectedMmcs,
        >,
        point: &Point<C61P3Fp2>,
        verifier_seed: [u8; 32],
    ) -> Option<p3_whir_c61::pcs::zk::ClaimlessWhirVerifierClosure<C61P3Fp2>> {
        let mut challenger = challenger(verifier_seed);
        let config = config::<C63SeparatedSizingChallenger>();
        let (_, contexts) = C63EncodedSketchAtoYContext::sample_pair_after_roots(
            mmcs.context.predecessor_d.clone(),
            mmcs.context.predecessor_a.clone(),
            mmcs.context.successor_d.clone(),
            mmcs.context.successor_a.clone(),
            mmcs.context.old_len,
            mmcs.context.dimensions.height,
            &mut challenger,
        )
        .ok()?;
        if &contexts[mmcs.context.limb] != mmcs.context.as_ref() {
            return None;
        }
        challenger.observe(commitment.clone());
        challenger.observe_algebra_slice(point.as_slice());
        let verifier = HidingWhirVerifier::new(&config, mmcs);
        catch_unwind(AssertUnwindSafe(|| match link {
            Some(link) => verifier.verify_claimless_with_initial_link(
                proof,
                commitment,
                std::slice::from_ref(point),
                link,
                &mut challenger,
            ),
            None => verifier.verify_claimless(
                proof,
                commitment,
                std::slice::from_ref(point),
                &mut challenger,
            ),
        }))
        .ok()?
        .ok()
    }

    /// Malicious-prover fixture: it uses the honest cached fixed base in the
    /// extra equation while still sending authenticated rows from a different
    /// accepted `A`. This preserves the linked proof shape and challenge
    /// schedule, so rejection cannot come from switching no-link/link modes.
    struct ForgedFixedBaseLink<'a> {
        fixed_base: &'a DenseMatrix<Goldilocks>,
    }

    impl ZkWhirInitialOracleLink<Goldilocks, C61P3Fp2, C63ProjectedMmcs> for ForgedFixedBaseLink<'_> {
        fn required(&self) -> bool {
            true
        }

        fn folded_mask_values(
            &self,
            opening: &QueryOpenings<Goldilocks, C61P3Fp2, C63ProjectedMultiProof>,
            indices: &[usize],
            randomness: &Point<C61P3Fp2>,
        ) -> Option<Vec<C61P3Fp2>> {
            let QueryOpenings::Base(opening) = opening else {
                return None;
            };
            if opening.proof.1.is_none()
                || opening.rows.len() != indices.len()
                || self.fixed_base.width != C63_ENCODED_SKETCH_FOLDED_POSITIONS
            {
                return None;
            }
            opening
                .rows
                .iter()
                .zip(indices)
                .map(|(randomized, &index)| {
                    let start = index.checked_mul(self.fixed_base.width)?;
                    let fixed = self.fixed_base.values.get(start..start + self.fixed_base.width)?;
                    if randomized.len() != fixed.len() {
                        return None;
                    }
                    let difference: Vec<Goldilocks> =
                        randomized.iter().zip(fixed).map(|(&y, &a)| y - a).collect();
                    Some(Poly::new(difference).eval_base(randomness))
                })
                .collect()
        }
    }

    #[test]
    fn preencoded_tensor_matches_normal_encode_and_keeps_fresh_masks() {
        assert_eq!(C63_ENCODED_SKETCH_PHYSICAL_ROWS, 1 << 19);
        assert_eq!(C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH, 32);
        assert_eq!(C63_ENCODED_SKETCH_INDEPENDENT_A_QUERIES, 490);

        let dft = Radix2DFTSmallBatch::default();
        let mmcs = c61_reference_mmcs();
        let config = config::<C63SeparatedSizingChallenger>();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);

        let columns = (0..C63_BOLT_COLUMNS)
            .map(|column| {
                Poly::new(
                    (0..1usize << TEST_NUM_VARIABLES)
                        .map(|row| {
                            Goldilocks::from_u64((row as u64 + 3) * (column as u64 * 2 + 5) + 11)
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let encoded_columns =
            columns.iter().map(|column| prover.c62_fixed_base_encoding(column)).collect::<Vec<_>>();
        let paired = c63_pack_encoded_sketch_rows_reference(&encoded_columns).unwrap();
        for row in 0..paired.values.len() / paired.width {
            for column in 0..C63_BOLT_COLUMNS {
                for folded_position in 0..C63_ENCODED_SKETCH_FOLDED_POSITIONS {
                    assert_eq!(
                        paired.values[row * paired.width
                            + column * C63_ENCODED_SKETCH_FOLDED_POSITIONS
                            + folded_position],
                        encoded_columns[column].values
                            [row * C63_ENCODED_SKETCH_FOLDED_POSITIONS + folded_position],
                    );
                }
            }
        }

        let rho = std::array::from_fn(|column| {
            Fp2::new(Fp::new(column as u64 * 7 + 2), Fp::new(column as u64 * 11 + 3))
        });
        let mut projected_messages = Vec::new();
        let mut projected_encodings = Vec::new();
        for limb in 0..2 {
            let message = c63_project_decoded_sketch_limb_reference(&columns, &rho, limb).unwrap();
            let projected = c63_project_encoded_sketch_limb_reference(&paired, &rho, limb).unwrap();
            let ordinary = prover.c62_fixed_base_encoding(&message);
            c63_check_preencoded_link_reference(&projected, &ordinary).unwrap();
            projected_messages.push(message);
            projected_encodings.push(projected);
        }
        for tape in 0..2 {
            for limb in 0..2 {
                let message =
                    c63_project_decoded_sketch_tape_limb_reference(&columns, &rho, tape, limb)
                        .unwrap();
                let projected =
                    c63_project_encoded_sketch_tape_limb_reference(&paired, &rho, tape, limb)
                        .unwrap();
                c63_check_preencoded_link_reference(
                    &projected,
                    &prover.c62_fixed_base_encoding(&message),
                )
                .unwrap();
            }
        }

        let (a_root, a_data) = mmcs.commit_matrix(paired.clone());
        let authenticated_row = 17usize;
        let (opened, frontier) = mmcs.open_multi_batch(&[authenticated_row], &a_data);
        let dimensions = [Dimensions {
            width: C63_ENCODED_SKETCH_PHYSICAL_ROW_WIDTH,
            height: 1 << TEST_NUM_VARIABLES,
        }];
        mmcs.verify_multi_batch(&a_root, &dimensions, &[authenticated_row], &opened, &frontier)
            .unwrap();
        let mut changed_opening = opened;
        changed_opening[0][0][9] += Goldilocks::ONE;
        assert!(mmcs
            .verify_multi_batch(
                &a_root,
                &dimensions,
                &[authenticated_row],
                &changed_opening,
                &frontier,
            )
            .is_err());

        let mut changed_paired = paired.clone();
        changed_paired.values[authenticated_row * changed_paired.width + 9] += Goldilocks::ONE;
        let changed_projection =
            c63_project_encoded_sketch_limb_reference(&changed_paired, &rho, 0).unwrap();
        assert!(c63_check_preencoded_link_reference(&changed_projection, &projected_encodings[0],)
            .is_err());

        let point = Point::new(
            (0..TEST_NUM_VARIABLES)
                .map(|index| C61P3Fp2::from_u64(index as u64 * 13 + 5))
                .collect(),
        );
        let evaluation = projected_messages[0].eval_base(&point);
        let verifier_seed = [0xA3; 32];
        let mut roots_and_proofs = Vec::new();
        for rng_seed in [0xC6_3001, 0xC6_3002] {
            let mut challenger = challenger(verifier_seed);
            let mut rng = StdRng::seed_from_u64(rng_seed);
            let (commitment, data) = prover.commit_c62_cached_fixed_base(
                projected_messages[0].clone(),
                &projected_encodings[0],
                &mut challenger,
                &mut rng,
            );
            challenger.observe_algebra_slice(point.as_slice());
            let output = prover.prove_claimless(
                data,
                &[(point.clone(), evaluation)],
                C61P3Fp2::ZERO,
                &mut challenger,
                &mut rng,
            );
            roots_and_proofs.push((commitment, output.proof));
        }
        assert_ne!(roots_and_proofs[0].0, roots_and_proofs[1].0);
        for (commitment, proof) in &roots_and_proofs {
            assert!(verify_claimless(commitment, proof, &point, verifier_seed));
        }
    }

    #[test]
    fn encoded_sketch_a_to_y_link_rejects_substituted_fixed_base() {
        let dft = Radix2DFTSmallBatch::default();
        let base_mmcs = c61_reference_mmcs();
        let config = config::<C63SeparatedSizingChallenger>();
        let base_prover = HidingWhirProver::new(&config, &dft, &base_mmcs);
        let columns = (0..C63_BOLT_COLUMNS)
            .map(|column| {
                Poly::new(
                    (0..1usize << TEST_NUM_VARIABLES)
                        .map(|row| {
                            Goldilocks::from_u64((row as u64 + 7) * (column as u64 * 3 + 2) + 19)
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();
        let mut systematic_values =
            Vec::with_capacity((1 << TEST_NUM_VARIABLES) * C63_BOLT_COLUMNS);
        for row in 0..1 << TEST_NUM_VARIABLES {
            for column in &columns {
                systematic_values.push(column.as_slice()[row]);
            }
        }
        let (accepted_d_root, _) =
            base_mmcs.commit_matrix(DenseMatrix::new(systematic_values, C63_BOLT_COLUMNS));

        let encoded_columns = columns
            .iter()
            .map(|column| base_prover.c62_fixed_base_encoding(column))
            .collect::<Vec<_>>();
        let honest_a = c63_pack_encoded_sketch_rows_reference(&encoded_columns).unwrap();
        let predecessor_a: DenseMatrix<Goldilocks> = DenseMatrix::new(
            (0..honest_a.values.len())
                .map(|index| Goldilocks::from_u64(31 + index as u64 * 7))
                .collect(),
            honest_a.width,
        );
        let successor_a = DenseMatrix::new(
            predecessor_a
                .values
                .iter()
                .zip(&honest_a.values)
                .map(|(&predecessor, &delta)| predecessor + delta)
                .collect(),
            honest_a.width,
        );
        let (predecessor_a_root, predecessor_a_data) = base_mmcs.commit_matrix(predecessor_a);
        let (honest_a_root, honest_a_data) = base_mmcs.commit_matrix(successor_a);
        let verifier_seed = [0x63; 32];
        let mut prover_challenger = challenger(verifier_seed);
        let (honest_rho, [honest_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                accepted_d_root.clone(),
                predecessor_a_root.clone(),
                accepted_d_root.clone(),
                honest_a_root.clone(),
                1,
                honest_a.values.len() / honest_a.width,
                &mut prover_challenger,
            )
            .unwrap();
        let honest_message =
            c63_project_decoded_sketch_limb_reference(&columns, &honest_rho, 0).unwrap();
        let honest_fixed_base = base_prover.c62_fixed_base_encoding(&honest_message);
        let projected_mmcs = C63ProjectedMmcs::new(honest_context);
        let link = projected_mmcs.link();
        let projected_prover = HidingWhirProver::new(&config, &dft, &projected_mmcs);
        let point = Point::new(
            (0..TEST_NUM_VARIABLES)
                .map(|index| C61P3Fp2::from_u64(index as u64 * 17 + 4))
                .collect(),
        );
        let honest_evaluation = honest_message.eval_base(&point);

        // Honest opt-in execution: the opened row difference is the encoding
        // of exactly the fresh initial-oracle randomness.
        let mut rng = StdRng::seed_from_u64(0xA63_0001);
        let (honest_root, mut honest_data) = projected_prover.commit_c62_cached_fixed_base(
            honest_message,
            &honest_fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        projected_mmcs
            .attach_encoded_sketch_a(
                &mut honest_data.merkle,
                Some((&predecessor_a_root, predecessor_a_data)),
                &honest_a_root,
                honest_a_data,
            )
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());
        let honest = projected_prover.prove_claimless_with_initial_link(
            honest_data,
            &[(point.clone(), honest_evaluation)],
            C61P3Fp2::ZERO,
            &link,
            &mut prover_challenger,
            &mut rng,
        );
        let honest_closure = replay_projected_claimless(
            &projected_mmcs,
            Some(&link),
            &honest_root,
            &honest.proof,
            &point,
            verifier_seed,
        )
        .unwrap();
        assert_eq!(honest_closure.claim_weights, honest.claim_weights);
        assert_eq!(honest_closure.target, honest.target);
        assert_eq!(honest_closure.base_case, honest.base_case);

        // Attack fixture: the accepted A root encodes a different tensor,
        // while the cached fixed base remains C(u) for the accepted D root.
        let mut substituted_columns = columns.clone();
        substituted_columns[0].as_mut_slice()[0] += Goldilocks::ONE;
        substituted_columns[0].as_mut_slice()[1 << (TEST_NUM_VARIABLES - 1)] += Goldilocks::ONE;
        let substituted_encoded = substituted_columns
            .iter()
            .map(|column| base_prover.c62_fixed_base_encoding(column))
            .collect::<Vec<_>>();
        let substituted_a = c63_pack_encoded_sketch_rows_reference(&substituted_encoded).unwrap();
        let (substituted_a_root, substituted_a_data) =
            base_mmcs.commit_matrix(substituted_a.clone());
        let mut prover_challenger = challenger(verifier_seed);
        let (attack_rho, [attack_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                accepted_d_root.clone(),
                substituted_a_root.clone(),
                accepted_d_root,
                substituted_a_root.clone(),
                0,
                substituted_a.values.len() / substituted_a.width,
                &mut prover_challenger,
            )
            .unwrap();
        let attack_message =
            c63_project_decoded_sketch_limb_reference(&columns, &attack_rho, 0).unwrap();
        let fixed_base = base_prover.c62_fixed_base_encoding(&attack_message);
        let substituted_projection =
            c63_project_encoded_sketch_limb_reference(&substituted_a, &attack_rho, 0).unwrap();
        assert!(substituted_projection
            .values
            .iter()
            .zip(&fixed_base.values)
            .all(|(substituted, honest)| substituted != honest));
        let attack_mmcs = C63ProjectedMmcs::new(attack_context);
        let attack_link = attack_mmcs.link();
        let attack_prover = HidingWhirProver::new(&config, &dft, &attack_mmcs);
        let attack_evaluation = attack_message.eval_base(&point);

        let mut rng = StdRng::seed_from_u64(0xA63_0002);
        let (attack_root, mut attack_data) = attack_prover.commit_c62_cached_fixed_base(
            attack_message.clone(),
            &fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        attack_mmcs
            .attach_encoded_sketch_a(
                &mut attack_data.merkle,
                None,
                &substituted_a_root,
                substituted_a_data,
            )
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());
        let attack = attack_prover.prove_claimless(
            attack_data,
            &[(point.clone(), attack_evaluation)],
            C61P3Fp2::ZERO,
            &mut prover_challenger,
            &mut rng,
        );

        // The historical/plain seam authenticates both supplied roots but has
        // no equation between them, so the substituted base is accepted.
        let plain_closure = replay_projected_claimless(
            &attack_mmcs,
            None,
            &attack_root,
            &attack.proof,
            &point,
            verifier_seed,
        )
        .unwrap();
        assert_eq!(plain_closure.claim_weights, attack.claim_weights);
        assert_eq!(plain_closure.target, attack.target);
        assert_eq!(plain_closure.base_case, attack.base_case);

        // Build a malicious proof with the linked coefficient count and exact
        // challenge schedule. Its prover-side link pretends the accepted A row
        // was the honest fixed base; the proof still carries and authenticates
        // the substituted A rows.
        let (linked_a_root, linked_a_data) = base_mmcs.commit_matrix(substituted_a);
        assert_eq!(linked_a_root, substituted_a_root);
        let mut prover_challenger = challenger(verifier_seed);
        let (replayed_rho, [replayed_context, _]) =
            C63EncodedSketchAtoYContext::sample_pair_after_roots(
                attack_mmcs.context.predecessor_d.clone(),
                attack_mmcs.context.predecessor_a.clone(),
                attack_mmcs.context.successor_d.clone(),
                linked_a_root.clone(),
                0,
                attack_mmcs.context.dimensions.height,
                &mut prover_challenger,
            )
            .unwrap();
        assert_eq!(replayed_rho, attack_rho);
        assert!(replayed_context == *attack_mmcs.context);
        let mut rng = StdRng::seed_from_u64(0xA63_0003);
        let (linked_root, mut linked_data) = attack_prover.commit_c62_cached_fixed_base(
            attack_message,
            &fixed_base,
            &mut prover_challenger,
            &mut rng,
        );
        attack_mmcs
            .attach_encoded_sketch_a(&mut linked_data.merkle, None, &linked_a_root, linked_a_data)
            .unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());

        let pcg_seed = [0xA6; 32];
        let delta = Fp2::new(Fp::new(101), Fp::new(103));
        let target_tag = Fp2::new(Fp::new(107), Fp::new(109));
        let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
        let mask_range = C61AuthenticatedWhirMaskRange { stage: 63, slot: 0, range_start: 0 };
        let mut correlations = CorrelationStream::new(pcg_seed);
        let prepared =
            prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations).unwrap();
        let forged_link = ForgedFixedBaseLink { fixed_base: &fixed_base };
        let linked_attack = attack_prover.prove_claimless_with_initial_link(
            linked_data,
            &[(point.clone(), attack_evaluation)],
            c61_p3_fp2_from_volta(prepared.value()),
            &forged_link,
            &mut prover_challenger,
            &mut rng,
        );

        // The linked WHIR proof remains structurally valid, but the verifier
        // projects the authenticated substituted A rows. The existing
        // designated ZeroOpen must therefore reject the forged terminal tag.
        let linked_closure = replay_projected_claimless(
            &attack_mmcs,
            Some(&attack_link),
            &linked_root,
            &linked_attack.proof,
            &point,
            verifier_seed,
        )
        .expect("forged linked shape should reach the designated closure");
        let target_value = c61_volta_fp2_from_p3(attack_evaluation);
        let target = ProverAuthed::new(target_value, target_tag);
        let aggregate_target = target.scale(c61_volta_fp2_from_p3(linked_attack.claim_weights[0]));
        let provider_affine = C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(linked_attack.target.coefficient),
            constant: c61_volta_fp2_from_p3(linked_attack.target.constant),
        };
        let mut prover_terminal_transcript = Transcript::new_fiat_shamir([0xB6; 32]).unwrap();
        let provider_closure = finish_c61_authenticated_whir_base(
            prepared,
            C61AuthenticatedWhirProverFinishInput {
                combined: c61_volta_fp2_from_p3(linked_attack.base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(
                    linked_attack.base_case.shifted_masked_claim,
                ),
                gamma: c61_volta_fp2_from_p3(linked_attack.base_case.gamma),
                target: provider_affine.authenticate_prover(aggregate_target),
            },
            &mut prover_terminal_transcript,
        )
        .unwrap();

        let target_key = VerifierKey::new(target_tag + delta * target_value);
        let aggregate_key =
            target_key.scale(c61_volta_fp2_from_p3(linked_closure.claim_weights[0]));
        let verifier_affine = C61AuthenticatedWhirAffineClaim {
            coefficient: c61_volta_fp2_from_p3(linked_closure.target.coefficient),
            constant: c61_volta_fp2_from_p3(linked_closure.target.constant),
        };
        let mut verifier_context = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_terminal_transcript = Transcript::new_fiat_shamir([0xB6; 32]).unwrap();
        let terminal_error = verify_c61_authenticated_whir_base(
            C61AuthenticatedWhirVerifierInput {
                id,
                mask_range,
                combined: c61_volta_fp2_from_p3(linked_closure.base_case.combined),
                shifted_masked_claim: c61_volta_fp2_from_p3(
                    linked_closure.base_case.shifted_masked_claim,
                ),
                gamma: c61_volta_fp2_from_p3(linked_closure.base_case.gamma),
                target: verifier_affine.derive_verifier_key(aggregate_key, delta),
            },
            provider_closure.proof,
            &mut verifier_context,
            &mut verifier_terminal_transcript,
        )
        .unwrap_err();
        assert_eq!(terminal_error.to_string(), "C6AWH1 authenticated target ZeroOpen failed");
    }

    #[cfg(feature = "cuda")]
    #[test]
    #[ignore = "requires the production ABI44 CUDA library and one A100"]
    fn production_resident_projected_lane_verifies_on_cpu() {
        let total_started = Instant::now();
        let setup_started = Instant::now();
        let sparse_setup = C63SparseSetupReference::sample(
            C63_PRODUCTION_SETUP_SEED,
            C63_BOLT_ROWS,
            C63_BOLT_SKETCH_ROWS,
            C63_BOLT_LDPC_COLUMN_DEGREE,
            C63_BOLT_LDPC_CHECK_DEGREE,
        )
        .unwrap();
        let backend = Backend::cuda_resident().expect("initialize ABI44 resident CUDA backend");
        let guard =
            C62GpuResourceGuard::for_lane(19, 1, 1 << 19, 19, 1, true, 40u64 << 30).unwrap();
        let base_mmcs = C62GpuMmcs::new(backend, 19, guard).unwrap();
        let setup = C63GpuSetupOwner::install(&base_mmcs, &sparse_setup).unwrap();
        let setup_ms = setup_started.elapsed().as_millis();

        let state_started = Instant::now();
        let backend = base_mmcs.backend();
        const ACCEPTED_LEN: usize = 150;
        let tapes: [Vec<u64>; 2] = std::array::from_fn(|tape| {
            (0..ACCEPTED_LEN * 2 * 12 * 768)
                .map(|index| 1 + tape as u64 * 1_000_003 + index as u64 * 17)
                .collect()
        });
        let (tape0, tape1) = {
            let mut gpu = backend.lock().unwrap();
            (gpu.upload_new_device(&tapes[0]).unwrap(), gpu.upload_new_device(&tapes[1]).unwrap())
        };
        let profile_digest = [0x73; 32];
        let state = Arc::new(
            C63GpuStateOwner::propose_append(
                &setup,
                None,
                profile_digest,
                1,
                DeviceSlice::new(&tape0, 0, tape0.len()).unwrap(),
                DeviceSlice::new(&tape1, 0, tape1.len()).unwrap(),
                &vec![
                    C63GpuTileMetadata {
                        birth_epoch: 1,
                        allocation_binding_digest: [0x71; 32],
                        source_schedule_digest: [0x72; 32],
                    };
                    ACCEPTED_LEN
                ],
            )
            .unwrap(),
        );
        {
            let mut gpu = backend.lock().unwrap();
            gpu.free_device(tape0).unwrap();
            gpu.free_device(tape1).unwrap();
            gpu.begin_measurement().unwrap();
        }
        let state_ms = state_started.elapsed().as_millis();

        let verifier_seed = [0x63; 32];
        let predecessor_frontier = C63CorrectionAppendFrontier::zero();
        let predecessor_d =
            C61Commitment::new(vec![predecessor_frontier.state_root(profile_digest, 0).unwrap()]);
        let predecessor_a = C61Commitment::new(vec![[0x74; 32]]);
        let accepted_d = C61Commitment::new(vec![state.correction_root()]);
        let accepted_a = C61Commitment::new(vec![state.encoded_sketch_root()]);
        let mut prover_challenger = challenger(verifier_seed);
        let (rho, [context, _]) = C63EncodedSketchAtoYContext::sample_pair_after_roots(
            predecessor_d,
            predecessor_a,
            accepted_d,
            accepted_a,
            0,
            C63_ENCODED_SKETCH_PHYSICAL_ROWS,
            &mut prover_challenger,
        )
        .unwrap();
        let cpu_context = context.clone();

        let projection_started = Instant::now();
        let mut projected = state.project_transition_messages(None, rho).unwrap();
        let projection_ms = projection_started.elapsed().as_millis();
        let spot_rows = c63_sample_systematic_query_rows(
            &mut prover_challenger,
            C63_BOLT_ROW_LOG2 as usize,
            C63_SYSTEMATIC_SPOT_QUERIES,
        )
        .unwrap();
        let correction_started = Instant::now();
        let correction_opening = state.open_correction_rows(&spot_rows).unwrap();
        let correction_artifact =
            correction_opening.encode(0, state.accepted_len(), &spot_rows).unwrap();
        let (spots, _) = c63_verify_correction_rows_reference(
            predecessor_frontier.state_root(profile_digest, 0).unwrap(),
            state.correction_root(),
            &predecessor_frontier,
            profile_digest,
            state.epoch(),
            0,
            state.accepted_len(),
            &spot_rows,
            &rho,
            &correction_opening,
        )
        .unwrap();
        let spots = spots
            .into_iter()
            .map(|(row, value)| C63SystematicSpot { row, value })
            .collect::<Vec<_>>();
        let correction_ms = correction_started.elapsed().as_millis();
        let h_started = Instant::now();
        let h = C63SparseSketchReference::new(
            C63_BOLT_ROWS,
            C63_BOLT_SKETCH_ROWS,
            sparse_setup.sketch_edges(),
        )
        .unwrap();
        let h_prepare_ms = h_started.elapsed().as_millis();
        let output_point = (0..19)
            .map(|index| Fp2::new(Fp::new(211 + index as u64), Fp::new(251 + index as u64)))
            .collect::<Vec<_>>();
        let u_opening = projected.evaluate_combined_sketch(&output_point).unwrap();
        let sparse_statement =
            C63SparseHClosureStatement::new(state.correction_root(), output_point).unwrap();
        let sparse_seeds = [[0x91; 32], [0x92; 32]];
        let sparse_deltas =
            [Fp2::new(Fp::new(97), Fp::new(101)), Fp2::new(Fp::new(103), Fp::new(107))];
        let sparse_transcript_seed = [0x93; 32];
        let mut sparse_streams = sparse_seeds.map(CorrelationStream::new);
        let mut sparse_prover_transcript = Transcript::new(sparse_transcript_seed);
        let sparse_started = Instant::now();
        let sparse_proof = prove_c63_sparse_h_closure_with_spots_resident(
            backend.clone(),
            &h,
            projected.combined_systematic().unwrap(),
            u_opening,
            &sparse_statement,
            &spots,
            &mut sparse_streams,
            &mut sparse_prover_transcript,
        )
        .unwrap();
        let sparse_prove_ms = sparse_started.elapsed().as_millis();
        let sparse_verify_started = Instant::now();
        let mut sparse_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        let mut sparse_verifier_transcript = Transcript::new(sparse_transcript_seed);
        let sparse_audit = verify_c63_sparse_h_closure_from_whir_openings_reference(
            &h,
            u_opening,
            &sparse_statement,
            &spots,
            &sparse_proof,
            &mut sparse_contexts,
            &mut sparse_verifier_transcript,
            |point| {
                projected.evaluate_combined_systematic(point).map_err(|error| {
                    crate::c63_sparse_h_closure::C63SparseHClosureError::new(error.to_string())
                })
            },
        )
        .unwrap();
        let sparse_verify_ms = sparse_verify_started.elapsed().as_millis();
        assert_eq!(sparse_audit.sumcheck_point.len(), 22);
        let lane_prepare_started = Instant::now();
        let message = projected.take_sketch(0).unwrap();
        let encoded = projected.take_encoded_sketch(0).unwrap();
        drop(projected);
        let key = C62ProviderCacheKey {
            model_digest: [0x31; 32],
            protocol_digest: [0x32; 32],
            parameter_digest: [0x33; 32],
            content_digest: [0x34; 32],
            field_tag: C62_GPU_WHIR_FIELD_TAG,
            encoder_version: C62_GPU_WHIR_EXECUTOR_VERSION,
            num_variables: 19,
            folding: 1,
            height: 1 << 19,
        };
        let cache = base_mmcs.prepare_linked_fixed_base_resident(key, message, encoded).unwrap();
        let point_values = (0..19)
            .map(|index| Fp2::new(Fp::new(41 + index as u64), Fp::new(71 + index as u64)))
            .collect::<Vec<_>>();
        let evaluation = base_mmcs.evaluate_fixed_base(&cache, &point_values).unwrap();
        let point = Point::new(point_values.iter().copied().map(c61_p3_fp2_from_volta).collect());
        let lane_prepare_ms = lane_prepare_started.elapsed().as_millis();

        let config = c63_whir_config(19).unwrap();
        let projected_mmcs = C63ProjectedGpuMmcs::new(base_mmcs.clone(), context);
        let link = projected_mmcs.link();
        let dft = Radix2DFTSmallBatch::default();
        let prover = HidingWhirProver::new(&config, &dft, &projected_mmcs);
        let committer = C62GpuWhirCommitter::provider_cached(base_mmcs.clone(), Arc::clone(&cache));
        let prove_started = Instant::now();
        let mut rng = StdRng::seed_from_u64(0xC6_3301);
        let (commitment, mut data) = prover
            .commit_resident_with_oracle(1 << 19, &committer, &mut prover_challenger, &mut rng)
            .unwrap();
        projected_mmcs.attach_encoded_sketch_a(&mut data.merkle, None, Arc::clone(&state)).unwrap();
        prover_challenger.observe_algebra_slice(point.as_slice());
        let output = prover
            .prove_claimless_with_oracle_and_initial_link(
                data,
                &[(point.clone(), c61_p3_fp2_from_volta(evaluation))],
                C61P3Fp2::ZERO,
                &committer,
                &link,
                &mut prover_challenger,
                &mut rng,
            )
            .unwrap();
        let prove_ms = prove_started.elapsed().as_millis();
        let stats = backend.lock().unwrap().finish_measurement().unwrap();

        let artifact =
            encode_c63_whir_projected_artifact_with_config(19, &config, &commitment, &output.proof)
                .unwrap();
        let verify_started = Instant::now();
        let (decoded_commitment, decoded_proof) =
            decode_c63_whir_projected_artifact_with_config(&artifact, 19, &config).unwrap();
        let verifier_mmcs = C63ProjectedMmcs::new(cpu_context);
        let verifier_link = verifier_mmcs.link();
        let mut verifier_challenger = challenger(verifier_seed);
        let (_, replayed_contexts) = C63EncodedSketchAtoYContext::sample_pair_after_roots(
            verifier_mmcs.context.predecessor_d.clone(),
            verifier_mmcs.context.predecessor_a.clone(),
            verifier_mmcs.context.successor_d.clone(),
            verifier_mmcs.context.successor_a.clone(),
            verifier_mmcs.context.old_len,
            C63_ENCODED_SKETCH_PHYSICAL_ROWS,
            &mut verifier_challenger,
        )
        .unwrap();
        assert!(replayed_contexts[0] == *verifier_mmcs.context);
        let replayed_spot_rows = c63_sample_systematic_query_rows(
            &mut verifier_challenger,
            C63_BOLT_ROW_LOG2 as usize,
            C63_SYSTEMATIC_SPOT_QUERIES,
        )
        .unwrap();
        assert_eq!(replayed_spot_rows, spot_rows);
        verifier_challenger.observe(decoded_commitment.clone());
        verifier_challenger.observe_algebra_slice(point.as_slice());
        let verifier = HidingWhirVerifier::new(&config, &verifier_mmcs);
        let closure = verifier
            .verify_claimless_with_initial_link(
                &decoded_proof,
                &decoded_commitment,
                std::slice::from_ref(&point),
                &verifier_link,
                &mut verifier_challenger,
            )
            .unwrap();
        let verify_ms = verify_started.elapsed().as_millis();
        assert_eq!(closure.claim_weights, output.claim_weights);
        assert_eq!(closure.target, output.target);
        assert_eq!(closure.base_case, output.base_case);
        eprintln!(
            "c63_resident_projected_lane setup_ms={setup_ms} state_ms={state_ms} projection_ms={projection_ms} correction_ms={correction_ms} correction_rows={} correction_bytes={} h_prepare_ms={h_prepare_ms} sparse_prove_ms={sparse_prove_ms} sparse_verify_ms={sparse_verify_ms} sparse_proof_bytes={} lane_prepare_ms={lane_prepare_ms} prove_ms={prove_ms} verify_ms={verify_ms} proof_bytes={} peak_device_bytes={} h2d_bytes={} d2h_bytes={} total_ms={}",
            spots.len(),
            correction_artifact.len(),
            sparse_proof.encode().unwrap().len(),
            artifact.len(),
            stats.peak_device_bytes,
            stats.h2d_bytes,
            stats.d2h_bytes,
            total_started.elapsed().as_millis(),
        );
    }

    #[test]
    fn eight_whir_bodies_feed_authenticated_tape_separated_sparse_h_terminals() {
        const INPUT_LOG2: usize = 13;
        const OUTPUT_LOG2: usize = 10;
        let input_len = 1usize << INPUT_LOG2;
        let output_len = 1usize << OUTPUT_LOG2;
        let edges = (0..input_len as u32)
            .map(|input| C63SparseSketchEdge {
                input,
                socket_ordinal: 0,
                output: input % output_len as u32,
                coefficient: Fp::new(1 + u64::from(input % 17)),
            })
            .collect::<Vec<_>>();
        let h = C63SparseSketchReference::new(input_len, output_len, edges.clone()).unwrap();

        let predecessor_rows = (0..C63_BOLT_LIVE_ROWS_PER_POSITION)
            .map(|row| C63CorrectionRowReference {
                position: 0,
                layer_high: (row >> 9) as u8,
                channel_low: (row & 0x01ff) as u16,
                birth_epoch: 1,
                allocation_binding_digest: [0x21; 32],
                source_schedule_digest: [0x22; 32],
                corrections: [Fp::ZERO; C63_BOLT_COLUMNS],
            })
            .collect::<Vec<_>>();
        let correction_rows = (0..C63_BOLT_LIVE_ROWS_PER_POSITION)
            .map(|row| C63CorrectionRowReference {
                position: 1,
                layer_high: (row >> 9) as u8,
                channel_low: (row & 0x01ff) as u16,
                birth_epoch: 2,
                allocation_binding_digest: [0x31; 32],
                source_schedule_digest: [0x32; 32],
                corrections: std::array::from_fn(|column| {
                    if row & 0x01ff >= 256 && column >= 8 {
                        Fp::ZERO
                    } else {
                        Fp::new(3 + row as u64 * 19 + column as u64 * 23)
                    }
                }),
            })
            .collect::<Vec<_>>();
        let d_columns = (0..C63_BOLT_COLUMNS)
            .map(|column| {
                Poly::new(
                    (0..input_len)
                        .map(|row| {
                            let local = row.checked_sub(C63_BOLT_ROWS_PER_POSITION);
                            Goldilocks::from_u64(
                                local
                                    .and_then(|row| correction_rows.get(row))
                                    .map_or(0, |opened| opened.corrections[column].value()),
                            )
                        })
                        .collect(),
                )
            })
            .collect::<Vec<_>>();

        let s_columns = d_columns
            .iter()
            .map(|column| {
                let mut output = Goldilocks::zero_vec(output_len);
                for edge in &edges {
                    output[edge.output as usize] += column.as_slice()[edge.input as usize]
                        * Goldilocks::from_u64(edge.coefficient.value());
                }
                Poly::new(output)
            })
            .collect::<Vec<_>>();

        let dft = Radix2DFTSmallBatch::default();
        let base_mmcs = c61_reference_mmcs();
        let u_config = config_for::<C63SeparatedSizingChallenger>(OUTPUT_LOG2);
        let u_base_prover = HidingWhirProver::new(&u_config, &dft, &base_mmcs);
        let encoded_s = s_columns
            .iter()
            .map(|column| u_base_prover.c62_fixed_base_encoding(column))
            .collect::<Vec<_>>();
        let paired_a = c63_pack_encoded_sketch_rows_reference(&encoded_s).unwrap();
        let predecessor_a: DenseMatrix<Goldilocks> = DenseMatrix::new(
            (0..paired_a.values.len())
                .map(|index| Goldilocks::from_u64(43 + index as u64 * 5))
                .collect(),
            paired_a.width,
        );
        let successor_a = DenseMatrix::new(
            predecessor_a
                .values
                .iter()
                .zip(&paired_a.values)
                .map(|(&predecessor, &delta)| predecessor + delta)
                .collect(),
            paired_a.width,
        );
        let profile_digest = [0x33; 32];
        let predecessor_tile = c63_correction_tile_root_reference(&predecessor_rows).unwrap();
        let correction_tile = c63_correction_tile_root_reference(&correction_rows).unwrap();
        let correction_root = c63_correction_state_root_reference(
            profile_digest,
            2,
            &[predecessor_tile, correction_tile],
        )
        .unwrap();
        let predecessor_frontier =
            C63CorrectionAppendFrontier::from_tile_roots(&[predecessor_tile]).unwrap();
        let predecessor_correction_root =
            predecessor_frontier.state_root(profile_digest, 1).unwrap();
        let d_root = C61Commitment::new(vec![correction_root]);
        let (a_root, _) = base_mmcs.commit_matrix(successor_a.clone());
        let (predecessor_a_root, _) = base_mmcs.commit_matrix(predecessor_a.clone());
        let predecessor_state = C63VerifierSketchState::for_test(
            profile_digest,
            1,
            predecessor_a_root.roots()[0],
            predecessor_frontier.clone(),
        )
        .unwrap();

        let statement_digest = [0xd1; 32];
        let statement = C63SparseHClosureStatement::new(
            correction_root,
            (0..OUTPUT_LOG2)
                .map(|index| Fp2::new(Fp::new(31 + index as u64), Fp::new(47 + index as u64)))
                .collect(),
        )
        .unwrap();
        let attempt = C6ClientAttempt {
            slot: 0,
            nonce: [0xd0; 32],
            setup_manifest_digest: [0xd2; 32],
            old_head_digest: [0xd3; 32],
            predecessor_certificate_digest: [0; 32],
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    C6CorrelationRange { stage: 1, start: 1_000, count: 1_000 },
                    C6CorrelationRange { stage: 1, start: 2_000, count: 1_000 },
                ],
            },
            workload: C6Workload {
                prompt_tokens: 1,
                decode_tokens: 0,
                old_context: 1,
                new_context: 2,
            },
        };
        let transcript_binding = C63TranscriptBinding::new(
            attempt,
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_a_root.roots()[0],
            correction_root,
            a_root.roots()[0],
            2,
            1,
            2,
        )
        .unwrap();
        let mut rho_challenger = challenger(transcript_binding.rho_seed());
        let (rho, contexts) = C63EncodedSketchAtoYContext::sample_tape_limb_after_roots(
            C61Commitment::new(vec![predecessor_correction_root]),
            predecessor_a_root.clone(),
            d_root,
            a_root.clone(),
            1,
            paired_a.values.len() / paired_a.width,
            &mut rho_challenger,
        )
        .unwrap();
        let m_limbs: [[Poly<Goldilocks>; 2]; 2] = std::array::from_fn(|tape| {
            std::array::from_fn(|limb| {
                c63_project_decoded_sketch_tape_limb_reference(&d_columns, &rho, tape, limb)
                    .unwrap()
            })
        });
        let u_limbs: [[Poly<Goldilocks>; 2]; 2] = std::array::from_fn(|tape| {
            std::array::from_fn(|limb| {
                c63_project_decoded_sketch_tape_limb_reference(&s_columns, &rho, tape, limb)
                    .unwrap()
            })
        });
        let combine_coefficients = |left: &Poly<Goldilocks>, right: &Poly<Goldilocks>| {
            left.as_slice()
                .iter()
                .zip(right.as_slice())
                .map(|(&c0, &c1)| {
                    Fp2::new(Fp::new(c0.as_canonical_u64()), Fp::new(c1.as_canonical_u64()))
                })
                .collect::<Vec<_>>()
        };
        let messages: [Vec<Fp2>; 2] =
            std::array::from_fn(|tape| combine_coefficients(&m_limbs[tape][0], &m_limbs[tape][1]));
        let sketches: [Vec<Fp2>; 2] =
            std::array::from_fn(|tape| combine_coefficients(&u_limbs[tape][0], &u_limbs[tape][1]));
        for tape in 0..2 {
            assert_eq!(h.apply(&messages[tape]).unwrap(), sketches[tape]);
        }

        let m_config = config_for::<C63SeparatedSizingChallenger>(INPUT_LOG2);
        let m_prover = HidingWhirProver::new(&m_config, &dft, &base_mmcs);
        let mask_range = C63AuthenticatedWhirMaskRange { stage: 70, slot: 0, range_start: 0 };
        let sparse_seeds = [[0x91; 32], [0x92; 32]];
        let sparse_deltas =
            [Fp2::new(Fp::new(97), Fp::new(101)), Fp2::new(Fp::new(103), Fp::new(107))];
        let mut whir_streams = sparse_seeds.map(CorrelationStream::new);
        let m_prepared: [C63AuthenticatedWhirPreparedLimbPair; 2] = std::array::from_fn(|tape| {
            prepare_c63_authenticated_whir_limb_pair(
                C63AuthenticatedWhirLane::Systematic,
                mask_range,
                &mut whir_streams[tape],
            )
            .unwrap()
        });
        let u_prepared: [C63AuthenticatedWhirPreparedLimbPair; 2] = std::array::from_fn(|tape| {
            prepare_c63_authenticated_whir_limb_pair(
                C63AuthenticatedWhirLane::Sketch,
                mask_range,
                &mut whir_streams[tape],
            )
            .unwrap()
        });

        let mut initial_roots = [[0u8; 32]; 8];
        let mut m_commits = Vec::with_capacity(4);
        for tape in 0..2 {
            for limb in 0..2 {
                let lane_seed = transcript_binding
                    .lane_seed(&rho, C63AuthenticatedWhirLane::Systematic, tape, limb)
                    .unwrap();
                let mut prover_challenger = challenger(lane_seed);
                let mut rng = StdRng::seed_from_u64(0xC6_3100 + (tape * 2 + limb) as u64);
                let fixed = m_prover.c62_fixed_base_encoding(&m_limbs[tape][limb]);
                let (root, data) = m_prover.commit_c62_cached_fixed_base(
                    m_limbs[tape][limb].clone(),
                    &fixed,
                    &mut prover_challenger,
                    &mut rng,
                );
                initial_roots[tape * 2 + limb] = root.roots()[0];
                m_commits.push((lane_seed, root, data, prover_challenger, rng));
            }
        }

        let mut u_commits = Vec::with_capacity(4);
        for tape in 0..2 {
            for limb in 0..2 {
                let lane_seed = transcript_binding
                    .lane_seed(&rho, C63AuthenticatedWhirLane::Sketch, tape, limb)
                    .unwrap();
                let projected_mmcs = C63ProjectedMmcs::new(contexts[tape][limb].clone());
                let projected_prover = HidingWhirProver::new(&u_config, &dft, &projected_mmcs);
                let fixed =
                    c63_project_encoded_sketch_tape_limb_reference(&paired_a, &rho, tape, limb)
                        .unwrap();
                c63_check_preencoded_link_reference(
                    &fixed,
                    &u_base_prover.c62_fixed_base_encoding(&u_limbs[tape][limb]),
                )
                .unwrap();
                let (recommitted_predecessor_root, predecessor_data) =
                    base_mmcs.commit_matrix(predecessor_a.clone());
                let (recommitted_a_root, a_data) = base_mmcs.commit_matrix(successor_a.clone());
                assert_eq!(recommitted_predecessor_root, predecessor_a_root);
                assert_eq!(recommitted_a_root, a_root);
                let mut prover_challenger = challenger(lane_seed);
                let mut rng = StdRng::seed_from_u64(0xC6_3100 + (4 + tape * 2 + limb) as u64);
                let (root, mut data) = projected_prover.commit_c62_cached_fixed_base(
                    u_limbs[tape][limb].clone(),
                    &fixed,
                    &mut prover_challenger,
                    &mut rng,
                );
                projected_mmcs
                    .attach_encoded_sketch_a(
                        &mut data.merkle,
                        Some((&predecessor_a_root, predecessor_data)),
                        &a_root,
                        a_data,
                    )
                    .unwrap();
                initial_roots[4 + tape * 2 + limb] = root.roots()[0];
                u_commits.push((lane_seed, root, data, prover_challenger, rng, projected_mmcs));
            }
        }

        let query_seed = transcript_binding.query_seed(&rho, &initial_roots).unwrap();
        let mut spot_challenger = challenger(transcript_binding.spot_seed(query_seed).unwrap());
        let spot_rows =
            c63_sample_systematic_query_rows(&mut spot_challenger, INPUT_LOG2, 3).unwrap();
        let (opened_root, correction_opening) = c63_open_correction_rows_reference(
            profile_digest,
            2,
            1,
            &[predecessor_rows, correction_rows.clone()],
            &spot_rows,
        )
        .unwrap();
        assert_eq!(opened_root, correction_root);
        let correction_artifact = correction_opening.encode(1, 2, &spot_rows).unwrap();
        let (spots, successor_frontier) = c63_verify_correction_rows_by_tape_reference(
            predecessor_correction_root,
            correction_root,
            &predecessor_frontier,
            profile_digest,
            2,
            1,
            2,
            &spot_rows,
            &rho,
            &correction_opening,
        )
        .unwrap();
        let spots = spots
            .into_iter()
            .map(|(row, values)| C63TapeSystematicSpot { row, values })
            .collect::<Vec<_>>();
        assert!(spots.iter().all(|spot| {
            (0..2).all(|tape| spot.values[tape] == messages[tape][spot.row as usize])
        }));
        let sparse_transcript_seed = transcript_binding.sparse_seed(query_seed).unwrap();
        let basis = Fp2::new(Fp::ZERO, Fp::ONE);
        let live_cells =
            expected_c6_cache_append_cells(C6PersistentCacheLayout::production(), 1, 2).unwrap();
        let mut authenticated_corrections = Vec::with_capacity(live_cells.len());
        let mut authenticated_correction_keys = Vec::with_capacity(live_cells.len());
        for (ordinal, cell) in live_cells.into_iter().enumerate() {
            let correction = std::array::from_fn(|tape| {
                let index = c63_bolt_correction_index(cell, tape as u8).unwrap();
                correction_rows[index.row as usize & (C63_BOLT_ROWS_PER_POSITION - 1)].corrections
                    [usize::from(index.column)]
            });
            let masks: [Fp; 2] =
                std::array::from_fn(|tape| Fp::new(179 + ordinal as u64 * 11 + tape as u64 * 13));
            let tags: [Fp2; 2] = std::array::from_fn(|tape| {
                Fp2::new(
                    Fp::new(181 + ordinal as u64 * 17 + tape as u64),
                    Fp::new(191 + ordinal as u64 * 19 + tape as u64),
                )
            });
            let source = std::array::from_fn(|tape| {
                ProverAuthed::new(Fp2::from_base(masks[tape] + correction[tape]), tags[tape])
            });
            let mask = std::array::from_fn(|tape| {
                ProverAuthed::new(Fp2::from_base(masks[tape]), tags[tape])
            });
            authenticated_corrections.push(C63AuthenticatedCorrectionProverCell {
                cell,
                correction,
                source,
                mask,
            });
            authenticated_correction_keys.push(C63AuthenticatedCorrectionVerifierCell {
                cell,
                source_keys: std::array::from_fn(|tape| {
                    VerifierKey::new(tags[tape] + sparse_deltas[tape] * source[tape].x)
                }),
                mask_keys: std::array::from_fn(|tape| {
                    VerifierKey::new(tags[tape] + sparse_deltas[tape] * mask[tape].x)
                }),
            });
        }
        let u_limb_tags: [[Fp2; 2]; 2] = std::array::from_fn(|tape| {
            std::array::from_fn(|limb| {
                Fp2::new(
                    Fp::new(131 + (tape * 2 + limb) as u64),
                    Fp::new(149 + (tape * 2 + limb) as u64),
                )
            })
        });
        let m_limb_tags = [[Fp2::ZERO; 2]; 2];
        let u_point = Point::new(
            statement.output_point().iter().rev().copied().map(c61_p3_fp2_from_volta).collect(),
        );
        let u_limb_values: [[Fp2; 2]; 2] = std::array::from_fn(|tape| {
            std::array::from_fn(|limb| {
                c61_volta_fp2_from_p3(u_limbs[tape][limb].eval_base(&u_point))
            })
        });
        let u_claims = std::array::from_fn(|tape| {
            ProverAuthed::new(u_limb_values[tape][0], u_limb_tags[tape][0])
                .add(ProverAuthed::new(u_limb_values[tape][1], u_limb_tags[tape][1]).scale(basis))
        });
        let u_opening_keys: [VerifierKey; 2] = std::array::from_fn(|tape| {
            VerifierKey::new(u_limb_tags[tape][0] + sparse_deltas[tape] * u_limb_values[tape][0])
                .add(
                    VerifierKey::new(
                        u_limb_tags[tape][1] + sparse_deltas[tape] * u_limb_values[tape][1],
                    )
                    .scale(basis),
                )
        });
        let mut sparse_streams = sparse_seeds.map(CorrelationStream::new);
        let mut sparse_prover_transcript = Transcript::new(sparse_transcript_seed);
        let sparse_proof = prove_c63_sparse_h_tape_closure_with_spots_reference(
            &h,
            [&messages[0], &messages[1]],
            [&sketches[0], &sketches[1]],
            u_claims,
            &statement,
            &spots,
            &mut sparse_streams,
            &mut sparse_prover_transcript,
            |tape, point| {
                c63_authenticated_correction_functional_prover_reference(
                    1,
                    2,
                    &authenticated_corrections,
                    &rho,
                    point,
                )
                .map(|openings| openings[tape][0].add(openings[tape][1].scale(basis)))
                .map_err(C63SparseHClosureError::new)
            },
        )
        .unwrap();
        let mut sparse_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        let mut sparse_transcript = Transcript::new(sparse_transcript_seed);
        let sparse_pending = begin_verify_c63_sparse_h_tape_closure_reference(
            &h,
            &statement,
            &spots,
            &sparse_proof,
            &mut sparse_contexts,
            &mut sparse_transcript,
        )
        .unwrap();
        let linked_m_limb_keys = c63_authenticated_correction_functional_verifier_reference(
            1,
            2,
            &authenticated_correction_keys,
            sparse_deltas,
            &rho,
            sparse_pending.sumcheck_point(),
        )
        .unwrap();

        let m_point = Point::new(
            sparse_pending
                .sumcheck_point()
                .iter()
                .rev()
                .copied()
                .map(c61_p3_fp2_from_volta)
                .collect(),
        );

        let mut m_artifacts: [[Vec<u8>; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
        let mut m_close_inputs = Vec::with_capacity(2);
        let mut m_commit_iter = m_commits.into_iter();
        for (tape, prepared) in m_prepared.into_iter().enumerate() {
            let masks = prepared.values();
            let mut outputs = Vec::with_capacity(2);
            let mut closures = Vec::with_capacity(2);
            let mut target_values = [Fp2::ZERO; 2];
            for limb in 0..2 {
                let (lane_seed, root, data, mut prover_challenger, mut rng) =
                    m_commit_iter.next().unwrap();
                let evaluation = m_limbs[tape][limb].eval_base(&m_point);
                prover_challenger.observe_algebra_slice(m_point.as_slice());
                let output = m_prover.prove_claimless(
                    data,
                    &[(m_point.clone(), evaluation)],
                    c61_p3_fp2_from_volta(masks[limb]),
                    &mut prover_challenger,
                    &mut rng,
                );
                let encoded = encode_c63_whir_ordinary_artifact_with_config(
                    INPUT_LOG2,
                    &m_config,
                    &root,
                    &output.proof,
                )
                .unwrap();
                closures.push(
                    verify_c63_whir_ordinary_artifact_with_config_at_point(
                        &encoded,
                        INPUT_LOG2,
                        &m_config,
                        sparse_pending.sumcheck_point(),
                        lane_seed,
                    )
                    .unwrap(),
                );
                m_artifacts[tape][limb] = encoded;
                target_values[limb] = c61_volta_fp2_from_p3(evaluation);
                outputs.push(output);
            }
            m_close_inputs.push((prepared, outputs, closures, target_values));
        }
        assert!(m_commit_iter.next().is_none());

        let mut u_artifacts: [[Vec<u8>; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
        let mut u_close_inputs = Vec::with_capacity(2);
        let mut u_commit_iter = u_commits.into_iter();
        for (tape, prepared) in u_prepared.into_iter().enumerate() {
            let masks = prepared.values();
            let mut outputs = Vec::with_capacity(2);
            let mut closures = Vec::with_capacity(2);
            let mut target_values = [Fp2::ZERO; 2];
            for limb in 0..2 {
                let (lane_seed, root, data, mut prover_challenger, mut rng, projected_mmcs) =
                    u_commit_iter.next().unwrap();
                let link = projected_mmcs.link();
                let projected_prover = HidingWhirProver::new(&u_config, &dft, &projected_mmcs);
                let evaluation = u_limbs[tape][limb].eval_base(&u_point);
                prover_challenger.observe_algebra_slice(u_point.as_slice());
                let output = projected_prover.prove_claimless_with_initial_link(
                    data,
                    &[(u_point.clone(), evaluation)],
                    c61_p3_fp2_from_volta(masks[limb]),
                    &link,
                    &mut prover_challenger,
                    &mut rng,
                );
                let encoded = encode_c63_whir_projected_artifact_with_config(
                    OUTPUT_LOG2,
                    &u_config,
                    &root,
                    &output.proof,
                )
                .unwrap();
                closures.push(
                    verify_c63_whir_projected_artifact_with_config_at_point(
                        &encoded,
                        OUTPUT_LOG2,
                        &u_config,
                        statement.output_point(),
                        contexts[tape][limb].clone(),
                        lane_seed,
                    )
                    .unwrap(),
                );
                u_artifacts[tape][limb] = encoded;
                target_values[limb] = c61_volta_fp2_from_p3(evaluation);
                outputs.push(output);
            }
            u_close_inputs.push((prepared, outputs, closures, target_values));
        }
        assert!(u_commit_iter.next().is_none());

        let public_argument = crate::c63_public_argument::C63PublicArgument::new_with_configs(
            statement_digest,
            profile_digest,
            predecessor_correction_root,
            predecessor_a_root.roots()[0],
            correction_root,
            a_root.roots()[0],
            2,
            1,
            2,
            &spot_rows,
            correction_artifact,
            m_artifacts,
            u_artifacts,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .unwrap();
        let public_bytes = public_argument.encode().unwrap();
        assert_eq!(
            public_bytes.len(),
            crate::c63_public_argument::C63_PUBLIC_ARGUMENT_FRAMING_BYTES
                + public_argument.correction_opening().len()
                + public_argument.d22_whir().iter().flatten().map(Vec::len).sum::<usize>()
                + public_argument
                    .d19_projected_whir()
                    .iter()
                    .flatten()
                    .map(Vec::len)
                    .sum::<usize>()
        );
        let decoded_public = crate::c63_public_argument::C63PublicArgument::decode_with_configs(
            &public_bytes,
            &spot_rows,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .unwrap();
        assert_eq!(decoded_public, public_argument);
        let mut changed_public = public_bytes.clone();
        changed_public[180] ^= 1;
        assert!(crate::c63_public_argument::C63PublicArgument::decode_with_configs(
            &changed_public,
            &spot_rows,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .is_err());

        let sparse_bytes = sparse_proof.encode().unwrap();
        let terminal_contexts =
            transcript_binding.terminal_contexts(query_seed, &public_bytes, &sparse_bytes).unwrap();
        let mut terminal_proofs = [C61AuthenticatedWhirBaseProof::decode(&[0; 16]).unwrap(); 4];
        let mut m_target_keys = [VerifierKey::ZERO; 2];
        for (tape, (prepared, outputs, closures, target_values)) in
            m_close_inputs.into_iter().enumerate()
        {
            let (_, key, proof) = close_authenticated_limb_pair(
                prepared,
                [&outputs[0], &outputs[1]],
                [&closures[0], &closures[1]],
                target_values,
                m_limb_tags[tape],
                &mut sparse_contexts[tape],
                C63AuthenticatedWhirLane::Systematic,
                mask_range,
                terminal_contexts[0][tape],
            )
            .unwrap();
            terminal_proofs[tape] = proof;
            m_target_keys[tape] =
                linked_m_limb_keys[tape][0].add(linked_m_limb_keys[tape][1].scale(basis));
            assert_eq!(key, m_target_keys[tape]);
        }
        let mut u_target_keys = [VerifierKey::ZERO; 2];
        for (tape, (prepared, outputs, closures, target_values)) in
            u_close_inputs.into_iter().enumerate()
        {
            let (_, key, proof) = close_authenticated_limb_pair(
                prepared,
                [&outputs[0], &outputs[1]],
                [&closures[0], &closures[1]],
                target_values,
                u_limb_tags[tape],
                &mut sparse_contexts[tape],
                C63AuthenticatedWhirLane::Sketch,
                mask_range,
                terminal_contexts[1][tape],
            )
            .unwrap();
            terminal_proofs[2 + tape] = proof;
            u_target_keys[tape] = key;
            assert_eq!(u_target_keys[tape], u_opening_keys[tape]);
            assert_eq!(whir_streams[tape].counters.full_corrs, 4);
        }

        let derived_u_target_keys = sparse_pending.derive_u_opening_keys(m_target_keys).unwrap();
        assert_eq!(derived_u_target_keys, u_target_keys);
        let sparse_audit = sparse_pending.finish(derived_u_target_keys, m_target_keys).unwrap();
        assert_eq!(
            sparse_audit.transcript_digest,
            sparse_prover_transcript.canonical_binding_digest().unwrap()
        );

        let mut joined_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        let source_link =
            C63ResidualSourceFunctionalsVerifiedLink::for_test([0x63; 32], m_target_keys);
        let joined = verify_c63_sketch_suffix_with_configs(
            &public_bytes,
            attempt,
            &h,
            statement.output_point(),
            &sparse_proof,
            &predecessor_state,
            source_link,
            terminal_proofs,
            mask_range,
            &mut joined_contexts,
            3,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .unwrap();
        assert_eq!(joined.0, sparse_audit);
        assert_eq!(joined.1.accepted_len(), successor_frontier.accepted_len());

        let mut changed_terminal_proofs = terminal_proofs;
        let mut changed_tag = changed_terminal_proofs[3].encode();
        changed_tag[0] ^= 1;
        changed_terminal_proofs[3] = C61AuthenticatedWhirBaseProof::decode(&changed_tag).unwrap();
        let mut changed_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        assert!(verify_c63_sketch_suffix_with_configs(
            &public_bytes,
            attempt,
            &h,
            statement.output_point(),
            &sparse_proof,
            &predecessor_state,
            source_link,
            changed_terminal_proofs,
            mask_range,
            &mut changed_contexts,
            3,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .is_err());

        let mut changed_sparse_bytes = sparse_bytes;
        let changed_sparse_tag = changed_sparse_bytes.len() - 32;
        changed_sparse_bytes[changed_sparse_tag] ^= 1;
        let changed_sparse = C63SparseHClosureProof::decode(&changed_sparse_bytes).unwrap();
        let mut changed_sparse_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        assert!(verify_c63_sketch_suffix_with_configs(
            &public_bytes,
            attempt,
            &h,
            statement.output_point(),
            &changed_sparse,
            &predecessor_state,
            source_link,
            terminal_proofs,
            mask_range,
            &mut changed_sparse_contexts,
            3,
            INPUT_LOG2,
            &m_config,
            OUTPUT_LOG2,
            &u_config,
        )
        .is_err());

        let mut bad_contexts =
            std::array::from_fn(|tape| VerifierCtx::new(sparse_seeds[tape], sparse_deltas[tape]));
        let mut bad_transcript = Transcript::new(sparse_transcript_seed);
        assert!(verify_c63_sparse_h_tape_closure_from_whir_openings_reference(
            &h,
            u_target_keys,
            &statement,
            &spots,
            &sparse_proof,
            &mut bad_contexts,
            &mut bad_transcript,
            |tape, _| {
                Ok(if tape == 0 {
                    m_target_keys[0].add(VerifierKey::from_public(Fp2::ONE, sparse_deltas[0]))
                } else {
                    m_target_keys[1]
                })
            },
        )
        .is_err());
    }
}
