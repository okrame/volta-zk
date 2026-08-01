//! Feature-gated CPU reference for the C6.1 native HVZK-WHIR chains.
//!
//! This module is deliberately excluded from default and production builds.
//! It pins the academic Plonky3 implementation used to validate the native
//! Goldilocks profile; it is not a production fallback and does not yet
//! implement [`crate::C61NativeBackendVerifier`].
//!
//! The selected profile is interactive, Johnson-bound, no-grinding,
//! Goldilocks/Fp2, with an initial rate of 1/2, folds 1 then 2, and the
//! smallest admissible mask-code inverse rate.  The structural byte bound
//! below uses the maximum possible deduplicated binary-Merkle frontier for
//! every opening.  It does not use average query collisions.
//!
//! The upstream prover/verifier APIs are monolithic, so this reference uses
//! the same private verifier seed in two independent single-process replays.
//! It validates message-before-challenge ordering and exact wire accounting;
//! it is not the deployed two-party transport.  A production adapter must
//! suspend after each prover move and must never reveal that seed to the
//! provider.

use p3_blake3::Blake3;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, HashChallenger, ResamplingError, SerializingChallenger64,
};
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::{MerkleTreeMmcs, PrunedMerklePaths};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::zk::ZkSumcheckData;
use p3_symmetric::{CompressionFunctionFromHasher, MerkleCap, SerializingHasher};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir::pcs::zk::{
    BaseCaseZkProof, BlindedMask, HidingWhirPcs, MaskOpeningPair, ZkParameters, ZkRoundProof,
    ZkWhirConfig, ZkWhirProof,
};
use rand_010::rngs::StdRng;
use rand_010::SeedableRng;
use volta_field::{Fp as VoltaFp, Fp2 as VoltaFp2, P};
use volta_mac::Transcript;

use crate::C61_NATIVE_CHAIN_MAX_BYTES;

/// Exact upstream revision pinned by the reference-only Cargo feature.
pub const C61_P3_REFERENCE_REVISION: &str = "66e290615de1858f2f2f6a804158064c406cda1c";
pub const C61_WHIRA1_MAGIC: [u8; 8] = *b"C6WIR1\0\0";
pub const C61_WHIRA1_VERSION: u16 = 1;
pub const C61_WHIRA1_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4;
pub const C61_WHIRA1_SECURITY_BITS: usize = 74;
pub const C61_WHIRA1_STARTING_LOG_INV_RATE: usize = 1;
pub const C61_WHIRA1_INITIAL_FOLD: usize = 1;
pub const C61_WHIRA1_LATER_FOLD: usize = 2;
pub const C61_WHIRA1_ELL_ZK: usize = 16;
pub const C61_WHIRA1_MASK_LOG_INV_RATE: usize = 1;
pub const C61_WHIRA1_OPENING_POINTS: usize = 1;
pub const C61_WHIRA1_DIGEST_BYTES: usize = 32;
pub const C61_WHIRA1_FP_BYTES: usize = 8;
pub const C61_WHIRA1_FP2_BYTES: usize = 16;
pub const C61_WHIRA1_MULTIPROOF_COUNT_BYTES: usize = 4;

pub type C61P3Fp2 = BinomialExtensionField<Goldilocks, 2>;
pub(crate) type C61SizingChallenger =
    SerializingChallenger64<Goldilocks, HashChallenger<u8, Blake3, 32>>;
type C61FieldHash = SerializingHasher<Blake3>;
type C61Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
pub(crate) type C61Mmcs = MerkleTreeMmcs<Goldilocks, u8, C61FieldHash, C61Compress, 2, 32>;
pub(crate) type C61Commitment = MerkleCap<Goldilocks, [u8; 32]>;
pub(crate) type C61MultiProof = PrunedMerklePaths<u8, 32>;
type C61Proof = ZkWhirProof<Goldilocks, C61P3Fp2, C61Mmcs>;

const C61_NATIVE_MESSAGE_LABEL: &str = "c61.native.interactive_message";
const C61_NATIVE_FINAL_PAYLOAD_LABEL: &str = "c61.native.final_payload";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61WhirReferenceError(String);

impl C61WhirReferenceError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61WhirReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61WhirReferenceError {}

pub(crate) type ReferenceResult<T> = Result<T, C61WhirReferenceError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C61WhirInteractionStats {
    pub provider_messages: u64,
    pub provider_semantic_bytes: u64,
    pub provider_payload_bytes: u64,
    pub client_fp_challenges: u64,
    pub client_query_challenges: u64,
    pub client_challenge_payload_bytes: u64,
}

struct C61InteractiveState<'a> {
    transcript: &'a mut Transcript,
    initial_root_seen: bool,
    public_statement_bound: bool,
    #[allow(dead_code)]
    public_point_num_variables: usize,
    public_base_observations_to_skip: usize,
    pending_provider_bytes: u64,
    stats: C61WhirInteractionStats,
}

/// Single-process adapter from Plonky3's generic challenger API to VOLTA's
/// interactive designated-verifier transcript model.  It never hashes the
/// proof to derive a Fiat--Shamir challenge.  Each `sample*` consumes fresh
/// verifier entropy only after any pending prover observations have been
/// appended.  This models round order; it is not a provider-side transport.
pub(crate) struct C61InteractiveChallenger<'a> {
    state: Arc<Mutex<C61InteractiveState<'a>>>,
}

impl Clone for C61InteractiveChallenger<'_> {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

impl<'a> C61InteractiveChallenger<'a> {
    pub(crate) fn new(transcript: &'a mut Transcript, num_variables: usize) -> Self {
        Self::new_with_point_mode(transcript, num_variables, true)
    }

    /// Low-level claimless calls bind the verifier point through an explicit
    /// typed method, so no future provider algebra observation may be
    /// mistaken for an implicit adapter-owned point limb.
    #[allow(dead_code)]
    pub(crate) fn new_claimless(transcript: &'a mut Transcript, num_variables: usize) -> Self {
        Self::new_with_point_mode(transcript, num_variables, false)
    }

    fn new_with_point_mode(
        transcript: &'a mut Transcript,
        num_variables: usize,
        implicit_adapter_point: bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(C61InteractiveState {
                transcript,
                initial_root_seen: false,
                public_statement_bound: false,
                public_point_num_variables: num_variables,
                // The opening point is already a verifier message.  The P3
                // adapter observes it before the claimed evaluation; do not
                // mischarge it as provider traffic.
                public_base_observations_to_skip: if implicit_adapter_point {
                    2 * num_variables
                } else {
                    0
                },
                pending_provider_bytes: 0,
                stats: C61WhirInteractionStats::default(),
            })),
        }
    }

    /// Bind one verifier-owned claimless opening point after the commitment
    /// and before the first native challenge.  It is client-to-provider
    /// statement data, so it is neither provider payload nor a skipped
    /// generic provider observation.
    #[allow(dead_code)]
    pub(crate) fn observe_public_point(&mut self, point: &Point<C61P3Fp2>) -> ReferenceResult<()> {
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        if !state.initial_root_seen {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 opening point must follow the initial commitment",
            ));
        }
        if state.public_base_observations_to_skip != 0 || state.public_statement_bound {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 opening point mode or multiplicity mismatch",
            ));
        }
        if point.num_variables() != state.public_point_num_variables {
            return Err(C61WhirReferenceError::new("C6WIR1 opening point arity mismatch"));
        }
        state.public_statement_bound = true;
        Ok(())
    }

    fn flush_pending(state: &mut C61InteractiveState<'_>) {
        if state.pending_provider_bytes == 0 {
            return;
        }
        state.transcript.append(C61_NATIVE_MESSAGE_LABEL, state.pending_provider_bytes);
        state.stats.provider_messages += 1;
        state.pending_provider_bytes = 0;
    }

    pub(crate) fn finish(&self, payload_bytes: usize) -> ReferenceResult<C61WhirInteractionStats> {
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        if !state.public_statement_bound || state.public_base_observations_to_skip != 0 {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 opening point was not completely bound before native challenges",
            ));
        }
        Self::flush_pending(&mut state);
        let payload_bytes = u64::try_from(payload_bytes)
            .map_err(|_| C61WhirReferenceError::new("C6WIR1 payload length exceeds u64"))?;
        if state.stats.provider_semantic_bytes > payload_bytes {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 observed transcript bytes exceed its strict payload",
            ));
        }
        let residual = payload_bytes - state.stats.provider_semantic_bytes;
        if residual > 0 {
            state.transcript.append(C61_NATIVE_FINAL_PAYLOAD_LABEL, residual);
            state.stats.provider_messages += 1;
        }
        state.stats.provider_payload_bytes = payload_bytes;
        Ok(state.stats)
    }

    /// Fail closed when a low-level caller bypasses the adapter without
    /// replaying the verifier-owned opening point after the initial root.
    #[allow(dead_code)]
    pub(crate) fn ensure_public_statement_bound(&self) -> ReferenceResult<()> {
        let state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        if state.public_statement_bound && state.public_base_observations_to_skip == 0 {
            Ok(())
        } else {
            Err(C61WhirReferenceError::new(
                "C6WIR1 opening point was not completely bound before native challenges",
            ))
        }
    }
}

impl CanObserve<Goldilocks> for C61InteractiveChallenger<'_> {
    fn observe(&mut self, _value: Goldilocks) {
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        if state.initial_root_seen && state.public_base_observations_to_skip > 0 {
            state.public_base_observations_to_skip -= 1;
            if state.public_base_observations_to_skip == 0 {
                state.public_statement_bound = true;
            }
            return;
        }
        state.pending_provider_bytes += C61_WHIRA1_FP_BYTES as u64;
        state.stats.provider_semantic_bytes += C61_WHIRA1_FP_BYTES as u64;
    }
}

impl CanObserve<C61Commitment> for C61InteractiveChallenger<'_> {
    fn observe(&mut self, value: C61Commitment) {
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        assert_eq!(value.num_roots(), 1, "C6WIR1 requires cap height zero");
        state.initial_root_seen = true;
        state.pending_provider_bytes += C61_WHIRA1_DIGEST_BYTES as u64;
        state.stats.provider_semantic_bytes += C61_WHIRA1_DIGEST_BYTES as u64;
    }
}

impl CanSample<Goldilocks> for C61InteractiveChallenger<'_> {
    fn sample(&mut self) -> Goldilocks {
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        Self::flush_pending(&mut state);
        let challenge = state.transcript.challenge_fp();
        state.stats.client_fp_challenges += 1;
        state.stats.client_challenge_payload_bytes += C61_WHIRA1_FP_BYTES as u64;
        Goldilocks::new(challenge.value())
    }
}

impl CanSampleBits<usize> for C61InteractiveChallenger<'_> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        assert!((1..=32).contains(&bits), "C6WIR1 query width must fit u32");
        let mut state = self.state.lock().expect("C6WIR1 challenger mutex poisoned");
        Self::flush_pending(&mut state);
        let challenge = state.transcript.challenge_bits(bits as u8) as usize;
        state.stats.client_query_challenges += 1;
        // Query indices use a canonical fixed u32 on the live wire.
        state.stats.client_challenge_payload_bytes += 4;
        challenge
    }
}

impl CanSampleUniformBits<Goldilocks> for C61InteractiveChallenger<'_> {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        bits: usize,
    ) -> Result<usize, ResamplingError> {
        Ok(self.sample_bits(bits))
    }
}

impl GrindingChallenger for C61InteractiveChallenger<'_> {
    type Witness = Goldilocks;

    fn grind(&mut self, bits: usize) -> Self::Witness {
        assert_eq!(bits, 0, "C6WIR1 proof-of-work is forbidden");
        Goldilocks::ZERO
    }
}

impl FieldChallenger<Goldilocks> for C61InteractiveChallenger<'_> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61WhirStructuralBudget {
    pub num_variables: usize,
    pub rounds: usize,
    pub mask_queries: usize,
    pub round_opening_bytes: usize,
    pub base_mask_opening_bytes: usize,
    pub blinded_mask_bytes: usize,
    pub base_case_bytes: usize,
    pub strict_chain_bytes: usize,
}

pub fn c61_p3_fp2_from_volta(value: VoltaFp2) -> C61P3Fp2 {
    C61P3Fp2::from_basis_coefficients_slice(&[
        Goldilocks::new(value.c0.value()),
        Goldilocks::new(value.c1.value()),
    ])
    .expect("quadratic extension has exactly two basis coefficients")
}

pub fn c61_volta_fp2_from_p3(value: C61P3Fp2) -> VoltaFp2 {
    let coefficients: &[Goldilocks] = value.as_basis_coefficients_slice();
    VoltaFp2::new(
        VoltaFp::new(coefficients[0].as_canonical_u64()),
        VoltaFp::new(coefficients[1].as_canonical_u64()),
    )
}

/// Build the exact selected upstream configuration for a single chain.
///
/// Only D27 and D28 are registered C6.1 production shapes.  Smaller shapes
/// are admitted by the private test helper below, never by this function.
pub fn c61_whir_selected_config(
    num_variables: usize,
) -> Result<ZkWhirConfig<C61P3Fp2, Goldilocks, C61SizingChallenger>, String> {
    if !matches!(num_variables, 27 | 28) {
        return Err("C6WIR1 production profile admits only D27 or D28".to_owned());
    }
    c61_whir_config::<C61SizingChallenger>(num_variables)
}

fn c61_whir_config<Challenger>(
    num_variables: usize,
) -> Result<ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>, String>
where
    Challenger: p3_challenger::FieldChallenger<Goldilocks>
        + p3_challenger::GrindingChallenger<Witness = Goldilocks>,
{
    ZkWhirConfig::new(
        num_variables,
        ProtocolParameters {
            security_level: C61_WHIRA1_SECURITY_BITS,
            pow_bits: 0,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::ConstantFromSecondRound(
                C61_WHIRA1_INITIAL_FOLD,
                C61_WHIRA1_LATER_FOLD,
            ),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: C61_WHIRA1_STARTING_LOG_INV_RATE,
        },
        ZkParameters { ell_zk: C61_WHIRA1_ELL_ZK, mask_log_inv_rate: C61_WHIRA1_MASK_LOG_INV_RATE },
    )
    .map_err(|error| error.to_string())
}

/// Maximum number of sibling hashes in a pruned binary multi-opening.
///
/// At a level with `nodes` possible nodes and `present` frontier nodes, at
/// most `min(present, nodes - present)` sibling nodes are missing.  Advancing
/// the frontier replaces `present` by `min(present, nodes / 2)`.  This is an
/// exact maximum over all sets of `queries` distinct leaves.
pub fn c61_max_pruned_binary_siblings(leaves: usize, queries: usize) -> usize {
    assert!(leaves.is_power_of_two());
    assert!(queries <= leaves);
    let mut nodes = leaves;
    let mut present = queries;
    let mut siblings = 0usize;
    while nodes > 1 {
        siblings += present.min(nodes - present);
        nodes /= 2;
        present = present.min(nodes);
    }
    siblings
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), String> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| "C6WIR1 structural byte count overflow".to_owned())?;
    Ok(())
}

fn opening_bytes(
    leaves: usize,
    queries: usize,
    row_width: usize,
    element_bytes: usize,
) -> Result<usize, String> {
    let rows = queries
        .checked_mul(row_width)
        .and_then(|value| value.checked_mul(element_bytes))
        .ok_or_else(|| "C6WIR1 opening row byte count overflow".to_owned())?;
    let siblings = c61_max_pruned_binary_siblings(leaves, queries)
        .checked_mul(C61_WHIRA1_DIGEST_BYTES)
        .ok_or_else(|| "C6WIR1 Merkle frontier byte count overflow".to_owned())?;
    C61_WHIRA1_MULTIPROOF_COUNT_BYTES
        .checked_add(rows)
        .and_then(|value| value.checked_add(siblings))
        .ok_or_else(|| "C6WIR1 opening byte count overflow".to_owned())
}

pub fn c61_whir_structural_budget(num_variables: usize) -> Result<C61WhirStructuralBudget, String> {
    let config = c61_whir_selected_config(num_variables)?;
    if config.params.pow_bits != 0
        || config.starting_folding_pow_bits != 0
        || config.final_pow_bits != 0
        || config.final_folding_pow_bits != 0
        || config
            .round_parameters
            .iter()
            .any(|round| round.pow_bits != 0 || round.folding_pow_bits != 0)
    {
        return Err("C6WIR1 forbids every proof-of-work transcript field".to_owned());
    }

    let mut round_opening_bytes = 0usize;
    let mut rounds_bytes = 0usize;
    for (index, round) in config.round_parameters.iter().enumerate() {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let element_bytes = if index == 0 { C61_WHIRA1_FP_BYTES } else { C61_WHIRA1_FP2_BYTES };
        let opening = opening_bytes(leaves, round.num_queries, 1usize << fold, element_bytes)?;
        checked_add(&mut round_opening_bytes, opening)?;
        // Next-oracle root, switch-mask root, one private OOD answer.  The
        // no-grinding witness is omitted from C6WIR1 rather than encoding 0.
        checked_add(
            &mut rounds_bytes,
            2 * C61_WHIRA1_DIGEST_BYTES + C61_WHIRA1_FP2_BYTES + opening,
        )?;
    }

    let groups = config.mask_groups();
    let flat_mask_count: usize = groups.iter().map(|group| group.width).sum();
    let mut base_mask_opening_bytes = 0usize;
    let mut blinded_mask_bytes = 0usize;
    for group in &groups {
        let one = opening_bytes(
            group.shape.domain_size,
            config.mask_queries,
            group.width,
            C61_WHIRA1_FP2_BYTES,
        )?;
        checked_add(&mut base_mask_opening_bytes, 2 * one)?;
        let one_mask = group
            .shape
            .message_len
            .checked_add(group.shape.randomness_len)
            .and_then(|elements| elements.checked_mul(C61_WHIRA1_FP2_BYTES))
            .ok_or_else(|| "C6WIR1 blinded-mask byte count overflow".to_owned())?;
        checked_add(&mut blinded_mask_bytes, group.width * one_mask)?;
    }

    let final_round = config.final_round_config();
    let final_fold = final_round.folding_factor;
    let final_domain = final_round.domain_size >> final_fold;
    let source_opening = opening_bytes(
        final_domain,
        config.final_queries,
        1usize << final_fold,
        C61_WHIRA1_FP2_BYTES,
    )?;
    let fresh_main_opening =
        opening_bytes(final_domain, config.final_queries, 1, C61_WHIRA1_FP2_BYTES)?;
    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];

    let mut base_case_bytes = 0usize;
    // One fresh-main root plus one fresh root per mask group.
    checked_add(&mut base_case_bytes, (1 + groups.len()) * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut base_case_bytes, C61_WHIRA1_FP2_BYTES)?; // masked claim
    checked_add(&mut base_case_bytes, final_message_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, final_randomness_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, blinded_mask_bytes)?;
    checked_add(&mut base_case_bytes, source_opening)?;
    checked_add(&mut base_case_bytes, fresh_main_opening)?;
    checked_add(&mut base_case_bytes, base_mask_opening_bytes)?;

    let sumcheck_batches = config.n_rounds() + 1;
    let sumcheck_rounds: usize =
        (0..sumcheck_batches).map(|round| config.round_folding_factor(round)).sum();
    let sumcheck_bytes =
        (sumcheck_batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES;

    let mut strict_chain_bytes = C61_WHIRA1_HEADER_BYTES;
    checked_add(&mut strict_chain_bytes, C61_WHIRA1_DIGEST_BYTES)?; // initial root
    checked_add(&mut strict_chain_bytes, C61_WHIRA1_OPENING_POINTS * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut strict_chain_bytes, sumcheck_bytes)?;
    checked_add(&mut strict_chain_bytes, sumcheck_batches * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut strict_chain_bytes, rounds_bytes)?;
    checked_add(&mut strict_chain_bytes, base_case_bytes)?;

    if flat_mask_count != config.folding_schedule.iter().sum::<usize>() + config.n_rounds() {
        return Err("C6WIR1 mask-group census mismatch".to_owned());
    }
    if strict_chain_bytes > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(format!(
            "C6WIR1 D{num_variables} structural maximum {strict_chain_bytes} exceeds the native-chain cap"
        ));
    }

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

#[derive(Default)]
pub(crate) struct C61Writer {
    pub(crate) bytes: Vec<u8>,
}

impl C61Writer {
    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: usize) -> ReferenceResult<()> {
        let value = u32::try_from(value)
            .map_err(|_| C61WhirReferenceError::new("C6WIR1 count exceeds u32"))?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub(crate) fn fp(&mut self, value: Goldilocks) {
        self.bytes.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
    }

    pub(crate) fn fp2(&mut self, value: C61P3Fp2) {
        for coefficient in value.as_basis_coefficients_slice() {
            self.fp(*coefficient);
        }
    }

    pub(crate) fn digest(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn commitment(&mut self, value: &C61Commitment) -> ReferenceResult<()> {
        if value.num_roots() != 1 {
            return Err(C61WhirReferenceError::new("C6WIR1 requires a one-root Merkle cap"));
        }
        self.digest(&value.roots()[0]);
        Ok(())
    }

    pub(crate) fn multiproof(
        &mut self,
        proof: &C61MultiProof,
        max_siblings: usize,
    ) -> ReferenceResult<()> {
        if proof.sibling_hashes.len() > max_siblings {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 multiproof exceeds its exact frontier bound",
            ));
        }
        self.u32(proof.sibling_hashes.len())?;
        for sibling in &proof.sibling_hashes {
            self.digest(sibling);
        }
        Ok(())
    }
}

pub(crate) struct C61Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> C61Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) fn take(&mut self, count: usize) -> ReferenceResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C61WhirReferenceError::new("C6WIR1 cursor overflow"))?;
        if end > self.bytes.len() {
            return Err(C61WhirReferenceError::new("truncated C6WIR1 payload"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    pub(crate) fn u8(&mut self) -> ReferenceResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> ReferenceResult<u16> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    pub(crate) fn u32(&mut self) -> ReferenceResult<usize> {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(bytes) as usize)
    }

    pub(crate) fn fp(&mut self) -> ReferenceResult<Goldilocks> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        let value = u64::from_le_bytes(bytes);
        if value >= P {
            return Err(C61WhirReferenceError::new("noncanonical C6WIR1 Goldilocks element"));
        }
        Ok(Goldilocks::new(value))
    }

    pub(crate) fn fp2(&mut self) -> ReferenceResult<C61P3Fp2> {
        let coefficients = [self.fp()?, self.fp()?];
        C61P3Fp2::from_basis_coefficients_slice(&coefficients)
            .ok_or_else(|| C61WhirReferenceError::new("invalid C6WIR1 quadratic-extension element"))
    }

    pub(crate) fn digest(&mut self) -> ReferenceResult<[u8; 32]> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    pub(crate) fn commitment(&mut self) -> ReferenceResult<C61Commitment> {
        Ok(C61Commitment::new(vec![self.digest()?]))
    }

    pub(crate) fn multiproof(&mut self, max_siblings: usize) -> ReferenceResult<C61MultiProof> {
        let count = self.u32()?;
        if count > max_siblings {
            return Err(C61WhirReferenceError::new(
                "C6WIR1 multiproof count exceeds its exact frontier bound",
            ));
        }
        let byte_count = count
            .checked_mul(C61_WHIRA1_DIGEST_BYTES)
            .ok_or_else(|| C61WhirReferenceError::new("C6WIR1 multiproof length overflow"))?;
        if byte_count > self.bytes.len().saturating_sub(self.offset) {
            return Err(C61WhirReferenceError::new("truncated C6WIR1 multiproof"));
        }
        let mut sibling_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            sibling_hashes.push(self.digest()?);
        }
        Ok(C61MultiProof { sibling_hashes })
    }

    pub(crate) fn finish(self) -> ReferenceResult<()> {
        if self.offset != self.bytes.len() {
            return Err(C61WhirReferenceError::new("trailing bytes in C6WIR1 payload"));
        }
        Ok(())
    }
}

fn encode_fp_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<Goldilocks, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<()> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err(C61WhirReferenceError::new("C6WIR1 base-field opening shape mismatch"));
    }
    for row in &opening.rows {
        for value in row {
            writer.fp(*value);
        }
    }
    writer.multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
}

fn encode_fp2_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<C61P3Fp2, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<()> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err(C61WhirReferenceError::new("C6WIR1 extension opening shape mismatch"));
    }
    for row in &opening.rows {
        for value in row {
            writer.fp2(*value);
        }
    }
    writer.multiproof(&opening.proof, c61_max_pruned_binary_siblings(leaves, queries))
}

fn decode_fp_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<SharedProofOpening<Goldilocks, C61MultiProof>> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp()?);
        }
        rows.push(row);
    }
    let proof = reader.multiproof(c61_max_pruned_binary_siblings(leaves, queries))?;
    Ok(SharedProofOpening { rows, proof })
}

fn decode_fp2_opening(
    reader: &mut C61Reader<'_>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<SharedProofOpening<C61P3Fp2, C61MultiProof>> {
    let mut rows = Vec::with_capacity(queries);
    for _ in 0..queries {
        let mut row = Vec::with_capacity(row_width);
        for _ in 0..row_width {
            row.push(reader.fp2()?);
        }
        rows.push(row);
    }
    let proof = reader.multiproof(c61_max_pruned_binary_siblings(leaves, queries))?;
    Ok(SharedProofOpening { rows, proof })
}

fn encode_c61_whir_artifact_inner(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &C61Proof,
    production_dimensions_only: bool,
) -> ReferenceResult<Vec<u8>> {
    if production_dimensions_only && !matches!(num_variables, 27 | 28) {
        return Err(C61WhirReferenceError::new("C6WIR1 production encoder admits only D27 or D28"));
    }
    let config = c61_whir_config::<C61SizingChallenger>(num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut body = C61Writer::default();
    body.commitment(commitment)?;
    if proof.evals.len() != C61_WHIRA1_OPENING_POINTS {
        return Err(C61WhirReferenceError::new("C6WIR1 evaluation count mismatch"));
    }
    for value in &proof.evals {
        body.fp2(*value);
    }

    if proof.sumchecks.len() != batches || proof.sumcheck_mask_commitments.len() != batches {
        return Err(C61WhirReferenceError::new("C6WIR1 sumcheck batch count mismatch"));
    }
    for (batch, sumcheck) in proof.sumchecks.iter().enumerate() {
        let rounds = config.round_folding_factor(batch);
        if sumcheck.ell_zk != C61_WHIRA1_ELL_ZK
            || sumcheck.round_coefficients.len() != rounds
            || sumcheck
                .round_coefficients
                .iter()
                .any(|coefficients| coefficients.len() != C61_WHIRA1_ELL_ZK - 1)
            || !sumcheck.pow_witnesses.is_empty()
        {
            return Err(C61WhirReferenceError::new("C6WIR1 sumcheck shape mismatch"));
        }
        body.fp2(sumcheck.mu_tilde);
        for coefficients in &sumcheck.round_coefficients {
            for coefficient in coefficients {
                body.fp2(*coefficient);
            }
        }
    }
    for root in &proof.sumcheck_mask_commitments {
        body.commitment(root)?;
    }

    if proof.rounds.len() != config.n_rounds() {
        return Err(C61WhirReferenceError::new("C6WIR1 round count mismatch"));
    }
    for (index, (round_proof, round)) in
        proof.rounds.iter().zip(&config.round_parameters).enumerate()
    {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        body.commitment(&round_proof.commitment)?;
        body.commitment(&round_proof.mask_commitment)?;
        if round_proof.ood_answers.len() != round.ood_samples
            || round_proof.pow_witness != Goldilocks::ZERO
        {
            return Err(C61WhirReferenceError::new("C6WIR1 round scalar shape mismatch"));
        }
        for answer in &round_proof.ood_answers {
            body.fp2(*answer);
        }
        match (&round_proof.openings, index) {
            (QueryOpenings::Base(opening), 0) => {
                encode_fp_opening(&mut body, opening, round.num_queries, 1usize << fold, leaves)?;
            }
            (QueryOpenings::Extension(opening), index) if index > 0 => {
                encode_fp2_opening(&mut body, opening, round.num_queries, 1usize << fold, leaves)?;
            }
            _ => {
                return Err(C61WhirReferenceError::new("C6WIR1 round opening field tag mismatch"));
            }
        }
    }

    let base = &proof.base_case;
    body.commitment(&base.fresh_main_commitment)?;
    if base.fresh_mask_commitments.len() != groups.len() {
        return Err(C61WhirReferenceError::new("C6WIR1 fresh-mask commitment count mismatch"));
    }
    for commitment in &base.fresh_mask_commitments {
        body.commitment(commitment)?;
    }
    body.fp2(base.masked_claim);

    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];
    if base.blinded_message.len() != final_message_elements
        || base.blinded_randomness.len() != final_randomness_elements
    {
        return Err(C61WhirReferenceError::new("C6WIR1 base source reveal shape mismatch"));
    }
    for value in &base.blinded_message {
        body.fp2(*value);
    }
    for value in &base.blinded_randomness {
        body.fp2(*value);
    }

    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    if base.blinded_masks.len() != flat_masks {
        return Err(C61WhirReferenceError::new("C6WIR1 blinded-mask count mismatch"));
    }
    let mut mask_index = 0usize;
    for group in &groups {
        for _ in 0..group.width {
            let mask = &base.blinded_masks[mask_index];
            mask_index += 1;
            if mask.message.len() != group.shape.message_len
                || mask.randomness.len() != group.shape.randomness_len
            {
                return Err(C61WhirReferenceError::new("C6WIR1 blinded-mask shape mismatch"));
            }
            for value in &mask.message {
                body.fp2(*value);
            }
            for value in &mask.randomness {
                body.fp2(*value);
            }
        }
    }
    if base.pow_witness != Goldilocks::ZERO {
        return Err(C61WhirReferenceError::new("C6WIR1 forbids a base-case PoW witness"));
    }
    match &base.source_openings {
        QueryOpenings::Extension(opening) => encode_fp2_opening(
            &mut body,
            opening,
            config.final_queries,
            1usize << final_round.folding_factor,
            final_domain,
        )?,
        QueryOpenings::Base(_) => {
            return Err(C61WhirReferenceError::new("C6WIR1 final source opening must use Fp2"));
        }
    }
    encode_fp2_opening(
        &mut body,
        &base.fresh_main_openings,
        config.final_queries,
        1,
        final_domain,
    )?;
    if base.mask_openings.len() != groups.len() {
        return Err(C61WhirReferenceError::new("C6WIR1 mask-opening group count mismatch"));
    }
    for (opening, group) in base.mask_openings.iter().zip(&groups) {
        encode_fp2_opening(
            &mut body,
            &opening.carried,
            config.mask_queries,
            group.width,
            group.shape.domain_size,
        )?;
        encode_fp2_opening(
            &mut body,
            &opening.fresh,
            config.mask_queries,
            group.width,
            group.shape.domain_size,
        )?;
    }

    let total = C61_WHIRA1_HEADER_BYTES
        .checked_add(body.bytes.len())
        .ok_or_else(|| C61WhirReferenceError::new("C6WIR1 total length overflow"))?;
    if total > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6WIR1 payload exceeds native-chain cap"));
    }
    let mut writer = C61Writer::default();
    writer.bytes.extend_from_slice(&C61_WHIRA1_MAGIC);
    writer.u16(C61_WHIRA1_VERSION);
    writer.u8(u8::try_from(num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6WIR1 dimension exceeds u8"))?);
    writer.u8(0);
    writer.u32(body.bytes.len())?;
    writer.bytes.extend_from_slice(&body.bytes);
    Ok(writer.bytes)
}

/// Encode a production D27/D28 chain using the fixed, non-Serde C6WIR1
/// grammar.  All vector lengths are inferred from the registered profile;
/// only pruned-frontier digest counts remain explicit and are capped before
/// serialization.
pub fn encode_c61_whir_artifact(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &C61Proof,
) -> ReferenceResult<Vec<u8>> {
    encode_c61_whir_artifact_inner(num_variables, commitment, proof, true)
}

fn decode_c61_whir_artifact_inner(
    bytes: &[u8],
    expected_num_variables: usize,
    production_dimensions_only: bool,
) -> ReferenceResult<(C61Commitment, C61Proof)> {
    if bytes.len() > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6WIR1 payload exceeds native-chain cap"));
    }
    if production_dimensions_only && !matches!(expected_num_variables, 27 | 28) {
        return Err(C61WhirReferenceError::new("C6WIR1 production decoder admits only D27 or D28"));
    }
    let config = c61_whir_config::<C61SizingChallenger>(expected_num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut reader = C61Reader::new(bytes);
    if reader.take(8)? != C61_WHIRA1_MAGIC {
        return Err(C61WhirReferenceError::new("C6WIR1 magic mismatch"));
    }
    if reader.u16()? != C61_WHIRA1_VERSION {
        return Err(C61WhirReferenceError::new("C6WIR1 version mismatch"));
    }
    if reader.u8()? as usize != expected_num_variables {
        return Err(C61WhirReferenceError::new("C6WIR1 dimension mismatch"));
    }
    if reader.u8()? != 0 {
        return Err(C61WhirReferenceError::new("C6WIR1 reserved byte is nonzero"));
    }
    let body_len = reader.u32()?;
    if body_len != bytes.len().saturating_sub(C61_WHIRA1_HEADER_BYTES) {
        return Err(C61WhirReferenceError::new("C6WIR1 body length mismatch"));
    }

    let commitment = reader.commitment()?;
    let mut evals = Vec::with_capacity(C61_WHIRA1_OPENING_POINTS);
    for _ in 0..C61_WHIRA1_OPENING_POINTS {
        evals.push(reader.fp2()?);
    }

    let mut sumchecks = Vec::with_capacity(batches);
    for batch in 0..batches {
        let rounds = config.round_folding_factor(batch);
        let mu_tilde = reader.fp2()?;
        let mut round_coefficients = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let mut coefficients = Vec::with_capacity(C61_WHIRA1_ELL_ZK - 1);
            for _ in 0..C61_WHIRA1_ELL_ZK - 1 {
                coefficients.push(reader.fp2()?);
            }
            round_coefficients.push(coefficients);
        }
        sumchecks.push(ZkSumcheckData {
            mu_tilde,
            ell_zk: C61_WHIRA1_ELL_ZK,
            round_coefficients,
            pow_witnesses: Vec::new(),
        });
    }
    let mut sumcheck_mask_commitments = Vec::with_capacity(batches);
    for _ in 0..batches {
        sumcheck_mask_commitments.push(reader.commitment()?);
    }

    let mut rounds = Vec::with_capacity(config.n_rounds());
    for (index, round) in config.round_parameters.iter().enumerate() {
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let round_commitment = reader.commitment()?;
        let mask_commitment = reader.commitment()?;
        let mut ood_answers = Vec::with_capacity(round.ood_samples);
        for _ in 0..round.ood_samples {
            ood_answers.push(reader.fp2()?);
        }
        let openings = if index == 0 {
            QueryOpenings::Base(decode_fp_opening(
                &mut reader,
                round.num_queries,
                1usize << fold,
                leaves,
            )?)
        } else {
            QueryOpenings::Extension(decode_fp2_opening(
                &mut reader,
                round.num_queries,
                1usize << fold,
                leaves,
            )?)
        };
        rounds.push(ZkRoundProof {
            commitment: round_commitment,
            mask_commitment,
            ood_answers,
            pow_witness: Goldilocks::ZERO,
            openings,
        });
    }

    let fresh_main_commitment = reader.commitment()?;
    let mut fresh_mask_commitments = Vec::with_capacity(groups.len());
    for _ in 0..groups.len() {
        fresh_mask_commitments.push(reader.commitment()?);
    }
    let masked_claim = reader.fp2()?;
    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];
    let mut blinded_message = Vec::with_capacity(final_message_elements);
    for _ in 0..final_message_elements {
        blinded_message.push(reader.fp2()?);
    }
    let mut blinded_randomness = Vec::with_capacity(final_randomness_elements);
    for _ in 0..final_randomness_elements {
        blinded_randomness.push(reader.fp2()?);
    }
    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    let mut blinded_masks = Vec::with_capacity(flat_masks);
    for group in &groups {
        for _ in 0..group.width {
            let mut message = Vec::with_capacity(group.shape.message_len);
            for _ in 0..group.shape.message_len {
                message.push(reader.fp2()?);
            }
            let mut randomness = Vec::with_capacity(group.shape.randomness_len);
            for _ in 0..group.shape.randomness_len {
                randomness.push(reader.fp2()?);
            }
            blinded_masks.push(BlindedMask { message, randomness });
        }
    }
    let source_openings = QueryOpenings::Extension(decode_fp2_opening(
        &mut reader,
        config.final_queries,
        1usize << final_round.folding_factor,
        final_domain,
    )?);
    let fresh_main_openings =
        decode_fp2_opening(&mut reader, config.final_queries, 1, final_domain)?;
    let mut mask_openings = Vec::with_capacity(groups.len());
    for group in &groups {
        mask_openings.push(MaskOpeningPair {
            carried: decode_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
            fresh: decode_fp2_opening(
                &mut reader,
                config.mask_queries,
                group.width,
                group.shape.domain_size,
            )?,
        });
    }
    reader.finish()?;

    let base_case = BaseCaseZkProof {
        fresh_main_commitment,
        fresh_mask_commitments,
        masked_claim,
        blinded_message,
        blinded_randomness,
        blinded_masks,
        pow_witness: Goldilocks::ZERO,
        source_openings,
        fresh_main_openings,
        mask_openings,
    };
    Ok((commitment, ZkWhirProof { evals, sumchecks, sumcheck_mask_commitments, rounds, base_case }))
}

/// Decode a production D27/D28 chain.  Every shape-dependent length is
/// reconstructed from `expected_num_variables`; caps are checked before any
/// proof-sized allocation, and trailing bytes are rejected.
pub fn decode_c61_whir_artifact(
    bytes: &[u8],
    expected_num_variables: usize,
) -> ReferenceResult<(C61Commitment, C61Proof)> {
    decode_c61_whir_artifact_inner(bytes, expected_num_variables, true)
}

pub(crate) fn c61_reference_mmcs() -> C61Mmcs {
    C61Mmcs::new(C61FieldHash::new(Blake3 {}), C61Compress::new(Blake3 {}), 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61WhirReferenceRun {
    pub payload: Vec<u8>,
    pub evaluation: C61P3Fp2,
    pub interaction: C61WhirInteractionStats,
}

fn prove_c61_whir_reference_inner(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    production_dimensions_only: bool,
) -> ReferenceResult<C61WhirReferenceRun> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err(C61WhirReferenceError::new("C6WIR1 witness/point dimension mismatch"));
    }
    if production_dimensions_only && !matches!(num_variables, 27 | 28) {
        return Err(C61WhirReferenceError::new("C6WIR1 production prover admits only D27 or D28"));
    }
    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new(&mut transcript, num_variables);
    let config = c61_whir_config::<C61InteractiveChallenger<'_>>(num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let pcs = HidingWhirPcs::new(
        config,
        Radix2DFTSmallBatch::default(),
        c61_reference_mmcs(),
        StdRng::seed_from_u64(prover_rng_seed),
    );
    let (commitment, data) = pcs.commit(witness, &mut challenger);
    let proof = pcs.open(data, vec![point], &mut challenger);
    let evaluation = proof.evals[0];
    let payload = encode_c61_whir_artifact_inner(
        num_variables,
        &commitment,
        &proof,
        production_dimensions_only,
    )?;
    let interaction = challenger.finish(payload.len())?;
    Ok(C61WhirReferenceRun { payload, evaluation, interaction })
}

/// Produce one single-process interactive-model CPU-reference chain.  This
/// API is feature-gated and accepts only the registered D27/D28 production
/// shapes; its verifier seed is diagnostic input and it is not called by the
/// default or production provider path.
pub fn prove_c61_whir_reference(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
) -> ReferenceResult<C61WhirReferenceRun> {
    prove_c61_whir_reference_inner(witness, point, verifier_seed, prover_rng_seed, true)
}

fn verify_c61_whir_reference_inner(
    payload: &[u8],
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    production_dimensions_only: bool,
) -> ReferenceResult<C61WhirInteractionStats> {
    let num_variables = point.num_variables();
    let (commitment, proof) =
        decode_c61_whir_artifact_inner(payload, num_variables, production_dimensions_only)?;
    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new(&mut transcript, num_variables);
    let config = c61_whir_config::<C61InteractiveChallenger<'_>>(num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let pcs = HidingWhirPcs::new(
        config,
        Radix2DFTSmallBatch::default(),
        c61_reference_mmcs(),
        StdRng::seed_from_u64(0),
    );
    let verification = catch_unwind(AssertUnwindSafe(|| {
        pcs.verify(&commitment, &proof, &mut challenger, vec![point])
    }))
    .map_err(|_| C61WhirReferenceError::new("C6WIR1 upstream verifier panicked"))?;
    verification.map_err(|error| {
        C61WhirReferenceError::new(format!("C6WIR1 verification failed: {error}"))
    })?;
    challenger.finish(payload.len())
}

/// Verify one independently replayed interactive-model CPU-reference chain
/// after strict decoding.  Upstream panics are contained and converted to
/// fail-closed errors; this remains a reference path and is not a production
/// fallback.
pub fn verify_c61_whir_reference(
    payload: &[u8],
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
) -> ReferenceResult<C61WhirInteractionStats> {
    verify_c61_whir_reference_inner(payload, point, verifier_seed, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_d27_d28_profiles_are_exact_and_under_cap() {
        let d27 = c61_whir_structural_budget(27).unwrap();
        let d28 = c61_whir_structural_budget(28).unwrap();

        assert_eq!(d27.rounds, 10);
        assert_eq!(d28.rounds, 11);
        assert_eq!(d27.mask_queries, 184);
        assert_eq!(d28.mask_queries, 184);
        assert_eq!(d27.strict_chain_bytes, 1_076_376);
        assert_eq!(d28.strict_chain_bytes, 1_162_908);
        assert!(d28.strict_chain_bytes < C61_NATIVE_CHAIN_MAX_BYTES);
    }

    #[test]
    fn pruned_frontier_bound_handles_dense_and_sparse_queries() {
        assert_eq!(c61_max_pruned_binary_siblings(512, 184), 256);
        assert_eq!(c61_max_pruned_binary_siblings(1 << 28, 173), 3_543);
        assert_eq!(c61_max_pruned_binary_siblings(128, 128), 0);
        assert_eq!(c61_max_pruned_binary_siblings(8, 1), 3);
    }

    #[test]
    fn production_profile_rejects_unregistered_dimensions() {
        assert!(c61_whir_selected_config(26).is_err());
        assert!(c61_whir_selected_config(29).is_err());
    }

    #[test]
    fn scaled_interactive_codec_round_trip_and_fail_closed_mutations() {
        let num_variables = 14;
        let verifier_seed = [0x61; 32];
        let mut rng = StdRng::seed_from_u64(0xC6_1001);
        let witness = Poly::<Goldilocks>::rand(&mut rng, num_variables);
        let point = Point::<C61P3Fp2>::rand(&mut rng, num_variables);

        let run =
            prove_c61_whir_reference_inner(witness, point.clone(), verifier_seed, 0xC6_1002, false)
                .unwrap();
        let verifier =
            verify_c61_whir_reference_inner(&run.payload, point.clone(), verifier_seed, false)
                .unwrap();
        assert_eq!(run.interaction, verifier);
        assert_eq!(run.payload.len(), 375_584);
        assert_eq!(run.interaction.provider_messages, 26);
        assert_eq!(run.interaction.provider_semantic_bytes, 52_192);
        assert_eq!(run.interaction.client_fp_challenges, 52);
        assert_eq!(run.interaction.client_query_challenges, 2_503);
        assert_eq!(run.interaction.client_challenge_payload_bytes, 10_428);
        assert_eq!(run.interaction.provider_payload_bytes as usize, run.payload.len());
        assert!(run.interaction.provider_messages > 1);
        assert!(run.interaction.client_fp_challenges > 0);
        assert!(run.interaction.client_query_challenges > 0);

        let (commitment, proof) =
            decode_c61_whir_artifact_inner(&run.payload, num_variables, false).unwrap();
        assert_eq!(
            encode_c61_whir_artifact_inner(num_variables, &commitment, &proof, false,).unwrap(),
            run.payload,
        );

        assert!(verify_c61_whir_reference_inner(&run.payload, point.clone(), [0x62; 32], false,)
            .is_err());

        let mut noncanonical = run.payload.clone();
        let first_eval = C61_WHIRA1_HEADER_BYTES + C61_WHIRA1_DIGEST_BYTES;
        noncanonical[first_eval..first_eval + 8].copy_from_slice(&P.to_le_bytes());
        assert!(decode_c61_whir_artifact_inner(&noncanonical, num_variables, false,).is_err());

        let mut trailing = run.payload.clone();
        trailing.push(0);
        assert!(decode_c61_whir_artifact_inner(&trailing, num_variables, false).is_err());

        let mut bad_evaluation = run.payload.clone();
        bad_evaluation[first_eval] ^= 1;
        assert!(
            verify_c61_whir_reference_inner(&bad_evaluation, point, verifier_seed, false,).is_err()
        );
    }

    #[test]
    fn multiproof_cap_is_checked_before_digest_allocation() {
        let bytes = u32::MAX.to_le_bytes();
        let mut reader = C61Reader::new(&bytes);
        assert!(reader.multiproof(256).is_err());
        assert_eq!(reader.offset, 4);
    }

    #[test]
    fn volta_and_p3_quadratic_extensions_are_operation_identical() {
        let samples = [
            VoltaFp2::ZERO,
            VoltaFp2::ONE,
            VoltaFp2::new(VoltaFp::new(P - 1), VoltaFp::new(P - 2)),
            VoltaFp2::new(VoltaFp::new(0x1234_5678), VoltaFp::new(0xDEAD_BEEF)),
        ];
        for left in samples {
            assert_eq!(c61_volta_fp2_from_p3(c61_p3_fp2_from_volta(left)), left);
            for right in samples {
                assert_eq!(
                    c61_volta_fp2_from_p3(
                        c61_p3_fp2_from_volta(left) * c61_p3_fp2_from_volta(right),
                    ),
                    left * right,
                );
            }
        }
    }
}
