//! Strict-codec CPU differential for the C6.1 claimless-affine WHIR fork.
//!
//! This feature-gated module connects the reviewed fork boundary to C6AWH1
//! without implementing a production backend.  The opening target is
//! authenticated before the native proof, never serialized, propagated as a
//! public affine form by both roles, and closed by one designated ZeroOpen.
//! The verifier consumes only the strict C6AWP1 payload, never a shared
//! in-memory proof object.

use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::DenseMatrix;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_whir_c61::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use p3_whir_c61::pcs::proof::{QueryOpenings, SharedProofOpening};
use p3_whir_c61::pcs::zk::{
    BaseCaseClaimlessClosure, BaseCaseZkProof, BlindedMask, HidingWhirProver, HidingWhirVerifier,
    MaskOpeningPair, ZkParameters, ZkRoundProof, ZkWhirConfig, ZkWhirProof,
};
use p3_whir_c61::{ClaimlessAffineClaim, ClaimlessZkSumcheckData};
use rand_010::rngs::StdRng;
use rand_010::{RngExt, SeedableRng};
use volta_field::{Fp, Fp2, P};
use volta_mac::{
    zero_open_verify, C6InstalledOperationPlan, C6OperationPlanTerminalMetadata,
    C6TraceSourceManifest, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::c6::{
    C6CacheHead, C6ClientAttempt, C6ClientState, C6CorrelationRange, C6PairedCorrelationRanges,
    C6Workload,
};

use crate::c61_authenticated_whir::{
    finish_c61_authenticated_whir_base, finish_c61_authenticated_whir_base_with_zero_rows,
    prepare_c61_authenticated_whir_mask, simulate_c61_authenticated_whir_base_view,
    verify_c61_authenticated_whir_base, verify_c61_authenticated_whir_base_with_zero_rows_residual,
    C61AuthenticatedWhirAffineClaim, C61AuthenticatedWhirBaseProof, C61AuthenticatedWhirMaskRange,
    C61AuthenticatedWhirProverFinishInput, C61AuthenticatedWhirVerifierInput,
    C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
};
use crate::c61_interactive_driver::{
    create_c61_durable_checkpoint_prefix, open_c61_durable_checkpoint,
    spawn_c61_durable_private_entropy_broker, spawn_c61_private_entropy_broker, C61DurableJournal,
    C61InteractiveCheckpoint, C61InteractiveTape, C61PrivateEntropyBrokerOutput,
    C61PrivateEntropyProverChallenger, C61PrivateEntropyReplayChallenger,
};
use crate::c61_persisted_mmcs::{
    C61MmcsResourceMetrics, C61PersistedMmcs, C61PersistedMmcsMetrics,
};
use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};
use crate::c61_shared_round_challenger::c61_shared_round_pair;
use crate::c61_terminal_functional::{
    authenticate_c61_sparse_response_targets_prover,
    authenticate_c61_sparse_response_targets_verifier, C61SparseRationalBlindArithmeticProof,
};
use crate::c61_whir_reference::{
    c61_max_pruned_binary_siblings, c61_p3_fp2_from_volta, c61_reference_mmcs,
    c61_volta_fp2_from_p3, C61Commitment, C61InteractiveChallenger, C61Mmcs, C61MultiProof,
    C61P3Fp2, C61Reader, C61SizingChallenger, C61WhirInteractionStats, C61WhirReferenceError,
    C61Writer, ReferenceResult, C61_WHIRA1_DIGEST_BYTES, C61_WHIRA1_ELL_ZK, C61_WHIRA1_FP2_BYTES,
    C61_WHIRA1_FP_BYTES, C61_WHIRA1_INITIAL_FOLD, C61_WHIRA1_LATER_FOLD,
    C61_WHIRA1_MASK_LOG_INV_RATE, C61_WHIRA1_MULTIPROOF_COUNT_BYTES,
    C61_WHIRA1_STARTING_LOG_INV_RATE,
};
use crate::C61_NATIVE_CHAIN_MAX_BYTES;

pub const C61_AUTHENTICATED_P3_SECURITY_BITS: usize = 75;
pub const C61_AUTHENTICATED_P3_REVISION: &str =
    "66e290615de1858f2f2f6a804158064c406cda1c+c61-claimless-affine-multi-v2";
pub const C61_AUTHENTICATED_P3_MAGIC: [u8; 8] = *b"C6AWP1\0\0";
pub const C61_AUTHENTICATED_P3_VERSION: u16 = 1;
pub const C61_AUTHENTICATED_P3_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4;
pub const C61_SHARED_MULTI_ORACLE_MAGIC: [u8; 8] = *b"C6SMO1\0\0";
pub const C61_SHARED_MULTI_ORACLE_VERSION: u16 = 1;
pub const C61_SHARED_MULTI_ORACLE_HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 4;
pub const C61_SHARED_MULTI_ORACLE_MAX_BYTES: usize = 2_500_000;
/// Frozen C6.1 coefficient-plus-witness component cap.  This is deliberately
/// not a cap on total process RSS or GPU memory; those must be measured
/// separately by the production executor.
pub const C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES: u64 = 2_293_198_848;
/// Admission floor for the explicit host-monolithic A100 baseline.  This is
/// not a protocol cap: it leaves room above the 35.43-GB initial-oracle lower
/// bound for materialized relation vectors, later WHIR rounds and allocator
/// overhead.  The production record must still measure actual RSS.
pub const C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES: u64 = 128 * 1024 * 1024 * 1024;

type C61AuthenticatedP3Proof = ZkWhirProof<Goldilocks, C61P3Fp2, C61Mmcs>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61AuthenticatedP3StructuralBudget {
    pub num_variables: usize,
    pub rounds: usize,
    pub mask_queries: usize,
    /// Largest number of private OOD answers in one code-switch round.
    pub max_ood_samples: usize,
    /// Numerator `sum_r t_r(t_r+1)/2` of the composed OOD privacy bad-event
    /// bound over the quadratic-extension field.
    pub ood_privacy_bad_event_numerator: usize,
    pub round_opening_bytes: usize,
    pub base_mask_opening_bytes: usize,
    pub blinded_mask_bytes: usize,
    pub base_case_bytes: usize,
    pub strict_chain_bytes: usize,
}

#[derive(Debug)]
pub struct C61AuthenticatedP3Diagnostic {
    pub num_variables: usize,
    pub provider_affine: C61AuthenticatedWhirAffineClaim,
    pub verifier_affine: C61AuthenticatedWhirAffineClaim,
    pub provider_transcript_bytes: u64,
    pub verifier_transcript_bytes: u64,
    pub provider_ledger: BTreeMap<&'static str, u64>,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub proof_has_clear_evaluation_field: bool,
    pub full_correlations: u64,
}

/// Scaled ordered multi-opening report used by the model/embedding relation
/// adapter.  Opening points and target keys stay in the enclosing statement;
/// the strict provider artifact remains claim-count independent.
#[derive(Debug)]
pub struct C61AuthenticatedP3MultiOpenDiagnostic {
    pub num_variables: usize,
    pub claim_count: usize,
    pub strict_payload_bytes: usize,
    /// Claim-count-independent maximum for this WHIR geometry.  Concrete
    /// payloads may be smaller when sampled Merkle queries share siblings.
    pub strict_payload_max_bytes: usize,
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub batching_weights_identical: bool,
    pub point_mutation_rejected: bool,
    pub full_correlations: u64,
}

/// Scaled physical response/plan compiler opening under one shared-round
/// transcript and one aggregated designated ZeroOpen.  The response carries
/// the two base-field limbs at Dn while the plan remains at D(n-1).
#[derive(Debug)]
pub struct C61AuthenticatedP3SharedMultiOracleDiagnostic {
    pub production_geometry: bool,
    /// True only for the explicitly admitted host-monolithic A100 baseline.
    /// It is never GPU performance credit.
    pub monolithic_host_baseline: bool,
    pub persisted_executor: bool,
    pub gpu_performance_credit: bool,
    pub admitted_available_host_bytes: u64,
    pub admitted_available_spill_bytes: u64,
    pub monolithic_retained_lower_bound_bytes: u64,
    pub pooled_pcg: bool,
    pub response_num_variables: usize,
    pub plan_num_variables: usize,
    pub response_claim_count: usize,
    pub plan_claim_count: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub strict_payload_max_bytes: usize,
    /// C6SBA1 bytes for the scaled executable relation fixture.
    pub arithmetic_payload_bytes: usize,
    /// Scaled C6SBA1 plus the strict two-oracle C6SMO1 artifact.
    pub total_provider_payload_bytes: usize,
    pub response_target_correction_bytes: u64,
    /// QuickSilver triples in the scaled executable relation fixture.
    pub arithmetic_product_triples: usize,
    /// Arithmetic rows folded into the one existing WHIR ZeroOpen.
    pub folded_zero_rows: usize,
    /// Wire ledger, including C6SBA1 bodies but excluding its framing.
    pub provider_transcript_bytes: u64,
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub native_challenges_shared: bool,
    pub postproof_batching_challenge_identical: bool,
    pub plan_reserved_tag_is_zero: bool,
    pub codec_mutations_rejected: bool,
    pub arithmetic_payload_mutation_rejected: bool,
    pub joint_tag_mutation_rejected: bool,
    pub subfield_correlations: u64,
    pub full_correlations: u64,
    pub response_spill: C61PersistedMmcsMetrics,
    pub plan_spill: C61PersistedMmcsMetrics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionMonolithicResourceAdmission {
    /// Available host memory sampled immediately before entering the runner,
    /// not installed RAM.
    pub available_host_bytes: u64,
    /// Informative A100 device capacity.  The monolithic P3 baseline does not
    /// consume it and receives no GPU performance credit.
    pub gpu_total_bytes: u64,
    pub a100_present: bool,
    /// Must be set explicitly by the owner-authorized campaign runner.
    pub allow_host_monolithic_baseline: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionPersistedResourceAdmission {
    pub available_host_bytes: u64,
    pub available_spill_bytes: u64,
    pub gpu_total_bytes: u64,
    pub a100_present: bool,
    pub allow_persisted_executor: bool,
}

/// Production total-memory census for the selected monolithic P3 prover data
/// layout.
///
/// `HidingWhirProverData` retains the Boolean message and the encoded initial
/// oracle, while `MerkleTreeMmcs` retains every digest layer.  Both response
/// and plan roots must be fixed before the relation challenges, so the two
/// prover-data objects coexist.  These are strict retained lower bounds: ZK
/// randomness, later round oracles, GKR state and allocator overhead are not
/// included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61ProductionMonolithicMemoryCensus {
    pub response_num_variables: usize,
    pub plan_num_variables: usize,
    pub response_message_bytes: u64,
    pub response_encoded_bytes: u64,
    pub response_merkle_bytes: u64,
    pub response_retained_lower_bound_bytes: u64,
    pub plan_message_bytes: u64,
    pub plan_encoded_bytes: u64,
    pub plan_merkle_bytes: u64,
    pub plan_retained_lower_bound_bytes: u64,
    pub concurrent_retained_lower_bound_bytes: u64,
    /// Informative comparison only.  The owner-frozen component cap excludes
    /// encoded PCS oracles and Merkle prover data.
    pub coefficient_witness_cap_bytes: u64,
    pub retained_minus_component_cap_bytes: u64,
}

/// Reference-only designated-verifier view simulation report.
///
/// The simulator receives the target MAC key but never the real opening
/// plaintext, its provider tag, the real witness, or provider correlation
/// state.  It samples a surrogate witness only to materialize concrete
/// Merkle trees in this executable differential; the security argument uses
/// the pinned HVZK query simulators for those oracle views.
#[derive(Debug)]
pub struct C61AuthenticatedP3PrivacyDiagnostic {
    pub num_variables: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub simulator_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub simulator_transcript_bytes: u64,
    pub verifier_transcript_bytes: u64,
    pub simulator_ledger: BTreeMap<&'static str, u64>,
    pub verifier_ledger: BTreeMap<&'static str, u64>,
    pub received_real_target_plaintext: bool,
    pub received_provider_target_tag: bool,
    pub received_provider_correlation_state: bool,
    pub verifier_full_key_draws: u64,
}

/// Reference-only two-party transport and replay-to-frontier report.
#[derive(Debug)]
pub struct C61PrivateEntropyDriverDiagnostic {
    pub num_variables: usize,
    pub strict_payload_bytes: usize,
    pub strict_payload_blake3: [u8; 32],
    pub provider_interaction: C61WhirInteractionStats,
    pub verifier_interaction: C61WhirInteractionStats,
    pub challenge_count: usize,
    pub checkpoint_frontier: usize,
    pub checkpoint_bytes: usize,
    pub replayed_challenges: usize,
    pub resumed_artifact_identical: bool,
    pub resumed_tape_identical: bool,
    pub mutated_checkpoint_rejected: bool,
    pub checkpoint_codec_mutations_rejected: bool,
    pub durable_journal_bytes: usize,
    pub durable_replayed_challenges: usize,
    pub durable_replayed_mask_events: usize,
    pub durable_mask_frontier: u32,
    pub durable_record_count: u32,
    pub durable_resume_artifact_identical: bool,
    pub durable_resume_tape_identical: bool,
    pub durable_wrong_binding_rejected: bool,
    pub durable_torn_journal_rejected: bool,
    pub durable_corrupt_journal_rejected: bool,
    pub provider_received_verifier_seed: bool,
    pub provider_received_checkpoint: bool,
    pub full_correlations: u64,
}

#[derive(Clone)]
struct C61AuthenticatedP3Artifact {
    payload: Vec<u8>,
}

#[derive(Clone)]
struct C61SharedMultiOracleArtifact {
    payload: Vec<u8>,
}

struct C61PrivateEntropyFixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    broker: C61PrivateEntropyBrokerOutput,
    full_correlations: u64,
}

struct C61PrivateEntropyProviderFixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    full_correlations: u64,
}

#[derive(Clone)]
struct C61AuthenticatedP3Fixture {
    artifact: C61AuthenticatedP3Artifact,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    provider_affine: C61AuthenticatedWhirAffineClaim,
    provider_base_case: BaseCaseClaimlessClosure<C61P3Fp2>,
    provider_interaction: C61WhirInteractionStats,
    provider_transcript_bytes: u64,
    provider_ledger: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Copy)]
struct C61AuthenticatedP3VerifierInput<'a> {
    point: &'a Point<C61P3Fp2>,
    target_key: VerifierKey,
    verifier_seed: [u8; 32],
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
}

fn c61_authenticated_config<Challenger>(
    num_variables: usize,
) -> Result<ZkWhirConfig<C61P3Fp2, Goldilocks, Challenger>, String>
where
    Challenger: FieldChallenger<Goldilocks> + GrindingChallenger<Witness = Goldilocks>,
{
    ZkWhirConfig::new(
        num_variables,
        ProtocolParameters {
            security_level: C61_AUTHENTICATED_P3_SECURITY_BITS,
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

fn affine_from_p3(claim: ClaimlessAffineClaim<C61P3Fp2>) -> C61AuthenticatedWhirAffineClaim {
    C61AuthenticatedWhirAffineClaim {
        coefficient: c61_volta_fp2_from_p3(claim.coefficient),
        constant: c61_volta_fp2_from_p3(claim.constant),
    }
}

fn aggregate_prover_targets(
    targets: &[ProverAuthed],
    claim_weights: &[C61P3Fp2],
) -> Result<ProverAuthed, String> {
    if targets.is_empty() || targets.len() != claim_weights.len() || targets.len() > 128 {
        return Err("C6AWP1 provider target batch census mismatch".to_owned());
    }
    Ok(targets.iter().zip(claim_weights).fold(ProverAuthed::ZERO, |sum, (target, weight)| {
        sum.add(target.scale(c61_volta_fp2_from_p3(*weight)))
    }))
}

fn aggregate_verifier_targets(
    targets: &[VerifierKey],
    claim_weights: &[C61P3Fp2],
) -> Result<VerifierKey, String> {
    if targets.is_empty() || targets.len() != claim_weights.len() || targets.len() > 128 {
        return Err("C6AWP1 verifier target batch census mismatch".to_owned());
    }
    Ok(targets.iter().zip(claim_weights).fold(VerifierKey::ZERO, |sum, (target, weight)| {
        sum.add(target.scale(c61_volta_fp2_from_p3(*weight)))
    }))
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), String> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| "C6AWP1 structural byte count overflow".to_owned())?;
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
        .ok_or_else(|| "C6AWP1 opening row byte count overflow".to_owned())?;
    let siblings = c61_max_pruned_binary_siblings(leaves, queries)
        .checked_mul(C61_WHIRA1_DIGEST_BYTES)
        .ok_or_else(|| "C6AWP1 Merkle frontier byte count overflow".to_owned())?;
    C61_WHIRA1_MULTIPROOF_COUNT_BYTES
        .checked_add(rows)
        .and_then(|value| value.checked_add(siblings))
        .ok_or_else(|| "C6AWP1 opening byte count overflow".to_owned())
}

fn c61_authenticated_structural_budget_inner(
    num_variables: usize,
    production_dimensions_only: bool,
) -> Result<C61AuthenticatedP3StructuralBudget, String> {
    if production_dimensions_only && !matches!(num_variables, 27 | 28) {
        return Err("C6AWP1 production profile admits only D27 or D28".to_owned());
    }
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWP1 dimension must be in 4..=28".to_owned());
    }
    let config = c61_authenticated_config::<C61SizingChallenger>(num_variables)?;
    if config.params.pow_bits != 0
        || config.starting_folding_pow_bits != 0
        || config.final_pow_bits != 0
        || config.final_folding_pow_bits != 0
        || config
            .round_parameters
            .iter()
            .any(|round| round.pow_bits != 0 || round.folding_pow_bits != 0)
    {
        return Err("C6AWP1 forbids every proof-of-work transcript field".to_owned());
    }

    let mut round_opening_bytes = 0usize;
    let mut rounds_bytes = 0usize;
    let mut max_ood_samples = 0usize;
    let mut ood_privacy_bad_event_numerator = 0usize;
    for (index, round) in config.round_parameters.iter().enumerate() {
        let switch_mask = config
            .switch_masks
            .get(index)
            .ok_or_else(|| "C6AWP1 missing code-switch privacy mask".to_owned())?;
        let pad_slots =
            switch_mask.message_len.checked_sub(config.oracle_randomness[index]).ok_or_else(
                || "C6AWP1 code-switch mask is shorter than source randomness".to_owned(),
            )?;
        if pad_slots != round.ood_samples {
            return Err("C6AWP1 does not have one fresh pad slot per OOD answer".to_owned());
        }
        max_ood_samples = max_ood_samples.max(round.ood_samples);
        let round_bad_numerator = round
            .ood_samples
            .checked_add(1)
            .and_then(|successor| round.ood_samples.checked_mul(successor))
            .and_then(|value| value.checked_div(2))
            .ok_or_else(|| "C6AWP1 OOD privacy numerator overflow".to_owned())?;
        checked_add(&mut ood_privacy_bad_event_numerator, round_bad_numerator)?;
        let fold = config.round_folding_factor(index);
        let leaves = round.domain_size >> fold;
        let element_bytes = if index == 0 { C61_WHIRA1_FP_BYTES } else { C61_WHIRA1_FP2_BYTES };
        let opening = opening_bytes(leaves, round.num_queries, 1usize << fold, element_bytes)?;
        checked_add(&mut round_opening_bytes, opening)?;
        checked_add(
            &mut rounds_bytes,
            2 * C61_WHIRA1_DIGEST_BYTES + round.ood_samples * C61_WHIRA1_FP2_BYTES + opening,
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
            .ok_or_else(|| "C6AWP1 blinded-mask byte count overflow".to_owned())?;
        checked_add(&mut blinded_mask_bytes, group.width * one_mask)?;
    }

    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;
    let source_opening = opening_bytes(
        final_domain,
        config.final_queries,
        1usize << final_round.folding_factor,
        C61_WHIRA1_FP2_BYTES,
    )?;
    let fresh_main_opening =
        opening_bytes(final_domain, config.final_queries, 1, C61_WHIRA1_FP2_BYTES)?;
    let final_message_elements = 1usize << final_round.num_variables;
    let final_randomness_elements = config.oracle_randomness[config.n_rounds()];

    let mut base_case_bytes = 0usize;
    checked_add(&mut base_case_bytes, (1 + groups.len()) * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut base_case_bytes, C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, final_message_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, final_randomness_elements * C61_WHIRA1_FP2_BYTES)?;
    checked_add(&mut base_case_bytes, blinded_mask_bytes)?;
    checked_add(&mut base_case_bytes, source_opening)?;
    checked_add(&mut base_case_bytes, fresh_main_opening)?;
    checked_add(&mut base_case_bytes, base_mask_opening_bytes)?;

    let sumcheck_batches = config.n_rounds() + 1;
    let sumcheck_rounds: usize =
        (0..sumcheck_batches).map(|batch| config.round_folding_factor(batch)).sum();
    let sumcheck_bytes =
        (sumcheck_batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES;

    let mut strict_chain_bytes = C61_AUTHENTICATED_P3_HEADER_BYTES;
    checked_add(&mut strict_chain_bytes, C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut strict_chain_bytes, sumcheck_bytes)?;
    checked_add(&mut strict_chain_bytes, sumcheck_batches * C61_WHIRA1_DIGEST_BYTES)?;
    checked_add(&mut strict_chain_bytes, rounds_bytes)?;
    checked_add(&mut strict_chain_bytes, base_case_bytes)?;
    checked_add(&mut strict_chain_bytes, C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)?;

    if flat_mask_count != config.folding_schedule.iter().sum::<usize>() + config.n_rounds() {
        return Err("C6AWP1 mask-group census mismatch".to_owned());
    }
    if strict_chain_bytes > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(format!(
            "C6AWP1 D{num_variables} structural maximum {strict_chain_bytes} exceeds the native-chain cap"
        ));
    }

    Ok(C61AuthenticatedP3StructuralBudget {
        num_variables,
        rounds: config.n_rounds(),
        mask_queries: config.mask_queries,
        max_ood_samples,
        ood_privacy_bad_event_numerator,
        round_opening_bytes,
        base_mask_opening_bytes,
        blinded_mask_bytes,
        base_case_bytes,
        strict_chain_bytes,
    })
}

/// Exact structural maximum for the registered 75-bit C6AWP1 D27/D28
/// profile.  It includes the final 16-byte designated ZeroOpen tag and no
/// clear opening evaluation.
pub fn c61_authenticated_p3_structural_budget(
    num_variables: usize,
) -> Result<C61AuthenticatedP3StructuralBudget, String> {
    c61_authenticated_structural_budget_inner(num_variables, true)
}

fn c61_monolithic_initial_oracle_retained_lower_bound(
    num_variables: usize,
) -> Result<(u64, u64, u64, u64), String> {
    if !matches!(num_variables, 27 | 28) {
        return Err("C6SPR4 production admission admits only D27 or D28".to_owned());
    }
    let n = u32::try_from(num_variables)
        .map_err(|_| "C6SPR4 production dimension exceeds u32".to_owned())?;
    let field_bytes = u64::try_from(std::mem::size_of::<Goldilocks>())
        .map_err(|_| "C6SPR4 field width exceeds u64".to_owned())?;
    if field_bytes != C61_WHIRA1_FP_BYTES as u64 {
        return Err("C6SPR4 Goldilocks storage width changed".to_owned());
    }

    // The initial fold is one bit.  `zk_padded_matrix` therefore has 2^n
    // rows and width two, while the retained Boolean message has 2^n base
    // elements.  The binary MMCS stores digest layers of lengths
    // 2^n, 2^(n-1), ..., 1.
    let message_elements =
        1u64.checked_shl(n).ok_or_else(|| "C6SPR4 message geometry overflows".to_owned())?;
    let encoded_elements = message_elements
        .checked_mul(2)
        .ok_or_else(|| "C6SPR4 encoded geometry overflows".to_owned())?;
    let merkle_digests = encoded_elements
        .checked_sub(1)
        .ok_or_else(|| "C6SPR4 Merkle geometry underflows".to_owned())?;
    let message_bytes = message_elements
        .checked_mul(field_bytes)
        .ok_or_else(|| "C6SPR4 message bytes overflow".to_owned())?;
    let encoded_bytes = encoded_elements
        .checked_mul(field_bytes)
        .ok_or_else(|| "C6SPR4 encoded bytes overflow".to_owned())?;
    let merkle_bytes = merkle_digests
        .checked_mul(C61_WHIRA1_DIGEST_BYTES as u64)
        .ok_or_else(|| "C6SPR4 Merkle bytes overflow".to_owned())?;
    let retained = message_bytes
        .checked_add(encoded_bytes)
        .and_then(|bytes| bytes.checked_add(merkle_bytes))
        .ok_or_else(|| "C6SPR4 retained bytes overflow".to_owned())?;
    Ok((message_bytes, encoded_bytes, merkle_bytes, retained))
}

/// Compute the exact total-memory lower bound retained by the generic P3
/// prover at the registered D28/D27 geometry.
///
/// The generic diagnostic rejects D28 rather than attempting this allocation
/// without resource instrumentation.  This report does not compare total
/// memory against the narrower coefficient-plus-witness protocol cap.
pub fn c61_production_monolithic_memory_census(
) -> Result<C61ProductionMonolithicMemoryCensus, String> {
    let response_num_variables = 28;
    let plan_num_variables = 27;
    let (
        response_message_bytes,
        response_encoded_bytes,
        response_merkle_bytes,
        response_retained_lower_bound_bytes,
    ) = c61_monolithic_initial_oracle_retained_lower_bound(response_num_variables)?;
    let (
        plan_message_bytes,
        plan_encoded_bytes,
        plan_merkle_bytes,
        plan_retained_lower_bound_bytes,
    ) = c61_monolithic_initial_oracle_retained_lower_bound(plan_num_variables)?;
    let concurrent_retained_lower_bound_bytes = response_retained_lower_bound_bytes
        .checked_add(plan_retained_lower_bound_bytes)
        .ok_or_else(|| "C6SPR4 concurrent retained bytes overflow".to_owned())?;
    let retained_minus_component_cap_bytes = concurrent_retained_lower_bound_bytes
        .checked_sub(C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES)
        .ok_or_else(|| "C6SPR4 retained total is below its informative comparison".to_owned())?;
    Ok(C61ProductionMonolithicMemoryCensus {
        response_num_variables,
        plan_num_variables,
        response_message_bytes,
        response_encoded_bytes,
        response_merkle_bytes,
        response_retained_lower_bound_bytes,
        plan_message_bytes,
        plan_encoded_bytes,
        plan_merkle_bytes,
        plan_retained_lower_bound_bytes,
        concurrent_retained_lower_bound_bytes,
        coefficient_witness_cap_bytes: C61_PRODUCTION_COEFFICIENT_WITNESS_CAP_BYTES,
        retained_minus_component_cap_bytes,
    })
}

fn reject_monolithic_production_backend() -> Result<(), String> {
    let census = c61_production_monolithic_memory_census()?;
    Err(format!(
        "C6SPR4 generic diagnostic is not a resource-instrumented production executor: its concurrent D28/D27 P3 prover data retains at least {} B; use an explicit persisted/recomputable or GPU-resident executor and measure total RSS/GPU memory separately",
        census.concurrent_retained_lower_bound_bytes,
    ))
}

fn encode_fp_opening(
    writer: &mut C61Writer,
    opening: &SharedProofOpening<Goldilocks, C61MultiProof>,
    queries: usize,
    row_width: usize,
    leaves: usize,
) -> ReferenceResult<()> {
    if opening.rows.len() != queries || opening.rows.iter().any(|row| row.len() != row_width) {
        return Err(C61WhirReferenceError::new("C6AWP1 base-field opening shape mismatch"));
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
        return Err(C61WhirReferenceError::new("C6AWP1 extension opening shape mismatch"));
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

fn encode_c61_authenticated_p3_artifact_inner<MT>(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &ZkWhirProof<Goldilocks, C61P3Fp2, MT>,
    base_proof: C61AuthenticatedWhirBaseProof,
    production_dimensions_only: bool,
) -> ReferenceResult<Vec<u8>>
where
    MT: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>,
{
    let budget =
        c61_authenticated_structural_budget_inner(num_variables, production_dimensions_only)
            .map_err(C61WhirReferenceError::new)?;
    let config = c61_authenticated_config::<C61SizingChallenger>(num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut body = C61Writer::default();
    body.commitment(commitment)?;
    if proof.sumchecks.len() != batches || proof.sumcheck_mask_commitments.len() != batches {
        return Err(C61WhirReferenceError::new("C6AWP1 sumcheck batch count mismatch"));
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
            return Err(C61WhirReferenceError::new("C6AWP1 sumcheck shape mismatch"));
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
        return Err(C61WhirReferenceError::new("C6AWP1 round count mismatch"));
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
            return Err(C61WhirReferenceError::new("C6AWP1 round scalar shape mismatch"));
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
                return Err(C61WhirReferenceError::new("C6AWP1 round opening field tag mismatch"));
            }
        }
    }

    let base = &proof.base_case;
    body.commitment(&base.fresh_main_commitment)?;
    if base.fresh_mask_commitments.len() != groups.len() {
        return Err(C61WhirReferenceError::new("C6AWP1 fresh-mask commitment count mismatch"));
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
        return Err(C61WhirReferenceError::new("C6AWP1 base source reveal shape mismatch"));
    }
    for value in &base.blinded_message {
        body.fp2(*value);
    }
    for value in &base.blinded_randomness {
        body.fp2(*value);
    }

    let flat_masks: usize = groups.iter().map(|group| group.width).sum();
    if base.blinded_masks.len() != flat_masks {
        return Err(C61WhirReferenceError::new("C6AWP1 blinded-mask count mismatch"));
    }
    let mut mask_index = 0usize;
    for group in &groups {
        for _ in 0..group.width {
            let mask = &base.blinded_masks[mask_index];
            mask_index += 1;
            if mask.message.len() != group.shape.message_len
                || mask.randomness.len() != group.shape.randomness_len
            {
                return Err(C61WhirReferenceError::new("C6AWP1 blinded-mask shape mismatch"));
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
        return Err(C61WhirReferenceError::new("C6AWP1 forbids a base-case PoW witness"));
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
            return Err(C61WhirReferenceError::new("C6AWP1 final source opening must use Fp2"));
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
        return Err(C61WhirReferenceError::new("C6AWP1 mask-opening group count mismatch"));
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
    body.bytes.extend_from_slice(&base_proof.encode());

    let total = C61_AUTHENTICATED_P3_HEADER_BYTES
        .checked_add(body.bytes.len())
        .ok_or_else(|| C61WhirReferenceError::new("C6AWP1 total length overflow"))?;
    if total > budget.strict_chain_bytes || total > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds its structural cap"));
    }
    let mut writer = C61Writer::default();
    writer.bytes.extend_from_slice(&C61_AUTHENTICATED_P3_MAGIC);
    writer.u16(C61_AUTHENTICATED_P3_VERSION);
    writer.u8(u8::try_from(num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6AWP1 dimension exceeds u8"))?);
    writer.u8(0);
    writer.u32(body.bytes.len())?;
    writer.bytes.extend_from_slice(&body.bytes);
    Ok(writer.bytes)
}

fn decode_c61_authenticated_p3_artifact_inner(
    bytes: &[u8],
    expected_num_variables: usize,
    production_dimensions_only: bool,
) -> ReferenceResult<(C61Commitment, C61AuthenticatedP3Proof, C61AuthenticatedWhirBaseProof)> {
    if bytes.len() > C61_NATIVE_CHAIN_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds native-chain cap"));
    }
    let budget = c61_authenticated_structural_budget_inner(
        expected_num_variables,
        production_dimensions_only,
    )
    .map_err(C61WhirReferenceError::new)?;
    if bytes.len() > budget.strict_chain_bytes {
        return Err(C61WhirReferenceError::new("C6AWP1 payload exceeds its structural cap"));
    }
    let config = c61_authenticated_config::<C61SizingChallenger>(expected_num_variables)
        .map_err(C61WhirReferenceError::new)?;
    let batches = config.n_rounds() + 1;
    let groups = config.mask_groups();
    let final_round = config.final_round_config();
    let final_domain = final_round.domain_size >> final_round.folding_factor;

    let mut reader = C61Reader::new(bytes);
    if reader.take(8)? != C61_AUTHENTICATED_P3_MAGIC {
        return Err(C61WhirReferenceError::new("C6AWP1 magic mismatch"));
    }
    if reader.u16()? != C61_AUTHENTICATED_P3_VERSION {
        return Err(C61WhirReferenceError::new("C6AWP1 version mismatch"));
    }
    if reader.u8()? as usize != expected_num_variables {
        return Err(C61WhirReferenceError::new("C6AWP1 dimension mismatch"));
    }
    if reader.u8()? != 0 {
        return Err(C61WhirReferenceError::new("C6AWP1 reserved byte is nonzero"));
    }
    let body_len = reader.u32()?;
    if body_len != bytes.len().saturating_sub(C61_AUTHENTICATED_P3_HEADER_BYTES) {
        return Err(C61WhirReferenceError::new("C6AWP1 body length mismatch"));
    }

    let commitment = reader.commitment()?;
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
        sumchecks.push(ClaimlessZkSumcheckData {
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
        let commitment = reader.commitment()?;
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
            commitment,
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
    let base_proof = C61AuthenticatedWhirBaseProof::decode(
        reader.take(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)?,
    )
    .map_err(|error| C61WhirReferenceError::new(error.to_string()))?;
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
    Ok((
        commitment,
        ZkWhirProof { sumchecks, sumcheck_mask_commitments, rounds, base_case },
        base_proof,
    ))
}

fn encode_c61_shared_multi_oracle_artifact(
    response_num_variables: usize,
    plan_num_variables: usize,
    response_payload: &[u8],
    plan_payload: &[u8],
) -> ReferenceResult<C61SharedMultiOracleArtifact> {
    let (_, _, _) = decode_c61_authenticated_p3_artifact_inner(
        response_payload,
        response_num_variables,
        false,
    )?;
    let (_, _, plan_reserved_tag) =
        decode_c61_authenticated_p3_artifact_inner(plan_payload, plan_num_variables, false)?;
    if plan_reserved_tag.tag() != Fp2::ZERO {
        return Err(C61WhirReferenceError::new(
            "C6SMO1 plan payload must carry the canonical zero reserved tag",
        ));
    }
    let body_len = response_payload
        .len()
        .checked_add(plan_payload.len())
        .ok_or_else(|| C61WhirReferenceError::new("C6SMO1 body length overflow"))?;
    let total_len = C61_SHARED_MULTI_ORACLE_HEADER_BYTES
        .checked_add(body_len)
        .ok_or_else(|| C61WhirReferenceError::new("C6SMO1 total length overflow"))?;
    if total_len > C61_SHARED_MULTI_ORACLE_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6SMO1 payload exceeds compiler-chain cap"));
    }
    let mut writer = C61Writer::default();
    writer.bytes.extend_from_slice(&C61_SHARED_MULTI_ORACLE_MAGIC);
    writer.u16(C61_SHARED_MULTI_ORACLE_VERSION);
    writer.u8(u8::try_from(response_num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6SMO1 response dimension exceeds u8"))?);
    writer.u8(u8::try_from(plan_num_variables)
        .map_err(|_| C61WhirReferenceError::new("C6SMO1 plan dimension exceeds u8"))?);
    writer.u32(response_payload.len())?;
    writer.bytes.extend_from_slice(response_payload);
    writer.bytes.extend_from_slice(plan_payload);
    Ok(C61SharedMultiOracleArtifact { payload: writer.bytes })
}

fn decode_c61_shared_multi_oracle_artifact(
    artifact: &C61SharedMultiOracleArtifact,
    expected_response_num_variables: usize,
    expected_plan_num_variables: usize,
) -> ReferenceResult<(
    (C61Commitment, C61AuthenticatedP3Proof),
    (C61Commitment, C61AuthenticatedP3Proof),
    C61AuthenticatedWhirBaseProof,
)> {
    if artifact.payload.len() > C61_SHARED_MULTI_ORACLE_MAX_BYTES {
        return Err(C61WhirReferenceError::new("C6SMO1 payload exceeds compiler-chain cap"));
    }
    let mut reader = C61Reader::new(&artifact.payload);
    if reader.take(8)? != C61_SHARED_MULTI_ORACLE_MAGIC {
        return Err(C61WhirReferenceError::new("C6SMO1 magic mismatch"));
    }
    if reader.u16()? != C61_SHARED_MULTI_ORACLE_VERSION {
        return Err(C61WhirReferenceError::new("C6SMO1 version mismatch"));
    }
    if reader.u8()? as usize != expected_response_num_variables {
        return Err(C61WhirReferenceError::new("C6SMO1 response dimension mismatch"));
    }
    if reader.u8()? as usize != expected_plan_num_variables {
        return Err(C61WhirReferenceError::new("C6SMO1 plan dimension mismatch"));
    }
    let response_len = reader.u32()?;
    if response_len == 0
        || response_len
            > artifact.payload.len().saturating_sub(C61_SHARED_MULTI_ORACLE_HEADER_BYTES)
    {
        return Err(C61WhirReferenceError::new("C6SMO1 response length is noncanonical"));
    }
    let response_payload = reader.take(response_len)?;
    let plan_payload = reader.take(
        artifact
            .payload
            .len()
            .saturating_sub(C61_SHARED_MULTI_ORACLE_HEADER_BYTES)
            .saturating_sub(response_len),
    )?;
    reader.finish()?;
    if plan_payload.is_empty() {
        return Err(C61WhirReferenceError::new("C6SMO1 plan payload is empty"));
    }
    let (response_commitment, response_proof, joint_tag) =
        decode_c61_authenticated_p3_artifact_inner(
            response_payload,
            expected_response_num_variables,
            false,
        )?;
    let (plan_commitment, plan_proof, plan_reserved_tag) =
        decode_c61_authenticated_p3_artifact_inner(
            plan_payload,
            expected_plan_num_variables,
            false,
        )?;
    if plan_reserved_tag.tag() != Fp2::ZERO {
        return Err(C61WhirReferenceError::new("C6SMO1 plan reserved tag is nonzero"));
    }
    Ok(((response_commitment, response_proof), (plan_commitment, plan_proof), joint_tag))
}

#[allow(clippy::too_many_arguments)]
fn prove_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedP3Fixture, u64), String> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err("C6AWH1-P3 witness/point dimension mismatch".to_owned());
    }
    let evaluation_p3 = witness.eval_base(&point);
    let evaluation = c61_volta_fp2_from_p3(evaluation_p3);
    let target = ProverAuthed::new(evaluation, target_tag);
    let target_key = VerifierKey::new(target_tag + delta * evaluation);

    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = StdRng::seed_from_u64(prover_rng_seed);
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);

    // The low-level fork deliberately has no target-revealing PCS adapter.
    // Reproduce its load-bearing statement order explicitly: root first,
    // then the verifier-owned opening point, then the first native challenge.
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    let mut correlations = CorrelationStream::new(pcg_seed);
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
        .map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), evaluation_p3)],
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;

    // Account for every serialized WHIR byte before the final ZeroOpen move.
    // Challenge-bearing fields were already observed in interactive order;
    // the tag itself is the final 16-byte move appended by C6AWH1.
    let placeholder_base_proof =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        placeholder_base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let provider_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&[target], &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 ZeroOpen tag changed the strict payload length".to_owned());
    }

    Ok((
        C61AuthenticatedP3Fixture {
            artifact: C61AuthenticatedP3Artifact { payload },
            point,
            target_key,
            provider_affine,
            provider_base_case: output.base_case,
            provider_interaction,
            provider_transcript_bytes: transcript.total_bytes(),
            provider_ledger: transcript.ledger().clone(),
        },
        correlations.counters.full_corrs,
    ))
}

fn c61_private_entropy_context_digest(
    point: &Point<C61P3Fp2>,
    target_key: VerifierKey,
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"C6ICT1-private-entropy-context-v1");
    hasher.update(&(point.num_variables() as u64).to_le_bytes());
    for coordinate in point.as_slice() {
        let coefficients: &[Goldilocks] =
            <C61P3Fp2 as BasedVectorSpace<Goldilocks>>::as_basis_coefficients_slice(coordinate);
        for coefficient in coefficients {
            hasher.update(&coefficient.as_canonical_u64().to_le_bytes());
        }
    }
    hasher.update(&target_key.k.c0.value().to_le_bytes());
    hasher.update(&target_key.k.c1.value().to_le_bytes());
    hasher.update(&delta.c0.value().to_le_bytes());
    hasher.update(&delta.c1.value().to_le_bytes());
    hasher.update(&[match id.component {
        C61NativeComponent::Model => 0,
        C61NativeComponent::Embedding => 1,
        C61NativeComponent::Compiler => 2,
    }]);
    hasher.update(&[id.repetition]);
    hasher.update(&[mask_range.stage]);
    hasher.update(&mask_range.slot.to_le_bytes());
    hasher.update(&mask_range.range_start.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[allow(clippy::too_many_arguments)]
fn prove_private_entropy_provider_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    mut challenger: C61PrivateEntropyProverChallenger,
) -> Result<C61PrivateEntropyProviderFixture, String> {
    let num_variables = witness.num_variables();
    if point.num_variables() != num_variables {
        return Err("C6ICT1 witness/point dimension mismatch".to_owned());
    }
    let evaluation_p3 = witness.eval_base(&point);
    let evaluation = c61_volta_fp2_from_p3(evaluation_p3);
    let target = ProverAuthed::new(evaluation, target_tag);
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let config = c61_authenticated_config::<C61PrivateEntropyProverChallenger>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let mut rng = StdRng::seed_from_u64(prover_rng_seed);
    let (commitment, data) = prover.commit(witness, &mut challenger, &mut rng);
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    let mut correlations = CorrelationStream::new(pcg_seed);
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
        .map_err(|error| error.to_string())?;
    challenger.note_mask_frontier(1).map_err(|error| error.to_string())?;
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), evaluation_p3)],
        c61_p3_fp2_from_volta(prepared.value()),
        &mut challenger,
        &mut rng,
    );

    // This transcript is provider-side accounting for the terminal ZeroOpen
    // only.  Its dummy seed is never used to draw a challenge; all native
    // challenges came through the endpoint-only transport challenger.
    let mut zero_open_transcript = Transcript::new([0u8; 32]);
    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&[target], &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut zero_open_transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let finish_result = challenger.finish(&payload[..whir_payload_bytes]);
    drop(challenger);
    finish_result.map_err(|error| error.to_string())?;

    Ok(C61PrivateEntropyProviderFixture {
        artifact: C61AuthenticatedP3Artifact { payload },
        point,
        target_key,
        provider_affine,
        provider_base_case: output.base_case,
        full_correlations: correlations.counters.full_corrs,
    })
}

#[allow(clippy::too_many_arguments)]
fn prove_private_entropy_diagnostic(
    witness: Poly<Goldilocks>,
    point: Point<C61P3Fp2>,
    verifier_seed: [u8; 32],
    prover_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    target_tag: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    checkpoint: C61InteractiveCheckpoint,
    durable: Option<C61DurableJournal>,
) -> Result<C61PrivateEntropyFixture, String> {
    let num_variables = witness.num_variables();
    let evaluation = c61_volta_fp2_from_p3(witness.eval_base(&point));
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let context_digest =
        c61_private_entropy_context_digest(&point, target_key, delta, id, mask_range);
    let (challenger, broker_handle) = match durable {
        Some(journal) => spawn_c61_durable_private_entropy_broker(
            verifier_seed,
            num_variables,
            context_digest,
            journal,
        ),
        None => spawn_c61_private_entropy_broker(
            verifier_seed,
            num_variables,
            context_digest,
            checkpoint,
        ),
    }
    .map_err(|error| error.to_string())?;
    let provider = prove_private_entropy_provider_diagnostic(
        witness,
        point,
        prover_rng_seed,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        challenger,
    );
    let broker = broker_handle
        .join()
        .map_err(|_| "C6ICT1 verifier broker panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    let provider = provider?;
    let whir_payload_bytes = provider
        .artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    if broker.transcript_bytes != whir_payload_bytes as u64 {
        return Err("C6ICT1 broker payload accounting mismatch".to_owned());
    }
    Ok(C61PrivateEntropyFixture {
        artifact: provider.artifact,
        point: provider.point,
        target_key: provider.target_key,
        provider_affine: provider.provider_affine,
        provider_base_case: provider.provider_base_case,
        broker,
        full_correlations: provider.full_correlations,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_private_entropy_diagnostic(
    artifact: &C61AuthenticatedP3Artifact,
    point: &Point<C61P3Fp2>,
    target_key: VerifierKey,
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    tape: C61InteractiveTape,
) -> Result<
    (C61AuthenticatedWhirAffineClaim, BaseCaseClaimlessClosure<C61P3Fp2>, C61WhirInteractionStats),
    String,
> {
    let num_variables = point.num_variables();
    let context_digest =
        c61_private_entropy_context_digest(point, target_key, delta, id, mask_range);
    let (commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&artifact.payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut challenger =
        C61PrivateEntropyReplayChallenger::new(tape, num_variables, context_digest)
            .map_err(|error| error.to_string())?;
    let config = c61_authenticated_config::<C61PrivateEntropyReplayChallenger>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(commitment.clone());
    challenger.observe_public_point(point).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(&proof, &commitment, std::slice::from_ref(point), &mut challenger)
    }))
    .map_err(|_| "C6ICT1 fork verifier panicked".to_owned())?
    .map_err(|error| format!("C6ICT1 verification failed: {error}"))?;
    let whir_payload_bytes = artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6ICT1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let verifier_interaction = challenger
        .finish(&artifact.payload[..whir_payload_bytes])
        .map_err(|error| error.to_string())?;
    drop(challenger);

    let verifier_affine = affine_from_p3(result.target);
    let aggregate_target = aggregate_verifier_targets(&[target_key], &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_target, delta);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let mut zero_open_transcript = Transcript::new([0u8; 32]);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut zero_open_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok((verifier_affine, result.base_case, verifier_interaction))
}

/// Produce an accepting designated-verifier view without the real witness or
/// target plaintext.  This is deliberately separate from `prove_diagnostic`:
/// it has no target-plaintext/tag argument and never constructs a provider
/// correlation stream.
#[allow(clippy::too_many_arguments)]
fn simulate_view_diagnostic(
    num_variables: usize,
    point: Point<C61P3Fp2>,
    target_key: VerifierKey,
    verifier_seed: [u8; 32],
    simulator_rng_seed: u64,
    pcg_seed: [u8; 32],
    delta: Fp2,
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<(C61AuthenticatedP3Fixture, u64), String> {
    if point.num_variables() != num_variables {
        return Err("C6AWP1 simulator point dimension mismatch".to_owned());
    }

    // A simulator may generate internal dummy values; it must not receive the
    // real relation witness.  A uniform surrogate makes the executable path
    // exercise the full commitment/opening machinery without coupling it to
    // the real target hidden behind `target_key`.
    let mut rng = StdRng::seed_from_u64(simulator_rng_seed);
    let surrogate = Poly::new((0..(1usize << num_variables)).map(|_| rng.random()).collect());
    let surrogate_evaluation = surrogate.eval_base(&point);

    let mut transcript = Transcript::new(verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    let dft = Radix2DFTSmallBatch::default();
    let prover = HidingWhirProver::new(&config, &dft, &mmcs);
    let (commitment, data) = prover.commit(surrogate, &mut challenger, &mut rng);
    challenger.observe_public_point(&point).map_err(|error| error.to_string())?;

    // In a real execution this shift is the plaintext half of the fresh
    // C6AWH1 correlation.  Conditioned on the verifier's mask key it remains
    // uniform, so the simulator samples it directly and later derives the
    // only correlated observable (the final tag) from verifier state.
    let simulated_base_shift: C61P3Fp2 = rng.random();
    let output = prover.prove_claimless(
        data,
        &[(point.clone(), surrogate_evaluation)],
        simulated_base_shift,
        &mut challenger,
        &mut rng,
    );
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;

    let placeholder_base_proof =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        placeholder_base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 simulator payload is shorter than its ZeroOpen tag".to_owned())?;
    let simulator_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_verifier_targets(&[target_key], &output.claim_weights)?;
    let final_key = affine.derive_verifier_key(aggregate_target, delta);
    let mut simulator_context = VerifierCtx::new(pcg_seed, delta);
    let base_proof = simulate_c61_authenticated_whir_base_view(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_key,
        },
        &mut simulator_context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        base_proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 simulator tag changed the strict payload length".to_owned());
    }

    Ok((
        C61AuthenticatedP3Fixture {
            artifact: C61AuthenticatedP3Artifact { payload },
            point,
            target_key,
            provider_affine: affine,
            provider_base_case: output.base_case,
            provider_interaction: simulator_interaction,
            provider_transcript_bytes: transcript.total_bytes(),
            provider_ledger: transcript.ledger().clone(),
        },
        simulator_context.counters.full_corrs,
    ))
}

fn verify_diagnostic(
    artifact: &C61AuthenticatedP3Artifact,
    input: C61AuthenticatedP3VerifierInput<'_>,
) -> Result<
    (
        C61AuthenticatedWhirAffineClaim,
        BaseCaseClaimlessClosure<C61P3Fp2>,
        Transcript,
        C61WhirInteractionStats,
    ),
    String,
> {
    let num_variables = input.point.num_variables();
    let (commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&artifact.payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut transcript = Transcript::new(input.verifier_seed);
    let mut challenger = C61InteractiveChallenger::new_claimless(&mut transcript, num_variables);
    let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let mmcs = c61_reference_mmcs();
    challenger.observe(commitment.clone());
    challenger.observe_public_point(input.point).map_err(|error| error.to_string())?;
    let verifier = HidingWhirVerifier::new(&config, &mmcs);
    let result = catch_unwind(AssertUnwindSafe(|| {
        verifier.verify_claimless(
            &proof,
            &commitment,
            std::slice::from_ref(input.point),
            &mut challenger,
        )
    }))
    .map_err(|_| "C6AWH1-P3 fork verifier panicked".to_owned())?
    .map_err(|error| format!("C6AWH1-P3 verification failed: {error}"))?;
    challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
    let whir_payload_bytes = artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6AWP1 payload is shorter than its ZeroOpen tag".to_owned())?;
    let verifier_interaction =
        challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
    drop(challenger);

    let verifier_affine = affine_from_p3(result.target);
    let aggregate_target = aggregate_verifier_targets(&[input.target_key], &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_target, input.delta);
    let mut context = VerifierCtx::new(input.pcg_seed, input.delta);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id: input.id,
            mask_range: input.mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok((verifier_affine, result.base_case, transcript, verifier_interaction))
}

/// Run one reference-only end-to-end differential.  Small dimensions are
/// diagnostic; D27/D28 remain the only production-profile shapes.
pub fn run_c61_authenticated_whir_p3_diagnostic(
    num_variables: usize,
) -> Result<C61AuthenticatedP3Diagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWH1-P3 diagnostic dimension must be in 4..=28".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(17).wrapping_add(3)))
            .collect(),
    );
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(19).wrapping_add(5)))
            .collect(),
    );
    let verifier_seed = [0x61; 32];
    let pcg_seed = [0xA7; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 17), volta_field::Fp::new(0x1234_5678));
    let target_tag = Fp2::new(volta_field::Fp::new(41), volta_field::Fp::new(43));
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 1, range_start: 40_000 };
    let (fixture, full_correlations) = prove_diagnostic(
        witness,
        point,
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
    )?;
    let (verifier_affine, verifier_base_case, verifier_transcript, verifier_interaction) =
        verify_diagnostic(
            &fixture.artifact,
            C61AuthenticatedP3VerifierInput {
                point: &fixture.point,
                target_key: fixture.target_key,
                verifier_seed,
                pcg_seed,
                delta,
                id,
                mask_range,
            },
        )?;
    if fixture.provider_affine != verifier_affine {
        return Err("C6AWH1-P3 provider/verifier affine replay mismatch".to_owned());
    }
    if fixture.provider_base_case != verifier_base_case {
        return Err("C6AWH1-P3 provider/verifier base closure mismatch".to_owned());
    }
    if fixture.provider_interaction != verifier_interaction {
        return Err("C6AWP1 provider/verifier interaction accounting mismatch".to_owned());
    }
    if fixture.provider_ledger != *verifier_transcript.ledger() {
        return Err("C6AWH1-P3 provider/verifier transcript ledger mismatch".to_owned());
    }
    Ok(C61AuthenticatedP3Diagnostic {
        num_variables,
        provider_affine: fixture.provider_affine,
        verifier_affine,
        provider_transcript_bytes: fixture.provider_transcript_bytes,
        verifier_transcript_bytes: verifier_transcript.total_bytes(),
        provider_ledger: fixture.provider_ledger,
        verifier_ledger: verifier_transcript.ledger().clone(),
        strict_payload_bytes: fixture.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&fixture.artifact.payload).as_bytes(),
        provider_interaction: fixture.provider_interaction,
        verifier_interaction,
        proof_has_clear_evaluation_field: false,
        full_correlations,
    })
}

/// Exercise the exact ordered multi-opening reduction needed by the future
/// model/embedding adapter.  This remains a scaled feature-only diagnostic:
/// it proves openings of one committed polynomial, not yet the complete C6
/// compiler relation.
pub fn run_c61_authenticated_whir_p3_multi_open_diagnostic(
    num_variables: usize,
    claim_count: usize,
) -> Result<C61AuthenticatedP3MultiOpenDiagnostic, String> {
    if !(4..=20).contains(&num_variables) || !(2..=128).contains(&claim_count) {
        return Err("C6AWP1 multi-open diagnostic geometry is out of range".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(31).wrapping_add(7)))
            .collect(),
    );
    let points: Vec<_> = (0..claim_count)
        .map(|claim| {
            Point::new(
                (0..num_variables)
                    .map(|coordinate| {
                        C61P3Fp2::from_u64(
                            (claim as u64 + 3)
                                .wrapping_mul(37)
                                .wrapping_add((coordinate as u64 + 5).wrapping_mul(41)),
                        )
                    })
                    .collect(),
            )
        })
        .collect();
    let evaluations: Vec<_> = points.iter().map(|point| witness.eval_base(point)).collect();
    let delta = Fp2::new(volta_field::Fp::new(P - 59), volta_field::Fp::new(0xC6_6101));
    let targets: Vec<_> = evaluations
        .iter()
        .enumerate()
        .map(|(index, evaluation)| {
            let value = c61_volta_fp2_from_p3(*evaluation);
            let tag = Fp2::new(
                volta_field::Fp::new(101 + index as u64 * 2),
                volta_field::Fp::new(103 + index as u64 * 2),
            );
            ProverAuthed::new(value, tag)
        })
        .collect();
    let target_keys: Vec<_> =
        targets.iter().map(|target| VerifierKey::new(target.m + delta * target.x)).collect();
    let claims: Vec<_> = points.iter().cloned().zip(evaluations.iter().copied()).collect();
    let verifier_seed = [0xB7; 32];
    let pcg_seed = [0xD9; 32];
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 1 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 21, range_start: 90_000 };

    let mut provider_transcript = Transcript::new(verifier_seed);
    let mut correlations = CorrelationStream::new(pcg_seed);
    let (
        commitment,
        output,
        prepared,
        placeholder_payload,
        whir_payload_bytes,
        provider_interaction,
    ) = {
        let mut provider_challenger =
            C61InteractiveChallenger::new_claimless(&mut provider_transcript, num_variables);
        let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
        let mmcs = c61_reference_mmcs();
        let dft = Radix2DFTSmallBatch::default();
        let prover = HidingWhirProver::new(&config, &dft, &mmcs);
        let mut rng = StdRng::seed_from_u64(0xC6_6101);
        let (commitment, data) = prover.commit(witness, &mut provider_challenger, &mut rng);
        provider_challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
        let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, &mut correlations)
            .map_err(|error| error.to_string())?;
        let output = prover.prove_claimless(
            data,
            &claims,
            c61_p3_fp2_from_volta(prepared.value()),
            &mut provider_challenger,
            &mut rng,
        );
        provider_challenger.ensure_public_statement_bound().map_err(|error| error.to_string())?;
        let placeholder = C61AuthenticatedWhirBaseProof::decode(
            &[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES],
        )
        .map_err(|error| error.to_string())?;
        let placeholder_payload = encode_c61_authenticated_p3_artifact_inner(
            num_variables,
            &commitment,
            &output.proof,
            placeholder,
            false,
        )
        .map_err(|error| error.to_string())?;
        let whir_payload_bytes = placeholder_payload
            .len()
            .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
            .ok_or_else(|| "C6AWP1 multi-open payload is shorter than its tag".to_owned())?;
        let provider_interaction =
            provider_challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
        (
            commitment,
            output,
            prepared,
            placeholder_payload,
            whir_payload_bytes,
            provider_interaction,
        )
    };
    let provider_affine = affine_from_p3(output.target);
    let aggregate_target = aggregate_prover_targets(&targets, &output.claim_weights)?;
    let final_target = provider_affine.authenticate_prover(aggregate_target);
    let provider_closure = finish_c61_authenticated_whir_base(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: c61_volta_fp2_from_p3(output.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(output.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(output.base_case.gamma),
            target: final_target,
        },
        &mut provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let payload = encode_c61_authenticated_p3_artifact_inner(
        num_variables,
        &commitment,
        &output.proof,
        provider_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    if payload.len() != placeholder_payload.len() {
        return Err("C6AWP1 multi-open tag changed the strict payload length".to_owned());
    }

    let (decoded_commitment, proof, base_proof) =
        decode_c61_authenticated_p3_artifact_inner(&payload, num_variables, false)
            .map_err(|error| error.to_string())?;
    let mut verifier_transcript = Transcript::new(verifier_seed);
    let (result, verifier_interaction) = {
        let mut verifier_challenger =
            C61InteractiveChallenger::new_claimless(&mut verifier_transcript, num_variables);
        let config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
        let mmcs = c61_reference_mmcs();
        verifier_challenger.observe(decoded_commitment.clone());
        verifier_challenger.observe_public_points(&points).map_err(|error| error.to_string())?;
        let verifier = HidingWhirVerifier::new(&config, &mmcs);
        let result = catch_unwind(AssertUnwindSafe(|| {
            verifier.verify_claimless(
                &proof,
                &decoded_commitment,
                &points,
                &mut verifier_challenger,
            )
        }))
        .map_err(|_| "C6AWP1 multi-open verifier panicked".to_owned())?
        .map_err(|error| format!("C6AWP1 multi-open verification failed: {error}"))?;
        let verifier_interaction =
            verifier_challenger.finish(whir_payload_bytes).map_err(|error| error.to_string())?;
        (result, verifier_interaction)
    };
    let verifier_affine = affine_from_p3(result.target);
    let aggregate_key = aggregate_verifier_targets(&target_keys, &result.claim_weights)?;
    let final_key = verifier_affine.derive_verifier_key(aggregate_key, delta);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    verify_c61_authenticated_whir_base(
        C61AuthenticatedWhirVerifierInput {
            id,
            mask_range,
            combined: c61_volta_fp2_from_p3(result.base_case.combined),
            shifted_masked_claim: c61_volta_fp2_from_p3(result.base_case.shifted_masked_claim),
            gamma: c61_volta_fp2_from_p3(result.base_case.gamma),
            target: final_key,
        },
        base_proof,
        &mut context,
        &mut verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    if provider_affine != verifier_affine
        || provider_interaction != verifier_interaction
        || provider_transcript.ledger() != verifier_transcript.ledger()
    {
        return Err("C6AWP1 multi-open role differential mismatch".to_owned());
    }

    let mut changed_points = points.clone();
    let mut changed_coordinates = changed_points[0].as_slice().to_vec();
    changed_coordinates[0] += C61P3Fp2::ONE;
    changed_points[0] = Point::new(changed_coordinates);
    let mut changed_transcript = Transcript::new(verifier_seed);
    let mut changed_challenger =
        C61InteractiveChallenger::new_claimless(&mut changed_transcript, num_variables);
    let changed_config = c61_authenticated_config::<C61InteractiveChallenger<'_>>(num_variables)?;
    let changed_mmcs = c61_reference_mmcs();
    let changed_verifier = HidingWhirVerifier::new(&changed_config, &changed_mmcs);
    changed_challenger.observe(decoded_commitment.clone());
    changed_challenger.observe_public_points(&changed_points).map_err(|error| error.to_string())?;
    let changed_result = catch_unwind(AssertUnwindSafe(|| {
        changed_verifier.verify_claimless(
            &proof,
            &decoded_commitment,
            &changed_points,
            &mut changed_challenger,
        )
    }));
    let point_mutation_rejected = match changed_result {
        Err(_) | Ok(Err(_)) => true,
        Ok(Ok(changed_closure)) => {
            let finish = changed_challenger.finish(whir_payload_bytes);
            let aggregate_key =
                aggregate_verifier_targets(&target_keys, &changed_closure.claim_weights);
            let (_, _, changed_base_proof) =
                decode_c61_authenticated_p3_artifact_inner(&payload, num_variables, false)
                    .map_err(|error| error.to_string())?;
            match (finish, aggregate_key) {
                (Ok(_), Ok(aggregate_key)) => {
                    let changed_affine = affine_from_p3(changed_closure.target);
                    let changed_final_key =
                        changed_affine.derive_verifier_key(aggregate_key, delta);
                    let mut changed_context = VerifierCtx::new(pcg_seed, delta);
                    verify_c61_authenticated_whir_base(
                        C61AuthenticatedWhirVerifierInput {
                            id,
                            mask_range,
                            combined: c61_volta_fp2_from_p3(changed_closure.base_case.combined),
                            shifted_masked_claim: c61_volta_fp2_from_p3(
                                changed_closure.base_case.shifted_masked_claim,
                            ),
                            gamma: c61_volta_fp2_from_p3(changed_closure.base_case.gamma),
                            target: changed_final_key,
                        },
                        changed_base_proof,
                        &mut changed_context,
                        &mut changed_transcript,
                    )
                    .is_err()
                }
                _ => true,
            }
        }
    };

    Ok(C61AuthenticatedP3MultiOpenDiagnostic {
        num_variables,
        claim_count,
        strict_payload_bytes: payload.len(),
        strict_payload_max_bytes: c61_authenticated_structural_budget_inner(num_variables, false)?
            .strict_chain_bytes,
        provider_interaction,
        verifier_interaction,
        batching_weights_identical: output.claim_weights == result.claim_weights,
        point_mutation_rejected,
        full_correlations: correlations.counters.full_corrs,
    })
}

fn c61_shared_statement_digest(
    response: &C61Commitment,
    plan: &C61Commitment,
    response_points: &[Point<C61P3Fp2>],
    plan_points: &[Point<C61P3Fp2>],
) -> Result<[u8; 32], String> {
    if response.num_roots() != 1 || plan.num_roots() != 1 {
        return Err("C6SMO1 statement requires one root per oracle".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/shared-multi-oracle/v1");
    hasher.update(&response.roots()[0]);
    hasher.update(&plan.roots()[0]);
    for (role, points) in [(0u8, response_points), (1u8, plan_points)] {
        hasher.update(&[role]);
        hasher.update(&(points.len() as u64).to_le_bytes());
        for point in points {
            hasher.update(&(point.num_variables() as u64).to_le_bytes());
            for coordinate in point.as_slice() {
                let limbs: &[Goldilocks] = coordinate.as_basis_coefficients_slice();
                for limb in limbs {
                    hasher.update(&limb.as_canonical_u64().to_le_bytes());
                }
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn c61_sparse_shared_statement_digest(
    response: &C61Commitment,
    plan: &C61Commitment,
    response_points: &[Point<C61P3Fp2>],
    plan_points: &[Point<C61P3Fp2>],
    relation_digest: [u8; 32],
    arithmetic_payload: &[u8],
    plan_values: &[Fp2; 3],
) -> Result<[u8; 32], String> {
    let base = c61_shared_statement_digest(response, plan, response_points, plan_points)?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/sparse-shared-statement/v1");
    hasher.update(&base);
    hasher.update(&relation_digest);
    hasher.update(blake3::hash(arithmetic_payload).as_bytes());
    for value in plan_values {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

enum C61SparseCompilerSource<'a> {
    Scaled(volta_proto::c6_residual::C6ResidualFusedScaledFixture),
    Production {
        operation_plan: &'a C6InstalledOperationPlan,
        extraction: &'a volta_mac::C6DecodedInstanceExtractionPlan,
        runtime: &'a volta_mac::C6RuntimeInstanceValues,
        relation: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    },
}

struct C61SparseCompilerPhysicalFixture<'a> {
    source: C61SparseCompilerSource<'a>,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    lanes: [volta_proto::c6_residual::C6ResidualFoldedTerminalAdjointLaneReference; 2],
    packed: volta_proto::c6_residual::C6SparseRationalPackedOracleReference,
    output_beta: Fp2,
    production: bool,
}

/// Public-only view handed to the verifier phase.  In particular this type
/// has no extraction map, runtime values, adjoint lanes, response
/// coefficients, or combined relation vectors.
struct C61SparseCompilerVerifierFixture<'a> {
    operation_plan: &'a C6InstalledOperationPlan,
    terminal_metadata: &'a C6OperationPlanTerminalMetadata,
    relation_challenges: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    output_beta: Fp2,
    base_domain_log2: u8,
    response_digest: [u8; 32],
    plan_digest: [u8; 32],
    physical_plan_values: Vec<Fp2>,
}

impl C61SparseCompilerPhysicalFixture<'_> {
    fn operation_plan(&self) -> &C6InstalledOperationPlan {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.operation_plan(),
            C61SparseCompilerSource::Production { operation_plan, .. } => operation_plan,
        }
    }

    fn extraction(&self) -> &volta_mac::C6DecodedInstanceExtractionPlan {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.extraction(),
            C61SparseCompilerSource::Production { extraction, .. } => extraction,
        }
    }

    fn runtime(&self) -> &volta_mac::C6RuntimeInstanceValues {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.runtime(),
            C61SparseCompilerSource::Production { runtime, .. } => runtime,
        }
    }

    fn relation(&self) -> &volta_proto::c6_residual::C6ResidualRelationChallenges {
        match &self.source {
            C61SparseCompilerSource::Scaled(direct) => direct.relation(),
            C61SparseCompilerSource::Production { relation, .. } => relation,
        }
    }

    fn verifier_fixture(&self) -> Result<C61SparseCompilerVerifierFixture<'_>, String> {
        Ok(C61SparseCompilerVerifierFixture {
            operation_plan: self.operation_plan(),
            terminal_metadata: &self.terminal_metadata,
            relation_challenges: self.relation(),
            output_beta: self.output_beta,
            base_domain_log2: self.packed.base_domain_log2(),
            response_digest: self.packed.response_digest(),
            plan_digest: self.packed.plan_digest(),
            physical_plan_values: self
                .packed
                .physical_plan_values()
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(Fp2::from_base)
                .collect(),
        })
    }
}

struct C61SparseCompilerProviderPhase {
    public_relation: volta_proto::c6_residual::C6ResidualSparseRationalPublicRelation,
    physical_points: volta_proto::c6_residual::C6SparseRationalPhysicalOpeningPoints,
    response_values: [Fp2; 12],
    plan_values: [Fp2; 3],
    response_targets: [ProverAuthed; 12],
    zero_rows: Vec<ProverAuthed>,
    arithmetic_payload: Vec<u8>,
    product_triples: usize,
}

struct C61SparseCompilerVerifierPhase {
    public_relation: volta_proto::c6_residual::C6ResidualSparseRationalPublicRelation,
    physical_points: volta_proto::c6_residual::C6SparseRationalPhysicalOpeningPoints,
    response_keys: [VerifierKey; 12],
    plan_values: [Fp2; 3],
    zero_rows: Vec<VerifierKey>,
    product_triples: usize,
}

fn c61_sparse_compiler_physical_fixture(
) -> Result<C61SparseCompilerPhysicalFixture<'static>, String> {
    use volta_proto::c6_residual::*;

    let direct =
        build_c6_residual_direct_fused_scaled_fixture().map_err(|error| error.to_string())?;
    let topology = direct.operation_plan().topology();
    let source_manifest = C6TraceSourceManifest::new(
        topology.source_count,
        topology.source_schedule_digest,
        direct.manifest().product_mask_sources().to_vec(),
    )
    .map_err(|error| error.to_string())?;
    let terminal_metadata =
        C6OperationPlanTerminalMetadata::from_installed(direct.operation_plan(), &source_manifest)
            .map_err(|error| error.to_string())?;
    let leaf_point = [
        Fp2::from_base(Fp::new(2)),
        Fp2::from_base(Fp::new(3)),
        Fp2::from_base(Fp::new(5)),
        Fp2::from_base(Fp::new(7)),
        Fp2::from_base(Fp::new(11)),
        Fp2::from_base(Fp::new(13)),
        Fp2::from_base(Fp::new(17)),
    ];
    let output_beta = Fp2::new(Fp::new(191), Fp::new(17));
    let lanes = std::array::from_fn(|repetition| {
        compile_c6_residual_folded_terminal_adjoint_lane_reference(
            direct.operation_plan(),
            &terminal_metadata,
            direct.extraction(),
            direct.runtime(),
            direct.relation(),
            repetition as u8,
            &leaf_point,
            output_beta,
        )
        .expect("scaled C6SPR3 adjoint lane fixture")
    });
    let packed = compile_c6_sparse_rational_packed_oracle_reference(
        direct.operation_plan(),
        direct.extraction(),
        direct.runtime(),
        [&lanes[0], &lanes[1]],
    )
    .map_err(|error| error.to_string())?;
    Ok(C61SparseCompilerPhysicalFixture {
        source: C61SparseCompilerSource::Scaled(direct),
        terminal_metadata,
        lanes,
        packed,
        output_beta,
        production: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn c61_sparse_compiler_production_fixture<'a>(
    operation_plan: &'a C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &'a volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &'a volta_mac::C6RuntimeInstanceValues,
    relation: &'a volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    output_beta: Fp2,
) -> Result<C61SparseCompilerPhysicalFixture<'a>, String> {
    use volta_proto::c6_residual::{
        compile_c6_residual_folded_terminal_adjoint_lane_reference,
        compile_c6_sparse_rational_packed_oracle_production,
    };

    if !relation.manifest().is_production_geometry() {
        return Err("C6SPR5 production fixture requires the frozen C6RLM1 geometry".to_owned());
    }
    let lanes: [volta_proto::c6_residual::C6ResidualFoldedTerminalAdjointLaneReference; 2] = (0
        ..2usize)
        .map(|repetition| {
            compile_c6_residual_folded_terminal_adjoint_lane_reference(
                operation_plan,
                &terminal_metadata,
                extraction,
                runtime,
                relation,
                repetition as u8,
                leaf_points[repetition],
                output_beta,
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "C6SPR5 production adjoint-lane census differs from two".to_owned())?;
    let packed = compile_c6_sparse_rational_packed_oracle_production(
        operation_plan,
        extraction,
        runtime,
        [&lanes[0], &lanes[1]],
    )
    .map_err(|error| error.to_string())?;
    if packed.physical_response_domain_log2() != 28 || packed.plan_domain_log2() != 27 {
        return Err("C6SPR5 production packing is not physical D28/D27".to_owned());
    }
    Ok(C61SparseCompilerPhysicalFixture {
        source: C61SparseCompilerSource::Production {
            operation_plan,
            extraction,
            runtime,
            relation,
        },
        terminal_metadata,
        lanes,
        packed,
        output_beta,
        production: true,
    })
}

/// Execute one exact compiler chain with the pinned host-monolithic P3
/// prover on an owner-authorized A100 node.
///
/// This is a resource-instrumented production-geometry baseline, not the
/// persisted/GPU-resident C6SPR5 solution and not GPU performance credit.
/// It fails closed unless the caller reports an A100, at least 64 GiB of
/// immediately available host memory, and real pooled PCG state for both
/// roles.  The caller remains responsible for measuring RSS and GPU memory
/// around this call and for using append-only clean records.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_monolithic_baseline(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    output_beta: Fp2,
    admission: C61ProductionMonolithicResourceAdmission,
    mut correlations: CorrelationStream,
    mut context: VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    let census = c61_production_monolithic_memory_census()?;
    if !admission.allow_host_monolithic_baseline
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES
        || admission.available_host_bytes < census.concurrent_retained_lower_bound_bytes
    {
        return Err(format!(
            "C6SPR5 monolithic A100 baseline admission failed: available_host={} B, minimum={} B, retained_lower_bound={} B, gpu={} B, a100={}, owner_baseline={}",
            admission.available_host_bytes,
            C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES,
            census.concurrent_retained_lower_bound_bytes,
            admission.gpu_total_bytes,
            admission.a100_present,
            admission.allow_host_monolithic_baseline,
        ));
    }
    if id.component != C61NativeComponent::Compiler {
        return Err("C6SPR5 production runner admits only compiler chains".to_owned());
    }
    if !correlations.uses_pooled_pcg() || !context.uses_pooled_pcg() {
        return Err("C6SPR5 production runner forbids mock PCG state".to_owned());
    }
    let fixture = c61_sparse_compiler_production_fixture(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        output_beta,
    )?;
    run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
        &fixture,
        28,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        admission.available_host_bytes,
    )
}

/// Execute one exact production compiler chain with the C6SPX1 persisted
/// prover-data lifecycle.  This is the only host executor admitted for the
/// C6SPR5 campaign; it never falls back to the resident MMCS and earns no GPU
/// performance credit.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_persisted(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    output_beta: Fp2,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    mut correlations: CorrelationStream,
    mut context: VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    run_c61_authenticated_whir_p3_production_persisted_in_attempt(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        output_beta,
        spill_root,
        admission,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
    )
}

/// Same production executor, borrowing the connection-owned PCG states so
/// an exact response runner can continue the indivisible paired attempt.
#[allow(clippy::too_many_arguments)]
pub fn run_c61_authenticated_whir_p3_production_persisted_in_attempt(
    operation_plan: &C6InstalledOperationPlan,
    terminal_metadata: C6OperationPlanTerminalMetadata,
    extraction: &volta_mac::C6DecodedInstanceExtractionPlan,
    runtime: &volta_mac::C6RuntimeInstanceValues,
    relation: &volta_proto::c6_residual::C6ResidualRelationChallenges,
    leaf_points: [&[Fp2]; 2],
    output_beta: Fp2,
    spill_root: &Path,
    admission: C61ProductionPersistedResourceAdmission,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    if !admission.allow_persisted_executor
        || !admission.a100_present
        || admission.gpu_total_bytes == 0
        || admission.available_host_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES
        || admission.available_spill_bytes < C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES
    {
        return Err(format!(
            "C6SPR5 persisted A100 admission failed: available_host={} B, minimum_host={} B, available_spill={} B, minimum_spill={} B, gpu={} B, a100={}, owner_persisted={}",
            admission.available_host_bytes,
            C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
            admission.available_spill_bytes,
            C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
            admission.gpu_total_bytes,
            admission.a100_present,
            admission.allow_persisted_executor,
        ));
    }
    if id.component != C61NativeComponent::Compiler {
        return Err("C6SPR5 persisted runner admits only compiler chains".to_owned());
    }
    if !correlations.uses_pooled_pcg() || !context.uses_pooled_pcg() {
        return Err("C6SPR5 persisted runner forbids mock PCG state".to_owned());
    }
    let fixture = c61_sparse_compiler_production_fixture(
        operation_plan,
        terminal_metadata,
        extraction,
        runtime,
        relation,
        leaf_points,
        output_beta,
    )?;
    let mut session_hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/c6spx1-session/v1");
    session_hasher.update(&verifier_seed);
    session_hasher.update(&operation_plan.artifact_digest());
    session_hasher.update(&(id.component as u16).to_le_bytes());
    session_hasher.update(&[id.repetition, mask_range.stage]);
    session_hasher.update(&mask_range.slot.to_le_bytes());
    session_hasher.update(&mask_range.range_start.to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    let commit_gate = Arc::new(Mutex::new(()));
    let response_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("response"),
        session_digest,
        *b"response",
        Arc::clone(&commit_gate),
    )?;
    let plan_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("plan"),
        session_digest,
        *b"planlane",
        commit_gate,
    )?;
    let report = run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs(
        &fixture,
        28,
        correlations,
        context,
        verifier_seed,
        id,
        mask_range,
        admission.available_host_bytes,
        admission.available_spill_bytes,
        response_mmcs,
        plan_mmcs,
    )?;
    if !report.production_geometry || !report.persisted_executor || report.monolithic_host_baseline
    {
        return Err("C6SPR5 persisted runner returned a non-persisted production report".to_owned());
    }
    Ok(report)
}

fn sample_c61_sparse_relation_challenges(
    operation_plan: &C6InstalledOperationPlan,
    transcript: &mut Transcript,
) -> Result<volta_proto::c6_residual::C6ResidualSparseRationalChallenges, String> {
    volta_proto::c6_residual::C6ResidualSparseRationalChallenges::new(
        operation_plan.topology(),
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
        transcript.challenge_fp2(),
    )
    .map_err(|error| error.to_string())
}

fn prove_c61_sparse_compiler_relation_phase(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    stream: &mut CorrelationStream,
    doms: &mut volta_proto::logup::Doms,
    transcript: &mut Transcript,
) -> Result<C61SparseCompilerProviderPhase, String> {
    use volta_proto::c6_residual::*;
    use volta_proto::prod_check::prod_batch_prover;

    let sparse_challenges =
        sample_c61_sparse_relation_challenges(fixture.operation_plan(), transcript)?;
    let relation = if fixture.production {
        compile_c6_residual_sparse_rational_relation_production(
            fixture.operation_plan(),
            &fixture.terminal_metadata,
            fixture.extraction(),
            fixture.runtime(),
            fixture.relation(),
            [&fixture.lanes[0], &fixture.lanes[1]],
            sparse_challenges,
            fixture.output_beta,
        )
    } else {
        compile_c6_residual_sparse_rational_relation_reference(
            fixture.operation_plan(),
            &fixture.terminal_metadata,
            fixture.extraction(),
            fixture.runtime(),
            fixture.relation(),
            [&fixture.lanes[0], &fixture.lanes[1]],
            sparse_challenges,
            fixture.output_beta,
        )
    }
    .map_err(|error| error.to_string())?;
    let public_relation = C6ResidualSparseRationalPublicRelation::new(
        fixture.operation_plan(),
        &fixture.terminal_metadata,
        fixture.relation(),
        sparse_challenges,
        fixture.output_beta,
    )
    .map_err(|error| error.to_string())?;
    fixture.packed.validate_relation(&relation).map_err(|error| error.to_string())?;

    let mut products = Vec::new();
    let mut zero_rows = Vec::new();
    let (gkr, leaf_claims) = prove_c6_residual_sparse_rational_gkr_blind_reference(
        fixture.operation_plan(),
        fixture.extraction(),
        fixture.runtime(),
        &relation,
        &public_relation,
        stream,
        doms,
        transcript,
        &mut volta_proto::logup::Counters::default(),
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let (joint, terminal) = prove_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
        fixture.operation_plan(),
        &relation,
        &public_relation,
        &fixture.packed,
        &leaf_claims,
        stream,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let physical_points = fixture
        .packed
        .physical_opening_points(terminal.points().input_point())
        .map_err(|error| error.to_string())?;
    let response_values = fixture
        .packed
        .evaluate_physical_response_openings(&physical_points)
        .map_err(|error| error.to_string())?;
    let plan_values = fixture
        .packed
        .evaluate_physical_plan_openings(&physical_points)
        .map_err(|error| error.to_string())?;
    let (response_target_proof, response_targets) =
        authenticate_c61_sparse_response_targets_prover(&response_values, stream, doms, transcript)
            .map_err(|error| error.to_string())?;
    let plan_targets = plan_values.map(ProverAuthed::from_public);
    let terminal_proof = crate::finish_c61_sparse_rational_blind_physical_terminal_prover(
        terminal,
        &response_targets,
        &plan_targets,
        stream,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let product_triples = products.len();
    let chi = transcript.challenge_fp2();
    let product_domain = doms.take(1);
    let product_mask = stream.draw_product_mask(product_domain, product_triples);
    let product_proof = prod_batch_prover(&products, chi, product_mask, transcript);
    let arithmetic = C61SparseRationalBlindArithmeticProof::new(
        fixture.operation_plan(),
        public_relation.digest(),
        response_target_proof,
        gkr,
        joint,
        terminal_proof,
        product_proof,
    )
    .map_err(|error| error.to_string())?;
    let arithmetic_payload = arithmetic
        .encode(fixture.operation_plan(), public_relation.digest())
        .map_err(|error| error.to_string())?;
    Ok(C61SparseCompilerProviderPhase {
        public_relation,
        physical_points,
        response_values,
        plan_values,
        response_targets,
        zero_rows,
        arithmetic_payload,
        product_triples,
    })
}

fn verify_c61_sparse_compiler_relation_phase(
    fixture: &C61SparseCompilerVerifierFixture<'_>,
    arithmetic_payload: &[u8],
    context: &mut VerifierCtx,
    doms: &mut volta_proto::logup::Doms,
    transcript: &mut Transcript,
) -> Result<C61SparseCompilerVerifierPhase, String> {
    use volta_proto::c6_residual::*;
    use volta_proto::prod_check::prod_batch_verify;

    let sparse_challenges =
        sample_c61_sparse_relation_challenges(fixture.operation_plan, transcript)?;
    let public_relation = C6ResidualSparseRationalPublicRelation::new(
        fixture.operation_plan,
        fixture.terminal_metadata,
        fixture.relation_challenges,
        sparse_challenges,
        fixture.output_beta,
    )
    .map_err(|error| error.to_string())?;
    let arithmetic = C61SparseRationalBlindArithmeticProof::decode(
        fixture.operation_plan,
        public_relation.digest(),
        arithmetic_payload,
    )
    .map_err(|error| error.to_string())?;
    let (response_target_proof, gkr, joint, terminal_proof, product_proof) =
        arithmetic.into_parts();
    let mut products = Vec::new();
    let mut zero_rows = Vec::new();
    let leaf_keys = verify_c6_residual_sparse_rational_gkr_blind_reference(
        fixture.operation_plan,
        &public_relation,
        &gkr,
        context,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "C6SPR3 blind GKR verifier rejected".to_owned())?;
    let terminal = verify_c6_residual_sparse_rational_joint_leaf_blind_rounds_reference(
        fixture.operation_plan,
        fixture.terminal_metadata,
        fixture.relation_challenges,
        &public_relation,
        fixture.base_domain_log2,
        fixture.response_digest,
        fixture.plan_digest,
        &leaf_keys,
        &joint,
        context,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?
    .ok_or_else(|| "C6SPR3 blind joint verifier rejected".to_owned())?;
    let physical_points = C6SparseRationalPhysicalOpeningPoints::new(
        fixture.base_domain_log2,
        fixture.response_digest,
        fixture.plan_digest,
        terminal.points().input_point(),
    )
    .map_err(|error| error.to_string())?;
    let plan_values = std::array::from_fn(|index| {
        volta_proto::mle::eval_mle(&fixture.physical_plan_values, &physical_points.plan()[index])
    });
    let response_keys = authenticate_c61_sparse_response_targets_verifier(
        response_target_proof,
        context,
        doms,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let plan_keys = plan_values.map(|value| VerifierKey::from_public(value, context.delta));
    crate::finish_c61_sparse_rational_blind_physical_terminal_verifier(
        terminal,
        &response_keys,
        &plan_keys,
        &terminal_proof,
        context,
        doms,
        transcript,
        &mut products,
        &mut zero_rows,
    )
    .map_err(|error| error.to_string())?;
    let product_triples = products.len();
    let chi = transcript.challenge_fp2();
    let product_domain = doms.take(1);
    let product_key = context.expand_product_mask_verifier_key(product_domain, product_triples);
    transcript.append("prod_check_m0_m1", 32);
    if !prod_batch_verify(&products, product_key, context.delta, chi, &product_proof) {
        return Err("C6SPR3 global QuickSilver product verification failed".to_owned());
    }
    Ok(C61SparseCompilerVerifierPhase {
        public_relation,
        physical_points,
        response_keys,
        plan_values,
        zero_rows,
        product_triples,
    })
}

/// Exercise the C6SPR3 physical response/plan opening as Dn and D(n-1)
/// commitments sharing every common native verifier challenge, the exact
/// response-only tail, and one final authenticated residual.  At production
/// this geometry is D28/D27; the executable differential uses D14/D13.
pub fn run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(
    response_num_variables: usize,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    if response_num_variables == 28 {
        reject_monolithic_production_backend()?;
        return Err("C6SPR4 production admission returned without a production backend".to_owned());
    }
    let fixture = c61_sparse_compiler_physical_fixture()?;
    let verifier_seed = [0xC2; 32];
    let pcg_seed = [0xD3; 32];
    let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
    let mut correlations = CorrelationStream::new(pcg_seed);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 };
    run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
        &fixture,
        response_num_variables,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        0,
    )
}

/// Execute the scaled shared-chain differential through the C6SPX1 persisted
/// prover-data lifecycle.  The unchanged resident MMCS is still used by the
/// verifier after strict decoding.
pub fn run_c61_authenticated_whir_p3_shared_multi_oracle_persisted_diagnostic(
    response_num_variables: usize,
    spill_root: &Path,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    if response_num_variables == 28 {
        return Err("C6SPX1 diagnostic does not admit production geometry".to_owned());
    }
    let fixture = c61_sparse_compiler_physical_fixture()?;
    let verifier_seed = [0xC2; 32];
    let pcg_seed = [0xD3; 32];
    let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
    let mut correlations = CorrelationStream::new(pcg_seed);
    let mut context = VerifierCtx::new(pcg_seed, delta);
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 };
    let mut session_hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/c6spx1-session/v1");
    session_hasher.update(&verifier_seed);
    session_hasher.update(&(response_num_variables as u64).to_le_bytes());
    let session_digest = *session_hasher.finalize().as_bytes();
    let commit_gate = Arc::new(Mutex::new(()));
    let response_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("response"),
        session_digest,
        *b"response",
        Arc::clone(&commit_gate),
    )?;
    let plan_mmcs = C61PersistedMmcs::new_with_commit_gate(
        c61_reference_mmcs(),
        spill_root.join("plan"),
        session_digest,
        *b"planlane",
        commit_gate,
    )?;
    run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs(
        &fixture,
        response_num_variables,
        &mut correlations,
        &mut context,
        verifier_seed,
        id,
        mask_range,
        0,
        0,
        response_mmcs,
        plan_mmcs,
    )
}

fn run_c61_authenticated_whir_p3_shared_multi_oracle_materialized(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    admitted_available_host_bytes: u64,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String> {
    run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs(
        fixture,
        response_num_variables,
        correlations,
        context,
        verifier_seed,
        id,
        mask_range,
        admitted_available_host_bytes,
        0,
        c61_reference_mmcs(),
        c61_reference_mmcs(),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_c61_authenticated_whir_p3_shared_multi_oracle_with_provider_mmcs<RM, PM>(
    fixture: &C61SparseCompilerPhysicalFixture<'_>,
    response_num_variables: usize,
    correlations: &mut CorrelationStream,
    context: &mut VerifierCtx,
    verifier_seed: [u8; 32],
    id: C61NativeChainId,
    mask_range: C61AuthenticatedWhirMaskRange,
    admitted_available_host_bytes: u64,
    admitted_available_spill_bytes: u64,
    response_mmcs: RM,
    plan_mmcs: PM,
) -> Result<C61AuthenticatedP3SharedMultiOracleDiagnostic, String>
where
    RM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    PM: Mmcs<Goldilocks, Commitment = C61Commitment, MultiProof = C61MultiProof>
        + C61MmcsResourceMetrics
        + Send
        + Sync,
    RM::ProverData<DenseMatrix<Goldilocks>>: Send,
    PM::ProverData<DenseMatrix<Goldilocks>>: Send,
{
    let verifier_fixture = fixture.verifier_fixture()?;
    let native_response_num_variables = usize::from(fixture.packed.physical_response_domain_log2());
    let native_plan_num_variables = usize::from(fixture.packed.plan_domain_log2());
    if fixture.production
        && (native_response_num_variables != 28
            || native_plan_num_variables != 27
            || response_num_variables != 28)
    {
        return Err("C6SPR5 production materialization must be exact D28/D27".to_owned());
    }
    if !fixture.production
        && !(native_response_num_variables..=20).contains(&response_num_variables)
    {
        return Err(format!(
            "C6SPR3 scaled response geometry must be in D{native_response_num_variables}..=D20; production uses the separate fail-closed D28 admission"
        ));
    }
    let plan_num_variables = response_num_variables - 1;
    if plan_num_variables < native_plan_num_variables {
        return Err("C6SPR3 plan padding dimension is below its native layout".to_owned());
    }
    let mut response_coefficients = fixture
        .packed
        .physical_response_values()
        .into_iter()
        .map(|value| Goldilocks::from_u64(value.value()))
        .collect::<Vec<_>>();
    response_coefficients.resize(1usize << response_num_variables, Goldilocks::ZERO);
    let response_witness = Poly::new(response_coefficients);
    let mut plan_coefficients = fixture
        .packed
        .physical_plan_values()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|value| Goldilocks::from_u64(value.value()))
        .collect::<Vec<_>>();
    plan_coefficients.resize(1usize << plan_num_variables, Goldilocks::ZERO);
    let plan_witness = Poly::new(plan_coefficients);
    let pooled_pcg = correlations.uses_pooled_pcg() && context.uses_pooled_pcg();
    if fixture.production && !pooled_pcg {
        return Err("C6SPR5 production executor requires real pooled PCG correlations".to_owned());
    }
    let delta = context.delta;
    let mut provider_doms = volta_proto::logup::Doms::new(50_000);

    let mut provider_transcript = Transcript::new(verifier_seed);
    let (mut response_challenger, mut plan_challenger, provider_coordinator) =
        c61_shared_round_pair(
            &mut provider_transcript,
            [response_num_variables, plan_num_variables],
        );
    let response_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(response_num_variables)?;
    let plan_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(plan_num_variables)?;
    let response_dft = Radix2DFTSmallBatch::default();
    let plan_dft = Radix2DFTSmallBatch::default();
    let response_prover = HidingWhirProver::new(&response_config, &response_dft, &response_mmcs);
    let plan_prover = HidingWhirProver::new(&plan_config, &plan_dft, &plan_mmcs);
    let mut response_rng = StdRng::seed_from_u64(0xC6_5202);
    let mut plan_rng = StdRng::seed_from_u64(0xC6_5203);
    let (response_commitment, response_data) =
        response_prover.commit(response_witness, &mut response_challenger, &mut response_rng);
    let (plan_commitment, plan_data) =
        plan_prover.commit(plan_witness, &mut plan_challenger, &mut plan_rng);
    let provider_phase = provider_coordinator.with_pre_statement_transcript(|transcript| {
        prove_c61_sparse_compiler_relation_phase(
            &fixture,
            correlations,
            &mut provider_doms,
            transcript,
        )
    })?;
    let arithmetic_payload_mutation_rejected = {
        let mut changed_payload = provider_phase.arithmetic_payload.clone();
        let changed_index = changed_payload.len() / 2;
        changed_payload[changed_index] ^= 1;
        let mut changed_context = VerifierCtx::new([0xD3; 32], delta);
        let mut changed_doms = volta_proto::logup::Doms::new(50_000);
        let mut changed_transcript = Transcript::new(verifier_seed);
        verify_c61_sparse_compiler_relation_phase(
            &verifier_fixture,
            &changed_payload,
            &mut changed_context,
            &mut changed_doms,
            &mut changed_transcript,
        )
        .is_err()
    };
    let response_points: Vec<_> = provider_phase
        .physical_points
        .response()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(response_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    let plan_points: Vec<_> = provider_phase
        .physical_points
        .plan()
        .iter()
        .map(|point| {
            let mut backend_point = point.clone();
            backend_point.resize(plan_num_variables, Fp2::ZERO);
            backend_point.reverse();
            Point::new(backend_point.into_iter().map(c61_p3_fp2_from_volta).collect())
        })
        .collect();
    if response_points.len() != 12
        || plan_points.len() != 3
        || response_points.iter().any(|point| point.num_variables() != response_num_variables)
        || plan_points.iter().any(|point| point.num_variables() != plan_num_variables)
    {
        return Err("C6SPR3 exact physical opening point shape mismatch".to_owned());
    }
    if response_points.iter().zip(provider_phase.response_values).any(|(point, expected)| {
        c61_volta_fp2_from_p3(response_data.message.eval_base(point)) != expected
    }) || plan_points.iter().zip(provider_phase.plan_values).any(|(point, expected)| {
        c61_volta_fp2_from_p3(plan_data.message.eval_base(point)) != expected
    }) {
        return Err("C6SPR3 Volta-LSB/P3-MSB physical evaluation adapter mismatch".to_owned());
    }
    let response_claims: Vec<_> = response_points
        .iter()
        .cloned()
        .zip(provider_phase.response_values.map(c61_p3_fp2_from_volta))
        .collect();
    let plan_claims: Vec<_> = plan_points
        .iter()
        .cloned()
        .zip(provider_phase.plan_values.map(c61_p3_fp2_from_volta))
        .collect();
    let prepared = prepare_c61_authenticated_whir_mask(id, mask_range, correlations)
        .map_err(|error| error.to_string())?;
    let response_base_shift = c61_p3_fp2_from_volta(prepared.value());
    let statement_digest = c61_sparse_shared_statement_digest(
        &response_commitment,
        &plan_commitment,
        &response_points,
        &plan_points,
        provider_phase.public_relation.digest(),
        &provider_phase.arithmetic_payload,
        &provider_phase.plan_values,
    )?;
    response_challenger
        .observe_public_points(statement_digest, &response_points)
        .map_err(|error| error.to_string())?;
    plan_challenger
        .observe_public_points(statement_digest, &plan_points)
        .map_err(|error| error.to_string())?;

    let (response_output, plan_output) = thread::scope(|scope| {
        let response_thread = scope.spawn(move || {
            let output = response_prover.prove_claimless(
                response_data,
                &response_claims,
                response_base_shift,
                &mut response_challenger,
                &mut response_rng,
            );
            response_challenger.finish_lane().map(|()| output)
        });
        let plan_thread = scope.spawn(move || {
            let output = plan_prover.prove_claimless(
                plan_data,
                &plan_claims,
                C61P3Fp2::ZERO,
                &mut plan_challenger,
                &mut plan_rng,
            );
            plan_challenger.finish_lane().map(|()| output)
        });
        (response_thread.join(), plan_thread.join())
    });
    let response_output = response_output.map_err(|_| "C6SMO1 response prover panicked")??;
    let plan_output = plan_output.map_err(|_| "C6SMO1 plan prover panicked")??;
    let provider_eta = provider_coordinator.sample_postproof_fp2()?;
    let placeholder =
        C61AuthenticatedWhirBaseProof::decode(&[0u8; C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES])
            .map_err(|error| error.to_string())?;
    let response_placeholder = encode_c61_authenticated_p3_artifact_inner(
        response_num_variables,
        &response_commitment,
        &response_output.proof,
        placeholder,
        false,
    )
    .map_err(|error| error.to_string())?;
    let plan_payload = encode_c61_authenticated_p3_artifact_inner(
        plan_num_variables,
        &plan_commitment,
        &plan_output.proof,
        placeholder,
        false,
    )
    .map_err(|error| error.to_string())?;
    let placeholder_artifact = encode_c61_shared_multi_oracle_artifact(
        response_num_variables,
        plan_num_variables,
        &response_placeholder,
        &plan_payload,
    )
    .map_err(|error| error.to_string())?;
    let whir_payload_bytes = placeholder_artifact
        .payload
        .len()
        .checked_sub(C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES)
        .ok_or_else(|| "C6SMO1 payload is shorter than its joint tag".to_owned())?;
    let provider_interaction = provider_coordinator.finish(whir_payload_bytes)?;
    drop(provider_coordinator);

    let response_affine = affine_from_p3(response_output.target);
    let plan_affine = affine_from_p3(plan_output.target);
    let response_target = response_affine.authenticate_prover(aggregate_prover_targets(
        &provider_phase.response_targets,
        &response_output.claim_weights,
    )?);
    let plan_targets = provider_phase.plan_values.map(ProverAuthed::from_public);
    let plan_target = plan_affine
        .authenticate_prover(aggregate_prover_targets(&plan_targets, &plan_output.claim_weights)?);
    let response_gamma = c61_volta_fp2_from_p3(response_output.base_case.gamma);
    let plan_gamma = c61_volta_fp2_from_p3(plan_output.base_case.gamma);
    let joint_target =
        response_target.scale(response_gamma).add(plan_target.scale(provider_eta * plan_gamma));
    let joint_combined = c61_volta_fp2_from_p3(response_output.base_case.combined)
        - c61_volta_fp2_from_p3(response_output.base_case.shifted_masked_claim)
        + provider_eta
            * (c61_volta_fp2_from_p3(plan_output.base_case.combined)
                - c61_volta_fp2_from_p3(plan_output.base_case.shifted_masked_claim));
    let joint_closure = finish_c61_authenticated_whir_base_with_zero_rows(
        prepared,
        C61AuthenticatedWhirProverFinishInput {
            combined: joint_combined,
            shifted_masked_claim: Fp2::ZERO,
            gamma: Fp2::ONE,
            target: joint_target,
        },
        &provider_phase.zero_rows,
        &mut provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let response_payload = encode_c61_authenticated_p3_artifact_inner(
        response_num_variables,
        &response_commitment,
        &response_output.proof,
        joint_closure.proof,
        false,
    )
    .map_err(|error| error.to_string())?;
    let artifact = encode_c61_shared_multi_oracle_artifact(
        response_num_variables,
        plan_num_variables,
        &response_payload,
        &plan_payload,
    )
    .map_err(|error| error.to_string())?;
    if artifact.payload.len() != placeholder_artifact.payload.len() {
        return Err("C6SMO1 joint tag changed strict payload length".to_owned());
    }
    let codec_mutations_rejected = {
        let rejects = |payload: Vec<u8>| {
            decode_c61_shared_multi_oracle_artifact(
                &C61SharedMultiOracleArtifact { payload },
                response_num_variables,
                plan_num_variables,
            )
            .is_err()
        };
        let mut bad_magic = artifact.payload.clone();
        bad_magic[0] ^= 1;
        let mut bad_version = artifact.payload.clone();
        bad_version[8] ^= 1;
        let mut bad_response_dimension = artifact.payload.clone();
        bad_response_dimension[10] ^= 1;
        let mut bad_plan_dimension = artifact.payload.clone();
        bad_plan_dimension[11] ^= 1;
        let mut bad_response_len = artifact.payload.clone();
        bad_response_len[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut bad_plan_reserved_tag = artifact.payload.clone();
        *bad_plan_reserved_tag.last_mut().expect("C6SMO1 artifact is nonempty") ^= 1;
        let mut trailing = artifact.payload.clone();
        trailing.push(0);
        let mut truncated = artifact.payload.clone();
        truncated.pop();
        [
            bad_magic,
            bad_version,
            bad_response_dimension,
            bad_plan_dimension,
            bad_response_len,
            bad_plan_reserved_tag,
            trailing,
            truncated,
        ]
        .into_iter()
        .all(rejects)
    };

    let ((response_commitment, response_proof), (plan_commitment, plan_proof), joint_tag) =
        decode_c61_shared_multi_oracle_artifact(
            &artifact,
            response_num_variables,
            plan_num_variables,
        )
        .map_err(|error| error.to_string())?;
    let mut verifier_transcript = Transcript::new(verifier_seed);
    let (mut response_challenger, mut plan_challenger, verifier_coordinator) =
        c61_shared_round_pair(
            &mut verifier_transcript,
            [response_num_variables, plan_num_variables],
        );
    let response_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(response_num_variables)?;
    let plan_config = c61_authenticated_config::<
        crate::c61_shared_round_challenger::C61SharedRoundChallenger<'_>,
    >(plan_num_variables)?;
    let verifier_response_mmcs = c61_reference_mmcs();
    let verifier_plan_mmcs = c61_reference_mmcs();
    response_challenger.observe(response_commitment.clone());
    plan_challenger.observe(plan_commitment.clone());
    let mut verifier_doms = volta_proto::logup::Doms::new(50_000);
    let verifier_phase = verifier_coordinator.with_pre_statement_transcript(|transcript| {
        verify_c61_sparse_compiler_relation_phase(
            &verifier_fixture,
            &provider_phase.arithmetic_payload,
            context,
            &mut verifier_doms,
            transcript,
        )
    })?;
    if verifier_phase.public_relation.digest() != provider_phase.public_relation.digest()
        || verifier_phase.physical_points != provider_phase.physical_points
        || verifier_phase.plan_values != provider_phase.plan_values
        || verifier_phase.product_triples != provider_phase.product_triples
        || verifier_phase.zero_rows.len() != provider_phase.zero_rows.len()
    {
        return Err("C6SPR3 provider/verifier pre-statement relation mismatch".to_owned());
    }
    let verifier_statement_digest = c61_sparse_shared_statement_digest(
        &response_commitment,
        &plan_commitment,
        &response_points,
        &plan_points,
        verifier_phase.public_relation.digest(),
        &provider_phase.arithmetic_payload,
        &verifier_phase.plan_values,
    )?;
    response_challenger
        .observe_public_points(verifier_statement_digest, &response_points)
        .map_err(|error| error.to_string())?;
    plan_challenger
        .observe_public_points(verifier_statement_digest, &plan_points)
        .map_err(|error| error.to_string())?;
    let response_verifier = HidingWhirVerifier::new(&response_config, &verifier_response_mmcs);
    let plan_verifier = HidingWhirVerifier::new(&plan_config, &verifier_plan_mmcs);
    let (response_result, plan_result) = thread::scope(|scope| {
        let response_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                response_verifier.verify_claimless(
                    &response_proof,
                    &response_commitment,
                    &response_points,
                    &mut response_challenger,
                )
            }));
            (result, response_challenger.finish_lane())
        });
        let plan_thread = scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                plan_verifier.verify_claimless(
                    &plan_proof,
                    &plan_commitment,
                    &plan_points,
                    &mut plan_challenger,
                )
            }));
            (result, plan_challenger.finish_lane())
        });
        (response_thread.join(), plan_thread.join())
    });
    let (response_result, response_finish) =
        response_result.map_err(|_| "C6SMO1 response verifier thread panicked")?;
    response_finish?;
    let response_result = response_result
        .map_err(|_| "C6SMO1 response verifier panicked")?
        .map_err(|error| format!("C6SMO1 response verification failed: {error}"))?;
    let (plan_result, plan_finish) =
        plan_result.map_err(|_| "C6SMO1 plan verifier thread panicked")?;
    plan_finish?;
    let plan_result = plan_result
        .map_err(|_| "C6SMO1 plan verifier panicked")?
        .map_err(|error| format!("C6SMO1 plan verification failed: {error}"))?;
    let verifier_eta = verifier_coordinator.sample_postproof_fp2()?;
    let verifier_interaction = verifier_coordinator.finish(whir_payload_bytes)?;
    drop(verifier_coordinator);

    let response_key = affine_from_p3(response_result.target).derive_verifier_key(
        aggregate_verifier_targets(&verifier_phase.response_keys, &response_result.claim_weights)?,
        delta,
    );
    let plan_keys = verifier_phase.plan_values.map(|value| VerifierKey::from_public(value, delta));
    let plan_key = affine_from_p3(plan_result.target).derive_verifier_key(
        aggregate_verifier_targets(&plan_keys, &plan_result.claim_weights)?,
        delta,
    );
    let response_gamma = c61_volta_fp2_from_p3(response_result.base_case.gamma);
    let plan_gamma = c61_volta_fp2_from_p3(plan_result.base_case.gamma);
    let joint_key =
        response_key.scale(response_gamma).add(plan_key.scale(verifier_eta * plan_gamma));
    let joint_combined = c61_volta_fp2_from_p3(response_result.base_case.combined)
        - c61_volta_fp2_from_p3(response_result.base_case.shifted_masked_claim)
        + verifier_eta
            * (c61_volta_fp2_from_p3(plan_result.base_case.combined)
                - c61_volta_fp2_from_p3(plan_result.base_case.shifted_masked_claim));
    let joint_verifier_input = C61AuthenticatedWhirVerifierInput {
        id,
        mask_range,
        combined: joint_combined,
        shifted_masked_claim: Fp2::ZERO,
        gamma: Fp2::ONE,
        target: joint_key,
    };
    let joint_residual = verify_c61_authenticated_whir_base_with_zero_rows_residual(
        joint_verifier_input,
        &verifier_phase.zero_rows,
        joint_tag,
        context,
        &mut verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    let joint_tag_mutation_rejected = {
        let mut bytes = joint_tag.encode();
        bytes[0] ^= 1;
        let changed_tag =
            C61AuthenticatedWhirBaseProof::decode(&bytes).map_err(|error| error.to_string())?;
        !zero_open_verify(joint_residual, changed_tag.tag())
    };
    if provider_interaction != verifier_interaction {
        return Err(format!(
            "C6SMO1 provider/verifier shared interaction mismatch: provider={provider_interaction:?}, verifier={verifier_interaction:?}"
        ));
    }
    if provider_transcript.ledger() != verifier_transcript.ledger() {
        return Err(format!(
            "C6SMO1 provider/verifier transcript ledger mismatch: provider={:?}, verifier={:?}",
            provider_transcript.ledger(),
            verifier_transcript.ledger()
        ));
    }
    if statement_digest != verifier_statement_digest {
        return Err("C6SMO1 provider/verifier statement digest mismatch".to_owned());
    }

    let strict_response = c61_authenticated_structural_budget_inner(response_num_variables, false)?
        .strict_chain_bytes;
    let strict_plan =
        c61_authenticated_structural_budget_inner(plan_num_variables, false)?.strict_chain_bytes;
    let response_spill = response_mmcs.c61_persisted_metrics();
    let plan_spill = plan_mmcs.c61_persisted_metrics();
    let persisted_executor = response_spill.is_some() && plan_spill.is_some();
    Ok(C61AuthenticatedP3SharedMultiOracleDiagnostic {
        production_geometry: fixture.production,
        monolithic_host_baseline: fixture.production && !persisted_executor,
        persisted_executor,
        gpu_performance_credit: false,
        admitted_available_host_bytes,
        admitted_available_spill_bytes,
        monolithic_retained_lower_bound_bytes: if fixture.production {
            c61_production_monolithic_memory_census()?.concurrent_retained_lower_bound_bytes
        } else {
            0
        },
        pooled_pcg,
        response_num_variables,
        plan_num_variables,
        response_claim_count: provider_phase.response_targets.len(),
        plan_claim_count: provider_phase.plan_values.len(),
        strict_payload_bytes: artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&artifact.payload).as_bytes(),
        strict_payload_max_bytes: C61_SHARED_MULTI_ORACLE_HEADER_BYTES
            + strict_response
            + strict_plan,
        arithmetic_payload_bytes: provider_phase.arithmetic_payload.len(),
        total_provider_payload_bytes: provider_phase
            .arithmetic_payload
            .len()
            .checked_add(artifact.payload.len())
            .ok_or_else(|| "C6SPR3 complete provider byte count overflow".to_owned())?,
        response_target_correction_bytes: provider_transcript
            .bytes_for("c6_sparse_response_target_corrections"),
        arithmetic_product_triples: provider_phase.product_triples,
        folded_zero_rows: provider_phase.zero_rows.len(),
        provider_transcript_bytes: provider_transcript.total_bytes(),
        provider_interaction,
        verifier_interaction,
        native_challenges_shared: response_output.claim_weights[..plan_output.claim_weights.len()]
            == plan_output.claim_weights,
        postproof_batching_challenge_identical: provider_eta == verifier_eta,
        plan_reserved_tag_is_zero: true,
        codec_mutations_rejected,
        arithmetic_payload_mutation_rejected,
        joint_tag_mutation_rejected,
        subfield_correlations: correlations.counters.sub_corrs,
        full_correlations: correlations.counters.full_corrs,
        response_spill: response_spill.unwrap_or_default(),
        plan_spill: plan_spill.unwrap_or_default(),
    })
}

/// Execute the target-plaintext-free designated-verifier view simulator and
/// feed its strict artifact to the ordinary verifier.
pub fn run_c61_authenticated_whir_p3_privacy_diagnostic(
    num_variables: usize,
) -> Result<C61AuthenticatedP3PrivacyDiagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6AWP1 privacy diagnostic dimension must be in 4..=28".to_owned());
    }
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(29).wrapping_add(7)))
            .collect(),
    );
    let verifier_seed = [0x93; 32];
    let pcg_seed = [0xD5; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 37), volta_field::Fp::new(0xC6_1001));
    // This is verifier state, not a `(target, provider_tag)` pair.  The
    // simulator API has no way to receive either missing provider value.
    let target_key =
        VerifierKey::new(Fp2::new(volta_field::Fp::new(0x1234_5678), volta_field::Fp::new(P - 41)));
    let id = C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 1 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 12, range_start: 60_000 };
    let (fixture, verifier_full_key_draws) = simulate_view_diagnostic(
        num_variables,
        point,
        target_key,
        verifier_seed,
        0xC6_3003,
        pcg_seed,
        delta,
        id,
        mask_range,
    )?;
    let (_, verifier_base_case, verifier_transcript, verifier_interaction) = verify_diagnostic(
        &fixture.artifact,
        C61AuthenticatedP3VerifierInput {
            point: &fixture.point,
            target_key,
            verifier_seed,
            pcg_seed,
            delta,
            id,
            mask_range,
        },
    )?;
    if fixture.provider_base_case != verifier_base_case {
        return Err("C6AWP1 simulator/verifier base closure mismatch".to_owned());
    }
    if fixture.provider_interaction != verifier_interaction {
        return Err("C6AWP1 simulator/verifier interaction accounting mismatch".to_owned());
    }
    if fixture.provider_ledger != *verifier_transcript.ledger() {
        return Err("C6AWP1 simulator/verifier transcript ledger mismatch".to_owned());
    }

    Ok(C61AuthenticatedP3PrivacyDiagnostic {
        num_variables,
        strict_payload_bytes: fixture.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&fixture.artifact.payload).as_bytes(),
        simulator_interaction: fixture.provider_interaction,
        verifier_interaction,
        simulator_transcript_bytes: fixture.provider_transcript_bytes,
        verifier_transcript_bytes: verifier_transcript.total_bytes(),
        simulator_ledger: fixture.provider_ledger,
        verifier_ledger: verifier_transcript.ledger().clone(),
        received_real_target_plaintext: false,
        received_provider_target_tag: false,
        received_provider_correlation_state: false,
        verifier_full_key_draws,
    })
}

/// Exercise the endpoint-only interactive driver, strict verifier-local
/// checkpoint codec, and deterministic replay to a mid-proof frontier.
pub fn run_c61_private_entropy_driver_diagnostic(
    num_variables: usize,
) -> Result<C61PrivateEntropyDriverDiagnostic, String> {
    if !(4..=28).contains(&num_variables) {
        return Err("C6ICT1 diagnostic dimension must be in 4..=28".to_owned());
    }
    let witness = Poly::new(
        (0..(1usize << num_variables))
            .map(|index| Goldilocks::from_u64((index as u64).wrapping_mul(17).wrapping_add(3)))
            .collect(),
    );
    let point = Point::new(
        (0..num_variables)
            .map(|index| C61P3Fp2::from_u64((index as u64).wrapping_mul(19).wrapping_add(5)))
            .collect(),
    );
    let verifier_seed = [0x61; 32];
    let pcg_seed = [0xA7; 32];
    let delta = Fp2::new(volta_field::Fp::new(P - 17), volta_field::Fp::new(0x1234_5678));
    let target_tag = Fp2::new(volta_field::Fp::new(41), volta_field::Fp::new(43));
    let id = C61NativeChainId { component: C61NativeComponent::Model, repetition: 0 };
    let mask_range = C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 1, range_start: 40_000 };
    let evaluation = c61_volta_fp2_from_p3(witness.eval_base(&point));
    let target_key = VerifierKey::new(target_tag + delta * evaluation);
    let context_digest =
        c61_private_entropy_context_digest(&point, target_key, delta, id, mask_range);
    let empty_checkpoint = C61InteractiveCheckpoint::empty(num_variables, context_digest)
        .map_err(|error| error.to_string())?;
    let first = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        empty_checkpoint,
        None,
    )?;
    if first.broker.ledger.values().sum::<u64>() != first.broker.transcript_bytes {
        return Err("C6ICT1 broker transcript ledger mismatch".to_owned());
    }
    let (verifier_affine, verifier_base_case, verifier_interaction) =
        verify_private_entropy_diagnostic(
            &first.artifact,
            &first.point,
            first.target_key,
            pcg_seed,
            delta,
            id,
            mask_range,
            first.broker.tape.clone(),
        )?;
    if first.provider_affine != verifier_affine
        || first.provider_base_case != verifier_base_case
        || first.broker.interaction != verifier_interaction
    {
        return Err("C6ICT1 provider/verifier differential mismatch".to_owned());
    }
    let checkpoint_frontier = first.broker.tape.challenge_count() / 2;
    let checkpoint_bytes = first
        .broker
        .tape
        .checkpoint_bytes(checkpoint_frontier)
        .map_err(|error| error.to_string())?;
    let checkpoint =
        C61InteractiveCheckpoint::decode(&checkpoint_bytes).map_err(|error| error.to_string())?;
    if checkpoint.challenge_count() != checkpoint_frontier {
        return Err("C6ICT1 checkpoint round-trip changed its frontier".to_owned());
    }
    let checkpoint_codec_mutations_rejected = {
        let mut wrong_magic = checkpoint_bytes.clone();
        wrong_magic[0] ^= 1;
        let mut wrong_version = checkpoint_bytes.clone();
        wrong_version[8] ^= 1;
        let mut wrong_reserved = checkpoint_bytes.clone();
        wrong_reserved[11] = 1;
        let mut wrong_record_tag = checkpoint_bytes.clone();
        wrong_record_tag[48] = 0xff;
        let mut wrong_record_reserved = checkpoint_bytes.clone();
        wrong_record_reserved[50] = 1;
        let mut trailing = checkpoint_bytes.clone();
        trailing.push(0);
        C61InteractiveCheckpoint::decode(&wrong_magic).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_version).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_reserved).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_record_tag).is_err()
            && C61InteractiveCheckpoint::decode(&wrong_record_reserved).is_err()
            && C61InteractiveCheckpoint::decode(&checkpoint_bytes[..checkpoint_bytes.len() - 1])
                .is_err()
            && C61InteractiveCheckpoint::decode(&trailing).is_err()
    };

    let durable_root = std::env::temp_dir().join(format!(
        "volta-c61-durable-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock predates UNIX epoch".to_owned())?
            .as_nanos()
    ));
    std::fs::create_dir_all(&durable_root)
        .map_err(|error| format!("cannot create C6ICJ1 diagnostic directory: {error}"))?;
    let journal_path = durable_root.join("interaction.c6icj1");
    let head = C6CacheHead {
        epoch: 0,
        cache_len: 0,
        cache_root: [0x31; 32],
        producer_transition_digest: [0; 32],
    };
    let attempt = C6ClientAttempt {
        slot: 0,
        nonce: [0x32; 32],
        setup_manifest_digest: [0x33; 32],
        old_head_digest: head.digest(),
        predecessor_certificate_digest: [0; 32],
        correlation_ranges: C6PairedCorrelationRanges {
            coordinates: [
                C6CorrelationRange { stage: 1, start: 40_000, count: 100 },
                C6CorrelationRange { stage: 1, start: 40_000, count: 100 },
            ],
        },
        workload: C6Workload { prompt_tokens: 1, decode_tokens: 0, old_context: 0, new_context: 1 },
    };
    let durable_state = C6ClientState {
        protocol_digest: [0x34; 32],
        model_digest: [0x35; 32],
        params_digest: [0x36; 32],
        setup_manifest_digest: attempt.setup_manifest_digest,
        connection_id: [0x37; 32],
        head,
        accepted_certificate_digest: [0; 32],
        next_slot: 1,
        raw_high_water: [40_100, 40_100],
        pending_attempt: Some(attempt),
    };
    durable_state.validate().map_err(|error| error.to_string())?;
    let checkpoint_mask_events: Vec<(usize, u32, [u8; 32])> = first
        .broker
        .mask_events
        .iter()
        .copied()
        .filter(|(index, _, _)| *index <= checkpoint_frontier)
        .collect();
    let durable_journal = create_c61_durable_checkpoint_prefix(
        &journal_path,
        durable_state,
        attempt,
        checkpoint.clone(),
        &checkpoint_mask_events,
    )
    .map_err(|error| error.to_string())?;
    drop(durable_journal);
    let durable_journal = open_c61_durable_checkpoint(
        &journal_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .map_err(|error| error.to_string())?;
    let durable_resumed = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        checkpoint.clone(),
        Some(durable_journal),
    )?;
    let durable_resume_artifact_identical =
        durable_resumed.artifact.payload == first.artifact.payload;
    let durable_resume_tape_identical = durable_resumed.broker.tape == first.broker.tape;
    let durable_journal_bytes = usize::try_from(
        std::fs::metadata(&journal_path)
            .map_err(|error| format!("cannot stat C6ICJ1 journal: {error}"))?
            .len(),
    )
    .map_err(|_| "C6ICJ1 journal length exceeds usize".to_owned())?;
    let durable_bytes = std::fs::read(&journal_path)
        .map_err(|error| format!("cannot read C6ICJ1 diagnostic journal: {error}"))?;
    let wrong_binding_state = C6ClientState { connection_id: [0x38; 32], ..durable_state };
    let durable_wrong_binding_rejected = open_c61_durable_checkpoint(
        &journal_path,
        wrong_binding_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();
    let torn_path = durable_root.join("torn.c6icj1");
    std::fs::write(&torn_path, &durable_bytes[..durable_bytes.len() - 1])
        .map_err(|error| format!("cannot write torn C6ICJ1 journal: {error}"))?;
    let durable_torn_journal_rejected = open_c61_durable_checkpoint(
        &torn_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();
    let corrupt_path = durable_root.join("corrupt.c6icj1");
    let mut corrupt_bytes = durable_bytes;
    let corrupt_index = corrupt_bytes.len() / 2;
    corrupt_bytes[corrupt_index] ^= 1;
    std::fs::write(&corrupt_path, &corrupt_bytes)
        .map_err(|error| format!("cannot write corrupt C6ICJ1 journal: {error}"))?;
    let durable_corrupt_journal_rejected = open_c61_durable_checkpoint(
        &corrupt_path,
        durable_state,
        attempt,
        num_variables,
        context_digest,
    )
    .is_err();

    let resumed = prove_private_entropy_diagnostic(
        witness.clone(),
        point.clone(),
        verifier_seed,
        0xC6_1001,
        pcg_seed,
        delta,
        target_tag,
        id,
        mask_range,
        checkpoint.clone(),
        None,
    )?;
    let resumed_artifact_identical = resumed.artifact.payload == first.artifact.payload;
    let resumed_tape_identical = resumed.broker.tape == first.broker.tape;

    let mut mutated_checkpoint = checkpoint;
    mutated_checkpoint.mutate_first_move_for_test();
    let mutated_checkpoint_rejected = catch_unwind(AssertUnwindSafe(|| {
        prove_private_entropy_diagnostic(
            witness,
            point,
            verifier_seed,
            0xC6_1001,
            pcg_seed,
            delta,
            target_tag,
            id,
            mask_range,
            mutated_checkpoint,
            None,
        )
    }))
    .map_or(true, |result| result.is_err());

    std::fs::remove_dir_all(&durable_root)
        .map_err(|error| format!("cannot remove C6ICJ1 diagnostic directory: {error}"))?;

    Ok(C61PrivateEntropyDriverDiagnostic {
        num_variables,
        strict_payload_bytes: first.artifact.payload.len(),
        strict_payload_blake3: *blake3::hash(&first.artifact.payload).as_bytes(),
        provider_interaction: first.broker.interaction,
        verifier_interaction,
        challenge_count: first.broker.tape.challenge_count(),
        checkpoint_frontier,
        checkpoint_bytes: checkpoint_bytes.len(),
        replayed_challenges: resumed.broker.replayed_challenges,
        resumed_artifact_identical,
        resumed_tape_identical,
        mutated_checkpoint_rejected,
        checkpoint_codec_mutations_rejected,
        durable_journal_bytes,
        durable_replayed_challenges: durable_resumed.broker.replayed_challenges,
        durable_replayed_mask_events: durable_resumed.broker.replayed_mask_events,
        durable_mask_frontier: durable_resumed.broker.mask_frontier,
        durable_record_count: durable_resumed.broker.durable_record_count,
        durable_resume_artifact_identical,
        durable_resume_tape_identical,
        durable_wrong_binding_rejected,
        durable_torn_journal_rejected,
        durable_corrupt_journal_rejected,
        provider_received_verifier_seed: false,
        provider_received_checkpoint: false,
        full_correlations: first.full_correlations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaled_claimless_affine_whir_closes_through_designated_mac() {
        let report = run_c61_authenticated_whir_p3_diagnostic(14).unwrap();
        assert_eq!(report.provider_affine, report.verifier_affine);
        assert_eq!(report.provider_ledger, report.verifier_ledger);
        assert_eq!(report.provider_transcript_bytes, report.verifier_transcript_bytes);
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(
            report.provider_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert_eq!(report.strict_payload_bytes, 378_496);
        assert_eq!(report.provider_interaction.provider_messages, 26);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 52_608);
        assert_eq!(report.provider_interaction.provider_payload_bytes, 378_480);
        assert_eq!(report.provider_interaction.client_fp_challenges, 52);
        assert_eq!(report.provider_interaction.client_query_challenges, 2_536);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 10_560);
        assert_eq!(
            report.strict_payload_blake3,
            [
                0x9d, 0xba, 0xa6, 0x63, 0x36, 0xf8, 0x83, 0x3b, 0x0a, 0x0e, 0x3a, 0x32, 0xf7, 0x02,
                0x3f, 0x5c, 0x25, 0xf2, 0x16, 0x6e, 0x6e, 0x84, 0x31, 0x24, 0x4a, 0x06, 0xb4, 0x1d,
                0x70, 0x79, 0x58, 0xbb,
            ],
        );
        assert!(!report.proof_has_clear_evaluation_field);
        assert_eq!(report.full_correlations, 1);

        let d27 = c61_authenticated_p3_structural_budget(27).unwrap();
        let d28 = c61_authenticated_p3_structural_budget(28).unwrap();
        assert_eq!(d27.rounds, 10);
        assert_eq!(d28.rounds, 11);
        assert_eq!(d27.mask_queries, 187);
        assert_eq!(d28.mask_queries, 187);
        assert_eq!(d27.max_ood_samples, 1);
        assert_eq!(d28.max_ood_samples, 1);
        assert_eq!(d27.ood_privacy_bad_event_numerator, 10);
        assert_eq!(d28.ood_privacy_bad_event_numerator, 11);
        assert_eq!(d27.strict_chain_bytes, 1_085_464);
        assert_eq!(d28.strict_chain_bytes, 1_172_652);
        assert!(d28.strict_chain_bytes < C61_NATIVE_CHAIN_MAX_BYTES);
        assert!(c61_authenticated_p3_structural_budget(26).is_err());
        assert!(c61_authenticated_structural_budget_inner(14, true).is_err());
    }

    #[test]
    fn ordered_multi_open_aggregates_authenticated_targets_without_wire_growth() {
        let embedding = run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 6).unwrap();
        let model = run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 96).unwrap();
        assert_eq!(embedding.claim_count, 6);
        assert_eq!(model.claim_count, 96);
        assert!(embedding.strict_payload_bytes <= embedding.strict_payload_max_bytes);
        assert!(model.strict_payload_bytes <= model.strict_payload_max_bytes);
        assert_eq!(
            embedding.strict_payload_max_bytes,
            c61_authenticated_structural_budget_inner(14, false).unwrap().strict_chain_bytes
        );
        assert_eq!(embedding.strict_payload_max_bytes, model.strict_payload_max_bytes);
        assert_eq!(embedding.provider_interaction, embedding.verifier_interaction);
        assert_eq!(model.provider_interaction, model.verifier_interaction);
        assert_eq!(
            embedding.provider_interaction.provider_payload_bytes as usize + 16,
            embedding.strict_payload_bytes
        );
        assert_eq!(
            model.provider_interaction.provider_payload_bytes as usize + 16,
            model.strict_payload_bytes
        );
        assert!(embedding.batching_weights_identical);
        assert!(model.batching_weights_identical);
        assert!(embedding.point_mutation_rejected);
        assert!(model.point_mutation_rejected);
        assert_eq!(embedding.full_correlations, 1);
        assert_eq!(model.full_correlations, 1);
        assert!(run_c61_authenticated_whir_p3_multi_open_diagnostic(14, 129).is_err());
    }

    #[test]
    fn physical_response_and_plan_share_common_rounds_and_one_authenticated_residual() {
        let report = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(14).unwrap();
        assert!(!report.production_geometry);
        assert!(!report.monolithic_host_baseline);
        assert!(!report.persisted_executor);
        assert!(!report.gpu_performance_credit);
        assert_eq!(report.admitted_available_host_bytes, 0);
        assert_eq!(report.admitted_available_spill_bytes, 0);
        assert_eq!(report.monolithic_retained_lower_bound_bytes, 0);
        assert!(!report.pooled_pcg);
        assert_eq!(report.response_num_variables, 14);
        assert_eq!(report.plan_num_variables, 13);
        assert_eq!(report.response_claim_count, 12);
        assert_eq!(report.plan_claim_count, 3);
        assert_eq!(report.strict_payload_bytes, 677_532);
        assert_eq!(report.strict_payload_max_bytes, 770_748);
        assert_eq!(report.arithmetic_payload_bytes, 5_212);
        assert_eq!(report.total_provider_payload_bytes, 682_744);
        assert_eq!(report.response_target_correction_bytes, 192);
        assert_eq!(report.arithmetic_product_triples, 87);
        assert_eq!(report.folded_zero_rows, 31);
        assert_eq!(report.provider_transcript_bytes, 682_652);
        assert_eq!(
            report.total_provider_payload_bytes as u64 - report.provider_transcript_bytes,
            crate::C61_SPARSE_RATIONAL_BLIND_ARITHMETIC_FRAMING_BYTES,
        );
        assert!(report.strict_payload_bytes <= report.strict_payload_max_bytes);
        assert!(report.strict_payload_max_bytes < C61_SHARED_MULTI_ORACLE_MAX_BYTES);
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(report.provider_interaction.provider_messages, 36);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 94_752);
        assert_eq!(report.provider_interaction.client_fp_challenges, 75);
        assert_eq!(report.provider_interaction.client_query_challenges, 4_193);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 17_372);
        assert_eq!(
            report.provider_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert!(report.native_challenges_shared);
        assert!(report.postproof_batching_challenge_identical);
        assert!(report.plan_reserved_tag_is_zero);
        assert!(report.codec_mutations_rejected);
        assert!(report.arithmetic_payload_mutation_rejected);
        assert!(report.joint_tag_mutation_rejected);
        assert_eq!(report.subfield_correlations, 24);
        assert_eq!(report.full_correlations, 305);
        assert_eq!(report.response_spill, C61PersistedMmcsMetrics::default());
        assert_eq!(report.plan_spill, C61PersistedMmcsMetrics::default());
    }

    #[test]
    fn persisted_shared_flow_is_byte_identical_to_resident_reference() {
        let resident = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(14).unwrap();
        let spill_root = std::env::temp_dir().join(format!(
            "volta-c61-shared-spill-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let persisted =
            run_c61_authenticated_whir_p3_shared_multi_oracle_persisted_diagnostic(14, &spill_root)
                .unwrap();
        assert!(persisted.persisted_executor);
        assert!(!persisted.monolithic_host_baseline);
        assert!(!persisted.gpu_performance_credit);
        assert_eq!(persisted.strict_payload_blake3, resident.strict_payload_blake3);
        assert_eq!(persisted.strict_payload_bytes, resident.strict_payload_bytes);
        assert_eq!(persisted.arithmetic_payload_bytes, resident.arithmetic_payload_bytes);
        assert_eq!(persisted.total_provider_payload_bytes, resident.total_provider_payload_bytes);
        assert_eq!(persisted.provider_interaction, resident.provider_interaction);
        assert_eq!(persisted.verifier_interaction, resident.verifier_interaction);
        assert_eq!(persisted.subfield_correlations, resident.subfield_correlations);
        assert_eq!(persisted.full_correlations, resident.full_correlations);
        for metrics in [persisted.response_spill, persisted.plan_spill] {
            assert!(metrics.spill_files > 1);
            assert!(metrics.logical_spill_bytes > 0);
            assert!(metrics.host_bytes_written >= metrics.logical_spill_bytes);
            assert!(metrics.host_bytes_read > 0);
            assert!(metrics.host_bytes_read < metrics.logical_spill_bytes);
            assert_eq!(metrics.fsync_calls, metrics.spill_files);
        }
        std::fs::remove_dir_all(spill_root).unwrap();
    }

    #[test]
    fn production_d28_d27_censuses_monolithic_memory_before_allocation() {
        let census = c61_production_monolithic_memory_census().unwrap();
        assert_eq!(census.response_num_variables, 28);
        assert_eq!(census.plan_num_variables, 27);
        assert_eq!(census.response_message_bytes, 2_147_483_648);
        assert_eq!(census.response_encoded_bytes, 4_294_967_296);
        assert_eq!(census.response_merkle_bytes, 17_179_869_152);
        assert_eq!(census.response_retained_lower_bound_bytes, 23_622_320_096);
        assert_eq!(census.plan_message_bytes, 1_073_741_824);
        assert_eq!(census.plan_encoded_bytes, 2_147_483_648);
        assert_eq!(census.plan_merkle_bytes, 8_589_934_560);
        assert_eq!(census.plan_retained_lower_bound_bytes, 11_811_160_032);
        assert_eq!(census.concurrent_retained_lower_bound_bytes, 35_433_480_128);
        assert_eq!(census.coefficient_witness_cap_bytes, 2_293_198_848);
        assert_eq!(census.retained_minus_component_cap_bytes, 33_140_281_280);

        let error = run_c61_authenticated_whir_p3_shared_multi_oracle_diagnostic(28)
            .expect_err("D28 must reject before materializing the scaled fixture or witness");
        assert!(error.contains("persisted/recomputable or GPU-resident executor"));
        assert!(error.contains("35433480128 B"));
        assert!(!error.contains("provider-state gate"));
    }

    #[test]
    fn production_monolithic_entry_requires_owner_resources_and_real_pcg() {
        use volta_proto::c6_residual::*;

        let direct = build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let topology = direct.operation_plan().topology();
        let source_manifest = C6TraceSourceManifest::new(
            topology.source_count,
            topology.source_schedule_digest,
            direct.manifest().product_mask_sources().to_vec(),
        )
        .unwrap();
        let terminal_metadata = C6OperationPlanTerminalMetadata::from_installed(
            direct.operation_plan(),
            &source_manifest,
        )
        .unwrap();
        let leaf_point = [Fp2::ZERO; 7];
        let delta = Fp2::new(Fp::new(P - 83), Fp::new(0xC6_5202));
        let invoke = |admission| {
            run_c61_authenticated_whir_p3_production_monolithic_baseline(
                direct.operation_plan(),
                terminal_metadata.clone(),
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                [&leaf_point, &leaf_point],
                Fp2::new(Fp::new(191), Fp::new(17)),
                admission,
                CorrelationStream::new([0xD3; 32]),
                VerifierCtx::new([0xD3; 32], delta),
                [0xC2; 32],
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 },
            )
            .unwrap_err()
        };
        let resource_error = invoke(C61ProductionMonolithicResourceAdmission {
            available_host_bytes: 11 * 1024 * 1024 * 1024,
            gpu_total_bytes: 0,
            a100_present: false,
            allow_host_monolithic_baseline: false,
        });
        assert!(resource_error.contains("baseline admission failed"));
        let pcg_error = invoke(C61ProductionMonolithicResourceAdmission {
            available_host_bytes: C61_PRODUCTION_MONOLITHIC_MIN_AVAILABLE_HOST_BYTES,
            gpu_total_bytes: 80 * 1024 * 1024 * 1024,
            a100_present: true,
            allow_host_monolithic_baseline: true,
        });
        assert!(pcg_error.contains("forbids mock PCG state"));

        let persisted_invoke = |admission| {
            run_c61_authenticated_whir_p3_production_persisted(
                direct.operation_plan(),
                terminal_metadata.clone(),
                direct.extraction(),
                direct.runtime(),
                direct.relation(),
                [&leaf_point, &leaf_point],
                Fp2::new(Fp::new(191), Fp::new(17)),
                Path::new("/tmp/volta-c61-persisted-admission-unused"),
                admission,
                CorrelationStream::new([0xD3; 32]),
                VerifierCtx::new([0xD3; 32], delta),
                [0xC2; 32],
                C61NativeChainId { component: C61NativeComponent::Compiler, repetition: 0 },
                C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 29, range_start: 120_000 },
            )
            .unwrap_err()
        };
        let resource_error = persisted_invoke(C61ProductionPersistedResourceAdmission {
            available_host_bytes: 11 * 1024 * 1024 * 1024,
            available_spill_bytes: 64 * 1024 * 1024 * 1024,
            gpu_total_bytes: 0,
            a100_present: false,
            allow_persisted_executor: false,
        });
        assert!(resource_error.contains("persisted A100 admission failed"));
        let pcg_error = persisted_invoke(C61ProductionPersistedResourceAdmission {
            available_host_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_HOST_BYTES,
            available_spill_bytes: C61_PRODUCTION_PERSISTED_MIN_AVAILABLE_SPILL_BYTES,
            gpu_total_bytes: 80 * 1024 * 1024 * 1024,
            a100_present: true,
            allow_persisted_executor: true,
        });
        assert!(pcg_error.contains("persisted runner forbids mock PCG state"));
    }

    #[test]
    fn fork_source_guard_has_no_eval_field_or_clear_claim_replay() {
        let proof = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/proof.rs");
        let prover = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs");
        let verifier = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/verifier/mod.rs");
        let sumcheck = include_str!("../../third_party/p3-sumcheck-c61/src/zk/prover/residual.rs");
        let prover_data = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/data.rs");
        let adapter = include_str!("c61_authenticated_whir_p3.rs");
        let production_adapter = adapter.split("#[cfg(test)]").next().unwrap();
        let sparse_verifier = production_adapter
            .split("fn verify_c61_sparse_compiler_relation_phase(")
            .nth(1)
            .unwrap()
            .split("/// Exercise the C6SPR3 physical response/plan opening")
            .next()
            .unwrap();
        assert!(!proof.contains("pub evals:"));
        assert_eq!(prover.matches("into_zk_sumcheck_claimless(").count(), 2);
        assert!(prover.contains("claims.len() <= 128"));
        assert!(!prover.contains("claims[0]"));
        assert!(verifier.contains("verify_affine_claim"));
        assert!(verifier.contains("points.len() > 128"));
        assert!(!verifier.contains("points[0]"));
        assert!(sumcheck.contains("into_zk_sumcheck_claimless"));
        assert!(sumcheck.contains("aux_claim,\n            false,"));
        assert!(prover_data.contains("pub message: Poly<F>"));
        assert!(prover_data.contains("pub merkle: MT::ProverData<DenseMatrix<F>>"));
        assert_eq!(
            production_adapter.matches("C61InteractiveChallenger::new_claimless(").count(),
            6
        );
        assert_eq!(production_adapter.matches(".observe_public_point(").count(), 5);
        assert_eq!(production_adapter.matches(".observe_public_points(").count(), 7);
        assert_eq!(production_adapter.matches(".ensure_public_statement_bound()").count(), 4);
        assert_eq!(production_adapter.matches("challenger.finish(").count(), 7);
        assert_eq!(production_adapter.matches("c61_shared_round_pair(").count(), 2);
        assert!(!sparse_verifier.contains(".direct"));
        assert!(!sparse_verifier.contains(".packed"));
        assert!(!sparse_verifier.contains("extraction"));
        assert!(!sparse_verifier.contains("runtime"));
        assert_eq!(production_adapter.matches(".sample_postproof_fp2()").count(), 2);
        assert!(production_adapter
            .contains("C61_SHARED_MULTI_ORACLE_MAGIC: [u8; 8] = *b\"C6SMO1\\0\\0\""));
        assert!(!production_adapter.contains("proof.evals"));
        let verifier_adapter = production_adapter
            .split("fn verify_diagnostic(")
            .nth(1)
            .unwrap()
            .split("/// Run one reference-only")
            .next()
            .unwrap();
        assert!(!verifier_adapter.contains("artifact.provider_"));
        assert!(!verifier_adapter.contains("artifact.point"));
        assert!(!verifier_adapter.contains("artifact.target_key"));

        let simulator_adapter = production_adapter
            .split("fn simulate_view_diagnostic(")
            .nth(1)
            .unwrap()
            .split("fn verify_diagnostic(")
            .next()
            .unwrap();
        assert!(simulator_adapter.contains("target_key: VerifierKey"));
        assert!(!simulator_adapter.contains("target_tag"));
        assert!(!simulator_adapter.contains("ProverAuthed"));
        assert!(!simulator_adapter.contains("CorrelationStream"));
        assert!(simulator_adapter.contains("simulate_c61_authenticated_whir_base_view("));

        let mut transcript = Transcript::new([0x31; 32]);
        let challenger = C61InteractiveChallenger::new_claimless(&mut transcript, 4);
        assert!(challenger.ensure_public_statement_bound().is_err());
    }

    #[test]
    fn designated_view_simulator_accepts_without_real_target_or_provider_state() {
        let report = run_c61_authenticated_whir_p3_privacy_diagnostic(14).unwrap();
        assert_eq!(report.simulator_ledger, report.verifier_ledger);
        assert_eq!(report.simulator_transcript_bytes, report.verifier_transcript_bytes);
        assert_eq!(report.simulator_interaction, report.verifier_interaction);
        assert_eq!(
            report.simulator_interaction.provider_payload_bytes as usize
                + C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES,
            report.strict_payload_bytes,
        );
        assert!(
            report.strict_payload_bytes
                <= c61_authenticated_structural_budget_inner(14, false).unwrap().strict_chain_bytes,
        );
        assert!(!report.received_real_target_plaintext);
        assert!(!report.received_provider_target_tag);
        assert!(!report.received_provider_correlation_state);
        assert_eq!(report.verifier_full_key_draws, 1);
    }

    #[test]
    fn private_entropy_driver_replays_to_frontier_without_seed_or_checkpoint_leak() {
        let report = run_c61_private_entropy_driver_diagnostic(14).unwrap();
        assert_eq!(report.provider_interaction, report.verifier_interaction);
        assert_eq!(report.strict_payload_bytes, 378_496);
        assert_eq!(report.provider_interaction.provider_messages, 26);
        assert_eq!(report.provider_interaction.provider_semantic_bytes, 52_608);
        assert_eq!(report.provider_interaction.provider_payload_bytes, 378_480);
        assert_eq!(report.provider_interaction.client_fp_challenges, 52);
        assert_eq!(report.provider_interaction.client_query_challenges, 2_536);
        assert_eq!(report.provider_interaction.client_challenge_payload_bytes, 10_560);
        assert_eq!(report.challenge_count, 2_588);
        assert_eq!(report.checkpoint_frontier, 1_294);
        assert_eq!(report.replayed_challenges, report.checkpoint_frontier);
        assert_eq!(report.checkpoint_bytes, 73_360);
        assert!(report.resumed_artifact_identical);
        assert!(report.resumed_tape_identical);
        assert!(report.mutated_checkpoint_rejected);
        assert!(report.checkpoint_codec_mutations_rejected);
        assert_eq!(report.durable_journal_bytes, 208_204);
        assert_eq!(report.durable_replayed_challenges, report.checkpoint_frontier);
        assert_eq!(report.durable_replayed_mask_events, 1);
        assert_eq!(report.durable_mask_frontier, 1);
        assert_eq!(report.durable_record_count, 2_590);
        assert!(report.durable_resume_artifact_identical);
        assert!(report.durable_resume_tape_identical);
        assert!(report.durable_wrong_binding_rejected);
        assert!(report.durable_torn_journal_rejected);
        assert!(report.durable_corrupt_journal_rejected);
        assert!(!report.provider_received_verifier_seed);
        assert!(!report.provider_received_checkpoint);
        assert_eq!(report.full_correlations, 1);

        let driver_source = include_str!("c61_interactive_driver.rs");
        let endpoint = driver_source
            .split("struct C61ProviderEndpoint")
            .nth(1)
            .unwrap()
            .split("struct C61ProviderState")
            .next()
            .unwrap();
        assert!(endpoint.contains("SyncSender<C61BrokerRequest>"));
        assert!(!endpoint.contains("verifier_seed"));
        assert!(!endpoint.contains("checkpoint"));
        assert!(!endpoint.contains("Transcript"));

        let provider = include_str!("c61_authenticated_whir_p3.rs")
            .split("fn prove_private_entropy_provider_diagnostic(")
            .nth(1)
            .unwrap()
            .split("fn prove_private_entropy_diagnostic(")
            .next()
            .unwrap();
        assert!(provider.contains("C61PrivateEntropyProverChallenger"));
        assert!(!provider.contains("verifier_seed"));
        assert!(!provider.contains("checkpoint"));
    }

    fn mutation_fixture() -> (
        C61AuthenticatedP3Fixture,
        [u8; 32],
        [u8; 32],
        Fp2,
        C61NativeChainId,
        C61AuthenticatedWhirMaskRange,
    ) {
        let num_variables = 14;
        let witness = Poly::new(
            (0..(1usize << num_variables))
                .map(|index| Goldilocks::from_u64((index as u64) * 13 + 7))
                .collect(),
        );
        let point = Point::new(
            (0..num_variables).map(|index| C61P3Fp2::from_u64(index as u64 * 23 + 11)).collect(),
        );
        let verifier_seed = [0x72; 32];
        let pcg_seed = [0xB8; 32];
        let delta = Fp2::new(volta_field::Fp::new(P - 29), volta_field::Fp::new(991));
        let id = C61NativeChainId { component: C61NativeComponent::Embedding, repetition: 1 };
        let mask_range =
            C61AuthenticatedWhirMaskRange { stage: 0x61, slot: 9, range_start: 50_000 };
        let (fixture, _) = prove_diagnostic(
            witness,
            point,
            verifier_seed,
            0xC6_2002,
            pcg_seed,
            delta,
            Fp2::new(volta_field::Fp::new(47), volta_field::Fp::new(53)),
            id,
            mask_range,
        )
        .unwrap();
        (fixture, verifier_seed, pcg_seed, delta, id, mask_range)
    }

    #[test]
    fn target_key_transcript_point_and_base_mutations_fail_closed() {
        let (fixture, verifier_seed, pcg_seed, delta, id, mask_range) = mutation_fixture();
        let artifact = &fixture.artifact;
        let verifier_input = C61AuthenticatedP3VerifierInput {
            point: &fixture.point,
            target_key: fixture.target_key,
            verifier_seed,
            pcg_seed,
            delta,
            id,
            mask_range,
        };

        let (commitment, proof, base_proof) =
            decode_c61_authenticated_p3_artifact_inner(&artifact.payload, 14, false).unwrap();
        assert_eq!(
            encode_c61_authenticated_p3_artifact_inner(14, &commitment, &proof, base_proof, false,)
                .unwrap(),
            artifact.payload,
        );

        let mut bad_key = fixture.target_key;
        bad_key.k += Fp2::ONE;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { target_key: bad_key, ..verifier_input },
        )
        .is_err());

        let mut bad_base = artifact.clone();
        let (commitment, mut proof, base_proof) =
            decode_c61_authenticated_p3_artifact_inner(&bad_base.payload, 14, false).unwrap();
        proof.base_case.masked_claim += C61P3Fp2::ONE;
        bad_base.payload =
            encode_c61_authenticated_p3_artifact_inner(14, &commitment, &proof, base_proof, false)
                .unwrap();
        assert!(verify_diagnostic(&bad_base, verifier_input,).is_err());

        let mut bad_tag = artifact.clone();
        let last = bad_tag.payload.len() - 1;
        bad_tag.payload[last] ^= 1;
        assert!(verify_diagnostic(&bad_tag, verifier_input,).is_err());

        let mut coordinates = fixture.point.as_slice().to_vec();
        coordinates[0] += C61P3Fp2::ONE;
        let bad_point = Point::new(coordinates);
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { point: &bad_point, ..verifier_input },
        )
        .is_err());

        let mut wrong_seed = verifier_seed;
        wrong_seed[0] ^= 1;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { verifier_seed: wrong_seed, ..verifier_input },
        )
        .is_err());

        let mut wrong_range = mask_range;
        wrong_range.range_start += 3;
        assert!(verify_diagnostic(
            artifact,
            C61AuthenticatedP3VerifierInput { mask_range: wrong_range, ..verifier_input },
        )
        .is_err());

        let mut bad_magic = artifact.payload.clone();
        bad_magic[0] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_magic, 14, false).is_err());

        let mut bad_version = artifact.payload.clone();
        bad_version[8] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_version, 14, false).is_err());

        let mut bad_dimension = artifact.payload.clone();
        bad_dimension[10] = 13;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_dimension, 14, false).is_err());

        let mut bad_reserved = artifact.payload.clone();
        bad_reserved[11] = 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_reserved, 14, false).is_err());

        let mut bad_body_len = artifact.payload.clone();
        bad_body_len[12] ^= 1;
        assert!(decode_c61_authenticated_p3_artifact_inner(&bad_body_len, 14, false).is_err());

        let mut noncanonical_tag = artifact.payload.clone();
        let tag_offset = noncanonical_tag.len() - C61_AUTHENTICATED_WHIR_ZERO_OPEN_TAG_BYTES;
        noncanonical_tag[tag_offset..tag_offset + 8].copy_from_slice(&P.to_le_bytes());
        assert!(decode_c61_authenticated_p3_artifact_inner(&noncanonical_tag, 14, false).is_err());

        let mut trailing = artifact.payload.clone();
        trailing.push(0);
        assert!(decode_c61_authenticated_p3_artifact_inner(&trailing, 14, false).is_err());
        assert!(decode_c61_authenticated_p3_artifact_inner(
            &artifact.payload[..artifact.payload.len() - 1],
            14,
            false,
        )
        .is_err());

        let config = c61_authenticated_config::<C61SizingChallenger>(14).unwrap();
        let batches = config.n_rounds() + 1;
        let sumcheck_rounds: usize =
            (0..batches).map(|batch| config.round_folding_factor(batch)).sum();
        let first_round = &config.round_parameters[0];
        let first_fold = config.round_folding_factor(0);
        let first_multiproof_count = C61_AUTHENTICATED_P3_HEADER_BYTES
            + C61_WHIRA1_DIGEST_BYTES
            + (batches + sumcheck_rounds * (C61_WHIRA1_ELL_ZK - 1)) * C61_WHIRA1_FP2_BYTES
            + batches * C61_WHIRA1_DIGEST_BYTES
            + 2 * C61_WHIRA1_DIGEST_BYTES
            + first_round.ood_samples * C61_WHIRA1_FP2_BYTES
            + first_round.num_queries * (1usize << first_fold) * C61_WHIRA1_FP_BYTES;
        let mut excessive_frontier = artifact.payload.clone();
        excessive_frontier[first_multiproof_count..first_multiproof_count + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_c61_authenticated_p3_artifact_inner(&excessive_frontier, 14, false).is_err());
    }
}
