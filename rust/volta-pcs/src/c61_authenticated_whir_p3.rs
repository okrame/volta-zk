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

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2DFTSmallBatch;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
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
use volta_field::{Fp2, P};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_proto::c6::{
    C6CacheHead, C6ClientAttempt, C6ClientState, C6CorrelationRange, C6PairedCorrelationRanges,
    C6Workload,
};

use crate::c61_authenticated_whir::{
    finish_c61_authenticated_whir_base, prepare_c61_authenticated_whir_mask,
    simulate_c61_authenticated_whir_base_view, verify_c61_authenticated_whir_base,
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
use crate::c61_public_compression::{C61NativeChainId, C61NativeComponent};
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

fn encode_c61_authenticated_p3_artifact_inner(
    num_variables: usize,
    commitment: &C61Commitment,
    proof: &C61AuthenticatedP3Proof,
    base_proof: C61AuthenticatedWhirBaseProof,
    production_dimensions_only: bool,
) -> ReferenceResult<Vec<u8>> {
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
    fn fork_source_guard_has_no_eval_field_or_clear_claim_replay() {
        let proof = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/proof.rs");
        let prover = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/prover/mod.rs");
        let verifier = include_str!("../../third_party/p3-whir-c61/src/pcs/zk/verifier/mod.rs");
        let sumcheck = include_str!("../../third_party/p3-sumcheck-c61/src/zk/prover/residual.rs");
        let adapter = include_str!("c61_authenticated_whir_p3.rs");
        let production_adapter = adapter.split("#[cfg(test)]").next().unwrap();
        assert!(!proof.contains("pub evals:"));
        assert_eq!(prover.matches("into_zk_sumcheck_claimless(").count(), 2);
        assert!(prover.contains("claims.len() <= 128"));
        assert!(!prover.contains("claims[0]"));
        assert!(verifier.contains("verify_affine_claim"));
        assert!(verifier.contains("points.len() > 128"));
        assert!(!verifier.contains("points[0]"));
        assert!(sumcheck.contains("into_zk_sumcheck_claimless"));
        assert!(sumcheck.contains("aux_claim,\n            false,"));
        assert_eq!(
            production_adapter.matches("C61InteractiveChallenger::new_claimless(").count(),
            6
        );
        assert_eq!(production_adapter.matches(".observe_public_point(").count(), 5);
        assert_eq!(production_adapter.matches(".observe_public_points(").count(), 3);
        assert_eq!(production_adapter.matches(".ensure_public_statement_bound()").count(), 4);
        assert_eq!(production_adapter.matches("challenger.finish(").count(), 7);
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
