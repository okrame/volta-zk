//! X4d GPT-2 response freeze and settlement-batch orchestration.
//!
//! This module deliberately owns no PCS algorithm.  It maps the existing
//! model-output claims into the protocol-library accumulator, keeps local MAC
//! shares behind opaque handles, and hands one exact contiguous range to the
//! reused schema-4 settlement prover.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use volta_field::Fp2;
use volta_gpt2::Gpt2Model;
use volta_mac::{
    CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey, RESERVED_DOMAIN_BITS,
};
use volta_pcg::X4dSettlementFreshnessJournalAudit;
use volta_pcs::x4::{
    authenticate_pending_aux_prover_v4, authenticate_pending_aux_verifier_v4,
    authenticated_output_link_schedule_digest_x4d_v1, evaluate_multilinear_table,
    gpt2_codec_reference_packed_opening_v4, manifest_id_digest_v4,
    multilinear_coefficients_in_place, multilinear_evaluations_in_place,
    opening_schedule_digest_x4d_v1, profile_digest_v4, prove_authenticated_output_link_x4d_v4,
    prove_bound_response_zero_batch_v4, verify_authenticated_output_link_x4d_v4,
    verify_bound_response_zero_batch_v4, AuthenticatedOutputBlockProverV4,
    AuthenticatedOutputBlockVerifierV4, AuthenticatedOutputLinkFrame,
    AuthenticatedOutputLinkMetricsV4, AuthenticatedOutputLinkPrefixV4,
    AuthenticatedOutputLinkProofV4, Digest, FoldCommitmentFrameV4, FrameV4,
    InitialOpeningScheduleV4, LinkPolynomialProverV4, LinkPolynomialVerifierV4, M9TransferFrame,
    ManifestFrameV4, ManifestLeafFrame, ManifestTreeV4, ModelGlobalOpeningSourceV4, OracleKindV4,
    PackedOpeningScheduleV4, Phase, ReducedClaimFrame, ResponseZeroBatchFrame, X4OpeningRegistryV4,
    X4cArenaRuntimeV4, X4cRamModelGlobalCohortV4, X4cResponseMetricsV4, X4cSealConfigV4,
    X4dAuthenticatedValueStoreV1, X4dClaimAccumulatorV1, X4dConnectionStateV1, X4dErrorV1,
    X4dFreezeReceiptV1, X4dFrozenClaimIdentityV1, X4dResponseStateV1, X4dSettlementContextV1,
    X4dSettlementEnvelopeV1, X4dSettlementPolicyV1, X4dSettlementQuerySeedV1,
    X4D_GPT2_CLAIMS_PER_RESPONSE_V1, X4D_GPT2_GROUPS_PER_RESPONSE_V1, X4D_GPT2_RESPONSE_BYTES_V1,
    X4D_PENDING_CLAIM_CAP_V1, X4D_QUERY_COUNT_V1,
};
use volta_pcs::{batch_reduce_prover, batch_reduce_verifier, BlockClaim};
use volta_proto::sumcheck_blind::BlindSumcheckProof;
use volta_proto::{ModelOut, ModelOutV, WeightClaimP};

use crate::x4c_gpt2::{
    cohort_index_for_auxiliary, cohort_index_for_weight, mirror_claim_reduction_round_accounting,
    padded_source_i16, UniformFp2Xof, X4cGpt2EvaluationTables, X4cGpt2Inventory,
    X4C_CLAIM_REDUCTION_DOMAIN_BASE, X4C_GPT2_CLAIM_REDUCTION_FULL_CORRELATIONS,
    X4C_GPT2_PHYSICAL_BLOCKS, X4C_WEXT_MU20_COHORT_ID, X4C_WEXT_MU22_COHORT_ID,
    X4C_WEXT_MU26_COHORT_ID,
};

pub const X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1: u64 = 41_270_400;
pub const X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1: u64 = 64;
pub const X4D_RESPONSE_CPU_WORKERS_V1: usize = 8;
pub const X4D_SETTLEMENT_CPU_WORKERS_V1: usize = 27;
pub const X4D_FULL_CORRELATIONS_PER_RESPONSE_V1: u64 = 2_259;
pub const X4D_FULL_CORRELATIONS_PER_SETTLEMENT_V1: u64 = 55;
pub const X4D_STATIC_WEIGHT_COHORTS_V1: usize = 3;
pub const X4D_FRESH_AUXILIARY_COHORTS_V1: usize = 2;

const X4D_SETTLEMENT_DOMAIN_EPOCH_STRIDE_V1: u64 = 0x10_0000;
const X4D_CLAIM_REDUCTION_DOMAIN_BASE_V1: u64 = 0x1001_0000_0000_0000;
const X4D_M9_DOMAIN_BASE_V1: u64 = 0x1001_0000_0001_0000;
const X4D_LINK_DOMAIN_BASE_V1: u64 = 0x1001_0000_0002_0000;
const X4D_ZERO_DOMAIN_BASE_V1: u64 = 0x1001_0000_0003_0000;
const X4D_AUX_MASK_XOF_CONTEXT_V1: &str = "volta-zk/x4d/gpt2-settlement-aux-mask/v1";
const X4D_AUX_MASK_SEED_COMMITMENT_CONTEXT_V1: &str =
    "volta-zk/x4d/gpt2-settlement-aux-mask-seed-commitment/v1";
const X4D_AUX_ROOT_SET_CONTEXT_V1: &str = "volta-zk/x4d/gpt2-settlement-aux-root-set/v1";
const X4D_STATIC_WEIGHT_COMMITMENT_CONTEXT_V1: &str =
    "volta-zk/x4d/gpt2-static-weight-commitment/v1";

#[derive(Clone, Debug)]
pub struct X4dGpt2FrozenResponseLocalV1 {
    pub response_nonce: Digest,
    pub model_transcript_digest: Digest,
    pub claim_frames: Vec<ReducedClaimFrame>,
    pub prover_parent_values: Vec<ProverAuthed>,
    pub verifier_parent_keys: Vec<VerifierKey>,
    pub freeze_receipt: X4dFreezeReceiptV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dDeliveredResponseV1 {
    pub response_nonce: Digest,
    pub product_state: X4dResponseStateV1,
    pub model_transcript_bytes: u64,
    pub model_mac_closure_bytes: u64,
    pub pcs_bytes: u64,
    pub response_bytes: u64,
    pub claim_freeze_wall_ns: u64,
    pub freeze_receipt: X4dFreezeReceiptV1,
}

#[derive(Clone, Debug)]
pub struct X4dGpt2SettlementBatchV1 {
    pub static_weight_commitment_digest: Digest,
    pub context: X4dSettlementContextV1,
    pub frozen_claims: Vec<X4dFrozenClaimIdentityV1>,
    pub responses: Vec<X4dGpt2FrozenResponseLocalV1>,
    pub prover_parent_values: Vec<ProverAuthed>,
    pub verifier_parent_keys: Vec<VerifierKey>,
    pub counters: X4dGpt2SettlementCountersV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4dGpt2SettlementCountersV1 {
    pub responses: usize,
    pub frozen_claims: usize,
    pub masked_groups: usize,
    pub active_chain_polynomials: usize,
    pub fold_rounds: usize,
    pub query_draws: usize,
    pub claim_reduction_full_correlations: u64,
    pub seam_full_correlations: u64,
    pub total_full_correlations_per_role: u64,
}

impl X4dGpt2SettlementCountersV1 {
    pub fn for_responses(responses: usize) -> Result<Self, String> {
        if responses == 0 || responses > 32 {
            return Err("X4d GPT-2 settlement response count is outside 1..=32".to_owned());
        }
        let frozen_claims = X4D_GPT2_CLAIMS_PER_RESPONSE_V1
            .checked_mul(responses)
            .ok_or_else(|| "X4d frozen-claim count overflows".to_owned())?;
        let masked_groups = X4D_GPT2_GROUPS_PER_RESPONSE_V1
            .checked_mul(responses)
            .ok_or_else(|| "X4d masked-group count overflows".to_owned())?;
        if frozen_claims > X4D_PENDING_CLAIM_CAP_V1 || masked_groups > 1_660 {
            return Err("X4d GPT-2 settlement exceeds its registered cap".to_owned());
        }
        let responses_u64 =
            u64::try_from(responses).map_err(|_| "X4d response count overflows".to_owned())?;
        let claim_reduction_full_correlations = 2_208u64
            .checked_mul(responses_u64)
            .ok_or_else(|| "X4d claim-reduction correlations overflow".to_owned())?;
        let seam_full_correlations = 51u64
            .checked_mul(responses_u64)
            .and_then(|value| value.checked_add(55))
            .ok_or_else(|| "X4d seam correlations overflow".to_owned())?;
        let total_full_correlations_per_role = X4D_FULL_CORRELATIONS_PER_RESPONSE_V1
            .checked_mul(responses_u64)
            .and_then(|value| value.checked_add(X4D_FULL_CORRELATIONS_PER_SETTLEMENT_V1))
            .ok_or_else(|| "X4d total correlations overflow".to_owned())?;
        if claim_reduction_full_correlations.checked_add(seam_full_correlations)
            != Some(total_full_correlations_per_role)
        {
            return Err("X4d correlation identity diverged".to_owned());
        }
        Ok(Self {
            responses,
            frozen_claims,
            masked_groups,
            active_chain_polynomials: 2 * X4C_GPT2_PHYSICAL_BLOCKS,
            fold_rounds: 27,
            query_draws: X4D_QUERY_COUNT_V1,
            claim_reduction_full_correlations,
            seam_full_correlations,
            total_full_correlations_per_role,
        })
    }
}

#[derive(Debug)]
pub struct X4dFreshAuxiliarySetV1 {
    pub cohorts: Vec<X4cRamModelGlobalCohortV4>,
    pub evaluation_slots: Vec<Vec<Option<Vec<Fp2>>>>,
    pub seed_commitment: Digest,
    pub root_set_digest: Digest,
    pub masks_created: usize,
}

#[derive(Debug)]
pub struct X4dBoundFreshAuxiliarySetV1 {
    settlement_epoch: u64,
    auxiliary: X4dFreshAuxiliarySetV1,
}

#[derive(Debug)]
pub struct X4dGpt2ReducedClaimsV1 {
    pub frames: Vec<ReducedClaimFrame>,
    pub proofs: Vec<BlindSumcheckProof>,
    pub points: Vec<Vec<Fp2>>,
    pub prover_values: Vec<ProverAuthed>,
    pub verifier_keys: Vec<VerifierKey>,
}

#[derive(Debug)]
pub struct X4dGpt2SettlementResultV1 {
    pub static_weight_commitment_digest: Digest,
    pub settlement_model_root: Digest,
    pub auxiliary_seed_commitment: Digest,
    pub auxiliary_root_set_digest: Digest,
    pub manifest_frames: Vec<ManifestFrameV4>,
    pub reduced: X4dGpt2ReducedClaimsV1,
    pub link_proof: AuthenticatedOutputLinkProofV4,
    pub link_metrics: AuthenticatedOutputLinkMetricsV4,
    pub x4c_metrics: X4cResponseMetricsV4,
    pub seal_wall_ns: u64,
    pub open_wall_ns: u64,
    pub verify_wall_ns: u64,
    pub settlement_wall_ns: u64,
    pub envelope: X4dSettlementEnvelopeV1,
    pub encoded_settlement: Vec<u8>,
    pub prover_full_correlations: u64,
    pub verifier_full_correlations: u64,
    pub auxiliary_masks_created: usize,
    pub static_weight_roots_reused: usize,
}

fn settlement_binding_bytes_v1(context: &X4dSettlementContextV1) -> Result<Vec<u8>, String> {
    let nonce_count = u32::try_from(context.range.ordered_response_nonces.len())
        .map_err(|_| "X4d settlement nonce count overflows".to_owned())?;
    let mut binding = Vec::with_capacity(152 + 32 * context.range.ordered_response_nonces.len());
    binding.extend_from_slice(&context.range.connection_id);
    binding.extend_from_slice(&context.range.settlement_epoch.to_le_bytes());
    binding.extend_from_slice(&context.range.first_claim_index.to_le_bytes());
    binding.extend_from_slice(&context.range.claim_count.to_le_bytes());
    binding.extend_from_slice(&context.range.starting_accumulator_digest);
    binding.extend_from_slice(&context.range.sealed_accumulator_digest);
    binding.extend_from_slice(&nonce_count.to_le_bytes());
    for nonce in &context.range.ordered_response_nonces {
        binding.extend_from_slice(nonce);
    }
    Ok(binding)
}

fn settlement_domain_v1(base: u64, epoch: u64) -> Result<u64, String> {
    let domain = epoch
        .checked_mul(X4D_SETTLEMENT_DOMAIN_EPOCH_STRIDE_V1)
        .and_then(|offset| base.checked_add(offset))
        .ok_or_else(|| "X4d settlement domain overflows".to_owned())?;
    if domain & RESERVED_DOMAIN_BITS != 0 {
        return Err("X4d settlement domain uses reserved MAC bits".to_owned());
    }
    Ok(domain)
}

pub fn x4d_static_weight_commitment_digest_v1(
    inventory: &X4cGpt2Inventory,
    weight_cohorts: &[X4cRamModelGlobalCohortV4],
) -> Result<Digest, String> {
    if weight_cohorts.len() != X4D_STATIC_WEIGHT_COHORTS_V1 {
        return Err("X4d static commitment requires exactly three weight cohorts".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key(X4D_STATIC_WEIGHT_COMMITMENT_CONTEXT_V1);
    hasher.update(&inventory.model_config_digest);
    hasher.update(&inventory.weights_digest);
    for (expected, cohort) in
        inventory.cohort_configs.iter().take(X4D_STATIC_WEIGHT_COHORTS_V1).zip(weight_cohorts)
    {
        if cohort.commitment().config != *expected
            || expected.identity.oracle_kind != OracleKindV4::WeightExtension
            || !matches!(
                expected.identity.cohort_id,
                X4C_WEXT_MU26_COHORT_ID | X4C_WEXT_MU22_COHORT_ID | X4C_WEXT_MU20_COHORT_ID
            )
        {
            return Err("X4d static weight cohort identity changed".to_owned());
        }
        hasher.update(&expected.identity.cohort_id.to_le_bytes());
        hasher.update(&cohort.root());
    }
    for block in &inventory.blocks {
        hasher.update(&block.descriptor_digest);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Generate exactly one settlement-fresh auxiliary polynomial per physical
/// GPT-2 block. The seed and coefficients stay local; only the commitment and
/// root-set digests are reportable.
pub fn materialize_fresh_auxiliary_set_v1(
    inventory: &X4cGpt2Inventory,
    context: &X4dSettlementContextV1,
    seed: [u8; 32],
) -> Result<X4dFreshAuxiliarySetV1, String> {
    inventory.validate()?;
    if seed == [0; 32] {
        return Err("X4d auxiliary-mask seed must be sampled fresh".to_owned());
    }
    let binding = settlement_binding_bytes_v1(context)?;
    let mut coefficients = inventory
        .cohort_configs
        .iter()
        .skip(X4D_STATIC_WEIGHT_COHORTS_V1)
        .map(|config| vec![None; config.slot_descriptors.len()])
        .collect::<Vec<_>>();
    let mut masks_created = 0usize;
    for block in &inventory.blocks {
        let auxiliary_index = cohort_index_for_auxiliary(block.ell())?
            .checked_sub(X4D_STATIC_WEIGHT_COHORTS_V1)
            .ok_or_else(|| "X4d auxiliary cohort index underflows".to_owned())?;
        let slot = usize::from(block.auxiliary_slot);
        let mut polynomial = vec![Fp2::ZERO; 1usize << block.ell()];
        let mut xof = UniformFp2Xof::new_with_context(
            X4D_AUX_MASK_XOF_CONTEXT_V1,
            seed,
            &binding,
            block.descriptor_digest,
            OracleKindV4::Auxiliary,
        );
        for value in &mut polynomial {
            *value = xof.fp2();
        }
        multilinear_coefficients_in_place(&mut polynomial)
            .map_err(|error| format!("X4d auxiliary coefficient transform: {error:?}"))?;
        let target = coefficients
            .get_mut(auxiliary_index)
            .and_then(|slots| slots.get_mut(slot))
            .ok_or_else(|| "X4d auxiliary slot is outside its cohort".to_owned())?;
        if target.replace(polynomial).is_some() {
            return Err("X4d auxiliary slot was materialized twice".to_owned());
        }
        masks_created = masks_created
            .checked_add(1)
            .ok_or_else(|| "X4d auxiliary-mask counter overflows".to_owned())?;
    }
    if masks_created != X4C_GPT2_PHYSICAL_BLOCKS {
        return Err("X4d did not materialize exactly 51 auxiliary masks".to_owned());
    }

    let mut evaluation_slots = coefficients.clone();
    for values in evaluation_slots.iter_mut().flat_map(|slots| slots.iter_mut().flatten()) {
        multilinear_evaluations_in_place(values)
            .map_err(|error| format!("X4d auxiliary evaluation transform: {error:?}"))?;
    }
    let cohorts = inventory
        .cohort_configs
        .iter()
        .skip(X4D_STATIC_WEIGHT_COHORTS_V1)
        .cloned()
        .zip(coefficients)
        .map(|(config, coefficients)| {
            X4cRamModelGlobalCohortV4::rebuild_from_coefficients(config, coefficients)
                .map_err(|error| format!("X4d fresh auxiliary cohort rebuild: {error:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if cohorts.len() != X4D_FRESH_AUXILIARY_COHORTS_V1 {
        return Err("X4d fresh auxiliary cohort count changed".to_owned());
    }
    let mut seed_hasher = blake3::Hasher::new_derive_key(X4D_AUX_MASK_SEED_COMMITMENT_CONTEXT_V1);
    seed_hasher.update(&binding);
    seed_hasher.update(&seed);
    let seed_commitment = *seed_hasher.finalize().as_bytes();
    let mut root_hasher = blake3::Hasher::new_derive_key(X4D_AUX_ROOT_SET_CONTEXT_V1);
    root_hasher.update(&binding);
    for cohort in &cohorts {
        root_hasher.update(&cohort.root());
    }
    let root_set_digest = *root_hasher.finalize().as_bytes();
    Ok(X4dFreshAuxiliarySetV1 {
        cohorts,
        evaluation_slots,
        seed_commitment,
        root_set_digest,
        masks_created,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4dSplitThreadPolicyV1 {
    pub response_cpu_ids: Vec<usize>,
    pub settlement_cpu_ids: Vec<usize>,
}

impl X4dSplitThreadPolicyV1 {
    pub fn validate(&self) -> Result<(), String> {
        let response = self.response_cpu_ids.iter().copied().collect::<BTreeSet<_>>();
        let settlement = self.settlement_cpu_ids.iter().copied().collect::<BTreeSet<_>>();
        if response.len() != X4D_RESPONSE_CPU_WORKERS_V1
            || settlement.len() != X4D_SETTLEMENT_CPU_WORKERS_V1
            || !response.is_disjoint(&settlement)
        {
            return Err("X4d split worker policy is missing, duplicated or overlapping".to_owned());
        }
        Ok(())
    }

    /// Local CPU tests use distinct Rayon pools.  Pod code must additionally
    /// pin these worker IDs and record the observed affinity.
    pub fn build_local_pools(&self) -> Result<(rayon::ThreadPool, rayon::ThreadPool), String> {
        self.validate()?;
        let response = rayon::ThreadPoolBuilder::new()
            .num_threads(X4D_RESPONSE_CPU_WORKERS_V1)
            .thread_name(|index| format!("x4d-response-{index}"))
            .build()
            .map_err(|error| format!("build X4d response pool: {error}"))?;
        let settlement = rayon::ThreadPoolBuilder::new()
            .num_threads(X4D_SETTLEMENT_CPU_WORKERS_V1)
            .thread_name(|index| format!("x4d-settlement-{index}"))
            .build()
            .map_err(|error| format!("build X4d settlement pool: {error}"))?;
        Ok((response, settlement))
    }

    /// Build the registered Linux pod pools and pin every worker to its
    /// declared CPU. Record-producing code uses this method; the unpinned
    /// helper remains for portable local tests only.
    #[cfg(target_os = "linux")]
    pub fn build_pinned_pools(&self) -> Result<(rayon::ThreadPool, rayon::ThreadPool), String> {
        self.validate()?;
        fn build(name: &'static str, cpu_ids: Vec<usize>) -> Result<rayon::ThreadPool, String> {
            let worker_count = cpu_ids.len();
            rayon::ThreadPoolBuilder::new()
                .num_threads(worker_count)
                .thread_name(move |index| format!("x4d-{name}-{index}"))
                .start_handler(move |index| {
                    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
                    // SAFETY: `set` is initialized and Rayon bounds `index`
                    // by the captured worker vector.
                    unsafe {
                        libc::CPU_ZERO(&mut set);
                        libc::CPU_SET(cpu_ids[index], &mut set);
                    }
                    let rc = unsafe {
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
                    };
                    assert_eq!(rc, 0, "X4d {name} worker affinity failed closed");
                })
                .build()
                .map_err(|error| format!("build pinned X4d {name} pool: {error}"))
        }
        Ok((
            build("response", self.response_cpu_ids.clone())?,
            build("settlement", self.settlement_cpu_ids.clone())?,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct X4dGpt2ConnectionV1 {
    prover_accumulator: X4dClaimAccumulatorV1,
    verifier_accumulator: X4dClaimAccumulatorV1,
    prover_values: X4dAuthenticatedValueStoreV1<ProverAuthed>,
    verifier_keys: X4dAuthenticatedValueStoreV1<VerifierKey>,
    frozen_responses: BTreeMap<Digest, X4dGpt2FrozenResponseLocalV1>,
    response_order: Vec<Digest>,
    used_auxiliary_root_sets: BTreeSet<Digest>,
    bound_auxiliary_root_set: Option<(u64, Digest)>,
    pub auth_handles_created: u64,
    pub response_nonces_burned: u64,
    pub settlement_static_root_uses: u64,
    pub settlement_challenge_epochs_started: u64,
    pub auxiliary_masks_created: u64,
}

impl X4dGpt2ConnectionV1 {
    pub fn new(
        static_weight_commitment_digest: Digest,
        connection_id: Digest,
    ) -> Result<Self, String> {
        let policy = X4dSettlementPolicyV1::production_gpt2();
        Ok(Self {
            prover_accumulator: X4dClaimAccumulatorV1::new(
                static_weight_commitment_digest,
                connection_id,
                policy,
            )
            .map_err(x4d_error)?,
            verifier_accumulator: X4dClaimAccumulatorV1::new(
                static_weight_commitment_digest,
                connection_id,
                policy,
            )
            .map_err(x4d_error)?,
            prover_values: X4dAuthenticatedValueStoreV1::default(),
            verifier_keys: X4dAuthenticatedValueStoreV1::default(),
            frozen_responses: BTreeMap::new(),
            response_order: Vec::new(),
            used_auxiliary_root_sets: BTreeSet::new(),
            bound_auxiliary_root_set: None,
            auth_handles_created: 0,
            response_nonces_burned: 0,
            settlement_static_root_uses: 0,
            settlement_challenge_epochs_started: 0,
            auxiliary_masks_created: 0,
        })
    }

    pub fn prover_accumulator(&self) -> &X4dClaimAccumulatorV1 {
        &self.prover_accumulator
    }

    pub fn verifier_accumulator(&self) -> &X4dClaimAccumulatorV1 {
        &self.verifier_accumulator
    }

    /// Pre-model-proof hard-cap check.  Refusal consumes neither nonce nor
    /// claim entry.
    pub fn preflight_response(&mut self) -> Result<(), String> {
        let prover =
            self.prover_accumulator.preflight_response_claims(X4D_GPT2_CLAIMS_PER_RESPONSE_V1);
        let verifier =
            self.verifier_accumulator.preflight_response_claims(X4D_GPT2_CLAIMS_PER_RESPONSE_V1);
        match (prover, verifier) {
            (Ok(()), Ok(())) => Ok(()),
            (
                Err(X4dErrorV1::CapacityRefused { pending: a, .. }),
                Err(X4dErrorV1::CapacityRefused { pending: b, .. }),
            ) if a == b => {
                Err(format!("X4d service refused at {a} pending claims until settlement completes"))
            }
            _ => Err("X4d prover/verifier cap decision diverged".to_owned()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn freeze_model_response(
        &mut self,
        inventory: &X4cGpt2Inventory,
        response_nonce: Digest,
        model_transcript_digest: Digest,
        model_transcript_bytes: u64,
        model_mac_closure_bytes: u64,
        prover_output: &ModelOut,
        verifier_output: &ModelOutV,
    ) -> Result<X4dDeliveredResponseV1, String> {
        if model_transcript_bytes != X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1
            || model_mac_closure_bytes != X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1
            || model_transcript_bytes.checked_add(model_mac_closure_bytes)
                != Some(X4D_GPT2_RESPONSE_BYTES_V1)
            || response_nonce == [0; 32]
            || model_transcript_digest == [0; 32]
        {
            return Err("X4d response projection or identity changed".to_owned());
        }
        self.preflight_response()?;
        inventory.validate_parent_domains(prover_output)?;
        if verifier_output.weight_keys.len() != prover_output.weight_claims.len()
            || verifier_output.embed_keys.len() != prover_output.embed_claims.len()
        {
            return Err("X4d prover/verifier parent-claim cardinality differs".to_owned());
        }
        let claim_frames = inventory.claim_frames(prover_output)?;
        let mut prover_parent_values = Vec::with_capacity(claim_frames.len());
        let mut verifier_parent_keys = Vec::with_capacity(claim_frames.len());
        for (block_index, block) in inventory.blocks.iter().enumerate() {
            let parent = block.claims(prover_output)?;
            let verifier_parent = block.verifier_claims(verifier_output)?;
            for (phase, ((claim, (point, key)), frame)) in parent
                .iter()
                .zip(verifier_parent.iter())
                .zip(&claim_frames[2 * block_index..2 * block_index + 2])
                .enumerate()
            {
                if claim.point != *point
                    || claim.point != frame.point
                    || claim.auth_domain != frame.auth_domain
                    || frame.phase_ordinal != phase as u16
                {
                    return Err("X4d frozen parent claim differs across roles".to_owned());
                }
                prover_parent_values.push(claim.value);
                verifier_parent_keys.push(*key);
            }
        }
        if prover_parent_values.len() != X4D_GPT2_CLAIMS_PER_RESPONSE_V1
            || verifier_parent_keys.len() != X4D_GPT2_CLAIMS_PER_RESPONSE_V1
        {
            return Err("X4d frozen GPT-2 claim count changed".to_owned());
        }

        // Atomic role-pair append: all mutations land only after receipts,
        // handles and local share tables have been checked on clones.
        let started = Instant::now();
        let mut prover_accumulator = self.prover_accumulator.clone();
        let mut verifier_accumulator = self.verifier_accumulator.clone();
        for accumulator in [&mut prover_accumulator, &mut verifier_accumulator] {
            accumulator.authorize_response(response_nonce).map_err(x4d_error)?;
            accumulator.mark_model_authenticated(response_nonce).map_err(x4d_error)?;
        }
        let prover_receipt = prover_accumulator
            .freeze_response(response_nonce, model_transcript_digest, claim_frames.clone())
            .map_err(x4d_error)?;
        let verifier_receipt = verifier_accumulator
            .freeze_response(response_nonce, model_transcript_digest, claim_frames.clone())
            .map_err(x4d_error)?;
        X4dClaimAccumulatorV1::compare_freeze_receipts(&prover_receipt, &verifier_receipt)
            .map_err(x4d_error)?;
        let appended = prover_accumulator
            .entries()
            .iter()
            .rev()
            .take(X4D_GPT2_CLAIMS_PER_RESPONSE_V1)
            .rev()
            .collect::<Vec<_>>();
        let mut prover_values = self.prover_values.clone();
        let mut verifier_keys = self.verifier_keys.clone();
        for ((identity, value), key) in
            appended.iter().zip(&prover_parent_values).zip(&verifier_parent_keys)
        {
            prover_values.freeze(identity.auth_handle_digest, *value).map_err(x4d_error)?;
            verifier_keys.freeze(identity.auth_handle_digest, *key).map_err(x4d_error)?;
        }
        let wall_ns = u64::try_from(started.elapsed().as_nanos())
            .map_err(|_| "X4d claim-freeze wall overflows".to_owned())?
            .max(1);
        self.prover_accumulator = prover_accumulator;
        self.verifier_accumulator = verifier_accumulator;
        self.prover_values = prover_values;
        self.verifier_keys = verifier_keys;
        self.auth_handles_created = self
            .auth_handles_created
            .checked_add(X4D_GPT2_CLAIMS_PER_RESPONSE_V1 as u64)
            .ok_or_else(|| "X4d handle counter overflows".to_owned())?;
        self.response_nonces_burned = self
            .response_nonces_burned
            .checked_add(1)
            .ok_or_else(|| "X4d response-nonce counter overflows".to_owned())?;
        let local = X4dGpt2FrozenResponseLocalV1 {
            response_nonce,
            model_transcript_digest,
            claim_frames,
            prover_parent_values,
            verifier_parent_keys,
            freeze_receipt: prover_receipt.clone(),
        };
        if self.frozen_responses.insert(response_nonce, local).is_some() {
            return Err("X4d response nonce was already frozen".to_owned());
        }
        self.response_order.push(response_nonce);
        Ok(X4dDeliveredResponseV1 {
            response_nonce,
            product_state: X4dResponseStateV1::WeightPending,
            model_transcript_bytes,
            model_mac_closure_bytes,
            pcs_bytes: 0,
            response_bytes: X4D_GPT2_RESPONSE_BYTES_V1,
            claim_freeze_wall_ns: wall_ns,
            freeze_receipt: prover_receipt,
        })
    }

    pub fn seal_settlement(&mut self) -> Result<X4dGpt2SettlementBatchV1, String> {
        let mut prover_accumulator = self.prover_accumulator.clone();
        let mut verifier_accumulator = self.verifier_accumulator.clone();
        let prover_range = prover_accumulator.seal_pending_range().map_err(x4d_error)?;
        let verifier_range = verifier_accumulator.seal_pending_range().map_err(x4d_error)?;
        if prover_range != verifier_range {
            self.abort();
            return Err("X4d settlement range differs across roles".to_owned());
        }
        let frozen_claims =
            prover_accumulator.expected_range_claims(&prover_range).map_err(x4d_error)?.to_vec();
        verifier_accumulator
            .verify_exact_union(&verifier_range, &frozen_claims)
            .map_err(x4d_error)?;
        let responses = prover_range
            .ordered_response_nonces
            .iter()
            .map(|nonce| {
                self.frozen_responses
                    .get(nonce)
                    .cloned()
                    .ok_or_else(|| "X4d sealed response is missing local shares".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prover_parent_values = frozen_claims
            .iter()
            .map(|claim| {
                self.prover_values
                    .get(&claim.auth_handle_digest)
                    .copied()
                    .ok_or_else(|| "X4d sealed claim is missing its frozen prover share".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let verifier_parent_keys = frozen_claims
            .iter()
            .map(|claim| {
                self.verifier_keys.get(&claim.auth_handle_digest).copied().ok_or_else(|| {
                    "X4d sealed claim is missing its frozen verifier share".to_owned()
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let counters = X4dGpt2SettlementCountersV1::for_responses(responses.len())?;
        if counters.frozen_claims != frozen_claims.len()
            || prover_parent_values.len() != frozen_claims.len()
            || verifier_parent_keys.len() != frozen_claims.len()
        {
            self.abort();
            return Err("X4d settlement claims do not match fixed GPT-2 geometry".to_owned());
        }
        self.prover_accumulator = prover_accumulator;
        self.verifier_accumulator = verifier_accumulator;
        Ok(X4dGpt2SettlementBatchV1 {
            static_weight_commitment_digest: self
                .prover_accumulator
                .static_weight_commitment_digest(),
            context: X4dSettlementContextV1 { range: prover_range },
            frozen_claims,
            responses,
            prover_parent_values,
            verifier_parent_keys,
            counters,
        })
    }

    /// Bind the settlement-fresh auxiliary roots before releasing any
    /// settlement challenge. A second set or a cross-epoch replay burns the
    /// connection.
    pub fn bind_fresh_auxiliary_set(
        &mut self,
        batch: &X4dGpt2SettlementBatchV1,
        auxiliary: X4dFreshAuxiliarySetV1,
    ) -> Result<X4dBoundFreshAuxiliarySetV1, String> {
        if self.state() != X4dConnectionStateV1::Open
            || self.prover_accumulator.inflight_range() != Some(&batch.context.range)
            || self.verifier_accumulator.inflight_range() != Some(&batch.context.range)
            || auxiliary.root_set_digest == [0; 32]
            || auxiliary.seed_commitment == [0; 32]
            || auxiliary.masks_created != X4C_GPT2_PHYSICAL_BLOCKS
            || self.bound_auxiliary_root_set.is_some()
            || self.used_auxiliary_root_sets.contains(&auxiliary.root_set_digest)
        {
            self.abort();
            return Err("X4d auxiliary mask/root set is missing, replayed or misbound".to_owned());
        }
        let Some(epochs) = self.settlement_challenge_epochs_started.checked_add(1) else {
            self.abort();
            return Err("X4d settlement epoch counter overflows".to_owned());
        };
        let Ok(mask_count) = u64::try_from(auxiliary.masks_created) else {
            self.abort();
            return Err("X4d auxiliary mask counter overflows".to_owned());
        };
        let Some(masks) = self.auxiliary_masks_created.checked_add(mask_count) else {
            self.abort();
            return Err("X4d auxiliary mask counter overflows".to_owned());
        };
        let Some(static_uses) = self.settlement_static_root_uses.checked_add(1) else {
            self.abort();
            return Err("X4d static-root use counter overflows".to_owned());
        };
        self.used_auxiliary_root_sets.insert(auxiliary.root_set_digest);
        self.bound_auxiliary_root_set =
            Some((batch.context.range.settlement_epoch, auxiliary.root_set_digest));
        self.settlement_challenge_epochs_started = epochs;
        self.auxiliary_masks_created = masks;
        self.settlement_static_root_uses = static_uses;
        Ok(X4dBoundFreshAuxiliarySetV1 {
            settlement_epoch: batch.context.range.settlement_epoch,
            auxiliary,
        })
    }

    pub fn settlement_succeeded(&mut self, batch: &X4dGpt2SettlementBatchV1) -> Result<(), String> {
        if self.bound_auxiliary_root_set.map(|(epoch, _)| epoch)
            != Some(batch.context.range.settlement_epoch)
        {
            self.abort();
            return Err("X4d settlement succeeded without its fresh auxiliary set".to_owned());
        }
        let mut prover_accumulator = self.prover_accumulator.clone();
        let mut verifier_accumulator = self.verifier_accumulator.clone();
        prover_accumulator.settlement_succeeded(&batch.context.range).map_err(x4d_error)?;
        verifier_accumulator.settlement_succeeded(&batch.context.range).map_err(x4d_error)?;
        self.prover_accumulator = prover_accumulator;
        self.verifier_accumulator = verifier_accumulator;
        self.bound_auxiliary_root_set = None;
        Ok(())
    }

    pub fn settlement_failed(&mut self) -> Result<(), String> {
        let mut prover_accumulator = self.prover_accumulator.clone();
        let mut verifier_accumulator = self.verifier_accumulator.clone();
        let prover = prover_accumulator.settlement_failed();
        let verifier = verifier_accumulator.settlement_failed();
        if prover.is_ok() && verifier.is_ok() {
            self.prover_accumulator = prover_accumulator;
            self.verifier_accumulator = verifier_accumulator;
            self.bound_auxiliary_root_set = None;
            Ok(())
        } else {
            self.abort();
            Err("X4d settlement failure transition diverged".to_owned())
        }
    }

    pub fn abort(&mut self) {
        self.prover_accumulator.abort();
        self.verifier_accumulator.abort();
        self.bound_auxiliary_root_set = None;
    }

    pub fn close_after_all_verified(&mut self) -> Result<(), String> {
        let mut prover_accumulator = self.prover_accumulator.clone();
        let mut verifier_accumulator = self.verifier_accumulator.clone();
        let prover = prover_accumulator.close_after_all_verified();
        let verifier = verifier_accumulator.close_after_all_verified();
        if prover.is_ok() && verifier.is_ok() {
            self.prover_accumulator = prover_accumulator;
            self.verifier_accumulator = verifier_accumulator;
            Ok(())
        } else {
            self.abort();
            Err("X4d graceful-close transition diverged or claims remain pending".to_owned())
        }
    }

    pub fn state(&self) -> X4dConnectionStateV1 {
        debug_assert_eq!(self.prover_accumulator.state(), self.verifier_accumulator.state());
        self.prover_accumulator.state()
    }

    pub fn response_state(&self, nonce: Digest) -> Option<X4dResponseStateV1> {
        let prover = self.prover_accumulator.response_state(nonce);
        debug_assert_eq!(prover, self.verifier_accumulator.response_state(nonce));
        prover
    }
}

fn x4d_error(error: X4dErrorV1) -> String {
    format!("X4d protocol state: {error:?}")
}

pub type X4dParentClaimPairRefV1<'a> = (&'a WeightClaimP, &'a (Vec<volta_field::Fp2>, VerifierKey));

/// Canonical raw-claim order used by the settlement reducer.
pub fn x4d_response_parent_claims_v1<'a>(
    inventory: &X4cGpt2Inventory,
    prover_output: &'a ModelOut,
    verifier_output: &'a ModelOutV,
) -> Result<Vec<X4dParentClaimPairRefV1<'a>>, String> {
    let mut claims = Vec::with_capacity(X4D_GPT2_CLAIMS_PER_RESPONSE_V1);
    for block in &inventory.blocks {
        let prover = block.claims(prover_output)?;
        let verifier = block.verifier_claims(verifier_output)?;
        claims.extend(prover.into_iter().zip(verifier));
    }
    Ok(claims)
}

fn combined_cohort_v1<'a>(
    index: usize,
    weight_cohorts: &'a [X4cRamModelGlobalCohortV4],
    auxiliary: &'a X4dFreshAuxiliarySetV1,
) -> Result<&'a X4cRamModelGlobalCohortV4, String> {
    if index < X4D_STATIC_WEIGHT_COHORTS_V1 {
        weight_cohorts.get(index).ok_or_else(|| "X4d static weight cohort is missing".to_owned())
    } else {
        auxiliary
            .cohorts
            .get(index - X4D_STATIC_WEIGHT_COHORTS_V1)
            .ok_or_else(|| "X4d settlement auxiliary cohort is missing".to_owned())
    }
}

fn combined_evaluations_v1<'a>(
    index: usize,
    weight_evaluations: &'a X4cGpt2EvaluationTables,
    auxiliary: &'a X4dFreshAuxiliarySetV1,
) -> Result<&'a [Option<Vec<Fp2>>], String> {
    if index < X4D_STATIC_WEIGHT_COHORTS_V1 {
        weight_evaluations
            .slots
            .get(index)
            .map(Vec::as_slice)
            .ok_or_else(|| "X4d static weight evaluations are missing".to_owned())
    } else {
        auxiliary
            .evaluation_slots
            .get(index - X4D_STATIC_WEIGHT_COHORTS_V1)
            .map(Vec::as_slice)
            .ok_or_else(|| "X4d settlement auxiliary evaluations are missing".to_owned())
    }
}

#[allow(clippy::too_many_arguments)]
fn reduce_frozen_weight_claims_v1(
    model: &Gpt2Model,
    inventory: &X4cGpt2Inventory,
    batch: &X4dGpt2SettlementBatchV1,
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
) -> Result<X4dGpt2ReducedClaimsV1, String> {
    let expected_claims = batch.counters.frozen_claims;
    if batch.frozen_claims.len() != expected_claims
        || batch.prover_parent_values.len() != expected_claims
        || batch.verifier_parent_keys.len() != expected_claims
        || batch.responses.len() != batch.counters.responses
    {
        return Err("X4d frozen settlement share geometry changed".to_owned());
    }
    let frames =
        batch.frozen_claims.iter().map(|claim| claim.claim_frame.clone()).collect::<Vec<_>>();
    let padded_sources = inventory
        .blocks
        .iter()
        .map(|block| padded_source_i16(model, block))
        .collect::<Result<Vec<_>, _>>()?;
    let claim_domain_base = settlement_domain_v1(
        X4D_CLAIM_REDUCTION_DOMAIN_BASE_V1,
        batch.context.range.settlement_epoch,
    )?;
    let response_domain_stride = X4C_GPT2_CLAIM_REDUCTION_FULL_CORRELATIONS / 2;
    let fulls_before = stream.counters.full_corrs;
    let verifier_fulls_before = verifier.counters.full_corrs;
    let prover_round_bytes_before = prover_tx.bytes_for("blind_round_corrections");
    let verifier_round_bytes_before = verifier_tx.bytes_for("blind_round_corrections");
    let mut proofs = Vec::with_capacity(batch.counters.masked_groups);
    let mut points = Vec::with_capacity(batch.counters.masked_groups);
    let mut prover_values = Vec::with_capacity(batch.counters.masked_groups);
    let mut verifier_keys = Vec::with_capacity(batch.counters.masked_groups);
    for response_index in 0..batch.counters.responses {
        for (block_index, block) in inventory.blocks.iter().enumerate() {
            let group_index = response_index
                .checked_mul(X4C_GPT2_PHYSICAL_BLOCKS)
                .and_then(|base| base.checked_add(block_index))
                .ok_or_else(|| "X4d reduced-group index overflows".to_owned())?;
            let claim_index = response_index
                .checked_mul(X4D_GPT2_CLAIMS_PER_RESPONSE_V1)
                .and_then(|base| base.checked_add(2 * block_index))
                .ok_or_else(|| "X4d claim index overflows".to_owned())?;
            let block_frames = frames
                .get(claim_index..claim_index + 2)
                .ok_or_else(|| "X4d response-local claim pair is missing".to_owned())?;
            for (phase, frame) in block_frames.iter().enumerate() {
                if frame.descriptor_digest != block.descriptor_digest
                    || usize::from(frame.phase_ordinal) != phase
                {
                    return Err("X4d response-local claim order changed".to_owned());
                }
                let bytes = FrameV4::ReducedClaim(frame.clone())
                    .encode()
                    .map_err(|error| format!("X4d reduced claim encode: {error:?}"))?;
                let byte_len = u64::try_from(bytes.len())
                    .map_err(|_| "X4d reduced-claim frame length overflows".to_owned())?;
                prover_tx.append("x4_v4_reduced_claim", byte_len);
                verifier_tx.append("x4_v4_reduced_claim", byte_len);
            }
            let prover_claims = block_frames
                .iter()
                .zip(&batch.prover_parent_values[claim_index..claim_index + 2])
                .map(|(frame, value)| {
                    (BlockClaim { offset: 0, point: frame.point.clone() }, *value)
                })
                .collect::<Vec<_>>();
            let verifier_claims = block_frames
                .iter()
                .zip(&batch.verifier_parent_keys[claim_index..claim_index + 2])
                .map(|(frame, key)| (BlockClaim { offset: 0, point: frame.point.clone() }, *key))
                .collect::<Vec<_>>();
            let block_offset = block
                .claim_reduction_domain_base
                .checked_sub(X4C_CLAIM_REDUCTION_DOMAIN_BASE)
                .ok_or_else(|| "X4d claim-reduction domain offset underflows".to_owned())?;
            let response_offset = u64::try_from(response_index)
                .map_err(|_| "X4d response index overflows".to_owned())?
                .checked_mul(response_domain_stride)
                .ok_or_else(|| "X4d response domain stride overflows".to_owned())?;
            let domain = claim_domain_base
                .checked_add(response_offset)
                .and_then(|value| value.checked_add(block_offset))
                .ok_or_else(|| "X4d claim-reduction domain overflows".to_owned())?;
            let (proof, point, value, _) = batch_reduce_prover(
                &padded_sources[block_index],
                block.mu(),
                &prover_claims,
                stream,
                domain,
                prover_tx,
            );
            let (verifier_point, key) = batch_reduce_verifier(
                block.mu(),
                &verifier_claims,
                &proof,
                verifier,
                domain,
                verifier_tx,
            )
            .ok_or_else(|| {
                format!("X4d verifier rejected response-local reduced group {group_index}")
            })?;
            mirror_claim_reduction_round_accounting(verifier_tx, block.mu());
            if point != verifier_point {
                return Err("X4d claim-reduction point differs across roles".to_owned());
            }
            proofs.push(proof);
            points.push(point);
            prover_values.push(value);
            verifier_keys.push(key);
        }
    }
    let expected_fulls = batch.counters.claim_reduction_full_correlations;
    let expected_round_bytes = expected_fulls
        .checked_div(2)
        .and_then(|rounds| rounds.checked_mul(32))
        .ok_or_else(|| "X4d claim-reduction byte count overflows".to_owned())?;
    if stream.counters.full_corrs.checked_sub(fulls_before) != Some(expected_fulls)
        || verifier.counters.full_corrs.checked_sub(verifier_fulls_before) != Some(expected_fulls)
        || prover_tx.bytes_for("blind_round_corrections").checked_sub(prover_round_bytes_before)
            != Some(expected_round_bytes)
        || verifier_tx.bytes_for("blind_round_corrections").checked_sub(verifier_round_bytes_before)
            != Some(expected_round_bytes)
        || prover_tx.ledger() != verifier_tx.ledger()
        || proofs.len() != batch.counters.masked_groups
    {
        return Err("X4d batched claim-reduction accounting diverged".to_owned());
    }
    Ok(X4dGpt2ReducedClaimsV1 { frames, proofs, points, prover_values, verifier_keys })
}

/// Execute one complete X4d settlement. Static weight cohorts/evaluations are
/// borrowed and reused; the auxiliary set is consumed exactly once.
#[allow(clippy::too_many_arguments)]
pub fn execute_real_weight_x4d_settlement_v1<R: X4cArenaRuntimeV4>(
    model: &Gpt2Model,
    inventory: &X4cGpt2Inventory,
    weight_cohorts: &[X4cRamModelGlobalCohortV4],
    weight_evaluations: &X4cGpt2EvaluationTables,
    batch: &X4dGpt2SettlementBatchV1,
    freshness: &X4dSettlementFreshnessJournalAudit,
    query_seed: X4dSettlementQuerySeedV1,
    bound_auxiliary: X4dBoundFreshAuxiliarySetV1,
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
    runtime: &mut R,
    seal_config: X4cSealConfigV4,
) -> Result<X4dGpt2SettlementResultV1, String> {
    let settlement_started = Instant::now();
    let epoch = batch.context.range.settlement_epoch;
    if bound_auxiliary.settlement_epoch != epoch {
        return Err("X4d bound auxiliary set names a different settlement epoch".to_owned());
    }
    let fresh_auxiliary = bound_auxiliary.auxiliary;
    if epoch == 0
        || freshness.settlement_epoch != epoch
        || freshness.static_weight_commitment_digest_bytes != batch.static_weight_commitment_digest
        || freshness.sealed_accumulator_digest_bytes
            != batch.context.range.sealed_accumulator_digest
        || freshness.auxiliary_seed_commitment_bytes != fresh_auxiliary.seed_commitment
        || freshness.auxiliary_root_set_digest_bytes != fresh_auxiliary.root_set_digest
        || freshness.query_seed_digest_bytes != query_seed.commitment()
        || freshness.freshness_record_digest_bytes == [0; 32]
        || usize::try_from(freshness.mask_count).ok() != Some(fresh_auxiliary.masks_created)
        || freshness.expected_full_correlations_per_role
            != batch.counters.total_full_correlations_per_role
        || weight_cohorts.len() != X4D_STATIC_WEIGHT_COHORTS_V1
        || weight_evaluations.slots.len() < X4D_STATIC_WEIGHT_COHORTS_V1
        || fresh_auxiliary.cohorts.len() != X4D_FRESH_AUXILIARY_COHORTS_V1
        || fresh_auxiliary.evaluation_slots.len() != X4D_FRESH_AUXILIARY_COHORTS_V1
        || fresh_auxiliary.masks_created != X4C_GPT2_PHYSICAL_BLOCKS
    {
        return Err("X4d settlement prerequisite is missing".to_owned());
    }
    inventory.validate()?;
    let static_weight_commitment_digest =
        x4d_static_weight_commitment_digest_v1(inventory, weight_cohorts)?;
    if static_weight_commitment_digest != batch.static_weight_commitment_digest {
        return Err("X4d frozen claims name a different static weight commitment".to_owned());
    }
    for index in 0..inventory.cohort_configs.len() {
        let cohort = combined_cohort_v1(index, weight_cohorts, &fresh_auxiliary)?;
        let evaluations = combined_evaluations_v1(index, weight_evaluations, &fresh_auxiliary)?;
        if cohort.commitment().config != inventory.cohort_configs[index]
            || evaluations.len() != inventory.cohort_configs[index].slot_descriptors.len()
        {
            return Err("X4d settlement cohort/evaluation identity mismatch".to_owned());
        }
    }

    let descriptor_digests =
        inventory.blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let leaves = inventory
        .blocks
        .iter()
        .map(|block| {
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            Ok(ManifestLeafFrame {
                descriptor_digest: block.descriptor_digest,
                ordered_roots: vec![
                    combined_cohort_v1(weight_index, weight_cohorts, &fresh_auxiliary)?.root(),
                    combined_cohort_v1(auxiliary_index, weight_cohorts, &fresh_auxiliary)?.root(),
                ],
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let manifest = ManifestTreeV4::build(
        manifest_id_digest_v4(inventory.model_config_digest, inventory.weights_digest, epoch),
        leaves,
    )
    .map_err(|error| format!("X4d settlement manifest: {error:?}"))?;
    let settlement_model_root = manifest.root();
    let manifest_frames = manifest
        .open(&descriptor_digests)
        .map_err(|error| format!("X4d settlement manifest opening: {error:?}"))?;

    let prover_fulls_before = stream.counters.full_corrs;
    let verifier_fulls_before = verifier.counters.full_corrs;
    let reduced = reduce_frozen_weight_claims_v1(
        model,
        inventory,
        batch,
        stream,
        verifier,
        prover_tx,
        verifier_tx,
    )?;
    let mut weight_points = Vec::with_capacity(batch.counters.masked_groups);
    let mut auxiliary_points = Vec::with_capacity(batch.counters.masked_groups);
    let mut auxiliary_values = Vec::with_capacity(batch.counters.masked_groups);
    let mut public_h = Vec::with_capacity(batch.counters.masked_groups);
    for response_index in 0..batch.counters.responses {
        for (block_index, block) in inventory.blocks.iter().enumerate() {
            let group_index = response_index * X4C_GPT2_PHYSICAL_BLOCKS + block_index;
            let mut weight_point = reduced.points[group_index].clone();
            weight_point.push(Fp2::ZERO);
            let auxiliary_point = crate::x4c_gpt2::canonical_auxiliary_point(
                &reduced.points[group_index],
                block.ell(),
            )?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            let table =
                combined_evaluations_v1(auxiliary_index, weight_evaluations, &fresh_auxiliary)?
                    .get(usize::from(block.auxiliary_slot))
                    .and_then(Option::as_ref)
                    .ok_or_else(|| "X4d auxiliary evaluation table is missing".to_owned())?;
            let auxiliary_value = evaluate_multilinear_table(table, &auxiliary_point)
                .map_err(|error| format!("X4d auxiliary evaluation: {error:?}"))?;
            public_h.push(reduced.prover_values[group_index].x + auxiliary_value);
            weight_points.push(weight_point);
            auxiliary_points.push(auxiliary_point);
            auxiliary_values.push(auxiliary_value);
        }
    }

    let m9_domain_base = settlement_domain_v1(X4D_M9_DOMAIN_BASE_V1, epoch)?;
    let mut pending_prover = Vec::with_capacity(batch.counters.masked_groups);
    let mut pending_verifier = Vec::with_capacity(batch.counters.masked_groups);
    let mut m9_frames = Vec::with_capacity(batch.counters.masked_groups);
    for (group_index, auxiliary_value) in auxiliary_values.iter().copied().enumerate() {
        let block = &inventory.blocks[group_index % X4C_GPT2_PHYSICAL_BLOCKS];
        let domain = m9_domain_base
            .checked_add(
                u64::try_from(group_index)
                    .map_err(|_| "X4d M9 group index overflows".to_owned())?,
            )
            .ok_or_else(|| "X4d M9 domain overflows".to_owned())?;
        let (pending, frame) = authenticate_pending_aux_prover_v4(
            block.descriptor_digest,
            auxiliary_value,
            stream,
            domain,
            prover_tx,
        )
        .map_err(|error| format!("X4d M9 prover: {error:?}"))?;
        let verifier_pending =
            authenticate_pending_aux_verifier_v4(&frame, verifier, domain, verifier_tx)
                .map_err(|error| format!("X4d M9 verifier: {error:?}"))?;
        pending_prover.push(pending);
        pending_verifier.push(verifier_pending);
        m9_frames.push(frame);
    }
    let prover_blocks = pending_prover
        .into_iter()
        .enumerate()
        .map(|(group_index, pending_aux)| {
            let block = &inventory.blocks[group_index % X4C_GPT2_PHYSICAL_BLOCKS];
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            let weight_table =
                combined_evaluations_v1(weight_index, weight_evaluations, &fresh_auxiliary)?
                    .get(usize::from(block.weight_slot))
                    .and_then(Option::as_ref)
                    .ok_or_else(|| "X4d weight evaluation table is missing".to_owned())?;
            let auxiliary_table =
                combined_evaluations_v1(auxiliary_index, weight_evaluations, &fresh_auxiliary)?
                    .get(usize::from(block.auxiliary_slot))
                    .and_then(Option::as_ref)
                    .ok_or_else(|| "X4d auxiliary evaluation table is missing".to_owned())?;
            Ok(AuthenticatedOutputBlockProverV4 {
                descriptor_digest: block.descriptor_digest,
                public_h: public_h[group_index],
                pending_aux,
                weight_extension: LinkPolynomialProverV4 {
                    cohort: combined_cohort_v1(weight_index, weight_cohorts, &fresh_auxiliary)?,
                    slot: block.weight_slot,
                    evaluations: weight_table,
                    target_point: &weight_points[group_index],
                },
                auxiliary: LinkPolynomialProverV4 {
                    cohort: combined_cohort_v1(auxiliary_index, weight_cohorts, &fresh_auxiliary)?,
                    slot: block.auxiliary_slot,
                    evaluations: auxiliary_table,
                    target_point: &auxiliary_points[group_index],
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let verifier_blocks = pending_verifier
        .into_iter()
        .enumerate()
        .map(|(group_index, pending_aux)| {
            let block = &inventory.blocks[group_index % X4C_GPT2_PHYSICAL_BLOCKS];
            let weight_index = cohort_index_for_weight(block.descriptor.cohort_id)?;
            let auxiliary_index = cohort_index_for_auxiliary(block.ell())?;
            Ok(AuthenticatedOutputBlockVerifierV4 {
                descriptor_digest: block.descriptor_digest,
                public_h: public_h[group_index],
                pending_aux,
                weight_extension: LinkPolynomialVerifierV4 {
                    commitment: combined_cohort_v1(weight_index, weight_cohorts, &fresh_auxiliary)?
                        .commitment(),
                    slot: block.weight_slot,
                    target_point: &weight_points[group_index],
                },
                auxiliary: LinkPolynomialVerifierV4 {
                    commitment: combined_cohort_v1(
                        auxiliary_index,
                        weight_cohorts,
                        &fresh_auxiliary,
                    )?
                    .commitment(),
                    slot: block.auxiliary_slot,
                    target_point: &auxiliary_points[group_index],
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let link_domain_base = settlement_domain_v1(X4D_LINK_DOMAIN_BASE_V1, epoch)?;
    let link_domains = (0..54u64)
        .map(|offset| {
            link_domain_base
                .checked_add(offset)
                .ok_or_else(|| "X4d link domain overflows".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prefix = AuthenticatedOutputLinkPrefixV4 {
        epoch,
        claim_frames: &reduced.frames,
        descriptor_digests: &descriptor_digests,
        ordered_h_symbols: &public_h,
        m9_frames: &m9_frames,
        round_correlation_domain_ids: &link_domains,
    };
    let prover_permit = X4OpeningRegistryV4::default()
        .authorize_after_persistent_freshness(
            settlement_model_root,
            epoch,
            freshness.freshness_record_digest_bytes,
        )
        .map_err(|error| format!("X4d prover opening permit: {error:?}"))?;
    let (mut link_proof, bound_prover, link_metrics, x4c_metrics, phase_walls, selected_draws) =
        prove_authenticated_output_link_x4d_v4(
            prover_permit,
            settlement_model_root,
            prover_blocks,
            prefix,
            &batch.context,
            stream,
            prover_tx,
            query_seed,
            runtime,
            seal_config,
        )
        .map_err(|error| format!("X4d link prover: {error:?}"))?;
    let verifier_permit = X4OpeningRegistryV4::default()
        .authorize_after_persistent_freshness(
            settlement_model_root,
            epoch,
            freshness.freshness_record_digest_bytes,
        )
        .map_err(|error| format!("X4d verifier opening permit: {error:?}"))?;
    let verify_started = Instant::now();
    let bound_verifier = verify_authenticated_output_link_x4d_v4(
        verifier_permit,
        settlement_model_root,
        verifier_blocks,
        prefix,
        &batch.context,
        &link_proof,
        &selected_draws,
        verifier,
        verifier_tx,
    )
    .map_err(|error| format!("X4d link verifier: {error:?}"))?;
    let zero_domain = settlement_domain_v1(X4D_ZERO_DOMAIN_BASE_V1, epoch)?;
    let zero_batch = prove_bound_response_zero_batch_v4(
        &reduced.prover_values,
        &bound_prover,
        &public_h,
        stream,
        zero_domain,
        prover_tx,
    )
    .map_err(|error| format!("X4d settlement ZeroBatch prover: {error:?}"))?;
    verify_bound_response_zero_batch_v4(
        &reduced.verifier_keys,
        &bound_verifier,
        &public_h,
        &zero_batch,
        verifier,
        zero_domain,
        verifier_tx,
    )
    .map_err(|error| format!("X4d settlement ZeroBatch verifier: {error:?}"))?;
    let verify_wall_ns = u64::try_from(verify_started.elapsed().as_nanos())
        .map(|value| value.max(1))
        .map_err(|_| "X4d verifier wall overflows".to_owned())?;

    let initial_groups = inventory
        .cohort_configs
        .iter()
        .enumerate()
        .map(|(index, config)| {
            let cohort = combined_cohort_v1(index, weight_cohorts, &fresh_auxiliary)?;
            Ok(InitialOpeningScheduleV4 {
                cohort_id: config.identity.cohort_id,
                domain_log2: config.outer_depth(),
                slot_count: u16::try_from(config.slot_descriptors.len())
                    .map_err(|_| "X4d opening slot count overflows".to_owned())?,
                touched_slots: config
                    .slot_descriptors
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, descriptor)| {
                        descriptor.and_then(|_| u16::try_from(slot).ok())
                    })
                    .collect(),
                root_digest: cohort.root(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let schedule = PackedOpeningScheduleV4 {
        profile_digest: profile_digest_v4(),
        model_root: settlement_model_root,
        epoch,
        initial_groups,
        fold_frames: link_proof.global_folding.fold_frames.clone(),
        draw_width: 30,
        query_draws: selected_draws,
    };
    schedule.validate().map_err(|error| format!("X4d opening schedule: {error:?}"))?;
    link_proof.global_folding.packed_opening.opening_schedule_digest =
        opening_schedule_digest_x4d_v1(&batch.context, &schedule)
            .map_err(|error| format!("X4d opening schedule digest: {error:?}"))?;
    let mut envelope = X4dSettlementEnvelopeV1 {
        profile_digest: volta_pcs::x4::x4d_profile_digest_v1(),
        model_root: settlement_model_root,
        settlement_epoch: epoch,
        descriptor_digests: descriptor_digests.clone(),
        manifest_frames: manifest_frames.clone(),
        claim_frames: reduced.frames.clone(),
        ordered_h_symbols: public_h,
        m9_frames,
        authenticated_output_link_frame: link_proof.frame.clone(),
        fold_frames: link_proof.global_folding.fold_frames.clone(),
        packed_opening_frame: link_proof.global_folding.packed_opening.clone(),
        zero_batch_frame: zero_batch,
        fixed_size_padding: Vec::new(),
    };
    envelope
        .pad_gpt2_settlement(batch.counters.responses)
        .map_err(|error| format!("X4d settlement padding: {error:?}"))?;
    envelope
        .validate(&batch.context, &batch.frozen_claims, &manifest_frames, &link_domains, &schedule)
        .map_err(|error| format!("X4d settlement envelope: {error:?}"))?;
    let encoded_settlement =
        envelope.encode().map_err(|error| format!("X4d settlement encode: {error:?}"))?;
    if X4dSettlementEnvelopeV1::decode(&encoded_settlement)
        .map_err(|error| format!("X4d settlement decode: {error:?}"))?
        != envelope
        || encoded_settlement.len() as u64
            != volta_pcs::x4::x4d_gpt2_settlement_bytes_v1(batch.counters.responses)
                .map_err(|error| format!("X4d settlement byte formula: {error:?}"))?
    {
        return Err("X4d exact settlement codec reference length changed".to_owned());
    }
    let prover_full_correlations = stream
        .counters
        .full_corrs
        .checked_sub(prover_fulls_before)
        .ok_or_else(|| "X4d prover correlation counter underflows".to_owned())?;
    let verifier_full_correlations = verifier
        .counters
        .full_corrs
        .checked_sub(verifier_fulls_before)
        .ok_or_else(|| "X4d verifier correlation counter underflows".to_owned())?;
    if prover_full_correlations != batch.counters.total_full_correlations_per_role
        || verifier_full_correlations != batch.counters.total_full_correlations_per_role
        || prover_tx.ledger() != verifier_tx.ledger()
        || x4c_metrics.io != Default::default()
        || x4c_metrics.execution.query_gather_calls != 1
        || x4c_metrics.sampling_soundness_credit_bits != 0
    {
        return Err("X4d settlement accounting/I/O/gather invariant failed".to_owned());
    }
    let settlement_wall_ns = u64::try_from(settlement_started.elapsed().as_nanos())
        .map(|value| value.max(1))
        .map_err(|_| "X4d settlement wall overflows".to_owned())?;
    Ok(X4dGpt2SettlementResultV1 {
        static_weight_commitment_digest,
        settlement_model_root,
        auxiliary_seed_commitment: fresh_auxiliary.seed_commitment,
        auxiliary_root_set_digest: fresh_auxiliary.root_set_digest,
        manifest_frames,
        reduced,
        link_proof,
        link_metrics,
        x4c_metrics,
        seal_wall_ns: phase_walls.seal_wall_ns,
        open_wall_ns: phase_walls.open_wall_ns,
        verify_wall_ns,
        settlement_wall_ns,
        envelope,
        encoded_settlement,
        prover_full_correlations,
        verifier_full_correlations,
        auxiliary_masks_created: fresh_auxiliary.masks_created,
        static_weight_roots_reused: X4D_STATIC_WEIGHT_COHORTS_V1,
    })
}

#[derive(Clone, Debug)]
pub struct X4dCodecReferenceV1 {
    pub responses: usize,
    pub context: X4dSettlementContextV1,
    pub expected_claims: Vec<X4dFrozenClaimIdentityV1>,
    pub link_domains: Vec<u64>,
    pub opening_schedule: PackedOpeningScheduleV4,
    pub envelope: X4dSettlementEnvelopeV1,
    pub encoded: Vec<u8>,
}

fn reference_digest_v1(index: usize) -> Digest {
    let mut value = [0u8; 32];
    value[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    value[8..].fill((index as u8).wrapping_mul(29).wrapping_add(7));
    value
}

fn reference_cohort_root_v1(cohort_id: u32) -> Digest {
    let mut root = [0u8; 32];
    root[..4].copy_from_slice(&cohort_id.to_le_bytes());
    root[4..].fill((cohort_id as u8).wrapping_mul(13).wrapping_add(5));
    root
}

/// Materialize the exact deterministic k-response X4d codec fixture without
/// invoking a prover or reading model artifacts.
pub fn x4d_codec_reference_v1(
    responses: usize,
    query_draws: Vec<u64>,
) -> Result<X4dCodecReferenceV1, String> {
    let counters = X4dGpt2SettlementCountersV1::for_responses(responses)?;
    if query_draws.len() != X4D_QUERY_COUNT_V1 {
        return Err("X4d codec reference needs exactly 111 query draws".to_owned());
    }
    let epoch = 0xD4_0000_0000u64
        .checked_add(u64::try_from(responses).map_err(|_| "X4d k overflows".to_owned())?)
        .ok_or_else(|| "X4d reference epoch overflows".to_owned())?;
    let descriptors = (0..X4C_GPT2_PHYSICAL_BLOCKS).map(reference_digest_v1).collect::<Vec<_>>();
    let leaves = descriptors
        .iter()
        .enumerate()
        .map(|(index, descriptor)| {
            let weight_id = if index < 2 {
                X4C_WEXT_MU26_COHORT_ID
            } else if index < 38 {
                X4C_WEXT_MU22_COHORT_ID
            } else {
                X4C_WEXT_MU20_COHORT_ID
            };
            let auxiliary_id = if index < 2 { 0xA500_0100 } else { 0xA500_0101 };
            ManifestLeafFrame {
                descriptor_digest: *descriptor,
                ordered_roots: vec![
                    reference_cohort_root_v1(weight_id),
                    reference_cohort_root_v1(auxiliary_id),
                ],
            }
        })
        .collect::<Vec<_>>();
    let manifest =
        ManifestTreeV4::build(manifest_id_digest_v4([0xC1; 32], [0xD2; 32], epoch), leaves)
            .map_err(|error| format!("X4d reference manifest: {error:?}"))?;
    let model_root = manifest.root();
    let manifest_frames = manifest
        .open(&descriptors)
        .map_err(|error| format!("X4d reference manifest opening: {error:?}"))?;
    let connection_id = [0xD5; 32];
    let response_nonces =
        (0..responses).map(|index| reference_digest_v1(10_000 + index)).collect::<Vec<_>>();
    let mut claim_frames = Vec::with_capacity(counters.frozen_claims);
    let mut expected_claims = Vec::with_capacity(counters.frozen_claims);
    for (response_index, response_nonce) in response_nonces.iter().copied().enumerate() {
        for (block_index, descriptor) in descriptors.iter().copied().enumerate() {
            let point_len = if block_index < 2 {
                26
            } else if block_index < 38 {
                22
            } else {
                20
            };
            for phase in 0..2usize {
                let claim_index = claim_frames.len();
                let frame = ReducedClaimFrame {
                    descriptor_digest: descriptor,
                    parent_claim_digest: reference_digest_v1(
                        20_000 + response_index * X4D_GPT2_CLAIMS_PER_RESPONSE_V1 + claim_index,
                    ),
                    phase: if phase == 0 { Phase::Prefill } else { Phase::Decode },
                    phase_ordinal: phase as u16,
                    point: vec![Fp2::ZERO; point_len],
                    affine_scale: Fp2::ONE,
                    auth_domain: 0xD6_0000
                        + u64::try_from(claim_index)
                            .map_err(|_| "X4d reference claim index overflows".to_owned())?,
                };
                let claim_index_u64 = u64::try_from(claim_index)
                    .map_err(|_| "X4d reference claim index overflows".to_owned())?;
                expected_claims.push(X4dFrozenClaimIdentityV1 {
                    connection_id,
                    response_nonce,
                    claim_index: claim_index_u64,
                    auth_handle_digest: reference_digest_v1(30_000 + claim_index),
                    claim_frame: frame.clone(),
                });
                claim_frames.push(frame);
            }
        }
    }
    let context = X4dSettlementContextV1 {
        range: volta_pcs::x4::X4dSettlementRangeV1 {
            connection_id,
            settlement_epoch: epoch,
            first_claim_index: 0,
            claim_count: u32::try_from(counters.frozen_claims)
                .map_err(|_| "X4d reference claim count overflows".to_owned())?,
            starting_accumulator_digest: [0xD7; 32],
            sealed_accumulator_digest: [0xD8; 32],
            ordered_response_nonces: response_nonces,
        },
    };
    let public_h = vec![Fp2::ZERO; counters.masked_groups];
    let m9_frames = (0..responses)
        .flat_map(|_| {
            descriptors.iter().map(|descriptor| M9TransferFrame {
                descriptor_digest: *descriptor,
                mask_correction_symbol: Fp2::ZERO,
            })
        })
        .collect::<Vec<_>>();
    let link_domains = (0..54u64).map(|index| 0xD9_0000 + index).collect::<Vec<_>>();
    let link_frame = AuthenticatedOutputLinkFrame {
        relation_count: u16::try_from(2 * counters.masked_groups)
            .map_err(|_| "X4d reference relation count overflows".to_owned())?,
        round_count: 27,
        link_schedule_digest: authenticated_output_link_schedule_digest_x4d_v1(
            &context,
            &claim_frames,
            &descriptors,
            &public_h,
            &m9_frames,
            27,
            &link_domains,
        )
        .map_err(|error| format!("X4d reference link digest: {error:?}"))?,
        ordered_round_correction_symbols: vec![Fp2::ZERO; 54],
        terminal_opened_tag_symbol: Fp2::ZERO,
    };
    let folds = (1..=27usize)
        .map(|round| FoldCommitmentFrameV4 {
            cohort_id: 0xA500_F001,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: round as u8,
            input_log2: (31 - round) as u8,
            output_log2: (30 - round) as u8,
            root_digest: reference_digest_v1(40_000 + round),
            ordered_message_symbols: vec![Fp2::ZERO; if round == 27 { 3 } else { 2 }],
        })
        .collect::<Vec<_>>();
    let initial_groups = [
        (X4C_WEXT_MU26_COHORT_ID, 30, 2, 2),
        (X4C_WEXT_MU22_COHORT_ID, 26, 64, 36),
        (X4C_WEXT_MU20_COHORT_ID, 24, 16, 13),
        (0xA500_0100, 20, 2, 2),
        (0xA500_0101, 19, 64, 49),
    ]
    .into_iter()
    .map(|(cohort_id, domain_log2, slot_count, touched)| InitialOpeningScheduleV4 {
        cohort_id,
        domain_log2,
        slot_count,
        touched_slots: (0..touched).collect(),
        root_digest: reference_cohort_root_v1(cohort_id),
    })
    .collect::<Vec<_>>();
    let opening_schedule = PackedOpeningScheduleV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        initial_groups,
        fold_frames: folds.clone(),
        draw_width: 30,
        query_draws,
    };
    opening_schedule
        .validate()
        .map_err(|error| format!("X4d reference opening schedule: {error:?}"))?;
    let mut packed = gpt2_codec_reference_packed_opening_v4();
    packed.opening_schedule_digest = opening_schedule_digest_x4d_v1(&context, &opening_schedule)
        .map_err(|error| format!("X4d reference opening digest: {error:?}"))?;
    let zero = ResponseZeroBatchFrame {
        claim_count: u16::try_from(counters.masked_groups)
            .map_err(|_| "X4d reference ZeroBatch count overflows".to_owned())?,
        mask_correction_symbol: Fp2::ZERO,
        opened_tag_symbol: Fp2::ZERO,
    };
    let mut envelope = X4dSettlementEnvelopeV1 {
        profile_digest: volta_pcs::x4::x4d_profile_digest_v1(),
        model_root,
        settlement_epoch: epoch,
        descriptor_digests: descriptors,
        manifest_frames,
        claim_frames,
        ordered_h_symbols: public_h,
        m9_frames,
        authenticated_output_link_frame: link_frame,
        fold_frames: folds,
        packed_opening_frame: packed,
        zero_batch_frame: zero,
        fixed_size_padding: Vec::new(),
    };
    envelope
        .pad_gpt2_settlement(responses)
        .map_err(|error| format!("X4d reference padding: {error:?}"))?;
    envelope
        .validate(
            &context,
            &expected_claims,
            &envelope.manifest_frames,
            &link_domains,
            &opening_schedule,
        )
        .map_err(|error| format!("X4d reference envelope: {error:?}"))?;
    let encoded = envelope.encode().map_err(|error| format!("X4d reference encode: {error:?}"))?;
    if encoded.len() as u64
        != volta_pcs::x4::x4d_gpt2_settlement_bytes_v1(responses)
            .map_err(|error| format!("X4d reference formula: {error:?}"))?
        || X4dSettlementEnvelopeV1::decode(&encoded)
            .map_err(|error| format!("X4d reference decode: {error:?}"))?
            != envelope
    {
        return Err("X4d reference encode/decode/length mismatch".to_owned());
    }
    Ok(X4dCodecReferenceV1 {
        responses,
        context,
        expected_claims,
        link_domains,
        opening_schedule,
        envelope,
        encoded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_counters_are_exact_at_registered_batch_sizes() {
        for (responses, claims, groups, correlations) in [
            (1, 102, 51, 2_314),
            (8, 816, 408, 18_127),
            (16, 1_632, 816, 36_199),
            (32, 3_264, 1_632, 72_343),
        ] {
            let counters = X4dGpt2SettlementCountersV1::for_responses(responses).unwrap();
            assert_eq!(counters.frozen_claims, claims);
            assert_eq!(counters.masked_groups, groups);
            assert_eq!(counters.total_full_correlations_per_role, correlations);
            assert_eq!(counters.active_chain_polynomials, 102);
            assert_eq!(counters.query_draws, 111);
        }
        assert!(X4dGpt2SettlementCountersV1::for_responses(33).is_err());
    }

    #[test]
    fn settlement_domains_are_disjoint_from_x4c_and_mac_reserved_bits() {
        let domains = [
            X4D_CLAIM_REDUCTION_DOMAIN_BASE_V1,
            X4D_M9_DOMAIN_BASE_V1,
            X4D_LINK_DOMAIN_BASE_V1,
            X4D_ZERO_DOMAIN_BASE_V1,
        ]
        .map(|base| settlement_domain_v1(base, 1).unwrap());
        assert!(domains.iter().all(|domain| domain & RESERVED_DOMAIN_BITS == 0));
        assert!(domains.iter().all(|domain| domain >> 48 == 0x1001));
        assert_eq!(domains.iter().copied().collect::<BTreeSet<_>>().len(), domains.len());
        assert!(settlement_domain_v1(1 << 61, 1).is_err());
    }

    #[test]
    fn split_thread_policy_requires_disjoint_eight_and_twenty_seven() {
        let valid = X4dSplitThreadPolicyV1 {
            response_cpu_ids: (0..8).collect(),
            settlement_cpu_ids: (8..35).collect(),
        };
        valid.validate().unwrap();
        let mut overlapping = valid;
        overlapping.settlement_cpu_ids[0] = 7;
        assert!(overlapping.validate().is_err());
    }
}

#[test]
fn codec_references_round_trip_at_all_registered_batch_sizes() {
    let preflight = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json"),
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&preflight).unwrap();
    let draws = value["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == "e29-r3-s111")
        .unwrap()["challenge"]["ordered_draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|draw| draw.as_u64().unwrap())
        .collect::<Vec<_>>();
    for responses in [1, 8, 16, 32] {
        let reference = x4d_codec_reference_v1(responses, draws.clone()).unwrap();
        assert_eq!(
            reference.encoded.len() as u64,
            volta_pcs::x4::x4d_gpt2_settlement_bytes_v1(responses).unwrap()
        );
        let mut tampered = reference.encoded.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(X4dSettlementEnvelopeV1::decode(&tampered).is_err());
        let mut shortened = reference.encoded.clone();
        shortened.pop();
        let body_len = u32::try_from(shortened.len() - 16).unwrap().to_le_bytes();
        shortened[12..16].copy_from_slice(&body_len);
        let shortened = X4dSettlementEnvelopeV1::decode(&shortened).unwrap();
        assert!(shortened
            .validate(
                &reference.context,
                &reference.expected_claims,
                &reference.envelope.manifest_frames,
                &reference.link_domains,
                &reference.opening_schedule,
            )
            .is_err());
        let mut wrong_context = reference.context.clone();
        wrong_context.range.settlement_epoch += 1;
        assert!(reference
            .envelope
            .validate(
                &wrong_context,
                &reference.expected_claims,
                &reference.envelope.manifest_frames,
                &reference.link_domains,
                &reference.opening_schedule,
            )
            .is_err());
        let mut wrong_subset = reference.expected_claims.clone();
        wrong_subset.pop();
        assert!(reference
            .envelope
            .validate(
                &reference.context,
                &wrong_subset,
                &reference.envelope.manifest_frames,
                &reference.link_domains,
                &reference.opening_schedule,
            )
            .is_err());
        let mut reordered = reference.expected_claims.clone();
        reordered.swap(0, 1);
        assert!(reference
            .envelope
            .validate(
                &reference.context,
                &reordered,
                &reference.envelope.manifest_frames,
                &reference.link_domains,
                &reference.opening_schedule,
            )
            .is_err());
        let mut wrong_manifest = reference.envelope.manifest_frames.clone();
        match &mut wrong_manifest[0] {
            ManifestFrameV4::Leaf(frame) => frame.ordered_roots[1][0] ^= 1,
            ManifestFrameV4::Node(_) => panic!("X4d reference manifest starts with leaves"),
        }
        assert!(reference
            .envelope
            .validate(
                &reference.context,
                &reference.expected_claims,
                &wrong_manifest,
                &reference.link_domains,
                &reference.opening_schedule,
            )
            .is_err());
    }
}
