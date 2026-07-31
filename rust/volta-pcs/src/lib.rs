//! P3.5: static code-based PCS for private weights (Ligero over Goldilocks),
//! with batched ZK openings that resolve into VOLE-authenticated values —
//! never a cleartext W̃(r). Design: docs/private-weights-pcs.md (A′);
//! formal interface: M9 `opening_mac_sound` (lean/VoltaZk/OpeningMac.lean).
//!
//! Pipeline per response:
//!   per-GEMM authenticated W̃ claims (volta-proto committed-W seam)
//!   → `batch::batch_reduce_*` (one blind sumcheck → single point r*)
//!   → `ligero::open_zk` / `verify_open` (claim bound to the public C_W).

pub mod batch;
pub mod c6_authenticated_output_link;
pub mod c6_hidden_u;
pub mod c6_hidden_u_sumcheck;
pub mod c6_hidden_u_sumcheck_blind;
pub mod c6_persistent_cache;
pub mod c6_persistent_cache_blind;
pub mod c6_residual_sumcheck;
pub mod c6_residual_sumcheck_blind;
pub mod c6_wrapper_pcs;
pub mod layer_layout;
pub mod ligero;
pub mod merkle;
pub mod ntt;
pub mod x4;

pub use batch::{
    batch_reduce_prover, batch_reduce_prover_cpu_resident, batch_reduce_prover_cuda_resident,
    batch_reduce_verifier, BatchTimings, BlockClaim, ClaimReduceResidentCounters,
    CpuClaimReduceSettlement, CudaClaimReduceSettlement,
};
pub use c6_authenticated_output_link::{
    prove_c6_authenticated_output_link_reference, verify_c6_authenticated_output_link_reference,
    C6AuthenticatedOutputLinkError, C6AuthenticatedOutputLinkMetrics,
    C6AuthenticatedOutputLinkProof, C6BoundSlotRegistryProver, C6BoundSlotRegistryVerifier,
    C6LinkSlotPolynomial, C6PendingSlotDescriptor, C6PendingSlotRegistryProver,
    C6PendingSlotRegistryVerifier, C6_AUTHENTICATED_OUTPUT_LINK_COHORTS,
    C6_AUTHENTICATED_OUTPUT_LINK_MAGIC, C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_BYTES,
    C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_CORRELATIONS_PER_TAPE,
    C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_OVERHEAD_BYTES,
    C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_RELATIONS,
    C6_AUTHENTICATED_OUTPUT_LINK_PRODUCTION_ROUNDS, C6_AUTHENTICATED_OUTPUT_LINK_TAPES,
    C6_AUTHENTICATED_OUTPUT_LINK_VERSION,
};
pub use c6_hidden_u::{
    derive_hidden_u_family_claims, hidden_u_functional_digest, hidden_u_prequery_encoded_len,
    production_hidden_u_reference_budget, C6HiddenUBundleWitness, C6HiddenUDerivedFamily,
    C6HiddenUDigest, C6HiddenUError, C6HiddenUFamily, C6HiddenUFamilyPostCommit,
    C6HiddenUFamilyWitness, C6HiddenULayout, C6HiddenUPostCommit, C6HiddenUPrequery,
    C6HiddenUQueryClaim, C6HiddenUReferenceAudit, C6HiddenUReferenceBudget, C6SealedHiddenUBundle,
    C6_EMBED_Q121, C6_HIDDEN_U_BATCH_SEED_BYTES, C6_HIDDEN_U_REPETITIONS, C6_WEIGHTS_Q121,
};
pub use c6_hidden_u_sumcheck::{
    hidden_u_sumcheck_encoded_len, prepare_hidden_u_prover_round_state,
    prepare_hidden_u_verifier_round_state, prove_hidden_u_sumchecks, reduce_hidden_u_sumchecks,
    C6HiddenUOpeningClaim, C6HiddenUProverRoundState, C6HiddenUSumcheckFamilyProof,
    C6HiddenUSumcheckProof, C6HiddenUSumcheckRepetition, C6HiddenUVerifierRoundState,
};
pub use c6_hidden_u_sumcheck_blind::{
    blind_hidden_u_sumcheck_encoded_len, production_c6_blind_hidden_u_sumcheck_encoded_len,
    prove_c6_blind_hidden_u_sumchecks_reference, verify_c6_blind_hidden_u_sumchecks,
    C6BlindHiddenUError, C6BlindHiddenUPendingClaimsProver, C6BlindHiddenUPendingClaimsVerifier,
    C6BlindHiddenUSumcheckProof, C6_BLIND_HIDDEN_U_FAMILIES, C6_BLIND_HIDDEN_U_MAGIC,
    C6_BLIND_HIDDEN_U_PRODUCTION_BYTES, C6_BLIND_HIDDEN_U_PRODUCTION_FULL_CORRELATIONS_PER_TAPE,
    C6_BLIND_HIDDEN_U_PRODUCTION_ROUND_VALUES_PER_REPETITION, C6_BLIND_HIDDEN_U_SLOTS_PER_FAMILY,
    C6_BLIND_HIDDEN_U_TAPES, C6_BLIND_HIDDEN_U_VERSION,
};
pub use c6_persistent_cache::{
    c6_cache_source_map_digest, derive_c6_persistent_cache_source_plan,
    expected_c6_cache_append_cells, validate_c6_persistent_cache_transition_reference, C6CacheCell,
    C6CacheSlotKind, C6CacheSourceValue, C6PersistentCacheBandPlan, C6PersistentCacheBandRole,
    C6PersistentCacheError, C6PersistentCacheLayout, C6PersistentCacheReferenceAudit,
    C6PersistentCacheSourcePlan, C6PersistentCacheStateWitness, C6PersistentCacheStaticProfile,
    C6PersistentCacheTransitionBinding, C6_BLIND_HIDDEN_PLUS_PERSISTENT_LINK_NUMERATOR,
    C6_PERSISTENT_CACHE_BINDING_MAGIC, C6_PERSISTENT_CACHE_CAPACITY_TOKENS,
    C6_PERSISTENT_CACHE_DEGREE, C6_PERSISTENT_CACHE_EVENT_NUMERATOR,
    C6_PERSISTENT_CACHE_FOLDS_PER_LIVE_BAND, C6_PERSISTENT_CACHE_FOLD_CAPACITY,
    C6_PERSISTENT_CACHE_HEADS, C6_PERSISTENT_CACHE_LAYERS, C6_PERSISTENT_CACHE_LIVE_ENTRIES,
    C6_PERSISTENT_CACHE_LIVE_SLOTS, C6_PERSISTENT_CACHE_PADDED_LAYERS,
    C6_PERSISTENT_CACHE_PADDED_WIDTH, C6_PERSISTENT_CACHE_PHASE_SLOTS,
    C6_PERSISTENT_CACHE_PROFILE_MAGIC, C6_PERSISTENT_CACHE_RELATION_POINT_ROOTS,
    C6_PERSISTENT_CACHE_ROOTS_PER_REPETITION, C6_PERSISTENT_CACHE_ROUNDS,
    C6_PERSISTENT_CACHE_SLOTS, C6_PERSISTENT_CACHE_SLOT_CAPACITY, C6_PERSISTENT_CACHE_VERSION,
    C6_PERSISTENT_CACHE_WIDTH, C6_PERSISTENT_LINK_RELATIONS,
    C6_PERSISTENT_LINK_ROOTS_PER_REPETITION,
};
pub use c6_residual_sumcheck::{
    prepare_residual_sumcheck_prover_round_state, prepare_residual_sumcheck_verifier_round_state,
    production_c6_residual_sumcheck_encoded_len, production_c6_residual_sumcheck_round_bytes,
    residual_sumcheck_encoded_len, C6ResidualOpeningClaim, C6ResidualSumcheckError,
    C6ResidualSumcheckFamily, C6ResidualSumcheckFamilyStatement, C6ResidualSumcheckProof,
    C6ResidualSumcheckProverRoundState, C6ResidualSumcheckRepetitionProof,
    C6ResidualSumcheckStatement, C6ResidualSumcheckTerm, C6ResidualSumcheckVerifierRoundState,
    C6ResidualSumcheckWitness, C6ResidualTableRef, C6_RESIDUAL_AUXILIARY_LOCAL_ACTIVATION,
    C6_RESIDUAL_AUXILIARY_ROUNDS, C6_RESIDUAL_AUXILIARY_TABLES_PER_REPETITION,
    C6_RESIDUAL_LEAF_ROUNDS, C6_RESIDUAL_LEAF_TABLES_PER_REPETITION,
    C6_RESIDUAL_SUMCHECK_PROOF_BYTES, C6_RESIDUAL_SUMCHECK_REPETITIONS,
    C6_RESIDUAL_SUMCHECK_ROUND_BYTES, C6_RESIDUAL_SUMCHECK_ROUND_VALUE_BYTES,
    C6_RESIDUAL_TABLES_PER_REPETITION,
};
pub use c6_residual_sumcheck_blind::{
    blind_residual_sumcheck_encoded_len, prepare_c6_blind_residual_statement,
    production_c6_blind_residual_sumcheck_encoded_len, prove_c6_blind_residual_sumchecks_reference,
    verify_c6_blind_residual_sumchecks, C6BlindResidualError, C6BlindResidualPendingClaimsProver,
    C6BlindResidualPendingClaimsVerifier, C6BlindResidualPendingTransferFrame,
    C6BlindResidualStatement, C6BlindResidualSumcheckProof,
    C6_RESIDUAL_BLIND_CORE_FULL_CORRELATIONS_PER_TAPE,
    C6_RESIDUAL_BLIND_FULL_CORRELATIONS_PER_TAPE,
    C6_RESIDUAL_BLIND_PENDING_FULL_CORRELATIONS_PER_TAPE, C6_RESIDUAL_BLIND_PROOF_BYTES,
    C6_RESIDUAL_BLIND_ROUND_VALUES_PER_REPETITION,
};
#[cfg(feature = "c6-trace")]
pub use c6_residual_sumcheck_blind::{
    prepare_c6_blind_residual_statement_fused, prove_c6_blind_residual_sumchecks_fused,
    prove_c6_blind_residual_sumchecks_fused_scaled, verify_c6_blind_residual_sumchecks_fused,
    verify_c6_blind_residual_sumchecks_fused_scaled, C6BlindResidualFusedCompilerContext,
};
pub use c6_wrapper_pcs::{
    bind_hidden_u_opening_claims_to_wrapper_slots, bind_production_c6_residual_relation_roots,
    c6_wrapper_profile_digest, commit_c6_cache_state_cohort, commit_c6_wrapper_cohort,
    fix_production_c6_wrapper_commitments, production_c6_wrapper_codec_reference,
    production_c6_wrapper_specs, prove_c6_wrapper_pcs, prove_c6_wrapper_pcs_assembled,
    verify_c6_wrapper_pcs, verify_c6_wrapper_pcs_assembled, C6AssembledWrapperClaims,
    C6CacheStateDescriptors, C6CommittedWrapperCohort, C6FixedWrapperCommitments,
    C6WrapperChainProof, C6WrapperCohortSpec, C6WrapperCommitment, C6WrapperDigest,
    C6WrapperOpeningClaim, C6WrapperOracleKind, C6WrapperPcsError, C6WrapperPcsProof,
    C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt, C6WrapperRoundPoint,
    C6WrapperSlotOpeningClaim, C6WrapperSlotWitness, C6_CACHE_ROUND_PARTICIPANT_ID,
    C6_CACHE_STATE_MERKLE_COHORT_ID, C6_DELTA_RESIDUAL_ACTIVATION_ROUND,
    C6_DELTA_RESIDUAL_COHORT_ID, C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
    C6_HIDDEN_U_EMBED_ACTIVATION_ROUND, C6_HIDDEN_U_EMBED_COHORT_ID,
    C6_HIDDEN_U_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND,
    C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    C6_WRAPPER_ACTIVE_SLOTS, C6_WRAPPER_AUXILIARY_ACTIVATION_ROUND, C6_WRAPPER_AUXILIARY_COHORT_ID,
    C6_WRAPPER_COMMON_POINT_LEN, C6_WRAPPER_ONE_CHAIN_BYTES, C6_WRAPPER_QUERY_COUNT,
    C6_WRAPPER_RANDOM_POINT_LEN, C6_WRAPPER_REPETITIONS, C6_WRAPPER_TERMINAL_LOG2,
    C6_WRAPPER_TWO_CHAIN_BYTES,
};
pub use layer_layout::{
    layout_gpt2_embed, layout_gpt2_embed_c3, layout_gpt2_layer, layout_gpt2_weights_c3,
    pcs_cost_projection, LayerWeightLayout, LayerWeightLayout2, ModelWeightLayout, TensorSlot,
    C3_EMBED, C3_WEIGHTS, C4_EMBED, C4_WEIGHTS, P4_LAYER,
};
pub use ligero::{
    commit, commit_resident, commit_resident_from_device, commit_with_backend,
    free_resident_matrix, open_multi_zk, open_multi_zk_resident, open_multi_zk_with_backend,
    open_zk, projected_multi_open_bytes, verify_multi_open, verify_open, Commitment, LigeroParams,
    MultiOpenProof, MultiOpenTimings, OpenTimings, OpeningProof, ProverMatrix,
    ResidentMatrixFreeError, ResidentProverMatrix, ResidentWeightPlacement, GPT2_FULL,
};
