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
pub mod c6_hidden_u;
pub mod c6_hidden_u_sumcheck;
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
pub use c6_wrapper_pcs::{
    assemble_production_c6_wrapper_claims, bind_hidden_u_opening_claims_to_wrapper_slots,
    c6_wrapper_profile_digest, commit_c6_wrapper_cohort, fix_production_c6_wrapper_commitments,
    production_c6_wrapper_codec_reference, production_c6_wrapper_specs, prove_c6_wrapper_pcs,
    prove_c6_wrapper_pcs_assembled, verify_c6_wrapper_pcs, verify_c6_wrapper_pcs_assembled,
    C6AssembledWrapperClaims, C6CommittedWrapperCohort, C6FixedWrapperCommitments,
    C6WrapperChainProof, C6WrapperCohortSpec, C6WrapperCommitment, C6WrapperDigest,
    C6WrapperOpeningClaim, C6WrapperOracleKind, C6WrapperPcsError, C6WrapperPcsProof,
    C6WrapperRoundCoordinator, C6WrapperRoundMessageReceipt, C6WrapperRoundPoint,
    C6WrapperSlotOpeningClaim, C6WrapperSlotWitness, C6_CACHE_COHORT_ID,
    C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ACTIVATION_ROUND, C6_DELTA_RESIDUAL_COHORT_ID,
    C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID, C6_HIDDEN_U_EMBED_ACTIVATION_ROUND,
    C6_HIDDEN_U_EMBED_COHORT_ID, C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
    C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND, C6_HIDDEN_U_WEIGHTS_COHORT_ID, C6_WRAPPER_ACTIVE_SLOTS,
    C6_WRAPPER_AUXILIARY_ACTIVATION_ROUND, C6_WRAPPER_AUXILIARY_COHORT_ID,
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
