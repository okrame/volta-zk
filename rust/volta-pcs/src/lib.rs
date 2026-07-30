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
    hidden_u_sumcheck_encoded_len, prove_hidden_u_sumchecks, reduce_hidden_u_sumchecks,
    C6HiddenUOpeningClaim, C6HiddenUSumcheckFamilyProof, C6HiddenUSumcheckProof,
    C6HiddenUSumcheckRepetition,
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
