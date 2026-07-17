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
pub mod layer_layout;
pub mod ligero;
pub mod merkle;
pub mod ntt;

pub use batch::{batch_reduce_prover, batch_reduce_verifier, BatchTimings, BlockClaim};
pub use layer_layout::{
    layout_gpt2_embed, layout_gpt2_embed_c3, layout_gpt2_layer, layout_gpt2_weights_c3,
    pcs_cost_projection, LayerWeightLayout, LayerWeightLayout2, ModelWeightLayout, TensorSlot,
    C3_EMBED, C3_WEIGHTS, P4_LAYER,
};
pub use ligero::{
    commit, commit_resident, commit_resident_from_device, commit_with_backend,
    free_resident_matrix, open_multi_zk, open_multi_zk_resident, open_multi_zk_with_backend,
    open_zk, projected_multi_open_bytes, verify_multi_open, verify_open, Commitment, LigeroParams,
    MultiOpenProof, MultiOpenTimings, OpenTimings, OpeningProof, ProverMatrix,
    ResidentMatrixFreeError, ResidentProverMatrix, ResidentWeightPlacement, GPT2_FULL,
};
