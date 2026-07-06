//! P3: blind sumcheck (M3 schema), Thaler matmul reduction, batched
//! QuickSilver product check (M7/M8), and the end-to-end blind GEMM proof
//! built on `volta-mac`'s authenticated values and mock-PCG correlations.
//! P4 adds `logup` (Gruen fraction-GKR, superseding the volta-bench spike).

pub mod block_proof;
pub mod gemm_proof;
pub mod hadamard;
pub mod logup;
pub mod mle;
pub mod model_proof;
pub mod wires;
pub mod prod_check;
pub mod sumcheck_blind;
pub mod sumcheck_clear;
pub mod thaler;

pub use block_proof::{
    build_attn_wires, cattn_permuted, prove_attn_block, prove_ffn_block, prove_layer,
    prove_layer_with_wires, verify_attn_block, verify_ffn_block, verify_layer, AttnBlockProof,
    AttnWires, BlockCtxP, BlockCtxV, FfnBlockProof, InstanceLookups, LayerBytes, LayerOut,
    LayerOutV, LayerProof, LnChainProof,
};
pub use gemm_proof::{
    auth_phase, prove_gemm_blind, prove_gemm_blind_committed, verify_gemm_blind,
    verify_gemm_blind_committed, GemmBlindProof, ProveTimings, WeightClaimP,
};
pub use gemm_proof::{
    auth_phase_at, prove_gemm_act_chained, prove_gemm_blind_at, prove_gemm_blind_committed_at,
    prove_gemm_committed_chained, verify_gemm_act_chained, verify_gemm_blind_at,
    verify_gemm_blind_committed_at, verify_gemm_committed_chained, ChainDoms, ChainedGemmProof,
    GemmDomains, WireKey, WireOut,
};
pub use hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
pub use model_proof::{
    prove_model, verify_model, EmbedProof, FinalLnProof, ModelOut, ModelOutV, ModelProof,
    SeamProof,
};
pub use prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
pub use sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
pub use sumcheck_clear::{prove_clear, verify_clear, ClearProof};
