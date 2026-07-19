//! P3: blind sumcheck (M3 schema), Thaler matmul reduction, batched
//! QuickSilver product check (M7/M8), and the end-to-end blind GEMM proof
//! built on `volta-mac`'s authenticated values and mock-PCG correlations.
//! P4 adds `logup` (Gruen fraction-GKR, superseding the volta-bench spike).

pub mod block_proof;
pub(crate) mod boundary_thinning;
pub(crate) mod ffn_schedule;
pub mod gemm_proof;
pub mod hadamard;
pub mod logup;
pub mod mle;
pub mod model_proof;
pub(crate) mod private_argmax;
pub mod prod_check;
pub mod schedule;
pub mod sumcheck_blind;
pub mod sumcheck_clear;
pub mod thaler;
pub mod wires;
pub mod x1_routing;

pub use block_proof::{
    build_attn_wires, cattn_permuted, layer_content_keys, layer_dom_base, prove_layer_phase1,
    prove_layer_phase1_with_wires, prove_layer_phase2, verify_layer_phase1, verify_layer_phase2,
    AttnBlockProof, AttnWires, BlockCtxP, BlockCtxV, FfnBlockProof, InstanceLookups, LayerBytes,
    LayerOut, LayerOutV, LayerProof, LnChainProof, TableBankP, TableBankV, TableCloseProof,
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
    prove_model, prove_model_with_backend, prove_response, prove_response_private_logits,
    prove_response_private_logits_with_backend, prove_response_resident,
    prove_response_resident_private_logits, prove_response_with_backend, verify_model,
    verify_response, verify_response_private_logits, ChunkPub, ChunkRef, EmbedProof, FinalLnProof,
    ModelOut, ModelOutV, ModelProof, PrivateChunkPub, ResidentChunkRef, SeamProof,
};
pub use prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
pub use schedule::{
    CorrelationScope, CorrelationSegment, RoundFamily, SchedulePlan, ScheduleSite, SiteCorrPlan,
    SiteId, StagedEpoch, StagedEpochSite,
};
pub use sumcheck_blind::{blind_prove, blind_prove_with_finals, blind_verify, BlindSumcheckProof};
pub use sumcheck_clear::{prove_clear, verify_clear, ClearProof};
pub use x1_routing::{
    build_x1_routing_fixture, encode_x1_golden, native_top_k_d1, prove_x1_routing,
    verify_x1_routing, x1_content_keys, x1_model_config, X1LayerWitness, X1RoutingFixture,
    X1RoutingProof, X1RoutingProverOut, X1RoutingVerifierOut, X1_D, X1_EXPERTS, X1_LAYERS, X1_T,
    X1_TOP_K,
};
