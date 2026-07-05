//! Fixed-point GPT-2 forward pass (= witness generation) and the integer GEMM
//! kernel with the fused MAC-authentication epilogue.
//!
//! P1 scope was the kernel + epilogue; P4 adds the one-layer fixed-point
//! forward pass with LUTs and lookup traces (`luts`, `layer`).

pub mod gemm;
pub mod layer;
pub mod luts;

pub use gemm::{gemm_i64, gemm_requant, gemm_requant_auth, EpilogueSpec};
pub use layer::{
    forward_layer, synthetic_input, synthetic_weights, LayerWeights, LayerWitness, LookupTrace,
    TableId, D, DFF, DH, H,
};
pub use luts::{build_luts, LutParams, Luts};
