//! Fixed-point GPT-2 forward pass (= witness generation) and the integer GEMM
//! kernel with the fused MAC-authentication epilogue.
//!
//! P1 scope was the kernel + epilogue; P4 adds the one-layer fixed-point
//! forward pass with LUTs and lookup traces (`luts`, `layer`); P5 adds the
//! frozen-artifact loader and the full-model witness (`model`).

pub mod band;
pub mod decode;
pub mod gemm;
pub mod layer;
pub mod luts;
pub mod model;

pub use band::{band_model_witness, BandModelWitness};
pub use decode::{argmax, decode_step, generate, requant_plain, KvCache};
pub use gemm::{gemm_i64, gemm_requant, gemm_requant_auth, EpilogueSpec};
pub use layer::{
    forward_layer, forward_layer_with, synthetic_input, synthetic_weights, GemmBiases,
    LayerWeights, LayerWitness, LookupTrace, TableId, D, DFF, DH, H,
};
pub use luts::{build_luts, LutParams, Luts};
pub use model::{
    forward_model, forward_model_tokens, load_model, Gpt2Model, ModelWitness, L, NPOS, VOCAB,
};
