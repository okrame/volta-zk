//! Fixed-point GPT-2 forward pass (= witness generation) and the integer GEMM
//! kernel with the fused MAC-authentication epilogue.
//!
//! P1 scope was the kernel + epilogue; P4 adds the one-layer fixed-point
//! forward pass with LUTs and lookup traces (`luts`, `layer`); P5 adds the
//! frozen-artifact loader and the full-model witness (`model`).

pub mod band;
pub mod config;
pub mod decode;
pub mod gemm;
pub mod layer;
pub mod luts;
pub mod model;
pub mod resident;

pub use band::{band_model_witness, BandModelWitness};
pub use config::{
    ActivationKind, AttentionMode, ConfigBinding, ExpertBlockShifts, LayerShiftSchedule,
    ModelConfig, NonlinearTableConfig, NormKind, PaddedMatrixLayout, RopeConfig, RouterTieRule,
};
pub use decode::{argmax, decode_step, generate, requant_plain, KvCache};
pub use gemm::{
    gemm_i64, gemm_i64_with_backend, gemm_requant, gemm_requant_auth,
    gemm_requant_auth_with_backend, gemm_requant_with_backend, EpilogueSpec,
};
pub use layer::{
    forward_layer, forward_layer_with, forward_layer_with_backend, forward_layer_with_config,
    forward_layer_with_config_backend, synthetic_input, synthetic_input_for_config,
    synthetic_weights, synthetic_weights_for_config, GemmBiases, LayerWeights, LayerWitness,
    LookupTrace, TableId, D, DFF, DH, H,
};
pub use luts::{build_luts, LutParams, Luts};
pub use model::{
    forward_model, forward_model_tokens, forward_model_tokens_with_backend,
    forward_model_with_backend, load_model, synthetic_model, Gpt2Model, ModelWitness, L, NPOS,
    VOCAB,
};
pub use resident::{
    band_model_witness_resident, forward_model_tokens_resident, upload_resident_model,
    LayerI16Field, LayerI64Field, LayerWeightField, ModelWeightField, ResidentBandLayerWitness,
    ResidentBandModelWitness, ResidentGpt2Model, ResidentLayerView, ResidentLayerWitness,
    ResidentModelWitness,
};
