//! P5 full-model witness generator + frozen-artifact loader.
//!
//! Loads the quantized GPT-2 small artifact produced by
//! `scripts/export_gpt2.py` (`gpt2s-q.bin` raw LE i16 tensors in the frozen
//! LAYER_TENSORS order + wte/wpe/ln_f + the 4 frozen LUTs; `gpt2s-q.params`
//! flat i32 sidecar, magic "VGPT2Q2\0") and runs the fixed-point forward for
//! the whole model: embed → 12 layers (per-layer residual shifts, seam
//! requants) → final LN on the last row → i64 logits (tied wte, no requant).
//! Bit-for-bit mirror of `scripts/gpt2_fixed.py::forward_model` per
//! docs/quantization-spec.md §P5.

use std::path::Path;

use rayon::prelude::*;
use volta_accel::{AccelError, Backend, BackendKind, Operation};

use crate::config::{
    ActivationKind, AttentionMode, ConfigBinding, LayerShiftSchedule, ModelConfig,
    NonlinearTableConfig, NormKind,
};
use crate::layer::{
    forward_layer_with_config_backend, layer_norm, requant_into, synthetic_weights_for_config,
    GemmBiases, LayerWeights, LayerWitness, LookupTrace, D, DFF,
};
use crate::luts::{build_luts, LutParams, Luts};

pub const L: usize = 12;
pub const VOCAB: usize = 50257;
pub const NPOS: usize = 1024;

// ---------------------------------------------------------------------------
// Params sidecar
// ---------------------------------------------------------------------------

/// Calibrated parameters of the frozen artifact. `lut` carries the global
/// scalars (its `shift_attn_proj`/`shift_ffn_down` are overwritten per layer
/// from the arrays below; `softmax_row_shift` is always true for P5).
#[derive(Clone, Debug)]
pub struct P5Params {
    pub lut: LutParams,
    pub shift_attn_proj: Vec<u32>,
    pub shift_ffn_down: Vec<u32>,
    pub seam_shifts: Vec<u32>,
    /// May be ≤ 0: a non-positive value is a LEFT shift by −s (exact,
    /// linear, no lookup).
    pub shift_embed: i32,
    pub f_res: Vec<u32>,
    pub tokens: Vec<u32>,
}

struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn i32(&mut self) -> i32 {
        let v = i32::from_le_bytes(self.b[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        v
    }
    fn u32(&mut self) -> u32 {
        self.i32() as u32
    }
}

fn parse_params(bytes: &[u8]) -> P5Params {
    assert_eq!(&bytes[..8], b"VGPT2Q2\0", "bad gpt2s-q.params magic");
    let mut r = Rd { b: bytes, pos: 8 };
    // Scalars, exactly export_gpt2.py::PARAMS_ORDER.
    let ln_var_shift = r.u32();
    let ln_rsqrt_log2 = r.u32();
    let shift_ln_norm = r.u32();
    let exp_in_log2 = r.u32();
    let exp_out_log2 = r.u32();
    let recip_den_shift = r.u32();
    let recip_log2 = r.u32();
    let gelu_scale_log2 = r.u32();
    let shift_qkv = r.u32();
    let shift_scores = r.u32();
    let shift_softmax_norm = r.u32();
    let shift_av = r.u32();
    let shift_ffn_up = r.u32();
    let shift_embed = r.i32();
    for _ in 0..12 {
        r.i32(); // f_ln..f_ln_gain (8) + fw_* (4) — in the JSON, unused here
    }
    // Arrays, exactly export_gpt2.py::ARRAYS_ORDER.
    let mut f_res = vec![0u32; L];
    let mut shift_attn_proj = vec![0u32; L];
    let mut shift_ffn_down = vec![0u32; L];
    let mut seam_shifts = vec![0u32; L - 1];
    for v in f_res.iter_mut() {
        *v = r.u32();
    }
    for v in shift_attn_proj.iter_mut() {
        *v = r.u32();
    }
    for v in shift_ffn_down.iter_mut() {
        *v = r.u32();
    }
    for v in seam_shifts.iter_mut() {
        *v = r.u32();
    }
    let n_tok = r.u32() as usize;
    let tokens: Vec<u32> = (0..n_tok).map(|_| r.u32()).collect();
    assert_eq!(r.pos, bytes.len(), "trailing bytes in gpt2s-q.params");

    let lut = LutParams {
        ln_var_shift,
        ln_rsqrt_log2,
        shift_ln_norm,
        exp_in_log2,
        exp_out_log2,
        recip_den_shift,
        recip_log2,
        gelu_scale_log2,
        shift_qkv,
        shift_scores,
        shift_softmax_norm,
        shift_av,
        shift_attn_proj: shift_attn_proj[0], // per-layer override at use site
        shift_ffn_up,
        shift_ffn_down: shift_ffn_down[0],
        softmax_row_shift: true,
    };
    P5Params { lut, shift_attn_proj, shift_ffn_down, seam_shifts, shift_embed, f_res, tokens }
}

// ---------------------------------------------------------------------------
// Weight blob
// ---------------------------------------------------------------------------

pub struct Gpt2Model {
    pub config: ModelConfig,
    pub p: P5Params,
    pub luts: Luts,
    pub layers: Vec<(LayerWeights, GemmBiases)>,
    pub wte: Vec<i16>,             // VOCAB × d token embedding
    pub lm_head: Option<Vec<i16>>, // None exactly when output is tied to wte
    pub wpe: Vec<i16>,             // NPOS × d
    pub lnf_gain: Vec<i16>,
    pub lnf_bias: Vec<i16>,
}

impl Gpt2Model {
    /// Shape-only preflight.  This runs before witness/backend allocation and
    /// prevents a prover-supplied ragged artifact from selecting geometry.
    pub fn validate_layout(&self) -> Result<(), String> {
        self.config.validate().map_err(|error| error.to_string())?;
        let c = &self.config;
        if self.layers.len() != c.n_layers
            || self.p.shift_attn_proj.len() != c.n_layers
            || self.p.shift_ffn_down.len() != c.n_layers
            || self.p.f_res.len() != c.n_layers
            || self.p.seam_shifts.len() != c.n_layers - 1
            || self.p.tokens.len() > c.max_positions
            || self.wte.len() != c.vocab_size * c.d_model
            || self.wpe.len() != c.max_positions * c.d_model
            || self.lnf_gain.len() != c.d_model
            || self.lnf_bias.len() != c.d_model
        {
            return Err("model-level artifact shape mismatch".to_owned());
        }
        match (c.tied_output, self.lm_head.as_ref()) {
            (true, None) => {}
            (false, Some(weights)) if weights.len() == c.vocab_size * c.d_model => {}
            _ => return Err("output-head artifact does not match tied_output policy".to_owned()),
        }
        if nonlinear_table_config(self.luts.params) != c.nonlinear_tables
            || [
                self.luts.exp.len(),
                self.luts.gelu.len(),
                self.luts.ln_rsqrt.len(),
                self.luts.softmax_recip.len(),
            ]
            .into_iter()
            .any(|len| len != 1 << 16)
        {
            return Err("global LUT schedule or table shape mismatch".to_owned());
        }
        for layer in 0..c.n_layers {
            let shifts = &c.layer_shifts[layer];
            if c.n_experts == 0
                && (shifts.router_requant != 0
                    || shifts.router_norm != 0
                    || !shifts.expert_blocks.is_empty())
            {
                return Err(format!("dense layer {layer} carries MoE shifts"));
            }
            if c.binding == ConfigBinding::LegacyImplicit {
                let expected = LayerShiftSchedule {
                    residual_fraction_bits: self.p.f_res[layer],
                    layer_norm: self.p.lut.shift_ln_norm,
                    qkv: self.p.lut.shift_qkv,
                    scores: self.p.lut.shift_scores,
                    softmax_norm: self.p.lut.shift_softmax_norm,
                    av: self.p.lut.shift_av,
                    attention_out: self.p.shift_attn_proj[layer],
                    ffn_up: self.p.lut.shift_ffn_up,
                    ffn_down: self.p.shift_ffn_down[layer],
                    residual_seam: self.p.seam_shifts.get(layer).copied().unwrap_or(0),
                    router_requant: 0,
                    router_norm: 0,
                    expert_blocks: Vec::new(),
                };
                if *shifts != expected
                    || c.embedding_shift != self.p.shift_embed
                    || c.final_norm_shift != self.p.lut.shift_ln_norm
                    || self.luts.params != self.p.lut
                {
                    return Err(format!("legacy layer {layer} shift schedule mismatch"));
                }
            }
        }
        for (layer, (weights, biases)) in self.layers.iter().enumerate() {
            let valid = weights.c_attn.len() == c.d_model * c.qkv_dim()
                && weights.attn_proj.len() == c.q_dim() * c.d_model
                && weights.ffn_up.len() == c.d_model * c.d_ff
                && weights.ffn_down.len() == c.d_ff * c.d_model
                && [
                    weights.ln1_gain.len(),
                    weights.ln1_bias.len(),
                    weights.ln2_gain.len(),
                    weights.ln2_bias.len(),
                    biases.attn_proj.len(),
                    biases.ffn_down.len(),
                ]
                .into_iter()
                .all(|len| len == c.d_model)
                && biases.c_attn.len() == c.qkv_dim()
                && biases.ffn_up.len() == c.d_ff;
            if !valid {
                return Err(format!("layer {layer} artifact shape mismatch"));
            }
        }
        Ok(())
    }

    pub fn output_weights(&self) -> &[i16] {
        self.lm_head.as_deref().unwrap_or(&self.wte)
    }
}

/// Loads `gpt2s-q.{bin,params}` from `dir` (see module docs for the frozen
/// layout — any layout change must bump the magic in export_gpt2.py).
pub fn load_model(dir: &Path) -> std::io::Result<Gpt2Model> {
    let p = parse_params(&std::fs::read(dir.join("gpt2s-q.params"))?);
    let config = legacy_model_config(&p);
    let blob = std::fs::read(dir.join("gpt2s-q.bin"))?;
    assert_eq!(blob.len() % 2, 0);

    let mut pos = 0usize;
    let mut take = |n: usize| -> Vec<i16> {
        let out: Vec<i16> = blob[pos..pos + 2 * n]
            .chunks_exact(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        pos += 2 * n;
        out
    };

    let mut layers = Vec::with_capacity(L);
    for _ in 0..L {
        // Order = export_gpt2.py::LAYER_TENSORS, frozen.
        let c_attn = take(D * 3 * D);
        let c_attn_bias = take(3 * D);
        let attn_proj = take(D * D);
        let attn_proj_bias = take(D);
        let ffn_up = take(D * DFF);
        let ffn_up_bias = take(DFF);
        let ffn_down = take(DFF * D);
        let ffn_down_bias = take(D);
        let ln1_gain = take(D);
        let ln1_bias = take(D);
        let ln2_gain = take(D);
        let ln2_bias = take(D);
        layers.push((
            LayerWeights {
                c_attn,
                attn_proj,
                ffn_up,
                ffn_down,
                ln1_gain,
                ln1_bias,
                ln2_gain,
                ln2_bias,
            },
            GemmBiases {
                c_attn: c_attn_bias,
                attn_proj: attn_proj_bias,
                ffn_up: ffn_up_bias,
                ffn_down: ffn_down_bias,
            },
        ));
    }
    let wte = take(VOCAB * D);
    let wpe = take(NPOS * D);
    let lnf_gain = take(D);
    let lnf_bias = take(D);
    let exp = take(1 << 16);
    let gelu = take(1 << 16);
    let ln_rsqrt = take(1 << 16);
    let softmax_recip = take(1 << 16);
    assert_eq!(pos, blob.len(), "trailing bytes in gpt2s-q.bin");

    let luts = Luts { params: p.lut, exp, gelu, ln_rsqrt, softmax_recip };
    Ok(Gpt2Model { config, p, luts, layers, wte, lm_head: None, wpe, lnf_gain, lnf_bias })
}

fn nonlinear_table_config(params: LutParams) -> NonlinearTableConfig {
    NonlinearTableConfig {
        ln_var_shift: params.ln_var_shift,
        ln_rsqrt_log2: params.ln_rsqrt_log2,
        exp_in_log2: params.exp_in_log2,
        exp_out_log2: params.exp_out_log2,
        recip_den_shift: params.recip_den_shift,
        recip_log2: params.recip_log2,
        gelu_scale_log2: params.gelu_scale_log2,
        softmax_row_shift: params.softmax_row_shift,
    }
}

fn legacy_model_config(p: &P5Params) -> ModelConfig {
    let mut config = ModelConfig::gpt2_small();
    config.nonlinear_tables = nonlinear_table_config(p.lut);
    config.embedding_shift = p.shift_embed;
    config.final_norm_shift = p.lut.shift_ln_norm;
    for layer in 0..L {
        config.layer_shifts[layer] = LayerShiftSchedule {
            residual_fraction_bits: p.f_res[layer],
            layer_norm: p.lut.shift_ln_norm,
            qkv: p.lut.shift_qkv,
            scores: p.lut.shift_scores,
            softmax_norm: p.lut.shift_softmax_norm,
            av: p.lut.shift_av,
            attention_out: p.shift_attn_proj[layer],
            ffn_up: p.lut.shift_ffn_up,
            ffn_down: p.shift_ffn_down[layer],
            residual_seam: p.seam_shifts.get(layer).copied().unwrap_or(0),
            ..LayerShiftSchedule::default()
        };
    }
    config.validate().expect("frozen GPT-2 ModelConfig must validate");
    config
}

/// Deterministic in-memory dense model used by the runtime-shape harness.
/// It exercises the same fixed-point/LUT path without reading or downloading
/// an architecture artifact.
pub fn synthetic_model(
    mut config: ModelConfig,
    tokens: Vec<u32>,
    seed: u64,
) -> Result<Gpt2Model, String> {
    config.validate().map_err(|error| error.to_string())?;
    if config.n_experts != 0
        || config.norm != NormKind::LayerNorm
        || config.activation != ActivationKind::Gelu
        || config.attention.iter().any(|mode| *mode != AttentionMode::FullCausal)
        || config.attention_sinks_per_q_head != 0
        || config.rope.is_some()
    {
        return Err("synthetic dense foundation model received an X2/X3 operator".to_owned());
    }
    if tokens.is_empty()
        || tokens.len() > config.max_positions
        || tokens.iter().any(|&token| (token as usize) >= config.vocab_size)
    {
        return Err("synthetic token sequence is outside ModelConfig".to_owned());
    }

    let lut = LutParams::default();
    let shift_attn_proj = vec![lut.shift_attn_proj; config.n_layers];
    let shift_ffn_down = vec![lut.shift_ffn_down; config.n_layers];
    let seam_shifts = vec![0; config.n_layers - 1];
    config.nonlinear_tables = nonlinear_table_config(lut);
    config.embedding_shift = 0;
    config.final_norm_shift = lut.shift_ln_norm;
    for layer in 0..config.n_layers {
        config.layer_shifts[layer] = LayerShiftSchedule {
            residual_fraction_bits: 0,
            layer_norm: lut.shift_ln_norm,
            qkv: lut.shift_qkv,
            scores: lut.shift_scores,
            softmax_norm: lut.shift_softmax_norm,
            av: lut.shift_av,
            attention_out: lut.shift_attn_proj,
            ffn_up: lut.shift_ffn_up,
            ffn_down: lut.shift_ffn_down,
            residual_seam: 0,
            ..LayerShiftSchedule::default()
        };
    }
    let p = P5Params {
        lut,
        shift_attn_proj,
        shift_ffn_down,
        seam_shifts,
        shift_embed: 0,
        f_res: vec![0; config.n_layers],
        tokens,
    };
    let luts = build_luts(lut);
    let layers = (0..config.n_layers)
        .map(|layer| {
            let weights = synthetic_weights_for_config(
                seed.wrapping_add((layer as u64).wrapping_mul(0x9E37_79B9)),
                &config,
            );
            let biases = GemmBiases {
                c_attn: vec![0; config.qkv_dim()],
                attn_proj: vec![0; config.d_model],
                ffn_up: vec![0; config.d_ff],
                ffn_down: vec![0; config.d_model],
            };
            (weights, biases)
        })
        .collect();
    let mut state = seed ^ 0xD1B5_4A32_D192_ED03;
    let mut values = |len: usize, radius: i16| {
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state % (2 * radius as u64 + 1)) as i16 - radius
            })
            .collect::<Vec<_>>()
    };
    let wte = values(config.vocab_size * config.d_model, 15);
    let lm_head = (!config.tied_output).then(|| values(config.vocab_size * config.d_model, 15));
    let wpe = values(config.max_positions * config.d_model, 7);
    let lnf_gain = vec![64; config.d_model];
    let lnf_bias = vec![0; config.d_model];
    let model = Gpt2Model { config, p, luts, layers, wte, lm_head, wpe, lnf_gain, lnf_bias };
    model.validate_layout()?;
    Ok(model)
}

pub(crate) fn layer_lut_params(mut params: LutParams, shifts: &LayerShiftSchedule) -> LutParams {
    params.shift_ln_norm = shifts.layer_norm;
    params.shift_qkv = shifts.qkv;
    params.shift_scores = shifts.scores;
    params.shift_softmax_norm = shifts.softmax_norm;
    params.shift_av = shifts.av;
    params.shift_attn_proj = shifts.attention_out;
    params.shift_ffn_up = shifts.ffn_up;
    params.shift_ffn_down = shifts.ffn_down;
    params
}

// ---------------------------------------------------------------------------
// Full-model witness
// ---------------------------------------------------------------------------

/// Embedding witness: `acc = wte[tok] + wpe[pos]` (T×d, i64), requantized to
/// the segment-0 residual scale. `trace` is None for `shift_embed ≤ 0`
/// (exact left shift — linear, no lookup).
#[derive(Debug, PartialEq, Eq)]
pub struct EmbedWitness {
    pub acc: Vec<i64>,
    pub out: Vec<i16>,
    pub trace: Option<LookupTrace>,
}

/// Final-LN witness (last position only) + its two lookup traces (the tables
/// are the shared ln_rsqrt / ln_norm_requant).
#[derive(Debug, PartialEq, Eq)]
pub struct FinalLnWitness {
    pub mean: i64,
    pub var: i64,
    pub rsqrt_in: i64,
    pub rsqrt_out: i16,
    pub acc: Vec<i64>, // d affine accumulator before requant
    pub out: Vec<i16>, // d
    pub rsqrt_trace: LookupTrace,
    pub norm_trace: LookupTrace,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ModelWitness {
    pub t: usize,
    pub embed: EmbedWitness,
    pub layers: Vec<LayerWitness>,
    /// Seam requant traces: index l is the seam between layer l and l+1;
    /// None when the seam shift is 0 (identity, free).
    pub seams: Vec<Option<LookupTrace>>,
    pub final_ln: FinalLnWitness,
    /// Last-position logits: i64 accumulators over the tied wte, NO requant
    /// (spec §P5 embedding requant).
    pub logits: Vec<i64>,
}

/// Fixed-point forward of the whole model on the first `t` prompt tokens.
pub fn forward_model(m: &Gpt2Model, t: usize) -> ModelWitness {
    let mut backend = Backend::cpu();
    forward_model_with_backend(m, t, &mut backend).expect("CPU backend is infallible")
}

pub fn forward_model_with_backend(
    m: &Gpt2Model,
    t: usize,
    backend: &mut Backend,
) -> Result<ModelWitness, AccelError> {
    assert!(t <= m.p.tokens.len());
    forward_model_tokens_with_backend(m, &m.p.tokens[..t], backend)
}

/// [`forward_model`] on an EXPLICIT token sequence (P6: prompt + generated
/// tokens — the fixed-point forward is causal, so the first `t0` rows are
/// bit-identical to the prefill run's).
pub fn forward_model_tokens(m: &Gpt2Model, tokens: &[u32]) -> ModelWitness {
    let mut backend = Backend::cpu();
    forward_model_tokens_with_backend(m, tokens, &mut backend).expect("CPU backend is infallible")
}

pub fn forward_model_tokens_with_backend(
    m: &Gpt2Model,
    tokens: &[u32],
    backend: &mut Backend,
) -> Result<ModelWitness, AccelError> {
    if backend.kind() == BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "cuda-resident requires the device-witness API; staged ModelWitness materialization is forbidden",
        ));
    }
    m.validate_layout().expect("model/config preflight failed");
    let config = &m.config;
    let d = config.d_model;
    let layers_count = config.n_layers;
    let vocab = config.vocab_size;
    let t = tokens.len();
    assert!(t > 0 && t <= config.max_positions);
    assert!(tokens.iter().all(|&token| (token as usize) < vocab));

    // ---- embedding ----
    let embed = backend.cpu_residual(Operation::Gemm, || {
        let mut acc = vec![0i64; t * d];
        for (i, &tok) in tokens.iter().enumerate() {
            let wt = &m.wte[tok as usize * d..(tok as usize + 1) * d];
            let wp = &m.wpe[i * d..(i + 1) * d];
            for j in 0..d {
                acc[i * d + j] = wt[j] as i64 + wp[j] as i64;
            }
        }
        let s_emb = config.embedding_shift;
        let (out, trace) = if s_emb > 0 {
            let mut tr = LookupTrace::new_requant(s_emb as u32);
            let out = acc
                .iter()
                .map(|&a| requant_into(&mut tr, "requant_embed", a, s_emb as u32))
                .collect();
            (out, Some(tr))
        } else {
            let out = acc
                .iter()
                .map(|&a| {
                    let v = a << (-s_emb) as u32;
                    assert!(
                        (i16::MIN as i64..=i16::MAX as i64).contains(&v),
                        "embed left shift overflows i16"
                    );
                    v as i16
                })
                .collect();
            (out, None)
        };
        EmbedWitness { acc, out, trace }
    })?;

    // ---- layers + seams ----
    let mut layers = Vec::with_capacity(layers_count);
    let mut seams: Vec<Option<LookupTrace>> = Vec::with_capacity(layers_count - 1);
    let mut x = embed.out.clone();
    for l in 0..layers_count {
        let params = layer_lut_params(m.luts.params, &config.layer_shifts[l]);
        let (w, b) = &m.layers[l];
        let wit = forward_layer_with_config_backend(
            config,
            l,
            &x,
            w,
            Some(b),
            &m.luts,
            params,
            t,
            backend,
        )?;
        x = wit.ffn_block_out.clone();
        layers.push(wit);
        if l < layers_count - 1 {
            let s = config.layer_shifts[l].residual_seam;
            if s > 0 {
                let (next, tr) = backend.cpu_residual(Operation::Gemm, || {
                    let mut tr = LookupTrace::new_requant(s);
                    let next = x
                        .iter()
                        .map(|&v| requant_into(&mut tr, "seam_requant", v as i64, s))
                        .collect();
                    (next, tr)
                })?;
                x = next;
                seams.push(Some(tr));
            } else {
                seams.push(None);
            }
        }
    }

    // ---- final LN (last row) ----
    let final_ln = backend.cpu_residual(Operation::Gemm, || {
        let last = &x[(t - 1) * d..t * d];
        let mut rsqrt_trace = LookupTrace::new(1 << 16);
        let mut norm_trace = LookupTrace::new_requant(config.final_norm_shift);
        let mut final_params = m.luts.params;
        final_params.shift_ln_norm = config.final_norm_shift;
        let ln = layer_norm(
            last,
            &m.lnf_gain,
            &m.lnf_bias,
            &m.luts,
            final_params,
            1,
            &mut rsqrt_trace,
            &mut norm_trace,
        );
        FinalLnWitness {
            mean: ln.mean[0],
            var: ln.var[0],
            rsqrt_in: ln.rsqrt_in[0],
            rsqrt_out: ln.rsqrt_out[0],
            acc: ln.acc,
            out: ln.out,
            rsqrt_trace,
            norm_trace,
        }
    })?;

    // ---- logits (tied wte, i64 accumulators, no requant) ----
    let logits = backend.cpu_residual(Operation::Gemm, || {
        let fin = &final_ln.out;
        (0..vocab)
            .into_par_iter()
            .map(|v| {
                let row = &m.output_weights()[v * d..(v + 1) * d];
                let mut s = 0i64;
                for j in 0..d {
                    s += fin[j] as i64 * row[j] as i64;
                }
                s
            })
            .collect::<Vec<i64>>()
    })?;

    Ok(ModelWitness { t, embed, layers, seams, final_ln, logits })
}

// ---------------------------------------------------------------------------
// Golden test (skipped when the frozen artifact is not present)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::band::band_model_witness;
    use crate::config::{ConfigBinding, LayerShiftSchedule};
    use crate::decode::{decode_step, KvCache};

    fn weights_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    /// Bit-exactness against scripts/dump_golden.py (numpy reference on the
    /// SAME frozen artifact): full logits vector + tensor checksums.
    #[test]
    fn golden_check_t100() {
        let dir = weights_dir();
        let golden_path = dir.join("golden-p5.bin");
        if !golden_path.exists() || !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping golden_check_t100: frozen artifact not present");
            return;
        }
        let g = std::fs::read(golden_path).unwrap();
        assert_eq!(&g[..8], b"VGOLD1\0\0");
        let rd_u32 = |o: usize| u32::from_le_bytes(g[o..o + 4].try_into().unwrap());
        let rd_i64 = |o: usize| i64::from_le_bytes(g[o..o + 8].try_into().unwrap());
        let t = rd_u32(8) as usize;
        let argmax = rd_u32(12) as usize;
        let mut off = 16;
        let logits_ref: Vec<i64> = (0..VOCAB).map(|i| rd_i64(off + 8 * i)).collect();
        off += 8 * VOCAB;
        let embed_sum = rd_i64(off);
        let finln_sum = rd_i64(off + 8);
        off += 16;
        let ffn_sums: Vec<i64> = (0..L).map(|i| rd_i64(off + 8 * i)).collect();
        off += 8 * L;
        let row_shift_sums: Vec<i64> = (0..L).map(|i| rd_i64(off + 8 * i)).collect();
        assert_eq!(off + 8 * L, g.len());

        let m = load_model(&dir).unwrap();
        let wit = forward_model(&m, t);

        assert_eq!(wit.logits, logits_ref, "logits mismatch vs numpy reference");
        let am = (0..VOCAB).max_by_key(|&v| wit.logits[v]).unwrap();
        assert_eq!(am, argmax);
        let sum_i16 = |v: &[i16]| v.iter().map(|&x| x as i64).sum::<i64>();
        assert_eq!(sum_i16(&wit.embed.out), embed_sum, "embed_out checksum");
        assert_eq!(sum_i16(&wit.final_ln.out), finln_sum, "final_ln checksum");
        for l in 0..L {
            assert_eq!(sum_i16(&wit.layers[l].ffn_block_out), ffn_sums[l], "ffn_block_out l={l}");
            assert_eq!(sum_i16(&wit.layers[l].row_shift), row_shift_sums[l], "row_shift l={l}");
        }
    }

    #[test]
    fn runtime_model_non_power_of_two_gqa_and_band() {
        let mut config = ModelConfig::gpt2_small();
        config.model_id = "x123-foundation-model".to_owned();
        config.binding = ConfigBinding::DigestV1;
        config.vocab_size = 97;
        config.max_positions = 8;
        config.n_layers = 2;
        config.d_model = 48;
        config.d_ff = 80;
        config.n_q_heads = 6;
        config.n_kv_heads = 2;
        config.head_dim = 8;
        config.attention = vec![AttentionMode::FullCausal; 2];
        config.layer_shifts = vec![LayerShiftSchedule::default(); 2];
        config.thin_k = 2;
        config.validate().unwrap();

        let tokens = vec![3, 5, 8, 13, 21, 34, 55];
        let model = synthetic_model(config, tokens.clone(), 0x1234).unwrap();
        assert!(model.config.session_digest().unwrap().is_some());
        let witness = forward_model_tokens(&model, &tokens);
        assert_eq!(witness.layers.len(), 2);
        assert_eq!(witness.layers[0].k.len(), 7 * 16);
        assert_eq!(witness.layers[0].q.len(), 7 * 48);
        assert_eq!(witness.logits.len(), 97);

        let band = band_model_witness(&model, &witness, 3);
        assert_eq!(band.q, 4);
        assert_eq!(band.layers[0].k.len(), 4 * 16);
        assert_eq!(band.logits.len(), 4 * 97);
        assert_eq!(&band.logits[3 * 97..], witness.logits.as_slice());

        let prefix = forward_model_tokens(&model, &tokens[..3]);
        let kv: Vec<(&[i16], &[i16])> =
            prefix.layers.iter().map(|layer| (layer.k.as_slice(), layer.v.as_slice())).collect();
        let mut cache = KvCache::from_prefill_with_config(&model.config, &kv, 3);
        let decoded = decode_step(&model, &mut cache, tokens[3], 3);
        let full4 = forward_model_tokens(&model, &tokens[..4]);
        assert_eq!(decoded, full4.logits);
    }

    #[test]
    fn runtime_untied_output_and_shift_preflight() {
        let mut config = ModelConfig::gpt2_small();
        config.model_id = "x123-foundation-untied".to_owned();
        config.binding = ConfigBinding::DigestV1;
        config.vocab_size = 17;
        config.max_positions = 4;
        config.n_layers = 1;
        config.d_model = 8;
        config.d_ff = 12;
        config.n_q_heads = 2;
        config.n_kv_heads = 1;
        config.head_dim = 4;
        config.tied_output = false;
        config.attention = vec![AttentionMode::FullCausal];
        config.layer_shifts = vec![LayerShiftSchedule::default()];
        config.thin_k = 1;
        let mut model = synthetic_model(config, vec![1, 2, 3], 77).unwrap();
        assert!(model.lm_head.is_some());
        assert_ne!(model.output_weights(), model.wte.as_slice());
        let baseline = forward_model(&model, 3).logits;
        assert_eq!(baseline.len(), 17);

        model.config.layer_shifts[0].qkv += 1;
        model.validate_layout().unwrap();
        assert_ne!(forward_model(&model, 3).logits, baseline);

        model.config.nonlinear_tables.exp_out_log2 += 1;
        assert_eq!(
            model.validate_layout().unwrap_err(),
            "global LUT schedule or table shape mismatch"
        );
    }
}
