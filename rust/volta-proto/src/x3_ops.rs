//! X3 CPU-only synthetic non-GPT operations pack.
//!
//! This is a runtime-shaped sibling of the X2 fixture.  It deliberately
//! keeps `volta-proto` model agnostic and reuses the existing GEMM, LUT and
//! band representations.  The independent numpy twin lives in
//! `scripts/x123_export.py`; [`encode_x3_golden`] is compared byte-for-byte
//! with its checked-in output.

use crate::block_proof::{x3_clamp_table, x3_silu_table};
use volta_gpt2::{
    build_luts, gemm_i64, ActivationKind, AttentionMode, ConfigBinding, ExpertBlockShifts,
    LayerShiftSchedule, LutParams, Luts, ModelConfig, NonlinearTableConfig, NormKind, RopeConfig,
    RouterTieRule,
};

pub const X3_T: usize = 7;
pub const X3_T_PAD: usize = 8;
pub const X3_LAYERS: usize = 2;
pub const X3_D: usize = 48;
pub const X3_D_PAD: usize = 64;
pub const X3_DFF: usize = 80;
pub const X3_DFF_PAD: usize = 128;
pub const X3_Q_HEADS: usize = 6;
pub const X3_KV_HEADS: usize = 2;
pub const X3_GQA_GROUP: usize = 3;
pub const X3_HEAD_DIM: usize = 8;
pub const X3_QKV: usize = X3_D + 2 * X3_KV_HEADS * X3_HEAD_DIM;
pub const X3_EXPERTS: usize = 8;
pub const X3_TOP_K: usize = 2;
pub const X3_VOCAB: usize = 97;
pub const X3_VOCAB_PAD: usize = 128;
pub const X3_SHIFT: u32 = 8;
pub const X3_SILU_SHIFT: u32 = 10;
pub const X3_ROPE_FRAC: u32 = 14;
pub const X3_SCORE_SHIFT: u32 = X3_SHIFT + X3_ROPE_FRAC;
pub const X3_CLAMP_MIN: i16 = -1024;
pub const X3_CLAMP_MAX: i16 = 1024;
pub const X3_SINKS: usize = 2;

const X3_ROUTES_0: [[u8; X3_TOP_K]; X3_T] =
    [[0, 1], [2, 3], [4, 5], [6, 7], [0, 2], [1, 4], [3, 5]];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X3PadMode {
    CanonicalizePoison,
    AdmitPoison,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3RmsWitness {
    pub input: Vec<i16>,
    pub sum_squares: Vec<i64>,
    pub mean_square: Vec<i64>,
    pub rsqrt_in: Vec<i16>,
    pub rsqrt_out: Vec<i16>,
    pub acc: Vec<i64>,
    pub output: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3ExpertWeights {
    pub gate: Vec<i16>,
    pub up: Vec<i16>,
    pub down: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3LayerWeights {
    pub qkv: Vec<i16>,
    pub attention: Vec<i16>,
    pub experts: Vec<X3ExpertWeights>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3ExpertWitness {
    pub rows: Vec<(usize, usize)>,
    pub gathered: Vec<i16>,
    pub gate_acc: Vec<i64>,
    pub gate_q: Vec<i16>,
    pub gate_clamped: Vec<i16>,
    pub up_acc: Vec<i64>,
    pub up_q: Vec<i16>,
    pub up_clamped: Vec<i16>,
    pub silu: Vec<i16>,
    pub product_acc: Vec<i64>,
    pub product_q: Vec<i16>,
    pub down_acc: Vec<i64>,
    pub down_q: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3AttentionWitness {
    pub rms1: X3RmsWitness,
    pub qkv_acc: Vec<i64>,
    pub qkv: Vec<i16>,
    pub q: Vec<i16>,
    pub k: Vec<i16>,
    pub v: Vec<i16>,
    pub lo: Vec<u32>,
    pub hi: Vec<u32>,
    /// head-major 6 x 8 x 8 physical rectangle.
    pub real_mask: Vec<u8>,
    /// Real-cell order: head, query row, key row, then head coordinate.
    pub grouped_k_reads: Vec<i16>,
    pub grouped_v_reads: Vec<i16>,
    pub rope_folded_k: Vec<i64>,
    pub rope_pair_terms: Vec<i64>,
    pub score_acc_rect: Vec<i64>,
    pub score_acc_real: Vec<i64>,
    /// Physical rectangle; non-real cells contain the canonical Exp zero input.
    pub score_q_rect: Vec<i16>,
    pub score_q_real: Vec<i16>,
    pub exp_rect: Vec<i16>,
    pub sink_scores: Vec<i16>,
    pub sink_exp: Vec<i16>,
    pub denoms: Vec<i64>,
    pub recip_in: Vec<i16>,
    pub recips: Vec<i16>,
    pub norm_acc_rect: Vec<i64>,
    pub weights_rect: Vec<i16>,
    pub av_acc: Vec<i64>,
    pub av_q: Vec<i16>,
    pub projection_acc: Vec<i64>,
    pub projection_q: Vec<i16>,
    pub output: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3LayerWitness {
    pub input: Vec<i16>,
    pub attention: X3AttentionWitness,
    pub rms2: X3RmsWitness,
    pub routes: Vec<[u8; X3_TOP_K]>,
    pub route_weights: Vec<i16>,
    pub experts: Vec<X3ExpertWitness>,
    pub route_values: Vec<i16>,
    pub combine_acc: Vec<i64>,
    pub combine_q: Vec<i16>,
    pub output: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3FinalWitness {
    pub rms: X3RmsWitness,
    pub logits: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3ClampProbe {
    pub gate_in: Vec<i16>,
    pub up_in: Vec<i16>,
    pub gate_clamped: Vec<i16>,
    pub up_clamped: Vec<i16>,
    pub silu: Vec<i16>,
    pub product_acc: Vec<i64>,
    pub product_q: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3OpsFixture {
    pub config: ModelConfig,
    pub luts: Luts,
    pub rope_coefficients: Vec<i16>,
    pub tokens: Vec<u16>,
    pub wte: Vec<i16>,
    pub wpe: Vec<i16>,
    /// Deliberately nonzero source pads.  They are never logical witness data.
    pub source_padding: Vec<i16>,
    /// Honest construction zeros this vector; the malicious poison run admits
    /// `source_padding` here and must be rejected by the proof.
    pub canonical_padding: Vec<i16>,
    pub embedding_acc: Vec<i64>,
    pub embedding_out: Vec<i16>,
    pub weights: Vec<X3LayerWeights>,
    pub layers: Vec<X3LayerWitness>,
    pub seam_acc: Vec<i64>,
    pub seam_out: Vec<i16>,
    pub output_weight: Vec<i16>,
    pub final_witness: X3FinalWitness,
    pub clamp_probe: X3ClampProbe,
}

fn checked_requant(acc: i64, shift: u32, label: &str) -> i16 {
    // P5 fixes shifts above 16 as two round-half-up stages so each
    // remainder stays inside an existing <=16-bit range table.
    let rounded = if shift > 16 {
        let stage1_shift = shift - 16;
        let stage1 = (acc + (1i64 << (stage1_shift - 1))) >> stage1_shift;
        (stage1 + (1i64 << 15)) >> 16
    } else {
        (acc + (1i64 << (shift - 1))) >> shift
    };
    assert!(
        (i16::MIN as i64..=i16::MAX as i64).contains(&rounded),
        "X3 {label} requant overflow: acc={acc}, shift={shift}"
    );
    rounded as i16
}

fn x3_lut_params() -> LutParams {
    LutParams {
        recip_log2: 22,
        shift_ln_norm: X3_SHIFT,
        shift_qkv: X3_SHIFT,
        shift_scores: X3_SCORE_SHIFT,
        shift_softmax_norm: X3_SHIFT,
        shift_av: X3_SHIFT,
        shift_attn_proj: X3_SHIFT,
        shift_ffn_up: X3_SHIFT,
        shift_ffn_down: X3_SHIFT,
        softmax_row_shift: false,
        ..LutParams::default()
    }
}

fn nonlinear_config(params: LutParams) -> NonlinearTableConfig {
    NonlinearTableConfig {
        ln_var_shift: params.ln_var_shift,
        ln_rsqrt_log2: params.ln_rsqrt_log2,
        exp_in_log2: params.exp_in_log2,
        exp_out_log2: params.exp_out_log2,
        recip_den_shift: params.recip_den_shift,
        recip_log2: params.recip_log2,
        gelu_scale_log2: X3_SILU_SHIFT,
        softmax_row_shift: params.softmax_row_shift,
    }
}

/// Q14 `(cos, sin)` entries for relative positions -6..=6 and four
/// even/odd pairs.  This is the complete public table used by the T=7 spike.
pub fn x3_rope_coefficients() -> Vec<i16> {
    let mut out = Vec::with_capacity(13 * (X3_HEAD_DIM / 2) * 2);
    for delta in -6i32..=6 {
        for pair in 0..X3_HEAD_DIM / 2 {
            let frequency = 10_000f64.powf(-((2 * pair) as f64) / X3_HEAD_DIM as f64);
            let angle = f64::from(delta) * frequency;
            for value in [angle.cos(), angle.sin()] {
                out.push((value * f64::from(1u32 << X3_ROPE_FRAC)).round() as i16);
            }
        }
    }
    out
}

fn rope_coeff(coeffs: &[i16], delta: isize, pair: usize) -> (i16, i16) {
    assert!((-6..=6).contains(&delta));
    let index = ((delta + 6) as usize * (X3_HEAD_DIM / 2) + pair) * 2;
    (coeffs[index], coeffs[index + 1])
}

pub fn x3_model_config() -> ModelConfig {
    let params = x3_lut_params();
    let coefficients = x3_rope_coefficients();
    let mut coefficient_bytes = Vec::with_capacity(coefficients.len() * 2);
    for value in &coefficients {
        coefficient_bytes.extend_from_slice(&value.to_le_bytes());
    }
    let layer = LayerShiftSchedule {
        layer_norm: X3_SHIFT,
        qkv: X3_SHIFT,
        scores: X3_SCORE_SHIFT,
        softmax_norm: X3_SHIFT,
        av: X3_SHIFT,
        attention_out: X3_SHIFT,
        ffn_up: X3_SHIFT,
        ffn_down: X3_SHIFT,
        residual_seam: X3_SHIFT,
        router_requant: X3_SHIFT,
        router_norm: X3_SHIFT,
        expert_blocks: vec![ExpertBlockShifts { gate_up: X3_SHIFT, down: X3_SHIFT }; X3_EXPERTS],
        ..LayerShiftSchedule::default()
    };
    let config = ModelConfig {
        schema_version: volta_gpt2::config::MODEL_CONFIG_SCHEMA,
        model_id: "volta-x3-moe-ops-v1".to_owned(),
        binding: ConfigBinding::DigestV1,
        vocab_size: X3_VOCAB,
        max_positions: X3_T,
        tied_output: false,
        n_layers: X3_LAYERS,
        d_model: X3_D,
        d_ff: X3_DFF,
        n_q_heads: X3_Q_HEADS,
        n_kv_heads: X3_KV_HEADS,
        head_dim: X3_HEAD_DIM,
        n_experts: X3_EXPERTS,
        top_k: X3_TOP_K,
        attention: vec![AttentionMode::FullCausal, AttentionMode::Sliding { window: 4 }],
        norm: NormKind::RmsNorm,
        activation: ActivationKind::SwiGlu { clamp_min: X3_CLAMP_MIN, clamp_max: X3_CLAMP_MAX },
        attention_sinks_per_q_head: X3_SINKS,
        rope: Some(RopeConfig {
            rotary_dim: X3_HEAD_DIM,
            base_num: 10_000,
            base_den: 1,
            frequency_scale_num: 1,
            frequency_scale_den: 1,
            coefficient_fraction_bits: X3_ROPE_FRAC,
            coefficient_table_digest: *blake3::hash(&coefficient_bytes).as_bytes(),
        }),
        nonlinear_tables: nonlinear_config(params),
        embedding_shift: X3_SHIFT as i32,
        final_norm_shift: X3_SHIFT,
        layer_shifts: vec![layer; X3_LAYERS],
        thin_k: 2,
        router_tie_rule: RouterTieRule::ScoreThenHigherExpertId,
    };
    config.validate().expect("pinned X3 runtime config must validate");
    config
}

fn routes_for_layer(layer: usize) -> Vec<[u8; X3_TOP_K]> {
    X3_ROUTES_0
        .iter()
        .map(|route| {
            [
                ((usize::from(route[0]) + layer) % X3_EXPERTS) as u8,
                ((usize::from(route[1]) + layer) % X3_EXPERTS) as u8,
            ]
        })
        .collect()
}

pub fn x3_public_routes() -> Vec<Vec<[u8; X3_TOP_K]>> {
    (0..X3_LAYERS).map(routes_for_layer).collect()
}

fn sparse_projection(rows: usize, cols: usize, salt: usize, magnitude: i16) -> Vec<i16> {
    let mut out = vec![0i16; rows * cols];
    for col in 0..cols {
        let row = (col * (salt * 2 + 1) + salt) % rows;
        let sign = if (col + salt) & 1 == 0 { 1 } else { -1 };
        out[row * cols + col] = sign * magnitude;
        let row2 = (row + 7 + salt) % rows;
        out[row2 * cols + col] = -sign;
    }
    out
}

fn expert_weights(layer: usize, expert: usize) -> X3ExpertWeights {
    let salt = 1 + 3 * layer + expert;
    X3ExpertWeights {
        gate: sparse_projection(X3_D, X3_DFF, salt, 96),
        up: sparse_projection(X3_D, X3_DFF, salt + 5, 112),
        down: sparse_projection(X3_DFF, X3_D, salt + 11, 2),
    }
}

fn layer_weights(layer: usize) -> X3LayerWeights {
    X3LayerWeights {
        qkv: sparse_projection(X3_D, X3_QKV, 3 + layer, 2),
        attention: sparse_projection(X3_D, X3_D, 7 + layer, 2),
        experts: (0..X3_EXPERTS).map(|expert| expert_weights(layer, expert)).collect(),
    }
}

fn embedding_weights() -> (Vec<i16>, Vec<i16>) {
    let mut wte = vec![0i16; X3_VOCAB * X3_D];
    for token in 0..X3_VOCAB {
        wte[token * X3_D + X3_D - 1] = ((token * 3 + 1) % 7) as i16 - 3;
    }
    for token in 0..X3_T {
        wte[token * X3_D + token] = 1_024;
    }
    let wpe = (0..X3_T * X3_D).map(|index| ((index * 5 + 3) % 9) as i16 - 4).collect();
    (wte, wpe)
}

fn poisoned_padding() -> Vec<i16> {
    // time row, wpe row, hidden-column pads, FFN pads, vocabulary pads.
    let count = X3_D_PAD
        + X3_D_PAD
        + X3_T_PAD * (X3_D_PAD - X3_D)
        + X3_T_PAD * (X3_DFF_PAD - X3_DFF)
        + (X3_VOCAB_PAD - X3_VOCAB) * X3_D_PAD;
    (0..count).map(|index| 1_001 + index as i16).collect()
}

fn rmsnorm(input: &[i16], rows: usize, luts: &Luts) -> X3RmsWitness {
    assert_eq!(input.len(), rows * X3_D);
    let mut sum_squares = Vec::with_capacity(rows);
    let mut mean_square = Vec::with_capacity(rows);
    let mut rsqrt_in = Vec::with_capacity(rows);
    let mut rsqrt_out = Vec::with_capacity(rows);
    let mut acc = Vec::with_capacity(input.len());
    let mut output = Vec::with_capacity(input.len());
    for row in 0..rows {
        let source = &input[row * X3_D..(row + 1) * X3_D];
        let sum: i64 = source.iter().map(|&value| i64::from(value) * i64::from(value)).sum();
        let mean = (sum + X3_D as i64 / 2).div_euclid(X3_D as i64);
        let rin = mean >> luts.params.ln_var_shift;
        assert!((0..1 << 16).contains(&rin), "X3 RMS rsqrt input overflow");
        let rout = luts.ln_rsqrt[rin as usize];
        sum_squares.push(sum);
        mean_square.push(mean);
        rsqrt_in.push(rin as i16);
        rsqrt_out.push(rout);
        for &value in source {
            let product = i64::from(value) * i64::from(rout);
            acc.push(product);
            output.push(checked_requant(product, X3_SHIFT, "RMSNorm"));
        }
    }
    X3RmsWitness {
        input: input.to_vec(),
        sum_squares,
        mean_square,
        rsqrt_in,
        rsqrt_out,
        acc,
        output,
    }
}

fn exp_zero_input(luts: &Luts) -> i16 {
    luts.exp.iter().position(|&value| value == 0).expect("Exp table has a zero pad") as u16 as i16
}

fn split_qkv(values: &[i16]) -> (Vec<i16>, Vec<i16>, Vec<i16>) {
    let mut q = Vec::with_capacity(X3_T * X3_D);
    let mut k = Vec::with_capacity(X3_T * X3_KV_HEADS * X3_HEAD_DIM);
    let mut v = Vec::with_capacity(X3_T * X3_KV_HEADS * X3_HEAD_DIM);
    for row in 0..X3_T {
        let base = row * X3_QKV;
        q.extend_from_slice(&values[base..base + X3_D]);
        k.extend_from_slice(&values[base + X3_D..base + X3_D + 16]);
        v.extend_from_slice(&values[base + X3_D + 16..base + X3_QKV]);
    }
    (q, k, v)
}

fn attention(
    input: &[i16],
    layer: usize,
    weights: &X3LayerWeights,
    luts: &Luts,
    rope_coefficients: &[i16],
) -> X3AttentionWitness {
    let rms1 = rmsnorm(input, X3_T, luts);
    let qkv_acc = gemm_i64(&rms1.output, &weights.qkv, X3_T, X3_D, X3_QKV);
    let qkv: Vec<i16> =
        qkv_acc.iter().map(|&value| checked_requant(value, X3_SHIFT, "QKV")).collect();
    let (q, k, v) = split_qkv(&qkv);
    let lo: Vec<u32> = (0..X3_T)
        .map(|row| if layer == 0 { 0 } else { (row + 1).saturating_sub(4) } as u32)
        .collect();
    let hi: Vec<u32> = (0..X3_T).map(|row| (row + 1) as u32).collect();
    let rect_len = X3_Q_HEADS * X3_T_PAD * X3_T_PAD;
    let mut real_mask = vec![0u8; rect_len];
    let mut score_acc_rect = vec![0i64; rect_len];
    let pad_score = exp_zero_input(luts);
    let mut score_q_rect = vec![pad_score; rect_len];
    let mut exp_rect = vec![0i16; rect_len];
    let mut grouped_k_reads = Vec::new();
    let mut grouped_v_reads = Vec::new();
    let mut rope_folded_k = Vec::new();
    let mut rope_pair_terms = Vec::new();
    let mut score_acc_real = Vec::new();
    let mut score_q_real = Vec::new();

    for head in 0..X3_Q_HEADS {
        let kv_head = head / X3_GQA_GROUP;
        for row in 0..X3_T {
            for key_row in lo[row] as usize..hi[row] as usize {
                let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + key_row;
                real_mask[rect] = 1;
                let delta = key_row as isize - row as isize;
                let mut score = 0i64;
                for pair in 0..X3_HEAD_DIM / 2 {
                    let (cos, sin) = rope_coeff(rope_coefficients, delta, pair);
                    let q_base = row * X3_D + head * X3_HEAD_DIM + 2 * pair;
                    let kv_base =
                        key_row * (X3_KV_HEADS * X3_HEAD_DIM) + kv_head * X3_HEAD_DIM + 2 * pair;
                    let (qe, qo) = (q[q_base], q[q_base + 1]);
                    let (ke, ko) = (k[kv_base], k[kv_base + 1]);
                    let kfe = i64::from(ke) * i64::from(cos) - i64::from(ko) * i64::from(sin);
                    let kfo = i64::from(ke) * i64::from(sin) + i64::from(ko) * i64::from(cos);
                    let te = i64::from(qe) * kfe;
                    let to = i64::from(qo) * kfo;
                    grouped_k_reads.extend_from_slice(&[ke, ko]);
                    grouped_v_reads.extend_from_slice(&v[kv_base..kv_base + 2]);
                    rope_folded_k.extend_from_slice(&[kfe, kfo]);
                    rope_pair_terms.extend_from_slice(&[te, to]);
                    score += te + to;
                }
                let quantized = checked_requant(score, X3_SCORE_SHIFT, "RoPE score");
                score_acc_rect[rect] = score;
                score_q_rect[rect] = quantized;
                exp_rect[rect] = luts.exp[quantized as u16 as usize];
                score_acc_real.push(score);
                score_q_real.push(quantized);
            }
        }
    }

    let mut sink_scores = Vec::with_capacity(X3_Q_HEADS * X3_T * X3_SINKS);
    let mut sink_exp = Vec::with_capacity(sink_scores.capacity());
    let mut denoms = vec![0i64; X3_Q_HEADS * X3_T];
    let mut recip_in = vec![0i16; X3_Q_HEADS * X3_T];
    let mut recips = vec![0i16; X3_Q_HEADS * X3_T];
    for head in 0..X3_Q_HEADS {
        for row in 0..X3_T {
            let mut denom = 0i64;
            for key_row in lo[row] as usize..hi[row] as usize {
                let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + key_row;
                denom += i64::from(exp_rect[rect]);
            }
            for sink in 0..X3_SINKS {
                let score = ((3 * layer + 2 * head + sink) as i16 - 6) * 16;
                let exp = luts.exp[score as u16 as usize];
                sink_scores.push(score);
                sink_exp.push(exp);
                denom += i64::from(exp);
            }
            let index = head * X3_T + row;
            denoms[index] = denom;
            let rin = denom >> luts.params.recip_den_shift;
            assert!((0..1 << 16).contains(&rin));
            recip_in[index] = rin as i16;
            recips[index] = luts.softmax_recip[rin as usize];
        }
    }

    let mut norm_acc_rect = vec![0i64; rect_len];
    let mut weights_rect = vec![0i16; rect_len];
    for head in 0..X3_Q_HEADS {
        for row in 0..X3_T {
            let reciprocal = recips[head * X3_T + row];
            for key_row in lo[row] as usize..hi[row] as usize {
                let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + key_row;
                let acc = i64::from(exp_rect[rect]) * i64::from(reciprocal);
                norm_acc_rect[rect] = acc;
                weights_rect[rect] = checked_requant(acc, X3_SHIFT, "softmax weight");
            }
        }
    }

    let mut av_acc = vec![0i64; X3_T * X3_D];
    let mut av_q = vec![0i16; X3_T * X3_D];
    for head in 0..X3_Q_HEADS {
        let kv_head = head / X3_GQA_GROUP;
        for row in 0..X3_T {
            for dim in 0..X3_HEAD_DIM {
                let mut acc = 0i64;
                for key_row in lo[row] as usize..hi[row] as usize {
                    let rect = head * X3_T_PAD * X3_T_PAD + row * X3_T_PAD + key_row;
                    let v_index =
                        key_row * (X3_KV_HEADS * X3_HEAD_DIM) + kv_head * X3_HEAD_DIM + dim;
                    acc += i64::from(weights_rect[rect]) * i64::from(v[v_index]);
                }
                let out_index = row * X3_D + head * X3_HEAD_DIM + dim;
                av_acc[out_index] = acc;
                av_q[out_index] = checked_requant(acc, X3_SHIFT, "AV");
            }
        }
    }
    let projection_acc = gemm_i64(&av_q, &weights.attention, X3_T, X3_D, X3_D);
    let projection_q: Vec<i16> = projection_acc
        .iter()
        .map(|&value| checked_requant(value, X3_SHIFT, "attention projection"))
        .collect();
    let output: Vec<i16> = input
        .iter()
        .zip(&projection_q)
        .map(|(&left, &right)| {
            let value = i32::from(left) + i32::from(right);
            assert!((i16::MIN as i32..=i16::MAX as i32).contains(&value));
            value as i16
        })
        .collect();
    X3AttentionWitness {
        rms1,
        qkv_acc,
        qkv,
        q,
        k,
        v,
        lo,
        hi,
        real_mask,
        grouped_k_reads,
        grouped_v_reads,
        rope_folded_k,
        rope_pair_terms,
        score_acc_rect,
        score_acc_real,
        score_q_rect,
        score_q_real,
        exp_rect,
        sink_scores,
        sink_exp,
        denoms,
        recip_in,
        recips,
        norm_acc_rect,
        weights_rect,
        av_acc,
        av_q,
        projection_acc,
        projection_q,
        output,
    }
}

fn build_experts(
    input: &[i16],
    routes: &[[u8; X3_TOP_K]],
    weights: &[X3ExpertWeights],
    silu_table: &[i16],
    clamp_table: &[i16],
) -> (Vec<X3ExpertWitness>, Vec<i16>) {
    let mut jobs: Vec<Vec<(usize, usize)>> = vec![Vec::new(); X3_EXPERTS];
    for (token, route) in routes.iter().enumerate() {
        for (slot, &expert) in route.iter().enumerate() {
            jobs[usize::from(expert)].push((token, slot));
        }
    }
    let mut route_values = vec![0i16; X3_T * X3_TOP_K * X3_D];
    let mut witnesses = Vec::with_capacity(X3_EXPERTS);
    for expert in 0..X3_EXPERTS {
        let rows = jobs[expert].clone();
        assert!(!rows.is_empty());
        let mut gathered = Vec::with_capacity(rows.len() * X3_D);
        for &(token, _) in &rows {
            gathered.extend_from_slice(&input[token * X3_D..(token + 1) * X3_D]);
        }
        let gate_acc = gemm_i64(&gathered, &weights[expert].gate, rows.len(), X3_D, X3_DFF);
        let gate_q: Vec<i16> =
            gate_acc.iter().map(|&value| checked_requant(value, X3_SHIFT, "expert gate")).collect();
        let up_acc = gemm_i64(&gathered, &weights[expert].up, rows.len(), X3_D, X3_DFF);
        let up_q: Vec<i16> =
            up_acc.iter().map(|&value| checked_requant(value, X3_SHIFT, "expert up")).collect();
        let gate_clamped: Vec<i16> =
            gate_q.iter().map(|&value| clamp_table[value as u16 as usize]).collect();
        let up_clamped: Vec<i16> =
            up_q.iter().map(|&value| clamp_table[value as u16 as usize]).collect();
        let silu: Vec<i16> =
            gate_clamped.iter().map(|&value| silu_table[value as u16 as usize]).collect();
        let product_acc: Vec<i64> = silu
            .iter()
            .zip(&up_clamped)
            .map(|(&left, &right)| i64::from(left) * i64::from(right))
            .collect();
        let product_q: Vec<i16> = product_acc
            .iter()
            .map(|&value| checked_requant(value, X3_SILU_SHIFT, "SwiGLU product"))
            .collect();
        let down_acc = gemm_i64(&product_q, &weights[expert].down, rows.len(), X3_DFF, X3_D);
        let down_q: Vec<i16> =
            down_acc.iter().map(|&value| checked_requant(value, X3_SHIFT, "expert down")).collect();
        for (job_row, &(token, slot)) in rows.iter().enumerate() {
            let destination = (token * X3_TOP_K + slot) * X3_D;
            route_values[destination..destination + X3_D]
                .copy_from_slice(&down_q[job_row * X3_D..(job_row + 1) * X3_D]);
        }
        witnesses.push(X3ExpertWitness {
            rows,
            gathered,
            gate_acc,
            gate_q,
            gate_clamped,
            up_acc,
            up_q,
            up_clamped,
            silu,
            product_acc,
            product_q,
            down_acc,
            down_q,
        });
    }
    (witnesses, route_values)
}

fn clamp_probe(silu_table: &[i16], clamp_table: &[i16]) -> X3ClampProbe {
    let gate_in = vec![-2048, -1025, -1024, -17, 0, 23, 1024, 1025, 2048];
    let up_in = vec![2048, 1025, 1024, 23, 0, -17, -1024, -1025, -2048];
    let gate_clamped: Vec<_> =
        gate_in.iter().map(|&value| clamp_table[value as u16 as usize]).collect();
    let up_clamped: Vec<_> =
        up_in.iter().map(|&value| clamp_table[value as u16 as usize]).collect();
    let silu: Vec<_> =
        gate_clamped.iter().map(|&value| silu_table[value as u16 as usize]).collect();
    let product_acc: Vec<_> = silu
        .iter()
        .zip(&up_clamped)
        .map(|(&left, &right)| i64::from(left) * i64::from(right))
        .collect();
    let product_q = product_acc
        .iter()
        .map(|&value| checked_requant(value, X3_SILU_SHIFT, "clamp probe product"))
        .collect();
    X3ClampProbe { gate_in, up_in, gate_clamped, up_clamped, silu, product_acc, product_q }
}

pub fn build_x3_ops_fixture(pad_mode: X3PadMode) -> X3OpsFixture {
    let config = x3_model_config();
    let params = x3_lut_params();
    let luts = build_luts(params);
    let silu_table = x3_silu_table();
    let clamp_table = x3_clamp_table();
    let rope_coefficients = x3_rope_coefficients();
    let tokens: Vec<u16> = (0..X3_T as u16).collect();
    let (wte, wpe) = embedding_weights();
    let source_padding = poisoned_padding();
    assert!(source_padding.iter().all(|&value| value != 0));
    let canonical_padding = match pad_mode {
        X3PadMode::CanonicalizePoison => vec![0; source_padding.len()],
        X3PadMode::AdmitPoison => source_padding.clone(),
    };
    let mut embedding_acc = Vec::with_capacity(X3_T * X3_D);
    for row in 0..X3_T {
        for col in 0..X3_D {
            let value = i64::from(wte[usize::from(tokens[row]) * X3_D + col])
                + i64::from(wpe[row * X3_D + col]);
            embedding_acc.push(value << X3_SHIFT);
        }
    }
    let embedding_out = embedding_acc
        .iter()
        .map(|&value| checked_requant(value, X3_SHIFT, "embedding"))
        .collect::<Vec<_>>();
    let weights: Vec<_> = (0..X3_LAYERS).map(layer_weights).collect();
    let mut layers = Vec::with_capacity(X3_LAYERS);
    let mut current = embedding_out.clone();
    let mut seam_acc = Vec::new();
    let mut seam_out = Vec::new();
    for layer in 0..X3_LAYERS {
        let attention = attention(&current, layer, &weights[layer], &luts, &rope_coefficients);
        let rms2 = rmsnorm(&attention.output, X3_T, &luts);
        let routes = routes_for_layer(layer);
        let route_weights = vec![128i16; X3_T * X3_TOP_K];
        let (experts, route_values) = build_experts(
            &rms2.output,
            &routes,
            &weights[layer].experts,
            &silu_table,
            &clamp_table,
        );
        let mut combine_acc = vec![0i64; X3_T * X3_D];
        let mut combine_q = vec![0i16; X3_T * X3_D];
        let mut output = vec![0i16; X3_T * X3_D];
        for token in 0..X3_T {
            for col in 0..X3_D {
                let mut acc = i64::from(attention.projection_q[token * X3_D + col]) << X3_SHIFT;
                for slot in 0..X3_TOP_K {
                    acc += i64::from(route_weights[token * X3_TOP_K + slot])
                        * i64::from(route_values[(token * X3_TOP_K + slot) * X3_D + col]);
                }
                let index = token * X3_D + col;
                combine_acc[index] = acc;
                combine_q[index] = checked_requant(acc, X3_SHIFT, "MoE combine");
                let residual = i32::from(current[index]) + i32::from(combine_q[index]);
                assert!((i16::MIN as i32..=i16::MAX as i32).contains(&residual));
                output[index] = residual as i16;
            }
        }
        layers.push(X3LayerWitness {
            input: current.clone(),
            attention,
            rms2,
            routes,
            route_weights,
            experts,
            route_values,
            combine_acc,
            combine_q,
            output: output.clone(),
        });
        if layer + 1 < X3_LAYERS {
            seam_acc = output.iter().map(|&value| i64::from(value) << X3_SHIFT).collect();
            seam_out = seam_acc
                .iter()
                .map(|&value| checked_requant(value, X3_SHIFT, "residual seam"))
                .collect();
            current = seam_out.clone();
        } else {
            current = output;
        }
    }
    let output_weight = sparse_projection(X3_D, X3_VOCAB, 19, 2);
    let final_input = current[(X3_T - 1) * X3_D..X3_T * X3_D].to_vec();
    let final_rms = rmsnorm(&final_input, 1, &luts);
    let logits = gemm_i64(&final_rms.output, &output_weight, 1, X3_D, X3_VOCAB);
    let final_witness = X3FinalWitness { rms: final_rms, logits };
    let clamp_probe = clamp_probe(&silu_table, &clamp_table);
    X3OpsFixture {
        config,
        luts,
        rope_coefficients,
        tokens,
        wte,
        wpe,
        source_padding,
        canonical_padding,
        embedding_acc,
        embedding_out,
        weights,
        layers,
        seam_acc,
        seam_out,
        output_weight,
        final_witness,
        clamp_probe,
    }
}

fn put_u8(out: &mut Vec<u8>, values: &[u8]) {
    out.extend_from_slice(values);
}

fn put_i16(out: &mut Vec<u8>, values: &[i16]) {
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_u16(out: &mut Vec<u8>, values: &[u16]) {
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_u32(out: &mut Vec<u8>, values: &[u32]) {
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_i64(out: &mut Vec<u8>, values: &[i64]) {
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_rms(out: &mut Vec<u8>, rms: &X3RmsWitness) {
    put_i16(out, &rms.input);
    put_i64(out, &rms.sum_squares);
    put_i64(out, &rms.mean_square);
    put_i16(out, &rms.rsqrt_in);
    put_i16(out, &rms.rsqrt_out);
    put_i64(out, &rms.acc);
    put_i16(out, &rms.output);
}

/// Canonical full-array encoding mirrored independently by numpy.
pub fn encode_x3_golden(fixture: &X3OpsFixture) -> Vec<u8> {
    let mut out = b"VOLTA-X3-GOLD-V1".to_vec();
    for value in [
        X3_T as u32,
        X3_T_PAD as u32,
        X3_LAYERS as u32,
        X3_D as u32,
        X3_D_PAD as u32,
        X3_DFF as u32,
        X3_DFF_PAD as u32,
        X3_Q_HEADS as u32,
        X3_KV_HEADS as u32,
        X3_HEAD_DIM as u32,
        X3_EXPERTS as u32,
        X3_TOP_K as u32,
        X3_VOCAB as u32,
        X3_VOCAB_PAD as u32,
        X3_SHIFT,
        X3_SILU_SHIFT,
        X3_ROPE_FRAC,
        X3_SCORE_SHIFT,
        X3_SINKS as u32,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    put_i16(&mut out, &fixture.rope_coefficients);
    out.extend_from_slice(&(fixture.source_padding.len() as u32).to_le_bytes());
    put_i16(&mut out, &fixture.source_padding);
    put_i16(&mut out, &fixture.canonical_padding);
    put_u16(&mut out, &fixture.tokens);
    put_i16(&mut out, &fixture.wte);
    put_i16(&mut out, &fixture.wpe);
    put_i64(&mut out, &fixture.embedding_acc);
    put_i16(&mut out, &fixture.embedding_out);
    for (weights, layer) in fixture.weights.iter().zip(&fixture.layers) {
        put_i16(&mut out, &weights.qkv);
        put_i16(&mut out, &weights.attention);
        for expert in &weights.experts {
            put_i16(&mut out, &expert.gate);
            put_i16(&mut out, &expert.up);
            put_i16(&mut out, &expert.down);
        }
        put_i16(&mut out, &layer.input);
        put_rms(&mut out, &layer.attention.rms1);
        put_i64(&mut out, &layer.attention.qkv_acc);
        put_i16(&mut out, &layer.attention.qkv);
        put_i16(&mut out, &layer.attention.q);
        put_i16(&mut out, &layer.attention.k);
        put_i16(&mut out, &layer.attention.v);
        put_u32(&mut out, &layer.attention.lo);
        put_u32(&mut out, &layer.attention.hi);
        put_u8(&mut out, &layer.attention.real_mask);
        put_i16(&mut out, &layer.attention.grouped_k_reads);
        put_i16(&mut out, &layer.attention.grouped_v_reads);
        put_i64(&mut out, &layer.attention.rope_folded_k);
        put_i64(&mut out, &layer.attention.rope_pair_terms);
        put_i64(&mut out, &layer.attention.score_acc_rect);
        put_i64(&mut out, &layer.attention.score_acc_real);
        put_i16(&mut out, &layer.attention.score_q_rect);
        put_i16(&mut out, &layer.attention.score_q_real);
        put_i16(&mut out, &layer.attention.exp_rect);
        put_i16(&mut out, &layer.attention.sink_scores);
        put_i16(&mut out, &layer.attention.sink_exp);
        put_i64(&mut out, &layer.attention.denoms);
        put_i16(&mut out, &layer.attention.recip_in);
        put_i16(&mut out, &layer.attention.recips);
        put_i64(&mut out, &layer.attention.norm_acc_rect);
        put_i16(&mut out, &layer.attention.weights_rect);
        put_i64(&mut out, &layer.attention.av_acc);
        put_i16(&mut out, &layer.attention.av_q);
        put_i64(&mut out, &layer.attention.projection_acc);
        put_i16(&mut out, &layer.attention.projection_q);
        put_i16(&mut out, &layer.attention.output);
        put_rms(&mut out, &layer.rms2);
        for route in &layer.routes {
            put_u8(&mut out, route);
        }
        put_i16(&mut out, &layer.route_weights);
        for expert in &layer.experts {
            out.extend_from_slice(&(expert.rows.len() as u32).to_le_bytes());
            for &(token, slot) in &expert.rows {
                put_u8(&mut out, &[token as u8, slot as u8]);
            }
            put_i16(&mut out, &expert.gathered);
            put_i64(&mut out, &expert.gate_acc);
            put_i16(&mut out, &expert.gate_q);
            put_i16(&mut out, &expert.gate_clamped);
            put_i64(&mut out, &expert.up_acc);
            put_i16(&mut out, &expert.up_q);
            put_i16(&mut out, &expert.up_clamped);
            put_i16(&mut out, &expert.silu);
            put_i64(&mut out, &expert.product_acc);
            put_i16(&mut out, &expert.product_q);
            put_i64(&mut out, &expert.down_acc);
            put_i16(&mut out, &expert.down_q);
        }
        put_i16(&mut out, &layer.route_values);
        put_i64(&mut out, &layer.combine_acc);
        put_i16(&mut out, &layer.combine_q);
        put_i16(&mut out, &layer.output);
    }
    put_i64(&mut out, &fixture.seam_acc);
    put_i16(&mut out, &fixture.seam_out);
    put_i16(&mut out, &fixture.output_weight);
    put_rms(&mut out, &fixture.final_witness.rms);
    put_i64(&mut out, &fixture.final_witness.logits);
    put_i16(&mut out, &fixture.clamp_probe.gate_in);
    put_i16(&mut out, &fixture.clamp_probe.up_in);
    put_i16(&mut out, &fixture.clamp_probe.gate_clamped);
    put_i16(&mut out, &fixture.clamp_probe.up_clamped);
    put_i16(&mut out, &fixture.clamp_probe.silu);
    put_i64(&mut out, &fixture.clamp_probe.product_acc);
    put_i16(&mut out, &fixture.clamp_probe.product_q);
    out
}

pub fn x3_native_operation_counts(fixture: &X3OpsFixture) -> Vec<(&'static str, u64)> {
    let mut qkv = 0u64;
    let mut qk = 0u64;
    let mut av = 0u64;
    let mut attention_out = 0u64;
    let mut expert_gate_up = 0u64;
    let mut expert_down = 0u64;
    for layer in &fixture.layers {
        qkv += (X3_T * X3_D * X3_QKV) as u64;
        qk += (layer.attention.score_acc_real.len() * X3_HEAD_DIM) as u64;
        av += (layer.attention.score_acc_real.len() * X3_HEAD_DIM) as u64;
        attention_out += (X3_T * X3_D * X3_D) as u64;
        for expert in &layer.experts {
            let rows = expert.rows.len();
            expert_gate_up += (2 * rows * X3_D * X3_DFF) as u64;
            expert_down += (rows * X3_DFF * X3_D) as u64;
        }
    }
    vec![
        ("qkv", qkv),
        ("rope_qk", qk),
        ("gqa_av", av),
        ("attention_out", attention_out),
        ("expert_gate_up", expert_gate_up),
        ("expert_down", expert_down),
        ("logits", (X3_D * X3_VOCAB) as u64),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x3_shape_config_windows_and_poison_contract_are_pinned() {
        let fixture = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
        assert_eq!(fixture.config.digest().unwrap(), x3_model_config().digest().unwrap());
        assert_eq!(fixture.layers[0].attention.lo, vec![0; X3_T]);
        assert_eq!(fixture.layers[0].attention.hi, vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(fixture.layers[1].attention.lo, vec![0, 0, 0, 0, 1, 2, 3]);
        assert_eq!(fixture.layers[1].attention.hi, vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(fixture.source_padding.iter().all(|&value| value != 0));
        assert!(fixture.canonical_padding.iter().all(|&value| value == 0));
        let admitted = build_x3_ops_fixture(X3PadMode::AdmitPoison);
        assert_eq!(fixture.layers, admitted.layers);
        assert_eq!(fixture.final_witness, admitted.final_witness);
        assert_eq!(admitted.canonical_padding, admitted.source_padding);
    }

    #[test]
    fn x3_swiglu_fixture_exercises_both_clamp_edges() {
        let fixture = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
        let all_gate = fixture
            .layers
            .iter()
            .flat_map(|layer| layer.experts.iter())
            .flat_map(|expert| expert.gate_q.iter().copied())
            .chain(fixture.clamp_probe.gate_in.iter().copied())
            .collect::<Vec<_>>();
        assert!(all_gate.iter().any(|&value| value < X3_CLAMP_MIN));
        assert!(all_gate.iter().any(|&value| value > X3_CLAMP_MAX));
        assert!(all_gate.iter().any(|&value| (X3_CLAMP_MIN..=X3_CLAMP_MAX).contains(&value)));
    }

    #[test]
    fn x3_native_trace_matches_the_independent_numpy_golden_byte_for_byte() {
        let fixture = build_x3_ops_fixture(X3PadMode::CanonicalizePoison);
        let native = encode_x3_golden(&fixture);
        let golden = include_bytes!("../../../tests/fixtures/x123/x3-ops-v1.golden.bin");
        assert_eq!(native.len(), golden.len());
        assert_eq!(native.as_slice(), golden.as_slice());
    }
}
