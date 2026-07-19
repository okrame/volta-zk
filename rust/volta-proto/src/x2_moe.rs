//! X2 CPU-only synthetic two-layer MoE harness.
//!
//! The native witness is runtime-shaped (`T=7`, `d=48`, GQA 6/2,
//! eight GELU experts/top-2).  The proof half below composes only the existing
//! committed-GEMM, LogUp/TableBank, Hadamard/Π_Prod, Π_ZeroBatch and T1
//! equality-reducer classes; it introduces no proof primitive.

use crate::mle::eval_mle;
use crate::thaler::pad_bits;
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    build_luts, forward_layer_with_config, gemm_i64, ActivationKind, AttentionMode, ConfigBinding,
    ExpertBlockShifts, LayerShiftSchedule, LayerWeights, LayerWitness, LutParams, Luts,
    ModelConfig, NonlinearTableConfig, NormKind, RouterTieRule,
};

pub const X2_T: usize = 7;
pub const X2_LAYERS: usize = 2;
pub const X2_D: usize = 48;
pub const X2_DFF: usize = 80;
pub const X2_Q_HEADS: usize = 6;
pub const X2_KV_HEADS: usize = 2;
pub const X2_HEAD_DIM: usize = 8;
pub const X2_QKV: usize = X2_D + 2 * X2_KV_HEADS * X2_HEAD_DIM;
pub const X2_EXPERTS: usize = 8;
pub const X2_TOP_K: usize = 2;
pub const X2_VOCAB: usize = 97;
pub const X2_SHIFT: u32 = 8;
pub const X2_NATIVE_MACS: u64 = 316_464;
pub const X2_LOGICAL_LOOKUPS: usize = 12_495;
pub const X2_PADDED_LOOKUPS: usize = 19_313;
pub const X2_LOOKUP_SITES: usize = 80;

const X2_ROUTES_0: [[u8; X2_TOP_K]; X2_T] =
    [[0, 1], [2, 3], [4, 5], [6, 7], [0, 2], [1, 4], [3, 5]];

fn x2_lut_params() -> LutParams {
    LutParams {
        // X2 deliberately shares one Range(8) content across every requant.
        // Lower reciprocal scale keeps exp*recip inside that no-clamp lane.
        recip_log2: 22,
        shift_ln_norm: X2_SHIFT,
        shift_qkv: X2_SHIFT,
        shift_scores: X2_SHIFT,
        shift_softmax_norm: X2_SHIFT,
        shift_av: X2_SHIFT,
        shift_attn_proj: X2_SHIFT,
        shift_ffn_up: X2_SHIFT,
        shift_ffn_down: X2_SHIFT,
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
        gelu_scale_log2: params.gelu_scale_log2,
        softmax_row_shift: params.softmax_row_shift,
    }
}

pub fn x2_model_config(thin_k: usize) -> ModelConfig {
    assert!(matches!(thin_k, 1 | 2), "X2 exercises only k=1 and k=2");
    let params = x2_lut_params();
    let layer = LayerShiftSchedule {
        layer_norm: X2_SHIFT,
        qkv: X2_SHIFT,
        scores: X2_SHIFT,
        softmax_norm: X2_SHIFT,
        av: X2_SHIFT,
        attention_out: X2_SHIFT,
        ffn_up: X2_SHIFT,
        ffn_down: X2_SHIFT,
        residual_seam: X2_SHIFT,
        router_requant: X2_SHIFT,
        router_norm: X2_SHIFT,
        expert_blocks: vec![ExpertBlockShifts { gate_up: X2_SHIFT, down: X2_SHIFT }; X2_EXPERTS],
        ..LayerShiftSchedule::default()
    };
    let config = ModelConfig {
        schema_version: volta_gpt2::config::MODEL_CONFIG_SCHEMA,
        model_id: "volta-x2-moe-v1".to_owned(),
        binding: ConfigBinding::DigestV1,
        vocab_size: X2_VOCAB,
        max_positions: X2_T,
        tied_output: false,
        n_layers: X2_LAYERS,
        d_model: X2_D,
        d_ff: X2_DFF,
        n_q_heads: X2_Q_HEADS,
        n_kv_heads: X2_KV_HEADS,
        head_dim: X2_HEAD_DIM,
        n_experts: X2_EXPERTS,
        top_k: X2_TOP_K,
        attention: vec![AttentionMode::FullCausal; X2_LAYERS],
        norm: NormKind::LayerNorm,
        activation: ActivationKind::Gelu,
        attention_sinks_per_q_head: 0,
        rope: None,
        nonlinear_tables: nonlinear_config(params),
        embedding_shift: X2_SHIFT as i32,
        final_norm_shift: X2_SHIFT,
        layer_shifts: vec![layer; X2_LAYERS],
        thin_k,
        router_tie_rule: RouterTieRule::ScoreThenHigherExpertId,
    };
    config.validate().expect("pinned X2 runtime config must validate");
    config
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2ExpertWeights {
    pub up: Vec<i16>,
    pub down: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2LayerWeights {
    pub dense: LayerWeights,
    pub router: Vec<i16>,
    pub experts: Vec<X2ExpertWeights>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2ExpertWitness {
    pub rows: Vec<(usize, usize)>,
    pub gathered: Vec<i16>,
    pub up_acc: Vec<i64>,
    pub up_q: Vec<i16>,
    pub gelu: Vec<i16>,
    pub down_acc: Vec<i64>,
    pub down_q: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2RouterWitness {
    pub acc: Vec<i64>,
    pub scores: Vec<i16>,
    pub exp: Vec<i16>,
    pub denoms: Vec<i64>,
    pub recip_in: Vec<i16>,
    pub recips: Vec<i16>,
    pub routes: Vec<[u8; X2_TOP_K]>,
    pub theta: Vec<i16>,
    pub comparisons: Vec<u16>,
    /// Private normalized weights in public route order, T×top_k.
    pub route_weights: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2LayerWitness {
    pub dense: LayerWitness,
    pub router: X2RouterWitness,
    pub experts: Vec<X2ExpertWitness>,
    /// T×top_k×d in token-major, route-slot-major order.
    pub route_values: Vec<i16>,
    pub combine_acc: Vec<i64>,
    pub combine_q: Vec<i16>,
    pub output: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2FinalNorm {
    pub input: Vec<i16>,
    pub mean: i64,
    pub var: i64,
    pub rsqrt_in: i16,
    pub rsqrt_out: i16,
    pub acc: Vec<i64>,
    pub output: Vec<i16>,
    pub logits: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X2MoeFixture {
    pub config: ModelConfig,
    pub luts: Luts,
    pub tokens: Vec<u16>,
    pub embedding: Vec<i16>,
    pub output_weight: Vec<i16>,
    pub weights: Vec<X2LayerWeights>,
    pub embedding_acc: Vec<i64>,
    pub embedding_out: Vec<i16>,
    pub layers: Vec<X2LayerWitness>,
    pub seam_acc: Vec<i64>,
    pub seam_out: Vec<i16>,
    pub final_norm: X2FinalNorm,
}

fn checked_requant(acc: i64, shift: u32, label: &str) -> i16 {
    let rounded = (acc + (1i64 << (shift - 1))) >> shift;
    assert!(
        (i16::MIN as i64..=i16::MAX as i64).contains(&rounded),
        "X2 {label} requant overflow: {acc}"
    );
    rounded as i16
}

fn routes_for_layer(layer: usize) -> Vec<[u8; X2_TOP_K]> {
    X2_ROUTES_0
        .iter()
        .map(|route| {
            [
                ((usize::from(route[0]) + layer) % X2_EXPERTS) as u8,
                ((usize::from(route[1]) + layer) % X2_EXPERTS) as u8,
            ]
        })
        .collect()
}

fn embedding_weights() -> Vec<i16> {
    let mut out = vec![0i16; X2_VOCAB * X2_D];
    for token in 0..X2_VOCAB {
        out[token * X2_D + X2_D - 1] = ((token * 3 + 1) % 7) as i16 - 3;
    }
    for token in 0..X2_T {
        out[token * X2_D + token] = 1_024;
    }
    // The one-claim synthetic public gather embeds the seven-token trace in
    // the low eight-row subcube.  Its canonical pad row must therefore be a
    // genuine zero row in the committed fixture (the non-power-of-two row is
    // not allowed to alias vocabulary token 7).
    out[X2_T * X2_D..(X2_T + 1) * X2_D].fill(0);
    out
}

fn dense_weights(layer: usize) -> LayerWeights {
    let pattern = |len: usize, salt: usize| -> Vec<i16> {
        (0..len).map(|index| ((index * (salt * 2 + 3) + 5 * salt + 1) % 5) as i16 - 2).collect()
    };
    LayerWeights {
        c_attn: pattern(X2_D * X2_QKV, 3 + layer),
        attn_proj: pattern(X2_D * X2_D, 7 + layer),
        // The dense body is executed only to reuse the existing runtime
        // attention/LN witness generator. X2 replaces these fields with its
        // public-gather expert jobs below.
        ffn_up: vec![0; X2_D * X2_DFF],
        ffn_down: vec![0; X2_DFF * X2_D],
        ln1_gain: vec![1; X2_D],
        ln1_bias: vec![0; X2_D],
        ln2_gain: vec![1; X2_D],
        ln2_bias: vec![0; X2_D],
    }
}

fn router_weights(layer: usize) -> Vec<i16> {
    let routes = routes_for_layer(layer);
    let mut out = vec![-1i16; X2_D * X2_EXPERTS];
    for (token, route) in routes.iter().enumerate() {
        for expert in 0..X2_EXPERTS {
            out[token * X2_EXPERTS + expert] = -64;
        }
        // route[0] is the cutoff; route[1] is deliberately strictly higher.
        out[token * X2_EXPERTS + usize::from(route[0])] = 160;
        out[token * X2_EXPERTS + usize::from(route[1])] = 192;
    }
    out
}

fn expert_weights(layer: usize, expert: usize) -> X2ExpertWeights {
    let values = |len: usize, salt: usize| -> Vec<i16> {
        (0..len).map(|index| ((index * (salt + 1) + 3 * salt + 1) % 3) as i16 - 1).collect()
    };
    X2ExpertWeights {
        up: values(X2_D * X2_DFF, 1 + 2 * layer + expert),
        down: values(X2_DFF * X2_D, 5 + 3 * layer + expert),
    }
}

fn make_layer_weights(layer: usize) -> X2LayerWeights {
    X2LayerWeights {
        dense: dense_weights(layer),
        router: router_weights(layer),
        experts: (0..X2_EXPERTS).map(|expert| expert_weights(layer, expert)).collect(),
    }
}

fn native_top2(scores: &[i16]) -> [u8; X2_TOP_K] {
    assert_eq!(scores.len(), X2_EXPERTS);
    let mut ranked: Vec<_> = (0..X2_EXPERTS).collect();
    ranked.sort_unstable_by(|&left, &right| (scores[right], right).cmp(&(scores[left], left)));
    let cutoff = ranked[1];
    [cutoff as u8, ranked[0] as u8]
}

/// Public D1/reference view of the native top-2 rule used by the X2 gate.
/// Canonical output is `[cutoff, strictly-better]`; ties rank the higher
/// expert id first, so an all-equal row returns `[6, 7]`.
pub fn x2_native_top2_d1(scores: &[i16]) -> Option<[u8; X2_TOP_K]> {
    (scores.len() == X2_EXPERTS).then(|| native_top2(scores))
}

fn build_router(
    input: &[i16],
    weights: &[i16],
    expected_routes: &[[u8; X2_TOP_K]],
    luts: &Luts,
) -> X2RouterWitness {
    let acc = gemm_i64(input, weights, X2_T, X2_D, X2_EXPERTS);
    let scores: Vec<i16> =
        acc.iter().map(|&value| checked_requant(value, X2_SHIFT, "router")).collect();
    let exp: Vec<i16> = scores.iter().map(|&value| luts.exp[value as u16 as usize]).collect();
    let mut denoms = vec![0i64; X2_T];
    let mut recip_in = vec![0i16; X2_T];
    let mut recips = vec![0i16; X2_T];
    for row in 0..X2_T {
        denoms[row] =
            exp[row * X2_EXPERTS..(row + 1) * X2_EXPERTS].iter().map(|&value| value as i64).sum();
        let input = denoms[row] >> luts.params.recip_den_shift;
        assert!((0..1 << 16).contains(&input));
        recip_in[row] = input as i16;
        recips[row] = luts.softmax_recip[input as usize];
    }
    let routes: Vec<_> = scores.chunks_exact(X2_EXPERTS).map(native_top2).collect();
    assert_eq!(routes, expected_routes, "native router missed the pinned public fixture");
    let mut theta = vec![0i16; X2_T];
    let mut comparisons = vec![0u16; X2_T * X2_EXPERTS];
    let mut route_weights = vec![0i16; X2_T * X2_TOP_K];
    for row in 0..X2_T {
        let cutoff = usize::from(routes[row][0]);
        theta[row] = scores[row * X2_EXPERTS + cutoff];
        for expert in 0..X2_EXPERTS {
            let selected = routes[row].contains(&(expert as u8));
            let score = i32::from(scores[row * X2_EXPERTS + expert]);
            let threshold = i32::from(theta[row]);
            let value = if selected {
                score - threshold - i32::from(expert < cutoff)
            } else {
                threshold - score - i32::from(expert > cutoff)
            };
            assert!((0..1 << 16).contains(&value));
            comparisons[row * X2_EXPERTS + expert] = value as u16;
        }
        for slot in 0..X2_TOP_K {
            let expert = usize::from(routes[row][slot]);
            route_weights[row * X2_TOP_K + slot] = checked_requant(
                i64::from(exp[row * X2_EXPERTS + expert]) * i64::from(recips[row]),
                X2_SHIFT,
                "router weight",
            );
        }
    }
    X2RouterWitness {
        acc,
        scores,
        exp,
        denoms,
        recip_in,
        recips,
        routes,
        theta,
        comparisons,
        route_weights,
    }
}

fn build_experts(
    input: &[i16],
    routes: &[[u8; X2_TOP_K]],
    weights: &[X2ExpertWeights],
    luts: &Luts,
) -> (Vec<X2ExpertWitness>, Vec<i16>) {
    let mut jobs: Vec<Vec<(usize, usize)>> = vec![Vec::new(); X2_EXPERTS];
    for (token, route) in routes.iter().enumerate() {
        for (slot, &expert) in route.iter().enumerate() {
            jobs[usize::from(expert)].push((token, slot));
        }
    }
    let mut route_values = vec![0i16; X2_T * X2_TOP_K * X2_D];
    let mut witnesses = Vec::with_capacity(X2_EXPERTS);
    for expert in 0..X2_EXPERTS {
        let rows = jobs[expert].clone();
        assert!(!rows.is_empty(), "the pinned route fixture touches every expert");
        let mut gathered = Vec::with_capacity(rows.len() * X2_D);
        for &(token, _) in &rows {
            gathered.extend_from_slice(&input[token * X2_D..(token + 1) * X2_D]);
        }
        let up_acc = gemm_i64(&gathered, &weights[expert].up, rows.len(), X2_D, X2_DFF);
        let up_q: Vec<i16> =
            up_acc.iter().map(|&value| checked_requant(value, X2_SHIFT, "expert up")).collect();
        let gelu: Vec<i16> = up_q.iter().map(|&value| luts.gelu[value as u16 as usize]).collect();
        let down_acc = gemm_i64(&gelu, &weights[expert].down, rows.len(), X2_DFF, X2_D);
        let down_q: Vec<i16> =
            down_acc.iter().map(|&value| checked_requant(value, X2_SHIFT, "expert down")).collect();
        for (job_row, &(token, slot)) in rows.iter().enumerate() {
            let dst = (token * X2_TOP_K + slot) * X2_D;
            route_values[dst..dst + X2_D]
                .copy_from_slice(&down_q[job_row * X2_D..(job_row + 1) * X2_D]);
        }
        witnesses.push(X2ExpertWitness { rows, gathered, up_acc, up_q, gelu, down_acc, down_q });
    }
    (witnesses, route_values)
}

fn combine_layer(
    input: &[i16],
    attention: &[i16],
    route_values: &[i16],
    route_weights: &[i16],
) -> (Vec<i64>, Vec<i16>, Vec<i16>) {
    let mut acc = vec![0i64; X2_T * X2_D];
    let mut q = vec![0i16; X2_T * X2_D];
    let mut output = vec![0i16; X2_T * X2_D];
    for token in 0..X2_T {
        for column in 0..X2_D {
            let mut value = i64::from(attention[token * X2_D + column]) << X2_SHIFT;
            for slot in 0..X2_TOP_K {
                value += i64::from(route_weights[token * X2_TOP_K + slot])
                    * i64::from(route_values[(token * X2_TOP_K + slot) * X2_D + column]);
            }
            let index = token * X2_D + column;
            acc[index] = value;
            q[index] = checked_requant(value, X2_SHIFT, "MoE combine");
            let residual = i32::from(input[index]) + i32::from(q[index]);
            assert!((i16::MIN as i32..=i16::MAX as i32).contains(&residual));
            output[index] = residual as i16;
        }
    }
    (acc, q, output)
}

fn final_norm(input: &[i16], luts: &Luts, output_weight: &[i16]) -> X2FinalNorm {
    assert_eq!(input.len(), X2_D);
    let sum: i64 = input.iter().map(|&value| i64::from(value)).sum();
    let mean = (sum + X2_D as i64 / 2).div_euclid(X2_D as i64);
    let var_sum: i64 = input
        .iter()
        .map(|&value| {
            let delta = i64::from(value) - mean;
            delta * delta
        })
        .sum();
    let var = (var_sum + X2_D as i64 / 2).div_euclid(X2_D as i64);
    let rin = var >> luts.params.ln_var_shift;
    assert!((0..1 << 16).contains(&rin));
    let rsqrt_out = luts.ln_rsqrt[rin as usize];
    let acc: Vec<i64> =
        input.iter().map(|&value| (i64::from(value) - mean) * i64::from(rsqrt_out)).collect();
    let output: Vec<i16> =
        acc.iter().map(|&value| checked_requant(value, X2_SHIFT, "final norm")).collect();
    let logits = gemm_i64(&output, output_weight, 1, X2_D, X2_VOCAB);
    X2FinalNorm {
        input: input.to_vec(),
        mean,
        var,
        rsqrt_in: rin as i16,
        rsqrt_out,
        acc,
        output,
        logits,
    }
}

pub fn build_x2_moe_fixture(thin_k: usize) -> X2MoeFixture {
    let config = x2_model_config(thin_k);
    let params = x2_lut_params();
    let luts = build_luts(params);
    let tokens: Vec<u16> = (0..X2_T as u16).collect();
    let embedding = embedding_weights();
    let embedding_acc: Vec<i64> = tokens
        .iter()
        .flat_map(|&token| {
            embedding[usize::from(token) * X2_D..(usize::from(token) + 1) * X2_D]
                .iter()
                .map(|&value| i64::from(value) << X2_SHIFT)
        })
        .collect();
    let embedding_out: Vec<i16> =
        embedding_acc.iter().map(|&value| checked_requant(value, X2_SHIFT, "embedding")).collect();
    let weights: Vec<_> = (0..X2_LAYERS).map(make_layer_weights).collect();

    let mut dense_config = config.clone();
    dense_config.n_experts = 0;
    dense_config.top_k = 0;
    for schedule in &mut dense_config.layer_shifts {
        schedule.expert_blocks.clear();
    }
    dense_config.validate().expect("X2 dense attention adapter config");

    let mut current = embedding_out.clone();
    let mut layers = Vec::with_capacity(X2_LAYERS);
    let mut seam_acc = Vec::new();
    let mut seam_out = Vec::new();
    for layer in 0..X2_LAYERS {
        let dense = forward_layer_with_config(
            &dense_config,
            layer,
            &current,
            &weights[layer].dense,
            None,
            &luts,
            params,
            X2_T,
        );
        let expected_routes = routes_for_layer(layer);
        let router = build_router(&current, &weights[layer].router, &expected_routes, &luts);
        let (experts, route_values) =
            build_experts(&dense.ln2_out, &router.routes, &weights[layer].experts, &luts);
        let (combine_acc, combine_q, output) =
            combine_layer(&current, &dense.attn_proj_q, &route_values, &router.route_weights);
        layers.push(X2LayerWitness {
            dense,
            router,
            experts,
            route_values,
            combine_acc,
            combine_q,
            output: output.clone(),
        });
        if layer + 1 < X2_LAYERS {
            seam_acc = output.iter().map(|&value| i64::from(value) << X2_SHIFT).collect();
            seam_out = seam_acc
                .iter()
                .map(|&value| checked_requant(value, X2_SHIFT, "residual seam"))
                .collect();
            current = seam_out.clone();
        } else {
            current = output;
        }
    }
    let output_weight: Vec<i16> =
        (0..X2_D * X2_VOCAB).map(|index| ((index * 7 + 3) % 5) as i16 - 2).collect();
    let final_input = current[(X2_T - 1) * X2_D..X2_T * X2_D].to_vec();
    let final_norm = final_norm(&final_input, &luts, &output_weight);
    X2MoeFixture {
        config,
        luts,
        tokens,
        embedding,
        output_weight,
        weights,
        embedding_acc,
        embedding_out,
        layers,
        seam_acc,
        seam_out,
        final_norm,
    }
}

fn put_i16(out: &mut Vec<u8>, values: &[i16]) {
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_u16(out: &mut Vec<u8>, values: &[u16]) {
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

fn put_i64(out: &mut Vec<u8>, values: &[i64]) {
    for &value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Versioned Rust encoding compared byte-for-byte with the independent numpy
/// X2 golden.  Both thinning schedules intentionally encode the same logical
/// witness; only the proof/authentication schedule differs.
pub fn encode_x2_golden(fixture: &X2MoeFixture) -> Vec<u8> {
    let mut out = b"VOLTA-X2-GOLD-V1".to_vec();
    for value in [
        X2_T as u32,
        X2_LAYERS as u32,
        X2_D as u32,
        X2_DFF as u32,
        X2_Q_HEADS as u32,
        X2_KV_HEADS as u32,
        X2_HEAD_DIM as u32,
        X2_EXPERTS as u32,
        X2_TOP_K as u32,
        X2_VOCAB as u32,
        X2_SHIFT,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    put_u16(&mut out, &fixture.tokens);
    put_i16(&mut out, &fixture.embedding);
    put_i64(&mut out, &fixture.embedding_acc);
    put_i16(&mut out, &fixture.embedding_out);
    for (layer, weights) in fixture.layers.iter().zip(&fixture.weights) {
        put_i16(&mut out, &weights.dense.c_attn);
        put_i16(&mut out, &weights.dense.attn_proj);
        put_i16(&mut out, &weights.router);
        put_i16(&mut out, &layer.dense.x_in);
        put_i64(&mut out, &layer.dense.ln1_mean);
        put_i64(&mut out, &layer.dense.ln1_var);
        put_i64(&mut out, &layer.dense.ln1_rsqrt_in);
        put_i16(&mut out, &layer.dense.ln1_rsqrt_out);
        put_i64(&mut out, &layer.dense.ln1_acc);
        put_i16(&mut out, &layer.dense.ln1_out);
        put_i64(&mut out, &layer.dense.qkv_acc);
        put_i16(&mut out, &layer.dense.q);
        put_i16(&mut out, &layer.dense.k);
        put_i16(&mut out, &layer.dense.v);
        put_i64(&mut out, &layer.dense.scores_acc);
        put_i16(&mut out, &layer.dense.scores_q);
        put_i16(&mut out, &layer.dense.exp_out);
        put_i64(&mut out, &layer.dense.denoms);
        put_i16(&mut out, &layer.dense.recips);
        put_i16(&mut out, &layer.dense.softmax_w);
        put_i64(&mut out, &layer.dense.av_acc);
        put_i16(&mut out, &layer.dense.av_q);
        put_i64(&mut out, &layer.dense.proj_acc);
        put_i16(&mut out, &layer.dense.attn_proj_q);
        put_i16(&mut out, &layer.dense.attn_block_out);
        put_i64(&mut out, &layer.dense.ln2_mean);
        put_i64(&mut out, &layer.dense.ln2_var);
        put_i64(&mut out, &layer.dense.ln2_rsqrt_in);
        put_i16(&mut out, &layer.dense.ln2_rsqrt_out);
        put_i64(&mut out, &layer.dense.ln2_acc);
        put_i16(&mut out, &layer.dense.ln2_out);
        put_i64(&mut out, &layer.router.acc);
        put_i16(&mut out, &layer.router.scores);
        put_i16(&mut out, &layer.router.exp);
        put_i64(&mut out, &layer.router.denoms);
        put_i16(&mut out, &layer.router.recip_in);
        put_i16(&mut out, &layer.router.recips);
        for route in &layer.router.routes {
            out.extend_from_slice(route);
        }
        put_i16(&mut out, &layer.router.theta);
        put_u16(&mut out, &layer.router.comparisons);
        put_i16(&mut out, &layer.router.route_weights);
        for (expert, ew) in layer.experts.iter().zip(&weights.experts) {
            out.extend_from_slice(&(expert.rows.len() as u32).to_le_bytes());
            for &(token, slot) in &expert.rows {
                out.push(token as u8);
                out.push(slot as u8);
            }
            put_i16(&mut out, &ew.up);
            put_i16(&mut out, &ew.down);
            put_i16(&mut out, &expert.gathered);
            put_i64(&mut out, &expert.up_acc);
            put_i16(&mut out, &expert.up_q);
            put_i16(&mut out, &expert.gelu);
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
    put_i16(&mut out, &fixture.final_norm.input);
    put_i64(&mut out, &[fixture.final_norm.mean, fixture.final_norm.var]);
    put_i16(&mut out, &[fixture.final_norm.rsqrt_in, fixture.final_norm.rsqrt_out]);
    put_i64(&mut out, &fixture.final_norm.acc);
    put_i16(&mut out, &fixture.final_norm.output);
    put_i64(&mut out, &fixture.final_norm.logits);
    // Logical outputs under k=1 and k=2 are required to be identical.
    put_i16(&mut out, &fixture.layers.last().unwrap().output);
    put_i16(&mut out, &fixture.layers.last().unwrap().output);
    out
}

pub fn x2_public_routes() -> Vec<Vec<[u8; X2_TOP_K]>> {
    (0..X2_LAYERS).map(routes_for_layer).collect()
}

pub fn x2_native_operation_counts() -> Vec<(&'static str, u64)> {
    vec![
        ("q_proj", 32_256),
        ("k_proj", 10_752),
        ("v_proj", 10_752),
        ("attention_qk", 2_688),
        ("attention_av", 2_688),
        ("attention_out_proj", 32_256),
        ("ffn_up", 107_520),
        ("ffn_down", 107_520),
        ("router", 5_376),
        ("logits", 4_656),
    ]
}

pub fn x2_lookup_counts() -> Vec<(&'static str, usize, usize, usize)> {
    vec![
        ("attention_exp", 336, 512, 2),
        ("embedding_requant", 336, 512, 1),
        ("final_norm_requant", 48, 64, 1),
        ("final_norm_rsqrt", 1, 1, 1),
        ("gelu", 2_240, 3_584, 16),
        ("moe_combine_requant", 672, 1_024, 2),
        ("norm_requant", 1_344, 2_048, 2),
        ("norm_rsqrt", 28, 32, 2),
        ("requant_attention_out", 672, 1_024, 2),
        ("requant_av", 672, 1_024, 2),
        ("requant_ffn_down", 1_344, 1_792, 16),
        ("requant_ffn_up", 2_240, 3_584, 16),
        ("requant_qkv", 1_120, 2_048, 2),
        ("requant_scores", 336, 512, 2),
        ("residual_seam_requant", 336, 512, 1),
        ("router_exp", 112, 128, 2),
        ("router_recip", 14, 16, 2),
        ("router_requant", 112, 128, 2),
        ("router_topk_range", 112, 128, 2),
        ("softmax_norm_requant", 336, 512, 2),
        ("softmax_recip", 84, 128, 2),
    ]
}

pub fn eval_i16_matrix(values: &[i16], rows: usize, cols: usize, point: &[Fp2]) -> Fp2 {
    assert_eq!(point.len(), pad_bits(rows) + pad_bits(cols));
    let mut padded = vec![Fp2::ZERO; rows.next_power_of_two() * cols.next_power_of_two()];
    for row in 0..rows {
        for col in 0..cols {
            padded[row * cols.next_power_of_two() + col] =
                Fp2::from_base(Fp::from_i64(values[row * cols + col] as i64));
        }
    }
    eval_mle(&padded, point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x2_native_router_tie_is_score_then_higher_expert_id() {
        assert_eq!(native_top2(&[17; X2_EXPERTS]), [6, 7]);
        let route = native_top2(&[17, 17, 17, 17, 17, 17, 17, 16]);
        assert_eq!(route, [5, 6]);
    }

    #[test]
    fn x2_native_shape_routes_counts_and_thinning_outputs_are_pinned() {
        let k1 = build_x2_moe_fixture(1);
        let k2 = build_x2_moe_fixture(2);
        assert_eq!(k1.layers, k2.layers);
        assert_eq!(k1.final_norm, k2.final_norm);
        assert_eq!(
            k1.layers.iter().map(|layer| layer.router.routes.clone()).collect::<Vec<_>>(),
            x2_public_routes()
        );
        assert_eq!(
            x2_native_operation_counts().iter().map(|row| row.1).sum::<u64>(),
            X2_NATIVE_MACS
        );
        assert_eq!(x2_lookup_counts().iter().map(|row| row.1).sum::<usize>(), X2_LOGICAL_LOOKUPS);
        assert_eq!(x2_lookup_counts().iter().map(|row| row.2).sum::<usize>(), X2_PADDED_LOOKUPS);
        assert_eq!(x2_lookup_counts().iter().map(|row| row.3).sum::<usize>(), X2_LOOKUP_SITES);
        for layer in &k1.layers {
            let histogram: Vec<_> = layer.experts.iter().map(|expert| expert.rows.len()).collect();
            assert_eq!(histogram.iter().sum::<usize>(), X2_T * X2_TOP_K);
            assert!(histogram.iter().all(|&rows| matches!(rows, 1 | 2)));
        }
    }

    #[test]
    fn x2_native_witness_is_bit_exact_with_external_numpy_golden() {
        let fixture = build_x2_moe_fixture(1);
        let expected = include_bytes!("../../../tests/fixtures/x123/x2-moe-v1.golden.bin");
        assert_eq!(encode_x2_golden(&fixture), expected);
    }
}
