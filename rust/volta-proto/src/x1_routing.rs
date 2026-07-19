//! X1 synthetic routing-soundness harness.
//!
//! This module deliberately contains no new proof primitive.  It composes
//! the existing committed-GEMM, requant/range LogUp, pair-LUT, Hadamard,
//! public weighted-selector, TableBank, Pi_Prod and Pi_ZeroBatch machinery
//! over the preregistered `T=31, L=4, d=48, E=32, top_k=4` shape.

use crate::block_proof::{
    auth_fp_vec_p, close_softmax_recip_cpu, close_softmax_recip_verifier, keys_fp_vec_v,
    layer_dom_base, open_fp_vec_k, open_fp_vec_p, open_weighted_k, open_weighted_p,
    pair_cols_padded, prove_range_site, range_mult, verify_range_site, BlockCtxP, BlockCtxV,
    TableBankP, TableBankV, TableCloseProof,
};
use crate::gemm_proof::{
    prove_gemm_committed_chained, verify_gemm_committed_chained, ChainDoms, ChainedGemmProof,
    WeightClaimP,
};
use crate::hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
use crate::logup::{
    BlindInstance, Counters, Doms, LeafAuxClaim, ProdKeyTriples, ProdTriples, TableKey,
};
use crate::mle::{eq_vec, eval_mle};
use crate::thaler::{fold_x, pad_bits};
use std::collections::BTreeSet;
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    build_luts, gemm_i64, requant_plain, ActivationKind, AttentionMode, ConfigBinding,
    ExpertBlockShifts, LayerShiftSchedule, LutParams, Luts, ModelConfig, NonlinearTableConfig,
    NormKind, RouterTieRule,
};
use volta_mac::{
    CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

pub const X1_T: usize = 31;
pub const X1_LAYERS: usize = 4;
pub const X1_D: usize = 48;
pub const X1_EXPERTS: usize = 32;
pub const X1_TOP_K: usize = 4;
pub const X1_ROUTER_REQUANT: u32 = 8;
pub const X1_ROUTER_NORM: u32 = 12;
pub const X1_LOGICAL_COMPARISONS: usize = X1_T * X1_LAYERS * X1_EXPERTS;
pub const X1_PADDED_COMPARISONS: usize = X1_LAYERS * 1024;

const X1_SECTION_BASE: u8 = 224;
const X1_TABLE_SECTION: u8 = 239;

/// Public runtime profile exercised by X1.  The attention/FFN fields are
/// present because `ModelConfig` is the model-agnostic statement schema; X1
/// itself consumes only the router fields.
pub fn x1_model_config() -> ModelConfig {
    let shifts = LayerShiftSchedule {
        router_requant: X1_ROUTER_REQUANT,
        router_norm: X1_ROUTER_NORM,
        expert_blocks: vec![ExpertBlockShifts { gate_up: 10, down: 10 }; X1_EXPERTS],
        ..LayerShiftSchedule::default()
    };
    let config = ModelConfig {
        schema_version: volta_gpt2::config::MODEL_CONFIG_SCHEMA,
        model_id: "volta-x1-router-v1".to_owned(),
        binding: ConfigBinding::DigestV1,
        vocab_size: 97,
        max_positions: X1_T,
        tied_output: false,
        n_layers: X1_LAYERS,
        d_model: X1_D,
        d_ff: 80,
        n_q_heads: 6,
        n_kv_heads: 2,
        head_dim: 8,
        n_experts: X1_EXPERTS,
        top_k: X1_TOP_K,
        attention: vec![AttentionMode::FullCausal; X1_LAYERS],
        norm: NormKind::LayerNorm,
        activation: ActivationKind::Gelu,
        attention_sinks_per_q_head: 0,
        rope: None,
        nonlinear_tables: NonlinearTableConfig::default(),
        embedding_shift: 0,
        final_norm_shift: 0,
        layer_shifts: vec![shifts; X1_LAYERS],
        thin_k: 1,
        router_tie_rule: RouterTieRule::ScoreThenHigherExpertId,
    };
    config.validate().expect("the pinned X1 runtime profile must validate");
    config
}

fn x1_luts(config: &ModelConfig) -> Luts {
    let nonlinear = config.nonlinear_tables;
    let first = &config.layer_shifts[0];
    let params = LutParams {
        ln_var_shift: nonlinear.ln_var_shift,
        ln_rsqrt_log2: nonlinear.ln_rsqrt_log2,
        shift_ln_norm: first.layer_norm.max(1),
        exp_in_log2: nonlinear.exp_in_log2,
        exp_out_log2: nonlinear.exp_out_log2,
        recip_den_shift: nonlinear.recip_den_shift,
        recip_log2: nonlinear.recip_log2,
        gelu_scale_log2: nonlinear.gelu_scale_log2,
        shift_qkv: first.qkv.max(1),
        shift_scores: first.scores.max(1),
        shift_softmax_norm: first.router_norm,
        shift_av: first.av.max(1),
        shift_attn_proj: first.attention_out.max(1),
        shift_ffn_up: first.ffn_up.max(1),
        shift_ffn_down: first.ffn_down.max(1),
        softmax_row_shift: nonlinear.softmax_row_shift,
    };
    build_luts(params)
}

/// Canonical D1 encoding.  Native ranking is descending `(score, expert_id)`;
/// the fourth-ranked expert is emitted first as the cutoff, while the other
/// three selected ids are ascending.
pub fn native_top_k_d1(scores: &[i16]) -> Option<[u8; X1_TOP_K]> {
    if scores.len() != X1_EXPERTS {
        return None;
    }
    let mut ids: Vec<usize> = (0..X1_EXPERTS).collect();
    ids.sort_unstable_by(|&a, &b| scores[b].cmp(&scores[a]).then_with(|| b.cmp(&a)));
    let cutoff = ids[X1_TOP_K - 1];
    let mut rest = [ids[0], ids[1], ids[2]];
    rest.sort_unstable();
    Some([cutoff as u8, rest[0] as u8, rest[1] as u8, rest[2] as u8])
}

fn d1_preflight(routes: &[[u8; X1_TOP_K]]) -> bool {
    routes.len() == X1_T
        && routes.iter().all(|route| {
            route.iter().all(|&id| usize::from(id) < X1_EXPERTS)
                && route[1] < route[2]
                && route[2] < route[3]
                && (0..X1_TOP_K).all(|i| (i + 1..X1_TOP_K).all(|j| route[i] != route[j]))
        })
}

fn selected(route: &[u8; X1_TOP_K], expert: usize) -> bool {
    route.iter().any(|&id| usize::from(id) == expert)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X1LayerWitness {
    /// Public activation matrix, row-major `31 x 48`.
    pub x: Vec<i16>,
    /// Synthetic private router matrix, row-major `48 x 32`.
    pub weights: Vec<i16>,
    pub raw_acc: Vec<i64>,
    pub requant: Vec<i16>,
    pub exp: Vec<i16>,
    pub denoms: Vec<i64>,
    pub recip_in: Vec<i16>,
    pub recips: Vec<i16>,
    pub norm_acc: Vec<i64>,
    pub scores: Vec<i16>,
    pub routes: Vec<[u8; X1_TOP_K]>,
    pub theta: Vec<i16>,
    pub comparisons: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X1RoutingFixture {
    pub config: ModelConfig,
    pub luts: Luts,
    pub layers: Vec<X1LayerWitness>,
    pub all_equal: bool,
}

fn comparison_value(score: i16, theta: i16, route: &[u8; X1_TOP_K], expert: usize) -> i64 {
    let cutoff = usize::from(route[0]);
    if selected(route, expert) {
        i64::from(score) - i64::from(theta) - i64::from(expert < cutoff)
    } else {
        i64::from(theta) - i64::from(score) - i64::from(expert > cutoff)
    }
}

fn build_x1_layer(layer: usize, luts: &Luts, all_equal: bool) -> X1LayerWitness {
    let mut x = vec![0i16; X1_T * X1_D];
    for row in 0..X1_T {
        x[row * X1_D] = 256 + 16 * (row % 5) as i16;
        // Exercise the logical non-power-of-two tail without affecting the
        // deliberately transparent monotone router fixture.
        x[row * X1_D + X1_D - 1] = (row as i16 % 9) - 4;
    }
    let mut weights = vec![0i16; X1_D * X1_EXPERTS];
    if !all_equal {
        let step = 28 + 2 * layer as i16;
        for expert in 0..X1_EXPERTS {
            weights[expert] = (expert as i16 - (X1_EXPERTS as i16 - 1)) * step;
        }
    }
    let raw_acc = gemm_i64(&x, &weights, X1_T, X1_D, X1_EXPERTS);
    let requant: Vec<i16> = raw_acc
        .iter()
        .map(|&value| {
            let rounded = (value + (1 << (X1_ROUTER_REQUANT - 1))) >> X1_ROUTER_REQUANT;
            assert!((i16::MIN as i64..=i16::MAX as i64).contains(&rounded));
            requant_plain(value, X1_ROUTER_REQUANT)
        })
        .collect();
    let exp: Vec<i16> = requant.iter().map(|&value| luts.exp[(value as u16) as usize]).collect();
    let mut denoms = Vec::with_capacity(X1_T);
    let mut recip_in = Vec::with_capacity(X1_T);
    let mut recips = Vec::with_capacity(X1_T);
    let mut norm_acc = Vec::with_capacity(X1_T * X1_EXPERTS);
    let mut scores = Vec::with_capacity(X1_T * X1_EXPERTS);
    for row in 0..X1_T {
        let erow = &exp[row * X1_EXPERTS..(row + 1) * X1_EXPERTS];
        let denom: i64 = erow.iter().map(|&value| i64::from(value)).sum();
        let rin = denom >> luts.params.recip_den_shift;
        assert!((0..1 << 16).contains(&rin));
        let recip = luts.softmax_recip[rin as usize];
        denoms.push(denom);
        recip_in.push(rin as i16);
        recips.push(recip);
        for &value in erow {
            let acc = i64::from(value) * i64::from(recip);
            let rounded = (acc + (1 << (X1_ROUTER_NORM - 1))) >> X1_ROUTER_NORM;
            assert!((i16::MIN as i64..=i16::MAX as i64).contains(&rounded));
            norm_acc.push(acc);
            scores.push(requant_plain(acc, X1_ROUTER_NORM));
        }
    }
    let mut routes = Vec::with_capacity(X1_T);
    let mut theta = Vec::with_capacity(X1_T);
    let mut comparisons = Vec::with_capacity(X1_T * X1_EXPERTS);
    for row in 0..X1_T {
        let score_row = &scores[row * X1_EXPERTS..(row + 1) * X1_EXPERTS];
        let route = native_top_k_d1(score_row).expect("fixed X1 score row");
        let threshold = score_row[usize::from(route[0])];
        routes.push(route);
        theta.push(threshold);
        for (expert, &score) in score_row.iter().enumerate() {
            let value = comparison_value(score, threshold, &route, expert);
            assert!((0..1 << 16).contains(&value), "honest X1 comparison must fit one u16 limb");
            comparisons.push(value as u16);
        }
    }
    assert!(d1_preflight(&routes));
    X1LayerWitness {
        x,
        weights,
        raw_acc,
        requant,
        exp,
        denoms,
        recip_in,
        recips,
        norm_acc,
        scores,
        routes,
        theta,
        comparisons,
    }
}

pub fn build_x1_routing_fixture(all_equal: bool) -> X1RoutingFixture {
    let config = x1_model_config();
    let luts = x1_luts(&config);
    let layers = (0..X1_LAYERS).map(|layer| build_x1_layer(layer, &luts, all_equal)).collect();
    X1RoutingFixture { config, luts, layers, all_equal }
}

/// Canonical observed bytes compared against the independently generated
/// numpy golden.  The external file is the expectation; this encoder is the
/// Rust implementation under test.
pub fn encode_x1_golden(fixture: &X1RoutingFixture) -> Vec<u8> {
    assert!(!fixture.all_equal && fixture.layers.len() == X1_LAYERS);
    let mut out = b"VOLTA-X1-GOLD-V1".to_vec();
    for value in [
        X1_T as u32,
        X1_LAYERS as u32,
        X1_D as u32,
        X1_EXPERTS as u32,
        X1_TOP_K as u32,
        X1_ROUTER_REQUANT,
        X1_ROUTER_NORM,
        fixture.luts.params.recip_den_shift,
        fixture.luts.params.exp_out_log2,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for layer in &fixture.layers {
        for &value in &layer.x {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.weights {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.raw_acc {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.requant {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.exp {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.denoms {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.recip_in {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.recips {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.norm_acc {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.scores {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for route in &layer.routes {
            out.extend_from_slice(route);
        }
        for &value in &layer.theta {
            out.extend_from_slice(&value.to_le_bytes());
        }
        for &value in &layer.comparisons {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    let tied = build_x1_routing_fixture(true);
    out.extend_from_slice(&tied.layers[0].routes[0]);
    for &value in &tied.layers[0].comparisons[..X1_EXPERTS] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn pad_matrix_i16(values: &[i16]) -> Vec<Fp> {
    assert_eq!(values.len(), X1_T * X1_EXPERTS);
    let mut out = vec![Fp::ZERO; 32 * 32];
    for row in 0..X1_T {
        for col in 0..X1_EXPERTS {
            out[row * 32 + col] = Fp::from_i64(values[row * X1_EXPERTS + col] as i64);
        }
    }
    out
}

fn pad_rows_i16(values: &[i16], pad: i16) -> Vec<Fp> {
    assert_eq!(values.len(), X1_T);
    let mut out = vec![Fp::from_i64(pad as i64); 32];
    for (dst, &value) in out.iter_mut().zip(values) {
        *dst = Fp::from_i64(value as i64);
    }
    out
}

fn pad_rows_i64(values: &[i64]) -> Vec<Fp> {
    assert_eq!(values.len(), X1_T);
    let mut out = vec![Fp::ZERO; 32];
    for (dst, &value) in out.iter_mut().zip(values) {
        *dst = Fp::from_i64(value);
    }
    out
}

fn pad_comparisons(values: &[u16]) -> Vec<Fp> {
    assert_eq!(values.len(), X1_T * X1_EXPERTS);
    let mut out = vec![Fp::ZERO; 32 * 32];
    for (dst, &value) in out.iter_mut().zip(values) {
        *dst = Fp::new(u64::from(value));
    }
    out
}

fn add_counts(dst: &mut Counters, value: &Counters) {
    dst.fp2_mults += value.fp2_mults;
    dst.base_mults += value.base_mults;
}

fn sub_counts(after: Counters, before: Counters) -> Counters {
    Counters {
        fp2_mults: after.fp2_mults - before.fp2_mults,
        base_mults: after.base_mults - before.base_mults,
    }
}

fn push_honest_zero(rows: &mut Vec<ProverAuthed>, row: ProverAuthed, label: &str) {
    debug_assert_eq!(row.x, Fp2::ZERO, "X1 honest relation failed at {label}");
    rows.push(row);
}

fn exp_pad(luts: &Luts) -> i16 {
    let index = luts.exp.iter().position(|&value| value == 0).expect("X1 exp table has zero pad");
    index as u16 as i16
}

fn pair_mult_signed(inputs: &[i16], pad_input: i16, padded_len: usize) -> Vec<u32> {
    assert!(inputs.len() <= padded_len);
    let mut out = vec![0u32; 1 << 16];
    for &value in inputs {
        out[(value as u16) as usize] += 1;
    }
    out[(pad_input as u16) as usize] += (padded_len - inputs.len()) as u32;
    out
}

fn pair_mult_unsigned(inputs: &[i16], padded_len: usize) -> Vec<u32> {
    assert!(inputs.len() <= padded_len);
    let mut out = vec![0u32; 1 << 16];
    for &value in inputs {
        assert!(value >= 0);
        out[value as usize] += 1;
    }
    // softmax_recip pads with the valid `(0, lut[0])` pair.
    out[0] += (padded_len - inputs.len()) as u32;
    out
}

fn comparison_mult(values: &[u16]) -> Vec<u32> {
    let mut out = vec![0u32; 1 << 16];
    for &value in values {
        out[value as usize] += 1;
    }
    out[0] += (32 * 32 - values.len()) as u32;
    out
}

pub fn x1_content_keys() -> BTreeSet<TableKey> {
    [
        TableKey::Range(X1_ROUTER_REQUANT),
        TableKey::Range(X1_ROUTER_NORM),
        TableKey::Range(16),
        TableKey::Exp,
        TableKey::SoftmaxRecip,
    ]
    .into_iter()
    .collect()
}

struct PreparedP {
    doms: Doms,
    score_dom: u64,
    theta_dom: u64,
    denom_dom: u64,
    recip_in_dom: u64,
    recips_dom: u64,
    score_corr: Vec<u64>,
    theta_corr: Vec<u64>,
    denom_corr: Vec<u64>,
    recip_in_corr: Vec<u64>,
    recips_corr: Vec<u64>,
}

struct PreparedV {
    doms: Doms,
    score_keys: Vec<Fp2>,
    theta_keys: Vec<Fp2>,
    denom_keys: Vec<Fp2>,
    recip_in_keys: Vec<Fp2>,
    recips_keys: Vec<Fp2>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X1LayerProof {
    pub score_corr: Vec<u64>,
    pub theta_corr: Vec<u64>,
    pub denom_corr: Vec<u64>,
    pub recip_in_corr: Vec<u64>,
    pub recips_corr: Vec<u64>,
    pub rowsum_corr: Fp2,
    pub comparison: BlindInstance,
    pub score_range: BlindInstance,
    pub score_range_stage1: Option<BlindInstance>,
    pub norm_hadamard: HadamardProof,
    pub exp: BlindInstance,
    pub recip: BlindInstance,
    pub router_range: BlindInstance,
    pub router_range_stage1: Option<BlindInstance>,
    pub gemm: ChainedGemmProof,
    pub x_corr: Fp2,
    pub weight_corr: Fp2,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X1RoutingProof {
    pub layers: Vec<X1LayerProof>,
    pub tables: Vec<TableCloseProof>,
}

pub struct X1RoutingProverOut {
    pub weight_claims: Vec<WeightClaimP>,
    pub prod: ProdTriples,
    pub zero: Vec<ProverAuthed>,
    pub comparison_counters: Counters,
    pub router_instance_counters: Counters,
    pub total_instance_counters: Counters,
    pub corr_counters: CorrCounters,
}

pub struct X1RoutingVerifierOut {
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    pub kprod: ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

fn prepare_layer_p(
    layer: usize,
    witness: &X1LayerWitness,
    luts: &Luts,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> PreparedP {
    let mut cx = BlockCtxP::new(stream, tx, X1_SECTION_BASE + layer as u8, bank);
    let score_dom = cx.doms.take(1);
    let theta_dom = cx.doms.take(1);
    let denom_dom = cx.doms.take(1);
    let recip_in_dom = cx.doms.take(1);
    let recips_dom = cx.doms.take(1);
    let score_corr = auth_fp_vec_p(cx.stream, cx.tx, score_dom, &pad_matrix_i16(&witness.scores));
    let theta_corr = auth_fp_vec_p(cx.stream, cx.tx, theta_dom, &pad_rows_i16(&witness.theta, 0));
    let denom_corr = auth_fp_vec_p(cx.stream, cx.tx, denom_dom, &pad_rows_i64(&witness.denoms));
    let recip_in_corr =
        auth_fp_vec_p(cx.stream, cx.tx, recip_in_dom, &pad_rows_i16(&witness.recip_in, 0));
    let recips_corr = auth_fp_vec_p(
        cx.stream,
        cx.tx,
        recips_dom,
        &pad_rows_i16(&witness.recips, luts.softmax_recip[0]),
    );

    cx.bank.add_mult(
        TableKey::Range(X1_ROUTER_REQUANT),
        &range_mult(&witness.raw_acc, &witness.requant, X1_T, X1_EXPERTS, X1_ROUTER_REQUANT),
    );
    cx.bank.add_mult(TableKey::Exp, &pair_mult_signed(&witness.requant, exp_pad(luts), 32 * 32));
    cx.bank.add_mult(TableKey::SoftmaxRecip, &pair_mult_unsigned(&witness.recip_in, 32));
    cx.bank.add_mult(
        TableKey::Range(X1_ROUTER_NORM),
        &range_mult(&witness.norm_acc, &witness.scores, X1_T, X1_EXPERTS, X1_ROUTER_NORM),
    );
    cx.bank.add_mult(TableKey::Range(16), &comparison_mult(&witness.comparisons));

    PreparedP {
        doms: cx.doms,
        score_dom,
        theta_dom,
        denom_dom,
        recip_in_dom,
        recips_dom,
        score_corr,
        theta_corr,
        denom_corr,
        recip_in_corr,
        recips_corr,
    }
}

fn prepare_layer_v(
    layer: usize,
    proof: &X1LayerProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<PreparedV> {
    if proof.score_corr.len() != 32 * 32
        || proof.theta_corr.len() != 32
        || proof.denom_corr.len() != 32
        || proof.recip_in_corr.len() != 32
        || proof.recips_corr.len() != 32
        || proof.score_range_stage1.is_some()
        || proof.router_range_stage1.is_some()
    {
        return None;
    }
    let mut empty = TableBankV::empty();
    let mut cx = BlockCtxV::new(ctx, tx, X1_SECTION_BASE + layer as u8, &mut empty);
    let score_keys = keys_fp_vec_v(cx.ctx, cx.doms.take(1), &proof.score_corr);
    let theta_keys = keys_fp_vec_v(cx.ctx, cx.doms.take(1), &proof.theta_corr);
    let denom_keys = keys_fp_vec_v(cx.ctx, cx.doms.take(1), &proof.denom_corr);
    let recip_in_keys = keys_fp_vec_v(cx.ctx, cx.doms.take(1), &proof.recip_in_corr);
    let recips_keys = keys_fp_vec_v(cx.ctx, cx.doms.take(1), &proof.recips_corr);
    Some(PreparedV {
        doms: cx.doms,
        score_keys,
        theta_keys,
        denom_keys,
        recip_in_keys,
        recips_keys,
    })
}

fn affine_weights(routes: &[[u8; X1_TOP_K]], point: &[Fp2]) -> (Vec<Fp2>, Vec<Fp2>, Fp2) {
    assert_eq!(point.len(), 10);
    let eq = eq_vec(point);
    let mut score_weights = vec![Fp2::ZERO; 32 * 32];
    let mut theta_weights = vec![Fp2::ZERO; 32];
    let mut public_term = Fp2::ZERO;
    for row in 0..X1_T {
        let route = &routes[row];
        let cutoff = usize::from(route[0]);
        for expert in 0..X1_EXPERTS {
            let weight = eq[row * 32 + expert];
            let a = if selected(route, expert) { Fp2::ONE } else { Fp2::ZERO - Fp2::ONE };
            score_weights[row * 32 + expert] = weight * a;
            theta_weights[row] = theta_weights[row] - weight * a;
            let strict = if selected(route, expert) { expert < cutoff } else { expert > cutoff };
            if strict {
                public_term = public_term - weight;
            }
        }
    }
    (score_weights, theta_weights, public_term)
}

/// Prover-side accounting wrapper for the public affine selector bridge.
/// `eq_vec` performs `2^n - 1` Fp2 multiplications and the implementation
/// above evaluates `weight * a` twice for every logical comparison cell.
fn affine_weights_counted(
    routes: &[[u8; X1_TOP_K]],
    point: &[Fp2],
    ctr: &mut Counters,
) -> (Vec<Fp2>, Vec<Fp2>, Fp2) {
    let out = affine_weights(routes, point);
    ctr.fp2_mults += ((1usize << point.len()) - 1 + 2 * X1_T * X1_EXPERTS) as u64;
    out
}

fn theta_gather_weights(routes: &[[u8; X1_TOP_K]], row_point: &[Fp2]) -> Vec<Fp2> {
    let eq_rows = eq_vec(row_point);
    let mut out = vec![Fp2::ZERO; 32 * 32];
    for row in 0..X1_T {
        out[row * 32 + usize::from(routes[row][0])] = eq_rows[row];
    }
    out
}

fn theta_gather_weights_counted(
    routes: &[[u8; X1_TOP_K]],
    row_point: &[Fp2],
    ctr: &mut Counters,
) -> Vec<Fp2> {
    let out = theta_gather_weights(routes, row_point);
    ctr.fp2_mults += ((1usize << row_point.len()) - 1) as u64;
    out
}

/// Exact arithmetic accounting for the existing streamed public-weight
/// opening: one Fp2 tag multiplication per entry and one Fp2-by-Fp value
/// multiplication (two base multiplications) per nonzero plaintext entry.
fn open_weighted_p_counted(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    weights: &[Fp2],
    ctr: &mut Counters,
) -> ProverAuthed {
    let out = open_weighted_p(stream, dom, vals, weights);
    ctr.fp2_mults += vals.len() as u64;
    ctr.base_mults += 2 * vals.iter().filter(|&&value| value != Fp::ZERO).count() as u64;
    out
}

/// Exact arithmetic accounting for `open_fp_vec_p`, including its internally
/// materialized equality table.
fn open_fp_vec_p_counted(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    point: &[Fp2],
    ctr: &mut Counters,
) -> ProverAuthed {
    let out = open_fp_vec_p(stream, dom, vals, point);
    ctr.fp2_mults += ((1usize << point.len()) - 1 + vals.len()) as u64;
    ctr.base_mults += 2 * vals.iter().filter(|&&value| value != Fp::ZERO).count() as u64;
    out
}

fn public_x_eval(x: &[i16], point: &[Fp2]) -> Fp2 {
    assert_eq!(point.len(), pad_bits(X1_D) + pad_bits(X1_T));
    let (r_l, r_i) = point.split_at(pad_bits(X1_D));
    let folded = fold_x(x, X1_T, X1_D, &eq_vec(r_i));
    eval_mle(&folded, r_l)
}

fn prove_layer(
    witness: &X1LayerWitness,
    luts: &Luts,
    prepared: PreparedP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> (X1LayerProof, WeightClaimP, ProdTriples, Vec<ProverAuthed>, Counters, Counters) {
    let PreparedP {
        doms,
        score_dom,
        theta_dom,
        denom_dom,
        recip_in_dom,
        recips_dom,
        score_corr,
        theta_corr,
        denom_corr,
        recip_in_corr,
        recips_corr,
    } = prepared;
    let score_fp = pad_matrix_i16(&witness.scores);
    let theta_fp = pad_rows_i16(&witness.theta, 0);
    let denom_fp = pad_rows_i64(&witness.denoms);
    let recip_in_fp = pad_rows_i16(&witness.recip_in, 0);
    let recips_fp = pad_rows_i16(&witness.recips, luts.softmax_recip[0]);
    let mut cx = BlockCtxP::with_doms(stream, tx, doms, bank);

    // 1. One u16 limb per expert/token, then the public affine bridge back to
    // authenticated scores and the private authenticated threshold vector.
    let before_comparison = cx.ctr_instances;
    let comparison_out = cx.inst(
        TableKey::Range(16),
        &[pad_comparisons(&witness.comparisons)],
        &[Some(0)],
        Vec::new(),
    );
    let (score_weights, theta_weights, public_term) =
        affine_weights_counted(&witness.routes, &comparison_out.point, &mut cx.ctr_instances);
    let score_open = open_weighted_p_counted(
        cx.stream,
        score_dom,
        &score_fp,
        &score_weights,
        &mut cx.ctr_instances,
    );
    let theta_open = open_weighted_p_counted(
        cx.stream,
        theta_dom,
        &theta_fp,
        &theta_weights,
        &mut cx.ctr_instances,
    );
    push_honest_zero(
        &mut cx.zero,
        comparison_out.col_claims[0]
            .value
            .sub(score_open)
            .sub(theta_open)
            .sub(ProverAuthed::from_public(public_term)),
        "comparison affine bridge",
    );

    // Public-selector gather: theta_i = score[i, cutoff_i].
    let rho_theta: Vec<Fp2> = (0..5).map(|_| cx.tx.challenge_fp2()).collect();
    let theta_at_rho =
        open_fp_vec_p_counted(cx.stream, theta_dom, &theta_fp, &rho_theta, &mut cx.ctr_instances);
    let gather_weights =
        theta_gather_weights_counted(&witness.routes, &rho_theta, &mut cx.ctr_instances);
    let gathered_score = open_weighted_p_counted(
        cx.stream,
        score_dom,
        &score_fp,
        &gather_weights,
        &mut cx.ctr_instances,
    );
    push_honest_zero(&mut cx.zero, theta_at_rho.sub(gathered_score), "theta gather");
    let comparison_counters = sub_counts(cx.ctr_instances, before_comparison);

    // 2. Normalized router score range and the existing softmax Hadamard.
    let score_site = prove_range_site(
        &witness.norm_acc,
        &witness.scores,
        X1_T,
        X1_EXPERTS,
        X1_ROUTER_NORM,
        Vec::new(),
        &mut cx,
    );
    let score_auth = open_fp_vec_p(cx.stream, score_dom, &score_fp, &score_site.main.point);
    push_honest_zero(
        &mut cx.zero,
        score_site.main.col_claims[1].value.sub(score_auth),
        "score authentication",
    );
    let exp_fp = pad_matrix_i16(&witness.exp);
    let exp_tab: Vec<Fp2> = exp_fp.iter().copied().map(Fp2::from_base).collect();
    let recips_tab: Vec<Fp2> =
        (0..32 * 32).map(|index| Fp2::from_base(recips_fp[index / 32])).collect();
    let norm_doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (norm_hadamard, norm_point, exp_claim, recip_claim) = hadamard_prove(
        &score_site.main.point,
        exp_tab.clone(),
        recips_tab,
        score_site.acc_claim,
        &norm_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let recip_open = open_fp_vec_p(cx.stream, recips_dom, &recips_fp, &norm_point[5..]);
    push_honest_zero(&mut cx.zero, recip_claim.sub(recip_open), "reciprocal broadcast");

    // 3. Denominator row sum.  At half column coordinates the MLE is the
    // average, hence the exact public factor 32.
    let rho_rows: Vec<Fp2> = (0..5).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 5];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_value = eval_mle(&exp_tab, &half_point);
    let rowsum_dom = cx.doms.take(1);
    let rowsum_mask = cx.stream.draw_fulls(rowsum_dom, 1)[0];
    let rowsum_corr = rowsum_value - rowsum_mask.x;
    cx.tx.append("x1_rowsum_correction", 16);
    let rowsum_auth = ProverAuthed { x: rowsum_value, m: rowsum_mask.m };
    let denom_open = open_fp_vec_p(cx.stream, denom_dom, &denom_fp, &rho_rows);
    push_honest_zero(
        &mut cx.zero,
        denom_open.sub(rowsum_auth.scale(Fp2::from_base(Fp::new(32)))),
        "exp denominator row sum",
    );

    // 4. Existing exp and reciprocal pair tables.  The reciprocal input
    // floor-shift is the already-logged P4 recip-in deviation: both sides are
    // authenticated and the native witness asserts the relation.
    let pad_in = exp_pad(luts);
    let (exp_in_col, exp_out_col) =
        pair_cols_padded(&witness.requant, &witness.exp, X1_T, X1_EXPERTS, pad_in, 0);
    let exp_out = cx.inst(
        TableKey::Exp,
        &[exp_in_col, exp_out_col],
        &[Some(0), Some(16)],
        vec![
            LeafAuxClaim { col: 1, point: norm_point.clone(), value: exp_claim },
            LeafAuxClaim { col: 1, point: half_point.clone(), value: rowsum_auth },
        ],
    );
    let (recip_in_col, recip_out_col) =
        pair_cols_padded(&witness.recip_in, &witness.recips, X1_T, 1, 0, luts.softmax_recip[0]);
    let recip_out = cx.inst(
        TableKey::SoftmaxRecip,
        &[recip_in_col, recip_out_col],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    close_softmax_recip_cpu(
        &recip_out,
        recip_in_dom,
        &recip_in_fp,
        recips_dom,
        &recips_fp,
        &mut cx,
    );

    // 5. Router requant consumes the exp input claim, then the existing
    // committed-GEMM seam carries the private W evaluation outward.
    // The exp pair uses a valid nonzero input whose output is zero on the
    // padded row; remove that public pad contribution before handing the
    // claim to the zero-padded requant output (the existing attention
    // pad-mask pattern).
    let exp_eq = eq_vec(&exp_out.point);
    let exp_padmask = exp_eq[X1_T * 32..].iter().copied().fold(Fp2::ZERO, |a, b| a + b);
    let exp_pad_term = Fp2::from_base(Fp::from_i64(pad_in as i64)) * exp_padmask;
    let exp_input_claim = exp_out.col_claims[0].value.sub(ProverAuthed::from_public(exp_pad_term));
    let router_site = prove_range_site(
        &witness.raw_acc,
        &witness.requant,
        X1_T,
        X1_EXPERTS,
        X1_ROUTER_REQUANT,
        vec![LeafAuxClaim { col: 1, point: exp_out.point.clone(), value: exp_input_claim }],
        &mut cx,
    );
    let point = router_site.acc_point().to_vec();
    let (r_j, r_i) = point.split_at(5);
    let gemm_doms = ChainDoms::alloc(&mut cx.doms, X1_D);
    let (gemm, x_wire, weight_corr, weight_claim, _, _) = prove_gemm_committed_chained(
        &witness.x,
        &witness.weights,
        X1_T,
        X1_D,
        X1_EXPERTS,
        r_i,
        r_j,
        router_site.acc_claim,
        &gemm_doms,
        cx.stream,
        cx.tx,
    );
    push_honest_zero(
        &mut cx.zero,
        x_wire.value.sub(ProverAuthed::from_public(public_x_eval(&witness.x, &x_wire.point))),
        "public router input",
    );

    let proof = X1LayerProof {
        score_corr,
        theta_corr,
        denom_corr,
        recip_in_corr,
        recips_corr,
        rowsum_corr,
        comparison: comparison_out.proof,
        score_range: score_site.main.proof,
        score_range_stage1: score_site.stage1.map(|value| value.proof),
        norm_hadamard,
        exp: exp_out.proof,
        recip: recip_out.proof,
        router_range: router_site.main.proof,
        router_range_stage1: router_site.stage1.map(|value| value.proof),
        gemm,
        x_corr: x_wire.corr,
        weight_corr,
    };
    (proof, weight_claim, cx.prod, cx.zero, cx.ctr_instances, comparison_counters)
}

pub fn prove_x1_routing(
    fixture: &X1RoutingFixture,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (X1RoutingProof, X1RoutingProverOut) {
    fixture.config.validate().expect("X1 prover config");
    assert_eq!(fixture.config.digest().unwrap(), x1_model_config().digest().unwrap());
    assert_eq!(fixture.layers.len(), X1_LAYERS);
    assert!(fixture.layers.iter().all(|layer| d1_preflight(&layer.routes)));
    let mut bank = TableBankP::new();
    let prepared: Vec<_> = fixture
        .layers
        .iter()
        .enumerate()
        .map(|(layer, witness)| {
            prepare_layer_p(layer, witness, &fixture.luts, stream, tx, &mut bank)
        })
        .collect();
    assert_eq!(bank.content_keys().into_iter().collect::<BTreeSet<_>>(), x1_content_keys());
    let mut table_doms = Doms::new(layer_dom_base(X1_TABLE_SECTION));
    bank.finalize(stream, tx, &mut table_doms);

    let mut proofs = Vec::with_capacity(X1_LAYERS);
    let mut weight_claims = Vec::with_capacity(X1_LAYERS);
    let mut prod = Vec::new();
    let mut zero = Vec::new();
    let mut total = Counters::default();
    let mut comparison = Counters::default();
    for (layer_index, (witness, prepared)) in fixture.layers.iter().zip(prepared).enumerate() {
        let (proof, weight, layer_prod, layer_zero, layer_ctr, comparison_ctr) =
            prove_layer(witness, &fixture.luts, prepared, stream, tx, &mut bank);
        debug_assert!(
            layer_zero.iter().all(|claim| claim.x == Fp2::ZERO),
            "X1 layer {layer_index} emitted a nonzero closure row at {:?}",
            layer_zero.iter().position(|claim| claim.x != Fp2::ZERO)
        );
        proofs.push(proof);
        weight_claims.push(weight);
        prod.extend(layer_prod);
        zero.extend(layer_zero);
        add_counts(&mut total, &layer_ctr);
        add_counts(&mut comparison, &comparison_ctr);
    }
    let preclose = total;
    let tables =
        bank.close(&fixture.luts, stream, &mut table_doms, tx, &mut total, &mut prod, &mut zero);
    let router = sub_counts(preclose, comparison);
    let corr_counters = stream.counters;
    (
        X1RoutingProof { layers: proofs, tables },
        X1RoutingProverOut {
            weight_claims,
            prod,
            zero,
            comparison_counters: comparison,
            router_instance_counters: router,
            total_instance_counters: total,
            corr_counters,
        },
    )
}

fn verify_layer(
    public_x: &[i16],
    routes: &[[u8; X1_TOP_K]],
    luts: &Luts,
    proof: &X1LayerProof,
    prepared: PreparedV,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    bank: &mut TableBankV,
) -> Option<((Vec<Fp2>, VerifierKey), ProdKeyTriples, Vec<VerifierKey>)> {
    let PreparedV { doms, score_keys, theta_keys, denom_keys, recip_in_keys, recips_keys } =
        prepared;
    let mut cx = BlockCtxV::with_doms(ctx, tx, doms, bank);

    let comparison = cx.inst(TableKey::Range(16), 10, &[Some(0)], &proof.comparison, &[])?;
    let (score_weights, theta_weights, public_term) = affine_weights(routes, &comparison.point);
    let score_key = open_weighted_k(&score_keys, &score_weights);
    let theta_key = open_weighted_k(&theta_keys, &theta_weights);
    cx.kzero.push(
        comparison.col_keys[0]
            .key
            .sub(score_key)
            .sub(theta_key)
            .sub(VerifierKey::from_public(public_term, cx.ctx.delta)),
    );

    let rho_theta: Vec<Fp2> = (0..5).map(|_| cx.tx.challenge_fp2()).collect();
    let theta_at_rho = open_fp_vec_k(&theta_keys, &rho_theta);
    let gathered = open_weighted_k(&score_keys, &theta_gather_weights(routes, &rho_theta));
    cx.kzero.push(theta_at_rho.sub(gathered));

    let score_site = verify_range_site(
        10,
        X1_ROUTER_NORM,
        &proof.score_range,
        proof.score_range_stage1.as_ref(),
        &[],
        &mut cx,
    )?;
    let score_auth = open_fp_vec_k(&score_keys, &score_site.main.point);
    cx.kzero.push(score_site.main.col_keys[1].key.sub(score_auth));
    let norm_doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (norm_point, exp_key, recip_key) = hadamard_verify(
        &score_site.main.point,
        score_site.acc_key,
        &proof.norm_hadamard,
        &norm_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    cx.kzero.push(recip_key.sub(open_fp_vec_k(&recips_keys, &norm_point[5..])));

    let rho_rows: Vec<Fp2> = (0..5).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 5];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_dom = cx.doms.take(1);
    let rowsum_key = VerifierKey {
        k: cx.ctx.expand_full_keys(rowsum_dom, 1)[0] + cx.ctx.delta * proof.rowsum_corr,
    };
    cx.kzero.push(
        open_fp_vec_k(&denom_keys, &rho_rows).sub(rowsum_key.scale(Fp2::from_base(Fp::new(32)))),
    );

    let exp_aux = [(1usize, norm_point, exp_key), (1usize, half_point, rowsum_key)];
    let exp = cx.inst(TableKey::Exp, 10, &[Some(0), Some(16)], &proof.exp, &exp_aux)?;
    let recip = cx.inst(TableKey::SoftmaxRecip, 5, &[Some(0), Some(16)], &proof.recip, &[])?;
    close_softmax_recip_verifier(&recip, &recip_in_keys, &recips_keys, &mut cx);

    let exp_eq = eq_vec(&exp.point);
    let exp_padmask = exp_eq[X1_T * 32..].iter().copied().fold(Fp2::ZERO, |a, b| a + b);
    let pad_in = exp_pad(luts);
    let exp_pad_term = Fp2::from_base(Fp::from_i64(pad_in as i64)) * exp_padmask;
    let exp_input_key =
        exp.col_keys[0].key.sub(VerifierKey::from_public(exp_pad_term, cx.ctx.delta));
    let router_aux = [(1usize, exp.point.clone(), exp_input_key)];
    let router = verify_range_site(
        10,
        X1_ROUTER_REQUANT,
        &proof.router_range,
        proof.router_range_stage1.as_ref(),
        &router_aux,
        &mut cx,
    )?;
    let point = router.acc_point().to_vec();
    let (r_j, r_i) = point.split_at(5);
    let gemm_doms = ChainDoms::alloc(&mut cx.doms, X1_D);
    let (x_key, weight_point, weight_key) = verify_gemm_committed_chained(
        X1_T,
        X1_D,
        X1_EXPERTS,
        r_i,
        r_j,
        router.acc_key,
        &proof.gemm,
        proof.x_corr,
        proof.weight_corr,
        &gemm_doms,
        cx.ctx,
        cx.tx,
    )?;
    cx.kzero.push(
        x_key
            .key
            .sub(VerifierKey::from_public(public_x_eval(public_x, &x_key.point), cx.ctx.delta)),
    );
    Some(((weight_point, weight_key), cx.kprod, cx.kzero))
}

pub fn verify_x1_routing(
    config: &ModelConfig,
    luts: &Luts,
    public_x: &[Vec<i16>],
    routes: &[Vec<[u8; X1_TOP_K]>],
    proof: &X1RoutingProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<X1RoutingVerifierOut> {
    config.validate().ok()?;
    if config.digest().ok()? != x1_model_config().digest().ok()?
        || public_x.len() != X1_LAYERS
        || routes.len() != X1_LAYERS
        || proof.layers.len() != X1_LAYERS
        || public_x.iter().any(|x| x.len() != X1_T * X1_D)
        || routes.iter().any(|route| !d1_preflight(route))
    {
        return None;
    }
    let prepared: Vec<_> = proof
        .layers
        .iter()
        .enumerate()
        .map(|(layer, proof)| prepare_layer_v(layer, proof, ctx, tx))
        .collect::<Option<_>>()?;
    let mut table_doms = Doms::new(layer_dom_base(X1_TABLE_SECTION));
    let mut bank =
        TableBankV::finalize(&x1_content_keys(), &proof.tables, ctx, tx, &mut table_doms)?;
    let mut weight_keys = Vec::with_capacity(X1_LAYERS);
    let mut kprod = Vec::new();
    let mut kzero = Vec::new();
    for ((((x, route), layer_proof), prepared), _layer) in
        public_x.iter().zip(routes).zip(&proof.layers).zip(prepared).zip(0..X1_LAYERS)
    {
        let (weight, layer_prod, layer_zero) =
            verify_layer(x, route, luts, layer_proof, prepared, ctx, tx, &mut bank)?;
        weight_keys.push(weight);
        kprod.extend(layer_prod);
        kzero.extend(layer_zero);
    }
    bank.close(luts, &proof.tables, ctx, &mut table_doms, tx, &mut kprod, &mut kzero)?;
    Some(X1RoutingVerifierOut { weight_keys, kprod, kzero })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::thaler::fold_w;
    use volta_mac::zero_batch_exchange;

    fn weight_eval(weight: &[i16], point: &[Fp2]) -> Fp2 {
        let eq_col = eq_vec(&point[..5]);
        let folded = fold_w(weight, X1_D, X1_EXPERTS, &eq_col);
        eval_mle(&folded, &point[5..])
    }

    enum Tamper {
        None,
        WrongSet,
        ScoreSwap,
        ForgedLimb,
        WorseTieCutoff,
    }

    struct GoldenReader {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl GoldenReader {
        fn new(bytes: Vec<u8>) -> Self {
            Self { bytes, pos: 0 }
        }

        fn take<const N: usize>(&mut self) -> [u8; N] {
            let end = self.pos + N;
            let out: [u8; N] = self.bytes[self.pos..end].try_into().unwrap();
            self.pos = end;
            out
        }

        fn u8(&mut self) -> u8 {
            self.take::<1>()[0]
        }

        fn u16(&mut self) -> u16 {
            u16::from_le_bytes(self.take())
        }

        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.take())
        }

        fn i16(&mut self) -> i16 {
            i16::from_le_bytes(self.take())
        }

        fn i64(&mut self) -> i64 {
            i64::from_le_bytes(self.take())
        }

        fn vec_i16(&mut self, n: usize) -> Vec<i16> {
            (0..n).map(|_| self.i16()).collect()
        }

        fn vec_i64(&mut self, n: usize) -> Vec<i64> {
            (0..n).map(|_| self.i64()).collect()
        }

        fn vec_u16(&mut self, n: usize) -> Vec<u16> {
            (0..n).map(|_| self.u16()).collect()
        }
    }

    fn run_case(all_equal: bool, tamper: Tamper) -> bool {
        let fixture = build_x1_routing_fixture(all_equal);
        let pcg_seed = [0x61; 32];
        let tx_seed = [0x62; 32];
        let delta = Fp2::new(Fp::new(0x1234_5678), Fp::new(0x9abc_def0));
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut txp = Transcript::new(tx_seed);
        let (mut proof, mut pout) = prove_x1_routing(&fixture, &mut stream, &mut txp);
        let public_x: Vec<_> = fixture.layers.iter().map(|layer| layer.x.clone()).collect();
        let mut routes: Vec<_> = fixture.layers.iter().map(|layer| layer.routes.clone()).collect();
        match tamper {
            Tamper::None => {}
            Tamper::WrongSet => routes[0][0] = [27, 29, 30, 31],
            Tamper::ScoreSwap => proof.layers[0].score_corr.swap(0, 1),
            Tamper::ForgedLimb => proof.layers[0].comparison.lookup.root_corrs[0] += Fp2::ONE,
            Tamper::WorseTieCutoff => routes[0][0] = [29, 28, 30, 31],
        }
        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut txv = Transcript::new(tx_seed);
        let Some(mut vout) = verify_x1_routing(
            &fixture.config,
            &fixture.luts,
            &public_x,
            &routes,
            &proof,
            &mut verifier,
            &mut txv,
        ) else {
            return false;
        };
        for (((claim, (point, key)), layer), _index) in
            pout.weight_claims.iter().zip(&vout.weight_keys).zip(&fixture.layers).zip(0..X1_LAYERS)
        {
            if claim.point != *point {
                return false;
            }
            let value = weight_eval(&layer.weights, point);
            pout.zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            vout.kzero.push(key.sub(VerifierKey::from_public(value, delta)));
        }
        if let Some((index, claim)) =
            pout.zero.iter().enumerate().find(|(_, claim)| claim.x != Fp2::ZERO)
        {
            panic!("X1 prover zero row {index} is nonzero: {:?}", claim.x);
        }
        let mut closure_p = Doms::new(layer_dom_base(253));
        let mut closure_v = Doms::new(layer_dom_base(253));
        let chi = txp.challenge_fp2();
        if chi != txv.challenge_fp2() {
            return false;
        }
        let prod_dom = closure_p.take(1);
        if prod_dom != closure_v.take(1) {
            return false;
        }
        let mask = stream.draw_fulls(prod_dom, 1)[0];
        let key = verifier.expand_full_keys(prod_dom, 1)[0];
        let prod_proof = prod_batch_prover(&pout.prod, chi, mask, &mut txp);
        let prod_ok = prod_batch_verify(&vout.kprod, key, delta, chi, &prod_proof);
        let zero_dom = closure_p.take(1);
        if zero_dom != closure_v.take(1) {
            return false;
        }
        let zero_ok = zero_batch_exchange(
            &pout.zero,
            &vout.kzero,
            &mut stream,
            &mut verifier,
            zero_dom,
            &mut txp,
        );
        prod_ok && zero_ok
    }

    #[test]
    fn native_tie_rule_and_geometry_are_pinned() {
        let route = native_top_k_d1(&[7; X1_EXPERTS]).unwrap();
        assert_eq!(route, [28, 29, 30, 31]);
        let fixture = build_x1_routing_fixture(false);
        assert_eq!(X1_LOGICAL_COMPARISONS, 3_968);
        assert_eq!(X1_PADDED_COMPARISONS, 4_096);
        assert!(fixture
            .layers
            .iter()
            .all(|layer| { layer.routes.iter().all(|route| *route == [28, 29, 30, 31]) }));
    }

    #[test]
    fn x1_native_witness_is_bit_exact_with_external_numpy_golden() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/x123/x1-router-v1.golden.bin");
        let bytes = std::fs::read(path).unwrap();
        let fixture = build_x1_routing_fixture(false);
        assert_eq!(encode_x1_golden(&fixture), bytes);
        let mut reader = GoldenReader::new(bytes);
        assert_eq!(&reader.take::<16>(), b"VOLTA-X1-GOLD-V1");
        assert_eq!(
            (0..9).map(|_| reader.u32()).collect::<Vec<_>>(),
            vec![31, 4, 48, 32, 4, 8, 12, 6, 12]
        );
        for layer in &fixture.layers {
            assert_eq!(reader.vec_i16(X1_T * X1_D), layer.x);
            assert_eq!(reader.vec_i16(X1_D * X1_EXPERTS), layer.weights);
            assert_eq!(reader.vec_i64(X1_T * X1_EXPERTS), layer.raw_acc);
            assert_eq!(reader.vec_i16(X1_T * X1_EXPERTS), layer.requant);
            assert_eq!(reader.vec_i16(X1_T * X1_EXPERTS), layer.exp);
            assert_eq!(reader.vec_i64(X1_T), layer.denoms);
            assert_eq!(reader.vec_i16(X1_T), layer.recip_in);
            assert_eq!(reader.vec_i16(X1_T), layer.recips);
            assert_eq!(reader.vec_i64(X1_T * X1_EXPERTS), layer.norm_acc);
            assert_eq!(reader.vec_i16(X1_T * X1_EXPERTS), layer.scores);
            let routes: Vec<u8> = layer.routes.iter().flatten().copied().collect();
            assert_eq!((0..X1_T * X1_TOP_K).map(|_| reader.u8()).collect::<Vec<_>>(), routes);
            assert_eq!(reader.vec_i16(X1_T), layer.theta);
            assert_eq!(reader.vec_u16(X1_T * X1_EXPERTS), layer.comparisons);
        }
        assert_eq!((0..X1_TOP_K).map(|_| reader.u8()).collect::<Vec<_>>(), [28, 29, 30, 31]);
        assert_eq!(reader.vec_u16(X1_EXPERTS), vec![0; X1_EXPERTS]);
        assert_eq!(reader.pos, reader.bytes.len());
    }

    #[test]
    fn x1_honest_and_preregistered_cheats() {
        assert!(run_case(false, Tamper::None));
        assert!(!run_case(false, Tamper::WrongSet));
        assert!(!run_case(false, Tamper::ScoreSwap));
        assert!(!run_case(false, Tamper::ForgedLimb));
        assert!(run_case(true, Tamper::None));
        assert!(!run_case(true, Tamper::WrongSet));
        assert!(!run_case(true, Tamper::WorseTieCutoff));
    }
}
