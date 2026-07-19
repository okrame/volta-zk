//! Existing-class proof composition for the X2 synthetic MoE fixture.

use crate::block_proof::{
    auth_fp_vec_p, close_softmax_recip_cpu, close_softmax_recip_verifier, keys_fp_vec_v,
    layer_dom_base, open_fp_vec_k, open_fp_vec_p, open_weighted_k, open_weighted_p,
    pair_cols_padded, prove_range_site, range_mult, verify_range_site, BlockCtxP, BlockCtxV,
    RangeSiteP, TableBankP, TableBankV, TableCloseProof,
};
use crate::boundary_thinning::{
    prove_eq_reduction_i16, prove_matrix_eval_claim_i16, verify_eq_reduction,
    verify_matrix_eval_claim, BoundaryClaimK, BoundaryClaimP, EqReductionProof,
};
use crate::gemm_proof::{
    prove_gemm_act_chained, prove_gemm_committed_chained, verify_gemm_act_chained,
    verify_gemm_committed_chained, ChainDoms, ChainedGemmProof, WeightClaimP,
};
use crate::hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
use crate::logup::{
    BlindInstance, Counters, Doms, LeafAuxClaim, ProdKeyTriples, ProdTriples, TableKey,
};
use crate::mle::{eq_vec, eval_mle};
use crate::thaler::pad_bits;
use crate::x2_moe::{
    eval_i16_matrix, x2_model_config, x2_public_routes, X2ExpertWitness, X2LayerWitness,
    X2MoeFixture, X2_D, X2_DFF, X2_EXPERTS, X2_HEAD_DIM, X2_KV_HEADS, X2_LAYERS, X2_QKV,
    X2_Q_HEADS, X2_SHIFT, X2_T, X2_TOP_K, X2_VOCAB,
};
use std::collections::BTreeSet;
use volta_field::{Fp, Fp2};
use volta_mac::{
    CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

const X2_GLOBAL_SECTION: u8 = 216;
const X2_LAYER_SECTION: u8 = 217;
const X2_TABLE_SECTION: u8 = 219;

const A_NORM_INPUT: usize = 0;
const A_NORM_MEAN: usize = 1;
const A_NORM_RIN: usize = 2;
const A_NORM_RSQRT: usize = 3;
const A_NORM_OUT: usize = 4;
const A_QKV: usize = 5;
const A_Q: usize = 6;
const A_K: usize = 7;
const A_V: usize = 8;
const A_DENOM: usize = 9;
const A_RECIP_IN: usize = 10;
const A_RECIP: usize = 11;
const A_ABOVE: usize = 13;
const A_ATTN_PROJ: usize = 14;
const A_ROUTER_SCORES: usize = 15;
const A_ROUTER_THETA: usize = 16;
const A_ROUTER_EXP: usize = 17;
const A_ROUTER_DENOM: usize = 18;
const A_ROUTER_RECIP_IN: usize = 19;
const A_ROUTER_RECIP: usize = 20;
const A_ROUTE_BASE: usize = 21;
const A_ROUTE_BROADCAST: usize = 22;
const A_ROUTE_VALUES: usize = 23;
const LAYER_AUTH_COUNT: usize = 24;

const G_EMBED_OUT: usize = 0;
const G_ENTRY: usize = 1;
const G_INTERNAL: usize = 2;
const G_EXIT: usize = 3;
const G_FINAL_MEAN: usize = 4;
const G_FINAL_RIN: usize = 5;
const G_FINAL_RSQRT: usize = 6;
const G_FINAL_OUT: usize = 7;
const G_FINAL_LUT_RIN: usize = 8;
const G_FINAL_LUT_ROUT: usize = 9;
const GLOBAL_AUTH_COUNT: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub struct X2RangeProof {
    pub main: BlindInstance,
    pub stage1: Option<BlindInstance>,
}

impl From<RangeSiteP> for X2RangeProof {
    fn from(site: RangeSiteP) -> Self {
        Self { main: site.main.proof, stage1: site.stage1.map(|value| value.proof) }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2CommittedGemmProof {
    pub proof: ChainedGemmProof,
    pub x_corr: Fp2,
    pub weight_corr: Fp2,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2ActGemmProof {
    pub proof: ChainedGemmProof,
    pub x_corr: Fp2,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2ExpertProof {
    pub down: X2RangeProof,
    pub down_gemm: X2CommittedGemmProof,
    pub gelu: BlindInstance,
    pub up: X2RangeProof,
    pub up_gemm: X2CommittedGemmProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2AttentionProof {
    pub projection: X2RangeProof,
    pub projection_gemm: X2CommittedGemmProof,
    pub av: X2RangeProof,
    pub av_split_corrs: Vec<Fp2>,
    pub av_gemms: Vec<X2ActGemmProof>,
    pub softmax_norm: X2RangeProof,
    pub softmax_hadamard: HadamardProof,
    pub exp_rowsum_corr: Fp2,
    pub exp: BlindInstance,
    pub reciprocal: BlindInstance,
    pub scores: X2RangeProof,
    pub score_split_corrs: Vec<Fp2>,
    pub qk_gemms: Vec<X2ActGemmProof>,
    pub qkv: X2RangeProof,
    pub qkv_gemm: X2CommittedGemmProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2NormProof {
    pub range: X2RangeProof,
    pub hadamard: HadamardProof,
    pub rsqrt: BlindInstance,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2RouterProof {
    pub comparisons: BlindInstance,
    pub requant: X2RangeProof,
    pub gemm: X2CommittedGemmProof,
    pub exp_rowsum_corr: Fp2,
    pub exp: BlindInstance,
    pub reciprocal: BlindInstance,
    pub route_norm: X2RangeProof,
    pub route_hadamard: HadamardProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2LayerProof {
    pub auth_corrs: Vec<Vec<u64>>,
    pub combine: X2RangeProof,
    pub combine_hadamard: HadamardProof,
    pub experts: Vec<X2ExpertProof>,
    pub router: X2RouterProof,
    pub attention: X2AttentionProof,
    pub norm: X2NormProof,
    pub local_output_corr: Option<Fp2>,
    pub(crate) reducer: Option<EqReductionProof>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2GlobalProof {
    pub auth_corrs: Vec<Vec<u64>>,
    pub embedding: X2RangeProof,
    pub seam: X2RangeProof,
    pub final_norm: X2RangeProof,
    pub final_hadamard: HadamardProof,
    pub final_rsqrt: BlindInstance,
    pub embedding_weight_corr: Fp2,
    pub output_gemm: X2CommittedGemmProof,
}

#[derive(Debug, PartialEq, Eq)]
pub struct X2MoeProof {
    pub thin_k: usize,
    pub global: X2GlobalProof,
    pub layers: Vec<X2LayerProof>,
    pub tables: Vec<TableCloseProof>,
}

impl X2MoeProof {
    /// Deterministic cheating-prover hook used only by the permanent X2 gate
    /// and its report binary. The verifier still sees an otherwise
    /// well-formed k=2 proof, so rejection exercises the existing T1
    /// equality reducer rather than a parser/preflight failure.
    #[doc(hidden)]
    pub fn smoke_tamper_internal_reducer(&mut self) -> bool {
        let Some(reducer) = self.layers.get_mut(0).and_then(|layer| layer.reducer.as_mut()) else {
            return false;
        };
        reducer.terminal_corr += Fp2::ONE;
        true
    }
}

pub struct X2MoeProverOut {
    /// `[layer0: 19, layer1: 19, global: 2]`.
    pub weight_claims: Vec<WeightClaimP>,
    pub prod: ProdTriples,
    pub zero: Vec<ProverAuthed>,
    pub instance_counters: Counters,
    pub other_counters: Counters,
    pub corr_counters: CorrCounters,
    pub table_sites: usize,
    pub table_contents: usize,
    pub table_finalizations: usize,
    pub logical_lookup_rows: usize,
    pub padded_lookup_rows: usize,
}

pub struct X2MoeVerifierOut {
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    pub kprod: ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

struct PreparedP {
    doms: Doms,
    auth_doms: Vec<u64>,
    auth_values: Vec<Vec<Fp>>,
    auth_corrs: Vec<Vec<u64>>,
}

struct PreparedV {
    doms: Doms,
    auth_keys: Vec<Vec<Fp2>>,
}

fn fp_i16(value: i16) -> Fp {
    Fp::from_i64(value as i64)
}

fn fp_i64(value: i64) -> Fp {
    Fp::from_i64(value)
}

fn pad_i16(values: &[i16], size: usize, pad: i16) -> Vec<Fp> {
    assert!(values.len() <= size && size.is_power_of_two());
    let mut out = vec![fp_i16(pad); size];
    for (dst, &value) in out.iter_mut().zip(values) {
        *dst = fp_i16(value);
    }
    out
}

fn pad_i64(values: &[i64], size: usize, pad: i64) -> Vec<Fp> {
    assert!(values.len() <= size && size.is_power_of_two());
    let mut out = vec![fp_i64(pad); size];
    for (dst, &value) in out.iter_mut().zip(values) {
        *dst = fp_i64(value);
    }
    out
}

fn pad_matrix_i16(values: &[i16], rows: usize, cols: usize, pad: i16) -> Vec<Fp> {
    assert_eq!(values.len(), rows * cols);
    let (rp, cp) = (rows.next_power_of_two(), cols.next_power_of_two());
    let mut out = vec![fp_i16(pad); rp * cp];
    for row in 0..rows {
        for col in 0..cols {
            out[row * cp + col] = fp_i16(values[row * cols + col]);
        }
    }
    out
}

fn pad_matrix_i64(values: &[i64], rows: usize, cols: usize, pad: i64) -> Vec<Fp> {
    assert_eq!(values.len(), rows * cols);
    let (rp, cp) = (rows.next_power_of_two(), cols.next_power_of_two());
    let mut out = vec![fp_i64(pad); rp * cp];
    for row in 0..rows {
        for col in 0..cols {
            out[row * cp + col] = fp_i64(values[row * cols + col]);
        }
    }
    out
}

fn fp2_table(values: &[Fp]) -> Vec<Fp2> {
    values.iter().copied().map(Fp2::from_base).collect()
}

fn signed_pair_mult(inputs: &[i16], outputs: &[i16], pad_in: i16, size: usize) -> Vec<u32> {
    assert_eq!(inputs.len(), outputs.len());
    assert!(inputs.len() <= size && size.is_power_of_two());
    let mut out = vec![0u32; 1 << 16];
    for (&input, _) in inputs.iter().zip(outputs) {
        out[input as u16 as usize] += 1;
    }
    out[pad_in as u16 as usize] += (size - inputs.len()) as u32;
    out
}

fn unsigned_pair_mult(inputs: &[i16], size: usize) -> Vec<u32> {
    assert!(inputs.len() <= size && size.is_power_of_two());
    let mut out = vec![0u32; 1 << 16];
    for &input in inputs {
        out[input as u16 as usize] += 1;
    }
    out[0] += (size - inputs.len()) as u32;
    out
}

fn comparison_mult(values: &[u16], size: usize) -> Vec<u32> {
    assert!(values.len() <= size && size.is_power_of_two());
    let mut out = vec![0u32; 1 << 16];
    for &value in values {
        out[usize::from(value)] += 1;
    }
    out[0] += (size - values.len()) as u32;
    out
}

fn exp_pad(luts: &volta_gpt2::Luts) -> i16 {
    luts.exp.iter().position(|&value| value == 0).expect("X2 exp zero pad") as u16 as i16
}

fn add_counts(dst: &mut Counters, src: Counters) {
    dst.fp2_mults += src.fp2_mults;
    dst.base_mults += src.base_mults;
}

fn push_zero(rows: &mut Vec<ProverAuthed>, value: ProverAuthed, label: &str) {
    debug_assert_eq!(value.x, Fp2::ZERO, "X2 honest relation failed: {label}");
    rows.push(value);
}

fn auth_values_p(values: Vec<Vec<Fp>>, cx: &mut BlockCtxP<'_>) -> (Vec<u64>, Vec<Vec<u64>>) {
    let mut doms = Vec::with_capacity(values.len());
    let mut corrections = Vec::with_capacity(values.len());
    for value in &values {
        let dom = cx.doms.take(1);
        doms.push(dom);
        corrections.push(auth_fp_vec_p(cx.stream, cx.tx, dom, value));
    }
    (doms, corrections)
}

fn auth_values_v(
    corrections: &[Vec<u64>],
    lengths: &[usize],
    cx: &mut BlockCtxV<'_>,
) -> Option<Vec<Vec<Fp2>>> {
    if corrections.len() != lengths.len()
        || corrections.iter().zip(lengths).any(|(corr, &len)| corr.len() != len)
    {
        return None;
    }
    Some(corrections.iter().map(|corr| keys_fp_vec_v(cx.ctx, cx.doms.take(1), corr)).collect())
}

fn open_auth_p(
    prepared: &PreparedP,
    index: usize,
    point: &[Fp2],
    stream: &mut CorrelationStream,
) -> ProverAuthed {
    open_fp_vec_p(stream, prepared.auth_doms[index], &prepared.auth_values[index], point)
}

fn open_auth_k(prepared: &PreparedV, index: usize, point: &[Fp2]) -> VerifierKey {
    open_fp_vec_k(&prepared.auth_keys[index], point)
}

fn open_auth_weighted_p(
    prepared: &PreparedP,
    index: usize,
    weights: &[Fp2],
    stream: &mut CorrelationStream,
) -> ProverAuthed {
    open_weighted_p(stream, prepared.auth_doms[index], &prepared.auth_values[index], weights)
}

fn open_auth_weighted_k(prepared: &PreparedV, index: usize, weights: &[Fp2]) -> VerifierKey {
    open_weighted_k(&prepared.auth_keys[index], weights)
}

fn inv_pow2(shift: u32) -> Fp2 {
    Fp2::from_base(Fp::new(1u64 << shift).inv())
}

fn bit_point(value: usize, bits: usize) -> Vec<Fp2> {
    (0..bits).map(|bit| if value & (1 << bit) == 0 { Fp2::ZERO } else { Fp2::ONE }).collect()
}

fn fresh_eval_p(value: Fp2, label: &'static str, cx: &mut BlockCtxP<'_>) -> (Fp2, ProverAuthed) {
    let dom = cx.doms.take(1);
    let mask = cx.stream.draw_fulls(dom, 1)[0];
    let corr = value - mask.x;
    cx.tx.append(label, 16);
    (corr, ProverAuthed { x: value, m: mask.m })
}

fn fresh_eval_k(corr: Fp2, label: &'static str, cx: &mut BlockCtxV<'_>) -> VerifierKey {
    let dom = cx.doms.take(1);
    let key = cx.ctx.expand_full_keys(dom, 1)[0] + cx.ctx.delta * corr;
    cx.tx.append(label, 16);
    VerifierKey { k: key }
}

fn fresh_split_p(
    values: &[Fp2],
    label: &'static str,
    cx: &mut BlockCtxP<'_>,
) -> (Vec<Fp2>, Vec<ProverAuthed>) {
    let dom = cx.doms.take(1);
    let masks = cx.stream.draw_fulls(dom, values.len());
    let corrs = values.iter().zip(&masks).map(|(&value, mask)| value - mask.x).collect();
    let claims = values.iter().zip(masks).map(|(&x, mask)| ProverAuthed { x, m: mask.m }).collect();
    cx.tx.append(label, 16 * values.len() as u64);
    (corrs, claims)
}

fn fresh_split_k(corrs: &[Fp2], label: &'static str, cx: &mut BlockCtxV<'_>) -> Vec<VerifierKey> {
    let dom = cx.doms.take(1);
    let masks = cx.ctx.expand_full_keys(dom, corrs.len());
    cx.tx.append(label, 16 * corrs.len() as u64);
    masks
        .into_iter()
        .zip(corrs)
        .map(|(mask, &corr)| VerifierKey { k: mask + cx.ctx.delta * corr })
        .collect()
}

fn eval_i64_matrix(values: &[i64], rows: usize, cols: usize, point: &[Fp2]) -> Fp2 {
    assert_eq!(values.len(), rows * cols);
    assert_eq!(point.len(), pad_bits(rows) + pad_bits(cols));
    let mut padded = vec![Fp2::ZERO; rows.next_power_of_two() * cols.next_power_of_two()];
    let cp = cols.next_power_of_two();
    for row in 0..rows {
        for col in 0..cols {
            padded[row * cp + col] = Fp2::from_base(fp_i64(values[row * cols + col]));
        }
    }
    eval_mle(&padded, point)
}

/// Explicit public selector into the combined `[LN1 rows || LN2 rows]`
/// authentication. `point` is a logical `T x d` point (`cols || rows`).
fn norm_half_weights(point: &[Fp2], second: bool) -> Vec<Fp2> {
    assert_eq!(point.len(), 9);
    let eq_col = eq_vec(&point[..6]);
    let eq_row = eq_vec(&point[6..]);
    let mut weights = vec![Fp2::ZERO; 16 * 64];
    for row in 0..X2_T {
        let physical = row + if second { X2_T } else { 0 };
        for col in 0..64 {
            weights[physical * 64 + col] = eq_row[row] * eq_col[col];
        }
    }
    weights
}

fn route_grid_weights(rows: &[(usize, usize)], point: &[Fp2]) -> Vec<Fp2> {
    let rb = pad_bits(rows.len());
    assert_eq!(point.len(), 6 + rb);
    let eq_col = eq_vec(&point[..6]);
    let eq_row = eq_vec(&point[6..]);
    let mut weights = vec![Fp2::ZERO; 16 * 64];
    for (job_row, &(token, slot)) in rows.iter().enumerate() {
        let route_row = token * X2_TOP_K + slot;
        for col in 0..64 {
            weights[route_row * 64 + col] = eq_row[job_row] * eq_col[col];
        }
    }
    weights
}

fn gathered_norm_weights(rows: &[(usize, usize)], point: &[Fp2]) -> Vec<Fp2> {
    let rb = pad_bits(rows.len());
    assert_eq!(point.len(), 6 + rb);
    let eq_col = eq_vec(&point[..6]);
    let eq_row = eq_vec(&point[6..]);
    let mut weights = vec![Fp2::ZERO; 16 * 64];
    for (job_row, &(token, _)) in rows.iter().enumerate() {
        let physical = X2_T + token;
        for col in 0..64 {
            weights[physical * 64 + col] = eq_row[job_row] * eq_col[col];
        }
    }
    weights
}

fn qkv_slice_weights(kind: usize, point: &[Fp2]) -> Vec<Fp2> {
    let source_cols = if kind == 0 { 64 } else { 16 };
    let logical_cols = if kind == 0 { X2_D } else { X2_KV_HEADS * X2_HEAD_DIM };
    let source_bits = pad_bits(source_cols);
    assert_eq!(point.len(), source_bits + 3);
    let eq = eq_vec(point);
    let base = match kind {
        0 => 0,
        1 => X2_D,
        2 => X2_D + X2_KV_HEADS * X2_HEAD_DIM,
        _ => unreachable!(),
    };
    let mut weights = vec![Fp2::ZERO; 8 * 128];
    for row in 0..X2_T {
        for col in 0..logical_cols {
            weights[row * 128 + base + col] = eq[row * source_cols + col];
        }
    }
    weights
}

fn d1_preflight(routes: &[[u8; X2_TOP_K]]) -> bool {
    routes.len() == X2_T
        && routes.iter().all(|route| {
            route[0] != route[1] && route.iter().all(|&expert| usize::from(expert) < X2_EXPERTS)
        })
}

fn selected(route: &[u8; X2_TOP_K], expert: usize) -> bool {
    route.iter().any(|&value| usize::from(value) == expert)
}

fn router_affine_weights(routes: &[[u8; X2_TOP_K]], point: &[Fp2]) -> (Vec<Fp2>, Vec<Fp2>, Fp2) {
    assert_eq!(point.len(), 6);
    let eq = eq_vec(point);
    let mut score_weights = vec![Fp2::ZERO; 64];
    let mut theta_weights = vec![Fp2::ZERO; 8];
    let mut public_term = Fp2::ZERO;
    for row in 0..X2_T {
        let route = &routes[row];
        let cutoff = usize::from(route[0]);
        for expert in 0..X2_EXPERTS {
            let weight = eq[row * 8 + expert];
            let sign = if selected(route, expert) { Fp2::ONE } else { Fp2::ZERO - Fp2::ONE };
            score_weights[row * 8 + expert] = weight * sign;
            theta_weights[row] = theta_weights[row] - weight * sign;
            let strict = if selected(route, expert) { expert < cutoff } else { expert > cutoff };
            if strict {
                public_term = public_term - weight;
            }
        }
    }
    (score_weights, theta_weights, public_term)
}

fn cutoff_gather_weights(routes: &[[u8; X2_TOP_K]], row_point: &[Fp2]) -> Vec<Fp2> {
    assert_eq!(row_point.len(), 3);
    let eq_rows = eq_vec(row_point);
    let mut weights = vec![Fp2::ZERO; 64];
    for row in 0..X2_T {
        weights[row * 8 + usize::from(routes[row][0])] = eq_rows[row];
    }
    weights
}

fn selected_exp_weights(routes: &[[u8; X2_TOP_K]], route_point: &[Fp2]) -> Vec<Fp2> {
    assert_eq!(route_point.len(), 4);
    let eq = eq_vec(route_point);
    let mut weights = vec![Fp2::ZERO; 64];
    for row in 0..X2_T {
        for slot in 0..X2_TOP_K {
            weights[row * 8 + usize::from(routes[row][slot])] += eq[row * X2_TOP_K + slot];
        }
    }
    weights
}

fn route_base_broadcast_weights(point: &[Fp2]) -> Vec<Fp2> {
    assert_eq!(point.len(), 10);
    let eq_col = eq_vec(&point[..6]);
    let col_mass = eq_col[..X2_D].iter().copied().fold(Fp2::ZERO, |sum, value| sum + value);
    let eq_row = eq_vec(&point[6..]);
    eq_row.into_iter().map(|value| value * col_mass).collect()
}

fn attention_head_slice(matrix: &[i64], point: &[Fp2], head: usize) -> Fp2 {
    assert_eq!(matrix.len(), X2_T * X2_D);
    assert_eq!(point.len(), 6);
    let mut slice = vec![0i64; X2_T * X2_HEAD_DIM];
    for row in 0..X2_T {
        slice[row * X2_HEAD_DIM..(row + 1) * X2_HEAD_DIM].copy_from_slice(
            &matrix[row * X2_D + head * X2_HEAD_DIM..row * X2_D + (head + 1) * X2_HEAD_DIM],
        );
    }
    eval_i64_matrix(&slice, X2_T, X2_HEAD_DIM, point)
}

fn score_head_slice(values: &[i64], point: &[Fp2], head: usize) -> Fp2 {
    assert_eq!(values.len(), X2_Q_HEADS * X2_T * X2_T);
    assert_eq!(point.len(), 6);
    eval_i64_matrix(&values[head * X2_T * X2_T..(head + 1) * X2_T * X2_T], X2_T, X2_T, point)
}

fn full_attention_scores(layer: &X2LayerWitness) -> Vec<i64> {
    let mut out = vec![0i64; X2_Q_HEADS * X2_T * X2_T];
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        for row in 0..X2_T {
            for col in 0..X2_T {
                let mut value = 0i64;
                for lane in 0..X2_HEAD_DIM {
                    value += i64::from(layer.dense.q[row * X2_D + head * X2_HEAD_DIM + lane])
                        * i64::from(
                            layer.dense.k
                                [col * (X2_KV_HEADS * X2_HEAD_DIM) + kv_head * X2_HEAD_DIM + lane],
                        );
                }
                out[head * X2_T * X2_T + row * X2_T + col] = value;
            }
        }
    }
    out
}

fn norm_arrays(layer: &X2LayerWitness) -> (Vec<i64>, Vec<i16>) {
    let mut acc = layer.dense.ln1_acc.clone();
    acc.extend_from_slice(&layer.dense.ln2_acc);
    let mut out = layer.dense.ln1_out.clone();
    out.extend_from_slice(&layer.dense.ln2_out);
    (acc, out)
}

fn norm_auth_values(layer: &X2LayerWitness) -> [Vec<Fp>; 5] {
    let mut inputs = layer.dense.x_in.clone();
    inputs.extend_from_slice(&layer.dense.attn_block_out);
    let mut means = Vec::with_capacity(14 * X2_D);
    let mut rins = Vec::with_capacity(14 * X2_D);
    let mut rsqrts = Vec::with_capacity(14 * X2_D);
    for ((&mean, &rin), &rsqrt) in layer
        .dense
        .ln1_mean
        .iter()
        .chain(&layer.dense.ln2_mean)
        .zip(layer.dense.ln1_rsqrt_in.iter().chain(&layer.dense.ln2_rsqrt_in))
        .zip(layer.dense.ln1_rsqrt_out.iter().chain(&layer.dense.ln2_rsqrt_out))
    {
        means.extend(std::iter::repeat_n(mean, X2_D));
        rins.extend(std::iter::repeat_n(rin, X2_D));
        rsqrts.extend(std::iter::repeat_n(rsqrt, X2_D));
    }
    let (_, outputs) = norm_arrays(layer);
    [
        pad_matrix_i16(&inputs, 2 * X2_T, X2_D, 0),
        pad_matrix_i64(&means, 2 * X2_T, X2_D, 0),
        pad_matrix_i64(&rins, 2 * X2_T, X2_D, 0),
        pad_matrix_i16(&rsqrts, 2 * X2_T, X2_D, 0),
        pad_matrix_i16(&outputs, 2 * X2_T, X2_D, 0),
    ]
}

fn attention_rect(
    layer: &X2LayerWitness,
    luts: &volta_gpt2::Luts,
) -> (Vec<i64>, Vec<i16>, Vec<i16>, Vec<i16>, Vec<i64>) {
    let pad_in = exp_pad(luts);
    let mut acc_transport = vec![(i64::from(pad_in)) << X2_SHIFT; 8 * 8 * 8];
    let mut scores = vec![pad_in; 8 * 8 * 8];
    let mut exp = vec![0i16; 8 * 8 * 8];
    let mut weights = vec![0i16; 8 * 8 * 8];
    let mut above = Vec::with_capacity(X2_Q_HEADS * X2_T * (X2_T - 1) / 2);
    let caus = X2_T * (X2_T + 1) / 2;
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        let q = &layer.dense.q;
        let k = &layer.dense.k;
        let mut full = vec![0i64; X2_T * X2_T];
        for row in 0..X2_T {
            for col in 0..X2_T {
                let mut value = 0i64;
                for lane in 0..X2_HEAD_DIM {
                    value += i64::from(q[row * X2_D + head * X2_HEAD_DIM + lane])
                        * i64::from(
                            k[col * (X2_KV_HEADS * X2_HEAD_DIM) + kv_head * X2_HEAD_DIM + lane],
                        );
                }
                full[row * X2_T + col] = value;
                if col > row {
                    above.push(value);
                }
            }
        }
        let mut packed = head * caus;
        for row in 0..X2_T {
            for col in 0..=row {
                let index = head * 64 + row * 8 + col;
                acc_transport[index] = full[row * X2_T + col];
                scores[index] = layer.dense.scores_q[packed];
                exp[index] = layer.dense.exp_out[packed];
                weights[index] = layer.dense.softmax_w[packed];
                packed += 1;
            }
        }
    }
    (acc_transport, scores, exp, weights, above)
}

fn row_table_i16(values: &[i16], pad: i16) -> Vec<Fp> {
    assert_eq!(values.len(), X2_Q_HEADS * X2_T);
    let mut out = vec![fp_i16(pad); 8 * 8];
    for head in 0..X2_Q_HEADS {
        for row in 0..X2_T {
            out[head * 8 + row] = fp_i16(values[head * X2_T + row]);
        }
    }
    out
}

fn row_table_i64(values: &[i64]) -> Vec<Fp> {
    assert_eq!(values.len(), X2_Q_HEADS * X2_T);
    let mut out = vec![Fp::ZERO; 8 * 8];
    for head in 0..X2_Q_HEADS {
        for row in 0..X2_T {
            out[head * 8 + row] = fp_i64(values[head * X2_T + row]);
        }
    }
    out
}

fn route_tables(layer: &X2LayerWitness) -> (Vec<Fp>, Vec<Fp>) {
    let mut base = vec![Fp::ZERO; 16];
    let mut broadcast = vec![Fp::ZERO; 16 * 64];
    for token in 0..X2_T {
        for slot in 0..X2_TOP_K {
            let value = fp_i16(layer.router.route_weights[token * X2_TOP_K + slot]);
            base[token * 2 + slot] = value;
            for col in 0..X2_D {
                broadcast[(token * 2 + slot) * 64 + col] = value;
            }
        }
    }
    (base, broadcast)
}

fn route_value_table(layer: &X2LayerWitness) -> Vec<Fp> {
    pad_matrix_i16(&layer.route_values, X2_T * X2_TOP_K, X2_D, 0)
}

fn layer_auth_values(layer: &X2LayerWitness, luts: &volta_gpt2::Luts) -> Vec<Vec<Fp>> {
    let mut norm = norm_auth_values(layer);
    for row in 2 * X2_T..16 {
        norm[A_NORM_RSQRT][row * 64] = fp_i16(luts.ln_rsqrt[0]);
    }
    let (_, _, _, _, above) = attention_rect(layer, luts);
    let (route_base, route_broadcast) = route_tables(layer);
    let mut qkv = Vec::with_capacity(X2_T * X2_QKV);
    for row in 0..X2_T {
        qkv.extend_from_slice(&layer.dense.q[row * X2_D..(row + 1) * X2_D]);
        qkv.extend_from_slice(
            &layer.dense.k[row * X2_KV_HEADS * X2_HEAD_DIM..(row + 1) * X2_KV_HEADS * X2_HEAD_DIM],
        );
        qkv.extend_from_slice(
            &layer.dense.v[row * X2_KV_HEADS * X2_HEAD_DIM..(row + 1) * X2_KV_HEADS * X2_HEAD_DIM],
        );
    }
    vec![
        norm[A_NORM_INPUT].clone(),
        norm[A_NORM_MEAN].clone(),
        norm[A_NORM_RIN].clone(),
        norm[A_NORM_RSQRT].clone(),
        norm[A_NORM_OUT].clone(),
        pad_matrix_i16(&qkv, X2_T, X2_QKV, 0),
        pad_matrix_i16(&layer.dense.q, X2_T, X2_D, 0),
        pad_matrix_i16(&layer.dense.k, X2_T, X2_KV_HEADS * X2_HEAD_DIM, 0),
        pad_matrix_i16(&layer.dense.v, X2_T, X2_KV_HEADS * X2_HEAD_DIM, 0),
        row_table_i64(&layer.dense.denoms),
        {
            let rin: Vec<i16> = layer
                .dense
                .denoms
                .iter()
                .map(|&value| (value >> luts.params.recip_den_shift) as i16)
                .collect();
            row_table_i16(&rin, 0)
        },
        row_table_i16(&layer.dense.recips, luts.softmax_recip[0]),
        row_table_i16(&layer.dense.row_shift, 0),
        above.iter().copied().map(fp_i64).collect(),
        pad_matrix_i16(&layer.dense.attn_proj_q, X2_T, X2_D, 0),
        pad_matrix_i16(&layer.router.scores, X2_T, X2_EXPERTS, 0),
        pad_i16(&layer.router.theta, 8, 0),
        pad_matrix_i16(&layer.router.exp, X2_T, X2_EXPERTS, 0),
        pad_i64(&layer.router.denoms, 8, 0),
        pad_i16(&layer.router.recip_in, 8, 0),
        pad_i16(&layer.router.recips, 8, luts.softmax_recip[0]),
        route_base,
        route_broadcast,
        route_value_table(layer),
    ]
}

fn global_auth_values(fixture: &X2MoeFixture) -> Vec<Vec<Fp>> {
    let internal = if fixture.config.thin_k == 1 {
        pad_matrix_i16(&fixture.layers[0].output, X2_T, X2_D, 0)
    } else {
        // Preserve a stable slot/domain while actually skipping the internal
        // element authentication: an empty correction is rejected by the
        // verifier and therefore cannot masquerade as k=1.  The one-element
        // public zero sentinel is not a boundary tensor.
        vec![Fp::ZERO]
    };
    let mut mean = vec![Fp::ZERO; 64];
    let mut rin = vec![Fp::ZERO; 64];
    let mut rsqrt = vec![Fp::ZERO; 64];
    mean[..X2_D].fill(fp_i64(fixture.final_norm.mean));
    rin[..X2_D].fill(fp_i16(fixture.final_norm.rsqrt_in));
    rsqrt[..X2_D].fill(fp_i16(fixture.final_norm.rsqrt_out));
    vec![
        pad_matrix_i16(&fixture.embedding_out, X2_T, X2_D, 0),
        pad_matrix_i16(&fixture.embedding_out, X2_T, X2_D, 0),
        internal,
        pad_matrix_i16(&fixture.layers[1].output, X2_T, X2_D, 0),
        mean,
        rin,
        rsqrt,
        pad_i16(&fixture.final_norm.output, 64, 0),
        vec![fp_i16(fixture.final_norm.rsqrt_in), Fp::ZERO],
        vec![fp_i16(fixture.final_norm.rsqrt_out), fp_i16(fixture.luts.ln_rsqrt[0])],
    ]
}

fn layer_auth_lengths() -> Vec<usize> {
    vec![
        1024, 1024, 1024, 1024, 1024, 1024, 512, 128, 128, 64, 64, 64, 64, 126, 512, 64, 8, 64, 8,
        8, 8, 16, 1024, 1024,
    ]
}

fn global_auth_lengths(thin_k: usize) -> Vec<usize> {
    vec![512, 512, if thin_k == 1 { 512 } else { 1 }, 512, 64, 64, 64, 64, 2, 2]
}

fn add_layer_multiplicities(
    bank: &mut TableBankP,
    layer: &X2LayerWitness,
    luts: &volta_gpt2::Luts,
) {
    let (norm_acc, norm_out) = norm_arrays(layer);
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&norm_acc, &norm_out, 2 * X2_T, X2_D, X2_SHIFT),
    );
    let mut norm_rin: Vec<i16> = layer
        .dense
        .ln1_rsqrt_in
        .iter()
        .chain(&layer.dense.ln2_rsqrt_in)
        .map(|&value| value as i16)
        .collect();
    bank.add_mult(TableKey::LnRsqrt, &unsigned_pair_mult(&norm_rin, 16));

    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(
            &layer.dense.qkv_acc,
            &{
                let mut qkv = Vec::with_capacity(X2_T * X2_QKV);
                for row in 0..X2_T {
                    qkv.extend_from_slice(&layer.dense.q[row * X2_D..(row + 1) * X2_D]);
                    qkv.extend_from_slice(&layer.dense.k[row * 16..(row + 1) * 16]);
                    qkv.extend_from_slice(&layer.dense.v[row * 16..(row + 1) * 16]);
                }
                qkv
            },
            X2_T,
            X2_QKV,
            X2_SHIFT,
        ),
    );
    let (score_acc, scores, exp, weights, _) = attention_rect(layer, luts);
    bank.add_mult(TableKey::Range(X2_SHIFT), &range_mult(&score_acc, &scores, 8, 64, X2_SHIFT));
    bank.add_mult(TableKey::Exp, &signed_pair_mult(&scores, &exp, exp_pad(luts), 512));
    let rin: Vec<i16> = layer
        .dense
        .denoms
        .iter()
        .map(|&value| (value >> luts.params.recip_den_shift) as i16)
        .collect();
    bank.add_mult(TableKey::SoftmaxRecip, &unsigned_pair_mult(&rin, 64));
    let mut norm_acc_rect = vec![0i64; 512];
    for head in 0..X2_Q_HEADS {
        for row in 0..X2_T {
            for col in 0..=row {
                let index = head * 64 + row * 8 + col;
                let packed = head * (X2_T * (X2_T + 1) / 2) + row * (row + 1) / 2 + col;
                norm_acc_rect[index] = i64::from(layer.dense.exp_out[packed])
                    * i64::from(layer.dense.recips[head * X2_T + row]);
            }
        }
    }
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&norm_acc_rect, &weights, 8, 64, X2_SHIFT),
    );
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&layer.dense.av_acc, &layer.dense.av_q, X2_T, X2_D, X2_SHIFT),
    );
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&layer.dense.proj_acc, &layer.dense.attn_proj_q, X2_T, X2_D, X2_SHIFT),
    );

    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&layer.router.acc, &layer.router.scores, X2_T, X2_EXPERTS, X2_SHIFT),
    );
    bank.add_mult(
        TableKey::Exp,
        &signed_pair_mult(&layer.router.scores, &layer.router.exp, exp_pad(luts), 64),
    );
    bank.add_mult(TableKey::SoftmaxRecip, &unsigned_pair_mult(&layer.router.recip_in, 8));
    bank.add_mult(TableKey::Range(16), &comparison_mult(&layer.router.comparisons, 64));
    let selected_acc: Vec<i64> = (0..X2_T)
        .flat_map(|row| {
            (0..X2_TOP_K).map(move |slot| {
                let expert = usize::from(layer.router.routes[row][slot]);
                i64::from(layer.router.exp[row * X2_EXPERTS + expert])
                    * i64::from(layer.router.recips[row])
            })
        })
        .collect();
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&selected_acc, &layer.router.route_weights, X2_T, X2_TOP_K, X2_SHIFT),
    );

    for expert in &layer.experts {
        let rows = expert.rows.len();
        bank.add_mult(
            TableKey::Range(X2_SHIFT),
            &range_mult(&expert.up_acc, &expert.up_q, rows, X2_DFF, X2_SHIFT),
        );
        bank.add_mult(
            TableKey::Gelu,
            &signed_pair_mult(&expert.up_q, &expert.gelu, 0, (rows * X2_DFF).next_power_of_two()),
        );
        bank.add_mult(
            TableKey::Range(X2_SHIFT),
            &range_mult(&expert.down_acc, &expert.down_q, rows, X2_D, X2_SHIFT),
        );
    }
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&layer.combine_acc, &layer.combine_q, X2_T, X2_D, X2_SHIFT),
    );
    norm_rin.clear();
}

fn add_global_multiplicities(bank: &mut TableBankP, fixture: &X2MoeFixture) {
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&fixture.embedding_acc, &fixture.embedding_out, X2_T, X2_D, X2_SHIFT),
    );
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&fixture.seam_acc, &fixture.seam_out, X2_T, X2_D, X2_SHIFT),
    );
    bank.add_mult(
        TableKey::Range(X2_SHIFT),
        &range_mult(&fixture.final_norm.acc, &fixture.final_norm.output, 1, X2_D, X2_SHIFT),
    );
    bank.add_mult(TableKey::LnRsqrt, &unsigned_pair_mult(&[fixture.final_norm.rsqrt_in], 2));
}

fn prepare_layer_p(
    index: usize,
    fixture: &X2MoeFixture,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> PreparedP {
    let mut cx = BlockCtxP::new(stream, tx, X2_LAYER_SECTION + index as u8, bank);
    let values = layer_auth_values(&fixture.layers[index], &fixture.luts);
    assert_eq!(values.iter().map(Vec::len).collect::<Vec<_>>(), layer_auth_lengths());
    let (auth_doms, auth_corrs) = auth_values_p(values.clone(), &mut cx);
    add_layer_multiplicities(cx.bank, &fixture.layers[index], &fixture.luts);
    PreparedP { doms: cx.doms, auth_doms, auth_values: values, auth_corrs }
}

fn prepare_global_p(
    fixture: &X2MoeFixture,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> PreparedP {
    let mut cx = BlockCtxP::new(stream, tx, X2_GLOBAL_SECTION, bank);
    let values = global_auth_values(fixture);
    assert_eq!(
        values.iter().map(Vec::len).collect::<Vec<_>>(),
        global_auth_lengths(fixture.config.thin_k)
    );
    let (auth_doms, auth_corrs) = auth_values_p(values.clone(), &mut cx);
    add_global_multiplicities(cx.bank, fixture);
    PreparedP { doms: cx.doms, auth_doms, auth_values: values, auth_corrs }
}

fn prepare_layer_v(
    index: usize,
    proof: &X2LayerProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<PreparedV> {
    let mut empty = TableBankV::empty();
    let mut cx = BlockCtxV::new(ctx, tx, X2_LAYER_SECTION + index as u8, &mut empty);
    let auth_keys = auth_values_v(&proof.auth_corrs, &layer_auth_lengths(), &mut cx)?;
    Some(PreparedV { doms: cx.doms, auth_keys })
}

fn prepare_global_v(
    thin_k: usize,
    proof: &X2GlobalProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<PreparedV> {
    let mut empty = TableBankV::empty();
    let mut cx = BlockCtxV::new(ctx, tx, X2_GLOBAL_SECTION, &mut empty);
    let auth_keys = auth_values_v(&proof.auth_corrs, &global_auth_lengths(thin_k), &mut cx)?;
    Some(PreparedV { doms: cx.doms, auth_keys })
}

pub fn x2_content_keys() -> Vec<TableKey> {
    let keys: BTreeSet<_> = [
        TableKey::Range(8),
        TableKey::Range(16),
        TableKey::Exp,
        TableKey::Gelu,
        TableKey::LnRsqrt,
        TableKey::SoftmaxRecip,
    ]
    .into_iter()
    .collect();
    keys.into_iter().collect()
}

fn prove_norm(
    layer: &X2LayerWitness,
    luts: &volta_gpt2::Luts,
    prepared: &PreparedP,
    cx: &mut BlockCtxP<'_>,
) -> X2NormProof {
    let (acc, out) = norm_arrays(layer);
    let range = prove_range_site(&acc, &out, 2 * X2_T, X2_D, X2_SHIFT, Vec::new(), cx);
    let out_open = open_auth_p(prepared, A_NORM_OUT, &range.main.point, cx.stream);
    push_zero(
        &mut cx.zero,
        range.main.col_claims[1].value.sub(out_open),
        "X2 norm output authentication",
    );

    let dev: Vec<Fp2> = prepared.auth_values[A_NORM_INPUT]
        .iter()
        .zip(&prepared.auth_values[A_NORM_MEAN])
        .map(|(&input, &mean)| Fp2::from_base(input - mean))
        .collect();
    let rsqrt = fp2_table(&prepared.auth_values[A_NORM_RSQRT]);
    let had_doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (hadamard, point, dev_claim, rsqrt_claim) = hadamard_prove(
        range.acc_point(),
        dev,
        rsqrt,
        range.acc_claim,
        &had_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let input_open = open_auth_p(prepared, A_NORM_INPUT, &point, cx.stream);
    let mean_open = open_auth_p(prepared, A_NORM_MEAN, &point, cx.stream);
    let rsqrt_open = open_auth_p(prepared, A_NORM_RSQRT, &point, cx.stream);
    push_zero(&mut cx.zero, dev_claim.sub(input_open.sub(mean_open)), "X2 norm centered factor");
    push_zero(&mut cx.zero, rsqrt_claim.sub(rsqrt_open), "X2 norm rsqrt factor");

    let inputs: Vec<i16> = layer
        .dense
        .ln1_rsqrt_in
        .iter()
        .chain(&layer.dense.ln2_rsqrt_in)
        .map(|&value| value as i16)
        .collect();
    let outputs: Vec<i16> =
        layer.dense.ln1_rsqrt_out.iter().chain(&layer.dense.ln2_rsqrt_out).copied().collect();
    let (rin_col, rout_col) = pair_cols_padded(&inputs, &outputs, 2 * X2_T, 1, 0, luts.ln_rsqrt[0]);
    let rsqrt_inst =
        cx.inst(TableKey::LnRsqrt, &[rin_col, rout_col], &[Some(0), Some(16)], Vec::new());
    let mut auth_point = vec![Fp2::ZERO; 6];
    auth_point.extend_from_slice(&rsqrt_inst.point);
    let rin_open = open_auth_p(prepared, A_NORM_RIN, &auth_point, cx.stream);
    let rout_open = open_auth_p(prepared, A_NORM_RSQRT, &auth_point, cx.stream);
    push_zero(
        &mut cx.zero,
        rsqrt_inst.col_claims[0].value.sub(rin_open),
        "X2 norm rsqrt input authentication",
    );
    push_zero(
        &mut cx.zero,
        rsqrt_inst.col_claims[1].value.sub(rout_open),
        "X2 norm rsqrt output authentication",
    );

    X2NormProof { range: range.into(), hadamard, rsqrt: rsqrt_inst.proof }
}

fn verify_norm(proof: &X2NormProof, prepared: &PreparedV, cx: &mut BlockCtxV<'_>) -> Option<()> {
    let range =
        verify_range_site(10, X2_SHIFT, &proof.range.main, proof.range.stage1.as_ref(), &[], cx)?;
    cx.kzero.push(range.main.col_keys[1].key.sub(open_auth_k(
        prepared,
        A_NORM_OUT,
        &range.main.point,
    )));
    let had_doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (point, dev_key, rsqrt_key) = hadamard_verify(
        range.acc_point(),
        range.acc_key,
        &proof.hadamard,
        &had_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let input_key = open_auth_k(prepared, A_NORM_INPUT, &point);
    let mean_key = open_auth_k(prepared, A_NORM_MEAN, &point);
    cx.kzero.push(dev_key.sub(input_key.sub(mean_key)));
    cx.kzero.push(rsqrt_key.sub(open_auth_k(prepared, A_NORM_RSQRT, &point)));

    let rsqrt = cx.inst(TableKey::LnRsqrt, 4, &[Some(0), Some(16)], &proof.rsqrt, &[])?;
    let mut auth_point = vec![Fp2::ZERO; 6];
    auth_point.extend_from_slice(&rsqrt.point);
    cx.kzero.push(rsqrt.col_keys[0].key.sub(open_auth_k(prepared, A_NORM_RIN, &auth_point)));
    cx.kzero.push(rsqrt.col_keys[1].key.sub(open_auth_k(prepared, A_NORM_RSQRT, &auth_point)));
    Some(())
}

fn prove_expert(
    expert: &X2ExpertWitness,
    weights: &crate::x2_moe::X2ExpertWeights,
    prepared: &PreparedP,
    cx: &mut BlockCtxP<'_>,
) -> (X2ExpertProof, WeightClaimP, WeightClaimP) {
    let rows = expert.rows.len();
    assert!(matches!(rows, 1 | 2));

    let down =
        prove_range_site(&expert.down_acc, &expert.down_q, rows, X2_D, X2_SHIFT, Vec::new(), cx);
    let route_open = open_auth_weighted_p(
        prepared,
        A_ROUTE_VALUES,
        &route_grid_weights(&expert.rows, &down.main.point),
        cx.stream,
    );
    push_zero(
        &mut cx.zero,
        down.main.col_claims[1].value.sub(route_open),
        "X2 expert public scatter",
    );
    let down_point = down.acc_point().to_vec();
    let (down_rj, down_ri) = down_point.split_at(6);
    let down_doms = ChainDoms::alloc(&mut cx.doms, X2_DFF);
    let (down_gemm, gelu_wire, down_weight_corr, down_weight, _, _) = prove_gemm_committed_chained(
        &expert.gelu,
        &weights.down,
        rows,
        X2_DFF,
        X2_D,
        down_ri,
        down_rj,
        down.acc_claim,
        &down_doms,
        cx.stream,
        cx.tx,
    );

    let (gelu_in, gelu_out) = pair_cols_padded(&expert.up_q, &expert.gelu, rows, X2_DFF, 0, 0);
    let gelu = cx.inst(
        TableKey::Gelu,
        &[gelu_in, gelu_out],
        &[Some(0), Some(16)],
        vec![LeafAuxClaim { col: 1, point: gelu_wire.point.clone(), value: gelu_wire.value }],
    );

    let up = prove_range_site(
        &expert.up_acc,
        &expert.up_q,
        rows,
        X2_DFF,
        X2_SHIFT,
        vec![LeafAuxClaim { col: 1, point: gelu.point.clone(), value: gelu.col_claims[0].value }],
        cx,
    );
    let up_point = up.acc_point().to_vec();
    let (up_rj, up_ri) = up_point.split_at(7);
    let up_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (up_gemm, gathered_wire, up_weight_corr, up_weight, _, _) = prove_gemm_committed_chained(
        &expert.gathered,
        &weights.up,
        rows,
        X2_D,
        X2_DFF,
        up_ri,
        up_rj,
        up.acc_claim,
        &up_doms,
        cx.stream,
        cx.tx,
    );
    let gathered_open = open_auth_weighted_p(
        prepared,
        A_NORM_OUT,
        &gathered_norm_weights(&expert.rows, &gathered_wire.point),
        cx.stream,
    );
    push_zero(&mut cx.zero, gathered_wire.value.sub(gathered_open), "X2 expert public gather");

    (
        X2ExpertProof {
            down: down.into(),
            down_gemm: X2CommittedGemmProof {
                proof: down_gemm,
                x_corr: gelu_wire.corr,
                weight_corr: down_weight_corr,
            },
            gelu: gelu.proof,
            up: up.into(),
            up_gemm: X2CommittedGemmProof {
                proof: up_gemm,
                x_corr: gathered_wire.corr,
                weight_corr: up_weight_corr,
            },
        },
        up_weight,
        down_weight,
    )
}

fn verify_expert(
    rows: &[(usize, usize)],
    proof: &X2ExpertProof,
    prepared: &PreparedV,
    cx: &mut BlockCtxV<'_>,
) -> Option<((Vec<Fp2>, VerifierKey), (Vec<Fp2>, VerifierKey))> {
    if !matches!(rows.len(), 1 | 2) {
        return None;
    }
    let rb = pad_bits(rows.len());
    let down =
        verify_range_site(6 + rb, X2_SHIFT, &proof.down.main, proof.down.stage1.as_ref(), &[], cx)?;
    let route_key =
        open_auth_weighted_k(prepared, A_ROUTE_VALUES, &route_grid_weights(rows, &down.main.point));
    cx.kzero.push(down.main.col_keys[1].key.sub(route_key));
    let down_point = down.acc_point().to_vec();
    let (down_rj, down_ri) = down_point.split_at(6);
    let down_doms = ChainDoms::alloc(&mut cx.doms, X2_DFF);
    let (gelu_wire, down_weight_point, down_weight_key) = verify_gemm_committed_chained(
        rows.len(),
        X2_DFF,
        X2_D,
        down_ri,
        down_rj,
        down.acc_key,
        &proof.down_gemm.proof,
        proof.down_gemm.x_corr,
        proof.down_gemm.weight_corr,
        &down_doms,
        cx.ctx,
        cx.tx,
    )?;
    let gelu_aux = [(1usize, gelu_wire.point.clone(), gelu_wire.key)];
    let gelu = cx.inst(TableKey::Gelu, 7 + rb, &[Some(0), Some(16)], &proof.gelu, &gelu_aux)?;
    let up_aux = [(1usize, gelu.point.clone(), gelu.col_keys[0].key)];
    let up =
        verify_range_site(7 + rb, X2_SHIFT, &proof.up.main, proof.up.stage1.as_ref(), &up_aux, cx)?;
    let up_point = up.acc_point().to_vec();
    let (up_rj, up_ri) = up_point.split_at(7);
    let up_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (gathered_wire, up_weight_point, up_weight_key) = verify_gemm_committed_chained(
        rows.len(),
        X2_D,
        X2_DFF,
        up_ri,
        up_rj,
        up.acc_key,
        &proof.up_gemm.proof,
        proof.up_gemm.x_corr,
        proof.up_gemm.weight_corr,
        &up_doms,
        cx.ctx,
        cx.tx,
    )?;
    let gathered_key = open_auth_weighted_k(
        prepared,
        A_NORM_OUT,
        &gathered_norm_weights(rows, &gathered_wire.point),
    );
    cx.kzero.push(gathered_wire.key.sub(gathered_key));
    Some(((up_weight_point, up_weight_key), (down_weight_point, down_weight_key)))
}

fn prove_router(
    layer: &X2LayerWitness,
    weights: &[i16],
    luts: &volta_gpt2::Luts,
    prepared: &PreparedP,
    cx: &mut BlockCtxP<'_>,
) -> (X2RouterProof, WeightClaimP) {
    let routes = &layer.router.routes;
    assert!(d1_preflight(routes));

    let comparisons = pad_i64(
        &layer.router.comparisons.iter().map(|&value| i64::from(value)).collect::<Vec<_>>(),
        64,
        0,
    );
    let comparison = cx.inst(TableKey::Range(16), &[comparisons], &[Some(0)], Vec::new());
    let (score_weights, theta_weights, public_term) =
        router_affine_weights(routes, &comparison.point);
    let score_open = open_auth_weighted_p(prepared, A_ROUTER_SCORES, &score_weights, cx.stream);
    let theta_open = open_auth_weighted_p(prepared, A_ROUTER_THETA, &theta_weights, cx.stream);
    push_zero(
        &mut cx.zero,
        comparison.col_claims[0]
            .value
            .sub(score_open)
            .sub(theta_open)
            .sub(ProverAuthed::from_public(public_term)),
        "X2 router comparison affine bridge",
    );
    let rho_theta: Vec<Fp2> = (0..3).map(|_| cx.tx.challenge_fp2()).collect();
    let theta_at_rho = open_auth_p(prepared, A_ROUTER_THETA, &rho_theta, cx.stream);
    let cutoff_score = open_auth_weighted_p(
        prepared,
        A_ROUTER_SCORES,
        &cutoff_gather_weights(routes, &rho_theta),
        cx.stream,
    );
    push_zero(&mut cx.zero, theta_at_rho.sub(cutoff_score), "X2 router cutoff gather");

    let selected_acc: Vec<i64> = (0..X2_T)
        .flat_map(|row| {
            (0..X2_TOP_K).map(move |slot| {
                let expert = usize::from(routes[row][slot]);
                i64::from(layer.router.exp[row * X2_EXPERTS + expert])
                    * i64::from(layer.router.recips[row])
            })
        })
        .collect();
    let route_norm = prove_range_site(
        &selected_acc,
        &layer.router.route_weights,
        X2_T,
        X2_TOP_K,
        X2_SHIFT,
        Vec::new(),
        cx,
    );
    let route_base_open = open_auth_p(prepared, A_ROUTE_BASE, &route_norm.main.point, cx.stream);
    push_zero(
        &mut cx.zero,
        route_norm.main.col_claims[1].value.sub(route_base_open),
        "X2 route-weight authentication",
    );
    let mut exp_selected = vec![Fp2::ZERO; 16];
    let mut recip_broadcast = vec![Fp2::ZERO; 16];
    for row in 0..X2_T {
        for slot in 0..X2_TOP_K {
            let index = row * X2_TOP_K + slot;
            exp_selected[index] = Fp2::from_base(fp_i16(
                layer.router.exp[row * X2_EXPERTS + usize::from(routes[row][slot])],
            ));
            recip_broadcast[index] = Fp2::from_base(fp_i16(layer.router.recips[row]));
        }
    }
    for slot in 0..X2_TOP_K {
        recip_broadcast[7 * X2_TOP_K + slot] = Fp2::from_base(fp_i16(luts.softmax_recip[0]));
    }
    let route_had_doms = HadamardDoms::alloc(&mut cx.doms, 4);
    let (route_hadamard, route_point, selected_exp_claim, route_recip_claim) = hadamard_prove(
        route_norm.acc_point(),
        exp_selected,
        recip_broadcast,
        route_norm.acc_claim,
        &route_had_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let selected_open = open_auth_weighted_p(
        prepared,
        A_ROUTER_EXP,
        &selected_exp_weights(routes, &route_point),
        cx.stream,
    );
    push_zero(&mut cx.zero, selected_exp_claim.sub(selected_open), "X2 selected router exp");
    let recip_open = open_auth_p(prepared, A_ROUTER_RECIP, &route_point[1..], cx.stream);
    push_zero(&mut cx.zero, route_recip_claim.sub(recip_open), "X2 route reciprocal broadcast");
    let rho_broadcast: Vec<Fp2> = (0..10).map(|_| cx.tx.challenge_fp2()).collect();
    let broadcast_open = open_auth_p(prepared, A_ROUTE_BROADCAST, &rho_broadcast, cx.stream);
    let base_open = open_auth_weighted_p(
        prepared,
        A_ROUTE_BASE,
        &route_base_broadcast_weights(&rho_broadcast),
        cx.stream,
    );
    push_zero(&mut cx.zero, broadcast_open.sub(base_open), "X2 route-weight broadcast");

    let exp_fp = pad_matrix_i16(&layer.router.exp, X2_T, X2_EXPERTS, 0);
    let rho_rows: Vec<Fp2> = (0..3).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 3];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_value = eval_mle(&fp2_table(&exp_fp), &half_point);
    let (exp_rowsum_corr, rowsum_claim) =
        fresh_eval_p(rowsum_value, "x2_router_rowsum_correction", cx);
    let denom_open = open_auth_p(prepared, A_ROUTER_DENOM, &rho_rows, cx.stream);
    push_zero(
        &mut cx.zero,
        denom_open.sub(rowsum_claim.scale(Fp2::from_base(Fp::new(8)))),
        "X2 router denominator rowsum",
    );
    let (exp_in, exp_out) = pair_cols_padded(
        &layer.router.scores,
        &layer.router.exp,
        X2_T,
        X2_EXPERTS,
        exp_pad(luts),
        0,
    );
    let exp = cx.inst(
        TableKey::Exp,
        &[exp_in, exp_out],
        &[Some(0), Some(16)],
        vec![LeafAuxClaim { col: 1, point: half_point, value: rowsum_claim }],
    );
    push_zero(
        &mut cx.zero,
        exp.col_claims[1].value.sub(open_auth_p(prepared, A_ROUTER_EXP, &exp.point, cx.stream)),
        "X2 router exp authentication",
    );

    let (recip_in, recip_out) = pair_cols_padded(
        &layer.router.recip_in,
        &layer.router.recips,
        X2_T,
        1,
        0,
        luts.softmax_recip[0],
    );
    let reciprocal =
        cx.inst(TableKey::SoftmaxRecip, &[recip_in, recip_out], &[Some(0), Some(16)], Vec::new());
    close_softmax_recip_cpu(
        &reciprocal,
        prepared.auth_doms[A_ROUTER_RECIP_IN],
        &prepared.auth_values[A_ROUTER_RECIP_IN],
        prepared.auth_doms[A_ROUTER_RECIP],
        &prepared.auth_values[A_ROUTER_RECIP],
        cx,
    );

    let exp_eq = eq_vec(&exp.point);
    let pad_mass = exp_eq[7 * 8..].iter().copied().fold(Fp2::ZERO, |sum, value| sum + value);
    let exp_input = exp.col_claims[0]
        .value
        .sub(ProverAuthed::from_public(Fp2::from_base(fp_i16(exp_pad(luts))) * pad_mass));
    let requant = prove_range_site(
        &layer.router.acc,
        &layer.router.scores,
        X2_T,
        X2_EXPERTS,
        X2_SHIFT,
        vec![LeafAuxClaim { col: 1, point: exp.point.clone(), value: exp_input }],
        cx,
    );
    push_zero(
        &mut cx.zero,
        requant.main.col_claims[1].value.sub(open_auth_p(
            prepared,
            A_ROUTER_SCORES,
            &requant.main.point,
            cx.stream,
        )),
        "X2 router score authentication",
    );
    let gemm_point = requant.acc_point().to_vec();
    let (rj, ri) = gemm_point.split_at(3);
    let gemm_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (gemm, input_wire, weight_corr, weight_claim, _, _) = prove_gemm_committed_chained(
        &layer.dense.x_in,
        weights,
        X2_T,
        X2_D,
        X2_EXPERTS,
        ri,
        rj,
        requant.acc_claim,
        &gemm_doms,
        cx.stream,
        cx.tx,
    );
    push_zero(
        &mut cx.zero,
        input_wire.value.sub(open_auth_weighted_p(
            prepared,
            A_NORM_INPUT,
            &norm_half_weights(&input_wire.point, false),
            cx.stream,
        )),
        "X2 router input wire",
    );

    (
        X2RouterProof {
            comparisons: comparison.proof,
            requant: requant.into(),
            gemm: X2CommittedGemmProof { proof: gemm, x_corr: input_wire.corr, weight_corr },
            exp_rowsum_corr,
            exp: exp.proof,
            reciprocal: reciprocal.proof,
            route_norm: route_norm.into(),
            route_hadamard,
        },
        weight_claim,
    )
}

fn verify_router(
    routes: &[[u8; X2_TOP_K]],
    luts: &volta_gpt2::Luts,
    proof: &X2RouterProof,
    prepared: &PreparedV,
    cx: &mut BlockCtxV<'_>,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if !d1_preflight(routes) {
        return None;
    }
    let comparison = cx.inst(TableKey::Range(16), 6, &[Some(0)], &proof.comparisons, &[])?;
    let (score_weights, theta_weights, public_term) =
        router_affine_weights(routes, &comparison.point);
    let score_key = open_auth_weighted_k(prepared, A_ROUTER_SCORES, &score_weights);
    let theta_key = open_auth_weighted_k(prepared, A_ROUTER_THETA, &theta_weights);
    cx.kzero.push(
        comparison.col_keys[0]
            .key
            .sub(score_key)
            .sub(theta_key)
            .sub(VerifierKey::from_public(public_term, cx.ctx.delta)),
    );
    let rho_theta: Vec<Fp2> = (0..3).map(|_| cx.tx.challenge_fp2()).collect();
    let theta_at_rho = open_auth_k(prepared, A_ROUTER_THETA, &rho_theta);
    let cutoff_key =
        open_auth_weighted_k(prepared, A_ROUTER_SCORES, &cutoff_gather_weights(routes, &rho_theta));
    cx.kzero.push(theta_at_rho.sub(cutoff_key));

    let route_norm = verify_range_site(
        4,
        X2_SHIFT,
        &proof.route_norm.main,
        proof.route_norm.stage1.as_ref(),
        &[],
        cx,
    )?;
    cx.kzero.push(route_norm.main.col_keys[1].key.sub(open_auth_k(
        prepared,
        A_ROUTE_BASE,
        &route_norm.main.point,
    )));
    let route_had_doms = HadamardDoms::alloc(&mut cx.doms, 4);
    let (route_point, selected_exp_key, route_recip_key) = hadamard_verify(
        route_norm.acc_point(),
        route_norm.acc_key,
        &proof.route_hadamard,
        &route_had_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    cx.kzero.push(selected_exp_key.sub(open_auth_weighted_k(
        prepared,
        A_ROUTER_EXP,
        &selected_exp_weights(routes, &route_point),
    )));
    cx.kzero.push(route_recip_key.sub(open_auth_k(prepared, A_ROUTER_RECIP, &route_point[1..])));
    let rho_broadcast: Vec<Fp2> = (0..10).map(|_| cx.tx.challenge_fp2()).collect();
    let broadcast_key = open_auth_k(prepared, A_ROUTE_BROADCAST, &rho_broadcast);
    let base_key =
        open_auth_weighted_k(prepared, A_ROUTE_BASE, &route_base_broadcast_weights(&rho_broadcast));
    cx.kzero.push(broadcast_key.sub(base_key));

    let rho_rows: Vec<Fp2> = (0..3).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 3];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_key = fresh_eval_k(proof.exp_rowsum_corr, "x2_router_rowsum_correction", cx);
    cx.kzero.push(
        open_auth_k(prepared, A_ROUTER_DENOM, &rho_rows)
            .sub(rowsum_key.scale(Fp2::from_base(Fp::new(8)))),
    );
    let exp_aux = [(1usize, half_point, rowsum_key)];
    let exp = cx.inst(TableKey::Exp, 6, &[Some(0), Some(16)], &proof.exp, &exp_aux)?;
    cx.kzero.push(exp.col_keys[1].key.sub(open_auth_k(prepared, A_ROUTER_EXP, &exp.point)));
    let reciprocal =
        cx.inst(TableKey::SoftmaxRecip, 3, &[Some(0), Some(16)], &proof.reciprocal, &[])?;
    close_softmax_recip_verifier(
        &reciprocal,
        &prepared.auth_keys[A_ROUTER_RECIP_IN],
        &prepared.auth_keys[A_ROUTER_RECIP],
        cx,
    );

    let exp_eq = eq_vec(&exp.point);
    let pad_mass = exp_eq[7 * 8..].iter().copied().fold(Fp2::ZERO, |sum, value| sum + value);
    let exp_input = exp.col_keys[0].key.sub(VerifierKey::from_public(
        Fp2::from_base(fp_i16(exp_pad(luts))) * pad_mass,
        cx.ctx.delta,
    ));
    let requant_aux = [(1usize, exp.point.clone(), exp_input)];
    let requant = verify_range_site(
        6,
        X2_SHIFT,
        &proof.requant.main,
        proof.requant.stage1.as_ref(),
        &requant_aux,
        cx,
    )?;
    cx.kzero.push(requant.main.col_keys[1].key.sub(open_auth_k(
        prepared,
        A_ROUTER_SCORES,
        &requant.main.point,
    )));
    let gemm_point = requant.acc_point().to_vec();
    let (rj, ri) = gemm_point.split_at(3);
    let gemm_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (input_wire, weight_point, weight_key) = verify_gemm_committed_chained(
        X2_T,
        X2_D,
        X2_EXPERTS,
        ri,
        rj,
        requant.acc_key,
        &proof.gemm.proof,
        proof.gemm.x_corr,
        proof.gemm.weight_corr,
        &gemm_doms,
        cx.ctx,
        cx.tx,
    )?;
    cx.kzero.push(input_wire.key.sub(open_auth_weighted_k(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&input_wire.point, false),
    )));
    Some((weight_point, weight_key))
}

fn attention_weight_matrix(layer: &X2LayerWitness, head: usize) -> Vec<i16> {
    let mut out = vec![0i16; X2_T * X2_T];
    let causal = X2_T * (X2_T + 1) / 2;
    let mut packed = head * causal;
    for row in 0..X2_T {
        for col in 0..=row {
            out[row * X2_T + col] = layer.dense.softmax_w[packed];
            packed += 1;
        }
    }
    out
}

fn q_head(layer: &X2LayerWitness, head: usize) -> Vec<i16> {
    let mut out = vec![0i16; X2_T * X2_HEAD_DIM];
    for row in 0..X2_T {
        out[row * X2_HEAD_DIM..(row + 1) * X2_HEAD_DIM].copy_from_slice(
            &layer.dense.q[row * X2_D + head * X2_HEAD_DIM..row * X2_D + (head + 1) * X2_HEAD_DIM],
        );
    }
    out
}

fn fold_kv_columns(values: &[i16], kv_head: usize, col_point: &[Fp2]) -> Vec<Fp2> {
    assert_eq!(values.len(), X2_T * X2_KV_HEADS * X2_HEAD_DIM);
    assert_eq!(col_point.len(), 3);
    let eq_col = eq_vec(col_point);
    let mut out = vec![Fp2::ZERO; 8];
    for row in 0..X2_T {
        for lane in 0..X2_HEAD_DIM {
            let value = values[row * X2_KV_HEADS * X2_HEAD_DIM + kv_head * X2_HEAD_DIM + lane];
            if value != 0 {
                out[row] += eq_col[lane].mul_base(fp_i16(value));
            }
        }
    }
    out
}

fn fold_k_rows(values: &[i16], kv_head: usize, row_point: &[Fp2]) -> Vec<Fp2> {
    assert_eq!(values.len(), X2_T * X2_KV_HEADS * X2_HEAD_DIM);
    assert_eq!(row_point.len(), 3);
    let eq_row = eq_vec(row_point);
    let mut out = vec![Fp2::ZERO; 8];
    for row in 0..X2_T {
        for lane in 0..X2_HEAD_DIM {
            let value = values[row * X2_KV_HEADS * X2_HEAD_DIM + kv_head * X2_HEAD_DIM + lane];
            if value != 0 {
                out[lane] += eq_row[row].mul_base(fp_i16(value));
            }
        }
    }
    out
}

fn fold_kv_auth_columns_p(
    prepared: &PreparedP,
    index: usize,
    kv_head: usize,
    col_point: &[Fp2],
    stream: &mut CorrelationStream,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let eq_col = eq_vec(col_point);
    let tags = stream.draw_sub_tags(prepared.auth_doms[index], prepared.auth_values[index].len());
    let mut values = vec![Fp2::ZERO; 8];
    let mut folded_tags = vec![Fp2::ZERO; 8];
    for row in 0..8 {
        for lane in 0..X2_HEAD_DIM {
            let offset = row * 16 + kv_head * X2_HEAD_DIM + lane;
            values[row] += eq_col[lane].mul_base(prepared.auth_values[index][offset]);
            folded_tags[row] += eq_col[lane] * tags[offset];
        }
    }
    (values, folded_tags)
}

fn fold_k_auth_rows_p(
    prepared: &PreparedP,
    kv_head: usize,
    row_point: &[Fp2],
    stream: &mut CorrelationStream,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let eq_row = eq_vec(row_point);
    let tags = stream.draw_sub_tags(prepared.auth_doms[A_K], prepared.auth_values[A_K].len());
    let mut values = vec![Fp2::ZERO; 8];
    let mut folded_tags = vec![Fp2::ZERO; 8];
    for row in 0..8 {
        for lane in 0..X2_HEAD_DIM {
            let offset = row * 16 + kv_head * X2_HEAD_DIM + lane;
            values[lane] += eq_row[row].mul_base(prepared.auth_values[A_K][offset]);
            folded_tags[lane] += eq_row[row] * tags[offset];
        }
    }
    (values, folded_tags)
}

fn folded_open(values: &[Fp2], tags: &[Fp2], point: &[Fp2]) -> ProverAuthed {
    let eq = eq_vec(point);
    ProverAuthed {
        x: values.iter().zip(&eq).fold(Fp2::ZERO, |sum, (&value, &weight)| sum + weight * value),
        m: tags.iter().zip(&eq).fold(Fp2::ZERO, |sum, (&tag, &weight)| sum + weight * tag),
    }
}

fn prove_attention(
    layer: &X2LayerWitness,
    weights: &volta_gpt2::LayerWeights,
    luts: &volta_gpt2::Luts,
    prepared: &PreparedP,
    cx: &mut BlockCtxP<'_>,
) -> (X2AttentionProof, WeightClaimP, WeightClaimP) {
    // Attention output projection and residual closure.
    let projection = prove_range_site(
        &layer.dense.proj_acc,
        &layer.dense.attn_proj_q,
        X2_T,
        X2_D,
        X2_SHIFT,
        Vec::new(),
        cx,
    );
    let projection_open = open_auth_p(prepared, A_ATTN_PROJ, &projection.main.point, cx.stream);
    push_zero(
        &mut cx.zero,
        projection.main.col_claims[1].value.sub(projection_open),
        "X2 attention projection authentication",
    );
    let x_open = open_auth_weighted_p(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&projection.main.point, false),
        cx.stream,
    );
    let residual_open = open_auth_weighted_p(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&projection.main.point, true),
        cx.stream,
    );
    push_zero(
        &mut cx.zero,
        residual_open.sub(x_open).sub(projection.main.col_claims[1].value),
        "X2 attention residual",
    );
    let projection_point = projection.acc_point().to_vec();
    let (projection_rj, projection_ri) = projection_point.split_at(6);
    let projection_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (projection_gemm, av_wire, projection_weight_corr, projection_weight, _, _) =
        prove_gemm_committed_chained(
            &layer.dense.av_q,
            &weights.attn_proj,
            X2_T,
            X2_D,
            X2_D,
            projection_ri,
            projection_rj,
            projection.acc_claim,
            &projection_doms,
            cx.stream,
            cx.tx,
        );

    // Per-query-head W·V activation GEMMs.
    let av = prove_range_site(
        &layer.dense.av_acc,
        &layer.dense.av_q,
        X2_T,
        X2_D,
        X2_SHIFT,
        vec![LeafAuxClaim { col: 1, point: av_wire.point.clone(), value: av_wire.value }],
        cx,
    );
    let av_point = av.acc_point().to_vec();
    let mut av_local_point = av_point[..3].to_vec();
    av_local_point.extend_from_slice(&av_point[6..]);
    let av_values: Vec<Fp2> = (0..X2_Q_HEADS)
        .map(|head| attention_head_slice(&layer.dense.av_acc, &av_local_point, head))
        .collect();
    let (av_split_corrs, av_claims) = fresh_split_p(&av_values, "x2_av_head_split_corrections", cx);
    let eq_heads = eq_vec(&av_point[3..6]);
    let mut av_split_row = ProverAuthed::ZERO.sub(av.acc_claim);
    for head in 0..X2_Q_HEADS {
        av_split_row = av_split_row.add(av_claims[head].scale(eq_heads[head]));
    }
    push_zero(&mut cx.zero, av_split_row, "X2 AV head split");
    let mut av_gemms = Vec::with_capacity(X2_Q_HEADS);
    let mut softmax_aux = Vec::with_capacity(X2_Q_HEADS);
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        let w = attention_weight_matrix(layer, head);
        let (b_folded, b_tags) =
            fold_kv_auth_columns_p(prepared, A_V, kv_head, &av_point[..3], cx.stream);
        debug_assert_eq!(b_folded, fold_kv_columns(&layer.dense.v, kv_head, &av_point[..3]));
        let b_values_for_open = b_folded.clone();
        let doms = ChainDoms::alloc(&mut cx.doms, X2_T);
        let (gemm, w_wire, r_l, _, _) = prove_gemm_act_chained(
            &w,
            b_folded,
            X2_T,
            X2_T,
            X2_HEAD_DIM,
            &av_point[6..],
            &av_point[..3],
            av_claims[head],
            |point| folded_open(&b_values_for_open, &b_tags, point),
            &doms,
            cx.stream,
            cx.tx,
        );
        debug_assert_eq!(r_l.len(), 3);
        let mut rect_point = w_wire.point.clone();
        rect_point.extend(bit_point(head, 3));
        softmax_aux.push(LeafAuxClaim { col: 1, point: rect_point, value: w_wire.value });
        av_gemms.push(X2ActGemmProof { proof: gemm, x_corr: w_wire.corr });
    }

    // Softmax normalized weights and exp/reciprocal relations.
    let (_, _, exp_rect_i16, weights_rect, _) = attention_rect(layer, luts);
    let mut norm_acc_rect = vec![0i64; 512];
    for head in 0..X2_Q_HEADS {
        let mut packed = head * (X2_T * (X2_T + 1) / 2);
        for row in 0..X2_T {
            for col in 0..=row {
                let index = head * 64 + row * 8 + col;
                norm_acc_rect[index] = i64::from(layer.dense.exp_out[packed])
                    * i64::from(layer.dense.recips[head * X2_T + row]);
                packed += 1;
            }
        }
    }
    let softmax_norm =
        prove_range_site(&norm_acc_rect, &weights_rect, 8, 64, X2_SHIFT, softmax_aux, cx);
    let exp_tab: Vec<Fp2> =
        pad_i16(&exp_rect_i16, 512, 0).into_iter().map(Fp2::from_base).collect();
    let mut recip_tab = vec![Fp2::ZERO; 512];
    for head in 0..8 {
        for row in 0..8 {
            let value = if head < X2_Q_HEADS && row < X2_T {
                layer.dense.recips[head * X2_T + row]
            } else {
                luts.softmax_recip[0]
            };
            for col in 0..8 {
                recip_tab[head * 64 + row * 8 + col] = Fp2::from_base(fp_i16(value));
            }
        }
    }
    let softmax_had_doms = HadamardDoms::alloc(&mut cx.doms, 9);
    let (softmax_hadamard, softmax_point, exp_claim, recip_claim) = hadamard_prove(
        softmax_norm.acc_point(),
        exp_tab.clone(),
        recip_tab,
        softmax_norm.acc_claim,
        &softmax_had_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let mut recip_point = softmax_point[3..6].to_vec();
    recip_point.extend_from_slice(&softmax_point[6..]);
    push_zero(
        &mut cx.zero,
        recip_claim.sub(open_auth_p(prepared, A_RECIP, &recip_point, cx.stream)),
        "X2 softmax reciprocal broadcast",
    );

    let rho_rows: Vec<Fp2> = (0..6).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 3];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_value = eval_mle(&exp_tab, &half_point);
    let (exp_rowsum_corr, rowsum_claim) =
        fresh_eval_p(rowsum_value, "x2_attention_rowsum_correction", cx);
    push_zero(
        &mut cx.zero,
        open_auth_p(prepared, A_DENOM, &rho_rows, cx.stream)
            .sub(rowsum_claim.scale(Fp2::from_base(Fp::new(8)))),
        "X2 attention denominator rowsum",
    );
    let (_, scores_rect, _, _, _) = attention_rect(layer, luts);
    let (exp_in, exp_out) = pair_cols_padded(&scores_rect, &exp_rect_i16, 8, 64, exp_pad(luts), 0);
    let exp = cx.inst(
        TableKey::Exp,
        &[exp_in, exp_out],
        &[Some(0), Some(16)],
        vec![
            LeafAuxClaim { col: 1, point: softmax_point.clone(), value: exp_claim },
            LeafAuxClaim { col: 1, point: half_point, value: rowsum_claim },
        ],
    );
    let recip_in: Vec<i16> = layer
        .dense
        .denoms
        .iter()
        .map(|&value| (value >> luts.params.recip_den_shift) as i16)
        .collect();
    let (recip_in_col, recip_out_col) = pair_cols_padded(
        &recip_in,
        &layer.dense.recips,
        X2_Q_HEADS,
        X2_T,
        0,
        luts.softmax_recip[0],
    );
    let reciprocal = cx.inst(
        TableKey::SoftmaxRecip,
        &[recip_in_col, recip_out_col],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    close_softmax_recip_cpu(
        &reciprocal,
        prepared.auth_doms[A_RECIP_IN],
        &prepared.auth_values[A_RECIP_IN],
        prepared.auth_doms[A_RECIP],
        &prepared.auth_values[A_RECIP],
        cx,
    );

    // Score requant, fake-pad correction, and six Q·K^T activation GEMMs.
    let (score_acc_rect, _, _, _, _) = attention_rect(layer, luts);
    let scores = prove_range_site(
        &score_acc_rect,
        &scores_rect,
        8,
        64,
        X2_SHIFT,
        vec![LeafAuxClaim { col: 1, point: exp.point.clone(), value: exp.col_claims[0].value }],
        cx,
    );
    let score_point = scores.main.point.clone();
    let eq_score = eq_vec(&score_point);
    let mut causal_mass = Fp2::ZERO;
    let mut above_weights = Vec::with_capacity(126);
    for head in 0..X2_Q_HEADS {
        for row in 0..X2_T {
            for col in 0..=row {
                causal_mass += eq_score[head * 64 + row * 8 + col];
            }
            for col in row + 1..X2_T {
                above_weights.push(eq_score[head * 64 + row * 8 + col]);
            }
        }
    }
    let pad_mass = Fp2::ONE - causal_mass;
    let pad_acc = Fp2::from_base(fp_i64(i64::from(exp_pad(luts)) << X2_SHIFT));
    let above_open = open_auth_weighted_p(prepared, A_ABOVE, &above_weights, cx.stream);
    let true_score_claim =
        scores.acc_claim.sub(ProverAuthed::from_public(pad_acc * pad_mass)).add(above_open);
    let local_score_point = score_point[..6].to_vec();
    let full_scores = full_attention_scores(layer);
    let score_values: Vec<Fp2> = (0..X2_Q_HEADS)
        .map(|head| score_head_slice(&full_scores, &local_score_point, head))
        .collect();
    let (score_split_corrs, score_claims) =
        fresh_split_p(&score_values, "x2_score_head_split_corrections", cx);
    let eq_score_heads = eq_vec(&score_point[6..]);
    let mut score_split_row = ProverAuthed::ZERO.sub(true_score_claim);
    for head in 0..X2_Q_HEADS {
        score_split_row = score_split_row.add(score_claims[head].scale(eq_score_heads[head]));
    }
    push_zero(&mut cx.zero, score_split_row, "X2 score head split");
    let mut qk_gemms = Vec::with_capacity(X2_Q_HEADS);
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        let q = q_head(layer, head);
        let (b_folded, b_tags) =
            fold_k_auth_rows_p(prepared, kv_head, &score_point[..3], cx.stream);
        debug_assert_eq!(b_folded, fold_k_rows(&layer.dense.k, kv_head, &score_point[..3]));
        let b_values_for_open = b_folded.clone();
        let doms = ChainDoms::alloc(&mut cx.doms, X2_HEAD_DIM);
        let (gemm, q_wire, _, _, _) = prove_gemm_act_chained(
            &q,
            b_folded,
            X2_T,
            X2_HEAD_DIM,
            X2_T,
            &score_point[3..6],
            &score_point[..3],
            score_claims[head],
            |point| folded_open(&b_values_for_open, &b_tags, point),
            &doms,
            cx.stream,
            cx.tx,
        );
        let mut q_point = q_wire.point[..3].to_vec();
        q_point.extend(bit_point(head, 3));
        q_point.extend_from_slice(&q_wire.point[3..]);
        push_zero(
            &mut cx.zero,
            q_wire.value.sub(open_auth_p(prepared, A_Q, &q_point, cx.stream)),
            "X2 Q head wire",
        );
        qk_gemms.push(X2ActGemmProof { proof: gemm, x_corr: q_wire.corr });
    }

    // Fused QKV requant and committed projection.
    let q_point: Vec<Fp2> = (0..9).map(|_| cx.tx.challenge_fp2()).collect();
    let k_point: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let v_point: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let q_open = open_auth_p(prepared, A_Q, &q_point, cx.stream);
    let k_open = open_auth_p(prepared, A_K, &k_point, cx.stream);
    let v_open = open_auth_p(prepared, A_V, &v_point, cx.stream);
    let mut qkv_out = Vec::with_capacity(X2_T * X2_QKV);
    for row in 0..X2_T {
        qkv_out.extend_from_slice(&layer.dense.q[row * X2_D..(row + 1) * X2_D]);
        qkv_out.extend_from_slice(&layer.dense.k[row * 16..(row + 1) * 16]);
        qkv_out.extend_from_slice(&layer.dense.v[row * 16..(row + 1) * 16]);
    }
    let qkv =
        prove_range_site(&layer.dense.qkv_acc, &qkv_out, X2_T, X2_QKV, X2_SHIFT, Vec::new(), cx);
    push_zero(
        &mut cx.zero,
        qkv.main.col_claims[1].value.sub(open_auth_p(prepared, A_QKV, &qkv.main.point, cx.stream)),
        "X2 QKV authentication",
    );
    push_zero(
        &mut cx.zero,
        open_auth_weighted_p(prepared, A_QKV, &qkv_slice_weights(0, &q_point), cx.stream)
            .sub(q_open),
        "X2 Q slice authentication",
    );
    push_zero(
        &mut cx.zero,
        open_auth_weighted_p(prepared, A_QKV, &qkv_slice_weights(1, &k_point), cx.stream)
            .sub(k_open),
        "X2 K slice authentication",
    );
    push_zero(
        &mut cx.zero,
        open_auth_weighted_p(prepared, A_QKV, &qkv_slice_weights(2, &v_point), cx.stream)
            .sub(v_open),
        "X2 V slice authentication",
    );
    let qkv_point = qkv.acc_point().to_vec();
    let (qkv_rj, qkv_ri) = qkv_point.split_at(7);
    let qkv_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (qkv_gemm, ln1_wire, qkv_weight_corr, qkv_weight, _, _) = prove_gemm_committed_chained(
        &layer.dense.ln1_out,
        &weights.c_attn,
        X2_T,
        X2_D,
        X2_QKV,
        qkv_ri,
        qkv_rj,
        qkv.acc_claim,
        &qkv_doms,
        cx.stream,
        cx.tx,
    );
    push_zero(
        &mut cx.zero,
        ln1_wire.value.sub(open_auth_weighted_p(
            prepared,
            A_NORM_OUT,
            &norm_half_weights(&ln1_wire.point, false),
            cx.stream,
        )),
        "X2 QKV input wire",
    );

    (
        X2AttentionProof {
            projection: projection.into(),
            projection_gemm: X2CommittedGemmProof {
                proof: projection_gemm,
                x_corr: av_wire.corr,
                weight_corr: projection_weight_corr,
            },
            av: av.into(),
            av_split_corrs,
            av_gemms,
            softmax_norm: softmax_norm.into(),
            softmax_hadamard,
            exp_rowsum_corr,
            exp: exp.proof,
            reciprocal: reciprocal.proof,
            scores: scores.into(),
            score_split_corrs,
            qk_gemms,
            qkv: qkv.into(),
            qkv_gemm: X2CommittedGemmProof {
                proof: qkv_gemm,
                x_corr: ln1_wire.corr,
                weight_corr: qkv_weight_corr,
            },
        },
        qkv_weight,
        projection_weight,
    )
}

fn verify_attention(
    luts: &volta_gpt2::Luts,
    proof: &X2AttentionProof,
    prepared: &PreparedV,
    cx: &mut BlockCtxV<'_>,
) -> Option<((Vec<Fp2>, VerifierKey), (Vec<Fp2>, VerifierKey))> {
    if proof.av_split_corrs.len() != X2_Q_HEADS
        || proof.av_gemms.len() != X2_Q_HEADS
        || proof.score_split_corrs.len() != X2_Q_HEADS
        || proof.qk_gemms.len() != X2_Q_HEADS
    {
        return None;
    }
    let projection = verify_range_site(
        9,
        X2_SHIFT,
        &proof.projection.main,
        proof.projection.stage1.as_ref(),
        &[],
        cx,
    )?;
    cx.kzero.push(projection.main.col_keys[1].key.sub(open_auth_k(
        prepared,
        A_ATTN_PROJ,
        &projection.main.point,
    )));
    let x_key = open_auth_weighted_k(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&projection.main.point, false),
    );
    let residual_key = open_auth_weighted_k(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&projection.main.point, true),
    );
    cx.kzero.push(residual_key.sub(x_key).sub(projection.main.col_keys[1].key));
    let projection_point = projection.acc_point().to_vec();
    let (projection_rj, projection_ri) = projection_point.split_at(6);
    let projection_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (av_wire, projection_weight_point, projection_weight_key) = verify_gemm_committed_chained(
        X2_T,
        X2_D,
        X2_D,
        projection_ri,
        projection_rj,
        projection.acc_key,
        &proof.projection_gemm.proof,
        proof.projection_gemm.x_corr,
        proof.projection_gemm.weight_corr,
        &projection_doms,
        cx.ctx,
        cx.tx,
    )?;

    let av_aux = [(1usize, av_wire.point.clone(), av_wire.key)];
    let av = verify_range_site(9, X2_SHIFT, &proof.av.main, proof.av.stage1.as_ref(), &av_aux, cx)?;
    let av_point = av.acc_point().to_vec();
    let av_claims = fresh_split_k(&proof.av_split_corrs, "x2_av_head_split_corrections", cx);
    let eq_heads = eq_vec(&av_point[3..6]);
    let mut av_split_key = VerifierKey::ZERO.sub(av.acc_key);
    for head in 0..X2_Q_HEADS {
        av_split_key = av_split_key.add(av_claims[head].scale(eq_heads[head]));
    }
    cx.kzero.push(av_split_key);
    let mut softmax_aux = Vec::with_capacity(X2_Q_HEADS);
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        let doms = ChainDoms::alloc(&mut cx.doms, X2_T);
        let (w_wire, _) = verify_gemm_act_chained(
            X2_T,
            X2_T,
            X2_HEAD_DIM,
            &av_point[6..],
            &av_point[..3],
            av_claims[head],
            &proof.av_gemms[head].proof,
            proof.av_gemms[head].x_corr,
            |point| {
                let mut auth_point = av_point[..3].to_vec();
                auth_point.extend(bit_point(kv_head, 1));
                auth_point.extend_from_slice(point);
                open_auth_k(prepared, A_V, &auth_point)
            },
            &doms,
            cx.ctx,
            cx.tx,
        )?;
        let mut rect_point = w_wire.point.clone();
        rect_point.extend(bit_point(head, 3));
        softmax_aux.push((1usize, rect_point, w_wire.key));
    }
    let softmax_norm = verify_range_site(
        9,
        X2_SHIFT,
        &proof.softmax_norm.main,
        proof.softmax_norm.stage1.as_ref(),
        &softmax_aux,
        cx,
    )?;
    let softmax_had_doms = HadamardDoms::alloc(&mut cx.doms, 9);
    let (softmax_point, exp_key, recip_key) = hadamard_verify(
        softmax_norm.acc_point(),
        softmax_norm.acc_key,
        &proof.softmax_hadamard,
        &softmax_had_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let mut recip_point = softmax_point[3..6].to_vec();
    recip_point.extend_from_slice(&softmax_point[6..]);
    cx.kzero.push(recip_key.sub(open_auth_k(prepared, A_RECIP, &recip_point)));

    let rho_rows: Vec<Fp2> = (0..6).map(|_| cx.tx.challenge_fp2()).collect();
    let half = Fp2::from_base(Fp::new(2).inv());
    let mut half_point = vec![half; 3];
    half_point.extend_from_slice(&rho_rows);
    let rowsum_key = fresh_eval_k(proof.exp_rowsum_corr, "x2_attention_rowsum_correction", cx);
    cx.kzero.push(
        open_auth_k(prepared, A_DENOM, &rho_rows).sub(rowsum_key.scale(Fp2::from_base(Fp::new(8)))),
    );
    let exp_aux = [(1usize, softmax_point, exp_key), (1usize, half_point, rowsum_key)];
    let exp = cx.inst(TableKey::Exp, 9, &[Some(0), Some(16)], &proof.exp, &exp_aux)?;
    let reciprocal =
        cx.inst(TableKey::SoftmaxRecip, 6, &[Some(0), Some(16)], &proof.reciprocal, &[])?;
    close_softmax_recip_verifier(
        &reciprocal,
        &prepared.auth_keys[A_RECIP_IN],
        &prepared.auth_keys[A_RECIP],
        cx,
    );

    let score_aux = [(1usize, exp.point.clone(), exp.col_keys[0].key)];
    let scores = verify_range_site(
        9,
        X2_SHIFT,
        &proof.scores.main,
        proof.scores.stage1.as_ref(),
        &score_aux,
        cx,
    )?;
    let score_point = scores.main.point.clone();
    let eq_score = eq_vec(&score_point);
    let mut causal_mass = Fp2::ZERO;
    let mut above_weights = Vec::with_capacity(126);
    for head in 0..X2_Q_HEADS {
        for row in 0..X2_T {
            for col in 0..=row {
                causal_mass += eq_score[head * 64 + row * 8 + col];
            }
            for col in row + 1..X2_T {
                above_weights.push(eq_score[head * 64 + row * 8 + col]);
            }
        }
    }
    let pad_mass = Fp2::ONE - causal_mass;
    let pad_acc = Fp2::from_base(fp_i64(i64::from(exp_pad(luts)) << X2_SHIFT));
    let true_score_key = scores
        .acc_key
        .sub(VerifierKey::from_public(pad_acc * pad_mass, cx.ctx.delta))
        .add(open_auth_weighted_k(prepared, A_ABOVE, &above_weights));
    let score_claims =
        fresh_split_k(&proof.score_split_corrs, "x2_score_head_split_corrections", cx);
    let eq_score_heads = eq_vec(&score_point[6..]);
    let mut score_split_key = VerifierKey::ZERO.sub(true_score_key);
    for head in 0..X2_Q_HEADS {
        score_split_key = score_split_key.add(score_claims[head].scale(eq_score_heads[head]));
    }
    cx.kzero.push(score_split_key);
    for head in 0..X2_Q_HEADS {
        let kv_head = head / (X2_Q_HEADS / X2_KV_HEADS);
        let doms = ChainDoms::alloc(&mut cx.doms, X2_HEAD_DIM);
        let (q_wire, _) = verify_gemm_act_chained(
            X2_T,
            X2_HEAD_DIM,
            X2_T,
            &score_point[3..6],
            &score_point[..3],
            score_claims[head],
            &proof.qk_gemms[head].proof,
            proof.qk_gemms[head].x_corr,
            |point| {
                let mut auth_point = point.to_vec();
                auth_point.extend(bit_point(kv_head, 1));
                auth_point.extend_from_slice(&score_point[..3]);
                open_auth_k(prepared, A_K, &auth_point)
            },
            &doms,
            cx.ctx,
            cx.tx,
        )?;
        let mut q_point = q_wire.point[..3].to_vec();
        q_point.extend(bit_point(head, 3));
        q_point.extend_from_slice(&q_wire.point[3..]);
        cx.kzero.push(q_wire.key.sub(open_auth_k(prepared, A_Q, &q_point)));
    }

    let q_point: Vec<Fp2> = (0..9).map(|_| cx.tx.challenge_fp2()).collect();
    let k_point: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let v_point: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let q_open = open_auth_k(prepared, A_Q, &q_point);
    let k_open = open_auth_k(prepared, A_K, &k_point);
    let v_open = open_auth_k(prepared, A_V, &v_point);
    let qkv = verify_range_site(10, X2_SHIFT, &proof.qkv.main, proof.qkv.stage1.as_ref(), &[], cx)?;
    cx.kzero.push(qkv.main.col_keys[1].key.sub(open_auth_k(prepared, A_QKV, &qkv.main.point)));
    cx.kzero
        .push(open_auth_weighted_k(prepared, A_QKV, &qkv_slice_weights(0, &q_point)).sub(q_open));
    cx.kzero
        .push(open_auth_weighted_k(prepared, A_QKV, &qkv_slice_weights(1, &k_point)).sub(k_open));
    cx.kzero
        .push(open_auth_weighted_k(prepared, A_QKV, &qkv_slice_weights(2, &v_point)).sub(v_open));
    let qkv_point = qkv.acc_point().to_vec();
    let (qkv_rj, qkv_ri) = qkv_point.split_at(7);
    let qkv_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (ln1_wire, qkv_weight_point, qkv_weight_key) = verify_gemm_committed_chained(
        X2_T,
        X2_D,
        X2_QKV,
        qkv_ri,
        qkv_rj,
        qkv.acc_key,
        &proof.qkv_gemm.proof,
        proof.qkv_gemm.x_corr,
        proof.qkv_gemm.weight_corr,
        &qkv_doms,
        cx.ctx,
        cx.tx,
    )?;
    cx.kzero.push(ln1_wire.key.sub(open_auth_weighted_k(
        prepared,
        A_NORM_OUT,
        &norm_half_weights(&ln1_wire.point, false),
    )));
    Some(((qkv_weight_point, qkv_weight_key), (projection_weight_point, projection_weight_key)))
}

fn prove_combine(
    layer: &X2LayerWitness,
    prepared: &PreparedP,
    cx: &mut BlockCtxP<'_>,
) -> (X2RangeProof, HadamardProof, BoundaryClaimP) {
    let combine = prove_range_site(
        &layer.combine_acc,
        &layer.combine_q,
        X2_T,
        X2_D,
        X2_SHIFT,
        Vec::new(),
        cx,
    );
    let attention = open_auth_p(prepared, A_ATTN_PROJ, combine.acc_point(), cx.stream);
    let moe_claim = combine
        .acc_claim
        .sub(attention.scale(Fp2::from_base(Fp::new(1 << X2_SHIFT))))
        .scale(Fp2::from_base(Fp::new(2).inv()));
    let mut rho = combine.acc_point()[..6].to_vec();
    rho.push(Fp2::from_base(Fp::new(2).inv()));
    rho.extend_from_slice(&combine.acc_point()[6..]);
    let route_values = fp2_table(&prepared.auth_values[A_ROUTE_VALUES]);
    let route_weights = fp2_table(&prepared.auth_values[A_ROUTE_BROADCAST]);
    let doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (hadamard, point, route_value_claim, route_weight_claim) = hadamard_prove(
        &rho,
        route_values,
        route_weights,
        moe_claim,
        &doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    push_zero(
        &mut cx.zero,
        route_value_claim.sub(open_auth_p(prepared, A_ROUTE_VALUES, &point, cx.stream)),
        "X2 combine route values",
    );
    push_zero(
        &mut cx.zero,
        route_weight_claim.sub(open_auth_p(prepared, A_ROUTE_BROADCAST, &point, cx.stream)),
        "X2 combine route weights",
    );
    let input = open_auth_weighted_p(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&combine.main.point, false),
        cx.stream,
    );
    let output = BoundaryClaimP {
        point: combine.main.point.clone(),
        value: input.add(combine.main.col_claims[1].value),
    };
    (combine.into(), hadamard, output)
}

fn verify_combine(
    proof: &X2LayerProof,
    prepared: &PreparedV,
    cx: &mut BlockCtxV<'_>,
) -> Option<BoundaryClaimK> {
    let combine = verify_range_site(
        9,
        X2_SHIFT,
        &proof.combine.main,
        proof.combine.stage1.as_ref(),
        &[],
        cx,
    )?;
    let attention = open_auth_k(prepared, A_ATTN_PROJ, combine.acc_point());
    let moe_key = combine
        .acc_key
        .sub(attention.scale(Fp2::from_base(Fp::new(1 << X2_SHIFT))))
        .scale(Fp2::from_base(Fp::new(2).inv()));
    let mut rho = combine.acc_point()[..6].to_vec();
    rho.push(Fp2::from_base(Fp::new(2).inv()));
    rho.extend_from_slice(&combine.acc_point()[6..]);
    let doms = HadamardDoms::alloc(&mut cx.doms, 10);
    let (point, route_value_key, route_weight_key) = hadamard_verify(
        &rho,
        moe_key,
        &proof.combine_hadamard,
        &doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    cx.kzero.push(route_value_key.sub(open_auth_k(prepared, A_ROUTE_VALUES, &point)));
    cx.kzero.push(route_weight_key.sub(open_auth_k(prepared, A_ROUTE_BROADCAST, &point)));
    let input = open_auth_weighted_k(
        prepared,
        A_NORM_INPUT,
        &norm_half_weights(&combine.main.point, false),
    );
    Some(BoundaryClaimK {
        point: combine.main.point.clone(),
        key: input.add(combine.main.col_keys[1].key),
    })
}

struct LayerPOut {
    proof: X2LayerProof,
    input: BoundaryClaimP,
    weights: Vec<WeightClaimP>,
    prod: ProdTriples,
    zero: Vec<ProverAuthed>,
    instances: Counters,
    other: Counters,
}

fn prove_layer(
    layer_index: usize,
    fixture: &X2MoeFixture,
    prepared: PreparedP,
    global: &PreparedP,
    downstream: Option<&BoundaryClaimP>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> LayerPOut {
    let layer = &fixture.layers[layer_index];
    let layer_weights = &fixture.weights[layer_index];
    let mut cx = BlockCtxP::with_doms(stream, tx, prepared.doms, bank);
    let (combine, combine_hadamard, output) = prove_combine(layer, &prepared, &mut cx);

    let (local_output_corr, reducer) = match (layer_index, fixture.config.thin_k) {
        (1, _) => {
            let exit = open_auth_p(global, G_EXIT, &output.point, cx.stream);
            push_zero(&mut cx.zero, output.value.sub(exit), "X2 group exit");
            (None, None)
        }
        (0, 1) => {
            let internal = open_auth_p(global, G_INTERNAL, &output.point, cx.stream);
            push_zero(&mut cx.zero, output.value.sub(internal), "X2 k=1 internal output");
            (None, None)
        }
        (0, 2) => {
            let downstream = downstream.expect("X2 k=2 downstream seam claim");
            let (corr, bridge) =
                prove_matrix_eval_claim_i16(&layer.output, X2_T, X2_D, &output.point, &mut cx);
            push_zero(&mut cx.zero, output.value.sub(bridge.value), "X2 k=2 q bridge");
            let (proof, _) =
                prove_eq_reduction_i16(&layer.output, X2_T, X2_D, &bridge, downstream, &mut cx);
            (Some(corr), Some(proof))
        }
        _ => unreachable!(),
    };

    let mut expert_proofs = Vec::with_capacity(X2_EXPERTS);
    let mut expert_weights = Vec::with_capacity(2 * X2_EXPERTS);
    for (expert, weights) in layer.experts.iter().zip(&layer_weights.experts) {
        let (proof, up, down) = prove_expert(expert, weights, &prepared, &mut cx);
        expert_proofs.push(proof);
        expert_weights.push(up);
        expert_weights.push(down);
    }
    let (router, router_weight) =
        prove_router(layer, &layer_weights.router, &fixture.luts, &prepared, &mut cx);
    let (attention, qkv_weight, projection_weight) =
        prove_attention(layer, &layer_weights.dense, &fixture.luts, &prepared, &mut cx);
    let norm = prove_norm(layer, &fixture.luts, &prepared, &mut cx);

    let input_point: Vec<Fp2> = (0..9).map(|_| cx.tx.challenge_fp2()).collect();
    let input = BoundaryClaimP {
        point: input_point.clone(),
        value: open_auth_weighted_p(
            &prepared,
            A_NORM_INPUT,
            &norm_half_weights(&input_point, false),
            cx.stream,
        ),
    };
    if layer_index == 0 {
        let entry = open_auth_p(global, G_ENTRY, &input.point, cx.stream);
        push_zero(&mut cx.zero, input.value.sub(entry), "X2 chunk entry");
    }

    let mut weight_claims = vec![qkv_weight, projection_weight, router_weight];
    weight_claims.extend(expert_weights);
    debug_assert_eq!(weight_claims.len(), 19);
    let proof = X2LayerProof {
        auth_corrs: prepared.auth_corrs,
        combine,
        combine_hadamard,
        experts: expert_proofs,
        router,
        attention,
        norm,
        local_output_corr,
        reducer,
    };
    LayerPOut {
        proof,
        input,
        weights: weight_claims,
        prod: cx.prod,
        zero: cx.zero,
        instances: cx.ctr_instances,
        other: cx.ctr_other,
    }
}

fn expert_jobs(routes: &[[u8; X2_TOP_K]]) -> Option<Vec<Vec<(usize, usize)>>> {
    if !d1_preflight(routes) {
        return None;
    }
    let mut jobs = vec![Vec::new(); X2_EXPERTS];
    for (token, route) in routes.iter().enumerate() {
        for (slot, &expert) in route.iter().enumerate() {
            jobs[usize::from(expert)].push((token, slot));
        }
    }
    if jobs.iter().any(|rows| !matches!(rows.len(), 1 | 2)) {
        return None;
    }
    Some(jobs)
}

struct LayerVOut {
    input: BoundaryClaimK,
    weights: Vec<(Vec<Fp2>, VerifierKey)>,
    kprod: ProdKeyTriples,
    kzero: Vec<VerifierKey>,
}

fn verify_layer(
    layer_index: usize,
    thin_k: usize,
    routes: &[[u8; X2_TOP_K]],
    luts: &volta_gpt2::Luts,
    proof: &X2LayerProof,
    prepared: PreparedV,
    global: &PreparedV,
    downstream: Option<&BoundaryClaimK>,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    bank: &mut TableBankV,
) -> Option<LayerVOut> {
    let jobs = expert_jobs(routes)?;
    if proof.experts.len() != X2_EXPERTS {
        return None;
    }
    let mut cx = BlockCtxV::with_doms(ctx, tx, prepared.doms, bank);
    let output = verify_combine(proof, &prepared, &mut cx)?;
    match (layer_index, thin_k) {
        (1, _) => {
            cx.kzero.push(output.key.sub(open_auth_k(global, G_EXIT, &output.point)));
            if proof.local_output_corr.is_some() || proof.reducer.is_some() {
                return None;
            }
        }
        (0, 1) => {
            cx.kzero.push(output.key.sub(open_auth_k(global, G_INTERNAL, &output.point)));
            if proof.local_output_corr.is_some() || proof.reducer.is_some() {
                return None;
            }
        }
        (0, 2) => {
            let bridge = verify_matrix_eval_claim(&output.point, proof.local_output_corr?, &mut cx);
            cx.kzero.push(output.key.sub(bridge.key));
            verify_eq_reduction(9, &bridge, downstream?, proof.reducer.as_ref()?, &mut cx)?;
        }
        _ => return None,
    }

    let mut expert_weight_keys = Vec::with_capacity(2 * X2_EXPERTS);
    for ((rows, expert_proof), _expert) in jobs.iter().zip(&proof.experts).zip(0..X2_EXPERTS) {
        let (up, down) = verify_expert(rows, expert_proof, &prepared, &mut cx)?;
        expert_weight_keys.push(up);
        expert_weight_keys.push(down);
    }
    let router_weight = verify_router(routes, luts, &proof.router, &prepared, &mut cx)?;
    let (qkv_weight, projection_weight) =
        verify_attention(luts, &proof.attention, &prepared, &mut cx)?;
    verify_norm(&proof.norm, &prepared, &mut cx)?;
    let input_point: Vec<Fp2> = (0..9).map(|_| cx.tx.challenge_fp2()).collect();
    let input = BoundaryClaimK {
        point: input_point.clone(),
        key: open_auth_weighted_k(&prepared, A_NORM_INPUT, &norm_half_weights(&input_point, false)),
    };
    if layer_index == 0 {
        cx.kzero.push(input.key.sub(open_auth_k(global, G_ENTRY, &input.point)));
    }
    let mut weights = vec![qkv_weight, projection_weight, router_weight];
    weights.extend(expert_weight_keys);
    debug_assert_eq!(weights.len(), 19);
    Some(LayerVOut { input, weights, kprod: cx.kprod, kzero: cx.kzero })
}

struct GlobalPOut {
    proof: X2GlobalProof,
    downstream: BoundaryClaimP,
    weights: Vec<WeightClaimP>,
    prod: ProdTriples,
    zero: Vec<ProverAuthed>,
    instances: Counters,
    other: Counters,
}

fn prove_global(
    fixture: &X2MoeFixture,
    prepared: &PreparedP,
    layer1_input: &BoundaryClaimP,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    bank: &mut TableBankP,
) -> GlobalPOut {
    let mut cx = BlockCtxP::with_doms(stream, tx, prepared.doms, bank);

    let seam = prove_range_site(
        &fixture.seam_acc,
        &fixture.seam_out,
        X2_T,
        X2_D,
        X2_SHIFT,
        vec![LeafAuxClaim { col: 1, point: layer1_input.point.clone(), value: layer1_input.value }],
        &mut cx,
    );
    let downstream = BoundaryClaimP {
        point: seam.acc_point().to_vec(),
        value: seam.acc_claim.scale(inv_pow2(X2_SHIFT)),
    };
    if fixture.config.thin_k == 1 {
        let internal = open_auth_p(&prepared, G_INTERNAL, &downstream.point, cx.stream);
        push_zero(&mut cx.zero, downstream.value.sub(internal), "X2 k=1 seam input");
    }

    let rho_logits: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let public_logits = ProverAuthed::from_public(eval_i64_matrix(
        &fixture.final_norm.logits,
        1,
        X2_VOCAB,
        &rho_logits,
    ));
    let output_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (output_gemm, final_wire, output_weight_corr, output_weight, _, _) =
        prove_gemm_committed_chained(
            &fixture.final_norm.output,
            &fixture.output_weight,
            1,
            X2_D,
            X2_VOCAB,
            &[],
            &rho_logits,
            public_logits,
            &output_doms,
            cx.stream,
            cx.tx,
        );
    push_zero(
        &mut cx.zero,
        final_wire.value.sub(open_auth_p(&prepared, G_FINAL_OUT, &final_wire.point, cx.stream)),
        "X2 output GEMM input",
    );

    let final_norm = prove_range_site(
        &fixture.final_norm.acc,
        &fixture.final_norm.output,
        1,
        X2_D,
        X2_SHIFT,
        Vec::new(),
        &mut cx,
    );
    push_zero(
        &mut cx.zero,
        final_norm.main.col_claims[1].value.sub(open_auth_p(
            &prepared,
            G_FINAL_OUT,
            &final_norm.main.point,
            cx.stream,
        )),
        "X2 final norm output",
    );
    let mut dev = vec![Fp2::ZERO; 64];
    let mut rsqrt_tab = vec![Fp2::ZERO; 64];
    for col in 0..X2_D {
        dev[col] = Fp2::from_base(fp_i64(
            i64::from(fixture.final_norm.input[col]) - fixture.final_norm.mean,
        ));
        rsqrt_tab[col] = Fp2::from_base(fp_i16(fixture.final_norm.rsqrt_out));
    }
    let final_had_doms = HadamardDoms::alloc(&mut cx.doms, 6);
    let (final_hadamard, final_point, dev_claim, rsqrt_claim) = hadamard_prove(
        final_norm.acc_point(),
        dev,
        rsqrt_tab,
        final_norm.acc_claim,
        &final_had_doms,
        cx.stream,
        cx.tx,
        &mut cx.prod,
        &mut cx.zero,
    );
    let mut exit_point = final_point.clone();
    exit_point.extend(bit_point(X2_T - 1, 3));
    let exit_open = open_auth_p(&prepared, G_EXIT, &exit_point, cx.stream);
    let mean_open = open_auth_p(&prepared, G_FINAL_MEAN, &final_point, cx.stream);
    push_zero(
        &mut cx.zero,
        dev_claim.sub(exit_open.sub(mean_open)),
        "X2 final norm centered factor",
    );
    push_zero(
        &mut cx.zero,
        rsqrt_claim.sub(open_auth_p(&prepared, G_FINAL_RSQRT, &final_point, cx.stream)),
        "X2 final norm rsqrt factor",
    );
    let rin_col = prepared.auth_values[G_FINAL_LUT_RIN].clone();
    let rout_col = prepared.auth_values[G_FINAL_LUT_ROUT].clone();
    let final_rsqrt =
        cx.inst(TableKey::LnRsqrt, &[rin_col, rout_col], &[Some(0), Some(16)], Vec::new());
    push_zero(
        &mut cx.zero,
        final_rsqrt.col_claims[0].value.sub(open_auth_p(
            prepared,
            G_FINAL_LUT_RIN,
            &final_rsqrt.point,
            cx.stream,
        )),
        "X2 final rsqrt pair input",
    );
    push_zero(
        &mut cx.zero,
        final_rsqrt.col_claims[1].value.sub(open_auth_p(
            prepared,
            G_FINAL_LUT_ROUT,
            &final_rsqrt.point,
            cx.stream,
        )),
        "X2 final rsqrt pair output",
    );
    let zero_pair_point = vec![Fp2::ZERO];
    let zero_point = vec![Fp2::ZERO; 6];
    push_zero(
        &mut cx.zero,
        open_auth_p(prepared, G_FINAL_LUT_RIN, &zero_pair_point, cx.stream).sub(open_auth_p(
            prepared,
            G_FINAL_RIN,
            &zero_point,
            cx.stream,
        )),
        "X2 final rsqrt input identity",
    );
    push_zero(
        &mut cx.zero,
        open_auth_p(prepared, G_FINAL_LUT_ROUT, &zero_pair_point, cx.stream).sub(open_auth_p(
            prepared,
            G_FINAL_RSQRT,
            &zero_point,
            cx.stream,
        )),
        "X2 final rsqrt output identity",
    );

    let embedding = prove_range_site(
        &fixture.embedding_acc,
        &fixture.embedding_out,
        X2_T,
        X2_D,
        X2_SHIFT,
        Vec::new(),
        &mut cx,
    );
    let embed_open = open_auth_p(&prepared, G_EMBED_OUT, &embedding.main.point, cx.stream);
    push_zero(
        &mut cx.zero,
        embedding.main.col_claims[1].value.sub(embed_open),
        "X2 embedding output",
    );
    let entry_open = open_auth_p(&prepared, G_ENTRY, &embedding.main.point, cx.stream);
    push_zero(&mut cx.zero, embed_open.sub(entry_open), "X2 embedding/entry identity");
    let mut embedding_weight_point = embedding.main.point.clone();
    embedding_weight_point.extend([Fp2::ZERO; 4]);
    let embedding_weight_value =
        eval_i16_matrix(&fixture.embedding, X2_VOCAB, X2_D, &embedding_weight_point);
    let (embedding_weight_corr, embedding_weight_auth) =
        fresh_eval_p(embedding_weight_value, "x2_embedding_weight_correction", &mut cx);
    push_zero(
        &mut cx.zero,
        embedding.main.col_claims[1].value.sub(embedding_weight_auth),
        "X2 public embedding gather",
    );
    let embedding_weight =
        WeightClaimP { point: embedding_weight_point, value: embedding_weight_auth };

    let proof = X2GlobalProof {
        auth_corrs: prepared.auth_corrs.clone(),
        embedding: embedding.into(),
        seam: seam.into(),
        final_norm: final_norm.into(),
        final_hadamard,
        final_rsqrt: final_rsqrt.proof,
        embedding_weight_corr,
        output_gemm: X2CommittedGemmProof {
            proof: output_gemm,
            x_corr: final_wire.corr,
            weight_corr: output_weight_corr,
        },
    };
    GlobalPOut {
        proof,
        downstream,
        weights: vec![embedding_weight, output_weight],
        prod: cx.prod,
        zero: cx.zero,
        instances: cx.ctr_instances,
        other: cx.ctr_other,
    }
}

struct GlobalVOut {
    downstream: BoundaryClaimK,
    weights: Vec<(Vec<Fp2>, VerifierKey)>,
    kprod: ProdKeyTriples,
    kzero: Vec<VerifierKey>,
}

fn verify_global(
    thin_k: usize,
    public_logits: &[i64],
    proof: &X2GlobalProof,
    prepared: &PreparedV,
    layer1_input: &BoundaryClaimK,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    bank: &mut TableBankV,
) -> Option<GlobalVOut> {
    if public_logits.len() != X2_VOCAB {
        return None;
    }
    let mut cx = BlockCtxV::with_doms(ctx, tx, prepared.doms, bank);
    let seam_aux = [(1usize, layer1_input.point.clone(), layer1_input.key)];
    let seam = verify_range_site(
        9,
        X2_SHIFT,
        &proof.seam.main,
        proof.seam.stage1.as_ref(),
        &seam_aux,
        &mut cx,
    )?;
    let downstream = BoundaryClaimK {
        point: seam.acc_point().to_vec(),
        key: seam.acc_key.scale(inv_pow2(X2_SHIFT)),
    };
    if thin_k == 1 {
        cx.kzero.push(downstream.key.sub(open_auth_k(&prepared, G_INTERNAL, &downstream.point)));
    }

    let rho_logits: Vec<Fp2> = (0..7).map(|_| cx.tx.challenge_fp2()).collect();
    let public_claim = VerifierKey::from_public(
        eval_i64_matrix(public_logits, 1, X2_VOCAB, &rho_logits),
        cx.ctx.delta,
    );
    let output_doms = ChainDoms::alloc(&mut cx.doms, X2_D);
    let (final_wire, output_weight_point, output_weight_key) = verify_gemm_committed_chained(
        1,
        X2_D,
        X2_VOCAB,
        &[],
        &rho_logits,
        public_claim,
        &proof.output_gemm.proof,
        proof.output_gemm.x_corr,
        proof.output_gemm.weight_corr,
        &output_doms,
        cx.ctx,
        cx.tx,
    )?;
    cx.kzero.push(final_wire.key.sub(open_auth_k(&prepared, G_FINAL_OUT, &final_wire.point)));

    let final_norm = verify_range_site(
        6,
        X2_SHIFT,
        &proof.final_norm.main,
        proof.final_norm.stage1.as_ref(),
        &[],
        &mut cx,
    )?;
    cx.kzero.push(final_norm.main.col_keys[1].key.sub(open_auth_k(
        &prepared,
        G_FINAL_OUT,
        &final_norm.main.point,
    )));
    let final_had_doms = HadamardDoms::alloc(&mut cx.doms, 6);
    let (final_point, dev_key, rsqrt_key) = hadamard_verify(
        final_norm.acc_point(),
        final_norm.acc_key,
        &proof.final_hadamard,
        &final_had_doms,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let mut exit_point = final_point.clone();
    exit_point.extend(bit_point(X2_T - 1, 3));
    cx.kzero.push(dev_key.sub(open_auth_k(&prepared, G_EXIT, &exit_point).sub(open_auth_k(
        &prepared,
        G_FINAL_MEAN,
        &final_point,
    ))));
    cx.kzero.push(rsqrt_key.sub(open_auth_k(&prepared, G_FINAL_RSQRT, &final_point)));
    let final_rsqrt =
        cx.inst(TableKey::LnRsqrt, 1, &[Some(0), Some(16)], &proof.final_rsqrt, &[])?;
    cx.kzero.push(final_rsqrt.col_keys[0].key.sub(open_auth_k(
        prepared,
        G_FINAL_LUT_RIN,
        &final_rsqrt.point,
    )));
    cx.kzero.push(final_rsqrt.col_keys[1].key.sub(open_auth_k(
        prepared,
        G_FINAL_LUT_ROUT,
        &final_rsqrt.point,
    )));
    let zero_pair_point = vec![Fp2::ZERO];
    let zero_point = vec![Fp2::ZERO; 6];
    cx.kzero.push(open_auth_k(prepared, G_FINAL_LUT_RIN, &zero_pair_point).sub(open_auth_k(
        prepared,
        G_FINAL_RIN,
        &zero_point,
    )));
    cx.kzero.push(open_auth_k(prepared, G_FINAL_LUT_ROUT, &zero_pair_point).sub(open_auth_k(
        prepared,
        G_FINAL_RSQRT,
        &zero_point,
    )));

    let embedding = verify_range_site(
        9,
        X2_SHIFT,
        &proof.embedding.main,
        proof.embedding.stage1.as_ref(),
        &[],
        &mut cx,
    )?;
    let embed_key = open_auth_k(&prepared, G_EMBED_OUT, &embedding.main.point);
    cx.kzero.push(embedding.main.col_keys[1].key.sub(embed_key));
    cx.kzero.push(embed_key.sub(open_auth_k(&prepared, G_ENTRY, &embedding.main.point)));
    let mut embedding_weight_point = embedding.main.point.clone();
    embedding_weight_point.extend([Fp2::ZERO; 4]);
    let embedding_weight_key =
        fresh_eval_k(proof.embedding_weight_corr, "x2_embedding_weight_correction", &mut cx);
    cx.kzero.push(embedding.main.col_keys[1].key.sub(embedding_weight_key));

    Some(GlobalVOut {
        downstream,
        weights: vec![
            (embedding_weight_point, embedding_weight_key),
            (output_weight_point, output_weight_key),
        ],
        kprod: cx.kprod,
        kzero: cx.kzero,
    })
}

pub fn prove_x2_moe(
    fixture: &X2MoeFixture,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (X2MoeProof, X2MoeProverOut) {
    fixture.config.validate().expect("X2 prover config");
    assert!(matches!(fixture.config.thin_k, 1 | 2));
    assert_eq!(
        fixture.config.digest().unwrap(),
        x2_model_config(fixture.config.thin_k).digest().unwrap()
    );
    assert_eq!(fixture.layers.len(), X2_LAYERS);
    assert_eq!(
        fixture.layers.iter().map(|layer| layer.router.routes.clone()).collect::<Vec<_>>(),
        x2_public_routes()
    );
    assert_eq!(LAYER_AUTH_COUNT, layer_auth_lengths().len());
    assert_eq!(GLOBAL_AUTH_COUNT, global_auth_lengths(fixture.config.thin_k).len());

    let mut bank = TableBankP::new();
    let mut prepared_layers = Vec::with_capacity(X2_LAYERS);
    for layer in 0..X2_LAYERS {
        prepared_layers.push(prepare_layer_p(layer, fixture, stream, tx, &mut bank));
    }
    let prepared_global = prepare_global_p(fixture, stream, tx, &mut bank);
    assert_eq!(bank.content_keys(), x2_content_keys());
    let mut table_doms = Doms::new(layer_dom_base(X2_TABLE_SECTION));
    bank.finalize(stream, tx, &mut table_doms);

    let prepared0 = prepared_layers.remove(0);
    let prepared1 = prepared_layers.remove(0);
    let layer1 = prove_layer(1, fixture, prepared1, &prepared_global, None, stream, tx, &mut bank);
    let global = prove_global(fixture, &prepared_global, &layer1.input, stream, tx, &mut bank);
    let layer0 = prove_layer(
        0,
        fixture,
        prepared0,
        &prepared_global,
        Some(&global.downstream),
        stream,
        tx,
        &mut bank,
    );
    debug_assert!(
        layer1.zero.iter().all(|claim| claim.x == Fp2::ZERO),
        "X2 layer1 nonzero row {:?}",
        layer1.zero.iter().position(|claim| claim.x != Fp2::ZERO)
    );
    debug_assert!(
        global.zero.iter().all(|claim| claim.x == Fp2::ZERO),
        "X2 global nonzero row {:?}",
        global.zero.iter().position(|claim| claim.x != Fp2::ZERO)
    );
    debug_assert!(
        layer0.zero.iter().all(|claim| claim.x == Fp2::ZERO),
        "X2 layer0 nonzero row {:?}",
        layer0.zero.iter().position(|claim| claim.x != Fp2::ZERO)
    );

    let mut prod = Vec::new();
    let mut zero = Vec::new();
    let mut instance_counters = Counters::default();
    let mut other_counters = Counters::default();
    for (rows, other, p, z) in [
        (layer1.instances, layer1.other, layer1.prod, layer1.zero),
        (global.instances, global.other, global.prod, global.zero),
        (layer0.instances, layer0.other, layer0.prod, layer0.zero),
    ] {
        add_counts(&mut instance_counters, rows);
        add_counts(&mut other_counters, other);
        prod.extend(p);
        zero.extend(z);
    }
    let zero_before_tables = zero.len();
    let tables = bank.close(
        &fixture.luts,
        stream,
        &mut table_doms,
        tx,
        &mut instance_counters,
        &mut prod,
        &mut zero,
    );
    debug_assert!(
        zero.iter().all(|claim| claim.x == Fp2::ZERO),
        "X2 nonzero closure row at {:?}: {:?}",
        zero.iter().position(|claim| claim.x != Fp2::ZERO).map(|index| (index, zero_before_tables)),
        zero.iter().find(|claim| claim.x != Fp2::ZERO).map(|claim| claim.x)
    );
    let mut weight_claims = layer0.weights;
    weight_claims.extend(layer1.weights);
    weight_claims.extend(global.weights);
    debug_assert_eq!(weight_claims.len(), 40);
    let corr_counters = stream.counters;
    (
        X2MoeProof {
            thin_k: fixture.config.thin_k,
            global: global.proof,
            layers: vec![layer0.proof, layer1.proof],
            tables,
        },
        X2MoeProverOut {
            weight_claims,
            prod,
            zero,
            instance_counters,
            other_counters,
            corr_counters,
            table_sites: 82,
            table_contents: x2_content_keys().len(),
            table_finalizations: 1,
            logical_lookup_rows: 12_523,
            padded_lookup_rows: 19_346,
        },
    )
}

pub fn verify_x2_moe(
    config: &volta_gpt2::ModelConfig,
    luts: &volta_gpt2::Luts,
    tokens: &[u16],
    routes: &[Vec<[u8; X2_TOP_K]>],
    public_logits: &[i64],
    proof: &X2MoeProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<X2MoeVerifierOut> {
    config.validate().ok()?;
    if !matches!(proof.thin_k, 1 | 2)
        || proof.thin_k != config.thin_k
        || config.digest().ok()? != x2_model_config(proof.thin_k).digest().ok()?
        || tokens != (0..X2_T as u16).collect::<Vec<_>>()
        || routes != x2_public_routes()
        || proof.layers.len() != X2_LAYERS
        || public_logits.len() != X2_VOCAB
    {
        return None;
    }
    let prepared0 = prepare_layer_v(0, &proof.layers[0], ctx, tx)?;
    let prepared1 = prepare_layer_v(1, &proof.layers[1], ctx, tx)?;
    let prepared_global = prepare_global_v(proof.thin_k, &proof.global, ctx, tx)?;
    let expected: BTreeSet<_> = x2_content_keys().into_iter().collect();
    let mut table_doms = Doms::new(layer_dom_base(X2_TABLE_SECTION));
    let mut bank = TableBankV::finalize(&expected, &proof.tables, ctx, tx, &mut table_doms)?;

    let layer1 = verify_layer(
        1,
        proof.thin_k,
        &routes[1],
        luts,
        &proof.layers[1],
        prepared1,
        &prepared_global,
        None,
        ctx,
        tx,
        &mut bank,
    )?;
    let global = verify_global(
        proof.thin_k,
        public_logits,
        &proof.global,
        &prepared_global,
        &layer1.input,
        ctx,
        tx,
        &mut bank,
    )?;
    let layer0 = verify_layer(
        0,
        proof.thin_k,
        &routes[0],
        luts,
        &proof.layers[0],
        prepared0,
        &prepared_global,
        Some(&global.downstream),
        ctx,
        tx,
        &mut bank,
    )?;

    let mut kprod = Vec::new();
    let mut kzero = Vec::new();
    for (p, z) in
        [(layer1.kprod, layer1.kzero), (global.kprod, global.kzero), (layer0.kprod, layer0.kzero)]
    {
        kprod.extend(p);
        kzero.extend(z);
    }
    bank.close(luts, &proof.tables, ctx, &mut table_doms, tx, &mut kprod, &mut kzero)?;
    let mut weight_keys = layer0.weights;
    weight_keys.extend(layer1.weights);
    weight_keys.extend(global.weights);
    if weight_keys.len() != 40 {
        return None;
    }
    Some(X2MoeVerifierOut { weight_keys, kprod, kzero })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::x2_moe::build_x2_moe_fixture;
    use volta_mac::zero_batch_exchange;

    #[derive(Clone, Copy)]
    enum Tamper {
        None,
        WrongExpertSet,
        ScoreSwap,
        ForgedLimb,
        InternalState,
        ChunkBoundary,
    }

    fn committed_weights(fixture: &X2MoeFixture) -> Vec<(&[i16], usize, usize)> {
        let mut out = Vec::with_capacity(40);
        for layer in &fixture.weights {
            out.push((layer.dense.c_attn.as_slice(), X2_D, X2_QKV));
            out.push((layer.dense.attn_proj.as_slice(), X2_D, X2_D));
            out.push((layer.router.as_slice(), X2_D, X2_EXPERTS));
            for expert in &layer.experts {
                out.push((expert.up.as_slice(), X2_D, X2_DFF));
                out.push((expert.down.as_slice(), X2_DFF, X2_D));
            }
        }
        out.push((fixture.embedding.as_slice(), X2_VOCAB, X2_D));
        out.push((fixture.output_weight.as_slice(), X2_D, X2_VOCAB));
        out
    }

    fn run_case(thin_k: usize, tamper: Tamper) -> bool {
        let fixture = build_x2_moe_fixture(thin_k);
        let pcg_seed = [0x72; 32];
        let tx_seed = [0x73; 32];
        let delta = Fp2::new(Fp::new(0x1234_5678), Fp::new(0x9abc_def0));
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut txp = Transcript::new(tx_seed);
        let (mut proof, mut pout) = prove_x2_moe(&fixture, &mut stream, &mut txp);
        let mut routes = x2_public_routes();
        match tamper {
            Tamper::None => {}
            Tamper::WrongExpertSet => routes[0][0] = [7, 1],
            Tamper::ScoreSwap => proof.layers[0].auth_corrs[A_ROUTER_SCORES].swap(0, 1),
            Tamper::ForgedLimb => {
                proof.layers[0].router.comparisons.lookup.root_corrs[0] += Fp2::ONE;
            }
            Tamper::InternalState => {
                if let Some(reducer) = &mut proof.layers[0].reducer {
                    reducer.terminal_corr += Fp2::ONE;
                } else {
                    proof.global.auth_corrs[G_INTERNAL][0] ^= 1;
                }
            }
            Tamper::ChunkBoundary => proof.global.auth_corrs[G_ENTRY][0] ^= 1,
        }

        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut txv = Transcript::new(tx_seed);
        let Some(mut vout) = verify_x2_moe(
            &fixture.config,
            &fixture.luts,
            &fixture.tokens,
            &routes,
            &fixture.final_norm.logits,
            &proof,
            &mut verifier,
            &mut txv,
        ) else {
            return false;
        };
        let weights = committed_weights(&fixture);
        if weights.len() != 40 || pout.weight_claims.len() != 40 {
            return false;
        }
        for (((claim, (point, key)), &(weight, rows, cols)), _index) in
            pout.weight_claims.iter().zip(&vout.weight_keys).zip(&weights).zip(0..40)
        {
            if claim.point != *point {
                return false;
            }
            let value = eval_i16_matrix(weight, rows, cols, point);
            pout.zero.push(claim.value.sub(ProverAuthed::from_public(value)));
            vout.kzero.push(key.sub(VerifierKey::from_public(value, delta)));
        }
        let mut closure_p = Doms::new(layer_dom_base(252));
        let mut closure_v = Doms::new(layer_dom_base(252));
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
    fn x2_k1_and_k2_existing_class_composition_accepts() {
        assert!(run_case(1, Tamper::None));
        assert!(run_case(2, Tamper::None));
    }

    #[test]
    fn x2_permanent_cheating_smokes_reject() {
        assert!(!run_case(1, Tamper::WrongExpertSet));
        assert!(!run_case(1, Tamper::ScoreSwap));
        assert!(!run_case(1, Tamper::ForgedLimb));
        assert!(!run_case(2, Tamper::InternalState));
        assert!(!run_case(2, Tamper::ChunkBoundary));
    }
}
