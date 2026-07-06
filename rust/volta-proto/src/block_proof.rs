//! P4 steps 5+6 — fused-block proofs for one transformer layer: the FFN half
//! (residual → requant_ffn_down → GEMM-down → gelu → requant_ffn_up →
//! GEMM-up → LN2 → boundary) and the attention half (residual → out-proj →
//! requant_av → per-head w·V → hadamard/softmax → exp → per-head QKᵀ →
//! requant_qkv → c_attn → LN1 → boundary), plus the whole-layer orchestration
//! `prove_layer`/`verify_layer` (boundary auth hoisted, exactly ONE Π_Prod
//! batch + ONE Π_ZeroBatch closed by the caller over the accumulated rows).
//! No element-wise authentication of internal wires: chains run in reverse
//! dataflow order (LogUp aux folding / chained-GEMM claim0 transport /
//! streamed boundary MAC openings).
//!
//! Layout conventions:
//! * T×d wires: zero-padded `2^pad_bits(d)`-column, `2^pad_bits(T)`-row MLE
//!   domain, column vars LSB, so an instance point `pt` splits as
//!   `(r_j = cols ‖ r_i = rows)` and feeds the chained GEMMs directly.
//! * Rectangular per-head attention wires (scores_q / exp_out / softmax_w):
//!   the causal-packed witness (packed idx = h·caus + i(i+1)/2 + j) is
//!   expanded to `h_pad(16) × T_pad × T_pad` with within-head column vars
//!   LSB, then row vars, then the 4 head bits on TOP:
//!   `y = j + i·T_pad + h·T_pad²`, domain `2^(4 + 2·pad_bits(T))`.
//! * qkv output wire: the c_attn output concat(q, k, v) lives on a PERMUTED
//!   padded T×4096 domain: col' = third·1024 + head·64 + l (natural col
//!   j = third·768 + head·64 + l), so `l` = bits 0..5, head = bits 6..9,
//!   third = bits 10..11 — boolean coordinates select the q/k/v thirds. The
//!   c_attn weight claim consequently lives on the SAME permuted 1024×4096
//!   tensor (`cattn_permuted`) — the P4 PCS layer commit must use it (same
//!   2^22 size as the natural padding, just a column permutation).
//!
//! **Padding** (lookup columns are padded with VALID table elements):
//! * range instances: `rem_pad = 2^(s−1)`, `out_pad = 0` ⇒ transported
//!   `acc_pad = 0` — EXCEPT requant_scores, whose out column is the shared
//!   `scores_q_rect` wire padded with the exp pad INPUT (see below); its
//!   implied non-causal accumulator `2^s·pad_in` is removed by a public
//!   pad-mask correction, and the true above-diagonal QKᵀ accumulators are
//!   element-wise authenticated and added back (they exist mathematically
//!   but are discarded by the causal forward).
//! * exp pair: pad pair `(pad_in, 0)` where `pad_in` is the LEAST exp-LUT
//!   index with output exactly 0 (asserted to exist — exp saturates to 0 for
//!   very negative inputs). Rectangular row sums therefore equal the causal
//!   row sums, so `deñoms(ρ) = 2^rb·ẽxp(½…½, ρ)` holds with NO pad-sum
//!   correction.
//! * softmax_recip pair: pad pair `(0, recip[0])`; the authenticated `recips`
//!   ROW TABLE is padded with `recip[0]` (mirrors ln_rsqrt) — its pad rows
//!   are killed in the hadamard by the zero exp factor.
//! * gelu pair `(0, gelu[0]=0)`, ln_rsqrt pair `(0, ln_rsqrt[0])` as before.
//!
//! **P4-DEVIATION(ln-stats)** (pre-registered, applies to LN1 AND LN2): the
//! LN statistics relations (`d·mean − rowsum` rounding, variance
//! sum-of-squares, `rsqrt_in = var >> ln_var_shift`) are NOT proved in-field;
//! `mean`, `var`, `rsqrt_in` are bound by element-wise authentication and
//! checked prover-side (`assert_ln_stats`). What IS proved: the ln_rsqrt LUT
//! membership, the LN affine `acc = (x−mean)∘(rsqrt·gain) + bias·2^s`
//! (hadamard), and the ln_norm_requant range instance chaining into the
//! upstream GEMM. **P4-DEVIATION(recip-in)** (same pattern, pre-registered
//! here): `recip_in = denoms >> recip_den_shift` (floor shift, exactly the
//! forward's computation) is bound only by element-wise authentication of
//! both vectors plus a prover-side assert; the softmax_recip LUT membership
//! and the `denoms = exp row sums` relation ARE proved in-field.
//!
//! LN gains/biases are PUBLIC in P4 (not among the 4 committed tensors).
//! Exp above the diagonal: `softmax_w_rect = 0` is proved directly by the
//! causal sumcheck; `exp_rect` above the diagonal is then forced to 0 whp by
//! the hadamard (`w = e·recip`, recip ≠ 0 — reciprocal LUT outputs are
//! positive) and independently pinned by the row-sum identity against the
//! authenticated denominators.

use crate::gemm_proof::{
    prove_gemm_act_chained, prove_gemm_committed_chained, verify_gemm_act_chained,
    verify_gemm_committed_chained, ChainDoms, ChainedGemmProof, WeightClaimP, WireKey, WireOut,
};
use crate::hadamard::{hadamard_prove, hadamard_verify, HadamardDoms, HadamardProof};
use crate::logup::{
    blind_instance_prove, blind_instance_verify, eval_mle_counted, BlindInstance, Counters, Doms,
    InstanceOutP, InstanceOutV, LeafAuxClaim, OpenKey,
};
use crate::mle::{eq_vec, eval_mle};
use crate::sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
use crate::thaler::pad_bits;
use volta_field::{Fp, Fp2};
use volta_gpt2::{gemm_i64, GemmBiases, LayerWeights, LayerWitness, Luts, TableId, D, DFF, DH, H};
use volta_mac::{
    auth_verifier, CorrIndex, CorrelationStream, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey,
};

/// Padded head count (4 head bits).
const H_PAD: usize = 16;
const HEAD_BITS: usize = 4;

// ---------------------------------------------------------------------------
// Block contexts (shared by both chains and the layer orchestration)
// ---------------------------------------------------------------------------

/// Layer-scoped base for the block's sequential one-time domains.
pub fn layer_dom_base(layer: u8) -> u64 {
    CorrIndex { session: 1, layer, head: 0, tensor: 0x20, row: 0 }.domain()
}

/// Prover-side block context: correlation stream, transcript, sequential
/// domain allocator and the per-layer Π_Prod / Π_ZeroBatch accumulators.
/// The final closures (one χ-batched prod check + one zero batch) are run by
/// the caller over the accumulated rows.
pub struct BlockCtxP<'a> {
    pub stream: &'a mut CorrelationStream,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub prod: crate::logup::ProdTriples,
    pub zero: Vec<ProverAuthed>,
    /// E-mults spent inside LogUp instances (the p4_report gate number).
    pub ctr_instances: Counters,
    /// E-mults spent on chain-level public evaluations (kept separable).
    pub ctr_other: Counters,
}

impl<'a> BlockCtxP<'a> {
    pub fn new(stream: &'a mut CorrelationStream, tx: &'a mut Transcript, layer: u8) -> Self {
        BlockCtxP {
            stream,
            tx,
            doms: Doms::new(layer_dom_base(layer)),
            prod: Vec::new(),
            zero: Vec::new(),
            ctr_instances: Counters::default(),
            ctr_other: Counters::default(),
        }
    }
}

/// Verifier mirror of [`BlockCtxP`].
pub struct BlockCtxV<'a> {
    pub ctx: &'a mut VerifierCtx,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub kprod: crate::logup::ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

impl<'a> BlockCtxV<'a> {
    pub fn new(ctx: &'a mut VerifierCtx, tx: &'a mut Transcript, layer: u8) -> Self {
        BlockCtxV {
            ctx,
            tx,
            doms: Doms::new(layer_dom_base(layer)),
            kprod: Vec::new(),
            kzero: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Element-wise auth + streamed MAC openings (boundaries, small vectors)
// ---------------------------------------------------------------------------

/// Π_Auth for a T×cols boundary tensor: per-row domains `base_dom + row`,
/// mask-only draws, 8 B corrections (the `auth_phase_at` pattern).
pub(crate) fn auth_matrix_rows_p(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
) -> Vec<u64> {
    assert_eq!(x.len(), rows * cols);
    let mut corr = Vec::with_capacity(rows * cols);
    for row in 0..rows {
        let masks = stream.draw_sub_masks(base_dom + row as u64, cols);
        for (j, &r) in masks.iter().enumerate() {
            corr.push((Fp::from_i64(x[row * cols + j] as i64) - r).value());
        }
    }
    tx.append("auth_corrections", 8 * corr.len() as u64);
    corr
}

/// Streamed MAC opening of a row-authenticated matrix at `point`
/// (= cols vars LSB ‖ rows vars): lazy tag expansion + eq fold. Callable
/// multiple times per tensor (tags are re-expanded, the ledger only checks
/// consistency with the mask draw).
pub(crate) fn open_matrix_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    point: &[Fp2],
) -> ProverAuthed {
    let cb = pad_bits(cols);
    assert_eq!(point.len(), cb + pad_bits(rows), "matrix opening point split mismatch");
    let eq_c = eq_vec(&point[..cb]);
    let eq_r = eq_vec(&point[cb..]);
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        let mut v = Fp2::ZERO;
        let mut mt = Fp2::ZERO;
        for (j, t) in tags.into_iter().enumerate() {
            let xv = x[row * cols + j];
            if xv != 0 {
                v += eq_c[j].mul_base(Fp::from_i64(xv as i64));
            }
            mt += eq_c[j] * t;
        }
        val += eq_r[row] * v;
        tag += eq_r[row] * mt;
    }
    ProverAuthed { x: val, m: tag }
}

/// Verifier: expand and CACHE the per-element keys of a row-authenticated
/// matrix (each domain is one-time — the cache serves every later opening).
pub(crate) fn auth_matrix_rows_v(
    ctx: &mut VerifierCtx,
    base_dom: u64,
    corr: &[u64],
    rows: usize,
    cols: usize,
) -> Vec<Fp2> {
    assert_eq!(corr.len(), rows * cols);
    let mut keys = Vec::with_capacity(rows * cols);
    for row in 0..rows {
        let kr = auth_verifier(ctx, base_dom + row as u64, &corr[row * cols..(row + 1) * cols]);
        keys.extend(kr.into_iter().map(|k| k.k));
    }
    keys
}

/// Verifier's streamed opening over cached keys.
pub(crate) fn open_matrix_k(keys: &[Fp2], rows: usize, cols: usize, point: &[Fp2]) -> VerifierKey {
    let cb = pad_bits(cols);
    assert_eq!(point.len(), cb + pad_bits(rows), "matrix opening point split mismatch");
    let eq_c = eq_vec(&point[..cb]);
    let eq_r = eq_vec(&point[cb..]);
    let mut k = Fp2::ZERO;
    for row in 0..rows {
        let mut acc = Fp2::ZERO;
        for j in 0..cols {
            acc += eq_c[j] * keys[row * cols + j];
        }
        k += eq_r[row] * acc;
    }
    VerifierKey { k }
}

/// Π_Auth for an `F_p` vector at one domain (LN small vectors, row tables,
/// multiplicity vectors, sparse above-diagonal accumulators).
pub(crate) fn auth_fp_vec_p(
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    dom: u64,
    vals: &[Fp],
) -> Vec<u64> {
    let masks = stream.draw_sub_masks(dom, vals.len());
    let corr: Vec<u64> = vals.iter().zip(&masks).map(|(&v, &r)| (v - r).value()).collect();
    tx.append("auth_corrections", 8 * corr.len() as u64);
    corr
}

/// Streamed MAC opening of an authenticated vector at `point`
/// (`vals.len() == 2^point.len()`).
pub(crate) fn open_fp_vec_p(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    point: &[Fp2],
) -> ProverAuthed {
    assert_eq!(vals.len(), 1 << point.len());
    let tags = stream.draw_sub_tags(dom, vals.len());
    let eq = eq_vec(point);
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for (i, t) in tags.into_iter().enumerate() {
        if vals[i] != Fp::ZERO {
            val += eq[i].mul_base(vals[i]);
        }
        tag += eq[i] * t;
    }
    ProverAuthed { x: val, m: tag }
}

pub(crate) fn keys_fp_vec_v(ctx: &mut VerifierCtx, dom: u64, corr: &[u64]) -> Vec<Fp2> {
    auth_verifier(ctx, dom, corr).into_iter().map(|k| k.k).collect()
}

pub(crate) fn open_fp_vec_k(keys: &[Fp2], point: &[Fp2]) -> VerifierKey {
    assert_eq!(keys.len(), 1 << point.len());
    let eq = eq_vec(point);
    VerifierKey { k: keys.iter().zip(&eq).fold(Fp2::ZERO, |s, (&k, &e)| s + e * k) }
}

/// Opening of an authenticated vector with EXPLICIT public weights (used for
/// the sparse above-diagonal accumulator list, whose entries sit at scattered
/// rectangular-domain positions): value/tag = Σ_i weights[i]·(vals[i]/tag_i).
pub(crate) fn open_weighted_p(
    stream: &mut CorrelationStream,
    dom: u64,
    vals: &[Fp],
    weights: &[Fp2],
) -> ProverAuthed {
    assert_eq!(vals.len(), weights.len());
    let tags = stream.draw_sub_tags(dom, vals.len());
    let mut val = Fp2::ZERO;
    let mut tag = Fp2::ZERO;
    for (i, t) in tags.into_iter().enumerate() {
        if vals[i] != Fp::ZERO {
            val += weights[i].mul_base(vals[i]);
        }
        tag += weights[i] * t;
    }
    ProverAuthed { x: val, m: tag }
}

pub(crate) fn open_weighted_k(keys: &[Fp2], weights: &[Fp2]) -> VerifierKey {
    assert_eq!(keys.len(), weights.len());
    VerifierKey { k: keys.iter().zip(weights).fold(Fp2::ZERO, |s, (&k, &w)| s + w * k) }
}

/// Fold a row-authenticated matrix over a COLUMN WINDOW `[c0, c0+w)` with
/// weights `wc` (len w), per row: returns (values, tags), each of length
/// `rows`. Used to pre-fold the per-head V slice for the w·V GEMM B leg
/// (the head-bit prefix is the window selection itself).
pub(crate) fn fold_cols_window_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    assert_eq!(wc.len(), w);
    let mut vals = Vec::with_capacity(rows);
    let mut tags_out = Vec::with_capacity(rows);
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        let mut v = Fp2::ZERO;
        let mut mt = Fp2::ZERO;
        for l in 0..w {
            let xv = x[row * cols + c0 + l];
            if xv != 0 {
                v += wc[l].mul_base(Fp::from_i64(xv as i64));
            }
            mt += wc[l] * tags[c0 + l];
        }
        vals.push(v);
        tags_out.push(mt);
    }
    (vals, tags_out)
}

pub(crate) fn fold_cols_window_k(
    keys: &[Fp2],
    rows: usize,
    cols: usize,
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> Vec<Fp2> {
    (0..rows)
        .map(|row| {
            (0..w).fold(Fp2::ZERO, |s, l| s + wc[l] * keys[row * cols + c0 + l])
        })
        .collect()
}

/// Fold a row-authenticated matrix over its ROWS with weights `wr`
/// (len ≥ rows), restricted to the column window `[c0, c0+w)`: returns
/// (values, tags) of length `w`. Used to pre-fold the per-head K slice for
/// the QKᵀ GEMM B leg — the sumcheck point lands in K's COLUMN (d_h) vars,
/// while the score-column point `r_j` weights K's ROWS (positions).
pub(crate) fn fold_rows_window_p(
    stream: &mut CorrelationStream,
    base_dom: u64,
    x: &[i16],
    rows: usize,
    cols: usize,
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = vec![Fp2::ZERO; w];
    let mut tags_out = vec![Fp2::ZERO; w];
    for row in 0..rows {
        let tags = stream.draw_sub_tags(base_dom + row as u64, cols);
        for l in 0..w {
            let xv = x[row * cols + c0 + l];
            if xv != 0 {
                vals[l] += wr[row].mul_base(Fp::from_i64(xv as i64));
            }
            tags_out[l] += wr[row] * tags[c0 + l];
        }
    }
    (vals, tags_out)
}

pub(crate) fn fold_rows_window_k(
    keys: &[Fp2],
    rows: usize,
    cols: usize,
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> Vec<Fp2> {
    let mut out = vec![Fp2::ZERO; w];
    for row in 0..rows {
        for l in 0..w {
            out[l] += wr[row] * keys[row * cols + c0 + l];
        }
    }
    out
}

/// The 4 head bits of head `h` as fixed boolean MLE coordinates.
pub(crate) fn head_bit_coords(h: usize) -> [Fp2; HEAD_BITS] {
    core::array::from_fn(|b| if (h >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO })
}

// ---------------------------------------------------------------------------
// Column / table builders
// ---------------------------------------------------------------------------

/// Requant range-instance columns over the padded matrix domain:
/// `rem = acc + 2^(s−1) − (out << s)` (round-half-up semantics of
/// `volta_gpt2::gemm::requant`, asserted in range), out zero-padded, rem
/// padded with the valid element `2^(s−1)` (implied pad accumulator = 0).
pub(crate) fn range_cols_padded(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) -> (Vec<Fp>, Vec<Fp>) {
    assert_eq!(acc.len(), rows * cols);
    assert_eq!(out.len(), rows * cols);
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let half = 1i64 << (shift - 1);
    let mut rem = vec![Fp::new(half as u64); rp * cp];
    let mut o = vec![Fp::ZERO; rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            let a = acc[i * cols + j];
            let y = out[i * cols + j] as i64;
            let r = a + half - (y << shift);
            assert!(
                (0..1i64 << shift).contains(&r),
                "requant remainder out of range (shift {shift}): acc={a}, out={y}"
            );
            rem[i * cp + j] = Fp::new(r as u64);
            o[i * cp + j] = Fp::from_i64(y);
        }
    }
    (rem, o)
}

/// Multiplicities of a range instance over the remainder domain, with the
/// pad element `2^(s−1)` bumped by the pad count.
pub(crate) fn range_mult(acc: &[i64], out: &[i16], rows: usize, cols: usize, shift: u32) -> Vec<u32> {
    let half = 1i64 << (shift - 1);
    let mut m = vec![0u32; 1 << shift];
    for (&a, &y) in acc.iter().zip(out) {
        m[(a + half - ((y as i64) << shift)) as usize] += 1;
    }
    let pads = (1usize << pad_bits(rows)) * (1usize << pad_bits(cols)) - rows * cols;
    m[half as usize] += pads as u32;
    m
}

/// Pair-LUT instance columns over the padded matrix domain, pad pair
/// `(pad_in, pad_out)` (must be a valid table pair — asserted by the caller).
pub(crate) fn pair_cols_padded(
    inp: &[i16],
    outp: &[i16],
    rows: usize,
    cols: usize,
    pad_in: i16,
    pad_out: i16,
) -> (Vec<Fp>, Vec<Fp>) {
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let mut ic = vec![Fp::from_i64(pad_in as i64); rp * cp];
    let mut oc = vec![Fp::from_i64(pad_out as i64); rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            ic[i * cp + j] = Fp::from_i64(inp[i * cols + j] as i64);
            oc[i * cp + j] = Fp::from_i64(outp[i * cols + j] as i64);
        }
    }
    (ic, oc)
}

/// Range table `0..2^shift` for a requant instance.
pub(crate) fn range_table(shift: u32) -> Vec<Fp> {
    (0..1u64 << shift).map(Fp::new).collect()
}

/// Packed pair table `t_u = in(u) + 2^16·lut[u]`. `signed_input`: the LUT is
/// indexed by the i16 input's bit pattern (`exp`/`gelu`); otherwise the
/// domain is the non-negative u16 index itself (`ln_rsqrt`/`softmax_recip`).
pub(crate) fn pair_table(lut: &[i16], signed_input: bool) -> Vec<Fp> {
    let two16 = Fp::new(1 << 16);
    lut.iter()
        .enumerate()
        .map(|(u, &o)| {
            let inp = if signed_input { (u as u16 as i16) as i64 } else { u as i64 };
            Fp::from_i64(inp) + Fp::from_i64(o as i64) * two16
        })
        .collect()
}

pub(crate) fn fp_vec_u32(vals: &[u32]) -> Vec<Fp> {
    vals.iter().map(|&m| Fp::new(m as u64)).collect()
}

/// Zero-padded lift of an i64 vector to length `1 << bits`.
pub(crate) fn fp_vec_pad_i64(vals: &[i64], bits: usize) -> Vec<Fp> {
    let mut v = vec![Fp::ZERO; 1 << bits];
    for (i, &x) in vals.iter().enumerate() {
        v[i] = Fp::from_i64(x);
    }
    v
}

/// Zero-padded public MLE lift of an i16 vector.
pub(crate) fn lift_padded_i16(vals: &[i16], bits: usize) -> Vec<Fp2> {
    let mut v = vec![Fp2::ZERO; 1 << bits];
    for (i, &x) in vals.iter().enumerate() {
        v[i] = Fp2::from_base(Fp::from_i64(x as i64));
    }
    v
}

/// Exact-length base-field lifts.
pub(crate) fn fp_col_i16(vals: &[i16]) -> Vec<Fp> {
    vals.iter().map(|&x| Fp::from_i64(x as i64)).collect()
}

pub(crate) fn fp_col_i64(vals: &[i64]) -> Vec<Fp> {
    vals.iter().map(|&x| Fp::from_i64(x)).collect()
}

pub(crate) fn lift_i16_fp2(vals: &[i16]) -> Vec<Fp2> {
    vals.iter().map(|&x| Fp2::from_base(Fp::from_i64(x as i64))).collect()
}

// ---------------------------------------------------------------------------
// Chain-stage helpers
// ---------------------------------------------------------------------------

/// Requant acc-claim transport (tested in logup):
/// `ãcc(pt) = 2^s·oũt(pt) + rẽm(pt) − 2^(s−1)` — col order is [rem, out].
pub(crate) fn transport_p(out: &InstanceOutP, shift: u32) -> ProverAuthed {
    let two_s = Fp2::from_base(Fp::new(1u64 << shift));
    let half = Fp2::from_base(Fp::new(1u64 << (shift - 1)));
    out.col_claims[1]
        .value
        .scale(two_s)
        .add(out.col_claims[0].value)
        .sub(ProverAuthed::from_public(half))
}

pub(crate) fn transport_k(out: &InstanceOutV, shift: u32, delta: Fp2) -> VerifierKey {
    let two_s = Fp2::from_base(Fp::new(1u64 << shift));
    let half = Fp2::from_base(Fp::new(1u64 << (shift - 1)));
    out.col_keys[1]
        .key
        .scale(two_s)
        .add(out.col_keys[0].key)
        .sub(VerifierKey::from_public(half, delta))
}

/// Subtract a per-GEMM bias's public contribution from a transported POST-bias
/// accumulator claim, recovering the pre-bias `acc0 = X·W` claim the chained
/// GEMM expects (P5 §per-GEMM biases; the LN affine's `bias·2^s·rowmask` term
/// is the same pattern, see [`prove_ln_chain`]). `col_bits` is the padded
/// column-var count, `pt` the instance's full point (`cols ‖ rows`).
pub(crate) fn sub_bias_p(
    claim: ProverAuthed,
    bias: &[i16],
    col_bits: usize,
    pt: &[Fp2],
    t: usize,
    shift: u32,
    ctr: &mut Counters,
) -> ProverAuthed {
    let bias_lift = lift_padded_i16(bias, col_bits);
    let bias_eval = eval_mle_counted(&bias_lift, &pt[..col_bits], ctr);
    let rmask = rowmask_eval(&pt[col_bits..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << shift));
    claim.sub(ProverAuthed::from_public(bias_term))
}

/// Verifier mirror of [`sub_bias_p`].
pub(crate) fn sub_bias_k(
    key: VerifierKey,
    bias: &[i16],
    col_bits: usize,
    pt: &[Fp2],
    t: usize,
    shift: u32,
    delta: Fp2,
) -> VerifierKey {
    let bias_lift = lift_padded_i16(bias, col_bits);
    let bias_eval = eval_mle(&bias_lift, &pt[..col_bits]);
    let rmask = rowmask_eval(&pt[col_bits..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << shift));
    key.sub(VerifierKey::from_public(bias_term, delta))
}

/// Resolve an instance's multiplicity claim against the element-wise
/// authenticated (adjusted) multiplicity vector: streamed MAC opening at the
/// table point, zero row.
pub(crate) fn close_mult_p(cx: &mut BlockCtxP, dom: u64, mult_fp: &[Fp], out: &InstanceOutP) {
    let opened = open_fp_vec_p(cx.stream, dom, mult_fp, &out.mult_claim.point);
    cx.zero.push(out.mult_claim.value.sub(opened));
}

pub(crate) fn close_mult_v(cx: &mut BlockCtxV, keys: &[Fp2], mult_key: &OpenKey) {
    let opened = open_fp_vec_k(keys, &mult_key.point);
    cx.kzero.push(mult_key.key.sub(opened));
}

/// Authenticate one multiplicity vector (dom taken from the ctx allocator).
fn auth_mult_p(cx: &mut BlockCtxP, mult: &[u32]) -> (u64, Vec<Fp>, Vec<u64>) {
    let fp = fp_vec_u32(mult);
    let dom = cx.doms.take(1);
    let corr = auth_fp_vec_p(cx.stream, cx.tx, dom, &fp);
    (dom, fp, corr)
}

fn keys_mult_v(cx: &mut BlockCtxV, corr: &[u64]) -> Vec<Fp2> {
    let dom = cx.doms.take(1);
    keys_fp_vec_v(cx.ctx, dom, corr)
}

/// `Σ_{i<t} eq(r_rows, i)` — the public indicator of real (non-pad) rows,
/// needed by the LN hadamard claim0 (the bias broadcast lives on real rows).
pub(crate) fn rowmask_eval(r_rows: &[Fp2], t: usize) -> Fp2 {
    if t == 1 << r_rows.len() {
        return Fp2::ONE;
    }
    let eq = eq_vec(r_rows);
    eq[..t].iter().fold(Fp2::ZERO, |s, &e| s + e)
}

/// Prover-side consistency check of LN statistics vectors against the
/// pre-LN input `x` — the P4-DEVIATION(ln-stats) fallback (see module doc).
fn assert_ln_stats(
    x: &[i16],
    t: usize,
    mean: &[i64],
    var: &[i64],
    rsqrt_in: &[i64],
    rsqrt_out: &[i16],
    luts: &Luts,
) {
    let d = D as i64;
    for i in 0..t {
        let row = &x[i * D..(i + 1) * D];
        let sum: i64 = row.iter().map(|&v| v as i64).sum();
        let m = (sum + d / 2).div_euclid(d);
        assert_eq!(m, mean[i], "P4-DEVIATION(ln-stats): mean inconsistent at row {i}");
        let vs: i64 = row
            .iter()
            .map(|&v| {
                let e = v as i64 - m;
                e * e
            })
            .sum();
        let vr = (vs + d / 2).div_euclid(d);
        assert_eq!(vr, var[i], "P4-DEVIATION(ln-stats): var inconsistent at row {i}");
        let vin = vr >> luts.params.ln_var_shift;
        assert!(vin < 1 << 16, "ln_rsqrt input exceeds u16 domain");
        assert_eq!(vin, rsqrt_in[i], "P4-DEVIATION(ln-stats): rsqrt_in inconsistent");
        assert_eq!(
            luts.ln_rsqrt[vin as usize], rsqrt_out[i],
            "P4-DEVIATION(ln-stats): rsqrt_out inconsistent"
        );
    }
}

// ---------------------------------------------------------------------------
// LN chain (shared by LN2/FFN and LN1/attention)
// ---------------------------------------------------------------------------

/// One LayerNorm's authenticated small vectors (padded to `t_pad`).
struct LnVecsP {
    mean_fp: Vec<Fp>,
    rin_fp: Vec<Fp>,
    rout_fp: Vec<Fp>,
    dom_mean: u64,
    dom_rin: u64,
    dom_rout: u64,
}

/// Authenticate mean/var/rsqrt_in/rsqrt_out (var is authenticated for the
/// record — the ln-stats deviation — but unused by the in-field relations).
/// Returns the vectors + domains and the 4 correction vectors.
fn auth_ln_vecs_p(
    cx: &mut BlockCtxP,
    rb: usize,
    mean: &[i64],
    var: &[i64],
    rsqrt_in: &[i64],
    rsqrt_out: &[i16],
    rout_pad: Fp,
) -> (LnVecsP, [Vec<u64>; 4]) {
    let t = mean.len();
    let t_pad = 1usize << rb;
    let mean_fp = fp_vec_pad_i64(mean, rb);
    let var_fp = fp_vec_pad_i64(var, rb);
    let rin_fp = fp_vec_pad_i64(rsqrt_in, rb);
    // rsqrt_out is padded with the LUT's index-0 output — the pad pair of the
    // ln_rsqrt instance is (0, lut[0]) and the SAME vector closes the
    // hadamard broadcast leg (pad rows killed by the zero centered factor).
    let mut rout_fp = vec![rout_pad; t_pad];
    for i in 0..t {
        rout_fp[i] = Fp::from_i64(rsqrt_out[i] as i64);
    }
    let dom_mean = cx.doms.take(1);
    let mean_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_mean, &mean_fp);
    let dom_var = cx.doms.take(1);
    let var_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_var, &var_fp);
    let dom_rin = cx.doms.take(1);
    let rin_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rin, &rin_fp);
    let dom_rout = cx.doms.take(1);
    let rout_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rout, &rout_fp);
    (
        LnVecsP { mean_fp, rin_fp, rout_fp, dom_mean, dom_rin, dom_rout },
        [mean_corr, var_corr, rin_corr, rout_corr],
    )
}

struct LnVecsK {
    mean_keys: Vec<Fp2>,
    rin_keys: Vec<Fp2>,
    rout_keys: Vec<Fp2>,
}

fn expand_ln_vecs_k(cx: &mut BlockCtxV, corrs: &[Vec<u64>; 4]) -> LnVecsK {
    let dom_mean = cx.doms.take(1);
    let mean_keys = keys_fp_vec_v(cx.ctx, dom_mean, &corrs[0]);
    let dom_var = cx.doms.take(1);
    let _var_keys = keys_fp_vec_v(cx.ctx, dom_var, &corrs[1]);
    let dom_rin = cx.doms.take(1);
    let rin_keys = keys_fp_vec_v(cx.ctx, dom_rin, &corrs[2]);
    let dom_rout = cx.doms.take(1);
    let rout_keys = keys_fp_vec_v(cx.ctx, dom_rout, &corrs[3]);
    LnVecsK { mean_keys, rin_keys, rout_keys }
}

/// The LN chain sub-proof: ln_norm_requant range instance (drains the
/// upstream GEMM's X wire claim) + LN-affine hadamard + ln_rsqrt pair
/// instance closed against the authenticated vectors.
pub struct LnChainProof {
    pub inst_ln: BlindInstance,
    pub hadamard: HadamardProof,
    pub inst_rsqrt: BlindInstance,
}

/// LN chain prover: `acc_ln`/`out_ln` are the T×D ln_norm_requant pairs,
/// `x` is the pre-LN boundary tensor (dom `dom_x`), `wire` the upstream
/// GEMM's X wire claim on `out_ln`.
#[allow(clippy::too_many_arguments)]
fn prove_ln_chain(
    t: usize,
    s_ln: u32,
    acc_ln: &[i64],
    out_ln: &[i16],
    x: &[i16],
    dom_x: u64,
    mean: &[i64],
    gain: &[i16],
    bias: &[i16],
    lv: &LnVecsP,
    mult_ln: &[u32],
    mult_ln_fp: &[Fp],
    dom_m_ln: u64,
    mult_rsq: &[u32],
    mult_rsq_fp: &[Fp],
    dom_m_rsq: u64,
    rsqrt_lut: &[i16],
    wire: &WireOut,
    cx: &mut BlockCtxP,
) -> LnChainProof {
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D);

    // -- ln_norm_requant range instance (drains the GEMM X wire) ------------
    let (rem_ln, out_col) = range_cols_padded(acc_ln, out_ln, t, D, s_ln);
    let inst_ln = blind_instance_prove(
        &[rem_ln, out_col],
        &[Some(0), None],
        &range_table(s_ln),
        mult_ln,
        vec![LeafAuxClaim { col: 1, point: wire.point.clone(), value: wire.value }],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_ln, mult_ln_fp, &inst_ln);

    // -- hadamard: acc_ln − bias·2^s·rowmask = (x − mean) ∘ (rsqrt·gain) ----
    let pt_ln = inst_ln.point.clone();
    let acc_ln_claim = transport_p(&inst_ln, s_ln);
    let bias_lift = lift_padded_i16(bias, d_cb);
    let bias_eval = eval_mle_counted(&bias_lift, &pt_ln[..d_cb], &mut cx.ctr_other);
    let rmask = rowmask_eval(&pt_ln[d_cb..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << s_ln));
    let claim0_h = acc_ln_claim.sub(ProverAuthed::from_public(bias_term));
    let n_ln = 1usize << pt_ln.len();
    let cp_d = 1usize << d_cb;
    let mut e_tab = vec![Fp2::ZERO; n_ln];
    let mut r_tab = vec![Fp2::ZERO; n_ln];
    for i in 0..t_pad {
        for j in 0..cp_d {
            if i < t {
                let a = if j < D { x[i * D + j] as i64 } else { 0 };
                e_tab[i * cp_d + j] = Fp2::from_base(Fp::from_i64(a - mean[i]));
            }
            if j < D {
                r_tab[i * cp_d + j] =
                    Fp2::from_base(lv.rout_fp[i] * Fp::from_i64(gain[j] as i64));
            }
        }
    }
    let hd = HadamardDoms::alloc(&mut cx.doms, pt_ln.len());
    let (had_proof, r_h, e_claim, r_claim) = hadamard_prove(
        &pt_ln, e_tab, r_tab, claim0_h, &hd, cx.stream, cx.tx, &mut cx.prod, &mut cx.zero,
    );
    // ẽ(r) = x̃(r) − meañ(r_rows): streamed boundary + vector openings.
    let x_open_r = open_matrix_p(cx.stream, dom_x, x, t, D, &r_h);
    let mean_open = open_fp_vec_p(cx.stream, lv.dom_mean, &lv.mean_fp, &r_h[d_cb..]);
    cx.zero.push(e_claim.sub(x_open_r.sub(mean_open)));
    // R̃(r) = rsqrt̃(r_rows)·g̃ain(r_cols): gain public, rsqrt authenticated.
    let gain_lift = lift_padded_i16(gain, d_cb);
    let gain_eval = eval_mle_counted(&gain_lift, &r_h[..d_cb], &mut cx.ctr_other);
    let rsq_open_h = open_fp_vec_p(cx.stream, lv.dom_rout, &lv.rout_fp, &r_h[d_cb..]);
    cx.zero.push(r_claim.sub(rsq_open_h.scale(gain_eval)));

    // -- ln_rsqrt pair instance, closed against the authed vectors ----------
    let rsq_tv = pair_table(rsqrt_lut, false);
    let inst_rsqrt = blind_instance_prove(
        &[lv.rin_fp.clone(), lv.rout_fp.clone()],
        &[Some(0), Some(16)],
        &rsq_tv,
        mult_rsq,
        Vec::new(),
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    let rsq_in_open = open_fp_vec_p(cx.stream, lv.dom_rin, &lv.rin_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[0].value.sub(rsq_in_open));
    let rsq_out_open = open_fp_vec_p(cx.stream, lv.dom_rout, &lv.rout_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[1].value.sub(rsq_out_open));
    close_mult_p(cx, dom_m_rsq, mult_rsq_fp, &inst_rsqrt);

    LnChainProof {
        inst_ln: inst_ln.proof,
        hadamard: had_proof,
        inst_rsqrt: inst_rsqrt.proof,
    }
}

/// LN chain verifier (mirror of [`prove_ln_chain`]).
#[allow(clippy::too_many_arguments)]
fn verify_ln_chain(
    t: usize,
    s_ln: u32,
    gain: &[i16],
    bias: &[i16],
    rsqrt_lut: &[i16],
    x_keys: &[Fp2],
    lvk: &LnVecsK,
    mult_ln_keys: &[Fp2],
    mult_rsq_keys: &[Fp2],
    proof: &LnChainProof,
    wire: &WireKey,
    cx: &mut BlockCtxV,
) -> Option<()> {
    let rb = pad_bits(t);
    let d_cb = pad_bits(D);
    let n_d = d_cb + rb;
    let shifts_range = [Some(0u32), None];
    let shifts_pair = [Some(0u32), Some(16u32)];

    let aux_ln = [(1usize, wire.point.clone(), wire.key)];
    let vl = blind_instance_verify(
        n_d,
        &shifts_range,
        &range_table(s_ln),
        &proof.inst_ln,
        &aux_ln,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, mult_ln_keys, &vl.mult_key);

    let pt_ln = vl.point.clone();
    let k_acc_ln = transport_k(&vl, s_ln, cx.ctx.delta);
    let bias_lift = lift_padded_i16(bias, d_cb);
    let bias_eval = eval_mle(&bias_lift, &pt_ln[..d_cb]);
    let rmask = rowmask_eval(&pt_ln[d_cb..], t);
    let bias_term = bias_eval * rmask * Fp2::from_base(Fp::new(1u64 << s_ln));
    let k_claim0_h = k_acc_ln.sub(VerifierKey::from_public(bias_term, cx.ctx.delta));
    let hd = HadamardDoms::alloc(&mut cx.doms, pt_ln.len());
    let (r_h, k_e, k_r) = hadamard_verify(
        &pt_ln,
        k_claim0_h,
        &proof.hadamard,
        &hd,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let x_k_r = open_matrix_k(x_keys, t, D, &r_h);
    let mean_k = open_fp_vec_k(&lvk.mean_keys, &r_h[d_cb..]);
    cx.kzero.push(k_e.sub(x_k_r.sub(mean_k)));
    let gain_lift = lift_padded_i16(gain, d_cb);
    let gain_eval = eval_mle(&gain_lift, &r_h[..d_cb]);
    let rsq_k_h = open_fp_vec_k(&lvk.rout_keys, &r_h[d_cb..]);
    cx.kzero.push(k_r.sub(rsq_k_h.scale(gain_eval)));

    let rsq_tv = pair_table(rsqrt_lut, false);
    let vr = blind_instance_verify(
        rb,
        &shifts_pair,
        &rsq_tv,
        &proof.inst_rsqrt,
        &[],
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let rin_k = open_fp_vec_k(&lvk.rin_keys, &vr.point);
    cx.kzero.push(vr.col_keys[0].key.sub(rin_k));
    let rout_k = open_fp_vec_k(&lvk.rout_keys, &vr.point);
    cx.kzero.push(vr.col_keys[1].key.sub(rout_k));
    close_mult_v(cx, mult_rsq_keys, &vr.mult_key);
    Some(())
}

// ---------------------------------------------------------------------------
// FFN block (boundary auth HOISTED to the caller — prove_layer or the tests)
// ---------------------------------------------------------------------------

pub struct FfnBlockProof {
    /// LN2 vector corrections: [mean, var, rsqrt_in, rsqrt_out].
    pub ln_vec_corrs: [Vec<u64>; 4],
    /// Adjusted multiplicity vectors: [ffn_down, gelu, ffn_up, ln_norm, ln_rsqrt].
    pub mult_corr: [Vec<u64>; 5],
    // Chain, reverse dataflow order.
    pub inst_down: BlindInstance,
    pub gemm_down: ChainedGemmProof,
    pub gelu_wire_corr: Fp2,
    pub w_down_corr: Fp2,
    pub inst_gelu: BlindInstance,
    pub inst_up: BlindInstance,
    pub gemm_up: ChainedGemmProof,
    pub ln2_wire_corr: Fp2,
    pub w_up_corr: Fp2,
    pub ln: LnChainProof,
}

/// Prove the FFN half. The caller has already authenticated the
/// `attn_block_out` / `ffn_block_out` boundaries at `dom_abo` / `dom_fbo`.
/// Returns the proof and the weight claims `[ffn_down, ffn_up]`.
pub fn prove_ffn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> (FfnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D); // 10
    let f_cb = pad_bits(DFF); // 12

    // ---- phase 0: LN-vector + multiplicity auth ---------------------------
    // Everything the instances look up is bound BEFORE any α is drawn.
    assert_ln_stats(
        &wit.attn_block_out, t, &wit.ln2_mean, &wit.ln2_var, &wit.ln2_rsqrt_in,
        &wit.ln2_rsqrt_out, luts,
    );
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv, ln_vec_corrs) = auth_ln_vecs_p(
        cx, rb, &wit.ln2_mean, &wit.ln2_var, &wit.ln2_rsqrt_in, &wit.ln2_rsqrt_out, rout_pad,
    );

    let s_dn = p.shift_ffn_down;
    let s_up = p.shift_ffn_up;
    let s_ln = p.shift_ln_norm;
    let mult_dn = range_mult(&wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn);
    assert_eq!(luts.gelu[0], 0, "gelu pad pair (0,0) requires gelu[0] == 0");
    let ff_pads = (t_pad << f_cb) - t * DFF;
    let mut mult_gelu = wit.traces[TableId::Gelu as usize].multiplicity.clone();
    mult_gelu[0] += ff_pads as u32; // pad pair (0, gelu[0]=0) at index 0
    let mult_up = range_mult(&wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    // LN2 half of the (LN1+LN2) ln_norm_requant trace: rows t·D..2·t·D.
    let ln_trace = &wit.traces[TableId::LnNormRequant as usize];
    let acc_ln = &ln_trace.inputs[t * D..2 * t * D];
    let mult_ln = range_mult(acc_ln, &wit.ln2_out, t, D, s_ln);
    let mut mult_rsq = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq[wit.ln2_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq[0] += (t_pad - t) as u32; // pad pair (0, ln_rsqrt[0]) at index 0

    let (dom_m_dn, mult_dn_fp, m_dn_corr) = auth_mult_p(cx, &mult_dn);
    let (dom_m_gelu, mult_gelu_fp, m_gelu_corr) = auth_mult_p(cx, &mult_gelu);
    let (dom_m_up, mult_up_fp, m_up_corr) = auth_mult_p(cx, &mult_up);
    let (dom_m_ln, mult_ln_fp, m_ln_corr) = auth_mult_p(cx, &mult_ln);
    let (dom_m_rsq, mult_rsq_fp, m_rsq_corr) = auth_mult_p(cx, &mult_rsq);

    // ---- 1+2: ffn_down range instance, closed against the residual --------
    let (rem_dn, out_dn) = range_cols_padded(&wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn);
    let inst_down = blind_instance_prove(
        &[rem_dn, out_dn],
        &[Some(0), None],
        &range_table(s_dn),
        &mult_dn,
        Vec::new(),
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    let pt = inst_down.point.clone();
    // Residual zero row: ffn_down_q̃(pt) − f̃bo(pt) + ãbo(pt) = 0, both
    // boundaries opened by streamed MAC opening at the instance's point.
    let f_open = open_matrix_p(cx.stream, dom_fbo, &wit.ffn_block_out, t, D, &pt);
    let a_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt);
    cx.zero.push(inst_down.col_claims[1].value.sub(f_open).add(a_open));
    close_mult_p(cx, dom_m_dn, &mult_dn_fp, &inst_down);

    // ---- 3: acc transport → GEMM-down (committed, chained) ----------------
    let mut acc_dn_claim = transport_p(&inst_down, s_dn);
    if let Some(b) = biases {
        acc_dn_claim =
            sub_bias_p(acc_dn_claim, &b.ffn_down, d_cb, &pt, t, s_dn, &mut cx.ctr_other);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (gemm_down, wire_gelu, w_down_corr, wclaim_down, _tm_dn, _cc_dn) =
        prove_gemm_committed_chained(
            &wit.gelu_out,
            &weights.ffn_down,
            t,
            DFF,
            D,
            r_i_dn,
            r_j_dn,
            acc_dn_claim,
            &cd_down,
            cx.stream,
            cx.tx,
        );

    // ---- 4: gelu pair instance (drains the GEMM-down X wire claim) --------
    let (gelu_in, gelu_out_col) = pair_cols_padded(&wit.ffn_up_q, &wit.gelu_out, t, DFF, 0, 0);
    let gelu_tv = pair_table(&luts.gelu, true);
    let inst_gelu = blind_instance_prove(
        &[gelu_in, gelu_out_col],
        &[Some(0), Some(16)],
        &gelu_tv,
        &mult_gelu,
        vec![LeafAuxClaim { col: 1, point: wire_gelu.point.clone(), value: wire_gelu.value }],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_gelu, &mult_gelu_fp, &inst_gelu);
    // col_claims[1] (gelu out) is redundant post-fold: the external GEMM
    // claim was consolidated into the instance's own leaf closure. Dropped.

    // ---- 5: ffn_up range instance → GEMM-up -------------------------------
    let (rem_up, out_up) = range_cols_padded(&wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    let inst_up = blind_instance_prove(
        &[rem_up, out_up],
        &[Some(0), None],
        &range_table(s_up),
        &mult_up,
        vec![LeafAuxClaim {
            col: 1,
            point: inst_gelu.point.clone(),
            value: inst_gelu.col_claims[0].value,
        }],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_up, &mult_up_fp, &inst_up);
    let mut acc_up_claim = transport_p(&inst_up, s_up);
    let pt_u = inst_up.point.clone();
    if let Some(b) = biases {
        acc_up_claim =
            sub_bias_p(acc_up_claim, &b.ffn_up, f_cb, &pt_u, t, s_up, &mut cx.ctr_other);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_up, wire_ln2, w_up_corr, wclaim_up, _tm_up, _cc_up) = prove_gemm_committed_chained(
        &wit.ln2_out,
        &weights.ffn_up,
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        acc_up_claim,
        &cd_up,
        cx.stream,
        cx.tx,
    );

    // ---- 6: LN2 chain ------------------------------------------------------
    let ln = prove_ln_chain(
        t,
        s_ln,
        acc_ln,
        &wit.ln2_out,
        &wit.attn_block_out,
        dom_abo,
        &wit.ln2_mean,
        &weights.ln2_gain,
        &weights.ln2_bias,
        &lv,
        &mult_ln,
        &mult_ln_fp,
        dom_m_ln,
        &mult_rsq,
        &mult_rsq_fp,
        dom_m_rsq,
        &luts.ln_rsqrt,
        &wire_ln2,
        cx,
    );

    let proof = FfnBlockProof {
        ln_vec_corrs,
        mult_corr: [m_dn_corr, m_gelu_corr, m_up_corr, m_ln_corr, m_rsq_corr],
        inst_down: inst_down.proof,
        gemm_down,
        gelu_wire_corr: wire_gelu.corr,
        w_down_corr,
        inst_gelu: inst_gelu.proof,
        inst_up: inst_up.proof,
        gemm_up,
        ln2_wire_corr: wire_ln2.corr,
        w_up_corr,
        ln,
    };
    (proof, vec![wclaim_down, wclaim_up])
}

/// Verify the FFN half. `abo_keys`/`fbo_keys` are the cached boundary keys
/// (expanded by the caller). On success returns the `[ffn_down, ffn_up]`
/// weight-claim (point, key) pairs; the caller must still close the
/// accumulated `kprod`/`kzero` batches.
#[allow(clippy::too_many_arguments)]
pub fn verify_ffn_block(
    t: usize,
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &FfnBlockProof,
    cx: &mut BlockCtxV,
    abo_keys: &[Fp2],
    fbo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D);
    let f_cb = pad_bits(DFF);
    let s_dn = p.shift_ffn_down;
    let s_up = p.shift_ffn_up;
    let s_ln = p.shift_ln_norm;

    // Length checks before consuming any correlations.
    for v in &proof.ln_vec_corrs {
        if v.len() != t_pad {
            return None;
        }
    }
    let mult_lens = [1usize << s_dn, 1 << 16, 1usize << s_up, 1usize << s_ln, 1 << 16];
    for (mc, &ml) in proof.mult_corr.iter().zip(&mult_lens) {
        if mc.len() != ml {
            return None;
        }
    }

    // ---- phase 0: expand + cache all element-wise keys --------------------
    let lvk = expand_ln_vecs_k(cx, &proof.ln_vec_corrs);
    let mult_keys: Vec<Vec<Fp2>> =
        proof.mult_corr.iter().map(|mc| keys_mult_v(cx, mc)).collect();

    // ---- ffn_down instance + residual + transport → GEMM-down -------------
    let n_d = d_cb + rb;
    let n_ff = f_cb + rb;
    let shifts_range = [Some(0u32), None];
    let vd = blind_instance_verify(
        n_d,
        &shifts_range,
        &range_table(s_dn),
        &proof.inst_down,
        &[],
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let pt = vd.point.clone();
    let f_k = open_matrix_k(fbo_keys, t, D, &pt);
    let a_k = open_matrix_k(abo_keys, t, D, &pt);
    cx.kzero.push(vd.col_keys[1].key.sub(f_k).add(a_k));
    close_mult_v(cx, &mult_keys[0], &vd.mult_key);

    let mut k_acc_dn = transport_k(&vd, s_dn, cx.ctx.delta);
    if let Some(b) = biases {
        k_acc_dn = sub_bias_k(k_acc_dn, &b.ffn_down, d_cb, &pt, t, s_dn, cx.ctx.delta);
    }
    let (r_j_dn, r_i_dn) = pt.split_at(d_cb);
    let cd_down = ChainDoms::alloc(&mut cx.doms, DFF);
    let (wk_gelu, w_pt_dn, k_w_dn) = verify_gemm_committed_chained(
        t,
        DFF,
        D,
        r_i_dn,
        r_j_dn,
        k_acc_dn,
        &proof.gemm_down,
        proof.gelu_wire_corr,
        proof.w_down_corr,
        &cd_down,
        cx.ctx,
        cx.tx,
    )?;

    // ---- gelu instance -----------------------------------------------------
    let gelu_tv = pair_table(&luts.gelu, true);
    let shifts_pair = [Some(0u32), Some(16u32)];
    let aux_gelu = [(1usize, wk_gelu.point.clone(), wk_gelu.key)];
    let vg = blind_instance_verify(
        n_ff,
        &shifts_pair,
        &gelu_tv,
        &proof.inst_gelu,
        &aux_gelu,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[1], &vg.mult_key);

    // ---- ffn_up instance + transport → GEMM-up -----------------------------
    let aux_up = [(1usize, vg.point.clone(), vg.col_keys[0].key)];
    let vu = blind_instance_verify(
        n_ff,
        &shifts_range,
        &range_table(s_up),
        &proof.inst_up,
        &aux_up,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[2], &vu.mult_key);
    let mut k_acc_up = transport_k(&vu, s_up, cx.ctx.delta);
    let pt_u = vu.point.clone();
    if let Some(b) = biases {
        k_acc_up = sub_bias_k(k_acc_up, &b.ffn_up, f_cb, &pt_u, t, s_up, cx.ctx.delta);
    }
    let (r_j_up, r_i_up) = pt_u.split_at(f_cb);
    let cd_up = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_ln2, w_pt_up, k_w_up) = verify_gemm_committed_chained(
        t,
        D,
        DFF,
        r_i_up,
        r_j_up,
        k_acc_up,
        &proof.gemm_up,
        proof.ln2_wire_corr,
        proof.w_up_corr,
        &cd_up,
        cx.ctx,
        cx.tx,
    )?;

    // ---- LN2 chain ----------------------------------------------------------
    verify_ln_chain(
        t,
        s_ln,
        ln2_gain,
        ln2_bias,
        &luts.ln_rsqrt,
        abo_keys,
        &lvk,
        &mult_keys[3],
        &mult_keys[4],
        &proof.ln,
        &wk_ln2,
        cx,
    )?;

    Some(vec![(w_pt_dn, k_w_dn), (w_pt_up, k_w_up)])
}

// ---------------------------------------------------------------------------
// Attention block — prover-side derived wires
// ---------------------------------------------------------------------------

/// The c_attn weight tensor on the PERMUTED padded 768×4096 column layout
/// (col' = third·1024 + head·64 + l). The P4 layer PCS commits THIS layout.
pub fn cattn_permuted(c_attn: &[i16]) -> Vec<i16> {
    assert_eq!(c_attn.len(), D * 3 * D);
    let mut w = vec![0i16; D * 4096];
    for r in 0..D {
        for j in 0..3 * D {
            let third = j / D;
            let rest = j % D;
            w[r * 4096 + third * 1024 + rest] = c_attn[r * 3 * D + j];
        }
    }
    w
}

/// The c_attn bias vector on the SAME permuted length-4096 column layout as
/// [`cattn_permuted`] (col' = third·1024 + rest, `rest` = head·64 + l), zero
/// at the pad columns (head 12..16 and third 3). Mirrors `cattn_permuted`'s
/// index math exactly, applied to a length-3D vector instead of a D×3D
/// matrix.
pub fn cattn_bias_permuted(c_attn_bias: &[i16]) -> Vec<i16> {
    assert_eq!(c_attn_bias.len(), 3 * D);
    let mut b = vec![0i16; 4096];
    for j in 0..3 * D {
        let third = j / D;
        let rest = j % D;
        b[third * 1024 + rest] = c_attn_bias[j];
    }
    b
}

/// Prover-side derived attention wires: the rectangular expansions of the
/// causal-packed witness fields plus the small authenticated row tables and
/// the recomputed above-diagonal QKᵀ accumulators. Built honestly by
/// [`build_attn_wires`]; the tamper tests mutate a copy (cheating-prover
/// emulation, as in the FFN tests).
pub struct AttnWires {
    /// h_pad×T_pad×T_pad, non-causal = exp pad INPUT (least zero-output idx).
    pub scores_rect: Vec<i16>,
    /// h_pad×T_pad×T_pad, non-causal = 0 (the exp pad pair's output).
    pub exp_rect: Vec<i16>,
    /// h_pad×T_pad×T_pad, non-causal = 0.
    pub w_rect: Vec<i16>,
    /// The copy the causal sumcheck's B leg folds (== w_rect honestly).
    pub w_rect_causal: Vec<i16>,
    /// Full per-head QKᵀ accumulators (H·t·t, row-major t×t per head) —
    /// recomputed; the forward discards the above-diagonal half.
    pub acc_full: Vec<i64>,
    /// Above-diagonal accumulators in fixed order (h, then i, then j>i).
    pub above_acc: Vec<i64>,
    /// h_pad·T_pad row tables (index = head·T_pad + i), zero pads.
    pub denoms_row: Vec<i64>,
    pub recip_in_row: Vec<i64>,
    /// Pads = softmax_recip[0] (the pad PAIR output — mirrors ln_rsqrt).
    pub recips_row: Vec<i16>,
    /// Least exp-LUT index with output 0 (upholds the zero row sums).
    pub exp_pad_u: usize,
}

impl AttnWires {
    pub fn exp_pad_in(&self) -> i16 {
        (self.exp_pad_u as u16) as i16
    }
}

pub fn build_attn_wires(wit: &LayerWitness, luts: &Luts) -> AttnWires {
    let t = wit.t;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let tp2 = t_pad * t_pad;
    let caus = t * (t + 1) / 2;

    // Exp pad pair: (pad_in, 0) — asserted to exist (exp underflows to 0).
    let exp_pad_u = (0..1usize << 16)
        .find(|&u| luts.exp[u] == 0)
        .expect("exp LUT has no zero output — rectangular padding impossible");
    let pad_in = (exp_pad_u as u16) as i16;

    let mut scores_rect = vec![pad_in; H_PAD * tp2];
    let mut exp_rect = vec![0i16; H_PAD * tp2];
    let mut w_rect = vec![0i16; H_PAD * tp2];
    for h in 0..H {
        for i in 0..t {
            for j in 0..=i {
                let pidx = h * caus + i * (i + 1) / 2 + j;
                let y = h * tp2 + i * t_pad + j;
                scores_rect[y] = wit.scores_q[pidx];
                exp_rect[y] = wit.exp_out[pidx];
                w_rect[y] = wit.softmax_w[pidx];
            }
        }
    }

    // Recompute the FULL per-head QKᵀ accumulators (above-diagonal included).
    let mut acc_full = vec![0i64; H * t * t];
    let mut above_acc = Vec::with_capacity(H * t * (t - 1) / 2);
    for h in 0..H {
        let mut qh = vec![0i16; t * DH];
        let mut kht = vec![0i16; DH * t];
        for i in 0..t {
            for l in 0..DH {
                qh[i * DH + l] = wit.q[i * D + h * DH + l];
                kht[l * t + i] = wit.k[i * D + h * DH + l];
            }
        }
        let s_full = gemm_i64(&qh, &kht, t, DH, t);
        for i in 0..t {
            for j in 0..=i {
                let pidx = h * caus + i * (i + 1) / 2 + j;
                assert_eq!(
                    s_full[i * t + j], wit.scores_acc[pidx],
                    "witness scores_acc inconsistent with QK^T recompute"
                );
            }
        }
        acc_full[h * t * t..(h + 1) * t * t].copy_from_slice(&s_full);
        for i in 0..t {
            for j in (i + 1)..t {
                above_acc.push(s_full[i * t + j]);
            }
        }
    }

    // Row tables + the P4-DEVIATION(recip-in) prover-side consistency check.
    let recip0 = luts.softmax_recip[0];
    let mut denoms_row = vec![0i64; H_PAD * t_pad];
    let mut recip_in_row = vec![0i64; H_PAD * t_pad];
    let mut recips_row = vec![recip0; H_PAD * t_pad];
    for idx in 0..H_PAD * t_pad {
        let (h, i) = (idx / t_pad, idx % t_pad);
        if h >= H || i >= t {
            denoms_row[idx] = 0;
            recip_in_row[idx] = 0;
            continue;
        }
        let denom = wit.denoms[h * t + i];
        let rin = denom >> luts.params.recip_den_shift;
        assert!(rin < 1 << 16, "softmax_recip input exceeds u16 domain");
        assert_eq!(
            luts.softmax_recip[rin as usize],
            wit.recips[h * t + i],
            "P4-DEVIATION(recip-in): recips inconsistent with denoms >> shift"
        );
        denoms_row[idx] = denom;
        recip_in_row[idx] = rin;
        recips_row[idx] = wit.recips[h * t + i];
    }

    AttnWires {
        scores_rect,
        exp_rect,
        w_rect_causal: w_rect.clone(),
        w_rect,
        acc_full,
        above_acc,
        denoms_row,
        recip_in_row,
        recips_row,
        exp_pad_u,
    }
}

// ---------------------------------------------------------------------------
// Attention block — proof object
// ---------------------------------------------------------------------------

pub struct AttnBlockProof {
    /// LN1 vector corrections: [mean, var, rsqrt_in, rsqrt_out].
    pub ln_vec_corrs: [Vec<u64>; 4],
    pub denoms_corr: Vec<u64>,
    pub recip_in_corr: Vec<u64>,
    pub recips_corr: Vec<u64>,
    /// Above-diagonal QKᵀ accumulators (fixed sparse order), 8 B each.
    pub above_corr: Vec<u64>,
    /// [attn_proj, av, softmax_norm, exp, softmax_recip, scores, qkv,
    ///  ln1_norm, ln1_rsqrt].
    pub mult_corr: [Vec<u64>; 9],
    // Chain, reverse dataflow order.
    pub inst_proj: BlindInstance,
    pub gemm_proj: ChainedGemmProof,
    pub av_wire_corr: Fp2,
    pub w_proj_corr: Fp2,
    pub inst_av: BlindInstance,
    pub av_split_corrs: [Fp2; H],
    pub gemm_wv: Vec<(ChainedGemmProof, Fp2)>,
    pub causal: BlindSumcheckProof,
    pub causal_w_corr: Fp2,
    pub inst_sn: BlindInstance,
    pub hadamard: HadamardProof,
    pub rowsum_corr: Fp2,
    pub inst_exp: BlindInstance,
    pub inst_recip: BlindInstance,
    pub inst_sc: BlindInstance,
    pub sc_split_corrs: [Fp2; H],
    pub gemm_qk: Vec<(ChainedGemmProof, Fp2)>,
    pub inst_qkv: BlindInstance,
    pub gemm_cattn: ChainedGemmProof,
    pub ln1_wire_corr: Fp2,
    pub w_cattn_corr: Fp2,
    pub ln: LnChainProof,
}

// ---------------------------------------------------------------------------
// Attention block — prover
// ---------------------------------------------------------------------------

/// Prove the attention half. Boundaries (x_in, K, V, attn_block_out) are
/// already authenticated by the caller at the given domains. Returns the
/// proof and the weight claims `[attn_proj, c_attn]`. The c_attn claim lives
/// on the PERMUTED tensor (see [`cattn_permuted`]).
#[allow(clippy::too_many_arguments)]
pub fn prove_attn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: &AttnWires,
    cx: &mut BlockCtxP,
    dom_xin: u64,
    dom_k: u64,
    dom_v: u64,
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> (AttnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let tp2 = t_pad * t_pad;
    let nr = 2 * rb + HEAD_BITS;
    let d_cb = pad_bits(D); // 10
    let caus = t * (t + 1) / 2;
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;

    // ---- phase 0a: build every derived column (before ANY α) --------------
    // softmax_norm remainder: rem = e·rc + 2^(s−1) − w·2^s uniformly over the
    // rect domain (pads: e = w = 0 ⇒ rem = 2^(s−1), the standard pad).
    let half_sn = 1i64 << (s_sn - 1);
    let mut rem_sn = vec![0i64; 1 << nr];
    for y in 0..1usize << nr {
        let e = wires.exp_rect[y] as i64;
        let rc = wires.recips_row[y >> rb] as i64;
        let w = wires.w_rect[y] as i64;
        let r = e * rc + half_sn - (w << s_sn);
        assert!((0..1i64 << s_sn).contains(&r), "softmax_norm remainder out of range");
        rem_sn[y] = r;
    }
    let mut mult_sn = vec![0u32; 1 << s_sn];
    for &r in &rem_sn {
        mult_sn[r as usize] += 1;
    }
    // scores remainder: causal from the witness accumulators, 2^(s−1) pads.
    let half_sc = 1i64 << (s_sc - 1);
    let mut rem_sc = vec![half_sc; 1 << nr];
    for h in 0..H {
        for i in 0..t {
            for j in 0..=i {
                let pidx = h * caus + i * (i + 1) / 2 + j;
                let r = wit.scores_acc[pidx] + half_sc
                    - ((wit.scores_q[pidx] as i64) << s_sc);
                assert!((0..1i64 << s_sc).contains(&r), "scores remainder out of range");
                rem_sc[h * tp2 + i * t_pad + j] = r;
            }
        }
    }
    let mut mult_sc = vec![0u32; 1 << s_sc];
    for &r in &rem_sc {
        mult_sc[r as usize] += 1;
    }
    // exp multiplicities: recount over the rect input column.
    let mut mult_exp = vec![0u32; 1 << 16];
    for &s in &wires.scores_rect {
        mult_exp[(s as u16) as usize] += 1;
    }
    // softmax_recip multiplicities over the row-table domain.
    let mut mult_recip = vec![0u32; 1 << 16];
    for &rin in &wires.recip_in_row {
        mult_recip[rin as usize] += 1;
    }
    // qkv on the permuted padded T×4096 domain.
    let half_qkv = 1i64 << (s_qkv - 1);
    let mut rem_qkv = vec![half_qkv; t_pad * 4096];
    let mut out_qkv = vec![0i16; t_pad * 4096];
    for i in 0..t {
        for j3 in 0..3 * D {
            let third = j3 / D;
            let rest = j3 % D;
            let cprime = third * 1024 + rest;
            let acc = wit.qkv_acc[i * 3 * D + j3];
            let outv = match third {
                0 => wit.q[i * D + rest],
                1 => wit.k[i * D + rest],
                _ => wit.v[i * D + rest],
            };
            let r = acc + half_qkv - ((outv as i64) << s_qkv);
            assert!((0..1i64 << s_qkv).contains(&r), "qkv remainder out of range");
            rem_qkv[i * 4096 + cprime] = r;
            out_qkv[i * 4096 + cprime] = outv;
        }
    }
    let mut mult_qkv = vec![0u32; 1 << s_qkv];
    for &r in &rem_qkv {
        mult_qkv[r as usize] += 1;
    }
    // LN1 (first half of the shared ln_norm_requant trace) + attn_proj/av.
    assert_ln_stats(
        &wit.x_in, t, &wit.ln1_mean, &wit.ln1_var, &wit.ln1_rsqrt_in, &wit.ln1_rsqrt_out, luts,
    );
    let ln_trace = &wit.traces[TableId::LnNormRequant as usize];
    let acc_ln1 = &ln_trace.inputs[..t * D];
    let mult_ln1 = range_mult(acc_ln1, &wit.ln1_out, t, D, s_ln);
    let mut mult_rsq1 = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq1[wit.ln1_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq1[0] += (t_pad - t) as u32;
    let mult_proj = range_mult(&wit.proj_acc, &wit.attn_proj_q, t, D, s_ap);
    let mult_av = range_mult(&wit.av_acc, &wit.av_q, t, D, s_av);

    // ---- phase 0b: element-wise auth ---------------------------------------
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv1, ln_vec_corrs) = auth_ln_vecs_p(
        cx, rb, &wit.ln1_mean, &wit.ln1_var, &wit.ln1_rsqrt_in, &wit.ln1_rsqrt_out, rout_pad,
    );
    let denoms_fp = fp_col_i64(&wires.denoms_row);
    let dom_denoms = cx.doms.take(1);
    let denoms_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_denoms, &denoms_fp);
    let rin_row_fp = fp_col_i64(&wires.recip_in_row);
    let dom_rin_row = cx.doms.take(1);
    let recip_in_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_rin_row, &rin_row_fp);
    let recips_fp = fp_col_i16(&wires.recips_row);
    let dom_recips = cx.doms.take(1);
    let recips_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_recips, &recips_fp);
    let above_fp = fp_col_i64(&wires.above_acc);
    let dom_above = cx.doms.take(1);
    let above_corr = auth_fp_vec_p(cx.stream, cx.tx, dom_above, &above_fp);

    let (dom_m_proj, mult_proj_fp, m_proj_corr) = auth_mult_p(cx, &mult_proj);
    let (dom_m_av, mult_av_fp, m_av_corr) = auth_mult_p(cx, &mult_av);
    let (dom_m_sn, mult_sn_fp, m_sn_corr) = auth_mult_p(cx, &mult_sn);
    let (dom_m_exp, mult_exp_fp, m_exp_corr) = auth_mult_p(cx, &mult_exp);
    let (dom_m_rcp, mult_rcp_fp, m_rcp_corr) = auth_mult_p(cx, &mult_recip);
    let (dom_m_sc, mult_sc_fp, m_sc_corr) = auth_mult_p(cx, &mult_sc);
    let (dom_m_qkv, mult_qkv_fp, m_qkv_corr) = auth_mult_p(cx, &mult_qkv);
    let (dom_m_ln1, mult_ln1_fp, m_ln1_corr) = auth_mult_p(cx, &mult_ln1);
    let (dom_m_rsq1, mult_rsq1_fp, m_rsq1_corr) = auth_mult_p(cx, &mult_rsq1);

    // ---- 1: attn_proj range instance, closed against the residual ----------
    let (rem_ap, out_ap) = range_cols_padded(&wit.proj_acc, &wit.attn_proj_q, t, D, s_ap);
    let inst_proj = blind_instance_prove(
        &[rem_ap, out_ap],
        &[Some(0), None],
        &range_table(s_ap),
        &mult_proj,
        Vec::new(),
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    let pt_ap = inst_proj.point.clone();
    // Residual: attn_block_out = x_in + attn_proj_q ⇒ zero row at pt_ap.
    let abo_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_ap);
    let xin_open = open_matrix_p(cx.stream, dom_xin, &wit.x_in, t, D, &pt_ap);
    cx.zero.push(inst_proj.col_claims[1].value.sub(abo_open).add(xin_open));
    close_mult_p(cx, dom_m_proj, &mult_proj_fp, &inst_proj);

    // ---- 2: transport → out-proj committed chained GEMM (768×768) ----------
    let mut acc_ap_claim = transport_p(&inst_proj, s_ap);
    if let Some(b) = biases {
        acc_ap_claim =
            sub_bias_p(acc_ap_claim, &b.attn_proj, d_cb, &pt_ap, t, s_ap, &mut cx.ctr_other);
    }
    let (r_j_ap, r_i_ap) = pt_ap.split_at(d_cb);
    let cd_proj = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_proj, wire_av, w_proj_corr, wclaim_proj, _tm, _cc) = prove_gemm_committed_chained(
        &wit.av_q,
        &weights.attn_proj,
        t,
        D,
        D,
        r_i_ap,
        r_j_ap,
        acc_ap_claim,
        &cd_proj,
        cx.stream,
        cx.tx,
    );

    // ---- 3: av range instance (drains the out-proj X wire) -----------------
    let (rem_av, out_av) = range_cols_padded(&wit.av_acc, &wit.av_q, t, D, s_av);
    let inst_av = blind_instance_prove(
        &[rem_av, out_av],
        &[Some(0), None],
        &range_table(s_av),
        &mult_av,
        vec![LeafAuxClaim { col: 1, point: wire_av.point.clone(), value: wire_av.value }],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_av, &mult_av_fp, &inst_av);
    let acc_av_claim = transport_p(&inst_av, s_av);
    let pt_av = inst_av.point.clone();

    // ---- 4: av head split ---------------------------------------------------
    // ãcc_av(pt) = Σ_h eq(pt_headbits, h)·ãcc_h(pt_within ‖ pt_rows): the av
    // column index is head·64 + l, so bits 0..5 = within-head (LSB), 6..9 =
    // head; the per-head accumulator MLE lives on (6 within vars ‖ row vars).
    let mut pt_wv: Vec<Fp2> = pt_av[..6].to_vec();
    pt_wv.extend_from_slice(&pt_av[d_cb..]);
    let eqh_av = eq_vec(&pt_av[6..d_cb]);
    cx.ctr_other.fp2_mults += 16 + (64 * t_pad) as u64;
    let mut av_vals = [Fp2::ZERO; H];
    for (h, val) in av_vals.iter_mut().enumerate() {
        let mut slice = vec![Fp2::ZERO; 64 * t_pad];
        for i in 0..t {
            for l in 0..DH {
                slice[i * 64 + l] =
                    Fp2::from_base(Fp::from_i64(wit.av_acc[i * D + h * DH + l]));
            }
        }
        *val = eval_mle_counted(&slice, &pt_wv, &mut cx.ctr_other);
    }
    let dom_split_av = cx.doms.take(1);
    let masks_av = cx.stream.draw_fulls(dom_split_av, H);
    let mut av_split_corrs = [Fp2::ZERO; H];
    let mut av_auth = Vec::with_capacity(H);
    for h in 0..H {
        av_split_corrs[h] = av_vals[h] - masks_av[h].x;
        av_auth.push(ProverAuthed { x: av_vals[h], m: masks_av[h].m });
    }
    cx.tx.append("head_split_corrections", 16 * H as u64);
    let mut row = ProverAuthed::ZERO.sub(acc_av_claim);
    for h in 0..H {
        row = row.add(av_auth[h].scale(eqh_av[h]));
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "av head-split relation violated");
    cx.zero.push(row);

    // ---- 5: per-head w·V act chained GEMMs (m=T, k=T_pad, n=64) ------------
    // Y_h = W_h·V_h; the B leg is the V head slice, pre-folded over its 64
    // within-head columns (fixed head-bit prefix = the column window), the
    // open_b closure finishes the fold over V's ROWS at the sumcheck point.
    let eq_within = eq_vec(&pt_av[..6]);
    let mut gemm_wv = Vec::with_capacity(H);
    let mut aux_sn: Vec<LeafAuxClaim> = Vec::with_capacity(H + 1);
    for h in 0..H {
        let (bvals, btags) =
            fold_cols_window_p(cx.stream, dom_v, &wit.v, t, D, &eq_within, h * DH, DH);
        let mut b_folded = vec![Fp2::ZERO; t_pad];
        b_folded[..t].copy_from_slice(&bvals);
        let open_b = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            let mut v = Fp2::ZERO;
            let mut m = Fp2::ZERO;
            for row in 0..t {
                v += eq_l[row] * bvals[row];
                m += eq_l[row] * btags[row];
            }
            ProverAuthed { x: v, m }
        };
        let x_slice = &wires.w_rect[h * tp2..h * tp2 + t * t_pad];
        let cd = ChainDoms::alloc(&mut cx.doms, t_pad);
        let (gp, wire, _r_l, _tm, _cc) = prove_gemm_act_chained(
            x_slice,
            b_folded,
            t,
            t_pad,
            DH,
            &pt_av[d_cb..],
            &pt_av[..6],
            av_auth[h],
            open_b,
            &cd,
            cx.stream,
            cx.tx,
        );
        // Lift the softmax_w wire claim to the full rect domain: the head
        // bits are appended as fixed boolean coordinates (top vars).
        let mut ptx = wire.point.clone();
        ptx.extend(head_bit_coords(h));
        aux_sn.push(LeafAuxClaim { col: 1, point: ptx, value: wire.value });
        gemm_wv.push((gp, wire.corr));
    }

    // ---- 6: causal mask relation --------------------------------------------
    // Σ_y maskAbove(y)·eq(τ, y)·w_rect(y) = 0 as a blind product sumcheck
    // with the PUBLIC table A = M and claim0 = public 0; the resulting w̃(r)
    // claim is drained by the softmax_norm instance (aux #13).
    let tau: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_tau = eq_vec(&tau);
    cx.ctr_other.fp2_mults += 3 * (1u64 << nr); // eq_tau + fold cost
    let mut m_tab = vec![Fp2::ZERO; 1 << nr];
    for h in 0..H {
        for i in 0..t {
            for j in (i + 1)..t {
                let y = h * tp2 + i * t_pad + j;
                m_tab[y] = eq_tau[y];
            }
        }
    }
    let b_causal = lift_i16_fp2(&wires.w_rect_causal);
    let dom_causal_rounds = cx.doms.take(nr as u64);
    let (causal, r_c, causal_claim_n) = blind_prove(
        m_tab.clone(),
        b_causal,
        ProverAuthed::from_public(Fp2::ZERO),
        cx.stream,
        dom_causal_rounds,
        cx.tx,
    );
    let m_eval = eval_mle_counted(&m_tab, &r_c, &mut cx.ctr_other);
    assert!(m_eval != Fp2::ZERO, "causal mask MLE vanished at r (negligible; redraw)");
    let eq_rc = eq_vec(&r_c);
    cx.ctr_other.fp2_mults += 1 << nr;
    cx.ctr_other.base_mults += wires.w_rect.len() as u64;
    let mut w_eval = Fp2::ZERO;
    for (y, &wv) in wires.w_rect.iter().enumerate() {
        if wv != 0 {
            w_eval += eq_rc[y].mul_base(Fp::from_i64(wv as i64));
        }
    }
    let dom_cw = cx.doms.take(1);
    let fc = cx.stream.draw_fulls(dom_cw, 1)[0];
    let causal_w_corr = w_eval - fc.x;
    cx.tx.append("causal_w_correction", 16);
    let w_auth = ProverAuthed { x: w_eval, m: fc.m };
    // No debug_assert here: this row is exactly where a causal violation
    // must land (cheating-prover emulation in the tests).
    cx.zero.push(w_auth.scale(m_eval).sub(causal_claim_n));
    aux_sn.push(LeafAuxClaim { col: 1, point: r_c.clone(), value: w_auth });

    // ---- 7: softmax_norm range instance (12 wire claims + causal claim) ----
    let rem_sn_col: Vec<Fp> = rem_sn.iter().map(|&r| Fp::new(r as u64)).collect();
    let w_col = fp_col_i16(&wires.w_rect);
    let inst_sn = blind_instance_prove(
        &[rem_sn_col, w_col],
        &[Some(0), None],
        &range_table(s_sn),
        &mult_sn,
        aux_sn,
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_sn, &mult_sn_fp, &inst_sn);
    let wacc_claim = transport_p(&inst_sn, s_sn);
    let pt_sn = inst_sn.point.clone();

    // ---- 8: hadamard w_acc = exp_rect ∘ broadcast(recips) -------------------
    // R is constant in the column (LSB) vars, so R̃ at the full sumcheck
    // point IS the recips row-table claim at the (rows ‖ head) part.
    let e_tab = lift_i16_fp2(&wires.exp_rect);
    let r_tab: Vec<Fp2> = (0..1usize << nr)
        .map(|y| Fp2::from_base(recips_fp[y >> rb]))
        .collect();
    let hd = HadamardDoms::alloc(&mut cx.doms, nr);
    let (had_proof, r_h, e_claim, r_claim) = hadamard_prove(
        &pt_sn, e_tab, r_tab, wacc_claim, &hd, cx.stream, cx.tx, &mut cx.prod, &mut cx.zero,
    );
    let rec_open = open_fp_vec_p(cx.stream, dom_recips, &recips_fp, &r_h[rb..]);
    cx.zero.push(r_claim.sub(rec_open));

    // ---- 9: denominator row sums --------------------------------------------
    // deñoms(ρ) = 2^rb·ẽxp_rect(½..½, ρ): the rect row sums equal the causal
    // ones because every non-causal exp entry is exactly 0 (pad pair).
    let rho: Vec<Fp2> = (0..rb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; rb];
    half_pt.extend_from_slice(&rho);
    let exp_lift = lift_i16_fp2(&wires.exp_rect);
    let rs_val = eval_mle_counted(&exp_lift, &half_pt, &mut cx.ctr_other);
    let dom_rs = cx.doms.take(1);
    let fr = cx.stream.draw_fulls(dom_rs, 1)[0];
    let rowsum_corr = rs_val - fr.x;
    cx.tx.append("rowsum_correction", 16);
    let rs_auth = ProverAuthed { x: rs_val, m: fr.m };
    let den_open = open_fp_vec_p(cx.stream, dom_denoms, &denoms_fp, &rho);
    let two_rb = Fp2::from_base(Fp::new(1u64 << rb));
    cx.zero.push(den_open.sub(rs_auth.scale(two_rb)));

    // ---- 10: exp pair instance ----------------------------------------------
    let sc_col = fp_col_i16(&wires.scores_rect);
    let exp_col = fp_col_i16(&wires.exp_rect);
    let exp_tv = pair_table(&luts.exp, true);
    let inst_exp = blind_instance_prove(
        &[sc_col.clone(), exp_col],
        &[Some(0), Some(16)],
        &exp_tv,
        &mult_exp,
        vec![
            LeafAuxClaim { col: 1, point: r_h.clone(), value: e_claim },
            LeafAuxClaim { col: 1, point: half_pt.clone(), value: rs_auth },
        ],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_exp, &mult_exp_fp, &inst_exp);

    // ---- 11: softmax_recip pair instance -------------------------------------
    let rc_tv = pair_table(&luts.softmax_recip, false);
    let inst_recip = blind_instance_prove(
        &[rin_row_fp.clone(), recips_fp.clone()],
        &[Some(0), Some(16)],
        &rc_tv,
        &mult_recip,
        Vec::new(),
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    let rin_open = open_fp_vec_p(cx.stream, dom_rin_row, &rin_row_fp, &inst_recip.point);
    cx.zero.push(inst_recip.col_claims[0].value.sub(rin_open));
    let rec_open2 = open_fp_vec_p(cx.stream, dom_recips, &recips_fp, &inst_recip.point);
    cx.zero.push(inst_recip.col_claims[1].value.sub(rec_open2));
    close_mult_p(cx, dom_m_rcp, &mult_rcp_fp, &inst_recip);

    // ---- 12: scores range instance + pad-mask correction ---------------------
    let rem_sc_col: Vec<Fp> = rem_sc.iter().map(|&r| Fp::new(r as u64)).collect();
    let inst_sc = blind_instance_prove(
        &[rem_sc_col, sc_col],
        &[Some(0), None],
        &range_table(s_sc),
        &mult_sc,
        vec![LeafAuxClaim {
            col: 1,
            point: inst_exp.point.clone(),
            value: inst_exp.col_claims[0].value,
        }],
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_sc, &mult_sc_fp, &inst_sc);
    let tr_sc = transport_p(&inst_sc, s_sc);
    let pt_sc = inst_sc.point.clone();
    // The out column is the shared scores_q_rect wire, padded with the exp
    // pad input; its implied non-causal accumulator is the CONSTANT
    // c_pad = pad_in·2^s (rem pads at 2^(s−1)). Public correction:
    //   ãcc_true(pt) = transport(pt) − c_pad·padmask̃(pt) + Ã_above(pt),
    // padmask̃ = 1 − Σ_{causal y} eq(pt, y), Ã_above = the authenticated
    // above-diagonal accumulators (true QKᵀ values on real above-diag cells).
    let eq_sc = eq_vec(&pt_sc);
    cx.ctr_other.fp2_mults += 1 << nr;
    let mut caus_sum = Fp2::ZERO;
    for h in 0..H {
        for i in 0..t {
            for j in 0..=i {
                caus_sum += eq_sc[h * tp2 + i * t_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((wires.exp_pad_in() as i64) << s_sc));
    let mut wts = Vec::with_capacity(wires.above_acc.len());
    for h in 0..H {
        for i in 0..t {
            for j in (i + 1)..t {
                wts.push(eq_sc[h * tp2 + i * t_pad + j]);
            }
        }
    }
    let above_open = open_weighted_p(cx.stream, dom_above, &above_fp, &wts);
    let acc_sc_true =
        tr_sc.sub(ProverAuthed::from_public(c_pad * padmask)).add(above_open);

    // ---- 13: scores head split ------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[2 * rb..]);
    let mut sc_vals = [Fp2::ZERO; H];
    for (h, val) in sc_vals.iter_mut().enumerate() {
        let mut slice = vec![Fp2::ZERO; tp2];
        for i in 0..t {
            for j in 0..t {
                slice[i * t_pad + j] =
                    Fp2::from_base(Fp::from_i64(wires.acc_full[h * t * t + i * t + j]));
            }
        }
        *val = eval_mle_counted(&slice, &pt_sc[..2 * rb], &mut cx.ctr_other);
    }
    let dom_split_sc = cx.doms.take(1);
    let masks_sc = cx.stream.draw_fulls(dom_split_sc, H);
    let mut sc_split_corrs = [Fp2::ZERO; H];
    let mut sc_auth = Vec::with_capacity(H);
    for h in 0..H {
        sc_split_corrs[h] = sc_vals[h] - masks_sc[h].x;
        sc_auth.push(ProverAuthed { x: sc_vals[h], m: masks_sc[h].m });
    }
    cx.tx.append("head_split_corrections", 16 * H as u64);
    let mut row = ProverAuthed::ZERO.sub(acc_sc_true);
    for h in 0..H {
        row = row.add(sc_auth[h].scale(eqh_sc[h]));
    }
    debug_assert_eq!(row.x, Fp2::ZERO, "scores head-split relation violated");
    cx.zero.push(row);

    // ---- 14: per-head QKᵀ act chained GEMMs (m=T, k=64, n=T) ----------------
    // Y_h = Q_h·K_hᵀ: the contraction runs over the 64 d_h vars, so the
    // sumcheck point r_l lands in K's COLUMN (within-head) vars while the
    // score-column point r_j weights K's ROWS (positions): the B opening is
    // K̃ at (r_l ‖ head bits ‖ r_j) — K rows pre-folded by eq(r_j), the
    // closure finishes over the 64-column window at r_l.
    let eq_rj_sc = eq_vec(&pt_sc[..rb]);
    let mut gemm_qk = Vec::with_capacity(H);
    let mut aux_qkv: Vec<LeafAuxClaim> = Vec::with_capacity(H + 2);
    for h in 0..H {
        let (kvals, ktags) =
            fold_rows_window_p(cx.stream, dom_k, &wit.k, t, D, &eq_rj_sc, h * DH, DH);
        let b_folded = kvals.clone();
        let open_b = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            let mut v = Fp2::ZERO;
            let mut m = Fp2::ZERO;
            for l in 0..DH {
                v += eq_l[l] * kvals[l];
                m += eq_l[l] * ktags[l];
            }
            ProverAuthed { x: v, m }
        };
        let mut qh = vec![0i16; t * DH];
        for i in 0..t {
            for l in 0..DH {
                qh[i * DH + l] = wit.q[i * D + h * DH + l];
            }
        }
        let cd = ChainDoms::alloc(&mut cx.doms, DH);
        let (gp, wire, _r_l, _tm, _cc) = prove_gemm_act_chained(
            &qh,
            b_folded,
            t,
            DH,
            t,
            &pt_sc[rb..2 * rb],
            &pt_sc[..rb],
            sc_auth[h],
            open_b,
            &cd,
            cx.stream,
            cx.tx,
        );
        // Lift the Q wire claim onto the qkv out column's permuted domain:
        // (r_l ‖ head bits ‖ third=(0,0) ‖ rows).
        let mut ptx = wire.point[..6].to_vec();
        ptx.extend(head_bit_coords(h));
        ptx.push(Fp2::ZERO);
        ptx.push(Fp2::ZERO);
        ptx.extend_from_slice(&wire.point[6..]);
        aux_qkv.push(LeafAuxClaim { col: 1, point: ptx, value: wire.value });
        gemm_qk.push((gp, wire.corr));
    }

    // ---- 15: K/V third-slice aux claims ---------------------------------------
    // The out column's k/v regions are bound to the BOUNDARY tensors by two
    // extra aux claims at fresh points with boolean third selectors; their
    // values ARE the streamed boundary MAC openings (no extra correlations).
    let rho_k: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let k_bound_open = open_matrix_p(cx.stream, dom_k, &wit.k, t, D, &rho_k);
    let mut pt_k = rho_k[..d_cb].to_vec();
    pt_k.push(Fp2::ONE);
    pt_k.push(Fp2::ZERO);
    pt_k.extend_from_slice(&rho_k[d_cb..]);
    aux_qkv.push(LeafAuxClaim { col: 1, point: pt_k, value: k_bound_open });
    let rho_v: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let v_bound_open = open_matrix_p(cx.stream, dom_v, &wit.v, t, D, &rho_v);
    let mut pt_v = rho_v[..d_cb].to_vec();
    pt_v.push(Fp2::ZERO);
    pt_v.push(Fp2::ONE);
    pt_v.extend_from_slice(&rho_v[d_cb..]);
    aux_qkv.push(LeafAuxClaim { col: 1, point: pt_v, value: v_bound_open });

    // ---- 16: qkv range instance → c_attn committed chained GEMM --------------
    let rem_qkv_col: Vec<Fp> = rem_qkv.iter().map(|&r| Fp::new(r as u64)).collect();
    let out_qkv_col = fp_col_i16(&out_qkv);
    let inst_qkv = blind_instance_prove(
        &[rem_qkv_col, out_qkv_col],
        &[Some(0), None],
        &range_table(s_qkv),
        &mult_qkv,
        aux_qkv,
        cx.stream,
        &mut cx.doms,
        cx.tx,
        &mut cx.ctr_instances,
        &mut cx.prod,
        &mut cx.zero,
    );
    close_mult_p(cx, dom_m_qkv, &mult_qkv_fp, &inst_qkv);
    let mut acc_qkv_claim = transport_p(&inst_qkv, s_qkv);
    let pt_qkv = inst_qkv.point.clone();
    if let Some(b) = biases {
        let bias_perm = cattn_bias_permuted(&b.c_attn);
        acc_qkv_claim =
            sub_bias_p(acc_qkv_claim, &bias_perm, 12, &pt_qkv, t, s_qkv, &mut cx.ctr_other);
    }
    let (r_j_qkv, r_i_qkv) = pt_qkv.split_at(12);
    let w_perm = cattn_permuted(&weights.c_attn);
    let cd_cattn = ChainDoms::alloc(&mut cx.doms, D);
    let (gemm_cattn, wire_ln1, w_cattn_corr, wclaim_cattn, _tm2, _cc2) =
        prove_gemm_committed_chained(
            &wit.ln1_out,
            &w_perm,
            t,
            D,
            4096,
            r_i_qkv,
            r_j_qkv,
            acc_qkv_claim,
            &cd_cattn,
            cx.stream,
            cx.tx,
        );

    // ---- 17: LN1 chain ----------------------------------------------------------
    let ln = prove_ln_chain(
        t,
        s_ln,
        acc_ln1,
        &wit.ln1_out,
        &wit.x_in,
        dom_xin,
        &wit.ln1_mean,
        &weights.ln1_gain,
        &weights.ln1_bias,
        &lv1,
        &mult_ln1,
        &mult_ln1_fp,
        dom_m_ln1,
        &mult_rsq1,
        &mult_rsq1_fp,
        dom_m_rsq1,
        &luts.ln_rsqrt,
        &wire_ln1,
        cx,
    );

    let proof = AttnBlockProof {
        ln_vec_corrs,
        denoms_corr,
        recip_in_corr,
        recips_corr,
        above_corr,
        mult_corr: [
            m_proj_corr, m_av_corr, m_sn_corr, m_exp_corr, m_rcp_corr, m_sc_corr, m_qkv_corr,
            m_ln1_corr, m_rsq1_corr,
        ],
        inst_proj: inst_proj.proof,
        gemm_proj,
        av_wire_corr: wire_av.corr,
        w_proj_corr,
        inst_av: inst_av.proof,
        av_split_corrs,
        gemm_wv,
        causal,
        causal_w_corr,
        inst_sn: inst_sn.proof,
        hadamard: had_proof,
        rowsum_corr,
        inst_exp: inst_exp.proof,
        inst_recip: inst_recip.proof,
        inst_sc: inst_sc.proof,
        sc_split_corrs,
        gemm_qk,
        inst_qkv: inst_qkv.proof,
        gemm_cattn,
        ln1_wire_corr: wire_ln1.corr,
        w_cattn_corr,
        ln,
    };
    (proof, vec![wclaim_proj, wclaim_cattn])
}

// ---------------------------------------------------------------------------
// Attention block — verifier
// ---------------------------------------------------------------------------

/// Verify the attention half against the cached boundary keys. Returns the
/// `[attn_proj, c_attn]` weight-claim (point, key) pairs on success.
#[allow(clippy::too_many_arguments)]
pub fn verify_attn_block(
    t: usize,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    luts: &Luts,
    proof: &AttnBlockProof,
    cx: &mut BlockCtxV,
    xin_keys: &[Fp2],
    k_keys: &[Fp2],
    v_keys: &[Fp2],
    abo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let tp2 = t_pad * t_pad;
    let nr = 2 * rb + HEAD_BITS;
    let d_cb = pad_bits(D);
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;
    let n_above = H * t * (t - 1) / 2;

    // Length checks before consuming any correlations.
    for v in &proof.ln_vec_corrs {
        if v.len() != t_pad {
            return None;
        }
    }
    for v in [&proof.denoms_corr, &proof.recip_in_corr, &proof.recips_corr] {
        if v.len() != H_PAD * t_pad {
            return None;
        }
    }
    if proof.above_corr.len() != n_above
        || proof.gemm_wv.len() != H
        || proof.gemm_qk.len() != H
    {
        return None;
    }
    let mult_lens = [
        1usize << s_ap,
        1usize << s_av,
        1usize << s_sn,
        1 << 16,
        1 << 16,
        1usize << s_sc,
        1usize << s_qkv,
        1usize << s_ln,
        1 << 16,
    ];
    for (mc, &ml) in proof.mult_corr.iter().zip(&mult_lens) {
        if mc.len() != ml {
            return None;
        }
    }

    // ---- phase 0: expand + cache all element-wise keys ---------------------
    let lvk1 = expand_ln_vecs_k(cx, &proof.ln_vec_corrs);
    let dom_denoms = cx.doms.take(1);
    let denoms_keys = keys_fp_vec_v(cx.ctx, dom_denoms, &proof.denoms_corr);
    let dom_rin_row = cx.doms.take(1);
    let rin_row_keys = keys_fp_vec_v(cx.ctx, dom_rin_row, &proof.recip_in_corr);
    let dom_recips = cx.doms.take(1);
    let recips_keys = keys_fp_vec_v(cx.ctx, dom_recips, &proof.recips_corr);
    let dom_above = cx.doms.take(1);
    let above_keys = keys_fp_vec_v(cx.ctx, dom_above, &proof.above_corr);
    let mult_keys: Vec<Vec<Fp2>> =
        proof.mult_corr.iter().map(|mc| keys_mult_v(cx, mc)).collect();

    // ---- 1+2: attn_proj instance + residual + GEMM -------------------------
    let n_d = d_cb + rb;
    let shifts_range = [Some(0u32), None];
    let shifts_pair = [Some(0u32), Some(16u32)];
    let vp = blind_instance_verify(
        n_d,
        &shifts_range,
        &range_table(s_ap),
        &proof.inst_proj,
        &[],
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let pt_ap = vp.point.clone();
    let abo_k = open_matrix_k(abo_keys, t, D, &pt_ap);
    let xin_k = open_matrix_k(xin_keys, t, D, &pt_ap);
    cx.kzero.push(vp.col_keys[1].key.sub(abo_k).add(xin_k));
    close_mult_v(cx, &mult_keys[0], &vp.mult_key);
    let mut k_acc_ap = transport_k(&vp, s_ap, cx.ctx.delta);
    if let Some(b) = biases {
        k_acc_ap = sub_bias_k(k_acc_ap, &b.attn_proj, d_cb, &pt_ap, t, s_ap, cx.ctx.delta);
    }
    let (r_j_ap, r_i_ap) = pt_ap.split_at(d_cb);
    let cd_proj = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_av, w_pt_proj, k_w_proj) = verify_gemm_committed_chained(
        t,
        D,
        D,
        r_i_ap,
        r_j_ap,
        k_acc_ap,
        &proof.gemm_proj,
        proof.av_wire_corr,
        proof.w_proj_corr,
        &cd_proj,
        cx.ctx,
        cx.tx,
    )?;

    // ---- 3: av instance ------------------------------------------------------
    let aux_av = [(1usize, wk_av.point.clone(), wk_av.key)];
    let va = blind_instance_verify(
        n_d,
        &shifts_range,
        &range_table(s_av),
        &proof.inst_av,
        &aux_av,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[1], &va.mult_key);
    let k_acc_av = transport_k(&va, s_av, cx.ctx.delta);
    let pt_av = va.point.clone();

    // ---- 4: av head split ------------------------------------------------------
    let eqh_av = eq_vec(&pt_av[6..d_cb]);
    let dom_split_av = cx.doms.take(1);
    let ks_av = cx.ctx.expand_full_keys(dom_split_av, H);
    let av_keys: Vec<VerifierKey> = (0..H)
        .map(|h| VerifierKey { k: ks_av[h] + cx.ctx.delta * proof.av_split_corrs[h] })
        .collect();
    let mut krow = VerifierKey::ZERO.sub(k_acc_av);
    for h in 0..H {
        krow = krow.add(av_keys[h].scale(eqh_av[h]));
    }
    cx.kzero.push(krow);

    // ---- 5: per-head w·V GEMMs --------------------------------------------------
    let eq_within = eq_vec(&pt_av[..6]);
    let mut aux_sn: Vec<(usize, Vec<Fp2>, VerifierKey)> = Vec::with_capacity(H + 1);
    for h in 0..H {
        let vkeys_row = fold_cols_window_k(v_keys, t, D, &eq_within, h * DH, DH);
        let open_b_key = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            VerifierKey {
                k: (0..t).fold(Fp2::ZERO, |s, row| s + eq_l[row] * vkeys_row[row]),
            }
        };
        let cd = ChainDoms::alloc(&mut cx.doms, t_pad);
        let (wk, _r_l) = verify_gemm_act_chained(
            t,
            t_pad,
            DH,
            &pt_av[d_cb..],
            &pt_av[..6],
            av_keys[h],
            &proof.gemm_wv[h].0,
            proof.gemm_wv[h].1,
            open_b_key,
            &cd,
            cx.ctx,
            cx.tx,
        )?;
        let mut ptx = wk.point.clone();
        ptx.extend(head_bit_coords(h));
        aux_sn.push((1, ptx, wk.key));
    }

    // ---- 6: causal mask relation --------------------------------------------
    let tau: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_tau = eq_vec(&tau);
    let mut m_tab = vec![Fp2::ZERO; 1 << nr];
    for h in 0..H {
        for i in 0..t {
            for j in (i + 1)..t {
                let y = h * tp2 + i * t_pad + j;
                m_tab[y] = eq_tau[y];
            }
        }
    }
    let dom_causal_rounds = cx.doms.take(nr as u64);
    let (r_c, k_causal_n) = blind_verify(
        nr,
        VerifierKey::from_public(Fp2::ZERO, cx.ctx.delta),
        &proof.causal,
        cx.ctx,
        dom_causal_rounds,
        cx.tx,
    )?;
    let m_eval = eval_mle(&m_tab, &r_c);
    if m_eval == Fp2::ZERO {
        return None; // negligible-probability event; redraw/panic acceptable
    }
    let dom_cw = cx.doms.take(1);
    let k_w_causal =
        VerifierKey { k: cx.ctx.expand_full_keys(dom_cw, 1)[0] + cx.ctx.delta * proof.causal_w_corr };
    cx.kzero.push(k_w_causal.scale(m_eval).sub(k_causal_n));
    aux_sn.push((1, r_c.clone(), k_w_causal));

    // ---- 7: softmax_norm instance ----------------------------------------------
    let vsn = blind_instance_verify(
        nr,
        &shifts_range,
        &range_table(s_sn),
        &proof.inst_sn,
        &aux_sn,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[2], &vsn.mult_key);
    let k_wacc = transport_k(&vsn, s_sn, cx.ctx.delta);
    let pt_sn = vsn.point.clone();

    // ---- 8: hadamard ---------------------------------------------------------
    let hd = HadamardDoms::alloc(&mut cx.doms, nr);
    let (r_h, k_e, k_r) = hadamard_verify(
        &pt_sn,
        k_wacc,
        &proof.hadamard,
        &hd,
        cx.ctx,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let rec_k = open_fp_vec_k(&recips_keys, &r_h[rb..]);
    cx.kzero.push(k_r.sub(rec_k));

    // ---- 9: denominator row sums ----------------------------------------------
    let rho: Vec<Fp2> = (0..rb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; rb];
    half_pt.extend_from_slice(&rho);
    let dom_rs = cx.doms.take(1);
    let k_rs =
        VerifierKey { k: cx.ctx.expand_full_keys(dom_rs, 1)[0] + cx.ctx.delta * proof.rowsum_corr };
    let den_k = open_fp_vec_k(&denoms_keys, &rho);
    let two_rb = Fp2::from_base(Fp::new(1u64 << rb));
    cx.kzero.push(den_k.sub(k_rs.scale(two_rb)));

    // ---- 10: exp instance --------------------------------------------------------
    let exp_tv = pair_table(&luts.exp, true);
    let aux_exp = [(1usize, r_h.clone(), k_e), (1usize, half_pt.clone(), k_rs)];
    let vexp = blind_instance_verify(
        nr,
        &shifts_pair,
        &exp_tv,
        &proof.inst_exp,
        &aux_exp,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[3], &vexp.mult_key);

    // ---- 11: softmax_recip instance -----------------------------------------------
    let rc_tv = pair_table(&luts.softmax_recip, false);
    let vrc = blind_instance_verify(
        rb + HEAD_BITS,
        &shifts_pair,
        &rc_tv,
        &proof.inst_recip,
        &[],
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    let rin_k = open_fp_vec_k(&rin_row_keys, &vrc.point);
    cx.kzero.push(vrc.col_keys[0].key.sub(rin_k));
    let rec_k2 = open_fp_vec_k(&recips_keys, &vrc.point);
    cx.kzero.push(vrc.col_keys[1].key.sub(rec_k2));
    close_mult_v(cx, &mult_keys[4], &vrc.mult_key);

    // ---- 12: scores instance + pad-mask correction -----------------------------
    let aux_sc = [(1usize, vexp.point.clone(), vexp.col_keys[0].key)];
    let vsc = blind_instance_verify(
        nr,
        &shifts_range,
        &range_table(s_sc),
        &proof.inst_sc,
        &aux_sc,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[5], &vsc.mult_key);
    let k_tr_sc = transport_k(&vsc, s_sc, cx.ctx.delta);
    let pt_sc = vsc.point.clone();
    let exp_pad_u = (0..1usize << 16).find(|&u| luts.exp[u] == 0)?;
    let pad_in = (exp_pad_u as u16) as i16;
    let eq_sc = eq_vec(&pt_sc);
    let mut caus_sum = Fp2::ZERO;
    for h in 0..H {
        for i in 0..t {
            for j in 0..=i {
                caus_sum += eq_sc[h * tp2 + i * t_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((pad_in as i64) << s_sc));
    let mut wts = Vec::with_capacity(n_above);
    for h in 0..H {
        for i in 0..t {
            for j in (i + 1)..t {
                wts.push(eq_sc[h * tp2 + i * t_pad + j]);
            }
        }
    }
    let above_k = open_weighted_k(&above_keys, &wts);
    let k_acc_sc_true = k_tr_sc
        .sub(VerifierKey::from_public(c_pad * padmask, cx.ctx.delta))
        .add(above_k);

    // ---- 13: scores head split ---------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[2 * rb..]);
    let dom_split_sc = cx.doms.take(1);
    let ks_sc = cx.ctx.expand_full_keys(dom_split_sc, H);
    let sc_keys: Vec<VerifierKey> = (0..H)
        .map(|h| VerifierKey { k: ks_sc[h] + cx.ctx.delta * proof.sc_split_corrs[h] })
        .collect();
    let mut krow = VerifierKey::ZERO.sub(k_acc_sc_true);
    for h in 0..H {
        krow = krow.add(sc_keys[h].scale(eqh_sc[h]));
    }
    cx.kzero.push(krow);

    // ---- 14: per-head QKᵀ GEMMs ---------------------------------------------------
    let eq_rj_sc = eq_vec(&pt_sc[..rb]);
    let mut aux_qkv: Vec<(usize, Vec<Fp2>, VerifierKey)> = Vec::with_capacity(H + 2);
    for h in 0..H {
        let kkeys_col = fold_rows_window_k(k_keys, t, D, &eq_rj_sc, h * DH, DH);
        let open_b_key = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            VerifierKey {
                k: (0..DH).fold(Fp2::ZERO, |s, l| s + eq_l[l] * kkeys_col[l]),
            }
        };
        let cd = ChainDoms::alloc(&mut cx.doms, DH);
        let (wk, _r_l) = verify_gemm_act_chained(
            t,
            DH,
            t,
            &pt_sc[rb..2 * rb],
            &pt_sc[..rb],
            sc_keys[h],
            &proof.gemm_qk[h].0,
            proof.gemm_qk[h].1,
            open_b_key,
            &cd,
            cx.ctx,
            cx.tx,
        )?;
        let mut ptx = wk.point[..6].to_vec();
        ptx.extend(head_bit_coords(h));
        ptx.push(Fp2::ZERO);
        ptx.push(Fp2::ZERO);
        ptx.extend_from_slice(&wk.point[6..]);
        aux_qkv.push((1, ptx, wk.key));
    }

    // ---- 15: K/V third-slice aux claims -------------------------------------------
    let rho_k: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let k_bound_k = open_matrix_k(k_keys, t, D, &rho_k);
    let mut pt_k = rho_k[..d_cb].to_vec();
    pt_k.push(Fp2::ONE);
    pt_k.push(Fp2::ZERO);
    pt_k.extend_from_slice(&rho_k[d_cb..]);
    aux_qkv.push((1, pt_k, k_bound_k));
    let rho_v: Vec<Fp2> = (0..d_cb + rb).map(|_| cx.tx.challenge_fp2()).collect();
    let v_bound_k = open_matrix_k(v_keys, t, D, &rho_v);
    let mut pt_v = rho_v[..d_cb].to_vec();
    pt_v.push(Fp2::ZERO);
    pt_v.push(Fp2::ONE);
    pt_v.extend_from_slice(&rho_v[d_cb..]);
    aux_qkv.push((1, pt_v, v_bound_k));

    // ---- 16: qkv instance → c_attn GEMM ---------------------------------------------
    let vqkv = blind_instance_verify(
        12 + rb,
        &shifts_range,
        &range_table(s_qkv),
        &proof.inst_qkv,
        &aux_qkv,
        cx.ctx,
        &mut cx.doms,
        cx.tx,
        &mut cx.kprod,
        &mut cx.kzero,
    )?;
    close_mult_v(cx, &mult_keys[6], &vqkv.mult_key);
    let mut k_acc_qkv = transport_k(&vqkv, s_qkv, cx.ctx.delta);
    let pt_qkv = vqkv.point.clone();
    if let Some(b) = biases {
        let bias_perm = cattn_bias_permuted(&b.c_attn);
        k_acc_qkv = sub_bias_k(k_acc_qkv, &bias_perm, 12, &pt_qkv, t, s_qkv, cx.ctx.delta);
    }
    let (r_j_qkv, r_i_qkv) = pt_qkv.split_at(12);
    let cd_cattn = ChainDoms::alloc(&mut cx.doms, D);
    let (wk_ln1, w_pt_cattn, k_w_cattn) = verify_gemm_committed_chained(
        t,
        D,
        4096,
        r_i_qkv,
        r_j_qkv,
        k_acc_qkv,
        &proof.gemm_cattn,
        proof.ln1_wire_corr,
        proof.w_cattn_corr,
        &cd_cattn,
        cx.ctx,
        cx.tx,
    )?;

    // ---- 17: LN1 chain -----------------------------------------------------------
    verify_ln_chain(
        t,
        s_ln,
        ln1_gain,
        ln1_bias,
        &luts.ln_rsqrt,
        xin_keys,
        &lvk1,
        &mult_keys[7],
        &mult_keys[8],
        &proof.ln,
        &wk_ln1,
        cx,
    )?;

    Some(vec![(w_pt_proj, k_w_proj), (w_pt_cattn, k_w_cattn)])
}

// ---------------------------------------------------------------------------
// Layer orchestration
// ---------------------------------------------------------------------------

pub struct LayerProof {
    // Boundary auth corrections (8 B each), hoisted here — owned once.
    pub xin_corr: Vec<u64>,
    pub k_corr: Vec<u64>,
    pub v_corr: Vec<u64>,
    pub abo_corr: Vec<u64>,
    pub fbo_corr: Vec<u64>,
    pub ffn: FfnBlockProof,
    pub attn: AttnBlockProof,
}

/// Correlation bytes consumed by the layer, by category.
#[derive(Clone, Copy, Debug, Default)]
pub struct LayerBytes {
    /// Element-wise boundary auth (x_in, K, V, attn/ffn_block_out), 8 B/val.
    pub boundary: u64,
    /// Element-wise multiplicity-vector auth (14 instances), 8 B/value.
    pub mult: u64,
    /// LN small vectors (mean/var/rsqrt_in/rsqrt_out ×2 LNs), 8 B/value.
    pub ln_vectors: u64,
    /// Attention vectors: denoms/recip_in/recips row tables + above-diag accs.
    pub attn_vectors: u64,
    /// Full-field correlations (round masks, wire/weight/split claims), 16 B.
    pub rounds_claims: u64,
}

/// Measured lookup count of one LogUp instance (= its padded lookup-side
/// leaf count: witness stream length + rectangular/pow2 pads).
#[derive(Clone, Copy, Debug)]
pub struct InstanceLookups {
    pub name: &'static str,
    pub table: &'static str,
    pub lookups: u64,
}

pub struct LayerOut {
    /// Exactly the 4 committed-weight claims, canonical order
    /// [c_attn, attn_proj, ffn_up, ffn_down]. c_attn is on the PERMUTED
    /// 1024×4096 layout (`cattn_permuted`).
    pub weight_claims: Vec<WeightClaimP>,
    pub bytes: LayerBytes,
    /// LogUp-instance E-mults (separable — p4_report's per-lookup number).
    pub ctr_instances: Counters,
    /// Chain-level E-mults outside the instances (public evals etc.).
    pub ctr_other: Counters,
    /// Per-instance measured lookups (p4_report budget gate input).
    pub lookups: Vec<InstanceLookups>,
}

pub struct LayerOutV {
    /// (point, key) of the 4 weight claims, canonical order (as LayerOut).
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
}

/// Per-instance measured lookups for the layer (domain sizes).
fn layer_lookups(t: usize) -> Vec<InstanceLookups> {
    let rb = pad_bits(t);
    let tp = 1u64 << rb;
    let rect = tp * tp * H_PAD as u64;
    vec![
        InstanceLookups { name: "attn_proj", table: "requant_attn_proj", lookups: tp << 10 },
        InstanceLookups { name: "av", table: "requant_av", lookups: tp << 10 },
        InstanceLookups { name: "softmax_norm", table: "softmax_norm_requant", lookups: rect },
        InstanceLookups { name: "exp", table: "exp", lookups: rect },
        InstanceLookups { name: "softmax_recip", table: "softmax_recip", lookups: tp * H_PAD as u64 },
        InstanceLookups { name: "scores", table: "requant_scores", lookups: rect },
        InstanceLookups { name: "qkv", table: "requant_qkv", lookups: tp << 12 },
        InstanceLookups { name: "ln1_norm", table: "ln_norm_requant", lookups: tp << 10 },
        InstanceLookups { name: "ln1_rsqrt", table: "ln_rsqrt", lookups: tp },
        InstanceLookups { name: "ffn_down", table: "requant_ffn_down", lookups: tp << 10 },
        InstanceLookups { name: "gelu", table: "gelu", lookups: tp << 12 },
        InstanceLookups { name: "ffn_up", table: "requant_ffn_up", lookups: tp << 12 },
        InstanceLookups { name: "ln2_norm", table: "ln_norm_requant", lookups: tp << 10 },
        InstanceLookups { name: "ln2_rsqrt", table: "ln_rsqrt", lookups: tp },
    ]
}

/// Prove one full layer: boundary auth once, FFN chain, attention chain.
/// The caller closes the accumulated Π_Prod / Π_ZeroBatch (exactly one of
/// each per layer) and resolves the 4 weight claims against the PCS.
pub fn prove_layer(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    let wires = build_attn_wires(wit, luts);
    prove_layer_with_wires(wit, weights, luts, &wires, cx, biases)
}

/// [`prove_layer`] with caller-supplied attention wires (the causal-tamper
/// test mutates a copy — cheating-prover emulation).
pub fn prove_layer_with_wires(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: &AttnWires,
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    let t = wit.t;
    let rb = pad_bits(t);
    let t_pad = 1u64 << rb;
    let p = luts.params;
    let fulls0 = cx.stream.counters.full_corrs;

    // ---- boundary auth, once per layer -------------------------------------
    let dom_xin = cx.doms.take(t as u64);
    let xin_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_xin, &wit.x_in, t, D);
    let dom_k = cx.doms.take(t as u64);
    let k_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_k, &wit.k, t, D);
    let dom_v = cx.doms.take(t as u64);
    let v_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_v, &wit.v, t, D);
    let dom_abo = cx.doms.take(t as u64);
    let abo_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_abo, &wit.attn_block_out, t, D);
    let dom_fbo = cx.doms.take(t as u64);
    let fbo_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_fbo, &wit.ffn_block_out, t, D);

    // ---- reverse dataflow: FFN chain, then attention chain ------------------
    let (ffn, w_ffn) = prove_ffn_block(wit, weights, luts, cx, dom_abo, dom_fbo, biases);
    let (attn, w_attn) = prove_attn_block(
        wit, weights, luts, wires, cx, dom_xin, dom_k, dom_v, dom_abo, biases,
    );

    // Canonical weight-claim order: [c_attn, attn_proj, ffn_up, ffn_down].
    let mut w_attn = w_attn;
    let mut w_ffn = w_ffn;
    let wclaim_cattn = w_attn.pop().expect("attn returns 2 claims");
    let wclaim_proj = w_attn.pop().expect("attn returns 2 claims");
    let wclaim_up = w_ffn.pop().expect("ffn returns 2 claims");
    let wclaim_down = w_ffn.pop().expect("ffn returns 2 claims");
    let weight_claims = vec![wclaim_cattn, wclaim_proj, wclaim_up, wclaim_down];
    assert_eq!(weight_claims.len(), 4, "exactly one claim per committed weight tensor");

    // ---- byte accounting ------------------------------------------------------
    let mult_len: u64 = (1u64 << p.shift_ffn_down)
        + (1 << 16) // gelu
        + (1u64 << p.shift_ffn_up)
        + (1u64 << p.shift_ln_norm) // ln2
        + (1 << 16) // ln2 rsqrt
        + (1u64 << p.shift_attn_proj)
        + (1u64 << p.shift_av)
        + (1u64 << p.shift_softmax_norm)
        + (1 << 16) // exp
        + (1 << 16) // softmax_recip
        + (1u64 << p.shift_scores)
        + (1u64 << p.shift_qkv)
        + (1u64 << p.shift_ln_norm) // ln1
        + (1 << 16); // ln1 rsqrt
    let n_above = (H * t * (t - 1) / 2) as u64;
    let bytes = LayerBytes {
        boundary: 8 * 5 * (t * D) as u64,
        mult: 8 * mult_len,
        ln_vectors: 8 * 8 * t_pad,
        attn_vectors: 8 * (3 * H_PAD as u64 * t_pad + n_above),
        rounds_claims: 16 * (cx.stream.counters.full_corrs - fulls0),
    };

    let proof = LayerProof { xin_corr, k_corr, v_corr, abo_corr, fbo_corr, ffn, attn };
    let out = LayerOut {
        weight_claims,
        bytes,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
        lookups: layer_lookups(t),
    };
    (proof, out)
}

/// Verify one full layer. `ln*_gain`/`ln*_bias` are the public LN parameters.
/// On success returns the 4 weight-claim keys (canonical order); the caller
/// must close the accumulated batches and bind the claims to the PCS.
#[allow(clippy::too_many_arguments)]
pub fn verify_layer(
    t: usize,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &LayerProof,
    cx: &mut BlockCtxV,
    biases: Option<&GemmBiases>,
) -> Option<LayerOutV> {
    for c in [&proof.xin_corr, &proof.k_corr, &proof.v_corr, &proof.abo_corr, &proof.fbo_corr] {
        if c.len() != t * D {
            return None;
        }
    }
    let dom_xin = cx.doms.take(t as u64);
    let xin_keys = auth_matrix_rows_v(cx.ctx, dom_xin, &proof.xin_corr, t, D);
    let dom_k = cx.doms.take(t as u64);
    let k_keys = auth_matrix_rows_v(cx.ctx, dom_k, &proof.k_corr, t, D);
    let dom_v = cx.doms.take(t as u64);
    let v_keys = auth_matrix_rows_v(cx.ctx, dom_v, &proof.v_corr, t, D);
    let dom_abo = cx.doms.take(t as u64);
    let abo_keys = auth_matrix_rows_v(cx.ctx, dom_abo, &proof.abo_corr, t, D);
    let dom_fbo = cx.doms.take(t as u64);
    let fbo_keys = auth_matrix_rows_v(cx.ctx, dom_fbo, &proof.fbo_corr, t, D);

    let mut w_ffn = verify_ffn_block(
        t, ln2_gain, ln2_bias, luts, &proof.ffn, cx, &abo_keys, &fbo_keys, biases,
    )?;
    let mut w_attn = verify_attn_block(
        t, ln1_gain, ln1_bias, luts, &proof.attn, cx, &xin_keys, &k_keys, &v_keys, &abo_keys,
        biases,
    )?;

    let wk_cattn = w_attn.pop()?;
    let wk_proj = w_attn.pop()?;
    let wk_up = w_ffn.pop()?;
    let wk_down = w_ffn.pop()?;
    Some(LayerOutV { weight_keys: vec![wk_cattn, wk_proj, wk_up, wk_down] })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::thaler::fold_w;
    use rand::{Rng, SeedableRng};
    use std::sync::OnceLock;
    use volta_gpt2::{build_luts, forward_layer, synthetic_input, synthetic_weights, LutParams};
    use volta_mac::zero_batch_exchange;

    const T: usize = 4;

    /// One real forward pass at T = 4 (≈19 M MACs), shared by all tests.
    fn fixture() -> &'static (Luts, LayerWeights, LayerWitness) {
        static FIX: OnceLock<(Luts, LayerWeights, LayerWitness)> = OnceLock::new();
        FIX.get_or_init(|| {
            let luts = build_luts(LutParams::default());
            let w = synthetic_weights(42);
            let x = synthetic_input(43, T);
            let wit = forward_layer(&x, &w, &luts, T);
            (luts, w, wit)
        })
    }

    /// True W̃ evaluation for a k×n weight tensor at a claim point
    /// (cols LSB: r_j ‖ r_l) — the test-only stand-in for the PCS opening.
    fn weight_true_eval(w: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
        let cb = pad_bits(n);
        let b = fold_w(w, k, n, &eq_vec(&point[..cb]));
        eval_mle(&b, &point[cb..])
    }

    /// Full layer round trip: prove (optionally on tampered witness/wires),
    /// (optionally tamper the proof), verify, resolve the 4 weight claims
    /// against the true tensors, then close one Π_Prod batch and one
    /// Π_ZeroBatch over ALL accumulated rows. Witness/wires tampers run the
    /// honest prover on bad data: nonzero zero-row values are cleared before
    /// the batch (cheating-prover emulation — the MAC keys keep the truth).
    fn run_layer_case(
        seed: u8,
        tamper_wit: impl FnOnce(&mut LayerWitness, &LayerWeights, &Luts),
        tamper_wires: impl FnOnce(&mut AttnWires),
        tamper_proof: impl FnOnce(&mut LayerProof),
    ) -> bool {
        let (luts, w, wit0) = fixture();
        let mut wit = wit0.clone();
        tamper_wit(&mut wit, w, luts);

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let mut cxp = BlockCtxP::new(&mut stream, &mut txp, 0);
        let mut wires = build_attn_wires(&wit, luts);
        tamper_wires(&mut wires);
        let (mut proof, out) = prove_layer_with_wires(&wit, w, luts, &wires, &mut cxp, None);
        let BlockCtxP { doms: mut domsp, prod, mut zero, .. } = cxp;
        tamper_proof(&mut proof);

        let mut cxv = BlockCtxV::new(&mut vc, &mut txv, 0);
        let Some(outv) = verify_layer(
            T, &w.ln1_gain, &w.ln1_bias, &w.ln2_gain, &w.ln2_bias, luts, &proof, &mut cxv, None,
        ) else {
            return false;
        };
        let BlockCtxV { doms: mut domsv, kprod, mut kzero, .. } = cxv;

        // Weight claims: exactly 4 (c_attn, attn_proj, ffn_up, ffn_down),
        // resolved here against the true W̃ evaluations (PCS = step 7/8).
        assert_eq!(out.weight_claims.len(), 4, "expected exactly 4 weight claims");
        assert_eq!(outv.weight_keys.len(), 4);
        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] = [
            (D, 4096, &w_perm),
            (D, D, &w.attn_proj),
            (D, DFF, &w.ffn_up),
            (DFF, D, &w.ffn_down),
        ];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(wc.point.len(), pad_bits(k) + pad_bits(n));
            assert_eq!(outv.weight_keys[i].0, wc.point, "weight point mismatch across parties");
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        // Cheating-prover emulation for witness/wires tampers (no-op honest).
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
        }

        // Final closures: exactly ONE χ-batched Π_Prod + ONE Π_ZeroBatch.
        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        ok_prod && ok_zero
    }

    #[test]
    fn attn_block_e2e() {
        assert!(
            run_layer_case(21, |_, _, _| {}, |_| {}, |_| {}),
            "honest full layer rejected"
        );
    }

    /// Nonzero softmax weight above the diagonal in the prover's causal-B
    /// copy (cheating-prover emulation at the wires level: everything else
    /// stays honest, so the reject is pinned to the causal sumcheck row).
    #[test]
    fn layer_rejects_causal_violation() {
        assert!(
            !run_layer_case(
                22,
                |_, _, _| {},
                |wires| {
                    // head 0, row 0, col 1 — real above-diagonal position.
                    assert_eq!(wires.w_rect_causal[1], 0, "honest above-diag must be 0");
                    wires.w_rect_causal[1] = 7;
                },
                |_| {}
            ),
            "causal violation accepted"
        );
    }

    /// Forged boundary: a K correction tampered on the wire — every K
    /// opening (QKᵀ B legs, the qkv third-slice claim) shifts.
    #[test]
    fn layer_rejects_forged_boundary() {
        assert!(
            !run_layer_case(23, |_, _, _| {}, |_| {}, |p| {
                p.k_corr[57] = p.k_corr[57].wrapping_add(1);
            }),
            "forged K boundary accepted"
        );
    }

    /// Tampered c_attn weight-claim correction: rejected when the claim is
    /// resolved against the true W̃ evaluation in the closing batch.
    #[test]
    fn layer_rejects_tampered_weight_claim() {
        assert!(
            !run_layer_case(24, |_, _, _| {}, |_| {}, |p| {
                p.attn.w_cattn_corr += Fp2::ONE;
            }),
            "tampered c_attn weight claim accepted"
        );
    }

    /// Flipped gelu output (out-of-table pair) with the FFN chain downstream
    /// recomputed — the FFN half's tamper coverage now runs layer-level.
    #[test]
    fn layer_rejects_flipped_gelu() {
        assert!(
            !run_layer_case(
                25,
                |wit, w, luts| {
                    wit.gelu_out[123] = wit.gelu_out[123].wrapping_add(7);
                    wit.ffn_down_acc =
                        volta_gpt2::gemm_i64(&wit.gelu_out, &w.ffn_down, wit.t, DFF, D);
                    let s = luts.params.shift_ffn_down;
                    for i in 0..wit.ffn_down_acc.len() {
                        wit.ffn_down_q[i] = volta_gpt2::gemm::requant(wit.ffn_down_acc[i], s);
                    }
                },
                |_| {},
                |_| {}
            ),
            "flipped gelu output accepted"
        );
    }

    /// Forged residual: ffn_block_out entry +1 (boundary auth + residual row).
    #[test]
    fn layer_rejects_forged_residual() {
        assert!(
            !run_layer_case(
                26,
                |wit, _, _| {
                    wit.ffn_block_out[57] = wit.ffn_block_out[57].wrapping_add(1);
                },
                |_| {},
                |_| {}
            ),
            "forged residual accepted"
        );
    }

    /// Tampered FFN wire-claim correction (GEMM-down X-wire WireOut corr).
    #[test]
    fn layer_rejects_tampered_wire_corr() {
        assert!(
            !run_layer_case(27, |_, _, _| {}, |_| {}, |p| {
                p.ffn.gelu_wire_corr += Fp2::ONE;
            }),
            "tampered wire-claim correction accepted"
        );
    }

    #[test]
    fn layer_counts() {
        let (luts, w, wit) = fixture();
        let mut stream = CorrelationStream::new([77; 32]);
        let mut txp = Transcript::new([78; 32]);
        let mut cxp = BlockCtxP::new(&mut stream, &mut txp, 0);
        let (_proof, out) = prove_layer(wit, w, luts, &mut cxp, None);

        // Exactly 4 weight claims with the right point shapes.
        assert_eq!(out.weight_claims.len(), 4);
        assert_eq!(out.weight_claims[0].point.len(), 12 + 10); // c_attn (permuted 1024×4096)
        assert_eq!(out.weight_claims[1].point.len(), 10 + 10); // attn_proj
        assert_eq!(out.weight_claims[2].point.len(), pad_bits(DFF) + pad_bits(D)); // ffn_up
        assert_eq!(out.weight_claims[3].point.len(), pad_bits(D) + pad_bits(DFF)); // ffn_down

        // Corr-byte categories.
        let p = luts.params;
        let t_pad = T.next_power_of_two() as u64;
        assert_eq!(out.bytes.boundary, 8 * 5 * (T * D) as u64);
        assert_eq!(out.bytes.ln_vectors, 8 * 8 * t_pad);
        let n_above = (H * T * (T - 1) / 2) as u64;
        assert_eq!(out.bytes.attn_vectors, 8 * (3 * 16 * t_pad + n_above));
        let mult_len: u64 = (1u64 << p.shift_ffn_down)
            + (1 << 16)
            + (1u64 << p.shift_ffn_up)
            + (1u64 << p.shift_ln_norm)
            + (1 << 16)
            + (1u64 << p.shift_attn_proj)
            + (1u64 << p.shift_av)
            + (1u64 << p.shift_softmax_norm)
            + (1 << 16)
            + (1 << 16)
            + (1u64 << p.shift_scores)
            + (1u64 << p.shift_qkv)
            + (1u64 << p.shift_ln_norm)
            + (1 << 16);
        assert_eq!(out.bytes.mult, 8 * mult_len);
        assert!(out.bytes.rounds_claims > 0, "full-corr bytes must be counted");

        // Measured lookups per instance == witness trace lens + pads.
        let tr = |id: TableId| wit.traces[id as usize].len() as u64;
        let rect = 16 * t_pad * t_pad;
        let expected: [(&str, u64, u64); 14] = [
            ("attn_proj", tr(TableId::RequantAttnProj), t_pad << 10),
            ("av", tr(TableId::RequantAv), t_pad << 10),
            ("softmax_norm", tr(TableId::SoftmaxNormRequant), rect),
            ("exp", tr(TableId::Exp), rect),
            ("softmax_recip", tr(TableId::SoftmaxRecip), 16 * t_pad),
            ("scores", tr(TableId::RequantScores), rect),
            ("qkv", tr(TableId::RequantQkv), t_pad << 12),
            ("ln1_norm", tr(TableId::LnNormRequant) / 2, t_pad << 10),
            ("ln1_rsqrt", tr(TableId::LnRsqrt) / 2, t_pad),
            ("ffn_down", tr(TableId::RequantFfnDown), t_pad << 10),
            ("gelu", tr(TableId::Gelu), t_pad << 12),
            ("ffn_up", tr(TableId::RequantFfnUp), t_pad << 12),
            ("ln2_norm", tr(TableId::LnNormRequant) / 2, t_pad << 10),
            ("ln2_rsqrt", tr(TableId::LnRsqrt) / 2, t_pad),
        ];
        assert_eq!(out.lookups.len(), expected.len());
        for (il, &(name, real, domain)) in out.lookups.iter().zip(&expected) {
            assert_eq!(il.name, name);
            let pads = domain - real;
            assert_eq!(il.lookups, real + pads, "lookup count mismatch for {name}");
        }

        // T=4 telemetry for the report (visible with -- --nocapture).
        println!(
            "layer T={T} bytes: boundary={} mult={} ln_vectors={} attn_vectors={} rounds_claims={}",
            out.bytes.boundary,
            out.bytes.mult,
            out.bytes.ln_vectors,
            out.bytes.attn_vectors,
            out.bytes.rounds_claims
        );
        println!(
            "layer T={T} emult: instances={:.0} other={:.0}; lookups total={}",
            out.ctr_instances.emult_equiv(),
            out.ctr_other.emult_equiv(),
            out.lookups.iter().map(|l| l.lookups).sum::<u64>()
        );

        // Instance E-mults are nonzero and separable from the chain-level ones.
        assert!(out.ctr_instances.emult_equiv() > 0.0);
        assert!(out.ctr_other.emult_equiv() > 0.0);
        assert!(
            out.ctr_instances.fp2_mults > out.ctr_other.fp2_mults,
            "instance counter should dominate the chain-level public evals"
        );
    }

    /// Deterministic small synthetic biases (splitmix-style, magnitude
    /// bounded so no requant saturates alongside `synthetic_weights`/
    /// `synthetic_input`'s sizing at T = 4).
    fn synthetic_biases(seed: u64) -> volta_gpt2::GemmBiases {
        let mut st = seed;
        let mut vec_of = |len: usize| -> Vec<i16> {
            (0..len).map(|_| (splitmix64_test(&mut st) % 64) as i16 - 32).collect()
        };
        volta_gpt2::GemmBiases {
            c_attn: vec_of(3 * D),
            attn_proj: vec_of(D),
            ffn_up: vec_of(DFF),
            ffn_down: vec_of(D),
        }
    }

    /// Test-local copy of the layer.rs splitmix64 (private there).
    fn splitmix64_test(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Full layer round trip with per-GEMM biases threaded through prove and
    /// verify (P5 §per-GEMM biases): synthetic weights/input/biases at T = 4,
    /// `forward_layer_with(Some(&biases))` builds the POST-bias witness, and
    /// the 4 `sub_bias_p`/`sub_bias_k` insertion points must recover the
    /// pre-bias `X·W` claim the chained GEMMs expect. Mirrors `run_layer_case`
    /// for the closing batches (biases aren't part of that harness's shared
    /// fixture, so this test builds its own witness).
    #[test]
    fn layer_with_biases_proves_and_verifies() {
        let luts = build_luts(LutParams::default());
        let w = synthetic_weights(42);
        let biases = synthetic_biases(0xB1A5);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, Some(&biases), &luts, luts.params, T);

        let seed = 90u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let mut cxp = BlockCtxP::new(&mut stream, &mut txp, 0);
        let (proof, out) = prove_layer(&wit, &w, &luts, &mut cxp, Some(&biases));
        let BlockCtxP { doms: mut domsp, prod, mut zero, .. } = cxp;

        let mut cxv = BlockCtxV::new(&mut vc, &mut txv, 0);
        let outv = verify_layer(
            T, &w.ln1_gain, &w.ln1_bias, &w.ln2_gain, &w.ln2_bias, &luts, &proof, &mut cxv,
            Some(&biases),
        )
        .expect("honest biased layer must verify");
        let BlockCtxV { doms: mut domsv, kprod, mut kzero, .. } = cxv;

        assert_eq!(out.weight_claims.len(), 4, "expected exactly 4 weight claims");
        assert_eq!(outv.weight_keys.len(), 4);
        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] = [
            (D, 4096, &w_perm),
            (D, D, &w.attn_proj),
            (D, DFF, &w.ffn_up),
            (DFF, D, &w.ffn_down),
        ];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(wc.point.len(), pad_bits(k) + pad_bits(n));
            assert_eq!(outv.weight_keys[i].0, wc.point, "weight point mismatch across parties");
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        let chi = txp.challenge_fp2();
        assert_eq!(chi, txv.challenge_fp2());
        let md = domsp.take(1);
        assert_eq!(md, domsv.take(1));
        let mask = stream.draw_fulls(md, 1)[0];
        let k_mask = vc.expand_full_keys(md, 1)[0];
        let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
        let ok_prod = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        assert!(ok_prod && ok_zero, "honest biased layer's batches must close");
    }

    /// Negative: proving with biases but verifying with `None` (the verifier
    /// unaware of the biases, or given the wrong ones) must be rejected — the
    /// POST-bias witness accumulators no longer match the pre-bias claim the
    /// chained GEMM would recompute without the `sub_bias_k` correction.
    #[test]
    fn layer_rejects_missing_biases_at_verify() {
        let luts = build_luts(LutParams::default());
        let w = synthetic_weights(42);
        let biases = synthetic_biases(0xB1A5);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, Some(&biases), &luts, luts.params, T);

        let seed = 91u8;
        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x5A; 32];
        let mut stream = CorrelationStream::new(pcg_seed);
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txp = Transcript::new(tx_seed);
        let mut txv = Transcript::new(tx_seed);

        let mut cxp = BlockCtxP::new(&mut stream, &mut txp, 0);
        let (proof, _out) = prove_layer(&wit, &w, &luts, &mut cxp, Some(&biases));

        let mut cxv = BlockCtxV::new(&mut vc, &mut txv, 0);
        let outv = verify_layer(
            T, &w.ln1_gain, &w.ln1_bias, &w.ln2_gain, &w.ln2_bias, &luts, &proof, &mut cxv, None,
        );
        assert!(outv.is_none(), "verifying a biased proof with no biases must be rejected");
    }
}
