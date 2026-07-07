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
    blind_instance_prove, blind_instance_verify, eval_mle_counted, table_side_prove,
    table_side_verify, BlindInstance, Counters, Doms, InstanceOutP, InstanceOutV, LeafAuxClaim,
    TableKey, TableSideProof,
};
use std::collections::BTreeMap;
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

// ---------------------------------------------------------------------------
// P6 shared-α table bank: one multiset argument per table CONTENT per model
// ---------------------------------------------------------------------------

/// The proof of one table content's closure (per model): its global
/// multiplicity-vector corrections + the shared table side (table fraction
/// tree, fraction-sum chain over all sites, root cross-check).
pub struct TableCloseProof {
    pub key: TableKey,
    pub mult_corr: Vec<u64>,
    pub side: TableSideProof,
}

/// Prover-side model-wide table bank. Phase 1 accumulates one global
/// multiplicity vector per content (`add_mult`); `finalize` authenticates
/// every vector and draws one α per content (strictly after every phase-1
/// binding); phase 2 instances fetch their α and register their lookup-tree
/// root fractions; `close` runs one table side per content.
#[derive(Default)]
pub struct TableBankP {
    mult: BTreeMap<TableKey, Vec<u32>>,
    alphas: BTreeMap<TableKey, Fp2>,
    roots: BTreeMap<TableKey, Vec<(ProverAuthed, ProverAuthed)>>,
    auth: BTreeMap<TableKey, (u64, Vec<Fp>, Vec<u64>)>,
    finalized: bool,
}

/// The length of a content's table (= multiplicity-vector length).
pub fn table_len(key: TableKey) -> usize {
    match key {
        TableKey::Range(s) => 1usize << s,
        _ => 1usize << 16,
    }
}

/// Table values of a content (pair LUTs are global per model — P5 froze one
/// LUT set; per-layer Luts clones only override shifts).
pub fn table_vals(key: TableKey, luts: &Luts) -> Vec<Fp> {
    match key {
        TableKey::Range(s) => range_table(s),
        TableKey::Exp => pair_table(&luts.exp, true),
        TableKey::Gelu => pair_table(&luts.gelu, true),
        TableKey::LnRsqrt => pair_table(&luts.ln_rsqrt, false),
        TableKey::SoftmaxRecip => pair_table(&luts.softmax_recip, false),
    }
}

/// The content key(s) of a requant range site: single table for s ≤ 16,
/// (stage-2, stage-1) contents for a chained site.
pub fn range_keys(shift: u32) -> (TableKey, Option<TableKey>) {
    if shift <= 16 {
        (TableKey::Range(shift), None)
    } else {
        (TableKey::Range(16), Some(TableKey::Range(shift - 16)))
    }
}

impl TableBankP {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accumulate a site's multiplicities into the content's global vector.
    pub fn add_mult(&mut self, key: TableKey, m: &[u32]) {
        assert!(!self.finalized, "phase 1 is closed — α already drawn");
        assert_eq!(m.len(), table_len(key), "site multiplicity length mismatch for {key:?}");
        let g = self.mult.entry(key).or_insert_with(|| vec![0u32; m.len()]);
        for (a, &b) in g.iter_mut().zip(m) {
            *a += b;
        }
    }

    /// End of phase 1: authenticate every content's global vector, then draw
    /// one α per content (canonical `TableKey` order on both sides).
    pub fn finalize(
        &mut self,
        stream: &mut CorrelationStream,
        tx: &mut Transcript,
        doms: &mut Doms,
    ) {
        assert!(!self.finalized);
        for (key, m) in &self.mult {
            let fp = fp_vec_u32(m);
            let dom = doms.take(1);
            let corr = auth_fp_vec_p(stream, tx, dom, &fp);
            self.auth.insert(*key, (dom, fp, corr));
        }
        for key in self.mult.keys() {
            self.alphas.insert(*key, tx.challenge_fp2());
        }
        self.finalized = true;
    }

    pub fn alpha(&self, key: TableKey) -> Fp2 {
        *self.alphas.get(&key).unwrap_or_else(|| panic!("no α for content {key:?}"))
    }

    pub fn push_roots(&mut self, key: TableKey, roots: (ProverAuthed, ProverAuthed)) {
        self.roots.entry(key).or_default().push(roots);
    }

    /// Multiplicity correction bytes (8 B/entry over all contents).
    /// Canonical (sorted) content keys accumulated so far.
    pub fn content_keys(&self) -> Vec<TableKey> {
        self.mult.keys().copied().collect()
    }

    pub fn mult_bytes(&self) -> u64 {
        8 * self.mult.values().map(|m| m.len() as u64).sum::<u64>()
    }

    /// Close every content: ONE table side against the global multiplicity
    /// vector, the fraction-sum chain over all registered sites, and the m̃
    /// claim resolved against the authenticated vector.
    #[allow(clippy::too_many_arguments)]
    pub fn close(
        self,
        luts: &Luts,
        stream: &mut CorrelationStream,
        doms: &mut Doms,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut crate::logup::ProdTriples,
        zero: &mut Vec<ProverAuthed>,
    ) -> Vec<TableCloseProof> {
        assert!(self.finalized);
        let mut out = Vec::with_capacity(self.mult.len());
        for (key, m) in &self.mult {
            let sites = self
                .roots
                .get(key)
                .unwrap_or_else(|| panic!("content {key:?} has a multiplicity vector but no sites"));
            let tv = table_vals(*key, luts);
            let alpha = self.alphas[key];
            let (side, mult_claim) =
                table_side_prove(&tv, m, alpha, sites, stream, doms, tx, ctr, prod, zero);
            let (dom, fp, corr) = &self.auth[key];
            let opened = open_fp_vec_p(stream, *dom, fp, &mult_claim.point);
            zero.push(mult_claim.value.sub(opened));
            out.push(TableCloseProof { key: *key, mult_corr: corr.clone(), side });
        }
        out
    }
}

/// Verifier mirror of [`TableBankP`].
pub struct TableBankV {
    alphas: BTreeMap<TableKey, Fp2>,
    kroots: BTreeMap<TableKey, Vec<(VerifierKey, VerifierKey)>>,
    keys: BTreeMap<TableKey, Vec<Fp2>>,
}

impl TableBankV {
    /// Placeholder bank for phase-1 contexts (no instance runs in phase 1).
    pub fn empty() -> Self {
        TableBankV { alphas: BTreeMap::new(), kroots: BTreeMap::new(), keys: BTreeMap::new() }
    }

    /// Mirror of `finalize`: `expected` is the content set derived from the
    /// PUBLIC parameters — the proof must present exactly these contents (in
    /// canonical order), with corr vectors of the right lengths.
    pub fn finalize(
        expected: &std::collections::BTreeSet<TableKey>,
        proofs: &[TableCloseProof],
        ctx: &mut VerifierCtx,
        tx: &mut Transcript,
        doms: &mut Doms,
    ) -> Option<Self> {
        if proofs.len() != expected.len() {
            return None;
        }
        let mut keys = BTreeMap::new();
        for (p, &key) in proofs.iter().zip(expected.iter()) {
            if p.key != key || p.mult_corr.len() != table_len(key) {
                return None;
            }
            let dom = doms.take(1);
            keys.insert(key, keys_fp_vec_v(ctx, dom, &p.mult_corr));
        }
        let mut alphas = BTreeMap::new();
        for &key in expected {
            alphas.insert(key, tx.challenge_fp2());
        }
        Some(TableBankV { alphas, kroots: BTreeMap::new(), keys })
    }

    pub fn alpha(&self, key: TableKey) -> Option<Fp2> {
        self.alphas.get(&key).copied()
    }

    pub fn push_kroots(&mut self, key: TableKey, kroots: (VerifierKey, VerifierKey)) {
        self.kroots.entry(key).or_default().push(kroots);
    }

    /// Mirror of `close` (same canonical order).
    #[allow(clippy::too_many_arguments)]
    pub fn close(
        self,
        luts: &Luts,
        proofs: &[TableCloseProof],
        ctx: &mut VerifierCtx,
        doms: &mut Doms,
        tx: &mut Transcript,
        kprod: &mut crate::logup::ProdKeyTriples,
        kzero: &mut Vec<VerifierKey>,
    ) -> Option<()> {
        for p in proofs {
            let ksites = self.kroots.get(&p.key)?;
            let tv = table_vals(p.key, luts);
            let alpha = self.alphas[&p.key];
            let mult_key =
                table_side_verify(&tv, alpha, &p.side, ksites, ctx, doms, tx, kprod, kzero)?;
            let opened = open_fp_vec_k(&self.keys[&p.key], &mult_key.point);
            kzero.push(mult_key.key.sub(opened));
        }
        Some(())
    }
}

/// Prover-side block context: correlation stream, transcript, sequential
/// domain allocator, the model-wide table bank and the Π_Prod / Π_ZeroBatch
/// accumulators. The final closures (one χ-batched prod check + one zero
/// batch) are run by the caller over the accumulated rows.
pub struct BlockCtxP<'a> {
    pub stream: &'a mut CorrelationStream,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub bank: &'a mut TableBankP,
    pub prod: crate::logup::ProdTriples,
    pub zero: Vec<ProverAuthed>,
    /// E-mults spent inside LogUp instances (the p4_report gate number).
    pub ctr_instances: Counters,
    /// E-mults spent on chain-level public evaluations (kept separable).
    pub ctr_other: Counters,
}

impl<'a> BlockCtxP<'a> {
    pub fn new(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        layer: u8,
        bank: &'a mut TableBankP,
    ) -> Self {
        Self::with_doms(stream, tx, Doms::new(layer_dom_base(layer)), bank)
    }

    /// Resume a context whose domain cursor was saved between the phases.
    pub fn with_doms(
        stream: &'a mut CorrelationStream,
        tx: &'a mut Transcript,
        doms: Doms,
        bank: &'a mut TableBankP,
    ) -> Self {
        BlockCtxP {
            stream,
            tx,
            doms,
            bank,
            prod: Vec::new(),
            zero: Vec::new(),
            ctr_instances: Counters::default(),
            ctr_other: Counters::default(),
        }
    }

    /// Prove one lookup-side instance with the content's shared α and
    /// register its root fraction with the bank.
    pub(crate) fn inst(
        &mut self,
        key: TableKey,
        cols: &[Vec<Fp>],
        shifts: &[Option<u32>],
        aux: Vec<LeafAuxClaim>,
    ) -> InstanceOutP {
        let alpha = self.bank.alpha(key);
        let out = blind_instance_prove(
            cols,
            shifts,
            alpha,
            aux,
            self.stream,
            &mut self.doms,
            self.tx,
            &mut self.ctr_instances,
            &mut self.prod,
            &mut self.zero,
        );
        self.bank.push_roots(key, out.roots);
        out
    }
}

/// Verifier mirror of [`BlockCtxP`].
pub struct BlockCtxV<'a> {
    pub ctx: &'a mut VerifierCtx,
    pub tx: &'a mut Transcript,
    pub doms: Doms,
    pub bank: &'a mut TableBankV,
    pub kprod: crate::logup::ProdKeyTriples,
    pub kzero: Vec<VerifierKey>,
}

impl<'a> BlockCtxV<'a> {
    pub fn new(
        ctx: &'a mut VerifierCtx,
        tx: &'a mut Transcript,
        layer: u8,
        bank: &'a mut TableBankV,
    ) -> Self {
        Self::with_doms(ctx, tx, Doms::new(layer_dom_base(layer)), bank)
    }

    pub fn with_doms(
        ctx: &'a mut VerifierCtx,
        tx: &'a mut Transcript,
        doms: Doms,
        bank: &'a mut TableBankV,
    ) -> Self {
        BlockCtxV { ctx, tx, doms, bank, kprod: Vec::new(), kzero: Vec::new() }
    }

    /// Verify one lookup-side instance with the content's shared α and
    /// register its root-fraction keys with the bank.
    pub(crate) fn inst(
        &mut self,
        key: TableKey,
        n_bits: usize,
        shifts: &[Option<u32>],
        proof: &BlindInstance,
        aux: &[(usize, Vec<Fp2>, VerifierKey)],
    ) -> Option<InstanceOutV> {
        let alpha = self.bank.alpha(key)?;
        let out = blind_instance_verify(
            n_bits,
            shifts,
            alpha,
            proof,
            aux,
            self.ctx,
            &mut self.doms,
            self.tx,
            &mut self.kprod,
            &mut self.kzero,
        )?;
        self.bank.push_kroots(key, out.kroots);
        Some(out)
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
// P6 band shapes + cross-phase K/V cache segments
// ---------------------------------------------------------------------------

/// Attention band shape: `q` query rows at positions `t0..t0+q`, attending
/// over the full cache of `s = t0+q` positions. Prefill is the SQUARE band
/// `t0 = 0` (q = s = t) — one code path serves both (ledger P6 plan #2).
#[derive(Clone, Copy, Debug)]
pub struct BandShape {
    pub t0: usize,
    pub q: usize,
}

impl BandShape {
    pub fn square(t: usize) -> BandShape {
        BandShape { t0: 0, q: t }
    }
    pub fn s(&self) -> usize {
        self.t0 + self.q
    }
    pub fn qb(&self) -> usize {
        pad_bits(self.q)
    }
    pub fn sb(&self) -> usize {
        pad_bits(self.s())
    }
    pub fn q_pad(&self) -> usize {
        1 << self.qb()
    }
    pub fn s_pad(&self) -> usize {
        1 << self.sb()
    }
    /// Per-head rectangle size (q_pad × s_pad).
    pub fn sp2(&self) -> usize {
        self.q_pad() * self.s_pad()
    }
    /// Rect domain vars: within-row (sb, LSB) ‖ rows (qb) ‖ heads (4).
    pub fn nr(&self) -> usize {
        self.sb() + self.qb() + HEAD_BITS
    }
    /// Causal window length of band row `i` (positions 0..=t0+i).
    pub fn win(&self, i: usize) -> usize {
        self.t0 + i + 1
    }
    /// Packed offset of band row `i` within one head's causal-packed data.
    pub fn packed_off(&self, i: usize) -> usize {
        i * self.t0 + i * (i + 1) / 2
    }
    /// Packed length per head.
    pub fn caus(&self) -> usize {
        self.packed_off(self.q)
    }
    /// Above-causal real-cell count per head (j in win(i)..s).
    pub fn n_above_head(&self) -> usize {
        (0..self.q).map(|i| self.s() - self.win(i)).sum()
    }
}

/// One authenticated K/V cache segment (rows×D matrix, per-row domains) —
/// the prover side. A layer's cache = the prefill segment(s) followed by the
/// band's own new rows; the square path is the single own segment.
pub struct CacheSegP<'a> {
    pub dom: u64,
    pub rows: usize,
    pub data: &'a [i16],
}

/// Verifier mirror: cached per-element keys of one segment.
pub struct CacheSegK<'a> {
    pub rows: usize,
    pub keys: &'a [Fp2],
}

/// One earlier phase's authenticated K/V (prover side): the prefill (or a
/// previous decode chunk's) boundary tensors + their domains.
pub struct KvPrefixP<'a> {
    pub rows: usize,
    pub dom_k: u64,
    pub k: &'a [i16],
    pub dom_v: u64,
    pub v: &'a [i16],
}

/// Verifier mirror of [`KvPrefixP`] (cached keys).
pub struct KvPrefixK<'a> {
    pub rows: usize,
    pub k_keys: &'a [Fp2],
    pub v_keys: &'a [Fp2],
}

/// Fold a segmented cache over its ROWS (global row index into `wr`),
/// restricted to the column window `[c0, c0+w)` — segment-general
/// [`fold_rows_window_p`].
pub(crate) fn cache_fold_rows_p(
    stream: &mut CorrelationStream,
    segs: &[CacheSegP],
    wr: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = vec![Fp2::ZERO; w];
    let mut tags_out = vec![Fp2::ZERO; w];
    let mut base = 0usize;
    for seg in segs {
        let (sv, st) = fold_rows_window_p(
            stream, seg.dom, seg.data, seg.rows, D, &wr[base..base + seg.rows], c0, w,
        );
        for l in 0..w {
            vals[l] += sv[l];
            tags_out[l] += st[l];
        }
        base += seg.rows;
    }
    (vals, tags_out)
}

pub(crate) fn cache_fold_rows_k(segs: &[CacheSegK], wr: &[Fp2], c0: usize, w: usize) -> Vec<Fp2> {
    let mut out = vec![Fp2::ZERO; w];
    let mut base = 0usize;
    for seg in segs {
        let sv = fold_rows_window_k(seg.keys, seg.rows, D, &wr[base..base + seg.rows], c0, w);
        for l in 0..w {
            out[l] += sv[l];
        }
        base += seg.rows;
    }
    out
}

/// Fold a segmented cache over a COLUMN WINDOW per row (segment-general
/// [`fold_cols_window_p`]): returns per-GLOBAL-row (values, tags).
pub(crate) fn cache_fold_cols_p(
    stream: &mut CorrelationStream,
    segs: &[CacheSegP],
    wc: &[Fp2],
    c0: usize,
    w: usize,
) -> (Vec<Fp2>, Vec<Fp2>) {
    let mut vals = Vec::new();
    let mut tags = Vec::new();
    for seg in segs {
        let (sv, st) = fold_cols_window_p(stream, seg.dom, seg.data, seg.rows, D, wc, c0, w);
        vals.extend(sv);
        tags.extend(st);
    }
    (vals, tags)
}

pub(crate) fn cache_fold_cols_k(segs: &[CacheSegK], wc: &[Fp2], c0: usize, w: usize) -> Vec<Fp2> {
    let mut out = Vec::new();
    for seg in segs {
        out.extend(fold_cols_window_k(seg.keys, seg.rows, D, wc, c0, w));
    }
    out
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

/// One round-half-up shift stage (mirror of the witness generator's).
#[inline]
pub(crate) fn round_stage(acc: i64, s: u32) -> i64 {
    (acc + (1i64 << (s - 1))) >> s
}

/// Chained requant columns (P5 spec §chained requant, shift s > 16):
/// stage 1 rounds the accumulator by s−16 (`y1 = round(acc, s−16)`,
/// `rem1 ∈ [0, 2^(s−16))`), stage 2 rounds `y1` by 16 (`rem2 ∈ [0, 2^16)`,
/// `out` must equal the witness output — double-round semantics). Pads:
/// acc = 0 ⇒ y1 = 0, rem1 = 2^(s−17), rem2 = 2^15, out = 0.
/// Returns ((rem1, y1), (rem2, out)).
#[allow(clippy::type_complexity)]
pub(crate) fn range_cols_padded_chained(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) -> ((Vec<Fp>, Vec<Fp>), (Vec<Fp>, Vec<Fp>)) {
    assert!(shift > 16);
    let s1 = shift - 16;
    let (h1, h2) = (1i64 << (s1 - 1), 1i64 << 15);
    let cp = 1usize << pad_bits(cols);
    let rp = 1usize << pad_bits(rows);
    let mut rem1 = vec![Fp::new(h1 as u64); rp * cp];
    let mut y1c = vec![Fp::ZERO; rp * cp];
    let mut rem2 = vec![Fp::new(h2 as u64); rp * cp];
    let mut o = vec![Fp::ZERO; rp * cp];
    for i in 0..rows {
        for j in 0..cols {
            let a = acc[i * cols + j];
            let y = out[i * cols + j] as i64;
            let y1 = round_stage(a, s1);
            let r1 = a + h1 - (y1 << s1);
            debug_assert_eq!(round_stage(y1, 16), y, "witness is not double-rounded");
            let r2 = y1 + h2 - (y << 16);
            assert!((0..1i64 << s1).contains(&r1), "chained stage-1 remainder out of range");
            assert!((0..1i64 << 16).contains(&r2), "chained stage-2 remainder out of range");
            rem1[i * cp + j] = Fp::new(r1 as u64);
            y1c[i * cp + j] = Fp::from_i64(y1);
            rem2[i * cp + j] = Fp::new(r2 as u64);
            o[i * cp + j] = Fp::from_i64(y);
        }
    }
    ((rem1, y1c), (rem2, o))
}

/// Multiplicities of both chained stages, pads bumped at their halves.
pub(crate) fn range_mult_chained(
    acc: &[i64],
    rows: usize,
    cols: usize,
    shift: u32,
) -> (Vec<u32>, Vec<u32>) {
    assert!(shift > 16);
    let s1 = shift - 16;
    let (h1, h2) = (1i64 << (s1 - 1), 1i64 << 15);
    let mut m1 = vec![0u32; 1 << s1];
    let mut m2 = vec![0u32; 1 << 16];
    for &a in acc {
        let y1 = round_stage(a, s1);
        m1[(a + h1 - (y1 << s1)) as usize] += 1;
        let y = round_stage(y1, 16);
        m2[(y1 + h2 - (y << 16)) as usize] += 1;
    }
    let pads = ((1usize << pad_bits(rows)) * (1usize << pad_bits(cols)) - rows * cols) as u32;
    m1[h1 as usize] += pads;
    m2[h2 as usize] += pads;
    (m1, m2)
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

/// A proved requant range site: `main` is the instance carrying the OUT
/// column (the single instance for s ≤ 16, stage 2 for s > 16); `stage1` is
/// the extra [rem1, y1] instance of a chained site. `acc_claim` is the
/// transported (post-bias) accumulator claim at `main.point`… stage-1's
/// point for chained sites — callers must use `main.point`/`main.col_claims`
/// for OUT-wire closures and `acc_point()` for the GEMM seam.
pub(crate) struct RangeSiteP {
    pub main: InstanceOutP,
    pub stage1: Option<InstanceOutP>,
    pub acc_claim: ProverAuthed,
}

impl RangeSiteP {
    /// Point the accumulator claim lives at (stage-1's for chained sites).
    pub(crate) fn acc_point(&self) -> &[Fp2] {
        match &self.stage1 {
            Some(s1) => &s1.point,
            None => &self.main.point,
        }
    }
}

/// Prove a requant range site, chained for shift > 16 (P5 spec). `aux`
/// drains external claims into the OUT column (col 1) of the main instance.
/// Multiplicities were accumulated into the bank in phase 1 (`range_keys`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_range_site(
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
    aux: Vec<LeafAuxClaim>,
    cx: &mut BlockCtxP,
) -> RangeSiteP {
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        let (rem, oc) = range_cols_padded(acc, out, rows, cols, shift);
        let inst = cx.inst(key_main, &[rem, oc], &[Some(0), None], aux);
        let acc_claim = transport_p(&inst, shift);
        RangeSiteP { main: inst, stage1: None, acc_claim }
    } else {
        let s1 = shift - 16;
        let ((rem1, y1c), (rem2, oc)) = range_cols_padded_chained(acc, out, rows, cols, shift);
        let inst2 = cx.inst(key_main, &[rem2, oc], &[Some(0), None], aux);
        let y1_claim = transport_p(&inst2, 16);
        let inst1 = cx.inst(
            key_s1.unwrap(),
            &[rem1, y1c],
            &[Some(0), None],
            vec![LeafAuxClaim { col: 1, point: inst2.point.clone(), value: y1_claim }],
        );
        let acc_claim = transport_p(&inst1, s1);
        RangeSiteP { main: inst2, stage1: Some(inst1), acc_claim }
    }
}

pub(crate) struct RangeSiteV {
    pub main: InstanceOutV,
    pub stage1: Option<InstanceOutV>,
    pub acc_key: VerifierKey,
}

impl RangeSiteV {
    pub(crate) fn acc_point(&self) -> &[Fp2] {
        match &self.stage1 {
            Some(s1) => &s1.point,
            None => &self.main.point,
        }
    }
}

/// Verifier mirror of [`prove_range_site`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_range_site(
    n_vars: usize,
    shift: u32,
    proof_main: &BlindInstance,
    proof_s1: Option<&BlindInstance>,
    aux: &[(usize, Vec<Fp2>, VerifierKey)],
    cx: &mut BlockCtxV,
) -> Option<RangeSiteV> {
    let shifts_range = [Some(0u32), None];
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        if proof_s1.is_some() {
            return None;
        }
        let v = cx.inst(key_main, n_vars, &shifts_range, proof_main, aux)?;
        let acc_key = transport_k(&v, shift, cx.ctx.delta);
        Some(RangeSiteV { main: v, stage1: None, acc_key })
    } else {
        let s1 = shift - 16;
        let v2 = cx.inst(key_main, n_vars, &shifts_range, proof_main, aux)?;
        let y1_key = transport_k(&v2, 16, cx.ctx.delta);
        let aux1 = [(1usize, v2.point.clone(), y1_key)];
        let v1 = cx.inst(key_s1.unwrap(), n_vars, &shifts_range, proof_s1?, &aux1)?;
        let acc_key = transport_k(&v1, s1, cx.ctx.delta);
        Some(RangeSiteV { main: v2, stage1: Some(v1), acc_key })
    }
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


/// Recompute the LN affine accumulators from the boundary + stats + public
/// gain/bias (bit-identical to the witness trace inputs — pure function, so
/// the band slices need no trace bookkeeping):
/// `acc[i,j] = (x[i,j] − mean[i])·rsqrt_out[i]·gain[j] + (bias[j] << s_ln)`.
pub(crate) fn ln_acc_recompute(
    x: &[i16],
    t: usize,
    mean: &[i64],
    rsqrt_out: &[i16],
    gain: &[i16],
    bias: &[i16],
    s_ln: u32,
) -> Vec<i64> {
    let mut acc = vec![0i64; t * D];
    for i in 0..t {
        for j in 0..D {
            acc[i * D + j] = (x[i * D + j] as i64 - mean[i]) * rsqrt_out[i] as i64
                * gain[j] as i64
                + ((bias[j] as i64) << s_ln);
        }
    }
    acc
}

/// Prover-side consistency check of LN statistics vectors against the
/// pre-LN input `x` — the P4-DEVIATION(ln-stats) fallback (see module doc).
pub(crate) fn assert_ln_stats(
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
pub(crate) struct LnVecsP {
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
pub(crate) fn auth_ln_vecs_p(
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

pub(crate) struct LnVecsK {
    mean_keys: Vec<Fp2>,
    rin_keys: Vec<Fp2>,
    rout_keys: Vec<Fp2>,
}

pub(crate) fn expand_ln_vecs_k(cx: &mut BlockCtxV, corrs: &[Vec<u64>; 4]) -> LnVecsK {
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
    /// Stage-1 instance when shift_ln_norm > 16 (P5 chained requant).
    pub inst_ln_stage1: Option<BlindInstance>,
    pub hadamard: HadamardProof,
    pub inst_rsqrt: BlindInstance,
}

/// LN chain prover: `acc_ln`/`out_ln` are the T×D ln_norm_requant pairs,
/// `x` is the pre-LN boundary tensor (dom `dom_x`), `wire` the upstream
/// GEMM's X wire claim on `out_ln`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_ln_chain(
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
    wire: &WireOut,
    cx: &mut BlockCtxP,
) -> LnChainProof {
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let d_cb = pad_bits(D);

    // -- ln_norm_requant range instance (drains the GEMM X wire; chained
    //    two-stage for s_ln > 16 — P5) --------------------------------------
    let site_ln = prove_range_site(
        acc_ln,
        out_ln,
        t,
        D,
        s_ln,
        vec![LeafAuxClaim { col: 1, point: wire.point.clone(), value: wire.value }],
        cx,
    );

    // -- hadamard: acc_ln − bias·2^s·rowmask = (x − mean) ∘ (rsqrt·gain) ----
    // Runs at the ACC claim's point (stage-1's for a chained site).
    let pt_ln = site_ln.acc_point().to_vec();
    let acc_ln_claim = site_ln.acc_claim;
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
    let inst_rsqrt = cx.inst(
        TableKey::LnRsqrt,
        &[lv.rin_fp.clone(), lv.rout_fp.clone()],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    let rsq_in_open = open_fp_vec_p(cx.stream, lv.dom_rin, &lv.rin_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[0].value.sub(rsq_in_open));
    let rsq_out_open = open_fp_vec_p(cx.stream, lv.dom_rout, &lv.rout_fp, &inst_rsqrt.point);
    cx.zero.push(inst_rsqrt.col_claims[1].value.sub(rsq_out_open));

    LnChainProof {
        inst_ln: site_ln.main.proof,
        inst_ln_stage1: site_ln.stage1.map(|s1| s1.proof),
        hadamard: had_proof,
        inst_rsqrt: inst_rsqrt.proof,
    }
}

/// LN chain verifier (mirror of [`prove_ln_chain`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ln_chain(
    t: usize,
    s_ln: u32,
    gain: &[i16],
    bias: &[i16],
    x_keys: &[Fp2],
    lvk: &LnVecsK,
    proof: &LnChainProof,
    wire: &WireKey,
    cx: &mut BlockCtxV,
) -> Option<()> {
    let rb = pad_bits(t);
    let d_cb = pad_bits(D);
    let n_d = d_cb + rb;
    let shifts_pair = [Some(0u32), Some(16u32)];

    if (s_ln > 16) != proof.inst_ln_stage1.is_some() {
        return None;
    }
    let aux_ln = [(1usize, wire.point.clone(), wire.key)];
    let site_ln = verify_range_site(
        n_d,
        s_ln,
        &proof.inst_ln,
        proof.inst_ln_stage1.as_ref(),
        &aux_ln,
        cx,
    )?;

    let pt_ln = site_ln.acc_point().to_vec();
    let k_acc_ln = site_ln.acc_key;
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

    let vr = cx.inst(TableKey::LnRsqrt, rb, &shifts_pair, &proof.inst_rsqrt, &[])?;
    let rin_k = open_fp_vec_k(&lvk.rin_keys, &vr.point);
    cx.kzero.push(vr.col_keys[0].key.sub(rin_k));
    let rout_k = open_fp_vec_k(&lvk.rout_keys, &vr.point);
    cx.kzero.push(vr.col_keys[1].key.sub(rout_k));
    Some(())
}

// ---------------------------------------------------------------------------
// FFN block (boundary auth HOISTED to the caller — prove_layer or the tests)
// ---------------------------------------------------------------------------

pub struct FfnBlockProof {
    /// LN2 vector corrections: [mean, var, rsqrt_in, rsqrt_out].
    pub ln_vec_corrs: [Vec<u64>; 4],
    // Chain, reverse dataflow order.
    pub inst_down: BlindInstance,
    /// Stage-1 instance when shift_ffn_down > 16 (chained requant).
    pub inst_down_stage1: Option<BlindInstance>,
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

/// FFN phase-1 state: LN2 vectors authenticated, all FFN-side multiplicities
/// accumulated into the bank.
pub struct FfnP1 {
    lv: LnVecsP,
    ln_vec_corrs: [Vec<u64>; 4],
}

/// FFN phase 1: bind everything the FFN instances will look up (LN vectors +
/// the content-global multiplicity contributions) BEFORE any α is drawn.
pub(crate) fn ffn_phase1(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
) -> FfnP1 {
    let t = wit.t;
    let p = luts.params;
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;
    let f_cb = pad_bits(DFF);

    assert_ln_stats(
        &wit.attn_block_out, t, &wit.ln2_mean, &wit.ln2_var, &wit.ln2_rsqrt_in,
        &wit.ln2_rsqrt_out, luts,
    );
    let rout_pad = Fp::from_i64(luts.ln_rsqrt[0] as i64);
    let (lv, ln_vec_corrs) = auth_ln_vecs_p(
        cx, rb, &wit.ln2_mean, &wit.ln2_var, &wit.ln2_rsqrt_in, &wit.ln2_rsqrt_out, rout_pad,
    );

    let (s_dn, s_up, s_ln) = (p.shift_ffn_down, p.shift_ffn_up, p.shift_ln_norm);
    add_range_mult(cx.bank, &wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn);
    assert_eq!(luts.gelu[0], 0, "gelu pad pair (0,0) requires gelu[0] == 0");
    let ff_pads = (t_pad << f_cb) - t * DFF;
    let mut mult_gelu = vec![0u32; 1 << 16];
    for &y in &wit.ffn_up_q {
        mult_gelu[(y as u16) as usize] += 1;
    }
    mult_gelu[0] += ff_pads as u32; // pad pair (0, gelu[0]=0) at index 0
    cx.bank.add_mult(TableKey::Gelu, &mult_gelu);
    add_range_mult(cx.bank, &wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    // LN2 accumulators, recomputed (bit-identical to the trace inputs).
    let acc_ln = ln_acc_recompute(
        &wit.attn_block_out, t, &wit.ln2_mean, &wit.ln2_rsqrt_out, &weights.ln2_gain,
        &weights.ln2_bias, s_ln,
    );
    add_range_mult(cx.bank, &acc_ln, &wit.ln2_out, t, D, s_ln);
    let mut mult_rsq = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq[wit.ln2_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq[0] += (t_pad - t) as u32; // pad pair (0, ln_rsqrt[0]) at index 0
    cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);

    FfnP1 { lv, ln_vec_corrs }
}

/// Accumulate a range site's multiplicities (both chained stages for
/// shift > 16) into the bank under the content key(s).
pub fn add_range_mult(
    bank: &mut TableBankP,
    acc: &[i64],
    out: &[i16],
    rows: usize,
    cols: usize,
    shift: u32,
) {
    let (key_main, key_s1) = range_keys(shift);
    if shift <= 16 {
        bank.add_mult(key_main, &range_mult(acc, out, rows, cols, shift));
    } else {
        let (m1, m2) = range_mult_chained(acc, rows, cols, shift);
        bank.add_mult(key_main, &m2);
        bank.add_mult(key_s1.unwrap(), &m1);
    }
}

/// Prove the FFN half (phase 2). The caller has already authenticated the
/// `attn_block_out` / `ffn_block_out` boundaries at `dom_abo` / `dom_fbo`
/// and run [`ffn_phase1`]. Returns the proof and the weight claims
/// `[ffn_down, ffn_up]`.
pub(crate) fn prove_ffn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: FfnP1,
    cx: &mut BlockCtxP,
    dom_abo: u64,
    dom_fbo: u64,
    biases: Option<&GemmBiases>,
) -> (FfnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    let d_cb = pad_bits(D); // 10
    let f_cb = pad_bits(DFF); // 12
    let FfnP1 { lv, ln_vec_corrs } = p1;

    let s_dn = p.shift_ffn_down;
    let s_up = p.shift_ffn_up;
    let s_ln = p.shift_ln_norm;
    let acc_ln = ln_acc_recompute(
        &wit.attn_block_out, t, &wit.ln2_mean, &wit.ln2_rsqrt_out, &weights.ln2_gain,
        &weights.ln2_bias, s_ln,
    );

    // ---- 1+2: ffn_down range site, closed against the residual ------------
    let site_dn =
        prove_range_site(&wit.ffn_down_acc, &wit.ffn_down_q, t, D, s_dn, Vec::new(), cx);
    let inst_down = &site_dn.main;
    let pt_out = inst_down.point.clone();
    // Residual zero row: ffn_down_q̃(pt) − f̃bo(pt) + ãbo(pt) = 0, both
    // boundaries opened by streamed MAC opening at the instance's point.
    let f_open = open_matrix_p(cx.stream, dom_fbo, &wit.ffn_block_out, t, D, &pt_out);
    let a_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_out);
    cx.zero.push(inst_down.col_claims[1].value.sub(f_open).add(a_open));

    // ---- 3: acc transport → GEMM-down (committed, chained) ----------------
    let pt = site_dn.acc_point().to_vec();
    let mut acc_dn_claim = site_dn.acc_claim;
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
    let inst_gelu = cx.inst(
        TableKey::Gelu,
        &[gelu_in, gelu_out_col],
        &[Some(0), Some(16)],
        vec![LeafAuxClaim { col: 1, point: wire_gelu.point.clone(), value: wire_gelu.value }],
    );
    // col_claims[1] (gelu out) is redundant post-fold: the external GEMM
    // claim was consolidated into the instance's own leaf closure. Dropped.

    // ---- 5: ffn_up range instance → GEMM-up -------------------------------
    assert!(s_up <= 16, "chained ffn_up requant not wired here");
    let (rem_up, out_up) = range_cols_padded(&wit.ffn_up_acc, &wit.ffn_up_q, t, DFF, s_up);
    let inst_up = cx.inst(
        TableKey::Range(s_up),
        &[rem_up, out_up],
        &[Some(0), None],
        vec![LeafAuxClaim {
            col: 1,
            point: inst_gelu.point.clone(),
            value: inst_gelu.col_claims[0].value,
        }],
    );
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
        &acc_ln,
        &wit.ln2_out,
        &wit.attn_block_out,
        dom_abo,
        &wit.ln2_mean,
        &weights.ln2_gain,
        &weights.ln2_bias,
        &lv,
        &wire_ln2,
        cx,
    );

    let proof = FfnBlockProof {
        ln_vec_corrs,
        inst_down: site_dn.main.proof,
        inst_down_stage1: site_dn.stage1.map(|s1| s1.proof),
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
pub(crate) fn verify_ffn_block(
    t: usize,
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &FfnBlockProof,
    lvk: &LnVecsK,
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

    if (s_ln > 16) != proof.ln.inst_ln_stage1.is_some() {
        return None;
    }
    let _ = t_pad;

    // ---- ffn_down site + residual + transport → GEMM-down ------------------
    let n_d = d_cb + rb;
    let n_ff = f_cb + rb;
    let shifts_range = [Some(0u32), None];
    let site_dn = verify_range_site(
        n_d,
        s_dn,
        &proof.inst_down,
        proof.inst_down_stage1.as_ref(),
        &[],
        cx,
    )?;
    let vd = &site_dn.main;
    let pt_out = vd.point.clone();
    let f_k = open_matrix_k(fbo_keys, t, D, &pt_out);
    let a_k = open_matrix_k(abo_keys, t, D, &pt_out);
    cx.kzero.push(vd.col_keys[1].key.sub(f_k).add(a_k));

    let pt = site_dn.acc_point().to_vec();
    let mut k_acc_dn = site_dn.acc_key;
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
    let shifts_pair = [Some(0u32), Some(16u32)];
    let aux_gelu = [(1usize, wk_gelu.point.clone(), wk_gelu.key)];
    let vg = cx.inst(TableKey::Gelu, n_ff, &shifts_pair, &proof.inst_gelu, &aux_gelu)?;

    // ---- ffn_up instance + transport → GEMM-up -----------------------------
    if s_up > 16 {
        return None;
    }
    let aux_up = [(1usize, vg.point.clone(), vg.col_keys[0].key)];
    let vu = cx.inst(TableKey::Range(s_up), n_ff, &shifts_range, &proof.inst_up, &aux_up)?;
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
    verify_ln_chain(t, s_ln, ln2_gain, ln2_bias, abo_keys, lvk, &proof.ln, &wk_ln2, cx)?;

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
/// Band-general view of one layer's attention witness: causal-packed wires
/// with per-row windows `t0+i+1` plus the layer's K cache segments (prefill
/// segment(s) followed by the band's own new rows). The square/prefill case
/// is `BandAttnRefs::square` (t0 = 0, single own segment).
pub struct BandAttnRefs<'a> {
    pub shape: BandShape,
    pub scores_acc: &'a [i64],
    pub scores_q: &'a [i16],
    pub exp_out: &'a [i16],
    pub softmax_w: &'a [i16],
    /// h×q row tables.
    pub row_shift: &'a [i16],
    pub denoms: &'a [i64],
    pub recips: &'a [i16],
    /// q×D.
    pub q_mat: &'a [i16],
    /// K cache segment data (rows×D each), Σ rows = s; the LAST segment is
    /// the band's own K rows.
    pub k_cache: Vec<&'a [i16]>,
}

impl<'a> BandAttnRefs<'a> {
    pub fn square(wit: &'a LayerWitness) -> Self {
        BandAttnRefs {
            shape: BandShape::square(wit.t),
            scores_acc: &wit.scores_acc,
            scores_q: &wit.scores_q,
            exp_out: &wit.exp_out,
            softmax_w: &wit.softmax_w,
            row_shift: &wit.row_shift,
            denoms: &wit.denoms,
            recips: &wit.recips,
            q_mat: &wit.q,
            k_cache: vec![&wit.k],
        }
    }

    /// Band view: `wit` is the band-packed LayerWitness (t = q, windows
    /// t0+i+1); `prefix_k` are the earlier phases' K segments.
    pub fn banded(wit: &'a LayerWitness, shape: BandShape, prefix_k: &[&'a [i16]]) -> Self {
        assert_eq!(wit.t, shape.q);
        let mut k_cache: Vec<&'a [i16]> = prefix_k.to_vec();
        k_cache.push(&wit.k);
        assert_eq!(k_cache.iter().map(|k| k.len()).sum::<usize>(), shape.s() * D);
        BandAttnRefs {
            shape,
            scores_acc: &wit.scores_acc,
            scores_q: &wit.scores_q,
            exp_out: &wit.exp_out,
            softmax_w: &wit.softmax_w,
            row_shift: &wit.row_shift,
            denoms: &wit.denoms,
            recips: &wit.recips,
            q_mat: &wit.q,
            k_cache,
        }
    }
}

pub struct AttnWires {
    pub shape: BandShape,
    /// h_pad×q_pad×s_pad, non-causal = exp pad INPUT (least zero-output idx).
    pub scores_rect: Vec<i16>,
    /// The SHARED scores/exp wire (P5 stable softmax): causal = s − c_row,
    /// non-causal/pads = the exp pad input. With `softmax_row_shift` off
    /// (c ≡ 0) this is byte-identical to `scores_rect`.
    pub sprime_rect: Vec<i16>,
    /// h_pad×q_pad row table of the per-(head,row) shifts c (pads 0).
    pub row_shift_row: Vec<i16>,
    /// Row-max indicator: 1 at the first causal position with s′ = 0 of each
    /// real row, 0 elsewhere (all zeros when the flag is off — unused).
    pub is_max_rect: Vec<i16>,
    /// h_pad×q_pad×s_pad, non-causal = 0 (the exp pad pair's output).
    pub exp_rect: Vec<i16>,
    /// h_pad×q_pad×s_pad, non-causal = 0.
    pub w_rect: Vec<i16>,
    /// The copy the causal sumcheck's B leg folds (== w_rect honestly).
    pub w_rect_causal: Vec<i16>,
    /// Full per-head Q·Kᵀ accumulators over the CACHE (H·q·s, row-major q×s
    /// per head) — recomputed; the forward discards the above-causal half.
    pub acc_full: Vec<i64>,
    /// Above-causal accumulators in fixed order (h, then i, then j≥win(i)).
    pub above_acc: Vec<i64>,
    /// h_pad·q_pad row tables (index = head·q_pad + i), zero pads.
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

/// Square/prefill wires (band with t0 = 0).
pub fn build_attn_wires(wit: &LayerWitness, luts: &Luts) -> AttnWires {
    build_attn_wires_band(&BandAttnRefs::square(wit), luts)
}

pub fn build_attn_wires_band(b: &BandAttnRefs, luts: &Luts) -> AttnWires {
    let sh = b.shape;
    let (q, s) = (sh.q, sh.s());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let caus = sh.caus();

    // Exp pad pair: (pad_in, 0) — asserted to exist (exp underflows to 0).
    let exp_pad_u = (0..1usize << 16)
        .find(|&u| luts.exp[u] == 0)
        .expect("exp LUT has no zero output — rectangular padding impossible");
    let pad_in = (exp_pad_u as u16) as i16;

    let mut scores_rect = vec![pad_in; H_PAD * sp2];
    let mut sprime_rect = vec![pad_in; H_PAD * sp2];
    let mut exp_rect = vec![0i16; H_PAD * sp2];
    let mut w_rect = vec![0i16; H_PAD * sp2];
    let row_shift_on = luts.params.softmax_row_shift;
    let mut row_shift_row = vec![0i16; H_PAD * q_pad];
    let mut is_max_rect = vec![0i16; H_PAD * sp2];
    for h in 0..H {
        for i in 0..q {
            let c = if row_shift_on { b.row_shift[h * q + i] } else { 0 };
            row_shift_row[h * q_pad + i] = c;
            let mut max_marked = false;
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                let y = h * sp2 + i * s_pad + j;
                scores_rect[y] = b.scores_q[pidx];
                let sp = b.scores_q[pidx] as i32 - c as i32;
                assert!(sp >= i16::MIN as i32, "row spread exceeds the exp domain");
                sprime_rect[y] = sp as i16;
                if row_shift_on && sp == 0 && !max_marked {
                    is_max_rect[y] = 1;
                    max_marked = true;
                }
                exp_rect[y] = b.exp_out[pidx];
                w_rect[y] = b.softmax_w[pidx];
            }
            assert!(
                !row_shift_on || max_marked,
                "row shift is not the row max (no zero s′ in row)"
            );
        }
    }

    // Recompute the FULL per-head Q·Kᵀ accumulators over the cache.
    let k_all: Vec<i16> = {
        let mut v = Vec::with_capacity(s * D);
        for seg in &b.k_cache {
            v.extend_from_slice(seg);
        }
        v
    };
    assert_eq!(k_all.len(), s * D);
    let mut acc_full = vec![0i64; H * q * s];
    let mut above_acc = Vec::with_capacity(H * sh.n_above_head());
    for h in 0..H {
        let mut qh = vec![0i16; q * DH];
        let mut kht = vec![0i16; DH * s];
        for i in 0..q {
            for l in 0..DH {
                qh[i * DH + l] = b.q_mat[i * D + h * DH + l];
            }
        }
        for j in 0..s {
            for l in 0..DH {
                kht[l * s + j] = k_all[j * D + h * DH + l];
            }
        }
        let s_full = gemm_i64(&qh, &kht, q, DH, s);
        for i in 0..q {
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                assert_eq!(
                    s_full[i * s + j], b.scores_acc[pidx],
                    "witness scores_acc inconsistent with Q·Kᵀ recompute"
                );
            }
        }
        acc_full[h * q * s..(h + 1) * q * s].copy_from_slice(&s_full);
        for i in 0..q {
            for j in sh.win(i)..s {
                above_acc.push(s_full[i * s + j]);
            }
        }
    }

    // Row tables + the P4-DEVIATION(recip-in) prover-side consistency check.
    let recip0 = luts.softmax_recip[0];
    let mut denoms_row = vec![0i64; H_PAD * q_pad];
    let mut recip_in_row = vec![0i64; H_PAD * q_pad];
    let mut recips_row = vec![recip0; H_PAD * q_pad];
    for idx in 0..H_PAD * q_pad {
        let (h, i) = (idx / q_pad, idx % q_pad);
        if h >= H || i >= q {
            denoms_row[idx] = 0;
            recip_in_row[idx] = 0;
            continue;
        }
        let denom = b.denoms[h * q + i];
        let rin = denom >> luts.params.recip_den_shift;
        assert!(rin < 1 << 16, "softmax_recip input exceeds u16 domain");
        assert_eq!(
            luts.softmax_recip[rin as usize],
            b.recips[h * q + i],
            "P4-DEVIATION(recip-in): recips inconsistent with denoms >> shift"
        );
        denoms_row[idx] = denom;
        recip_in_row[idx] = rin;
        recips_row[idx] = b.recips[h * q + i];
    }

    AttnWires {
        shape: sh,
        scores_rect,
        sprime_rect,
        row_shift_row,
        is_max_rect,
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
    /// P5 stable softmax (present iff softmax_row_shift): the authenticated
    /// row-shift table c, the is_max∘s′ ≡ 0 hadamard, and the is_max rowsum
    /// correction.
    pub row_shift_corr: Option<Vec<u64>>,
    pub hadamard2: Option<HadamardProof>,
    pub ismax_rowsum_corr: Option<Fp2>,
    // Chain, reverse dataflow order.
    pub inst_proj: BlindInstance,
    /// Stage-1 instance when shift_attn_proj > 16 (P5 chained requant,
    /// per-layer residual scales).
    pub inst_proj_stage1: Option<BlindInstance>,
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

/// Build the softmax_norm remainder column over the rect domain:
/// rem = e·rc + 2^(s−1) − w·2^s (pads: e = w = 0 ⇒ rem = 2^(s−1)).
pub(crate) fn build_rem_sn(wires: &AttnWires, s_sn: u32) -> Vec<i64> {
    let sh = wires.shape;
    let half_sn = 1i64 << (s_sn - 1);
    let mut rem_sn = vec![0i64; 1 << sh.nr()];
    for (y, r) in rem_sn.iter_mut().enumerate() {
        let e = wires.exp_rect[y] as i64;
        let rc = wires.recips_row[y >> sh.sb()] as i64;
        let w = wires.w_rect[y] as i64;
        let v = e * rc + half_sn - (w << s_sn);
        assert!((0..1i64 << s_sn).contains(&v), "softmax_norm remainder out of range");
        *r = v;
    }
    rem_sn
}

/// Build the scores remainder column: causal from the witness accumulators,
/// 2^(s−1) pads.
pub(crate) fn build_rem_sc_packed(
    scores_acc: &[i64],
    scores_q: &[i16],
    sh: BandShape,
    s_sc: u32,
) -> Vec<i64> {
    let (s_pad, sp2, caus) = (sh.s_pad(), sh.sp2(), sh.caus());
    let half_sc = 1i64 << (s_sc - 1);
    let mut rem_sc = vec![half_sc; 1 << sh.nr()];
    for h in 0..H {
        for i in 0..sh.q {
            for j in 0..sh.win(i) {
                let pidx = h * caus + sh.packed_off(i) + j;
                let r = scores_acc[pidx] + half_sc - ((scores_q[pidx] as i64) << s_sc);
                assert!((0..1i64 << s_sc).contains(&r), "scores remainder out of range");
                rem_sc[h * sp2 + i * s_pad + j] = r;
            }
        }
    }
    rem_sc
}

/// Build the qkv (rem, out) columns on the permuted padded T×4096 domain.
pub(crate) fn build_qkv_cols(wit: &LayerWitness, s_qkv: u32, t_pad: usize) -> (Vec<i64>, Vec<i16>) {
    let t = wit.t;
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
    (rem_qkv, out_qkv)
}

/// Attention phase-1 state: derived wires + every element-wise auth (LN1
/// vectors, attention row tables, above-diagonal accumulators, row-shift
/// table); all attention-side multiplicities are in the bank.
pub struct AttnP1 {
    pub wires: AttnWires,
    lv1: LnVecsP,
    ln_vec_corrs: [Vec<u64>; 4],
    denoms_fp: Vec<Fp>,
    dom_denoms: u64,
    denoms_corr: Vec<u64>,
    rin_row_fp: Vec<Fp>,
    dom_rin_row: u64,
    recip_in_corr: Vec<u64>,
    recips_fp: Vec<Fp>,
    dom_recips: u64,
    recips_corr: Vec<u64>,
    above_fp: Vec<Fp>,
    dom_above: u64,
    above_corr: Vec<u64>,
    rowshift_fp: Vec<Fp>,
    dom_rowshift: Option<u64>,
    row_shift_corr: Option<Vec<u64>>,
}

/// Attention phase 1 with caller-supplied wires (the causal-tamper test
/// mutates a copy — cheating-prover emulation).
pub(crate) fn attn_phase1_with_wires(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: AttnWires,
    cx: &mut BlockCtxP,
) -> AttnP1 {
    let t = wit.t;
    let p = luts.params;
    let sh = wires.shape;
    assert_eq!(sh.q, t, "band wires row count must match the witness");
    let rb = pad_bits(t);
    let t_pad = 1usize << rb;

    // ---- multiplicities (before ANY α) --------------------------------------
    let rem_sn = build_rem_sn(&wires, p.shift_softmax_norm);
    let mut mult_sn = vec![0u32; 1 << p.shift_softmax_norm];
    for &r in &rem_sn {
        mult_sn[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_softmax_norm), &mult_sn);
    drop(rem_sn);
    let rem_sc = build_rem_sc_packed(
        &wit.scores_acc, &wit.scores_q, sh, p.shift_scores,
    );
    let mut mult_sc = vec![0u32; 1 << p.shift_scores];
    for &r in &rem_sc {
        mult_sc[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_scores), &mult_sc);
    drop(rem_sc);
    // exp multiplicities: recount over the rect input column (the SHARED
    // wire s′ — equals scores_rect when the row shift is off).
    let mut mult_exp = vec![0u32; 1 << 16];
    for &s in &wires.sprime_rect {
        mult_exp[(s as u16) as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Exp, &mult_exp);
    // softmax_recip multiplicities over the row-table domain.
    let mut mult_recip = vec![0u32; 1 << 16];
    for &rin in &wires.recip_in_row {
        mult_recip[rin as usize] += 1;
    }
    cx.bank.add_mult(TableKey::SoftmaxRecip, &mult_recip);
    let (rem_qkv, _) = build_qkv_cols(wit, p.shift_qkv, t_pad);
    let mut mult_qkv = vec![0u32; 1 << p.shift_qkv];
    for &r in &rem_qkv {
        mult_qkv[r as usize] += 1;
    }
    cx.bank.add_mult(TableKey::Range(p.shift_qkv), &mult_qkv);
    drop(rem_qkv);
    // LN1 (first half of the shared ln_norm_requant trace) + attn_proj/av.
    assert_ln_stats(
        &wit.x_in, t, &wit.ln1_mean, &wit.ln1_var, &wit.ln1_rsqrt_in, &wit.ln1_rsqrt_out, luts,
    );
    let acc_ln1 = ln_acc_recompute(
        &wit.x_in, t, &wit.ln1_mean, &wit.ln1_rsqrt_out, &weights.ln1_gain, &weights.ln1_bias,
        p.shift_ln_norm,
    );
    add_range_mult(cx.bank, &acc_ln1, &wit.ln1_out, t, D, p.shift_ln_norm);
    let mut mult_rsq1 = vec![0u32; 1 << 16];
    for i in 0..t {
        mult_rsq1[wit.ln1_rsqrt_in[i] as usize] += 1;
    }
    mult_rsq1[0] += (t_pad - t) as u32;
    cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq1);
    add_range_mult(cx.bank, &wit.proj_acc, &wit.attn_proj_q, t, D, p.shift_attn_proj);
    add_range_mult(cx.bank, &wit.av_acc, &wit.av_q, t, D, p.shift_av);

    // ---- element-wise auth ---------------------------------------------------
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
    // P5 stable softmax: authenticate the row-shift table c (h_pad×t_pad).
    let rowshift_fp = fp_col_i16(&wires.row_shift_row);
    let (dom_rowshift, row_shift_corr) = if p.softmax_row_shift {
        let dom = cx.doms.take(1);
        let corr = auth_fp_vec_p(cx.stream, cx.tx, dom, &rowshift_fp);
        (Some(dom), Some(corr))
    } else {
        (None, None)
    };

    AttnP1 {
        wires,
        lv1,
        ln_vec_corrs,
        denoms_fp,
        dom_denoms,
        denoms_corr,
        rin_row_fp,
        dom_rin_row,
        recip_in_corr,
        recips_fp,
        dom_recips,
        recips_corr,
        above_fp,
        dom_above,
        above_corr,
        rowshift_fp,
        dom_rowshift,
        row_shift_corr,
    }
}

/// Prove the attention half (phase 2). Boundaries (x_in, K, V,
/// attn_block_out) are already authenticated by the caller at the given
/// domains; [`attn_phase1`] ran before any α. Returns the proof and the
/// weight claims `[attn_proj, c_attn]`. The c_attn claim lives on the
/// PERMUTED tensor (see [`cattn_permuted`]).
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_attn_block(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: AttnP1,
    cx: &mut BlockCtxP,
    dom_xin: u64,
    k_segs: &[CacheSegP],
    v_segs: &[CacheSegP],
    dom_abo: u64,
    biases: Option<&GemmBiases>,
) -> (AttnBlockProof, Vec<WeightClaimP>) {
    let t = wit.t;
    assert!(t >= 2, "block proof needs at least 2 rows");
    let p = luts.params;
    // Band shape: queries = the witness's t rows, cache = the segments. The
    // band's OWN K/V rows are the LAST segment (its dom also serves the qkv
    // third-slice binding).
    let sh = p1.wires.shape;
    assert_eq!(sh.q, t);
    assert_eq!(k_segs.iter().map(|g| g.rows).sum::<usize>(), sh.s());
    assert_eq!(v_segs.iter().map(|g| g.rows).sum::<usize>(), sh.s());
    let own_k = k_segs.last().unwrap();
    let own_v = v_segs.last().unwrap();
    assert_eq!(own_k.rows, t);
    assert_eq!(own_v.rows, t);
    let (dom_k, dom_v) = (own_k.dom, own_v.dom);
    let (qb, sb) = (sh.qb(), sh.sb());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let s_len = sh.s();
    let nr = sh.nr();
    let rb = qb; // row bits of the q×D domains (av/proj/qkv/LN)
    let t_pad = q_pad;
    let d_cb = pad_bits(D); // 10
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;
    let AttnP1 {
        wires,
        lv1,
        ln_vec_corrs,
        denoms_fp,
        dom_denoms,
        denoms_corr,
        rin_row_fp,
        dom_rin_row,
        recip_in_corr,
        recips_fp,
        dom_recips,
        recips_corr,
        above_fp,
        dom_above,
        above_corr,
        rowshift_fp,
        dom_rowshift,
        row_shift_corr,
    } = p1;
    let wires = &wires;

    // Rebuild the cheap derived columns (their multiplicities were bound in
    // phase 1; the columns themselves are pure witness functions).
    let rem_sn = build_rem_sn(wires, s_sn);
    let rem_sc = build_rem_sc_packed(&wit.scores_acc, &wit.scores_q, sh, s_sc);
    let (rem_qkv, out_qkv) = build_qkv_cols(wit, s_qkv, t_pad);
    let acc_ln1 = ln_acc_recompute(
        &wit.x_in, t, &wit.ln1_mean, &wit.ln1_rsqrt_out, &weights.ln1_gain, &weights.ln1_bias,
        s_ln,
    );

    // ---- 1: attn_proj range instance, closed against the residual ----------
    // (chained two-stage for s_ap > 16 — P5 per-layer residual scales).
    let site_proj =
        prove_range_site(&wit.proj_acc, &wit.attn_proj_q, t, D, s_ap, Vec::new(), cx);
    let inst_proj = &site_proj.main;
    let pt_ap = inst_proj.point.clone();
    // Residual: attn_block_out = x_in + attn_proj_q ⇒ zero row at pt_ap.
    let abo_open = open_matrix_p(cx.stream, dom_abo, &wit.attn_block_out, t, D, &pt_ap);
    let xin_open = open_matrix_p(cx.stream, dom_xin, &wit.x_in, t, D, &pt_ap);
    cx.zero.push(inst_proj.col_claims[1].value.sub(abo_open).add(xin_open));

    // ---- 2: transport → out-proj committed chained GEMM (768×768) ----------
    let pt_acc_ap = site_proj.acc_point().to_vec();
    let mut acc_ap_claim = site_proj.acc_claim;
    if let Some(b) = biases {
        acc_ap_claim =
            sub_bias_p(acc_ap_claim, &b.attn_proj, d_cb, &pt_acc_ap, t, s_ap, &mut cx.ctr_other);
    }
    let (r_j_ap, r_i_ap) = pt_acc_ap.split_at(d_cb);
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
    let inst_av = cx.inst(
        TableKey::Range(s_av),
        &[rem_av, out_av],
        &[Some(0), None],
        vec![LeafAuxClaim { col: 1, point: wire_av.point.clone(), value: wire_av.value }],
    );
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
        let (bvals, btags) = cache_fold_cols_p(cx.stream, v_segs, &eq_within, h * DH, DH);
        let mut b_folded = vec![Fp2::ZERO; s_pad];
        b_folded[..s_len].copy_from_slice(&bvals);
        let open_b = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            let mut v = Fp2::ZERO;
            let mut m = Fp2::ZERO;
            for row in 0..s_len {
                v += eq_l[row] * bvals[row];
                m += eq_l[row] * btags[row];
            }
            ProverAuthed { x: v, m }
        };
        let x_slice = &wires.w_rect[h * sp2..h * sp2 + t * s_pad];
        let cd = ChainDoms::alloc(&mut cx.doms, s_pad);
        let (gp, wire, _r_l, _tm, _cc) = prove_gemm_act_chained(
            x_slice,
            b_folded,
            t,
            s_pad,
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
            for j in sh.win(i)..s_len {
                let y = h * sp2 + i * s_pad + j;
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
    let inst_sn = cx.inst(TableKey::Range(s_sn), &[rem_sn_col, w_col], &[Some(0), None], aux_sn);
    let wacc_claim = transport_p(&inst_sn, s_sn);
    let pt_sn = inst_sn.point.clone();

    // ---- 8: hadamard w_acc = exp_rect ∘ broadcast(recips) -------------------
    // R is constant in the column (LSB) vars, so R̃ at the full sumcheck
    // point IS the recips row-table claim at the (rows ‖ head) part.
    let e_tab = lift_i16_fp2(&wires.exp_rect);
    let r_tab: Vec<Fp2> = (0..1usize << nr)
        .map(|y| Fp2::from_base(recips_fp[y >> sb]))
        .collect();
    let hd = HadamardDoms::alloc(&mut cx.doms, nr);
    let (had_proof, r_h, e_claim, r_claim) = hadamard_prove(
        &pt_sn, e_tab, r_tab, wacc_claim, &hd, cx.stream, cx.tx, &mut cx.prod, &mut cx.zero,
    );
    let rec_open = open_fp_vec_p(cx.stream, dom_recips, &recips_fp, &r_h[sb..]);
    cx.zero.push(r_claim.sub(rec_open));

    // ---- 9: denominator row sums --------------------------------------------
    // deñoms(ρ) = 2^rb·ẽxp_rect(½..½, ρ): the rect row sums equal the causal
    // ones because every non-causal exp entry is exactly 0 (pad pair).
    let rho: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; sb];
    half_pt.extend_from_slice(&rho);
    let exp_lift = lift_i16_fp2(&wires.exp_rect);
    let rs_val = eval_mle_counted(&exp_lift, &half_pt, &mut cx.ctr_other);
    let dom_rs = cx.doms.take(1);
    let fr = cx.stream.draw_fulls(dom_rs, 1)[0];
    let rowsum_corr = rs_val - fr.x;
    cx.tx.append("rowsum_correction", 16);
    let rs_auth = ProverAuthed { x: rs_val, m: fr.m };
    let den_open = open_fp_vec_p(cx.stream, dom_denoms, &denoms_fp, &rho);
    let two_sb = Fp2::from_base(Fp::new(1u64 << sb));
    cx.zero.push(den_open.sub(rs_auth.scale(two_sb)));

    // ---- 10: exp pair instance ----------------------------------------------
    // Input column = the shared s′ wire. With the row shift on, the row-max
    // soundness rows run first (P5 ledger 2026-07-06 #8): (a) hadamard with
    // public claim 0 at fresh τ₂ proves ĩs_max ∘ s̃′ ≡ 0; (b) an is_max
    // rowsum identity forces Σ_j is_max = 1 on every real row. Their claims
    // drain into the instance's s′ (col 0) and is_max (col 2) columns.
    let sc_col = fp_col_i16(&wires.sprime_rect);
    let exp_col = fp_col_i16(&wires.exp_rect);
    let mut exp_aux = vec![
        LeafAuxClaim { col: 1, point: r_h.clone(), value: e_claim },
        LeafAuxClaim { col: 1, point: half_pt.clone(), value: rs_auth },
    ];
    let mut hadamard2 = None;
    let mut ismax_rowsum_corr = None;
    if p.softmax_row_shift {
        let ismax_tab = lift_i16_fp2(&wires.is_max_rect);
        let sprime_tab = lift_i16_fp2(&wires.sprime_rect);
        let tau2: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
        let hd2 = HadamardDoms::alloc(&mut cx.doms, nr);
        let (had2, r_h2, e2_claim, r2_claim) = hadamard_prove(
            &tau2,
            ismax_tab,
            sprime_tab,
            ProverAuthed::from_public(Fp2::ZERO),
            &hd2,
            cx.stream,
            cx.tx,
            &mut cx.prod,
            &mut cx.zero,
        );
        hadamard2 = Some(had2);
        // Rowsum: ĩs_max(½..½, ρ₂)·2^rb = realmask̃(ρ₂) (public RHS).
        let rho2: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
        let mut half_pt2 = vec![half_scalar; sb];
        half_pt2.extend_from_slice(&rho2);
        let ismax_lift = lift_i16_fp2(&wires.is_max_rect);
        let rs2_val = eval_mle_counted(&ismax_lift, &half_pt2, &mut cx.ctr_other);
        let dom_rs2 = cx.doms.take(1);
        let fr2 = cx.stream.draw_fulls(dom_rs2, 1)[0];
        ismax_rowsum_corr = Some(rs2_val - fr2.x);
        cx.tx.append("ismax_rowsum_correction", 16);
        let rs2_auth = ProverAuthed { x: rs2_val, m: fr2.m };
        let eq_rho2 = eq_vec(&rho2);
        cx.ctr_other.fp2_mults += 1u64 << (qb + HEAD_BITS);
        let mut realmask = Fp2::ZERO;
        for h in 0..H {
            for i in 0..t {
                realmask += eq_rho2[h * q_pad + i];
            }
        }
        cx.zero.push(rs2_auth.scale(two_sb).sub(ProverAuthed::from_public(realmask)));
        exp_aux.push(LeafAuxClaim { col: 0, point: r_h2.clone(), value: r2_claim });
        exp_aux.push(LeafAuxClaim { col: 2, point: r_h2, value: e2_claim });
        exp_aux.push(LeafAuxClaim { col: 2, point: half_pt2, value: rs2_auth });
    }
    let ismax_col = fp_col_i16(&wires.is_max_rect);
    let (exp_cols, exp_shifts): (Vec<Vec<Fp>>, Vec<Option<u32>>) = if p.softmax_row_shift {
        (vec![sc_col.clone(), exp_col, ismax_col], vec![Some(0), Some(16), None])
    } else {
        (vec![sc_col.clone(), exp_col], vec![Some(0), Some(16)])
    };
    let inst_exp = cx.inst(TableKey::Exp, &exp_cols, &exp_shifts, exp_aux);

    // ---- 11: softmax_recip pair instance -------------------------------------
    let inst_recip = cx.inst(
        TableKey::SoftmaxRecip,
        &[rin_row_fp.clone(), recips_fp.clone()],
        &[Some(0), Some(16)],
        Vec::new(),
    );
    let rin_open = open_fp_vec_p(cx.stream, dom_rin_row, &rin_row_fp, &inst_recip.point);
    cx.zero.push(inst_recip.col_claims[0].value.sub(rin_open));
    let rec_open2 = open_fp_vec_p(cx.stream, dom_recips, &recips_fp, &inst_recip.point);
    cx.zero.push(inst_recip.col_claims[1].value.sub(rec_open2));

    // ---- 12: scores range instance + pad-mask correction ---------------------
    let rem_sc_col: Vec<Fp> = rem_sc.iter().map(|&r| Fp::new(r as u64)).collect();
    let inst_sc = cx.inst(
        TableKey::Range(s_sc),
        &[rem_sc_col, sc_col],
        &[Some(0), None],
        vec![LeafAuxClaim {
            col: 1,
            point: inst_exp.point.clone(),
            value: inst_exp.col_claims[0].value,
        }],
    );
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
            for j in 0..sh.win(i) {
                caus_sum += eq_sc[h * sp2 + i * s_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((wires.exp_pad_in() as i64) << s_sc));
    let mut wts = Vec::with_capacity(wires.above_acc.len());
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                wts.push(eq_sc[h * sp2 + i * s_pad + j]);
            }
        }
    }
    let above_open = open_weighted_p(cx.stream, dom_above, &above_fp, &wts);
    let mut acc_sc_true =
        tr_sc.sub(ProverAuthed::from_public(c_pad * padmask)).add(above_open);
    if p.softmax_row_shift {
        // The out column is s′ = s − c: add back 2^s·⟨gc, c⟩, gc_i = the
        // causal eq mass of row i (authenticated weighted opening of c).
        let mut gcw = vec![Fp2::ZERO; H_PAD * q_pad];
        for h in 0..H {
            for i in 0..t {
                for j in 0..sh.win(i) {
                    gcw[h * q_pad + i] += eq_sc[h * sp2 + i * s_pad + j];
                }
            }
        }
        let gc_open = open_weighted_p(cx.stream, dom_rowshift.unwrap(), &rowshift_fp, &gcw);
        acc_sc_true = acc_sc_true.add(gc_open.scale(Fp2::from_base(Fp::new(1u64 << s_sc))));
    }

    // ---- 13: scores head split ------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[sb + qb..]);
    let mut sc_vals = [Fp2::ZERO; H];
    for (h, val) in sc_vals.iter_mut().enumerate() {
        let mut slice = vec![Fp2::ZERO; sp2];
        for i in 0..t {
            for j in 0..s_len {
                slice[i * s_pad + j] =
                    Fp2::from_base(Fp::from_i64(wires.acc_full[h * t * s_len + i * s_len + j]));
            }
        }
        *val = eval_mle_counted(&slice, &pt_sc[..sb + qb], &mut cx.ctr_other);
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
    let eq_rj_sc = eq_vec(&pt_sc[..sb]);
    let mut gemm_qk = Vec::with_capacity(H);
    let mut aux_qkv: Vec<LeafAuxClaim> = Vec::with_capacity(H + 2);
    for h in 0..H {
        let (kvals, ktags) = cache_fold_rows_p(cx.stream, k_segs, &eq_rj_sc, h * DH, DH);
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
            s_len,
            &pt_sc[sb..sb + qb],
            &pt_sc[..sb],
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
    let inst_qkv =
        cx.inst(TableKey::Range(s_qkv), &[rem_qkv_col, out_qkv_col], &[Some(0), None], aux_qkv);
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
        &acc_ln1,
        &wit.ln1_out,
        &wit.x_in,
        dom_xin,
        &wit.ln1_mean,
        &weights.ln1_gain,
        &weights.ln1_bias,
        &lv1,
        &wire_ln1,
        cx,
    );

    let proof = AttnBlockProof {
        ln_vec_corrs,
        denoms_corr,
        recip_in_corr,
        recips_corr,
        above_corr,
        row_shift_corr,
        hadamard2,
        ismax_rowsum_corr,
        inst_proj: site_proj.main.proof,
        inst_proj_stage1: site_proj.stage1.map(|s1| s1.proof),
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

/// Attention verifier phase-1 state: cached element-wise keys.
pub struct AttnV1 {
    lvk1: LnVecsK,
    denoms_keys: Vec<Fp2>,
    rin_row_keys: Vec<Fp2>,
    recips_keys: Vec<Fp2>,
    above_keys: Vec<Fp2>,
    rowshift_keys: Option<Vec<Fp2>>,
}

/// Mirror of [`attn_phase1_with_wires`]: length checks + key expansion, in
/// the prover's exact dom/correction order.
pub(crate) fn verify_attn_phase1(
    sh: BandShape,
    luts: &Luts,
    proof: &AttnBlockProof,
    cx: &mut BlockCtxV,
) -> Option<AttnV1> {
    let p = luts.params;
    let t = sh.q;
    let t_pad = sh.q_pad();
    let n_above = H * sh.n_above_head();

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
    // P5 stable softmax: presence of the row-shift machinery must match the
    // flag; the row-shift table has the row-table length.
    let row_shift_on = p.softmax_row_shift;
    if row_shift_on != proof.row_shift_corr.is_some()
        || row_shift_on != proof.hadamard2.is_some()
        || row_shift_on != proof.ismax_rowsum_corr.is_some()
    {
        return None;
    }
    if let Some(c) = &proof.row_shift_corr {
        if c.len() != H_PAD * t_pad {
            return None;
        }
    }
    let lvk1 = expand_ln_vecs_k(cx, &proof.ln_vec_corrs);
    let dom_denoms = cx.doms.take(1);
    let denoms_keys = keys_fp_vec_v(cx.ctx, dom_denoms, &proof.denoms_corr);
    let dom_rin_row = cx.doms.take(1);
    let rin_row_keys = keys_fp_vec_v(cx.ctx, dom_rin_row, &proof.recip_in_corr);
    let dom_recips = cx.doms.take(1);
    let recips_keys = keys_fp_vec_v(cx.ctx, dom_recips, &proof.recips_corr);
    let dom_above = cx.doms.take(1);
    let above_keys = keys_fp_vec_v(cx.ctx, dom_above, &proof.above_corr);
    let rowshift_keys = proof.row_shift_corr.as_ref().map(|corr| {
        let dom = cx.doms.take(1);
        keys_fp_vec_v(cx.ctx, dom, corr)
    });
    Some(AttnV1 { lvk1, denoms_keys, rin_row_keys, recips_keys, above_keys, rowshift_keys })
}

/// Verify the attention half against the cached boundary keys (phase 2).
/// Returns the `[attn_proj, c_attn]` weight-claim (point, key) pairs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_attn_block(
    sh: BandShape,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    luts: &Luts,
    proof: &AttnBlockProof,
    v1: AttnV1,
    cx: &mut BlockCtxV,
    xin_keys: &[Fp2],
    k_segs: &[CacheSegK],
    v_segs: &[CacheSegK],
    abo_keys: &[Fp2],
    biases: Option<&GemmBiases>,
) -> Option<Vec<(Vec<Fp2>, VerifierKey)>> {
    let p = luts.params;
    let t = sh.q;
    if k_segs.iter().map(|g| g.rows).sum::<usize>() != sh.s()
        || v_segs.iter().map(|g| g.rows).sum::<usize>() != sh.s()
        || k_segs.last()?.rows != t
        || v_segs.last()?.rows != t
    {
        return None;
    }
    let k_keys = k_segs.last()?.keys;
    let v_keys = v_segs.last()?.keys;
    let (qb, sb) = (sh.qb(), sh.sb());
    let (q_pad, s_pad, sp2) = (sh.q_pad(), sh.s_pad(), sh.sp2());
    let s_len = sh.s();
    let nr = sh.nr();
    let rb = qb;
    let t_pad = q_pad;
    let d_cb = pad_bits(D);
    let s_ap = p.shift_attn_proj;
    let s_av = p.shift_av;
    let s_sn = p.shift_softmax_norm;
    let s_sc = p.shift_scores;
    let s_qkv = p.shift_qkv;
    let s_ln = p.shift_ln_norm;
    let n_above = H * sh.n_above_head();
    let row_shift_on = p.softmax_row_shift;
    let AttnV1 { lvk1, denoms_keys, rin_row_keys, recips_keys, above_keys, rowshift_keys } = v1;

    // Presence of the chained stage-1 instances must match the shifts.
    if (s_ap > 16) != proof.inst_proj_stage1.is_some()
        || (s_ln > 16) != proof.ln.inst_ln_stage1.is_some()
    {
        return None;
    }

    // ---- 1+2: attn_proj instance + residual + GEMM -------------------------
    let n_d = d_cb + rb;
    let shifts_range = [Some(0u32), None];
    let shifts_pair = [Some(0u32), Some(16u32)];
    let site_proj = verify_range_site(
        n_d,
        s_ap,
        &proof.inst_proj,
        proof.inst_proj_stage1.as_ref(),
        &[],
        cx,
    )?;
    let vp = &site_proj.main;
    let pt_ap = vp.point.clone();
    let abo_k = open_matrix_k(abo_keys, t, D, &pt_ap);
    let xin_k = open_matrix_k(xin_keys, t, D, &pt_ap);
    cx.kzero.push(vp.col_keys[1].key.sub(abo_k).add(xin_k));
    let pt_acc_ap = site_proj.acc_point().to_vec();
    let mut k_acc_ap = site_proj.acc_key;
    if let Some(b) = biases {
        k_acc_ap = sub_bias_k(k_acc_ap, &b.attn_proj, d_cb, &pt_acc_ap, t, s_ap, cx.ctx.delta);
    }
    let (r_j_ap, r_i_ap) = pt_acc_ap.split_at(d_cb);
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
    let va = cx.inst(TableKey::Range(s_av), n_d, &shifts_range, &proof.inst_av, &aux_av)?;
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
        let vkeys_row = cache_fold_cols_k(v_segs, &eq_within, h * DH, DH);
        let open_b_key = move |ptl: &[Fp2]| {
            let eq_l = eq_vec(ptl);
            VerifierKey {
                k: (0..s_len).fold(Fp2::ZERO, |s, row| s + eq_l[row] * vkeys_row[row]),
            }
        };
        let cd = ChainDoms::alloc(&mut cx.doms, s_pad);
        let (wk, _r_l) = verify_gemm_act_chained(
            t,
            s_pad,
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
            for j in sh.win(i)..s_len {
                let y = h * sp2 + i * s_pad + j;
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
    let vsn = cx.inst(TableKey::Range(s_sn), nr, &shifts_range, &proof.inst_sn, &aux_sn)?;
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
    let rec_k = open_fp_vec_k(&recips_keys, &r_h[sb..]);
    cx.kzero.push(k_r.sub(rec_k));

    // ---- 9: denominator row sums ----------------------------------------------
    let rho: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
    let half_scalar = Fp2::from_base(Fp::new(2).inv());
    let mut half_pt = vec![half_scalar; sb];
    half_pt.extend_from_slice(&rho);
    let dom_rs = cx.doms.take(1);
    let k_rs =
        VerifierKey { k: cx.ctx.expand_full_keys(dom_rs, 1)[0] + cx.ctx.delta * proof.rowsum_corr };
    let den_k = open_fp_vec_k(&denoms_keys, &rho);
    let two_sb = Fp2::from_base(Fp::new(1u64 << sb));
    cx.kzero.push(den_k.sub(k_rs.scale(two_sb)));

    // ---- 10: exp instance --------------------------------------------------------
    let mut aux_exp = vec![(1usize, r_h.clone(), k_e), (1usize, half_pt.clone(), k_rs)];
    if row_shift_on {
        // (a) is_max ∘ s′ ≡ 0 via hadamard with public claim 0 at fresh τ₂.
        let tau2: Vec<Fp2> = (0..nr).map(|_| cx.tx.challenge_fp2()).collect();
        let hd2 = HadamardDoms::alloc(&mut cx.doms, nr);
        let (r_h2, k_e2, k_r2) = hadamard_verify(
            &tau2,
            VerifierKey::from_public(Fp2::ZERO, cx.ctx.delta),
            proof.hadamard2.as_ref()?,
            &hd2,
            cx.ctx,
            cx.tx,
            &mut cx.kprod,
            &mut cx.kzero,
        )?;
        // (b) is_max rowsum = 1 per real row (public realmask RHS).
        let rho2: Vec<Fp2> = (0..qb + HEAD_BITS).map(|_| cx.tx.challenge_fp2()).collect();
        let mut half_pt2 = vec![half_scalar; sb];
        half_pt2.extend_from_slice(&rho2);
        let dom_rs2 = cx.doms.take(1);
        let k_rs2 = VerifierKey {
            k: cx.ctx.expand_full_keys(dom_rs2, 1)[0]
                + cx.ctx.delta * proof.ismax_rowsum_corr?,
        };
        let eq_rho2 = eq_vec(&rho2);
        let mut realmask = Fp2::ZERO;
        for h in 0..H {
            for i in 0..t {
                realmask += eq_rho2[h * q_pad + i];
            }
        }
        cx.kzero
            .push(k_rs2.scale(two_sb).sub(VerifierKey::from_public(realmask, cx.ctx.delta)));
        aux_exp.push((0usize, r_h2.clone(), k_r2));
        aux_exp.push((2usize, r_h2, k_e2));
        aux_exp.push((2usize, half_pt2, k_rs2));
    }
    let exp_shifts: Vec<Option<u32>> = if row_shift_on {
        vec![Some(0), Some(16), None]
    } else {
        vec![Some(0), Some(16)]
    };
    let vexp = cx.inst(TableKey::Exp, nr, &exp_shifts, &proof.inst_exp, &aux_exp)?;

    // ---- 11: softmax_recip instance -----------------------------------------------
    let vrc = cx.inst(
        TableKey::SoftmaxRecip,
        rb + HEAD_BITS,
        &shifts_pair,
        &proof.inst_recip,
        &[],
    )?;
    let rin_k = open_fp_vec_k(&rin_row_keys, &vrc.point);
    cx.kzero.push(vrc.col_keys[0].key.sub(rin_k));
    let rec_k2 = open_fp_vec_k(&recips_keys, &vrc.point);
    cx.kzero.push(vrc.col_keys[1].key.sub(rec_k2));

    // ---- 12: scores instance + pad-mask correction -----------------------------
    let aux_sc = [(1usize, vexp.point.clone(), vexp.col_keys[0].key)];
    let vsc = cx.inst(TableKey::Range(s_sc), nr, &shifts_range, &proof.inst_sc, &aux_sc)?;
    let k_tr_sc = transport_k(&vsc, s_sc, cx.ctx.delta);
    let pt_sc = vsc.point.clone();
    let exp_pad_u = (0..1usize << 16).find(|&u| luts.exp[u] == 0)?;
    let pad_in = (exp_pad_u as u16) as i16;
    let eq_sc = eq_vec(&pt_sc);
    let mut caus_sum = Fp2::ZERO;
    for h in 0..H {
        for i in 0..t {
            for j in 0..sh.win(i) {
                caus_sum += eq_sc[h * sp2 + i * s_pad + j];
            }
        }
    }
    let padmask = Fp2::ONE - caus_sum;
    let c_pad = Fp2::from_base(Fp::from_i64((pad_in as i64) << s_sc));
    let mut wts = Vec::with_capacity(n_above);
    for h in 0..H {
        for i in 0..t {
            for j in sh.win(i)..s_len {
                wts.push(eq_sc[h * sp2 + i * s_pad + j]);
            }
        }
    }
    let above_k = open_weighted_k(&above_keys, &wts);
    let mut k_acc_sc_true = k_tr_sc
        .sub(VerifierKey::from_public(c_pad * padmask, cx.ctx.delta))
        .add(above_k);
    if row_shift_on {
        let mut gcw = vec![Fp2::ZERO; H_PAD * q_pad];
        for h in 0..H {
            for i in 0..t {
                for j in 0..sh.win(i) {
                    gcw[h * q_pad + i] += eq_sc[h * sp2 + i * s_pad + j];
                }
            }
        }
        let gc_k = open_weighted_k(rowshift_keys.as_ref()?, &gcw);
        k_acc_sc_true =
            k_acc_sc_true.add(gc_k.scale(Fp2::from_base(Fp::new(1u64 << s_sc))));
    }

    // ---- 13: scores head split ---------------------------------------------------
    let eqh_sc = eq_vec(&pt_sc[sb + qb..]);
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
    let eq_rj_sc = eq_vec(&pt_sc[..sb]);
    let mut aux_qkv: Vec<(usize, Vec<Fp2>, VerifierKey)> = Vec::with_capacity(H + 2);
    for h in 0..H {
        let kkeys_col = cache_fold_rows_k(k_segs, &eq_rj_sc, h * DH, DH);
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
            s_len,
            &pt_sc[sb..sb + qb],
            &pt_sc[..sb],
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
    let vqkv =
        cx.inst(TableKey::Range(s_qkv), 12 + rb, &shifts_range, &proof.inst_qkv, &aux_qkv)?;
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
    verify_ln_chain(t, s_ln, ln1_gain, ln1_bias, xin_keys, &lvk1, &proof.ln, &wk_ln1, cx)?;

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
    /// Boundary domains for `x_in` / `ffn_block_out` (P5 model-level seam
    /// closures need to re-open these streamed MAC-authenticated matrices at
    /// fresh points).
    pub dom_xin: u64,
    pub dom_fbo: u64,
    /// K/V boundary domains (P6 decode chunks reference the prefill's — and
    /// previous chunks' — cache segments through these).
    pub dom_k: u64,
    pub dom_v: u64,
}

pub struct LayerOutV {
    /// (point, key) of the 4 weight claims, canonical order (as LayerOut).
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    /// Cached per-element keys of the `x_in` / `ffn_block_out` boundaries
    /// (P5 model-level seam closures).
    pub xin_keys: Vec<Fp2>,
    /// Cached K/V boundary keys (P6 decode chunks reference the prefill's —
    /// and previous chunks' — cache segments through these).
    pub k_keys: Vec<Fp2>,
    pub v_keys: Vec<Fp2>,
    pub fbo_keys: Vec<Fp2>,
}

/// Per-instance measured lookups for the layer (domain sizes).
fn layer_lookups(sh: BandShape) -> Vec<InstanceLookups> {
    let tp = sh.q_pad() as u64;
    let rect = sh.sp2() as u64 * H_PAD as u64;
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

/// Layer phase-1 state: boundary auths + both blocks' phase-1 states, plus
/// the saved domain cursor (phase 2 resumes it via `BlockCtxP::with_doms`).
pub struct LayerP1 {
    pub doms: Doms,
    dom_xin: u64,
    dom_k: u64,
    dom_v: u64,
    dom_abo: u64,
    dom_fbo: u64,
    xin_corr: Vec<u64>,
    k_corr: Vec<u64>,
    v_corr: Vec<u64>,
    abo_corr: Vec<u64>,
    fbo_corr: Vec<u64>,
    ffn: FfnP1,
    attn: AttnP1,
    /// Full corrs consumed by phase 1 (byte accounting continuity).
    fulls0: u64,
}

/// Layer phase 1: authenticate every boundary + element vector and
/// accumulate every multiplicity vector into the bank — all strictly before
/// any α is drawn.
pub fn prove_layer_phase1(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let wires = build_attn_wires(wit, luts);
    prove_layer_phase1_with_wires(wit, weights, luts, wires, cx)
}

/// Band phase 1: the witness is a band-packed LayerWitness (t = q rows at
/// positions t0..t0+q); `prefix` supplies the earlier phases' K data for the
/// Q·Kᵀ recompute in the wires build.
pub fn prove_layer_phase1_band(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    prefix_k: &[&[i16]],
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let t0: usize = prefix_k.iter().map(|k| k.len() / D).sum();
    let sh = BandShape { t0, q: wit.t };
    let refs = BandAttnRefs::banded(wit, sh, prefix_k);
    let wires = build_attn_wires_band(&refs, luts);
    prove_layer_phase1_with_wires(wit, weights, luts, wires, cx)
}

/// [`prove_layer_phase1`] with caller-supplied attention wires (the
/// causal-tamper test mutates a copy — cheating-prover emulation).
pub fn prove_layer_phase1_with_wires(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    wires: AttnWires,
    cx: &mut BlockCtxP,
) -> LayerP1 {
    let t = wit.t;
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

    let ffn = ffn_phase1(wit, weights, luts, cx);
    let attn = attn_phase1_with_wires(wit, weights, luts, wires, cx);

    LayerP1 {
        doms: cx.doms,
        dom_xin,
        dom_k,
        dom_v,
        dom_abo,
        dom_fbo,
        xin_corr,
        k_corr,
        v_corr,
        abo_corr,
        fbo_corr,
        ffn,
        attn,
        fulls0,
    }
}

/// Layer phase 2 (after `TableBankP::finalize`): FFN chain, then attention
/// chain, with the shared per-content αs. The caller closes the accumulated
/// Π_Prod / Π_ZeroBatch and the table bank, and resolves the 4 weight claims
/// against the PCS.
pub fn prove_layer_phase2(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: LayerP1,
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    prove_layer_phase2_band(wit, weights, luts, p1, &[], cx, biases)
}

/// Band phase 2: `prefix` are the earlier phases' authenticated K/V segments
/// (empty for the square/prefill case).
pub fn prove_layer_phase2_band(
    wit: &LayerWitness,
    weights: &LayerWeights,
    luts: &Luts,
    p1: LayerP1,
    prefix: &[KvPrefixP],
    cx: &mut BlockCtxP,
    biases: Option<&GemmBiases>,
) -> (LayerProof, LayerOut) {
    let t = wit.t;
    let t_pad = 1u64 << pad_bits(t);
    let p = luts.params;
    let sh = p1.attn.wires.shape;
    let LayerP1 {
        doms: _,
        dom_xin,
        dom_k,
        dom_v,
        dom_abo,
        dom_fbo,
        xin_corr,
        k_corr,
        v_corr,
        abo_corr,
        fbo_corr,
        ffn: ffn_p1,
        attn: attn_p1,
        fulls0,
    } = p1;

    // ---- reverse dataflow: FFN chain, then attention chain ------------------
    let (ffn, w_ffn) =
        prove_ffn_block(wit, weights, luts, ffn_p1, cx, dom_abo, dom_fbo, biases);
    let mut k_segs: Vec<CacheSegP> = prefix
        .iter()
        .map(|pf| CacheSegP { dom: pf.dom_k, rows: pf.rows, data: pf.k })
        .collect();
    k_segs.push(CacheSegP { dom: dom_k, rows: t, data: &wit.k });
    let mut v_segs: Vec<CacheSegP> = prefix
        .iter()
        .map(|pf| CacheSegP { dom: pf.dom_v, rows: pf.rows, data: pf.v })
        .collect();
    v_segs.push(CacheSegP { dom: dom_v, rows: t, data: &wit.v });
    let (attn, w_attn) = prove_attn_block(
        wit, weights, luts, attn_p1, cx, dom_xin, &k_segs, &v_segs, dom_abo, biases,
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

    // ---- byte accounting (multiplicity bytes live at the MODEL level now —
    // one vector per table content, see `TableBankP::mult_bytes`) -------------
    let n_above = (H * sh.n_above_head()) as u64;
    let bytes = LayerBytes {
        boundary: 8 * 5 * (t * D) as u64,
        mult: 0,
        ln_vectors: 8 * 8 * t_pad,
        attn_vectors: 8
            * ((3 + p.softmax_row_shift as u64) * H_PAD as u64 * t_pad + n_above),
        rounds_claims: 16 * (cx.stream.counters.full_corrs - fulls0),
    };

    let proof = LayerProof { xin_corr, k_corr, v_corr, abo_corr, fbo_corr, ffn, attn };
    let out = LayerOut {
        weight_claims,
        bytes,
        ctr_instances: cx.ctr_instances,
        ctr_other: cx.ctr_other,
        lookups: layer_lookups(sh),
        dom_xin,
        dom_fbo,
        dom_k,
        dom_v,
    };
    (proof, out)
}

/// The table-content set of one layer (from PUBLIC shift parameters) — the
/// verifier derives the model's expected content set from these.
pub fn layer_content_keys(luts: &Luts, keys: &mut std::collections::BTreeSet<TableKey>) {
    let p = luts.params;
    for s in [
        p.shift_ffn_down,
        p.shift_ffn_up,
        p.shift_ln_norm,
        p.shift_attn_proj,
        p.shift_av,
        p.shift_softmax_norm,
        p.shift_scores,
        p.shift_qkv,
    ] {
        let (k, k1) = range_keys(s);
        keys.insert(k);
        if let Some(k1) = k1 {
            keys.insert(k1);
        }
    }
    keys.insert(TableKey::Gelu);
    keys.insert(TableKey::LnRsqrt);
    keys.insert(TableKey::Exp);
    keys.insert(TableKey::SoftmaxRecip);
}

/// Layer verifier phase-1 state (mirror of [`LayerP1`]).
pub struct LayerV1 {
    pub doms: Doms,
    xin_keys: Vec<Fp2>,
    k_keys: Vec<Fp2>,
    v_keys: Vec<Fp2>,
    abo_keys: Vec<Fp2>,
    fbo_keys: Vec<Fp2>,
    lvk2: LnVecsK,
    attn: AttnV1,
}

/// Layer phase 1 (verifier): expand + cache every element-wise key, in the
/// prover's exact transcript/dom order.
pub fn verify_layer_phase1(
    t: usize,
    luts: &Luts,
    proof: &LayerProof,
    cx: &mut BlockCtxV,
) -> Option<LayerV1> {
    verify_layer_phase1_band(BandShape::square(t), luts, proof, cx)
}

/// Band phase 1 (verifier).
pub fn verify_layer_phase1_band(
    sh: BandShape,
    luts: &Luts,
    proof: &LayerProof,
    cx: &mut BlockCtxV,
) -> Option<LayerV1> {
    let t = sh.q;
    for c in [&proof.xin_corr, &proof.k_corr, &proof.v_corr, &proof.abo_corr, &proof.fbo_corr] {
        if c.len() != t * D {
            return None;
        }
    }
    let t_pad = 1usize << pad_bits(t);
    for v in &proof.ffn.ln_vec_corrs {
        if v.len() != t_pad {
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

    let lvk2 = expand_ln_vecs_k(cx, &proof.ffn.ln_vec_corrs);
    let attn = verify_attn_phase1(sh, luts, &proof.attn, cx)?;

    Some(LayerV1 { doms: cx.doms, xin_keys, k_keys, v_keys, abo_keys, fbo_keys, lvk2, attn })
}

/// Verify one full layer (phase 2, after `TableBankV::finalize`). On success
/// returns the 4 weight-claim keys (canonical order); the caller must close
/// the accumulated batches, the table bank, and bind the claims to the PCS.
#[allow(clippy::too_many_arguments)]
pub fn verify_layer_phase2(
    t: usize,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &LayerProof,
    v1: LayerV1,
    cx: &mut BlockCtxV,
    biases: Option<&GemmBiases>,
) -> Option<LayerOutV> {
    verify_layer_phase2_band(
        BandShape::square(t),
        ln1_gain,
        ln1_bias,
        ln2_gain,
        ln2_bias,
        luts,
        proof,
        v1,
        &[],
        cx,
        biases,
    )
}

/// Band phase 2 (verifier): `prefix` are the earlier phases' cached K/V key
/// segments (empty for the square/prefill case).
#[allow(clippy::too_many_arguments)]
pub fn verify_layer_phase2_band(
    sh: BandShape,
    ln1_gain: &[i16],
    ln1_bias: &[i16],
    ln2_gain: &[i16],
    ln2_bias: &[i16],
    luts: &Luts,
    proof: &LayerProof,
    v1: LayerV1,
    prefix: &[KvPrefixK],
    cx: &mut BlockCtxV,
    biases: Option<&GemmBiases>,
) -> Option<LayerOutV> {
    let t = sh.q;
    let LayerV1 { doms: _, xin_keys, k_keys, v_keys, abo_keys, fbo_keys, lvk2, attn } = v1;

    let mut w_ffn = verify_ffn_block(
        t, ln2_gain, ln2_bias, luts, &proof.ffn, &lvk2, cx, &abo_keys, &fbo_keys, biases,
    )?;
    let w_attn_res = {
        let mut k_segs: Vec<CacheSegK> =
            prefix.iter().map(|pf| CacheSegK { rows: pf.rows, keys: pf.k_keys }).collect();
        k_segs.push(CacheSegK { rows: t, keys: &k_keys });
        let mut v_segs: Vec<CacheSegK> =
            prefix.iter().map(|pf| CacheSegK { rows: pf.rows, keys: pf.v_keys }).collect();
        v_segs.push(CacheSegK { rows: t, keys: &v_keys });
        verify_attn_block(
            sh, ln1_gain, ln1_bias, luts, &proof.attn, attn, cx, &xin_keys, &k_segs, &v_segs,
            &abo_keys, biases,
        )
    };
    let mut w_attn = w_attn_res?;

    let wk_cattn = w_attn.pop()?;
    let wk_proj = w_attn.pop()?;
    let wk_up = w_ffn.pop()?;
    let wk_down = w_ffn.pop()?;
    Some(LayerOutV {
        weight_keys: vec![wk_cattn, wk_proj, wk_up, wk_down],
        xin_keys,
        k_keys,
        v_keys,
        fbo_keys,
    })
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

    /// Two-phase single-layer prover harness (phase 1 → finalize → phase 2 →
    /// per-content table closures). Returns everything the closing batches
    /// need.
    #[allow(clippy::type_complexity)]
    fn prove_layer_test(
        wit: &LayerWitness,
        w: &LayerWeights,
        luts: &Luts,
        wires: Option<AttnWires>,
        stream: &mut CorrelationStream,
        txp: &mut Transcript,
        biases: Option<&GemmBiases>,
    ) -> (
        LayerProof,
        LayerOut,
        Vec<TableCloseProof>,
        crate::logup::ProdTriples,
        Vec<ProverAuthed>,
        Doms,
    ) {
        let mut bank = TableBankP::new();
        let wires = wires.unwrap_or_else(|| build_attn_wires(wit, luts));
        let p1 = {
            let mut cx = BlockCtxP::new(stream, txp, 0, &mut bank);
            prove_layer_phase1_with_wires(wit, w, luts, wires, &mut cx)
        };
        let mut table_doms = Doms::new(layer_dom_base(240));
        bank.finalize(stream, txp, &mut table_doms);
        let mut cx = BlockCtxP::with_doms(stream, txp, p1.doms, &mut bank);
        let (proof, out) = prove_layer_phase2(wit, w, luts, p1, &mut cx, biases);
        let BlockCtxP { doms, mut prod, mut zero, mut ctr_instances, .. } = cx;
        let tables = bank.close(
            luts, stream, &mut table_doms, txp, &mut ctr_instances, &mut prod, &mut zero,
        );
        (proof, out, tables, prod, zero, doms)
    }

    /// Two-phase single-layer verifier harness (mirror of `prove_layer_test`).
    #[allow(clippy::type_complexity)]
    fn verify_layer_test(
        w: &LayerWeights,
        luts: &Luts,
        proof: &LayerProof,
        tables: &[TableCloseProof],
        vc: &mut VerifierCtx,
        txv: &mut Transcript,
        biases: Option<&GemmBiases>,
    ) -> Option<(LayerOutV, crate::logup::ProdKeyTriples, Vec<VerifierKey>, Doms)> {
        let mut pre = TableBankV::empty();
        let v1 = {
            let mut cx = BlockCtxV::new(vc, txv, 0, &mut pre);
            verify_layer_phase1(T, luts, proof, &mut cx)?
        };
        let mut expected = std::collections::BTreeSet::new();
        layer_content_keys(luts, &mut expected);
        let mut table_doms = Doms::new(layer_dom_base(240));
        let mut bankv = TableBankV::finalize(&expected, tables, vc, txv, &mut table_doms)?;
        let mut cx = BlockCtxV::with_doms(vc, txv, v1.doms, &mut bankv);
        let outv = verify_layer_phase2(
            T, &w.ln1_gain, &w.ln1_bias, &w.ln2_gain, &w.ln2_bias, luts, proof, v1, &mut cx,
            biases,
        )?;
        let BlockCtxV { doms, mut kprod, mut kzero, .. } = cx;
        bankv.close(luts, tables, vc, &mut table_doms, txv, &mut kprod, &mut kzero)?;
        Some((outv, kprod, kzero, doms))
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

        let mut wires = build_attn_wires(&wit, luts);
        tamper_wires(&mut wires);
        let (mut proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, w, luts, Some(wires), &mut stream, &mut txp, None);
        tamper_proof(&mut proof);

        let Some((outv, kprod, mut kzero, mut domsv)) =
            verify_layer_test(w, luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return false;
        };

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
        let (_proof, out, _tables, _prod, _zero, _doms) =
            prove_layer_test(wit, w, luts, None, &mut stream, &mut txp, None);

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
        // Multiplicity bytes live at the MODEL level now (one vector per
        // table CONTENT — the P6 shared-α restructure): per-layer mult = 0.
        let _ = p;
        assert_eq!(out.bytes.mult, 0);
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

        let (proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, Some(&biases));

        let (outv, kprod, mut kzero, mut domsv) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, Some(&biases))
                .expect("honest biased layer must verify");

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

    /// P5 chained requant e2e: shift_attn_proj = shift_ln_norm = 18 forces
    /// the two-stage range instances on both chained sites (per-layer
    /// residual scales / real shift_ln_norm=20). Same closing harness as the
    /// biases test.
    #[test]
    fn layer_with_chained_requant_proves_and_verifies() {
        let params = LutParams { shift_attn_proj: 18, shift_ln_norm: 18, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);
        // The chained trace really is two-stage on both sites.
        assert_eq!(wit.traces[TableId::LnNormRequant as usize].stage1_shift, 2);
        assert_eq!(wit.traces[TableId::RequantAttnProj as usize].stage1_shift, 2);

        let seed = 92u8;
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

        let (proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, None);
        assert!(proof.ffn.ln.inst_ln_stage1.is_some(), "ln2 stage-1 instance must be present");
        assert!(proof.attn.inst_proj_stage1.is_some(), "proj stage-1 instance must be present");

        let (outv, kprod, mut kzero, mut domsv) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
                .expect("honest chained layer must verify");

        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] = [
            (D, 4096, &w_perm),
            (D, D, &w.attn_proj),
            (D, DFF, &w.ffn_up),
            (DFF, D, &w.ffn_down),
        ];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            assert_eq!(outv.weight_keys[i].0, wc.point);
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
        assert!(ok_prod && ok_zero, "honest chained layer's batches must close");
    }

    /// Shared harness for the P5 stable-softmax (row-shift) tests: proves a
    /// row-shifted layer (optionally with tampered wires), verifies, closes.
    fn run_row_shift_case(
        seed: u8,
        tamper_wires: impl FnOnce(&mut AttnWires),
        tamper_proof: impl FnOnce(&mut LayerProof),
    ) -> bool {
        let params = LutParams { softmax_row_shift: true, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);
        assert!(wit.row_shift.iter().any(|&c| c != 0), "row shifts should be nontrivial");

        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 6000);
        let delta = Fp2::new(
            Fp::new(rng.gen_range(1..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        );
        let mut stream = CorrelationStream::new([seed; 32]);
        let mut vc = VerifierCtx::new([seed; 32], delta);
        let mut txp = Transcript::new([seed ^ 0x5A; 32]);
        let mut txv = Transcript::new([seed ^ 0x5A; 32]);

        let mut wires = build_attn_wires(&wit, &luts);
        assert!(wires.is_max_rect.iter().any(|&m| m == 1));
        tamper_wires(&mut wires);
        let (mut proof, out, tables, prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, Some(wires), &mut stream, &mut txp, None);
        assert!(proof.attn.row_shift_corr.is_some() && proof.attn.hadamard2.is_some());
        tamper_proof(&mut proof);

        let Some((outv, kprod, mut kzero, mut domsv)) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return false;
        };

        let w_perm = cattn_permuted(&w.c_attn);
        let dims: [(usize, usize, &[i16]); 4] = [
            (D, 4096, &w_perm),
            (D, D, &w.attn_proj),
            (D, DFF, &w.ffn_up),
            (DFF, D, &w.ffn_down),
        ];
        for (i, wc) in out.weight_claims.iter().enumerate() {
            let (k, n, mat) = dims[i];
            let tv = weight_true_eval(mat, k, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }
        // Cheating-prover emulation (wires tampers): clear nonzero zero rows.
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
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
        ok_prod && ok_zero
    }

    /// P5 stable softmax e2e: honest row-shifted layer must verify.
    #[test]
    fn layer_with_row_shift_proves_and_verifies() {
        assert!(run_row_shift_case(94, |_| {}, |_| {}), "honest row-shifted layer rejected");
    }

    /// Negative: moving an is_max marker to a position with s′ ≠ 0 (a lying
    /// row-max) must be rejected by the is_max∘s′ hadamard row.
    ///
    /// PRE-EXISTING (also fails at the P5 commit, dev profile): the library's
    /// honest-prover `debug_assert` in `hadamard_prove` fires before the
    /// proof is even produced — dev builds cannot emulate this cheating
    /// prover at the wires level (P4 deviation #10's caveat). A prover-side
    /// panic therefore counts as detection here; release builds exercise the
    /// verifier-side reject.
    #[test]
    fn layer_rejects_lying_row_max() {
        let outcome = std::panic::catch_unwind(|| run_row_shift_case(
            95,
            |wires| {
                // Find a marked row with >1 causal entries and move the 1 to
                // a neighbor whose s′ is nonzero.
                let n = wires.is_max_rect.len();
                for y in 0..n {
                    if wires.is_max_rect[y] == 1 {
                        for d in [y.wrapping_sub(1), y + 1] {
                            if d < n && wires.sprime_rect[d] != 0 {
                                wires.is_max_rect[y] = 0;
                                wires.is_max_rect[d] = 1;
                                return;
                            }
                        }
                    }
                }
                panic!("no movable is_max marker found");
            },
            |_| {},
        ));
        assert!(
            !outcome.unwrap_or(false),
            "lying row max accepted (neither prover assert nor verifier reject fired)"
        );
    }

    /// Negative: stripping the row-shift machinery from a row-shifted proof
    /// must be rejected structurally.
    #[test]
    fn layer_rejects_stripped_row_shift() {
        assert!(!run_row_shift_case(96, |_| {}, |proof| {
            proof.attn.hadamard2 = None;
        }));
    }

    /// Negative: a chained proof whose stage-1 instance is stripped (or whose
    /// stage-1 mult corr is dropped) must be rejected structurally.
    #[test]
    fn layer_rejects_stripped_chain_stage1() {
        let params = LutParams { shift_attn_proj: 18, shift_ln_norm: 18, ..LutParams::default() };
        let luts = build_luts(params);
        let w = synthetic_weights(42);
        let x = synthetic_input(43, T);
        let wit = volta_gpt2::forward_layer_with(&x, &w, None, &luts, params, T);

        let seed = 93u8;
        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let mut stream = CorrelationStream::new([seed; 32]);
        let mut vc = VerifierCtx::new([seed; 32], delta);
        let mut txp = Transcript::new([seed ^ 0x5A; 32]);
        let mut txv = Transcript::new([seed ^ 0x5A; 32]);

        let (mut proof, _out, tables, _prod, _zero, _doms) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, None);
        proof.attn.inst_proj_stage1 = None;

        let outv = verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None);
        assert!(outv.is_none(), "stripped stage-1 must be rejected");
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

        let (proof, _out, tables, _prod, mut zero, mut domsp) =
            prove_layer_test(&wit, &w, &luts, None, &mut stream, &mut txp, Some(&biases));

        // Structural checks pass (the corrections are well-formed), so the
        // mismatch must land in the closing Π_ZeroBatch: the verifier's
        // pre-bias claim reconstruction differs without `sub_bias_k`.
        let Some((_outv, _kprod, mut kzero, mut domsv)) =
            verify_layer_test(&w, &luts, &proof, &tables, &mut vc, &mut txv, None)
        else {
            return; // structural reject is also a pass for this negative test
        };
        // Cheating-prover emulation: clear the prover's nonzero zero rows so
        // the MAC keys carry the discrepancy.
        for row in zero.iter_mut() {
            row.x = Fp2::ZERO;
        }
        let _ = txp.challenge_fp2();
        let _ = txv.challenge_fp2();
        let _ = domsp.take(1);
        let _ = domsv.take(1);
        let mz = domsp.take(1);
        assert_eq!(mz, domsv.take(1));
        let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
        let _ = &mut kzero;
        assert!(!ok_zero, "verifying a biased proof with no biases must be rejected");
    }
}
