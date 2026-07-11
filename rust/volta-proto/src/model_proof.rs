//! P5 full-model prove/verify driver: 12 GPT-2 layers + 11 seam requants +
//! the embedding requant + the final LayerNorm, wired together from EXACTLY
//! the same machinery `block_proof.rs` uses per layer. No new cryptographic
//! design: every piece here is an instance of a mechanism already exercised
//! by `prove_layer`/`verify_layer` — this module only orchestrates the
//! model-level boundary stitching (seams, embedding, final LN) and collects
//! ONE model-wide Π_Prod batch + ONE model-wide Π_ZeroBatch for the caller to
//! close (mirrors `prove_layer`'s per-layer accumulator contract, just
//! scaled up).
//!
//! Layer ids (the `CorrIndex.layer` byte, one-time domain separation): layer
//! `l` uses id `l` (0..11); the seam between layer `l` and `l+1` uses id
//! `200 + l` (200..210, ≤ 11 seams); the embedding uses id 220; the final LN
//! uses id 221. These ranges are disjoint by construction.
//!
//! **Seams**: `forward_model` requants `ffn_block_out(l)` into `x_in(l+1)`
//! with a per-seam shift ≤ 16 (asserted — no chained seams in the P5
//! artifact). Shift 0 is the identity (no lookup): the two boundaries are
//! tied by an equality zero row at a fresh transcript challenge point
//! instead of a range instance.
//!
//! **Embedding**: `embed.acc = wte[tok] + wpe[pos]` requantized into
//! `embed.out`, which is ALSO `layer[0].x_in` (tied by the same equality
//! trick). The requant's ACC claim is deliberately left PENDING in
//! [`ModelOut::embed_acc_claim`] — resolving it against the true
//! `wte[tok]+wpe[pos]` MLE evaluation is the embedding-SELECTION sumcheck's
//! job, out of scope here (the e2e test below stands in for it with the
//! true evaluation directly, exactly like the per-layer tests stand in for
//! the weight-tensor PCS).
//!
//! **Final LN**: runs on the LAST row only (t=1). Its pre-LN input is the
//! last row of `layer[11].ffn_block_out`, which is already authenticated as
//! part of that T×D boundary matrix under a DIFFERENT domain (per-row use);
//! `prove_ln_chain`'s hadamard needs a domain that opens as a 1×D matrix, so
//! the last row is re-authenticated fresh (1×D, +6 KB — negligible) and tied
//! to the T×D boundary by an equality zero row at a fresh challenge point,
//! row-selected by the boolean coordinates of index `t−1`. The chain's
//! upstream `wire` claim (normally the downstream GEMM's X-wire) has no
//! natural producer here (logits are out of scope), so it is manufactured as
//! a fresh opening of the SAME `final_ln.out` boundary auth at a fresh
//! challenge point — a trivially-true "wire" the verifier reconstructs
//! identically, `corr = 0`, no correction needed. The real artifact's
//! `shift_ln_norm = 20 > 16`, so the chained (two-stage) range-site path is
//! exercised here exactly as it is per-layer.

use crate::block_proof::{
    add_range_mult, auth_ln_vecs_p, auth_matrix_rows_p, auth_matrix_rows_v, expand_ln_vecs_k,
    layer_content_keys, layer_dom_base, ln_acc_recompute, open_matrix_k, open_matrix_p,
    prove_layer_phase1, prove_layer_phase1_band, prove_layer_phase2, prove_layer_phase2_band,
    prove_ln_chain, prove_range_site, range_keys, verify_layer_phase1, verify_layer_phase1_band,
    verify_layer_phase2, verify_layer_phase2_band, verify_ln_chain, verify_range_site, BandShape,
    BlockCtxP, BlockCtxV, InstanceLookups, KvPrefixK, KvPrefixP, LayerBytes, LayerOut, LayerP1,
    LayerProof, LayerV1, LnChainProof, TableBankP, TableBankV, TableCloseProof,
};
use crate::gemm_proof::{WeightClaimP, WireKey, WireOut};
use crate::logup::{eval_mle_counted, Counters, ProdKeyTriples, ProdTriples};
use crate::logup::{Doms, TableKey};
use crate::mle::eq_vec;
use crate::sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
use crate::thaler::{fold_w, pad_bits};
use rayon::prelude::*;
use std::collections::BTreeSet;
use volta_accel::{Backend, BackendKind};
use volta_field::{Fp, Fp2};
use volta_gpt2::{BandModelWitness, Gpt2Model, ModelWitness, D, L, NPOS, VOCAB};
use volta_mac::{
    CorrCounters, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn add_bytes(a: &mut LayerBytes, b: &LayerBytes) {
    a.boundary += b.boundary;
    a.mult += b.mult;
    a.ln_vectors += b.ln_vectors;
    a.attn_vectors += b.attn_vectors;
    a.rounds_claims += b.rounds_claims;
}

fn add_counters(a: &mut Counters, b: &Counters) {
    a.fp2_mults += b.fp2_mults;
    a.base_mults += b.base_mults;
}

/// Boolean MLE coordinates of `idx` over `bits` variables, LSB first (mirrors
/// `head_bit_coords`, generalized to an arbitrary bit width — used to select
/// a single row out of a T×D boundary matrix by its row-var coordinates).
/// S̃(ρ_z) = Σ_i eq_i[i] · Π_b (tok_i bit b ? ρ_z[b] : 1 − ρ_z[b]), bits
/// LSB-first (matching the MLE var order everywhere in this codebase).
fn sel_s_eval(tokens: &[u32], eq_i: &[Fp2], rho_z: &[Fp2]) -> Fp2 {
    let mut s = Fp2::ZERO;
    for (i, &tok) in tokens.iter().enumerate() {
        let mut p = eq_i[i];
        for (b, &r) in rho_z.iter().enumerate() {
            p = p * if (tok >> b) & 1 == 1 { r } else { Fp2::ONE - r };
        }
        s += p;
    }
    s
}

/// G̃(ρ_w) for G(w) = [t0 ≤ w < t0+q]·eq(r_i, w−t0) over the wpe row vars:
/// Σ_{r<q} eq_i[r] · eq(bits(t0+r), ρ_w), bits LSB-first. The P5 prefill case
/// is the window at t0 = 0.
fn masked_eq_eval(eq_i: &[Fp2], t0: usize, q: usize, rho_w: &[Fp2]) -> Fp2 {
    let mut s = Fp2::ZERO;
    for (r, &e) in eq_i.iter().enumerate().take(q) {
        let w = t0 + r;
        let mut p = e;
        for (b, &rr) in rho_w.iter().enumerate() {
            p = p * if (w >> b) & 1 == 1 { rr } else { Fp2::ONE - rr };
        }
        s += p;
    }
    s
}

fn bit_coords(idx: usize, bits: usize) -> Vec<Fp2> {
    (0..bits).map(|b| if (idx >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO }).collect()
}

// ---------------------------------------------------------------------------
// Proof / output types
// ---------------------------------------------------------------------------

/// A seam requant range site (shift ≤ 16, single-stage — P5 seams never
/// chain). `None` at the model level means shift == 0 (identity, no
/// instance — see module docs).
pub struct SeamProof {
    pub inst: crate::logup::BlindInstance,
}

pub struct EmbedProof {
    /// Boundary auth of `embed.out` (T×d, 8 B/value — same convention as the
    /// per-layer boundaries).
    pub out_corr: Vec<u64>,
    pub inst: crate::logup::BlindInstance,
}

pub struct FinalLnProof {
    /// Boundary auth of `final_ln.out` (d values, 1×D).
    pub out_corr: Vec<u64>,
    /// Fresh re-auth of `layer[11].ffn_block_out`'s LAST ROW (1×D) — the LN
    /// chain's `x`/`dom_x` (see module docs).
    pub row_corr: Vec<u64>,
    /// LN vector corrections [mean, var, rsqrt_in, rsqrt_out] at t = 1.
    pub ln_vec_corrs: [Vec<u64>; 4],
    pub ln: LnChainProof,
}

/// Logits claim (P5-D2): the public logits vector is bound at a random ρ_v
/// and reduced by one blind matvec sumcheck over the d vars to one wte PCS
/// claim × one MAC opening of the authenticated final-LN row (Π_Prod row).
pub struct LogitsClaimProof {
    pub sc: BlindSumcheckProof,
    /// Correction authenticating the prover's w̃te(ρ_v, r_l).
    pub wte_corr: Fp2,
}

/// Embedding-selection claim (P5-D2): the pending embed-acc claim equals
/// Σ_z S(z)·w̃te(z, r_d) + w̃pe(r_d ‖ r_i ‖ 0…) with S public (tokens are
/// public); one blind sumcheck over the 16 vocab-bit vars, resolved into one
/// wte claim (zero row, S̃(ρ_z) public) and one wpe claim.
pub struct SelectionProof {
    pub sc: BlindSumcheckProof,
    pub wte_corr: Fp2,
    /// Correction authenticating the claimed masked-wpe contribution
    /// P = Σ_{i<t} eq_i[i]·w̃pe(i, r_d) (real rows only — the committed wpe
    /// block has NONZERO rows t..1023 that the embed acc does not contain,
    /// so a direct w̃pe point claim is wrong at any non-power-of-two t).
    pub p_corr: Fp2,
    /// The masked-wpe sumcheck over the block's 10 row vars:
    /// P = Σ_w G(w)·w̃pe(w, r_d) with G(w) = [w<t]·eq(r_i, w) public.
    pub sc_wpe: BlindSumcheckProof,
    pub wpe_corr: Fp2,
}

/// One decode chunk's PUBLIC data (verifier side): its band logits matrix
/// (q×VOCAB, the response's per-position logits) and the full token sequence.
pub struct ChunkPub<'a> {
    pub q: usize,
    pub logits: &'a [i64],
    pub seq: &'a [u32],
}

/// One decode chunk's witness + the full public token sequence.
pub struct ChunkRef<'a> {
    pub band: &'a BandModelWitness,
    /// Full response tokens (prompt ++ generated), len ≥ t0+q.
    pub seq: &'a [u32],
}

/// Per-chunk section ids (CorrIndex.layer bytes): base 16+32c, disjoint from
/// the prefill's (0..11, 200..210, 220, 221, 230, 231) for c < 5.
fn chunk_ids(c: usize) -> (u8, u8, u8, u8, u8, u8) {
    assert!(c < 5, "at most 5 decode chunks per response (id space)");
    let b = (16 + 32 * c) as u8;
    (b, b + 12, b + 23, b + 24, b + 25, b + 26)
}

/// One decode chunk's proof: 12 band layers + band seams + band embedding
/// (+ selection at the position window) + band final LN + the band logits
/// claim. Same machinery as the prefill sections, at t = q with the
/// cross-phase K/V cache segments.
pub struct ChunkProof {
    pub layers: Vec<LayerProof>,
    pub seams: Vec<Option<SeamProof>>,
    pub embed: EmbedProof,
    /// Boundary auth of the band final-LN output (q×D).
    pub fin_out_corr: Vec<u64>,
    /// Final-LN vector corrections [mean, var, rsqrt_in, rsqrt_out] (q_pad).
    pub fin_ln_vec_corrs: [Vec<u64>; 4],
    pub fin_ln: LnChainProof,
    pub logits: LogitsClaimProof,
    pub selection: SelectionProof,
}

pub struct ModelProof {
    pub layers: Vec<LayerProof>,
    /// Index `l` is the seam between layer `l` and `l+1` (11 entries).
    pub seams: Vec<Option<SeamProof>>,
    pub embed: EmbedProof,
    pub final_ln: FinalLnProof,
    pub logits: LogitsClaimProof,
    pub selection: SelectionProof,
    /// Decode chunks (P6), in response order.
    pub chunks: Vec<ChunkProof>,
    /// Per-content table closures (ONE multiset argument per table content
    /// per model — P6 shared-α restructure), canonical `TableKey` order.
    pub tables: Vec<TableCloseProof>,
}

pub struct ModelOut {
    /// Committed-weight claims, LAYER-MAJOR per phase (48 prefill, then 48
    /// per chunk), canonical per-layer order [c_attn, attn_proj, ffn_up,
    /// ffn_down] (as `LayerOut`).
    pub weight_claims: Vec<WeightClaimP>,
    /// Wall time of each decode chunk's phase-1 / phase-2 sections (P6
    /// flat-cost curve; empty without chunks).
    pub chunk_p1_s: Vec<f64>,
    pub chunk_p2_s: Vec<f64>,
    /// The 3 embedding-commitment claims, order [wte(logits), wte(selection),
    /// wpe]: the logits/selection sumchecks CONSUME the embed-acc claim, so
    /// nothing is left pending — these resolve against `layout_gpt2_embed`.
    pub embed_claims: Vec<WeightClaimP>,
    pub bytes: LayerBytes,
    pub ctr_instances: Counters,
    pub ctr_other: Counters,
    pub lookups: Vec<InstanceLookups>,
    pub corr_counters: CorrCounters,
}

pub struct ModelOutV {
    pub weight_keys: Vec<(Vec<Fp2>, VerifierKey)>,
    pub embed_keys: Vec<(Vec<Fp2>, VerifierKey)>,
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// The model's expected table-content set, from PUBLIC parameters (per-layer
/// shift overrides, seam shifts, embed shift). Both parties derive it.
pub fn model_content_keys(model: &Gpt2Model) -> BTreeSet<TableKey> {
    let mut keys = BTreeSet::new();
    for l in 0..L {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        layer_content_keys(&luts_l, &mut keys);
    }
    for &shift in &model.p.seam_shifts[..L - 1] {
        if shift > 0 {
            let (k, k1) = range_keys(shift);
            keys.insert(k);
            if let Some(k1) = k1 {
                keys.insert(k1);
            }
        }
    }
    let (ke, ke1) = range_keys(model.p.shift_embed as u32);
    keys.insert(ke);
    if let Some(k1) = ke1 {
        keys.insert(k1);
    }
    keys
}

/// Prove the whole model (P6 two-phase pipeline). Phase 1 binds every
/// boundary / element auth and ONE global multiplicity vector per table
/// content, model-wide; per-content αs are drawn only then; phase 2 runs all
/// chains/instances with the shared αs and closes ONE table side per
/// content. Π_Prod / Π_ZeroBatch rows accumulate into ONE pair of vectors,
/// returned to the caller for a single closure.
pub fn prove_model(
    model: &Gpt2Model,
    wit: &ModelWitness,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    prove_response(model, wit, &[], stream, tx)
}

pub fn prove_model_with_backend(
    model: &Gpt2Model,
    wit: &ModelWitness,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    prove_response_with_backend(model, wit, &[], stream, tx, backend)
}

/// Prove a full RESPONSE: the prefill (`wit`, t rows) plus any number of
/// deferred decode chunks (P6) — one two-phase session, one table bank, one
/// Π_Prod/Π_ZeroBatch closure, weight claims stacked for one PCS opening.
pub fn prove_response(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    prove_response_impl(model, wit, chunks, stream, tx, None)
}

pub fn prove_response_with_backend(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    assert_eq!(
        backend.kind(),
        BackendKind::CudaHybrid,
        "host ModelWitness proving is the hybrid gate; resident proving requires a device witness"
    );
    prove_response_impl(model, wit, chunks, stream, tx, Some(backend))
}

fn prove_response_impl(
    model: &Gpt2Model,
    wit: &ModelWitness,
    chunks: &[ChunkRef],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    mut backend: Option<&mut Backend>,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    let t = wit.t;
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut bank = TableBankP::new();
    let mut prod: ProdTriples = Vec::new();
    let mut zero: Vec<ProverAuthed> = Vec::new();
    let mut weight_claims: Vec<WeightClaimP> = Vec::with_capacity(4 * L);
    let mut bytes = LayerBytes::default();
    let mut ctr_instances = Counters::default();
    let mut ctr_other = Counters::default();
    let mut lookups: Vec<InstanceLookups> = Vec::new();
    let mut layer_proofs: Vec<LayerProof> = Vec::with_capacity(L);
    let mut boundary_doms: Vec<(u64, u64)> = Vec::with_capacity(L);
    // Prefill (dom_k, dom_v) per layer — the decode chunks' first cache segment.
    let mut layer_kv_doms: Vec<(u64, u64)> = Vec::with_capacity(L);

    let luts_for = |l: usize| {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        luts_l
    };

    macro_rules! new_block_ctx {
        ($layer:expr) => {{
            if let Some(accel) = backend.as_deref_mut() {
                BlockCtxP::with_backend(stream, tx, $layer, &mut bank, accel)
            } else {
                BlockCtxP::new(stream, tx, $layer, &mut bank)
            }
        }};
    }

    // ======================= PHASE 1 (bind everything) =====================
    let mut layer_p1s: Vec<LayerP1> = Vec::with_capacity(L);
    for l in 0..L {
        let luts_l = luts_for(l);
        let mut cx = new_block_ctx!(l as u8);
        let p1 = prove_layer_phase1(&wit.layers[l], &model.layers[l].0, &luts_l, &mut cx);
        layer_p1s.push(p1);
    }
    // Seams: multiplicity contributions only (auth-free phase 1).
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        assert!(
            shift <= 16,
            "P5 seam shifts must be ≤16 (no chained seams supported here) — got {shift} at seam {l}"
        );
        if shift > 0 {
            let acc: Vec<i64> = wit.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
            add_range_mult(&mut bank, &acc, &wit.layers[l + 1].x_in, t, D, shift);
        }
    }
    // Embedding: out boundary auth + requant multiplicities.
    let s_emb = model.p.shift_embed;
    assert!(
        s_emb > 0 && s_emb <= 16,
        "P5 embed shift must be single-stage positive ≤16 (got {s_emb}) — left-shift/chained embed not implemented here"
    );
    let s_emb = s_emb as u32;
    let (embed_doms, dom_out, out_corr) = {
        let mut cx = new_block_ctx!(220);
        let dom_out = cx.doms.take(t as u64);
        let out_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_out, &wit.embed.out, t, D);
        add_range_mult(cx.bank, &wit.embed.acc, &wit.embed.out, t, D, s_emb);
        (cx.doms, dom_out, out_corr)
    };
    // Final LN (t=2 duplicated-row batch — see the P5-DEVIATION note below).
    let t_ln = 2usize;
    let rb_ln = 1usize;
    let s_ln = model.p.lut.shift_ln_norm;
    let out2: Vec<i16> = wit.final_ln.out.iter().chain(wit.final_ln.out.iter()).copied().collect();
    let acc_ln2: Vec<i64> = wit
        .final_ln
        .norm_trace
        .inputs
        .iter()
        .chain(wit.final_ln.norm_trace.inputs.iter())
        .copied()
        .collect();
    let last_row: Vec<i16> = wit.layers[L - 1].ffn_block_out[(t - 1) * D..t * D].to_vec();
    let x2: Vec<i16> = last_row.iter().chain(last_row.iter()).copied().collect();
    let mean2 = [wit.final_ln.mean, wit.final_ln.mean];
    let var2 = [wit.final_ln.var, wit.final_ln.var];
    let rin2 = [wit.final_ln.rsqrt_in, wit.final_ln.rsqrt_in];
    let rout2 = [wit.final_ln.rsqrt_out, wit.final_ln.rsqrt_out];
    let (fl_doms, dom_out_f, out_corr_f, lv_f, ln_vec_corrs_f, dom_row, row_corr) = {
        let mut cx = new_block_ctx!(221);
        let dom_out_f = cx.doms.take(t_ln as u64);
        let out_corr_f = auth_matrix_rows_p(cx.stream, cx.tx, dom_out_f, &out2, t_ln, D);
        let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
        let (lv, ln_vec_corrs) =
            auth_ln_vecs_p(&mut cx, rb_ln, &mean2, &var2, &rin2, &rout2, rout_pad);
        let dom_row = cx.doms.take(t_ln as u64);
        let row_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_row, &x2, t_ln, D);
        add_range_mult(cx.bank, &acc_ln2, &out2, t_ln, D, s_ln);
        let mut mult_rsq = vec![0u32; 1 << 16];
        for &r in &rin2 {
            mult_rsq[r as usize] += 1;
        }
        cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);
        (cx.doms, dom_out_f, out_corr_f, lv, ln_vec_corrs, dom_row, row_corr)
    };
    // ---- decode chunks, phase 1 -------------------------------------------
    // Band layer auths + band mults; band embedding/final-LN auths + mults.
    struct ChunkP1 {
        layer_p1s: Vec<LayerP1>,
        embed_doms: Doms,
        dom_out: u64,
        out_corr: Vec<u64>,
        fin_doms: Doms,
        dom_out_f: u64,
        fin_out_corr: Vec<u64>,
        fin_lv: crate::block_proof::LnVecsP,
        fin_ln_vec_corrs: [Vec<u64>; 4],
        acc_fin: Vec<i64>,
    }
    let s_lnf = model.p.lut.shift_ln_norm;
    let mut chunk_p1s: Vec<ChunkP1> = Vec::with_capacity(chunks.len());
    let mut chunk_p1_s: Vec<f64> = Vec::with_capacity(chunks.len());
    let mut chunk_p2_s: Vec<f64> = Vec::with_capacity(chunks.len());
    {
        let mut t0_expect = t;
        for (c, ch) in chunks.iter().enumerate() {
            let c_t0 = std::time::Instant::now();
            let bw = ch.band;
            assert_eq!(bw.t0, t0_expect, "chunk {c} does not extend the cache");
            assert!(bw.q >= 2, "chunk needs at least 2 rows");
            t0_expect += bw.q;
            let (lb, _sb_id, eb, fb, _gb, _zb) = chunk_ids(c);
            let mut layer_p1s = Vec::with_capacity(L);
            for l in 0..L {
                let luts_l = luts_for(l);
                // K prefix DATA for the Q·Kᵀ wires recompute: prefill rows +
                // every earlier chunk's band rows.
                let mut prefix_k: Vec<&[i16]> = vec![&wit.layers[l].k];
                for cc in chunks[..c].iter() {
                    prefix_k.push(&cc.band.layers[l].k);
                }
                let mut cx = new_block_ctx!(lb + l as u8);
                let p1 = prove_layer_phase1_band(
                    &bw.layers[l],
                    &model.layers[l].0,
                    &luts_l,
                    &prefix_k,
                    &mut cx,
                );
                layer_p1s.push(p1);
            }
            // Band seams: multiplicity contributions only.
            for l in 0..L - 1 {
                let shift = model.p.seam_shifts[l];
                if shift > 0 {
                    let acc: Vec<i64> =
                        bw.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
                    add_range_mult(&mut bank, &acc, &bw.layers[l + 1].x_in, bw.q, D, shift);
                }
            }
            // Band embedding: out auth + requant mults.
            let (embed_doms, dom_out, out_corr) = {
                let mut cx = new_block_ctx!(eb);
                let dom_out = cx.doms.take(bw.q as u64);
                let out_corr =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_out, &bw.embed_out, bw.q, D);
                add_range_mult(cx.bank, &bw.embed_acc, &bw.embed_out, bw.q, D, s_emb);
                (cx.doms, dom_out, out_corr)
            };
            // Band final LN: out auth + LN vectors + mults (t = q).
            let (fin_doms, dom_out_f, fin_out_corr, fin_lv, fin_ln_vec_corrs, acc_fin) = {
                let mut cx = new_block_ctx!(fb);
                let dom_out_f = cx.doms.take(bw.q as u64);
                let out_corr_f =
                    auth_matrix_rows_p(cx.stream, cx.tx, dom_out_f, &bw.fin_out, bw.q, D);
                let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
                let (lv, corrs) = auth_ln_vecs_p(
                    &mut cx,
                    pad_bits(bw.q),
                    &bw.fin_mean,
                    &bw.fin_var,
                    &bw.fin_rsqrt_in,
                    &bw.fin_rsqrt_out,
                    rout_pad,
                );
                let acc_fin = ln_acc_recompute(
                    &bw.layers[L - 1].ffn_block_out,
                    bw.q,
                    &bw.fin_mean,
                    &bw.fin_rsqrt_out,
                    &model.lnf_gain,
                    &model.lnf_bias,
                    s_lnf,
                );
                add_range_mult(cx.bank, &acc_fin, &bw.fin_out, bw.q, D, s_lnf);
                let mut mult_rsq = vec![0u32; 1 << 16];
                for &r in &bw.fin_rsqrt_in {
                    mult_rsq[r as usize] += 1;
                }
                mult_rsq[0] += ((1usize << pad_bits(bw.q)) - bw.q) as u32;
                cx.bank.add_mult(TableKey::LnRsqrt, &mult_rsq);
                (cx.doms, dom_out_f, out_corr_f, lv, corrs, acc_fin)
            };
            chunk_p1s.push(ChunkP1 {
                layer_p1s,
                embed_doms,
                dom_out,
                out_corr,
                fin_doms,
                dom_out_f,
                fin_out_corr,
                fin_lv,
                fin_ln_vec_corrs,
                acc_fin,
            });
            chunk_p1_s.push(c_t0.elapsed().as_secs_f64());
        }
    }

    // End of phase 1: authenticate every content vector, draw the αs.
    debug_assert_eq!(
        bank.content_keys(),
        model_content_keys(model).into_iter().collect::<Vec<_>>(),
        "prover bank contents diverge from the public content set"
    );
    let mut table_doms = Doms::new(layer_dom_base(240));
    bank.finalize(stream, tx, &mut table_doms);
    bytes.mult += bank.mult_bytes();

    // ======================= PHASE 2 (chains + instances) ==================
    // ---- (a) 12 layers -----------------------------------------------------
    for (l, p1) in layer_p1s.into_iter().enumerate() {
        let luts_l = luts_for(l);
        let mut cx = BlockCtxP::with_doms(stream, tx, p1.doms, &mut bank);
        let (proof, out): (LayerProof, LayerOut) = prove_layer_phase2(
            &wit.layers[l],
            &model.layers[l].0,
            &luts_l,
            p1,
            &mut cx,
            Some(&model.layers[l].1),
        );
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        add_bytes(&mut bytes, &out.bytes);
        boundary_doms.push((out.dom_xin, out.dom_fbo));
        layer_kv_doms.push((out.dom_k, out.dom_v));
        lookups.extend(out.lookups);
        weight_claims.extend(out.weight_claims);
        layer_proofs.push(proof);
    }

    // ---- (c) seams -----------------------------------------------------------
    let mut seams: Vec<Option<SeamProof>> = Vec::with_capacity(L - 1);
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        let mut cx = new_block_ctx!(200 + l as u8);
        let (dom_xin_next, _) = boundary_doms[l + 1];
        let (_, dom_fbo_l) = boundary_doms[l];
        if shift > 0 {
            let acc: Vec<i64> = wit.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
            let out16 = &wit.layers[l + 1].x_in;
            let site = prove_range_site(&acc, out16, t, D, shift, Vec::new(), &mut cx);
            let out_open = open_matrix_p(cx.stream, dom_xin_next, out16, t, D, &site.main.point);
            cx.zero.push(site.main.col_claims[1].value.sub(out_open));
            let acc_open = open_matrix_p(
                cx.stream,
                dom_fbo_l,
                &wit.layers[l].ffn_block_out,
                t,
                D,
                site.acc_point(),
            );
            cx.zero.push(site.acc_claim.sub(acc_open));
            seams.push(Some(SeamProof { inst: site.main.proof }));
        } else {
            let rho: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
            let a = open_matrix_p(cx.stream, dom_fbo_l, &wit.layers[l].ffn_block_out, t, D, &rho);
            let b = open_matrix_p(cx.stream, dom_xin_next, &wit.layers[l + 1].x_in, t, D, &rho);
            cx.zero.push(a.sub(b));
            seams.push(None);
        }
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
    }

    // ---- (d) embedding ---------------------------------------------------
    let mut cx = BlockCtxP::with_doms(stream, tx, embed_doms, &mut bank);
    let site = prove_range_site(&wit.embed.acc, &wit.embed.out, t, D, s_emb, Vec::new(), &mut cx);
    let out_open = open_matrix_p(cx.stream, dom_out, &wit.embed.out, t, D, &site.main.point);
    cx.zero.push(site.main.col_claims[1].value.sub(out_open));
    let embed_acc_point = site.acc_point().to_vec();
    let embed_acc_claim = site.acc_claim;
    let (dom_xin0, _) = boundary_doms[0];
    let rho_e: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
    let e_open = open_matrix_p(cx.stream, dom_out, &wit.embed.out, t, D, &rho_e);
    let x0_open = open_matrix_p(cx.stream, dom_xin0, &wit.layers[0].x_in, t, D, &rho_e);
    cx.zero.push(e_open.sub(x0_open));
    let embed = EmbedProof { out_corr, inst: site.main.proof };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (e) final LN (last row only) --------------------------------------
    // **P5-DEVIATION(final-ln-t1)**: run on a length-2 batch where row 1 is
    // an HONEST duplicate of row 0 (the machinery needs n ≥ 2; row 1 is
    // bound to nothing downstream — not a soundness relaxation).
    let mut cx = BlockCtxP::with_doms(stream, tx, fl_doms, &mut bank);
    // Bind row 0 of the duplicated x-auth to layer[11].ffn_block_out's real
    // last row (row 1 is an honest duplicate, unbound).
    let rho_r: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
    let mut pt_row0 = rho_r.clone();
    pt_row0.extend(bit_coords(0, rb_ln));
    let row_open = open_matrix_p(cx.stream, dom_row, &x2, t_ln, D, &pt_row0);
    let (_, dom_fbo_last) = boundary_doms[L - 1];
    let mut pt_fbo = rho_r;
    pt_fbo.extend(bit_coords(t - 1, rb_t));
    let fbo_open =
        open_matrix_p(cx.stream, dom_fbo_last, &wit.layers[L - 1].ffn_block_out, t, D, &pt_fbo);
    cx.zero.push(row_open.sub(fbo_open));

    // Manufactured "wire": a fresh opening of row 0 of the SAME final_ln.out
    // auth (see module docs).
    let rho_f: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
    let mut pt_wire = rho_f.clone();
    pt_wire.extend(bit_coords(0, rb_ln));
    let wire_val = open_matrix_p(cx.stream, dom_out_f, &out2, t_ln, D, &pt_wire);
    let wire = WireOut { point: pt_wire, value: wire_val, corr: Fp2::ZERO };

    let ln = prove_ln_chain(
        t_ln,
        s_ln,
        &acc_ln2,
        &out2,
        &x2,
        dom_row,
        &mean2,
        &model.lnf_gain,
        &model.lnf_bias,
        &lv_f,
        &wire,
        &mut cx,
    );

    let final_ln =
        FinalLnProof { out_corr: out_corr_f, row_corr, ln_vec_corrs: ln_vec_corrs_f, ln };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (f) logits claim ---------------------------------------------------
    // L is PUBLIC (the model output). L̃(ρ_v) = Σ_l w̃te(ρ_v, l)·f̃in(l):
    // blind matvec sumcheck over the d vars; resolution = one wte PCS claim
    // (authenticated) × the MAC opening of the final-LN row (Π_Prod row).
    let mut embed_claims: Vec<WeightClaimP> = Vec::with_capacity(3);
    let mut cx = new_block_ctx!(230);
    let rho_v: Vec<Fp2> = (0..16).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_v = eq_vec(&rho_v);
    cx.ctr_other.fp2_mults += 1 << 16;
    let mut l_eval = Fp2::ZERO;
    for (v, &lv) in wit.logits.iter().enumerate() {
        l_eval += eq_v[v].mul_base(Fp::from_i64(lv));
    }
    cx.ctr_other.base_mults += VOCAB as u64;
    // A(l) = w̃te(ρ_v, l): row fold of wte by eq_v — the O(V·d) pass.
    let a_tab: Vec<Fp2> = {
        let wte = &model.wte;
        (0..VOCAB)
            .into_par_iter()
            .fold(
                || vec![Fp2::ZERO; 1 << d_cb],
                |mut acc, v| {
                    let e = eq_v[v];
                    let row = &wte[v * D..(v + 1) * D];
                    for (j, &w) in row.iter().enumerate() {
                        if w != 0 {
                            acc[j] += e.mul_base(Fp::from_i64(w as i64));
                        }
                    }
                    acc
                },
            )
            .reduce(
                || vec![Fp2::ZERO; 1 << d_cb],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b) {
                        *x += y;
                    }
                    a
                },
            )
    };
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    let mut fin_lift = vec![Fp2::ZERO; 1 << d_cb];
    for (j, &x) in wit.final_ln.out.iter().enumerate() {
        fin_lift[j] = Fp2::from_base(Fp::from_i64(x as i64));
    }
    let dom_lg = cx.doms.take(d_cb as u64);
    let (lg_sc, r_l, lg_claim_n) = blind_prove(
        a_tab.clone(),
        fin_lift,
        ProverAuthed::from_public(l_eval),
        cx.stream,
        dom_lg,
        cx.tx,
    );
    // f̃in(r_l): row-0 opening of the (duplicated) final-LN-out boundary.
    let mut pt_fin = r_l.clone();
    pt_fin.extend(bit_coords(0, rb_ln));
    let fin_open = open_matrix_p(cx.stream, dom_out_f, &out2, t_ln, D, &pt_fin);
    // Authenticated w̃te(ρ_v, r_l) → PCS claim on the embed commitment.
    let wv = eval_mle_counted(&a_tab, &r_l, &mut cx.ctr_other);
    let dom_wv = cx.doms.take(1);
    let mk = cx.stream.draw_fulls(dom_wv, 1)[0];
    let logits_wte_corr = wv - mk.x;
    cx.tx.append("logits_wte_correction", 16);
    let wte_auth = ProverAuthed { x: wv, m: mk.m };
    cx.prod.push((fin_open, wte_auth, lg_claim_n));
    let mut pt_wte = r_l.clone();
    pt_wte.extend(rho_v.iter().copied());
    embed_claims.push(WeightClaimP { point: pt_wte, value: wte_auth });
    let logits_proof = LogitsClaimProof { sc: lg_sc, wte_corr: logits_wte_corr };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (g) embedding selection ---------------------------------------------
    // Consumes the pending embed-acc claim: ẽmbed_acc(r_d, r_i) =
    // Σ_z S(z)·w̃te(z, r_d) + w̃pe(r_d ‖ r_i ‖ 0…), S(z) public from the
    // prompt tokens. Blind sumcheck over the 16 vocab-bit vars, closed by a
    // zero row (S̃(ρ_z) public) against one wte claim, plus one wpe claim.
    let mut cx = new_block_ctx!(231);
    let r_d = &embed_acc_point[..d_cb];
    let r_i = &embed_acc_point[d_cb..];
    let eq_i = eq_vec(r_i);
    cx.ctr_other.fp2_mults += 1u64 << r_i.len();
    let mut s_tab = vec![Fp2::ZERO; 1 << 16];
    for (i, &tok) in model.p.tokens[..t].iter().enumerate() {
        s_tab[tok as usize] += eq_i[i];
    }
    let eq_d = eq_vec(r_d);
    // W(z) = w̃te(z, r_d): column fold of wte by eq_d (the second O(V·d) pass).
    let mut w_tab = vec![Fp2::ZERO; 1 << 16];
    let folded = fold_w(&model.wte, VOCAB, D, &eq_d);
    w_tab[..folded.len()].copy_from_slice(&folded);
    cx.ctr_other.base_mults += (VOCAB * D) as u64;
    // Masked-wpe contribution P = Σ_{i<t} eq_i[i]·w̃pe(i, r_d): the embed
    // acc contains wpe rows 0..t only, while the committed block has nonzero
    // rows up to 1023 — a direct w̃pe point claim over-counts at every
    // non-power-of-two t (pad rows). P is claimed authenticated here and
    // proved by a dedicated masked sumcheck below.
    let wpe_folded = fold_w(&model.wpe, NPOS, D, &eq_d); // w̃pe(·, r_d), 2^10
    cx.ctr_other.base_mults += (NPOS * D) as u64;
    let mut p_val = Fp2::ZERO;
    for i in 0..t {
        p_val += eq_i[i] * wpe_folded[i];
    }
    cx.ctr_other.fp2_mults += t as u64;
    let dom_p = cx.doms.take(1);
    let mk_p = cx.stream.draw_fulls(dom_p, 1)[0];
    let sel_p_corr = p_val - mk_p.x;
    cx.tx.append("selection_p_correction", 16);
    let p_auth = ProverAuthed { x: p_val, m: mk_p.m };
    let claim0 = embed_acc_claim.sub(p_auth);
    let dom_sel = cx.doms.take(16);
    let (sel_sc, rho_z, sel_claim_n) =
        blind_prove(s_tab, w_tab.clone(), claim0, cx.stream, dom_sel, cx.tx);
    // S̃(ρ_z): public (tokens + eq weights).
    let s_eval = sel_s_eval(&model.p.tokens[..t], &eq_i, &rho_z);
    cx.ctr_other.fp2_mults += 16 * t as u64;
    // Authenticated w̃te(ρ_z, r_d) → second wte claim.
    let wv2 = eval_mle_counted(&w_tab, &rho_z, &mut cx.ctr_other);
    let dom_wv2 = cx.doms.take(1);
    let mk2 = cx.stream.draw_fulls(dom_wv2, 1)[0];
    let sel_wte_corr = wv2 - mk2.x;
    cx.tx.append("selection_wte_correction", 16);
    let wte2_auth = ProverAuthed { x: wv2, m: mk2.m };
    cx.zero.push(wte2_auth.scale(s_eval).sub(sel_claim_n));
    let mut pt_wte2 = r_d.to_vec();
    pt_wte2.extend(rho_z.iter().copied());
    embed_claims.push(WeightClaimP { point: pt_wte2, value: wte2_auth });
    // Masked-wpe sumcheck: P = Σ_w G(w)·w̃pe(w, r_d) over the 10 row vars,
    // G(w) = [w<t]·eq(r_i, w) public. Resolution: G̃(ρ_w) public × one wpe
    // claim at (r_d ‖ ρ_w).
    let mut g_tab = vec![Fp2::ZERO; 1 << 10];
    g_tab[..t].copy_from_slice(&eq_i[..t]);
    let dom_wpe_sc = cx.doms.take(10);
    let (wpe_sc, rho_w, wpe_claim_n) =
        blind_prove(g_tab, wpe_folded.clone(), p_auth, cx.stream, dom_wpe_sc, cx.tx);
    let g_eval = masked_eq_eval(&eq_i, 0, t, &rho_w);
    cx.ctr_other.fp2_mults += 10 * t as u64;
    let wpe_val = eval_mle_counted(&wpe_folded, &rho_w, &mut cx.ctr_other);
    let dom_wpe = cx.doms.take(1);
    let mk_wpe = cx.stream.draw_fulls(dom_wpe, 1)[0];
    let sel_wpe_corr = wpe_val - mk_wpe.x;
    cx.tx.append("selection_wpe_correction", 16);
    let wpe_auth = ProverAuthed { x: wpe_val, m: mk_wpe.m };
    cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim_n));
    let mut wpe_pt = r_d.to_vec();
    wpe_pt.extend(rho_w.iter().copied());
    embed_claims.push(WeightClaimP { point: wpe_pt, value: wpe_auth });
    let selection = SelectionProof {
        sc: sel_sc,
        wte_corr: sel_wte_corr,
        p_corr: sel_p_corr,
        sc_wpe: wpe_sc,
        wpe_corr: sel_wpe_corr,
    };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- decode chunks, phase 2 (P6) ----------------------------------------
    let mut chunk_proofs: Vec<ChunkProof> = Vec::with_capacity(chunks.len());
    // (dom_k, dom_v) of every proven segment per layer, prefill first —
    // extended chunk by chunk (the cache prefixes).
    let mut kv_doms: Vec<Vec<(u64, u64)>> = Vec::with_capacity(L);
    for l in 0..L {
        kv_doms.push(vec![(layer_kv_doms[l].0, layer_kv_doms[l].1)]);
    }
    for (c, (ch, p1c)) in chunks.iter().zip(chunk_p1s.into_iter()).enumerate() {
        let c_t0 = std::time::Instant::now();
        let bw = ch.band;
        let q = bw.q;
        let qb = pad_bits(q);
        let n_vars_qd = d_cb + qb;
        let (lb, sb_id, eb, fb, gb, zb) = chunk_ids(c);
        let mut band_boundary_doms: Vec<(u64, u64)> = Vec::with_capacity(L);
        let mut layer_proofs_c: Vec<LayerProof> = Vec::with_capacity(L);
        // ---- 12 band layers -------------------------------------------------
        for (l, p1) in p1c.layer_p1s.into_iter().enumerate() {
            let luts_l = luts_for(l);
            let prefix: Vec<KvPrefixP> = {
                let mut v = vec![KvPrefixP {
                    rows: t,
                    dom_k: kv_doms[l][0].0,
                    k: &wit.layers[l].k,
                    dom_v: kv_doms[l][0].1,
                    v: &wit.layers[l].v,
                }];
                for (cc, chc) in chunks[..c].iter().enumerate() {
                    v.push(KvPrefixP {
                        rows: chc.band.q,
                        dom_k: kv_doms[l][cc + 1].0,
                        k: &chc.band.layers[l].k,
                        dom_v: kv_doms[l][cc + 1].1,
                        v: &chc.band.layers[l].v,
                    });
                }
                v
            };
            let mut cx = BlockCtxP::with_doms(stream, tx, p1.doms, &mut bank);
            let (proof, out) = prove_layer_phase2_band(
                &bw.layers[l],
                &model.layers[l].0,
                &luts_l,
                p1,
                &prefix,
                &mut cx,
                Some(&model.layers[l].1),
            );
            let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
            prod.extend(lp);
            zero.extend(lz);
            add_counters(&mut ctr_instances, &lci);
            add_counters(&mut ctr_other, &lco);
            add_bytes(&mut bytes, &out.bytes);
            band_boundary_doms.push((out.dom_xin, out.dom_fbo));
            kv_doms[l].push((out.dom_k, out.dom_v));
            lookups.extend(out.lookups);
            weight_claims.extend(out.weight_claims);
            layer_proofs_c.push(proof);
        }
        let _ = lb;
        // ---- band seams ------------------------------------------------------
        let mut seams_c: Vec<Option<SeamProof>> = Vec::with_capacity(L - 1);
        for l in 0..L - 1 {
            let shift = model.p.seam_shifts[l];
            let mut cx = new_block_ctx!(sb_id + l as u8);
            let (dom_xin_next, _) = band_boundary_doms[l + 1];
            let (_, dom_fbo_l) = band_boundary_doms[l];
            if shift > 0 {
                let acc: Vec<i64> = bw.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
                let out16 = &bw.layers[l + 1].x_in;
                let site = prove_range_site(&acc, out16, q, D, shift, Vec::new(), &mut cx);
                let out_open =
                    open_matrix_p(cx.stream, dom_xin_next, out16, q, D, &site.main.point);
                cx.zero.push(site.main.col_claims[1].value.sub(out_open));
                let acc_open = open_matrix_p(
                    cx.stream,
                    dom_fbo_l,
                    &bw.layers[l].ffn_block_out,
                    q,
                    D,
                    site.acc_point(),
                );
                cx.zero.push(site.acc_claim.sub(acc_open));
                seams_c.push(Some(SeamProof { inst: site.main.proof }));
            } else {
                let rho: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
                let a =
                    open_matrix_p(cx.stream, dom_fbo_l, &bw.layers[l].ffn_block_out, q, D, &rho);
                let b = open_matrix_p(cx.stream, dom_xin_next, &bw.layers[l + 1].x_in, q, D, &rho);
                cx.zero.push(a.sub(b));
                seams_c.push(None);
            }
            let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
            prod.extend(lp);
            zero.extend(lz);
            add_counters(&mut ctr_instances, &lci);
            add_counters(&mut ctr_other, &lco);
        }
        let _ = eb;
        // ---- band embedding ---------------------------------------------------
        let mut cx = BlockCtxP::with_doms(stream, tx, p1c.embed_doms, &mut bank);
        let site = prove_range_site(&bw.embed_acc, &bw.embed_out, q, D, s_emb, Vec::new(), &mut cx);
        let out_open = open_matrix_p(cx.stream, p1c.dom_out, &bw.embed_out, q, D, &site.main.point);
        cx.zero.push(site.main.col_claims[1].value.sub(out_open));
        let embed_acc_point_c = site.acc_point().to_vec();
        let embed_acc_claim_c = site.acc_claim;
        let (dom_xin0, _) = band_boundary_doms[0];
        let rho_e: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
        let e_open = open_matrix_p(cx.stream, p1c.dom_out, &bw.embed_out, q, D, &rho_e);
        let x0_open = open_matrix_p(cx.stream, dom_xin0, &bw.layers[0].x_in, q, D, &rho_e);
        cx.zero.push(e_open.sub(x0_open));
        let embed_c = EmbedProof { out_corr: p1c.out_corr, inst: site.main.proof };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = fb;
        // ---- band final LN (all q rows; x = the band fbo boundary itself) -----
        let mut cx = BlockCtxP::with_doms(stream, tx, p1c.fin_doms, &mut bank);
        let (_, dom_fbo_last) = band_boundary_doms[L - 1];
        let rho_f: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
        let wire_val = open_matrix_p(cx.stream, p1c.dom_out_f, &bw.fin_out, q, D, &rho_f);
        let wire = WireOut { point: rho_f, value: wire_val, corr: Fp2::ZERO };
        let fin_ln = prove_ln_chain(
            q,
            s_lnf,
            &p1c.acc_fin,
            &bw.fin_out,
            &bw.layers[L - 1].ffn_block_out,
            dom_fbo_last,
            &bw.fin_mean,
            &model.lnf_gain,
            &model.lnf_bias,
            &p1c.fin_lv,
            &wire,
            &mut cx,
        );
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = gb;
        // ---- band logits claim (q×VOCAB public output) --------------------------
        let mut cx = new_block_ctx!(gb);
        let rho_v: Vec<Fp2> = (0..16).map(|_| cx.tx.challenge_fp2()).collect();
        let rho_q: Vec<Fp2> = (0..qb).map(|_| cx.tx.challenge_fp2()).collect();
        let eq_v = eq_vec(&rho_v);
        let eq_q = eq_vec(&rho_q);
        cx.ctr_other.fp2_mults += (1 << 16) + (1u64 << qb);
        let mut l_eval = Fp2::ZERO;
        for r in 0..q {
            let mut row_e = Fp2::ZERO;
            for (v, &lv) in bw.logits[r * VOCAB..(r + 1) * VOCAB].iter().enumerate() {
                row_e += eq_v[v].mul_base(Fp::from_i64(lv));
            }
            l_eval += eq_q[r] * row_e;
        }
        cx.ctr_other.base_mults += (q * VOCAB) as u64;
        let a_tab: Vec<Fp2> = {
            let wte = &model.wte;
            (0..VOCAB)
                .into_par_iter()
                .fold(
                    || vec![Fp2::ZERO; 1 << d_cb],
                    |mut acc, v| {
                        let e = eq_v[v];
                        let row = &wte[v * D..(v + 1) * D];
                        for (j, &w) in row.iter().enumerate() {
                            if w != 0 {
                                acc[j] += e.mul_base(Fp::from_i64(w as i64));
                            }
                        }
                        acc
                    },
                )
                .reduce(
                    || vec![Fp2::ZERO; 1 << d_cb],
                    |mut a, b| {
                        for (x, y) in a.iter_mut().zip(b) {
                            *x += y;
                        }
                        a
                    },
                )
        };
        cx.ctr_other.base_mults += (VOCAB * D) as u64;
        // B(j) = Σ_r eq_q[r]·fin[r,j] — the row fold of the band final-LN out.
        let mut b_tab = vec![Fp2::ZERO; 1 << d_cb];
        for r in 0..q {
            for j in 0..D {
                b_tab[j] += eq_q[r].mul_base(Fp::from_i64(bw.fin_out[r * D + j] as i64));
            }
        }
        cx.ctr_other.base_mults += (q * D) as u64;
        let dom_lg = cx.doms.take(d_cb as u64);
        let (lg_sc, r_l, lg_claim_n) = blind_prove(
            a_tab.clone(),
            b_tab,
            ProverAuthed::from_public(l_eval),
            cx.stream,
            dom_lg,
            cx.tx,
        );
        let mut pt_fin = r_l.clone();
        pt_fin.extend(rho_q.iter().copied());
        let fin_open = open_matrix_p(cx.stream, p1c.dom_out_f, &bw.fin_out, q, D, &pt_fin);
        let wv = eval_mle_counted(&a_tab, &r_l, &mut cx.ctr_other);
        let dom_wv = cx.doms.take(1);
        let mk = cx.stream.draw_fulls(dom_wv, 1)[0];
        let logits_wte_corr = wv - mk.x;
        cx.tx.append("logits_wte_correction", 16);
        let wte_auth = ProverAuthed { x: wv, m: mk.m };
        cx.prod.push((fin_open, wte_auth, lg_claim_n));
        let mut pt_wte = r_l.clone();
        pt_wte.extend(rho_v.iter().copied());
        embed_claims.push(WeightClaimP { point: pt_wte, value: wte_auth });
        let logits_c = LogitsClaimProof { sc: lg_sc, wte_corr: logits_wte_corr };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);
        let _ = zb;
        // ---- band embedding selection (window at t0) ---------------------------
        let mut cx = new_block_ctx!(zb);
        let r_d = &embed_acc_point_c[..d_cb];
        let r_i = &embed_acc_point_c[d_cb..];
        let eq_i = eq_vec(r_i);
        cx.ctr_other.fp2_mults += 1u64 << r_i.len();
        let band_tokens = &ch.seq[bw.t0..bw.t0 + q];
        let mut s_tab = vec![Fp2::ZERO; 1 << 16];
        for (r, &tok) in band_tokens.iter().enumerate() {
            s_tab[tok as usize] += eq_i[r];
        }
        let eq_d = eq_vec(r_d);
        let mut w_tab = vec![Fp2::ZERO; 1 << 16];
        let folded = fold_w(&model.wte, VOCAB, D, &eq_d);
        w_tab[..folded.len()].copy_from_slice(&folded);
        cx.ctr_other.base_mults += (VOCAB * D) as u64;
        let wpe_folded = fold_w(&model.wpe, NPOS, D, &eq_d);
        cx.ctr_other.base_mults += (NPOS * D) as u64;
        let mut p_val = Fp2::ZERO;
        for r in 0..q {
            p_val += eq_i[r] * wpe_folded[bw.t0 + r];
        }
        cx.ctr_other.fp2_mults += q as u64;
        let dom_p = cx.doms.take(1);
        let mk_p = cx.stream.draw_fulls(dom_p, 1)[0];
        let sel_p_corr = p_val - mk_p.x;
        cx.tx.append("selection_p_correction", 16);
        let p_auth = ProverAuthed { x: p_val, m: mk_p.m };
        let claim0 = embed_acc_claim_c.sub(p_auth);
        let dom_sel = cx.doms.take(16);
        let (sel_sc, rho_z, sel_claim_n) =
            blind_prove(s_tab, w_tab.clone(), claim0, cx.stream, dom_sel, cx.tx);
        let s_eval = sel_s_eval(band_tokens, &eq_i, &rho_z);
        cx.ctr_other.fp2_mults += 16 * q as u64;
        let wv2 = eval_mle_counted(&w_tab, &rho_z, &mut cx.ctr_other);
        let dom_wv2 = cx.doms.take(1);
        let mk2 = cx.stream.draw_fulls(dom_wv2, 1)[0];
        let sel_wte_corr = wv2 - mk2.x;
        cx.tx.append("selection_wte_correction", 16);
        let wte2_auth = ProverAuthed { x: wv2, m: mk2.m };
        cx.zero.push(wte2_auth.scale(s_eval).sub(sel_claim_n));
        let mut pt_wte2 = r_d.to_vec();
        pt_wte2.extend(rho_z.iter().copied());
        embed_claims.push(WeightClaimP { point: pt_wte2, value: wte2_auth });
        let mut g_tab = vec![Fp2::ZERO; 1 << 10];
        for r in 0..q {
            g_tab[bw.t0 + r] = eq_i[r];
        }
        let dom_wpe_sc = cx.doms.take(10);
        let (wpe_sc, rho_w, wpe_claim_n) =
            blind_prove(g_tab, wpe_folded.clone(), p_auth, cx.stream, dom_wpe_sc, cx.tx);
        let g_eval = masked_eq_eval(&eq_i, bw.t0, q, &rho_w);
        cx.ctr_other.fp2_mults += 10 * q as u64;
        let wpe_val = eval_mle_counted(&wpe_folded, &rho_w, &mut cx.ctr_other);
        let dom_wpe = cx.doms.take(1);
        let mk_wpe = cx.stream.draw_fulls(dom_wpe, 1)[0];
        let sel_wpe_corr = wpe_val - mk_wpe.x;
        cx.tx.append("selection_wpe_correction", 16);
        let wpe_auth = ProverAuthed { x: wpe_val, m: mk_wpe.m };
        cx.zero.push(wpe_auth.scale(g_eval).sub(wpe_claim_n));
        let mut wpe_pt = r_d.to_vec();
        wpe_pt.extend(rho_w.iter().copied());
        embed_claims.push(WeightClaimP { point: wpe_pt, value: wpe_auth });
        let selection_c = SelectionProof {
            sc: sel_sc,
            wte_corr: sel_wte_corr,
            p_corr: sel_p_corr,
            sc_wpe: wpe_sc,
            wpe_corr: sel_wpe_corr,
        };
        let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
        prod.extend(lp);
        zero.extend(lz);
        add_counters(&mut ctr_instances, &lci);
        add_counters(&mut ctr_other, &lco);

        chunk_proofs.push(ChunkProof {
            layers: layer_proofs_c,
            seams: seams_c,
            embed: embed_c,
            fin_out_corr: p1c.fin_out_corr,
            fin_ln_vec_corrs: p1c.fin_ln_vec_corrs,
            fin_ln,
            logits: logits_c,
            selection: selection_c,
        });
        chunk_p2_s.push(c_t0.elapsed().as_secs_f64());
    }

    // ---- (h) per-content table sides (ONE multiset argument per content) ----
    let tables = if let Some(accel) = backend.as_deref_mut() {
        bank.close_with_backend(
            &model.luts,
            stream,
            &mut table_doms,
            tx,
            &mut ctr_instances,
            &mut prod,
            &mut zero,
            accel,
        )
    } else {
        bank.close(
            &model.luts,
            stream,
            &mut table_doms,
            tx,
            &mut ctr_instances,
            &mut prod,
            &mut zero,
        )
    };

    let proof = ModelProof {
        layers: layer_proofs,
        seams,
        embed,
        final_ln,
        logits: logits_proof,
        selection,
        chunks: chunk_proofs,
        tables,
    };
    let out = ModelOut {
        weight_claims,
        chunk_p1_s,
        chunk_p2_s,
        embed_claims,
        bytes,
        ctr_instances,
        ctr_other,
        lookups,
        corr_counters: stream.counters,
    };
    (proof, out, prod, zero)
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify the whole model (mirror of [`prove_model`], same order throughout).
pub fn verify_model(
    model: &Gpt2Model,
    t: usize,
    logits: &[i64],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    verify_response(model, t, logits, &[], proof, vc, tx)
}

/// Verify a full response (prefill + decode chunks — mirror of
/// [`prove_response`], same order throughout). Also runs the PUBLIC greedy
/// checks: every sampled token must be the argmax of the logits row at the
/// previous position.
pub fn verify_response(
    model: &Gpt2Model,
    t: usize,
    logits: &[i64],
    chunks: &[ChunkPub],
    proof: &ModelProof,
    vc: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(ModelOutV, ProdKeyTriples, Vec<VerifierKey>)> {
    if proof.layers.len() != L || proof.seams.len() != L - 1 {
        return None;
    }
    if proof.chunks.len() != chunks.len() {
        return None;
    }
    // ---- PUBLIC greedy checks + chunk shape checks --------------------------
    {
        let mut t0 = t;
        for (c, ch) in chunks.iter().enumerate() {
            if ch.q < 2
                || ch.logits.len() != ch.q * VOCAB
                || ch.seq.len() < t0 + ch.q
                || ch.seq[..t] != model.p.tokens[..t]
            {
                return None;
            }
            // Token at position t0 is sampled by the PREVIOUS position's
            // logits: the prefill's last row for c = 0 (r = -1), the chunk's
            // own rows after.
            if c == 0 {
                let am = (0..VOCAB).max_by_key(|&v| logits[v])?;
                if ch.seq[t] != am as u32 {
                    return None;
                }
            }
            for r in 0..ch.q {
                let nxt = t0 + r + 1;
                if nxt < ch.seq.len() {
                    let row = &ch.logits[r * VOCAB..(r + 1) * VOCAB];
                    let am = (0..VOCAB).max_by_key(|&v| row[v])?;
                    if ch.seq[nxt] != am as u32 {
                        return None;
                    }
                }
            }
            t0 += ch.q;
        }
    }
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut kprod: ProdKeyTriples = Vec::new();
    let mut kzero: Vec<VerifierKey> = Vec::new();
    let mut weight_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(4 * L);
    // (xin_keys, fbo_keys) per layer.
    let mut boundary_keys: Vec<(Vec<Fp2>, Vec<Fp2>)> = Vec::with_capacity(L);
    // Prefill (k_keys, v_keys) per layer — the chunks' first cache segment.
    let mut boundary_kv_keys: Vec<(Vec<Fp2>, Vec<Fp2>)> = Vec::with_capacity(L);

    let luts_for = |l: usize| {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        luts_l
    };

    // ======================= PHASE 1 mirror (key expansion) =================
    let mut pre_bank = TableBankV::empty();
    let mut layer_v1s: Vec<LayerV1> = Vec::with_capacity(L);
    for l in 0..L {
        let luts_l = luts_for(l);
        let mut cx = BlockCtxV::new(vc, tx, l as u8, &mut pre_bank);
        let v1 = verify_layer_phase1(t, &luts_l, &proof.layers[l], &mut cx)?;
        layer_v1s.push(v1);
    }
    let s_emb = model.p.shift_embed;
    if !(s_emb > 0 && s_emb <= 16) {
        return None;
    }
    let s_emb = s_emb as u32;
    let (embed_doms, out_keys) = {
        let mut cx = BlockCtxV::new(vc, tx, 220, &mut pre_bank);
        let dom_out = cx.doms.take(t as u64);
        if proof.embed.out_corr.len() != t * D {
            return None;
        }
        let out_keys = auth_matrix_rows_v(cx.ctx, dom_out, &proof.embed.out_corr, t, D);
        (cx.doms, out_keys)
    };
    let t_ln = 2usize;
    let rb_ln = 1usize;
    let (fl_doms, out_keys_f, lvk_f, row_keys) = {
        let mut cx = BlockCtxV::new(vc, tx, 221, &mut pre_bank);
        if proof.final_ln.out_corr.len() != t_ln * D
            || proof.final_ln.row_corr.len() != t_ln * D
            || proof.final_ln.ln_vec_corrs.iter().any(|c| c.len() != t_ln)
        {
            return None;
        }
        let dom_out_f = cx.doms.take(t_ln as u64);
        let out_keys_f = auth_matrix_rows_v(cx.ctx, dom_out_f, &proof.final_ln.out_corr, t_ln, D);
        let lvk = expand_ln_vecs_k(&mut cx, &proof.final_ln.ln_vec_corrs);
        let dom_row = cx.doms.take(t_ln as u64);
        let row_keys = auth_matrix_rows_v(cx.ctx, dom_row, &proof.final_ln.row_corr, t_ln, D);
        (cx.doms, out_keys_f, lvk, row_keys)
    };
    // ---- decode chunks, phase 1 mirror --------------------------------------
    struct ChunkV1 {
        layer_v1s: Vec<LayerV1>,
        embed_doms: Doms,
        out_keys: Vec<Fp2>,
        fin_doms: Doms,
        fin_out_keys: Vec<Fp2>,
        fin_lvk: crate::block_proof::LnVecsK,
    }
    let mut chunk_v1s: Vec<ChunkV1> = Vec::with_capacity(chunks.len());
    {
        let mut t0 = t;
        for (c, (ch, cp)) in chunks.iter().zip(&proof.chunks).enumerate() {
            let q = ch.q;
            let sh_c = BandShape { t0, q };
            let q_pad = 1usize << pad_bits(q);
            let (lb, _sb_id, eb, fb, _gb, _zb) = chunk_ids(c);
            let mut layer_v1s = Vec::with_capacity(L);
            for l in 0..L {
                let luts_l = luts_for(l);
                let mut cx = BlockCtxV::new(vc, tx, lb + l as u8, &mut pre_bank);
                let v1 = verify_layer_phase1_band(sh_c, &luts_l, &cp.layers[l], &mut cx)?;
                layer_v1s.push(v1);
            }
            let (embed_doms, out_keys) = {
                let mut cx = BlockCtxV::new(vc, tx, eb, &mut pre_bank);
                let dom_out = cx.doms.take(q as u64);
                if cp.embed.out_corr.len() != q * D {
                    return None;
                }
                let out_keys = auth_matrix_rows_v(cx.ctx, dom_out, &cp.embed.out_corr, q, D);
                (cx.doms, out_keys)
            };
            let (fin_doms, fin_out_keys, fin_lvk) = {
                let mut cx = BlockCtxV::new(vc, tx, fb, &mut pre_bank);
                if cp.fin_out_corr.len() != q * D
                    || cp.fin_ln_vec_corrs.iter().any(|cc| cc.len() != q_pad)
                {
                    return None;
                }
                let dom_out_f = cx.doms.take(q as u64);
                let out_keys_f = auth_matrix_rows_v(cx.ctx, dom_out_f, &cp.fin_out_corr, q, D);
                let lvk = expand_ln_vecs_k(&mut cx, &cp.fin_ln_vec_corrs);
                (cx.doms, out_keys_f, lvk)
            };
            chunk_v1s.push(ChunkV1 {
                layer_v1s,
                embed_doms,
                out_keys,
                fin_doms,
                fin_out_keys,
                fin_lvk,
            });
            t0 += q;
        }
    }

    // End of phase 1: expand the per-content multiplicity keys against the
    // PUBLIC expected content set, draw the shared αs.
    let expected = model_content_keys(model);
    let mut table_doms = Doms::new(layer_dom_base(240));
    let mut bank = TableBankV::finalize(&expected, &proof.tables, vc, tx, &mut table_doms)?;

    // ======================= PHASE 2 mirror =================================
    // ---- (a) 12 layers -----------------------------------------------------
    for (l, v1) in layer_v1s.into_iter().enumerate() {
        let luts_l = luts_for(l);
        let w = &model.layers[l].0;
        let b = &model.layers[l].1;
        let mut cx = BlockCtxV::with_doms(vc, tx, v1.doms, &mut bank);
        let out = verify_layer_phase2(
            t,
            &w.ln1_gain,
            &w.ln1_bias,
            &w.ln2_gain,
            &w.ln2_bias,
            &luts_l,
            &proof.layers[l],
            v1,
            &mut cx,
            Some(b),
        )?;
        let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
        kprod.extend(lkp);
        kzero.extend(lkz);
        weight_keys.extend(out.weight_keys);
        boundary_keys.push((out.xin_keys, out.fbo_keys));
        boundary_kv_keys.push((out.k_keys, out.v_keys));
    }

    // ---- (c) seams -----------------------------------------------------------
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        if shift > 16 {
            return None;
        }
        let mut cx = BlockCtxV::new(vc, tx, 200 + l as u8, &mut bank);
        match (&proof.seams[l], shift > 0) {
            (Some(sp), true) => {
                let site = verify_range_site(n_vars_td, shift, &sp.inst, None, &[], &mut cx)?;
                let out_k = open_matrix_k(&boundary_keys[l + 1].0, t, D, &site.main.point);
                cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
                let acc_open_k = open_matrix_k(&boundary_keys[l].1, t, D, site.acc_point());
                cx.kzero.push(site.acc_key.sub(acc_open_k));
            }
            (None, false) => {
                let rho: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
                let a = open_matrix_k(&boundary_keys[l].1, t, D, &rho);
                let b = open_matrix_k(&boundary_keys[l + 1].0, t, D, &rho);
                cx.kzero.push(a.sub(b));
            }
            _ => return None,
        }
        let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
        kprod.extend(lkp);
        kzero.extend(lkz);
    }

    // ---- (d) embedding ---------------------------------------------------
    let mut cx = BlockCtxV::with_doms(vc, tx, embed_doms, &mut bank);
    let site = verify_range_site(n_vars_td, s_emb, &proof.embed.inst, None, &[], &mut cx)?;
    let out_k = open_matrix_k(&out_keys, t, D, &site.main.point);
    cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
    let embed_acc_point = site.acc_point().to_vec();
    let embed_acc_key = site.acc_key;
    let rho_e: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
    let e_k = open_matrix_k(&out_keys, t, D, &rho_e);
    let x0_k = open_matrix_k(&boundary_keys[0].0, t, D, &rho_e);
    cx.kzero.push(e_k.sub(x0_k));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (e) final LN (mirrors the t=2 duplicated-row fix) -----------------
    let mut cx = BlockCtxV::with_doms(vc, tx, fl_doms, &mut bank);
    let rho_r: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
    let mut pt_row0 = rho_r.clone();
    pt_row0.extend(bit_coords(0, rb_ln));
    let row_k = open_matrix_k(&row_keys, t_ln, D, &pt_row0);
    let mut pt_fbo = rho_r;
    pt_fbo.extend(bit_coords(t - 1, rb_t));
    let fbo_k = open_matrix_k(&boundary_keys[L - 1].1, t, D, &pt_fbo);
    cx.kzero.push(row_k.sub(fbo_k));

    let rho_f: Vec<Fp2> = (0..d_cb).map(|_| cx.tx.challenge_fp2()).collect();
    let mut pt_wire = rho_f;
    pt_wire.extend(bit_coords(0, rb_ln));
    let wire_key = open_matrix_k(&out_keys_f, t_ln, D, &pt_wire);
    let wk = WireKey { point: pt_wire, key: wire_key };

    let s_ln = model.p.lut.shift_ln_norm;
    verify_ln_chain(
        t_ln,
        s_ln,
        &model.lnf_gain,
        &model.lnf_bias,
        &row_keys,
        &lvk_f,
        &proof.final_ln.ln,
        &wk,
        &mut cx,
    )?;
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (f) logits claim (mirror) -----------------------------------------
    let mut embed_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(3);
    let mut cx = BlockCtxV::new(vc, tx, 230, &mut bank);
    let rho_v: Vec<Fp2> = (0..16).map(|_| cx.tx.challenge_fp2()).collect();
    let eq_v = eq_vec(&rho_v);
    let mut l_eval = Fp2::ZERO;
    for (v, &lv) in logits.iter().enumerate() {
        if v >= VOCAB {
            return None;
        }
        l_eval += eq_v[v].mul_base(Fp::from_i64(lv));
    }
    let dom_lg = cx.doms.take(d_cb as u64);
    let (r_l, k_claim_n) = blind_verify(
        d_cb,
        VerifierKey::from_public(l_eval, cx.ctx.delta),
        &proof.logits.sc,
        cx.ctx,
        dom_lg,
        cx.tx,
    )?;
    let mut pt_fin = r_l.clone();
    pt_fin.extend(bit_coords(0, rb_ln));
    let k_fin = open_matrix_k(&out_keys_f, t_ln, D, &pt_fin);
    let dom_wv = cx.doms.take(1);
    let k_wte = VerifierKey {
        k: cx.ctx.expand_full_keys(dom_wv, 1)[0] + cx.ctx.delta * proof.logits.wte_corr,
    };
    cx.kprod.push((k_fin, k_wte, k_claim_n));
    let mut pt_wte = r_l;
    pt_wte.extend(rho_v.iter().copied());
    embed_keys.push((pt_wte, k_wte));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (g) embedding selection (mirror) ----------------------------------
    let mut cx = BlockCtxV::new(vc, tx, 231, &mut bank);
    let r_d = &embed_acc_point[..d_cb];
    let r_i = &embed_acc_point[d_cb..];
    let eq_i = eq_vec(r_i);
    let dom_p = cx.doms.take(1);
    let k_p = VerifierKey {
        k: cx.ctx.expand_full_keys(dom_p, 1)[0] + cx.ctx.delta * proof.selection.p_corr,
    };
    let k_claim0 = embed_acc_key.sub(k_p);
    let dom_sel = cx.doms.take(16);
    let (rho_z, k_sel_n) = blind_verify(16, k_claim0, &proof.selection.sc, cx.ctx, dom_sel, cx.tx)?;
    let s_eval = sel_s_eval(&model.p.tokens[..t], &eq_i, &rho_z);
    let dom_wv2 = cx.doms.take(1);
    let k_wte2 = VerifierKey {
        k: cx.ctx.expand_full_keys(dom_wv2, 1)[0] + cx.ctx.delta * proof.selection.wte_corr,
    };
    cx.kzero.push(k_wte2.scale(s_eval).sub(k_sel_n));
    let mut pt_wte2 = r_d.to_vec();
    pt_wte2.extend(rho_z.iter().copied());
    embed_keys.push((pt_wte2, k_wte2));
    // Masked-wpe sumcheck (mirror): P = Σ_w G(w)·w̃pe(w, r_d).
    let dom_wpe_sc = cx.doms.take(10);
    let (rho_w, k_wpe_n) =
        blind_verify(10, k_p, &proof.selection.sc_wpe, cx.ctx, dom_wpe_sc, cx.tx)?;
    let g_eval = masked_eq_eval(&eq_i, 0, t, &rho_w);
    let dom_wpe = cx.doms.take(1);
    let k_wpe = VerifierKey {
        k: cx.ctx.expand_full_keys(dom_wpe, 1)[0] + cx.ctx.delta * proof.selection.wpe_corr,
    };
    cx.kzero.push(k_wpe.scale(g_eval).sub(k_wpe_n));
    let mut wpe_pt = r_d.to_vec();
    wpe_pt.extend(rho_w.iter().copied());
    embed_keys.push((wpe_pt, k_wpe));
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- decode chunks, phase 2 mirror (P6) ----------------------------------
    // Prefill boundary keys are the chunks' first cache segment; each proven
    // chunk extends the per-layer segment lists.
    let mut kv_keys: Vec<Vec<(Vec<Fp2>, Vec<Fp2>)>> = Vec::with_capacity(L);
    for bk in &boundary_kv_keys {
        kv_keys.push(vec![(bk.0.clone(), bk.1.clone())]);
    }
    {
        let mut t0 = t;
        for (c, (ch, (cp, v1c))) in
            chunks.iter().zip(proof.chunks.iter().zip(chunk_v1s.into_iter())).enumerate()
        {
            let q = ch.q;
            let qb = pad_bits(q);
            let sh_c = BandShape { t0, q };
            let n_vars_qd = d_cb + qb;
            let (_lb, sb_id, _eb, _fb, gb, zb) = chunk_ids(c);
            let mut band_boundary_keys: Vec<(Vec<Fp2>, Vec<Fp2>)> = Vec::with_capacity(L);
            // ---- 12 band layers ------------------------------------------------
            for (l, v1) in v1c.layer_v1s.into_iter().enumerate() {
                let luts_l = luts_for(l);
                let w = &model.layers[l].0;
                let b = &model.layers[l].1;
                let prefix: Vec<KvPrefixK> = kv_keys[l]
                    .iter()
                    .map(|(kk, vk)| KvPrefixK { rows: kk.len() / D, k_keys: kk, v_keys: vk })
                    .collect();
                let mut cx = BlockCtxV::with_doms(vc, tx, v1.doms, &mut bank);
                let out = verify_layer_phase2_band(
                    sh_c,
                    &w.ln1_gain,
                    &w.ln1_bias,
                    &w.ln2_gain,
                    &w.ln2_bias,
                    &luts_l,
                    &cp.layers[l],
                    v1,
                    &prefix,
                    &mut cx,
                    Some(b),
                )?;
                let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
                kprod.extend(lkp);
                kzero.extend(lkz);
                weight_keys.extend(out.weight_keys);
                band_boundary_keys.push((out.xin_keys, out.fbo_keys));
                kv_keys[l].push((out.k_keys, out.v_keys));
            }
            // ---- band seams -----------------------------------------------------
            for l in 0..L - 1 {
                let shift = model.p.seam_shifts[l];
                if shift > 16 {
                    return None;
                }
                let mut cx = BlockCtxV::new(vc, tx, sb_id + l as u8, &mut bank);
                match (&cp.seams[l], shift > 0) {
                    (Some(sp), true) => {
                        let site =
                            verify_range_site(n_vars_qd, shift, &sp.inst, None, &[], &mut cx)?;
                        let out_k =
                            open_matrix_k(&band_boundary_keys[l + 1].0, q, D, &site.main.point);
                        cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
                        let acc_open_k =
                            open_matrix_k(&band_boundary_keys[l].1, q, D, site.acc_point());
                        cx.kzero.push(site.acc_key.sub(acc_open_k));
                    }
                    (None, false) => {
                        let rho: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
                        let a = open_matrix_k(&band_boundary_keys[l].1, q, D, &rho);
                        let b = open_matrix_k(&band_boundary_keys[l + 1].0, q, D, &rho);
                        cx.kzero.push(a.sub(b));
                    }
                    _ => return None,
                }
                let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
                kprod.extend(lkp);
                kzero.extend(lkz);
            }
            // ---- band embedding -------------------------------------------------
            let mut cx = BlockCtxV::with_doms(vc, tx, v1c.embed_doms, &mut bank);
            let site = verify_range_site(n_vars_qd, s_emb, &cp.embed.inst, None, &[], &mut cx)?;
            let out_k = open_matrix_k(&v1c.out_keys, q, D, &site.main.point);
            cx.kzero.push(site.main.col_keys[1].key.sub(out_k));
            let embed_acc_point_c = site.acc_point().to_vec();
            let embed_acc_key_c = site.acc_key;
            let rho_e: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
            let e_k = open_matrix_k(&v1c.out_keys, q, D, &rho_e);
            let x0_k = open_matrix_k(&band_boundary_keys[0].0, q, D, &rho_e);
            cx.kzero.push(e_k.sub(x0_k));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band final LN ---------------------------------------------------
            let mut cx = BlockCtxV::with_doms(vc, tx, v1c.fin_doms, &mut bank);
            let rho_f: Vec<Fp2> = (0..n_vars_qd).map(|_| cx.tx.challenge_fp2()).collect();
            let wire_key = open_matrix_k(&v1c.fin_out_keys, q, D, &rho_f);
            let wk = WireKey { point: rho_f, key: wire_key };
            let s_lnf = model.p.lut.shift_ln_norm;
            verify_ln_chain(
                q,
                s_lnf,
                &model.lnf_gain,
                &model.lnf_bias,
                &band_boundary_keys[L - 1].1,
                &v1c.fin_lvk,
                &cp.fin_ln,
                &wk,
                &mut cx,
            )?;
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band logits claim ----------------------------------------------
            let mut cx = BlockCtxV::new(vc, tx, gb, &mut bank);
            let rho_v: Vec<Fp2> = (0..16).map(|_| cx.tx.challenge_fp2()).collect();
            let rho_q: Vec<Fp2> = (0..qb).map(|_| cx.tx.challenge_fp2()).collect();
            let eq_v = eq_vec(&rho_v);
            let eq_q = eq_vec(&rho_q);
            let mut l_eval = Fp2::ZERO;
            for r in 0..q {
                let mut row_e = Fp2::ZERO;
                for (v, &lv) in ch.logits[r * VOCAB..(r + 1) * VOCAB].iter().enumerate() {
                    row_e += eq_v[v].mul_base(Fp::from_i64(lv));
                }
                l_eval += eq_q[r] * row_e;
            }
            let dom_lg = cx.doms.take(d_cb as u64);
            let (r_l, k_claim_n) = blind_verify(
                d_cb,
                VerifierKey::from_public(l_eval, cx.ctx.delta),
                &cp.logits.sc,
                cx.ctx,
                dom_lg,
                cx.tx,
            )?;
            let mut pt_fin = r_l.clone();
            pt_fin.extend(rho_q.iter().copied());
            let k_fin = open_matrix_k(&v1c.fin_out_keys, q, D, &pt_fin);
            let dom_wv = cx.doms.take(1);
            let k_wte = VerifierKey {
                k: cx.ctx.expand_full_keys(dom_wv, 1)[0] + cx.ctx.delta * cp.logits.wte_corr,
            };
            cx.kprod.push((k_fin, k_wte, k_claim_n));
            let mut pt_wte = r_l;
            pt_wte.extend(rho_v.iter().copied());
            embed_keys.push((pt_wte, k_wte));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);
            // ---- band embedding selection ------------------------------------------
            let mut cx = BlockCtxV::new(vc, tx, zb, &mut bank);
            let r_d = &embed_acc_point_c[..d_cb];
            let r_i = &embed_acc_point_c[d_cb..];
            let eq_i = eq_vec(r_i);
            let band_tokens = &ch.seq[t0..t0 + q];
            let dom_p = cx.doms.take(1);
            let k_p = VerifierKey {
                k: cx.ctx.expand_full_keys(dom_p, 1)[0] + cx.ctx.delta * cp.selection.p_corr,
            };
            let k_claim0 = embed_acc_key_c.sub(k_p);
            let dom_sel = cx.doms.take(16);
            let (rho_z, k_sel_n) =
                blind_verify(16, k_claim0, &cp.selection.sc, cx.ctx, dom_sel, cx.tx)?;
            let s_eval = sel_s_eval(band_tokens, &eq_i, &rho_z);
            let dom_wv2 = cx.doms.take(1);
            let k_wte2 = VerifierKey {
                k: cx.ctx.expand_full_keys(dom_wv2, 1)[0] + cx.ctx.delta * cp.selection.wte_corr,
            };
            cx.kzero.push(k_wte2.scale(s_eval).sub(k_sel_n));
            let mut pt_wte2 = r_d.to_vec();
            pt_wte2.extend(rho_z.iter().copied());
            embed_keys.push((pt_wte2, k_wte2));
            let dom_wpe_sc = cx.doms.take(10);
            let (rho_w, k_wpe_n) =
                blind_verify(10, k_p, &cp.selection.sc_wpe, cx.ctx, dom_wpe_sc, cx.tx)?;
            let g_eval = masked_eq_eval(&eq_i, t0, q, &rho_w);
            let dom_wpe = cx.doms.take(1);
            let k_wpe = VerifierKey {
                k: cx.ctx.expand_full_keys(dom_wpe, 1)[0] + cx.ctx.delta * cp.selection.wpe_corr,
            };
            cx.kzero.push(k_wpe.scale(g_eval).sub(k_wpe_n));
            let mut wpe_pt = r_d.to_vec();
            wpe_pt.extend(rho_w.iter().copied());
            embed_keys.push((wpe_pt, k_wpe));
            let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
            kprod.extend(lkp);
            kzero.extend(lkz);

            t0 += q;
        }
    }

    // ---- (h) per-content table sides (mirror) -------------------------------
    bank.close(&model.luts, &proof.tables, vc, &mut table_doms, tx, &mut kprod, &mut kzero)?;

    Some((ModelOutV { weight_keys, embed_keys }, kprod, kzero))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_proof::{cattn_permuted, layer_dom_base};
    use crate::logup::Doms;
    use crate::mle::eval_mle;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use crate::thaler::fold_w;
    use rand::{Rng, SeedableRng};
    use volta_gpt2::{forward_model, load_model, DFF};
    use volta_mac::zero_batch_exchange;

    fn weights_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights")
    }

    fn weight_true_eval(w: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
        let cb = pad_bits(n);
        let b = fold_w(w, k, n, &eq_vec(&point[..cb]));
        eval_mle(&b, &point[cb..])
    }

    /// P6 response e2e: prefill (t=12) + ONE decode chunk (q=4) proven in one
    /// two-phase session — band layers over the cross-phase KV cache, band
    /// seams/embed/selection/final-LN/logits, stacked weight claims, one
    /// Π_Prod + one Π_ZeroBatch. Greedy argmax checks run inside
    /// `verify_response`.
    #[test]
    fn response_e2e_on_frozen_artifact() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping response_e2e_on_frozen_artifact: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, n_gen) = (12usize, 4usize);
        let wit0 = volta_gpt2::forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> =
            wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (gen, _rows) = volta_gpt2::generate(&model, &mut cache, &wit0.logits, t, n_gen);
        let mut seq: Vec<u32> = model.p.tokens[..t].to_vec();
        seq.extend_from_slice(&gen);
        let full = volta_gpt2::forward_model_tokens(&model, &seq);
        let band = volta_gpt2::band_model_witness(&model, &full, t);

        let seed = 201u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 9000);
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

        let chunks_p = [ChunkRef { band: &band, seq: &seq }];
        let (proof, out, prod, mut zero) =
            prove_response(&model, &wit0, &chunks_p, &mut stream, &mut txp);

        let chunks_v = [ChunkPub { q: n_gen, logits: &band.logits, seq: &seq }];
        let (outv, kprod, mut kzero) =
            verify_response(&model, t, &wit0.logits, &chunks_v, &proof, &mut vc, &mut txv)
                .expect("response proof must verify");

        // Stacked weight claims: 48 prefill + 48 chunk, layer-major.
        assert_eq!(out.weight_claims.len(), 8 * L, "expected 96 stacked weight claims");
        assert_eq!(outv.weight_keys.len(), 8 * L);
        for idx in 0..8 * L {
            let l = (idx / 4) % L;
            let k4 = idx % 4;
            let w = &model.layers[l].0;
            let w_perm = cattn_permuted(&w.c_attn);
            let dims: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &w_perm),
                (D, D, &w.attn_proj),
                (D, DFF, &w.ffn_up),
                (DFF, D, &w.ffn_down),
            ];
            let (kk, n, mat) = dims[k4];
            let wc = &out.weight_claims[idx];
            assert_eq!(outv.weight_keys[idx].0, wc.point, "weight point mismatch at {idx}");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.weight_keys[idx].1.sub(VerifierKey::from_public(tv, delta)));
        }
        // Embedding claims: 3 prefill + 3 chunk, order [wte, wte, wpe] each.
        assert_eq!(out.embed_claims.len(), 6);
        assert_eq!(outv.embed_keys.len(), 6);
        for (i, wc) in out.embed_claims.iter().enumerate() {
            let (kk, n, mat): (usize, usize, &[i16]) =
                if i % 3 == 2 { (NPOS, D, &model.wpe) } else { (VOCAB, D, &model.wte) };
            assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n), "embed claim {i} point len");
            assert_eq!(outv.embed_keys[i].0, wc.point, "embed claim {i} point mismatch");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.embed_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        let mut domsp = Doms::new(layer_dom_base(255));
        let mut domsv = Doms::new(layer_dom_base(255));
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
        assert!(ok_prod && ok_zero, "response e2e must verify");
        eprintln!("response_e2e: t={t} q={n_gen} tokens {gen:?} accepted");
    }

    /// P6 anti-replay smoke: reusing another position's cache-row corrections
    /// (prefill rows replayed as the chunk's K rows, or two chunk K rows
    /// swapped) must be rejected — domains are position-separated.
    #[test]
    fn response_rejects_kv_replay() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping response_rejects_kv_replay: artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        let (t, n_gen) = (12usize, 4usize);
        let wit0 = volta_gpt2::forward_model(&model, t);
        let kv: Vec<(&[i16], &[i16])> =
            wit0.layers.iter().map(|lw| (lw.k.as_slice(), lw.v.as_slice())).collect();
        let mut cache = volta_gpt2::KvCache::from_prefill(&kv, t);
        let (gen, _rows) = volta_gpt2::generate(&model, &mut cache, &wit0.logits, t, n_gen);
        let mut seq: Vec<u32> = model.p.tokens[..t].to_vec();
        seq.extend_from_slice(&gen);
        let full = volta_gpt2::forward_model_tokens(&model, &seq);
        let band = volta_gpt2::band_model_witness(&model, &full, t);

        for case in 0..2 {
            let seed = 205 + case as u8;
            let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
            let mut stream = CorrelationStream::new([seed; 32]);
            let mut vc = VerifierCtx::new([seed; 32], delta);
            let mut txp = Transcript::new([seed ^ 0x5A; 32]);
            let mut txv = Transcript::new([seed ^ 0x5A; 32]);
            let chunks_p = [ChunkRef { band: &band, seq: &seq }];
            let (mut proof, _out, prod, mut zero) =
                prove_response(&model, &wit0, &chunks_p, &mut stream, &mut txp);
            match case {
                0 => {
                    // Replay: the chunk's K corrections replaced by the
                    // prefill's first q rows (cache-row reuse across phases).
                    let q = n_gen;
                    proof.chunks[0].layers[0]
                        .k_corr
                        .copy_from_slice(&proof.layers[0].k_corr[..q * D]);
                }
                _ => {
                    // Position swap within the chunk's own K rows.
                    let (a, b) = (0usize, 1usize);
                    for j in 0..D {
                        proof.chunks[0].layers[0].k_corr.swap(a * D + j, b * D + j);
                    }
                }
            }
            let chunks_v = [ChunkPub { q: n_gen, logits: &band.logits, seq: &seq }];
            let Some((_outv, kprod, kzero)) =
                verify_response(&model, t, &wit0.logits, &chunks_v, &proof, &mut vc, &mut txv)
            else {
                continue; // structural reject also counts
            };
            // Cheating-prover emulation: clear the prover's zero rows so the
            // MAC keys carry the discrepancy, then close the batches.
            for row in zero.iter_mut() {
                row.x = Fp2::ZERO;
            }
            let mut domsp = Doms::new(layer_dom_base(255));
            let mut domsv = Doms::new(layer_dom_base(255));
            let chi = txp.challenge_fp2();
            assert_eq!(chi, txv.challenge_fp2());
            let md = domsp.take(1);
            assert_eq!(md, domsv.take(1));
            let mask = stream.draw_fulls(md, 1)[0];
            let k_mask = vc.expand_full_keys(md, 1)[0];
            let pp = prod_batch_prover(&prod, chi, mask, &mut txp);
            let _ = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
            let mz = domsp.take(1);
            assert_eq!(mz, domsv.take(1));
            let ok_zero = zero_batch_exchange(&zero, &kzero, &mut stream, &mut vc, mz, &mut txp);
            assert!(!ok_zero, "K/V replay case {case} accepted");
        }
    }

    #[test]
    fn model_e2e_on_frozen_artifact() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping model_e2e_on_frozen_artifact: frozen artifact not present");
            return;
        }
        let model = load_model(&dir).unwrap();
        // Non-power-of-two on purpose: the padded-row/masked-wpe class of
        // bugs (selection identity) is invisible at t == t_pad.
        let t = 20usize;
        let wit = forward_model(&model, t);

        let seed = 200u8;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 9000);
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

        let t0 = std::time::Instant::now();
        let (proof, out, prod, mut zero) = prove_model(&model, &wit, &mut stream, &mut txp);
        let dt = t0.elapsed();

        let (outv, kprod, mut kzero) =
            verify_model(&model, t, &wit.logits, &proof, &mut vc, &mut txv)
                .expect("model proof must verify");

        // Resolve all 48 weight claims (layer-major, canonical per-layer order).
        assert_eq!(out.weight_claims.len(), 4 * L, "expected 48 weight claims");
        assert_eq!(outv.weight_keys.len(), 4 * L);
        for l in 0..L {
            let w = &model.layers[l].0;
            let w_perm = cattn_permuted(&w.c_attn);
            let dims: [(usize, usize, &[i16]); 4] = [
                (D, 4096, &w_perm),
                (D, D, &w.attn_proj),
                (D, DFF, &w.ffn_up),
                (DFF, D, &w.ffn_down),
            ];
            for k in 0..4 {
                let idx = 4 * l + k;
                let (kk, n, mat) = dims[k];
                let wc = &out.weight_claims[idx];
                assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n));
                assert_eq!(
                    outv.weight_keys[idx].0, wc.point,
                    "weight point mismatch across parties, layer {l} slot {k}"
                );
                let tv = weight_true_eval(mat, kk, n, &wc.point);
                zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
                kzero.push(outv.weight_keys[idx].1.sub(VerifierKey::from_public(tv, delta)));
            }
        }

        // Resolve the 3 embedding-commitment claims [wte(logits),
        // wte(selection), wpe] against the true tensor evaluations —
        // test-only stand-in for the real `layout_gpt2_embed` PCS opening.
        assert_eq!(out.embed_claims.len(), 3);
        assert_eq!(outv.embed_keys.len(), 3);
        let embed_dims: [(usize, usize, &[i16]); 3] =
            [(VOCAB, D, &model.wte), (VOCAB, D, &model.wte), (NPOS, D, &model.wpe)];
        for (i, wc) in out.embed_claims.iter().enumerate() {
            let (kk, n, mat) = embed_dims[i];
            assert_eq!(wc.point.len(), pad_bits(kk) + pad_bits(n), "embed claim {i} point len");
            assert_eq!(outv.embed_keys[i].0, wc.point, "embed claim {i} point mismatch");
            let tv = weight_true_eval(mat, kk, n, &wc.point);
            zero.push(wc.value.sub(ProverAuthed::from_public(tv)));
            kzero.push(outv.embed_keys[i].1.sub(VerifierKey::from_public(tv, delta)));
        }

        // Close ONE Π_Prod batch + ONE Π_ZeroBatch over ALL accumulated rows.
        let mut domsp = Doms::new(layer_dom_base(255));
        let mut domsv = Doms::new(layer_dom_base(255));
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
        assert!(ok_prod && ok_zero, "model e2e must verify");

        eprintln!(
            "model_e2e_on_frozen_artifact: t={t} prove_model wall time = {:.3} s",
            dt.as_secs_f64()
        );
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_full_model_proof_matches_cpu_and_fault_is_rejected() {
        let dir = weights_dir();
        if !dir.join("gpt2s-q.bin").exists() {
            eprintln!("skipping CUDA full-proof differential: artifact not present");
            return;
        }
        let mut backend = match Backend::cuda_hybrid() {
            Ok(gpu) => gpu,
            Err(e) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping CUDA full-proof differential: {e}");
                return;
            }
            Err(e) => panic!("CUDA required: {e}"),
        };
        let model = load_model(&dir).unwrap();
        let t = 3usize; // non-power-of-two padding path
        let wit = forward_model(&model, t);
        let pcg_seed = [231; 32];
        let tx_seed = [0xA7; 32];

        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let (_cpu_proof, cpu_out, cpu_prod, cpu_zero) =
            prove_model(&model, &wit, &mut cpu_stream, &mut cpu_tx);

        backend.begin_measurement().unwrap();
        let mut gpu_stream = CorrelationStream::new(pcg_seed);
        let mut gpu_tx = Transcript::new(tx_seed);
        let (gpu_proof, gpu_out, gpu_prod, gpu_zero) =
            prove_model_with_backend(&model, &wit, &mut gpu_stream, &mut gpu_tx, &mut backend);
        assert_eq!(gpu_out.weight_claims, cpu_out.weight_claims);
        assert_eq!(gpu_out.embed_claims, cpu_out.embed_claims);
        assert_eq!(gpu_out.bytes, cpu_out.bytes);
        assert_eq!(gpu_out.ctr_instances, cpu_out.ctr_instances);
        assert_eq!(gpu_out.ctr_other, cpu_out.ctr_other);
        assert_eq!(gpu_out.lookups, cpu_out.lookups);
        assert_eq!(gpu_out.corr_counters, cpu_out.corr_counters);
        assert_eq!(gpu_prod, cpu_prod);
        assert_eq!(gpu_zero, cpu_zero);
        assert_eq!(gpu_stream.counters, cpu_stream.counters);
        assert_eq!(gpu_tx.ledger(), cpu_tx.ledger());
        assert_eq!(gpu_tx.total_bytes(), cpu_tx.total_bytes());

        let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
        let mut vc = VerifierCtx::new(pcg_seed, delta);
        let mut txv = Transcript::new(tx_seed);
        assert!(verify_model(&model, t, &wit.logits, &gpu_proof, &mut vc, &mut txv).is_some());

        // Same persistent context, fresh protocol correlations. The proof
        // outputs stay deterministic, then a device-derived boundary
        // correction is faulted and the final zero batch must reject it.
        let mut fault_stream = CorrelationStream::new(pcg_seed);
        let mut fault_tx = Transcript::new(tx_seed);
        let (mut fault_proof, fault_out, fault_prod, fault_zero) =
            prove_model_with_backend(&model, &wit, &mut fault_stream, &mut fault_tx, &mut backend);
        assert_eq!(fault_out.weight_claims, gpu_out.weight_claims);
        assert_eq!(fault_out.embed_claims, gpu_out.embed_claims);
        assert_eq!(fault_prod, gpu_prod);
        assert_eq!(fault_zero, gpu_zero);
        fault_proof.layers[0].k_corr[0] ^= 1;

        let mut fault_vc = VerifierCtx::new(pcg_seed, delta);
        let mut fault_txv = Transcript::new(tx_seed);
        if let Some((_outv, kprod, kzero)) =
            verify_model(&model, t, &wit.logits, &fault_proof, &mut fault_vc, &mut fault_txv)
        {
            let mut domsp = Doms::new(layer_dom_base(255));
            let mut domsv = Doms::new(layer_dom_base(255));
            let chi = fault_tx.challenge_fp2();
            assert_eq!(chi, fault_txv.challenge_fp2());
            let md = domsp.take(1);
            assert_eq!(md, domsv.take(1));
            let mask = fault_stream.draw_fulls(md, 1)[0];
            let k_mask = fault_vc.expand_full_keys(md, 1)[0];
            let pp = prod_batch_prover(&fault_prod, chi, mask, &mut fault_tx);
            let _ = prod_batch_verify(&kprod, k_mask, delta, chi, &pp);
            let mz = domsp.take(1);
            assert_eq!(mz, domsv.take(1));
            assert!(
                !zero_batch_exchange(
                    &fault_zero,
                    &kzero,
                    &mut fault_stream,
                    &mut fault_vc,
                    mz,
                    &mut fault_tx,
                ),
                "faulted CUDA-derived correction was accepted"
            );
        }
        let stats = backend.finish_measurement().unwrap();
        assert!(stats.operation(volta_accel::Operation::Logup).calls > 0);
        assert!(stats.operation(volta_accel::Operation::Logup).cpu_residual_ns > 0);
    }
}
