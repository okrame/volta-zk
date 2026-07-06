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
    auth_ln_vecs_p, auth_matrix_rows_p, auth_matrix_rows_v, auth_mult_p, close_mult_p,
    close_mult_v, expand_ln_vecs_k, keys_mult_v, open_matrix_k,
    open_matrix_p, prove_layer, prove_ln_chain, prove_range_site, range_mult, range_mult_chained,
    verify_layer, verify_ln_chain, verify_range_site, BlockCtxP, BlockCtxV, InstanceLookups,
    LayerBytes, LayerOut, LayerProof, LnChainProof,
};
use crate::gemm_proof::{WeightClaimP, WireKey, WireOut};
use crate::logup::{eval_mle_counted, Counters, ProdKeyTriples, ProdTriples};
use crate::mle::eq_vec;
use crate::sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
use crate::thaler::{fold_w, pad_bits};
use rayon::prelude::*;
use volta_field::{Fp, Fp2};
use volta_gpt2::{Gpt2Model, ModelWitness, D, L, NPOS, VOCAB};
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

/// G̃(ρ_w) for G(w) = [w<t]·eq(r_i, w) over 10 row vars: Σ_{i<t} eq_i[i] ·
/// eq(bits(i), ρ_w), bits LSB-first.
fn masked_eq_eval(eq_i: &[Fp2], t: usize, rho_w: &[Fp2]) -> Fp2 {
    let mut s = Fp2::ZERO;
    for (i, &e) in eq_i.iter().enumerate().take(t) {
        let mut p = e;
        for (b, &r) in rho_w.iter().enumerate() {
            p = p * if (i >> b) & 1 == 1 { r } else { Fp2::ONE - r };
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
    pub mult_corr: Vec<u64>,
    pub inst: crate::logup::BlindInstance,
}

pub struct EmbedProof {
    /// Boundary auth of `embed.out` (T×d, 8 B/value — same convention as the
    /// per-layer boundaries).
    pub out_corr: Vec<u64>,
    pub mult_corr: Vec<u64>,
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
    /// [ln_norm (main/stage-2), ln_rsqrt] multiplicity corrections.
    pub mult_corr: [Vec<u64>; 2],
    /// ln_norm stage-1 multiplicity corr — Some iff shift_ln_norm > 16 (the
    /// real artifact has shift_ln_norm = 20, so this path IS exercised).
    pub m_ln_s1_corr: Option<Vec<u64>>,
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

pub struct ModelProof {
    pub layers: Vec<LayerProof>,
    /// Index `l` is the seam between layer `l` and `l+1` (11 entries).
    pub seams: Vec<Option<SeamProof>>,
    pub embed: EmbedProof,
    pub final_ln: FinalLnProof,
    pub logits: LogitsClaimProof,
    pub selection: SelectionProof,
}

pub struct ModelOut {
    /// Exactly 48 committed-weight claims, LAYER-MAJOR, canonical per-layer
    /// order [c_attn, attn_proj, ffn_up, ffn_down] (as `LayerOut`).
    pub weight_claims: Vec<WeightClaimP>,
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

/// Prove the whole model. Boundary/instance machinery is IDENTICAL to
/// `prove_layer`'s (this function is pure orchestration); it accumulates
/// every layer's + every model-level context's Π_Prod / Π_ZeroBatch rows
/// into ONE pair of vectors, returned to the caller for a single closure
/// (exactly `run_layer_case`'s pattern, scaled to the model).
pub fn prove_model(
    model: &Gpt2Model,
    wit: &ModelWitness,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ModelProof, ModelOut, ProdTriples, Vec<ProverAuthed>) {
    let t = wit.t;
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut prod: ProdTriples = Vec::new();
    let mut zero: Vec<ProverAuthed> = Vec::new();
    let mut weight_claims: Vec<WeightClaimP> = Vec::with_capacity(4 * L);
    let mut bytes = LayerBytes::default();
    let mut ctr_instances = Counters::default();
    let mut ctr_other = Counters::default();
    let mut lookups: Vec<InstanceLookups> = Vec::new();
    let mut layer_proofs: Vec<LayerProof> = Vec::with_capacity(L);
    // (dom_xin, dom_fbo) per layer — needed for the seam / embed / final-LN
    // boundary re-openings.
    let mut boundary_doms: Vec<(u64, u64)> = Vec::with_capacity(L);

    // ---- (a) 12 layers -----------------------------------------------------
    for l in 0..L {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        let mut cx = BlockCtxP::new(stream, tx, l as u8);
        let (proof, out): (LayerProof, LayerOut) = prove_layer(
            &wit.layers[l],
            &model.layers[l].0,
            &luts_l,
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
        lookups.extend(out.lookups);
        weight_claims.extend(out.weight_claims);
        layer_proofs.push(proof);
    }

    // ---- (c) seams -----------------------------------------------------------
    let mut seams: Vec<Option<SeamProof>> = Vec::with_capacity(L - 1);
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        assert!(
            shift <= 16,
            "P5 seam shifts must be ≤16 (no chained seams supported here) — got {shift} at seam {l}"
        );
        let mut cx = BlockCtxP::new(stream, tx, 200 + l as u8);
        let (dom_xin_next, _) = boundary_doms[l + 1];
        let (_, dom_fbo_l) = boundary_doms[l];
        if shift > 0 {
            let acc: Vec<i64> = wit.layers[l].ffn_block_out.iter().map(|&v| v as i64).collect();
            let out16 = &wit.layers[l + 1].x_in;
            let mult = range_mult(&acc, out16, t, D, shift);
            let (dom_m, mult_fp, mult_corr) = auth_mult_p(&mut cx, &mult);
            let site = prove_range_site(&acc, out16, t, D, shift, &mult, None, Vec::new(), &mut cx);
            close_mult_p(&mut cx, dom_m, &mult_fp, &site.main);
            let out_open = open_matrix_p(cx.stream, dom_xin_next, out16, t, D, &site.main.point);
            cx.zero.push(site.main.col_claims[1].value.sub(out_open));
            let acc_open =
                open_matrix_p(cx.stream, dom_fbo_l, &wit.layers[l].ffn_block_out, t, D, site.acc_point());
            cx.zero.push(site.acc_claim.sub(acc_open));
            seams.push(Some(SeamProof { mult_corr, inst: site.main.proof }));
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
    let mut cx = BlockCtxP::new(stream, tx, 220);
    let dom_out = cx.doms.take(t as u64);
    let out_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_out, &wit.embed.out, t, D);
    let s_emb = model.p.shift_embed;
    assert!(
        s_emb > 0 && s_emb <= 16,
        "P5 embed shift must be single-stage positive ≤16 (got {s_emb}) — left-shift/chained embed not implemented here"
    );
    let s_emb = s_emb as u32;
    let mult = range_mult(&wit.embed.acc, &wit.embed.out, t, D, s_emb);
    let (dom_m, mult_fp, mult_corr) = auth_mult_p(&mut cx, &mult);
    let site =
        prove_range_site(&wit.embed.acc, &wit.embed.out, t, D, s_emb, &mult, None, Vec::new(), &mut cx);
    close_mult_p(&mut cx, dom_m, &mult_fp, &site.main);
    let out_open = open_matrix_p(cx.stream, dom_out, &wit.embed.out, t, D, &site.main.point);
    cx.zero.push(site.main.col_claims[1].value.sub(out_open));
    let embed_acc_point = site.acc_point().to_vec();
    let embed_acc_claim = site.acc_claim;
    let (dom_xin0, _) = boundary_doms[0];
    let rho_e: Vec<Fp2> = (0..n_vars_td).map(|_| cx.tx.challenge_fp2()).collect();
    let e_open = open_matrix_p(cx.stream, dom_out, &wit.embed.out, t, D, &rho_e);
    let x0_open = open_matrix_p(cx.stream, dom_xin0, &wit.layers[0].x_in, t, D, &rho_e);
    cx.zero.push(e_open.sub(x0_open));
    let embed = EmbedProof { out_corr, mult_corr, inst: site.main.proof };
    let BlockCtxP { prod: lp, zero: lz, ctr_instances: lci, ctr_other: lco, .. } = cx;
    prod.extend(lp);
    zero.extend(lz);
    add_counters(&mut ctr_instances, &lci);
    add_counters(&mut ctr_other, &lco);

    // ---- (e) final LN (last row only) --------------------------------------
    // **P5-DEVIATION(final-ln-t1)**: the LogUp/blind-sumcheck machinery
    // (`blind_prove` et al.) asserts `n.is_power_of_two() && n >= 2` — it has
    // no 0-round degenerate case. `t = 1` is ALREADY a power of two with
    // `pad_bits(1) = 0`, so every t=1 instance here (ln_rsqrt pair, the
    // ln_norm_requant range site, the hadamard) would be a length-1
    // sumcheck, which the shared machinery cannot run. Fix: run the whole
    // final-LN chain on a length-2 batch where row 1 is an HONEST
    // byte-identical duplicate of row 0 (the real last row) — every relation
    // here (LN stats, LUT membership, hadamard) is per-row-independent, so a
    // duplicate row trivially satisfies them, and row 1's output is bound to
    // nothing downstream (only row 0 is tied to the public `final_ln.out`
    // boundary and to `layer[11].ffn_block_out`'s real last row below). This
    // is NOT a soundness relaxation — a cheating prover gains nothing by
    // deviating row 1, since nothing consumes it.
    let mut cx = BlockCtxP::new(stream, tx, 221);
    let t_ln = 2usize; // pad_bits(2) = 1 ⇒ n = 2, satisfies the machinery's floor.
    let rb_ln = 1usize;

    let out2: Vec<i16> =
        wit.final_ln.out.iter().chain(wit.final_ln.out.iter()).copied().collect();
    let dom_out_f = cx.doms.take(t_ln as u64);
    let out_corr_f = auth_matrix_rows_p(cx.stream, cx.tx, dom_out_f, &out2, t_ln, D);

    let rout_pad = Fp::from_i64(model.luts.ln_rsqrt[0] as i64);
    let mean2 = [wit.final_ln.mean, wit.final_ln.mean];
    let var2 = [wit.final_ln.var, wit.final_ln.var];
    let rin2 = [wit.final_ln.rsqrt_in, wit.final_ln.rsqrt_in];
    let rout2 = [wit.final_ln.rsqrt_out, wit.final_ln.rsqrt_out];
    let (lv, ln_vec_corrs) = auth_ln_vecs_p(&mut cx, rb_ln, &mean2, &var2, &rin2, &rout2, rout_pad);

    let s_ln = model.p.lut.shift_ln_norm;
    let acc_ln2: Vec<i64> = wit
        .final_ln
        .norm_trace
        .inputs
        .iter()
        .chain(wit.final_ln.norm_trace.inputs.iter())
        .copied()
        .collect();
    let (mult_ln, mult_ln_s1) = if s_ln <= 16 {
        (range_mult(&acc_ln2, &out2, t_ln, D, s_ln), None)
    } else {
        let (m1, m2) = range_mult_chained(&acc_ln2, t_ln, D, s_ln);
        (m2, Some(m1))
    };
    let mut mult_rsq = vec![0u32; 1 << 16];
    for &r in &rin2 {
        mult_rsq[r as usize] += 1;
    }

    let (dom_m_ln, mult_ln_fp, m_ln_corr) = auth_mult_p(&mut cx, &mult_ln);
    let ln_s1_auth = mult_ln_s1.as_ref().map(|m1| auth_mult_p(&mut cx, m1));
    let (dom_m_rsq, mult_rsq_fp, m_rsq_corr) = auth_mult_p(&mut cx, &mult_rsq);

    // Re-auth the pre-LN input's last row, duplicated the same way (2×D) —
    // see module docs and the deviation note above.
    let last_row: Vec<i16> = wit.layers[L - 1].ffn_block_out[(t - 1) * D..t * D].to_vec();
    let x2: Vec<i16> = last_row.iter().chain(last_row.iter()).copied().collect();
    let dom_row = cx.doms.take(t_ln as u64);
    let row_corr = auth_matrix_rows_p(cx.stream, cx.tx, dom_row, &x2, t_ln, D);

    // Bind row 0 of the duplicated x-auth to layer[11].ffn_block_out's real
    // last row (row 1 is an honest duplicate, unbound — see deviation note).
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
        &lv,
        &mult_ln,
        &mult_ln_fp,
        dom_m_ln,
        mult_ln_s1.as_ref().map(|m1| {
            let (d, fp, _) = ln_s1_auth.as_ref().unwrap();
            (m1.as_slice(), fp.as_slice(), *d)
        }),
        &mult_rsq,
        &mult_rsq_fp,
        dom_m_rsq,
        &model.luts.ln_rsqrt,
        &wire,
        &mut cx,
    );

    let final_ln = FinalLnProof {
        out_corr: out_corr_f,
        row_corr,
        ln_vec_corrs,
        mult_corr: [m_ln_corr, m_rsq_corr],
        m_ln_s1_corr: ln_s1_auth.map(|(_, _, c)| c),
        ln,
    };
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
    let mut cx = BlockCtxP::new(stream, tx, 230);
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
    let mut cx = BlockCtxP::new(stream, tx, 231);
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
    let g_eval = masked_eq_eval(&eq_i, t, &rho_w);
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

    let proof =
        ModelProof { layers: layer_proofs, seams, embed, final_ln, logits: logits_proof, selection };
    let out = ModelOut {
        weight_claims,
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
    if proof.layers.len() != L || proof.seams.len() != L - 1 {
        return None;
    }
    let d_cb = pad_bits(D);
    let rb_t = pad_bits(t);
    let n_vars_td = d_cb + rb_t;

    let mut kprod: ProdKeyTriples = Vec::new();
    let mut kzero: Vec<VerifierKey> = Vec::new();
    let mut weight_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(4 * L);
    // (xin_keys, fbo_keys) per layer.
    let mut boundary_keys: Vec<(Vec<Fp2>, Vec<Fp2>)> = Vec::with_capacity(L);

    // ---- (a) 12 layers -----------------------------------------------------
    for l in 0..L {
        let mut luts_l = model.luts.clone();
        luts_l.params.shift_attn_proj = model.p.shift_attn_proj[l];
        luts_l.params.shift_ffn_down = model.p.shift_ffn_down[l];
        let w = &model.layers[l].0;
        let b = &model.layers[l].1;
        let mut cx = BlockCtxV::new(vc, tx, l as u8);
        let out = verify_layer(
            t,
            &w.ln1_gain,
            &w.ln1_bias,
            &w.ln2_gain,
            &w.ln2_bias,
            &luts_l,
            &proof.layers[l],
            &mut cx,
            Some(b),
        )?;
        let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
        kprod.extend(lkp);
        kzero.extend(lkz);
        weight_keys.extend(out.weight_keys);
        boundary_keys.push((out.xin_keys, out.fbo_keys));
    }

    // ---- (c) seams -----------------------------------------------------------
    for l in 0..L - 1 {
        let shift = model.p.seam_shifts[l];
        assert!(
            shift <= 16,
            "P5 seam shifts must be ≤16 (no chained seams supported here) — got {shift} at seam {l}"
        );
        let mut cx = BlockCtxV::new(vc, tx, 200 + l as u8);
        match (&proof.seams[l], shift > 0) {
            (Some(sp), true) => {
                let mult_keys = keys_mult_v(&mut cx, &sp.mult_corr);
                let site = verify_range_site(n_vars_td, shift, &sp.inst, None, &[], &mut cx)?;
                close_mult_v(&mut cx, &mult_keys, &site.main.mult_key);
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
    let mut cx = BlockCtxV::new(vc, tx, 220);
    let dom_out = cx.doms.take(t as u64);
    let out_keys = auth_matrix_rows_v(cx.ctx, dom_out, &proof.embed.out_corr, t, D);
    let s_emb = model.p.shift_embed;
    if !(s_emb > 0 && s_emb <= 16) {
        return None;
    }
    let s_emb = s_emb as u32;
    let mult_keys = keys_mult_v(&mut cx, &proof.embed.mult_corr);
    let site = verify_range_site(n_vars_td, s_emb, &proof.embed.inst, None, &[], &mut cx)?;
    close_mult_v(&mut cx, &mult_keys, &site.main.mult_key);
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

    // ---- (e) final LN (mirrors the t=2 duplicated-row fix — see the
    // P5-DEVIATION(final-ln-t1) note in `prove_model`) -----------------------
    let mut cx = BlockCtxV::new(vc, tx, 221);
    let t_ln = 2usize;
    let rb_ln = 1usize;
    let dom_out_f = cx.doms.take(t_ln as u64);
    let out_keys_f = auth_matrix_rows_v(cx.ctx, dom_out_f, &proof.final_ln.out_corr, t_ln, D);
    let lvk = expand_ln_vecs_k(&mut cx, &proof.final_ln.ln_vec_corrs);
    let mult_ln_keys = keys_mult_v(&mut cx, &proof.final_ln.mult_corr[0]);
    let mult_ln_s1_keys = proof.final_ln.m_ln_s1_corr.as_ref().map(|c| keys_mult_v(&mut cx, c));
    let mult_rsq_keys = keys_mult_v(&mut cx, &proof.final_ln.mult_corr[1]);

    let dom_row = cx.doms.take(t_ln as u64);
    let row_keys = auth_matrix_rows_v(cx.ctx, dom_row, &proof.final_ln.row_corr, t_ln, D);
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
        &model.luts.ln_rsqrt,
        &row_keys,
        &lvk,
        &mult_ln_keys,
        mult_ln_s1_keys.as_deref(),
        &mult_rsq_keys,
        &proof.final_ln.ln,
        &wk,
        &mut cx,
    )?;
    let BlockCtxV { kprod: lkp, kzero: lkz, .. } = cx;
    kprod.extend(lkp);
    kzero.extend(lkz);

    // ---- (f) logits claim (mirror) -----------------------------------------
    let mut embed_keys: Vec<(Vec<Fp2>, VerifierKey)> = Vec::with_capacity(3);
    let mut cx = BlockCtxV::new(vc, tx, 230);
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
    let mut cx = BlockCtxV::new(vc, tx, 231);
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
    let g_eval = masked_eq_eval(&eq_i, t, &rho_w);
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
        let embed_dims: [(usize, usize, &[i16]); 3] = [
            (VOCAB, D, &model.wte),
            (VOCAB, D, &model.wte),
            (NPOS, D, &model.wpe),
        ];
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
}
