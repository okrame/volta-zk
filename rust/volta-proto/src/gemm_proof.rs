//! End-to-end blind proof of one GEMM `Y = X·W` (X, Y authenticated; W
//! public in P3 — the committed-weights leg arrives with P3.5/M9):
//! Π_Auth corrections → blind Thaler sumcheck → Π_Prod closing the final
//! claim against the authenticated X opening and the public W̃ evaluation.
//!
//! The prover's lazy `m_r` tag expansion (ledger deviation 2026-07-03)
//! happens here, at opening time, and is timed separately (`t_open_tags`).
//!
//! P4 adds the *chained* variants: the initial claim comes from a downstream
//! instance (its point split `r_i`/`r_j` is inherited, not drawn fresh), X is
//! an internal wire whose evaluation claim is handed outward through the
//! `ClaimLedger`, and correlation domains are caller-allocated so several
//! GEMMs coexist in one session.

use crate::logup::Doms;
use crate::mle::{eq_vec, eval_mle};
use crate::prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
use crate::sumcheck_blind::{blind_prove, blind_prove_resident, blind_verify, BlindSumcheckProof};
use crate::thaler::{fold_w, fold_x, fold_y_acc, pad_bits};
use std::time::Instant;
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceSlice, Fp2Repr, MatrixFoldAxis};
use volta_field::{Fp, Fp2};
use volta_mac::{
    auth_verifier, CorrCounters, CorrIndex, CorrelationStream, ProverAuthed, Transcript,
    VerifierCtx, VerifierKey,
};

/// Correlation domains for one element-wise-authenticated GEMM instance.
/// P3 hardcoded these; with more than one GEMM per session the caller
/// allocates a fresh, non-overlapping set per instance (the `DomainLedger`
/// panics on any reuse). Row `r` of X/Y draws its sub-correlations at
/// `x_row_base + r` / `y_row_base + r`.
pub struct GemmDomains {
    pub x_row_base: u64,
    pub y_row_base: u64,
    /// Blind sumcheck round masks: `round_masks + round`, 2 fulls per round.
    pub round_masks: u64,
    /// Single full mask for the closing Π_Prod message.
    pub prod_mask: u64,
}

impl GemmDomains {
    /// The P3 constants (CorrIndex packing) — valid for a session with a
    /// single GEMM only; kept so the P3/P3.5 call sites stay byte-identical.
    pub fn p3_default() -> GemmDomains {
        GemmDomains {
            x_row_base: CorrIndex { session: 1, layer: 0, head: 0, tensor: 1, row: 0 }.domain(),
            y_row_base: CorrIndex { session: 1, layer: 0, head: 0, tensor: 2, row: 0 }.domain(),
            round_masks: CorrIndex { session: 1, layer: 0, head: 0, tensor: 0xF0, row: 0 }.domain(),
            prod_mask: CorrIndex { session: 1, layer: 0, head: 0, tensor: 0xF1, row: 0 }.domain(),
        }
    }

    #[inline]
    fn dom_x(&self, row: usize) -> u64 {
        self.x_row_base + row as u64
    }

    #[inline]
    fn dom_y(&self, row: usize) -> u64 {
        self.y_row_base + row as u64
    }
}

pub struct GemmBlindProof {
    pub corr_x: Vec<u64>,
    pub corr_y: Vec<u64>,
    pub sumcheck: BlindSumcheckProof,
    pub prod: ProdProof,
}

#[derive(Default, Clone, Copy)]
pub struct ProveTimings {
    /// A/B Freivalds folds + Ỹ(r_i,r_j) value.
    pub t_fold_s: f64,
    /// Lazy m_r expansion + tag folds for the X and Y openings.
    pub t_open_tags_s: f64,
    /// Blind sumcheck rounds (incl. mask draws + corrections).
    pub t_rounds_s: f64,
    /// Final Π_Prod message.
    pub t_prod_s: f64,
}

impl ProveTimings {
    pub fn total_s(&self) -> f64 {
        self.t_fold_s + self.t_open_tags_s + self.t_rounds_s + self.t_prod_s
    }
}

/// Prover-side Π_Auth for X (i16) and Y accumulators (i64): mask-only draws
/// (the tag halves stay lazy), corrections 8 B/value.
pub fn auth_phase(
    x: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (Vec<u64>, Vec<u64>) {
    auth_phase_at(&GemmDomains::p3_default(), x, yacc, m, k, n, stream, tx)
}

/// [`auth_phase`] with explicit correlation domains.
#[allow(clippy::too_many_arguments)]
pub fn auth_phase_at(
    doms: &GemmDomains,
    x: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (Vec<u64>, Vec<u64>) {
    let mut corr_x = Vec::with_capacity(m * k);
    let mut corr_y = Vec::with_capacity(m * n);
    for row in 0..m {
        let masks = stream.draw_sub_masks(doms.dom_x(row), k);
        for (l, &r) in masks.iter().enumerate() {
            corr_x.push((Fp::from_i64(x[row * k + l] as i64) - r).value());
        }
    }
    for row in 0..m {
        let masks = stream.draw_sub_masks(doms.dom_y(row), n);
        for (j, &r) in masks.iter().enumerate() {
            corr_y.push((Fp::from_i64(yacc[row * n + j]) - r).value());
        }
    }
    tx.append("auth_corrections", 8 * (corr_x.len() + corr_y.len()) as u64);
    (corr_x, corr_y)
}

/// Blind prover for one GEMM. `stream`/`tx` must be the ones used by
/// `auth_phase` (tag expansion continues those domains).
pub fn prove_gemm_blind(
    x: &[i16],
    w: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    corr: (Vec<u64>, Vec<u64>),
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (GemmBlindProof, ProveTimings, CorrCounters) {
    prove_gemm_blind_at(&GemmDomains::p3_default(), x, w, yacc, m, k, n, corr, stream, tx)
}

/// [`prove_gemm_blind`] with explicit correlation domains (must match the
/// `auth_phase_at` call that produced `corr`).
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_blind_at(
    doms: &GemmDomains,
    x: &[i16],
    w: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    corr: (Vec<u64>, Vec<u64>),
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (GemmBlindProof, ProveTimings, CorrCounters) {
    let mut tm = ProveTimings::default();
    let (corr_x, corr_y) = corr;

    let t0 = Instant::now();
    let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);
    let a = fold_x(x, m, k, &eq_i);
    let b = fold_w(w, k, n, &eq_j);
    let y_val = fold_y_acc(yacc, m, n, &eq_i, &eq_j);
    tm.t_fold_s = t0.elapsed().as_secs_f64();

    // Y-opening tags: lazy m_r expansion + eq-weighted fold.
    let t1 = Instant::now();
    let mut m_y = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(doms.dom_y(row), n);
        let mut acc = Fp2::ZERO;
        for (j, t) in tags.into_iter().enumerate() {
            acc += eq_j[j] * t;
        }
        m_y += eq_i[row] * acc;
    }
    tm.t_open_tags_s = t1.elapsed().as_secs_f64();
    let claim0 = ProverAuthed { x: y_val, m: m_y };

    let t2 = Instant::now();
    let (sumcheck, point, claim_n) =
        blind_prove(a.clone(), b.clone(), claim0, stream, doms.round_masks, tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    // X-opening: value X̃(r_i, r_l) plus lazily expanded tags.
    let t3 = Instant::now();
    let eq_l = eq_vec(&point);
    let x_val = eval_mle(&a, &point);
    let mut m_x = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(doms.dom_x(row), k);
        let mut acc = Fp2::ZERO;
        for (l, t) in tags.into_iter().enumerate() {
            acc += eq_l[l] * t;
        }
        m_x += eq_i[row] * acc;
    }
    tm.t_open_tags_s += t3.elapsed().as_secs_f64();

    let t4 = Instant::now();
    let b_final = eval_mle(&b, &point);
    let x_open = ProverAuthed { x: x_val, m: m_x };
    let b_pub = ProverAuthed::from_public(b_final);
    debug_assert_eq!(claim_n.x, x_val * b_final, "honest final claim mismatch");
    let mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_open, b_pub, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    (GemmBlindProof { corr_x, corr_y, sumcheck, prod }, tm, stream.counters)
}

/// P3.5 committed-W seam (M9): the W̃(r_l, r_j) leg is not public — the
/// prover authenticates it with a fresh full correlation (16 B correction,
/// uniform, leaks nothing) and the claim is handed outward, to be bound to
/// the static commitment C_W by volta-pcs (batch reduction + ZK opening).
#[derive(Debug, PartialEq, Eq)]
pub struct WeightClaimP {
    /// Point on the W MLE (k×n, column vars LSB): r_j ‖ r_l.
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
}

/// Same as `prove_gemm_blind`, but the W̃ leg is authenticated at
/// `dom_w_claim` instead of public. Returns the outward weight claim.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_blind_committed(
    x: &[i16],
    w: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    corr: (Vec<u64>, Vec<u64>),
    dom_w_claim: u64,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (GemmBlindProof, Fp2, WeightClaimP, ProveTimings, CorrCounters) {
    prove_gemm_blind_committed_at(
        &GemmDomains::p3_default(),
        x,
        w,
        yacc,
        m,
        k,
        n,
        corr,
        dom_w_claim,
        stream,
        tx,
    )
}

/// [`prove_gemm_blind_committed`] with explicit correlation domains.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_blind_committed_at(
    doms: &GemmDomains,
    x: &[i16],
    w: &[i16],
    yacc: &[i64],
    m: usize,
    k: usize,
    n: usize,
    corr: (Vec<u64>, Vec<u64>),
    dom_w_claim: u64,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (GemmBlindProof, Fp2, WeightClaimP, ProveTimings, CorrCounters) {
    let mut tm = ProveTimings::default();
    let (corr_x, corr_y) = corr;

    let t0 = Instant::now();
    let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);
    let a = fold_x(x, m, k, &eq_i);
    let b = fold_w(w, k, n, &eq_j);
    let y_val = fold_y_acc(yacc, m, n, &eq_i, &eq_j);
    tm.t_fold_s = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let mut m_y = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(doms.dom_y(row), n);
        let mut acc = Fp2::ZERO;
        for (j, t) in tags.into_iter().enumerate() {
            acc += eq_j[j] * t;
        }
        m_y += eq_i[row] * acc;
    }
    tm.t_open_tags_s = t1.elapsed().as_secs_f64();
    let claim0 = ProverAuthed { x: y_val, m: m_y };

    let t2 = Instant::now();
    let (sumcheck, point, claim_n) =
        blind_prove(a.clone(), b.clone(), claim0, stream, doms.round_masks, tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    let t3 = Instant::now();
    let eq_l = eq_vec(&point);
    let x_val = eval_mle(&a, &point);
    let mut m_x = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(doms.dom_x(row), k);
        let mut acc = Fp2::ZERO;
        for (l, t) in tags.into_iter().enumerate() {
            acc += eq_l[l] * t;
        }
        m_x += eq_i[row] * acc;
    }
    tm.t_open_tags_s += t3.elapsed().as_secs_f64();

    let t4 = Instant::now();
    let b_final = eval_mle(&b, &point);
    let x_open = ProverAuthed { x: x_val, m: m_x };
    // The committed-W leg: authenticate W̃(r_l, r_j) with a fresh full
    // correlation — never sent in clear (corr_w = b_final − r is uniform).
    let fc = stream.draw_fulls(dom_w_claim, 1)[0];
    let corr_w = b_final - fc.x;
    tx.append("w_claim_correction", 16);
    let b_auth = ProverAuthed { x: b_final, m: fc.m };
    debug_assert_eq!(claim_n.x, x_val * b_final, "honest final claim mismatch");
    let mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_open, b_auth, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    let mut w_point = r_j.clone();
    w_point.extend_from_slice(&point);
    let claim = WeightClaimP { point: w_point, value: b_auth };
    (GemmBlindProof { corr_x, corr_y, sumcheck, prod }, corr_w, claim, tm, stream.counters)
}

/// Verifier for the committed-W variant: never sees W. Returns the outward
/// weight claim (point, MAC key) on acceptance of the local checks; the
/// caller must still bind it to C_W (soundness is discharged there — this
/// mirrors M9's `hfin` hand-off to the blind sumcheck statement).
pub fn verify_gemm_blind_committed(
    m: usize,
    k: usize,
    n: usize,
    proof: &GemmBlindProof,
    corr_w: Fp2,
    dom_w_claim: u64,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    verify_gemm_blind_committed_at(
        &GemmDomains::p3_default(),
        m,
        k,
        n,
        proof,
        corr_w,
        dom_w_claim,
        ctx,
        tx,
    )
}

/// [`verify_gemm_blind_committed`] with explicit correlation domains.
#[allow(clippy::too_many_arguments)]
pub fn verify_gemm_blind_committed_at(
    doms: &GemmDomains,
    m: usize,
    k: usize,
    n: usize,
    proof: &GemmBlindProof,
    corr_w: Fp2,
    dom_w_claim: u64,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if proof.corr_x.len() != m * k || proof.corr_y.len() != m * n {
        return None;
    }
    let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);

    let mut k_y = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, doms.dom_y(row), &proof.corr_y[row * n..(row + 1) * n]);
        let mut acc = Fp2::ZERO;
        for (j, key) in keys.iter().enumerate() {
            acc += eq_j[j] * key.k;
        }
        k_y += eq_i[row] * acc;
    }

    let n_vars = pad_bits(k);
    let (point, k_claim_n) =
        blind_verify(n_vars, VerifierKey { k: k_y }, &proof.sumcheck, ctx, doms.round_masks, tx)?;

    let eq_l = eq_vec(&point);
    let mut k_x = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, doms.dom_x(row), &proof.corr_x[row * k..(row + 1) * k]);
        let mut acc = Fp2::ZERO;
        for (l, key) in keys.iter().enumerate() {
            acc += eq_l[l] * key.k;
        }
        k_x += eq_i[row] * acc;
    }

    // Committed W̃ leg: key from the correlation + correction, no cleartext.
    let k_b = VerifierKey { k: ctx.expand_full_keys(dom_w_claim, 1)[0] + ctx.delta * corr_w };

    let k_mask = ctx.expand_full_keys(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let keys = [(VerifierKey { k: k_x }, k_b, k_claim_n)];
    if !prod_batch_verify(&keys, k_mask, ctx.delta, chi, &proof.prod) {
        return None;
    }
    let mut w_point = r_j;
    w_point.extend_from_slice(&point);
    Some((w_point, k_b))
}

/// Verifier. Knows W (public in P3), Δ and the shared PCG seed.
pub fn verify_gemm_blind(
    w: &[i16],
    m: usize,
    k: usize,
    n: usize,
    proof: &GemmBlindProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> bool {
    verify_gemm_blind_at(&GemmDomains::p3_default(), w, m, k, n, proof, ctx, tx)
}

/// [`verify_gemm_blind`] with explicit correlation domains.
#[allow(clippy::too_many_arguments)]
pub fn verify_gemm_blind_at(
    doms: &GemmDomains,
    w: &[i16],
    m: usize,
    k: usize,
    n: usize,
    proof: &GemmBlindProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> bool {
    if proof.corr_x.len() != m * k || proof.corr_y.len() != m * n {
        return false;
    }
    let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);

    // Streamed opening of the authenticated Y at (r_i, r_j).
    let mut k_y = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, doms.dom_y(row), &proof.corr_y[row * n..(row + 1) * n]);
        let mut acc = Fp2::ZERO;
        for (j, key) in keys.iter().enumerate() {
            acc += eq_j[j] * key.k;
        }
        k_y += eq_i[row] * acc;
    }

    let n_vars = pad_bits(k);
    let Some((point, k_claim_n)) =
        blind_verify(n_vars, VerifierKey { k: k_y }, &proof.sumcheck, ctx, doms.round_masks, tx)
    else {
        return false;
    };

    // Streamed opening of the authenticated X at (r_i, r_l).
    let eq_l = eq_vec(&point);
    let mut k_x = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, doms.dom_x(row), &proof.corr_x[row * k..(row + 1) * k]);
        let mut acc = Fp2::ZERO;
        for (l, key) in keys.iter().enumerate() {
            acc += eq_l[l] * key.k;
        }
        k_x += eq_i[row] * acc;
    }

    // Public W̃(r_l, r_j), recomputed by the verifier itself.
    let b = fold_w(w, k, n, &eq_j);
    let b_final = eval_mle(&b, &point);

    let k_mask = ctx.expand_full_keys(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let keys = [(VerifierKey { k: k_x }, VerifierKey::from_public(b_final, ctx.delta), k_claim_n)];
    prod_batch_verify(&keys, k_mask, ctx.delta, chi, &proof.prod)
}

// ---------------------------------------------------------------------------
// P4: chained GEMMs — the claim arrives from downstream, X is a wire.
// ---------------------------------------------------------------------------

/// Correlation domains for one chained GEMM, all caller-allocated via
/// `crate::logup::Doms` (mirrored verifier-side with the same base). The
/// round block needs `pad_bits(k)` consecutive domains.
pub struct ChainDoms {
    /// Blind sumcheck rounds: `round_masks + round`, 2 fulls per round.
    pub round_masks: u64,
    /// Fresh full correlation authenticating the X̃ wire claim.
    pub x_claim: u64,
    /// Fresh full correlation authenticating the committed-W̃ claim
    /// (unused by the activation×activation variant).
    pub w_claim: u64,
    /// Π_Prod mask.
    pub prod_mask: u64,
}

impl ChainDoms {
    /// Allocate all domains for one chained GEMM with contraction size `k`.
    pub fn alloc(doms: &mut Doms, k: usize) -> ChainDoms {
        ChainDoms {
            round_masks: doms.take(pad_bits(k) as u64),
            x_claim: doms.take(1),
            w_claim: doms.take(1),
            prod_mask: doms.take(1),
        }
    }
}

/// Outward wire claim, prover side: the X̃ evaluation at `point`
/// (contraction vars LSB: r_l ‖ r_i), authenticated by a fresh full
/// correlation — `corr` is the 16 B transfer the verifier consumed. The
/// caller routes it to the wire's producer via the `ClaimLedger`.
#[derive(Debug, PartialEq, Eq)]
pub struct WireOut {
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
    pub corr: Fp2,
}

/// Verifier half of a [`WireOut`].
pub struct WireKey {
    pub point: Vec<Fp2>,
    pub key: VerifierKey,
}

/// Chained GEMM proof: no element-wise corrections at all — both tensor
/// legs leave as outward claims (compare [`GemmBlindProof`]).
#[derive(Debug, PartialEq, Eq)]
pub struct ChainedGemmProof {
    pub sumcheck: BlindSumcheckProof,
    pub prod: ProdProof,
}

/// Chained committed-W GEMM prover: the downstream instance already holds
/// the authenticated `claim0 = ỹacc(r_i, r_j)` at ITS point split — nothing
/// is drawn fresh here. X is an internal wire (never element-wise
/// authenticated): its final evaluation X̃(r_l ‖ r_i) is authenticated with
/// a fresh full correlation at `doms.x_claim`, exactly like the committed-W
/// leg, and handed outward. Returns
/// `(proof, x wire claim, corr_w, weight claim, timings, counters)`.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_committed_chained(
    x: &[i16],
    w: &[i16],
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    claim0: ProverAuthed,
    doms: &ChainDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ChainedGemmProof, WireOut, Fp2, WeightClaimP, ProveTimings, CorrCounters) {
    assert_eq!(r_i.len(), pad_bits(m), "r_i must split the downstream row vars");
    assert_eq!(r_j.len(), pad_bits(n), "r_j must split the downstream col vars");
    let mut tm = ProveTimings::default();

    let t0 = Instant::now();
    let eq_i = eq_vec(r_i);
    let eq_j = eq_vec(r_j);
    let a = fold_x(x, m, k, &eq_i);
    let b = fold_w(w, k, n, &eq_j);
    tm.t_fold_s = t0.elapsed().as_secs_f64();
    debug_assert_eq!(
        claim0.x,
        a.iter().zip(&b).fold(Fp2::ZERO, |s, (&p, &q)| s + p * q),
        "claim0 is not the sumcheck total"
    );

    let t2 = Instant::now();
    let (sumcheck, point, claim_n) =
        blind_prove(a.clone(), b.clone(), claim0, stream, doms.round_masks, tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    let t4 = Instant::now();
    let x_val = eval_mle(&a, &point);
    let b_final = eval_mle(&b, &point);
    // X wire leg: no element-wise tags to fold — authenticate the evaluation
    // itself with a fresh full correlation (uniform, leaks nothing).
    let fx = stream.draw_fulls(doms.x_claim, 1)[0];
    let corr_x = x_val - fx.x;
    tx.append("x_claim_correction", 16);
    let x_auth = ProverAuthed { x: x_val, m: fx.m };
    // Committed-W leg, identical to `prove_gemm_blind_committed`.
    let fw = stream.draw_fulls(doms.w_claim, 1)[0];
    let corr_w = b_final - fw.x;
    tx.append("w_claim_correction", 16);
    let b_auth = ProverAuthed { x: b_final, m: fw.m };
    debug_assert_eq!(claim_n.x, x_val * b_final, "honest final claim mismatch");
    let mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_auth, b_auth, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    let mut w_point = r_j.to_vec();
    w_point.extend_from_slice(&point);
    (
        ChainedGemmProof { sumcheck, prod },
        WireOut { point: x_point, value: x_auth, corr: corr_x },
        corr_w,
        WeightClaimP { point: w_point, value: b_auth },
        tm,
        stream.counters,
    )
}

fn free_resident_fp2_pair(
    backend: &mut Backend,
    a: DeviceBuffer<Fp2Repr>,
    b: DeviceBuffer<Fp2Repr>,
) -> Result<(), AccelError> {
    let first = backend.free_device(a).err();
    let second = backend.free_device(b).err();
    first.or(second).map_or(Ok(()), Err)
}

/// Device-resident counterpart of [`prove_gemm_committed_chained`]. The X/W
/// matrices never leave their owning context: public equality weights are
/// uploaded, both Thaler folds remain resident, and only compressed
/// sumcheck messages/final claims cross D2H. Proof and verifier formats are
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_committed_chained_resident(
    x: DeviceSlice<'_, i16>,
    w: DeviceSlice<'_, i16>,
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    claim0: ProverAuthed,
    doms: &ChainDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(ChainedGemmProof, WireOut, Fp2, WeightClaimP, ProveTimings, CorrCounters), AccelError>
{
    if r_i.len() != pad_bits(m) || r_j.len() != pad_bits(n) {
        return Err(AccelError::InvalidInput(
            "resident chained GEMM point split does not match geometry",
        ));
    }
    let mut tm = ProveTimings::default();
    let t0 = Instant::now();
    let eq_i = eq_vec(r_i);
    let eq_j = eq_vec(r_j);
    let eq_i_raw: Vec<Fp2Repr> = eq_i.iter().copied().map(Into::into).collect();
    let eq_j_raw: Vec<Fp2Repr> = eq_j.iter().copied().map(Into::into).collect();
    let d_eq_i = backend.upload_new_device(&eq_i_raw)?;
    let d_eq_j = match backend.upload_new_device(&eq_j_raw) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(d_eq_i);
            return Err(error);
        }
    };
    let a = match backend.matrix_fold_device(
        x,
        DeviceSlice::new(&d_eq_i, 0, eq_i_raw.len()).expect("whole row-eq buffer"),
        m,
        k,
        MatrixFoldAxis::Rows,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = free_resident_fp2_pair(backend, d_eq_i, d_eq_j);
            return Err(error);
        }
    };
    let b = match backend.matrix_fold_device(
        w,
        DeviceSlice::new(&d_eq_j, 0, eq_j_raw.len()).expect("whole column-eq buffer"),
        k,
        n,
        MatrixFoldAxis::Columns,
    ) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(a);
            let _ = free_resident_fp2_pair(backend, d_eq_i, d_eq_j);
            return Err(error);
        }
    };
    if let Err(error) = free_resident_fp2_pair(backend, d_eq_i, d_eq_j) {
        let _ = free_resident_fp2_pair(backend, a, b);
        return Err(error);
    }
    tm.t_fold_s = t0.elapsed().as_secs_f64();
    #[cfg(debug_assertions)]
    {
        let total = match backend.fp2_dot_device(
            DeviceSlice::new(&a, 0, a.len()).expect("whole A fold"),
            DeviceSlice::new(&b, 0, b.len()).expect("whole B fold"),
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = free_resident_fp2_pair(backend, a, b);
                return Err(error);
            }
        };
        debug_assert_eq!(claim0.x, total, "claim0 is not the resident sumcheck total");
    }

    let t2 = Instant::now();
    let (sumcheck, point, claim_n, x_val, b_final) =
        blind_prove_resident(a, b, claim0, stream, doms.round_masks, tx, backend)?;
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    let t4 = Instant::now();
    let fx = stream.draw_fulls(doms.x_claim, 1)[0];
    let corr_x = x_val - fx.x;
    tx.append("x_claim_correction", 16);
    let x_auth = ProverAuthed { x: x_val, m: fx.m };
    let fw = stream.draw_fulls(doms.w_claim, 1)[0];
    let corr_w = b_final - fw.x;
    tx.append("w_claim_correction", 16);
    let b_auth = ProverAuthed { x: b_final, m: fw.m };
    debug_assert_eq!(claim_n.x, x_val * b_final, "honest final claim mismatch");
    let mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_auth, b_auth, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    let mut w_point = r_j.to_vec();
    w_point.extend_from_slice(&point);
    Ok((
        ChainedGemmProof { sumcheck, prod },
        WireOut { point: x_point, value: x_auth, corr: corr_x },
        corr_w,
        WeightClaimP { point: w_point, value: b_auth },
        tm,
        stream.counters,
    ))
}

/// Verifier for [`prove_gemm_committed_chained`]: mirrors the recursion on
/// keys from `k_claim0` (the key the downstream instance handed over), then
/// returns the two outward key claims — the X wire key (to the `KeyLedger`)
/// and the W̃ point + key (to the PCS binding).
#[allow(clippy::too_many_arguments)]
pub fn verify_gemm_committed_chained(
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    k_claim0: VerifierKey,
    proof: &ChainedGemmProof,
    x_corr: Fp2,
    corr_w: Fp2,
    doms: &ChainDoms,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(WireKey, Vec<Fp2>, VerifierKey)> {
    if r_i.len() != pad_bits(m) || r_j.len() != pad_bits(n) {
        return None;
    }
    let (point, k_claim_n) =
        blind_verify(pad_bits(k), k_claim0, &proof.sumcheck, ctx, doms.round_masks, tx)?;

    // Both final legs: keys from fresh correlations + corrections.
    let k_x = VerifierKey { k: ctx.expand_full_keys(doms.x_claim, 1)[0] + ctx.delta * x_corr };
    let k_w = VerifierKey { k: ctx.expand_full_keys(doms.w_claim, 1)[0] + ctx.delta * corr_w };

    let k_mask = ctx.expand_full_keys(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    if !prod_batch_verify(&[(k_x, k_w, k_claim_n)], k_mask, ctx.delta, chi, &proof.prod) {
        return None;
    }
    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    let mut w_point = r_j.to_vec();
    w_point.extend_from_slice(&point);
    Some((WireKey { point: x_point, key: k_x }, w_point, k_w))
}

/// Chained activation×activation GEMM prover: same shape as the committed
/// variant, but the B leg is a boundary-authenticated tensor OPENED BY THE
/// CALLER — `b_folded` is B̃ already folded over its non-contraction vars
/// (length `2^pad_bits(k)`), and `open_b` produces the authenticated
/// B̃ opening at the sumcheck point (streamed MAC-tag fold). Returns the
/// sumcheck point `r_l` so the caller can place the B claim. No `w_claim`
/// domain is consumed.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_act_chained(
    x: &[i16],
    b_folded: Vec<Fp2>,
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    claim0: ProverAuthed,
    open_b: impl FnOnce(&[Fp2]) -> ProverAuthed,
    doms: &ChainDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> (ChainedGemmProof, WireOut, Vec<Fp2>, ProveTimings, CorrCounters) {
    assert_eq!(r_i.len(), pad_bits(m), "r_i must split the downstream row vars");
    assert_eq!(r_j.len(), pad_bits(n), "r_j must split the downstream col vars");
    assert_eq!(b_folded.len(), 1 << pad_bits(k), "b_folded must cover the padded contraction");
    let mut tm = ProveTimings::default();

    let t0 = Instant::now();
    let eq_i = eq_vec(r_i);
    let a = fold_x(x, m, k, &eq_i);
    tm.t_fold_s = t0.elapsed().as_secs_f64();
    debug_assert_eq!(
        claim0.x,
        a.iter().zip(&b_folded).fold(Fp2::ZERO, |s, (&p, &q)| s + p * q),
        "claim0 is not the sumcheck total"
    );

    let t2 = Instant::now();
    let (sumcheck, point, claim_n) =
        blind_prove(a.clone(), b_folded.clone(), claim0, stream, doms.round_masks, tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    // B leg: the caller opens its element-wise-authenticated tensor at the
    // sumcheck point (lazy tag fold — same pattern as the X opening in
    // `prove_gemm_blind`, but owned by the tensor's boundary instance).
    let t1 = Instant::now();
    let b_open = open_b(&point);
    tm.t_open_tags_s = t1.elapsed().as_secs_f64();
    debug_assert_eq!(b_open.x, eval_mle(&b_folded, &point), "open_b value mismatch");

    let t4 = Instant::now();
    let x_val = eval_mle(&a, &point);
    let fx = stream.draw_fulls(doms.x_claim, 1)[0];
    let corr_x = x_val - fx.x;
    tx.append("x_claim_correction", 16);
    let x_auth = ProverAuthed { x: x_val, m: fx.m };
    debug_assert_eq!(claim_n.x, x_val * b_open.x, "honest final claim mismatch");
    let mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_auth, b_open, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    (
        ChainedGemmProof { sumcheck, prod },
        WireOut { point: x_point, value: x_auth, corr: corr_x },
        point,
        tm,
        stream.counters,
    )
}

/// Resident activation×activation chained GEMM after both public-point
/// matrix folds have been constructed on device. The two buffers are
/// consumed on every path. `open_b` supplies the MAC tag for the boundary B
/// tensor at the sumcheck point; its plaintext scalar is the device-computed
/// `b_final`, so no witness-sized host mirror is required.
#[allow(clippy::too_many_arguments)]
pub fn prove_gemm_act_chained_resident(
    a_folded: DeviceBuffer<Fp2Repr>,
    b_folded: DeviceBuffer<Fp2Repr>,
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    claim0: ProverAuthed,
    open_b: impl FnOnce(&[Fp2], Fp2) -> Result<ProverAuthed, AccelError>,
    doms: &ChainDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(ChainedGemmProof, WireOut, Vec<Fp2>, ProveTimings, CorrCounters), AccelError> {
    let expected = 1usize
        .checked_shl(pad_bits(k) as u32)
        .ok_or(AccelError::InvalidInput("resident activation GEMM dimension overflow"))?;
    if r_i.len() != pad_bits(m)
        || r_j.len() != pad_bits(n)
        || a_folded.len() != expected
        || b_folded.len() != expected
    {
        let _ = free_resident_fp2_pair(backend, a_folded, b_folded);
        return Err(AccelError::InvalidInput("resident activation GEMM fold geometry mismatch"));
    }
    #[cfg(debug_assertions)]
    {
        let total = match backend.fp2_dot_device(
            DeviceSlice::new(&a_folded, 0, expected).expect("whole resident A fold"),
            DeviceSlice::new(&b_folded, 0, expected).expect("whole resident B fold"),
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = free_resident_fp2_pair(backend, a_folded, b_folded);
                return Err(error);
            }
        };
        debug_assert_eq!(claim0.x, total, "claim0 is not the resident activation GEMM total");
    }

    let mut timings = ProveTimings::default();
    let rounds_started = Instant::now();
    let (sumcheck, point, claim_n, x_final, b_final) =
        blind_prove_resident(a_folded, b_folded, claim0, stream, doms.round_masks, tx, backend)?;
    timings.t_rounds_s = rounds_started.elapsed().as_secs_f64();

    let open_started = Instant::now();
    let b_open = open_b(&point, b_final)?;
    timings.t_open_tags_s = open_started.elapsed().as_secs_f64();
    if b_open.x != b_final {
        return Err(AccelError::InvalidInput(
            "resident activation GEMM boundary opening value mismatch",
        ));
    }

    let product_started = Instant::now();
    let x_mask = stream.draw_fulls(doms.x_claim, 1)[0];
    let corr_x = x_final - x_mask.x;
    tx.append("x_claim_correction", 16);
    let x_auth = ProverAuthed { x: x_final, m: x_mask.m };
    debug_assert_eq!(claim_n.x, x_final * b_final, "honest final claim mismatch");
    let product_mask = stream.draw_fulls(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_auth, b_open, claim_n)], chi, product_mask, tx);
    timings.t_prod_s = product_started.elapsed().as_secs_f64();

    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    Ok((
        ChainedGemmProof { sumcheck, prod },
        WireOut { point: x_point, value: x_auth, corr: corr_x },
        point,
        timings,
        stream.counters,
    ))
}

/// Verifier for [`prove_gemm_act_chained`]: `open_b_key` is the caller's key
/// side of the B opening at the sumcheck point. Returns the X wire key and
/// the sumcheck point `r_l` (for placing the caller's B claim).
#[allow(clippy::too_many_arguments)]
pub fn verify_gemm_act_chained(
    m: usize,
    k: usize,
    n: usize,
    r_i: &[Fp2],
    r_j: &[Fp2],
    k_claim0: VerifierKey,
    proof: &ChainedGemmProof,
    x_corr: Fp2,
    open_b_key: impl FnOnce(&[Fp2]) -> VerifierKey,
    doms: &ChainDoms,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<(WireKey, Vec<Fp2>)> {
    if r_i.len() != pad_bits(m) || r_j.len() != pad_bits(n) {
        return None;
    }
    let (point, k_claim_n) =
        blind_verify(pad_bits(k), k_claim0, &proof.sumcheck, ctx, doms.round_masks, tx)?;
    let k_b = open_b_key(&point);
    let k_x = VerifierKey { k: ctx.expand_full_keys(doms.x_claim, 1)[0] + ctx.delta * x_corr };
    let k_mask = ctx.expand_full_keys(doms.prod_mask, 1)[0];
    let chi = tx.challenge_fp2();
    if !prod_batch_verify(&[(k_x, k_b, k_claim_n)], k_mask, ctx.delta, chi, &proof.prod) {
        return None;
    }
    let mut x_point = point.clone();
    x_point.extend_from_slice(r_i);
    Some((WireKey { point: x_point, key: k_x }, point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn run(m: usize, k: usize, n: usize, seed: u8, tamper: bool) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 90);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-800..800)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-800..800)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &w, m, k, n);
        let pcg_seed = [seed; 32];
        let tx_seed = [seed ^ 0x77; 32];
        let delta = Fp2::new(Fp::new(0xDEAD_BEEF + seed as u64), Fp::new(31 + seed as u64));

        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let corr = auth_phase(&x, &yacc, m, k, n, &mut stream, &mut tx);
        let (mut proof, _tm, _c) =
            prove_gemm_blind(&x, &w, &yacc, m, k, n, corr, &mut stream, &mut tx);
        if tamper {
            // Prover lying about the total: shift a round correction, which
            // shifts the authenticated g(0) and hence the claim chain.
            proof.sumcheck.round_corrs[1][0] += Fp2::ONE;
        }
        let mut ctx = VerifierCtx::new(pcg_seed, delta);
        let mut vtx = Transcript::new(tx_seed);
        verify_gemm_blind(&w, m, k, n, &proof, &mut ctx, &mut vtx)
    }

    #[test]
    fn gemm_e2e_small() {
        for s in 0..5u8 {
            assert!(run(16, 32, 16, s, false), "honest GEMM proof rejected, seed {s}");
        }
    }

    #[test]
    fn blind_rejects_wrong_total() {
        for s in 0..10u8 {
            assert!(!run(16, 32, 16, s, true), "tampered GEMM proof accepted, seed {s}");
        }
    }

    #[test]
    fn mask_freshness_counters() {
        let (m, k, n) = (8usize, 16usize, 8usize);
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-100..100)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-100..100)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &w, m, k, n);
        let mut stream = CorrelationStream::new([9; 32]);
        let mut tx = Transcript::new([8; 32]);
        let corr = auth_phase(&x, &yacc, m, k, n, &mut stream, &mut tx);
        let (_p, _t, counters) =
            prove_gemm_blind(&x, &w, &yacc, m, k, n, corr, &mut stream, &mut tx);
        // 2 full masks per sumcheck round + 1 Π_Prod mask; subfield corrs =
        // every authenticated element, exactly once.
        assert_eq!(counters.full_corrs, 2 * pad_bits(k) as u64 + 1);
        assert_eq!(counters.sub_corrs, (m * k + m * n) as u64);
    }

    // --- P4 chained variants -------------------------------------------

    /// Brute-force X̃ (m×k, contraction vars LSB) at `point` = r_l ‖ r_i.
    fn x_mle_eval(x: &[i16], m: usize, k: usize, point: &[Fp2]) -> Fp2 {
        let k_pad = k.next_power_of_two();
        let m_pad = m.next_power_of_two();
        let mut vals = vec![Fp2::ZERO; m_pad * k_pad];
        for i in 0..m {
            for l in 0..k {
                vals[i * k_pad + l] = Fp2::from_base(Fp::from_i64(x[i * k + l] as i64));
            }
        }
        eval_mle(&vals, point)
    }

    /// Brute-force W̃ (k×n, column vars LSB) at `point` = r_j ‖ r_l.
    fn w_mle_eval(w: &[i16], k: usize, n: usize, point: &[Fp2]) -> Fp2 {
        let n_pad = n.next_power_of_two();
        let k_pad = k.next_power_of_two();
        let mut vals = vec![Fp2::ZERO; k_pad * n_pad];
        for l in 0..k {
            for j in 0..n {
                vals[l * n_pad + j] = Fp2::from_base(Fp::from_i64(w[l * n + j] as i64));
            }
        }
        eval_mle(&vals, point)
    }

    /// 0 = honest, 1 = flipped round correction, 2 = false claim0 value
    /// (prover claims ỹacc while the downstream key binds ỹacc − 1).
    fn run_committed_chained(m: usize, k: usize, n: usize, seed: u8, tamper: u8) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 400);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-800..800)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-800..800)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &w, m, k, n);
        let pcg_seed = [seed ^ 0x21; 32];
        let tx_seed = [seed ^ 0x84; 32];
        let delta = Fp2::new(Fp::new(0xC0FFEE + seed as u64), Fp::new(17 + seed as u64));

        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let mut ctx = VerifierCtx::new(pcg_seed, delta);
        let mut vtx = Transcript::new(tx_seed);

        // Downstream point split (interactive-mock: both sides draw it).
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
        let r_i_v: Vec<Fp2> = (0..pad_bits(m)).map(|_| vtx.challenge_fp2()).collect();
        let r_j_v: Vec<Fp2> = (0..pad_bits(n)).map(|_| vtx.challenge_fp2()).collect();

        // claim0 = true ỹacc(r_i, r_j), authenticated on both sides via the
        // mock streams at a test domain (prod_check.rs trick).
        let eq_i = eq_vec(&r_i);
        let eq_j = eq_vec(&r_j);
        let y_val = fold_y_acc(&yacc, m, n, &eq_i, &eq_j);
        let f0 = stream.draw_fulls(0x9000, 1)[0];
        let c0 = y_val - f0.x;
        let claim0 = ProverAuthed { x: y_val, m: f0.m };
        let mut k0 = ctx.expand_full_keys(0x9000, 1)[0] + delta * c0;
        if tamper == 2 {
            // Downstream really bound ỹacc − 1; the prover overclaims by 1.
            // blind_verify has no value checks, so the mismatch must surface
            // at prod_batch_verify.
            k0 = k0 - delta;
        }

        let mut alloc = Doms::new(0xA000);
        let cd = ChainDoms::alloc(&mut alloc, k);
        let (mut proof, wire, corr_w, wclaim, _tm, _ctr) = prove_gemm_committed_chained(
            &x,
            &w,
            m,
            k,
            n,
            &r_i,
            &r_j,
            claim0,
            &cd,
            &mut stream,
            &mut tx,
        );
        if tamper == 1 {
            proof.sumcheck.round_corrs[1][0] += Fp2::ONE;
        }

        let Some((wk, w_point_v, k_w)) = verify_gemm_committed_chained(
            m,
            k,
            n,
            &r_i_v,
            &r_j_v,
            VerifierKey { k: k0 },
            &proof,
            wire.corr,
            corr_w,
            &cd,
            &mut ctx,
            &mut vtx,
        ) else {
            return false;
        };

        // Resolve the outward claims against the true tensors: values match
        // the brute-force MLE evals, and the keys satisfy k = m + Δ·x.
        assert_eq!(wk.point, wire.point, "x claim point mismatch across parties");
        assert_eq!(w_point_v, wclaim.point, "w claim point mismatch across parties");
        assert_eq!(wire.value.x, x_mle_eval(&x, m, k, &wire.point), "x claim value wrong");
        assert_eq!(wclaim.value.x, w_mle_eval(&w, k, n, &wclaim.point), "w claim value wrong");
        wk.key.k == wire.value.m + delta * wire.value.x
            && k_w.k == wclaim.value.m + delta * wclaim.value.x
    }

    #[test]
    fn committed_chained_e2e() {
        for s in 0..3u8 {
            assert!(run_committed_chained(8, 16, 8, s, 0), "honest 8x16x8 rejected, seed {s}");
            assert!(run_committed_chained(6, 12, 10, s, 0), "honest 6x12x10 rejected, seed {s}");
        }
    }

    #[test]
    fn committed_chained_rejects_tampered_round() {
        for s in 0..5u8 {
            assert!(!run_committed_chained(8, 16, 8, s, 1), "flipped corr accepted, seed {s}");
            assert!(!run_committed_chained(6, 12, 10, s, 1), "flipped corr accepted, seed {s}");
        }
    }

    #[test]
    fn committed_chained_rejects_false_claim0() {
        for s in 0..5u8 {
            assert!(!run_committed_chained(8, 16, 8, s, 2), "false claim0 accepted, seed {s}");
        }
    }

    #[test]
    fn committed_chained_counters() {
        // The chained variant must consume exactly 2·rounds (sumcheck) + 2
        // (x/w claims) + 1 (Π_Prod) FULL correlations and ZERO sub corrs.
        let (m, k, n) = (8usize, 16usize, 8usize);
        let mut rng = rand::rngs::StdRng::seed_from_u64(500);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-100..100)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-100..100)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &w, m, k, n);
        let mut stream = CorrelationStream::new([7; 32]);
        let mut tx = Transcript::new([6; 32]);
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
        let (eq_i, eq_j) = (eq_vec(&r_i), eq_vec(&r_j));
        let y_val = fold_y_acc(&yacc, m, n, &eq_i, &eq_j);
        let f0 = stream.draw_fulls(0x9000, 1)[0];
        let claim0 = ProverAuthed { x: y_val, m: f0.m };
        let before = stream.counters;
        let cd = ChainDoms::alloc(&mut Doms::new(0xA000), k);
        let (_p, _w, _cw, _wc, _tm, after) = prove_gemm_committed_chained(
            &x,
            &w,
            m,
            k,
            n,
            &r_i,
            &r_j,
            claim0,
            &cd,
            &mut stream,
            &mut tx,
        );
        assert_eq!(after.full_corrs - before.full_corrs, 2 * pad_bits(k) as u64 + 3);
        assert_eq!(after.sub_corrs - before.sub_corrs, 0);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_committed_chained_matches_cpu_byte_for_byte() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident chained GEMM differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let (m, k, n) = (6usize, 12usize, 10usize);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0DE_7711);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-600..600)).collect();
        let w: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-600..600)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &w, m, k, n);
        let pcg_seed = [0x35; 32];
        let tx_seed = [0xA9; 32];
        let mut cpu_tx = Transcript::new(tx_seed);
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| cpu_tx.challenge_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| cpu_tx.challenge_fp2()).collect();
        let eq_i = eq_vec(&r_i);
        let eq_j = eq_vec(&r_j);
        let claim0 = ProverAuthed {
            x: fold_y_acc(&yacc, m, n, &eq_i, &eq_j),
            m: Fp2::new(Fp::new(0x1234), Fp::new(0x5678)),
        };
        let doms = ChainDoms::alloc(&mut Doms::new(0xB000), k);
        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let (cpu_proof, cpu_wire, cpu_corr_w, cpu_weight, _, cpu_counters) =
            prove_gemm_committed_chained(
                &x,
                &w,
                m,
                k,
                n,
                &r_i,
                &r_j,
                claim0,
                &doms,
                &mut cpu_stream,
                &mut cpu_tx,
            );

        let dx = gpu.upload_new_device(&x).unwrap();
        let dw = gpu.upload_new_device(&w).unwrap();
        let mut live_after_first = None;
        for _ in 0..2 {
            let mut tx = Transcript::new(tx_seed);
            let r_i_gpu: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
            let r_j_gpu: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
            assert_eq!(r_i_gpu, r_i);
            assert_eq!(r_j_gpu, r_j);
            let mut stream = CorrelationStream::new(pcg_seed);
            let (proof, wire, corr_w, weight, _, counters) = prove_gemm_committed_chained_resident(
                DeviceSlice::new(&dx, 0, x.len()).unwrap(),
                DeviceSlice::new(&dw, 0, w.len()).unwrap(),
                m,
                k,
                n,
                &r_i_gpu,
                &r_j_gpu,
                claim0,
                &doms,
                &mut stream,
                &mut tx,
                &mut gpu,
            )
            .unwrap();
            assert_eq!(proof.sumcheck, cpu_proof.sumcheck);
            assert_eq!(proof.prod.m0, cpu_proof.prod.m0);
            assert_eq!(proof.prod.m1, cpu_proof.prod.m1);
            assert_eq!(wire.point, cpu_wire.point);
            assert_eq!(wire.value, cpu_wire.value);
            assert_eq!(wire.corr, cpu_wire.corr);
            assert_eq!(corr_w, cpu_corr_w);
            assert_eq!(weight, cpu_weight);
            assert_eq!(counters, cpu_counters);
            assert_eq!(tx.ledger(), cpu_tx.ledger());
            let live = gpu.stats().unwrap().live_device_bytes;
            if let Some(first) = live_after_first {
                assert_eq!(live, first, "resident chained GEMM leaked across reuse");
            } else {
                live_after_first = Some(live);
            }
        }
        gpu.free_device(dw).unwrap();
        gpu.free_device(dx).unwrap();
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_activation_chained_matches_cpu_byte_for_byte() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident activation GEMM differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let (m, k, n) = (6usize, 12usize, 10usize);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xAC71_7712);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-600..600)).collect();
        let b: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-600..600)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &b, m, k, n);
        let pcg_seed = [0x71; 32];
        let tx_seed = [0xB2; 32];
        let mut cpu_tx = Transcript::new(tx_seed);
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| cpu_tx.challenge_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| cpu_tx.challenge_fp2()).collect();
        let eq_i = eq_vec(&r_i);
        let eq_j = eq_vec(&r_j);
        let b_folded = fold_w(&b, k, n, &eq_j);
        let tags: Vec<Fp2> = (0..k.next_power_of_two())
            .map(|i| Fp2::new(Fp::new(1009 + i as u64 * 17), Fp::new(2017 + i as u64 * 29)))
            .collect();
        let b_for_open = b_folded.clone();
        let tags_for_open = tags.clone();
        let claim0 = ProverAuthed {
            x: fold_y_acc(&yacc, m, n, &eq_i, &eq_j),
            m: Fp2::new(Fp::new(0xAA55), Fp::new(0x55AA)),
        };
        let doms = ChainDoms::alloc(&mut Doms::new(0xC000), k);
        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let (cpu_proof, cpu_wire, cpu_point, _, cpu_counters) = prove_gemm_act_chained(
            &x,
            b_folded,
            m,
            k,
            n,
            &r_i,
            &r_j,
            claim0,
            move |point| {
                let eq = eq_vec(point);
                ProverAuthed {
                    x: eq.iter().zip(&b_for_open).fold(Fp2::ZERO, |sum, (&w, &v)| sum + w * v),
                    m: eq
                        .iter()
                        .zip(&tags_for_open)
                        .fold(Fp2::ZERO, |sum, (&w, &tag)| sum + w * tag),
                }
            },
            &doms,
            &mut cpu_stream,
            &mut cpu_tx,
        );

        let dx = gpu.upload_new_device(&x).unwrap();
        let db = gpu.upload_new_device(&b).unwrap();
        let eq_i_raw: Vec<Fp2Repr> = eq_i.iter().copied().map(Into::into).collect();
        let eq_j_raw: Vec<Fp2Repr> = eq_j.iter().copied().map(Into::into).collect();
        let d_eq_i = gpu.upload_new_device(&eq_i_raw).unwrap();
        let d_eq_j = gpu.upload_new_device(&eq_j_raw).unwrap();
        let mut live_after_first = None;
        for _ in 0..2 {
            let mut tx = Transcript::new(tx_seed);
            let r_i_gpu: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
            let r_j_gpu: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
            assert_eq!(r_i_gpu, r_i);
            assert_eq!(r_j_gpu, r_j);
            let a_device = gpu
                .matrix_fold_device(
                    DeviceSlice::new(&dx, 0, x.len()).unwrap(),
                    DeviceSlice::new(&d_eq_i, 0, eq_i.len()).unwrap(),
                    m,
                    k,
                    MatrixFoldAxis::Rows,
                )
                .unwrap();
            let b_device = gpu
                .matrix_fold_device(
                    DeviceSlice::new(&db, 0, b.len()).unwrap(),
                    DeviceSlice::new(&d_eq_j, 0, eq_j.len()).unwrap(),
                    k,
                    n,
                    MatrixFoldAxis::Columns,
                )
                .unwrap();
            let tags_for_open = tags.clone();
            let mut stream = CorrelationStream::new(pcg_seed);
            let (proof, wire, point, _, counters) = prove_gemm_act_chained_resident(
                a_device,
                b_device,
                m,
                k,
                n,
                &r_i_gpu,
                &r_j_gpu,
                claim0,
                move |point, value| {
                    let eq = eq_vec(point);
                    Ok(ProverAuthed {
                        x: value,
                        m: eq
                            .iter()
                            .zip(&tags_for_open)
                            .fold(Fp2::ZERO, |sum, (&w, &tag)| sum + w * tag),
                    })
                },
                &doms,
                &mut stream,
                &mut tx,
                &mut gpu,
            )
            .unwrap();
            assert_eq!(proof, cpu_proof);
            assert_eq!(wire, cpu_wire);
            assert_eq!(point, cpu_point);
            assert_eq!(counters, cpu_counters);
            assert_eq!(tx.ledger(), cpu_tx.ledger());
            let live = gpu.stats().unwrap().live_device_bytes;
            if let Some(first) = live_after_first {
                assert_eq!(live, first, "resident activation GEMM leaked across reuse");
            } else {
                live_after_first = Some(live);
            }
        }
        gpu.free_device(d_eq_j).unwrap();
        gpu.free_device(d_eq_i).unwrap();
        gpu.free_device(db).unwrap();
        gpu.free_device(dx).unwrap();
    }

    fn run_act_chained(m: usize, k: usize, n: usize, seed: u8, tamper: bool) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 700);
        let x: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-800..800)).collect();
        let b_mat: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-800..800)).collect();
        let yacc = volta_gpt2::gemm_i64(&x, &b_mat, m, k, n);
        let pcg_seed = [seed ^ 0x42; 32];
        let tx_seed = [seed ^ 0x19; 32];
        let delta = Fp2::new(Fp::new(0xBEEF01 + seed as u64), Fp::new(23 + seed as u64));

        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let mut ctx = VerifierCtx::new(pcg_seed, delta);
        let mut vtx = Transcript::new(tx_seed);

        // B is boundary-authenticated element-wise (k rows of n), the
        // existing X-opening pattern: mask-only draws, 8 B corrections.
        let dom_b = |row: usize| 0x9200u64 + row as u64;
        let mut corr_b: Vec<Vec<u64>> = Vec::with_capacity(k);
        for l in 0..k {
            let masks = stream.draw_sub_masks(dom_b(l), n);
            corr_b.push(
                masks
                    .iter()
                    .enumerate()
                    .map(|(j, &r)| (Fp::from_i64(b_mat[l * n + j] as i64) - r).value())
                    .collect(),
            );
        }
        tx.append("auth_corrections", 8 * (k * n) as u64);

        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
        let r_i_v: Vec<Fp2> = (0..pad_bits(m)).map(|_| vtx.challenge_fp2()).collect();
        let r_j_v: Vec<Fp2> = (0..pad_bits(n)).map(|_| vtx.challenge_fp2()).collect();
        let eq_i = eq_vec(&r_i);
        let eq_j = eq_vec(&r_j);

        // Caller folds B over its non-contraction vars, and pre-folds the
        // lazily expanded tags the same way; the open_b closure finishes the
        // fold over the contraction point when the sumcheck lands.
        let b_folded = fold_w(&b_mat, k, n, &eq_j);
        let mut tag_rows: Vec<Fp2> = Vec::with_capacity(k);
        for l in 0..k {
            let tags = stream.draw_sub_tags(dom_b(l), n);
            tag_rows
                .push(tags.into_iter().enumerate().fold(Fp2::ZERO, |s, (j, t)| s + eq_j[j] * t));
        }
        let b_folded_p = b_folded.clone();
        let open_b = move |pt: &[Fp2]| {
            let eq_l = eq_vec(pt);
            let mut v = Fp2::ZERO;
            let mut mt = Fp2::ZERO;
            for (l, &t) in tag_rows.iter().enumerate() {
                v += eq_l[l] * b_folded_p[l];
                mt += eq_l[l] * t;
            }
            ProverAuthed { x: v, m: mt }
        };

        let y_val = fold_y_acc(&yacc, m, n, &eq_i, &eq_j);
        let f0 = stream.draw_fulls(0x9300, 1)[0];
        let c0 = y_val - f0.x;
        let claim0 = ProverAuthed { x: y_val, m: f0.m };
        let k0 = ctx.expand_full_keys(0x9300, 1)[0] + delta * c0;

        let cd = ChainDoms::alloc(&mut Doms::new(0xA100), k);
        let (mut proof, wire, r_l, _tm, _ctr) = prove_gemm_act_chained(
            &x,
            b_folded,
            m,
            k,
            n,
            &r_i,
            &r_j,
            claim0,
            open_b,
            &cd,
            &mut stream,
            &mut tx,
        );
        if tamper {
            proof.sumcheck.round_corrs[0][1] += Fp2::ONE;
        }

        // Verifier's B opening: streamed key expansion, pre-folded over j.
        let eq_j_v = eq_vec(&r_j_v);
        let mut key_rows: Vec<Fp2> = Vec::with_capacity(k);
        for l in 0..k {
            let keys = auth_verifier(&mut ctx, dom_b(l), &corr_b[l]);
            key_rows
                .push(keys.iter().enumerate().fold(Fp2::ZERO, |s, (j, key)| s + eq_j_v[j] * key.k));
        }
        let open_b_key = move |pt: &[Fp2]| {
            let eq_l = eq_vec(pt);
            let kk = key_rows.iter().enumerate().fold(Fp2::ZERO, |s, (l, &kr)| s + eq_l[l] * kr);
            VerifierKey { k: kk }
        };

        let Some((wk, r_l_v)) = verify_gemm_act_chained(
            m,
            k,
            n,
            &r_i_v,
            &r_j_v,
            VerifierKey { k: k0 },
            &proof,
            wire.corr,
            open_b_key,
            &cd,
            &mut ctx,
            &mut vtx,
        ) else {
            return false;
        };
        assert_eq!(r_l_v, r_l, "sumcheck point mismatch across parties");
        assert_eq!(wire.value.x, x_mle_eval(&x, m, k, &wire.point), "x claim value wrong");
        wk.key.k == wire.value.m + delta * wire.value.x
    }

    #[test]
    fn act_chained_e2e() {
        for s in 0..3u8 {
            assert!(run_act_chained(8, 16, 8, s, false), "honest act GEMM rejected, seed {s}");
            assert!(run_act_chained(6, 12, 10, s, false), "honest act GEMM rejected, seed {s}");
        }
    }

    #[test]
    fn act_chained_rejects_tampered_round() {
        for s in 0..5u8 {
            assert!(!run_act_chained(8, 16, 8, s, true), "tampered act GEMM accepted, seed {s}");
        }
    }
}
