//! End-to-end blind proof of one GEMM `Y = X·W` (X, Y authenticated; W
//! public in P3 — the committed-weights leg arrives with P3.5/M9):
//! Π_Auth corrections → blind Thaler sumcheck → Π_Prod closing the final
//! claim against the authenticated X opening and the public W̃ evaluation.
//!
//! The prover's lazy `m_r` tag expansion (ledger deviation 2026-07-03)
//! happens here, at opening time, and is timed separately (`t_open_tags`).

use crate::mle::{eq_vec, eval_mle};
use crate::prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};
use crate::sumcheck_blind::{blind_prove, blind_verify, BlindSumcheckProof};
use crate::thaler::{fold_w, fold_x, fold_y_acc, pad_bits};
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{
    auth_verifier, CorrCounters, CorrIndex, CorrelationStream, ProverAuthed, Transcript,
    VerifierCtx, VerifierKey,
};

fn dom_x(row: u32) -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor: 1, row }.domain()
}
fn dom_y(row: u32) -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor: 2, row }.domain()
}
fn dom_round_masks() -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor: 0xF0, row: 0 }.domain()
}
fn dom_prod_mask() -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor: 0xF1, row: 0 }.domain()
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
    let mut corr_x = Vec::with_capacity(m * k);
    let mut corr_y = Vec::with_capacity(m * n);
    for row in 0..m {
        let masks = stream.draw_sub_masks(dom_x(row as u32), k);
        for (l, &r) in masks.iter().enumerate() {
            corr_x.push((Fp::from_i64(x[row * k + l] as i64) - r).value());
        }
    }
    for row in 0..m {
        let masks = stream.draw_sub_masks(dom_y(row as u32), n);
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
        let tags = stream.draw_sub_tags(dom_y(row as u32), n);
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
        blind_prove(a.clone(), b.clone(), claim0, stream, dom_round_masks(), tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    // X-opening: value X̃(r_i, r_l) plus lazily expanded tags.
    let t3 = Instant::now();
    let eq_l = eq_vec(&point);
    let x_val = eval_mle(&a, &point);
    let mut m_x = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(dom_x(row as u32), k);
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
    let mask = stream.draw_fulls(dom_prod_mask(), 1)[0];
    let chi = tx.challenge_fp2();
    let prod = prod_batch_prover(&[(x_open, b_pub, claim_n)], chi, mask, tx);
    tm.t_prod_s = t4.elapsed().as_secs_f64();

    (GemmBlindProof { corr_x, corr_y, sumcheck, prod }, tm, stream.counters)
}

/// P3.5 committed-W seam (M9): the W̃(r_l, r_j) leg is not public — the
/// prover authenticates it with a fresh full correlation (16 B correction,
/// uniform, leaks nothing) and the claim is handed outward, to be bound to
/// the static commitment C_W by volta-pcs (batch reduction + ZK opening).
pub struct WeightClaimP {
    /// Point on the W MLE (k×n, column vars LSB): r_j ‖ r_l.
    pub point: Vec<Fp2>,
    pub value: ProverAuthed,
}

/// Same as `prove_gemm_blind`, but the W̃ leg is authenticated at
/// `dom_w_claim` instead of public. Returns the outward weight claim.
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
        let tags = stream.draw_sub_tags(dom_y(row as u32), n);
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
        blind_prove(a.clone(), b.clone(), claim0, stream, dom_round_masks(), tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    let t3 = Instant::now();
    let eq_l = eq_vec(&point);
    let x_val = eval_mle(&a, &point);
    let mut m_x = Fp2::ZERO;
    for row in 0..m {
        let tags = stream.draw_sub_tags(dom_x(row as u32), k);
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
    let mask = stream.draw_fulls(dom_prod_mask(), 1)[0];
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
    if proof.corr_x.len() != m * k || proof.corr_y.len() != m * n {
        return None;
    }
    let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| tx.challenge_fp2()).collect();
    let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| tx.challenge_fp2()).collect();
    let eq_i = eq_vec(&r_i);
    let eq_j = eq_vec(&r_j);

    let mut k_y = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, dom_y(row as u32), &proof.corr_y[row * n..(row + 1) * n]);
        let mut acc = Fp2::ZERO;
        for (j, key) in keys.iter().enumerate() {
            acc += eq_j[j] * key.k;
        }
        k_y += eq_i[row] * acc;
    }

    let n_vars = pad_bits(k);
    let (point, k_claim_n) = blind_verify(
        n_vars,
        VerifierKey { k: k_y },
        &proof.sumcheck,
        ctx,
        dom_round_masks(),
        tx,
    )?;

    let eq_l = eq_vec(&point);
    let mut k_x = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, dom_x(row as u32), &proof.corr_x[row * k..(row + 1) * k]);
        let mut acc = Fp2::ZERO;
        for (l, key) in keys.iter().enumerate() {
            acc += eq_l[l] * key.k;
        }
        k_x += eq_i[row] * acc;
    }

    // Committed W̃ leg: key from the correlation + correction, no cleartext.
    let k_b = VerifierKey { k: ctx.expand_full_keys(dom_w_claim, 1)[0] + ctx.delta * corr_w };

    let k_mask = ctx.expand_full_keys(dom_prod_mask(), 1)[0];
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
        let keys = auth_verifier(ctx, dom_y(row as u32), &proof.corr_y[row * n..(row + 1) * n]);
        let mut acc = Fp2::ZERO;
        for (j, key) in keys.iter().enumerate() {
            acc += eq_j[j] * key.k;
        }
        k_y += eq_i[row] * acc;
    }

    let n_vars = pad_bits(k);
    let Some((point, k_claim_n)) = blind_verify(
        n_vars,
        VerifierKey { k: k_y },
        &proof.sumcheck,
        ctx,
        dom_round_masks(),
        tx,
    ) else {
        return false;
    };

    // Streamed opening of the authenticated X at (r_i, r_l).
    let eq_l = eq_vec(&point);
    let mut k_x = Fp2::ZERO;
    for row in 0..m {
        let keys = auth_verifier(ctx, dom_x(row as u32), &proof.corr_x[row * k..(row + 1) * k]);
        let mut acc = Fp2::ZERO;
        for (l, key) in keys.iter().enumerate() {
            acc += eq_l[l] * key.k;
        }
        k_x += eq_i[row] * acc;
    }

    // Public W̃(r_l, r_j), recomputed by the verifier itself.
    let b = fold_w(w, k, n, &eq_j);
    let b_final = eval_mle(&b, &point);

    let k_mask = ctx.expand_full_keys(dom_prod_mask(), 1)[0];
    let chi = tx.challenge_fp2();
    let keys = [(
        VerifierKey { k: k_x },
        VerifierKey::from_public(b_final, ctx.delta),
        k_claim_n,
    )];
    prod_batch_verify(&keys, k_mask, ctx.delta, chi, &proof.prod)
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
        let (_p, _t, counters) = prove_gemm_blind(&x, &w, &yacc, m, k, n, corr, &mut stream, &mut tx);
        // 2 full masks per sumcheck round + 1 Π_Prod mask; subfield corrs =
        // every authenticated element, exactly once.
        assert_eq!(counters.full_corrs, 2 * pad_bits(k) as u64 + 1);
        assert_eq!(counters.sub_corrs, (m * k + m * n) as u64);
    }
}
