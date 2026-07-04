//! Batch reduction of many authenticated W̃ evaluation claims to a single
//! point, so one PCS opening serves a whole response (design note A′,
//! "standard sumcheck batching").
//!
//! Claims arrive as (block, point, authenticated value): each weight tensor
//! occupies a power-of-two aligned block of the flat coefficient vector, so a
//! claim on tensor t at block-point p is a claim on the global MLE at
//! (p ‖ bits(block index)) — the boolean suffix keeps the eq tables
//! block-local, which is what makes the F-side build O(Σ block sizes) instead
//! of O(G·|W|).
//!
//! Protocol: λ drawn after all claims are fixed; one blind product sumcheck
//! (M3 machinery, byte- and correlation-compatible with
//! `volta_proto::blind_prove` — the verifier side IS `blind_verify`) over
//! F(x)·W̃(x) with F = Σ_g λ^{g+1}·eq(r_g, ·) and initial claim
//! Σ λ^{g+1}·v_g (authenticated by linearity). The final authenticated claim
//! F̃(r*)·W̃(r*) divides by the public F̃(r*), leaving the authenticated
//! W̃(r*) that `ligero::open_zk` binds to C_W.

use rayon::prelude::*;
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_proto::mle::{eq_points, lagrange3};
use volta_proto::sumcheck_blind::{blind_verify, BlindSumcheckProof};

/// One W̃ evaluation claim on the block at `offset` (aligned: offset is a
/// multiple of 2^point.len()); `point` binds the low variables of the block.
#[derive(Clone, Debug)]
pub struct BlockClaim {
    pub offset: usize,
    pub point: Vec<Fp2>,
}

impl BlockClaim {
    /// The claim's point on the global n_vars MLE: block point ‖ boolean
    /// suffix selecting the block.
    pub fn global_point(&self, n_vars: usize) -> Vec<Fp2> {
        let bv = self.point.len();
        assert!(self.offset % (1 << bv) == 0, "block offset not aligned");
        let mut p = self.point.clone();
        let idx = self.offset >> bv;
        for b in 0..n_vars - bv {
            p.push(if (idx >> b) & 1 == 1 { Fp2::ONE } else { Fp2::ZERO });
        }
        p
    }
}

#[derive(Default, Clone, Copy)]
pub struct BatchTimings {
    /// F = Σ λ^g eq_g table build (block-local).
    pub t_f_build_s: f64,
    /// i16 → F_p² embedding of W.
    pub t_w_embed_s: f64,
    /// Blind sumcheck rounds (incl. masks + folds).
    pub t_rounds_s: f64,
}

impl BatchTimings {
    pub fn total_s(&self) -> f64 {
        self.t_f_build_s + self.t_w_embed_s + self.t_rounds_s
    }
}

/// Build `dst += scale·eq(point, ·)` over a block (dst.len() = 2^point.len()).
fn add_scaled_eq(dst: &mut [Fp2], point: &[Fp2], scale: Fp2) {
    let mut t = vec![Fp2::ZERO; dst.len()];
    t[0] = scale;
    let mut size = 1usize;
    for &ri in point.iter().rev() {
        for i in (0..size).rev() {
            let v = t[i];
            let v1 = v * ri;
            t[2 * i] = v - v1;
            t[2 * i + 1] = v1;
        }
        size *= 2;
    }
    for (d, s) in dst.iter_mut().zip(&t) {
        *d += *s;
    }
}

/// Parallel twin of `volta_proto::blind_prove`: identical messages, masks and
/// transcript labels; g(0)/g(2) accumulation and folds run on rayon.
fn blind_prove_par(
    mut a: Vec<Fp2>,
    mut b: Vec<Fp2>,
    claim0: ProverAuthed,
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> (BlindSumcheckProof, Vec<Fp2>, ProverAuthed) {
    assert_eq!(a.len(), b.len());
    let n_vars = a.len().trailing_zeros() as usize;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    for round in 0..n_vars {
        let half = a.len() / 2;
        let (g0, g2) = (0..half)
            .into_par_iter()
            .fold(
                || (Fp2::ZERO, Fp2::ZERO),
                |(s0, s2), i| {
                    let (a0, a1) = (a[2 * i], a[2 * i + 1]);
                    let (b0, b1) = (b[2 * i], b[2 * i + 1]);
                    let (da, db) = (a1 - a0, b1 - b0);
                    (s0 + a0 * b0, s2 + (a0 + da + da) * (b0 + db + db))
                },
            )
            .reduce(|| (Fp2::ZERO, Fp2::ZERO), |(x0, x2), (y0, y2)| (x0 + y0, x2 + y2));
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        let corrs = [g0 - masks[0].x, g2 - masks[1].x];
        tx.append("blind_round_corrections", 32);
        round_corrs.push(corrs);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g1_a = claim.sub(g0_a);

        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));
        a = (0..half).into_par_iter().map(|i| a[2 * i] + (a[2 * i + 1] - a[2 * i]) * r).collect();
        b = (0..half).into_par_iter().map(|i| b[2 * i] + (b[2 * i + 1] - b[2 * i]) * r).collect();
        point.push(r);
    }
    (BlindSumcheckProof { round_corrs }, point, claim)
}

/// Public F̃(r*) = Σ_g λ^{g+1}·eq(r_g, r*), computable by both parties.
fn f_at(claims_pts: &[Vec<Fp2>], lambda: Fp2, rstar: &[Fp2]) -> Fp2 {
    let mut acc = Fp2::ZERO;
    let mut w = Fp2::ONE;
    for p in claims_pts {
        w = w * lambda;
        acc += w * eq_points(p, rstar);
    }
    acc
}

/// Reduce all claims to one authenticated `W̃(r*)`. `w` is the full padded
/// coefficient vector (2^n_vars entries as i16, caller pads).
pub fn batch_reduce_prover(
    w: &[i16],
    n_vars: usize,
    claims: &[(BlockClaim, ProverAuthed)],
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> (BlindSumcheckProof, Vec<Fp2>, ProverAuthed, BatchTimings) {
    let size = 1usize << n_vars;
    assert_eq!(w.len(), size);
    assert!(!claims.is_empty());
    let mut tm = BatchTimings::default();

    // λ after all claims are fixed (their corrections are already in tx).
    let lambda = tx.challenge_fp2();

    // F table: block-local eq builds, parallel over disjoint blocks.
    let t0 = Instant::now();
    let mut lam_pows = Vec::with_capacity(claims.len());
    let mut acc = Fp2::ONE;
    for _ in claims {
        acc = acc * lambda;
        lam_pows.push(acc);
    }
    let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
    for (g, (c, _)) in claims.iter().enumerate() {
        let len = 1usize << c.point.len();
        assert!(c.offset % len == 0 && c.offset + len <= size, "bad block");
        groups.entry(c.offset).or_default().push(g);
    }
    let mut f = vec![Fp2::ZERO; size];
    {
        // Disjoint mutable block slices in ascending offset order. Blocks
        // sharing an offset must have equal length (same tensor).
        let mut slices: Vec<(&mut [Fp2], &Vec<usize>)> = Vec::with_capacity(groups.len());
        let mut rest: &mut [Fp2] = &mut f;
        let mut cursor = 0usize;
        for (&off, idxs) in &groups {
            let len = 1usize << claims[idxs[0]].0.point.len();
            for &g in idxs {
                assert_eq!(claims[g].0.point.len(), claims[idxs[0]].0.point.len());
            }
            let (_skip, r) = rest.split_at_mut(off - cursor);
            let (blk, r2) = r.split_at_mut(len);
            slices.push((blk, idxs));
            rest = r2;
            cursor = off + len;
        }
        slices.into_par_iter().for_each(|(blk, idxs)| {
            for &g in idxs {
                add_scaled_eq(blk, &claims[g].0.point, lam_pows[g]);
            }
        });
    }
    tm.t_f_build_s = t0.elapsed().as_secs_f64();

    let t1 = Instant::now();
    let w2: Vec<Fp2> = w.par_iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect();
    tm.t_w_embed_s = t1.elapsed().as_secs_f64();

    let mut claim0 = ProverAuthed::ZERO;
    for (g, (_, v)) in claims.iter().enumerate() {
        claim0 = claim0.add(v.scale(lam_pows[g]));
    }

    let t2 = Instant::now();
    let (proof, rstar, claim_n) = blind_prove_par(f, w2, claim0, stream, mask_dom_base, tx);
    tm.t_rounds_s = t2.elapsed().as_secs_f64();

    let pts: Vec<Vec<Fp2>> = claims.iter().map(|(c, _)| c.global_point(n_vars)).collect();
    let fstar = f_at(&pts, lambda, &rstar);
    assert!(fstar != Fp2::ZERO, "F̃(r*) = 0 (negligible honest probability)");
    let v_star = claim_n.scale(fstar.inv());
    (proof, rstar, v_star, tm)
}

/// Verifier mirror: returns (r*, key of the authenticated W̃(r*)) to be bound
/// to C_W by `ligero::verify_open`.
pub fn batch_reduce_verifier(
    n_vars: usize,
    claims: &[(BlockClaim, VerifierKey)],
    proof: &BlindSumcheckProof,
    ctx: &mut VerifierCtx,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if claims.is_empty() {
        return None;
    }
    let lambda = tx.challenge_fp2();
    let mut lam_pows = Vec::with_capacity(claims.len());
    let mut acc = Fp2::ONE;
    for _ in claims {
        acc = acc * lambda;
        lam_pows.push(acc);
    }
    let mut k0 = VerifierKey::ZERO;
    for (g, (_, k)) in claims.iter().enumerate() {
        k0 = k0.add(k.scale(lam_pows[g]));
    }
    let (rstar, k_n) = blind_verify(n_vars, k0, proof, ctx, mask_dom_base, tx)?;
    let pts: Vec<Vec<Fp2>> = claims.iter().map(|(c, _)| c.global_point(n_vars)).collect();
    let fstar = f_at(&pts, lambda, &rstar);
    if fstar == Fp2::ZERO {
        return None;
    }
    Some((rstar, k_n.scale(fstar.inv())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_proto::mle::{eq_vec, eval_mle};

    #[test]
    fn add_scaled_eq_matches_eq_vec() {
        let mut s = volta_field::FpStream::from_seed([2u8; 32]);
        let point: Vec<Fp2> = (0..5).map(|_| s.next_fp2()).collect();
        let scale = s.next_fp2();
        let mut dst = vec![Fp2::ZERO; 32];
        add_scaled_eq(&mut dst, &point, scale);
        let eq = eq_vec(&point);
        for i in 0..32 {
            assert_eq!(dst[i], eq[i] * scale, "index {i}");
        }
    }

    #[test]
    fn global_point_selects_block() {
        // W̃_global(p ‖ bits(t)) equals the block MLE at p.
        let mut s = volta_field::FpStream::from_seed([3u8; 32]);
        let w: Vec<Fp2> = (0..64).map(|_| s.next_fp2()).collect();
        let point: Vec<Fp2> = (0..4).map(|_| s.next_fp2()).collect();
        let claim = BlockClaim { offset: 48, point: point.clone() };
        let gp = claim.global_point(6);
        assert_eq!(eval_mle(&w, &gp), eval_mle(&w[48..64], &point));
    }
}
