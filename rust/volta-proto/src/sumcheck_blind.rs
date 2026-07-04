//! Blind product sumcheck (M3 schema, compressed variant): the round
//! polynomial evaluations are never revealed — each is transferred as an
//! authenticated value via a correction against a **fresh full-field mask**
//! (one per coefficient per round, never reused: `CorrelationStream`'s
//! one-time ledger enforces what M3's `uniformVec_zipWith_sub` requires).
//! Challenges are public (interactive-mock, from the shared transcript).
//!
//! With the compressed `[g(0), g(2)]` encoding, `g(1) = claim − g(0)` holds
//! by construction on both the value and the key side, so the per-round zero
//! claims of the Lean statement fold into the final claim, which the caller
//! closes with Π_Prod / ZeroBatch against authenticated tensor openings.

use crate::mle::{fold_low, lagrange3};
use volta_field::Fp2;
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

pub struct BlindSumcheckProof {
    /// Per round: corrections (16 B each) transferring g(0), g(2) onto masks.
    pub round_corrs: Vec<[Fp2; 2]>,
}

/// Prover. `claim0` is the (authenticated) initial claim Ỹ(r_i, r_j).
/// Returns the proof, the bound point, and the authenticated final claim.
/// Mask domains are `mask_dom_base + round`.
pub fn blind_prove(
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
        let mut g0 = Fp2::ZERO;
        let mut g2 = Fp2::ZERO;
        for i in 0..half {
            let (a0, a1) = (a[2 * i], a[2 * i + 1]);
            let (b0, b1) = (b[2 * i], b[2 * i + 1]);
            g0 += a0 * b0;
            let (da, db) = (a1 - a0, b1 - b0);
            g2 += (a0 + da + da) * (b0 + db + db);
        }
        // Fresh full-field masks for the two coefficients of this round.
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        let corrs = [g0 - masks[0].x, g2 - masks[1].x];
        tx.append("blind_round_corrections", 32);
        round_corrs.push(corrs);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g1_a = claim.sub(g0_a); // g(1) = claim − g(0), authenticated

        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));
        fold_low(&mut a, r);
        fold_low(&mut b, r);
        point.push(r);
    }
    (BlindSumcheckProof { round_corrs }, point, claim)
}

/// Verifier: mirrors the recursion on the key side. Returns the bound point
/// and the key of the final claim.
pub fn blind_verify(
    n_vars: usize,
    k_claim0: VerifierKey,
    proof: &BlindSumcheckProof,
    ctx: &mut VerifierCtx,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if proof.round_corrs.len() != n_vars {
        return None;
    }
    let mut point = Vec::with_capacity(n_vars);
    let mut k_claim = k_claim0;
    for (round, corrs) in proof.round_corrs.iter().enumerate() {
        let k_masks = ctx.expand_full_keys(mask_dom_base + round as u64, 2);
        let k_g0 = VerifierKey { k: k_masks[0] + ctx.delta * corrs[0] };
        let k_g2 = VerifierKey { k: k_masks[1] + ctx.delta * corrs[1] };
        let k_g1 = k_claim.sub(k_g0);
        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        k_claim = k_g0.scale(w[0]).add(k_g1.scale(w[1])).add(k_g2.scale(w[2]));
        point.push(r);
    }
    Some((point, k_claim))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumcheck_clear::prove_clear;
    use volta_field::{Fp, FpStream};
    use rand::{Rng, SeedableRng};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(Fp::new(rng.gen_range(0..volta_field::P)), Fp::new(rng.gen_range(0..volta_field::P)))
    }

    #[test]
    fn blind_matches_clear_differential() {
        // Same witness, same challenges: the blind transcript's authenticated
        // round values must equal the clear round polys pointwise.
        let mut rng = rand::rngs::StdRng::seed_from_u64(81);
        let a: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
        let b: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
        let claim_val = a.iter().zip(&b).fold(Fp2::ZERO, |s, (&x, &y)| s + x * y);

        // Clear reference with the transcript's challenge stream: Transcript
        // challenges come from domain u64::MAX of the tx seed.
        let tx_seed = [4u8; 32];
        let (clear, _) = prove_clear(a.clone(), b.clone(), &mut FpStream::domain_separated(tx_seed, u64::MAX));

        let mut ps = CorrelationStream::new([5u8; 32]);
        let mut tx = Transcript::new(tx_seed);
        let claim0 = ProverAuthed { x: claim_val, m: rand_fp2(&mut rng) };
        let (blind, _, final_claim) = blind_prove(a.clone(), b.clone(), claim0, &mut ps, 1000, &mut tx);

        // Reconstruct blind g values from corrections + the same mask stream.
        let mut check = CorrelationStream::new([5u8; 32]);
        for (round, corrs) in blind.round_corrs.iter().enumerate() {
            let masks = check.draw_fulls(1000 + round as u64, 2);
            assert_eq!(masks[0].x + corrs[0], clear.rounds[round][0], "g(0) round {round}");
            assert_eq!(masks[1].x + corrs[1], clear.rounds[round][1], "g(2) round {round}");
        }
        assert_eq!(final_claim.x, clear.a_final * clear.b_final);
        // Mask freshness: 2 fresh full correlations per round, all counted.
        assert_eq!(ps.counters.full_corrs, 2 * blind.round_corrs.len() as u64);
    }
}
