//! Clear (unblinded) product sumcheck — the timed reference of the P3 gate
//! (ρ_clear = t_clear / t_gemm) and the differential oracle for the blind
//! variant. Proves `claim = Σ_l A(l)·B(l)` for two multilinear tables.
//!
//! Round messages are the compressed pair `[g(0), g(2)]`; the verifier
//! derives `g(1) = claim − g(0)`, so per-round consistency holds by
//! construction and soundness rests on the final evaluation check (the
//! standard compressed sumcheck; M3's per-round zero claims specialize to
//! this when the claims are folded into the final one).

use crate::mle::{fold_low, lagrange3};
use volta_field::{Fp2, FpStream};

pub struct ClearProof {
    /// Per round: [g(0), g(2)].
    pub rounds: Vec<[Fp2; 2]>,
    pub a_final: Fp2,
    pub b_final: Fp2,
}

/// Prove; `a`/`b` are consumed (folded in place). Returns the proof and the
/// bound point r_l (LSB-first).
pub fn prove_clear(mut a: Vec<Fp2>, mut b: Vec<Fp2>, chal: &mut FpStream) -> (ClearProof, Vec<Fp2>) {
    assert_eq!(a.len(), b.len());
    assert!(a.len().is_power_of_two());
    let n_vars = a.len().trailing_zeros() as usize;
    let mut rounds = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    for _ in 0..n_vars {
        let half = a.len() / 2;
        let mut g0 = Fp2::ZERO;
        let mut g2 = Fp2::ZERO;
        for i in 0..half {
            let (a0, a1) = (a[2 * i], a[2 * i + 1]);
            let (b0, b1) = (b[2 * i], b[2 * i + 1]);
            g0 += a0 * b0;
            let (da, db) = (a1 - a0, b1 - b0);
            let (a2, b2) = (a0 + da + da, b0 + db + db);
            g2 += a2 * b2;
        }
        rounds.push([g0, g2]);
        let r = chal.next_fp2();
        fold_low(&mut a, r);
        fold_low(&mut b, r);
        point.push(r);
    }
    (ClearProof { rounds, a_final: a[0], b_final: b[0] }, point)
}

/// Verify against a claimed sum; the caller must separately check
/// `a_final`/`b_final` against the input MLEs at the returned point.
pub fn verify_clear(claim: Fp2, proof: &ClearProof, chal: &mut FpStream) -> Option<Vec<Fp2>> {
    let mut claim = claim;
    let mut point = Vec::with_capacity(proof.rounds.len());
    for &[g0, g2] in &proof.rounds {
        let g1 = claim - g0;
        let r = chal.next_fp2();
        let w = lagrange3(r);
        claim = w[0] * g0 + w[1] * g1 + w[2] * g2;
        point.push(r);
    }
    if claim == proof.a_final * proof.b_final {
        Some(point)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::{Fp, FpStream};
    use rand::{Rng, SeedableRng};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(Fp::new(rng.gen_range(0..volta_field::P)), Fp::new(rng.gen_range(0..volta_field::P)))
    }

    #[test]
    fn clear_sumcheck_completeness() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(51);
        let a: Vec<Fp2> = (0..64).map(|_| rand_fp2(&mut rng)).collect();
        let b: Vec<Fp2> = (0..64).map(|_| rand_fp2(&mut rng)).collect();
        let claim = a.iter().zip(&b).fold(Fp2::ZERO, |s, (&x, &y)| s + x * y);
        let seed = [1u8; 32];
        let (proof, point_p) = prove_clear(a.clone(), b.clone(), &mut FpStream::domain_separated(seed, 1));
        let point_v = verify_clear(claim, &proof, &mut FpStream::domain_separated(seed, 1)).expect("accept");
        assert_eq!(point_p, point_v);
        assert_eq!(crate::mle::eval_mle(&a, &point_v), proof.a_final);
        assert_eq!(crate::mle::eval_mle(&b, &point_v), proof.b_final);
    }

    #[test]
    fn clear_sumcheck_rejects_perturbed_round() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(52);
        for trial in 0..50u64 {
            let a: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
            let b: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
            let claim = a.iter().zip(&b).fold(Fp2::ZERO, |s, (&x, &y)| s + x * y);
            let seed = [2u8; 32];
            let (mut proof, _) = prove_clear(a, b, &mut FpStream::domain_separated(seed, trial));
            let k = rng.gen_range(0..proof.rounds.len());
            proof.rounds[k][rng.gen_range(0..2)] += Fp2::ONE;
            // Perturbing a round leaves final a·b unchanged but shifts the
            // running claim — the final check must catch it.
            assert!(verify_clear(claim, &proof, &mut FpStream::domain_separated(seed, trial)).is_none());
        }
    }
}
