//! Batched QuickSilver degree-2 product check (M7/M8).
//!
//! For MAC'd triples (a, b, c) with claimed c = a·b:
//! `k_a·k_b − Δ·k_c = A0 + A1·Δ + (x_a·x_b − x_c)·Δ²` with prover-computable
//! `A0 = m_a·m_b`, `A1 = x_a·m_b + x_b·m_a − m_c`. Honest triples kill the Δ²
//! term, so the χ-batched sum is linear in Δ; the prover opens (M0, M1)
//! masked by one fresh full-field correlation (M7: masked degree-2 messages;
//! M8: batched soundness error ≤ 3/|F|).

use volta_field::Fp2;
use volta_mac::{FullCorr, ProverAuthed, Transcript, VerifierKey};

#[derive(Debug, PartialEq, Eq)]
pub struct ProdProof {
    pub m0: Fp2,
    pub m1: Fp2,
}

/// Prover: χ-batched masked opening for `triples` = [(a, b, c = a·b)].
pub fn prod_batch_prover(
    triples: &[(ProverAuthed, ProverAuthed, ProverAuthed)],
    chi: Fp2,
    mask: FullCorr,
    tx: &mut Transcript,
) -> ProdProof {
    let mut m0 = mask.m;
    let mut m1 = mask.x;
    let mut w = Fp2::ONE;
    for (a, b, c) in triples {
        debug_assert_eq!(c.x, a.x * b.x, "Π_Prod on a false product");
        w = w * chi;
        m0 += w * (a.m * b.m);
        m1 += w * (a.x * b.m + b.x * a.m - c.m);
    }
    tx.append("prod_check_m0_m1", 32);
    ProdProof { m0, m1 }
}

/// Verifier: `Σ χ^{t+1}(k_a·k_b − Δ·k_c) + k_mask == M0 + M1·Δ`.
pub fn prod_batch_verify(
    keys: &[(VerifierKey, VerifierKey, VerifierKey)],
    k_mask: Fp2,
    delta: Fp2,
    chi: Fp2,
    proof: &ProdProof,
) -> bool {
    let mut acc = k_mask;
    let mut w = Fp2::ONE;
    for (ka, kb, kc) in keys {
        w = w * chi;
        acc += w * (ka.k * kb.k - delta * kc.k);
    }
    acc == proof.m0 + proof.m1 * delta
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use volta_field::Fp;
    use volta_mac::{CorrelationStream, VerifierCtx};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
    }

    fn setup(seed_byte: u8, rng: &mut impl Rng) -> (CorrelationStream, VerifierCtx) {
        let seed = [seed_byte; 32];
        (CorrelationStream::new(seed), VerifierCtx::new(seed, rand_fp2(rng)))
    }

    /// Authenticate arbitrary Fp2 plaintexts from full correlations (the
    /// production path authenticates via corrections; for the unit test the
    /// mock streams make both halves directly computable).
    fn authed_batch(
        ps: &mut CorrelationStream,
        vc: &mut VerifierCtx,
        dom: u64,
        xs: &[Fp2],
    ) -> (Vec<ProverAuthed>, Vec<VerifierKey>) {
        let fulls = ps.draw_fulls(dom, xs.len());
        let kfulls = vc.expand_full_keys(dom, xs.len());
        let mut pa = Vec::new();
        let mut ka = Vec::new();
        for ((f, kf), &x) in fulls.iter().zip(&kfulls).zip(xs) {
            let c = x - f.x; // correction transfer, 16 B in production
            pa.push(ProverAuthed { x, m: f.m });
            ka.push(VerifierKey { k: *kf + vc.delta * c });
        }
        (pa, ka)
    }

    fn run_case(tamper: bool, seed: u8) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 70);
        let (mut ps, mut vc) = setup(seed, &mut rng);
        let mut tx = Transcript::new([seed ^ 0x55; 32]);
        let t = 8;
        let xa: Vec<Fp2> = (0..t).map(|_| rand_fp2(&mut rng)).collect();
        let xb: Vec<Fp2> = (0..t).map(|_| rand_fp2(&mut rng)).collect();
        let mut xc: Vec<Fp2> = xa.iter().zip(&xb).map(|(&a, &b)| a * b).collect();
        if tamper {
            xc[3] += Fp2::ONE;
        }
        let (pa, ka) = authed_batch(&mut ps, &mut vc, 1, &xa);
        let (pb, kb) = authed_batch(&mut ps, &mut vc, 2, &xb);
        let (pc, kc) = authed_batch(&mut ps, &mut vc, 3, &xc);
        let mask = ps.draw_fulls(9, 1)[0];
        let k_mask = vc.expand_full_keys(9, 1)[0];
        let chi = tx.challenge_fp2();
        let triples: Vec<_> = (0..t).map(|i| (pa[i], pb[i], pc[i])).collect();
        let keys: Vec<_> = (0..t).map(|i| (ka[i], kb[i], kc[i])).collect();
        let proof = if tamper {
            // bypass the debug assert: prover lies, computing A1 as if honest
            let mut m0 = mask.m;
            let mut m1 = mask.x;
            let mut w = Fp2::ONE;
            for (a, b, c) in &triples {
                w = w * chi;
                m0 += w * (a.m * b.m);
                m1 += w * (a.x * b.m + b.x * a.m - c.m);
            }
            ProdProof { m0, m1 }
        } else {
            prod_batch_prover(&triples, chi, mask, &mut tx)
        };
        prod_batch_verify(&keys, k_mask, vc.delta, chi, &proof)
    }

    #[test]
    fn prod_batch_completeness() {
        for s in 0..20u8 {
            assert!(run_case(false, s), "honest batch rejected at seed {s}");
        }
    }

    #[test]
    fn prod_batch_rejects_false_product() {
        for s in 0..20u8 {
            assert!(!run_case(true, s), "false product accepted at seed {s}");
        }
    }
}
