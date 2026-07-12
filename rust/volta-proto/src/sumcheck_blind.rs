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
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceSlice, Fp2Repr};
use volta_field::Fp2;
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

#[derive(Debug, PartialEq, Eq)]
pub struct BlindSumcheckProof {
    /// Per round: corrections (16 B each) transferring g(0), g(2) onto masks.
    pub round_corrs: Vec<[Fp2; 2]>,
}

fn free_fp2_pair(
    backend: &mut Backend,
    a: DeviceBuffer<Fp2Repr>,
    b: DeviceBuffer<Fp2Repr>,
) -> Result<(), AccelError> {
    let first = backend.free_device(a).err();
    let second = backend.free_device(b).err();
    first.or(second).map_or(Ok(()), Err)
}

/// Resident counterpart of [`blind_prove`]. Rust retains transcript and MAC
/// orchestration; each round returns only `[g(0), g(2)]`, then folds both
/// witness vectors D2D. The input buffers are consumed on every path.
pub fn blind_prove_resident(
    mut a: DeviceBuffer<Fp2Repr>,
    mut b: DeviceBuffer<Fp2Repr>,
    claim0: ProverAuthed,
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(BlindSumcheckProof, Vec<Fp2>, ProverAuthed, Fp2, Fp2), AccelError> {
    if a.len() != b.len() || a.len() < 2 || !a.len().is_power_of_two() {
        let _ = free_fp2_pair(backend, a, b);
        return Err(AccelError::InvalidInput(
            "resident blind sumcheck requires equal power-of-two vectors",
        ));
    }
    let n_vars = a.len().trailing_zeros() as usize;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    for round in 0..n_vars {
        let len = a.len();
        let round_values = match backend.fp2_product_round_device(
            DeviceSlice::new(&a, 0, len).expect("whole resident A vector"),
            DeviceSlice::new(&b, 0, len).expect("whole resident B vector"),
        ) {
            Ok(values) => values,
            Err(error) => {
                let _ = free_fp2_pair(backend, a, b);
                return Err(error);
            }
        };
        let [g0, g2] = round_values;
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
        tx.append("blind_round_corrections", 32);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g1_a = claim.sub(g0_a);
        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));

        let next_a = match backend.fp2_fold_rows_device(&a, 0, 1, len, r) {
            Ok(value) => value,
            Err(error) => {
                let _ = free_fp2_pair(backend, a, b);
                return Err(error);
            }
        };
        let next_b = match backend.fp2_fold_rows_device(&b, 0, 1, len, r) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(next_a);
                let _ = free_fp2_pair(backend, a, b);
                return Err(error);
            }
        };
        if let Err(error) = free_fp2_pair(backend, a, b) {
            let _ = free_fp2_pair(backend, next_a, next_b);
            return Err(error);
        }
        a = next_a;
        b = next_b;
        point.push(r);
    }
    let a_final = match backend.download_device(&a, 0, 1) {
        Ok(value) => Fp2::from(value[0]),
        Err(error) => {
            let _ = free_fp2_pair(backend, a, b);
            return Err(error);
        }
    };
    let b_final = match backend.download_device(&b, 0, 1) {
        Ok(value) => Fp2::from(value[0]),
        Err(error) => {
            let _ = free_fp2_pair(backend, a, b);
            return Err(error);
        }
    };
    free_fp2_pair(backend, a, b)?;
    Ok((BlindSumcheckProof { round_corrs }, point, claim, a_final, b_final))
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
    use rand::{Rng, SeedableRng};
    use volta_field::{Fp, FpStream};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
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
        let (clear, _) =
            prove_clear(a.clone(), b.clone(), &mut FpStream::domain_separated(tx_seed, u64::MAX));

        let mut ps = CorrelationStream::new([5u8; 32]);
        let mut tx = Transcript::new(tx_seed);
        let claim0 = ProverAuthed { x: claim_val, m: rand_fp2(&mut rng) };
        let (blind, _, final_claim) =
            blind_prove(a.clone(), b.clone(), claim0, &mut ps, 1000, &mut tx);

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

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_blind_sumcheck_matches_cpu_and_reuses_context() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident sumcheck differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51A7);
        let a: Vec<Fp2> = (0..128).map(|_| rand_fp2(&mut rng)).collect();
        let b: Vec<Fp2> = (0..128).map(|_| rand_fp2(&mut rng)).collect();
        let total = a.iter().zip(&b).fold(Fp2::ZERO, |sum, (&x, &y)| sum + x * y);
        let claim0 = ProverAuthed { x: total, m: rand_fp2(&mut rng) };
        let pcg_seed = [0xA3; 32];
        let tx_seed = [0x6C; 32];
        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let (cpu_proof, cpu_point, cpu_claim) =
            blind_prove(a.clone(), b.clone(), claim0, &mut cpu_stream, 0xD000, &mut cpu_tx);
        let mut live_after_first = None;
        for _ in 0..2 {
            let da = gpu
                .upload_new_device(&a.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let db = gpu
                .upload_new_device(&b.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let mut stream = CorrelationStream::new(pcg_seed);
            let mut tx = Transcript::new(tx_seed);
            let (proof, point, claim, a_final, b_final) =
                blind_prove_resident(da, db, claim0, &mut stream, 0xD000, &mut tx, &mut gpu)
                    .unwrap();
            assert_eq!(proof, cpu_proof);
            assert_eq!(point, cpu_point);
            assert_eq!(claim, cpu_claim);
            assert_eq!(a_final, crate::mle::eval_mle(&a, &point));
            assert_eq!(b_final, crate::mle::eval_mle(&b, &point));
            assert_eq!(stream.counters, cpu_stream.counters);
            assert_eq!(tx.ledger(), cpu_tx.ledger());
            let live = gpu.stats().unwrap().live_device_bytes;
            if let Some(first) = live_after_first {
                assert_eq!(live, first, "resident sumcheck leaked across context reuse");
            } else {
                // Workspace is persistent by design; resident inputs/folds
                // have already been freed by the sumcheck.
                assert!(live > 0);
                live_after_first = Some(live);
            }
        }
    }
}
