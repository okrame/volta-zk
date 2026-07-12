//! Blind degree-3 sumcheck for a broadcast Hadamard product (P4):
//! `w̃acc(ρ) = Σ_y eq(ρ, y)·e(y)·R(y)`, where `R` is a per-row vector
//! broadcast over the column block. The caller passes both factors already
//! expanded to the full 2^n domain (`e` lifted to `Fp2`, `R` replicated
//! across columns), so each round folds three tables (eq/e/R) and the round
//! polynomial has degree 3: the masked evaluations `[g(0), g(2), g(3)]`
//! travel as corrections against fresh full-field masks; `g(1) = claim −
//! g(0)` holds by construction on both the value and the key side, and the
//! next claim is a cubic interpolation (`crate::logup::lagrange4`).
//!
//! The end game mirrors the logup leaf sink: ẽ(r) and R̃(r) are
//! authenticated with fresh full correlations, `z = ẽ(r)·R̃(r)` is pushed as
//! a Π_Prod triple into the caller's batch, and the closing relation
//! `eq(ρ, r)·z − claim_n = 0` (eq(ρ, r) is public) goes into the caller's
//! ZeroBatch rows. Nothing here draws sub-field correlations.
//!
//! **Broadcast fact** (for the caller routing the R claim): with column
//! variables LSB, `R(y) = recip(row(y))` implies
//! `R̃(r_cols ‖ r_rows) = rẽcip(r_rows)` — the multilinear extension of a
//! column-constant table is constant in the column variables, so the
//! returned R claim at the FULL sumcheck point IS the recip claim at the row
//! part of that point. No extra reduction is needed to hand it to the
//! instance that owns the per-row reciprocals.

use crate::logup::{lagrange4, Doms, ProdKeyTriples, ProdTriples};
use crate::mle::{eq_points, eq_vec, fold_low};
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceSlice, Fp2Repr};
use volta_field::Fp2;
use volta_mac::{CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};

/// Correlation domains for one Hadamard instance, caller-allocated via
/// `crate::logup::Doms` (mirrored verifier-side). The round block needs
/// `n_vars` consecutive domains (3 fulls each).
pub struct HadamardDoms {
    /// Degree-3 rounds: `round_masks + round`, 3 fulls per round.
    pub round_masks: u64,
    /// Fresh full correlation authenticating ẽ(r).
    pub e_claim: u64,
    /// Fresh full correlation authenticating R̃(r).
    pub r_claim: u64,
    /// Fresh full correlation authenticating z = ẽ(r)·R̃(r).
    pub z: u64,
}

impl HadamardDoms {
    /// Allocate all domains for one instance over `n_vars` variables.
    pub fn alloc(doms: &mut Doms, n_vars: usize) -> HadamardDoms {
        HadamardDoms {
            round_masks: doms.take(n_vars as u64),
            e_claim: doms.take(1),
            r_claim: doms.take(1),
            z: doms.take(1),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct HadamardProof {
    /// Per round: corrections (16 B each) transferring g(0), g(2), g(3).
    pub round_corrs: Vec<[Fp2; 3]>,
    pub e_corr: Fp2,
    pub r_corr: Fp2,
    pub z_corr: Fp2,
}

/// Evaluations of the line through (0, v0), (1, v1) at t ∈ {0, 2, 3}.
#[inline]
fn at023(v0: Fp2, v1: Fp2) -> (Fp2, Fp2, Fp2) {
    let d = v1 - v0;
    let v2 = v0 + d + d;
    (v0, v2, v2 + d)
}

/// Prover. `claim0` is the (authenticated) initial claim w̃acc(ρ); `e` and
/// `r_tab` are the full-domain tables (length 2^ρ.len()). Returns the proof,
/// the bound point, and the authenticated ẽ(r) / R̃(r) claims — the Π_Prod
/// triple and the closing zero row are pushed into the caller's batches.
#[allow(clippy::too_many_arguments)]
pub fn hadamard_prove(
    rho: &[Fp2],
    e: Vec<Fp2>,
    r_tab: Vec<Fp2>,
    claim0: ProverAuthed,
    doms: &HadamardDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> (HadamardProof, Vec<Fp2>, ProverAuthed, ProverAuthed) {
    let n_vars = rho.len();
    assert_eq!(e.len(), 1 << n_vars);
    assert_eq!(r_tab.len(), 1 << n_vars);
    let mut e = e;
    let mut r_tab = r_tab;
    let mut eq_t = eq_vec(rho);
    debug_assert_eq!(
        claim0.x,
        eq_t.iter().zip(&e).zip(&r_tab).fold(Fp2::ZERO, |s, ((&q, &a), &b)| s + q * a * b),
        "claim0 is not the Hadamard total"
    );

    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    for round in 0..n_vars {
        let half = e.len() / 2;
        let (mut g0, mut g2, mut g3) = (Fp2::ZERO, Fp2::ZERO, Fp2::ZERO);
        for i in 0..half {
            let (q0, q2, q3) = at023(eq_t[2 * i], eq_t[2 * i + 1]);
            let (e0, e2, e3) = at023(e[2 * i], e[2 * i + 1]);
            let (r0, r2, r3) = at023(r_tab[2 * i], r_tab[2 * i + 1]);
            g0 += q0 * e0 * r0;
            g2 += q2 * e2 * r2;
            g3 += q3 * e3 * r3;
        }
        // Three fresh full-field masks for this round's coefficients.
        let masks = stream.draw_fulls(doms.round_masks + round as u64, 3);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x, g3 - masks[2].x]);
        tx.append("hadamard_round_corrections", 48);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g3_a = ProverAuthed { x: g3, m: masks[2].m };
        let g1_a = claim.sub(g0_a); // g(1) = claim − g(0), authenticated

        let r = tx.challenge_fp2();
        let w = lagrange4(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2])).add(g3_a.scale(w[3]));
        fold_low(&mut eq_t, r);
        fold_low(&mut e, r);
        fold_low(&mut r_tab, r);
        point.push(r);
    }

    // End game: authenticate the two openings, close through Π_Prod and a
    // public-eq zero row (caller batches both).
    let e_final = e[0];
    let r_final = r_tab[0];
    let fe = stream.draw_fulls(doms.e_claim, 1)[0];
    let e_corr = e_final - fe.x;
    let fr = stream.draw_fulls(doms.r_claim, 1)[0];
    let r_corr = r_final - fr.x;
    let zx = e_final * r_final;
    let fz = stream.draw_fulls(doms.z, 1)[0];
    let z_corr = zx - fz.x;
    tx.append("hadamard_claim_corrections", 48);
    let e_a = ProverAuthed { x: e_final, m: fe.m };
    let r_a = ProverAuthed { x: r_final, m: fr.m };
    let z_a = ProverAuthed { x: zx, m: fz.m };
    prod.push((e_a, r_a, z_a));
    let row = z_a.scale(eq_points(rho, &point)).sub(claim);
    debug_assert_eq!(row.x, Fp2::ZERO, "hadamard closing relation violated");
    zero.push(row);

    (HadamardProof { round_corrs, e_corr, r_corr, z_corr }, point, e_a, r_a)
}

fn free_resident_triple(
    backend: &mut Backend,
    a: DeviceBuffer<Fp2Repr>,
    b: DeviceBuffer<Fp2Repr>,
    c: DeviceBuffer<Fp2Repr>,
) -> Result<(), AccelError> {
    let first = backend.free_device(a).err();
    let second = backend.free_device(b).err();
    let third = backend.free_device(c).err();
    first.or(second).or(third).map_or(Ok(()), Err)
}

/// Device-resident counterpart of [`hadamard_prove`]. The two factors and
/// equality table are folded D2D; Rust receives only the three round values
/// and two final scalar openings required to construct the unchanged proof.
#[allow(clippy::too_many_arguments)]
pub fn hadamard_prove_resident(
    rho: &[Fp2],
    e: DeviceBuffer<Fp2Repr>,
    r_tab: DeviceBuffer<Fp2Repr>,
    claim0: ProverAuthed,
    doms: &HadamardDoms,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> Result<(HadamardProof, Vec<Fp2>, ProverAuthed, ProverAuthed), AccelError> {
    let expected = 1usize
        .checked_shl(rho.len() as u32)
        .ok_or(AccelError::InvalidInput("resident Hadamard dimension overflow"))?;
    if e.len() != expected || r_tab.len() != expected || expected < 2 {
        let _ = backend.free_device(r_tab);
        let _ = backend.free_device(e);
        return Err(AccelError::InvalidInput("resident Hadamard geometry mismatch"));
    }
    let mut eq_t = match backend.equality_weights_device(rho) {
        Ok(value) => value,
        Err(error) => {
            let _ = backend.free_device(r_tab);
            let _ = backend.free_device(e);
            return Err(error);
        }
    };
    let mut e = e;
    let mut r_tab = r_tab;
    let mut len = expected;
    let mut round_corrs = Vec::with_capacity(rho.len());
    let mut point = Vec::with_capacity(rho.len());
    let mut claim = claim0;
    for round in 0..rho.len() {
        let values = backend.fp2_triple_product_round_device(
            DeviceSlice::new(&eq_t, 0, len).expect("resident Hadamard eq prefix"),
            DeviceSlice::new(&e, 0, len).expect("resident Hadamard e prefix"),
            DeviceSlice::new(&r_tab, 0, len).expect("resident Hadamard R prefix"),
        );
        let [g0, g2, g3] = match values {
            Ok(value) => value,
            Err(error) => {
                let _ = free_resident_triple(backend, eq_t, e, r_tab);
                return Err(error);
            }
        };
        let masks = stream.draw_fulls(doms.round_masks + round as u64, 3);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x, g3 - masks[2].x]);
        tx.append("hadamard_round_corrections", 48);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g3_a = ProverAuthed { x: g3, m: masks[2].m };
        let g1_a = claim.sub(g0_a);
        let challenge = tx.challenge_fp2();
        let weights = lagrange4(challenge);
        claim = g0_a
            .scale(weights[0])
            .add(g1_a.scale(weights[1]))
            .add(g2_a.scale(weights[2]))
            .add(g3_a.scale(weights[3]));

        let next_eq = match backend.fp2_fold_rows_device(&eq_t, 0, 1, len, challenge) {
            Ok(value) => value,
            Err(error) => {
                let _ = free_resident_triple(backend, eq_t, e, r_tab);
                return Err(error);
            }
        };
        let next_e = match backend.fp2_fold_rows_device(&e, 0, 1, len, challenge) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(next_eq);
                let _ = free_resident_triple(backend, eq_t, e, r_tab);
                return Err(error);
            }
        };
        let next_r = match backend.fp2_fold_rows_device(&r_tab, 0, 1, len, challenge) {
            Ok(value) => value,
            Err(error) => {
                let _ = backend.free_device(next_e);
                let _ = backend.free_device(next_eq);
                let _ = free_resident_triple(backend, eq_t, e, r_tab);
                return Err(error);
            }
        };
        if let Err(error) = free_resident_triple(backend, eq_t, e, r_tab) {
            let _ = free_resident_triple(backend, next_eq, next_e, next_r);
            return Err(error);
        }
        eq_t = next_eq;
        e = next_e;
        r_tab = next_r;
        len /= 2;
        point.push(challenge);
    }

    let e_final = backend.download_device(&e, 0, 1).map(|values| Fp2::from(values[0]));
    let r_final = backend.download_device(&r_tab, 0, 1).map(|values| Fp2::from(values[0]));
    let free_result = free_resident_triple(backend, eq_t, e, r_tab);
    let (e_final, r_final) = match (e_final, r_final, free_result) {
        (Ok(e), Ok(r), Ok(())) => (e, r),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => return Err(error),
    };
    let fe = stream.draw_fulls(doms.e_claim, 1)[0];
    let e_corr = e_final - fe.x;
    let fr = stream.draw_fulls(doms.r_claim, 1)[0];
    let r_corr = r_final - fr.x;
    let product = e_final * r_final;
    let fz = stream.draw_fulls(doms.z, 1)[0];
    let z_corr = product - fz.x;
    tx.append("hadamard_claim_corrections", 48);
    let e_auth = ProverAuthed { x: e_final, m: fe.m };
    let r_auth = ProverAuthed { x: r_final, m: fr.m };
    let z_auth = ProverAuthed { x: product, m: fz.m };
    prod.push((e_auth, r_auth, z_auth));
    let row = z_auth.scale(eq_points(rho, &point)).sub(claim);
    debug_assert_eq!(row.x, Fp2::ZERO, "resident Hadamard closing relation violated");
    zero.push(row);
    Ok((HadamardProof { round_corrs, e_corr, r_corr, z_corr }, point, e_auth, r_auth))
}

/// Verifier: mirrors the recursion on the key side, pushes the key triple
/// and the key zero row into the caller's batches, and returns the bound
/// point plus the ẽ(r) / R̃(r) claim keys for outward routing.
#[allow(clippy::too_many_arguments)]
pub fn hadamard_verify(
    rho: &[Fp2],
    k_claim0: VerifierKey,
    proof: &HadamardProof,
    doms: &HadamardDoms,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    prod: &mut ProdKeyTriples,
    zero: &mut Vec<VerifierKey>,
) -> Option<(Vec<Fp2>, VerifierKey, VerifierKey)> {
    let n_vars = rho.len();
    if proof.round_corrs.len() != n_vars {
        return None;
    }
    let mut point = Vec::with_capacity(n_vars);
    let mut k_claim = k_claim0;
    for (round, corrs) in proof.round_corrs.iter().enumerate() {
        let k_masks = ctx.expand_full_keys(doms.round_masks + round as u64, 3);
        let k_g0 = VerifierKey { k: k_masks[0] + ctx.delta * corrs[0] };
        let k_g2 = VerifierKey { k: k_masks[1] + ctx.delta * corrs[1] };
        let k_g3 = VerifierKey { k: k_masks[2] + ctx.delta * corrs[2] };
        let k_g1 = k_claim.sub(k_g0);
        let r = tx.challenge_fp2();
        let w = lagrange4(r);
        k_claim =
            k_g0.scale(w[0]).add(k_g1.scale(w[1])).add(k_g2.scale(w[2])).add(k_g3.scale(w[3]));
        point.push(r);
    }
    let k_e =
        VerifierKey { k: ctx.expand_full_keys(doms.e_claim, 1)[0] + ctx.delta * proof.e_corr };
    let k_r =
        VerifierKey { k: ctx.expand_full_keys(doms.r_claim, 1)[0] + ctx.delta * proof.r_corr };
    let k_z = VerifierKey { k: ctx.expand_full_keys(doms.z, 1)[0] + ctx.delta * proof.z_corr };
    prod.push((k_e, k_r, k_z));
    zero.push(k_z.scale(eq_points(rho, &point)).sub(k_claim));
    Some((point, k_e, k_r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mle::eval_mle;
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use rand::{Rng, SeedableRng};
    use volta_field::Fp;

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
    }

    /// T = 8 rows × 4 broadcast columns (5 vars, column vars LSB). Closes
    /// the Π_Prod batch and checks the zero rows with the test-only
    /// both-sides equality k = m + Δ·x (prod_check.rs trick).
    fn run(seed: u8, tamper: bool) -> bool {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 120);
        let (col_bits, row_bits) = (2usize, 3usize);
        let n_vars = col_bits + row_bits;
        let pcg_seed = [seed ^ 0x0B; 32];
        let tx_seed = [seed ^ 0x6E; 32];
        let delta = Fp2::new(Fp::new(0xFACADE + seed as u64), Fp::new(41 + seed as u64));

        let mut stream = CorrelationStream::new(pcg_seed);
        let mut tx = Transcript::new(tx_seed);
        let mut ctx = VerifierCtx::new(pcg_seed, delta);
        let mut vtx = Transcript::new(tx_seed);

        let rho: Vec<Fp2> = (0..n_vars).map(|_| tx.challenge_fp2()).collect();
        let rho_v: Vec<Fp2> = (0..n_vars).map(|_| vtx.challenge_fp2()).collect();

        let e: Vec<Fp2> = (0..1 << n_vars).map(|_| rand_fp2(&mut rng)).collect();
        let row_vals: Vec<Fp2> = (0..1 << row_bits).map(|_| rand_fp2(&mut rng)).collect();
        let r_tab: Vec<Fp2> = (0..1usize << n_vars).map(|y| row_vals[y >> col_bits]).collect();

        // claim0 = true Σ eq(ρ,y)·e(y)·R(y), authed both sides at a test dom.
        let eq = eq_vec(&rho);
        let total =
            eq.iter().zip(&e).zip(&r_tab).fold(Fp2::ZERO, |s, ((&q, &a), &b)| s + q * a * b);
        let f0 = stream.draw_fulls(1, 1)[0];
        let c0 = total - f0.x;
        let claim0 = ProverAuthed { x: total, m: f0.m };
        let k0 = VerifierKey { k: ctx.expand_full_keys(1, 1)[0] + delta * c0 };

        let hd = HadamardDoms::alloc(&mut Doms::new(0x100), n_vars);
        let mut prod_p: ProdTriples = Vec::new();
        let mut zero_p: Vec<ProverAuthed> = Vec::new();
        let (mut proof, point, e_claim, r_claim) = hadamard_prove(
            &rho,
            e.clone(),
            r_tab.clone(),
            claim0,
            &hd,
            &mut stream,
            &mut tx,
            &mut prod_p,
            &mut zero_p,
        );
        if tamper {
            proof.round_corrs[1][0] += Fp2::ONE;
        }

        let mut prod_k: ProdKeyTriples = Vec::new();
        let mut zero_k: Vec<VerifierKey> = Vec::new();
        let Some((point_v, k_e, k_r)) =
            hadamard_verify(&rho_v, k0, &proof, &hd, &mut ctx, &mut vtx, &mut prod_k, &mut zero_k)
        else {
            return false;
        };
        assert_eq!(point_v, point, "sumcheck point mismatch across parties");

        if !tamper {
            // Opened claims equal the brute-force MLE evaluations …
            assert_eq!(e_claim.x, eval_mle(&e, &point), "e claim value wrong");
            assert_eq!(r_claim.x, eval_mle(&r_tab, &point), "R claim value wrong");
            // … and the broadcast fact: the R claim at the FULL point is the
            // per-row (recip) claim at the row part of the point.
            assert_eq!(
                r_claim.x,
                eval_mle(&row_vals, &point[col_bits..]),
                "broadcast R claim != row-claim at r_rows"
            );
        }

        // Close the Π_Prod batch (fresh mask, both sides).
        let mask = stream.draw_fulls(2, 1)[0];
        let k_mask = ctx.expand_full_keys(2, 1)[0];
        let chi = tx.challenge_fp2();
        let chi_v = vtx.challenge_fp2();
        let pp = prod_batch_prover(&prod_p, chi, mask, &mut tx);
        let prod_ok = prod_batch_verify(&prod_k, k_mask, delta, chi_v, &pp);

        // ZeroBatch stand-in: zero rows valid on both sides (x = 0, k = m).
        let zeros_ok = zero_p.len() == zero_k.len()
            && zero_p
                .iter()
                .zip(&zero_k)
                .all(|(row, key)| row.x == Fp2::ZERO && key.k == row.m + delta * row.x);
        // Outward claim keys are valid MACs on the returned values.
        let keys_ok =
            k_e.k == e_claim.m + delta * e_claim.x && k_r.k == r_claim.m + delta * r_claim.x;
        prod_ok && zeros_ok && keys_ok
    }

    #[test]
    fn hadamard_honest_completeness() {
        for s in 0..5u8 {
            assert!(run(s, false), "honest hadamard rejected, seed {s}");
        }
    }

    #[test]
    fn hadamard_rejects_tampered_round() {
        // A flipped round correction shifts the verifier's key chain; the
        // Π_Prod legs stay honest, so the reject surfaces at the zero row.
        for s in 0..10u8 {
            assert!(!run(s, true), "tampered hadamard accepted, seed {s}");
        }
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_hadamard_matches_cpu_and_reuses_context() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident Hadamard differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let n_vars = 6usize;
        let len = 1usize << n_vars;
        let rho: Vec<Fp2> = (0..n_vars)
            .map(|i| Fp2::new(Fp::new(i as u64 * 73 + 5), Fp::new(i as u64 * 89 + 7)))
            .collect();
        let e: Vec<Fp2> = (0..len)
            .map(|i| Fp2::new(Fp::new(i as u64 * 97 + 11), Fp::new(i as u64 * 101 + 13)))
            .collect();
        let r_tab: Vec<Fp2> = (0..len)
            .map(|i| Fp2::new(Fp::new(i as u64 * 103 + 17), Fp::new(i as u64 * 107 + 19)))
            .collect();
        let eq = eq_vec(&rho);
        let total =
            eq.iter().zip(&e).zip(&r_tab).fold(Fp2::ZERO, |sum, ((&q, &a), &b)| sum + q * a * b);

        let run_cpu = || {
            let mut stream = CorrelationStream::new([101; 32]);
            let mut tx = Transcript::new([102; 32]);
            let initial = stream.draw_fulls(1, 1)[0];
            let claim0 = ProverAuthed { x: total, m: initial.m };
            let doms = HadamardDoms::alloc(&mut Doms::new(0xA100), n_vars);
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let out = hadamard_prove(
                &rho,
                e.clone(),
                r_tab.clone(),
                claim0,
                &doms,
                &mut stream,
                &mut tx,
                &mut prod,
                &mut zero,
            );
            (out, prod, zero, stream.counters, tx.ledger().clone())
        };
        let expected = run_cpu();

        gpu.begin_measurement().unwrap();
        let run_resident = |backend: &mut Backend| {
            let de = backend
                .upload_new_device(&e.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let dr = backend
                .upload_new_device(&r_tab.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let mut stream = CorrelationStream::new([101; 32]);
            let mut tx = Transcript::new([102; 32]);
            let initial = stream.draw_fulls(1, 1)[0];
            let claim0 = ProverAuthed { x: total, m: initial.m };
            let doms = HadamardDoms::alloc(&mut Doms::new(0xA100), n_vars);
            let mut prod = Vec::new();
            let mut zero = Vec::new();
            let out = hadamard_prove_resident(
                &rho,
                de,
                dr,
                claim0,
                &doms,
                &mut stream,
                &mut tx,
                &mut prod,
                &mut zero,
                backend,
            )
            .unwrap();
            (out, prod, zero, stream.counters, tx.ledger().clone())
        };
        let got = run_resident(&mut gpu);
        assert_eq!(got, expected);
        let live_after_first = gpu.stats().unwrap().live_device_bytes;
        let got_reused = run_resident(&mut gpu);
        assert_eq!(got_reused, expected);
        assert_eq!(gpu.stats().unwrap().live_device_bytes, live_after_first);
        let stats = gpu.finish_measurement().unwrap();
        assert_eq!(stats.operation(volta_accel::Operation::Gemm).cpu_residual_ns, 0);
    }
}
