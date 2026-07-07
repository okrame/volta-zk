//! P2 gate tests: e2e auth→open on synthetic tensors, soundness smoke tests
//! mirroring the Lean statements (M2/M5), P1-epilogue interop, and counter
//! coherence with the P0 analytic budget.

use rand::{Rng, SeedableRng};
use volta_field::{Fp, Fp2, P};
use volta_mac::*;

fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
    Fp2::new(Fp::new(rng.gen_range(0..P)), Fp::new(rng.gen_range(0..P)))
}

fn setup(seed_byte: u8, rng: &mut impl Rng) -> (CorrelationStream, VerifierCtx, Transcript) {
    let seed = [seed_byte; 32];
    let delta = rand_fp2(rng);
    (
        CorrelationStream::new(seed),
        VerifierCtx::new(seed, delta),
        Transcript::new([seed_byte ^ 0xAA; 32]),
    )
}

/// Claims "authenticated x_j equals public v_j" as authenticated zeros, on
/// both sides (prover: x−v with tag m; verifier: k − Δ·v).
fn equality_claims(
    authed: &[ProverSubAuthed],
    keys: &[VerifierKey],
    claimed: &[i16],
    delta: Fp2,
) -> (Vec<ProverAuthed>, Vec<VerifierKey>) {
    let ys: Vec<ProverAuthed> = authed
        .iter()
        .zip(claimed)
        .map(|(a, &v)| {
            a.embed().sub(ProverAuthed::from_public(Fp2::from_base(Fp::from_i64(v as i64))))
        })
        .collect();
    let ks: Vec<VerifierKey> = keys
        .iter()
        .zip(claimed)
        .map(|(k, &v)| {
            k.sub(VerifierKey::from_public(Fp2::from_base(Fp::from_i64(v as i64)), delta))
        })
        .collect();
    (ys, ks)
}

#[test]
fn auth_open_completeness() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(21);
    let (mut ps, mut vc, mut tx) = setup(7, &mut rng);
    let xs: Vec<i16> = (0..1000).map(|_| rng.gen()).collect();
    let (corr, authed) = auth_prover(&mut ps, 100, &xs, &mut tx);
    let keys = auth_verifier(&mut vc, 100, &corr);
    let (ys, ks) = equality_claims(&authed, &keys, &xs, vc.delta);
    assert!(zero_batch_exchange(&ys, &ks, &mut ps, &mut vc, 101, &mut tx));
    assert_eq!(ps.counters, vc.counters);
}

#[test]
fn zero_open_rejects_perturbed_x_m_claim() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(22);
    let mut accepted = 0u32;
    for trial in 0..1000u64 {
        let (mut ps, mut vc, mut tx) = setup((trial % 251) as u8, &mut rng);
        let xs: Vec<i16> = (0..8).map(|_| rng.gen()).collect();
        let (corr, authed) = auth_prover(&mut ps, trial, &xs, &mut tx);
        let keys = auth_verifier(&mut vc, trial, &corr);
        // Perturb: wrong plaintext claim, forged tag, or wrong opened value.
        let mut claimed = xs.clone();
        let j = rng.gen_range(0..xs.len());
        match trial % 3 {
            0 => claimed[j] = claimed[j].wrapping_add(1 + rng.gen_range(0..100)),
            1 => {
                // forged tag on an honest claim
                let (ys, ks) = equality_claims(&authed, &keys, &claimed, vc.delta);
                let forged = ys[j].m + rand_fp2(&mut rng);
                if zero_open_verify(ks[j], forged) {
                    accepted += 1;
                }
                continue;
            }
            _ => {}
        }
        let (mut ys, ks) = equality_claims(&authed, &keys, &claimed, vc.delta);
        if trial % 3 == 2 {
            // honest claims but tampered batch opening
            ys[j].m = ys[j].m + rand_fp2(&mut rng);
        } else {
            // wrong claim: prover "pretends" x == claimed by zeroing x
            ys[j].x = Fp2::ZERO;
        }
        if zero_batch_exchange(&ys, &ks, &mut ps, &mut vc, u32::MAX as u64 + trial, &mut tx) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 0, "soundness smoke: no perturbed opening may verify");
}

#[test]
fn corrections_are_subfield_typed() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(23);
    let (mut ps, _vc, mut tx) = setup(9, &mut rng);
    let xs: Vec<i16> = (0..500).map(|_| rng.gen()).collect();
    let (corr, _) = auth_prover(&mut ps, 5, &xs, &mut tx);
    // δ ∈ F_p canonical (8 bytes), and δ + r re-embeds x.
    let mut check = CorrelationStream::new([9u8; 32]);
    let subs = check.draw_subs(5, xs.len());
    for ((&c, s), &x) in corr.iter().zip(&subs).zip(&xs) {
        assert!(c < P);
        assert_eq!(Fp::new(c) + s.r, Fp::from_i64(x as i64));
    }
    assert_eq!(tx.bytes_for("auth_corrections"), 8 * xs.len() as u64);
}

#[test]
fn epilogue_interop() {
    // P1 → P2 seam: the fused GEMM epilogue's corrections feed Π_Auth's
    // verifier half and the lazily expanded prover tags, then open cleanly.
    let mut rng = rand::rngs::StdRng::seed_from_u64(24);
    let (m, k, n) = (16, 32, 24);
    let a: Vec<i16> = (0..m * k).map(|_| rng.gen_range(-2000..2000)).collect();
    let b: Vec<i16> = (0..k * n).map(|_| rng.gen_range(-2000..2000)).collect();
    let seed = [5u8; 32];
    let ep = volta_gpt2::EpilogueSpec { shift: 8, seed, tensor_tag: 3 };
    let (out, corr) = volta_gpt2::gemm_requant_auth(&a, &b, m, k, n, ep);

    let delta = rand_fp2(&mut rng);
    let mut vc = VerifierCtx::new(seed, delta);
    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new([1u8; 32]);
    let keys = auth_verifier_from_epilogue(&mut vc, 3, m, n, &corr);
    let authed = prover_tags_from_epilogue(&mut ps, 3, &out, m, n);
    let (ys, ks) = equality_claims(&authed, &keys, &out, delta);
    assert!(zero_batch_exchange(&ys, &ks, &mut ps, &mut vc, 1 << 40, &mut tx));
    assert_eq!(ps.counters.sub_corrs, (m * n) as u64);
}

#[test]
fn counters_match_budget_scaled() {
    // Same boundary formula as scripts/budget_p0.py: embed_out T·d,
    // {attn_out, ffn_out, K, V} L·T·d each, final_ln d ⇒ T·d·(1+4L) + d.
    let budget = |t: u64, d: u64, l: u64| t * d * (1 + 4 * l) + d;
    assert_eq!(budget(100, 768, 12), 3_763_968); // pre-registered P0 number

    // Mini-GPT-2 (T=10, d=48, L=2): draw exactly the boundary correlations
    // through domain-separated indices and check the counter matches.
    let (t, d, l) = (10u64, 48u64, 2u64);
    let mut ps = CorrelationStream::new([2u8; 32]);
    let mut draw = |layer: u8, tensor: u8, count: u64| {
        for row in 0..t as u32 {
            let idx = CorrIndex { session: 1, layer, head: 0, tensor, row };
            let _ = ps.draw_sub_masks(idx.domain(), (count / t) as usize);
        }
    };
    draw(0xFF, 0, t * d); // embed_out (layer-independent, own tag)
    for layer in 0..l as u8 {
        for tensor in 1..=4u8 {
            draw(layer, tensor, t * d); // attn_out, ffn_out, K, V
        }
    }
    // final_ln_out_last_pos: d values, single row
    let idx = CorrIndex { session: 1, layer: 0xFE, head: 0, tensor: 0, row: 0 };
    let _ = ps.draw_sub_masks(idx.domain(), d as usize);
    assert_eq!(ps.counters.sub_corrs, budget(t, d, l));
}
