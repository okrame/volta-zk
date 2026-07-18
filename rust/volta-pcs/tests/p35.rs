//! P3.5 integration tests: Ligero completeness/soundness smokes, the M9
//! opening-into-MAC interface end-to-end on a real (small) GEMM, and the
//! pre-registered leakage smoke (transcripts for two different weight sets
//! structurally identical, masked messages uniform).

use rayon::prelude::*;
use volta_field::{Fp, Fp2, FpStream};
use volta_mac::{CorrIndex, CorrelationStream, ProverAuthed, Transcript, VerifierCtx};
use volta_pcs::{
    batch_reduce_prover, batch_reduce_verifier, commit, open_multi_zk, open_zk, verify_multi_open,
    verify_open, BlockClaim, LigeroParams, MultiOpenProof, C3_EMBED, C3_WEIGHTS,
};
use volta_proto::mle::{eq_vec, eval_mle};
use volta_proto::{auth_phase, prove_gemm_blind_committed, verify_gemm_blind_committed};

fn dom(tensor: u8, row: u32) -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor, row }.domain()
}
const DOM_W_CLAIM: u8 = 0xE0;
const DOM_BATCH_MASKS: u8 = 0xE1;
const DOM_S: u8 = 0xE2;

fn rand_w(seed: u64, len: usize) -> Vec<i16> {
    // Deterministic i16 weights (16-bit quantized range).
    (0..len)
        .map(|i| {
            let x = (i as u64).wrapping_add(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            (x >> 40) as i16
        })
        .collect()
}

fn embed(w: &[i16]) -> Vec<Fp2> {
    w.iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect()
}

/// Evaluate an i16 coefficient vector without materialising a production-size
/// `Vec<Fp2>`.  The equality polynomial factors across the low/high split, so
/// this is exactly `eval_mle(&embed(values), point)` with implicit zero padding.
fn eval_i16_mle_streaming(values: &[i16], point: &[Fp2]) -> Fp2 {
    assert!(values.len() <= 1usize << point.len());
    let low_vars = point.len().min(16);
    let low_eq = eq_vec(&point[..low_vars]);
    let high_eq = eq_vec(&point[low_vars..]);
    let low_size = 1usize << low_vars;

    values
        .par_chunks(low_size)
        .enumerate()
        .map(|(high, chunk)| {
            let inner = chunk.iter().zip(&low_eq).fold(Fp2::ZERO, |acc, (&value, &eq)| {
                acc + eq * Fp2::from_base(Fp::from_i64(value as i64))
            });
            inner * high_eq[high]
        })
        .reduce(|| Fp2::ZERO, |left, right| left + right)
}

#[test]
fn streaming_i16_mle_matches_reference_with_zero_padding() {
    let values = rand_w(0x51, 37);
    let mut source = FpStream::domain_separated([0x52; 32], 0x53);
    let point: Vec<Fp2> = (0..6).map(|_| source.next_fp2()).collect();
    assert_eq!(eval_i16_mle_streaming(&values, &point), eval_mle(&embed(&values), &point));
}

/// Small standalone opening: one claim, batch → open → verify.
fn run_pcs_once(
    w: &[i16],
    params: &LigeroParams,
    w_seed_tag: u8,
    tamper: impl FnOnce(&mut volta_pcs::OpeningProof),
) -> bool {
    let n_vars = params.n_vars();
    let seed = [w_seed_tag; 32];
    let tx_seed = [0xA5u8; 32];
    let delta = Fp2::new(Fp::new(0xD31A), Fp::new(77));

    let (com, pm) = commit(w, params, [0x51u8 ^ w_seed_tag; 32]);

    // One authenticated claim at a random point (stands in for a GEMM's leg).
    let mut point_src = FpStream::domain_separated([9u8; 32], w_seed_tag as u64);
    let point: Vec<Fp2> = (0..n_vars).map(|_| point_src.next_fp2()).collect();
    let v = eval_mle(&embed(w), &point);

    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let fc = ps.draw_fulls(dom(DOM_W_CLAIM, 0), 1)[0];
    let corr_v = v - fc.x;
    tx.append("w_claim_correction", 16);
    let v_auth = ProverAuthed { x: v, m: fc.m };

    let claims_p = [(BlockClaim { offset: 0, point: point.clone() }, v_auth)];
    let (bproof, rstar, vstar, _tm) =
        batch_reduce_prover(w, n_vars, &claims_p, &mut ps, dom(DOM_BATCH_MASKS, 0), &mut tx);
    let (mut oproof, _ot) =
        open_zk(w, &pm, &rstar, vstar, &mut ps, dom(DOM_S, 0), [0x33u8 ^ w_seed_tag; 32], &mut tx);
    tamper(&mut oproof);

    // Verifier chain.
    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let k_v = volta_mac::VerifierKey {
        k: ctx.expand_full_keys(dom(DOM_W_CLAIM, 0), 1)[0] + delta * corr_v,
    };
    let claims_v = [(BlockClaim { offset: 0, point }, k_v)];
    let Some((rstar_v, k_vstar)) = batch_reduce_verifier(
        n_vars,
        &claims_v,
        &bproof,
        &mut ctx,
        dom(DOM_BATCH_MASKS, 0),
        &mut txv,
    ) else {
        return false;
    };
    assert_eq!(rstar_v, rstar);
    verify_open(&com.root, params, &rstar_v, k_vstar, &oproof, &mut ctx, dom(DOM_S, 0), &mut txv)
}

const SMALL: LigeroParams =
    LigeroParams { rows: 1 << 5, col_bits: 5, pad: 8, code_bits: 6, n_queries: 8 };

#[test]
fn ligero_completeness_small() {
    let w = rand_w(1, 1 << SMALL.n_vars());
    assert!(run_pcs_once(&w, &SMALL, 1, |_| ()));
}

#[test]
fn ligero_rejects_tampered_zero_open_tag() {
    let w = rand_w(2, 1 << SMALL.n_vars());
    assert!(!run_pcs_once(&w, &SMALL, 2, |p| p.m_z = p.m_z + Fp2::ONE));
}

#[test]
fn ligero_rejects_tampered_column() {
    let w = rand_w(3, 1 << SMALL.n_vars());
    assert!(!run_pcs_once(&w, &SMALL, 3, |p| p.columns[0].col[0] += Fp::ONE));
}

#[test]
fn ligero_rejects_tampered_u_vector() {
    let w = rand_w(4, 1 << SMALL.n_vars());
    assert!(!run_pcs_once(&w, &SMALL, 4, |p| p.u_q[0] = p.u_q[0] + Fp2::ONE));
}

#[test]
fn ligero_rejects_tampered_s_correction() {
    let w = rand_w(5, 1 << SMALL.n_vars());
    assert!(!run_pcs_once(&w, &SMALL, 5, |p| p.corr_s = p.corr_s + Fp2::ONE));
}

/// Binding through the MAC: commit/open honestly for W₂ while the verifier's
/// authenticated claim came from W₁ ⇒ the zero-open must fail.
#[test]
fn ligero_rejects_wrong_committed_weights() {
    let params = &SMALL;
    let n_vars = params.n_vars();
    let w1 = rand_w(6, 1 << n_vars);
    let w2 = rand_w(7, 1 << n_vars);
    let seed = [6u8; 32];
    let tx_seed = [0xA5u8; 32];
    let delta = Fp2::new(Fp::new(0xD31A), Fp::new(77));

    let (com2, pm2) = commit(&w2, params, [0x52u8; 32]);

    let mut point_src = FpStream::domain_separated([9u8; 32], 6);
    let point: Vec<Fp2> = (0..n_vars).map(|_| point_src.next_fp2()).collect();
    let v1 = eval_mle(&embed(&w1), &point); // claim value from W₁

    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let fc = ps.draw_fulls(dom(DOM_W_CLAIM, 0), 1)[0];
    let corr_v = v1 - fc.x;
    tx.append("w_claim_correction", 16);
    let v_auth = ProverAuthed { x: v1, m: fc.m };

    let claims_p = [(BlockClaim { offset: 0, point: point.clone() }, v_auth)];
    let (bproof, rstar, vstar, _) =
        batch_reduce_prover(&w1, n_vars, &claims_p, &mut ps, dom(DOM_BATCH_MASKS, 0), &mut tx);
    // Cheating prover: opens C_{W₂} with a locally-consistent value for W₂
    // but the batch tag from the W₁ claim chain.
    let v2_star = eval_mle(&embed(&w2), &rstar);
    let cheat = ProverAuthed { x: v2_star, m: vstar.m };
    let (oproof, _) =
        open_zk(&w2, &pm2, &rstar, cheat, &mut ps, dom(DOM_S, 0), [0x34u8; 32], &mut tx);

    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let k_v = volta_mac::VerifierKey {
        k: ctx.expand_full_keys(dom(DOM_W_CLAIM, 0), 1)[0] + delta * corr_v,
    };
    let claims_v = [(BlockClaim { offset: 0, point }, k_v)];
    let (rstar_v, k_vstar) = batch_reduce_verifier(
        n_vars,
        &claims_v,
        &bproof,
        &mut ctx,
        dom(DOM_BATCH_MASKS, 0),
        &mut txv,
    )
    .unwrap();
    assert!(!verify_open(
        &com2.root,
        params,
        &rstar_v,
        k_vstar,
        &oproof,
        &mut ctx,
        dom(DOM_S, 0),
        &mut txv
    ));
}

/// The M9 seam end-to-end on a real GEMM: Π_Auth → blind Thaler sumcheck with
/// committed W leg → batch reduction → ZK opening bound to C_W.
#[test]
fn gemm_committed_w_e2e() {
    let (m, k, n) = (8usize, 32usize, 32usize); // power-of-two dims: W MLE = flat W
    let params = SMALL; // n_vars = 10 = pad_bits(k) + pad_bits(n)
    assert_eq!(params.n_vars(), 10);

    let x: Vec<i16> = (0..m * k).map(|i| ((i * 31 + 7) % 251) as i16 - 125).collect();
    let w = rand_w(10, k * n);
    let mut yacc = vec![0i64; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc = 0i64;
            for l in 0..k {
                acc += x[i * k + l] as i64 * w[l * n + j] as i64;
            }
            yacc[i * n + j] = acc;
        }
    }

    let seed = [0x77u8; 32];
    let tx_seed = [0xB2u8; 32];
    let delta = Fp2::new(Fp::new(31337), Fp::new(271828));
    let (com, pm) = commit(&w, &params, [0x53u8; 32]);

    // Prover chain.
    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let corr = auth_phase(&x, &yacc, m, k, n, &mut ps, &mut tx);
    let (gproof, corr_w, wclaim, _tm, _cnt) = prove_gemm_blind_committed(
        &x,
        &w,
        &yacc,
        m,
        k,
        n,
        corr,
        dom(DOM_W_CLAIM, 0),
        &mut ps,
        &mut tx,
    );
    // The outward claim is exactly an MLE evaluation of the flat W.
    assert_eq!(wclaim.value.x, eval_mle(&embed(&w), &wclaim.point));

    let claims_p = [(BlockClaim { offset: 0, point: wclaim.point.clone() }, wclaim.value)];
    let (bproof, rstar, vstar, _bt) =
        batch_reduce_prover(&w, 10, &claims_p, &mut ps, dom(DOM_BATCH_MASKS, 0), &mut tx);
    assert_eq!(vstar.x, eval_mle(&embed(&w), &rstar));
    let (oproof, _ot) =
        open_zk(&w, &pm, &rstar, vstar, &mut ps, dom(DOM_S, 0), [0x35u8; 32], &mut tx);

    // Verifier chain — never touches w.
    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let (w_point, k_b) = verify_gemm_blind_committed(
        m,
        k,
        n,
        &gproof,
        corr_w,
        dom(DOM_W_CLAIM, 0),
        &mut ctx,
        &mut txv,
    )
    .expect("committed GEMM verification");
    assert_eq!(w_point, wclaim.point);
    let claims_v = [(BlockClaim { offset: 0, point: w_point }, k_b)];
    let (rstar_v, k_vstar) =
        batch_reduce_verifier(10, &claims_v, &bproof, &mut ctx, dom(DOM_BATCH_MASKS, 0), &mut txv)
            .expect("batch reduction verification");
    assert!(verify_open(
        &com.root,
        &params,
        &rstar_v,
        k_vstar,
        &oproof,
        &mut ctx,
        dom(DOM_S, 0),
        &mut txv
    ));

    // Perturbed W-claim correction ⇒ the chain rejects at Π_Prod already.
    let mut ctx2 = VerifierCtx::new(seed, delta);
    let mut txv2 = Transcript::new(tx_seed);
    assert!(verify_gemm_blind_committed(
        m,
        k,
        n,
        &gproof,
        corr_w + Fp2::ONE,
        dom(DOM_W_CLAIM, 0),
        &mut ctx2,
        &mut txv2,
    )
    .is_none());
}

/// Row-local multi-eval opening: several claims on different aligned blocks,
/// one shared column set, one Π_ZeroBatch — no reduction sumcheck.
fn run_multi_once(
    params: &LigeroParams,
    n_claims: usize,
    block_vars: usize,
    seed_tag: u8,
    tamper: impl FnOnce(&mut MultiOpenProof),
) -> bool {
    let n_vars = params.n_vars();
    let n_blocks = 1usize << (n_vars - block_vars);
    let w = rand_w(seed_tag as u64, 1 << n_vars);
    let seed = [seed_tag; 32];
    let tx_seed = [0xA6u8; 32];
    let delta = Fp2::new(Fp::new(0xD31B), Fp::new(78));
    let (com, pm) = commit(&w, params, [0x61u8 ^ seed_tag; 32]);
    let w2 = embed(&w);

    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let mut claims_p = Vec::new();
    let mut corr_vs = Vec::new();
    for g in 0..n_claims {
        let mut src = FpStream::domain_separated([9u8; 32], (seed_tag as u64) << 8 | g as u64);
        let point: Vec<Fp2> = (0..block_vars).map(|_| src.next_fp2()).collect();
        let offset = (g % n_blocks) << block_vars;
        let claim = BlockClaim { offset, point };
        let v = eval_mle(&w2, &claim.global_point(n_vars));
        let fc = ps.draw_fulls(dom(DOM_W_CLAIM, g as u32), 1)[0];
        corr_vs.push(v - fc.x);
        tx.append("w_claim_correction", 16);
        claims_p.push((claim, ProverAuthed { x: v, m: fc.m }));
    }
    let (mut oproof, _tm) = open_multi_zk(
        &w,
        &pm,
        &claims_p,
        &mut ps,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        [0x62u8 ^ seed_tag; 32],
        &mut tx,
    );
    tamper(&mut oproof);

    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let claims_v: Vec<(BlockClaim, volta_mac::VerifierKey)> = claims_p
        .iter()
        .enumerate()
        .map(|(g, (c, _))| {
            let kf = ctx.expand_full_keys(dom(DOM_W_CLAIM, g as u32), 1)[0];
            (c.clone(), volta_mac::VerifierKey { k: kf + delta * corr_vs[g] })
        })
        .collect();
    verify_multi_open(
        &com.root,
        params,
        &claims_v,
        &oproof,
        &mut ctx,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut txv,
    )
}

const MULTI: LigeroParams =
    LigeroParams { rows: 1 << 6, col_bits: 5, pad: 8, code_bits: 6, n_queries: 8 };

#[test]
fn multi_open_completeness_across_blocks() {
    // 11-var vector, 4 blocks of 2^9, 7 claims spread over them.
    assert!(run_multi_once(&MULTI, 7, 9, 30, |_| ()));
}

#[test]
fn multi_open_rejects_tampered_tag_column_and_correction() {
    assert!(!run_multi_once(&MULTI, 7, 9, 31, |p| p.m_z = p.m_z + Fp2::ONE));
    assert!(!run_multi_once(&MULTI, 7, 9, 32, |p| p.columns[2].col[5] += Fp::ONE));
    assert!(!run_multi_once(&MULTI, 7, 9, 33, |p| p.corr_ss[3] = p.corr_ss[3] + Fp2::ONE));
    assert!(!run_multi_once(&MULTI, 7, 9, 34, |p| p.u_gs[1][0] = p.u_gs[1][0] + Fp2::ONE));
}

#[test]
fn multi_open_supports_non_power_of_two_rows_and_rejects_tail_claims() {
    let params = LigeroParams { rows: 6, col_bits: 3, pad: 4, code_bits: 4, n_queries: 4 };
    let w = rand_w(35, params.rows() * params.cols());
    let mut padded = vec![0i16; 1 << params.n_vars()];
    padded[..w.len()].copy_from_slice(&w);
    let padded_fp = embed(&padded);
    let seed = [35u8; 32];
    let tx_seed = [0xC3u8; 32];
    let delta = Fp2::new(Fp::new(0xC301), Fp::new(81));
    let (commitment, matrix) = commit(&w, &params, [0x73u8; 32]);

    let mut prover = CorrelationStream::new(seed);
    let mut txp = Transcript::new(tx_seed);
    let claims = [
        BlockClaim { offset: 0, point: vec![Fp2::new(Fp::new(2), Fp::new(3)); 4] },
        BlockClaim { offset: 40, point: vec![Fp2::new(Fp::new(5), Fp::new(7)); 3] },
    ];
    let mut corrections = Vec::new();
    let claims_p: Vec<_> = claims
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            let value = eval_mle(&padded_fp, &claim.global_point(params.n_vars()));
            let corr = prover.draw_fulls(dom(DOM_W_CLAIM, index as u32), 1)[0];
            corrections.push(value - corr.x);
            txp.append("w_claim_correction", 16);
            (claim.clone(), ProverAuthed { x: value, m: corr.m })
        })
        .collect();
    let (proof, _) = open_multi_zk(
        &w,
        &matrix,
        &claims_p,
        &mut prover,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        [0x74u8; 32],
        &mut txp,
    );

    let mut verifier = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let claims_v: Vec<_> = claims
        .iter()
        .enumerate()
        .map(|(index, claim)| {
            let key = verifier.expand_full_keys(dom(DOM_W_CLAIM, index as u32), 1)[0];
            (claim.clone(), volta_mac::VerifierKey { k: key + delta * corrections[index] })
        })
        .collect();
    assert!(verify_multi_open(
        &commitment.root,
        &params,
        &claims_v,
        &proof,
        &mut verifier,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut txv,
    ));

    let mut bad_claims = claims_v;
    bad_claims[1].0.offset = 48;
    let mut verifier_bad = VerifierCtx::new(seed, delta);
    let mut tx_bad = Transcript::new(tx_seed);
    assert!(!verify_multi_open(
        &commitment.root,
        &params,
        &bad_claims,
        &proof,
        &mut verifier_bad,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut tx_bad,
    ));
}

/// The M9 seam through the multi-eval opening: GEMM committed-W claim bound
/// directly to C_W (the pipeline of record after the P3.5 iteration).
#[test]
fn gemm_committed_w_e2e_multi_open() {
    let (m, k, n) = (8usize, 32usize, 32usize);
    let params = SMALL;
    let x: Vec<i16> = (0..m * k).map(|i| ((i * 29 + 3) % 251) as i16 - 125).collect();
    let w = rand_w(40, k * n);
    let mut yacc = vec![0i64; m * n];
    for i in 0..m {
        for j in 0..n {
            let mut acc = 0i64;
            for l in 0..k {
                acc += x[i * k + l] as i64 * w[l * n + j] as i64;
            }
            yacc[i * n + j] = acc;
        }
    }
    let seed = [0x78u8; 32];
    let tx_seed = [0xB3u8; 32];
    let delta = Fp2::new(Fp::new(31338), Fp::new(271829));
    let (com, pm) = commit(&w, &params, [0x63u8; 32]);

    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);
    let corr = auth_phase(&x, &yacc, m, k, n, &mut ps, &mut tx);
    let (gproof, corr_w, wclaim, _, _) = prove_gemm_blind_committed(
        &x,
        &w,
        &yacc,
        m,
        k,
        n,
        corr,
        dom(DOM_W_CLAIM, 0),
        &mut ps,
        &mut tx,
    );
    let claims_p = [(BlockClaim { offset: 0, point: wclaim.point.clone() }, wclaim.value)];
    let (oproof, _) = open_multi_zk(
        &w,
        &pm,
        &claims_p,
        &mut ps,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        [0x64u8; 32],
        &mut tx,
    );

    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let (w_point, k_b) = verify_gemm_blind_committed(
        m,
        k,
        n,
        &gproof,
        corr_w,
        dom(DOM_W_CLAIM, 0),
        &mut ctx,
        &mut txv,
    )
    .expect("committed GEMM verification");
    let claims_v = [(BlockClaim { offset: 0, point: w_point }, k_b)];
    assert!(verify_multi_open(
        &com.root,
        &params,
        &claims_v,
        &oproof,
        &mut ctx,
        dom(DOM_S, 0),
        dom(DOM_S, 1),
        &mut txv,
    ));
}

/// Pre-registered leakage smoke: two different weight sets, same protocol —
/// (a) transcript byte ledgers structurally identical, (b) masked messages
/// (u_q, u_c) uniform by a generous χ² on the top 4 bits, no small-value
/// structure, (c) opened C_W columns uniform (row pads randomize symbols).
#[test]
fn leakage_smoke_two_weight_sets() {
    let params = LigeroParams { rows: 1 << 6, col_bits: 6, pad: 40, code_bits: 7, n_queries: 32 };
    let n_vars = params.n_vars();

    let chi2_top4 = |vals: &[Fp]| -> f64 {
        let mut buckets = [0f64; 16];
        for v in vals {
            buckets[(v.value() >> 60) as usize] += 1.0;
        }
        let exp = vals.len() as f64 / 16.0;
        buckets.iter().map(|b| (b - exp) * (b - exp) / exp).sum()
    };

    let mut ledgers = Vec::new();
    for (tag, wseed) in [(20u8, 20u64), (21u8, 21u64)] {
        let w = rand_w(wseed, 1 << n_vars);
        let seed = [tag; 32];
        let tx_seed = [0xC7u8; 32];
        let (_, pm) = commit(&w, &params, [0x54u8 ^ tag; 32]);

        let mut point_src = FpStream::domain_separated([9u8; 32], tag as u64);
        let point: Vec<Fp2> = (0..n_vars).map(|_| point_src.next_fp2()).collect();
        let v = eval_mle(&embed(&w), &point);
        let mut ps = CorrelationStream::new(seed);
        let mut tx = Transcript::new(tx_seed);
        let fc = ps.draw_fulls(dom(DOM_W_CLAIM, 0), 1)[0];
        tx.append("w_claim_correction", 16);
        let v_auth = ProverAuthed { x: v, m: fc.m };
        let claims = [(BlockClaim { offset: 0, point }, v_auth)];
        let (_bp, rstar, vstar, _) =
            batch_reduce_prover(&w, n_vars, &claims, &mut ps, dom(DOM_BATCH_MASKS, 0), &mut tx);
        let (oproof, _) =
            open_zk(&w, &pm, &rstar, vstar, &mut ps, dom(DOM_S, 0), [0x36u8 ^ tag; 32], &mut tx);

        // (b) masked u vectors: uniform top bits, no small values.
        let mut comps: Vec<Fp> = Vec::new();
        for v in oproof.u_q.iter().chain(&oproof.u_c) {
            comps.push(v.c0);
            comps.push(v.c1);
        }
        let x2 = chi2_top4(&comps);
        assert!(x2 < 60.0, "u-vector χ² too high: {x2}");
        assert_eq!(comps.iter().filter(|v| v.value() < (1 << 32)).count(), 0);

        // (c) opened columns: symbols carry the pad entropy, uniform top bits.
        let col_vals: Vec<Fp> = oproof.columns.iter().flat_map(|c| c.col.iter().copied()).collect();
        let x2c = chi2_top4(&col_vals);
        assert!(x2c < 60.0, "column χ² too high: {x2c}");

        ledgers.push(tx.ledger().clone());
    }
    // (a) identical transcript structure and byte counts for W₁ vs W₂.
    assert_eq!(ledgers[0], ledgers[1]);
}

fn leakage_smoke_geometry(params: LigeroParams) {
    let n_vars = params.n_vars();
    let mut ledgers = Vec::new();
    for (tag, wseed) in [(0xC3u8, 0xC3u64), (0xC4u8, 0xC4u64)] {
        let physical_len = params.rows() * params.cols();
        let mut weights = rand_w(wseed, physical_len);
        let mut point_source = FpStream::domain_separated([0x73; 32], tag as u64);
        let point: Vec<Fp2> = (0..n_vars).map(|_| point_source.next_fp2()).collect();
        let value = eval_i16_mle_streaming(&weights, &point);
        let mut stream = CorrelationStream::new([tag; 32]);
        let mut transcript = Transcript::new([0x75; 32]);
        let claim_mask = stream.draw_fulls(dom(DOM_W_CLAIM, 0), 1)[0];
        transcript.append("w_claim_correction", 16);
        let claim = ProverAuthed { x: value, m: claim_mask.m };
        let claims = [(BlockClaim { offset: 0, point }, claim)];
        // The batch API consumes the full power-of-two MLE domain; C3's PCS
        // stores only its non-power-of-two physical rows.  The absent rows are
        // the same implicit zeros used by the evaluation above.
        weights.resize(1usize << n_vars, 0);
        let (_, reduced_point, reduced_value, _) = batch_reduce_prover(
            &weights,
            n_vars,
            &claims,
            &mut stream,
            dom(DOM_BATCH_MASKS, 0),
            &mut transcript,
        );
        weights.truncate(physical_len);

        // Materialise the encoded PCS matrix only after the batch-reduction
        // scratch has been dropped.  `commit` is deterministic and appends no
        // transcript message, so this changes allocation lifetime only, not
        // protocol ordering, challenges, or the statement being opened.
        let (_, matrix) = commit(&weights, &params, [0x71 ^ tag; 32]);
        let (opening, _) = open_zk(
            &weights,
            &matrix,
            &reduced_point,
            reduced_value,
            &mut stream,
            dom(DOM_S, 0),
            [0x77 ^ tag; 32],
            &mut transcript,
        );
        assert_eq!(opening.columns.len(), params.n_queries);
        assert!(opening.u_q.iter().chain(&opening.u_c).any(|value| *value != Fp2::ZERO));
        ledgers.push(transcript.ledger().clone());
    }
    assert_eq!(ledgers[0], ledgers[1]);
}

#[test]
#[ignore = "C3 production-size 6.4 GB encoded weight geometry"]
fn c3_weights_two_weight_set_leakage_smoke() {
    leakage_smoke_geometry(C3_WEIGHTS);
}

#[test]
#[ignore = "C3 production-size 2.2 GB encoded embed geometry"]
fn c3_embed_two_weight_set_leakage_smoke() {
    leakage_smoke_geometry(C3_EMBED);
}
