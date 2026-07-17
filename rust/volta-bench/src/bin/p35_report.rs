//! P3.5 report: static Ligero weight PCS at full GPT-2 small scale
//! (2^27 coefficients, synthetic i16 weights — cost is data-independent;
//! real weights arrive with P5's export script).
//!
//! Measures: one-off commit; per-response batched ZK opening decomposed into
//! (claim batch reduction sumcheck | Ligero row combination | columns) and
//! the verifier side; bytes; correlations; peak RSS. Gate (pre-registered):
//! opening ≤ ~15 % of native prefill-100 standalone, ≤ ~3 % amortized per
//! 600-token response (= standalone × 100/600).
//!
//! Run: cargo run --release -p volta-bench --bin p35_report [-- --quick]

use rayon::prelude::*;
use serde::Serialize;
use std::time::Instant;
use volta_bench::time_median;
use volta_field::{Fp, Fp2, FpStream};
use volta_gpt2::gemm_requant;
use volta_mac::{CorrIndex, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey};
use volta_pcs::{
    batch_reduce_prover, batch_reduce_verifier, commit, open_multi_zk, open_zk, verify_multi_open,
    verify_open, BlockClaim, LigeroParams, GPT2_FULL,
};
use volta_proto::mle::eval_mle;

fn dom(tensor: u8, row: u32) -> u64 {
    CorrIndex { session: 1, layer: 0, head: 0, tensor, row }.domain()
}
const T_W_CLAIM: u8 = 0xE0;
const T_BATCH: u8 = 0xE1;
const T_OPEN_S: u8 = 0xE2;

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    machine: String,
    threads: usize,
    // Parameters (pre-registered).
    n_coeffs: u64,
    rows: usize,
    cols: usize,
    pad: usize,
    code_len: usize,
    n_queries: usize,
    rate: f64,
    query_soundness_note: String,
    n_claims: usize,
    n_blocks: usize,
    // One-off.
    t_commit_s: f64,
    // Path A (comparison, rejected): generic multi-point → single-point
    // reduction via blind sumcheck over 2^n_vars, then one Ligero opening.
    t_batch_f_build_s: f64,
    t_batch_w_embed_s: f64,
    t_batch_rounds_s: f64,
    t_open_masks_s: f64,
    t_open_row_combine_s: f64,
    t_open_ip_s: f64,
    t_open_columns_s: f64,
    t_reduction_path_total_s: f64,
    t_reduction_verify_s: f64,
    reduction_proof_bytes: u64,
    // Path B (pipeline of record): row-local multi-eval opening — block-local
    // masked row combinations, shared columns, one Π_ZeroBatch.
    t_multi_masks_s: f64,
    t_multi_global_pass_s: f64,
    t_multi_block_passes_s: f64,
    t_multi_ip_zb_s: f64,
    t_multi_columns_s: f64,
    t_opening_total_s: f64,
    t_verify_s: f64,
    // Bytes and correlations.
    opening_proof_bytes: u64,
    transcript_bytes_total: u64,
    sub_corrs_consumed: u64,
    full_corrs_consumed: u64,
    peak_rss_gb: f64,
    // Anchors and gate.
    gmacs_native: f64,
    native_prefill_est_s: f64,
    ratio_standalone: f64,
    ratio_600tok: f64,
    gate_standalone_015: bool,
    gate_600tok_003: bool,
    accepted: bool,
    leakage_smoke_ok: bool,
}

fn peak_rss_gb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|kb| kb.parse::<f64>().ok())
        .map(|kb| kb / 1024.0 / 1024.0)
        .unwrap_or(0.0)
}

/// Inline leakage smoke (mirror of the pre-registered test in
/// volta-pcs/tests/p35.rs): two weight sets, identical transcript structure,
/// masked messages uniform by a generous χ² on the top 4 bits.
fn leakage_smoke() -> bool {
    let params = LigeroParams { rows: 1 << 6, col_bits: 6, pad: 40, code_bits: 7, n_queries: 32 };
    let chi2_top4 = |vals: &[Fp]| -> f64 {
        let mut b = [0f64; 16];
        for v in vals {
            b[(v.value() >> 60) as usize] += 1.0;
        }
        let e = vals.len() as f64 / 16.0;
        b.iter().map(|x| (x - e) * (x - e) / e).sum()
    };
    let mut ledgers = Vec::new();
    let mut ok = true;
    for tag in [20u8, 21u8] {
        let w: Vec<i16> = (0..1usize << params.n_vars())
            .map(|i| (((i as u64 + tag as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> 40) as i16)
            .collect();
        let (_, pm) = commit(&w, &params, [0x54u8 ^ tag; 32]);
        let mut psrc = FpStream::domain_separated([9u8; 32], tag as u64);
        let point: Vec<Fp2> = (0..params.n_vars()).map(|_| psrc.next_fp2()).collect();
        let w2: Vec<Fp2> = w.iter().map(|&v| Fp2::from_base(Fp::from_i64(v as i64))).collect();
        let v = eval_mle(&w2, &point);
        let mut ps = CorrelationStream::new([tag; 32]);
        let mut tx = Transcript::new([0xC7u8; 32]);
        let fc = ps.draw_fulls(dom(T_W_CLAIM, 0), 1)[0];
        tx.append("w_claim_correction", 16);
        let claims = [(BlockClaim { offset: 0, point }, ProverAuthed { x: v, m: fc.m })];
        let (_bp, rstar, vstar, _) =
            batch_reduce_prover(&w, params.n_vars(), &claims, &mut ps, dom(T_BATCH, 0), &mut tx);
        let (op, _) =
            open_zk(&w, &pm, &rstar, vstar, &mut ps, dom(T_OPEN_S, 0), [0x36 ^ tag; 32], &mut tx);
        let mut comps: Vec<Fp> = Vec::new();
        for v in op.u_q.iter().chain(&op.u_c) {
            comps.push(v.c0);
            comps.push(v.c1);
        }
        ok &= chi2_top4(&comps) < 60.0;
        ok &= comps.iter().all(|v| v.value() >= (1 << 32));
        ledgers.push(tx.ledger().clone());
    }
    ok && ledgers[0] == ledgers[1]
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");

    // Native anchor: measured GEMM throughput scaled to the budget's 8.63 G
    // MACs (same formula as p25_report).
    let (m, k, n) = (100usize, 768usize, 3072usize);
    let a: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
    let b: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
    let t_g = time_median(1, 3, || gemm_requant(&a, &b, m, k, n, 8));
    let gmacs = (m * k * n) as f64 / t_g.as_secs_f64() / 1e9;
    let native_prefill_s = 8.63e9 / (gmacs * 1e9);
    eprintln!("native anchor: {gmacs:.1} GMAC/s → prefill-100 ≈ {native_prefill_s:.3} s");

    // Parameters: full 2^27 (or 2^24 with --quick, for iteration only).
    let params = if quick {
        LigeroParams { rows: 1 << 12, col_bits: 12, pad: 512, code_bits: 13, n_queries: 200 }
    } else {
        GPT2_FULL
    };
    let n_vars = params.n_vars();
    let size = 1usize << n_vars;
    // Synthetic block inventory: 64 aligned blocks stand in for the ~50 real
    // weight tensors; 220 claims ≈ q·#weight-GEMMs of one prefill.
    let n_blocks = 64usize;
    let block_vars = n_vars - 6;
    let n_claims = 220usize;

    eprintln!("generating synthetic W (2^{n_vars} i16) ...");
    let w: Vec<i16> = (0..size)
        .into_par_iter()
        .map(|i| (((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xC0FFEE) >> 40) as i16)
        .collect();

    // One-off commit.
    let t0 = Instant::now();
    let (com, pm) = commit(&w, &params, [0x51u8; 32]);
    let t_commit_s = t0.elapsed().as_secs_f64();
    eprintln!("commit: {t_commit_s:.2} s (one-off)");

    // Claims: honest W̃ evaluations at random block points (in the protocol
    // these fall out of the GEMM sumchecks for free — setup, not timed).
    let claim_meta: Vec<(usize, Vec<Fp2>)> = (0..n_claims)
        .map(|g| {
            let mut s = FpStream::domain_separated([9u8; 32], g as u64);
            let point: Vec<Fp2> = (0..block_vars).map(|_| s.next_fp2()).collect();
            ((g % n_blocks) << block_vars, point)
        })
        .collect();
    eprintln!("evaluating {n_claims} honest claims (setup) ...");
    let values: Vec<Fp2> = claim_meta
        .par_iter()
        .map(|(off, point)| {
            let blk: Vec<Fp2> = w[*off..*off + (1 << block_vars)]
                .iter()
                .map(|&v| Fp2::from_base(Fp::from_i64(v as i64)))
                .collect();
            eval_mle(&blk, point)
        })
        .collect();

    // Prover side (timed = per-response work).
    let seed = [0x77u8; 32];
    let tx_seed = [0xB2u8; 32];
    let delta = Fp2::new(Fp::new(31337), Fp::new(271828));
    let mut ps = CorrelationStream::new(seed);
    let mut tx = Transcript::new(tx_seed);

    let mut claims_p = Vec::with_capacity(n_claims);
    let mut corr_vs = Vec::with_capacity(n_claims);
    for (g, (off, point)) in claim_meta.iter().enumerate() {
        let fc = ps.draw_fulls(dom(T_W_CLAIM, g as u32), 1)[0];
        corr_vs.push(values[g] - fc.x);
        tx.append("w_claim_correction", 16);
        claims_p.push((
            BlockClaim { offset: *off, point: point.clone() },
            ProverAuthed { x: values[g], m: fc.m },
        ));
    }

    eprintln!("batch reduction ({n_claims} claims → 1 point) ...");
    let t1 = Instant::now();
    let (bproof, rstar, vstar, bt) =
        batch_reduce_prover(&w, n_vars, &claims_p, &mut ps, dom(T_BATCH, 0), &mut tx);
    let t_batch = t1.elapsed().as_secs_f64();
    eprintln!(
        "  f_build {:.2} s | w_embed {:.2} s | rounds {:.2} s  (total {t_batch:.2} s)",
        bt.t_f_build_s, bt.t_w_embed_s, bt.t_rounds_s
    );

    eprintln!("ZK opening ...");
    let t2 = Instant::now();
    let (oproof, ot) =
        open_zk(&w, &pm, &rstar, vstar, &mut ps, dom(T_OPEN_S, 0), [0x33u8; 32], &mut tx);
    let t_open = t2.elapsed().as_secs_f64();
    eprintln!(
        "  masks {:.3} s | row_combine {:.3} s | ip {:.3} s | columns {:.3} s  (total {t_open:.3} s)",
        ot.t_masks_s, ot.t_row_combine_s, ot.t_ip_s, ot.t_columns_s
    );

    // Verifier side.
    let t3 = Instant::now();
    let mut ctx = VerifierCtx::new(seed, delta);
    let mut txv = Transcript::new(tx_seed);
    let mut claims_v = Vec::with_capacity(n_claims);
    for (g, (off, point)) in claim_meta.iter().enumerate() {
        let kf = ctx.expand_full_keys(dom(T_W_CLAIM, g as u32), 1)[0];
        claims_v.push((
            BlockClaim { offset: *off, point: point.clone() },
            VerifierKey { k: kf + delta * corr_vs[g] },
        ));
    }
    let red_accepted = match batch_reduce_verifier(
        n_vars,
        &claims_v,
        &bproof,
        &mut ctx,
        dom(T_BATCH, 0),
        &mut txv,
    ) {
        Some((rstar_v, k_vstar)) => verify_open(
            &com.root,
            &params,
            &rstar_v,
            k_vstar,
            &oproof,
            &mut ctx,
            dom(T_OPEN_S, 0),
            &mut txv,
        ),
        None => false,
    };
    let t_red_verify = t3.elapsed().as_secs_f64();
    let t_reduction_total = t_batch + t_open;
    eprintln!(
        "path A (reduction sumcheck): total {t_reduction_total:.2} s, verify {t_red_verify:.3} s, accepted = {red_accepted}"
    );

    // Path B (pipeline of record): row-local multi-eval opening. Fresh
    // streams (fresh session in deployment; one-time domains forbid reuse).
    eprintln!("multi-eval opening ({n_claims} claims, block-local rows) ...");
    let seed_b = [0x88u8; 32];
    let txb_seed = [0xB9u8; 32];
    let mut psb = CorrelationStream::new(seed_b);
    let mut txb = Transcript::new(txb_seed);
    let mut claims_pb = Vec::with_capacity(n_claims);
    let mut corr_vsb = Vec::with_capacity(n_claims);
    for (g, (off, point)) in claim_meta.iter().enumerate() {
        let fc = psb.draw_fulls(dom(T_W_CLAIM, g as u32), 1)[0];
        corr_vsb.push(values[g] - fc.x);
        txb.append("w_claim_correction", 16);
        claims_pb.push((
            BlockClaim { offset: *off, point: point.clone() },
            ProverAuthed { x: values[g], m: fc.m },
        ));
    }
    let t4 = Instant::now();
    let (mproof, mt) = open_multi_zk(
        &w,
        &pm,
        &claims_pb,
        &mut psb,
        dom(T_OPEN_S, 0),
        dom(T_OPEN_S, 1),
        [0x44u8; 32],
        &mut txb,
    );
    let t_multi = t4.elapsed().as_secs_f64();
    eprintln!(
        "  masks {:.3} s | global pass {:.3} s | block passes {:.3} s | ip+zb {:.3} s | columns {:.3} s  (total {t_multi:.3} s)",
        mt.t_masks_s, mt.t_global_pass_s, mt.t_block_passes_s, mt.t_ip_zb_s, mt.t_columns_s
    );

    let t5 = Instant::now();
    let mut ctxb = VerifierCtx::new(seed_b, delta);
    let mut txbv = Transcript::new(txb_seed);
    let claims_vb: Vec<(BlockClaim, VerifierKey)> = claim_meta
        .iter()
        .enumerate()
        .map(|(g, (off, point))| {
            let kf = ctxb.expand_full_keys(dom(T_W_CLAIM, g as u32), 1)[0];
            (
                BlockClaim { offset: *off, point: point.clone() },
                VerifierKey { k: kf + delta * corr_vsb[g] },
            )
        })
        .collect();
    let accepted = verify_multi_open(
        &com.root,
        &params,
        &claims_vb,
        &mproof,
        &mut ctxb,
        dom(T_OPEN_S, 0),
        dom(T_OPEN_S, 1),
        &mut txbv,
    );
    let t_verify = t5.elapsed().as_secs_f64();
    eprintln!("multi verify: {t_verify:.3} s, accepted = {accepted}");

    let t_opening_total = t_multi;
    let ratio_standalone = t_opening_total / native_prefill_s;
    let ratio_600tok = ratio_standalone * (100.0 / 600.0);
    eprintln!(
        "opening of record (multi-eval) {t_opening_total:.3} s → {:.1}% of native prefill standalone, {:.2}% per 600-tok response",
        100.0 * ratio_standalone,
        100.0 * ratio_600tok
    );

    let leakage_ok = leakage_smoke();
    eprintln!("leakage smoke: {leakage_ok}");

    let sha = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let date = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let report = Report {
        milestone: if quick { "P3.5-quick".into() } else { "P3.5".into() },
        date: date.clone(),
        git_sha: sha.clone(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads: rayon::current_num_threads(),
        n_coeffs: size as u64,
        rows: params.rows(),
        cols: params.cols(),
        pad: params.pad,
        code_len: params.code_len(),
        n_queries: params.n_queries,
        rate: params.msg_len() as f64 / params.code_len() as f64,
        query_soundness_note: "(1-δ/2)^Q ≈ 2^-81 at Q=200, δ≈0.48 (d/3 analysis would need Q≈312; pad=512 keeps hiding headroom)".into(),
        n_claims,
        n_blocks,
        t_commit_s,
        t_batch_f_build_s: bt.t_f_build_s,
        t_batch_w_embed_s: bt.t_w_embed_s,
        t_batch_rounds_s: bt.t_rounds_s,
        t_open_masks_s: ot.t_masks_s,
        t_open_row_combine_s: ot.t_row_combine_s,
        t_open_ip_s: ot.t_ip_s,
        t_open_columns_s: ot.t_columns_s,
        t_reduction_path_total_s: t_reduction_total,
        t_reduction_verify_s: t_red_verify,
        reduction_proof_bytes: oproof.bytes(),
        t_multi_masks_s: mt.t_masks_s,
        t_multi_global_pass_s: mt.t_global_pass_s,
        t_multi_block_passes_s: mt.t_block_passes_s,
        t_multi_ip_zb_s: mt.t_ip_zb_s,
        t_multi_columns_s: mt.t_columns_s,
        t_opening_total_s: t_opening_total,
        t_verify_s: t_verify,
        opening_proof_bytes: mproof.bytes(),
        transcript_bytes_total: txb.total_bytes(),
        sub_corrs_consumed: psb.counters.sub_corrs,
        full_corrs_consumed: psb.counters.full_corrs,
        peak_rss_gb: peak_rss_gb(),
        gmacs_native: gmacs,
        native_prefill_est_s: native_prefill_s,
        ratio_standalone,
        ratio_600tok,
        gate_standalone_015: ratio_standalone <= 0.15,
        gate_600tok_003: ratio_600tok <= 0.03,
        accepted,
        leakage_smoke_ok: leakage_ok,
    };
    assert!(red_accepted, "P3.5 sanity: reduction-path opening must verify");
    assert!(accepted, "P3.5 sanity: multi-eval opening must verify");
    let label = if quick { "p3.5-quick" } else { "p3.5" };
    let path = format!(
        "{}/../../benchmarks/results/{label}-{date}-{sha}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}
