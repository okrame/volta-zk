//! P3 report: decomposed protocol ρ for one blind GEMM proof on
//! (100×768)·(768×768) — ρ_clear = t(clear sumcheck)/t(GEMM) and
//! ρ_blind/clear = t(blind)/t(clear), with the lazy m_r expansion as its own
//! sub-line. The gate is the attribution, not a threshold.
//!
//! Run: cargo run --release -p volta-bench --bin p3_report [-- --quick]

use serde::Serialize;
use volta_bench::{time_median, time_paired};
use volta_field::{Fp, Fp2, FpStream};
use volta_gpt2::{gemm_i64, gemm_requant};
use volta_mac::{CorrelationStream, Transcript, VerifierCtx};
use volta_proto::thaler::{fold_w, fold_x, fold_y_acc, output_eqs, pad_bits};
use volta_proto::{auth_phase, prove_clear, prove_gemm_blind, verify_gemm_blind};

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    machine: String,
    threads_note: String,
    m: usize,
    k: usize,
    n: usize,
    t_gemm_ms: f64,
    t_clear_ms: f64,
    t_blind_ms: f64,
    t_blind_fold_ms: f64,
    t_blind_open_tags_ms: f64, // lazy m_r expansion + tag folds (P3-charged)
    t_blind_rounds_ms: f64,
    t_blind_prod_ms: f64,
    t_verify_ms: f64,
    rho_clear: f64,
    rho_blind_over_clear: f64,
    rho_blind_total: f64,
    auth_correction_bytes: u64,
    proof_bytes_excl_auth: u64,
    sub_corrs_consumed: u64,
    full_corrs_consumed: u64,
    accepted: bool,
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let iters = if quick { 3 } else { 9 };
    let warmup = if quick { 1 } else { 2 };

    let (m, k, n) = (100usize, 768usize, 768usize);
    let x: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
    let w: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
    let yacc = gemm_i64(&x, &w, m, k, n);

    // Clear prover: Freivalds folds + Ỹ eval + clear sumcheck (single-thread,
    // like the blind path — protocol cost, not kernel cost).
    let clear_once = || {
        let mut chal = FpStream::domain_separated([3; 32], 11);
        let r_i: Vec<Fp2> = (0..pad_bits(m)).map(|_| chal.next_fp2()).collect();
        let r_j: Vec<Fp2> = (0..pad_bits(n)).map(|_| chal.next_fp2()).collect();
        let (eq_i, eq_j) = output_eqs(&r_i, &r_j);
        let a = fold_x(&x, m, k, &eq_i);
        let b = fold_w(&w, k, n, &eq_j);
        let claim = fold_y_acc(&yacc, m, n, &eq_i, &eq_j);
        let (proof, _) = prove_clear(a, b, &mut chal);
        (claim, proof)
    };

    // ABBA pair 1: native GEMM vs clear prover.
    let (t_gemm, t_clear) =
        time_paired(warmup, iters, || gemm_requant(&x, &w, m, k, n, 8), clear_once);

    // Blind prover (fresh streams per run — domains are one-time).
    let blind_once = |seed_tag: u8| {
        let mut stream = CorrelationStream::new([seed_tag; 32]);
        let mut tx = Transcript::new([seed_tag ^ 0x77; 32]);
        let corr = auth_phase(&x, &yacc, m, k, n, &mut stream, &mut tx);
        let (proof, tm, counters) =
            prove_gemm_blind(&x, &w, &yacc, m, k, n, corr, &mut stream, &mut tx);
        (proof, tm, counters, tx)
    };
    // ABBA pair 2: clear vs blind (auth_phase corrections included in blind —
    // its GEMM-side cost is P1's epilogue; here it is the protocol-side copy).
    let mut run_id = 0u8;
    let (t_clear2, t_blind) = time_paired(warmup, iters, clear_once, || {
        run_id = run_id.wrapping_add(1);
        blind_once(run_id)
    });

    // Timing decomposition + artifacts from one instrumented run.
    let (proof, tm, counters, tx) = blind_once(200);
    let auth_bytes = tx.bytes_for("auth_corrections");
    let proof_bytes = tx.total_bytes() - auth_bytes;

    // Verifier (its own timing; includes the O(k·n) public W̃ fold).
    let delta = Fp2::new(Fp::new(0xACE1), Fp::new(0xBEE7));
    let mut accepted = false;
    let t_verify = time_median(if quick { 0 } else { 1 }, iters.min(5), || {
        let mut ctx = VerifierCtx::new([200; 32], delta);
        let mut vtx = Transcript::new([200 ^ 0x77; 32]);
        accepted = verify_gemm_blind(&w, m, k, n, &proof, &mut ctx, &mut vtx);
    });
    assert!(accepted, "P3 gate: blind GEMM proof must verify");

    let (g_ms, c_ms, b_ms) = (
        t_gemm.as_secs_f64() * 1e3,
        (t_clear.as_secs_f64() + t_clear2.as_secs_f64()) / 2.0 * 1e3,
        t_blind.as_secs_f64() * 1e3,
    );
    let report = Report {
        milestone: "P3".into(),
        date: chrono_date(),
        git_sha: git_sha(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads_note: "GEMM uses rayon (4 cores); clear/blind provers single-thread".into(),
        m,
        k,
        n,
        t_gemm_ms: g_ms,
        t_clear_ms: c_ms,
        t_blind_ms: b_ms,
        t_blind_fold_ms: tm.t_fold_s * 1e3,
        t_blind_open_tags_ms: tm.t_open_tags_s * 1e3,
        t_blind_rounds_ms: tm.t_rounds_s * 1e3,
        t_blind_prod_ms: tm.t_prod_s * 1e3,
        t_verify_ms: t_verify.as_secs_f64() * 1e3,
        rho_clear: c_ms / g_ms,
        rho_blind_over_clear: b_ms / c_ms,
        rho_blind_total: b_ms / g_ms,
        auth_correction_bytes: auth_bytes,
        proof_bytes_excl_auth: proof_bytes,
        sub_corrs_consumed: counters.sub_corrs,
        full_corrs_consumed: counters.full_corrs,
        accepted,
    };
    eprintln!(
        "GEMM {g_ms:.2} ms | clear {c_ms:.2} ms (ρ_clear {:.2}) | blind {b_ms:.2} ms (blind/clear {:.2}, total ρ {:.2})",
        report.rho_clear, report.rho_blind_over_clear, report.rho_blind_total
    );
    eprintln!(
        "blind split: fold {:.2} + open_tags(m_r) {:.2} + rounds {:.2} + prod {:.2} ms | verify {:.2} ms",
        report.t_blind_fold_ms,
        report.t_blind_open_tags_ms,
        report.t_blind_rounds_ms,
        report.t_blind_prod_ms,
        report.t_verify_ms
    );
    eprintln!(
        "bytes: auth {} | proof {} | corrs: sub {} full {}",
        auth_bytes, proof_bytes, counters.sub_corrs, counters.full_corrs
    );

    let path = format!(
        "{}/../../benchmarks/results/p3-{}-{}.json",
        env!("CARGO_MANIFEST_DIR"),
        report.date,
        report.git_sha
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}

fn git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn chrono_date() -> String {
    std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}
