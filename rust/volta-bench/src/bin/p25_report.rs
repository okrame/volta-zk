//! P2.5 report: clear-LogUp prover constant on GPT-2-shaped lookup batches.
//! Informative gate (does not block P3): ns/lookup and E-mult/lookup are
//! pre-registered against the budget's "O(1) E-mults per lookup" line.
//!
//! Run: cargo run --release -p volta-bench --bin p25_report [-- --quick]

use serde::Serialize;
use volta_bench::logup::{logup_prove, logup_verify, Counters};
use volta_bench::time_median;
use volta_field::FpStream;
use volta_gpt2::gemm_requant;

#[derive(Serialize)]
struct LogupResult {
    n_lookups: usize,
    table_bits: u32,
    prove_wall_s: f64,
    verify_wall_s: f64,
    ns_per_lookup: f64,
    emult_per_lookup_prover: f64,
    fp2_mults_prover: u64,
    base_mults_prover: u64,
    proof_bytes: u64,
    ratio_prove_vs_native_prefill: f64,
}

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    machine: String,
    threads_note: String,
    native_prefill_est_s: f64,
    budget_lookups_prefill: u64,
    runs: Vec<LogupResult>,
    extrapolated_prefill_logup_s: f64,
}

fn run_one(n_bits: u32, table_bits: u32, native_prefill_s: f64) -> LogupResult {
    let n = 1usize << n_bits;
    let table: Vec<i16> = (0..1i32 << table_bits)
        .map(|j| (j - (1 << (table_bits - 1))) as i16)
        .collect();
    let offset = 1i32 << (table_bits - 1);
    // Deterministic synthetic lookup mix (stands in for requant/exp/LN values).
    let f: Vec<i16> = (0..n)
        .map(|i| table[((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize % table.len()])
        .collect();
    let mut mult = vec![0u32; table.len()];
    for &v in &f {
        mult[(v as i32 + offset) as usize] += 1;
    }

    let seed = [7u8; 32];
    let mut ctr_p = Counters::default();
    let mut proof_holder = None;
    let t_prove = time_median(0, 1, || {
        let mut chal = FpStream::domain_separated(seed, 0xC4A1);
        let mut c = Counters::default();
        let (_a, proof) = logup_prove(&f, &table, &mult, &mut chal, &mut c);
        ctr_p = c;
        proof_holder = Some(proof);
    });
    let proof = proof_holder.unwrap();
    let mut ok = false;
    let t_verify = time_median(0, 1, || {
        let mut chal = FpStream::domain_separated(seed, 0xC4A1);
        let mut c = Counters::default();
        ok = logup_verify(&f, &table, &mult, &proof, &mut chal, &mut c);
    });
    assert!(ok, "P2.5 sanity: honest proof must verify");

    let prove_s = t_prove.as_secs_f64();
    LogupResult {
        n_lookups: n,
        table_bits,
        prove_wall_s: prove_s,
        verify_wall_s: t_verify.as_secs_f64(),
        ns_per_lookup: prove_s * 1e9 / n as f64,
        emult_per_lookup_prover: ctr_p.emult_equiv() / n as f64,
        fp2_mults_prover: ctr_p.fp2_mults,
        base_mults_prover: ctr_p.base_mults,
        proof_bytes: proof.bytes(),
        ratio_prove_vs_native_prefill: prove_s / native_prefill_s,
    }
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");

    // Native anchor: measured GEMM throughput scaled to the budget's 8.63 G
    // MACs (single JSON-internal estimate, same machine, 4 threads).
    let (m, k, n) = (100usize, 768usize, 3072usize);
    let a: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
    let b: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
    let t_g = time_median(1, 3, || gemm_requant(&a, &b, m, k, n, 8));
    let gmacs = (m * k * n) as f64 / t_g.as_secs_f64() / 1e9;
    let native_prefill_s = 8.63e9 / (gmacs * 1e9);
    eprintln!("native anchor: {gmacs:.1} GMAC/s → prefill-100 ≈ {native_prefill_s:.3} s");

    let budget_lookups: u64 = 16_940_400; // budget_p0.py lookups_total
    let main_bits = if quick { 20 } else { 23 };
    let runs: Vec<LogupResult> = [(20u32, 16u32), (main_bits, 16)]
        .iter()
        .map(|&(nb, tb)| {
            let r = run_one(nb, tb, native_prefill_s);
            eprintln!(
                "N=2^{nb}: prove {:.2} s ({:.0} ns/lookup, {:.2} E-mult/lookup), verify {:.2} s, {} B",
                r.prove_wall_s, r.ns_per_lookup, r.emult_per_lookup_prover, r.verify_wall_s, r.proof_bytes
            );
            r
        })
        .collect();

    let main_run = runs.last().unwrap();
    let extrapolated = main_run.ns_per_lookup * budget_lookups as f64 / 1e9;
    eprintln!(
        "extrapolated prefill-100 LogUp prover: {extrapolated:.2} s  (native ≈ {native_prefill_s:.3} s → ratio {:.1})",
        extrapolated / native_prefill_s
    );

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
        milestone: "P2.5".into(),
        date: date.clone(),
        git_sha: sha.clone(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads_note: "logup prover single-threaded (spike); native anchor uses rayon".into(),
        native_prefill_est_s: native_prefill_s,
        budget_lookups_prefill: budget_lookups,
        runs,
        extrapolated_prefill_logup_s: extrapolated,
    };
    let path = format!(
        "{}/../../benchmarks/results/p2.5-{date}-{sha}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {path}");
}
