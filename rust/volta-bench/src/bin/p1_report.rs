//! P1 report: measures ρ_kernel on the GPT-2 GEMM shapes and the verifier-side
//! streaming throughput, and emits the JSON of record into benchmarks/results/.
//!
//! Run: cargo run --release -p volta-bench --bin p1_report [-- --quick]

use serde::Serialize;
use volta_bench::{time_median, time_paired, verifier_fused_scan};
use volta_field::{Fp, Fp2};
use volta_gpt2::{gemm_requant, gemm_requant_auth, EpilogueSpec};

#[derive(Serialize)]
struct ShapeResult {
    m: usize,
    k: usize,
    n: usize,
    label: String,
    native_ms: f64,
    fused_ms: f64,
    rho_kernel: f64,
    epilogue_ns_per_elem: f64,
    correction_bytes_per_elem: usize,
    gmacs_native: f64,
}

#[derive(Serialize)]
struct VerifierResult {
    n_elems: usize,
    fused_scan_ms: f64,
    ns_per_elem: f64,
    elems_per_sec: f64,
    prefill_100tok_extrapolated_s: f64,
}

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    machine: String,
    threads: usize,
    iters: usize,
    shapes: Vec<ShapeResult>,
    rho_kernel_weighted_layer: f64,
    verifier: VerifierResult,
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let iters = if quick { 3 } else { 9 };
    let warmup = if quick { 1 } else { 3 };

    // GPT-2 small GEMM shapes reached by the fused epilogue (K/V from
    // qkv_proj, block outputs from attn_out_proj / ffn_down; ffn_up is an
    // internal wire — measured anyway to bound the worst case).
    let shapes = [
        (100usize, 768usize, 768usize, "attn_out_proj / ffn_down-shape"),
        (100, 768, 2304, "qkv_proj"),
        (100, 768, 3072, "ffn_up (internal, worst case)"),
    ];

    let mut results = Vec::new();
    for &(m, k, n, label) in &shapes {
        let a: Vec<i16> = (0..m * k).map(|i| ((i * 37 + 11) % 4001) as i16 - 2000).collect();
        let b: Vec<i16> = (0..k * n).map(|i| ((i * 53 + 5) % 4001) as i16 - 2000).collect();
        let ep = EpilogueSpec { shift: 8, seed: [1; 32], tensor_tag: 3 };

        let (t_native, t_fused) = time_paired(
            warmup,
            iters,
            || gemm_requant(&a, &b, m, k, n, 8),
            || gemm_requant_auth(&a, &b, m, k, n, ep),
        );
        let (native_ms, fused_ms) = (t_native.as_secs_f64() * 1e3, t_fused.as_secs_f64() * 1e3);
        let rho = fused_ms / native_ms;
        let epi_ns = (t_fused.as_secs_f64() - t_native.as_secs_f64()) * 1e9 / (m * n) as f64;
        eprintln!(
            "{label:<34} {m}x{k}x{n}: native {native_ms:8.2} ms  fused {fused_ms:8.2} ms  ρ_kernel {rho:5.3}  epilogue {epi_ns:6.1} ns/elem"
        );
        results.push(ShapeResult {
            m,
            k,
            n,
            label: label.into(),
            native_ms,
            fused_ms,
            rho_kernel: rho,
            epilogue_ns_per_elem: epi_ns,
            correction_bytes_per_elem: 8,
            gmacs_native: (m * k * n) as f64 / t_native.as_secs_f64() / 1e9,
        });
    }

    // Layer-weighted ρ: per layer only qkv (K,V slice), attn_out_proj and
    // ffn_down outputs are authenticated; scores/AV/ffn_up epilogues are
    // requant-only. Weight fused vs native GEMM times accordingly:
    // fused for qkv_proj + out_proj + ffn_down-shape, native for ffn_up.
    let t_of = |i: usize, fused: bool| -> f64 {
        if fused { results[i].fused_ms } else { results[i].native_ms }
    };
    // per-layer big GEMMs: qkv(idx1), out_proj(idx0), ffn_up(idx2), ffn_down≈idx2 shape native time
    let ffn_down_native = results[2].native_ms; // same MAC count as ffn_up
    let ffn_down_fused = ffn_down_native * results[0].rho_kernel; // d-out epilogue density ≈ idx0
    let layer_fused = t_of(1, true) + t_of(0, true) + t_of(2, false) + ffn_down_fused;
    let layer_native = t_of(1, false) + t_of(0, false) + t_of(2, false) + ffn_down_native;
    let rho_layer = layer_fused / layer_native;

    // Verifier: fused scan (PCG key expansion + key update + eq inner product)
    // over one layer's worth of authenticated values, padded to 2^20.
    let n_elems = 1usize << 20;
    let corr: Vec<u64> = (0..n_elems).map(|i| (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();
    let delta = Fp2::new(Fp::new(123456789), Fp::new(987654321));
    let rs: Vec<Fp2> = (0..20).map(|j| Fp2::new(Fp::new(j as u64 + 2), Fp::new(3 * j as u64 + 1))).collect();
    let t_scan = time_median(warmup, iters, || verifier_fused_scan([2; 32], 5, delta, &rs, &corr));
    let scan_s = t_scan.as_secs_f64();
    let elems_per_sec = n_elems as f64 / scan_s;
    let auth_total = 3_763_968.0; // budget_p0.py
    let q = 3.0;
    let verifier = VerifierResult {
        n_elems,
        fused_scan_ms: scan_s * 1e3,
        ns_per_elem: scan_s * 1e9 / n_elems as f64,
        elems_per_sec,
        prefill_100tok_extrapolated_s: auth_total * q / elems_per_sec,
    };
    eprintln!(
        "verifier fused scan: {:.1} ms / 2^20 elems = {:.0} ns/elem → prefill-100 (q=3): {:.2} s",
        verifier.fused_scan_ms, verifier.ns_per_elem, verifier.prefill_100tok_extrapolated_s
    );
    eprintln!("ρ_kernel weighted over one layer: {rho_layer:.3}");

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
        milestone: "P1".into(),
        date: date.clone(),
        git_sha: sha.clone(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        threads: std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1),
        iters,
        shapes: results,
        rho_kernel_weighted_layer: rho_layer,
        verifier,
    };
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results");
    let path = out_dir.join(format!("p1-{date}-{sha}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}
