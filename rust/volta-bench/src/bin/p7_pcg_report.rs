//! P7 local PCG spike: measure the current mock-PCG expansion cost for the
//! counted one-response correlation volume.
//!
//! This is deliberately NOT a real Ferret/silent-VOLE benchmark. It is a
//! lower-bound/plumbing measurement over the ChaCha-backed mock generator
//! already used by the prototype, so the P7 report can separate "local
//! expansion cost we can measure here" from "real-PCG cost still required
//! before GPU go/no-go".

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, VerifierCtx};

#[derive(Deserialize)]
struct SourceRun {
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    corr_sub_corrs: u64,
    corr_full_corrs: u64,
}

#[derive(Serialize)]
struct Report {
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    machine: String,
    source: String,
    source_milestone: String,
    source_git_sha: String,
    source_git_dirty: bool,
    corr_sub_corrs: u64,
    corr_full_corrs: u64,
    t_prover_subs_s: f64,
    t_verifier_sub_keys_s: f64,
    t_prover_fulls_s: f64,
    t_verifier_full_keys_s: f64,
    t_total_mock_expansion_s: f64,
    sub_corrs_per_s_prover: f64,
    sub_corrs_per_s_verifier: f64,
    full_corrs_per_s_prover: f64,
    full_corrs_per_s_verifier: f64,
    expanded_prover_bytes: u64,
    expanded_verifier_bytes: u64,
    peak_rss_gb: f64,
    checksum: u64,
    is_real_pcg: bool,
    note: String,
}

fn default_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/results/p6-2026-07-07-515bb1c.json")
}

fn results_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/results")
}

fn usage() -> ! {
    eprintln!("usage: p7_pcg_report [--source benchmarks/results/p6-....json]");
    std::process::exit(2);
}

fn parse_source() -> PathBuf {
    let mut source = default_source();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--source" {
            let Some(p) = args.next() else { usage() };
            source = PathBuf::from(p);
        } else if let Some(p) = a.strip_prefix("--source=") {
            source = PathBuf::from(p);
        } else {
            usage();
        }
    }
    source
}

fn git(args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(true)
}

fn date() -> String {
    std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
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

fn unique_result_path(label: &str, date: &str, sha: &str) -> PathBuf {
    let first = results_dir().join(format!("{label}-{date}-{sha}.json"));
    if !first.exists() {
        return first;
    }
    for i in 1..1000 {
        let p = results_dir().join(format!("{label}-{date}-{sha}-{i}.json"));
        if !p.exists() {
            return p;
        }
    }
    panic!("could not find unused result path for {label}-{date}-{sha}");
}

fn mix_fp(acc: &mut u64, x: Fp) {
    *acc ^= x.value().rotate_left((*acc & 63) as u32);
    *acc = acc.wrapping_mul(0x9E37_79B9_7F4A_7C15);
}

fn mix_fp2(acc: &mut u64, x: Fp2) {
    mix_fp(acc, x.c0);
    mix_fp(acc, x.c1);
}

fn main() {
    let source_path = parse_source();
    let source_text = std::fs::read_to_string(&source_path).expect("read source JSON");
    let source: SourceRun = serde_json::from_str(&source_text).expect("parse source JSON");
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let seed = [0xC7u8; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut checksum = 0xA5A5_5A5Au64;

    eprintln!("mock-PCG lower-bound expansion for {n_sub} sub + {n_full} full correlations");

    let mut ps = CorrelationStream::new(seed);
    let t0 = Instant::now();
    let subs = ps.draw_subs(0x1000, n_sub);
    std::hint::black_box(&subs);
    let t_prover_subs_s = t0.elapsed().as_secs_f64();
    for s in &subs {
        mix_fp(&mut checksum, s.r);
        mix_fp2(&mut checksum, s.m);
    }
    drop(subs);

    let mut vc = VerifierCtx::new(seed, delta);
    let t1 = Instant::now();
    let sub_keys = vc.expand_sub_keys(0x1000, n_sub);
    std::hint::black_box(&sub_keys);
    let t_verifier_sub_keys_s = t1.elapsed().as_secs_f64();
    for k in &sub_keys {
        mix_fp2(&mut checksum, *k);
    }
    drop(sub_keys);

    let t2 = Instant::now();
    let fulls = ps.draw_fulls(0x2000, n_full);
    std::hint::black_box(&fulls);
    let t_prover_fulls_s = t2.elapsed().as_secs_f64();
    for f in &fulls {
        mix_fp2(&mut checksum, f.x);
        mix_fp2(&mut checksum, f.m);
    }
    drop(fulls);

    let t3 = Instant::now();
    let full_keys = vc.expand_full_keys(0x2000, n_full);
    std::hint::black_box(&full_keys);
    let t_verifier_full_keys_s = t3.elapsed().as_secs_f64();
    for k in &full_keys {
        mix_fp2(&mut checksum, *k);
    }
    drop(full_keys);

    let total =
        t_prover_subs_s + t_verifier_sub_keys_s + t_prover_fulls_s + t_verifier_full_keys_s;
    let date = date();
    let sha = git(&["rev-parse", "--short", "HEAD"]);
    let source_rel = source_path
        .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .unwrap_or(&source_path)
        .display()
        .to_string();
    let report = Report {
        milestone: "P7-mock-pcg-lower-bound".into(),
        date: date.clone(),
        git_sha: sha.clone(),
        git_dirty: git_dirty(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        source: source_rel,
        source_milestone: source.milestone,
        source_git_sha: source.git_sha,
        source_git_dirty: source.git_dirty,
        corr_sub_corrs: source.corr_sub_corrs,
        corr_full_corrs: source.corr_full_corrs,
        t_prover_subs_s,
        t_verifier_sub_keys_s,
        t_prover_fulls_s,
        t_verifier_full_keys_s,
        t_total_mock_expansion_s: total,
        sub_corrs_per_s_prover: source.corr_sub_corrs as f64 / t_prover_subs_s,
        sub_corrs_per_s_verifier: source.corr_sub_corrs as f64 / t_verifier_sub_keys_s,
        full_corrs_per_s_prover: source.corr_full_corrs as f64 / t_prover_fulls_s,
        full_corrs_per_s_verifier: source.corr_full_corrs as f64 / t_verifier_full_keys_s,
        expanded_prover_bytes: 24 * source.corr_sub_corrs + 32 * source.corr_full_corrs,
        expanded_verifier_bytes: 16 * (source.corr_sub_corrs + source.corr_full_corrs),
        peak_rss_gb: peak_rss_gb(),
        checksum,
        is_real_pcg: false,
        note: "Mock ChaCha expansion lower bound only; this is not a Ferret/silent-VOLE real-PCG setup+expansion measurement.".into(),
    };
    let path = unique_result_path("p7-mock-pcg", &date, &sha);
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    eprintln!(
        "mock expansion total {:.3}s (prover sub {:.3}s, verifier sub {:.3}s, prover full {:.3}s, verifier full {:.3}s)",
        total, t_prover_subs_s, t_verifier_sub_keys_s, t_prover_fulls_s, t_verifier_full_keys_s
    );
    eprintln!("wrote {}", path.display());
}
