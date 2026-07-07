//! P7 local PCG spike: measure mock and phase-A real-PCG expansion cost for
//! the counted one-response correlation volume.
//!
//! `--backend mock` is the historical ChaCha lower bound. `--backend real`
//! runs the P7 phase-A in-repo Goldilocks PCG expansion: trusted-dealer base
//! VOLE stub, GGM single-point noise, regular-noise local-linear LPN, and
//! consistency-check arithmetic.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, VerifierCtx};
use volta_pcg::{expand_phase_a, ConsistencyReport, PhaseAParams, PhaseATimings};

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
    backend: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    t_prover_subs_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_verifier_sub_keys_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_prover_fulls_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_verifier_full_keys_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_total_mock_expansion_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    t_total_real_expansion_s: Option<f64>,
    sub_corrs_per_s_prover: f64,
    sub_corrs_per_s_verifier: f64,
    full_corrs_per_s_prover: f64,
    full_corrs_per_s_verifier: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_equiv_corrs_per_s_joint: Option<f64>,
    expanded_prover_bytes: u64,
    expanded_verifier_bytes: u64,
    setup_comm_bytes: u64,
    base_vole: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lpn_parameters: Option<PhaseAParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase_a_timings: Option<PhaseATimings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consistency: Option<ConsistencyReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ggm_checksum: Option<u64>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Mock,
    Real,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Mock => "mock",
            Backend::Real => "real",
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: p7_pcg_report [--backend mock|real] [--source benchmarks/results/p6-....json]");
    std::process::exit(2);
}

fn parse_args() -> (PathBuf, Backend) {
    let mut source = default_source();
    let mut backend = Backend::Mock;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--source" {
            let Some(p) = args.next() else { usage() };
            source = PathBuf::from(p);
        } else if let Some(p) = a.strip_prefix("--source=") {
            source = PathBuf::from(p);
        } else if a == "--backend" {
            let Some(b) = args.next() else { usage() };
            backend = parse_backend(&b);
        } else if let Some(b) = a.strip_prefix("--backend=") {
            backend = parse_backend(b);
        } else {
            usage();
        }
    }
    (source, backend)
}

fn parse_backend(s: &str) -> Backend {
    match s {
        "mock" => Backend::Mock,
        "real" => Backend::Real,
        _ => usage(),
    }
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
    let (source_path, backend) = parse_args();
    let source_text = std::fs::read_to_string(&source_path).expect("read source JSON");
    let source: SourceRun = serde_json::from_str(&source_text).expect("parse source JSON");
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let seed = [0xC7u8; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut checksum = 0xA5A5_5A5Au64;

    eprintln!(
        "{} PCG expansion for {n_sub} sub + {n_full} full correlations",
        backend.as_str()
    );

    let report = match backend {
        Backend::Mock => run_mock(&source, &source_path, seed, delta, &mut checksum),
        Backend::Real => run_real(&source, &source_path, seed, delta, &mut checksum),
    };

    let date = report.date.clone();
    let sha = report.git_sha.clone();
    let label = if backend == Backend::Mock { "p7-mock-pcg" } else { "p7-real-pcg" };
    let path = unique_result_path(label, &date, &sha);
    std::fs::write(&path, serde_json::to_string_pretty(&report).unwrap()).unwrap();
    if backend == Backend::Mock {
        eprintln!(
            "mock expansion total {:.3}s",
            report.t_total_mock_expansion_s.unwrap_or_default()
        );
    } else {
        let tm = report.phase_a_timings.expect("phase-A timings");
        eprintln!(
            "real phase-A total {:.3}s (setup {:.3}s, ggm {:.3}s, lpn {:.3}s, check {:.3}s)",
            tm.t_total_real_expansion_s,
            tm.t_setup_stub_s,
            tm.t_ggm_pprf_s,
            tm.t_lpn_expand_s,
            tm.t_consistency_check_s
        );
    }
    eprintln!("wrote {}", path.display());
}

fn source_rel(source_path: &Path) -> String {
    source_path
        .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .unwrap_or(source_path)
        .display()
        .to_string()
}

fn common_report(
    milestone: &str,
    backend: Backend,
    source: &SourceRun,
    source_path: &Path,
    checksum: u64,
    is_real_pcg: bool,
    note: String,
) -> Report {
    Report {
        milestone: milestone.into(),
        backend: backend.as_str().into(),
        date: date(),
        git_sha: git(&["rev-parse", "--short", "HEAD"]),
        git_dirty: git_dirty(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        source: source_rel(source_path),
        source_milestone: source.milestone.clone(),
        source_git_sha: source.git_sha.clone(),
        source_git_dirty: source.git_dirty,
        corr_sub_corrs: source.corr_sub_corrs,
        corr_full_corrs: source.corr_full_corrs,
        t_prover_subs_s: None,
        t_verifier_sub_keys_s: None,
        t_prover_fulls_s: None,
        t_verifier_full_keys_s: None,
        t_total_mock_expansion_s: None,
        t_total_real_expansion_s: None,
        sub_corrs_per_s_prover: 0.0,
        sub_corrs_per_s_verifier: 0.0,
        full_corrs_per_s_prover: 0.0,
        full_corrs_per_s_verifier: 0.0,
        sub_equiv_corrs_per_s_joint: None,
        expanded_prover_bytes: 0,
        expanded_verifier_bytes: 0,
        setup_comm_bytes: 0,
        base_vole: String::new(),
        lpn_parameters: None,
        phase_a_timings: None,
        consistency: None,
        ggm_checksum: None,
        peak_rss_gb: 0.0,
        checksum,
        is_real_pcg,
        note,
    }
}

fn run_mock(
    source: &SourceRun,
    source_path: &Path,
    seed: [u8; 32],
    delta: Fp2,
    checksum: &mut u64,
) -> Report {
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let mut ps = CorrelationStream::new(seed);
    let t0 = Instant::now();
    let subs = ps.draw_subs(0x1000, n_sub);
    std::hint::black_box(&subs);
    let t_prover_subs_s = t0.elapsed().as_secs_f64();
    for s in &subs {
        mix_fp(checksum, s.r);
        mix_fp2(checksum, s.m);
    }
    drop(subs);

    let mut vc = VerifierCtx::new(seed, delta);
    let t1 = Instant::now();
    let sub_keys = vc.expand_sub_keys(0x1000, n_sub);
    std::hint::black_box(&sub_keys);
    let t_verifier_sub_keys_s = t1.elapsed().as_secs_f64();
    for k in &sub_keys {
        mix_fp2(checksum, *k);
    }
    drop(sub_keys);

    let t2 = Instant::now();
    let fulls = ps.draw_fulls(0x2000, n_full);
    std::hint::black_box(&fulls);
    let t_prover_fulls_s = t2.elapsed().as_secs_f64();
    for f in &fulls {
        mix_fp2(checksum, f.x);
        mix_fp2(checksum, f.m);
    }
    drop(fulls);

    let t3 = Instant::now();
    let full_keys = vc.expand_full_keys(0x2000, n_full);
    std::hint::black_box(&full_keys);
    let t_verifier_full_keys_s = t3.elapsed().as_secs_f64();
    for k in &full_keys {
        mix_fp2(checksum, *k);
    }
    drop(full_keys);

    let total =
        t_prover_subs_s + t_verifier_sub_keys_s + t_prover_fulls_s + t_verifier_full_keys_s;
    let mut report = common_report(
        "P7-mock-pcg-lower-bound",
        Backend::Mock,
        source,
        source_path,
        *checksum,
        false,
        "Mock ChaCha expansion lower bound only; this is not a WYKW/silent-VOLE real-PCG setup+expansion measurement.".into(),
    );
    report.t_prover_subs_s = Some(t_prover_subs_s);
    report.t_verifier_sub_keys_s = Some(t_verifier_sub_keys_s);
    report.t_prover_fulls_s = Some(t_prover_fulls_s);
    report.t_verifier_full_keys_s = Some(t_verifier_full_keys_s);
    report.t_total_mock_expansion_s = Some(total);
    report.sub_corrs_per_s_prover = source.corr_sub_corrs as f64 / t_prover_subs_s;
    report.sub_corrs_per_s_verifier = source.corr_sub_corrs as f64 / t_verifier_sub_keys_s;
    report.full_corrs_per_s_prover = source.corr_full_corrs as f64 / t_prover_fulls_s;
    report.full_corrs_per_s_verifier = source.corr_full_corrs as f64 / t_verifier_full_keys_s;
    report.expanded_prover_bytes = 24 * source.corr_sub_corrs + 32 * source.corr_full_corrs;
    report.expanded_verifier_bytes = 16 * (source.corr_sub_corrs + source.corr_full_corrs);
    report.setup_comm_bytes = 0;
    report.base_vole = "mock-shared-seed".into();
    report.peak_rss_gb = peak_rss_gb();
    report
}

fn run_real(
    source: &SourceRun,
    source_path: &Path,
    seed: [u8; 32],
    delta: Fp2,
    checksum: &mut u64,
) -> Report {
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let params = PhaseAParams::for_counts(n_sub, n_full);
    let expansion = expand_phase_a(seed, delta, n_sub, n_full, params);

    for s in &expansion.prover.subs {
        mix_fp(checksum, s.r);
        mix_fp2(checksum, s.m);
    }
    for k in &expansion.verifier.sub_keys {
        mix_fp2(checksum, *k);
    }
    for f in &expansion.prover.fulls {
        mix_fp2(checksum, f.x);
        mix_fp2(checksum, f.m);
    }
    for k in &expansion.verifier.full_keys {
        mix_fp2(checksum, *k);
    }
    mix_fp(checksum, Fp::new(expansion.ggm_checksum));
    mix_fp(checksum, Fp::new(expansion.consistency.checksum));

    let total = expansion.timings.t_total_real_expansion_s;
    let sub_equiv = source.corr_sub_corrs + 2 * source.corr_full_corrs;
    let mut report = common_report(
        "P7-real-pcg-phase-a",
        Backend::Real,
        source,
        source_path,
        *checksum,
        true,
        "Phase-A Goldilocks WYKW/Wolverine-style expansion: GGM PPRF + regular-noise local-linear LPN + consistency-check arithmetic; base sVOLE is a mock trusted-dealer stub, not phase-B real setup.".into(),
    );
    report.t_total_real_expansion_s = Some(total);
    report.sub_corrs_per_s_prover = source.corr_sub_corrs as f64 / total;
    report.sub_corrs_per_s_verifier = source.corr_sub_corrs as f64 / total;
    report.full_corrs_per_s_prover = source.corr_full_corrs as f64 / total;
    report.full_corrs_per_s_verifier = source.corr_full_corrs as f64 / total;
    report.sub_equiv_corrs_per_s_joint = Some(sub_equiv as f64 / total);
    report.expanded_prover_bytes = expansion.prover.expanded_bytes();
    report.expanded_verifier_bytes = expansion.verifier.expanded_bytes();
    report.setup_comm_bytes = expansion.params.setup_comm_bytes();
    report.base_vole = "mock-stub".into();
    report.lpn_parameters = Some(expansion.params);
    report.phase_a_timings = Some(expansion.timings);
    report.consistency = Some(expansion.consistency);
    report.ggm_checksum = Some(expansion.ggm_checksum);
    report.peak_rss_gb = peak_rss_gb();
    report
}
