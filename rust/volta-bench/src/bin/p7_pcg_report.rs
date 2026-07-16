//! P7 local PCG report: measure the two-party malicious phase-B expansion for
//! the counted one-response volume, or explicitly select a diagnostic legacy
//! backend.
//!
//! The default and `--backend real` are phase B. `--backend mock` is the
//! historical ChaCha lower bound and `--backend phase-a` is the trusted-dealer
//! cost model; both require `--diagnostic` and never write a result artifact.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_mac::{CorrelationStream, VerifierCtx};
use volta_pcg::{
    expand_phase_a, expand_phase_b_production_with_ggm_prg, ConsistencyReport, GgmPrg,
    PhaseAParams, PhaseATimings, PhaseBSetupReport, PhaseBTimings, ProductionSetupAudit,
    ResponseAuthorizationStore, SessionBinding,
};

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
    ggm_prg: String,
    ggm_prg_active: bool,
    ggm_aes_feature: String,
    detected_physical_cpu_cores: usize,
    detected_logical_cpu_cores: usize,
    pcg_setup_rayon_threads: usize,
    pcg_production_ready: bool,
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
    phase_b_timings: Option<PhaseBTimings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase_b_setup: Option<PhaseBSetupReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    production_setup_audit: Option<ProductionSetupAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    production_ready: Option<bool>,
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
    PhaseA,
    PhaseB,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GgmPrgArg {
    Aes128Mmo,
    Blake3,
}

impl GgmPrgArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Aes128Mmo => "aes128-mmo",
            Self::Blake3 => "blake3",
        }
    }

    fn into_pcg(self) -> GgmPrg {
        match self {
            Self::Aes128Mmo => GgmPrg::Aes128Mmo,
            Self::Blake3 => GgmPrg::Blake3,
        }
    }
}

struct Args {
    source: PathBuf,
    backend: Backend,
    ggm_prg: GgmPrgArg,
    diagnostic: bool,
    authorization_store: Option<PathBuf>,
}

impl Backend {
    fn as_str(self) -> &'static str {
        match self {
            Backend::Mock => "mock",
            Backend::PhaseA => "phase-a",
            Backend::PhaseB => "phase-b",
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: p7_pcg_report [--backend real|phase-b|phase-a|mock] \
         [--ggm-prg aes128-mmo|blake3] [--diagnostic] \
         [--pcg-authorization-store PATH] \
         [--source benchmarks/results/p6-....json]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut out = Args {
        source: default_source(),
        backend: Backend::PhaseB,
        ggm_prg: GgmPrgArg::Aes128Mmo,
        diagnostic: false,
        authorization_store: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--source" {
            let Some(p) = args.next() else { usage() };
            out.source = PathBuf::from(p);
        } else if let Some(p) = a.strip_prefix("--source=") {
            out.source = PathBuf::from(p);
        } else if a == "--backend" {
            let Some(b) = args.next() else { usage() };
            out.backend = parse_backend(&b);
        } else if let Some(b) = a.strip_prefix("--backend=") {
            out.backend = parse_backend(b);
        } else if a == "--ggm-prg" {
            let Some(prg) = args.next() else { usage() };
            out.ggm_prg = parse_ggm_prg(&prg);
        } else if let Some(prg) = a.strip_prefix("--ggm-prg=") {
            out.ggm_prg = parse_ggm_prg(prg);
        } else if a == "--diagnostic" {
            out.diagnostic = true;
        } else if a == "--pcg-authorization-store" {
            out.authorization_store = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
        } else if let Some(path) = a.strip_prefix("--pcg-authorization-store=") {
            out.authorization_store = Some(PathBuf::from(path));
        } else {
            usage();
        }
    }
    out
}

fn os_identity(label: &str) -> [u8; 32] {
    let mut value = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut value)
        .unwrap_or_else(|error| panic!("OS entropy unavailable for {label}: {error}"));
    value
}

fn parse_backend(s: &str) -> Backend {
    match s {
        "mock" => Backend::Mock,
        "phase-a" => Backend::PhaseA,
        "real" | "phase-b" => Backend::PhaseB,
        _ => usage(),
    }
}

fn parse_ggm_prg(s: &str) -> GgmPrgArg {
    match s {
        "aes128-mmo" => GgmPrgArg::Aes128Mmo,
        "blake3" => GgmPrgArg::Blake3,
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

fn detected_logical_cpu_cores() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

fn detected_physical_cpu_cores(logical_fallback: usize) -> usize {
    let mut cores = BTreeSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(index) = name.strip_prefix("cpu") else { continue };
            if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
                continue;
            }
            let topology = entry.path().join("topology");
            let package = std::fs::read_to_string(topology.join("physical_package_id"));
            let core = std::fs::read_to_string(topology.join("core_id"));
            if let (Ok(package), Ok(core)) = (package, core) {
                cores.insert((package.trim().to_owned(), core.trim().to_owned()));
            }
        }
    }
    if cores.is_empty() {
        logical_fallback
    } else {
        cores.len()
    }
}

fn detected_aes_feature() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::arch::is_x86_feature_detected!("aes") {
        return "aes-ni";
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        return "armv8-ce";
    }
    "portable"
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
    let args = parse_args();
    let source_path = args.source.clone();
    let backend = args.backend;
    if matches!(backend, Backend::Mock | Backend::PhaseA) && !args.diagnostic {
        eprintln!(
            "p7_pcg_report: mock and phase-a are diagnostic-only; add --diagnostic or use the default real phase-B backend"
        );
        std::process::exit(2);
    }
    if backend == Backend::PhaseA && args.ggm_prg != GgmPrgArg::Blake3 {
        eprintln!(
            "p7_pcg_report: historical phase-a uses BLAKE3 GGM; select --ggm-prg blake3 explicitly"
        );
        std::process::exit(2);
    }
    if !args.diagnostic && args.ggm_prg != GgmPrgArg::Aes128Mmo {
        eprintln!(
            "p7_pcg_report: record-producing mode requires the default --ggm-prg aes128-mmo; BLAKE3 is diagnostic-only"
        );
        std::process::exit(2);
    }
    let production_store = (backend == Backend::PhaseB).then(|| {
        let path = args
            .authorization_store
            .clone()
            .or_else(|| std::env::var_os("VOLTA_PCG_AUTHORIZATION_STORE").map(PathBuf::from))
            .unwrap_or_else(|| {
                eprintln!(
                    "p7_pcg_report: real PCG requires --pcg-authorization-store PATH or VOLTA_PCG_AUTHORIZATION_STORE"
                );
                std::process::exit(2);
            });
        ResponseAuthorizationStore::new(path)
            .unwrap_or_else(|error| panic!("authorization-store preflight failed: {error}"))
    });
    let source_text = std::fs::read_to_string(&source_path).expect("read source JSON");
    let source: SourceRun = serde_json::from_str(&source_text).expect("parse source JSON");
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let seed = [0xC7u8; 32];
    let delta = Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE));
    let mut checksum = 0xA5A5_5A5Au64;

    eprintln!("{} PCG expansion for {n_sub} sub + {n_full} full correlations", backend.as_str());

    let report = match backend {
        Backend::Mock => run_mock(&source, &source_path, seed, delta, args.ggm_prg, &mut checksum),
        Backend::PhaseA => run_phase_a(&source, &source_path, seed, delta, &mut checksum),
        Backend::PhaseB => run_phase_b(
            &source,
            &source_path,
            production_store.as_ref().expect("real store"),
            args.ggm_prg,
            &mut checksum,
        ),
    };

    let json = serde_json::to_string_pretty(&report).unwrap();
    if backend == Backend::Mock {
        eprintln!(
            "mock expansion total {:.3}s",
            report.t_total_mock_expansion_s.unwrap_or_default()
        );
    } else {
        let total = report.t_total_real_expansion_s.unwrap_or_default();
        eprintln!(
            "{} total {:.3}s setup_comm={} B",
            backend.as_str(),
            total,
            report.setup_comm_bytes
        );
    }
    if args.diagnostic {
        println!("{json}");
        eprintln!("diagnostic only; no result artifact written");
    } else {
        let date = report.date.clone();
        let sha = report.git_sha.clone();
        let path = unique_result_path("p7-real-pcg", &date, &sha);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = options.open(&path).expect("create append-only result JSON");
        std::io::Write::write_all(&mut file, json.as_bytes()).expect("write result JSON");
        eprintln!("wrote {}", path.display());
    }
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
    ggm_prg: GgmPrgArg,
    ggm_prg_active: bool,
    note: String,
) -> Report {
    let logical_cores = detected_logical_cpu_cores();
    Report {
        milestone: milestone.into(),
        backend: backend.as_str().into(),
        date: date(),
        git_sha: git(&["rev-parse", "--short", "HEAD"]),
        git_dirty: git_dirty(),
        machine: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        ggm_prg: ggm_prg.as_str().into(),
        ggm_prg_active,
        ggm_aes_feature: detected_aes_feature().into(),
        detected_physical_cpu_cores: detected_physical_cpu_cores(logical_cores),
        detected_logical_cpu_cores: logical_cores,
        pcg_setup_rayon_threads: rayon::current_num_threads(),
        pcg_production_ready: false,
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
        phase_b_timings: None,
        phase_b_setup: None,
        production_setup_audit: None,
        production_ready: None,
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
    ggm_prg: GgmPrgArg,
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

    let total = t_prover_subs_s + t_verifier_sub_keys_s + t_prover_fulls_s + t_verifier_full_keys_s;
    let mut report = common_report(
        "P7-mock-pcg-lower-bound",
        Backend::Mock,
        source,
        source_path,
        *checksum,
        false,
        ggm_prg,
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

fn run_phase_a(
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
        Backend::PhaseA,
        source,
        source_path,
        *checksum,
        true,
        GgmPrgArg::Blake3,
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

fn run_phase_b(
    source: &SourceRun,
    source_path: &Path,
    store: &ResponseAuthorizationStore,
    ggm_prg: GgmPrgArg,
    checksum: &mut u64,
) -> Report {
    let n_sub = source.corr_sub_corrs as usize;
    let n_full = source.corr_full_corrs as usize;
    let params = PhaseAParams::for_counts(n_sub, n_full);
    let binding = SessionBinding::new(
        os_identity("P7 PCG session identity"),
        os_identity("P7 authenticated channel identity"),
        os_identity("P7 response authorization nonce"),
    )
    .expect("nonzero P7 PCG identities");
    let production = expand_phase_b_production_with_ggm_prg(
        store,
        binding,
        n_sub,
        n_full,
        params,
        ggm_prg.into_pcg(),
    )
    .expect("production-provisioned two-party phase-B expansion");
    let production_audit = production.production;
    let expansion = production.expansion;
    assert_eq!(
        expansion.setup.params.ggm_prg.as_str(),
        ggm_prg.as_str(),
        "report GGM selection must match phase-B setup"
    );
    assert_eq!(
        expansion.setup.params.ggm_aes_backend.as_str(),
        detected_aes_feature(),
        "report AES feature must match phase-B runtime selection"
    );

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
    mix_fp(checksum, Fp::new(expansion.consistency.checksum));

    let total = expansion.timings.t_total_setup_and_expansion_s;
    let sub_equiv = source.corr_sub_corrs + 2 * source.corr_full_corrs;
    let production_ready = expansion.setup.params.production_ready;
    assert!(production_ready, "production phase-B preflight must enact the default flip");
    let setup_comm = expansion.setup.comm.total_bytes;
    let mut report = common_report(
        "P7-real-pcg-phase-b",
        Backend::PhaseB,
        source,
        source_path,
        *checksum,
        true,
        ggm_prg,
        true,
        "Phase-B genuine two-party host setup: independent roles, framed serialized channel, verifier-only Delta, Ristretto base OT + checked IKNP/COPEe, WYKW GGM single-point sVOLE and transcript-bound malicious consistency check. Real phase-B is the production-ready binary default; mock remains explicit and diagnostic-only.".into(),
    );
    report.t_total_real_expansion_s = Some(total);
    report.sub_corrs_per_s_prover = source.corr_sub_corrs as f64 / total;
    report.sub_corrs_per_s_verifier = source.corr_sub_corrs as f64 / total;
    report.full_corrs_per_s_prover = source.corr_full_corrs as f64 / total;
    report.full_corrs_per_s_verifier = source.corr_full_corrs as f64 / total;
    report.sub_equiv_corrs_per_s_joint = Some(sub_equiv as f64 / total);
    report.expanded_prover_bytes = expansion.prover.expanded_bytes();
    report.expanded_verifier_bytes = expansion.verifier.expanded_bytes();
    report.setup_comm_bytes = setup_comm;
    report.base_vole = "real-COPEe-WYKW-checked".into();
    report.lpn_parameters = Some(expansion.params);
    report.phase_b_timings = Some(expansion.timings);
    report.phase_b_setup = Some(expansion.setup);
    report.production_setup_audit = Some(production_audit);
    report.pcg_production_ready = production_ready;
    report.production_ready = Some(production_ready);
    report.consistency = Some(expansion.consistency);
    report.peak_rss_gb = peak_rss_gb();
    report
}
