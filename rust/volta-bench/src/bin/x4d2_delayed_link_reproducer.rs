//! Standalone X4d.2 delayed-link resident/CPU differential.
//!
//! This diagnostic has no model-weight, onboarding, durable-tier, connection,
//! authorization, or settlement dependency. It cannot issue a gate verdict or
//! start a production pair. The production suite is intentionally explicit:
//! one exact round-count-27 case and a separate max-mu 20/22/24/26 ladder.

use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_accel::{Backend, ResidentTimingPolicy, CUDA_ABI_VERSION};
use volta_pcs::x4::{
    x4d2_delayed_link_diagnostic_case_v4, X4dDelayedLinkDiagnosticCaseV4, X4dResidentLinkCountersV4,
};

const MILESTONE: &str = "X4d.2-delayed-link-diagnostic-v1";
const DESIGN_PATH: &str = "docs/x4d2-byte-identical-resident-settlement-design.md";

#[derive(Clone, Copy)]
enum BackendArg {
    Cpu,
    Cuda,
}

struct Args {
    backend: BackendArg,
    output: PathBuf,
    hourly_usd_scenario: f64,
}

fn usage() -> ! {
    eprintln!(
        "usage: x4d2_delayed_link_reproducer --backend cpu|cuda \
         --output benchmarks/results/x4d2-diag-<date>-<sha>.json \
         [--hourly-usd-scenario 2.00]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut backend = None;
    let mut output = None;
    let mut hourly_usd_scenario = 2.0f64;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--backend" => {
                backend = Some(match value().as_str() {
                    "cpu" => BackendArg::Cpu,
                    "cuda" => BackendArg::Cuda,
                    _ => usage(),
                });
            }
            "--output" => output = Some(PathBuf::from(value())),
            "--hourly-usd-scenario" => {
                hourly_usd_scenario = value().parse().unwrap_or_else(|_| usage());
                if !hourly_usd_scenario.is_finite() || hourly_usd_scenario < 0.0 {
                    usage();
                }
            }
            _ => usage(),
        }
    }
    Args {
        backend: backend.unwrap_or_else(|| usage()),
        output: output.unwrap_or_else(|| usage()),
        hourly_usd_scenario,
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn command_text(output: &Path, backend: BackendArg, hourly_usd_scenario: f64) -> String {
    format!(
        "cargo run --release -p volta-bench --features cuda --bin \
         x4d2_delayed_link_reproducer -- --backend {} --output {} \
         --hourly-usd-scenario {hourly_usd_scenario:.6}",
        match backend {
            BackendArg::Cpu => "cpu",
            BackendArg::Cuda => "cuda",
        },
        output.display()
    )
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| format!("{program} emitted non-UTF8"))
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("run sha256sum: {error}"))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "sha256sum emitted non-UTF8".to_owned())?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn counters_json(counters: X4dResidentLinkCountersV4) -> Value {
    json!({
        "unique_terms": counters.unique_terms,
        "source_symbols": counters.source_symbols,
        "equality_symbols": counters.equality_symbols,
        "host_bytes": counters.host_bytes,
        "device_bytes": counters.device_bytes,
        "h2d_bytes": counters.h2d_bytes,
        "source_clone_bytes": counters.source_clone_bytes,
        "d2h_bytes": counters.d2h_bytes,
        "d2d_bytes": counters.d2d_bytes,
        "protocol_scalar_d2h_bytes": counters.protocol_scalar_d2h_bytes,
        "kernel_calls": counters.kernel_calls,
        "allocation_requests": counters.allocation_requests,
        "buffer_reuse_hits": counters.buffer_reuse_hits,
        "peak_live_host_scratch_bytes": counters.peak_live_host_scratch_bytes,
        "peak_live_scratch_bytes": counters.peak_live_scratch_bytes,
    })
}

fn case_json(case: X4dDelayedLinkDiagnosticCaseV4, wall_s: f64) -> Value {
    json!({
        "max_mu": case.max_mu,
        "round_count": case.round_count,
        "dimension_multiplicities": case.dimension_multiplicities,
        "physical_source_slots": case.physical_source_slots,
        "resident_terms": case.resident_terms,
        "logical_contributions": case.logical_contributions,
        "source_symbols": case.source_symbols,
        "round_messages_checked": case.round_messages_checked,
        "challenges_checked": case.challenges_checked,
        "fold_states_checked": case.fold_states_checked,
        "correction_count": case.correction_count,
        "transcript_bytes": case.transcript_bytes,
        "correlation_counters_equal": case.correlation_counters_equal,
        "correlation_allocation_ledger_equal": case.correlation_allocation_ledger_equal,
        "transcript_ledger_equal": case.transcript_ledger_equal,
        "terminal_point_equal": case.terminal_point_equal,
        "terminal_value_equal": case.terminal_value_equal,
        "resident_counters": counters_json(case.resident_counters),
        "analytic_host_source_bytes": case.analytic_host_source_bytes,
        "analytic_device_live_bytes": case.analytic_device_live_bytes,
        "trace_blake3": hex(&case.trace_blake3),
        "diagnostic_wall_s": wall_s,
        "performance_result": false,
        "gate_verdict": false,
    })
}

fn run_case(
    backend: &mut Backend,
    max_mu: usize,
    multiplicities: [usize; 3],
) -> Result<(X4dDelayedLinkDiagnosticCaseV4, f64), String> {
    let started = Instant::now();
    let result = x4d2_delayed_link_diagnostic_case_v4(backend, max_mu, multiplicities)
        .map_err(|error| format!("max_mu={max_mu} multiplicities={multiplicities:?}: {error:?}"))?;
    Ok((result, started.elapsed().as_secs_f64()))
}

fn run() -> Result<(), String> {
    let args = parse_args();
    let name = args
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "diagnostic output needs a UTF-8 filename".to_owned())?;
    if !name.starts_with("x4d2-diag-") || !name.ends_with(".json") {
        return Err("diagnostic output must use the fresh x4d2-diag-*.json namespace".to_owned());
    }
    let git_sha = command_stdout("git", &["rev-parse", "HEAD"])?;
    let dirty = !command_stdout("git", &["status", "--porcelain"])?.is_empty();
    if dirty {
        return Err("standalone diagnostic requires a clean tree".to_owned());
    }
    let design_path = repo_root().join(DESIGN_PATH);
    let design_sha256 = sha256(&design_path)?;
    let producer_sha256 = sha256(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/x4d2_delayed_link_reproducer.rs"),
    )?;
    let mut backend = match args.backend {
        BackendArg::Cpu => Backend::cpu(),
        BackendArg::Cuda => {
            Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
                .map_err(|error| format!("fail-closed CUDA selection: {error}"))?
        }
    };

    let mut ladder = Vec::new();
    for max_mu in [20usize, 22, 24, 26] {
        let (case, wall_s) = run_case(&mut backend, max_mu, [1, 1, 1])?;
        ladder.push(case_json(case, wall_s));
    }
    let (exact, exact_wall_s) = run_case(&mut backend, 26, [2, 36, 13])?;
    if exact.round_count != 27
        || exact.physical_source_slots != 51
        || exact.resident_terms != 51
        || exact.logical_contributions != 102
    {
        return Err("exact production-shape census mismatch".to_owned());
    }
    let exact_host_peak_projection = exact
        .analytic_host_source_bytes
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add((1u64 << 26) * 16))
        .ok_or_else(|| "analytic host peak overflow".to_owned())?;
    let runtime_projection_seconds = [60.0f64, 180.0, 600.0];
    let projected_cost =
        runtime_projection_seconds.map(|seconds| args.hourly_usd_scenario * seconds / 3_600.0);
    let record = json!({
        "schema": 1,
        "milestone": MILESTONE,
        "git_sha": git_sha,
        "git_dirty": false,
        "design_path": DESIGN_PATH,
        "design_sha256": design_sha256,
        "producer_source_sha256": producer_sha256,
        "cuda_abi_version": CUDA_ABI_VERSION,
        "backend": match args.backend {
            BackendArg::Cpu => "cpu",
            BackendArg::Cuda => "cuda-resident-fail-closed",
        },
        "command": command_text(&args.output, args.backend, args.hourly_usd_scenario),
        "scope": {
            "weights_required": false,
            "schema3_onboarding_required": false,
            "durable_tier_required": false,
            "connection_required": false,
            "settlement_required": false,
            "pod_contacted_by_program": false,
            "production_pair_started": false,
            "gate_verdict": false,
        },
        "scale_ladder": ladder,
        "exact_production_shape": case_json(exact.clone(), exact_wall_s),
        "analytic_memory_envelope": {
            "source_symbols": exact.source_symbols,
            "host_source_bytes": exact.analytic_host_source_bytes,
            "conservative_host_peak_bytes": exact_host_peak_projection,
            "device_live_bytes": exact.analytic_device_live_bytes,
            "measured": false,
            "classification": "analytic projection, not resource-admission evidence",
        },
        "runtime_cost_scenario": {
            "runtime_seconds": {
                "lower": runtime_projection_seconds[0],
                "central": runtime_projection_seconds[1],
                "upper": runtime_projection_seconds[2],
            },
            "hourly_usd_scenario": args.hourly_usd_scenario,
            "cost_usd": {
                "lower": projected_cost[0],
                "central": projected_cost[1],
                "upper": projected_cost[2],
            },
            "measured": false,
            "classification": "engineering scenario only; never a performance result or gate verdict",
        },
        "assurance": "Synthetic delayed-link differential only. No production settlement pair is authorized or started."
    });
    let encoded = serde_json::to_vec_pretty(&record)
        .map_err(|error| format!("encode diagnostic record: {error}"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .map_err(|error| format!("create fresh {}: {error}", args.output.display()))?;
    output
        .write_all(&encoded)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|error| format!("write {}: {error}", args.output.display()))?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("x4d2_delayed_link_reproducer HARD STOP: {error}");
        std::process::exit(1);
    }
}
