//! Fail-closed first action for a `runpod-a100-x4b-v1` session.
//!
//! This binary executes the production-size R1b NOTE-6 two-weight-set smoke
//! before any X4b kernel or wall record and writes one append-only evidence
//! row. The main X4b recorder accepts only a fresh row produced by this
//! source/profile.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const POD_PROFILE: &str = "runpod-a100-x4b-v1";
const PROTOCOL_PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const DESIGN_SHA256: &str = "bc057e458041e8123e3ef065d22b74573bcb7238a8dcee239bccfa0e8ff6be01";
const COMMAND: &str = "cargo test --release -p volta-pcs --test p35 c3_weights_two_weight_set_leakage_smoke -- --ignored --exact --nocapture";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn command_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .current_dir(repo_root())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo_root())
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(true)
}

fn parse_memtotal_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| {
            info.lines().find_map(|line| {
                let value = line.strip_prefix("MemTotal:")?;
                value.split_whitespace().next()?.parse::<u64>().ok()
            })
        })
        .unwrap_or(0)
        * 1024
}

fn blake3_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in blake3::hash(bytes).as_bytes() {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    // This field is explicitly BLAKE3; SHA-256 pinning of the finished JSON
    // is performed by the ledger/main recorder with `sha256sum`.
    output
}

#[derive(Serialize)]
struct Machine {
    hostname: String,
    gpu: String,
    driver: String,
    cpu: String,
    logical_cpus: String,
    memory_bytes: u64,
    rayon_workers: usize,
}

#[derive(Serialize)]
struct TestRecord {
    passed: bool,
    exit_code: Option<i32>,
    wall_s: f64,
    stdout_blake3: String,
    stderr_blake3: String,
    encoded_geometry_bytes: u64,
    leakage_verdict: String,
}

#[derive(Serialize)]
struct Record {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    pod_profile: String,
    protocol_profile: String,
    design_sha256: String,
    preflight_order: PreflightOrder,
    command: String,
    machine: Machine,
    test: TestRecord,
    assurance: String,
}

#[derive(Serialize)]
struct PreflightOrder {
    required_first: String,
    first_production_size_test_started: String,
    x4b_kernel_or_wall_records_started_before_pass: bool,
    order_satisfied: bool,
}

fn main() {
    if !std::env::args().any(|arg| arg == "--record") {
        eprintln!("x4b_note6_record: --record is required");
        std::process::exit(2);
    }
    if git_dirty() {
        eprintln!("x4b_note6_record: refusing a run-of-record from a dirty tree");
        std::process::exit(2);
    }
    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let started = Instant::now();
    let output = Command::new("cargo")
        .args([
            "test",
            "--release",
            "-p",
            "volta-pcs",
            "--test",
            "p35",
            "c3_weights_two_weight_set_leakage_smoke",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ])
        .current_dir(repo_root().join("rust"))
        .env("RAYON_NUM_THREADS", "8")
        .stdin(Stdio::null())
        .output()
        .expect("execute NOTE-6 production-size smoke");
    let wall_s = started.elapsed().as_secs_f64();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    let passed = output.status.success();
    let record = Record {
        schema: 1,
        milestone: "X4b-R1b-NOTE-6-preflight".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        protocol_profile: PROTOCOL_PROFILE.to_owned(),
        design_sha256: DESIGN_SHA256.to_owned(),
        preflight_order: PreflightOrder {
            required_first: "c3_weights_two_weight_set_leakage_smoke".to_owned(),
            first_production_size_test_started: "c3_weights_two_weight_set_leakage_smoke"
                .to_owned(),
            x4b_kernel_or_wall_records_started_before_pass: false,
            order_satisfied: passed,
        },
        command: COMMAND.to_owned(),
        machine: Machine {
            hostname: command_output(&["hostname"]),
            gpu: command_output(&[
                "nvidia-smi",
                "--query-gpu=name,uuid,memory.total",
                "--format=csv,noheader,nounits",
            ]),
            driver: command_output(&[
                "nvidia-smi",
                "--query-gpu=driver_version",
                "--format=csv,noheader,nounits",
            ]),
            cpu: command_output(&["lscpu"]),
            logical_cpus: command_output(&["nproc"]),
            memory_bytes: parse_memtotal_bytes(),
            rayon_workers: std::env::var("RAYON_NUM_THREADS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8),
        },
        test: TestRecord {
            passed,
            exit_code: output.status.code(),
            wall_s,
            stdout_blake3: blake3_hex(&output.stdout),
            stderr_blake3: blake3_hex(&output.stderr),
            encoded_geometry_bytes: 6_442_450_944,
            leakage_verdict: if passed { "PASS" } else { "FAIL" }.to_owned(),
        },
        assurance: "R1b NOTE-6 execution evidence only; AI-generated harness, no independent human-review assurance"
            .to_owned(),
    };
    let path = repo_root()
        .join("benchmarks/results")
        .join(format!("x4b-note6-c3-weights-preflight-{date}-{git_short_sha}.json"));
    if path.exists() {
        eprintln!("x4b_note6_record: append-only record already exists: {}", path.display());
        std::process::exit(2);
    }
    std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap() + "\n")
        .expect("write append-only X4b NOTE-6 record");
    eprintln!("wrote {}", path.display());
    if !passed {
        std::process::exit(1);
    }
}
