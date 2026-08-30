//! CPU-only C4.1 seed-expansion/streaming-fold report.

use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use volta_field::{Fp, Fp2};
use volta_proto::{
    c41_folded_tole::{C41_PRG_USABLE_BITS, C41_SEED_BITS},
    c41_seed_streaming_checksum, C41TypedSetupVerifierState,
};

const DEFAULT_CELLS: usize = 3_110_400;
const DEFAULT_ROWS: usize = 253;
const DEFAULT_CHUNK_CELLS: usize = 4_096;
const RSS_STOP_BYTES: u64 = 2_000_000_000;

#[derive(Serialize)]
struct ThreadRun {
    threads: usize,
    wall_s: f64,
    cells_per_second: f64,
    checksum: [[u64; 2]; 2],
    minor_faults_delta: u64,
    major_faults_delta: u64,
    peak_rss_bytes: u64,
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    unix_time_s: u64,
    git_sha: String,
    git_dirty: bool,
    architecture: &'static str,
    cpu_summary: String,
    target_feature_neon: bool,
    available_parallelism: usize,
    cells: usize,
    rows: usize,
    chunk_cells: usize,
    persistent_seed_bytes: u64,
    materialized_lot_bytes_avoided: u64,
    full_query_bytes_avoided: u64,
    runs: Vec<ThreadRun>,
    checksums_equal: bool,
    rss_stop_bytes: u64,
    rss_stop_pass: bool,
}

fn parse_args() -> (usize, usize, usize, Option<PathBuf>) {
    let mut cells = DEFAULT_CELLS;
    let mut rows = DEFAULT_ROWS;
    let mut chunk = DEFAULT_CHUNK_CELLS;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = match argument.as_str() {
            "--cells" | "--rows" | "--chunk-cells" | "--output" => {
                args.next().unwrap_or_else(|| panic!("{argument} requires a value"))
            }
            _ => panic!("unknown argument {argument}"),
        };
        match argument.as_str() {
            "--cells" => cells = value.parse().expect("--cells must be usize"),
            "--rows" => rows = value.parse().expect("--rows must be usize"),
            "--chunk-cells" => chunk = value.parse().expect("--chunk-cells must be usize"),
            "--output" => output = Some(PathBuf::from(value)),
            _ => unreachable!(),
        }
    }
    (cells, rows, chunk, output)
}

fn git(args: &[&str]) -> String {
    String::from_utf8_lossy(
        &Command::new("git").args(args).output().expect("run git for report identity").stdout,
    )
    .trim()
    .to_owned()
}

fn process_counters() -> (u64, u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let peak_rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        * 1024;
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields = stat.rsplit_once(')').map(|(_, tail)| tail.split_whitespace().collect::<Vec<_>>());
    let minor = fields
        .as_ref()
        .and_then(|values| values.get(7))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let major = fields
        .as_ref()
        .and_then(|values| values.get(9))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    (minor, major, peak_rss)
}

fn cpu_summary() -> String {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let wanted = ["model name", "Model", "Hardware", "CPU implementer", "CPU part"];
    let summary = cpuinfo
        .lines()
        .filter(|line| wanted.iter().any(|key| line.starts_with(key)))
        .take(5)
        .collect::<Vec<_>>()
        .join("; ");
    if summary.is_empty() { "unknown".to_owned() } else { summary }
}

fn checksum_wire(value: (Fp2, Fp2)) -> [[u64; 2]; 2] {
    [[value.0.c0.value(), value.0.c1.value()], [value.1.c0.value(), value.1.c1.value()]]
}

fn main() {
    let (cells, rows, chunk_cells, output) = parse_args();
    assert!(cells > 0 && rows > 0 && chunk_cells > 0);
    assert!(
        cells * 17 <= rows * C41_PRG_USABLE_BITS,
        "requested cells exceed the compact seed inventory"
    );
    let git_sha = git(&["rev-parse", "HEAD"]);
    let git_dirty = !git(&["status", "--porcelain"]).is_empty();
    if output.is_some() && git_dirty {
        panic!("run-of-record output requires a clean tree");
    }

    let setup = C41TypedSetupVerifierState {
        keys: (0..rows * C41_SEED_BITS)
            .map(|index| {
                Fp2::new(
                    Fp::new((index as u64 + 1).wrapping_mul(0x9E37_79B9)),
                    Fp::new((index as u64 + 7).wrapping_mul(0x85EB_CA6B)),
                )
            })
            .collect(),
        rows,
    };
    let public_seed = [0xC4; 32];
    let delta = Fp2::new(Fp::new(0xC4_1001), Fp::new(0xC4_1003));
    let mut runs = Vec::new();
    for threads in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("create bounded verifier thread pool");
        let before = process_counters();
        let started = Instant::now();
        let checksum = pool
            .install(|| {
                c41_seed_streaming_checksum(&setup, public_seed, 0, cells, delta, chunk_cells)
            })
            .expect("complete C4.1 seed-only expansion");
        let wall_s = started.elapsed().as_secs_f64();
        let after = process_counters();
        runs.push(ThreadRun {
            threads,
            wall_s,
            cells_per_second: cells as f64 / wall_s,
            checksum: checksum_wire(std::hint::black_box(checksum)),
            minor_faults_delta: after.0.saturating_sub(before.0),
            major_faults_delta: after.1.saturating_sub(before.1),
            peak_rss_bytes: after.2,
        });
    }
    let checksums_equal = runs[0].checksum == runs[1].checksum;
    let peak = runs.iter().map(|run| run.peak_rss_bytes).max().unwrap_or(0);
    assert!(checksums_equal, "one-thread and four-thread field results differ");
    assert!(peak < RSS_STOP_BYTES, "C4.1 verifier exceeded the 2 GB RSS safety stop");
    let report = Report {
        schema: "volta-c41-seed-stream-v1",
        unix_time_s: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        git_sha,
        git_dirty,
        architecture: std::env::consts::ARCH,
        cpu_summary: cpu_summary(),
        target_feature_neon: cfg!(all(target_arch = "aarch64", target_feature = "neon")),
        available_parallelism: std::thread::available_parallelism().map(usize::from).unwrap_or(1),
        cells,
        rows,
        chunk_cells,
        persistent_seed_bytes: (setup.keys.len() * std::mem::size_of::<Fp2>()) as u64,
        materialized_lot_bytes_avoided: (2 * cells * std::mem::size_of::<Fp2>()) as u64,
        full_query_bytes_avoided: (cells * std::mem::size_of::<Fp2>()) as u64,
        runs,
        checksums_equal,
        rss_stop_bytes: RSS_STOP_BYTES,
        rss_stop_pass: true,
    };
    let encoded = serde_json::to_vec_pretty(&report).expect("serialize seed-stream report");
    if let Some(path) = output {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create append-only seed-stream report");
        file.write_all(&encoded).expect("write seed-stream report");
        file.write_all(b"\n").expect("terminate seed-stream report");
        file.sync_all().expect("sync seed-stream report");
    } else {
        println!("{}", String::from_utf8(encoded).expect("JSON is UTF-8"));
    }
}
