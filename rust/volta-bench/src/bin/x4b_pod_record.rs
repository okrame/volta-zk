//! Fail-closed A100 record harness for `runpod-a100-x4b-v1`.
//!
//! NOTE-6 is supplied as a fresh, SHA-pinned first-session record.  This
//! harness then runs CUDA correctness, the complete CPU node pipeline, full
//! initial-oracle passes, isolated Wext-mu26 candidates, a final durable
//! materialization, and independent sealed/opened/verified response
//! candidates. Timings are host wall only; CUDA events are prohibited.

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use volta_accel::{
    Backend, BackendStats, DeviceTimingMode, Operation, ResidentTimingPolicy, CUDA_ABI_VERSION,
};
use volta_field::{Fp, Fp2, P};
use volta_mac::Transcript;
use volta_pcs::x4::{
    commit_cohort_cuda_v4, encode_rate_eighth, fp2_pow, global_fold_descriptor_digest_v4,
    hash_pcs_inner_leaf_fields_v4, hash_pcs_node_fields_v4, hash_pcs_outer_leaf_fields_v4,
    read_persisted_coefficients_v4, root_of_unity, verify_global_folding_v4, CohortIdentityV4,
    CohortTreeV4, CohortVerifierConfigV4, DenseOuterNodeCacheV4, FrameV4, GlobalChainDraftV4,
    GlobalOpenMetricsV4, GlobalProverGroupV4, ModelGlobalOpeningSourceV4, OracleKindV4,
    OuterCachePolicyV4, OuterNodeSourceV4, PcsLeafFrameV4, PcsLeafPayloadV4, PcsNodeFrameV4,
    PersistedModelGlobalCohortV4, PersistedOracleBindingV4, TreeRole, X4bCudaCohortArtifactsV4,
    X4bCudaCohortPathsV4, X4bCudaCommitMetricsV4, X4bOpeningSourcePolicyV4,
    MANIFEST_LEAF_HASH_CONTEXT_V4, MANIFEST_NODE_HASH_CONTEXT_V4, PCS_LEAF_HASH_CONTEXT_V4,
    PCS_NODE_HASH_CONTEXT_V4, X4B_DEVICE_BYTE_CEILING_V4, X4B_N4_TILE_BYTE_CEILING_V4,
};

const PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const POD_PROFILE: &str = "runpod-a100-x4b-v1";
const DESIGN_SHA256: &str = "bc057e458041e8123e3ef065d22b74573bcb7238a8dcee239bccfa0e8ff6be01";
const MIGRATION_PATH: &str = "benchmarks/results/x4-v4-gpt2-migration-2026-07-21-31fc866.json";
const MIGRATION_SHA256: &str = "d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e";
const PREFLIGHT_PATH: &str =
    "benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json";
const PREFLIGHT_SHA256: &str = "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499";
const LOCAL_PREFLIGHT_PATH: &str =
    "benchmarks/results/x4b-local-cpu-preflight-2026-07-22-bcbda45.json";
const LOCAL_PREFLIGHT_SHA256: &str =
    "bf391aa2045a426c67ff46d53215d6fd0d57847b5d4fdd42365740c43400447c";

const QUERY_COUNT: usize = 111;
const PCS_BYTES: u64 = 2_683_236;
const PACKED_OPENING_BYTES: u64 = 2_615_414;
const RESPONSE_BYTES: u64 = 43_953_700;
const OPENED_SYMBOLS: u64 = 27_564;
const REAL_SIBLING_DIGESTS: u64 = 67_930;
const SOUNDNESS_BITS: f64 = 80.255_370_163_990_41;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const CPU_GATE_BPS: f64 = 500_000_000.0;
const COMMIT_CEILING_S: f64 = 15.0;
const OPEN_CEILING_S: f64 = 1.50;
const VERIFY_CEILING_S: f64 = 0.25;
const COEFFICIENT_BYTES: u64 = 9_618_587_648;
const ORACLE_BYTES: u64 = 76_948_701_184;
const ROOT_BYTES: u64 = 160;
const DURABLE_BYTES: u64 = 86_567_288_992;
const FULL_INITIAL_CACHE_BYTES: u64 = 37_094_424_416;
const DEGRADED_INITIAL_CACHE_BYTES: u64 = 18_547_212_128;
const FULL_FOLD_CACHE_BYTES: u64 = 34_359_737_248;
const DEGRADED_FOLD_CACHE_BYTES: u64 = 17_179_868_192;
const MIN_VOLUME_BYTES: u64 = 150_000_000_000;
const BASELINE_RAM_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const DEGRADED_RAM_FLOOR_BYTES: u64 = 120 * 1024 * 1024 * 1024;
const GLOBAL_COHORT_ID: u32 = 0xA500_F001;
const MODEL_CONFIG_DIGEST: [u8; 32] = [0xC1; 32];
const MODEL_ROOT: [u8; 32] = [0xD2; 32];
const QUERY_TAPE_BLAKE3: &str = "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299";

type PersistedSource = PersistedModelGlobalCohortV4<DenseOuterNodeCacheV4>;

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

fn sha256(path: &Path) -> String {
    Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|line| line.split_whitespace().next().map(str::to_owned))
        })
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

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
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

fn proc_status_bytes(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let rest = line.strip_prefix(field)?;
                rest.split_whitespace().next()?.parse::<u64>().ok()
            })
        })
        .unwrap_or(0)
        * 1024
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct IoSnapshot {
    rchar: u64,
    wchar: u64,
    read_bytes: u64,
    write_bytes: u64,
}

impl IoSnapshot {
    fn current() -> Self {
        let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
        let read = |field: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(field)?.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        Self {
            rchar: read("rchar:"),
            wchar: read("wchar:"),
            read_bytes: read("read_bytes:"),
            write_bytes: read("write_bytes:"),
        }
    }

    fn delta(self, before: Self) -> Self {
        Self {
            rchar: self.rchar.saturating_sub(before.rchar),
            wchar: self.wchar.saturating_sub(before.wchar),
            read_bytes: self.read_bytes.saturating_sub(before.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(before.write_bytes),
        }
    }
}

struct RssSampler {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    handle: thread::JoinHandle<()>,
}

impl RssSampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(proc_status_bytes("VmRSS:")));
        let thread_stop = Arc::clone(&stop);
        let thread_peak = Arc::clone(&peak);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                thread_peak.fetch_max(proc_status_bytes("VmRSS:"), Ordering::Relaxed);
                thread::sleep(Duration::from_millis(25));
            }
            thread_peak.fetch_max(proc_status_bytes("VmRSS:"), Ordering::Relaxed);
        });
        Self { stop, peak, handle }
    }

    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("RSS sampler");
        self.peak.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Serialize)]
struct AcceleratorOperationRow {
    calls: u64,
    cpu_residual_s: f64,
}

#[derive(Clone, Serialize)]
struct AcceleratorRow {
    timing_method: String,
    phase_attribution_available: bool,
    measurement_wall_s: f64,
    operations: std::collections::BTreeMap<String, AcceleratorOperationRow>,
    h2d_bytes: u64,
    d2h_bytes: u64,
    explicit_d2d_copy_bytes: u64,
    device_zeroed_bytes: u64,
    device_generated_bytes: u64,
    synchronizations: u64,
    synchronization_s: f64,
    sync_host_output: u64,
    sync_upload_lifetime: u64,
    sync_timing_flush: u64,
    sync_profiling_legacy: u64,
    sync_allocator_flush: u64,
    allocation_calls: u64,
    physical_free_calls: u64,
    live_device_bytes: u64,
    peak_device_bytes: u64,
    timing_event_api_calls: u64,
    timing_records: u64,
}

impl AcceleratorRow {
    fn from_stats(stats: BackendStats) -> Self {
        assert_eq!(stats.timing_mode, DeviceTimingMode::WallOnlyCounters);
        assert_eq!(stats.timing_event_api_calls, 0);
        assert_eq!(stats.timing_records, 0);
        assert_eq!(stats.timing_elapsed_query_attempts, 0);
        assert_eq!(stats.h2d_ns, 0);
        assert_eq!(stats.d2h_ns, 0);
        assert_eq!(stats.kernel_ns(), 0);
        let operations = Operation::ALL
            .into_iter()
            .map(|operation| {
                let row = stats.operation(operation);
                (
                    operation.name().to_owned(),
                    AcceleratorOperationRow {
                        calls: row.calls,
                        cpu_residual_s: row.cpu_residual_ns as f64 / 1e9,
                    },
                )
            })
            .collect();
        Self {
            timing_method: stats.timing_mode.name().to_owned(),
            phase_attribution_available: stats.timing_mode.phase_attribution_available(),
            measurement_wall_s: stats.measurement_wall_ns as f64 / 1e9,
            operations,
            h2d_bytes: stats.h2d_bytes,
            d2h_bytes: stats.d2h_bytes,
            explicit_d2d_copy_bytes: stats.explicit_d2d_copy_bytes,
            device_zeroed_bytes: stats.device_zeroed_bytes,
            device_generated_bytes: stats.device_generated_bytes,
            synchronizations: stats.synchronizations,
            synchronization_s: stats.synchronization_ns as f64 / 1e9,
            sync_host_output: stats.sync_host_output,
            sync_upload_lifetime: stats.sync_upload_lifetime,
            sync_timing_flush: stats.sync_timing_flush,
            sync_profiling_legacy: stats.sync_profiling_legacy,
            sync_allocator_flush: stats.sync_allocator_flush,
            allocation_calls: stats.allocation_calls,
            physical_free_calls: stats.physical_free_calls,
            live_device_bytes: stats.live_device_bytes,
            peak_device_bytes: stats.peak_device_bytes,
            timing_event_api_calls: stats.timing_event_api_calls,
            timing_records: stats.timing_records,
        }
    }
}

#[derive(Clone, Debug)]
struct CohortSpec {
    name: &'static str,
    config: CohortVerifierConfigV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
}

fn descriptor(cohort_id: u32, slot: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[..4].copy_from_slice(&cohort_id.to_le_bytes());
    value[4..12].copy_from_slice(&(slot as u64).to_le_bytes());
    value[12..].fill((slot as u8).wrapping_mul(37).wrapping_add(11));
    value
}

fn fixture_value(cohort_id: u32, slot: usize, ordinal: usize) -> Fp2 {
    let seed = u64::from(cohort_id)
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add((slot as u64 + 1) * 0x1_0001)
        .wrapping_add((ordinal as u64 + 1) * 0x101);
    Fp2::new(Fp::new(seed), Fp::new(seed.wrapping_mul(17).wrapping_add(3)))
}

fn nonzero_positions(coefficient_len: usize) -> Vec<usize> {
    [0, 1.min(coefficient_len - 1), coefficient_len / 2, coefficient_len - 1]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn build_spec(
    name: &'static str,
    cohort_id: u32,
    kind: OracleKindV4,
    domain_log2: u8,
    present: usize,
    structural: usize,
) -> CohortSpec {
    let outer_len = 1usize << domain_log2;
    let config = CohortVerifierConfigV4 {
        identity: CohortIdentityV4 { cohort_id, oracle_kind: kind, fold_round: 0 },
        slot_descriptors: (0..structural)
            .map(|slot| (slot < present).then(|| descriptor(cohort_id, slot)))
            .collect(),
        outer_len,
        expected_symbol_count: 1,
    };
    let coefficient_len = outer_len / 8;
    let positions = nonzero_positions(coefficient_len);
    let coefficients = (0..structural)
        .map(|slot| {
            (slot < present).then(|| {
                let mut values = vec![Fp2::ZERO; coefficient_len];
                for (ordinal, position) in positions.iter().enumerate() {
                    values[*position] = fixture_value(cohort_id, slot, ordinal);
                }
                values
            })
        })
        .collect();
    CohortSpec { name, config, coefficients }
}

fn gpt2_specs() -> Vec<CohortSpec> {
    vec![
        build_spec(
            "Wext-mu26-global-tied-roles",
            0xA500_0001,
            OracleKindV4::WeightExtension,
            30,
            2,
            2,
        ),
        build_spec("Wext-mu22-all-layers", 0xA500_0002, OracleKindV4::WeightExtension, 26, 36, 64),
        build_spec(
            "Wext-mu20-layers-and-position",
            0xA500_0003,
            OracleKindV4::WeightExtension,
            24,
            13,
            16,
        ),
        build_spec("auxiliary-ell17", 0xA500_0100, OracleKindV4::Auxiliary, 20, 2, 2),
        build_spec("auxiliary-ell16", 0xA500_0101, OracleKindV4::Auxiliary, 19, 49, 64),
    ]
}

#[derive(Clone, Default, Serialize)]
struct CommitMetricsRow {
    present_slots: u64,
    structural_slots: u64,
    coefficient_bytes_read: u64,
    coefficient_bytes_persisted: u64,
    oracle_bytes_persisted: u64,
    root_bytes_persisted: u64,
    persisted_oracle_bytes_read_for_n4: u64,
    staging_bytes_read: u64,
    staging_bytes_written: u64,
    peak_live_staging_bytes: u64,
    retained_outer_cache_bytes: u64,
    expected_h2d_bytes: u64,
    expected_d2h_bytes: u64,
    expected_device_zeroed_bytes: u64,
    maximum_n4_tile_bytes: u64,
    ntt_calls: u64,
    inner_tile_calls: u64,
    outer_tile_calls: u64,
    page_cache_dontneed_bytes: u64,
    page_cache_advice_calls: u64,
    persistent_artifact_bytes: u64,
}

impl CommitMetricsRow {
    fn from_metrics(metrics: &X4bCudaCommitMetricsV4) -> Self {
        Self {
            present_slots: metrics.present_slots,
            structural_slots: metrics.structural_slots,
            coefficient_bytes_read: metrics.coefficient_bytes_read,
            coefficient_bytes_persisted: metrics.coefficient_bytes_persisted,
            oracle_bytes_persisted: metrics.oracle_bytes_persisted,
            root_bytes_persisted: metrics.root_bytes_persisted,
            persisted_oracle_bytes_read_for_n4: metrics.persisted_oracle_bytes_read_for_n4,
            staging_bytes_read: metrics.staging_bytes_read,
            staging_bytes_written: metrics.staging_bytes_written,
            peak_live_staging_bytes: metrics.peak_live_staging_bytes,
            retained_outer_cache_bytes: metrics.retained_outer_cache_bytes,
            expected_h2d_bytes: metrics.expected_h2d_bytes,
            expected_d2h_bytes: metrics.expected_d2h_bytes,
            expected_device_zeroed_bytes: metrics.expected_device_zeroed_bytes,
            maximum_n4_tile_bytes: metrics.maximum_n4_tile_bytes,
            ntt_calls: metrics.ntt_calls,
            inner_tile_calls: metrics.inner_tile_calls,
            outer_tile_calls: metrics.outer_tile_calls,
            page_cache_dontneed_bytes: metrics.page_cache_dontneed_bytes,
            page_cache_advice_calls: metrics.page_cache_advice_calls,
            persistent_artifact_bytes: metrics.persistent_artifact_bytes().unwrap(),
        }
    }
}

#[derive(Clone, Serialize)]
struct CohortCommitRow {
    name: String,
    cohort_id: u32,
    domain_log2: u8,
    present_slots: usize,
    structural_slots: usize,
    wall_s: f64,
    root_hex: String,
    metrics: CommitMetricsRow,
}

#[derive(Clone, Serialize)]
struct InitialPassRow {
    role: String,
    wall_s: f64,
    peak_rss_bytes: u64,
    process_io: IoSnapshot,
    accelerator: AcceleratorRow,
    cohorts: Vec<CohortCommitRow>,
    totals: CommitMetricsRow,
    reconciliation_pass: bool,
    artifacts_retained: bool,
}

struct InitialPassOutcome {
    row: InitialPassRow,
    artifacts: Vec<X4bCudaCohortArtifactsV4>,
    directory: PathBuf,
}

fn pass_paths(directory: &Path, cohort_id: u32) -> X4bCudaCohortPathsV4 {
    let cohort = directory.join(format!("cohort-{cohort_id:08x}"));
    fs::create_dir(&cohort).expect("create X4b cohort artifact directory");
    X4bCudaCohortPathsV4 {
        coefficients: cohort.join("coefficients.bin"),
        oracle: cohort.join("oracle.bin"),
        root: cohort.join("root.bin"),
        staging_directory: cohort.join("staging"),
    }
}

fn run_initial_pass(
    role: &str,
    backend: &mut Backend,
    specs: &[CohortSpec],
    directory: PathBuf,
    cache_policy: OuterCachePolicyV4,
) -> InitialPassOutcome {
    fs::create_dir(&directory).expect("create X4b pass directory");
    let before_io = IoSnapshot::current();
    let rss = RssSampler::start();
    backend.begin_measurement().expect("begin X4b initial-pass counters");
    let started = Instant::now();
    let mut artifacts = Vec::with_capacity(specs.len());
    let mut cohort_rows = Vec::with_capacity(specs.len());
    let mut totals = X4bCudaCommitMetricsV4::default();
    for spec in specs {
        let paths = pass_paths(&directory, spec.config.identity.cohort_id);
        let cohort_started = Instant::now();
        let artifact = commit_cohort_cuda_v4(
            backend,
            spec.config.clone(),
            &spec.coefficients,
            paths,
            cache_policy,
        )
        .expect("complete exact X4b CUDA cohort commit");
        let cohort_wall = cohort_started.elapsed().as_secs_f64();
        totals.include(&artifact.metrics).unwrap();
        cohort_rows.push(CohortCommitRow {
            name: spec.name.to_owned(),
            cohort_id: spec.config.identity.cohort_id,
            domain_log2: spec.config.outer_depth(),
            present_slots: spec.config.slot_descriptors.iter().flatten().count(),
            structural_slots: spec.config.slot_descriptors.len(),
            wall_s: cohort_wall,
            root_hex: hex(&artifact.commitment.root),
            metrics: CommitMetricsRow::from_metrics(&artifact.metrics),
        });
        artifacts.push(artifact);
    }
    let wall_s = started.elapsed().as_secs_f64();
    let stats = backend.finish_measurement().expect("finish X4b initial-pass counters");
    let peak_rss_bytes = rss.finish();
    let process_io = IoSnapshot::current().delta(before_io);
    let accelerator = AcceleratorRow::from_stats(stats);
    let expected_host_writes = totals
        .persistent_artifact_bytes()
        .unwrap()
        .checked_add(totals.staging_bytes_written)
        .unwrap();
    let expected_host_reads =
        totals.persisted_oracle_bytes_read_for_n4.checked_add(totals.staging_bytes_read).unwrap();
    let reconciliation_pass = totals.coefficient_bytes_persisted == COEFFICIENT_BYTES
        && totals.oracle_bytes_persisted == ORACLE_BYTES
        && totals.root_bytes_persisted == ROOT_BYTES
        && totals.persistent_artifact_bytes().unwrap() == DURABLE_BYTES
        && totals.persisted_oracle_bytes_read_for_n4 == ORACLE_BYTES
        && totals.maximum_n4_tile_bytes <= X4B_N4_TILE_BYTE_CEILING_V4
        && totals.page_cache_dontneed_bytes
            == totals.persistent_artifact_bytes().unwrap()
                + totals.staging_bytes_written
                + totals.persisted_oracle_bytes_read_for_n4
        && process_io.wchar >= expected_host_writes
        && process_io.rchar >= expected_host_reads
        && accelerator.h2d_bytes == totals.expected_h2d_bytes
        && accelerator.d2h_bytes == totals.expected_d2h_bytes
        && accelerator.device_zeroed_bytes == totals.expected_device_zeroed_bytes
        && accelerator.peak_device_bytes <= X4B_DEVICE_BYTE_CEILING_V4
        && accelerator.timing_event_api_calls == 0;
    InitialPassOutcome {
        row: InitialPassRow {
            role: role.to_owned(),
            wall_s,
            peak_rss_bytes,
            process_io,
            accelerator,
            cohorts: cohort_rows,
            totals: CommitMetricsRow::from_metrics(&totals),
            reconciliation_pass,
            artifacts_retained: true,
        },
        artifacts,
        directory,
    }
}

fn cleanup_pass(mut outcome: InitialPassOutcome) -> InitialPassRow {
    let paths = outcome.artifacts.iter().map(|artifact| artifact.paths.clone()).collect::<Vec<_>>();
    outcome.artifacts.clear();
    for paths in paths {
        for path in [&paths.coefficients, &paths.oracle, &paths.root] {
            fs::remove_file(path).expect("remove non-retained X4b artifact");
        }
        fs::remove_dir(&paths.staging_directory).expect("remove empty X4b staging directory");
        fs::remove_dir(paths.coefficients.parent().unwrap())
            .expect("remove empty X4b cohort directory");
    }
    fs::remove_dir(&outcome.directory).expect("remove empty X4b pass directory");
    outcome.row.artifacts_retained = false;
    outcome.row
}

fn assert_root_vector(expected: &[String], candidate: &InitialPassRow) {
    let observed = candidate.cohorts.iter().map(|row| row.root_hex.clone()).collect::<Vec<_>>();
    assert_eq!(observed, expected, "X4b initial roots changed across candidates");
}

fn codewords_from_coefficients(spec: &CohortSpec) -> Vec<Option<Vec<Fp2>>> {
    spec.coefficients
        .iter()
        .map(|values| values.as_ref().map(|values| encode_rate_eighth(values).unwrap()))
        .collect()
}

fn cpu_root(spec: &CohortSpec) -> [u8; 32] {
    CohortTreeV4::build_flat(spec.config.clone(), codewords_from_coefficients(spec))
        .expect("CPU reference cohort")
        .root()
}

fn present_rank(config: &CohortVerifierConfigV4, slot: usize) -> Option<usize> {
    if config.slot_descriptors.get(slot)?.is_none() {
        return None;
    }
    Some(config.slot_descriptors[..slot].iter().flatten().count())
}

fn read_symbol_at(
    path: &Path,
    config: &CohortVerifierConfigV4,
    slot: usize,
    coordinate: usize,
) -> Fp2 {
    let rank = present_rank(config, slot).expect("read present X4b slot");
    let symbol_index = rank * config.outer_len + coordinate;
    let mut encoded = [0u8; 16];
    let file = OpenOptions::new().read(true).open(path).unwrap();
    file.read_exact_at(&mut encoded, (symbol_index as u64) * 16).unwrap();
    let c0 = u64::from_le_bytes(encoded[..8].try_into().unwrap());
    let c1 = u64::from_le_bytes(encoded[8..].try_into().unwrap());
    assert!(c0 < P && c1 < P);
    Fp2::new(Fp::new(c0), Fp::new(c1))
}

fn expected_sparse_ntt_symbol(spec: &CohortSpec, slot: usize, coordinate: usize) -> Fp2 {
    let root = root_of_unity(u32::from(spec.config.outer_depth())).unwrap();
    let values = spec.coefficients[slot].as_ref().unwrap();
    nonzero_positions(values.len()).into_iter().fold(Fp2::ZERO, |sum, index| {
        sum + values[index] * fp2_pow(root, (coordinate as u128) * (index as u128))
    })
}

fn cpu_outer_leaf_from_oracle(
    path: &Path,
    config: &CohortVerifierConfigV4,
    coordinate: usize,
) -> [u8; 32] {
    let mut current = config
        .slot_descriptors
        .iter()
        .enumerate()
        .map(|(slot, descriptor)| {
            hash_pcs_inner_leaf_fields_v4(
                config.identity.cohort_id,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate as u64,
                descriptor.unwrap_or([0; 32]),
                slot as u16,
                descriptor.map(|_| read_symbol_at(path, config, slot, coordinate)),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut width = current.len();
    let mut level = 1u8;
    while width > 1 {
        for node in 0..width / 2 {
            current[node] = hash_pcs_node_fields_v4(
                config.identity.cohort_id,
                TreeRole::Inner,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate as u64,
                level,
                node as u64,
                current[2 * node],
                current[2 * node + 1],
            )
            .unwrap();
        }
        width /= 2;
        level += 1;
    }
    hash_pcs_outer_leaf_fields_v4(
        config.identity.cohort_id,
        config.identity.oracle_kind,
        config.identity.fold_round,
        coordinate as u64,
        current[0],
    )
    .unwrap()
}

fn cpu_outer_digest(
    path: &Path,
    config: &CohortVerifierConfigV4,
    cache: &DenseOuterNodeCacheV4,
    policy: OuterCachePolicyV4,
    level: u8,
    index: u64,
) -> [u8; 32] {
    if level == 0 {
        return cpu_outer_leaf_from_oracle(path, config, index as usize);
    }
    if level > policy.bottom_levels_omitted {
        return cache.read_cached_digest(level, index).unwrap();
    }
    let left = cpu_outer_digest(path, config, cache, policy, level - 1, 2 * index);
    let right = cpu_outer_digest(path, config, cache, policy, level - 1, 2 * index + 1);
    hash_pcs_node_fields_v4(
        config.identity.cohort_id,
        TreeRole::Outer,
        config.identity.oracle_kind,
        config.identity.fold_round,
        u64::MAX,
        level,
        index,
        left,
        right,
    )
    .unwrap()
}

#[derive(Clone, Serialize)]
struct SyntheticEqualityRow {
    structural_slots: usize,
    present_slots: usize,
    oracle_kind: String,
    fold_round: u8,
    root_hex: String,
    equal: bool,
}

#[derive(Clone, Serialize)]
struct ContextEqualityRow {
    context: String,
    digest_hex: String,
    equal: bool,
}

#[derive(Clone, Serialize)]
struct LargeSampleRow {
    cohort: String,
    ntt_symbols_checked: u64,
    typed_inner_leaves_checked: u64,
    typed_inner_nodes_checked: u64,
    typed_inner_roots_checked: u64,
    typed_outer_leaves_checked: u64,
    outer_levels_checked: u64,
    all_equal: bool,
}

#[derive(Clone, Serialize)]
struct CorrectnessRecord {
    synthetic_preflight_before_full_pass: bool,
    contexts: Vec<ContextEqualityRow>,
    synthetic: Vec<SyntheticEqualityRow>,
    complete_aux_roots: Vec<LargeSampleRow>,
    larger_cohort_samples: Vec<LargeSampleRow>,
    all_equal: bool,
}

/// Exercise the GPU derive-key compressor on every typed digest along one
/// complete inner path.  The production tile API returns only outer leaves,
/// so this bring-up probe prevents a matching outer digest from obscuring
/// which N4 layer was actually cross-checked in the record.
fn compare_typed_inner_sample(
    backend: &mut Backend,
    spec: &CohortSpec,
    oracle_path: &Path,
    coordinate: usize,
) -> (u64, u64, u64, [u8; 32], bool) {
    let config = &spec.config;
    let mut equal = true;
    let mut current = Vec::with_capacity(config.slot_descriptors.len());
    let mut leaf_count = 0u64;
    for (slot, descriptor) in config.slot_descriptors.iter().enumerate() {
        let symbol = descriptor.map(|_| read_symbol_at(oracle_path, config, slot, coordinate));
        let frame = PcsLeafFrameV4 {
            cohort_id: config.identity.cohort_id,
            tree_role: TreeRole::Inner,
            oracle_kind: config.identity.oracle_kind,
            fold_round: config.identity.fold_round,
            outer_index: coordinate as u64,
            payload: PcsLeafPayloadV4::Inner {
                descriptor_digest: descriptor.unwrap_or([0; 32]),
                slot: slot as u16,
                present: symbol.is_some(),
                symbols: symbol.into_iter().collect(),
            },
        };
        let encoded = FrameV4::PcsLeaf(frame).encode().unwrap();
        let observed = backend.x4b_context_probe(&encoded).unwrap()[0];
        let expected = hash_pcs_inner_leaf_fields_v4(
            config.identity.cohort_id,
            config.identity.oracle_kind,
            config.identity.fold_round,
            coordinate as u64,
            descriptor.unwrap_or([0; 32]),
            slot as u16,
            symbol,
        )
        .unwrap();
        equal &= observed == expected;
        current.push(expected);
        leaf_count += 1;
    }

    let mut width = current.len();
    let mut level = 1u8;
    let mut node_count = 0u64;
    while width > 1 {
        for node in 0..width / 2 {
            let frame = PcsNodeFrameV4 {
                cohort_id: config.identity.cohort_id,
                tree_role: TreeRole::Inner,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index: coordinate as u64,
                level,
                node_index: node as u64,
                left_digest: current[2 * node],
                right_digest: current[2 * node + 1],
            };
            let encoded = FrameV4::PcsNode(frame).encode().unwrap();
            let observed = backend.x4b_context_probe(&encoded).unwrap()[1];
            let expected = hash_pcs_node_fields_v4(
                config.identity.cohort_id,
                TreeRole::Inner,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate as u64,
                level,
                node as u64,
                current[2 * node],
                current[2 * node + 1],
            )
            .unwrap();
            equal &= observed == expected;
            current[node] = expected;
            node_count += 1;
        }
        width /= 2;
        level += 1;
    }
    let inner_root = current[0];
    let outer_frame = PcsLeafFrameV4 {
        cohort_id: config.identity.cohort_id,
        tree_role: TreeRole::Outer,
        oracle_kind: config.identity.oracle_kind,
        fold_round: config.identity.fold_round,
        outer_index: coordinate as u64,
        payload: PcsLeafPayloadV4::Outer { inner_root_digest: inner_root },
    };
    let encoded = FrameV4::PcsLeaf(outer_frame).encode().unwrap();
    let observed_outer = backend.x4b_context_probe(&encoded).unwrap()[0];
    let expected_outer = hash_pcs_outer_leaf_fields_v4(
        config.identity.cohort_id,
        config.identity.oracle_kind,
        config.identity.fold_round,
        coordinate as u64,
        inner_root,
    )
    .unwrap();
    equal &= observed_outer == expected_outer;
    (leaf_count, node_count, 1, expected_outer, equal)
}

fn synthetic_correctness(
    backend: &mut Backend,
    directory: &Path,
) -> (Vec<ContextEqualityRow>, Vec<SyntheticEqualityRow>) {
    fs::create_dir(directory).unwrap();
    let payload = (0..104u8).map(|value| value.wrapping_mul(37)).collect::<Vec<_>>();
    let observed = backend.x4b_context_probe(&payload).unwrap();
    let contexts = [
        PCS_LEAF_HASH_CONTEXT_V4,
        PCS_NODE_HASH_CONTEXT_V4,
        MANIFEST_LEAF_HASH_CONTEXT_V4,
        MANIFEST_NODE_HASH_CONTEXT_V4,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, context)| {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(&payload);
        let expected = *hasher.finalize().as_bytes();
        ContextEqualityRow {
            context: context.to_owned(),
            digest_hex: hex(&observed[index]),
            equal: observed[index] == expected,
        }
    })
    .collect::<Vec<_>>();

    let mut roots = Vec::new();
    for (case, structural, present, kind, round) in [
        (0u32, 1usize, 1usize, OracleKindV4::WeightExtension, 0u8),
        (1, 2, 1, OracleKindV4::Auxiliary, 0),
        (2, 16, 13, OracleKindV4::WeightExtension, 0),
        (3, 64, 49, OracleKindV4::Auxiliary, 0),
        (4, 1, 1, OracleKindV4::GlobalFoldAggregate, 3),
    ] {
        let cohort_id = 0xB400_0000 + case;
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 { cohort_id, oracle_kind: kind, fold_round: round },
            slot_descriptors: (0..structural)
                .map(|slot| (slot < present).then(|| descriptor(cohort_id, slot)))
                .collect(),
            outer_len: 32,
            expected_symbol_count: 1,
        };
        let coefficients = (0..structural)
            .map(|slot| {
                (slot < present).then(|| {
                    (0..4).map(|index| fixture_value(cohort_id, slot, index)).collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let codewords = coefficients
            .iter()
            .map(|values| values.as_ref().map(|values| encode_rate_eighth(values).unwrap()))
            .collect::<Vec<_>>();
        let cpu = CohortTreeV4::build_flat(config.clone(), codewords).unwrap();
        let case_directory = directory.join(format!("case-{case}"));
        fs::create_dir(&case_directory).unwrap();
        let artifact = commit_cohort_cuda_v4(
            backend,
            config,
            &coefficients,
            X4bCudaCohortPathsV4 {
                coefficients: case_directory.join("coefficients.bin"),
                oracle: case_directory.join("oracle.bin"),
                root: case_directory.join("root.bin"),
                staging_directory: case_directory.join("staging"),
            },
            OuterCachePolicyV4::FULL,
        )
        .unwrap();
        let equal = artifact.commitment.root == cpu.root();
        roots.push(SyntheticEqualityRow {
            structural_slots: structural,
            present_slots: present,
            oracle_kind: format!("{:?}", kind),
            fold_round: round,
            root_hex: hex(&artifact.commitment.root),
            equal,
        });
        let paths = artifact.paths.clone();
        drop(artifact);
        for path in [&paths.coefficients, &paths.oracle, &paths.root] {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(paths.staging_directory).unwrap();
        fs::remove_dir(case_directory).unwrap();
    }
    fs::remove_dir(directory).unwrap();
    (contexts, roots)
}

fn compare_warmup_artifact(
    backend: &mut Backend,
    spec: &CohortSpec,
    artifact: &X4bCudaCohortArtifactsV4,
    policy: OuterCachePolicyV4,
    complete_cpu_root: bool,
) -> LargeSampleRow {
    let mut all_equal = true;
    if complete_cpu_root {
        all_equal &= cpu_root(spec) == artifact.commitment.root;
    }
    let coordinates = [0usize, 1, spec.config.outer_len / 3, spec.config.outer_len - 1];
    let mut ntt_checked = 0u64;
    for slot in 0..spec.config.slot_descriptors.len() {
        if spec.config.slot_descriptors[slot].is_none() {
            continue;
        }
        for coordinate in coordinates {
            all_equal &= read_symbol_at(&artifact.paths.oracle, &spec.config, slot, coordinate)
                == expected_sparse_ntt_symbol(spec, slot, coordinate);
            ntt_checked += 1;
        }
    }

    let tile_start = (spec.config.outer_len / 3) & !7usize;
    let (typed_inner_leaves, typed_inner_nodes, typed_inner_roots, sampled_outer, typed_equal) =
        compare_typed_inner_sample(backend, spec, &artifact.paths.oracle, tile_start);
    all_equal &= typed_equal;
    let present = spec.config.slot_descriptors.iter().flatten().count();
    let mut symbols = Vec::with_capacity(present * 8);
    for slot in 0..spec.config.slot_descriptors.len() {
        if spec.config.slot_descriptors[slot].is_some() {
            for coordinate in tile_start..tile_start + 8 {
                symbols.push(read_symbol_at(
                    &artifact.paths.oracle,
                    &spec.config,
                    slot,
                    coordinate,
                ));
            }
        }
    }
    let mut rank = 0u16;
    let mut ranks = Vec::with_capacity(spec.config.slot_descriptors.len());
    let mut descriptors = Vec::with_capacity(spec.config.slot_descriptors.len());
    for descriptor in &spec.config.slot_descriptors {
        if let Some(descriptor) = descriptor {
            ranks.push(rank);
            rank += 1;
            descriptors.push(*descriptor);
        } else {
            ranks.push(u16::MAX);
            descriptors.push([0; 32]);
        }
    }
    let gpu_leaves = backend
        .x4b_n4_inner_tile(
            &symbols,
            8,
            &ranks,
            &descriptors,
            tile_start as u64,
            spec.config.identity.cohort_id,
            spec.config.identity.oracle_kind as u8,
            spec.config.identity.fold_round,
        )
        .unwrap();
    for (offset, observed) in gpu_leaves.iter().enumerate() {
        all_equal &= *observed
            == cpu_outer_leaf_from_oracle(
                &artifact.paths.oracle,
                &spec.config,
                tile_start + offset,
            );
    }
    all_equal &= gpu_leaves[0] == sampled_outer;

    let mut levels_checked = 0u64;
    for level in 1..=spec.config.outer_depth() {
        let parent_count = spec.config.outer_len >> level;
        let index =
            ((u64::from(level) * 1_000_003) % parent_count as u64).min(parent_count as u64 - 1);
        let left = cpu_outer_digest(
            &artifact.paths.oracle,
            &spec.config,
            &artifact.outer_cache,
            policy,
            level - 1,
            2 * index,
        );
        let right = cpu_outer_digest(
            &artifact.paths.oracle,
            &spec.config,
            &artifact.outer_cache,
            policy,
            level - 1,
            2 * index + 1,
        );
        let expected = hash_pcs_node_fields_v4(
            spec.config.identity.cohort_id,
            TreeRole::Outer,
            spec.config.identity.oracle_kind,
            spec.config.identity.fold_round,
            u64::MAX,
            level,
            index,
            left,
            right,
        )
        .unwrap();
        let direct_gpu = backend
            .x4b_n4_outer_nodes(
                &[left, right],
                index,
                spec.config.identity.cohort_id,
                spec.config.identity.oracle_kind as u8,
                spec.config.identity.fold_round,
                level,
            )
            .unwrap()[0];
        all_equal &= direct_gpu == expected;
        if level > policy.bottom_levels_omitted {
            all_equal &= artifact.outer_cache.read_cached_digest(level, index).unwrap() == expected;
        }
        levels_checked += 1;
    }
    LargeSampleRow {
        cohort: spec.name.to_owned(),
        ntt_symbols_checked: ntt_checked,
        typed_inner_leaves_checked: typed_inner_leaves,
        typed_inner_nodes_checked: typed_inner_nodes,
        typed_inner_roots_checked: typed_inner_roots,
        typed_outer_leaves_checked: 8,
        outer_levels_checked: levels_checked,
        all_equal,
    }
}

fn selected_query_draws() -> Vec<u64> {
    let bytes = fs::read(repo_root().join(PREFLIGHT_PATH)).expect("read frozen Amendment-5 tape");
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let row = value["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == "e29-r3-s111")
        .expect("frozen selected query row");
    assert_eq!(row["query_count"], QUERY_COUNT);
    let draws = row["challenge"]["ordered_draws"]
        .as_array()
        .unwrap()
        .iter()
        .map(|draw| draw.as_u64().unwrap())
        .collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(4 * draws.len());
    for draw in &draws {
        encoded.extend_from_slice(&u32::try_from(*draw).unwrap().to_le_bytes());
    }
    assert_eq!(blake3::hash(&encoded).to_hex().as_str(), QUERY_TAPE_BLAKE3);
    draws
}

fn local_cpu_preflight() -> Value {
    let executable = std::env::current_exe().unwrap().with_file_name("x4b_cpu_preflight");
    let path =
        std::env::temp_dir().join(format!("x4b-pod-cpu-preflight-{}.json", std::process::id()));
    let status = Command::new(executable)
        .arg(&path)
        .current_dir(repo_root().join("rust"))
        .status()
        .expect("run exact X4b CPU/opening preflight on pod host");
    assert!(status.success() || status.code() == Some(2));
    let value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    fs::remove_file(path).unwrap();
    value
}

#[derive(Clone, Serialize)]
struct Note6Pin {
    path: String,
    sha256: String,
    source_git_sha: String,
    passed: bool,
    first_action: bool,
}

fn validate_note6(path: &Path) -> Note6Pin {
    let bytes = fs::read(path).expect("read fresh X4b NOTE-6 record");
    let value: Value = serde_json::from_slice(&bytes).expect("parse fresh X4b NOTE-6 record");
    let source_git_sha = value["git_sha"].as_str().unwrap_or_default().to_owned();
    let ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &source_git_sha, "HEAD"])
        .current_dir(repo_root())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let passed = value["milestone"] == "X4b-R1b-NOTE-6-preflight"
        && value["pod_profile"] == POD_PROFILE
        && value["protocol_profile"] == PROFILE
        && value["design_sha256"] == DESIGN_SHA256
        && value["test"]["passed"] == true
        && value["test"]["leakage_verdict"] == "PASS"
        && value["preflight_order"]["order_satisfied"] == true
        && value["preflight_order"]["x4b_kernel_or_wall_records_started_before_pass"] == false
        && ancestor;
    Note6Pin {
        path: path.display().to_string(),
        sha256: sha256(path),
        source_git_sha,
        passed,
        first_action: value["preflight_order"]["order_satisfied"] == true,
    }
}

fn df_bytes(path: &Path, field: usize) -> u64 {
    Command::new("df")
        .args(["-B1", "--output=size,avail"])
        .arg(path)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()?
                .lines()
                .nth(1)?
                .split_whitespace()
                .nth(field)?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

#[derive(Clone, Serialize)]
struct Machine {
    provider: String,
    instance_id: String,
    hostname: String,
    gpu: String,
    driver: String,
    cpu: String,
    logical_cpus: String,
    memory_bytes: u64,
    volume_path: String,
    persistent_volume_bytes: u64,
    persistent_volume_available_bytes_at_start: u64,
    rayon_threads: usize,
    cuda_abi: u32,
    timing_policy: String,
}

fn machine(volume: &Path) -> Machine {
    Machine {
        provider: std::env::var("VOLTA_CLOUD_PROVIDER").unwrap_or_else(|_| "RunPod".to_owned()),
        instance_id: std::env::var("VOLTA_CLOUD_INSTANCE_ID")
            .unwrap_or_else(|_| command_output(&["hostname"])),
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
        volume_path: volume.display().to_string(),
        persistent_volume_bytes: df_bytes(volume, 0),
        persistent_volume_available_bytes_at_start: df_bytes(volume, 1),
        rayon_threads: rayon::current_num_threads(),
        cuda_abi: CUDA_ABI_VERSION,
        timing_policy: "wall-only+counters; no CUDA-event timing".to_owned(),
    }
}

#[derive(Clone, Serialize)]
struct IsolatedCommitRow {
    role: String,
    wall_s: f64,
    ceiling_s: f64,
    margin_s: f64,
    margin_percent: f64,
    pass: bool,
    peak_rss_bytes: u64,
    process_io: IoSnapshot,
    accelerator: AcceleratorRow,
    root_hex: String,
    metrics: CommitMetricsRow,
    reconciliation_pass: bool,
}

fn run_isolated_commit(
    role: &str,
    backend: &mut Backend,
    spec: &CohortSpec,
    directory: PathBuf,
    cache_policy: OuterCachePolicyV4,
) -> IsolatedCommitRow {
    fs::create_dir(&directory).unwrap();
    let paths = pass_paths(&directory, spec.config.identity.cohort_id);
    let before_io = IoSnapshot::current();
    let rss = RssSampler::start();
    backend.begin_measurement().unwrap();
    let started = Instant::now();
    let artifact = commit_cohort_cuda_v4(
        backend,
        spec.config.clone(),
        &spec.coefficients,
        paths,
        cache_policy,
    )
    .unwrap();
    let wall_s = started.elapsed().as_secs_f64();
    let accelerator = AcceleratorRow::from_stats(backend.finish_measurement().unwrap());
    let peak_rss_bytes = rss.finish();
    let process_io = IoSnapshot::current().delta(before_io);
    let metrics = &artifact.metrics;
    let expected_coefficients = 2 * (1u64 << 27) * 16;
    let expected_oracle = 2 * (1u64 << 30) * 16;
    let reconciliation_pass = metrics.coefficient_bytes_persisted == expected_coefficients
        && metrics.oracle_bytes_persisted == expected_oracle
        && metrics.persisted_oracle_bytes_read_for_n4 == expected_oracle
        && accelerator.h2d_bytes == metrics.expected_h2d_bytes
        && accelerator.d2h_bytes == metrics.expected_d2h_bytes
        && accelerator.device_zeroed_bytes == metrics.expected_device_zeroed_bytes
        && accelerator.peak_device_bytes <= X4B_DEVICE_BYTE_CEILING_V4
        && metrics.page_cache_dontneed_bytes
            == metrics.persistent_artifact_bytes().unwrap()
                + metrics.staging_bytes_written
                + metrics.persisted_oracle_bytes_read_for_n4
        && process_io.wchar
            >= metrics.persistent_artifact_bytes().unwrap() + metrics.staging_bytes_written
        && process_io.rchar
            >= metrics.persisted_oracle_bytes_read_for_n4 + metrics.staging_bytes_read;
    let root_hex = hex(&artifact.commitment.root);
    let paths = artifact.paths.clone();
    let metric_row = CommitMetricsRow::from_metrics(metrics);
    drop(artifact);
    for path in [&paths.coefficients, &paths.oracle, &paths.root] {
        fs::remove_file(path).unwrap();
    }
    fs::remove_dir(paths.staging_directory).unwrap();
    fs::remove_dir(paths.coefficients.parent().unwrap()).unwrap();
    fs::remove_dir(directory).unwrap();
    let margin_s = COMMIT_CEILING_S - wall_s;
    IsolatedCommitRow {
        role: role.to_owned(),
        wall_s,
        ceiling_s: COMMIT_CEILING_S,
        margin_s,
        margin_percent: 100.0 * margin_s / COMMIT_CEILING_S,
        pass: wall_s <= COMMIT_CEILING_S,
        peak_rss_bytes,
        process_io,
        accelerator,
        root_hex,
        metrics: metric_row,
        reconciliation_pass,
    }
}

#[derive(Clone, Serialize)]
struct FoldMetricsRow {
    source_coefficients_read: u64,
    initial_encoded_symbols_read: u64,
    combined_coefficient_symbols: u64,
    combined_codeword_symbols: u64,
    folded_symbols_written: u64,
    aggregate_merkle_symbols_written: u64,
    aggregate_merkle_digests_written: u64,
    serialized_fold_bytes: u64,
    serialized_packed_opening_bytes: u64,
    recomputed_source_bytes_read: u64,
    recomputed_oracle_bytes: u64,
    recomputed_merkle_bytes: u64,
    persisted_oracle_bytes_read: u64,
    persisted_page_cache_dontneed_bytes: u64,
    persisted_page_cache_advice_calls: u64,
    outer_cache_bytes_read: u64,
    inner_trees_rebuilt: u64,
    outer_frontier_leaves_rebuilt: u64,
    outer_internal_nodes_rebuilt: u64,
    x4b_fold_coefficient_bytes_persisted: u64,
    x4b_fold_oracle_bytes_persisted: u64,
    x4b_fold_root_bytes_persisted: u64,
    x4b_fold_reference_bytes_read: u64,
    x4b_fold_staging_bytes_read: u64,
    x4b_fold_staging_bytes_written: u64,
    x4b_fold_retained_outer_cache_bytes: u64,
    x4b_fold_expected_h2d_bytes: u64,
    x4b_fold_expected_d2h_bytes: u64,
    x4b_fold_expected_device_zeroed_bytes: u64,
    x4b_fold_maximum_n4_tile_bytes: u64,
    x4b_fold_page_cache_dontneed_bytes: u64,
    x4b_fold_page_cache_advice_calls: u64,
}

impl From<&GlobalOpenMetricsV4> for FoldMetricsRow {
    fn from(value: &GlobalOpenMetricsV4) -> Self {
        Self {
            source_coefficients_read: value.source_coefficients_read,
            initial_encoded_symbols_read: value.initial_encoded_symbols_read,
            combined_coefficient_symbols: value.combined_coefficient_symbols,
            combined_codeword_symbols: value.combined_codeword_symbols,
            folded_symbols_written: value.folded_symbols_written,
            aggregate_merkle_symbols_written: value.aggregate_merkle_symbols_written,
            aggregate_merkle_digests_written: value.aggregate_merkle_digests_written,
            serialized_fold_bytes: value.serialized_fold_bytes,
            serialized_packed_opening_bytes: value.serialized_packed_opening_bytes,
            recomputed_source_bytes_read: value.recomputed_source_bytes_read,
            recomputed_oracle_bytes: value.recomputed_oracle_bytes,
            recomputed_merkle_bytes: value.recomputed_merkle_bytes,
            persisted_oracle_bytes_read: value.persisted_oracle_bytes_read,
            persisted_page_cache_dontneed_bytes: value.persisted_page_cache_dontneed_bytes,
            persisted_page_cache_advice_calls: value.persisted_page_cache_advice_calls,
            outer_cache_bytes_read: value.outer_cache_bytes_read,
            inner_trees_rebuilt: value.inner_trees_rebuilt,
            outer_frontier_leaves_rebuilt: value.outer_frontier_leaves_rebuilt,
            outer_internal_nodes_rebuilt: value.outer_internal_nodes_rebuilt,
            x4b_fold_coefficient_bytes_persisted: value.x4b_fold_coefficient_bytes_persisted,
            x4b_fold_oracle_bytes_persisted: value.x4b_fold_oracle_bytes_persisted,
            x4b_fold_root_bytes_persisted: value.x4b_fold_root_bytes_persisted,
            x4b_fold_reference_bytes_read: value.x4b_fold_reference_bytes_read,
            x4b_fold_staging_bytes_read: value.x4b_fold_staging_bytes_read,
            x4b_fold_staging_bytes_written: value.x4b_fold_staging_bytes_written,
            x4b_fold_retained_outer_cache_bytes: value.x4b_fold_retained_outer_cache_bytes,
            x4b_fold_expected_h2d_bytes: value.x4b_fold_expected_h2d_bytes,
            x4b_fold_expected_d2h_bytes: value.x4b_fold_expected_d2h_bytes,
            x4b_fold_expected_device_zeroed_bytes: value.x4b_fold_expected_device_zeroed_bytes,
            x4b_fold_maximum_n4_tile_bytes: value.x4b_fold_maximum_n4_tile_bytes,
            x4b_fold_page_cache_dontneed_bytes: value.x4b_fold_page_cache_dontneed_bytes,
            x4b_fold_page_cache_advice_calls: value.x4b_fold_page_cache_advice_calls,
        }
    }
}

#[derive(Clone, Serialize)]
struct ResponseCandidateRow {
    role: String,
    epoch: u64,
    seal_wall_s: f64,
    open_wall_s: f64,
    verify_wall_s: f64,
    peak_rss_bytes: u64,
    process_io: IoSnapshot,
    accelerator_seal: AcceleratorRow,
    packed_opening_bytes: u64,
    opened_symbols: u64,
    real_sibling_digests: u64,
    accepted: bool,
    metrics: FoldMetricsRow,
    g6_reconciliation_pass: bool,
}

fn common_point() -> Vec<Fp2> {
    (0..27u64).map(|index| Fp2::new(Fp::new(3 + 2 * index), Fp::new(11 + 7 * index))).collect()
}

fn prover_groups<'a>(
    sources: &'a [PersistedSource],
    point: &[Fp2],
) -> Vec<GlobalProverGroupV4<'a>> {
    sources
        .iter()
        .enumerate()
        .map(|(group_index, source)| {
            let config = &source.commitment().config;
            let touched_slots = config
                .slot_descriptors
                .iter()
                .enumerate()
                .filter_map(|(slot, descriptor)| descriptor.map(|_| slot as u16))
                .collect::<Vec<_>>();
            let weights = touched_slots
                .iter()
                .map(|slot| {
                    let base = 101 + group_index as u64 * 131 + u64::from(*slot) * 17;
                    Fp2::new(Fp::new(base), Fp::new(3 * base + 1))
                })
                .collect();
            let dimension = usize::from(config.outer_depth() - 3);
            GlobalProverGroupV4 {
                cohort: source,
                touched_slots,
                weights,
                target_point: point[point.len() - dimension..].to_vec(),
                activation_challenge: Fp2::new(
                    Fp::new(401 + group_index as u64 * 19),
                    Fp::new(809 + group_index as u64 * 23),
                ),
            }
        })
        .collect()
}

fn run_response_candidate(
    role: &str,
    ordinal: usize,
    backend: &mut Backend,
    sources: &[PersistedSource],
    draws: &[u64],
    directory: PathBuf,
    cache_policy: OuterCachePolicyV4,
) -> ResponseCandidateRow {
    fs::create_dir(&directory).unwrap();
    let expected_initial_advice_calls = sources
        .iter()
        .map(|source| source.commitment().config.slot_descriptors.iter().flatten().count() as u64)
        .sum::<u64>();
    let point = common_point();
    let groups = prover_groups(sources, &point);
    let descriptor = global_fold_descriptor_digest_v4(
        &groups
            .iter()
            .map(|group| {
                (
                    group.cohort.commitment().config.identity.cohort_id,
                    group.cohort.commitment().root,
                )
            })
            .collect::<Vec<_>>(),
    );
    let epoch = 0x5842_0000 + ordinal as u64;
    let draft = GlobalChainDraftV4::new_interactive(
        MODEL_ROOT,
        epoch,
        GLOBAL_COHORT_ID,
        descriptor,
        point.clone(),
        groups,
    )
    .unwrap();
    assert!(draft.reject_query_before_seal().is_err());
    let mut transcript = Transcript::new([0x70u8.wrapping_add(ordinal as u8); 32]);
    let before_io = IoSnapshot::current();
    let rss = RssSampler::start();
    backend.begin_measurement().unwrap();
    let seal_started = Instant::now();
    let sealed = draft
        .seal_interactive_x4b_cuda(&mut transcript, backend, &directory, cache_policy)
        .unwrap();
    let seal_wall_s = seal_started.elapsed().as_secs_f64();
    let challenges = sealed.challenges().clone();
    let accelerator_seal = AcceleratorRow::from_stats(backend.finish_measurement().unwrap());

    let open_started = Instant::now();
    let (proof, verifier_groups, metrics) = sealed.issue_queries(draws.to_vec()).unwrap();
    let open_wall_s = open_started.elapsed().as_secs_f64();
    let verify_started = Instant::now();
    let accepted = verify_global_folding_v4(
        MODEL_ROOT,
        epoch,
        &point,
        &verifier_groups,
        &challenges,
        draws,
        &proof,
    )
    .is_ok();
    let verify_wall_s = verify_started.elapsed().as_secs_f64();
    let packed_bytes =
        FrameV4::PackedBatchOpening(proof.packed_opening.clone()).encode().unwrap().len() as u64;
    let components = proof.packed_opening.byte_components().unwrap();
    let siblings = components.initial_inner_siblings
        + components.initial_outer_siblings
        + components.fold_outer_siblings;
    let peak_rss_bytes = rss.finish();
    let process_io = IoSnapshot::current().delta(before_io);
    let fold_persistent_bytes = metrics.x4b_fold_coefficient_bytes_persisted
        + metrics.x4b_fold_oracle_bytes_persisted
        + metrics.x4b_fold_root_bytes_persisted;
    let fold_host_writes = fold_persistent_bytes + metrics.x4b_fold_staging_bytes_written;
    let fold_host_reads = metrics.x4b_fold_oracle_bytes_persisted
        + metrics.x4b_fold_reference_bytes_read
        + metrics.x4b_fold_staging_bytes_read;
    let g6_reconciliation_pass = metrics.recomputed_source_bytes_read == 0
        && metrics.recomputed_oracle_bytes == 0
        && metrics.recomputed_merkle_bytes == 0
        && metrics.persisted_oracle_bytes_read > 0
        && metrics.x4b_fold_reference_bytes_read == metrics.x4b_fold_oracle_bytes_persisted
        && metrics.x4b_fold_maximum_n4_tile_bytes <= X4B_N4_TILE_BYTE_CEILING_V4
        && metrics.x4b_fold_page_cache_dontneed_bytes
            == fold_persistent_bytes
                + metrics.x4b_fold_staging_bytes_written
                + metrics.x4b_fold_oracle_bytes_persisted
        && metrics.persisted_page_cache_dontneed_bytes == metrics.initial_encoded_symbols_read * 16
        && metrics.persisted_page_cache_advice_calls == expected_initial_advice_calls
        && process_io.wchar >= fold_host_writes
        && process_io.rchar >= metrics.persisted_oracle_bytes_read + fold_host_reads
        && accelerator_seal.h2d_bytes == metrics.x4b_fold_expected_h2d_bytes
        && accelerator_seal.d2h_bytes == metrics.x4b_fold_expected_d2h_bytes
        && accelerator_seal.device_zeroed_bytes == metrics.x4b_fold_expected_device_zeroed_bytes
        && accelerator_seal.peak_device_bytes <= X4B_DEVICE_BYTE_CEILING_V4
        && accelerator_seal.timing_event_api_calls == 0;
    let staging = directory.join("n4-staging");
    if staging.exists() {
        fs::remove_dir(staging).unwrap();
    }
    fs::remove_dir(directory).unwrap();
    ResponseCandidateRow {
        role: role.to_owned(),
        epoch,
        seal_wall_s,
        open_wall_s,
        verify_wall_s,
        peak_rss_bytes,
        process_io,
        accelerator_seal,
        packed_opening_bytes: packed_bytes,
        opened_symbols: components.opened_symbols,
        real_sibling_digests: siblings,
        accepted,
        metrics: FoldMetricsRow::from(&metrics),
        g6_reconciliation_pass,
    }
}

#[derive(Clone, Serialize)]
struct ArtifactFootprintRow {
    directory: String,
    coefficient_files: u64,
    oracle_files: u64,
    root_files: u64,
    coefficient_bytes: u64,
    oracle_bytes: u64,
    root_bytes: u64,
    durable_bytes: u64,
    retained_initial_outer_cache_bytes: u64,
    expected_initial_outer_cache_bytes: u64,
    all_lengths_and_bindings_checked: bool,
}

#[derive(Clone, Serialize)]
struct ArtifactLoadRow {
    wall_s: f64,
    peak_rss_bytes: u64,
    process_io: IoSnapshot,
    page_cache_dontneed_bytes: u64,
    page_cache_advice_calls: u64,
    footprint: ArtifactFootprintRow,
}

fn advise_path_dontneed(path: &Path, bytes: u64) {
    assert!(bytes <= i64::MAX as u64);
    unsafe extern "C" {
        fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    }
    const POSIX_FADV_DONTNEED: i32 = 4;
    let file = OpenOptions::new().read(true).open(path).unwrap();
    // SAFETY: `file` remains live for the call and `bytes` was range-checked.
    let status = unsafe { posix_fadvise(file.as_raw_fd(), 0, bytes as i64, POSIX_FADV_DONTNEED) };
    assert_eq!(status, 0, "X4b artifact-load fadvise failed");
}

fn load_final_sources(
    specs: Vec<CohortSpec>,
    outcome: InitialPassOutcome,
    cache_policy: OuterCachePolicyV4,
) -> (InitialPassRow, Vec<PersistedSource>, ArtifactLoadRow) {
    assert_eq!(specs.len(), outcome.artifacts.len());
    let before_io = IoSnapshot::current();
    let rss = RssSampler::start();
    let started = Instant::now();
    let mut coefficient_bytes = 0u64;
    let mut oracle_bytes = 0u64;
    let mut root_bytes = 0u64;
    let mut retained_initial_outer_cache_bytes = 0u64;
    let mut page_cache_dontneed_bytes = 0u64;
    let mut page_cache_advice_calls = 0u64;
    let mut sources = Vec::with_capacity(specs.len());
    for (spec, artifact) in specs.into_iter().zip(outcome.artifacts) {
        let CohortSpec { name: _, config, coefficients } = spec;
        let X4bCudaCohortArtifactsV4 { commitment, outer_cache, paths, metrics: _ } = artifact;
        assert_eq!(commitment.config, config);
        assert_eq!(commitment.root, outer_cache.root());
        coefficient_bytes += fs::metadata(&paths.coefficients).unwrap().len();
        oracle_bytes += fs::metadata(&paths.oracle).unwrap().len();
        root_bytes += fs::metadata(&paths.root).unwrap().len();
        retained_initial_outer_cache_bytes += outer_cache.retained_bytes().unwrap();
        let encoded_root = fs::read(&paths.root).unwrap();
        assert_eq!(encoded_root.as_slice(), commitment.root);
        advise_path_dontneed(&paths.root, 32);
        page_cache_dontneed_bytes += 32;
        page_cache_advice_calls += 1;

        // The durable coefficient file, rather than the pre-commit fixture,
        // is the production source of truth after materialization.
        drop(coefficients);
        let persisted_coefficients =
            read_persisted_coefficients_v4(&paths.coefficients, &config).unwrap();
        let cohort_coefficient_bytes = fs::metadata(&paths.coefficients).unwrap().len();
        advise_path_dontneed(&paths.coefficients, cohort_coefficient_bytes);
        page_cache_dontneed_bytes += cohort_coefficient_bytes;
        page_cache_advice_calls += 1;
        let binding =
            PersistedOracleBindingV4::new(MODEL_CONFIG_DIGEST, MODEL_ROOT, commitment.root);
        sources.push(
            PersistedModelGlobalCohortV4::load(
                &paths.oracle,
                config,
                persisted_coefficients,
                outer_cache,
                binding,
                binding,
            )
            .unwrap(),
        );
    }
    let expected_cache = if cache_policy == OuterCachePolicyV4::FULL {
        FULL_INITIAL_CACHE_BYTES
    } else {
        DEGRADED_INITIAL_CACHE_BYTES
    };
    let durable_bytes = coefficient_bytes + oracle_bytes + root_bytes;
    let checked = coefficient_bytes == COEFFICIENT_BYTES
        && oracle_bytes == ORACLE_BYTES
        && root_bytes == ROOT_BYTES
        && durable_bytes == DURABLE_BYTES
        && retained_initial_outer_cache_bytes == expected_cache;
    assert!(checked, "X4b final durable artifact inventory changed");
    let load = ArtifactLoadRow {
        wall_s: started.elapsed().as_secs_f64(),
        peak_rss_bytes: rss.finish(),
        process_io: IoSnapshot::current().delta(before_io),
        page_cache_dontneed_bytes,
        page_cache_advice_calls,
        footprint: ArtifactFootprintRow {
            directory: outcome.directory.display().to_string(),
            coefficient_files: 5,
            oracle_files: 5,
            root_files: 5,
            coefficient_bytes,
            oracle_bytes,
            root_bytes,
            durable_bytes,
            retained_initial_outer_cache_bytes,
            expected_initial_outer_cache_bytes: expected_cache,
            all_lengths_and_bindings_checked: checked,
        },
    };
    (outcome.row, sources, load)
}

#[derive(Clone, Serialize)]
struct CodecReferenceRow {
    migration_path: String,
    migration_sha256: String,
    observed_codec_sha256: String,
    frozen_codec_sha256: String,
    packed_opening_bytes: u64,
    complete_pcs_bytes: u64,
    response_bytes: u64,
    golden_decode_exact: bool,
    exact_match: bool,
}

fn frozen_codec_reference() -> CodecReferenceRow {
    let pinned: Value =
        serde_json::from_slice(&fs::read(repo_root().join(MIGRATION_PATH)).unwrap()).unwrap();
    let frozen_codec_sha256 = pinned["codec"]["encoded_sha256"].as_str().unwrap().to_owned();
    let executable = std::env::current_exe().unwrap().with_file_name("x4_v4_gpt2_migration");
    let output = Command::new(executable)
        .arg(format!("--profile={PROFILE}"))
        .current_dir(repo_root().join("rust"))
        .stdin(Stdio::null())
        .output()
        .expect("re-run frozen GPT-2 migration/codec reference");
    assert!(output.status.success(), "frozen GPT-2 migration reference failed");
    let observed: Value = serde_json::from_slice(&output.stdout).unwrap();
    let observed_codec_sha256 = observed["codec"]["encoded_sha256"].as_str().unwrap().to_owned();
    let packed_opening_bytes = observed["codec"]["packed_opening_frame"].as_u64().unwrap();
    let complete_pcs_bytes = observed["complete_pcs_bytes"].as_u64().unwrap();
    let response_bytes = observed["measured_response_bytes"].as_u64().unwrap();
    let golden_decode_exact = observed["golden_decode"]["exact_match"] == true;
    let exact_match = observed_codec_sha256 == frozen_codec_sha256
        && packed_opening_bytes == PACKED_OPENING_BYTES
        && complete_pcs_bytes == PCS_BYTES
        && response_bytes == RESPONSE_BYTES
        && golden_decode_exact;
    assert!(exact_match, "frozen X4 v4 codec or golden reference changed");
    CodecReferenceRow {
        migration_path: MIGRATION_PATH.to_owned(),
        migration_sha256: MIGRATION_SHA256.to_owned(),
        observed_codec_sha256,
        frozen_codec_sha256,
        packed_opening_bytes,
        complete_pcs_bytes,
        response_bytes,
        golden_decode_exact,
        exact_match,
    }
}

fn validate_local_cpu_value(value: &Value, require_clean: bool) -> bool {
    value["schema"] == 1
        && value["milestone"] == "X4b-local-CPU-persisted-opening-preflight"
        && (!require_clean || value["git_dirty"] == false)
        && value["profile"] == PROFILE
        && value["pod_profile"] == POD_PROFILE
        && value["design_sha256"] == DESIGN_SHA256
        && value["query_count"] == QUERY_COUNT
        && value["query_draws_blake3"] == QUERY_TAPE_BLAKE3
        && value["source_policy"] == "PersistedOracle (record eligible)"
        && value["audit_recompute_refused"] == true
        && value["cpu_full_node_pipeline"]["measurement_scope"]
            .as_str()
            .map(|scope| {
                scope.contains("serialization")
                    && scope.contains("allocations")
                    && scope.contains("hash_many")
            })
            .unwrap_or(false)
        && value["cpu_full_node_pipeline"]["pinned_workers"] == 1
        && value["cpu_full_node_pipeline"]["warmup_count"] == 1
        && value["cpu_full_node_pipeline"]["measured_candidates"]
            .as_u64()
            .map(|count| count >= 5)
            .unwrap_or(false)
        && value["cpu_full_node_pipeline"]["canonical_frame_bytes"] == 460_324_760u64
        && value["cpu_full_node_pipeline"]["hash_calls"] == 5_242_879u64
        && value["cpu_full_node_pipeline"]["gate_bytes_per_s_per_core"] == CPU_GATE_BPS
        && value["cpu_full_node_pipeline"]["selected_canonical_frame_bytes_per_s"]
            .as_f64()
            .map(|bps| bps >= CPU_GATE_BPS)
            .unwrap_or(false)
        && value["cpu_full_node_pipeline"]["local_gate_met"] == true
        && value["persisted_open_full_cache"]["selected_upper_median_open_wall_s"]
            .as_f64()
            .map(|wall| wall <= OPEN_CEILING_S)
            .unwrap_or(false)
        && value["persisted_open_full_cache"]["selected_upper_median_verify_wall_s"]
            .as_f64()
            .map(|wall| wall <= VERIFY_CEILING_S)
            .unwrap_or(false)
        && value["persisted_open_full_cache"]["logical_outer_cache_bytes"]
            == FULL_INITIAL_CACHE_BYTES + FULL_FOLD_CACHE_BYTES
        && value["persisted_open_ram_degraded"]["selected_upper_median_open_wall_s"]
            .as_f64()
            .map(|wall| wall <= OPEN_CEILING_S)
            .unwrap_or(false)
        && value["persisted_open_ram_degraded"]["selected_upper_median_verify_wall_s"]
            .as_f64()
            .map(|wall| wall <= VERIFY_CEILING_S)
            .unwrap_or(false)
        && value["persisted_open_ram_degraded"]["logical_outer_cache_bytes"]
            == DEGRADED_INITIAL_CACHE_BYTES + DEGRADED_FOLD_CACHE_BYTES
        && value["full_and_degraded_openings_byte_identical"] == true
        && value["local_pre_pod_gate_pass"] == true
}

#[derive(Clone, Serialize)]
struct FrozenReferencesRow {
    design_sha256: String,
    migration_path: String,
    migration_sha256: String,
    amendment5_preflight_path: String,
    amendment5_preflight_sha256: String,
    local_preflight_path: String,
    local_preflight_sha256: String,
    note6: Note6Pin,
    profile: String,
    rate: String,
    query_count: usize,
    maximum_claim_union: u64,
    opened_symbols: u64,
    real_sibling_digests: u64,
    packed_opening_bytes: u64,
    pcs_bytes: u64,
    response_bytes: u64,
    soundness_expression: String,
    soundness_bits: f64,
    soundness_floor_bits: f64,
    soundness_new_terms: u64,
}

#[derive(Clone, Serialize)]
struct CachePolicyRow {
    name: String,
    bottom_levels_omitted: u8,
    retained_initial_outer_cache_bytes: u64,
    retained_fold_outer_cache_bytes: u64,
    retained_total_outer_cache_bytes: u64,
    memory_requirement: String,
    graceful_degradation: String,
}

fn cache_policy_row(policy: OuterCachePolicyV4) -> CachePolicyRow {
    let (name, initial, fold, requirement) = if policy == OuterCachePolicyV4::FULL {
        (
            "full",
            FULL_INITIAL_CACHE_BYTES,
            FULL_FOLD_CACHE_BYTES,
            ">=128 GiB actual host RAM; a higher-memory SKU is recommended for allocator and I/O headroom",
        )
    } else {
        (
            "ram-degraded-one-level",
            DEGRADED_INITIAL_CACHE_BYTES,
            DEGRADED_FOLD_CACHE_BYTES,
            "diagnostic graceful-degradation path for approximately 125 GiB actual RAM; the frozen >=128 GiB hardware requirement remains independently reported",
        )
    };
    CachePolicyRow {
        name: name.to_owned(),
        bottom_levels_omitted: policy.bottom_levels_omitted,
        retained_initial_outer_cache_bytes: initial,
        retained_fold_outer_cache_bytes: fold,
        retained_total_outer_cache_bytes: initial + fold,
        memory_requirement: requirement.to_owned(),
        graceful_degradation: "Omit outer level 1 in every initial and fold cache; reconstruct each required level-1 sibling from two persisted level-0 leaves, increasing counted oracle reads, inner-tree rebuilds, frontier leaves and outer internal nodes. No paging, silent overcommit, root or proof-byte change is permitted."
            .to_owned(),
    }
}

#[derive(Clone, Serialize)]
struct FullPassBenchmarkRow {
    status: String,
    warmup: InitialPassRow,
    measured: Vec<InitialPassRow>,
    selected_upper_median_wall_s: f64,
    selected_throughput_oracle_bytes_per_s: f64,
    final_materialization: InitialPassRow,
    hard_ceiling: Option<f64>,
}

#[derive(Clone, Serialize)]
struct IsolatedBenchmarkRow {
    warmup: IsolatedCommitRow,
    measured: Vec<IsolatedCommitRow>,
    selected_upper_median_wall_s: f64,
    ceiling_s: f64,
    margin_s: f64,
    margin_percent: f64,
    pass: bool,
}

#[derive(Clone, Serialize)]
struct OpeningBenchmarkRow {
    source_policy: String,
    warmup: ResponseCandidateRow,
    measured: Vec<ResponseCandidateRow>,
    selected_upper_median_open_wall_s: f64,
    selected_upper_median_verify_wall_s: f64,
    open_ceiling_s: f64,
    verify_ceiling_s: f64,
    open_pass: bool,
    verify_pass: bool,
    all_accepted: bool,
    all_byte_counts_exact: bool,
    all_g6_reconciled: bool,
}

#[derive(Clone, Serialize)]
struct HistoricalBaselineRow {
    path: String,
    sha256: String,
    verdict: String,
    immutable: bool,
}

#[derive(Clone, Serialize)]
struct GateRecord {
    cpu_full_node_pipeline: String,
    cpu_gpu_root_equality: String,
    isolated_commit: String,
    full_pass_commit: String,
    persisted_open: String,
    persisted_verify: String,
    communication_identity: String,
    g6_honesty: String,
    hardware_profile: String,
    overall_x4b: String,
    historical_x4: String,
}

#[derive(Serialize)]
struct Report {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    pod_profile: String,
    protocol_or_parameter_change: bool,
    machine: Machine,
    frozen: FrozenReferencesRow,
    cache_policy: CachePolicyRow,
    local_preflight_of_record: Value,
    pod_host_cpu_preflight: Value,
    correctness: CorrectnessRecord,
    full_pass_commit: FullPassBenchmarkRow,
    isolated_wext_mu26_commit: IsolatedBenchmarkRow,
    final_artifacts: ArtifactLoadRow,
    persisted_response: OpeningBenchmarkRow,
    codec_reference: CodecReferenceRow,
    audit_recompute_refused: bool,
    draw_before_complete_seal_rejected: bool,
    historical_baseline: HistoricalBaselineRow,
    gate: GateRecord,
    assurance: String,
}

fn warmup_correctness(
    backend: &mut Backend,
    specs: &[CohortSpec],
    artifacts: &[X4bCudaCohortArtifactsV4],
    cache_policy: OuterCachePolicyV4,
    contexts: Vec<ContextEqualityRow>,
    synthetic: Vec<SyntheticEqualityRow>,
) -> CorrectnessRecord {
    let mut complete_aux_roots = Vec::new();
    let mut larger_cohort_samples = Vec::new();
    for (index, (spec, artifact)) in specs.iter().zip(artifacts).enumerate() {
        let row = compare_warmup_artifact(backend, spec, artifact, cache_policy, index >= 3);
        if index >= 3 {
            complete_aux_roots.push(row);
        } else {
            larger_cohort_samples.push(row);
        }
    }
    let all_equal = contexts.iter().all(|row| row.equal)
        && synthetic.iter().all(|row| row.equal)
        && complete_aux_roots.iter().all(|row| row.all_equal)
        && larger_cohort_samples.iter().all(|row| row.all_equal);
    CorrectnessRecord {
        synthetic_preflight_before_full_pass: true,
        contexts,
        synthetic,
        complete_aux_roots,
        larger_cohort_samples,
        all_equal,
    }
}

struct Args {
    note6: PathBuf,
    artifact_root: PathBuf,
    cache_policy: OuterCachePolicyV4,
}

fn parse_args() -> Args {
    let mut record = false;
    let mut profile = POD_PROFILE.to_owned();
    let mut note6 = None;
    let mut artifact_root = None;
    let mut cache = None;
    for arg in std::env::args().skip(1) {
        if arg == "--record" {
            record = true;
        } else if let Some(value) = arg.strip_prefix("--profile=") {
            profile = value.to_owned();
        } else if let Some(value) = arg.strip_prefix("--note6-record=") {
            note6 = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--artifact-root=") {
            artifact_root = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--cache-policy=") {
            cache = Some(value.to_owned());
        } else {
            eprintln!("x4b_pod_record: unknown argument {arg:?}");
            std::process::exit(2);
        }
    }
    if !record || profile != POD_PROFILE {
        eprintln!(
            "x4b_pod_record: --record --profile={POD_PROFILE} are mandatory; no diagnostic profile is implicit"
        );
        std::process::exit(2);
    }
    let note6 = note6.unwrap_or_else(|| {
        eprintln!("x4b_pod_record: --note6-record=PATH is mandatory");
        std::process::exit(2);
    });
    let artifact_root = artifact_root.unwrap_or_else(|| {
        eprintln!("x4b_pod_record: --artifact-root=PATH is mandatory");
        std::process::exit(2);
    });
    let cache_policy = match cache.as_deref() {
        Some("full") => OuterCachePolicyV4::FULL,
        Some("ram-degraded-one-level") => OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL,
        _ => {
            eprintln!(
                "x4b_pod_record: explicitly select --cache-policy=full or --cache-policy=ram-degraded-one-level"
            );
            std::process::exit(2);
        }
    };
    Args { note6, artifact_root, cache_policy }
}

fn main() {
    let args = parse_args();
    assert_eq!(rayon::current_num_threads(), 8, "frozen X4b pod profile requires 8 Rayon workers");
    assert!(!git_dirty(), "X4b pod records require a tracked-clean tree");
    assert!(!LOCAL_PREFLIGHT_PATH.starts_with("__"), "local X4b preflight pin was not frozen");
    assert_eq!(sha256(&repo_root().join("docs/x4-folding-pcs-design.md")), DESIGN_SHA256);
    assert_eq!(sha256(&repo_root().join(MIGRATION_PATH)), MIGRATION_SHA256);
    assert_eq!(sha256(&repo_root().join(PREFLIGHT_PATH)), PREFLIGHT_SHA256);
    assert_eq!(sha256(&repo_root().join(LOCAL_PREFLIGHT_PATH)), LOCAL_PREFLIGHT_SHA256);
    let local_preflight_of_record: Value =
        serde_json::from_slice(&fs::read(repo_root().join(LOCAL_PREFLIGHT_PATH)).unwrap()).unwrap();
    assert!(validate_local_cpu_value(&local_preflight_of_record, true));

    let note6_path =
        if args.note6.is_absolute() { args.note6.clone() } else { repo_root().join(&args.note6) };
    let note6 = validate_note6(&note6_path);
    assert!(note6.passed && note6.first_action, "fresh NOTE-6 preflight is not eligible");
    assert!(args.artifact_root.is_dir(), "X4b persistent artifact root does not exist");
    let observed_machine = machine(&args.artifact_root);
    assert!(observed_machine.gpu.contains("A100-SXM4-80GB"), "profile requires A100-SXM4 80 GB");
    assert!(observed_machine.persistent_volume_bytes >= MIN_VOLUME_BYTES);
    assert!(
        observed_machine.persistent_volume_available_bytes_at_start
            >= DURABLE_BYTES + 40 * 1024 * 1024 * 1024,
        "insufficient free volume for durable artifacts plus bounded response staging"
    );
    if args.cache_policy == OuterCachePolicyV4::FULL {
        assert!(
            observed_machine.memory_bytes >= BASELINE_RAM_BYTES,
            "full cache requires >=128 GiB actual RAM; use the explicit degraded policy only for the ~125-GiB diagnostic path"
        );
    } else {
        assert!(
            observed_machine.memory_bytes >= DEGRADED_RAM_FLOOR_BYTES,
            "degraded cache still requires at least 120 GiB actual RAM"
        );
    }
    X4bOpeningSourcePolicyV4::PersistedOracle.require_record_eligible().unwrap();
    let audit_recompute_refused =
        X4bOpeningSourcePolicyV4::AuditRecompute.require_record_eligible().is_err();
    assert!(audit_recompute_refused);

    let session_directory = args.artifact_root.join(format!(
        "x4b-{}-{}",
        command_output(&["git", "rev-parse", "--short", "HEAD"]),
        std::process::id()
    ));
    fs::create_dir(&session_directory).expect("create append-only X4b artifact session");

    let pod_host_cpu_preflight = local_cpu_preflight();
    assert!(validate_local_cpu_value(&pod_host_cpu_preflight, true));
    let draws = selected_query_draws();
    let specs = gpt2_specs();
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .expect("initialize wall-only X4b CUDA backend");

    // Fail closed on the cheap synthetic geometries before allocating or
    // committing the 77-GB GPT-2 oracle. This ordering is part of the pod
    // record, not merely a runbook convention.
    let (contexts, synthetic) = synthetic_correctness(
        &mut backend,
        &session_directory.join("correctness-synthetic-preflight"),
    );
    assert_eq!(contexts.len(), 4, "all N4 derive-key domains must be checked");
    assert_eq!(synthetic.len(), 5, "all synthetic structural families must be checked");
    assert!(
        contexts.iter().all(|row| row.equal) && synthetic.iter().all(|row| row.equal),
        "pre-full-pass CPU/GPU synthetic root/digest equality failed"
    );

    let warmup_outcome = run_initial_pass(
        "warmup",
        &mut backend,
        &specs,
        session_directory.join("initial-warmup"),
        args.cache_policy,
    );
    let correctness = warmup_correctness(
        &mut backend,
        &specs,
        &warmup_outcome.artifacts,
        args.cache_policy,
        contexts,
        synthetic,
    );
    assert!(correctness.all_equal, "CPU/GPU X4b root/digest equality failed");
    let expected_roots =
        warmup_outcome.row.cohorts.iter().map(|row| row.root_hex.clone()).collect::<Vec<_>>();
    let warmup_row = cleanup_pass(warmup_outcome);

    let mut measured_full = Vec::new();
    for ordinal in 1..=3 {
        let outcome = run_initial_pass(
            &format!("measured-{ordinal}"),
            &mut backend,
            &specs,
            session_directory.join(format!("initial-measured-{ordinal}")),
            args.cache_policy,
        );
        assert_root_vector(&expected_roots, &outcome.row);
        measured_full.push(cleanup_pass(outcome));
    }
    let selected_full_wall = upper_median(measured_full.iter().map(|row| row.wall_s).collect());

    let isolated_warmup = run_isolated_commit(
        "warmup",
        &mut backend,
        &specs[0],
        session_directory.join("isolated-warmup"),
        args.cache_policy,
    );
    let isolated_root = isolated_warmup.root_hex.clone();
    let mut isolated_measured = Vec::new();
    for ordinal in 1..=3 {
        let row = run_isolated_commit(
            &format!("measured-{ordinal}"),
            &mut backend,
            &specs[0],
            session_directory.join(format!("isolated-measured-{ordinal}")),
            args.cache_policy,
        );
        assert_eq!(row.root_hex, isolated_root);
        isolated_measured.push(row);
    }
    let isolated_selected = upper_median(isolated_measured.iter().map(|row| row.wall_s).collect());
    let isolated_margin = COMMIT_CEILING_S - isolated_selected;
    let isolated_pass = isolated_selected <= COMMIT_CEILING_S
        && isolated_measured.iter().all(|row| row.reconciliation_pass);
    let isolated = IsolatedBenchmarkRow {
        warmup: isolated_warmup,
        measured: isolated_measured,
        selected_upper_median_wall_s: isolated_selected,
        ceiling_s: COMMIT_CEILING_S,
        margin_s: isolated_margin,
        margin_percent: 100.0 * isolated_margin / COMMIT_CEILING_S,
        pass: isolated_pass,
    };

    let final_outcome = run_initial_pass(
        "final-durable-materialization",
        &mut backend,
        &specs,
        session_directory.join("durable-initial"),
        args.cache_policy,
    );
    assert_root_vector(&expected_roots, &final_outcome.row);
    let (final_materialization, sources, final_artifacts) =
        load_final_sources(specs, final_outcome, args.cache_policy);
    let full_pass = FullPassBenchmarkRow {
        status: "MEASURED/INFORMATIVE; no hard ceiling in runpod-a100-x4b-v1".to_owned(),
        warmup: warmup_row,
        measured: measured_full,
        selected_upper_median_wall_s: selected_full_wall,
        selected_throughput_oracle_bytes_per_s: ORACLE_BYTES as f64 / selected_full_wall,
        final_materialization,
        hard_ceiling: None,
    };

    let response_warmup = run_response_candidate(
        "warmup",
        0,
        &mut backend,
        &sources,
        &draws,
        session_directory.join("response-warmup"),
        args.cache_policy,
    );
    let mut response_measured = Vec::new();
    for ordinal in 1..=3 {
        response_measured.push(run_response_candidate(
            &format!("measured-{ordinal}"),
            ordinal,
            &mut backend,
            &sources,
            &draws,
            session_directory.join(format!("response-measured-{ordinal}")),
            args.cache_policy,
        ));
    }
    let selected_open = upper_median(response_measured.iter().map(|row| row.open_wall_s).collect());
    let selected_verify =
        upper_median(response_measured.iter().map(|row| row.verify_wall_s).collect());
    let all_accepted =
        std::iter::once(&response_warmup).chain(&response_measured).all(|row| row.accepted);
    let all_byte_counts_exact =
        std::iter::once(&response_warmup).chain(&response_measured).all(|row| {
            row.packed_opening_bytes == PACKED_OPENING_BYTES
                && row.opened_symbols == OPENED_SYMBOLS
                && row.real_sibling_digests == REAL_SIBLING_DIGESTS
        });
    let all_g6_reconciled = std::iter::once(&response_warmup)
        .chain(&response_measured)
        .all(|row| row.g6_reconciliation_pass);
    let persisted_response = OpeningBenchmarkRow {
        source_policy: "PersistedOracle (record eligible); AuditRecompute refused".to_owned(),
        warmup: response_warmup,
        measured: response_measured,
        selected_upper_median_open_wall_s: selected_open,
        selected_upper_median_verify_wall_s: selected_verify,
        open_ceiling_s: OPEN_CEILING_S,
        verify_ceiling_s: VERIFY_CEILING_S,
        open_pass: selected_open <= OPEN_CEILING_S,
        verify_pass: selected_verify <= VERIFY_CEILING_S,
        all_accepted,
        all_byte_counts_exact,
        all_g6_reconciled,
    };
    let codec_reference = frozen_codec_reference();

    let cpu_bps = pod_host_cpu_preflight["cpu_full_node_pipeline"]
        ["selected_canonical_frame_bytes_per_s"]
        .as_f64()
        .unwrap();
    let cpu_pass = cpu_bps >= CPU_GATE_BPS;
    let full_g6 = full_pass.warmup.reconciliation_pass
        && full_pass.measured.iter().all(|row| row.reconciliation_pass)
        && full_pass.final_materialization.reconciliation_pass;
    let g6_pass = full_g6
        && isolated.warmup.reconciliation_pass
        && isolated.measured.iter().all(|row| row.reconciliation_pass)
        && persisted_response.all_g6_reconciled
        && final_artifacts.footprint.all_lengths_and_bindings_checked
        && final_artifacts.page_cache_dontneed_bytes == COEFFICIENT_BYTES + ROOT_BYTES
        && final_artifacts.page_cache_advice_calls == 10
        && final_artifacts.process_io.rchar >= COEFFICIENT_BYTES + ROOT_BYTES;
    let communication_pass =
        persisted_response.all_byte_counts_exact && codec_reference.exact_match;
    let hardware_pass = observed_machine.memory_bytes >= BASELINE_RAM_BYTES
        && observed_machine.persistent_volume_bytes >= MIN_VOLUME_BYTES
        && observed_machine.gpu.contains("A100-SXM4-80GB")
        && observed_machine.rayon_threads == 8;
    let overall_pass = cpu_pass
        && correctness.all_equal
        && isolated.pass
        && persisted_response.open_pass
        && persisted_response.verify_pass
        && persisted_response.all_accepted
        && communication_pass
        && g6_pass
        && hardware_pass;
    let pass_fail = |pass| if pass { "PASS" } else { "FAIL" };
    let gate = GateRecord {
        cpu_full_node_pipeline: format!(
            "{} — full serialization+allocation+hash pipeline {:.3} B/s/core against >=500,000,000",
            pass_fail(cpu_pass), cpu_bps
        ),
        cpu_gpu_root_equality: format!(
            "{} — all four derive contexts, synthetic structural families, complete aux roots and larger-cohort samples",
            pass_fail(correctness.all_equal)
        ),
        isolated_commit: format!(
            "{} — exact Wext-mu26 upper-median {:.9} s <=15.000 s; margin {:.9} s ({:.6}%)",
            pass_fail(isolated.pass), isolated_selected, isolated_margin, 100.0 * isolated_margin / COMMIT_CEILING_S
        ),
        full_pass_commit: format!(
            "MEASURED / INFORMATIVE — upper-median complete GPT-2 pass {:.9} s; no ceiling in this profile",
            selected_full_wall
        ),
        persisted_open: format!(
            "{} — PersistedOracle upper-median {:.9} s <=1.500 s",
            pass_fail(persisted_response.open_pass), selected_open
        ),
        persisted_verify: format!(
            "{} — upper-median {:.9} s <=0.250 s",
            pass_fail(persisted_response.verify_pass), selected_verify
        ),
        communication_identity: format!(
            "{} — PCS exactly 2,683,236 B; response exactly 43,953,700 B; frozen codec digest unchanged",
            pass_fail(communication_pass)
        ),
        g6_honesty: format!(
            "{} — durable/resident/recompute/H2D/D2H/host-I/O/scratch/RSS/page-cache/VRAM counters present and reconciled",
            pass_fail(g6_pass)
        ),
        hardware_profile: format!(
            "{} — A100-SXM4 80 GB, 8 Rayon workers, >=150 GB volume, actual RAM {} B against frozen >=128 GiB requirement",
            pass_fail(hardware_pass), observed_machine.memory_bytes
        ),
        overall_x4b: format!(
            "{} — conjunctive runpod-a100-x4b-v1 gates; no threshold relaxed",
            pass_fail(overall_pass)
        ),
        historical_x4: "FAIL IMMUTABLE — x4-v4-a100-production-2026-07-22-47a701e.json remains the X4 verdict"
            .to_owned(),
    };

    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_short_sha = command_output(&["git", "rev-parse", "--short", "HEAD"]);
    let date = command_output(&["date", "+%Y-%m-%d"]);
    let report = Report {
        schema: 1,
        milestone: "X4b-A100-production-record".to_owned(),
        date: date.clone(),
        git_sha,
        git_short_sha: git_short_sha.clone(),
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        protocol_or_parameter_change: false,
        machine: observed_machine,
        frozen: FrozenReferencesRow {
            design_sha256: DESIGN_SHA256.to_owned(),
            migration_path: MIGRATION_PATH.to_owned(),
            migration_sha256: MIGRATION_SHA256.to_owned(),
            amendment5_preflight_path: PREFLIGHT_PATH.to_owned(),
            amendment5_preflight_sha256: PREFLIGHT_SHA256.to_owned(),
            local_preflight_path: LOCAL_PREFLIGHT_PATH.to_owned(),
            local_preflight_sha256: LOCAL_PREFLIGHT_SHA256.to_owned(),
            note6,
            profile: PROFILE.to_owned(),
            rate: "1/8".to_owned(),
            query_count: QUERY_COUNT,
            maximum_claim_union: 3_320,
            opened_symbols: OPENED_SYMBOLS,
            real_sibling_digests: REAL_SIBLING_DIGESTS,
            packed_opening_bytes: PACKED_OPENING_BYTES,
            pcs_bytes: PCS_BYTES,
            response_bytes: RESPONSE_BYTES,
            soundness_expression: "3320*(9/16)^111 + 28522064267253/340282366762482138490186164457219031041"
                .to_owned(),
            soundness_bits: SOUNDNESS_BITS,
            soundness_floor_bits: SOUNDNESS_FLOOR_BITS,
            soundness_new_terms: 0,
        },
        cache_policy: cache_policy_row(args.cache_policy),
        local_preflight_of_record,
        pod_host_cpu_preflight,
        correctness,
        full_pass_commit: full_pass,
        isolated_wext_mu26_commit: isolated,
        final_artifacts,
        persisted_response,
        codec_reference,
        audit_recompute_refused,
        draw_before_complete_seal_rejected: true,
        historical_baseline: HistoricalBaselineRow {
            path: "benchmarks/results/x4-v4-a100-production-2026-07-22-47a701e.json"
                .to_owned(),
            sha256: "111e4056feb0ba53569889a0bf1d0af73c99ab4613ab9a76aae975f8adbb0237"
                .to_owned(),
            verdict: "G4 COMMIT FAIL; OVERALL X4 FAIL".to_owned(),
            immutable: true,
        },
        gate,
        assurance: "AI-generated implementation and records; no independent human-review assurance. R1c hostile review remains mandatory."
            .to_owned(),
    };
    assert!(!git_dirty(), "source tree changed during X4b measurement");
    let path = repo_root()
        .join("benchmarks/results")
        .join(format!("x4b-a100-production-{date}-{git_short_sha}.json"));
    if path.exists() {
        eprintln!("x4b_pod_record: append-only record already exists: {}", path.display());
        std::process::exit(2);
    }
    fs::write(&path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    eprintln!(
        "X4b pod {}: CPU={:.3} B/s/core isolated={:.6}s open={:.6}s verify={:.6}s; wrote {}",
        pass_fail(overall_pass),
        cpu_bps,
        isolated_selected,
        selected_open,
        selected_verify,
        path.display()
    );
}
