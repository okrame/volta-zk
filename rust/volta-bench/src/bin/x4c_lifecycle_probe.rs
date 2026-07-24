//! X4c exact-size host lifecycle probe.
//!
//! The default/local mode is a tiny structural smoke test.  The 51.54 GB
//! geometry is reachable only through `--exact-pod` and refuses execution
//! before allocation unless the frozen RunPod hardware, storage, thread and
//! clean-tree anchors are explicit.  Each warm-up/candidate runs in a fresh
//! child process so the no-teardown diagnostic cannot leak into the next run.

use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use volta_bench::x4c_instrumentation::{
    touch_populated_bytes, BoundaryCollectorV1, BoundarySnapshotV1, CudaSnapshotV1,
    SealedOwnershipSnapshotV1, TemporaryFileStateV1, X4cCountingAllocator,
    X4C_PRODUCTION_FOLD_CODEWORD_BYTES, X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES,
    X4C_PRODUCTION_SEALED_STATE_BYTES,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: X4cCountingAllocator = X4cCountingAllocator;

const SCHEMA: u64 = 1;
const MILESTONE: &str = "X4c-phase2-exact-size-lifecycle-probe";
const POD_PROFILE: &str = "runpod-a100-x4c-v1";
const PROTOCOL_PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const EXACT_DOMAIN_LOG2: u8 = 29;
const SMOKE_DOMAIN_LOG2: u8 = 12;
const WARMUP_COUNT: usize = 1;
const MEASURED_CANDIDATES: usize = 3;
const MIN_HOST_RAM_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const MIN_LOCAL_STORAGE_BYTES: u64 = 150_000_000_000;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Variant {
    DistributedDrop,
    ManuallyDropNoTeardown,
    CategorizedDrop,
    SingleArenaReset,
}

impl Variant {
    const ALL: [Self; 4] = [
        Self::DistributedDrop,
        Self::ManuallyDropNoTeardown,
        Self::CategorizedDrop,
        Self::SingleArenaReset,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::DistributedDrop => "distributed_drop",
            Self::ManuallyDropNoTeardown => "manually_drop_no_teardown",
            Self::CategorizedDrop => "categorized_drop",
            Self::SingleArenaReset => "single_arena_reset",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|candidate| candidate.as_str() == value)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct PayloadGeometry {
    domain_log2: u8,
    fold_rounds: u64,
    fold_codeword_bytes: u64,
    fold_outer_cache_bytes: u64,
    populated_bytes: u64,
}

fn geometry(domain_log2: u8) -> Option<PayloadGeometry> {
    if !(3..=62).contains(&domain_log2) {
        return None;
    }
    let mut fold_codeword_bytes = 0u64;
    let mut fold_outer_cache_bytes = 0u64;
    for log in (3..=domain_log2).rev() {
        let symbols = 1u64.checked_shl(u32::from(log))?;
        fold_codeword_bytes = fold_codeword_bytes.checked_add(symbols.checked_mul(16)?)?;
        fold_outer_cache_bytes =
            fold_outer_cache_bytes.checked_add(symbols.checked_sub(1)?.checked_mul(32)?)?;
    }
    Some(PayloadGeometry {
        domain_log2,
        fold_rounds: u64::from(domain_log2 - 2),
        fold_codeword_bytes,
        fold_outer_cache_bytes,
        populated_bytes: fold_codeword_bytes.checked_add(fold_outer_cache_bytes)?,
    })
}

#[derive(Debug)]
struct DistributedState {
    codewords: Option<Vec<Vec<u8>>>,
    outer_cache_levels: Option<Vec<Vec<Vec<u8>>>>,
    metadata: Option<Vec<(u8, u64, u64)>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PopulationStats {
    populated_bytes: u64,
    touched_pages: u64,
    checksum_u64: u64,
}

impl PopulationStats {
    fn add(&mut self, byte: u8, length: usize, touched_pages: u64) {
        let length = u64::try_from(length).expect("payload length fits u64");
        self.populated_bytes =
            self.populated_bytes.checked_add(length).expect("population byte overflow");
        self.touched_pages =
            self.touched_pages.checked_add(touched_pages).expect("touch count overflow");
        self.checksum_u64 =
            self.checksum_u64.wrapping_add(u64::from(byte).wrapping_mul(length)).rotate_left(7);
    }
}

fn populated_vec(length: u64, byte: u8, stats: &mut PopulationStats) -> Vec<u8> {
    let length = usize::try_from(length).expect("probe requires a 64-bit address space");
    let mut bytes = vec![byte; length];
    let touched_pages = touch_populated_bytes(&mut bytes);
    stats.add(byte, length, touched_pages);
    bytes
}

fn build_distributed_state(domain_log2: u8) -> (DistributedState, PopulationStats) {
    let mut stats = PopulationStats::default();
    let mut codewords = Vec::with_capacity(usize::from(domain_log2 - 2));
    let mut outer_cache_levels = Vec::with_capacity(usize::from(domain_log2 - 2));
    let mut metadata = Vec::with_capacity(usize::from(domain_log2 - 2));
    for (round, log) in (3..=domain_log2).rev().enumerate() {
        let symbols = 1u64 << log;
        let codeword_bytes = symbols * 16;
        let cache_bytes = (symbols - 1) * 32;
        codewords.push(populated_vec(codeword_bytes, 1 + (round % 251) as u8, &mut stats));
        let mut levels = Vec::with_capacity(usize::from(log));
        for level in (0..log).rev() {
            let level_bytes = (1u64 << level) * 32;
            levels.push(populated_vec(
                level_bytes,
                1 + ((round + usize::from(level) + 97) % 251) as u8,
                &mut stats,
            ));
        }
        outer_cache_levels.push(levels);
        metadata.push((log, codeword_bytes, cache_bytes));
    }
    (
        DistributedState {
            codewords: Some(codewords),
            outer_cache_levels: Some(outer_cache_levels),
            metadata: Some(metadata),
        },
        stats,
    )
}

fn ownership(codewords: u64, cache: u64, other: u64) -> SealedOwnershipSnapshotV1 {
    SealedOwnershipSnapshotV1 {
        fold_codeword_bytes: codewords,
        fold_outer_cache_bytes: cache,
        other_ordinary_host_bytes: other,
        ordinary_host_bytes: codewords
            .checked_add(cache)
            .and_then(|value| value.checked_add(other))
            .expect("ownership overflow"),
        ..SealedOwnershipSnapshotV1::default()
    }
}

fn ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct CandidateTiming {
    allocation_population_wall_ns: u64,
    proof_ready_wall_ns: u64,
    distributed_drop_wall_ns: u64,
    destroy_codewords_wall_ns: u64,
    destroy_outer_cache_levels_wall_ns: u64,
    destroy_remaining_state_wall_ns: u64,
    logical_arena_reset_wall_ns: u64,
    backing_release_wall_ns: u64,
    teardown_total_wall_ns: u64,
    session_reusable_wall_ns: Option<u64>,
    parent_child_wall_ns: u64,
    child_reap_wall_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Candidate {
    ordinal: usize,
    measured: bool,
    child_pid: u32,
    variant: Variant,
    geometry: PayloadGeometry,
    populated_bytes: u64,
    touched_pages: u64,
    population_checksum_u64: u64,
    timing: CandidateTiming,
    boundaries: Vec<BoundarySnapshotV1>,
    termination: String,
    intentionally_retained_bytes: u64,
    arena_backing_retained_after_reset_bytes: u64,
    outstanding_payload_bytes_after_teardown: u64,
    child_exit_success: bool,
    child_exit_code: Option<i32>,
    accepted: bool,
    obstruction_reasons: Vec<String>,
}

fn candidate_accepted(candidate: &Candidate) -> bool {
    let expected = &candidate.geometry;
    if candidate.populated_bytes != expected.populated_bytes
        || candidate.touched_pages == 0
        || candidate.population_checksum_u64 == 0
        || candidate.boundaries.iter().any(|boundary| {
            !boundary.is_internally_consistent()
                || !boundary.host_counters_available()
                || !boundary.cuda.availability.available
        })
        || candidate.boundaries.windows(2).any(|pair| pair[1].seq != pair[0].seq + 1)
    {
        return false;
    }
    match candidate.variant {
        Variant::DistributedDrop => {
            candidate.timing.distributed_drop_wall_ns > 0
                && candidate.timing.teardown_total_wall_ns > 0
                && candidate.timing.session_reusable_wall_ns.is_some()
                && candidate.outstanding_payload_bytes_after_teardown == 0
                && candidate.intentionally_retained_bytes == 0
        }
        Variant::ManuallyDropNoTeardown => {
            candidate.termination == "_exit_no_destructors"
                && candidate.timing.teardown_total_wall_ns == 0
                && candidate.timing.session_reusable_wall_ns.is_none()
                && candidate.intentionally_retained_bytes == expected.populated_bytes
                && candidate.outstanding_payload_bytes_after_teardown == expected.populated_bytes
        }
        Variant::CategorizedDrop => {
            candidate.timing.destroy_codewords_wall_ns > 0
                && candidate.timing.destroy_outer_cache_levels_wall_ns > 0
                && candidate.timing.destroy_remaining_state_wall_ns > 0
                && candidate.timing.teardown_total_wall_ns > 0
                && candidate.timing.session_reusable_wall_ns.is_some()
                && candidate.outstanding_payload_bytes_after_teardown == 0
        }
        Variant::SingleArenaReset => {
            candidate.timing.logical_arena_reset_wall_ns > 0
                && candidate.timing.backing_release_wall_ns > 0
                && candidate.timing.teardown_total_wall_ns > 0
                && candidate.timing.session_reusable_wall_ns.is_some()
                && candidate.arena_backing_retained_after_reset_bytes == expected.populated_bytes
                && candidate.outstanding_payload_bytes_after_teardown == 0
        }
    }
}

fn run_distributed_candidate(
    domain_log2: u8,
    ordinal: usize,
    measured: bool,
    variant: Variant,
) -> Candidate {
    let geometry = geometry(domain_log2).expect("valid geometry");
    let session_started = Instant::now();
    let mut collector = BoundaryCollectorV1::new(true);
    let mut boundaries = vec![collector.capture(
        "probe_start",
        ownership(0, 0, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    )];
    let allocation_started = Instant::now();
    let (mut state, population) = build_distributed_state(domain_log2);
    let allocation_population_wall_ns = ns(allocation_started);
    boundaries.push(collector.capture(
        "payload_populated",
        ownership(geometry.fold_codeword_bytes, geometry.fold_outer_cache_bytes, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    ));
    let proof_ready_wall_ns = ns(session_started);
    let teardown_started = Instant::now();
    let mut timing = CandidateTiming {
        allocation_population_wall_ns,
        proof_ready_wall_ns,
        ..CandidateTiming::default()
    };
    match variant {
        Variant::DistributedDrop => {
            let started = Instant::now();
            drop(state);
            timing.distributed_drop_wall_ns = ns(started);
            timing.teardown_total_wall_ns = ns(teardown_started);
            boundaries.push(collector.capture(
                "distributed_state_destroyed",
                ownership(0, 0, 0),
                TemporaryFileStateV1::default(),
                CudaSnapshotV1::cpu_only_zero(),
            ));
            timing.session_reusable_wall_ns = Some(ns(session_started));
        }
        Variant::CategorizedDrop => {
            let started = Instant::now();
            drop(state.codewords.take());
            timing.destroy_codewords_wall_ns = ns(started);
            boundaries.push(collector.capture(
                "codewords_destroyed",
                ownership(0, geometry.fold_outer_cache_bytes, 0),
                TemporaryFileStateV1::default(),
                CudaSnapshotV1::cpu_only_zero(),
            ));
            let started = Instant::now();
            drop(state.outer_cache_levels.take());
            timing.destroy_outer_cache_levels_wall_ns = ns(started);
            boundaries.push(collector.capture(
                "outer_cache_levels_destroyed",
                ownership(0, 0, 0),
                TemporaryFileStateV1::default(),
                CudaSnapshotV1::cpu_only_zero(),
            ));
            let started = Instant::now();
            drop(state.metadata.take());
            drop(state);
            timing.destroy_remaining_state_wall_ns = ns(started);
            timing.teardown_total_wall_ns = ns(teardown_started);
            boundaries.push(collector.capture(
                "remaining_state_destroyed",
                ownership(0, 0, 0),
                TemporaryFileStateV1::default(),
                CudaSnapshotV1::cpu_only_zero(),
            ));
            timing.session_reusable_wall_ns = Some(ns(session_started));
        }
        Variant::ManuallyDropNoTeardown | Variant::SingleArenaReset => {
            unreachable!("variant handled by a dedicated path")
        }
    }
    let mut candidate = Candidate {
        ordinal,
        measured,
        child_pid: std::process::id(),
        variant,
        geometry,
        populated_bytes: population.populated_bytes,
        touched_pages: population.touched_pages,
        population_checksum_u64: population.checksum_u64,
        timing,
        boundaries,
        termination: "normal_return_after_explicit_teardown".to_owned(),
        intentionally_retained_bytes: 0,
        arena_backing_retained_after_reset_bytes: 0,
        outstanding_payload_bytes_after_teardown: 0,
        child_exit_success: false,
        child_exit_code: None,
        accepted: false,
        obstruction_reasons: Vec::new(),
    };
    candidate.accepted = candidate_accepted(&candidate);
    candidate
}

fn run_arena_candidate(domain_log2: u8, ordinal: usize, measured: bool) -> Candidate {
    let geometry = geometry(domain_log2).expect("valid geometry");
    let session_started = Instant::now();
    let mut collector = BoundaryCollectorV1::new(true);
    let mut boundaries = vec![collector.capture(
        "probe_start",
        ownership(0, 0, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    )];
    let allocation_started = Instant::now();
    let mut stats = PopulationStats::default();
    let mut arena = populated_vec(geometry.populated_bytes, 0xA7, &mut stats);
    let mut logical_allocations = (3..=domain_log2).rev().collect::<Vec<_>>();
    let allocation_population_wall_ns = ns(allocation_started);
    boundaries.push(collector.capture(
        "payload_populated",
        ownership(geometry.fold_codeword_bytes, geometry.fold_outer_cache_bytes, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    ));
    let proof_ready_wall_ns = ns(session_started);
    let teardown_started = Instant::now();
    let reset_started = Instant::now();
    logical_allocations.clear();
    logical_allocations.shrink_to_fit();
    let logical_arena_reset_wall_ns = ns(reset_started);
    boundaries.push(collector.capture(
        "arena_logically_reset_backing_retained",
        ownership(0, 0, geometry.populated_bytes),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    ));
    let release_started = Instant::now();
    arena.clear();
    arena.shrink_to_fit();
    drop(arena);
    let backing_release_wall_ns = ns(release_started);
    let teardown_total_wall_ns = ns(teardown_started);
    let arena_backing_retained_after_reset_bytes = geometry.populated_bytes;
    boundaries.push(collector.capture(
        "arena_backing_released",
        ownership(0, 0, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    ));
    let mut candidate = Candidate {
        ordinal,
        measured,
        child_pid: std::process::id(),
        variant: Variant::SingleArenaReset,
        geometry,
        populated_bytes: stats.populated_bytes,
        touched_pages: stats.touched_pages,
        population_checksum_u64: stats.checksum_u64,
        timing: CandidateTiming {
            allocation_population_wall_ns,
            proof_ready_wall_ns,
            logical_arena_reset_wall_ns,
            backing_release_wall_ns,
            teardown_total_wall_ns,
            session_reusable_wall_ns: Some(ns(session_started)),
            ..CandidateTiming::default()
        },
        boundaries,
        termination: "normal_return_after_explicit_teardown".to_owned(),
        intentionally_retained_bytes: 0,
        arena_backing_retained_after_reset_bytes,
        outstanding_payload_bytes_after_teardown: 0,
        child_exit_success: false,
        child_exit_code: None,
        accepted: false,
        obstruction_reasons: Vec::new(),
    };
    candidate.accepted = candidate_accepted(&candidate);
    candidate
}

fn no_teardown_candidate(domain_log2: u8, ordinal: usize, measured: bool) -> ! {
    let geometry = geometry(domain_log2).expect("valid geometry");
    let session_started = Instant::now();
    let mut collector = BoundaryCollectorV1::new(true);
    let mut boundaries = vec![collector.capture(
        "probe_start",
        ownership(0, 0, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    )];
    let allocation_started = Instant::now();
    let (state, population) = build_distributed_state(domain_log2);
    let retained = ManuallyDrop::new(state);
    let allocation_population_wall_ns = ns(allocation_started);
    boundaries.push(collector.capture(
        "payload_populated_no_teardown",
        ownership(geometry.fold_codeword_bytes, geometry.fold_outer_cache_bytes, 0),
        TemporaryFileStateV1::default(),
        CudaSnapshotV1::cpu_only_zero(),
    ));
    let mut candidate = Candidate {
        ordinal,
        measured,
        child_pid: std::process::id(),
        variant: Variant::ManuallyDropNoTeardown,
        geometry,
        populated_bytes: population.populated_bytes,
        touched_pages: population.touched_pages,
        population_checksum_u64: population.checksum_u64,
        timing: CandidateTiming {
            allocation_population_wall_ns,
            proof_ready_wall_ns: ns(session_started),
            ..CandidateTiming::default()
        },
        boundaries,
        termination: "_exit_no_destructors".to_owned(),
        intentionally_retained_bytes: population.populated_bytes,
        arena_backing_retained_after_reset_bytes: 0,
        outstanding_payload_bytes_after_teardown: population.populated_bytes,
        child_exit_success: false,
        child_exit_code: None,
        accepted: false,
        obstruction_reasons: Vec::new(),
    };
    candidate.accepted = candidate_accepted(&candidate);
    serde_json::to_writer(std::io::stdout().lock(), &candidate).expect("serialize child record");
    std::io::stdout().lock().flush().expect("flush child record");
    std::hint::black_box(&retained);
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn _exit(status: std::os::raw::c_int) -> !;
        }
        // SAFETY: record bytes are flushed and `_exit` is the intended
        // no-destructor termination control.
        _exit(0)
    }
    #[cfg(not(unix))]
    std::process::exit(0)
}

fn run_child_mode(args: &[String]) -> Result<(), String> {
    let variant = args
        .windows(2)
        .find(|pair| pair[0] == "--variant")
        .and_then(|pair| Variant::parse(&pair[1]))
        .ok_or_else(|| "child requires valid --variant".to_owned())?;
    let domain_log2 = args
        .windows(2)
        .find(|pair| pair[0] == "--domain-log2")
        .and_then(|pair| pair[1].parse::<u8>().ok())
        .ok_or_else(|| "child requires --domain-log2".to_owned())?;
    let ordinal = args
        .windows(2)
        .find(|pair| pair[0] == "--ordinal")
        .and_then(|pair| pair[1].parse::<usize>().ok())
        .ok_or_else(|| "child requires --ordinal".to_owned())?;
    let measured = args.iter().any(|argument| argument == "--measured");
    if domain_log2 == EXACT_DOMAIN_LOG2 {
        exact_pod_guard()?;
    } else if domain_log2 != SMOKE_DOMAIN_LOG2 {
        return Err("child geometry must be the frozen smoke or exact-pod geometry".to_owned());
    }
    if variant == Variant::ManuallyDropNoTeardown {
        no_teardown_candidate(domain_log2, ordinal, measured);
    }
    let candidate = match variant {
        Variant::DistributedDrop | Variant::CategorizedDrop => {
            run_distributed_candidate(domain_log2, ordinal, measured, variant)
        }
        Variant::SingleArenaReset => run_arena_candidate(domain_log2, ordinal, measured),
        Variant::ManuallyDropNoTeardown => unreachable!(),
    };
    serde_json::to_writer(std::io::stdout().lock(), &candidate)
        .map_err(|error| format!("serialize child record: {error}"))?;
    Ok(())
}

fn run_isolated_child(
    domain_log2: u8,
    variant: Variant,
    ordinal: usize,
    measured: bool,
) -> Result<Candidate, String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve current executable: {error}"))?;
    let parent_started = Instant::now();
    let mut command = Command::new(executable);
    command
        .args([
            "--child",
            "--variant",
            variant.as_str(),
            "--domain-log2",
            &domain_log2.to_string(),
            "--ordinal",
            &ordinal.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if measured {
        command.arg("--measured");
    }
    let mut child = command.spawn().map_err(|error| format!("spawn child: {error}"))?;
    let mut json = String::new();
    child
        .stdout
        .take()
        .ok_or_else(|| "child stdout was not piped".to_owned())?
        .read_to_string(&mut json)
        .map_err(|error| format!("read child record: {error}"))?;
    let reap_started = Instant::now();
    let status = child.wait().map_err(|error| format!("reap child: {error}"))?;
    let child_reap_wall_ns = ns(reap_started);
    let parent_child_wall_ns = ns(parent_started);
    let mut candidate: Candidate =
        serde_json::from_str(&json).map_err(|error| format!("parse child record: {error}"))?;
    candidate.timing.parent_child_wall_ns = parent_child_wall_ns;
    candidate.timing.child_reap_wall_ns = child_reap_wall_ns;
    candidate.child_exit_success = status.success();
    candidate.child_exit_code = status.code();
    candidate.accepted = status.success()
        && candidate.obstruction_reasons.is_empty()
        && candidate_accepted(&candidate);
    Ok(candidate)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct VariantRecord {
    variant: Variant,
    warmup_count: usize,
    measured_candidate_count: usize,
    warmup: Candidate,
    measured_candidates: Vec<Candidate>,
    selected_upper_median_ordinal: usize,
    all_accepted: bool,
}

fn variant_record(domain_log2: u8, variant: Variant) -> Result<VariantRecord, String> {
    let warmup = run_isolated_child(domain_log2, variant, 0, false)?;
    let mut measured_candidates = Vec::with_capacity(MEASURED_CANDIDATES);
    for ordinal in 1..=MEASURED_CANDIDATES {
        measured_candidates.push(run_isolated_child(domain_log2, variant, ordinal, true)?);
    }
    let mut order = (0..measured_candidates.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| measured_candidates[*index].timing.parent_child_wall_ns);
    let selected_upper_median_ordinal = measured_candidates[order[order.len() / 2]].ordinal;
    let all_accepted = warmup.accepted && measured_candidates.iter().all(|row| row.accepted);
    Ok(VariantRecord {
        variant,
        warmup_count: WARMUP_COUNT,
        measured_candidate_count: MEASURED_CANDIDATES,
        warmup,
        measured_candidates,
        selected_upper_median_ordinal,
        all_accepted,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StorageAnchor {
    path: String,
    filesystem_type: String,
    mount_point: String,
    available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MachineRecord {
    provider: String,
    gpu: String,
    memory_bytes: u64,
    rayon_threads: usize,
    commit_seal_open_unpinned: bool,
    durable_tier: String,
    local_storage_role: String,
    persistent_class: String,
    persistent_volume: StorageAnchor,
    local_non_mfs_storage: StorageAnchor,
}

fn memtotal_bytes() -> Result<u64, String> {
    let text =
        fs::read_to_string("/proc/meminfo").map_err(|error| format!("read meminfo: {error}"))?;
    let kib = text
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("MemTotal:")?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
        .ok_or_else(|| "MemTotal missing from /proc/meminfo".to_owned())?;
    kib.checked_mul(1024).ok_or_else(|| "MemTotal overflow".to_owned())
}

fn storage_anchor(path: &Path) -> Result<StorageAnchor, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", canonical.display()));
    }
    let output = Command::new("df")
        .args(["-B1", "--output=avail,fstype,target"])
        .arg(&canonical)
        .output()
        .map_err(|error| format!("run df for {}: {error}", canonical.display()))?;
    if !output.status.success() {
        return Err(format!("df failed for {}", canonical.display()));
    }
    let text = String::from_utf8(output.stdout).map_err(|error| format!("decode df: {error}"))?;
    let values = text
        .lines()
        .nth(1)
        .ok_or_else(|| format!("df returned no data for {}", canonical.display()))?
        .split_whitespace()
        .collect::<Vec<_>>();
    if values.len() < 3 {
        return Err(format!("df output incomplete for {}", canonical.display()));
    }
    let available_bytes =
        values[0].parse::<u64>().map_err(|error| format!("parse df available bytes: {error}"))?;
    Ok(StorageAnchor {
        path: canonical.display().to_string(),
        filesystem_type: values[1].to_owned(),
        mount_point: values[2..].join(" "),
        available_bytes,
    })
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("execute {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed with {:?}: {}",
            args.join(" "),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("decode {program} output: {error}"))?
        .trim()
        .to_owned();
    if text.is_empty() {
        return Err(format!("{program} {} returned an empty result", args.join(" ")));
    }
    Ok(text)
}

fn git_dirty() -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("execute git status: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git status failed with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(!output.stdout.is_empty())
}

fn exact_pod_guard() -> Result<MachineRecord, String> {
    if env::var("VOLTA_X4C_EXACT_PROBE_APPROVED").as_deref() != Ok("1") {
        return Err(
            "--exact-pod requires VOLTA_X4C_EXACT_PROBE_APPROVED=1 after separate pod provisioning approval"
                .to_owned(),
        );
    }
    let provider = env::var("VOLTA_CLOUD_PROVIDER")
        .map_err(|_| "VOLTA_CLOUD_PROVIDER is required".to_owned())?;
    let gpu = env::var("VOLTA_CLOUD_GPU_SKU")
        .map_err(|_| "VOLTA_CLOUD_GPU_SKU is required".to_owned())?;
    let memory_bytes = memtotal_bytes()?;
    let rayon_threads = env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| "RAYON_NUM_THREADS=8 is required".to_owned())?;
    let commit_seal_open_unpinned =
        env::var("VOLTA_X4C_COMMIT_SEAL_OPEN_UNPINNED").as_deref() == Ok("1");
    let persistent = env::var("VOLTA_X4C_PERSISTENT_DIR")
        .map_err(|_| "VOLTA_X4C_PERSISTENT_DIR is required".to_owned())?;
    let persistent_class = env::var("VOLTA_X4C_PERSISTENT_CLASS")
        .map_err(|_| "VOLTA_X4C_PERSISTENT_CLASS=PERSISTENT is required".to_owned())?;
    let local = env::var("VOLTA_X4C_LOCAL_STORAGE_DIR")
        .map_err(|_| "VOLTA_X4C_LOCAL_STORAGE_DIR is required".to_owned())?;
    let persistent_volume = storage_anchor(Path::new(&persistent))?;
    let local_non_mfs_storage = storage_anchor(Path::new(&local))?;
    let tree_dirty = git_dirty()?;
    if provider != "RunPod"
        || !gpu.contains("A100-SXM4-80GB")
        || memory_bytes < MIN_HOST_RAM_BYTES
        || rayon_threads != 8
        || !commit_seal_open_unpinned
        || persistent_class != "PERSISTENT"
        || local_non_mfs_storage.available_bytes < MIN_LOCAL_STORAGE_BYTES
        || matches!(local_non_mfs_storage.filesystem_type.as_str(), "tmpfs" | "ramfs" | "mfs")
        || persistent_volume.mount_point == local_non_mfs_storage.mount_point
        || tree_dirty
    {
        return Err(
            "exact probe refused: requires RunPod A100-SXM4-80GB, >=256 GiB actual RAM, RAYON_NUM_THREADS=8, unpinned commit/seal/open, distinct PERSISTENT and >=150 GB local non-mfs storage, and a clean tree"
                .to_owned(),
        );
    }
    Ok(MachineRecord {
        provider,
        gpu,
        memory_bytes,
        rayon_threads,
        commit_seal_open_unpinned,
        durable_tier: "coefficients_plus_five_roots_on_persistent".to_owned(),
        local_storage_role: "scratch_ram_spill_and_records".to_owned(),
        persistent_class,
        persistent_volume,
        local_non_mfs_storage,
    })
}

fn smoke_machine() -> MachineRecord {
    MachineRecord {
        provider: "local-smoke".to_owned(),
        gpu: "none".to_owned(),
        memory_bytes: memtotal_bytes().unwrap_or(0),
        rayon_threads: env::var("RAYON_NUM_THREADS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        commit_seal_open_unpinned: true,
        durable_tier: "coefficients_plus_five_roots_on_persistent".to_owned(),
        local_storage_role: "scratch_ram_spill_and_records".to_owned(),
        persistent_class: "not-applicable".to_owned(),
        persistent_volume: StorageAnchor {
            path: "not-applicable".to_owned(),
            filesystem_type: "not-applicable".to_owned(),
            mount_point: "not-applicable-persistent".to_owned(),
            available_bytes: 0,
        },
        local_non_mfs_storage: StorageAnchor {
            path: "not-applicable".to_owned(),
            filesystem_type: "not-applicable".to_owned(),
            mount_point: "not-applicable-local".to_owned(),
            available_bytes: 0,
        },
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ImmutableRecord {
    protocol_profile: String,
    rate: String,
    query_count: u64,
    pcs_bytes: u64,
    response_bytes: u64,
    proof_format_changed: bool,
    root_changed: bool,
    lean_changed: bool,
    soundness_changed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProbeRecord {
    schema: u64,
    milestone: String,
    phase: u64,
    date: String,
    git_sha: String,
    git_dirty: bool,
    pod_profile: String,
    mode: String,
    pod_contacted: bool,
    machine: MachineRecord,
    immutable: ImmutableRecord,
    geometry: PayloadGeometry,
    warmup_count_per_variant: usize,
    measured_candidates_per_variant: usize,
    child_process_isolation: bool,
    variants: Vec<VariantRecord>,
    all_accepted: bool,
    hard_stop_before_x4c_online: bool,
}

fn run_record(exact: bool) -> Result<ProbeRecord, String> {
    let domain_log2 = if exact { EXACT_DOMAIN_LOG2 } else { SMOKE_DOMAIN_LOG2 };
    let machine = if exact { exact_pod_guard()? } else { smoke_machine() };
    let probe_geometry = geometry(domain_log2).expect("valid geometry");
    if exact
        && (probe_geometry.fold_codeword_bytes != X4C_PRODUCTION_FOLD_CODEWORD_BYTES
            || probe_geometry.fold_outer_cache_bytes != X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES
            || probe_geometry.populated_bytes != X4C_PRODUCTION_SEALED_STATE_BYTES)
    {
        return Err("exact production lifecycle geometry changed".to_owned());
    }
    let mut variants = Vec::with_capacity(Variant::ALL.len());
    for variant in Variant::ALL {
        variants.push(variant_record(domain_log2, variant)?);
    }
    let all_accepted = variants.iter().all(|variant| variant.all_accepted);
    Ok(ProbeRecord {
        schema: SCHEMA,
        milestone: MILESTONE.to_owned(),
        phase: 2,
        date: command_output("date", &["+%Y-%m-%d"])?,
        git_sha: command_output("git", &["rev-parse", "HEAD"])?,
        git_dirty: git_dirty()?,
        pod_profile: POD_PROFILE.to_owned(),
        mode: if exact { "exact_pod" } else { "local_smoke" }.to_owned(),
        pod_contacted: exact,
        machine,
        immutable: ImmutableRecord {
            protocol_profile: PROTOCOL_PROFILE.to_owned(),
            rate: "1/8".to_owned(),
            query_count: 111,
            pcs_bytes: 2_683_236,
            response_bytes: 43_953_700,
            proof_format_changed: false,
            root_changed: false,
            lean_changed: false,
            soundness_changed: false,
        },
        geometry: probe_geometry,
        warmup_count_per_variant: WARMUP_COUNT,
        measured_candidates_per_variant: MEASURED_CANDIDATES,
        child_process_isolation: true,
        variants,
        all_accepted,
        hard_stop_before_x4c_online: exact,
    })
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_data().map_err(|error| format!("sync {}: {error}", path.display()))
}

fn exact_output_guard(path: &Path) -> Result<(), String> {
    let local = env::var("VOLTA_X4C_LOCAL_STORAGE_DIR")
        .map_err(|_| "VOLTA_X4C_LOCAL_STORAGE_DIR is required".to_owned())?;
    let local = fs::canonicalize(local)
        .map_err(|error| format!("canonicalize local record tier: {error}"))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("canonicalize output parent {}: {error}", parent.display()))?;
    if !parent.starts_with(&local) {
        return Err(format!(
            "exact probe record must be created under local non-mfs record tier {}",
            local.display()
        ));
    }
    Ok(())
}

fn usage() -> &'static str {
    "usage: x4c_lifecycle_probe --smoke | --exact-pod --output <new.json>"
}

fn real_main() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|argument| argument == "--child") {
        return run_child_mode(&args);
    }
    let exact = args.iter().any(|argument| argument == "--exact-pod");
    let smoke = args.iter().any(|argument| argument == "--smoke");
    if exact == smoke {
        return Err(usage().to_owned());
    }
    let output =
        args.windows(2).find(|pair| pair[0] == "--output").map(|pair| PathBuf::from(&pair[1]));
    if exact && output.is_none() {
        return Err("--exact-pod requires --output and never emits an unanchored record".to_owned());
    }
    if exact {
        exact_output_guard(output.as_ref().expect("checked exact output"))?;
    }
    let record = run_record(exact)?;
    if !record.all_accepted {
        return Err("one or more lifecycle candidates failed internal accounting".to_owned());
    }
    let mut bytes =
        serde_json::to_vec_pretty(&record).map_err(|error| format!("serialize record: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        write_create_new(&path, &bytes)?;
        println!("wrote {}", path.display());
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("write smoke record: {error}"))?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("x4c_lifecycle_probe: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_geometry_matches_frozen_payload() {
        let exact = geometry(EXACT_DOMAIN_LOG2).unwrap();
        assert_eq!(exact.fold_rounds, 27);
        assert_eq!(exact.fold_codeword_bytes, X4C_PRODUCTION_FOLD_CODEWORD_BYTES);
        assert_eq!(exact.fold_outer_cache_bytes, X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES);
        assert_eq!(exact.populated_bytes, X4C_PRODUCTION_SEALED_STATE_BYTES);
    }

    #[test]
    fn tiny_categorized_and_arena_paths_reconcile() {
        let categorized = run_distributed_candidate(8, 1, true, Variant::CategorizedDrop);
        assert!(categorized.accepted);
        let expected = geometry(8).unwrap();
        assert_eq!(
            categorized.boundaries[2].sealed_ownership.fold_outer_cache_bytes,
            expected.fold_outer_cache_bytes
        );
        assert_eq!(categorized.boundaries.last().unwrap().sealed_ownership.ordinary_host_bytes, 0);

        let arena = run_arena_candidate(8, 1, true);
        assert!(arena.accepted);
        assert_eq!(
            arena.boundaries[2].sealed_ownership.other_ordinary_host_bytes,
            expected.populated_bytes
        );
        assert_eq!(arena.outstanding_payload_bytes_after_teardown, 0);
    }

    #[test]
    fn exact_mode_refuses_without_separate_approval_anchor() {
        if env::var("VOLTA_X4C_EXACT_PROBE_APPROVED").as_deref() != Ok("1") {
            let error = exact_pod_guard().unwrap_err();
            assert!(error.contains("separate pod provisioning approval"));
        }
    }
}
