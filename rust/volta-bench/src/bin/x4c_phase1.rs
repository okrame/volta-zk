//! X4c Phase-1 local lifecycle decomposition and counter postdiction.
//!
//! This binary is deliberately CPU-only and synthetic. It records the four
//! timing categories added to `SealedGlobalChainV4::issue_queries`, checks the
//! exact X4b I/O identities, and projects (without fitting) the measured local
//! sealed-state teardown rate to the production byte count. It neither
//! implements the X4c direct-fold design nor contacts a pod.

use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use volta_field::{Fp, Fp2};
use volta_pcs::x4::{
    global_fold_descriptor_digest_v4, verify_global_folding_v4, CohortIdentityV4,
    CohortVerifierConfigV4, CommittedModelGlobalCohortV4, GlobalChainDraftV4,
    GlobalFoldChallengesV4, GlobalOpenMetricsV4, GlobalProverGroupV4, OracleKindV4,
};

const DATE: &str = "2026-07-23";
const MILESTONE: &str = "X4c-phase1-open-lifecycle-postdiction";
const X4C_PREREGISTRATION_V1_SHA256: &str =
    "7d4f8254b066b91fea9ee52fbef0f0008632adccceef1513d3d3478eeea3a52a";
const X4C_DESIGN_SHA256: &str = "1a744625078e3ffe5772b040c24854e9510dcedebc906416279cf3a7c29bf191";
const X4B_RECORD: &str = "benchmarks/results/x4b-a100-production-2026-07-22-6c6907a.json";
const X4B_RECORD_SHA256: &str = "63f4a97b263e4d09649d5a6ede5af1ba420efdcc78bb30f54b9f8cf200cfe6e0";
const X4B_WEXT_WALL_S: f64 = 254.861_527_720;
const X4B_OPEN_WALL_S: f64 = 6.683_486_611;
const X4B_POD_NO_TEARDOWN_OPEN_ANCHOR_S: f64 = 0.109_631_491;
const PRODUCTION_FOLD_CODEWORD_BYTES: u64 = 17_179_869_056;
const PRODUCTION_FOLD_OUTER_CACHE_BYTES: u64 = 34_359_737_248;
const SYNTHETIC_DOMAIN_LOG2: [u8; 4] = [16, 18, 20, 22];
const MEASURED_CANDIDATES: usize = 5;
const QUERY_COUNT: usize = 111;

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: `ptr` and `layout` are the pair received from the caller.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        DEALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn reset_allocator_counters() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    REALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
    DEALLOCATED_BYTES.store(0, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Serialize)]
struct AllocatorRow {
    allocations: u64,
    reallocations: u64,
    deallocations: u64,
    cumulative_requested_bytes: u64,
    cumulative_deallocated_bytes: u64,
}

fn allocator_row() -> AllocatorRow {
    AllocatorRow {
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        reallocations: REALLOCATIONS.load(Ordering::Relaxed),
        deallocations: DEALLOCATIONS.load(Ordering::Relaxed),
        cumulative_requested_bytes: REQUESTED_BYTES.load(Ordering::Relaxed),
        cumulative_deallocated_bytes: DEALLOCATED_BYTES.load(Ordering::Relaxed),
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
struct TimingRow {
    query_gather_wall_ns: u64,
    hashing_path_assembly_wall_ns: u64,
    encode_serialize_wall_ns: u64,
    teardown_wall_ns: u64,
    instrumented_total_wall_ns: u64,
    caller_wall_ns: u64,
}

impl TimingRow {
    fn from_metrics(metrics: &GlobalOpenMetricsV4, caller_wall_ns: u64) -> Self {
        Self {
            query_gather_wall_ns: metrics.issue_queries_query_gather_wall_ns,
            hashing_path_assembly_wall_ns: metrics.issue_queries_hashing_path_assembly_wall_ns,
            encode_serialize_wall_ns: metrics.issue_queries_encode_serialize_wall_ns,
            teardown_wall_ns: metrics.issue_queries_teardown_wall_ns,
            instrumented_total_wall_ns: metrics.issue_queries_total_wall_ns,
            caller_wall_ns,
        }
    }
}

#[derive(Debug, Serialize)]
struct CandidateRow {
    ordinal: usize,
    sealed_fold_codeword_bytes: u64,
    sealed_fold_outer_cache_bytes: u64,
    sealed_state_bytes: u64,
    sealed_fold_tree_count: u64,
    sealed_fold_outer_level_vectors: u64,
    timing: TimingRow,
    allocator: AllocatorRow,
    accepted: bool,
    canonical_proof_bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct SelectedTimingRow {
    query_gather_wall_ns: u64,
    hashing_path_assembly_wall_ns: u64,
    encode_serialize_wall_ns: u64,
    teardown_wall_ns: u64,
    instrumented_total_wall_ns: u64,
    caller_wall_ns: u64,
}

#[derive(Debug, Serialize)]
struct ScaleRow {
    domain_log2: u8,
    outer_len: u64,
    warmup_count: usize,
    measured_candidates: usize,
    candidates: Vec<CandidateRow>,
    selected_upper_median: SelectedTimingRow,
    all_accepted: bool,
    exact_state_accounting: bool,
}

#[derive(Debug, Serialize)]
struct MachineRow {
    architecture: String,
    kernel: String,
    logical_parallelism: usize,
    rayon_threads: usize,
    memory_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ImmutableRow {
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

#[derive(Debug, Serialize)]
struct InstrumentationContractRow {
    query_gather: String,
    hashing_path_assembly: String,
    encode_serialize: String,
    teardown: String,
    timer_unit: String,
    proof_or_transcript_effect: String,
}

#[derive(Debug, Serialize)]
struct IoPostdictionRow {
    source_record: String,
    source_record_sha256: String,
    selected_wall_s: f64,
    coefficient_bytes: u64,
    oracle_bytes: u64,
    staging_bytes_read: u64,
    staging_bytes_written: u64,
    modeled_host_read_bytes: u64,
    modeled_host_write_bytes: u64,
    modeled_physical_io_bytes: u64,
    observed_process_read_bytes: u64,
    observed_process_write_bytes: u64,
    observed_physical_io_bytes: u64,
    reconciliation_delta_bytes: u64,
    observed_aggregate_bytes_per_s: f64,
    postdicted_wall_s: f64,
    postdiction_residual_s: f64,
    h2d_bytes: u64,
    d2h_bytes: u64,
    pcie_transfer_bytes: u64,
    model_policy: String,
}

#[derive(Debug, Serialize)]
struct OpenPostdictionRow {
    observed_open_wall_s: f64,
    same_host_exact_geometry_no_sealed_state_anchor_s: f64,
    implied_lifecycle_debt_s: f64,
    implied_lifecycle_share: f64,
    issue_query_oracle_bytes_read: u64,
    issue_query_outer_cache_bytes_read: u64,
    inner_trees_rebuilt: u64,
    sealed_fold_codeword_bytes: u64,
    sealed_fold_outer_cache_bytes: u64,
    sealed_state_bytes: u64,
    lifecycle_debt_dominance_threshold_s: f64,
    hypothesis_decision_rule: String,
    hypothesis_disposition_code: String,
    hypothesis_disposition: String,
}

#[derive(Debug, Serialize)]
struct ProjectionRow {
    policy: String,
    source_domain_log2: u8,
    source_sealed_state_bytes: u64,
    production_sealed_state_bytes: u64,
    byte_scale: f64,
    projected_teardown_wall_s: f64,
    projected_teardown_wall_s_low: f64,
    projected_teardown_wall_s_high: f64,
    projected_teardown_share_of_lifecycle_debt: f64,
    projected_teardown_share_of_lifecycle_debt_low: f64,
    projected_teardown_share_of_lifecycle_debt_high: f64,
    same_host_no_teardown_anchor_s: f64,
    projected_total_open_wall_s: f64,
    observed_x4b_open_wall_s: f64,
    hardware_transfer_warning: String,
}

#[derive(Debug, Serialize)]
struct Phase1Record {
    schema: u64,
    milestone: String,
    date: String,
    git_sha: String,
    git_short_sha: String,
    git_dirty: bool,
    phase: u64,
    pod_contacted: bool,
    preregistration_v1_sha256: String,
    design_sha256: String,
    interpretation_correction: String,
    machine: MachineRow,
    immutable: ImmutableRow,
    instrumentation: InstrumentationContractRow,
    io_postdiction: IoPostdictionRow,
    open_postdiction: OpenPostdictionRow,
    synthetic_scales: Vec<ScaleRow>,
    analytic_pod_scale_projection: ProjectionRow,
    hard_stop: String,
}

fn symbol(value: u64) -> Fp2 {
    Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(7).wrapping_add(11)))
}

fn source(domain_log2: u8) -> CommittedModelGlobalCohortV4 {
    let outer_len = 1usize << domain_log2;
    let coefficient_len = outer_len / 8;
    let mut descriptor = [0u8; 32];
    descriptor[..8].copy_from_slice(&(u64::from(domain_log2) + 1).to_le_bytes());
    let coefficients = (0..coefficient_len)
        .map(|index| symbol(index as u64 + 101 * u64::from(domain_log2)))
        .collect::<Vec<_>>();
    CommittedModelGlobalCohortV4::commit(
        CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xC400_0000 + u32::from(domain_log2),
                oracle_kind: OracleKindV4::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some(descriptor)],
            outer_len,
            expected_symbol_count: 1,
        },
        vec![Some(coefficients)],
    )
    .unwrap()
}

fn common_point(domain_log2: u8) -> Vec<Fp2> {
    (0..usize::from(domain_log2 - 3)).map(|index| symbol(1_003 + 2 * index as u64)).collect()
}

fn fold_challenges(domain_log2: u8) -> GlobalFoldChallengesV4 {
    GlobalFoldChallengesV4 {
        folds: (0..usize::from(domain_log2 - 3))
            .map(|index| symbol(2_003 + 4 * index as u64))
            .collect(),
    }
}

fn query_draws(domain_log2: u8) -> Vec<u64> {
    let mask = (1u64 << domain_log2) - 1;
    (0..QUERY_COUNT)
        .map(|index| {
            (0x9E37_79B9_7F4A_7C15u64.wrapping_mul(index as u64 + 1)
                ^ (u64::from(domain_log2) << 41))
                & mask
        })
        .collect()
}

fn as_u64_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap()
}

fn run_candidate(
    committed: &CommittedModelGlobalCohortV4,
    domain_log2: u8,
    ordinal: usize,
) -> CandidateRow {
    let point = common_point(domain_log2);
    let challenges = fold_challenges(domain_log2);
    let draws = query_draws(domain_log2);
    let groups = vec![GlobalProverGroupV4 {
        cohort: committed,
        touched_slots: vec![0],
        weights: vec![symbol(3_001)],
        target_point: point.clone(),
        activation_challenge: symbol(4_001),
    }];
    let descriptor = global_fold_descriptor_digest_v4(&[(
        committed.commitment().config.identity.cohort_id,
        committed.commitment().root,
    )]);
    let epoch = 0x5844_0000 + ordinal as u64;
    let sealed = GlobalChainDraftV4::new(
        [0xC4; 32],
        epoch,
        0xC400_F001,
        descriptor,
        point.clone(),
        groups,
        challenges.clone(),
    )
    .unwrap()
    .seal()
    .unwrap();

    reset_allocator_counters();
    let caller_started = Instant::now();
    let (proof, verifier_groups, metrics) = sealed.issue_queries(draws.clone()).unwrap();
    let caller_wall_ns = as_u64_ns(caller_started);
    let allocator = allocator_row();
    let accepted = verify_global_folding_v4(
        [0xC4; 32],
        epoch,
        &point,
        &verifier_groups,
        &challenges,
        &draws,
        &proof,
    )
    .is_ok();
    let canonical_proof_bytes = u64::try_from(proof.canonical_bytes().unwrap().len()).unwrap();
    let sealed_state_bytes = metrics
        .sealed_fold_codeword_bytes
        .checked_add(metrics.sealed_fold_outer_cache_bytes)
        .unwrap();
    CandidateRow {
        ordinal,
        sealed_fold_codeword_bytes: metrics.sealed_fold_codeword_bytes,
        sealed_fold_outer_cache_bytes: metrics.sealed_fold_outer_cache_bytes,
        sealed_state_bytes,
        sealed_fold_tree_count: metrics.sealed_fold_tree_count,
        sealed_fold_outer_level_vectors: metrics.sealed_fold_outer_level_vectors,
        timing: TimingRow::from_metrics(&metrics, caller_wall_ns),
        allocator,
        accepted,
        canonical_proof_bytes,
    }
}

fn upper_median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn selected_timing(candidates: &[CandidateRow]) -> SelectedTimingRow {
    SelectedTimingRow {
        query_gather_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.query_gather_wall_ns).collect(),
        ),
        hashing_path_assembly_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.hashing_path_assembly_wall_ns).collect(),
        ),
        encode_serialize_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.encode_serialize_wall_ns).collect(),
        ),
        teardown_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.teardown_wall_ns).collect(),
        ),
        instrumented_total_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.instrumented_total_wall_ns).collect(),
        ),
        caller_wall_ns: upper_median(
            candidates.iter().map(|row| row.timing.caller_wall_ns).collect(),
        ),
    }
}

fn exact_state_bytes(domain_log2: u8) -> (u64, u64) {
    let outer_len = 1u64 << domain_log2;
    let rounds = u64::from(domain_log2 - 3);
    let codeword = (outer_len - 8) * 16;
    let outer_cache = (outer_len - 8 - rounds) * 32;
    (codeword, outer_cache)
}

fn run_scale(domain_log2: u8) -> ScaleRow {
    let committed = source(domain_log2);
    let _warmup = run_candidate(&committed, domain_log2, 0);
    let candidates = (1..=MEASURED_CANDIDATES)
        .map(|ordinal| run_candidate(&committed, domain_log2, ordinal))
        .collect::<Vec<_>>();
    let expected = exact_state_bytes(domain_log2);
    let exact_state_accounting = candidates.iter().all(|row| {
        row.sealed_fold_codeword_bytes == expected.0
            && row.sealed_fold_outer_cache_bytes == expected.1
            && row.sealed_state_bytes == expected.0 + expected.1
    });
    let all_accepted = candidates.iter().all(|row| row.accepted);
    assert!(exact_state_accounting && all_accepted);
    let selected_upper_median = selected_timing(&candidates);
    ScaleRow {
        domain_log2,
        outer_len: 1u64 << domain_log2,
        warmup_count: 1,
        measured_candidates: candidates.len(),
        candidates,
        selected_upper_median,
        all_accepted,
        exact_state_accounting,
    }
}

fn command(args: &[&str]) -> String {
    let output = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(output.status.success(), "command failed: {args:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn git(args: &[&str]) -> String {
    let root = repo_root();
    let mut command_args = vec!["git", "-C", root.to_str().unwrap()];
    command_args.extend_from_slice(args);
    command(&command_args)
}

fn memory_bytes() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .unwrap()
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix("MemTotal:")?.trim().strip_suffix(" kB")?.trim();
            Some(value.parse::<u64>().unwrap() * 1024)
        })
        .unwrap()
}

fn io_postdiction() -> IoPostdictionRow {
    let coefficient_bytes = 4_294_967_296;
    let oracle_bytes = 34_359_738_368;
    let staging_bytes_read = 68_719_476_672;
    let staging_bytes_written = 68_719_476_704;
    let modeled_host_read_bytes = oracle_bytes + staging_bytes_read;
    let modeled_host_write_bytes = coefficient_bytes + oracle_bytes + staging_bytes_written + 32;
    let modeled_physical_io_bytes = modeled_host_read_bytes + modeled_host_write_bytes;
    let observed_process_read_bytes = 103_079_235_584;
    let observed_process_write_bytes = 107_374_211_072;
    let observed_physical_io_bytes = observed_process_read_bytes + observed_process_write_bytes;
    let observed_aggregate_bytes_per_s = observed_physical_io_bytes as f64 / X4B_WEXT_WALL_S;
    let postdicted_wall_s = modeled_physical_io_bytes as f64 / observed_aggregate_bytes_per_s;
    IoPostdictionRow {
        source_record: X4B_RECORD.to_owned(),
        source_record_sha256: X4B_RECORD_SHA256.to_owned(),
        selected_wall_s: X4B_WEXT_WALL_S,
        coefficient_bytes,
        oracle_bytes,
        staging_bytes_read,
        staging_bytes_written,
        modeled_host_read_bytes,
        modeled_host_write_bytes,
        modeled_physical_io_bytes,
        observed_process_read_bytes,
        observed_process_write_bytes,
        observed_physical_io_bytes,
        reconciliation_delta_bytes: observed_physical_io_bytes - modeled_physical_io_bytes,
        observed_aggregate_bytes_per_s,
        postdicted_wall_s,
        postdiction_residual_s: X4B_WEXT_WALL_S - postdicted_wall_s,
        h2d_bytes: 107_374_217_152,
        d2h_bytes: 103_079_215_072,
        pcie_transfer_bytes: 210_453_432_224,
        model_policy: "counter identity with one observed aggregate physical-I/O rate; no fitted category coefficients".to_owned(),
    }
}

fn record() -> Phase1Record {
    assert_ne!(X4C_DESIGN_SHA256, "__X4C_DESIGN_SHA256__");
    let status = git(&["status", "--porcelain", "--untracked-files=normal"]);
    assert!(status.is_empty(), "X4c Phase-1 record requires a clean tracked tree");
    let git_sha = git(&["rev-parse", "HEAD"]);
    let git_short_sha = git(&["rev-parse", "--short", "HEAD"]);
    let synthetic_scales = SYNTHETIC_DOMAIN_LOG2.into_iter().map(run_scale).collect::<Vec<_>>();
    let largest = synthetic_scales.last().unwrap();
    let source_state_bytes = largest.candidates[0].sealed_state_bytes;
    let production_state_bytes = PRODUCTION_FOLD_CODEWORD_BYTES + PRODUCTION_FOLD_OUTER_CACHE_BYTES;
    let byte_scale = production_state_bytes as f64 / source_state_bytes as f64;
    let teardown_candidates =
        largest.candidates.iter().map(|row| row.timing.teardown_wall_ns).collect::<Vec<_>>();
    let projected_teardown_wall_s =
        largest.selected_upper_median.teardown_wall_ns as f64 * byte_scale / 1e9;
    let projected_teardown_wall_s_low =
        *teardown_candidates.iter().min().unwrap() as f64 * byte_scale / 1e9;
    let projected_teardown_wall_s_high =
        *teardown_candidates.iter().max().unwrap() as f64 * byte_scale / 1e9;
    let implied_lifecycle_debt_s = X4B_OPEN_WALL_S - X4B_POD_NO_TEARDOWN_OPEN_ANCHOR_S;
    let dominance_threshold_s = implied_lifecycle_debt_s / 2.0;
    let (hypothesis_disposition_code, hypothesis_disposition) = if projected_teardown_wall_s_high
        < dominance_threshold_s
    {
        (
                "REFUTED_LOCAL_SYNTHETIC_DIRECT_PROJECTION",
                format!(
                    "REFUTED at the Phase-1 evidence level: the selected direct byte-scaled teardown is {projected_teardown_wall_s:.9} s and the five-candidate sensitivity interval is {projected_teardown_wall_s_low:.9}--{projected_teardown_wall_s_high:.9} s; even its high endpoint is below the {dominance_threshold_s:.9}-s dominance threshold. The measured {implied_lifecycle_debt_s:.9}-s lifecycle gap remains real, but ordinary sealed-state container destruction does not postdict it and its cause remains unresolved pending production-host instrumentation"
                ),
            )
    } else if projected_teardown_wall_s_low > dominance_threshold_s {
        (
                "CONFIRMED_LOCAL_SYNTHETIC_DIRECT_PROJECTION",
                format!(
                    "CONFIRMED at the Phase-1 evidence level: even the low endpoint {projected_teardown_wall_s_low:.9} s exceeds the {dominance_threshold_s:.9}-s dominance threshold; this remains an analytic local-to-pod projection rather than a production-host result"
                ),
            )
    } else {
        (
                "INCONCLUSIVE_LOCAL_SYNTHETIC_DIRECT_PROJECTION",
                format!(
                    "INCONCLUSIVE at the Phase-1 evidence level: the five-candidate direct-projection interval {projected_teardown_wall_s_low:.9}--{projected_teardown_wall_s_high:.9} s crosses the {dominance_threshold_s:.9}-s dominance threshold; production-host instrumentation is required"
                ),
            )
    };

    Phase1Record {
        schema: 2,
        milestone: MILESTONE.to_owned(),
        date: DATE.to_owned(),
        git_sha,
        git_short_sha,
        git_dirty: false,
        phase: 1,
        pod_contacted: false,
        preregistration_v1_sha256: X4C_PREREGISTRATION_V1_SHA256.to_owned(),
        design_sha256: X4C_DESIGN_SHA256.to_owned(),
        interpretation_correction: "schema 1 predeclared CONFIRMED before measurement and is retained as an ineligible diagnostic; schema 2 derives the disposition from the unchanged five-candidate direct-projection interval and the explicit >50% lifecycle-debt rule".to_owned(),
        machine: MachineRow {
            architecture: std::env::consts::ARCH.to_owned(),
            kernel: command(&["uname", "-srmo"]),
            logical_parallelism: std::thread::available_parallelism().unwrap().get(),
            rayon_threads: rayon::current_num_threads(),
            memory_bytes: memory_bytes(),
        },
        immutable: ImmutableRow {
            protocol_profile: "x4-zkdeepfold-ud-e29-v4".to_owned(),
            rate: "1/8".to_owned(),
            query_count: 111,
            pcs_bytes: 2_683_236,
            response_bytes: 43_953_700,
            proof_format_changed: false,
            root_changed: false,
            lean_changed: false,
            soundness_changed: false,
        },
        instrumentation: InstrumentationContractRow {
            query_gather: "draw validation plus canonical verifier-owned opening schedule construction".to_owned(),
            hashing_path_assembly: "all source/tree open calls: queried symbol and cached-digest reads, inner-tree hashing, and ordered sibling-path assembly".to_owned(),
            encode_serialize: "schedule digest, packed-opening structural validation, and one canonical packed-frame encode".to_owned(),
            teardown: "explicit destruction of residual sealed round trees, prover groups, common point, challenges, and query schedule before issue_queries returns".to_owned(),
            timer_unit: "host monotonic wall nanoseconds (std::time::Instant)".to_owned(),
            proof_or_transcript_effect: "none; timing and state-byte counters are out-of-band metrics".to_owned(),
        },
        io_postdiction: io_postdiction(),
        open_postdiction: OpenPostdictionRow {
            observed_open_wall_s: X4B_OPEN_WALL_S,
            same_host_exact_geometry_no_sealed_state_anchor_s:
                X4B_POD_NO_TEARDOWN_OPEN_ANCHOR_S,
            implied_lifecycle_debt_s,
            implied_lifecycle_share: implied_lifecycle_debt_s / X4B_OPEN_WALL_S,
            issue_query_oracle_bytes_read: 724_608,
            issue_query_outer_cache_bytes_read: 507_008,
            inner_trees_rebuilt: 2_220,
            sealed_fold_codeword_bytes: PRODUCTION_FOLD_CODEWORD_BYTES,
            sealed_fold_outer_cache_bytes: PRODUCTION_FOLD_OUTER_CACHE_BYTES,
            sealed_state_bytes: production_state_bytes,
            lifecycle_debt_dominance_threshold_s: dominance_threshold_s,
            hypothesis_decision_rule: "dominant means >50% of implied lifecycle debt; REFUTED if the largest direct byte-scaled candidate is below the threshold, CONFIRMED if the smallest is above it, otherwise INCONCLUSIVE; no regression or fitted intercept".to_owned(),
            hypothesis_disposition_code: hypothesis_disposition_code.to_owned(),
            hypothesis_disposition,
        },
        analytic_pod_scale_projection: ProjectionRow {
            policy: "direct byte-ratio projection from the largest synthetic scale; no regression or fitted intercept".to_owned(),
            source_domain_log2: largest.domain_log2,
            source_sealed_state_bytes: source_state_bytes,
            production_sealed_state_bytes: production_state_bytes,
            byte_scale,
            projected_teardown_wall_s,
            projected_teardown_wall_s_low,
            projected_teardown_wall_s_high,
            projected_teardown_share_of_lifecycle_debt:
                projected_teardown_wall_s / implied_lifecycle_debt_s,
            projected_teardown_share_of_lifecycle_debt_low:
                projected_teardown_wall_s_low / implied_lifecycle_debt_s,
            projected_teardown_share_of_lifecycle_debt_high:
                projected_teardown_wall_s_high / implied_lifecycle_debt_s,
            same_host_no_teardown_anchor_s: X4B_POD_NO_TEARDOWN_OPEN_ANCHOR_S,
            projected_total_open_wall_s:
                projected_teardown_wall_s + X4B_POD_NO_TEARDOWN_OPEN_ANCHOR_S,
            observed_x4b_open_wall_s: X4B_OPEN_WALL_S,
            hardware_transfer_warning: "analytic projection only: local aarch64/System allocator and kernel page-table teardown are not a pod A100-host measurement".to_owned(),
        },
        synthetic_scales,
        hard_stop: "PHASE 1 COMPLETE ONLY; no X4c direct-fold/GPU-resident/RAM-oracle/arena implementation and no pod access".to_owned(),
    }
}

fn main() {
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["--record"]);
    let record = record();
    let path = repo_root()
        .join("benchmarks/results")
        .join(format!("x4c-phase1-open-decomposition-{}-{}.json", DATE, record.git_short_sha));
    assert!(!path.exists(), "append-only X4c record already exists: {}", path.display());
    let mut bytes = serde_json::to_vec_pretty(&record).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    println!("{}", path.strip_prefix(repo_root()).unwrap().display());
}
