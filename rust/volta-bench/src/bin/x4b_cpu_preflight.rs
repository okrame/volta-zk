//! Local X4b CPU preflight for the frozen `runpod-a100-x4b-v1` profile.
//!
//! The aux17 benchmark times the complete one-worker canonical node
//! pipeline (serialization, pipeline allocations and hashing), never a
//! pre-encoded hash loop.  The opening preflight uses sparse files with the
//! exact GPT-2 logical lengths and executes every real query-coordinate read,
//! inner rebuild and outer-cache access for all five initial cohorts and 27
//! fold rounds.  Sparse allocation is a local-fixture device only; operation
//! counts, codec bytes and domain depths are production-exact.

use rayon::ThreadPoolBuilder;
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::fs::OpenOptions;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use volta_field::Fp2;
use volta_pcs::x4::{
    profile_digest_v4, reconstruct_fold_round_packed_opening_root_v4,
    reconstruct_initial_packed_opening_root_v4, verify_fold_round_packed_opening_v4,
    verify_initial_packed_opening_v4, CohortIdentityV4, CohortTreeV4, CohortVerifierConfigV4,
    FrameV4, OracleKindV4, OuterCachePolicyV4, PackedBatchOpeningFrameV4, PersistedCohortOpeningV4,
    PersistedOpeningTrafficV4, PersistedOracleBindingV4, SparseOuterNodeCacheV4,
    X4bOpeningSourcePolicyV4,
};

const PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const POD_PROFILE: &str = "runpod-a100-x4b-v1";
const DESIGN_SHA256: &str = "bc057e458041e8123e3ef065d22b74573bcb7238a8dcee239bccfa0e8ff6be01";
const QUERY_XOF_CONTEXT: &str = "volta-zk/x4/amendment5-gpt2-preflight/v1";
const QUERY_XOF_INPUT: &[u8] = b"e29-r3-s111|gpt2-small|102-claims|2026-07-21";
const QUERY_COUNT: usize = 111;
const QUERY_TAPE_BLAKE3: &str = "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299";
const AUX17_OUTER_LEN: usize = 1 << 20;
const AUX17_CANONICAL_FRAME_BYTES: u64 = 460_324_760;
const AUX17_ORACLE_BYTES: u64 = 33_554_432;
const AUX17_HASH_CALLS: u64 = 5_242_879;
const CPU_GATE_BPS_PER_CORE: f64 = 500_000_000.0;
const OPEN_CEILING_S: f64 = 1.50;
const VERIFY_CEILING_S: f64 = 0.25;
const EXPECTED_PACKED_BYTES: u64 = 2_615_414;
const EXPECTED_OPENED_SYMBOLS: u64 = 27_564;
const EXPECTED_SIBLING_DIGESTS: u64 = 67_930;
const NORMAL_OUTER_CACHE_BYTES: u64 = 71_454_161_664;
const DEGRADED_OUTER_CACHE_BYTES: u64 = 35_727_080_320;

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

fn reset_allocations() {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    REALLOCATIONS.store(0, Ordering::Relaxed);
    DEALLOCATIONS.store(0, Ordering::Relaxed);
    REQUESTED_BYTES.store(0, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Serialize)]
struct AllocationSnapshot {
    allocations: u64,
    reallocations: u64,
    deallocations: u64,
    cumulative_requested_bytes: u64,
}

fn allocation_snapshot() -> AllocationSnapshot {
    AllocationSnapshot {
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        reallocations: REALLOCATIONS.load(Ordering::Relaxed),
        deallocations: DEALLOCATIONS.load(Ordering::Relaxed),
        cumulative_requested_bytes: REQUESTED_BYTES.load(Ordering::Relaxed),
    }
}

#[derive(Serialize)]
struct PipelineCandidate {
    wall_s: f64,
    canonical_frame_bytes_per_s: f64,
    oracle_bytes_per_s: f64,
    hash_calls_per_s: f64,
    allocator: AllocationSnapshot,
}

#[derive(Serialize)]
struct CpuPipelineRecord {
    status: String,
    measurement_scope: String,
    pinned_workers: usize,
    warmup_count: usize,
    measured_candidates: usize,
    canonical_frame_bytes: u64,
    logical_oracle_bytes: u64,
    hash_calls: u64,
    candidates: Vec<PipelineCandidate>,
    selected_upper_median_wall_s: f64,
    selected_canonical_frame_bytes_per_s: f64,
    gate_bytes_per_s_per_core: f64,
    local_gate_comparison_only: bool,
    local_gate_met: bool,
    available_parallelism: usize,
    all_local_cores_wall_s: f64,
    all_local_cores_canonical_frame_bytes_per_s: f64,
    root_hex: String,
}

fn descriptor(cohort_id: u32, slot: usize) -> [u8; 32] {
    let mut value = [0u8; 32];
    value[..4].copy_from_slice(&cohort_id.to_le_bytes());
    value[4..12].copy_from_slice(&(slot as u64).to_le_bytes());
    value[12..].fill((slot as u8).wrapping_mul(37).wrapping_add(11));
    value
}

fn config(
    cohort_id: u32,
    oracle_kind: OracleKindV4,
    fold_round: u8,
    domain_log2: u8,
    present_slots: usize,
    structural_slots: usize,
) -> CohortVerifierConfigV4 {
    CohortVerifierConfigV4 {
        identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round },
        slot_descriptors: (0..structural_slots)
            .map(|slot| (slot < present_slots).then(|| descriptor(cohort_id, slot)))
            .collect(),
        outer_len: 1usize << domain_log2,
        expected_symbol_count: 1,
    }
}

fn aux17_symbols() -> Vec<Option<Vec<Fp2>>> {
    vec![Some(vec![Fp2::ZERO; AUX17_OUTER_LEN]), Some(vec![Fp2::ZERO; AUX17_OUTER_LEN])]
}

fn candidate_from_wall(wall_s: f64, allocator: AllocationSnapshot) -> PipelineCandidate {
    PipelineCandidate {
        wall_s,
        canonical_frame_bytes_per_s: AUX17_CANONICAL_FRAME_BYTES as f64 / wall_s,
        oracle_bytes_per_s: AUX17_ORACLE_BYTES as f64 / wall_s,
        hash_calls_per_s: AUX17_HASH_CALLS as f64 / wall_s,
        allocator,
    }
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    values[values.len() / 2]
}

fn run_aux17_pipeline(threads: usize) -> (f64, [u8; 32], AllocationSnapshot) {
    let cfg = config(0xA500_0100, OracleKindV4::Auxiliary, 0, 20, 2, 2);
    let symbols = aux17_symbols();
    let pool = ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    reset_allocations();
    let started = Instant::now();
    let tree = pool.install(|| CohortTreeV4::build_flat(cfg, symbols)).unwrap();
    let wall = started.elapsed().as_secs_f64();
    let allocations = allocation_snapshot();
    (wall, tree.root(), allocations)
}

fn cpu_pipeline_record() -> CpuPipelineRecord {
    let (_, warm_root, _) = run_aux17_pipeline(1);
    let mut candidates = Vec::new();
    for _ in 0..5 {
        let (wall, root, allocations) = run_aux17_pipeline(1);
        assert_eq!(root, warm_root);
        candidates.push(candidate_from_wall(wall, allocations));
    }
    let selected_wall = upper_median(candidates.iter().map(|row| row.wall_s).collect());
    let selected_bps = AUX17_CANONICAL_FRAME_BYTES as f64 / selected_wall;
    let available_parallelism = std::thread::available_parallelism().map(usize::from).unwrap_or(1);
    let (all_cores_wall, all_cores_root, _) = run_aux17_pipeline(available_parallelism);
    assert_eq!(all_cores_root, warm_root);
    CpuPipelineRecord {
        status: "LOCAL_MEASUREMENT_ONLY; runpod-a100-x4b-v1 gate remains pending".to_owned(),
        measurement_scope: "complete aux17 N4 node pipeline: fixed-width canonical serialization + tile/level pipeline allocations + BLAKE3 first-block hash_many and exact lane-specific root compression; NTT and input preparation excluded"
            .to_owned(),
        pinned_workers: 1,
        warmup_count: 1,
        measured_candidates: candidates.len(),
        canonical_frame_bytes: AUX17_CANONICAL_FRAME_BYTES,
        logical_oracle_bytes: AUX17_ORACLE_BYTES,
        hash_calls: AUX17_HASH_CALLS,
        candidates,
        selected_upper_median_wall_s: selected_wall,
        selected_canonical_frame_bytes_per_s: selected_bps,
        gate_bytes_per_s_per_core: CPU_GATE_BPS_PER_CORE,
        local_gate_comparison_only: true,
        local_gate_met: selected_bps >= CPU_GATE_BPS_PER_CORE,
        available_parallelism,
        all_local_cores_wall_s: all_cores_wall,
        all_local_cores_canonical_frame_bytes_per_s: AUX17_CANONICAL_FRAME_BYTES as f64
            / all_cores_wall,
        root_hex: hex(&warm_root),
    }
}

fn query_draws() -> Vec<u64> {
    let mut hasher = blake3::Hasher::new_derive_key(QUERY_XOF_CONTEXT);
    hasher.update(QUERY_XOF_INPUT);
    let mut reader = hasher.finalize_xof();
    let mut draws = Vec::with_capacity(QUERY_COUNT);
    for _ in 0..QUERY_COUNT {
        let mut word = [0u8; 4];
        reader.fill(&mut word);
        draws.push(u64::from(u32::from_le_bytes(word) & ((1u32 << 30) - 1)));
    }
    draws
}

fn logical_oracle_bytes(config: &CohortVerifierConfigV4) -> u64 {
    config.slot_descriptors.iter().flatten().count() as u64 * config.outer_len as u64 * 16
}

fn ensure_sparse_oracle(path: &Path, config: &CohortVerifierConfigV4) {
    let file = OpenOptions::new().create_new(true).write(true).open(path).unwrap();
    file.set_len(logical_oracle_bytes(config)).unwrap();
}

#[derive(Clone, Copy)]
enum FixtureKind {
    Initial,
    Fold,
}

struct PersistedFixture {
    config: CohortVerifierConfigV4,
    source: PersistedCohortOpeningV4<SparseOuterNodeCacheV4>,
    touched_slots: Vec<u16>,
    kind: FixtureKind,
}

fn load_fixture(
    path: &Path,
    config: CohortVerifierConfigV4,
    draws: &[u64],
    policy: OuterCachePolicyV4,
    touched_slots: Vec<u16>,
    kind: FixtureKind,
) -> PersistedFixture {
    let provisional_cache =
        SparseOuterNodeCacheV4::deterministic_fixture(&config, draws, policy, [0; 32]).unwrap();
    let provisional_binding = PersistedOracleBindingV4::new([0x22; 32], [0x44; 32], [0; 32]);
    let provisional = PersistedCohortOpeningV4::load(
        path,
        config.clone(),
        provisional_cache,
        provisional_binding,
        provisional_binding,
    )
    .unwrap();
    let root = match kind {
        FixtureKind::Initial => {
            let (opening, _) = provisional.open_initial(draws, &touched_slots).unwrap();
            reconstruct_initial_packed_opening_root_v4(&config, draws, &touched_slots, &opening)
                .unwrap()
        }
        FixtureKind::Fold => {
            let (opening, _) = provisional.open_fold_round(draws).unwrap();
            reconstruct_fold_round_packed_opening_root_v4(&config, draws, &opening).unwrap()
        }
    };
    let cache =
        SparseOuterNodeCacheV4::deterministic_fixture(&config, draws, policy, root).unwrap();
    let binding = PersistedOracleBindingV4::new([0x22; 32], [0x44; 32], root);
    let source =
        PersistedCohortOpeningV4::load(path, config.clone(), cache, binding, binding).unwrap();
    PersistedFixture { config, source, touched_slots, kind }
}

fn build_fixtures(
    directory: &Path,
    draws: &[u64],
    policy: OuterCachePolicyV4,
) -> Vec<PersistedFixture> {
    let initial = [
        (0xA500_0001, OracleKindV4::WeightExtension, 30, 2, 2),
        (0xA500_0002, OracleKindV4::WeightExtension, 26, 36, 64),
        (0xA500_0003, OracleKindV4::WeightExtension, 24, 13, 16),
        (0xA500_0100, OracleKindV4::Auxiliary, 20, 2, 2),
        (0xA500_0101, OracleKindV4::Auxiliary, 19, 49, 64),
    ];
    let mut fixtures = Vec::with_capacity(32);
    for (cohort_id, kind, log2, present, structural) in initial {
        let cfg = config(cohort_id, kind, 0, log2, present, structural);
        let path = directory.join(format!("{cohort_id:08x}.oracle"));
        if !path.exists() {
            ensure_sparse_oracle(&path, &cfg);
        }
        fixtures.push(load_fixture(
            &path,
            cfg,
            draws,
            policy,
            (0..present as u16).collect(),
            FixtureKind::Initial,
        ));
    }
    for round in 1..=27u8 {
        let log2 = 30 - round;
        let cfg = config(0xA500_F001, OracleKindV4::GlobalFoldAggregate, round, log2, 1, 1);
        let path = directory.join(format!("fold-{round:02}.oracle"));
        if !path.exists() {
            ensure_sparse_oracle(&path, &cfg);
        }
        fixtures.push(load_fixture(&path, cfg, draws, policy, vec![0], FixtureKind::Fold));
    }
    fixtures
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct TrafficTotal {
    oracle_file_bytes_read: u64,
    outer_cache_bytes_read: u64,
    inner_trees_rebuilt: u64,
    outer_frontier_leaves_rebuilt: u64,
    outer_internal_nodes_rebuilt: u64,
}

impl TrafficTotal {
    fn include(&mut self, traffic: PersistedOpeningTrafficV4) {
        self.oracle_file_bytes_read += traffic.oracle_file_bytes_read;
        self.outer_cache_bytes_read += traffic.outer_cache_bytes_read;
        self.inner_trees_rebuilt += traffic.inner_trees_rebuilt;
        self.outer_frontier_leaves_rebuilt += traffic.outer_frontier_leaves_rebuilt;
        self.outer_internal_nodes_rebuilt += traffic.outer_internal_nodes_rebuilt;
    }
}

struct OpenMaterial {
    frame: PackedBatchOpeningFrameV4,
    encoded: Vec<u8>,
    traffic: TrafficTotal,
}

fn open_all(fixtures: &[PersistedFixture], draws: &[u64]) -> OpenMaterial {
    let mut initial_groups = Vec::with_capacity(5);
    let mut fold_rounds = Vec::with_capacity(27);
    let mut traffic = TrafficTotal::default();
    for fixture in fixtures {
        match fixture.kind {
            FixtureKind::Initial => {
                let (opening, observed) =
                    fixture.source.open_initial(draws, &fixture.touched_slots).unwrap();
                traffic.include(observed);
                initial_groups.push(opening);
            }
            FixtureKind::Fold => {
                let (opening, observed) = fixture.source.open_fold_round(draws).unwrap();
                traffic.include(observed);
                fold_rounds.push(opening);
            }
        }
    }
    let frame =
        PackedBatchOpeningFrameV4 { opening_schedule_digest: [0; 32], initial_groups, fold_rounds };
    let encoded = FrameV4::PackedBatchOpening(frame.clone()).encode().unwrap();
    let components = frame.byte_components().unwrap();
    assert_eq!(components.opened_symbols, EXPECTED_OPENED_SYMBOLS);
    assert_eq!(
        components.initial_inner_siblings
            + components.initial_outer_siblings
            + components.fold_outer_siblings,
        EXPECTED_SIBLING_DIGESTS
    );
    assert_eq!(encoded.len() as u64, EXPECTED_PACKED_BYTES);
    OpenMaterial { frame, encoded, traffic }
}

fn verify_all(fixtures: &[PersistedFixture], draws: &[u64], frame: &PackedBatchOpeningFrameV4) {
    let mut initial = frame.initial_groups.iter();
    let mut folds = frame.fold_rounds.iter();
    for fixture in fixtures {
        match fixture.kind {
            FixtureKind::Initial => verify_initial_packed_opening_v4(
                fixture.source.root(),
                &fixture.config,
                draws,
                &fixture.touched_slots,
                initial.next().unwrap(),
            )
            .unwrap(),
            FixtureKind::Fold => verify_fold_round_packed_opening_v4(
                fixture.source.root(),
                &fixture.config,
                draws,
                folds.next().unwrap(),
            )
            .unwrap(),
        }
    }
    assert!(initial.next().is_none() && folds.next().is_none());
}

#[derive(Serialize)]
struct OpeningPolicyRecord {
    name: String,
    bottom_outer_levels_omitted: u8,
    logical_outer_cache_bytes: u64,
    cache_bytes_saved_vs_full: u64,
    warmup_count: usize,
    candidate_open_wall_s: Vec<f64>,
    selected_upper_median_open_wall_s: f64,
    open_ceiling_s: f64,
    open_pass: bool,
    candidate_verify_wall_s: Vec<f64>,
    selected_upper_median_verify_wall_s: f64,
    verify_ceiling_s: f64,
    verify_pass: bool,
    traffic_per_open: TrafficTotal,
    encoded_bytes: u64,
    encoded_blake3: String,
}

fn measure_opening_policy(
    name: &str,
    fixtures: &[PersistedFixture],
    draws: &[u64],
    policy: OuterCachePolicyV4,
    cache_bytes: u64,
) -> (OpeningPolicyRecord, Vec<u8>) {
    let warm = open_all(fixtures, draws);
    verify_all(fixtures, draws, &warm.frame);
    let mut open_walls = Vec::new();
    let mut selected_material = warm;
    for _ in 0..3 {
        let started = Instant::now();
        let material = open_all(fixtures, draws);
        open_walls.push(started.elapsed().as_secs_f64());
        selected_material = material;
    }
    let mut verify_walls = Vec::new();
    for _ in 0..3 {
        let started = Instant::now();
        verify_all(fixtures, draws, &selected_material.frame);
        verify_walls.push(started.elapsed().as_secs_f64());
    }
    let selected_open = upper_median(open_walls.clone());
    let selected_verify = upper_median(verify_walls.clone());
    let encoded_digest = hex(blake3::hash(&selected_material.encoded).as_bytes());
    let record = OpeningPolicyRecord {
        name: name.to_owned(),
        bottom_outer_levels_omitted: policy.bottom_levels_omitted,
        logical_outer_cache_bytes: cache_bytes,
        cache_bytes_saved_vs_full: NORMAL_OUTER_CACHE_BYTES - cache_bytes,
        warmup_count: 1,
        candidate_open_wall_s: open_walls,
        selected_upper_median_open_wall_s: selected_open,
        open_ceiling_s: OPEN_CEILING_S,
        open_pass: selected_open <= OPEN_CEILING_S,
        candidate_verify_wall_s: verify_walls,
        selected_upper_median_verify_wall_s: selected_verify,
        verify_ceiling_s: VERIFY_CEILING_S,
        verify_pass: selected_verify <= VERIFY_CEILING_S,
        traffic_per_open: selected_material.traffic,
        encoded_bytes: selected_material.encoded.len() as u64,
        encoded_blake3: encoded_digest,
    };
    (record, selected_material.encoded)
}

#[derive(Serialize)]
struct SparseArtifactRecord {
    file_count: usize,
    logical_bytes: u64,
    allocated_bytes: u64,
    scope: String,
}

#[cfg(target_family = "unix")]
fn allocated_file_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    path.metadata().unwrap().blocks() * 512
}

fn sparse_artifacts(directory: &Path) -> SparseArtifactRecord {
    let mut file_count = 0usize;
    let mut logical_bytes = 0u64;
    let mut allocated_bytes = 0u64;
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let metadata = path.metadata().unwrap();
        file_count += 1;
        logical_bytes += metadata.len();
        allocated_bytes += allocated_file_bytes(&path);
    }
    SparseArtifactRecord {
        file_count,
        logical_bytes,
        allocated_bytes,
        scope: "local geometry-exact sparse fixture; logical lengths and every accessed offset are production-exact, unused pages are holes and this is not a physical G6 record"
            .to_owned(),
    }
}

fn command_output(args: &[&str]) -> String {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        output.push(TABLE[usize::from(byte >> 4)] as char);
        output.push(TABLE[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[derive(Serialize)]
struct PreflightRecord {
    schema: u32,
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    pod_profile: String,
    design_sha256: String,
    source_policy: String,
    audit_recompute_refused: bool,
    profile_digest: String,
    query_derive_context: String,
    query_xof_input_ascii: String,
    query_count: usize,
    query_draws_blake3: String,
    cpu_full_node_pipeline: CpuPipelineRecord,
    sparse_artifacts: SparseArtifactRecord,
    persisted_open_full_cache: OpeningPolicyRecord,
    persisted_open_ram_degraded: OpeningPolicyRecord,
    full_and_degraded_openings_byte_identical: bool,
    local_pre_pod_gate_pass: bool,
    ram_guidance: String,
}

fn main() {
    X4bOpeningSourcePolicyV4::PersistedOracle.require_record_eligible().unwrap();
    let audit_recompute_refused =
        X4bOpeningSourcePolicyV4::AuditRecompute.require_record_eligible().is_err();
    let draws = query_draws();
    let mut draw_bytes = Vec::with_capacity(4 * draws.len());
    for draw in &draws {
        draw_bytes.extend_from_slice(&u32::try_from(*draw).unwrap().to_le_bytes());
    }
    assert_eq!(blake3::hash(&draw_bytes).to_hex().as_str(), QUERY_TAPE_BLAKE3);

    let temp = std::env::temp_dir().join(format!("volta-x4b-preflight-{}", std::process::id()));
    std::fs::create_dir(&temp).unwrap();
    let full_fixtures = build_fixtures(&temp, &draws, OuterCachePolicyV4::FULL);
    let degraded_fixtures =
        build_fixtures(&temp, &draws, OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL);
    let sparse_artifacts = sparse_artifacts(&temp);
    assert_eq!(sparse_artifacts.file_count, 32);
    assert_eq!(sparse_artifacts.logical_bytes, 94_128_570_240);

    let (full, full_bytes) = measure_opening_policy(
        "full outer-internal cache",
        &full_fixtures,
        &draws,
        OuterCachePolicyV4::FULL,
        NORMAL_OUTER_CACHE_BYTES,
    );
    let (degraded, degraded_bytes) = measure_opening_policy(
        "omit bottom outer-internal level; rebuild from persisted oracle",
        &degraded_fixtures,
        &draws,
        OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL,
        DEGRADED_OUTER_CACHE_BYTES,
    );
    let byte_identical = full_bytes == degraded_bytes;
    assert!(byte_identical);
    let cpu = cpu_pipeline_record();
    let local_pre_pod_gate_pass = cpu.local_gate_met
        && full.open_pass
        && full.verify_pass
        && degraded.open_pass
        && degraded.verify_pass
        && byte_identical;

    let git_sha = command_output(&["git", "rev-parse", "HEAD"]);
    let git_dirty = !command_output(&["git", "status", "--porcelain"]).is_empty();
    let record = PreflightRecord {
        schema: 1,
        milestone: "X4b-local-CPU-persisted-opening-preflight".to_owned(),
        date: "2026-07-22".to_owned(),
        git_sha,
        git_dirty,
        profile: PROFILE.to_owned(),
        pod_profile: POD_PROFILE.to_owned(),
        design_sha256: DESIGN_SHA256.to_owned(),
        source_policy: "PersistedOracle (record eligible)".to_owned(),
        audit_recompute_refused,
        profile_digest: hex(&profile_digest_v4()),
        query_derive_context: QUERY_XOF_CONTEXT.to_owned(),
        query_xof_input_ascii: String::from_utf8(QUERY_XOF_INPUT.to_vec()).unwrap(),
        query_count: draws.len(),
        query_draws_blake3: hex(blake3::hash(&draw_bytes).as_bytes()),
        cpu_full_node_pipeline: cpu,
        sparse_artifacts,
        persisted_open_full_cache: full,
        persisted_open_ram_degraded: degraded,
        full_and_degraded_openings_byte_identical: byte_identical,
        local_pre_pod_gate_pass,
        ram_guidance: "At approximately 125 GiB select bottom_levels_omitted=1 for both initial and fold outer caches: retained cache falls from 71,454,161,664 B to 35,727,080,320 B (35,727,081,344 B saved). Every missing level-one node is rebuilt from two persisted level-zero neighbors and counted. If this degraded policy misses 1.50 s on the target host, provision >=128 GiB and use the full cache; never page or silently overcommit."
            .to_owned(),
    };
    let encoded = serde_json::to_string_pretty(&record).unwrap() + "\n";
    if let Some(path) = std::env::args().nth(1) {
        std::fs::write(path, encoded.as_bytes()).unwrap();
    } else {
        print!("{encoded}");
    }
    drop(full_fixtures);
    drop(degraded_fixtures);
    std::fs::remove_dir_all(&temp).unwrap();
    if !local_pre_pod_gate_pass {
        std::process::exit(2);
    }
}
