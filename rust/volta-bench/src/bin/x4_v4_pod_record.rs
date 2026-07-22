//! Fail-closed A100 record for the frozen X4 schema-4 profile.
//!
//! The current schema-4 prover has a CPU-only, fully materializing N4 cohort
//! commit path.  This harness therefore does not substitute the CUDA Ligero
//! tree for the incompatible schema-4 leaf/node preimages.  It first derives
//! the exact GPT-2 physical inventory, then:
//!
//! * probes the largest exact GPT-2 cohort against the complete 15-second
//!   commit ceiling (one warm-up plus three measured candidates); and
//! * measures an exact production auxiliary cohort for informative X5 host
//!   encode+hash and one-query recomputation anchors.
//!
//! A timeout of the largest constituent cohort is a lower-bound G4 failure
//! for the current sequential full-response implementation.  Open/verify are
//! left NOT EVALUATED if no complete production commitment exists.

use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use volta_field::{Fp, Fp2};
use volta_pcs::x4::{
    CohortIdentityV4, CohortVerifierConfigV4, CommittedModelGlobalCohortV4,
    ModelGlobalOpeningSourceV4, OracleKindV4, RecomputableModelGlobalCohortV4, V4ArtifactPolicy,
    V4CohortArtifactPlan,
};

const PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const POD_PROFILE: &str = "runpod-a100-x4-v1";
const DESIGN_SHA256: &str = "c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544";
const FROZEN_DESIGN_BASELINE_SHA256: &str =
    "1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7";
const MIGRATION_PATH: &str = "benchmarks/results/x4-v4-gpt2-migration-2026-07-21-31fc866.json";
const MIGRATION_SHA256: &str = "d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e";
const NOTE6_PATH: &str = "benchmarks/results/x4-note6-c3-weights-preflight-2026-07-22-71edbd7.json";
const NOTE6_SHA256: &str = "8fef35aae0412c45556b37fbfba89c88041d9de8b3c9733ad65227daeb83b0c2";
const SOURCE_EQUIVALENT_FLOOR_BYTES: u64 = 31_923_699_712;
const PCS_BYTES: u64 = 2_683_236;
const RESPONSE_BYTES: u64 = 43_953_700;
const OPENED_SYMBOLS: u64 = 27_564;
const REAL_SIBLING_DIGESTS: u64 = 67_930;
const SOUNDNESS_BITS: f64 = 80.255_370_163_990_41;
const SOUNDNESS_FLOOR_BITS: f64 = 78.809_294_874;
const COMMIT_CEILING_S: f64 = 15.0;
const COMMIT_KILL_AFTER: Duration = Duration::from_millis(15_050);
const PREP_TIMEOUT: Duration = Duration::from_secs(300);
const AUX17_OUTER_LEN: usize = 1 << 20;
const LARGEST_OUTER_LEN: usize = 1 << 30;

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
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(repo_root())
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(true)
}

fn descriptor(index: usize) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
    digest[8..].fill((index as u8).wrapping_mul(37).wrapping_add(11));
    digest
}

fn config(
    cohort_id: u32,
    oracle_kind: OracleKindV4,
    outer_len: usize,
    present_slots: usize,
    structural_slots: usize,
) -> CohortVerifierConfigV4 {
    assert!(present_slots <= structural_slots && structural_slots.is_power_of_two());
    CohortVerifierConfigV4 {
        identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round: 0 },
        slot_descriptors: (0..structural_slots)
            .map(|slot| (slot < present_slots).then(|| descriptor((cohort_id as usize) ^ slot)))
            .collect(),
        outer_len,
        expected_symbol_count: 1,
    }
}

fn deterministic_coefficients(
    present_slots: usize,
    structural_slots: usize,
    coefficient_len: usize,
) -> Vec<Option<Vec<Fp2>>> {
    (0..structural_slots)
        .map(|slot| {
            (slot < present_slots).then(|| {
                (0..coefficient_len)
                    .map(|index| {
                        let base =
                            (slot as u64 + 1).wrapping_mul(0x9e37_79b9).wrapping_add(index as u64);
                        Fp2::new(Fp::new(base), Fp::new(base.wrapping_mul(17).wrapping_add(3)))
                    })
                    .collect()
            })
        })
        .collect()
}

fn zero_coefficients(
    present_slots: usize,
    structural_slots: usize,
    coefficient_len: usize,
) -> Vec<Option<Vec<Fp2>>> {
    (0..structural_slots)
        .map(|slot| (slot < present_slots).then(|| vec![Fp2::ZERO; coefficient_len]))
        .collect()
}

#[derive(Clone, Serialize)]
struct CohortInventory {
    name: String,
    domain_log2: u32,
    present_slots: u64,
    structural_slots: u64,
    coefficient_bytes: u64,
    first_oracle_bytes: u64,
    inner_merkle_digests: u64,
    outer_merkle_digests: u64,
    merkle_digest_bytes: u64,
    materialization_bytes: u64,
    persistent_coefficients_plus_root_bytes: u64,
    logical_working_set_bytes: u64,
}

fn inventory_row(
    name: &str,
    cohort_id: u32,
    kind: OracleKindV4,
    domain_log2: u32,
    present: usize,
    slots: usize,
) -> CohortInventory {
    let cfg = config(cohort_id, kind, 1usize << domain_log2, present, slots);
    let plan = V4CohortArtifactPlan::new(&cfg, V4ArtifactPolicy::RecomputeOracleAndMerkle)
        .expect("valid frozen GPT-2 cohort inventory");
    CohortInventory {
        name: name.to_owned(),
        domain_log2,
        present_slots: plan.present_slots,
        structural_slots: plan.structural_slots,
        coefficient_bytes: plan.coefficient_bytes,
        first_oracle_bytes: plan.logical_first_oracle_bytes,
        inner_merkle_digests: plan.inner_merkle_digests,
        outer_merkle_digests: plan.outer_merkle_digests,
        merkle_digest_bytes: plan.merkle_digest_bytes,
        materialization_bytes: plan.logical_first_oracle_bytes + plan.merkle_digest_bytes,
        persistent_coefficients_plus_root_bytes: plan.retained_logical_payload_bytes,
        logical_working_set_bytes: plan.logical_commit_working_set_bytes,
    }
}

#[derive(Serialize)]
struct PhysicalInventory {
    source_equivalent_unpadded_floor_bytes: u64,
    cohorts: Vec<CohortInventory>,
    coefficient_bytes: u64,
    physical_padded_first_oracle_bytes: u64,
    physical_to_unpadded_floor_ratio: f64,
    inner_merkle_digests: u64,
    outer_merkle_digests: u64,
    merkle_digest_bytes: u64,
    bytes_per_materialization: u64,
    bytes_recomputed_per_response: u64,
    persistent_coefficients_plus_roots_bytes: u64,
    maximum_current_cohort_working_set_bytes: u64,
}

fn physical_inventory() -> PhysicalInventory {
    let cohorts = vec![
        inventory_row(
            "Wext-mu26-global-tied-roles",
            0xA500_0001,
            OracleKindV4::WeightExtension,
            30,
            2,
            2,
        ),
        inventory_row(
            "Wext-mu22-all-layers",
            0xA500_0002,
            OracleKindV4::WeightExtension,
            26,
            36,
            64,
        ),
        inventory_row(
            "Wext-mu20-layers-and-position",
            0xA500_0003,
            OracleKindV4::WeightExtension,
            24,
            13,
            16,
        ),
        inventory_row("auxiliary-ell17", 0xA500_0100, OracleKindV4::Auxiliary, 20, 2, 2),
        inventory_row("auxiliary-ell16", 0xA500_0101, OracleKindV4::Auxiliary, 19, 49, 64),
    ];
    let sum = |f: fn(&CohortInventory) -> u64| cohorts.iter().map(f).sum::<u64>();
    let coefficient_bytes = sum(|row| row.coefficient_bytes);
    let physical_padded_first_oracle_bytes = sum(|row| row.first_oracle_bytes);
    let inner_merkle_digests = sum(|row| row.inner_merkle_digests);
    let outer_merkle_digests = sum(|row| row.outer_merkle_digests);
    let merkle_digest_bytes = sum(|row| row.merkle_digest_bytes);
    let bytes_per_materialization = sum(|row| row.materialization_bytes);
    let persistent_coefficients_plus_roots_bytes =
        sum(|row| row.persistent_coefficients_plus_root_bytes);
    let maximum_current_cohort_working_set_bytes =
        cohorts.iter().map(|row| row.logical_working_set_bytes).max().unwrap();
    PhysicalInventory {
        source_equivalent_unpadded_floor_bytes: SOURCE_EQUIVALENT_FLOOR_BYTES,
        cohorts,
        coefficient_bytes,
        physical_padded_first_oracle_bytes,
        physical_to_unpadded_floor_ratio: physical_padded_first_oracle_bytes as f64
            / SOURCE_EQUIVALENT_FLOOR_BYTES as f64,
        inner_merkle_digests,
        outer_merkle_digests,
        merkle_digest_bytes,
        bytes_per_materialization,
        bytes_recomputed_per_response: 2 * bytes_per_materialization,
        persistent_coefficients_plus_roots_bytes,
        maximum_current_cohort_working_set_bytes,
    }
}

fn proc_value_bytes(pid: u32, field: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
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

fn proc_io_bytes(pid: u32, field: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/io"))
        .ok()
        .and_then(|io| {
            io.lines().find_map(|line| {
                let rest = line.strip_prefix(field)?;
                rest.trim().parse::<u64>().ok()
            })
        })
        .unwrap_or(0)
}

#[derive(Serialize)]
struct CommitProbe {
    role: String,
    exact_cohort: String,
    domain_log2: u32,
    present_slots: usize,
    structural_slots: usize,
    value_fixture: String,
    ceiling_s: f64,
    observed_wall_s: f64,
    completed: bool,
    timed_out: bool,
    exit_code: Option<i32>,
    peak_rss_bytes: u64,
    maximum_read_bytes: u64,
    maximum_write_bytes: u64,
    h2d_bytes: u64,
    d2h_bytes: u64,
    peak_vram_bytes: u64,
}

fn child_ready(child: &mut Child) {
    let stdout = child.stdout.take().expect("commit child stdout pipe");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let result = reader.read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    let line = receiver
        .recv_timeout(PREP_TIMEOUT)
        .expect("production commit child preparation timeout")
        .expect("read production commit child readiness");
    assert_eq!(line.trim(), "X4_V4_PRODUCTION_COHORT_READY");
}

fn run_commit_probe(role: &str) -> CommitProbe {
    let executable = std::env::current_exe().expect("current X4 pod harness executable");
    let mut child = Command::new(executable)
        .arg("--commit-child")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn exact production-cohort commit child");
    child_ready(&mut child);
    let pid = child.id();
    let started = Instant::now();
    let mut peak_rss_bytes = 0u64;
    let mut maximum_read_bytes = 0u64;
    let mut maximum_write_bytes = 0u64;
    let (completed, timed_out, exit_code);
    loop {
        peak_rss_bytes = peak_rss_bytes.max(proc_value_bytes(pid, "VmRSS:"));
        maximum_read_bytes = maximum_read_bytes.max(proc_io_bytes(pid, "read_bytes:"));
        maximum_write_bytes = maximum_write_bytes.max(proc_io_bytes(pid, "write_bytes:"));
        if let Some(status) = child.try_wait().expect("poll production commit child") {
            completed = status.success();
            timed_out = false;
            exit_code = status.code();
            break;
        }
        if started.elapsed() >= COMMIT_KILL_AFTER {
            child.kill().expect("kill over-ceiling production commit child");
            let status = child.wait().expect("reap production commit child");
            completed = false;
            timed_out = true;
            exit_code = status.code();
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    CommitProbe {
        role: role.to_owned(),
        exact_cohort: "Wext-mu26-global-tied-roles".to_owned(),
        domain_log2: 30,
        present_slots: 2,
        structural_slots: 2,
        value_fixture:
            "deterministic zero coefficients; exact operation/memory geometry; no correctness credit"
                .to_owned(),
        ceiling_s: COMMIT_CEILING_S,
        observed_wall_s: started.elapsed().as_secs_f64(),
        completed,
        timed_out,
        exit_code,
        peak_rss_bytes,
        maximum_read_bytes,
        maximum_write_bytes,
        h2d_bytes: 0,
        d2h_bytes: 0,
        peak_vram_bytes: 0,
    }
}

fn production_commit_child() -> ! {
    let cfg = config(0xA500_0001, OracleKindV4::WeightExtension, LARGEST_OUTER_LEN, 2, 2);
    let coefficients = zero_coefficients(2, 2, LARGEST_OUTER_LEN / 8);
    println!("X4_V4_PRODUCTION_COHORT_READY");
    std::io::stdout().flush().expect("flush production child readiness");
    let committed = CommittedModelGlobalCohortV4::commit(cfg, coefficients)
        .expect("exact production cohort commit");
    eprintln!("completed exact production cohort root={:02x?}", committed.commitment().root);
    std::process::exit(0)
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

#[derive(Serialize)]
struct HostStreamingAnchor {
    status: String,
    exact_cohort: String,
    warmup_count: usize,
    measured_candidates: usize,
    candidate_wall_s: Vec<f64>,
    selected_upper_median_wall_s: f64,
    measured_first_oracle_bytes_per_candidate: u64,
    measured_merkle_bytes_per_candidate: u64,
    selected_first_oracle_bytes_per_s: f64,
    projected_unpadded_floor_wall_s_at_measured_rate: f64,
    projected_physical_padded_oracle_wall_s_at_measured_rate: f64,
    full_31_9gb_pass_completed: bool,
    scope: String,
}

#[derive(Serialize)]
struct RecomputeAnchor {
    exact_cohort: String,
    query_count_per_candidate: usize,
    candidate_wall_s: Vec<f64>,
    selected_upper_median_wall_s: f64,
    source_bytes_read_per_query: u64,
    oracle_bytes_recomputed_per_query: u64,
    merkle_bytes_recomputed_per_query: u64,
    total_logical_bytes_per_query: u64,
    root_checked: bool,
    scope: String,
}

fn informative_anchors(physical_oracle_bytes: u64) -> (HostStreamingAnchor, RecomputeAnchor) {
    let cfg = config(0xA500_0100, OracleKindV4::Auxiliary, AUX17_OUTER_LEN, 2, 2);
    let coefficients = deterministic_coefficients(2, 2, AUX17_OUTER_LEN / 8);
    let plan = V4CohortArtifactPlan::new(&cfg, V4ArtifactPolicy::RecomputeOracleAndMerkle)
        .expect("aux17 artifact plan");

    let run_commit = || {
        let inputs = coefficients.clone();
        let started = Instant::now();
        let committed = CommittedModelGlobalCohortV4::commit(cfg.clone(), inputs)
            .expect("exact aux17 host encode+N4 hash");
        (started.elapsed().as_secs_f64(), committed.commitment().root)
    };
    let (_, warm_root) = run_commit();
    let mut walls = Vec::new();
    for _ in 0..3 {
        let (wall, root) = run_commit();
        assert_eq!(root, warm_root);
        walls.push(wall);
    }
    let selected = upper_median(walls.clone());
    let bytes_per_s = plan.logical_first_oracle_bytes as f64 / selected;
    let streaming = HostStreamingAnchor {
        status: "MEASURED_EXACT_AUX17_ANCHOR; FULL_FLOOR_BLOCKED_BY_G4_TIMEOUT".to_owned(),
        exact_cohort: "auxiliary-ell17 (domain_log2=20, 2/2 slots)".to_owned(),
        warmup_count: 1,
        measured_candidates: 3,
        candidate_wall_s: walls,
        selected_upper_median_wall_s: selected,
        measured_first_oracle_bytes_per_candidate: plan.logical_first_oracle_bytes,
        measured_merkle_bytes_per_candidate: plan.merkle_digest_bytes,
        selected_first_oracle_bytes_per_s: bytes_per_s,
        projected_unpadded_floor_wall_s_at_measured_rate: SOURCE_EQUIVALENT_FLOOR_BYTES as f64
            / bytes_per_s,
        projected_physical_padded_oracle_wall_s_at_measured_rate: physical_oracle_bytes as f64
            / bytes_per_s,
        full_31_9gb_pass_completed: false,
        scope: "informative X5 anchor only; projection is not a G4 result and does not model the 64-slot N4 hash multiplier"
            .to_owned(),
    };

    let source = RecomputableModelGlobalCohortV4::commit(
        cfg,
        coefficients,
        V4ArtifactPolicy::RecomputeOracleAndMerkle,
    )
    .expect("exact aux17 recomputable source");
    let mut recompute_walls = Vec::new();
    let mut traffic = None;
    for draw in [17u64, 1_000_003, 777_777_777] {
        let started = Instant::now();
        let (opening, observed) = source
            .open_initial_source(&[draw], &[0, 1])
            .expect("one-query exact aux17 rebuild, root-check and opening");
        recompute_walls.push(started.elapsed().as_secs_f64());
        // One strict-UD draw opens its `+/-` coordinate pair, then each of
        // the two touched slots at both coordinates.
        assert_eq!(opening.opened_symbols.len(), 4);
        if let Some(previous) = traffic {
            assert_eq!(previous, observed);
        }
        traffic = Some(observed);
    }
    let traffic = traffic.unwrap();
    let recompute = RecomputeAnchor {
        exact_cohort: "auxiliary-ell17 (domain_log2=20, 2/2 slots)".to_owned(),
        query_count_per_candidate: 1,
        selected_upper_median_wall_s: upper_median(recompute_walls.clone()),
        candidate_wall_s: recompute_walls,
        source_bytes_read_per_query: traffic.source_bytes_read,
        oracle_bytes_recomputed_per_query: traffic.oracle_bytes_recomputed,
        merkle_bytes_recomputed_per_query: traffic.merkle_bytes_recomputed,
        total_logical_bytes_per_query: traffic.source_bytes_read
            + traffic.oracle_bytes_recomputed
            + traffic.merkle_bytes_recomputed,
        root_checked: true,
        scope: "informative exact-cohort one-query rebuild; not the five-cohort response opening"
            .to_owned(),
    };
    (streaming, recompute)
}

#[derive(Serialize)]
struct GpuAnchor {
    available: bool,
    measured: bool,
    reason: String,
    incompatible_existing_primitive: String,
}

#[derive(Serialize)]
struct Machine {
    provider: String,
    instance_id: String,
    hostname: String,
    gpu: String,
    driver: String,
    cpu: String,
    logical_cpus: String,
    memory_bytes: u64,
    persistent_volume_bytes: u64,
    persistent_volume_available_bytes: u64,
    rayon_threads: usize,
    timing_policy: String,
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

fn df_bytes(field: usize) -> u64 {
    command_output(&["df", "-B1", "--output=size,avail", "/workspace"])
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().nth(field))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn machine() -> Machine {
    Machine {
        provider: std::env::var("VOLTA_CLOUD_PROVIDER").unwrap_or_else(|_| "RunPod".to_owned()),
        instance_id: std::env::var("VOLTA_CLOUD_INSTANCE_ID")
            .unwrap_or_else(|_| command_output(&["hostname"])),
        hostname: command_output(&["hostname"]),
        gpu: command_output(&[
            "nvidia-smi",
            "--query-gpu=name,uuid",
            "--format=csv,noheader,nounits",
        ]),
        driver: command_output(&[
            "nvidia-smi",
            "--query-gpu=driver_version",
            "--format=csv,noheader,nounits",
        ]),
        cpu: command_output(&["sh", "-c", "lscpu | sed -n 's/^Model name:[[:space:]]*//p'"]),
        logical_cpus: command_output(&["nproc"]),
        memory_bytes: parse_memtotal_bytes(),
        persistent_volume_bytes: df_bytes(0),
        persistent_volume_available_bytes: df_bytes(1),
        rayon_threads: rayon::current_num_threads(),
        timing_policy: "wall-only+counters; no CUDA-event timing".to_owned(),
    }
}

#[derive(Serialize)]
struct FrozenReferences {
    design_sha256: String,
    frozen_design_baseline_sha256: String,
    migration_path: String,
    migration_sha256: String,
    note6_path: String,
    note6_sha256: String,
    profile: String,
    rate: String,
    query_count: u64,
    maximum_claim_union: u64,
    opened_symbols: u64,
    real_sibling_digests: u64,
    pcs_bytes: u64,
    response_bytes: u64,
    soundness_expression: String,
    soundness_bits: f64,
    soundness_floor_bits: f64,
    soundness_new_terms: u64,
}

#[derive(Serialize)]
struct GateRecord {
    g1_lean: String,
    g2_full_production_correctness: String,
    g3_communication: String,
    g4_commit: String,
    g4_open: String,
    g4_verify: String,
    g5_proportionality: String,
    g6_storage_traffic: String,
    inherited_resident_prefill: String,
    inherited_resident_decode: String,
    inherited_h2d: String,
    inherited_max_sync: String,
    inherited_flatness: String,
    overall_x4: String,
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
    machine: Machine,
    frozen: FrozenReferences,
    physical_inventory: PhysicalInventory,
    production_commit_probe: Vec<CommitProbe>,
    informative_streaming_commit: HostStreamingAnchor,
    informative_per_query_cohort_recompute: RecomputeAnchor,
    informative_gpu_assisted_streaming_commit: GpuAnchor,
    implementation_obstruction: String,
    protocol_or_parameter_change: bool,
    gate: GateRecord,
}

fn main() {
    if std::env::args().any(|arg| arg == "--commit-child") {
        production_commit_child();
    }
    let record = std::env::args().any(|arg| arg == "--record");
    if !record {
        eprintln!("x4_v4_pod_record: --record is required; this harness has no diagnostic profile");
        std::process::exit(2);
    }
    let requested_profile = std::env::args()
        .find_map(|arg| arg.strip_prefix("--profile=").map(str::to_owned))
        .unwrap_or_else(|| POD_PROFILE.to_owned());
    if requested_profile != POD_PROFILE {
        eprintln!("x4_v4_pod_record: refusing profile {requested_profile:?}");
        std::process::exit(2);
    }
    assert_eq!(rayon::current_num_threads(), 8, "frozen pod profile requires 8 Rayon threads");
    assert!(!git_dirty(), "X4 pod record requires a tracked-clean tree");
    assert_eq!(sha256(&repo_root().join("docs/x4-folding-pcs-design.md")), DESIGN_SHA256);
    assert_eq!(sha256(&repo_root().join(MIGRATION_PATH)), MIGRATION_SHA256);
    assert_eq!(sha256(&repo_root().join(NOTE6_PATH)), NOTE6_SHA256);

    let inventory = physical_inventory();
    assert_eq!(inventory.coefficient_bytes, 9_618_587_648);
    assert_eq!(inventory.physical_padded_first_oracle_bytes, 76_948_701_184);
    assert_eq!(inventory.inner_merkle_digests, 12_333_875_200);
    assert_eq!(inventory.outer_merkle_digests, 2_318_401_531);
    assert_eq!(inventory.merkle_digest_bytes, 468_872_855_392);
    assert_eq!(inventory.bytes_per_materialization, 545_821_556_576);
    assert_eq!(inventory.bytes_recomputed_per_response, 1_091_643_113_152);
    assert_eq!(inventory.persistent_coefficients_plus_roots_bytes, 9_618_587_808);
    assert_eq!(inventory.maximum_current_cohort_working_set_bytes, 363_998_478_304);

    let mut probes = vec![run_commit_probe("warmup")];
    for ordinal in 1..=3 {
        probes.push(run_commit_probe(&format!("measured-{ordinal}")));
    }
    let measured = &probes[1..];
    assert!(measured.iter().all(|probe| {
        probe.timed_out && !probe.completed && probe.observed_wall_s >= COMMIT_CEILING_S
    }));

    let (streaming, recompute) = informative_anchors(inventory.physical_padded_first_oracle_bytes);
    let report = Report {
        schema: 1,
        milestone: "X4-v4-A100-production-record".to_owned(),
        date: command_output(&["date", "+%Y-%m-%d"]),
        git_sha: command_output(&["git", "rev-parse", "HEAD"]),
        git_short_sha: command_output(&["git", "rev-parse", "--short", "HEAD"]),
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        machine: machine(),
        frozen: FrozenReferences {
            design_sha256: DESIGN_SHA256.to_owned(),
            frozen_design_baseline_sha256: FROZEN_DESIGN_BASELINE_SHA256.to_owned(),
            migration_path: MIGRATION_PATH.to_owned(),
            migration_sha256: MIGRATION_SHA256.to_owned(),
            note6_path: NOTE6_PATH.to_owned(),
            note6_sha256: NOTE6_SHA256.to_owned(),
            profile: PROFILE.to_owned(),
            rate: "1/8".to_owned(),
            query_count: 111,
            maximum_claim_union: 3_320,
            opened_symbols: OPENED_SYMBOLS,
            real_sibling_digests: REAL_SIBLING_DIGESTS,
            pcs_bytes: PCS_BYTES,
            response_bytes: RESPONSE_BYTES,
            soundness_expression:
                "3320*(9/16)^111 + 28522064267253/340282366762482138490186164457219031041"
                    .to_owned(),
            soundness_bits: SOUNDNESS_BITS,
            soundness_floor_bits: SOUNDNESS_FLOOR_BITS,
            soundness_new_terms: 0,
        },
        physical_inventory: inventory,
        production_commit_probe: probes,
        informative_streaming_commit: streaming,
        informative_per_query_cohort_recompute: recompute,
        informative_gpu_assisted_streaming_commit: GpuAnchor {
            available: false,
            measured: false,
            reason: "No schema-4 N4 CUDA leaf/node or streaming-frontier path exists in the production X4 implementation."
                .to_owned(),
            incompatible_existing_primitive: "volta_accel::Backend::hash_fp2_tree_device hashes a Ligero row-matrix tree and cannot reproduce PcsLeafFrameV4/PcsNodeFrameV4 preimages; it receives no cohort/slot/descriptor/tree-role metadata."
                .to_owned(),
        },
        implementation_obstruction: "The frozen protocol requires model-global N4 cohorts, but the current Rust path encodes every slot on the host, clones every codeword, and retains every inner and outer level. One exact Wext-mu26 constituent exceeds the complete 15-second commit ceiling in all measured candidates; no complete production commitment exists from which an authenticated opening can be generated."
            .to_owned(),
        protocol_or_parameter_change: false,
        gate: GateRecord {
            g1_lean: "PASS — exact frozen v4 statements; 209/116 audit; no new axioms"
                .to_owned(),
            g2_full_production_correctness: "NOT EVALUATED — no complete production commitment/opening after G4 commit failure"
                .to_owned(),
            g3_communication: "PASS — PCS 2,683,236 B <= 4,000,000 B; response 43,953,700 B <= 45,270,464 B"
                .to_owned(),
            g4_commit: "FAIL — one exact constituent cohort exceeded 15.000 s in warmup and all three measured candidates"
                .to_owned(),
            g4_open: "NOT EVALUATED — production commitment unavailable; 1.50 s ceiling unchanged"
                .to_owned(),
            g4_verify: "NOT EVALUATED — production opening unavailable; 0.25 s ceiling unchanged"
                .to_owned(),
            g5_proportionality: "PASS IN IMMUTABLE CPU SYNTHETIC RECORD ONLY"
                .to_owned(),
            g6_storage_traffic: "NOT EVALUATED AS PASS — exact logical physical inventory recorded, but no completed production materialization supplied physical RSS/traffic closure"
                .to_owned(),
            inherited_resident_prefill: "NOT RE-RUN AFTER CONJUNCTIVE PCS G4 FAILURE; 10 s ceiling unchanged"
                .to_owned(),
            inherited_resident_decode: "NOT RE-RUN AFTER CONJUNCTIVE PCS G4 FAILURE; 4 s ceiling unchanged"
                .to_owned(),
            inherited_h2d: "NOT RE-RUN AFTER CONJUNCTIVE PCS G4 FAILURE; 100,000,000 B ceiling unchanged"
                .to_owned(),
            inherited_max_sync: "NOT RE-RUN AFTER CONJUNCTIVE PCS G4 FAILURE; 0.150 s ceiling unchanged"
                .to_owned(),
            inherited_flatness: "NOT RE-RUN AFTER CONJUNCTIVE PCS G4 FAILURE; 1.5 ceiling unchanged"
                .to_owned(),
            overall_x4: "FAIL — conjunctive G4 commit gate failed; no threshold was relaxed"
                .to_owned(),
        },
    };
    assert_eq!(report.machine.rayon_threads, 8);
    assert!(report.machine.gpu.contains("A100-SXM4-80GB"));

    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    let path = repo_root()
        .join("benchmarks/results")
        .join(format!("x4-v4-a100-production-{}-{}.json", report.date, report.git_short_sha));
    if path.exists() {
        eprintln!("x4_v4_pod_record: append-only record already exists: {}", path.display());
        std::process::exit(2);
    }
    std::fs::write(&path, json).expect("write append-only X4 v4 pod record");
    eprintln!(
        "X4 v4 pod: G4 commit FAIL; physical oracle={} B, Merkle={} B; wrote {}",
        report.physical_inventory.physical_padded_first_oracle_bytes,
        report.physical_inventory.merkle_digest_bytes,
        path.display()
    );
}
