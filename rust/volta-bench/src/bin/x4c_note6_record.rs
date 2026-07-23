//! Fail-closed first production-size action for `runpod-a100-x4c-v1`.
//!
//! This entry point is intentionally separate from every X4c onboarding,
//! lifecycle-probe and online-response binary. It validates the frozen
//! machine/storage profile, creates a fresh append-only session-order guard,
//! and then runs the existing R1b NOTE-6 two-weight-set leakage smoke. No
//! X4c or 77-GB work is performed here.

use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Instant;

const POD_PROFILE: &str = "runpod-a100-x4c-v1";
const PROTOCOL_PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const DESIGN_SHA256: &str = "57d0c0d691cc63ec043d18384348ad0e1130a5e763dc8e9ef00a7132d8abb880";
const GPU_NAME: &str = "NVIDIA A100-SXM4-80GB";
const GPU_MEMORY_MIB: u64 = 81_920;
const MIN_HOST_RAM_BYTES: u64 = 274_877_906_944;
const DURABLE_COEFFICIENT_BYTES: u64 = 9_618_587_648;
const DURABLE_ROOT_BYTES: u64 = 160;
const DURABLE_TIER_BYTES: u64 = 9_618_587_808;
const MIN_LOCAL_STORAGE_BYTES: u64 = 150_000_000_000;
const PROVING_RAYON_THREADS: usize = 8;
const ENCODED_GEOMETRY_BYTES: u64 = 6_442_450_944;
const COMMAND: &str = "cargo test --release -p volta-pcs --test p35 c3_weights_two_weight_set_leakage_smoke -- --ignored --exact --nocapture";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn checked_output(program: &str, args: &[&str], cwd: &Path) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
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
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("decode {program} output: {error}"))
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn require_env_exact(name: &str, expected: &str) -> Result<String, String> {
    let value = required_env(name)?;
    if value != expected {
        return Err(format!("{name} must be exactly {expected:?}, got {value:?}"));
    }
    Ok(value)
}

fn parse_memtotal_bytes(text: &str) -> Result<u64, String> {
    let kib = text
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("MemTotal:")?;
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
        .ok_or_else(|| "MemTotal is missing or invalid".to_owned())?;
    kib.checked_mul(1024).ok_or_else(|| "MemTotal byte conversion overflow".to_owned())
}

fn memtotal_bytes() -> Result<u64, String> {
    let text = fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("read /proc/meminfo: {error}"))?;
    parse_memtotal_bytes(&text)
}

fn blake3_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in blake3::hash(bytes).as_bytes() {
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("execute sha256sum for {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("decode sha256sum output: {error}"))?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("sha256sum returned no digest for {}", path.display()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SelectedGpu {
    cuda_ordinal: u32,
    nvidia_smi_index: u32,
    name: String,
    uuid: String,
    memory_mib: u64,
    memory_bytes: u64,
    cuda_visible_devices: Option<String>,
}

fn parse_selected_gpu(
    text: &str,
    cuda_visible_devices: Option<&str>,
) -> Result<SelectedGpu, String> {
    let rows = text.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(format!(
            "profile requires exactly one selected GPU, nvidia-smi reported {}",
            rows.len()
        ));
    }
    let fields = rows[0].split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 4 {
        return Err("nvidia-smi GPU row must contain index,name,uuid,memory.total".to_owned());
    }
    let index =
        fields[0].parse::<u32>().map_err(|error| format!("parse nvidia-smi GPU index: {error}"))?;
    let memory_mib = fields[3]
        .parse::<u64>()
        .map_err(|error| format!("parse nvidia-smi memory.total: {error}"))?;
    if fields[1] != GPU_NAME || memory_mib != GPU_MEMORY_MIB {
        return Err(format!(
            "selected GPU must be {GPU_NAME}, {GPU_MEMORY_MIB} MiB; got index {index}, {}, {memory_mib} MiB",
            fields[1]
        ));
    }
    if fields[2].is_empty() {
        return Err("nvidia-smi returned an empty GPU UUID".to_owned());
    }
    if let Some(selection) = cuda_visible_devices {
        if selection.is_empty() || selection.contains(',') {
            return Err("CUDA_VISIBLE_DEVICES must select exactly one device".to_owned());
        }
        if selection != fields[0] && selection != fields[2] {
            return Err(format!(
                "CUDA_VISIBLE_DEVICES={selection:?} does not select physical index {index} / {}",
                fields[2],
            ));
        }
    } else if index != 0 {
        return Err("a sole unqualified GPU must have physical index 0".to_owned());
    }
    let memory_bytes = memory_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "GPU memory byte conversion overflow".to_owned())?;
    Ok(SelectedGpu {
        cuda_ordinal: 0,
        nvidia_smi_index: index,
        name: fields[1].to_owned(),
        uuid: fields[2].to_owned(),
        memory_mib,
        memory_bytes,
        cuda_visible_devices: cuda_visible_devices.map(str::to_owned),
    })
}

fn selected_gpu() -> Result<SelectedGpu, String> {
    let selection = env::var("CUDA_VISIBLE_DEVICES").ok();
    if selection.as_deref().is_some_and(|value| value.is_empty() || value.contains(',')) {
        return Err("CUDA_VISIBLE_DEVICES must select exactly one device".to_owned());
    }
    let mut command = Command::new("nvidia-smi");
    if let Some(selector) = &selection {
        command.arg(format!("--id={selector}"));
    }
    let output = command
        .args(["--query-gpu=index,name,uuid,memory.total", "--format=csv,noheader,nounits"])
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("execute nvidia-smi: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "nvidia-smi selected-GPU query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("decode nvidia-smi selected-GPU output: {error}"))?;
    parse_selected_gpu(&text, selection.as_deref())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct StorageAnchor {
    path: String,
    filesystem_type: String,
    mount_target: String,
    mount_source: String,
    mount_options: String,
    mount_major_minor: String,
    filesystem_root: String,
    device_id: u64,
    total_bytes: u64,
    available_bytes: u64,
}

fn storage_anchor(path: &Path) -> Result<StorageAnchor, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", canonical.display()));
    }
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("stat {}: {error}", canonical.display()))?;
    let df = Command::new("df")
        .args(["-B1", "--output=size,avail"])
        .arg(&canonical)
        .output()
        .map_err(|error| format!("execute df for {}: {error}", canonical.display()))?;
    if !df.status.success() {
        return Err(format!("df failed for {}", canonical.display()));
    }
    let df_text =
        String::from_utf8(df.stdout).map_err(|error| format!("decode df output: {error}"))?;
    let df_fields = df_text
        .lines()
        .nth(1)
        .ok_or_else(|| format!("df returned no row for {}", canonical.display()))?
        .split_whitespace()
        .collect::<Vec<_>>();
    if df_fields.len() != 2 {
        return Err(format!("df returned an incomplete row for {}", canonical.display()));
    }
    let total_bytes =
        df_fields[0].parse::<u64>().map_err(|error| format!("parse df size: {error}"))?;
    let available_bytes =
        df_fields[1].parse::<u64>().map_err(|error| format!("parse df available: {error}"))?;

    let mount = Command::new("findmnt")
        .args([
            "--json",
            "--target",
            canonical
                .to_str()
                .ok_or_else(|| format!("non-UTF8 storage path {}", canonical.display()))?,
            "--output",
            "TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN,FSROOT",
        ])
        .output()
        .map_err(|error| format!("execute findmnt for {}: {error}", canonical.display()))?;
    if !mount.status.success() {
        return Err(format!("findmnt failed for {}", canonical.display()));
    }
    let value: Value = serde_json::from_slice(&mount.stdout)
        .map_err(|error| format!("parse findmnt JSON: {error}"))?;
    let filesystem = value["filesystems"]
        .as_array()
        .and_then(|rows| (rows.len() == 1).then(|| &rows[0]))
        .ok_or_else(|| {
            format!("findmnt must return exactly one row for {}", canonical.display())
        })?;
    let field = |name: &str| {
        filesystem[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("findmnt field {name} missing for {}", canonical.display()))
    };
    Ok(StorageAnchor {
        path: canonical.display().to_string(),
        filesystem_type: field("fstype")?,
        mount_target: field("target")?,
        mount_source: field("source")?,
        mount_options: field("options")?,
        mount_major_minor: field("maj:min")?,
        filesystem_root: field("fsroot")?,
        device_id: metadata.dev(),
        total_bytes,
        available_bytes,
    })
}

fn is_mfs_like(filesystem_type: &str) -> bool {
    let lower = filesystem_type.to_ascii_lowercase();
    matches!(lower.as_str(), "mfs" | "tmpfs" | "ramfs") || lower.ends_with(".mfs")
}

#[derive(Clone, Debug, Serialize)]
struct StorageProfile {
    persistent_class: String,
    durable_role: String,
    durable_coefficients_bytes: u64,
    durable_five_roots_bytes: u64,
    durable_exact_payload_bytes: u64,
    durable_capacity_sufficient: bool,
    durable: StorageAnchor,
    local_role: String,
    local_minimum_available_bytes: u64,
    local_is_non_mfs: bool,
    local: StorageAnchor,
    records: StorageAnchor,
    separate_device_ids: bool,
    separate_mount_sources: bool,
    separate_mount_targets: bool,
    records_on_local_device: bool,
}

fn validate_storage(
    durable: StorageAnchor,
    local: StorageAnchor,
    records: StorageAnchor,
) -> Result<StorageProfile, String> {
    let durable_capacity_sufficient = durable.available_bytes >= DURABLE_TIER_BYTES;
    let local_is_non_mfs = !is_mfs_like(&local.filesystem_type);
    let separate_device_ids = durable.device_id != local.device_id;
    let separate_mount_sources = durable.mount_source != local.mount_source;
    let separate_mount_targets = durable.mount_target != local.mount_target;
    let records_on_local_device =
        records.device_id == local.device_id && !is_mfs_like(&records.filesystem_type);
    if !durable_capacity_sufficient {
        return Err(format!(
            "PERSISTENT tier has {} B available, needs exact {} B payload capacity",
            durable.available_bytes, DURABLE_TIER_BYTES
        ));
    }
    if local.available_bytes < MIN_LOCAL_STORAGE_BYTES {
        return Err(format!(
            "local storage has {} B available, needs at least {} B",
            local.available_bytes, MIN_LOCAL_STORAGE_BYTES
        ));
    }
    if !local_is_non_mfs {
        return Err(format!(
            "local storage filesystem {} is mfs/tmpfs/ramfs",
            local.filesystem_type
        ));
    }
    if !(separate_device_ids && separate_mount_sources && separate_mount_targets) {
        return Err("PERSISTENT and local storage must be separate devices/mounts".to_owned());
    }
    if !records_on_local_device {
        return Err("benchmarks/results must reside on the declared local non-mfs mount".to_owned());
    }
    Ok(StorageProfile {
        persistent_class: "PERSISTENT".to_owned(),
        durable_role: "coefficients_plus_five_roots_only".to_owned(),
        durable_coefficients_bytes: DURABLE_COEFFICIENT_BYTES,
        durable_five_roots_bytes: DURABLE_ROOT_BYTES,
        durable_exact_payload_bytes: DURABLE_TIER_BYTES,
        durable_capacity_sufficient,
        durable,
        local_role: "scratch_ram_spill_and_append_only_records".to_owned(),
        local_minimum_available_bytes: MIN_LOCAL_STORAGE_BYTES,
        local_is_non_mfs,
        local,
        records,
        separate_device_ids,
        separate_mount_sources,
        separate_mount_targets,
        records_on_local_device,
    })
}

fn git_clean() -> Result<bool, String> {
    checked_output("git", &["status", "--porcelain", "--untracked-files=all"], &repo_root())
        .map(|output| output.is_empty())
}

fn process_affinity() -> String {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:").map(str::trim))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn live_production_processes() -> Vec<String> {
    let self_pid = std::process::id();
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return vec!["/proc scan unavailable".to_owned()];
    };
    for entry in entries.flatten() {
        let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        let Ok(executable) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let name = executable.file_name().and_then(|value| value.to_str()).unwrap_or_default();
        let x4c_production = name.starts_with("x4c_");
        let legacy_production = matches!(name, "x4b_pod_record" | "x4_v4_pod_record");
        if x4c_production || legacy_production {
            found.push(format!("{pid}:{name}"));
        }
    }
    found.sort();
    found
}

#[derive(Serialize)]
struct SessionStartMarker<'a> {
    schema: u32,
    state: &'a str,
    pod_profile: &'a str,
    pod_id: &'a str,
    git_sha: &'a str,
    required_first_action: &'a str,
    prior_x4c_or_77gb_work: bool,
}

#[derive(Serialize)]
struct SessionOutcomeMarker<'a> {
    schema: u32,
    state: &'a str,
    pod_profile: &'a str,
    git_sha: &'a str,
    note6_passed: bool,
    x4c_or_77gb_work_started_before_pass: bool,
    next_action_authorized: bool,
}

fn create_new_json<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create append-only {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("persist append-only {}: {error}", path.display()))?;
    Ok(bytes)
}

#[derive(Serialize)]
struct Machine {
    provider: String,
    pod_id: String,
    hostname: String,
    gpu: SelectedGpu,
    driver: String,
    cpu: String,
    logical_cpus: String,
    proc_memtotal_bytes: u64,
    proc_memtotal_gate_bytes: u64,
    proc_memtotal_gate_passed: bool,
    current_process_affinity: String,
}

#[derive(Serialize)]
struct WorkerPolicy {
    proving_rayon_num_threads: usize,
    note6_child_rayon_num_threads: usize,
    commit_onboarding_policy: String,
    seal_policy: String,
    open_policy: String,
    commit_seal_open_executed_by_note6: bool,
    actual_phase_workers_and_affinity_required_in_later_records: bool,
}

#[derive(Serialize)]
struct PreflightOrder {
    required_first: String,
    first_production_size_test_started: String,
    operator_first_action_attestation: bool,
    fresh_session_directory_created_exclusively: bool,
    session_start_marker_path: String,
    session_start_marker_blake3: String,
    session_outcome_marker_path: String,
    session_outcome_marker_blake3: String,
    live_x4c_or_legacy_production_processes_before_start: Vec<String>,
    x4c_or_77gb_work_started_before_pass: bool,
    order_satisfied: bool,
}

#[derive(Serialize)]
struct TestRecord {
    passed: bool,
    exit_code: Option<i32>,
    monotonic_wall_s: f64,
    timing_source: String,
    cuda_event_timing_used: bool,
    stdout_blake3: String,
    stderr_blake3: String,
    encoded_geometry_bytes: u64,
    leakage_verdict: String,
}

#[derive(Serialize)]
struct ImmutableSurface {
    rate: String,
    query_count: u64,
    pcs_bytes: u64,
    response_bytes: u64,
    protocol_changed: bool,
    proof_format_changed: bool,
    roots_changed: bool,
    lean_changed: bool,
    soundness_changed: bool,
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
    command: String,
    machine: Machine,
    storage: StorageProfile,
    worker_policy: WorkerPolicy,
    preflight_order: PreflightOrder,
    test: TestRecord,
    immutable_surface: ImmutableSurface,
    assurance: String,
}

fn parse_args() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--record" {
        Ok(())
    } else {
        Err("exactly one argument is required: --record".to_owned())
    }
}

fn execute_note6() -> Result<Output, String> {
    Command::new("cargo")
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
        .env("RAYON_NUM_THREADS", PROVING_RAYON_THREADS.to_string())
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("execute NOTE-6 production-size smoke: {error}"))
}

fn run() -> Result<bool, String> {
    parse_args()?;
    require_env_exact("VOLTA_X4C_POD_PROVISIONING_APPROVED", "1")?;
    let provider = require_env_exact("VOLTA_CLOUD_PROVIDER", "RunPod")?;
    let declared_gpu = require_env_exact("VOLTA_CLOUD_GPU_SKU", GPU_NAME)?;
    debug_assert_eq!(declared_gpu, GPU_NAME);
    let persistent_class = require_env_exact("VOLTA_X4C_PERSISTENT_CLASS", "PERSISTENT")?;
    debug_assert_eq!(persistent_class, "PERSISTENT");
    require_env_exact("VOLTA_X4C_COMMIT_SEAL_OPEN_UNPINNED", "1")?;
    require_env_exact("VOLTA_X4C_NOTE6_FIRST_ACTION", "1")?;
    let pod_id = required_env("RUNPOD_POD_ID")?;

    if !git_clean()? {
        return Err("refusing a run-of-record from a dirty tree".to_owned());
    }
    let git_sha = checked_output("git", &["rev-parse", "HEAD"], &repo_root())?;
    let git_short_sha = checked_output("git", &["rev-parse", "--short", "HEAD"], &repo_root())?;
    let date = checked_output("date", &["+%Y-%m-%d"], &repo_root())?;
    let observed_design_sha = sha256(&repo_root().join("docs/x4c-io-lifecycle-design.md"))?;
    if observed_design_sha != DESIGN_SHA256 {
        return Err(format!(
            "X4c design digest mismatch: expected {DESIGN_SHA256}, got {observed_design_sha}"
        ));
    }

    let memory_bytes = memtotal_bytes()?;
    if memory_bytes < MIN_HOST_RAM_BYTES {
        return Err(format!("/proc MemTotal is {memory_bytes} B, below {MIN_HOST_RAM_BYTES} B"));
    }
    let gpu = selected_gpu()?;
    let hostname = checked_output("hostname", &[], &repo_root())?;
    let gpu_id = format!("--id={}", gpu.nvidia_smi_index);
    let driver = checked_output(
        "nvidia-smi",
        &[gpu_id.as_str(), "--query-gpu=driver_version", "--format=csv,noheader,nounits"],
        &repo_root(),
    )?;
    let cpu = checked_output("lscpu", &[], &repo_root())?;
    let logical_cpus = checked_output("nproc", &[], &repo_root())?;
    let durable_path = PathBuf::from(required_env("VOLTA_X4C_PERSISTENT_DIR")?);
    let local_path = PathBuf::from(required_env("VOLTA_X4C_LOCAL_STORAGE_DIR")?);
    let records_path = repo_root().join("benchmarks/results");
    let durable = storage_anchor(&durable_path)?;
    let local = storage_anchor(&local_path)?;
    let records = storage_anchor(&records_path)?;
    let storage = validate_storage(durable, local.clone(), records)?;

    let output_path =
        records_path.join(format!("x4c-note6-c3-weights-preflight-{date}-{git_short_sha}.json"));
    if output_path.exists() {
        return Err(format!("append-only NOTE-6 record already exists: {}", output_path.display()));
    }

    let live_processes = live_production_processes();
    if !live_processes.is_empty() {
        return Err(format!(
            "X4c/legacy production processes are already live: {}",
            live_processes.join(", ")
        ));
    }
    let session_dir = PathBuf::from(required_env("VOLTA_X4C_SESSION_DIR")?);
    if !session_dir.is_absolute() {
        return Err("VOLTA_X4C_SESSION_DIR must be absolute".to_owned());
    }
    let expected_session_name = format!("x4c-session-{pod_id}");
    if session_dir.file_name().and_then(|value| value.to_str())
        != Some(expected_session_name.as_str())
    {
        return Err(format!(
            "VOLTA_X4C_SESSION_DIR basename must be exactly {expected_session_name:?}"
        ));
    }
    let canonical_repo_root = fs::canonicalize(repo_root())
        .map_err(|error| format!("canonicalize repository root: {error}"))?;
    if session_dir.starts_with(&canonical_repo_root) {
        return Err("VOLTA_X4C_SESSION_DIR must be outside the source checkout".to_owned());
    }
    let session_parent =
        session_dir.parent().ok_or_else(|| "VOLTA_X4C_SESSION_DIR has no parent".to_owned())?;
    let canonical_parent = fs::canonicalize(session_parent).map_err(|error| {
        format!("canonicalize session parent {}: {error}", session_parent.display())
    })?;
    if canonical_parent != PathBuf::from(&local.path) {
        return Err("VOLTA_X4C_SESSION_DIR must be a direct child of VOLTA_X4C_LOCAL_STORAGE_DIR"
            .to_owned());
    }
    fs::create_dir(&session_dir).map_err(|error| {
        format!("create fresh exclusive X4c session directory {}: {error}", session_dir.display())
    })?;
    let session_metadata = fs::metadata(&session_dir)
        .map_err(|error| format!("stat session directory {}: {error}", session_dir.display()))?;
    if session_metadata.dev() != local.device_id {
        return Err("X4c session directory is not on declared local storage".to_owned());
    }

    let start_path = session_dir.join("00-note6-started.json");
    let start_bytes = create_new_json(
        &start_path,
        &SessionStartMarker {
            schema: 1,
            state: "NOTE6_STARTED_NO_X4C_OR_77GB_WORK",
            pod_profile: POD_PROFILE,
            pod_id: &pod_id,
            git_sha: &git_sha,
            required_first_action: "c3_weights_two_weight_set_leakage_smoke",
            prior_x4c_or_77gb_work: false,
        },
    )?;

    let started = Instant::now();
    let output = execute_note6()?;
    let wall_s = started.elapsed().as_secs_f64();
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    let passed = output.status.success();

    let outcome_path =
        session_dir.join(if passed { "01-note6-pass.json" } else { "01-note6-fail.json" });
    let outcome_bytes = create_new_json(
        &outcome_path,
        &SessionOutcomeMarker {
            schema: 1,
            state: if passed { "NOTE6_PASS" } else { "NOTE6_FAIL" },
            pod_profile: POD_PROFILE,
            git_sha: &git_sha,
            note6_passed: passed,
            x4c_or_77gb_work_started_before_pass: false,
            next_action_authorized: passed,
        },
    )?;

    let record = Record {
        schema: 1,
        milestone: "X4c-R1b-NOTE-6-preflight".to_owned(),
        date,
        git_sha,
        git_short_sha,
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        protocol_profile: PROTOCOL_PROFILE.to_owned(),
        design_sha256: DESIGN_SHA256.to_owned(),
        command: COMMAND.to_owned(),
        machine: Machine {
            provider,
            pod_id,
            hostname,
            gpu,
            driver,
            cpu,
            logical_cpus,
            proc_memtotal_bytes: memory_bytes,
            proc_memtotal_gate_bytes: MIN_HOST_RAM_BYTES,
            proc_memtotal_gate_passed: true,
            current_process_affinity: process_affinity(),
        },
        storage,
        worker_policy: WorkerPolicy {
            proving_rayon_num_threads: PROVING_RAYON_THREADS,
            note6_child_rayon_num_threads: PROVING_RAYON_THREADS,
            commit_onboarding_policy: "UNPINNED; not executed by NOTE-6".to_owned(),
            seal_policy: "UNPINNED; not executed by NOTE-6".to_owned(),
            open_policy: "UNPINNED; not executed by NOTE-6".to_owned(),
            commit_seal_open_executed_by_note6: false,
            actual_phase_workers_and_affinity_required_in_later_records: true,
        },
        preflight_order: PreflightOrder {
            required_first: "c3_weights_two_weight_set_leakage_smoke".to_owned(),
            first_production_size_test_started: "c3_weights_two_weight_set_leakage_smoke".to_owned(),
            operator_first_action_attestation: true,
            fresh_session_directory_created_exclusively: true,
            session_start_marker_path: start_path.display().to_string(),
            session_start_marker_blake3: blake3_hex(&start_bytes),
            session_outcome_marker_path: outcome_path.display().to_string(),
            session_outcome_marker_blake3: blake3_hex(&outcome_bytes),
            live_x4c_or_legacy_production_processes_before_start: live_processes,
            x4c_or_77gb_work_started_before_pass: false,
            order_satisfied: passed,
        },
        test: TestRecord {
            passed,
            exit_code: output.status.code(),
            monotonic_wall_s: wall_s,
            timing_source: "std::time::Instant host monotonic wall".to_owned(),
            cuda_event_timing_used: false,
            stdout_blake3: blake3_hex(&output.stdout),
            stderr_blake3: blake3_hex(&output.stderr),
            encoded_geometry_bytes: ENCODED_GEOMETRY_BYTES,
            leakage_verdict: if passed { "PASS" } else { "FAIL" }.to_owned(),
        },
        immutable_surface: ImmutableSurface {
            rate: "1/8".to_owned(),
            query_count: 111,
            pcs_bytes: 2_683_236,
            response_bytes: 43_953_700,
            protocol_changed: false,
            proof_format_changed: false,
            roots_changed: false,
            lean_changed: false,
            soundness_changed: false,
        },
        assurance: "R1b NOTE-6 execution and X4c session-order evidence only; no X4c/77-GB work and no independent human-review assurance"
            .to_owned(),
    };
    create_new_json(&output_path, &record)?;
    eprintln!("wrote append-only {}", output_path.display());
    Ok(passed)
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("x4c_note6_record: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(
        path: &str,
        filesystem_type: &str,
        source: &str,
        target: &str,
        device_id: u64,
        available_bytes: u64,
    ) -> StorageAnchor {
        StorageAnchor {
            path: path.to_owned(),
            filesystem_type: filesystem_type.to_owned(),
            mount_target: target.to_owned(),
            mount_source: source.to_owned(),
            mount_options: "rw".to_owned(),
            mount_major_minor: device_id.to_string(),
            filesystem_root: "/".to_owned(),
            device_id,
            total_bytes: available_bytes * 2,
            available_bytes,
        }
    }

    #[test]
    fn parses_exact_proc_memtotal_bytes() {
        assert_eq!(
            parse_memtotal_bytes("MemTotal:       268435456 kB\nMemFree: 1 kB\n").unwrap(),
            MIN_HOST_RAM_BYTES
        );
        assert!(parse_memtotal_bytes("MemFree: 10 kB\n").is_err());
    }

    #[test]
    fn gpu_selection_is_exact_and_single() {
        let row = "0, NVIDIA A100-SXM4-80GB, GPU-abc, 81920";
        let gpu = parse_selected_gpu(row, Some("GPU-abc")).unwrap();
        assert_eq!(gpu.cuda_ordinal, 0);
        assert_eq!(gpu.memory_bytes, 85_899_345_920);
        let remapped =
            parse_selected_gpu("3, NVIDIA A100-SXM4-80GB, GPU-def, 81920", Some("3")).unwrap();
        assert_eq!(remapped.cuda_ordinal, 0);
        assert_eq!(remapped.nvidia_smi_index, 3);
        assert!(parse_selected_gpu("3, NVIDIA A100-SXM4-80GB, GPU-def, 81920", None).is_err());
        assert!(parse_selected_gpu(row, Some("0,1")).is_err());
        assert!(parse_selected_gpu(
            "0, NVIDIA A100-SXM4-80GB, GPU-a, 81920\n1, NVIDIA A100-SXM4-80GB, GPU-b, 81920",
            None
        )
        .is_err());
        assert!(parse_selected_gpu("0, NVIDIA A100-PCIE-80GB, GPU-a, 81920", None).is_err());
        assert!(parse_selected_gpu("0, NVIDIA A100-SXM4-80GB, GPU-a, 81251", None).is_err());
    }

    #[test]
    fn storage_profile_requires_exact_separate_tiers() {
        let durable = storage(
            "/persistent",
            "ext4",
            "/dev/persistent",
            "/persistent",
            10,
            DURABLE_TIER_BYTES,
        );
        let local = storage("/local", "xfs", "/dev/local", "/local", 20, MIN_LOCAL_STORAGE_BYTES);
        let records = storage(
            "/repo/benchmarks/results",
            "xfs",
            "/dev/local",
            "/local",
            20,
            MIN_LOCAL_STORAGE_BYTES,
        );
        let profile = validate_storage(durable.clone(), local.clone(), records).unwrap();
        assert_eq!(profile.durable_exact_payload_bytes, DURABLE_TIER_BYTES);
        assert!(profile.separate_device_ids);
        assert!(profile.records_on_local_device);

        let mut undersized = durable.clone();
        undersized.available_bytes -= 1;
        assert!(validate_storage(
            undersized,
            local.clone(),
            storage(
                "/repo/benchmarks/results",
                "xfs",
                "/dev/local",
                "/local",
                20,
                MIN_LOCAL_STORAGE_BYTES,
            )
        )
        .is_err());

        let mfs =
            storage("/local", "fuse.mfs", "/dev/local", "/local", 20, MIN_LOCAL_STORAGE_BYTES);
        assert!(validate_storage(
            durable,
            mfs,
            storage(
                "/repo/benchmarks/results",
                "fuse.mfs",
                "/dev/local",
                "/local",
                20,
                MIN_LOCAL_STORAGE_BYTES,
            )
        )
        .is_err());
    }

    #[test]
    fn frozen_durable_geometry_is_exact() {
        assert_eq!(DURABLE_COEFFICIENT_BYTES + DURABLE_ROOT_BYTES, DURABLE_TIER_BYTES);
        assert_eq!(DURABLE_ROOT_BYTES, 5 * 32);
        assert_eq!(GPU_MEMORY_MIB * 1024 * 1024, 85_899_345_920);
    }
}
