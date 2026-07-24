//! Fail-closed RunPod record harness for the frozen X4c v1 design.
//!
//! `onboard` creates the durable coefficient/root tier after one warm-up and
//! three measured CUDA commit passes. `online` is intentionally a separate
//! invocation: it rebuilds the complete initial oracle/cache in host RAM from
//! that durable tier, then runs one warm-up and three measured X4c responses.
//! All timers are monotonic host wall timers. CUDA timing events are forbidden.

use rayon::prelude::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_accel::{Backend, BackendStats, Operation, ResidentTimingPolicy};
use volta_field::{Fp, Fp2};
use volta_mac::Transcript;
use volta_pcs::x4::{
    commit_cohort_cuda_v4, global_fold_descriptor_digest_v4,
    gpt2_codec_reference_packed_opening_v4, read_persisted_coefficients_v4,
    validate_x4c_frozen_surface_v4, verify_global_folding_v4, CohortIdentityV4,
    CohortVerifierConfigV4, FrameV4, GlobalChainDraftV4, GlobalFoldChallengesV4,
    GlobalOpenMetricsV4, GlobalProverGroupV4, ModelGlobalOpeningSourceV4, OracleKindV4,
    OuterCachePolicyV4, SealedGlobalChainX4cV4, X4bCudaCohortArtifactsV4, X4bCudaCohortPathsV4,
    X4bCudaCommitMetricsV4, X4cArenaCensusV4, X4cCudaArenaRuntimeV4, X4cLifecycleWallsV4,
    X4cRamModelGlobalCohortV4, X4cResponseExecutionCountersV4, X4cResponseIoCountersV4,
    X4cResponseMetricsV4, X4cSealConfigV4, X4C_COMPLETE_PCS_BYTES_V4,
    X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4, X4C_FOLD_FRAME_BYTES_V4,
    X4C_GLOBAL_FOLDING_PROOF_BYTES_V4, X4C_MANDATORY_NON_QUERY_BYTES_V4,
    X4C_PACKED_OPENING_BYTES_V4, X4C_PRODUCTION_FOLD_ROUNDS_V4, X4C_QUERY_COUNT_V4,
    X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4, X4C_RESPONSE_BYTES_V4,
};

const SCHEMA: u64 = 1;
const POD_PROFILE: &str = "runpod-a100-x4c-v1";
const PROTOCOL_PROFILE: &str = "x4-zkdeepfold-ud-e29-v4";
const DESIGN_SHA256: &str = "57d0c0d691cc63ec043d18384348ad0e1130a5e763dc8e9ef00a7132d8abb880";
const NOTE6_MILESTONE: &str = "X4c-R1b-NOTE-6-preflight";
const LIFECYCLE_MILESTONE: &str = "X4c-phase2-exact-size-lifecycle-probe";
const NOTE6_SOURCE_SHA: &str = "207b92c60c3656efca21ca2c3167a4390c8f4463";
const DIAGNOSTIC_ONBOARDING_SOURCE_SHA: &str = "39a1868e64afd9d527756cfb2811a6f3f6a321a8";
const DIAGNOSTIC_ONBOARDING_RECORD_SHA256: &str =
    "2c4b8d71931f3bfecb48bd63612c499f2c1fe685495b705cc000449460e9e28f";
const AMENDMENT5_PREFLIGHT_PATH: &str =
    "benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json";
const AMENDMENT5_PREFLIGHT_SHA256: &str =
    "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499";
const AMENDMENT5_PREFLIGHT_SOURCE_SHA: &str = "93749b3878ea517602eee06a8d46a201b7cb3346";
const SELECTED_QUERY_TAPE_BLAKE3: &str =
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299";
const MIGRATION_REFERENCE_PATH: &str =
    "benchmarks/results/x4-v4-gpt2-migration-2026-07-21-31fc866.json";
const MIGRATION_REFERENCE_SHA256: &str =
    "d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e";
const GPU_NAME: &str = "NVIDIA A100-SXM4-80GB";
const COEFFICIENT_BYTES: u64 = 9_618_587_648;
const ROOT_BYTES: u64 = 160;
const DURABLE_BYTES: u64 = COEFFICIENT_BYTES + ROOT_BYTES;
const INITIAL_ORACLE_BYTES: u64 = 76_948_701_184;
const INITIAL_OUTER_CACHE_BYTES: u64 = 37_094_424_416;
const EXACT_LIFECYCLE_BYTES: u64 = 51_539_606_304;
const MIN_HOST_RAM_BYTES: u64 = 256 * 1024 * 1024 * 1024;
const MIN_LOCAL_AVAILABLE_BYTES: u64 = 150_000_000_000;
const GLOBAL_COHORT_ID: u32 = 0xA500_F001;
const MODEL_ROOT: [u8; 32] = [0xD2; 32];
const OPEN_CEILING_S: f64 = 1.50;
const VERIFY_CEILING_S: f64 = 0.25;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("execute {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("decode {program}: {error}"))
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
}

fn exact_env(name: &str, expected: &str) -> Result<(), String> {
    let observed = required_env(name)?;
    if observed != expected {
        return Err(format!("{name} must equal {expected:?}, got {observed:?}"));
    }
    Ok(())
}

fn clean_git_sha() -> Result<String, String> {
    let status = command_output("git", &["status", "--porcelain"])?;
    if !status.is_empty() {
        return Err("record-eligible execution requires a tracked-clean tree".to_owned());
    }
    let sha = command_output("git", &["rev-parse", "HEAD"])?;
    if !git_is_ancestor(NOTE6_SOURCE_SHA, &sha)? {
        return Err("current source is not a descendant of the NOTE-6 checkpoint".to_owned());
    }
    Ok(sha)
}

fn git_is_ancestor(ancestor: &str, descendant: &str) -> Result<bool, String> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .current_dir(repo_root())
        .status()
        .map_err(|error| format!("execute git merge-base: {error}"))?;
    Ok(status.success())
}

fn sha256(path: &Path) -> Result<String, String> {
    command_output("sha256sum", &[path.to_str().ok_or_else(|| "non-UTF8 record path".to_owned())?])?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| format!("sha256sum returned no digest for {}", path.display()))
}

fn parse_memtotal_bytes() -> Result<u64, String> {
    let text =
        fs::read_to_string("/proc/meminfo").map_err(|error| format!("read meminfo: {error}"))?;
    let kib = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemTotal:")?.split_whitespace().next()?.parse::<u64>().ok()
        })
        .ok_or_else(|| "MemTotal missing".to_owned())?;
    kib.checked_mul(1024).ok_or_else(|| "MemTotal overflow".to_owned())
}

fn available_bytes(path: &Path) -> Result<u64, String> {
    let output = command_output(
        "df",
        &[
            "--output=avail",
            "-B1",
            path.to_str().ok_or_else(|| "non-UTF8 storage path".to_owned())?,
        ],
    )?;
    output
        .lines()
        .nth(1)
        .and_then(|line| line.trim().parse::<u64>().ok())
        .ok_or_else(|| format!("invalid df output for {}", path.display()))
}

fn filesystem_type(path: &Path) -> Result<String, String> {
    command_output(
        "stat",
        &["-f", "-c", "%T", path.to_str().ok_or_else(|| "non-UTF8 storage path".to_owned())?],
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write String");
    }
    output
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("expected 32-byte lowercase hex string".to_owned());
    }
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .map_err(|error| format!("invalid hex digest: {error}"))?;
    }
    Ok(output)
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn write_append_only<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create append-only {}: {error}", path.display()))?;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    file.write_all(&bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("sync {}: {error}", path.display()))
}

fn load_json(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", path.display()))
}

fn bool_at(value: &Value, pointer: &str) -> bool {
    value.pointer(pointer).and_then(Value::as_bool) == Some(true)
}

#[derive(Clone, Debug, Serialize)]
struct InputPin {
    path: String,
    sha256: String,
    git_sha: String,
}

fn amendment5_preflight_pin() -> Result<InputPin, String> {
    let path = repo_root().join(AMENDMENT5_PREFLIGHT_PATH);
    if sha256(&path)? != AMENDMENT5_PREFLIGHT_SHA256 {
        return Err("Amendment-5 selected-tape reference digest changed".to_owned());
    }
    Ok(InputPin {
        path: path.display().to_string(),
        sha256: AMENDMENT5_PREFLIGHT_SHA256.to_owned(),
        git_sha: AMENDMENT5_PREFLIGHT_SOURCE_SHA.to_owned(),
    })
}

fn load_selected_query_draws() -> Result<Vec<u64>, String> {
    let path = repo_root().join(AMENDMENT5_PREFLIGHT_PATH);
    if sha256(&path)? != AMENDMENT5_PREFLIGHT_SHA256 {
        return Err("Amendment-5 selected-tape reference digest changed".to_owned());
    }
    let value = load_json(&path)?;
    let row = value["candidates"]
        .as_array()
        .and_then(|candidates| candidates.iter().find(|candidate| candidate["id"] == "e29-r3-s111"))
        .ok_or_else(|| "selected e29-r3-s111 row missing".to_owned())?;
    if row["rate"] != "1/8"
        || row["query_count"] != X4C_QUERY_COUNT_V4 as u64
        || row.pointer("/challenge/draw_width_bits").and_then(Value::as_u64) != Some(30)
        || row.pointer("/challenge/replacement").and_then(Value::as_bool) != Some(true)
        || row.pointer("/challenge/ordered_draws_blake3").and_then(Value::as_str)
            != Some(SELECTED_QUERY_TAPE_BLAKE3)
        || row.pointer("/bytes/packed_opening_serialized_bytes").and_then(Value::as_u64)
            != Some(X4C_PACKED_OPENING_BYTES_V4)
        || row.pointer("/bytes/complete_pcs_bytes").and_then(Value::as_u64)
            != Some(X4C_COMPLETE_PCS_BYTES_V4)
    {
        return Err("selected Amendment-5 query row changed".to_owned());
    }
    let draws = row["challenge"]["ordered_draws"]
        .as_array()
        .ok_or_else(|| "selected query draws missing".to_owned())?
        .iter()
        .map(|draw| draw.as_u64().ok_or_else(|| "selected query draw is not u64".to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    if draws.len() != X4C_QUERY_COUNT_V4 {
        return Err("selected query draw count changed".to_owned());
    }
    let mut encoded = Vec::with_capacity(4 * draws.len());
    for draw in &draws {
        encoded.extend_from_slice(
            &u32::try_from(*draw)
                .map_err(|_| "selected query draw exceeds u32".to_owned())?
                .to_le_bytes(),
        );
    }
    if blake3::hash(&encoded).to_hex().as_str() != SELECTED_QUERY_TAPE_BLAKE3 {
        return Err("selected query tape digest mismatch".to_owned());
    }
    Ok(draws)
}

#[derive(Clone, Debug)]
struct SelectedQueryTapeV4 {
    draws: Vec<u64>,
}

impl SelectedQueryTapeV4 {
    fn load() -> Result<Self, String> {
        Ok(Self { draws: load_selected_query_draws()? })
    }

    /// The selected tape is verifier-owned and can be released only through
    /// an already sealed X4c state. The prover draft/seal APIs never receive
    /// this value.
    fn release_after_roots<A>(&self, _sealed: &SealedGlobalChainX4cV4<'_, A>) -> Vec<u64> {
        self.draws.clone()
    }
}

fn validate_migration_reference() -> Result<InputPin, String> {
    let path = repo_root().join(MIGRATION_REFERENCE_PATH);
    if sha256(&path)? != MIGRATION_REFERENCE_SHA256 {
        return Err("schema-4 GPT-2 migration reference digest changed".to_owned());
    }
    let value = load_json(&path)?;
    if value["milestone"] != "X4-v4-GPT2-migration"
        || value["git_dirty"] != false
        || value["profile"] != PROTOCOL_PROFILE
        || value["query_count"] != X4C_QUERY_COUNT_V4 as u64
        || value["rate"] != "1/8"
        || value["selected_tape_blake3"] != SELECTED_QUERY_TAPE_BLAKE3
        || value.pointer("/codec/fold_frames").and_then(Value::as_u64)
            != Some(X4C_FOLD_FRAME_BYTES_V4)
        || value.pointer("/codec/packed_opening_frame").and_then(Value::as_u64)
            != Some(X4C_PACKED_OPENING_BYTES_V4)
        || value.pointer("/codec/serialized_bytes").and_then(Value::as_u64)
            != Some(X4C_COMPLETE_PCS_BYTES_V4)
        || value["complete_pcs_bytes"] != X4C_COMPLETE_PCS_BYTES_V4
        || value["non_pcs_response_bytes"] != X4C_RESPONSE_BYTES_V4 - X4C_COMPLETE_PCS_BYTES_V4
        || value["measured_response_bytes"] != X4C_RESPONSE_BYTES_V4
    {
        return Err("schema-4 GPT-2 migration reference fields changed".to_owned());
    }
    Ok(InputPin {
        path: path.display().to_string(),
        sha256: MIGRATION_REFERENCE_SHA256.to_owned(),
        git_sha: value["git_sha"]
            .as_str()
            .ok_or_else(|| "migration reference git_sha missing".to_owned())?
            .to_owned(),
    })
}

fn validate_note6(path: &Path) -> Result<InputPin, String> {
    let value = load_json(path)?;
    if value["schema"] != SCHEMA
        || value["milestone"] != NOTE6_MILESTONE
        || value["pod_profile"] != POD_PROFILE
        || value["design_sha256"] != DESIGN_SHA256
        || value["git_dirty"] != false
        || !bool_at(&value, "/preflight_order/order_satisfied")
        || value
            .pointer("/preflight_order/x4c_or_77gb_work_started_before_pass")
            .and_then(Value::as_bool)
            != Some(false)
        || !bool_at(&value, "/test/passed")
        || value.pointer("/test/leakage_verdict").and_then(Value::as_str) != Some("PASS")
    {
        return Err("NOTE-6 record is missing a required eligibility field".to_owned());
    }
    let git_sha =
        value["git_sha"].as_str().ok_or_else(|| "NOTE-6 git_sha missing".to_owned())?.to_owned();
    if git_sha != NOTE6_SOURCE_SHA {
        return Err("NOTE-6 source checkpoint changed".to_owned());
    }
    Ok(InputPin { path: path.display().to_string(), sha256: sha256(path)?, git_sha })
}

fn validate_lifecycle(path: &Path) -> Result<InputPin, String> {
    let value = load_json(path)?;
    let variants =
        value["variants"].as_array().ok_or_else(|| "lifecycle variants missing".to_owned())?;
    if value["schema"] != SCHEMA
        || value["milestone"] != LIFECYCLE_MILESTONE
        || value["pod_profile"] != POD_PROFILE
        || value["mode"] != "exact_pod"
        || value["git_dirty"] != false
        || value.pointer("/geometry/populated_bytes").and_then(Value::as_u64)
            != Some(EXACT_LIFECYCLE_BYTES)
        || value["warmup_count_per_variant"] != 1
        || value["measured_candidates_per_variant"] != 3
        || !bool_at(&value, "/all_accepted")
        || variants.len() != 4
        || variants.iter().any(|variant| {
            variant["all_accepted"] != true
                || variant["warmup_count"] != 1
                || variant["measured_candidate_count"] != 3
        })
    {
        return Err("lifecycle probe is missing a required eligibility field".to_owned());
    }
    Ok(InputPin {
        path: path.display().to_string(),
        sha256: sha256(path)?,
        git_sha: value["git_sha"]
            .as_str()
            .ok_or_else(|| "lifecycle git_sha missing".to_owned())?
            .to_owned(),
    })
}

#[derive(Clone, Debug, Serialize)]
struct MachineRow {
    provider: String,
    pod_id: String,
    gpu: String,
    gpu_uuid: String,
    cuda_visible_devices: String,
    host_ram_bytes: u64,
    logical_cpus: usize,
    rayon_workers: usize,
    affinity: String,
    commit_seal_open_unpinned: bool,
    persistent_root: String,
    persistent_filesystem_type: String,
    persistent_available_bytes: u64,
    local_root: String,
    local_filesystem_type: String,
    local_available_bytes: u64,
}

fn validate_machine(durable_root: &Path, local_root: &Path) -> Result<MachineRow, String> {
    exact_env("VOLTA_CLOUD_PROVIDER", "RunPod")?;
    exact_env("VOLTA_CLOUD_GPU_SKU", GPU_NAME)?;
    exact_env("VOLTA_X4C_PERSISTENT_CLASS", "PERSISTENT")?;
    exact_env("VOLTA_X4C_COMMIT_SEAL_OPEN_UNPINNED", "1")?;
    let cuda_visible_devices = required_env("CUDA_VISIBLE_DEVICES")?;
    if cuda_visible_devices.contains(',') {
        return Err("CUDA_VISIBLE_DEVICES must select exactly one device".to_owned());
    }
    if env::var_os("RAYON_NUM_THREADS").is_some() {
        return Err("commit/seal/open must be unpinned; RAYON_NUM_THREADS is set".to_owned());
    }
    let persistent_anchor = PathBuf::from(required_env("VOLTA_X4C_PERSISTENT_DIR")?);
    let local_anchor = PathBuf::from(required_env("VOLTA_X4C_LOCAL_STORAGE_DIR")?);
    if !durable_root.starts_with(&persistent_anchor) || !local_root.starts_with(&local_anchor) {
        return Err("durable/local output roots violate their storage anchors".to_owned());
    }
    let gpu_selector = format!("--id={cuda_visible_devices}");
    let gpu_row = command_output(
        "nvidia-smi",
        &[&gpu_selector, "--query-gpu=name,uuid", "--format=csv,noheader,nounits"],
    )?;
    let gpu_rows = gpu_row.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>();
    if gpu_rows.len() != 1 {
        return Err("CUDA_VISIBLE_DEVICES did not resolve to exactly one physical GPU".to_owned());
    }
    let gpu_fields = gpu_rows[0].split(',').map(str::trim).collect::<Vec<_>>();
    if gpu_fields.len() != 2 || gpu_fields[1].is_empty() {
        return Err("selected GPU identity row is incomplete".to_owned());
    }
    let gpu = gpu_fields[0].to_owned();
    let gpu_uuid = gpu_fields[1].to_owned();
    if gpu != GPU_NAME {
        return Err(format!("selected GPU is {gpu:?}, expected {GPU_NAME:?}"));
    }
    let host_ram_bytes = parse_memtotal_bytes()?;
    if host_ram_bytes < MIN_HOST_RAM_BYTES {
        return Err("actual host RAM is below 256 GiB".to_owned());
    }
    let local_available_bytes = available_bytes(&local_anchor)?;
    if local_available_bytes < MIN_LOCAL_AVAILABLE_BYTES {
        return Err("local non-mfs storage has less than 150 GB available".to_owned());
    }
    let persistent_filesystem_type = filesystem_type(&persistent_anchor)?;
    let local_filesystem_type = filesystem_type(&local_anchor)?;
    if persistent_filesystem_type == local_filesystem_type || local_filesystem_type == "fuse" {
        return Err("persistent and local storage classes are not separated".to_owned());
    }
    Ok(MachineRow {
        provider: "RunPod".to_owned(),
        pod_id: required_env("VOLTA_X4C_POD_ID")?,
        gpu,
        gpu_uuid,
        cuda_visible_devices,
        host_ram_bytes,
        logical_cpus: std::thread::available_parallelism().map_or(0, usize::from),
        rayon_workers: rayon::current_num_threads(),
        affinity: command_output("taskset", &["-pc", &std::process::id().to_string()])?,
        commit_seal_open_unpinned: true,
        persistent_root: persistent_anchor.display().to_string(),
        persistent_filesystem_type,
        persistent_available_bytes: available_bytes(&persistent_anchor)?,
        local_root: local_anchor.display().to_string(),
        local_filesystem_type,
        local_available_bytes,
    })
}

fn clean_source_sha256() -> Result<([u8; 32], String, String), String> {
    let encoded = required_env("VOLTA_X4C_CLEAN_SOURCE_SHA256")?;
    let digest = parse_hex_32(&encoded)?;
    if digest == [0; 32] {
        return Err("VOLTA_X4C_CLEAN_SOURCE_SHA256 must be nonzero".to_owned());
    }
    let bundle = PathBuf::from(required_env("VOLTA_X4C_SOURCE_BUNDLE")?);
    if !bundle.is_file() || sha256(&bundle)? != encoded {
        return Err("clean-source bundle is missing or its SHA-256 does not match".to_owned());
    }
    Ok((digest, encoded, bundle.display().to_string()))
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

fn config_specs() -> Vec<CohortSpec> {
    [
        ("Wext-mu26-global-tied-roles", 0xA500_0001, OracleKindV4::WeightExtension, 30, 2, 2),
        ("Wext-mu22-all-layers", 0xA500_0002, OracleKindV4::WeightExtension, 26, 36, 64),
        ("Wext-mu20-layers-and-position", 0xA500_0003, OracleKindV4::WeightExtension, 24, 13, 16),
        ("auxiliary-ell17", 0xA500_0100, OracleKindV4::Auxiliary, 20, 2, 2),
        ("auxiliary-ell16", 0xA500_0101, OracleKindV4::Auxiliary, 19, 49, 64),
    ]
    .into_iter()
    .map(|(name, cohort_id, oracle_kind, domain_log2, present, structural)| CohortSpec {
        name,
        config: CohortVerifierConfigV4 {
            identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round: 0 },
            slot_descriptors: (0..structural)
                .map(|slot| (slot < present).then(|| descriptor(cohort_id, slot)))
                .collect(),
            outer_len: 1usize << domain_log2,
            expected_symbol_count: 1,
        },
        coefficients: Vec::new(),
    })
    .collect()
}

#[derive(Clone, Debug, Default, Serialize)]
struct IoSnapshot {
    rchar: u64,
    wchar: u64,
    read_bytes: u64,
    write_bytes: u64,
}

impl IoSnapshot {
    fn current() -> Self {
        let text = fs::read_to_string("/proc/self/io").unwrap_or_default();
        let read = |name: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        Self {
            rchar: read("rchar:"),
            wchar: read("wchar:"),
            read_bytes: read("read_bytes:"),
            write_bytes: read("write_bytes:"),
        }
    }

    fn delta(&self, before: &Self) -> Self {
        Self {
            rchar: self.rchar.saturating_sub(before.rchar),
            wchar: self.wchar.saturating_sub(before.wchar),
            read_bytes: self.read_bytes.saturating_sub(before.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(before.write_bytes),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct BackendRow {
    measurement_wall_ns: u64,
    operations: Vec<(String, u64)>,
    h2d_bytes: u64,
    d2h_bytes: u64,
    device_zeroed_bytes: u64,
    synchronizations: u64,
    allocation_calls: u64,
    resident_alloc_requests: u64,
    resident_reuse_hits: u64,
    resident_free_requests: u64,
    physical_free_calls: u64,
    peak_device_bytes: u64,
    pinned_allocation_calls: u64,
    pinned_alloc_requests: u64,
    pinned_reuse_hits: u64,
    pinned_free_requests: u64,
    pinned_physical_free_calls: u64,
    x4c_arena_reset_calls: u64,
    x4c_arena_reset_bytes: u64,
    x4c_kernel_launches: u64,
    timing_event_api_calls: u64,
}

impl From<BackendStats> for BackendRow {
    fn from(stats: BackendStats) -> Self {
        Self {
            measurement_wall_ns: stats.measurement_wall_ns,
            operations: Operation::ALL
                .into_iter()
                .map(|operation| (operation.name().to_owned(), stats.operation(operation).calls))
                .collect(),
            h2d_bytes: stats.h2d_bytes,
            d2h_bytes: stats.d2h_bytes,
            device_zeroed_bytes: stats.device_zeroed_bytes,
            synchronizations: stats.synchronizations,
            allocation_calls: stats.allocation_calls,
            resident_alloc_requests: stats.resident_alloc_requests,
            resident_reuse_hits: stats.resident_reuse_hits,
            resident_free_requests: stats.resident_free_requests,
            physical_free_calls: stats.physical_free_calls,
            peak_device_bytes: stats.peak_device_bytes,
            pinned_allocation_calls: stats.pinned_allocation_calls,
            pinned_alloc_requests: stats.pinned_alloc_requests,
            pinned_reuse_hits: stats.pinned_reuse_hits,
            pinned_free_requests: stats.pinned_free_requests,
            pinned_physical_free_calls: stats.pinned_physical_free_calls,
            x4c_arena_reset_calls: stats.x4c_arena_reset_calls,
            x4c_arena_reset_bytes: stats.x4c_arena_reset_bytes,
            x4c_kernel_launches: stats.x4c_kernel_launches,
            timing_event_api_calls: stats.timing_event_api_calls,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CommitMetricsRow {
    coefficient_bytes_persisted: u64,
    oracle_bytes_persisted: u64,
    root_bytes_persisted: u64,
    staging_bytes_read: u64,
    staging_bytes_written: u64,
    retained_outer_cache_bytes: u64,
    expected_h2d_bytes: u64,
    expected_d2h_bytes: u64,
}

impl From<&X4bCudaCommitMetricsV4> for CommitMetricsRow {
    fn from(value: &X4bCudaCommitMetricsV4) -> Self {
        Self {
            coefficient_bytes_persisted: value.coefficient_bytes_persisted,
            oracle_bytes_persisted: value.oracle_bytes_persisted,
            root_bytes_persisted: value.root_bytes_persisted,
            staging_bytes_read: value.staging_bytes_read,
            staging_bytes_written: value.staging_bytes_written,
            retained_outer_cache_bytes: value.retained_outer_cache_bytes,
            expected_h2d_bytes: value.expected_h2d_bytes,
            expected_d2h_bytes: value.expected_d2h_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct CohortPassRow {
    name: String,
    cohort_id: u32,
    wall_s: f64,
    root_hex: String,
    metrics: CommitMetricsRow,
}

#[derive(Clone, Debug, Serialize)]
struct OnboardingPassRow {
    role: String,
    measured: bool,
    wall_s: f64,
    io: IoSnapshot,
    backend: BackendRow,
    cohorts: Vec<CohortPassRow>,
    coefficient_bytes: u64,
    oracle_bytes: u64,
    root_bytes: u64,
    retained_durable: bool,
    cleanup_complete: bool,
    accepted: bool,
}

fn cohort_paths(
    coefficient_root: &Path,
    scratch_root: &Path,
    cohort_id: u32,
) -> Result<X4bCudaCohortPathsV4, String> {
    let durable = coefficient_root.join(format!("cohort-{cohort_id:08x}"));
    let scratch = scratch_root.join(format!("cohort-{cohort_id:08x}"));
    fs::create_dir(&durable)
        .map_err(|error| format!("create durable cohort {}: {error}", durable.display()))?;
    fs::create_dir(&scratch)
        .map_err(|error| format!("create scratch cohort {}: {error}", scratch.display()))?;
    Ok(X4bCudaCohortPathsV4 {
        coefficients: durable.join("coefficients.bin"),
        oracle: scratch.join("oracle.bin"),
        root: durable.join("root.bin"),
        staging_directory: scratch.join("staging"),
    })
}

fn run_onboarding_pass(
    role: &str,
    measured: bool,
    backend: &mut Backend,
    specs: &[CohortSpec],
    coefficient_root: &Path,
    scratch_root: &Path,
    retain_durable: bool,
) -> Result<(OnboardingPassRow, Vec<String>), String> {
    fs::create_dir_all(coefficient_root)
        .map_err(|error| format!("create pass coefficient root: {error}"))?;
    fs::create_dir_all(scratch_root)
        .map_err(|error| format!("create pass scratch root: {error}"))?;
    let before_io = IoSnapshot::current();
    backend
        .begin_measurement()
        .map_err(|error| format!("begin onboarding measurement: {error}"))?;
    let started = Instant::now();
    let mut artifacts: Vec<X4bCudaCohortArtifactsV4> = Vec::new();
    let mut cohorts = Vec::new();
    let mut totals = X4bCudaCommitMetricsV4::default();
    for spec in specs {
        let paths = cohort_paths(coefficient_root, scratch_root, spec.config.identity.cohort_id)?;
        let cohort_started = Instant::now();
        let artifact = commit_cohort_cuda_v4(
            backend,
            spec.config.clone(),
            &spec.coefficients,
            paths,
            OuterCachePolicyV4::FULL,
        )
        .map_err(|error| format!("commit {}: {error}", spec.name))?;
        totals
            .include(&artifact.metrics)
            .map_err(|error| format!("sum commit metrics: {error}"))?;
        cohorts.push(CohortPassRow {
            name: spec.name.to_owned(),
            cohort_id: spec.config.identity.cohort_id,
            wall_s: cohort_started.elapsed().as_secs_f64(),
            root_hex: hex(&artifact.commitment.root),
            metrics: CommitMetricsRow::from(&artifact.metrics),
        });
        artifacts.push(artifact);
    }
    let wall_s = started.elapsed().as_secs_f64();
    let stats = backend
        .finish_measurement()
        .map_err(|error| format!("finish onboarding measurement: {error}"))?;
    let roots = cohorts.iter().map(|cohort| cohort.root_hex.clone()).collect::<Vec<_>>();
    let paths = artifacts.iter().map(|artifact| artifact.paths.clone()).collect::<Vec<_>>();
    drop(artifacts);
    for path in &paths {
        fs::remove_file(&path.oracle)
            .map_err(|error| format!("remove onboarding oracle: {error}"))?;
        fs::remove_dir(&path.staging_directory)
            .map_err(|error| format!("remove onboarding staging: {error}"))?;
        fs::remove_dir(
            path.oracle.parent().ok_or_else(|| "scratch cohort has no parent".to_owned())?,
        )
        .map_err(|error| format!("remove scratch cohort: {error}"))?;
        if !retain_durable {
            fs::remove_file(&path.coefficients)
                .map_err(|error| format!("remove temporary coefficients: {error}"))?;
            fs::remove_file(&path.root)
                .map_err(|error| format!("remove temporary root: {error}"))?;
            fs::remove_dir(
                path.coefficients
                    .parent()
                    .ok_or_else(|| "durable cohort has no parent".to_owned())?,
            )
            .map_err(|error| format!("remove temporary durable cohort: {error}"))?;
        }
    }
    fs::remove_dir(scratch_root).map_err(|error| format!("remove pass scratch root: {error}"))?;
    if !retain_durable {
        fs::remove_dir(coefficient_root)
            .map_err(|error| format!("remove temporary coefficient root: {error}"))?;
    }
    let backend_row = BackendRow::from(stats);
    let io = IoSnapshot::current().delta(&before_io);
    let accepted = totals.coefficient_bytes_persisted == COEFFICIENT_BYTES
        && totals.oracle_bytes_persisted == INITIAL_ORACLE_BYTES
        && totals.root_bytes_persisted == ROOT_BYTES
        && totals.retained_outer_cache_bytes == INITIAL_OUTER_CACHE_BYTES
        && backend_row.h2d_bytes == totals.expected_h2d_bytes
        && backend_row.d2h_bytes == totals.expected_d2h_bytes
        && backend_row.timing_event_api_calls == 0
        && paths.iter().all(|path| {
            !path.oracle.exists()
                && !path.staging_directory.exists()
                && (retain_durable
                    == (path.coefficients.is_file()
                        && path.root.is_file()
                        && path.coefficients.parent().is_some_and(Path::is_dir)))
        });
    Ok((
        OnboardingPassRow {
            role: role.to_owned(),
            measured,
            wall_s,
            io,
            backend: backend_row,
            cohorts,
            coefficient_bytes: totals.coefficient_bytes_persisted,
            oracle_bytes: totals.oracle_bytes_persisted,
            root_bytes: totals.root_bytes_persisted,
            retained_durable: retain_durable,
            cleanup_complete: true,
            accepted,
        },
        roots,
    ))
}

#[derive(Clone, Debug, Serialize)]
struct DurableFileRow {
    cohort_id: u32,
    coefficient_path: String,
    coefficient_bytes: u64,
    coefficient_sha256: String,
    root_path: String,
    root_bytes: u64,
    root_hex: String,
    root_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct OnboardingReport {
    schema: u64,
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    pod_profile: String,
    protocol_profile: String,
    design_sha256: String,
    clean_source_sha256: String,
    clean_source_bundle_path: String,
    note6: InputPin,
    lifecycle_probe: InputPin,
    machine: MachineRow,
    worker_policy: String,
    warmup: OnboardingPassRow,
    measured: Vec<OnboardingPassRow>,
    selected_upper_median_wall_s: f64,
    durable_files: Vec<DurableFileRow>,
    durable_coefficient_file_count: u64,
    durable_root_file_count: u64,
    durable_oracle_file_count: u64,
    durable_bytes: u64,
    durable_tier_exact: bool,
    roots_identical_across_passes: bool,
    response_work_executed: bool,
    complete_online_wall_ceiling: Option<f64>,
    overall_pass: bool,
    assurance: String,
}

fn run_onboard(args: &Args) -> Result<(), String> {
    validate_x4c_frozen_surface_v4(
        "1/8",
        X4C_QUERY_COUNT_V4,
        X4C_COMPLETE_PCS_BYTES_V4,
        X4C_RESPONSE_BYTES_V4,
    )
    .map_err(|error| format!("frozen surface: {error:?}"))?;
    let git_sha = clean_git_sha()?;
    let (_, clean_source_sha256, clean_source_bundle_path) = clean_source_sha256()?;
    let note6 = validate_note6(&args.note6)?;
    let lifecycle = validate_lifecycle(
        args.lifecycle.as_deref().ok_or_else(|| "onboard requires --lifecycle".to_owned())?,
    )?;
    let durable_root = &args.durable_root;
    let scratch_root =
        args.scratch_root.as_deref().ok_or_else(|| "onboard requires --scratch-root".to_owned())?;
    let machine = validate_machine(durable_root, scratch_root)?;
    let local_anchor = PathBuf::from(required_env("VOLTA_X4C_LOCAL_STORAGE_DIR")?);
    if !args.output.starts_with(&local_anchor) {
        return Err("onboarding record output must be on local non-mfs storage".to_owned());
    }
    if durable_root.exists() || scratch_root.exists() {
        return Err("onboarding roots must be fresh append-only paths".to_owned());
    }
    let specs = gpt2_specs();
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize wall-only CUDA backend: {error}"))?;
    let temp_root = scratch_root.join("temporary-coefficients");
    let (warmup, roots) = run_onboarding_pass(
        "warmup",
        false,
        &mut backend,
        &specs,
        &temp_root.join("warmup"),
        &scratch_root.join("warmup"),
        false,
    )?;
    let mut measured = Vec::new();
    let mut roots_identical = true;
    for ordinal in 1..=3 {
        let retain = ordinal == 3;
        let coefficient_root = if retain {
            durable_root.clone()
        } else {
            temp_root.join(format!("measured-{ordinal}"))
        };
        let (row, observed_roots) = run_onboarding_pass(
            &format!("measured-{ordinal}"),
            true,
            &mut backend,
            &specs,
            &coefficient_root,
            &scratch_root.join(format!("measured-{ordinal}")),
            retain,
        )?;
        roots_identical &= observed_roots == roots;
        measured.push(row);
    }
    fs::remove_dir(&temp_root)
        .map_err(|error| format!("remove temporary coefficient root: {error}"))?;
    fs::remove_dir(scratch_root)
        .map_err(|error| format!("remove empty onboarding scratch root: {error}"))?;
    let mut durable_files = Vec::new();
    for (spec, root_hex) in specs.iter().zip(&roots) {
        let cohort = durable_root.join(format!("cohort-{:08x}", spec.config.identity.cohort_id));
        let coefficient_path = cohort.join("coefficients.bin");
        let root_path = cohort.join("root.bin");
        let mut root_bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .open(&root_path)
            .map_err(|error| format!("open durable root: {error}"))?
            .read_to_end(&mut root_bytes)
            .map_err(|error| format!("read durable root: {error}"))?;
        if root_bytes.len() != 32 || hex(&root_bytes) != *root_hex {
            return Err("durable root bytes differ from measured root".to_owned());
        }
        durable_files.push(DurableFileRow {
            cohort_id: spec.config.identity.cohort_id,
            coefficient_path: coefficient_path.display().to_string(),
            coefficient_bytes: fs::metadata(&coefficient_path)
                .map_err(|error| format!("stat coefficients: {error}"))?
                .len(),
            coefficient_sha256: sha256(&coefficient_path)?,
            root_path: root_path.display().to_string(),
            root_bytes: root_bytes.len() as u64,
            root_hex: root_hex.clone(),
            root_sha256: sha256(&root_path)?,
        });
    }
    let durable_bytes = durable_files.iter().try_fold(0u64, |sum, file| {
        sum.checked_add(file.coefficient_bytes + file.root_bytes)
            .ok_or_else(|| "durable byte sum overflow".to_owned())
    })?;
    let selected = upper_median(measured.iter().map(|row| row.wall_s).collect());
    let all_passes = warmup.accepted && measured.iter().all(|row| row.accepted);
    let durable_tier_exact = durable_files.len() == 5 && durable_bytes == DURABLE_BYTES;
    let overall_pass = all_passes && durable_tier_exact && roots_identical;
    let report = OnboardingReport {
        schema: SCHEMA,
        milestone: "X4c-v1-A100-onboarding".to_owned(),
        date: command_output("date", &["+%Y-%m-%d"])?,
        git_sha,
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        protocol_profile: PROTOCOL_PROFILE.to_owned(),
        design_sha256: DESIGN_SHA256.to_owned(),
        clean_source_sha256,
        clean_source_bundle_path,
        note6,
        lifecycle_probe: lifecycle,
        machine,
        worker_policy: "UNPINNED commit path; RAYON_NUM_THREADS absent".to_owned(),
        warmup,
        measured,
        selected_upper_median_wall_s: selected,
        durable_files,
        durable_coefficient_file_count: 5,
        durable_root_file_count: 5,
        durable_oracle_file_count: 0,
        durable_bytes,
        durable_tier_exact,
        roots_identical_across_passes: roots_identical,
        response_work_executed: false,
        complete_online_wall_ceiling: None,
        overall_pass,
        assurance: "AI-generated X4c onboarding record; no independent human-review assurance. R1c review remains mandatory.".to_owned(),
    };
    write_append_only(&args.output, &report)?;
    if !overall_pass {
        return Err(format!(
            "X4c onboarding hard gate failed; obstruction record written to {}",
            args.output.display()
        ));
    }
    eprintln!(
        "X4c onboarding PASS: upper median {:.6}s, durable {} B; wrote {}",
        selected,
        durable_bytes,
        args.output.display()
    );
    Ok(())
}

fn read_durable_root(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    bytes.try_into().map_err(|_| format!("{} is not exactly 32 bytes", path.display()))
}

#[derive(Clone, Debug, Serialize)]
struct RebuildCohortRow {
    ordinal: usize,
    name: String,
    cohort_id: u32,
    wall_s: f64,
    coefficient_bytes_read: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    root: String,
    expected_root: String,
    root_equal: bool,
    durable_oracle_file: bool,
    accepted: bool,
}

#[derive(Clone, Debug, Serialize)]
struct RebuildRow {
    wall_s: f64,
    io: IoSnapshot,
    parallel_task_count: usize,
    rayon_workers: usize,
    cohorts: Vec<RebuildCohortRow>,
    coefficient_bytes_read: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    roots: Vec<String>,
    roots_equal_onboarding: bool,
    durable_oracle_files: u64,
    accepted: bool,
}

fn rebuild_one_source(
    ordinal: usize,
    spec: CohortSpec,
    recorded: &Value,
    durable_root: &Path,
) -> Result<(X4cRamModelGlobalCohortV4, RebuildCohortRow), String> {
    let started = Instant::now();
    let cohort_id = spec.config.identity.cohort_id;
    let cohort = durable_root.join(format!("cohort-{cohort_id:08x}"));
    let coefficient_path = cohort.join("coefficients.bin");
    let root_path = cohort.join("root.bin");
    let expected_root_hex =
        recorded["root_hex"].as_str().ok_or_else(|| "onboarding root_hex missing".to_owned())?;
    let expected_root = parse_hex_32(expected_root_hex)?;
    if read_durable_root(&root_path)? != expected_root
        || sha256(&coefficient_path)?
            != recorded["coefficient_sha256"]
                .as_str()
                .ok_or_else(|| "onboarding coefficient digest missing".to_owned())?
        || sha256(&root_path)?
            != recorded["root_sha256"]
                .as_str()
                .ok_or_else(|| "onboarding root digest missing".to_owned())?
    {
        return Err(format!("durable artifact digest/root mismatch for cohort {cohort_id:08x}"));
    }
    let coefficient_bytes = fs::metadata(&coefficient_path)
        .map_err(|error| format!("stat coefficients: {error}"))?
        .len();
    let expected_oracle_bytes =
        u64::try_from(spec.config.slot_descriptors.iter().flatten().count())
            .map_err(|_| "cohort present-slot count overflows u64".to_owned())?
            .checked_mul(
                u64::try_from(spec.config.outer_len)
                    .map_err(|_| "cohort outer length overflows u64".to_owned())?,
            )
            .and_then(|symbols| symbols.checked_mul(16))
            .ok_or_else(|| "cohort oracle byte overflow".to_owned())?;
    let expected_outer_cache_bytes = u64::try_from(spec.config.outer_len)
        .map_err(|_| "cohort outer length overflows u64".to_owned())?
        .checked_sub(1)
        .and_then(|digests| digests.checked_mul(32))
        .ok_or_else(|| "cohort outer-cache byte overflow".to_owned())?;
    let coefficients = read_persisted_coefficients_v4(&coefficient_path, &spec.config)
        .map_err(|error| format!("read persisted coefficients: {error:?}"))?;
    let source = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
        spec.config,
        coefficients,
        expected_root,
    )
    .map_err(|error| format!("rebuild X4c RAM source: {error:?}"))?;
    let root = hex(&source.root());
    let host_oracle_bytes =
        source.host_oracle_bytes().map_err(|error| format!("host oracle census: {error:?}"))?;
    let host_outer_cache_bytes =
        source.host_outer_cache_bytes().map_err(|error| format!("host cache census: {error:?}"))?;
    let root_equal = root == expected_root_hex;
    let durable_oracle_file = cohort.join("oracle.bin").exists();
    let accepted = root_equal
        && coefficient_bytes
            == recorded["coefficient_bytes"]
                .as_u64()
                .ok_or_else(|| "onboarding coefficient_bytes missing".to_owned())?
        && host_oracle_bytes == expected_oracle_bytes
        && host_outer_cache_bytes == expected_outer_cache_bytes
        && !durable_oracle_file;
    Ok((
        source,
        RebuildCohortRow {
            ordinal,
            name: spec.name.to_owned(),
            cohort_id,
            wall_s: started.elapsed().as_secs_f64(),
            coefficient_bytes_read: coefficient_bytes,
            host_oracle_bytes,
            host_outer_cache_bytes,
            root,
            expected_root: expected_root_hex.to_owned(),
            root_equal,
            durable_oracle_file,
            accepted,
        },
    ))
}

fn rebuild_sources(
    durable_root: &Path,
    onboarding: &Value,
) -> Result<(Vec<X4cRamModelGlobalCohortV4>, RebuildRow), String> {
    let before_io = IoSnapshot::current();
    let started = Instant::now();
    let specs = config_specs();
    let recorded_files = onboarding["durable_files"]
        .as_array()
        .ok_or_else(|| "onboarding durable_files missing".to_owned())?;
    if recorded_files.len() != specs.len() {
        return Err("onboarding durable file count changed".to_owned());
    }
    let parallel_task_count = specs.len();
    let rebuilt = specs
        .into_par_iter()
        .zip(recorded_files.par_iter())
        .enumerate()
        .map(|(ordinal, (spec, recorded))| {
            rebuild_one_source(ordinal, spec, recorded, durable_root)
        })
        .collect::<Vec<_>>();
    let mut sources = Vec::with_capacity(parallel_task_count);
    let mut cohorts = Vec::with_capacity(parallel_task_count);
    for result in rebuilt {
        let (source, row) = result?;
        sources.push(source);
        cohorts.push(row);
    }
    if !cohorts.windows(2).all(|pair| pair[0].ordinal < pair[1].ordinal) {
        return Err("parallel rebuild result order changed".to_owned());
    }
    let coefficient_bytes = cohorts.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.coefficient_bytes_read)
            .ok_or_else(|| "coefficient byte overflow".to_owned())
    })?;
    let host_oracle_bytes = cohorts.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.host_oracle_bytes).ok_or_else(|| "host oracle byte overflow".to_owned())
    })?;
    let host_outer_cache_bytes = cohorts.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.host_outer_cache_bytes)
            .ok_or_else(|| "host cache byte overflow".to_owned())
    })?;
    let roots = cohorts.iter().map(|row| row.root.clone()).collect::<Vec<_>>();
    let roots_equal = cohorts.iter().all(|row| row.root_equal);
    let durable_oracle_files = cohorts.iter().filter(|row| row.durable_oracle_file).count() as u64;
    let all_cohorts_accepted = cohorts.iter().all(|row| row.accepted);
    let row = RebuildRow {
        wall_s: started.elapsed().as_secs_f64(),
        io: IoSnapshot::current().delta(&before_io),
        parallel_task_count,
        rayon_workers: rayon::current_num_threads(),
        cohorts,
        coefficient_bytes_read: coefficient_bytes,
        host_oracle_bytes,
        host_outer_cache_bytes,
        roots,
        roots_equal_onboarding: roots_equal,
        durable_oracle_files,
        accepted: coefficient_bytes == COEFFICIENT_BYTES
            && host_oracle_bytes == INITIAL_ORACLE_BYTES
            && host_outer_cache_bytes == INITIAL_OUTER_CACHE_BYTES
            && roots_equal
            && durable_oracle_files == 0
            && all_cohorts_accepted,
    };
    Ok((sources, row))
}

fn common_point() -> Vec<Fp2> {
    (0..27u64).map(|index| Fp2::new(Fp::new(3 + 2 * index), Fp::new(11 + 7 * index))).collect()
}

fn prover_groups<'a>(
    sources: &'a [X4cRamModelGlobalCohortV4],
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

#[derive(Clone, Debug, Serialize)]
struct ExecutionRow {
    direct_fold_calls: u64,
    diagnostic_comparisons: u64,
    diagnostic_mismatches: u64,
    diagnostic_gather_calls: u64,
    diagnostic_index_h2d_bytes: u64,
    diagnostic_value_d2h_bytes: u64,
    n4_tree_calls: u64,
    query_gather_calls: u64,
    query_gather_operation_count: u64,
    query_gather_operation_h2d_bytes: u64,
    canonical_template_h2d_bytes: u64,
    query_draw_count: u64,
    canonical_opening_d2h_bytes: u64,
    noncanonical_opening_d2h_bytes: u64,
    cpu_fold_tree_clone_bytes: u64,
}

impl From<X4cResponseExecutionCountersV4> for ExecutionRow {
    fn from(value: X4cResponseExecutionCountersV4) -> Self {
        Self {
            direct_fold_calls: value.direct_fold_calls,
            diagnostic_comparisons: value.direct_fold_sample_comparisons,
            diagnostic_mismatches: value.direct_fold_sample_mismatches,
            diagnostic_gather_calls: value.direct_fold_diagnostic_gather_calls,
            diagnostic_index_h2d_bytes: value.direct_fold_diagnostic_index_h2d_bytes,
            diagnostic_value_d2h_bytes: value.direct_fold_diagnostic_value_d2h_bytes,
            n4_tree_calls: value.n4_tree_calls,
            query_gather_calls: value.query_gather_calls,
            query_gather_operation_count: value.query_gather_operation_count,
            query_gather_operation_h2d_bytes: value.query_gather_operation_h2d_bytes,
            canonical_template_h2d_bytes: value.canonical_template_h2d_bytes,
            query_draw_count: value.query_draw_count,
            canonical_opening_d2h_bytes: value.canonical_opening_d2h_bytes,
            noncanonical_opening_d2h_bytes: value.noncanonical_opening_d2h_bytes,
            cpu_fold_tree_clone_bytes: value.cpu_fold_tree_clone_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ArenaRow {
    capacity_bytes: u64,
    committed_bytes: u64,
    logical_allocations: u64,
    logical_deallocations: u64,
    reset_count: u64,
    zeroed_bytes: u64,
    outstanding_allocations: u64,
    outstanding_bytes: u64,
    cached_reusable_bytes: u64,
    active_device_allocations: u64,
    active_pinned_allocations: u64,
    active_pinned_bytes: u64,
    outstanding_cuda_operations: u64,
    stream_synchronized: bool,
}

impl From<X4cArenaCensusV4> for ArenaRow {
    fn from(value: X4cArenaCensusV4) -> Self {
        Self {
            capacity_bytes: value.arena_capacity_bytes,
            committed_bytes: value.arena_committed_bytes,
            logical_allocations: value.logical_allocation_count,
            logical_deallocations: value.logical_deallocation_count,
            reset_count: value.reset_count,
            zeroed_bytes: value.zeroed_bytes,
            outstanding_allocations: value.outstanding_allocation_count,
            outstanding_bytes: value.outstanding_bytes,
            cached_reusable_bytes: value.cached_reusable_bytes,
            active_device_allocations: value.backend_active_device_allocations,
            active_pinned_allocations: value.backend_active_pinned_allocations,
            active_pinned_bytes: value.backend_active_pinned_bytes,
            outstanding_cuda_operations: value.backend_outstanding_cuda_operations,
            stream_synchronized: value.backend_stream_synchronized,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct MetricsRow {
    response_io: ResponseIoRow,
    execution: ExecutionRow,
    proof_ready_arena: ArenaRow,
    session_reusable_arena: ArenaRow,
    proof_ready_wall_ns: u64,
    session_reusable_wall_ns: u64,
    source_coefficients_read: u64,
    initial_encoded_symbols_read: u64,
    combined_codeword_symbols: u64,
    serialized_fold_bytes: u64,
    serialized_packed_opening_bytes: u64,
    sampling_soundness_credit_bits: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ResponseIoRow {
    response_coefficient_bytes_read: u64,
    response_coefficient_bytes_written: u64,
    response_oracle_bytes_read: u64,
    response_oracle_bytes_written: u64,
    response_full_oracle_comparison_bytes: u64,
    response_staging_bytes_read: u64,
    response_staging_bytes_written: u64,
    response_staging_file_count: u64,
    response_overlay_reread_bytes: u64,
}

impl From<X4cResponseIoCountersV4> for ResponseIoRow {
    fn from(value: X4cResponseIoCountersV4) -> Self {
        Self {
            response_coefficient_bytes_read: value.response_coefficient_bytes_read,
            response_coefficient_bytes_written: value.response_coefficient_bytes_written,
            response_oracle_bytes_read: value.response_oracle_bytes_read,
            response_oracle_bytes_written: value.response_oracle_bytes_written,
            response_full_oracle_comparison_bytes: value.response_full_oracle_comparison_bytes,
            response_staging_bytes_read: value.staging_bytes_read,
            response_staging_bytes_written: value.staging_bytes_written,
            response_staging_file_count: value.staging_files_created,
            response_overlay_reread_bytes: value.response_overlay_reread_bytes,
        }
    }
}

impl From<X4cResponseMetricsV4> for MetricsRow {
    fn from(value: X4cResponseMetricsV4) -> Self {
        let X4cResponseMetricsV4 {
            io,
            execution,
            proof_ready_arena,
            session_reusable_arena,
            lifecycle_walls: X4cLifecycleWallsV4 { proof_ready_wall_ns, session_reusable_wall_ns },
            global_open:
                GlobalOpenMetricsV4 {
                    source_coefficients_read,
                    initial_encoded_symbols_read,
                    combined_codeword_symbols,
                    serialized_fold_bytes,
                    serialized_packed_opening_bytes,
                    ..
                },
            sampling_soundness_credit_bits,
            ..
        } = value;
        Self {
            response_io: io.into(),
            execution: execution.into(),
            proof_ready_arena: proof_ready_arena.into(),
            session_reusable_arena: session_reusable_arena.into(),
            proof_ready_wall_ns,
            session_reusable_wall_ns,
            source_coefficients_read,
            initial_encoded_symbols_read,
            combined_codeword_symbols,
            serialized_fold_bytes,
            serialized_packed_opening_bytes,
            sampling_soundness_credit_bits,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ResponseCandidateRow {
    role: String,
    measured: bool,
    ordinal: u64,
    epoch: u64,
    seal_wall_s: f64,
    open_wall_s: f64,
    verify_wall_s: f64,
    proof_ready_wall_s: f64,
    session_reusable_wall_s: f64,
    complete_online_wall_s: f64,
    global_folding_proof_bytes: u64,
    complete_pcs_bytes: u64,
    frozen_non_query_pcs_bytes: u64,
    packed_opening_bytes: u64,
    packed_opened_symbol_count: u64,
    packed_opened_symbol_bytes: u64,
    packed_initial_inner_sibling_count: u64,
    packed_initial_inner_sibling_bytes: u64,
    packed_initial_outer_sibling_count: u64,
    packed_initial_outer_sibling_bytes: u64,
    packed_fold_outer_sibling_count: u64,
    packed_fold_outer_sibling_bytes: u64,
    packed_metadata_bytes: u64,
    packed_components_exact: bool,
    selected_query_tape_blake3: String,
    selected_query_tape_exact: bool,
    fold_challenges_replayed: bool,
    response_bytes: u64,
    query_draws: u64,
    verifier_accepted: bool,
    transcript_bytes_equal: bool,
    transcript_ledger_equal: bool,
    process_io: IoSnapshot,
    backend: BackendRow,
    metrics: MetricsRow,
    expected_h2d_bytes: u64,
    expected_d2h_bytes: u64,
    traffic_exact: bool,
    zero_response_staging: bool,
    accepted: bool,
}

fn run_response(
    role: &str,
    ordinal: u64,
    measured: bool,
    sources: &[X4cRamModelGlobalCohortV4],
    runtime: &mut X4cCudaArenaRuntimeV4<'_>,
    clean_source_sha: [u8; 32],
    selected_query_tape: &SelectedQueryTapeV4,
) -> Result<ResponseCandidateRow, String> {
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
    let epoch = 0x5843_0000 + ordinal;
    let draft = GlobalChainDraftV4::new_interactive(
        MODEL_ROOT,
        epoch,
        GLOBAL_COHORT_ID,
        descriptor,
        point.clone(),
        groups,
    )
    .map_err(|error| format!("create X4c draft: {error:?}"))?;
    if draft.reject_query_before_seal().is_ok() {
        return Err("query draw became available before all roots were fixed".to_owned());
    }
    let seed = [0x70u8.wrapping_add(ordinal as u8); 32];
    let mut prover_tx = Transcript::new(seed);
    let before_io = IoSnapshot::current();
    runtime
        .begin_response_measurement()
        .map_err(|error| format!("begin response measurement: {error:?}"))?;
    let online_started = Instant::now();
    let seal_started = Instant::now();
    let sealed = match draft.seal_interactive_x4c(
        &mut prover_tx,
        runtime,
        X4cSealConfigV4::production(clean_source_sha, ordinal)
            .map_err(|error| format!("production seal config: {error:?}"))?,
    ) {
        Ok(sealed) => sealed,
        Err(error) => {
            let finish = runtime.finish_response_measurement();
            return Err(format!("X4c seal: {error:?}; backend_finish_after_error={finish:?}"));
        }
    };
    let seal_wall_s = seal_started.elapsed().as_secs_f64();
    let fold_challenges = sealed.challenges().clone();
    let selected_draws = selected_query_tape.release_after_roots(&sealed);
    let open_started = Instant::now();
    let (proof, verifier_groups, metrics, draws) =
        match sealed.issue_queries_x4c(selected_draws.clone(), &mut prover_tx, runtime) {
            Ok(result) => result,
            Err(error) => {
                let finish = runtime.finish_response_measurement();
                return Err(format!(
                    "X4c opening: {error:?}; backend_finish_after_error={finish:?}"
                ));
            }
        };
    let open_wall_s = open_started.elapsed().as_secs_f64();
    let complete_online_wall_s = online_started.elapsed().as_secs_f64();
    let stats = runtime
        .finish_response_measurement()
        .map_err(|error| format!("finish response measurement: {error:?}"))?;
    let verify_started = Instant::now();
    let mut verifier_tx = Transcript::new(seed);
    let mut replayed_folds = Vec::with_capacity(proof.fold_frames.len());
    for frame in &proof.fold_frames {
        verifier_tx.append("x4_v4_global_fold_line", 32);
        replayed_folds.push(verifier_tx.challenge_fp2());
        let frame_bytes = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| format!("encode fold frame for verifier replay: {error:?}"))?
            .len();
        verifier_tx.append(
            "x4_v4_global_fold_post_challenge",
            u64::try_from(
                frame_bytes
                    .checked_sub(32)
                    .ok_or_else(|| "fold frame line width underflow".to_owned())?,
            )
            .map_err(|_| "fold frame byte count overflows u64".to_owned())?,
        );
    }
    let fold_challenges_replayed =
        GlobalFoldChallengesV4 { folds: replayed_folds } == fold_challenges;
    let verifier_accepted = fold_challenges_replayed
        && verify_global_folding_v4(
            MODEL_ROOT,
            epoch,
            &point,
            &verifier_groups,
            &fold_challenges,
            &draws,
            &proof,
        )
        .is_ok();
    let packed_opening_bytes = u64::try_from(
        FrameV4::PackedBatchOpening(proof.packed_opening.clone())
            .encode()
            .map_err(|error| format!("encode packed opening: {error:?}"))?
            .len(),
    )
    .map_err(|_| "packed-opening length overflows u64".to_owned())?;
    verifier_tx.append("x4_v4_packed_opening", packed_opening_bytes);
    let verify_wall_s = verify_started.elapsed().as_secs_f64();
    let global_folding_proof_bytes = u64::try_from(
        proof
            .canonical_bytes()
            .map_err(|error| format!("encode canonical proof: {error:?}"))?
            .len(),
    )
    .map_err(|_| "global folding proof length overflows u64".to_owned())?;
    let complete_pcs_bytes = packed_opening_bytes
        .checked_add(X4C_MANDATORY_NON_QUERY_BYTES_V4)
        .ok_or_else(|| "complete PCS byte count overflows u64".to_owned())?;
    let packed_components = proof
        .packed_opening
        .byte_components()
        .map_err(|error| format!("measure packed-opening components: {error:?}"))?;
    let expected_packed_components = gpt2_codec_reference_packed_opening_v4()
        .byte_components()
        .map_err(|error| format!("measure reference packed-opening components: {error:?}"))?;
    let packed_components_exact = packed_components == expected_packed_components;
    let expected_h2d_bytes = metrics
        .global_open
        .combined_codeword_symbols
        .checked_mul(16)
        .and_then(|bytes| {
            bytes.checked_add(metrics.execution.direct_fold_diagnostic_index_h2d_bytes)
        })
        .and_then(|bytes| bytes.checked_add(metrics.execution.query_gather_operation_h2d_bytes))
        .and_then(|bytes| bytes.checked_add(metrics.execution.canonical_template_h2d_bytes))
        .ok_or_else(|| "expected H2D overflow".to_owned())?;
    let expected_d2h_bytes = (X4C_PRODUCTION_FOLD_ROUNDS_V4 as u64)
        .checked_mul(32)
        .and_then(|bytes| {
            bytes.checked_add(metrics.execution.direct_fold_diagnostic_value_d2h_bytes)
        })
        .and_then(|bytes| bytes.checked_add(metrics.execution.canonical_opening_d2h_bytes))
        .ok_or_else(|| "expected D2H overflow".to_owned())?;
    let traffic_exact = stats.h2d_bytes == expected_h2d_bytes
        && stats.d2h_bytes == expected_d2h_bytes
        && stats.x4c_arena_reset_calls == 1
        && stats.x4c_arena_reset_bytes == X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4
        && stats.device_zeroed_bytes == X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4
        && stats.timing_event_api_calls == 0;
    let zero_response_staging = metrics.io == X4cResponseIoCountersV4::default();
    let transcript_bytes_equal = prover_tx.total_bytes() == verifier_tx.total_bytes();
    let transcript_ledger_equal = prover_tx.ledger() == verifier_tx.ledger();
    let selected_query_tape_exact = selected_draws == draws && draws == selected_query_tape.draws;
    let accepted = verifier_accepted
        && global_folding_proof_bytes == X4C_GLOBAL_FOLDING_PROOF_BYTES_V4
        && complete_pcs_bytes == X4C_COMPLETE_PCS_BYTES_V4
        && metrics.global_open.serialized_fold_bytes == X4C_FOLD_FRAME_BYTES_V4
        && packed_opening_bytes == X4C_PACKED_OPENING_BYTES_V4
        && packed_components_exact
        && selected_query_tape_exact
        && fold_challenges_replayed
        && X4C_RESPONSE_BYTES_V4 == 43_953_700
        && draws.len() == X4C_QUERY_COUNT_V4
        && metrics.execution.direct_fold_sample_comparisons
            == X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 as u64
        && metrics.execution.direct_fold_sample_mismatches == 0
        && metrics.sampling_soundness_credit_bits == 0
        && metrics.execution.query_gather_calls == 1
        && metrics.execution.cpu_fold_tree_clone_bytes == 0
        && zero_response_staging
        && traffic_exact
        && transcript_bytes_equal
        && transcript_ledger_equal;
    let proof_ready_wall_s = metrics.lifecycle_walls.proof_ready_wall_ns as f64 / 1e9;
    let session_reusable_wall_s = metrics.lifecycle_walls.session_reusable_wall_ns as f64 / 1e9;
    Ok(ResponseCandidateRow {
        role: role.to_owned(),
        measured,
        ordinal,
        epoch,
        seal_wall_s,
        open_wall_s,
        verify_wall_s,
        proof_ready_wall_s,
        session_reusable_wall_s,
        complete_online_wall_s,
        global_folding_proof_bytes,
        complete_pcs_bytes,
        frozen_non_query_pcs_bytes: X4C_MANDATORY_NON_QUERY_BYTES_V4,
        packed_opening_bytes,
        packed_opened_symbol_count: packed_components.opened_symbols,
        packed_opened_symbol_bytes: packed_components.opened_symbols * 16,
        packed_initial_inner_sibling_count: packed_components.initial_inner_siblings,
        packed_initial_inner_sibling_bytes: packed_components.initial_inner_siblings * 32,
        packed_initial_outer_sibling_count: packed_components.initial_outer_siblings,
        packed_initial_outer_sibling_bytes: packed_components.initial_outer_siblings * 32,
        packed_fold_outer_sibling_count: packed_components.fold_outer_siblings,
        packed_fold_outer_sibling_bytes: packed_components.fold_outer_siblings * 32,
        packed_metadata_bytes: packed_components.metadata_bytes,
        packed_components_exact,
        selected_query_tape_blake3: SELECTED_QUERY_TAPE_BLAKE3.to_owned(),
        selected_query_tape_exact,
        fold_challenges_replayed,
        response_bytes: X4C_RESPONSE_BYTES_V4,
        query_draws: draws.len() as u64,
        verifier_accepted,
        transcript_bytes_equal,
        transcript_ledger_equal,
        process_io: IoSnapshot::current().delta(&before_io),
        backend: stats.into(),
        metrics: metrics.into(),
        expected_h2d_bytes,
        expected_d2h_bytes,
        traffic_exact,
        zero_response_staging,
        accepted,
    })
}

#[derive(Clone, Debug, Serialize)]
struct OnlineReport {
    schema: u64,
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    pod_profile: String,
    protocol_profile: String,
    design_sha256: String,
    clean_source_sha256: String,
    clean_source_bundle_path: String,
    note6: InputPin,
    lifecycle_probe: InputPin,
    onboarding: InputPin,
    amendment5_preflight: InputPin,
    codec_reference: InputPin,
    machine: MachineRow,
    worker_policy: String,
    fresh_process_rebuild: RebuildRow,
    warmup: ResponseCandidateRow,
    measured: Vec<ResponseCandidateRow>,
    selected_upper_median_open_wall_s: f64,
    selected_upper_median_verify_wall_s: f64,
    selected_upper_median_proof_ready_wall_s: f64,
    selected_upper_median_session_reusable_wall_s: f64,
    selected_upper_median_complete_online_wall_s: f64,
    complete_online_wall_status: String,
    open_ceiling_s: f64,
    verify_ceiling_s: f64,
    open_pass: bool,
    verify_pass: bool,
    all_candidates_accepted: bool,
    zero_response_staging: bool,
    exact_communication: bool,
    diagnostic_comparisons: u64,
    diagnostic_soundness_credit_bits: u64,
    pinned_pool_release_wall_s: f64,
    pinned_pool_release_restored_ownership: bool,
    protocol_or_parameter_change: bool,
    root_or_proof_format_change: bool,
    lean_or_soundness_change: bool,
    overall_pass: bool,
    assurance: String,
}

#[derive(Clone, Debug, Serialize)]
struct CanonicalDiagnosticReport {
    schema: u64,
    milestone: String,
    date: String,
    git_sha: String,
    git_dirty: bool,
    pod_profile: String,
    protocol_profile: String,
    design_sha256: String,
    clean_source_sha256: String,
    clean_source_bundle_path: String,
    note6: InputPin,
    lifecycle_probe: InputPin,
    onboarding: InputPin,
    amendment5_preflight: InputPin,
    codec_reference: InputPin,
    onboarding_ancestor_input: bool,
    machine: MachineRow,
    worker_policy: String,
    fresh_process_rebuild: RebuildRow,
    response: Option<ResponseCandidateRow>,
    response_error: Option<String>,
    pinned_pool_release_wall_s: f64,
    pinned_pool_release_error: Option<String>,
    post_release_control: Value,
    post_release_ownership_restored: bool,
    candidate_eligible: bool,
    gate_verdict: String,
    hard_stop: bool,
    protocol_or_parameter_change: bool,
    root_or_proof_format_change: bool,
    lean_or_soundness_change: bool,
    assurance: String,
}

fn run_online(args: &Args, diagnostic_only: bool) -> Result<(), String> {
    validate_x4c_frozen_surface_v4(
        "1/8",
        X4C_QUERY_COUNT_V4,
        X4C_COMPLETE_PCS_BYTES_V4,
        X4C_RESPONSE_BYTES_V4,
    )
    .map_err(|error| format!("frozen surface: {error:?}"))?;
    let git_sha = clean_git_sha()?;
    let (clean_source_sha, clean_source_sha256, clean_source_bundle_path) = clean_source_sha256()?;
    let amendment5_preflight = amendment5_preflight_pin()?;
    let selected_query_tape = SelectedQueryTapeV4::load()?;
    let codec_reference = validate_migration_reference()?;
    let note6 = validate_note6(&args.note6)?;
    let lifecycle = validate_lifecycle(
        args.lifecycle.as_deref().ok_or_else(|| "online requires --lifecycle".to_owned())?,
    )?;
    let onboarding_path =
        args.onboarding.as_deref().ok_or_else(|| "online requires --onboarding".to_owned())?;
    let onboarding_value = load_json(onboarding_path)?;
    let onboarding_sha256 = sha256(onboarding_path)?;
    let onboarding_git_sha = onboarding_value["git_sha"]
        .as_str()
        .ok_or_else(|| "onboarding git_sha missing".to_owned())?
        .to_owned();
    let onboarding_clean_source_sha256 = onboarding_value["clean_source_sha256"]
        .as_str()
        .ok_or_else(|| "onboarding clean_source_sha256 missing".to_owned())?;
    let exact_source =
        onboarding_git_sha == git_sha && onboarding_clean_source_sha256 == clean_source_sha256;
    let diagnostic_ancestor_input = diagnostic_only
        && onboarding_git_sha == DIAGNOSTIC_ONBOARDING_SOURCE_SHA
        && onboarding_sha256 == DIAGNOSTIC_ONBOARDING_RECORD_SHA256
        && git_is_ancestor(&onboarding_git_sha, &git_sha)?;
    if onboarding_value["milestone"] != "X4c-v1-A100-onboarding"
        || onboarding_value["overall_pass"] != true
        || onboarding_value["design_sha256"] != DESIGN_SHA256
        || onboarding_value["durable_tier_exact"] != true
        || (!exact_source && !diagnostic_ancestor_input)
    {
        return Err("onboarding record is not eligible for this source".to_owned());
    }
    let onboarding = InputPin {
        path: onboarding_path.display().to_string(),
        sha256: onboarding_sha256,
        git_sha: onboarding_git_sha,
    };
    let local_anchor = PathBuf::from(required_env("VOLTA_X4C_LOCAL_STORAGE_DIR")?);
    let machine = validate_machine(&args.durable_root, &local_anchor)?;
    if !args.output.starts_with(&local_anchor) {
        return Err("online record output must be on local non-mfs storage".to_owned());
    }
    let (sources, rebuild) = rebuild_sources(&args.durable_root, &onboarding_value)?;
    if !rebuild.accepted {
        return Err("fresh-process rebuild equivalence failed".to_owned());
    }
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize wall-only CUDA backend: {error}"))?;
    let mut runtime = X4cCudaArenaRuntimeV4::production(&mut backend)
        .map_err(|error| format!("create X4c reusable runtime: {error:?}"))?;
    let warmup_result = run_response(
        "warmup",
        0,
        false,
        &sources,
        &mut runtime,
        clean_source_sha,
        &selected_query_tape,
    );
    if diagnostic_only {
        let release_started = Instant::now();
        let release_error = runtime.release_pinned_pool().err().map(|error| format!("{error:?}"));
        let release_wall_s = release_started.elapsed().as_secs_f64();
        let control_result = runtime.backend_control_state();
        let release_restored = release_error.is_none()
            && control_result.as_ref().is_ok_and(|control| {
                !control.measurement_active
                    && control.outstanding_cuda_operations == 0
                    && control.active_device_allocations == 0
                    && control.active_pinned_allocations == 0
                    && control.in_flight_pinned_allocations == 0
            });
        let post_release_control = match control_result {
            Ok(control) => serde_json::json!({
                "stream_state": format!("{:?}", control.stream_state),
                "measurement_active": control.measurement_active,
                "coarse_timing_active": control.coarse_timing_active,
                "timing_record_active": control.timing_record_active,
                "measurement_poisoned": control.measurement_poisoned,
                "outstanding_cuda_operations": control.outstanding_cuda_operations,
                "pending_timing_records": control.pending_timing_records,
                "active_device_allocations": control.active_device_allocations,
                "cached_device_allocations": control.cached_device_allocations,
                "active_pinned_allocations": control.active_pinned_allocations,
                "cached_pinned_allocations": control.cached_pinned_allocations,
                "in_flight_pinned_allocations": control.in_flight_pinned_allocations,
                "workspace_device_bytes": control.workspace_device_bytes,
                "active_device_bytes": control.active_device_bytes,
                "cached_device_bytes": control.cached_device_bytes,
                "active_pinned_bytes": control.active_pinned_bytes,
                "cached_pinned_bytes": control.cached_pinned_bytes,
            }),
            Err(error) => serde_json::json!({"error": format!("{error:?}")}),
        };
        let (response, response_error) = match warmup_result {
            Ok(response) => (
                Some(response),
                Some(
                    "diagnose-only response unexpectedly reached exact canonical bytes; \
                     no candidate may be emitted"
                        .to_owned(),
                ),
            ),
            Err(error) => (None, Some(error)),
        };
        let hard_stop_reason =
            response_error.clone().expect("diagnostic response always has a stop reason");
        let report = CanonicalDiagnosticReport {
            schema: SCHEMA,
            milestone: "X4c-v1-A100-canonical-byte-diagnostic".to_owned(),
            date: command_output("date", &["+%Y-%m-%d"])?,
            git_sha,
            git_dirty: false,
            pod_profile: POD_PROFILE.to_owned(),
            protocol_profile: PROTOCOL_PROFILE.to_owned(),
            design_sha256: DESIGN_SHA256.to_owned(),
            clean_source_sha256,
            clean_source_bundle_path,
            note6,
            lifecycle_probe: lifecycle,
            onboarding,
            amendment5_preflight,
            codec_reference,
            onboarding_ancestor_input: diagnostic_ancestor_input,
            machine,
            worker_policy: "five ordered cohort tasks on unpinned Rayon; seal/open paths unpinned"
                .to_owned(),
            fresh_process_rebuild: rebuild,
            response,
            response_error,
            pinned_pool_release_wall_s: release_wall_s,
            pinned_pool_release_error: release_error,
            post_release_control,
            post_release_ownership_restored: release_restored,
            candidate_eligible: false,
            gate_verdict: "NOT EVALUATED — diagnose-only HARD STOP".to_owned(),
            hard_stop: true,
            protocol_or_parameter_change: false,
            root_or_proof_format_change: false,
            lean_or_soundness_change: false,
            assurance:
                "AI-generated diagnostic obstruction record; no independent human-review assurance."
                    .to_owned(),
        };
        write_append_only(&args.output, &report)?;
        return Err(format!(
            "diagnose-only HARD STOP; no candidate emitted; {hard_stop_reason}; wrote {}",
            args.output.display()
        ));
    }
    let warmup = warmup_result?;
    let mut measured = Vec::new();
    for ordinal in 1..=3 {
        measured.push(run_response(
            &format!("measured-{ordinal}"),
            ordinal,
            true,
            &sources,
            &mut runtime,
            clean_source_sha,
            &selected_query_tape,
        )?);
    }
    let release_started = Instant::now();
    runtime.release_pinned_pool().map_err(|error| format!("release X4c pinned pool: {error:?}"))?;
    let release_wall_s = release_started.elapsed().as_secs_f64();
    let control = runtime
        .backend_control_state()
        .map_err(|error| format!("post-release control state: {error:?}"))?;
    let release_restored = control.active_device_allocations == 0
        && control.active_pinned_allocations == 0
        && control.in_flight_pinned_allocations == 0
        && control.outstanding_cuda_operations == 0;
    let selected_open = upper_median(measured.iter().map(|row| row.open_wall_s).collect());
    let selected_verify = upper_median(measured.iter().map(|row| row.verify_wall_s).collect());
    let selected_proof_ready =
        upper_median(measured.iter().map(|row| row.proof_ready_wall_s).collect());
    let selected_reusable =
        upper_median(measured.iter().map(|row| row.session_reusable_wall_s).collect());
    let selected_complete =
        upper_median(measured.iter().map(|row| row.complete_online_wall_s).collect());
    let all_candidates =
        std::iter::once(&warmup).chain(&measured).all(|candidate| candidate.accepted);
    let zero_staging =
        std::iter::once(&warmup).chain(&measured).all(|candidate| candidate.zero_response_staging);
    let exact_communication = std::iter::once(&warmup).chain(&measured).all(|candidate| {
        candidate.complete_pcs_bytes == X4C_COMPLETE_PCS_BYTES_V4
            && candidate.global_folding_proof_bytes == X4C_GLOBAL_FOLDING_PROOF_BYTES_V4
            && candidate.packed_opening_bytes == X4C_PACKED_OPENING_BYTES_V4
            && candidate.frozen_non_query_pcs_bytes == X4C_MANDATORY_NON_QUERY_BYTES_V4
            && candidate.response_bytes == X4C_RESPONSE_BYTES_V4
    });
    let open_pass = selected_open <= OPEN_CEILING_S;
    let verify_pass = selected_verify <= VERIFY_CEILING_S;
    let overall_pass = rebuild.accepted
        && all_candidates
        && zero_staging
        && exact_communication
        && open_pass
        && verify_pass
        && release_restored;
    let report = OnlineReport {
        schema: SCHEMA,
        milestone: "X4c-v1-A100-online".to_owned(),
        date: command_output("date", &["+%Y-%m-%d"])?,
        git_sha,
        git_dirty: false,
        pod_profile: POD_PROFILE.to_owned(),
        protocol_profile: PROTOCOL_PROFILE.to_owned(),
        design_sha256: DESIGN_SHA256.to_owned(),
        clean_source_sha256,
        clean_source_bundle_path,
        note6,
        lifecycle_probe: lifecycle,
        onboarding,
        amendment5_preflight,
        codec_reference,
        machine,
        worker_policy: "UNPINNED seal/open paths; RAYON_NUM_THREADS absent".to_owned(),
        fresh_process_rebuild: rebuild,
        warmup,
        measured,
        selected_upper_median_open_wall_s: selected_open,
        selected_upper_median_verify_wall_s: selected_verify,
        selected_upper_median_proof_ready_wall_s: selected_proof_ready,
        selected_upper_median_session_reusable_wall_s: selected_reusable,
        selected_upper_median_complete_online_wall_s: selected_complete,
        complete_online_wall_status:
            "MEASURED/INFORMATIVE in runpod-a100-x4c-v1; no v2 ceiling projected".to_owned(),
        open_ceiling_s: OPEN_CEILING_S,
        verify_ceiling_s: VERIFY_CEILING_S,
        open_pass,
        verify_pass,
        all_candidates_accepted: all_candidates,
        zero_response_staging: zero_staging,
        exact_communication,
        diagnostic_comparisons: X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 as u64,
        diagnostic_soundness_credit_bits: 0,
        pinned_pool_release_wall_s: release_wall_s,
        pinned_pool_release_restored_ownership: release_restored,
        protocol_or_parameter_change: false,
        root_or_proof_format_change: false,
        lean_or_soundness_change: false,
        overall_pass,
        assurance: "AI-generated X4c v1 record; no independent human-review assurance. R1c scope extends to instrumentation, direct-fold, arena and gather code.".to_owned(),
    };
    write_append_only(&args.output, &report)?;
    if !overall_pass {
        return Err(format!(
            "X4c online hard gate failed: open={selected_open:.6}s verify={selected_verify:.6}s; obstruction record written to {}",
            args.output.display()
        ));
    }
    eprintln!(
        "X4c online PASS: open {:.6}s verify {:.6}s reusable {:.6}s; wrote {}",
        selected_open,
        selected_verify,
        selected_reusable,
        args.output.display()
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Onboard,
    Online,
    Diagnose,
}

#[derive(Clone, Debug)]
struct Args {
    mode: Mode,
    note6: PathBuf,
    lifecycle: Option<PathBuf>,
    onboarding: Option<PathBuf>,
    durable_root: PathBuf,
    scratch_root: Option<PathBuf>,
    output: PathBuf,
}

fn parse_args_from(values: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut values = values.into_iter();
    let mode = match values.next().as_deref() {
        Some("onboard") => Mode::Onboard,
        Some("online") => Mode::Online,
        Some("diagnose") => Mode::Diagnose,
        _ => return Err("first argument must be onboard, online or diagnose".to_owned()),
    };
    let mut note6 = None;
    let mut lifecycle = None;
    let mut onboarding = None;
    let mut durable_root = None;
    let mut scratch_root = None;
    let mut output = None;
    for value in values {
        let (name, argument) =
            value.split_once('=').ok_or_else(|| format!("expected --name=value, got {value:?}"))?;
        let target = match name {
            "--note6" => &mut note6,
            "--lifecycle" => &mut lifecycle,
            "--onboarding" => &mut onboarding,
            "--durable-root" => &mut durable_root,
            "--scratch-root" => &mut scratch_root,
            "--output" => &mut output,
            _ => return Err(format!("unknown argument {name:?}")),
        };
        if target.replace(PathBuf::from(argument)).is_some() {
            return Err(format!("duplicate argument {name:?}"));
        }
    }
    let args = Args {
        mode,
        note6: note6.ok_or_else(|| "--note6 is required".to_owned())?,
        lifecycle,
        onboarding,
        durable_root: durable_root.ok_or_else(|| "--durable-root is required".to_owned())?,
        scratch_root,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
    };
    match args.mode {
        Mode::Onboard if args.lifecycle.is_none() || args.scratch_root.is_none() => {
            Err("onboard requires --lifecycle and --scratch-root".to_owned())
        }
        Mode::Online | Mode::Diagnose if args.lifecycle.is_none() || args.onboarding.is_none() => {
            Err("online/diagnose requires --lifecycle and --onboarding".to_owned())
        }
        _ => Ok(args),
    }
}

fn main() {
    let result = parse_args_from(env::args().skip(1)).and_then(|args| match args.mode {
        Mode::Onboard => run_onboard(&args),
        Mode::Online => run_online(&args, false),
        Mode::Diagnose => run_online(&args, true),
    });
    if let Err(error) = result {
        eprintln!("x4c_pod_record HARD STOP: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_fixture_geometry_is_exact() {
        let specs = gpt2_specs();
        assert_eq!(specs.len(), 5);
        assert_eq!(
            specs
                .iter()
                .map(|spec| {
                    spec.config.slot_descriptors.iter().flatten().count() as u64
                        * (spec.config.outer_len / 8) as u64
                        * 16
                })
                .sum::<u64>(),
            COEFFICIENT_BYTES
        );
        assert_eq!(
            specs
                .iter()
                .map(|spec| {
                    spec.config.slot_descriptors.iter().flatten().count() as u64
                        * spec.config.outer_len as u64
                        * 16
                })
                .sum::<u64>(),
            INITIAL_ORACLE_BYTES
        );
        assert_eq!(
            specs.iter().map(|spec| (spec.config.outer_len as u64 - 1) * 32).sum::<u64>(),
            INITIAL_OUTER_CACHE_BYTES
        );
    }

    #[test]
    fn cli_requires_record_anchors() {
        assert!(parse_args_from(["onboard".to_owned()]).is_err());
        let args = parse_args_from([
            "online".to_owned(),
            "--note6=n.json".to_owned(),
            "--lifecycle=l.json".to_owned(),
            "--onboarding=o.json".to_owned(),
            "--durable-root=/persistent/run".to_owned(),
            "--output=/local/result.json".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.mode, Mode::Online);
        let args = parse_args_from([
            "diagnose".to_owned(),
            "--note6=n.json".to_owned(),
            "--lifecycle=l.json".to_owned(),
            "--onboarding=o.json".to_owned(),
            "--durable-root=/persistent/run".to_owned(),
            "--output=/local/diagnostic.json".to_owned(),
        ])
        .unwrap();
        assert_eq!(args.mode, Mode::Diagnose);
    }

    #[test]
    fn frozen_surface_and_sample_count_are_unchanged() {
        validate_x4c_frozen_surface_v4("1/8", 111, 2_683_236, 43_953_700).unwrap();
        assert_eq!(X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4, 1_592);
        assert_eq!(
            X4C_PACKED_OPENING_BYTES_V4 + X4C_MANDATORY_NON_QUERY_BYTES_V4,
            X4C_COMPLETE_PCS_BYTES_V4
        );
        assert_eq!(
            X4C_PACKED_OPENING_BYTES_V4 + X4C_FOLD_FRAME_BYTES_V4,
            X4C_GLOBAL_FOLDING_PROOF_BYTES_V4
        );
        let tape = SelectedQueryTapeV4::load().unwrap();
        assert_eq!(tape.draws.len(), X4C_QUERY_COUNT_V4);
        amendment5_preflight_pin().unwrap();
        validate_migration_reference().unwrap();
    }
}
