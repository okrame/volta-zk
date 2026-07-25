//! Manual, progressive CUDA rebuild preflight for X4c real-weight geometry.
//!
//! Every invocation executes exactly one requested stage.  It never advances
//! to a larger geometry, never provisions hardware, never performs onboarding
//! and never selects the CPU rebuild after a CUDA error.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use serde::Serialize;
use serde_json::Value;
use volta_accel::{Backend, ResidentTimingPolicy};
use volta_bench::x4c_gpt2::{
    X4C_AUX_ELL16_COHORT_ID, X4C_AUX_ELL17_COHORT_ID, X4C_WEXT_MU20_COHORT_ID,
    X4C_WEXT_MU22_COHORT_ID, X4C_WEXT_MU26_COHORT_ID,
};
use volta_bench::x4c_rebuild_record::{
    accelerated_rebuild_cohort_record, process_memory_record, AcceleratedRebuildCohortRecord,
    ProcessMemoryRecord,
};
use volta_field::{Fp, Fp2};
use volta_pcs::x4::{
    rebuild_cohort_ram_v4, CohortIdentityV4, CohortVerifierConfigV4, OracleKindV4,
    X4cRamModelGlobalCohortV4, X4cRamRebuildStrategyV4, X4B_N4_TILE_BYTE_CEILING_V4,
    X4C_DESIGN_SHA256_HEX_V4,
};

const SCHEMA: u64 = 2;
const MILESTONE: &str = "X4c-GPT2-rebuild-preflight";
const PROFILE: &str = "runpod-a100-x4c-v1";
const PROTOCOL: &str = "x4-zkdeepfold-ud-e29-v4";
const FIXTURE_CONTRACT: &str = "x4c-deterministic-production-geometry-v1";
const SYNTHETIC_COHORT_ID: u32 = 0xA5FF_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    SyntheticSmall,
    AuxiliaryEll16,
    AuxiliaryEll17,
    Mu20,
    Project,
}

impl Stage {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "synthetic-small" => Some(Self::SyntheticSmall),
            "aux-ell16" => Some(Self::AuxiliaryEll16),
            "aux-ell17" => Some(Self::AuxiliaryEll17),
            "mu20" => Some(Self::Mu20),
            "project" => Some(Self::Project),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::SyntheticSmall => "synthetic-small",
            Self::AuxiliaryEll16 => "aux-ell16",
            Self::AuxiliaryEll17 => "aux-ell17",
            Self::Mu20 => "mu20",
            Self::Project => "project",
        }
    }
}

struct Args {
    stage: Stage,
    durable_root: PathBuf,
    output: PathBuf,
    inputs: Vec<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: x4c_rebuild_preflight --stage \
         synthetic-small|aux-ell16|aux-ell17|mu20|project \
         --durable-root PATH --output PATH [--input PREVIOUS.json ...]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut stage = None;
    let mut durable_root = None;
    let mut output = None;
    let mut inputs = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--stage" => stage = Stage::parse(&value()),
            "--durable-root" => durable_root = Some(PathBuf::from(value())),
            "--output" => output = Some(PathBuf::from(value())),
            "--input" => inputs.push(PathBuf::from(value())),
            _ => usage(),
        }
    }
    let stage = stage.unwrap_or_else(|| usage());
    if (stage == Stage::Project) != !inputs.is_empty() {
        usage();
    }
    Args {
        stage,
        durable_root: durable_root.unwrap_or_else(|| usage()),
        output: output.unwrap_or_else(|| usage()),
        inputs,
    }
}

fn git_sha_clean() -> Result<String, String> {
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|error| format!("git status: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("preflight record requires a clean git tree".to_owned());
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("git rev-parse: {error}"))?;
    if !output.status.success() {
        return Err("git rev-parse failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "git SHA is not UTF-8".to_owned())
}

fn write_append_only<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create append-only record {}: {error}", path.display()))?;
    let encoded =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize record: {error}"))?;
    file.write_all(&encoded)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_data())
        .map_err(|error| format!("persist record {}: {error}", path.display()))
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DurableCensus {
    root_exists: bool,
    directory_count: u64,
    file_count: u64,
    symlink_count: u64,
    byte_count: u64,
    structural_blake3: String,
}

fn durable_census(root: &Path) -> Result<DurableCensus, String> {
    if !root.exists() {
        return Ok(DurableCensus {
            root_exists: false,
            directory_count: 0,
            file_count: 0,
            symlink_count: 0,
            byte_count: 0,
            structural_blake3: blake3::hash(b"x4c-preflight-absent-durable-root")
                .to_hex()
                .to_string(),
        });
    }
    if !root.is_dir() {
        return Err("durable root exists but is not a directory".to_owned());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut directory_count = 0u64;
    let mut file_count = 0u64;
    let mut symlink_count = 0u64;
    let mut byte_count = 0u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("read durable census {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("read durable census entry: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("stat durable census {}: {error}", path.display()))?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "durable census path escaped root".to_owned())?
                .to_string_lossy()
                .into_owned();
            if metadata.file_type().is_symlink() {
                symlink_count += 1;
                entries.push((relative, "symlink", 0));
            } else if metadata.is_dir() {
                directory_count += 1;
                entries.push((relative, "directory", 0));
                pending.push(path);
            } else if metadata.is_file() {
                file_count += 1;
                byte_count =
                    byte_count.checked_add(metadata.len()).ok_or("durable byte overflow")?;
                entries.push((relative, "file", metadata.len()));
            } else {
                return Err("unsupported durable filesystem entry".to_owned());
            }
        }
    }
    entries.sort_unstable();
    let mut hasher = blake3::Hasher::new_derive_key("volta-x4c-preflight-durable-census-v1");
    for (path, kind, bytes) in entries {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(kind.as_bytes());
        hasher.update(&bytes.to_le_bytes());
    }
    Ok(DurableCensus {
        root_exists: true,
        directory_count,
        file_count,
        symlink_count,
        byte_count,
        structural_blake3: hasher.finalize().to_hex().to_string(),
    })
}

#[derive(Clone, Debug, Serialize)]
struct HostMemoryPreflight {
    mem_available_bytes: u64,
    estimated_rebuild_peak_bytes: u64,
    sufficient: bool,
}

fn mem_available_bytes() -> Result<u64, String> {
    let text =
        fs::read_to_string("/proc/meminfo").map_err(|error| format!("read meminfo: {error}"))?;
    let kib = text
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "MemAvailable missing from /proc/meminfo".to_owned())?;
    kib.checked_mul(1024).ok_or_else(|| "MemAvailable overflows".to_owned())
}

#[derive(Clone, Debug, Serialize)]
struct CudaMemoryPreflight {
    free_bytes: u64,
    total_bytes: u64,
    estimated_working_set_bytes: u64,
    sufficient: bool,
}

fn cuda_memory(estimated_working_set_bytes: u64) -> Result<CudaMemoryPreflight, String> {
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=memory.free,memory.total", "--format=csv,noheader,nounits"])
        .output()
        .map_err(|error| format!("nvidia-smi memory census: {error}"))?;
    if !output.status.success() {
        return Err("nvidia-smi memory census failed".to_owned());
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "nvidia-smi output is not UTF-8".to_owned())?;
    let row = text.lines().next().ok_or_else(|| "nvidia-smi returned no GPU".to_owned())?;
    let values = row
        .split(',')
        .map(|value| value.trim().parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse nvidia-smi memory census: {error}"))?;
    if values.len() != 2 {
        return Err("nvidia-smi memory census has wrong shape".to_owned());
    }
    let mib = 1024u64 * 1024;
    let free_bytes = values[0].checked_mul(mib).ok_or("free VRAM overflows")?;
    let total_bytes = values[1].checked_mul(mib).ok_or("total VRAM overflows")?;
    Ok(CudaMemoryPreflight {
        free_bytes,
        total_bytes,
        estimated_working_set_bytes,
        sufficient: free_bytes >= estimated_working_set_bytes,
    })
}

#[derive(Clone, Debug, Serialize)]
struct FixtureGeometry {
    contract: String,
    descriptor_layout: String,
    cohort_id: u32,
    oracle_kind: String,
    outer_log2: u8,
    outer_len: u64,
    structural_slots: u64,
    present_slots: u64,
    coefficient_bytes: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    final_resident_host_bytes: u64,
    estimated_rebuild_peak_bytes: u64,
    estimated_device_working_set_bytes: u64,
    production_geometry: bool,
}

fn checked_geometry(
    cohort_id: u32,
    oracle_kind: OracleKindV4,
    outer_log2: u8,
    structural_slots: usize,
    present_slots: usize,
    production_geometry: bool,
) -> Result<(CohortVerifierConfigV4, FixtureGeometry), String> {
    let mut descriptors = vec![None; structural_slots];
    for (slot, descriptor) in descriptors.iter_mut().take(present_slots).enumerate() {
        let mut hasher =
            blake3::Hasher::new_derive_key("volta-x4c-rebuild-preflight-descriptor-v1");
        hasher.update(&cohort_id.to_le_bytes());
        hasher.update(&(slot as u64).to_le_bytes());
        *descriptor = Some(*hasher.finalize().as_bytes());
    }
    let outer_len = 1usize
        .checked_shl(u32::from(outer_log2))
        .ok_or_else(|| "preflight outer geometry overflows".to_owned())?;
    let config = CohortVerifierConfigV4 {
        identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round: 0 },
        slot_descriptors: descriptors,
        outer_len,
        expected_symbol_count: 1,
    };
    config.validate().map_err(|error| format!("preflight config: {error:?}"))?;
    let outer = u64::try_from(outer_len).map_err(|_| "outer length overflows u64")?;
    let present = u64::try_from(present_slots).map_err(|_| "present slots overflow u64")?;
    let coefficient_bytes = present
        .checked_mul(outer)
        .and_then(|value| value.checked_mul(2))
        .ok_or("coefficient geometry overflows")?;
    let host_oracle_bytes = present
        .checked_mul(outer)
        .and_then(|value| value.checked_mul(16))
        .ok_or("oracle geometry overflows")?;
    let host_outer_cache_bytes =
        outer.checked_sub(1).and_then(|value| value.checked_mul(32)).ok_or("cache overflow")?;
    let final_resident_host_bytes = coefficient_bytes
        .checked_add(host_oracle_bytes)
        .and_then(|value| value.checked_add(host_outer_cache_bytes))
        .ok_or("resident geometry overflows")?;
    // At the widest outer reduction boundary both the current and next
    // digest levels coexist: outer_len * (32 + 16) bytes.
    let estimated_rebuild_peak_bytes = coefficient_bytes
        .checked_add(host_oracle_bytes)
        .and_then(|value| value.checked_add(outer.checked_mul(48)?))
        .ok_or("peak host geometry overflows")?;
    // The frozen X4b kernel owns two full Fp2 buffers plus n/2 Fp2
    // twiddles: 16n + 16n + 8n bytes for one slot.
    let one_slot_ntt = outer.checked_mul(40).ok_or("NTT working-set geometry overflows")?;
    let estimated_device_working_set_bytes = one_slot_ntt.max(X4B_N4_TILE_BYTE_CEILING_V4);
    let geometry = FixtureGeometry {
        contract: FIXTURE_CONTRACT.to_owned(),
        descriptor_layout: "deterministic-prefix-present".to_owned(),
        cohort_id,
        oracle_kind: match oracle_kind {
            OracleKindV4::WeightExtension => "weight-extension",
            OracleKindV4::Auxiliary => "auxiliary",
            OracleKindV4::GlobalFoldAggregate => "global-fold-aggregate",
        }
        .to_owned(),
        outer_log2,
        outer_len: outer,
        structural_slots: structural_slots as u64,
        present_slots: present,
        coefficient_bytes,
        host_oracle_bytes,
        host_outer_cache_bytes,
        final_resident_host_bytes,
        estimated_rebuild_peak_bytes,
        estimated_device_working_set_bytes,
        production_geometry,
    };
    Ok((config, geometry))
}

fn stage_geometry(stage: Stage) -> Result<(CohortVerifierConfigV4, FixtureGeometry), String> {
    match stage {
        Stage::SyntheticSmall => {
            checked_geometry(SYNTHETIC_COHORT_ID, OracleKindV4::WeightExtension, 12, 4, 3, false)
        }
        Stage::AuxiliaryEll16 => {
            checked_geometry(X4C_AUX_ELL16_COHORT_ID, OracleKindV4::Auxiliary, 19, 64, 49, true)
        }
        Stage::AuxiliaryEll17 => {
            checked_geometry(X4C_AUX_ELL17_COHORT_ID, OracleKindV4::Auxiliary, 20, 2, 2, true)
        }
        Stage::Mu20 => checked_geometry(
            X4C_WEXT_MU20_COHORT_ID,
            OracleKindV4::WeightExtension,
            24,
            16,
            13,
            true,
        ),
        Stage::Project => Err("projection has no executable geometry".to_owned()),
    }
}

fn deterministic_coefficients(config: &CohortVerifierConfigV4) -> Vec<Option<Vec<Fp2>>> {
    let coefficient_len = config.outer_len / 8;
    config
        .slot_descriptors
        .iter()
        .enumerate()
        .map(|(slot, descriptor)| {
            descriptor.map(|_| {
                let value = Fp2 {
                    c0: Fp::new(u64::from(config.identity.cohort_id) + slot as u64 + 1),
                    c1: Fp::new((slot as u64 + 1) * 17),
                };
                vec![value; coefficient_len]
            })
        })
        .collect()
}

#[derive(Clone, Debug, Serialize)]
struct StageRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    protocol: String,
    design_sha256: String,
    stage: String,
    manual_single_stage: bool,
    next_stage_launched: bool,
    automatic_cpu_fallback: bool,
    production_gate_credit: bool,
    fixture: FixtureGeometry,
    durable_census_before: DurableCensus,
    durable_census_after: DurableCensus,
    durable_census_stable: bool,
    host_memory_preflight: HostMemoryPreflight,
    cuda_memory_preflight: CudaMemoryPreflight,
    fixture_generation_wall_s: f64,
    cpu_reference_wall_s: f64,
    cpu_reference_root: String,
    cuda_rebuild_root: String,
    root_reference_equality: bool,
    rebuild: AcceleratedRebuildCohortRecord,
    logical_rebuild_bytes: u64,
    logical_bytes_per_second: f64,
    final_process_memory: ProcessMemoryRecord,
    scratch_files_created: u64,
    scratch_bytes_read: u64,
    scratch_bytes_written: u64,
    abort_reasons: Vec<String>,
    accepted: bool,
}

fn run_stage(args: &Args, git_sha: String) -> Result<(), String> {
    let (config, geometry) = stage_geometry(args.stage)?;
    let durable_census_before = durable_census(&args.durable_root)?;
    let available = mem_available_bytes()?;
    let host_memory_preflight = HostMemoryPreflight {
        mem_available_bytes: available,
        estimated_rebuild_peak_bytes: geometry.estimated_rebuild_peak_bytes,
        sufficient: available >= geometry.estimated_rebuild_peak_bytes,
    };
    if !host_memory_preflight.sufficient {
        return Err("insufficient host RAM for requested preflight geometry".to_owned());
    }
    let cuda_memory_preflight = cuda_memory(geometry.estimated_device_working_set_bytes)?;
    if !cuda_memory_preflight.sufficient {
        return Err("insufficient free VRAM for requested preflight geometry".to_owned());
    }

    let fixture_started = Instant::now();
    let cpu_coefficients = deterministic_coefficients(&config);
    let fixture_cpu_wall_s = fixture_started.elapsed().as_secs_f64();
    let cpu_started = Instant::now();
    let cpu_reference =
        X4cRamModelGlobalCohortV4::rebuild_from_coefficients(config.clone(), cpu_coefficients)
            .map_err(|error| format!("CPU fixture reference: {error:?}"))?;
    let cpu_reference_wall_s = cpu_started.elapsed().as_secs_f64();
    let cpu_reference_root = cpu_reference.root();
    drop(cpu_reference);

    let fixture_started = Instant::now();
    let cuda_coefficients = deterministic_coefficients(&config);
    let fixture_cuda_wall_s = fixture_started.elapsed().as_secs_f64();
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize CUDA rebuild backend: {error}"))?;
    let process_before = process_memory_record()?;
    let (source, metrics) = rebuild_cohort_ram_v4(
        X4cRamRebuildStrategyV4::CudaRam,
        Some(&mut backend),
        config,
        cuda_coefficients,
        cpu_reference_root,
    )
    .map_err(|error| format!("CUDA preflight rebuild: {error}"))?;
    let cuda_rebuild_root = source.root();
    let process_after = process_memory_record()?;
    let rebuild = accelerated_rebuild_cohort_record(
        geometry.cohort_id,
        metrics,
        process_before,
        process_after,
    )?;
    drop(source);
    let final_process_memory = process_memory_record()?;
    let durable_census_after = durable_census(&args.durable_root)?;
    let durable_census_stable = durable_census_before == durable_census_after;
    let logical_rebuild_bytes = geometry
        .coefficient_bytes
        .checked_add(geometry.host_oracle_bytes)
        .and_then(|value| value.checked_add(geometry.host_outer_cache_bytes))
        .ok_or_else(|| "logical rebuild bytes overflow".to_owned())?;
    let logical_bytes_per_second = logical_rebuild_bytes as f64 / rebuild.wall_s;
    let root_reference_equality = cpu_reference_root == cuda_rebuild_root;
    let accepted = root_reference_equality
        && rebuild.accepted
        && durable_census_stable
        && rebuild.scratch_files_created == 0
        && rebuild.scratch_bytes_read == 0
        && rebuild.scratch_bytes_written == 0;
    let record = StageRecord {
        schema: SCHEMA,
        milestone: MILESTONE.to_owned(),
        git_sha,
        git_dirty: false,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        design_sha256: X4C_DESIGN_SHA256_HEX_V4.to_owned(),
        stage: args.stage.as_str().to_owned(),
        manual_single_stage: true,
        next_stage_launched: false,
        automatic_cpu_fallback: false,
        production_gate_credit: false,
        fixture: geometry,
        durable_census_before,
        durable_census_after,
        durable_census_stable,
        host_memory_preflight,
        cuda_memory_preflight,
        fixture_generation_wall_s: fixture_cpu_wall_s + fixture_cuda_wall_s,
        cpu_reference_wall_s,
        cpu_reference_root: hex(&cpu_reference_root),
        cuda_rebuild_root: hex(&cuda_rebuild_root),
        root_reference_equality,
        logical_rebuild_bytes,
        logical_bytes_per_second,
        scratch_files_created: rebuild.scratch_files_created,
        scratch_bytes_read: rebuild.scratch_bytes_read,
        scratch_bytes_written: rebuild.scratch_bytes_written,
        rebuild,
        final_process_memory,
        abort_reasons: Vec::new(),
        accepted,
    };
    write_append_only(&args.output, &record)?;
    if !accepted {
        return Err("preflight stage counters failed closed".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionTarget {
    cohort_id: u32,
    name: String,
    coefficient_bytes: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    final_resident_host_bytes: u64,
    estimated_rebuild_peak_bytes: u64,
    estimated_device_working_set_bytes: u64,
    projected_wall_s: f64,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    protocol: String,
    design_sha256: String,
    stage: String,
    manual_single_stage: bool,
    next_stage_launched: bool,
    production_gate_credit: bool,
    source_stages: Vec<String>,
    source_record_blake3: Vec<String>,
    conservative_floor_logical_bytes_per_second: f64,
    targets: Vec<ProjectionTarget>,
    durable_census_before: DurableCensus,
    durable_census_after: DurableCensus,
    durable_census_stable: bool,
    decision_only: bool,
    accepted: bool,
}

fn projection_geometry(
    cohort_id: u32,
    name: &str,
    outer_log2: u8,
    structural_slots: usize,
    present_slots: usize,
) -> Result<(String, FixtureGeometry), String> {
    let (_, geometry) = checked_geometry(
        cohort_id,
        OracleKindV4::WeightExtension,
        outer_log2,
        structural_slots,
        present_slots,
        true,
    )?;
    Ok((name.to_owned(), geometry))
}

fn run_projection(args: &Args, git_sha: String) -> Result<(), String> {
    let durable_census_before = durable_census(&args.durable_root)?;
    let mut stages = BTreeSet::new();
    let mut digests = Vec::new();
    let mut throughputs = Vec::new();
    for path in &args.inputs {
        let bytes = fs::read(path)
            .map_err(|error| format!("read preflight input {}: {error}", path.display()))?;
        let row: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse preflight input {}: {error}", path.display()))?;
        if row.get("schema").and_then(Value::as_u64) != Some(SCHEMA)
            || row.get("milestone").and_then(Value::as_str) != Some(MILESTONE)
            || row.get("accepted").and_then(Value::as_bool) != Some(true)
            || row.get("root_reference_equality").and_then(Value::as_bool) != Some(true)
            || row.get("next_stage_launched").and_then(Value::as_bool) != Some(false)
            || row.get("production_gate_credit").and_then(Value::as_bool) != Some(false)
        {
            return Err("projection input is not an accepted preflight stage".to_owned());
        }
        let stage = row
            .get("stage")
            .and_then(Value::as_str)
            .ok_or_else(|| "projection input stage missing".to_owned())?;
        if !matches!(stage, "aux-ell16" | "aux-ell17" | "mu20") || !stages.insert(stage.to_owned())
        {
            return Err("projection inputs have missing or duplicate stage identity".to_owned());
        }
        let throughput = row
            .get("logical_bytes_per_second")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite() && *value > 0.0)
            .ok_or_else(|| "projection input throughput missing".to_owned())?;
        throughputs.push(throughput);
        digests.push(blake3::hash(&bytes).to_hex().to_string());
    }
    let expected =
        BTreeSet::from(["aux-ell16".to_owned(), "aux-ell17".to_owned(), "mu20".to_owned()]);
    if stages != expected {
        return Err("projection requires exactly aux-ell16, aux-ell17 and mu20".to_owned());
    }
    let conservative_floor = throughputs.into_iter().fold(f64::INFINITY, f64::min);
    let targets = [
        projection_geometry(X4C_WEXT_MU22_COHORT_ID, "mu22", 26, 64, 36)?,
        projection_geometry(X4C_WEXT_MU26_COHORT_ID, "mu26", 30, 2, 2)?,
    ]
    .into_iter()
    .map(|(name, geometry)| ProjectionTarget {
        cohort_id: geometry.cohort_id,
        name,
        coefficient_bytes: geometry.coefficient_bytes,
        host_oracle_bytes: geometry.host_oracle_bytes,
        host_outer_cache_bytes: geometry.host_outer_cache_bytes,
        final_resident_host_bytes: geometry.final_resident_host_bytes,
        estimated_rebuild_peak_bytes: geometry.estimated_rebuild_peak_bytes,
        estimated_device_working_set_bytes: geometry.estimated_device_working_set_bytes,
        projected_wall_s: geometry.final_resident_host_bytes as f64 / conservative_floor,
    })
    .collect();
    let durable_census_after = durable_census(&args.durable_root)?;
    let durable_census_stable = durable_census_before == durable_census_after;
    let record = ProjectionRecord {
        schema: SCHEMA,
        milestone: MILESTONE.to_owned(),
        git_sha,
        git_dirty: false,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        design_sha256: X4C_DESIGN_SHA256_HEX_V4.to_owned(),
        stage: Stage::Project.as_str().to_owned(),
        manual_single_stage: true,
        next_stage_launched: false,
        production_gate_credit: false,
        source_stages: stages.into_iter().collect(),
        source_record_blake3: digests,
        conservative_floor_logical_bytes_per_second: conservative_floor,
        targets,
        durable_census_before,
        durable_census_after,
        durable_census_stable,
        decision_only: true,
        accepted: durable_census_stable,
    };
    write_append_only(&args.output, &record)
}

fn main() {
    let args = parse_args();
    let result = (|| {
        if args.output.exists() {
            return Err("preflight output must be a fresh path".to_owned());
        }
        let git_sha = git_sha_clean()?;
        match args.stage {
            Stage::Project => run_projection(&args, git_sha),
            _ => run_stage(&args, git_sha),
        }
    })();
    if let Err(error) = result {
        eprintln!("x4c_rebuild_preflight HARD STOP: {error}");
        std::process::exit(1);
    }
}
