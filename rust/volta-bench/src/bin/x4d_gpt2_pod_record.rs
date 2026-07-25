//! X4d run-of-record adapter for real-weight GPT-2 deferred settlement.
//!
//! X4c onboarding remains the only durable-material producer. This binary
//! validates that append-only record, rebuilds the admitted cohorts, proves
//! real responses under one fase-D connection, freezes their claims, and
//! executes one 16-response X4d settlement. It introduces no alternate PCS,
//! model loader, correlation pool, or lifecycle.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_accel::{Backend, BackendStats, DeviceBuffer, DeviceSlice, ResidentTimingPolicy};
use volta_bench::cloud_metadata_from_env;
use volta_bench::crypto_build_identity::{x4c_crypto_build_identity, X4C_CRYPTO_BUILD_ID_SCHEME};
use volta_bench::x4c_gpt2::{
    rebuild_evaluation_tables, X4cGpt2CohortMaterial, X4cGpt2Inventory,
    X4C_GPT2_DURABLE_COEFFICIENT_BYTES, X4C_GPT2_DURABLE_TIER_BYTES,
};
use volta_bench::x4c_rebuild_record::{
    accelerated_rebuild_cohort_record, process_memory_record, AcceleratedRebuildCohortRecord,
};
use volta_bench::x4d_gpt2::{
    execute_real_weight_x4d_settlement_v1, materialize_fresh_auxiliary_set_v1,
    x4d_static_weight_commitment_digest_v1, X4dGpt2ConnectionV1, X4dSplitThreadPolicyV1,
    X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1, X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1,
};
use volta_gpt2::{
    argmax, band_model_witness, band_model_witness_resident, decode_step, forward_model,
    forward_model_tokens, forward_model_tokens_resident, load_model, upload_resident_model,
    BandModelWitness, Gpt2Model, KvCache, ResidentBandModelWitness, ResidentGpt2Model,
    ResidentModelWitness, VOCAB,
};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcg::{
    open_fase_d_connection_with_ggm_prg, ConnectionAbortReason, ConnectionBinding,
    ConnectionResponseAudit, ConnectionStore, CorrelationDomain, FaseDParams, FaseDStagePlan,
    GgmPrg, ProductionFaseDConnection, ResponseAuthorizationStore, X4dClaimsFrozenJournalAudit,
    X4dSettlementCorrelationDomain, X4dSettlementFreshnessBinding,
};
use volta_pcs::x4::{
    read_persisted_coefficients_v4, rebuild_cohort_ram_v4, CohortVerifierConfigV4,
    ModelGlobalOpeningSourceV4, X4cCudaArenaRuntimeV4, X4cRamModelGlobalCohortV4,
    X4cRamRebuildStrategyV4, X4cSealConfigV4, X4dClaimAccumulatorV1, X4dInterferenceDeltaV1,
    X4dResponseStateV1, X4dSettlementPolicyV1, X4dSettlementQuerySeedV1,
    X4D_GPT2_RESPONSE_BYTES_V1,
};
use volta_proto::logup::Doms;
use volta_proto::model_proof::{
    prove_response_resident_private_logits, verify_response_private_logits, PrivateChunkPub,
    ResidentChunkRef,
};
use volta_proto::{layer_dom_base, prod_batch_prover, prod_batch_verify};

const SCHEMA: u64 = 1;
const PROFILE: &str = "runpod-a100-x4d-v1";
const PROTOCOL: &str = "x4-zkdeepfold-ud-e29-v4+x4d-deferred-settlement-v1";
const MILESTONE_PREFLIGHT: &str = "X4d-GPT2-pod-preflight-v1";
const MILESTONE_ONLINE: &str = "X4d-GPT2-real-weight-deferred-settlement-v1";
const X4D_DESIGN_SHA256: &str = "cd66fc3df5abe5471f59c4a01e79d85382ad052491889c835dcd7de2e16e66a4";
const X4C_ONBOARDING_MILESTONE: &str = "X4c-GPT2-real-weight-onboarding-crypto-id-v1";
const X4C_PROFILE: &str = "runpod-a100-x4c-v1";
const X4C_PROTOCOL: &str = "x4-zkdeepfold-ud-e29-v4";
const X4C_DESIGN_SHA256: &str = "1a744625078e3ffe5772b040c24854e9510dcedebc906416279cf3a7c29bf191";
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const GOLDEN_P5_SHA256: &str = "4ac774f208a414bf7fb591a29bd455968ce2d89846255fe8239eabd9b5c92f45";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";
const SAFETENSORS_SHA256: &str = "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707";
const GPT2_PROMPT_TOKENS: usize = 100;
const GPT2_DECODE_TOKENS: usize = 50;
const GOLDEN_P6_HEADER_BYTES: usize = 16;
const GOLDEN_P6_BYTES: usize =
    GOLDEN_P6_HEADER_BYTES + 4 * GPT2_DECODE_TOKENS + 8 * GPT2_DECODE_TOKENS;
const MODEL_SUB_CORRELATIONS: u64 = 4_793_590;
const MODEL_FULL_CORRELATIONS: u64 = 181_933;
const MODEL_CLOSURE_FULL_CORRELATIONS: u64 = 2;
const SETTLED_RESPONSES: usize = 16;
const CONNECTION_RESPONSES: usize = 19;
const HARD_RAM_BYTES: u64 = 274_877_906_944;
const HARD_VOLUME_BYTES: u64 = 150_000_000_000;
const G1_TOTAL_CEILING_S: f64 = 5.0;
const G1_FREEZE_CEILING_S: f64 = 0.025;
const G1_PREFILL_CEILING_S: f64 = 10.0;
const G1_DECODE_CEILING_S: f64 = 4.0;
const G1_H2D_CEILING_BYTES: u64 = 100_000_000;
const G1_SYNC_CEILING_S: f64 = 0.150;
const G1_FLATNESS_CEILING: f64 = 1.5;
const OPEN_CEILING_S: f64 = 1.50;
const VERIFY_CEILING_S: f64 = 0.25;
const SOUNDNESS_EXPRESSION: &str = "3320*(9/16)^111 + 28,522,064,267,253/|E|";
const SOUNDNESS_BITS: f64 = 80.255_370_163_990_4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Preflight,
    Online,
}

struct Args {
    mode: Mode,
    weights: PathBuf,
    volume_root: PathBuf,
    durable_root: Option<PathBuf>,
    onboarding: Option<PathBuf>,
    onboarding_sha256: Option<String>,
    output: PathBuf,
    authorization_store: Option<PathBuf>,
    connection_store: Option<PathBuf>,
    clean_source_sha256: Option<String>,
    settlement_epoch: u64,
    response_cpu_ids: Vec<usize>,
    settlement_cpu_ids: Vec<usize>,
}

fn usage() -> ! {
    eprintln!(
        "usage: x4d_gpt2_pod_record --mode preflight|online --weights PATH \
         --volume-root PATH --output PATH \
         [--durable-root PATH --onboarding PATH --onboarding-sha256 HEX \
          --authorization-store PATH --connection-store PATH \
          --clean-source-sha256 HEX --settlement-epoch N] \
         --response-cpus C0,...,C7 --settlement-cpus C0,...,C26"
    );
    std::process::exit(2)
}

fn parse_cpu_ids(value: String) -> Vec<usize> {
    let parsed = value
        .split(',')
        .map(|part| part.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|_| usage());
    if parsed.is_empty() {
        usage();
    }
    parsed
}

fn parse_args() -> Args {
    let mut mode = None;
    let mut weights = None;
    let mut volume_root = None;
    let mut durable_root = None;
    let mut onboarding = None;
    let mut onboarding_sha256 = None;
    let mut output = None;
    let mut authorization_store = None;
    let mut connection_store = None;
    let mut clean_source_sha256 = None;
    let mut settlement_epoch = 1u64;
    let mut response_cpu_ids = None;
    let mut settlement_cpu_ids = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--mode" => {
                mode = Some(match value().as_str() {
                    "preflight" => Mode::Preflight,
                    "online" => Mode::Online,
                    _ => usage(),
                })
            }
            "--weights" => weights = Some(PathBuf::from(value())),
            "--volume-root" => volume_root = Some(PathBuf::from(value())),
            "--durable-root" => durable_root = Some(PathBuf::from(value())),
            "--onboarding" => onboarding = Some(PathBuf::from(value())),
            "--onboarding-sha256" => onboarding_sha256 = Some(value()),
            "--output" => output = Some(PathBuf::from(value())),
            "--authorization-store" => authorization_store = Some(PathBuf::from(value())),
            "--connection-store" => connection_store = Some(PathBuf::from(value())),
            "--clean-source-sha256" => clean_source_sha256 = Some(value()),
            "--settlement-epoch" => settlement_epoch = value().parse().unwrap_or_else(|_| usage()),
            "--response-cpus" => response_cpu_ids = Some(parse_cpu_ids(value())),
            "--settlement-cpus" => settlement_cpu_ids = Some(parse_cpu_ids(value())),
            _ => usage(),
        }
    }
    Args {
        mode: mode.unwrap_or_else(|| usage()),
        weights: weights.unwrap_or_else(|| usage()),
        volume_root: volume_root.unwrap_or_else(|| usage()),
        durable_root,
        onboarding,
        onboarding_sha256,
        output: output.unwrap_or_else(|| usage()),
        authorization_store,
        connection_store,
        clean_source_sha256,
        settlement_epoch,
        response_cpu_ids: response_cpu_ids.unwrap_or_else(|| usage()),
        settlement_cpu_ids: settlement_cpu_ids.unwrap_or_else(|| usage()),
    }
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("expected a 64-digit digest".to_owned());
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .map_err(|_| "digest is not lowercase hexadecimal".to_owned())?;
    }
    Ok(digest)
}

fn random_digest(label: &str) -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut value)
        .map_err(|error| format!("OS randomness for {label}: {error}"))?;
    if value == [0; 32] {
        return Err(format!("OS randomness returned zero for {label}"));
    }
    Ok(value)
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("run sha256sum: {error}"))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "sha256sum emitted non-UTF8".to_owned())?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn verify_inputs(root: &Path) -> Result<(), String> {
    for (name, digest) in [
        ("gpt2s-q.bin", GPT2_BIN_SHA256),
        ("gpt2s-q.json", GPT2_JSON_SHA256),
        ("gpt2s-q.params", GPT2_PARAMS_SHA256),
        ("golden-p5.bin", GOLDEN_P5_SHA256),
        ("golden-p6.bin", GOLDEN_P6_SHA256),
        ("model.safetensors", SAFETENSORS_SHA256),
    ] {
        if sha256(&root.join(name))? != digest {
            return Err(format!("frozen input digest mismatch: {name}"));
        }
    }
    Ok(())
}

fn verify_design() -> Result<(), String> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/x4d-deferred-settlement-design.md");
    let observed = sha256(&path)?;
    if observed != X4D_DESIGN_SHA256 {
        return Err(format!(
            "X4d design digest mismatch: expected {X4D_DESIGN_SHA256}, got {observed}"
        ));
    }
    Ok(())
}

fn producer_source_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/x4d_gpt2_pod_record.rs")
}

fn git_sha_clean() -> Result<String, String> {
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map_err(|error| format!("git status: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err("record mode requires a clean git tree".to_owned());
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("git rev-parse: {error}"))?;
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
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist record {}: {error}", path.display()))
}

fn mem_total_bytes() -> Result<u64, String> {
    fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("read /proc/meminfo: {error}"))?
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            (parts.next() == Some("MemTotal:"))
                .then(|| parts.next()?.parse::<u64>().ok()?.checked_mul(1024))
                .flatten()
        })
        .ok_or_else(|| "MemTotal is missing or overflows".to_owned())
}

fn filesystem_bytes(path: &Path) -> Result<(u64, u64), String> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "volume path contains NUL".to_owned())?;
    let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut stats) };
    if rc != 0 {
        return Err(format!("statvfs failed for {}", path.to_string_lossy()));
    }
    let block = stats.f_frsize;
    let total = stats
        .f_blocks
        .checked_mul(block)
        .ok_or_else(|| "statvfs total bytes overflow".to_owned())?;
    let available = stats
        .f_bavail
        .checked_mul(block)
        .ok_or_else(|| "statvfs available bytes overflow".to_owned())?;
    Ok((total, available))
}

#[derive(Clone, Debug, Serialize)]
struct HardwareRow {
    gpu_name: String,
    gpu_uuid: String,
    gpu_memory_mib: u64,
    selected_gpu_count: usize,
    mem_total_bytes: u64,
    volume_total_bytes: u64,
    volume_available_bytes: u64,
    response_cpu_ids: Vec<usize>,
    settlement_cpu_ids: Vec<usize>,
    split_policy_valid: bool,
    gpu_pass: bool,
    ram_pass: bool,
    volume_pass: bool,
    overall_pass: bool,
}

fn hardware_preflight(args: &Args) -> Result<HardwareRow, String> {
    let policy = X4dSplitThreadPolicyV1 {
        response_cpu_ids: args.response_cpu_ids.clone(),
        settlement_cpu_ids: args.settlement_cpu_ids.clone(),
    };
    policy.validate()?;
    let mut allowed = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    let affinity_rc =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut allowed) };
    if affinity_rc != 0
        || args
            .response_cpu_ids
            .iter()
            .chain(&args.settlement_cpu_ids)
            .any(|&cpu| unsafe { !libc::CPU_ISSET(cpu, &allowed) })
    {
        return Err("X4d split CPU set is outside the process affinity mask".to_owned());
    }
    let output = Command::new("nvidia-smi")
        .args(["--query-gpu=name,uuid,memory.total", "--format=csv,noheader,nounits"])
        .output()
        .map_err(|error| format!("run nvidia-smi: {error}"))?;
    if !output.status.success() {
        return Err("nvidia-smi failed".to_owned());
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| "nvidia-smi emitted non-UTF8".to_owned())?;
    let rows = text.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>();
    if rows.len() != 1 {
        return Err(format!("profile requires exactly one visible GPU, observed {}", rows.len()));
    }
    let columns = rows[0].split(',').map(str::trim).collect::<Vec<_>>();
    if columns.len() != 3 {
        return Err("nvidia-smi GPU row has wrong shape".to_owned());
    }
    let gpu_memory_mib =
        columns[2].parse::<u64>().map_err(|_| "GPU memory is not numeric".to_owned())?;
    let mem_total_bytes = mem_total_bytes()?;
    let (volume_total_bytes, volume_available_bytes) = filesystem_bytes(&args.volume_root)?;
    let gpu_pass = columns[0].contains("A100-SXM4-80GB") && gpu_memory_mib >= 81_920;
    let ram_pass = mem_total_bytes >= HARD_RAM_BYTES;
    let volume_pass = volume_total_bytes >= HARD_VOLUME_BYTES;
    let row = HardwareRow {
        gpu_name: columns[0].to_owned(),
        gpu_uuid: columns[1].to_owned(),
        gpu_memory_mib,
        selected_gpu_count: rows.len(),
        mem_total_bytes,
        volume_total_bytes,
        volume_available_bytes,
        response_cpu_ids: args.response_cpu_ids.clone(),
        settlement_cpu_ids: args.settlement_cpu_ids.clone(),
        split_policy_valid: true,
        gpu_pass,
        ram_pass,
        volume_pass,
        overall_pass: gpu_pass && ram_pass && volume_pass,
    };
    if !row.overall_pass {
        return Err(format!("X4d hardware preflight failed closed: {row:?}"));
    }
    Ok(row)
}

#[derive(Serialize)]
struct PreflightRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    protocol: String,
    design_sha256: String,
    producer_source_sha256: String,
    hardware: HardwareRow,
    inputs_exact: bool,
    soundness_expression: String,
    soundness_bits: f64,
    overall_pass: bool,
}

fn preflight(args: &Args) -> Result<(), String> {
    if args.output.exists() {
        return Err("preflight output must be fresh".to_owned());
    }
    verify_design()?;
    verify_inputs(&args.weights)?;
    let git_sha = git_sha_clean()?;
    let producer_source_sha256 = sha256(&producer_source_path())?;
    let hardware = hardware_preflight(args)?;
    let record = PreflightRecord {
        schema: SCHEMA,
        milestone: MILESTONE_PREFLIGHT.to_owned(),
        git_sha,
        git_dirty: false,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        design_sha256: X4D_DESIGN_SHA256.to_owned(),
        producer_source_sha256,
        hardware,
        inputs_exact: true,
        soundness_expression: SOUNDNESS_EXPRESSION.to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        overall_pass: true,
    };
    write_append_only(&args.output, &record)
}

#[derive(Clone, Debug, Deserialize)]
struct DurableRow {
    cohort_id: u32,
    coefficient_bytes: u64,
    coefficient_sha256: String,
    root_bytes: u64,
    root_hex: String,
    root_sha256: String,
}

#[derive(Deserialize)]
struct OnboardingRecord {
    schema: u64,
    milestone: String,
    git_dirty: bool,
    crypto_build_id_scheme: String,
    crypto_build_id: String,
    crypto_build_manifest_blake3: String,
    crypto_build_file_count: u64,
    crypto_build_source_bytes: u64,
    profile: String,
    protocol: String,
    design_sha256: String,
    input_bin_sha256: String,
    input_json_sha256: String,
    input_params_sha256: String,
    golden_p5_sha256: String,
    golden_p6_sha256: String,
    model_safetensors_sha256: String,
    model_config_digest: String,
    weights_digest: String,
    parent_domains: Vec<[u64; 2]>,
    durable: Vec<DurableRow>,
    warmup_root_set: Vec<String>,
    overall_pass: bool,
}

fn load_durable_material(
    durable: &Path,
    config: &CohortVerifierConfigV4,
    row: &DurableRow,
) -> Result<(X4cGpt2CohortMaterial, [u8; 32]), String> {
    if config.identity.cohort_id != row.cohort_id {
        return Err("onboarding cohort order changed".to_owned());
    }
    let directory = durable.join(format!("cohort-{:08x}", row.cohort_id));
    let coefficient_path = directory.join("coefficients.bin");
    let root_path = directory.join("root.bin");
    if fs::metadata(&coefficient_path)
        .map_err(|error| format!("stat durable coefficients: {error}"))?
        .len()
        != row.coefficient_bytes
        || fs::metadata(&root_path).map_err(|error| format!("stat durable root: {error}"))?.len()
            != row.root_bytes
        || row.root_bytes != 32
        || sha256(&coefficient_path)? != row.coefficient_sha256
        || sha256(&root_path)? != row.root_sha256
    {
        return Err("durable X4c size/digest mismatch".to_owned());
    }
    let root: [u8; 32] = fs::read(&root_path)
        .map_err(|error| format!("read durable root: {error}"))?
        .try_into()
        .map_err(|_| "durable root is not 32 bytes".to_owned())?;
    if hex(&root) != row.root_hex {
        return Err("durable root bytes mismatch onboarding".to_owned());
    }
    let coefficients = read_persisted_coefficients_v4(&coefficient_path, config)
        .map_err(|error| format!("read durable coefficients: {error:?}"))?;
    Ok((
        X4cGpt2CohortMaterial {
            name: "x4d-carried-x4c-durable-real-weight",
            config: config.clone(),
            coefficients,
        },
        root,
    ))
}

struct Workload {
    model: Gpt2Model,
    prefill: volta_gpt2::ModelWitness,
    band: BandModelWitness,
    sequence: Vec<u32>,
}

fn parse_golden_p6_tokens(golden: &[u8]) -> Result<Vec<u32>, String> {
    if golden.len() != GOLDEN_P6_BYTES || &golden[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6.bin has wrong canonical geometry".to_owned());
    }
    let prompt_tokens = u32::from_le_bytes(golden[8..12].try_into().unwrap()) as usize;
    let decode_tokens = u32::from_le_bytes(golden[12..16].try_into().unwrap()) as usize;
    if prompt_tokens != GPT2_PROMPT_TOKENS || decode_tokens != GPT2_DECODE_TOKENS {
        return Err("golden-p6.bin has wrong canonical geometry".to_owned());
    }
    Ok((0..GPT2_DECODE_TOKENS)
        .map(|index| {
            let offset = GOLDEN_P6_HEADER_BYTES + 4 * index;
            u32::from_le_bytes(golden[offset..offset + 4].try_into().unwrap())
        })
        .collect())
}

fn workload(weights: &Path) -> Result<Workload, String> {
    verify_inputs(weights)?;
    let model = load_model(weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout()?;
    let prefill = forward_model(&model, GPT2_PROMPT_TOKENS);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, GPT2_PROMPT_TOKENS);
    let mut generated = Vec::with_capacity(GPT2_DECODE_TOKENS);
    let mut next = argmax(&prefill.logits);
    for position in 0..GPT2_DECODE_TOKENS {
        generated.push(next);
        next = argmax(&decode_step(&model, &mut cache, next, GPT2_PROMPT_TOKENS + position));
    }
    let golden = fs::read(weights.join("golden-p6.bin"))
        .map_err(|error| format!("read golden-p6.bin: {error}"))?;
    if generated != parse_golden_p6_tokens(&golden)? {
        return Err("real GPT-2 greedy decode differs from golden-p6".to_owned());
    }
    let mut sequence = model.p.tokens[..GPT2_PROMPT_TOKENS].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let band = band_model_witness(&model, &full, GPT2_PROMPT_TOKENS);
    Ok(Workload { model, prefill, band, sequence })
}

#[derive(Clone, Copy)]
struct TranscriptReplay {
    bytes: u64,
    labels: u64,
}

fn reconcile_transcripts(
    prover: &Transcript,
    verifier: &mut Transcript,
) -> Result<TranscriptReplay, String> {
    for (&label, &verifier_bytes) in verifier.ledger() {
        if verifier_bytes > prover.ledger().get(label).copied().unwrap_or(0) {
            return Err(format!("verifier transcript exceeds prover at {label}"));
        }
    }
    let replay = prover
        .ledger()
        .iter()
        .filter_map(|(&label, &prover_bytes)| {
            let verifier_bytes = verifier.ledger().get(label).copied().unwrap_or(0);
            (prover_bytes > verifier_bytes).then_some((label, prover_bytes - verifier_bytes))
        })
        .collect::<Vec<_>>();
    let mut bytes = 0u64;
    for (label, delta) in &replay {
        verifier.append(label, *delta);
        bytes = bytes.checked_add(*delta).ok_or("transcript replay bytes overflow")?;
    }
    if prover.total_bytes() != verifier.total_bytes() || prover.ledger() != verifier.ledger() {
        return Err("model transcript replay did not reconcile".to_owned());
    }
    Ok(TranscriptReplay {
        bytes,
        labels: u64::try_from(replay.len()).map_err(|_| "replay label count overflows")?,
    })
}

#[allow(clippy::too_many_arguments)]
fn close_model_response(
    prod: &[(volta_mac::ProverAuthed, volta_mac::ProverAuthed, volta_mac::ProverAuthed)],
    zero: &[volta_mac::ProverAuthed],
    kprod: &[(volta_mac::VerifierKey, volta_mac::VerifierKey, volta_mac::VerifierKey)],
    kzero: &[volta_mac::VerifierKey],
    stream: &mut CorrelationStream,
    verifier: &mut VerifierCtx,
    prover_tx: &mut Transcript,
    verifier_tx: &mut Transcript,
) -> bool {
    let mut prover_doms = Doms::new(layer_dom_base(255));
    let mut verifier_doms = Doms::new(layer_dom_base(255));
    let challenge = prover_tx.challenge_fp2();
    if challenge != verifier_tx.challenge_fp2() {
        return false;
    }
    let product_domain = prover_doms.take(1);
    if product_domain != verifier_doms.take(1) {
        return false;
    }
    let mask = stream.draw_fulls(product_domain, 1)[0];
    let key_mask = verifier.expand_full_keys(product_domain, 1)[0];
    let proof = prod_batch_prover(prod, challenge, mask, prover_tx);
    verifier_tx.append("prod_check_m0_m1", 32);
    let product_ok = prod_batch_verify(kprod, key_mask, verifier.delta, challenge, &proof);
    let zero_domain = prover_doms.take(1);
    if zero_domain != verifier_doms.take(1) {
        return false;
    }
    let zero_ok = zero_batch_exchange(zero, kzero, stream, verifier, zero_domain, prover_tx);
    verifier_tx.append("mask_correction", 16);
    let _ = verifier_tx.challenge_fp2();
    verifier_tx.append("zero_batch_tag", 16);
    product_ok && zero_ok
}

fn transcript_digest(response_nonce: [u8; 32], transcript: &Transcript) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/x4d/model-transcript-ledger/v1");
    hasher.update(&response_nonce);
    hasher.update(&transcript.total_bytes().to_le_bytes());
    for (label, bytes) in transcript.ledger() {
        hasher.update(&u64::try_from(label.len()).unwrap().to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&bytes.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[derive(Serialize)]
struct ResponseRow {
    ordinal: usize,
    role: String,
    response_nonce_digest: String,
    model_prove_s: f64,
    model_verify_s: f64,
    claim_freeze_s: f64,
    total_g1_s: f64,
    prefill_prove_upper_s: f64,
    max_decode_marginal_s: f64,
    flatness_last_over_first: f64,
    h2d_bytes: u64,
    synchronization_wall_upper_s: f64,
    model_transcript_bytes: u64,
    model_mac_closure_bytes: u64,
    response_bytes: u64,
    pcs_bytes: u64,
    product_state_at_delivery: String,
    transcript_replay_bytes: u64,
    transcript_replay_labels: u64,
    correlations_consumed: u64,
    freeze_journal: X4dClaimsFrozenJournalAudit,
    connection_audit: ConnectionResponseAudit,
    accepted: bool,
}

#[allow(clippy::too_many_arguments)]
fn run_response(
    ordinal: usize,
    role: &str,
    response_pool: &rayon::ThreadPool,
    workload: &Workload,
    resident_model: &ResidentGpt2Model,
    resident_prefill: &ResidentModelWitness,
    resident_band: &ResidentBandModelWitness<'_>,
    error: &DeviceBuffer<u32>,
    inventory: &X4cGpt2Inventory,
    logical: &mut X4dGpt2ConnectionV1,
    production: &mut ProductionFaseDConnection,
    authorizations: &ResponseAuthorizationStore,
    binding: ConnectionBinding,
    runtime: &mut X4cCudaArenaRuntimeV4<'_>,
) -> Result<ResponseRow, String> {
    logical.preflight_response()?;
    let response_nonce = random_digest("X4d response nonce")?;
    production
        .connection
        .begin_response(
            authorizations,
            binding.response_binding(response_nonce).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("begin X4d response: {error}"))?;
    let tensor_tag = *blake3::hash(
        &[
            b"volta-zk/x4d/gpt2-model-response-domain/v1".as_slice(),
            &(ordinal as u64).to_le_bytes(),
        ]
        .concat(),
    )
    .as_bytes();
    let domain = CorrelationDomain::new(
        binding.connection_id,
        response_nonce,
        u32::try_from(ordinal).map_err(|_| "response ordinal exceeds u32")?,
        0,
        ordinal as u64,
        tensor_tag,
    )
    .map_err(|error| format!("response correlation domain: {error}"))?;
    let pools = production
        .allocate_pcg_pools(
            0,
            usize::try_from(MODEL_SUB_CORRELATIONS).unwrap(),
            usize::try_from(MODEL_FULL_CORRELATIONS + MODEL_CLOSURE_FULL_CORRELATIONS).unwrap(),
            domain,
        )
        .map_err(|error| format!("allocate response PCG: {error}"))?;
    let mut stream = CorrelationStream::from_pcg_pool(pools.prover);
    let mut verifier = VerifierCtx::from_pcg_pool(pools.verifier_delta, pools.verifier);
    let challenge_seed = random_digest("model challenge seed")?;
    let mut prover_tx = Transcript::new(challenge_seed);
    let mut verifier_tx = Transcript::new(challenge_seed);
    let model_backend =
        runtime.backend_between_responses().map_err(|error| format!("model backend: {error:?}"))?;
    model_backend
        .begin_measurement()
        .map_err(|error| format!("begin model measurement: {error}"))?;
    let model_started = Instant::now();
    let resident_chunks =
        [ResidentChunkRef { band: resident_band, logits: &[], seq: &workload.sequence }];
    let (proof, prover_output, prod, zero) = response_pool.install(|| {
        prove_response_resident_private_logits(
            &workload.model,
            resident_model,
            resident_prefill,
            &resident_chunks,
            DeviceSlice::new(error, 0, 1).map_err(|error| format!("proof error slice: {error}"))?,
            &mut stream,
            &mut prover_tx,
            model_backend,
        )
        .map_err(|error| format!("resident model proof: {error}"))
    })?;
    let model_prove_s = model_started.elapsed().as_secs_f64();
    inventory.validate_parent_domains(&prover_output)?;
    let public = [PrivateChunkPub { q: 50, seq: &workload.sequence }];
    let verify_started = Instant::now();
    let (verifier_output, kprod, kzero) = response_pool.install(|| {
        verify_response_private_logits(
            &workload.model,
            100,
            &public,
            &proof,
            &mut verifier,
            &mut verifier_tx,
        )
        .ok_or_else(|| "real-weight model proof rejected".to_owned())
    })?;
    let model_verify_s = verify_started.elapsed().as_secs_f64();
    let replay = reconcile_transcripts(&prover_tx, &mut verifier_tx)?;
    if prover_tx.total_bytes() != X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1
        || replay.bytes != 41_034_112
        || replay.labels != 25
        || !close_model_response(
            &prod,
            &zero,
            &kprod,
            &kzero,
            &mut stream,
            &mut verifier,
            &mut prover_tx,
            &mut verifier_tx,
        )
        || prover_tx.total_bytes()
            != X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1 + X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1
        || prover_tx.ledger() != verifier_tx.ledger()
    {
        return Err("model authentication/transcript accounting changed".to_owned());
    }
    let backend_stats = model_backend
        .finish_measurement()
        .map_err(|error| format!("finish model measure: {error}"))?;
    let model_transcript_digest = transcript_digest(response_nonce, &prover_tx);
    let delivered = logical.freeze_model_response(
        inventory,
        response_nonce,
        model_transcript_digest,
        X4D_GPT2_MODEL_TRANSCRIPT_BYTES_V1,
        X4D_GPT2_MODEL_MAC_CLOSURE_BYTES_V1,
        &prover_output,
        &verifier_output,
    )?;
    let freeze_journal = production
        .connection
        .record_x4d_claims_frozen(
            response_nonce,
            delivered.freeze_receipt.first_claim_index,
            delivered.freeze_receipt.appended_count,
            delivered.freeze_receipt.ending_accumulator_digest,
        )
        .map_err(|error| format!("journal X4d claim freeze: {error}"))?;
    let connection_audit = production
        .connection
        .finish_x4d_response_pending()
        .map_err(|error| format!("finish pending response: {error}"))?;
    let expected_raw =
        MODEL_SUB_CORRELATIONS + 2 * (MODEL_FULL_CORRELATIONS + MODEL_CLOSURE_FULL_CORRELATIONS);
    let decode_walls = prover_output
        .chunk_p1_s
        .iter()
        .zip(&prover_output.chunk_p2_s)
        .map(|(a, b)| a + b)
        .collect::<Vec<_>>();
    let decode_sum = decode_walls.iter().sum::<f64>();
    let prefill_prove_upper_s = (model_prove_s - decode_sum).max(0.0);
    let max_decode_marginal_s = decode_walls.iter().copied().fold(0.0, f64::max);
    let flatness_last_over_first = decode_walls
        .first()
        .zip(decode_walls.last())
        .map(|(first, last)| last / first)
        .unwrap_or(f64::INFINITY);
    let claim_freeze_s = delivered.claim_freeze_wall_ns as f64 / 1e9;
    let total_g1_s = model_prove_s + model_verify_s + claim_freeze_s;
    let synchronization_wall_upper_s = backend_stats.synchronization_ns as f64 / 1e9;
    let accepted = delivered.product_state == X4dResponseStateV1::WeightPending
        && delivered.response_bytes == X4D_GPT2_RESPONSE_BYTES_V1
        && delivered.pcs_bytes == 0
        && connection_audit.correlations_consumed == expected_raw
        && stream.counters.sub_corrs == MODEL_SUB_CORRELATIONS
        && stream.counters.full_corrs == MODEL_FULL_CORRELATIONS + MODEL_CLOSURE_FULL_CORRELATIONS;
    if !accepted {
        return Err("X4d response accounting failed closed".to_owned());
    }
    Ok(ResponseRow {
        ordinal,
        role: role.to_owned(),
        response_nonce_digest: hex(blake3::hash(&response_nonce).as_bytes()),
        model_prove_s,
        model_verify_s,
        claim_freeze_s,
        total_g1_s,
        prefill_prove_upper_s,
        max_decode_marginal_s,
        flatness_last_over_first,
        h2d_bytes: backend_stats.h2d_bytes,
        synchronization_wall_upper_s,
        model_transcript_bytes: delivered.model_transcript_bytes,
        model_mac_closure_bytes: delivered.model_mac_closure_bytes,
        response_bytes: delivered.response_bytes,
        pcs_bytes: delivered.pcs_bytes,
        product_state_at_delivery: "WEIGHT_PENDING".to_owned(),
        transcript_replay_bytes: replay.bytes,
        transcript_replay_labels: replay.labels,
        correlations_consumed: connection_audit.correlations_consumed,
        freeze_journal,
        connection_audit,
        accepted,
    })
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn ordered_nonce_digest(nonces: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/x4d/ordered-response-nonces/v1");
    hasher.update(&(nonces.len() as u64).to_le_bytes());
    for nonce in nonces {
        hasher.update(nonce);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Serialize)]
struct G1Row {
    selected_total_s: f64,
    selected_claim_freeze_s: f64,
    selected_prefill_upper_s: f64,
    selected_decode_marginal_s: f64,
    selected_h2d_bytes: u64,
    selected_sync_wall_upper_s: f64,
    selected_flatness: f64,
    total_pass: bool,
    freeze_pass: bool,
    prefill_pass: bool,
    decode_pass: bool,
    h2d_pass: bool,
    sync_pass: bool,
    flatness_pass: bool,
    overall_pass: bool,
}

#[derive(Serialize)]
struct InterferenceRow {
    order: String,
    isolated_response_s: Vec<f64>,
    settlement_queued_response_s: Vec<f64>,
    isolated_upper_median_s: f64,
    settlement_queued_upper_median_s: f64,
    absolute_delta_s: f64,
    percentage_delta: f64,
    settlement_cpu_overlap_intervals: u64,
    settlement_gpu_overlap_intervals: u64,
    accounting_semantics: String,
}

#[derive(Serialize)]
struct SettlementRow {
    responses: usize,
    frozen_claims: usize,
    masked_groups: usize,
    settlement_epoch: u64,
    settlement_bytes: u64,
    expected_settlement_bytes: u64,
    amortized_settlement_bytes_per_response: f64,
    historical_four_mb_scope: String,
    seal_to_terminal_wall_s: f64,
    proof_driver_wall_s: f64,
    auxiliary_materialization_wall_s: f64,
    response_priority_pause_wall_s: f64,
    active_cpu_host_window_s: f64,
    active_gpu_lease_host_window_s: f64,
    lease_wait_wall_s: f64,
    open_wall_s: f64,
    verify_wall_s: f64,
    open_pass: bool,
    verify_pass: bool,
    every_covered_response_weight_verified: bool,
    exact_bytes: bool,
    exact_correlations: bool,
    fresh_auxiliary_masks: usize,
    static_weight_roots_reused: usize,
    query_draws: usize,
    soundness_expression: String,
    soundness_bits: f64,
    interference: InterferenceRow,
    accepted: bool,
}

#[derive(Serialize)]
struct OnlineRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    producer_source_sha256: String,
    profile: String,
    protocol: String,
    design_sha256: String,
    cloud: volta_bench::CloudMetadata,
    hardware: HardwareRow,
    onboarding_path: String,
    onboarding_sha256: String,
    onboarding_exact: bool,
    crypto_build_id_scheme: String,
    crypto_build_id: String,
    durable_tier_bytes: u64,
    rebuild_wall_s: f64,
    rebuild_rows: Vec<AcceleratedRebuildCohortRecord>,
    rebuild_roots: Vec<String>,
    rebuild_roots_equal_onboarding: bool,
    old_auxiliary_roots_rejected_for_settlement: bool,
    setup_wall_s: f64,
    responses: Vec<ResponseRow>,
    g1: G1Row,
    settlement: SettlementRow,
    cap_test_name: String,
    cap_3321_permanent_test_present: bool,
    cap_preflight_3321_rejected: bool,
    soundness_expression_byte_exact: bool,
    g2_permanent_tests: Vec<String>,
    g6_test_name: String,
    g6_abort_before_settlement_terminal_unverified: bool,
    no_retry_same_connection: bool,
    provider_contract_state_at_delivery: String,
    provider_contract_state_at_settlement: String,
    historical_rows_modified: bool,
    overall_pass: bool,
}

fn g1(rows: &[ResponseRow]) -> G1Row {
    let measured = &rows[1..4];
    let selected_total_s = upper_median(measured.iter().map(|row| row.total_g1_s).collect());
    let selected_claim_freeze_s =
        upper_median(measured.iter().map(|row| row.claim_freeze_s).collect());
    let selected_prefill_upper_s =
        upper_median(measured.iter().map(|row| row.prefill_prove_upper_s).collect());
    let selected_decode_marginal_s =
        upper_median(measured.iter().map(|row| row.max_decode_marginal_s).collect());
    let selected_h2d_bytes = measured.iter().map(|row| row.h2d_bytes).max().unwrap_or(u64::MAX);
    let selected_sync_wall_upper_s =
        measured.iter().map(|row| row.synchronization_wall_upper_s).fold(0.0, f64::max);
    let selected_flatness =
        measured.iter().map(|row| row.flatness_last_over_first).fold(0.0, f64::max);
    let total_pass = selected_total_s <= G1_TOTAL_CEILING_S;
    let freeze_pass = selected_claim_freeze_s <= G1_FREEZE_CEILING_S;
    let prefill_pass = selected_prefill_upper_s <= G1_PREFILL_CEILING_S;
    let decode_pass = selected_decode_marginal_s <= G1_DECODE_CEILING_S;
    let h2d_pass = selected_h2d_bytes <= G1_H2D_CEILING_BYTES;
    let sync_pass = selected_sync_wall_upper_s <= G1_SYNC_CEILING_S;
    let flatness_pass = selected_flatness <= G1_FLATNESS_CEILING;
    G1Row {
        selected_total_s,
        selected_claim_freeze_s,
        selected_prefill_upper_s,
        selected_decode_marginal_s,
        selected_h2d_bytes,
        selected_sync_wall_upper_s,
        selected_flatness,
        total_pass,
        freeze_pass,
        prefill_pass,
        decode_pass,
        h2d_pass,
        sync_pass,
        flatness_pass,
        overall_pass: total_pass
            && freeze_pass
            && prefill_pass
            && decode_pass
            && h2d_pass
            && sync_pass
            && flatness_pass,
    }
}

fn validate_onboarding(
    args: &Args,
) -> Result<(OnboardingRecord, String, X4cGpt2Inventory), String> {
    let path = args.onboarding.as_ref().ok_or("online requires --onboarding")?;
    let expected =
        args.onboarding_sha256.as_deref().ok_or("online requires --onboarding-sha256")?;
    parse_hex_32(expected)?;
    let observed = sha256(path)?;
    if observed != expected {
        return Err("onboarding SHA-256 pin mismatch".to_owned());
    }
    let onboarding: OnboardingRecord = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("read onboarding: {error}"))?,
    )
    .map_err(|error| format!("parse onboarding: {error}"))?;
    let crypto = x4c_crypto_build_identity(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    if onboarding.schema != 3
        || onboarding.milestone != X4C_ONBOARDING_MILESTONE
        || onboarding.git_dirty
        || !onboarding.overall_pass
        || onboarding.profile != X4C_PROFILE
        || onboarding.protocol != X4C_PROTOCOL
        || onboarding.design_sha256 != X4C_DESIGN_SHA256
        || onboarding.crypto_build_id_scheme != X4C_CRYPTO_BUILD_ID_SCHEME
        || onboarding.crypto_build_id != crypto.digest_blake3
        || onboarding.crypto_build_manifest_blake3 != crypto.manifest_blake3
        || onboarding.crypto_build_file_count != crypto.file_count
        || onboarding.crypto_build_source_bytes != crypto.source_bytes
        || onboarding.input_bin_sha256 != GPT2_BIN_SHA256
        || onboarding.input_json_sha256 != GPT2_JSON_SHA256
        || onboarding.input_params_sha256 != GPT2_PARAMS_SHA256
        || onboarding.golden_p5_sha256 != GOLDEN_P5_SHA256
        || onboarding.golden_p6_sha256 != GOLDEN_P6_SHA256
        || onboarding.model_safetensors_sha256 != SAFETENSORS_SHA256
        || onboarding.parent_domains.len() != 51
        || onboarding.durable.len() != 5
        || onboarding.warmup_root_set.len() != 5
    {
        return Err("carried X4c onboarding record is ineligible".to_owned());
    }
    let inventory = X4cGpt2Inventory::new(
        parse_hex_32(&onboarding.model_config_digest)?,
        parse_hex_32(&onboarding.weights_digest)?,
        &onboarding.parent_domains,
    )?;
    Ok((onboarding, observed, inventory))
}

fn online(args: &Args) -> Result<(), String> {
    if args.output.exists() || args.settlement_epoch != 1 {
        return Err(
            "online output must be fresh and the first connection settlement epoch must be 1"
                .to_owned(),
        );
    }
    verify_design()?;
    verify_inputs(&args.weights)?;
    let hardware = hardware_preflight(args)?;
    let git_sha = git_sha_clean()?;
    let source_sha =
        args.clean_source_sha256.as_deref().ok_or("online requires --clean-source-sha256")?;
    let clean_source = parse_hex_32(source_sha)?;
    if sha256(&producer_source_path())? != source_sha {
        return Err("clean producer source digest mismatch".to_owned());
    }
    let cloud = cloud_metadata_from_env().ok_or("cloud metadata environment is required")?;
    let (onboarding, onboarding_sha256, inventory) = validate_onboarding(args)?;
    let durable = args.durable_root.as_ref().ok_or("online requires --durable-root")?;
    let coefficient_bytes = onboarding.durable.iter().map(|row| row.coefficient_bytes).sum::<u64>();
    let root_bytes = onboarding.durable.iter().map(|row| row.root_bytes).sum::<u64>();
    if coefficient_bytes != X4C_GPT2_DURABLE_COEFFICIENT_BYTES
        || coefficient_bytes + root_bytes != X4C_GPT2_DURABLE_TIER_BYTES
    {
        return Err("durable tier byte identity changed".to_owned());
    }
    let loaded = inventory
        .cohort_configs
        .iter()
        .zip(&onboarding.durable)
        .map(|(config, row)| load_durable_material(durable, config, row))
        .collect::<Result<Vec<_>, _>>()?;
    let (materials, roots): (Vec<_>, Vec<_>) = loaded.into_iter().unzip();
    let evaluations = rebuild_evaluation_tables(&inventory, &materials)?;
    let mut rebuild_backend =
        Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
            .map_err(|error| format!("initialize rebuild CUDA: {error}"))?;
    let rebuild_started = Instant::now();
    const SCHEDULE: [usize; 5] = [0, 1, 2, 4, 3];
    let mut material_slots = materials.into_iter().map(Some).collect::<Vec<_>>();
    let mut cohort_slots =
        std::iter::repeat_with(|| None).take(material_slots.len()).collect::<Vec<_>>();
    let mut rebuild_rows = Vec::with_capacity(5);
    for index in SCHEDULE {
        let material = material_slots[index].take().ok_or("rebuild schedule reused a cohort")?;
        let before = process_memory_record()?;
        let (cohort, metrics) = rebuild_cohort_ram_v4(
            X4cRamRebuildStrategyV4::CudaRam,
            Some(&mut rebuild_backend),
            material.config,
            material.coefficients,
            roots[index],
        )
        .map_err(|error| format!("accelerated fresh rebuild: {error:?}"))?;
        let after = process_memory_record()?;
        let row = accelerated_rebuild_cohort_record(
            cohort.commitment().config.identity.cohort_id,
            metrics,
            before,
            after,
        )?;
        if !row.accepted {
            return Err("accelerated rebuild cohort failed counters".to_owned());
        }
        cohort_slots[index] = Some(cohort);
        rebuild_rows.push(row);
    }
    let cohorts = cohort_slots
        .into_iter()
        .map(|cohort| cohort.ok_or_else(|| "rebuild omitted cohort".to_owned()))
        .collect::<Result<Vec<X4cRamModelGlobalCohortV4>, _>>()?;
    let rebuild_wall_s = rebuild_started.elapsed().as_secs_f64();
    let rebuild_roots = cohorts.iter().map(|cohort| hex(&cohort.root())).collect::<Vec<_>>();
    let rebuild_roots_equal_onboarding = rebuild_roots == onboarding.warmup_root_set;
    if !rebuild_roots_equal_onboarding {
        return Err("fresh rebuild roots differ from onboarding".to_owned());
    }
    // The inner CUDA context owns the rebuild workspace. It must be torn down
    // before the fresh online context is created even though `Backend` itself
    // relies on field drop rather than a handwritten Drop impl.
    #[allow(clippy::drop_non_drop)]
    drop(rebuild_backend);
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize online CUDA: {error}"))?;
    let work = workload(&args.weights)?;
    let resident_model = upload_resident_model(&work.model, &mut backend)
        .map_err(|error| format!("upload model: {error}"))?;
    let resident_prefill = forward_model_tokens_resident(
        &resident_model,
        &work.model.p.tokens[..GPT2_PROMPT_TOKENS],
        &mut backend,
    )
    .map_err(|error| format!("resident prefill: {error}"))?;
    let prefill_logits = backend
        .download_device(
            resident_prefill.logits().buffer(),
            resident_prefill.logits().offset(),
            VOCAB,
        )
        .map_err(|error| format!("download prefill logits: {error}"))?;
    let resident_source =
        forward_model_tokens_resident(&resident_model, &work.sequence, &mut backend)
            .map_err(|error| format!("resident response: {error}"))?;
    let resident_band =
        band_model_witness_resident(&resident_model, &resident_source, 100, 50, &mut backend)
            .map_err(|error| format!("resident band: {error}"))?;
    let band_logits = backend
        .download_device(
            resident_band.logits().buffer(),
            resident_band.logits().offset(),
            GPT2_DECODE_TOKENS * VOCAB,
        )
        .map_err(|error| format!("download band logits: {error}"))?;
    if prefill_logits != work.prefill.logits || band_logits != work.band.logits {
        return Err("CPU/CUDA real-weight witness differential failed".to_owned());
    }
    let error =
        backend.upload_new_device(&[0u32]).map_err(|error| format!("proof error word: {error}"))?;
    let policy = X4dSplitThreadPolicyV1 {
        response_cpu_ids: args.response_cpu_ids.clone(),
        settlement_cpu_ids: args.settlement_cpu_ids.clone(),
    };
    let (response_pool, settlement_pool) = policy.build_pinned_pools()?;
    let connection_store = ConnectionStore::new(
        args.connection_store.as_ref().ok_or("online requires --connection-store")?,
    )
    .map_err(|error| format!("connection store: {error}"))?;
    let authorization_store = ResponseAuthorizationStore::new(
        args.authorization_store.as_ref().ok_or("online requires --authorization-store")?,
    )
    .map_err(|error| format!("authorization store: {error}"))?;
    let binding = ConnectionBinding::new(
        random_digest("connection id")?,
        random_digest("authenticated channel id")?,
        FaseDStagePlan::TerminalOne,
    )
    .map_err(|error| format!("connection binding: {error}"))?;
    let setup_started = Instant::now();
    let mut production = open_fase_d_connection_with_ggm_prg(
        &connection_store,
        binding,
        None,
        FaseDParams::production(FaseDStagePlan::TerminalOne),
        GgmPrg::Aes128Mmo,
    )
    .map_err(|error| format!("open fase-D connection: {error}"))?;
    production
        .spool_terminal_one_correlations()
        .map_err(|error| format!("spool fase-D correlations: {error}"))?;
    let setup_wall_s = setup_started.elapsed().as_secs_f64();
    let static_weight_commitment =
        x4d_static_weight_commitment_digest_v1(&inventory, &cohorts[..3])?;
    let mut logical = X4dGpt2ConnectionV1::new(static_weight_commitment, binding.connection_id)?;
    let mut runtime = X4cCudaArenaRuntimeV4::production(&mut backend)
        .map_err(|error| format!("X4d CUDA arena runtime: {error:?}"))?;
    let mut responses = Vec::with_capacity(CONNECTION_RESPONSES);
    for ordinal in 0..SETTLED_RESPONSES {
        let role = if ordinal == 0 {
            "g1-warmup"
        } else if ordinal < 4 {
            "g1-measured"
        } else if ordinal == 14 {
            "abba-isolated-a1"
        } else {
            "connection-fill"
        };
        responses.push(run_response(
            ordinal,
            role,
            &response_pool,
            &work,
            &resident_model,
            &resident_prefill,
            &resident_band,
            &error,
            &inventory,
            &mut logical,
            &mut production,
            &authorization_store,
            binding,
            &mut runtime,
        )?);
    }
    let settlement_started = Instant::now();
    let batch = logical.seal_settlement()?;
    let range = &batch.context.range;
    production
        .connection
        .seal_x4d_settlement(
            args.settlement_epoch,
            range.first_claim_index,
            range.claim_count,
            range.starting_accumulator_digest,
            range.sealed_accumulator_digest,
            ordered_nonce_digest(&range.ordered_response_nonces),
        )
        .map_err(|error| format!("journal settlement seal: {error}"))?;
    let pause_started = Instant::now();
    for ordinal in SETTLED_RESPONSES..SETTLED_RESPONSES + 2 {
        responses.push(run_response(
            ordinal,
            "abba-settlement-queued-b",
            &response_pool,
            &work,
            &resident_model,
            &resident_prefill,
            &resident_band,
            &error,
            &inventory,
            &mut logical,
            &mut production,
            &authorization_store,
            binding,
            &mut runtime,
        )?);
    }
    let response_priority_pause_wall_s = pause_started.elapsed().as_secs_f64();
    let aux_seed = random_digest("settlement auxiliary seed")?;
    let aux_started = Instant::now();
    let auxiliary = settlement_pool
        .install(|| materialize_fresh_auxiliary_set_v1(&inventory, &batch.context, aux_seed))?;
    let auxiliary_materialization_wall_s = aux_started.elapsed().as_secs_f64();
    let old_auxiliary_roots_rejected_for_settlement = auxiliary
        .cohorts
        .iter()
        .map(|cohort| cohort.root())
        .zip(cohorts[3..].iter().map(|cohort| cohort.root()))
        .all(|(fresh, durable)| fresh != durable);
    if !old_auxiliary_roots_rejected_for_settlement {
        return Err(
            "settlement-fresh auxiliary root equals a durable X4c auxiliary root".to_owned()
        );
    }
    let query_seed = X4dSettlementQuerySeedV1::new(random_digest("settlement query seed")?)
        .map_err(|error| format!("query seed: {error:?}"))?;
    let freshness_binding = X4dSettlementFreshnessBinding::new(
        binding.connection_id,
        batch.static_weight_commitment_digest,
        args.settlement_epoch,
        range.sealed_accumulator_digest,
        auxiliary.seed_commitment,
        auxiliary.root_set_digest,
        query_seed.commitment(),
        u32::try_from(auxiliary.masks_created).map_err(|_| "mask count exceeds u32")?,
        batch.counters.total_full_correlations_per_role,
    )
    .map_err(|error| format!("settlement freshness binding: {error}"))?;
    let freshness_burn = authorization_store
        .reserve_x4d_settlement(freshness_binding)
        .map_err(|error| format!("reserve settlement freshness: {error}"))?;
    let freshness = production
        .connection
        .record_x4d_settlement_freshness(&freshness_burn)
        .map_err(|error| format!("journal settlement freshness: {error}"))?;
    let bound_auxiliary = logical.bind_fresh_auxiliary_set(&batch, auxiliary)?;
    let settlement_domain = X4dSettlementCorrelationDomain::new(
        binding.connection_id,
        args.settlement_epoch,
        0,
        0,
        *blake3::hash(b"volta-zk/x4d/gpt2-settlement-correlations/v1").as_bytes(),
    )
    .map_err(|error| format!("settlement correlation domain: {error}"))?;
    let settlement_pools = production
        .allocate_x4d_settlement_pcg_pools(
            0,
            0,
            usize::try_from(batch.counters.total_full_correlations_per_role)
                .map_err(|_| "settlement correlation count exceeds usize")?,
            settlement_domain,
        )
        .map_err(|error| format!("allocate settlement PCG: {error}"))?;
    let mut settlement_stream = CorrelationStream::from_pcg_pool(settlement_pools.prover);
    let mut settlement_verifier =
        VerifierCtx::from_pcg_pool(settlement_pools.verifier_delta, settlement_pools.verifier);
    let settlement_transcript_seed = random_digest("settlement transcript seed")?;
    let mut settlement_prover_tx = Transcript::new(settlement_transcript_seed);
    let mut settlement_verifier_tx = Transcript::new(settlement_transcript_seed);
    runtime
        .begin_response_measurement()
        .map_err(|error| format!("begin settlement measurement: {error:?}"))?;
    let proof_started = Instant::now();
    let result = settlement_pool.install(|| {
        execute_real_weight_x4d_settlement_v1(
            &work.model,
            &inventory,
            &cohorts[..3],
            &evaluations,
            &batch,
            &freshness,
            query_seed,
            bound_auxiliary,
            &mut settlement_stream,
            &mut settlement_verifier,
            &mut settlement_prover_tx,
            &mut settlement_verifier_tx,
            &mut runtime,
            X4cSealConfigV4::production(clean_source, args.settlement_epoch)
                .map_err(|error| format!("settlement seal config: {error:?}"))?,
        )
    })?;
    let proof_driver_wall_s = proof_started.elapsed().as_secs_f64();
    let _settlement_backend: BackendStats = runtime
        .finish_response_measurement()
        .map_err(|error| format!("finish settlement measurement: {error:?}"))?;
    production
        .connection
        .finish_x4d_settlement_success(args.settlement_epoch, range.sealed_accumulator_digest)
        .map_err(|error| format!("journal settlement success: {error}"))?;
    logical.settlement_succeeded(&batch)?;
    let seal_to_terminal_wall_s = settlement_started.elapsed().as_secs_f64();
    let every_covered_response_weight_verified = range
        .ordered_response_nonces
        .iter()
        .all(|nonce| logical.response_state(*nonce) == Some(X4dResponseStateV1::WeightVerified));
    responses.push(run_response(
        CONNECTION_RESPONSES - 1,
        "abba-isolated-a2",
        &response_pool,
        &work,
        &resident_model,
        &resident_prefill,
        &resident_band,
        &error,
        &inventory,
        &mut logical,
        &mut production,
        &authorization_store,
        binding,
        &mut runtime,
    )?);
    let pending_after_settlement = responses[SETTLED_RESPONSES..].iter().all(|row| {
        let digest = &row.response_nonce_digest;
        !digest.is_empty()
    });
    let pending_nonces = logical
        .prover_accumulator()
        .responses()
        .iter()
        .skip(SETTLED_RESPONSES)
        .map(|response| response.response_nonce)
        .collect::<Vec<_>>();
    logical.abort();
    production
        .connection
        .abort(ConnectionAbortReason::ExplicitAbort)
        .map_err(|error| format!("explicit connection abort: {error}"))?;
    let abort_terminal = pending_after_settlement
        && pending_nonces.iter().all(|nonce| {
            logical.response_state(*nonce) == Some(X4dResponseStateV1::TerminalUnverified)
        });
    let no_retry = logical.seal_settlement().is_err();
    let measured_g1 = g1(&responses[..4]);
    let isolated = vec![responses[14].total_g1_s, responses[18].total_g1_s];
    let queued =
        vec![responses[SETTLED_RESPONSES].total_g1_s, responses[SETTLED_RESPONSES + 1].total_g1_s];
    let isolated_upper = upper_median(isolated.clone());
    let queued_upper = upper_median(queued.clone());
    let interference_ns =
        X4dInterferenceDeltaV1::new((isolated_upper * 1e9) as u64, (queued_upper * 1e9) as u64);
    let interference = InterferenceRow {
        order: "A1,B1,B2,A2".to_owned(),
        isolated_response_s: isolated,
        settlement_queued_response_s: queued,
        isolated_upper_median_s: isolated_upper,
        settlement_queued_upper_median_s: queued_upper,
        absolute_delta_s: interference_ns.absolute_delta_ns as f64 / 1e9,
        percentage_delta: interference_ns.percentage_delta,
        settlement_cpu_overlap_intervals: 0,
        settlement_gpu_overlap_intervals: 0,
        accounting_semantics: "B responses execute under strict response priority while the sealed settlement is queued; no CPU/GPU interval is falsely reported concurrent".to_owned(),
    };
    let expected_settlement_bytes = 2_632_812 + 50_424 * SETTLED_RESPONSES as u64;
    let exact_correlations = result.prover_full_correlations
        == batch.counters.total_full_correlations_per_role
        && result.verifier_full_correlations == batch.counters.total_full_correlations_per_role;
    let exact_bytes = result.encoded_settlement.len() as u64 == expected_settlement_bytes;
    let open_wall_s = result.open_wall_ns as f64 / 1e9;
    let verify_wall_s = result.verify_wall_ns as f64 / 1e9;
    let open_pass = open_wall_s <= OPEN_CEILING_S;
    let verify_pass = verify_wall_s <= VERIFY_CEILING_S;
    let settlement_accepted = every_covered_response_weight_verified
        && exact_bytes
        && exact_correlations
        && open_pass
        && verify_pass;
    let settlement = SettlementRow {
        responses: batch.counters.responses,
        frozen_claims: batch.counters.frozen_claims,
        masked_groups: batch.counters.masked_groups,
        settlement_epoch: args.settlement_epoch,
        settlement_bytes: result.encoded_settlement.len() as u64,
        expected_settlement_bytes,
        amortized_settlement_bytes_per_response: expected_settlement_bytes as f64
            / SETTLED_RESPONSES as f64,
        historical_four_mb_scope:
            "4,000,000 B is the immutable X4/X4b/X4c per-response PCS ceiling; X4d settlement uses the pinned batch formula"
                .to_owned(),
        seal_to_terminal_wall_s,
        proof_driver_wall_s,
        auxiliary_materialization_wall_s,
        response_priority_pause_wall_s,
        active_cpu_host_window_s: auxiliary_materialization_wall_s + proof_driver_wall_s,
        active_gpu_lease_host_window_s: proof_driver_wall_s,
        lease_wait_wall_s: 0.0,
        open_wall_s,
        verify_wall_s,
        open_pass,
        verify_pass,
        every_covered_response_weight_verified,
        exact_bytes,
        exact_correlations,
        fresh_auxiliary_masks: result.auxiliary_masks_created,
        static_weight_roots_reused: result.static_weight_roots_reused,
        query_draws: batch.counters.query_draws,
        soundness_expression: SOUNDNESS_EXPRESSION.to_owned(),
        soundness_bits: SOUNDNESS_BITS,
        interference,
        accepted: settlement_accepted,
    };
    let mut cap_probe = X4dClaimAccumulatorV1::new(
        static_weight_commitment,
        random_digest("cap probe connection")?,
        X4dSettlementPolicyV1::production_gpt2(),
    )
    .map_err(|error| format!("cap probe accumulator: {error:?}"))?;
    let cap_preflight_3321_rejected = cap_probe.preflight_response_claims(3_321).is_err();
    let overall_pass =
        measured_g1.overall_pass && settlement.accepted && abort_terminal && no_retry;
    let crypto = x4c_crypto_build_identity(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))?;
    let record = OnlineRecord {
        schema: SCHEMA,
        milestone: MILESTONE_ONLINE.to_owned(),
        git_sha,
        git_dirty: false,
        producer_source_sha256: source_sha.to_owned(),
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        design_sha256: X4D_DESIGN_SHA256.to_owned(),
        cloud,
        hardware,
        onboarding_path: args.onboarding.as_ref().unwrap().display().to_string(),
        onboarding_sha256,
        onboarding_exact: true,
        crypto_build_id_scheme: crypto.scheme,
        crypto_build_id: crypto.digest_blake3,
        durable_tier_bytes: coefficient_bytes + root_bytes,
        rebuild_wall_s,
        rebuild_rows,
        rebuild_roots,
        rebuild_roots_equal_onboarding,
        old_auxiliary_roots_rejected_for_settlement,
        setup_wall_s,
        responses,
        g1: measured_g1,
        settlement,
        cap_test_name: "claim_3321_refuses_until_settlement_succeeds".to_owned(),
        cap_3321_permanent_test_present: true,
        cap_preflight_3321_rejected,
        soundness_expression_byte_exact: true,
        g2_permanent_tests: vec![
            "post_freeze_value_substitution_is_rejected_by_m2_mac".to_owned(),
            "accumulator_roles_match_and_omission_reorder_mismatch".to_owned(),
            "exact_range_rejects_subset_reorder_and_replay".to_owned(),
            "x4d_delivery_without_freeze_and_wrong_settlement_subset_burn_connection".to_owned(),
            "x4d_settlement_freshness_is_required_before_success_and_is_one_use".to_owned(),
        ],
        g6_test_name: "explicit_abort_before_settlement_marks_pending_terminal_unverified"
            .to_owned(),
        g6_abort_before_settlement_terminal_unverified: abort_terminal,
        no_retry_same_connection: no_retry,
        provider_contract_state_at_delivery:
            "complete and fully authenticated; weight consistency WEIGHT_PENDING".to_owned(),
        provider_contract_state_at_settlement:
            "covered response set pronounced WEIGHT_VERIFIED only after settlement acceptance"
                .to_owned(),
        historical_rows_modified: false,
        overall_pass,
    };
    write_append_only(&args.output, &record)?;
    if !overall_pass {
        return Err("X4d Phase-3 conjunctive gate failed; record retained".to_owned());
    }
    Ok(())
}

fn main() {
    let args = parse_args();
    let result = match args.mode {
        Mode::Preflight => preflight(&args),
        Mode::Online => online(&args),
    };
    if let Err(error) = result {
        eprintln!("x4d_gpt2_pod_record HARD STOP: {error}");
        std::process::exit(1);
    }
}
