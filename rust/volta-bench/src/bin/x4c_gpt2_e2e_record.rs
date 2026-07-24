//! Real-weight GPT-2-small T=100+50 driver for the qualified X4c path.
//!
//! The two run-of-record modes are intentionally separate:
//!
//! * `--mode onboard` derives the actual descriptor/domain inventory from a
//!   mock-PCG model-proof prepass, materializes real-weight coefficients, and
//!   writes only five coefficient files plus five roots to PERSISTENT.
//! * `--mode online` verifies that exact onboarding chain, performs a
//!   fresh-process parallel rebuild, then runs one warm-up plus three
//!   real-PCG/CUDA/X4c candidates.
//!
//! Local CI uses `--mode preflight`; no pod is contacted by this binary.

use rand::{rngs::OsRng, RngCore};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_accel::{
    Backend, BackendStats, CudaStreamState, DeviceSlice, Operation, ResidentTimingPolicy,
};
use volta_bench::x4c_gpt2::{
    execute_real_weight_x4c, mask_seed_commitment, materialize_real_weight_cohorts,
    rebuild_evaluation_tables, X4cGpt2CohortMaterial, X4cGpt2Inventory,
    X4C_GPT2_DURABLE_COEFFICIENT_BYTES, X4C_GPT2_DURABLE_TIER_BYTES, X4C_GPT2_FULL_CORRELATIONS,
    X4C_GPT2_HOST_ORACLE_BYTES, X4C_GPT2_HOST_OUTER_CACHE_BYTES, X4C_GPT2_PCS_BYTES,
    X4C_GPT2_RESPONSE_BYTES,
};
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    argmax, band_model_witness, band_model_witness_resident, decode_step, forward_model,
    forward_model_tokens, forward_model_tokens_resident, load_model, upload_resident_model,
    BandModelWitness, Gpt2Model, KvCache, VOCAB,
};
use volta_mac::{zero_batch_exchange, CorrelationStream, Transcript, VerifierCtx};
use volta_pcg::{
    open_fase_d_connection_with_ggm_prg, ConnectionBinding, ConnectionStore, CorrelationDomain,
    FaseDParams, FaseDStagePlan, GgmPrg, ResponseAuthorizationStore, X4ResponseFreshnessBinding,
};
use volta_pcs::x4::{
    commit_cohort_cuda_v4, read_persisted_coefficients_v4, validate_x4c_frozen_surface_v4,
    GlobalOpenMetricsV4, OuterCachePolicyV4, X4bCudaCohortPathsV4, X4bCudaCommitMetricsV4,
    X4cArenaCensusV4, X4cCudaArenaRuntimeV4, X4cLifecycleWallsV4, X4cRamModelGlobalCohortV4,
    X4cResponseExecutionCountersV4, X4cResponseIoCountersV4, X4cResponseMetricsV4, X4cSealConfigV4,
    X4cSelectedQueryTapeV4,
};
use volta_proto::logup::Doms;
use volta_proto::model_proof::{
    prove_response_private_logits, prove_response_resident_private_logits,
    verify_response_private_logits, ChunkRef, PrivateChunkPub, ResidentChunkRef,
};
use volta_proto::{layer_dom_base, prod_batch_prover, prod_batch_verify, ModelOut, ModelOutV};

const SCHEMA: u64 = 2;
const PROFILE: &str = "runpod-a100-x4c-v1";
const PROTOCOL: &str = "x4-zkdeepfold-ud-e29-v4";
const SELECTED_TAPE_DIGEST: &str =
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299";
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const GOLDEN_P5_SHA256: &str = "4ac774f208a414bf7fb591a29bd455968ce2d89846255fe8239eabd9b5c92f45";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";
const SAFETENSORS_SHA256: &str = "248dfc3911869ec493c76e65bf2fcf7f615828b0254c12b473182f0f81d3a707";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Preflight,
    Onboard,
    Online,
}

struct Args {
    mode: Mode,
    weights: PathBuf,
    durable_root: Option<PathBuf>,
    scratch_root: Option<PathBuf>,
    onboarding: Option<PathBuf>,
    onboarding_sha256: Option<String>,
    output: Option<PathBuf>,
    authorization_store: Option<PathBuf>,
    connection_store: Option<PathBuf>,
    clean_source_sha256: Option<String>,
    epoch_base: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage: x4c_gpt2_e2e_record --mode preflight|onboard|online \
         --weights PATH [--durable-root PATH --scratch-root PATH --output PATH] \
         [--onboarding PATH --onboarding-sha256 HEX --authorization-store PATH --connection-store PATH \
          --clean-source-sha256 HEX --epoch-base N]"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut mode = None;
    let mut weights = None;
    let mut durable_root = None;
    let mut scratch_root = None;
    let mut onboarding = None;
    let mut onboarding_sha256 = None;
    let mut output = None;
    let mut authorization_store = None;
    let mut connection_store = None;
    let mut clean_source_sha256 = None;
    let mut epoch_base = 1u64;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match argument.as_str() {
            "--mode" => {
                mode = Some(match value().as_str() {
                    "preflight" => Mode::Preflight,
                    "onboard" => Mode::Onboard,
                    "online" => Mode::Online,
                    _ => usage(),
                })
            }
            "--weights" => weights = Some(PathBuf::from(value())),
            "--durable-root" => durable_root = Some(PathBuf::from(value())),
            "--scratch-root" => scratch_root = Some(PathBuf::from(value())),
            "--onboarding" => onboarding = Some(PathBuf::from(value())),
            "--onboarding-sha256" => onboarding_sha256 = Some(value()),
            "--output" => output = Some(PathBuf::from(value())),
            "--authorization-store" => authorization_store = Some(PathBuf::from(value())),
            "--connection-store" => connection_store = Some(PathBuf::from(value())),
            "--clean-source-sha256" => clean_source_sha256 = Some(value()),
            "--epoch-base" => epoch_base = value().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    Args {
        mode: mode.unwrap_or_else(|| usage()),
        weights: weights.unwrap_or_else(|| usage()),
        durable_root,
        scratch_root,
        onboarding,
        onboarding_sha256,
        output,
        authorization_store,
        connection_store,
        clean_source_sha256,
        epoch_base,
    }
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("expected a 64-digit digest".to_owned());
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .map_err(|_| "digest is not hexadecimal".to_owned())?;
    }
    Ok(digest)
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn upper_median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
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
        .and_then(|_| file.sync_data())
        .map_err(|error| format!("persist record {}: {error}", path.display()))
}

struct Workload {
    model: Gpt2Model,
    prefill: volta_gpt2::ModelWitness,
    band: BandModelWitness,
    sequence: Vec<u32>,
    golden_match: bool,
}

fn workload(weights: &Path) -> Result<Workload, String> {
    verify_inputs(weights)?;
    let model = load_model(weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout()?;
    let prefill = forward_model(&model, 100);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, 100);
    let mut generated = Vec::with_capacity(50);
    let mut next = argmax(&prefill.logits);
    for position in 0..50 {
        generated.push(next);
        next = argmax(&decode_step(&model, &mut cache, next, 100 + position));
    }
    let golden = fs::read(weights.join("golden-p6.bin"))
        .map_err(|error| format!("read golden-p6.bin: {error}"))?;
    if golden.len() != 16 + 4 * 50 || &golden[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6.bin has wrong canonical geometry".to_owned());
    }
    let golden_tokens = (0..50)
        .map(|index| u32::from_le_bytes(golden[16 + 4 * index..20 + 4 * index].try_into().unwrap()))
        .collect::<Vec<_>>();
    let golden_match = generated == golden_tokens;
    if !golden_match {
        return Err("real GPT-2 greedy decode differs from golden-p6".to_owned());
    }
    let mut sequence = model.p.tokens[..100].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let band = band_model_witness(&model, &full, 100);
    Ok(Workload { model, prefill, band, sequence, golden_match })
}

fn mock_model_outputs(workload: &Workload) -> Result<(ModelOut, ModelOutV, u64, u64), String> {
    let chunks = [ChunkRef { band: &workload.band, seq: &workload.sequence }];
    let mut stream = CorrelationStream::new([0x42; 32]);
    let mut prover_tx = Transcript::new([0x18; 32]);
    let (proof, output, _, _) = prove_response_private_logits(
        &workload.model,
        &workload.prefill,
        &chunks,
        &mut stream,
        &mut prover_tx,
    );
    let mut verifier =
        VerifierCtx::new([0x42; 32], Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE)));
    let mut verifier_tx = Transcript::new([0x18; 32]);
    let public = [PrivateChunkPub { q: workload.band.q, seq: &workload.sequence }];
    let (verified, _, _) = verify_response_private_logits(
        &workload.model,
        workload.prefill.t,
        &public,
        &proof,
        &mut verifier,
        &mut verifier_tx,
    )
    .ok_or_else(|| "mock model proof failed verification".to_owned())?;
    if prover_tx.total_bytes() != verifier_tx.total_bytes() {
        return Err("mock model transcript differs across roles".to_owned());
    }
    Ok((output, verified, stream.counters.sub_corrs, stream.counters.full_corrs))
}

fn selected_tape() -> Result<X4cSelectedQueryTapeV4, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../benchmarks/results/x4-amendment5-gpt2-preflight-2026-07-21-93749b3.json");
    let value: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("read selected tape: {error}"))?,
    )
    .map_err(|error| format!("parse selected tape: {error}"))?;
    let candidate = value["candidates"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == "e29-r3-s111"))
        .ok_or_else(|| "selected X4c candidate missing".to_owned())?;
    if candidate["challenge"]["ordered_draws_blake3"] != SELECTED_TAPE_DIGEST {
        return Err("selected query tape digest changed".to_owned());
    }
    let draws = candidate["challenge"]["ordered_draws"]
        .as_array()
        .ok_or_else(|| "selected query tape missing".to_owned())?
        .iter()
        .map(|value| value.as_u64().ok_or_else(|| "invalid selected draw".to_owned()))
        .collect::<Result<Vec<_>, _>>()?;
    X4cSelectedQueryTapeV4::new(draws).map_err(|error| format!("selected query tape: {error:?}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableRow {
    cohort_id: u32,
    coefficient_bytes: u64,
    coefficient_sha256: String,
    root_bytes: u64,
    root_hex: String,
    root_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DurableTierCensusRow {
    cohort_directory_count: u64,
    cohort_ids: Vec<u32>,
    coefficient_file_count: u64,
    root_file_count: u64,
    oracle_file_count: u64,
    other_file_count: u64,
    other_directory_count: u64,
    symlink_count: u64,
    total_regular_file_bytes: u64,
    unexpected_paths: Vec<String>,
    exact: bool,
}

fn durable_tier_census(
    durable_root: &Path,
    expected_ids: &[u32],
) -> Result<DurableTierCensusRow, String> {
    let expected = expected_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut cohort_ids = Vec::new();
    let mut coefficient_file_count = 0u64;
    let mut root_file_count = 0u64;
    let mut oracle_file_count = 0u64;
    let mut other_file_count = 0u64;
    let mut other_directory_count = 0u64;
    let mut symlink_count = 0u64;
    let mut total_regular_file_bytes = 0u64;
    let mut unexpected_paths = Vec::new();
    for entry in
        fs::read_dir(durable_root).map_err(|error| format!("census durable tier: {error}"))?
    {
        let entry = entry.map_err(|error| format!("read durable entry: {error}"))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|error| format!("stat durable entry: {error}"))?;
        if kind.is_symlink() {
            symlink_count += 1;
            unexpected_paths.push(path.display().to_string());
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let cohort_id = name
            .strip_prefix("cohort-")
            .filter(|suffix| suffix.len() == 8)
            .and_then(|suffix| u32::from_str_radix(suffix, 16).ok());
        if !kind.is_dir() || cohort_id.is_none() {
            if kind.is_dir() {
                other_directory_count += 1;
            } else if kind.is_file() {
                other_file_count += 1;
                total_regular_file_bytes +=
                    entry.metadata().map_err(|error| format!("stat durable file: {error}"))?.len();
            }
            unexpected_paths.push(path.display().to_string());
            continue;
        }
        let cohort_id = cohort_id.expect("checked cohort ID");
        cohort_ids.push(cohort_id);
        if !expected.contains(&cohort_id) {
            unexpected_paths.push(path.display().to_string());
        }
        for child in fs::read_dir(&path)
            .map_err(|error| format!("census durable cohort {}: {error}", path.display()))?
        {
            let child = child.map_err(|error| format!("read durable cohort entry: {error}"))?;
            let child_path = child.path();
            let child_kind =
                child.file_type().map_err(|error| format!("stat durable cohort entry: {error}"))?;
            if child_kind.is_symlink() {
                symlink_count += 1;
                unexpected_paths.push(child_path.display().to_string());
                continue;
            }
            if child_kind.is_dir() {
                other_directory_count += 1;
                unexpected_paths.push(child_path.display().to_string());
                continue;
            }
            if !child_kind.is_file() {
                other_file_count += 1;
                unexpected_paths.push(child_path.display().to_string());
                continue;
            }
            let bytes =
                child.metadata().map_err(|error| format!("stat durable child: {error}"))?.len();
            total_regular_file_bytes = total_regular_file_bytes
                .checked_add(bytes)
                .ok_or_else(|| "durable byte census overflow".to_owned())?;
            match child.file_name().to_string_lossy().as_ref() {
                "coefficients.bin" => coefficient_file_count += 1,
                "root.bin" => root_file_count += 1,
                "oracle.bin" => {
                    oracle_file_count += 1;
                    unexpected_paths.push(child_path.display().to_string());
                }
                _ => {
                    other_file_count += 1;
                    unexpected_paths.push(child_path.display().to_string());
                }
            }
        }
    }
    cohort_ids.sort_unstable();
    unexpected_paths.sort();
    let mut expected_sorted = expected_ids.to_vec();
    expected_sorted.sort_unstable();
    let exact = cohort_ids == expected_sorted
        && cohort_ids.len() == 5
        && coefficient_file_count == 5
        && root_file_count == 5
        && oracle_file_count == 0
        && other_file_count == 0
        && other_directory_count == 0
        && symlink_count == 0
        && total_regular_file_bytes == X4C_GPT2_DURABLE_TIER_BYTES
        && unexpected_paths.is_empty();
    Ok(DurableTierCensusRow {
        cohort_directory_count: cohort_ids.len() as u64,
        cohort_ids,
        coefficient_file_count,
        root_file_count,
        oracle_file_count,
        other_file_count,
        other_directory_count,
        symlink_count,
        total_regular_file_bytes,
        unexpected_paths,
        exact,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnboardingPassRow {
    role: String,
    measured: bool,
    wall_s: f64,
    io: IoSnapshot,
    backend: BackendRow,
    roots: Vec<String>,
    coefficient_bytes: u64,
    oracle_bytes: u64,
    root_bytes: u64,
    retained_durable: bool,
    cleanup_complete: bool,
    accepted: bool,
}

#[derive(Serialize, Deserialize)]
struct OnboardingRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    protocol: String,
    input_bin_sha256: String,
    input_json_sha256: String,
    input_params_sha256: String,
    golden_p5_sha256: String,
    golden_p6_sha256: String,
    model_safetensors_sha256: String,
    model_config_digest: String,
    weights_digest: String,
    parent_domains: Vec<[u64; 2]>,
    descriptor_digests: Vec<String>,
    mask_seed_commitment_blake3: String,
    warmup: OnboardingPassRow,
    measured: Vec<OnboardingPassRow>,
    selected_upper_median_wall_s: f64,
    warmup_root_set: Vec<String>,
    measured_root_sets: Vec<Vec<String>>,
    durable: Vec<DurableRow>,
    durable_census: DurableTierCensusRow,
    durable_bytes: u64,
    durable_tier_exact: bool,
    roots_identical: bool,
    golden_match: bool,
    overall_pass: bool,
}

fn paths(root: &Path, scratch: &Path, cohort_id: u32) -> Result<X4bCudaCohortPathsV4, String> {
    let durable = root.join(format!("cohort-{cohort_id:08x}"));
    let temporary = scratch.join(format!("cohort-{cohort_id:08x}"));
    fs::create_dir(&durable).map_err(|error| format!("create durable cohort: {error}"))?;
    fs::create_dir(&temporary).map_err(|error| format!("create scratch cohort: {error}"))?;
    Ok(X4bCudaCohortPathsV4 {
        coefficients: durable.join("coefficients.bin"),
        oracle: temporary.join("oracle.bin"),
        root: durable.join("root.bin"),
        staging_directory: temporary.join("staging"),
    })
}

fn commit_pass(
    role: &str,
    measured: bool,
    backend: &mut Backend,
    materials: &[X4cGpt2CohortMaterial],
    durable: &Path,
    scratch: &Path,
    retain: bool,
) -> Result<OnboardingPassRow, String> {
    fs::create_dir(durable).map_err(|error| format!("create pass durable: {error}"))?;
    fs::create_dir(scratch).map_err(|error| format!("create pass scratch: {error}"))?;
    let before_io = IoObservation::current()?;
    backend
        .begin_measurement()
        .map_err(|error| format!("begin onboarding measurement: {error}"))?;
    let started = Instant::now();
    let mut roots = Vec::new();
    let mut artifact_paths = Vec::new();
    let mut totals = X4bCudaCommitMetricsV4::default();
    for material in materials {
        let artifact = commit_cohort_cuda_v4(
            backend,
            material.config.clone(),
            &material.coefficients,
            paths(durable, scratch, material.config.identity.cohort_id)?,
            OuterCachePolicyV4::FULL,
        )
        .map_err(|error| format!("commit real-weight cohort: {error:?}"))?;
        totals
            .include(&artifact.metrics)
            .map_err(|error| format!("sum onboarding commit metrics: {error:?}"))?;
        roots.push(hex(&artifact.commitment.root));
        artifact_paths.push(artifact.paths.clone());
        drop(artifact);
    }
    for artifact in artifact_paths {
        fs::remove_file(&artifact.oracle)
            .map_err(|error| format!("remove response oracle: {error}"))?;
        fs::remove_dir(&artifact.staging_directory)
            .map_err(|error| format!("remove staging directory: {error}"))?;
        fs::remove_dir(artifact.oracle.parent().unwrap())
            .map_err(|error| format!("remove cohort scratch: {error}"))?;
        if !retain {
            fs::remove_file(&artifact.coefficients)
                .map_err(|error| format!("remove temporary coefficients: {error}"))?;
            fs::remove_file(&artifact.root)
                .map_err(|error| format!("remove temporary root: {error}"))?;
            fs::remove_dir(artifact.coefficients.parent().unwrap())
                .map_err(|error| format!("remove temporary durable cohort: {error}"))?;
        }
    }
    fs::remove_dir(scratch).map_err(|error| format!("remove pass scratch: {error}"))?;
    if !retain {
        fs::remove_dir(durable).map_err(|error| format!("remove pass durable: {error}"))?;
    }
    let wall_s = started.elapsed().as_secs_f64();
    let stats = backend
        .finish_measurement()
        .map_err(|error| format!("finish onboarding measurement: {error}"))?;
    let io = IoObservation::current()?.delta(&before_io)?;
    let accepted = roots.len() == 5
        && totals.coefficient_bytes_persisted == X4C_GPT2_DURABLE_COEFFICIENT_BYTES
        && totals.oracle_bytes_persisted
            == X4C_GPT2_DURABLE_COEFFICIENT_BYTES
                .checked_mul(8)
                .ok_or_else(|| "onboarding oracle byte count overflow".to_owned())?
        && totals.root_bytes_persisted == 5 * 32
        && stats.h2d_bytes == totals.expected_h2d_bytes
        && stats.d2h_bytes == totals.expected_d2h_bytes
        && stats.timing_event_api_calls == 0;
    Ok(OnboardingPassRow {
        role: role.to_owned(),
        measured,
        wall_s,
        io,
        backend: stats.into(),
        roots,
        coefficient_bytes: totals.coefficient_bytes_persisted,
        oracle_bytes: totals.oracle_bytes_persisted,
        root_bytes: totals.root_bytes_persisted,
        retained_durable: retain,
        cleanup_complete: true,
        accepted,
    })
}

fn onboard(args: &Args) -> Result<(), String> {
    let output = args.output.as_ref().ok_or_else(|| "onboard requires --output".to_owned())?;
    let durable =
        args.durable_root.as_ref().ok_or_else(|| "onboard requires --durable-root".to_owned())?;
    let scratch =
        args.scratch_root.as_ref().ok_or_else(|| "onboard requires --scratch-root".to_owned())?;
    if durable.exists() || scratch.exists() || output.exists() {
        return Err("onboarding paths must be fresh".to_owned());
    }
    let git_sha = git_sha_clean()?;
    let workload = workload(&args.weights)?;
    let (mock, _, _, _) = mock_model_outputs(&workload)?;
    let parent_domains = X4cGpt2Inventory::parent_domains_from_output(&mock)?;
    let inventory = X4cGpt2Inventory::new(
        parse_hex_32(GPT2_JSON_SHA256)?,
        parse_hex_32(GPT2_BIN_SHA256)?,
        &parent_domains,
    )?;
    let mut seed = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|error| format!("OS randomness for X4c masks: {error}"))?;
    let materials = materialize_real_weight_cohorts(&workload.model, &inventory, seed)?;
    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize CUDA onboarding backend: {error}"))?;
    let temporary = scratch.join("temporary");
    fs::create_dir(scratch).map_err(|error| format!("create onboarding scratch: {error}"))?;
    fs::create_dir(&temporary).map_err(|error| format!("create temporary root: {error}"))?;
    let warmup = commit_pass(
        "warmup",
        false,
        &mut backend,
        &materials,
        &temporary.join("warmup-durable"),
        &temporary.join("warmup-scratch"),
        false,
    )?;
    let mut measured = Vec::new();
    for ordinal in 1..=3 {
        let retain = ordinal == 3;
        let measured_durable = temporary.join(format!("m{ordinal}-durable"));
        let measured_scratch = temporary.join(format!("m{ordinal}-scratch"));
        measured.push(commit_pass(
            &format!("measured-{ordinal}"),
            true,
            &mut backend,
            &materials,
            if retain { durable } else { &measured_durable },
            &measured_scratch,
            retain,
        )?);
    }
    fs::remove_dir(&temporary).map_err(|error| format!("remove temporary root: {error}"))?;
    fs::remove_dir(scratch).map_err(|error| format!("remove onboarding scratch: {error}"))?;
    let roots_identical = measured.iter().all(|pass| pass.roots == warmup.roots);
    let mut durable_rows = Vec::new();
    for (material, root_hex) in materials.iter().zip(&warmup.roots) {
        let root = durable.join(format!("cohort-{:08x}", material.config.identity.cohort_id));
        let coefficient = root.join("coefficients.bin");
        let root_file = root.join("root.bin");
        durable_rows.push(DurableRow {
            cohort_id: material.config.identity.cohort_id,
            coefficient_bytes: fs::metadata(&coefficient)
                .map_err(|error| format!("stat coefficients: {error}"))?
                .len(),
            coefficient_sha256: sha256(&coefficient)?,
            root_bytes: fs::metadata(&root_file)
                .map_err(|error| format!("stat root: {error}"))?
                .len(),
            root_hex: root_hex.clone(),
            root_sha256: sha256(&root_file)?,
        });
    }
    let durable_bytes =
        durable_rows.iter().map(|row| row.coefficient_bytes + row.root_bytes).sum::<u64>();
    let expected_ids =
        materials.iter().map(|material| material.config.identity.cohort_id).collect::<Vec<_>>();
    let durable_census = durable_tier_census(durable, &expected_ids)?;
    let durable_tier_exact = durable_rows.len() == 5
        && durable_bytes == X4C_GPT2_DURABLE_TIER_BYTES
        && durable_rows.iter().map(|row| row.coefficient_bytes).sum::<u64>()
            == X4C_GPT2_DURABLE_COEFFICIENT_BYTES
        && durable_census.exact;
    let selected_upper_median_wall_s =
        upper_median(measured.iter().map(|pass| pass.wall_s).collect());
    let overall_pass = workload.golden_match
        && warmup.accepted
        && measured.iter().all(|pass| pass.accepted)
        && roots_identical
        && durable_tier_exact;
    let warmup_root_set = warmup.roots.clone();
    let measured_root_sets = measured.iter().map(|pass| pass.roots.clone()).collect();
    let record = OnboardingRecord {
        schema: SCHEMA,
        milestone: "X4c-GPT2-real-weight-onboarding".to_owned(),
        git_sha,
        git_dirty: false,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        input_bin_sha256: GPT2_BIN_SHA256.to_owned(),
        input_json_sha256: GPT2_JSON_SHA256.to_owned(),
        input_params_sha256: GPT2_PARAMS_SHA256.to_owned(),
        golden_p5_sha256: GOLDEN_P5_SHA256.to_owned(),
        golden_p6_sha256: GOLDEN_P6_SHA256.to_owned(),
        model_safetensors_sha256: SAFETENSORS_SHA256.to_owned(),
        model_config_digest: GPT2_JSON_SHA256.to_owned(),
        weights_digest: GPT2_BIN_SHA256.to_owned(),
        parent_domains,
        descriptor_digests: inventory
            .blocks
            .iter()
            .map(|block| hex(&block.descriptor_digest))
            .collect(),
        mask_seed_commitment_blake3: hex(&mask_seed_commitment(seed)),
        warmup,
        measured,
        selected_upper_median_wall_s,
        warmup_root_set,
        measured_root_sets,
        durable: durable_rows,
        durable_census,
        durable_bytes,
        durable_tier_exact,
        roots_identical,
        golden_match: workload.golden_match,
        overall_pass,
    };
    write_append_only(output, &record)?;
    if !overall_pass {
        return Err("real-weight onboarding hard gate failed".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct IoObservation {
    counters: IoSnapshot,
    observer_rchar_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct IoSnapshot {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: u64,
    observer_rchar_bytes: u64,
    unexpected_rchar_bytes: u64,
    unexpected_wchar_bytes: u64,
    unexpected_read_bytes: u64,
    unexpected_write_bytes: u64,
    response_window_exact: bool,
}

impl IoObservation {
    fn current() -> Result<Self, String> {
        let text = fs::read_to_string("/proc/self/io")
            .map_err(|error| format!("read proc I/O: {error}"))?;
        let read = |name: &str| -> Result<u64, String> {
            text.lines()
                .find_map(|line| line.strip_prefix(name))
                .ok_or_else(|| format!("required /proc/self/io field {name:?} missing"))?
                .trim()
                .parse::<u64>()
                .map_err(|error| format!("invalid /proc/self/io field {name:?}: {error}"))
        };
        Ok(Self {
            counters: IoSnapshot {
                rchar: read("rchar:")?,
                wchar: read("wchar:")?,
                syscr: read("syscr:")?,
                syscw: read("syscw:")?,
                read_bytes: read("read_bytes:")?,
                write_bytes: read("write_bytes:")?,
                cancelled_write_bytes: read("cancelled_write_bytes:")?,
                ..IoSnapshot::default()
            },
            observer_rchar_bytes: text.len() as u64,
        })
    }

    fn delta(&self, before: &Self) -> Result<IoSnapshot, String> {
        let subtract = |after: u64, prior: u64, field: &str| {
            after.checked_sub(prior).ok_or_else(|| {
                format!("/proc/self/io counter {field} moved backwards during response")
            })
        };
        let rchar = subtract(self.counters.rchar, before.counters.rchar, "rchar")?;
        let wchar = subtract(self.counters.wchar, before.counters.wchar, "wchar")?;
        let read_bytes =
            subtract(self.counters.read_bytes, before.counters.read_bytes, "read_bytes")?;
        let write_bytes =
            subtract(self.counters.write_bytes, before.counters.write_bytes, "write_bytes")?;
        let cancelled_write_bytes = subtract(
            self.counters.cancelled_write_bytes,
            before.counters.cancelled_write_bytes,
            "cancelled_write_bytes",
        )?;
        let unexpected_rchar_bytes = rchar
            .checked_sub(before.observer_rchar_bytes)
            .ok_or_else(|| "response I/O observer was not reflected in rchar".to_owned())?;
        Ok(IoSnapshot {
            rchar,
            wchar,
            syscr: subtract(self.counters.syscr, before.counters.syscr, "syscr")?,
            syscw: subtract(self.counters.syscw, before.counters.syscw, "syscw")?,
            read_bytes,
            write_bytes,
            cancelled_write_bytes,
            observer_rchar_bytes: before.observer_rchar_bytes,
            unexpected_rchar_bytes,
            unexpected_wchar_bytes: wchar,
            unexpected_read_bytes: read_bytes,
            unexpected_write_bytes: write_bytes,
            response_window_exact: unexpected_rchar_bytes == 0
                && wchar == 0
                && read_bytes == 0
                && write_bytes == 0
                && cancelled_write_bytes == 0,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BackendRow {
    measurement_wall_ns: u64,
    operations: Vec<(String, u64)>,
    h2d_bytes: u64,
    d2h_bytes: u64,
    explicit_d2d_copy_bytes: u64,
    device_zeroed_bytes: u64,
    device_generated_bytes: u64,
    resident_alloc_requests: u64,
    resident_reuse_hits: u64,
    resident_free_requests: u64,
    live_device_bytes: u64,
    peak_device_bytes: u64,
    pinned_allocation_calls: u64,
    pinned_alloc_requests: u64,
    pinned_reuse_hits: u64,
    pinned_free_requests: u64,
    pinned_physical_free_calls: u64,
    live_pinned_bytes: u64,
    peak_pinned_bytes: u64,
    x4c_arena_reset_calls: u64,
    x4c_arena_reset_bytes: u64,
    timing_event_api_calls: u64,
    outstanding_timing_records: u64,
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
            explicit_d2d_copy_bytes: stats.explicit_d2d_copy_bytes,
            device_zeroed_bytes: stats.device_zeroed_bytes,
            device_generated_bytes: stats.device_generated_bytes,
            resident_alloc_requests: stats.resident_alloc_requests,
            resident_reuse_hits: stats.resident_reuse_hits,
            resident_free_requests: stats.resident_free_requests,
            live_device_bytes: stats.live_device_bytes,
            peak_device_bytes: stats.peak_device_bytes,
            pinned_allocation_calls: stats.pinned_allocation_calls,
            pinned_alloc_requests: stats.pinned_alloc_requests,
            pinned_reuse_hits: stats.pinned_reuse_hits,
            pinned_free_requests: stats.pinned_free_requests,
            pinned_physical_free_calls: stats.pinned_physical_free_calls,
            live_pinned_bytes: stats.live_pinned_bytes,
            peak_pinned_bytes: stats.peak_pinned_bytes,
            x4c_arena_reset_calls: stats.x4c_arena_reset_calls,
            x4c_arena_reset_bytes: stats.x4c_arena_reset_bytes,
            timing_event_api_calls: stats.timing_event_api_calls,
            outstanding_timing_records: stats.timing_records,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ResponseIoRow {
    response_e_ntt_calls: u64,
    response_coefficient_files_created: u64,
    response_coefficient_bytes_read: u64,
    response_coefficient_bytes_written: u64,
    response_oracle_files_created: u64,
    response_oracle_bytes_read: u64,
    response_oracle_bytes_written: u64,
    response_full_oracle_comparison_bytes: u64,
    staging_files_created: u64,
    staging_bytes_read: u64,
    staging_bytes_written: u64,
    cpu_fold_tree_clone_bytes: u64,
    response_overlay_reread_bytes: u64,
    response_fadv_dontneed_calls: u64,
}

impl From<X4cResponseIoCountersV4> for ResponseIoRow {
    fn from(value: X4cResponseIoCountersV4) -> Self {
        Self {
            response_e_ntt_calls: value.response_e_ntt_calls,
            response_coefficient_files_created: value.response_coefficient_files_created,
            response_coefficient_bytes_read: value.response_coefficient_bytes_read,
            response_coefficient_bytes_written: value.response_coefficient_bytes_written,
            response_oracle_files_created: value.response_oracle_files_created,
            response_oracle_bytes_read: value.response_oracle_bytes_read,
            response_oracle_bytes_written: value.response_oracle_bytes_written,
            response_full_oracle_comparison_bytes: value.response_full_oracle_comparison_bytes,
            staging_files_created: value.staging_files_created,
            staging_bytes_read: value.staging_bytes_read,
            staging_bytes_written: value.staging_bytes_written,
            cpu_fold_tree_clone_bytes: value.cpu_fold_tree_clone_bytes,
            response_overlay_reread_bytes: value.response_overlay_reread_bytes,
            response_fadv_dontneed_calls: value.response_fadv_dontneed_calls,
        }
    }
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
    peak_bytes: u64,
    logical_allocations: u64,
    response_round_allocations: u64,
    reallocations: u64,
    logical_deallocations: u64,
    reset_count: u64,
    zeroed_bytes: u64,
    outstanding_allocations: u64,
    outstanding_bytes: u64,
    cached_reusable_bytes: u64,
    accelerator_available: bool,
    baseline_active_device_allocations: u64,
    baseline_active_pinned_allocations: u64,
    baseline_active_pinned_bytes: u64,
    active_device_allocations: u64,
    active_pinned_allocations: u64,
    active_pinned_bytes: u64,
    outstanding_cuda_operations: u64,
    stream_synchronized: bool,
    pinned_pool_allocations: u64,
    pinned_pool_requested_bytes: u64,
    native_live_device_bytes: u64,
    native_peak_device_bytes: u64,
    native_resident_alloc_requests: u64,
    native_resident_reuse_hits: u64,
    native_resident_free_requests: u64,
    native_arena_reset_calls: u64,
    native_arena_reset_bytes: u64,
    native_device_zeroed_bytes: u64,
}

impl From<X4cArenaCensusV4> for ArenaRow {
    fn from(value: X4cArenaCensusV4) -> Self {
        Self {
            capacity_bytes: value.arena_capacity_bytes,
            committed_bytes: value.arena_committed_bytes,
            peak_bytes: value.arena_peak_bytes,
            logical_allocations: value.logical_allocation_count,
            response_round_allocations: value.response_round_allocation_count,
            reallocations: value.reallocation_count,
            logical_deallocations: value.logical_deallocation_count,
            reset_count: value.reset_count,
            zeroed_bytes: value.zeroed_bytes,
            outstanding_allocations: value.outstanding_allocation_count,
            outstanding_bytes: value.outstanding_bytes,
            cached_reusable_bytes: value.cached_reusable_bytes,
            accelerator_available: value.accelerator_available,
            baseline_active_device_allocations: value.backend_baseline_active_device_allocations,
            baseline_active_pinned_allocations: value.backend_baseline_active_pinned_allocations,
            baseline_active_pinned_bytes: value.backend_baseline_active_pinned_bytes,
            active_device_allocations: value.backend_active_device_allocations,
            active_pinned_allocations: value.backend_active_pinned_allocations,
            active_pinned_bytes: value.backend_active_pinned_bytes,
            outstanding_cuda_operations: value.backend_outstanding_cuda_operations,
            stream_synchronized: value.backend_stream_synchronized,
            pinned_pool_allocations: value.x4c_pinned_pool_allocations,
            pinned_pool_requested_bytes: value.x4c_pinned_pool_requested_bytes,
            native_live_device_bytes: value.native_live_device_bytes,
            native_peak_device_bytes: value.native_peak_device_bytes,
            native_resident_alloc_requests: value.native_resident_alloc_requests,
            native_resident_reuse_hits: value.native_resident_reuse_hits,
            native_resident_free_requests: value.native_resident_free_requests,
            native_arena_reset_calls: value.native_arena_reset_calls,
            native_arena_reset_bytes: value.native_arena_reset_bytes,
            native_device_zeroed_bytes: value.native_device_zeroed_bytes,
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

#[derive(Serialize)]
struct CandidateRow {
    role: String,
    ordinal: u64,
    measured: bool,
    epoch: u64,
    challenge_seed_digest: String,
    response_nonce_digest: String,
    freshness_binding_digest: String,
    freshness_record_digest: String,
    authorization_record_digest: String,
    freshness_markers_persisted: bool,
    model_root: String,
    model_prove_s: f64,
    model_verify_s: f64,
    pcs_total_s: f64,
    seal_wall_s: f64,
    open_wall_s: f64,
    verify_wall_s: f64,
    proof_ready_wall_s: f64,
    session_reusable_wall_s: f64,
    complete_e2e_wall_s: f64,
    complete_pcs_bytes: u64,
    response_bytes: u64,
    sub_correlations: u64,
    full_correlations: u64,
    expected_sub_correlations: u64,
    expected_full_correlations: u64,
    correlation_allocation_digest: String,
    prover_verifier_correlation_digest_equal: bool,
    transcript_bytes_equal: bool,
    transcript_ledger_equal: bool,
    process_io: IoSnapshot,
    response_window_io_exact: bool,
    backend: BackendRow,
    metrics: MetricsRow,
    expected_h2d_bytes: u64,
    expected_d2h_bytes: u64,
    traffic_exact: bool,
    zero_response_staging: bool,
    verifier_accepted: bool,
    connection_audit: volta_pcg::ConnectionResponseAudit,
    accepted: bool,
}

#[derive(Serialize)]
struct RebuildCohortRow {
    cohort_id: u32,
    coefficient_bytes_read: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    root: String,
    expected_root: String,
    root_equal: bool,
    accepted: bool,
}

#[derive(Serialize)]
struct RebuildRow {
    wall_s: f64,
    io: IoSnapshot,
    parallel_task_count: usize,
    rayon_workers: usize,
    cohorts: Vec<RebuildCohortRow>,
    coefficient_bytes_read: u64,
    evaluation_table_bytes: u64,
    host_oracle_bytes: u64,
    host_outer_cache_bytes: u64,
    roots_equal_onboarding: bool,
    durable_census_before: DurableTierCensusRow,
    durable_census_after: DurableTierCensusRow,
    durable_census_stable: bool,
    accepted: bool,
}

#[derive(Serialize)]
struct OnlineRecord {
    schema: u64,
    milestone: String,
    git_sha: String,
    git_dirty: bool,
    profile: String,
    protocol: String,
    onboarding_path: String,
    onboarding_sha256: String,
    onboarding_sha256_exact: bool,
    onboarding_git_sha: String,
    clean_source_sha256: String,
    selected_query_tape_blake3: String,
    input_bin_sha256: String,
    input_json_sha256: String,
    input_params_sha256: String,
    golden_p5_sha256: String,
    golden_p6_sha256: String,
    model_safetensors_sha256: String,
    prefill_tokens: usize,
    decode_tokens: usize,
    pcg_prg: String,
    pcg_stage_plan: String,
    model_sub_correlations: u64,
    model_full_correlations: u64,
    x4c_full_correlations: u64,
    closure_full_correlations: u64,
    golden_match: bool,
    cpu_cuda_prefill_logits_equal: bool,
    cpu_cuda_band_logits_equal: bool,
    rebuild: RebuildRow,
    rebuild_roots: Vec<String>,
    rebuild_roots_equal_onboarding: bool,
    rebuild_parallel_tasks: usize,
    warmup_count: usize,
    measured_count: usize,
    candidates: Vec<CandidateRow>,
    selected_upper_median_open_wall_s: f64,
    selected_upper_median_verify_wall_s: f64,
    selected_upper_median_proof_ready_wall_s: f64,
    selected_upper_median_session_reusable_wall_s: f64,
    selected_upper_median_complete_e2e_wall_s: f64,
    open_ceiling_s: f64,
    verify_ceiling_s: f64,
    open_pass: bool,
    verify_pass: bool,
    pinned_pool_release_wall_s: f64,
    pinned_pool_release_restored_ownership: bool,
    pcs_bytes: u64,
    response_bytes: u64,
    rate: String,
    query_count: usize,
    all_candidates_accepted: bool,
    zero_response_staging: bool,
    exact_communication: bool,
    diagnostic_comparisons: u64,
    diagnostic_soundness_credit_bits: u64,
    protocol_or_parameter_change: bool,
    root_or_proof_format_change: bool,
    lean_or_soundness_change: bool,
    overall_pass: bool,
}

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
    // `zero_batch_exchange` executes both roles over the prover transcript.
    // Replay the unchanged message/challenge schedule on the verifier ledger.
    verifier_tx.append("mask_correction", 16);
    let _ = verifier_tx.challenge_fp2();
    verifier_tx.append("zero_batch_tag", 16);
    product_ok && zero_ok
}

fn online(args: &Args) -> Result<(), String> {
    let output = args.output.as_ref().ok_or_else(|| "online requires --output".to_owned())?;
    let durable =
        args.durable_root.as_ref().ok_or_else(|| "online requires --durable-root".to_owned())?;
    let onboarding_path =
        args.onboarding.as_ref().ok_or_else(|| "online requires --onboarding".to_owned())?;
    let expected_onboarding_sha256 = args
        .onboarding_sha256
        .as_deref()
        .ok_or_else(|| "online requires --onboarding-sha256".to_owned())?;
    if expected_onboarding_sha256.len() != 64
        || !expected_onboarding_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--onboarding-sha256 must be 64 lowercase hex digits".to_owned());
    }
    let authorization_path = args
        .authorization_store
        .as_ref()
        .ok_or_else(|| "online requires --authorization-store".to_owned())?;
    let connection_path = args
        .connection_store
        .as_ref()
        .ok_or_else(|| "online requires --connection-store".to_owned())?;
    let clean_source_sha256 = args
        .clean_source_sha256
        .as_deref()
        .ok_or_else(|| "online requires --clean-source-sha256".to_owned())?;
    if clean_source_sha256.len() != 64
        || !clean_source_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--clean-source-sha256 must be 64 lowercase hex digits".to_owned());
    }
    let clean_source = parse_hex_32(clean_source_sha256)?;
    if output.exists() || args.epoch_base == 0 {
        return Err("online output must be fresh and epoch-base nonzero".to_owned());
    }
    let git_sha = git_sha_clean()?;
    let observed_onboarding_sha256 = sha256(onboarding_path)?;
    if observed_onboarding_sha256 != expected_onboarding_sha256 {
        return Err("explicit onboarding SHA-256 pin mismatch".to_owned());
    }
    let onboarding_bytes =
        fs::read(onboarding_path).map_err(|error| format!("read onboarding: {error}"))?;
    let onboarding: OnboardingRecord = serde_json::from_slice(&onboarding_bytes)
        .map_err(|error| format!("parse onboarding: {error}"))?;
    if onboarding.schema != SCHEMA
        || !onboarding.overall_pass
        || onboarding.profile != PROFILE
        || onboarding.protocol != PROTOCOL
        || onboarding.input_bin_sha256 != GPT2_BIN_SHA256
        || onboarding.input_json_sha256 != GPT2_JSON_SHA256
        || onboarding.input_params_sha256 != GPT2_PARAMS_SHA256
        || onboarding.golden_p5_sha256 != GOLDEN_P5_SHA256
        || onboarding.golden_p6_sha256 != GOLDEN_P6_SHA256
        || onboarding.model_safetensors_sha256 != SAFETENSORS_SHA256
        || onboarding.parent_domains.len() != 51
        || onboarding.descriptor_digests.len() != 51
        || onboarding.measured.len() != 3
        || onboarding.durable.len() != 5
        || !onboarding.durable_census.exact
    {
        return Err("onboarding record is not eligible for real-weight online".to_owned());
    }
    verify_inputs(&args.weights)?;
    let inventory = X4cGpt2Inventory::new(
        parse_hex_32(&onboarding.model_config_digest)?,
        parse_hex_32(&onboarding.weights_digest)?,
        &onboarding.parent_domains,
    )?;
    let expected_cohort_ids =
        inventory.cohort_configs.iter().map(|config| config.identity.cohort_id).collect::<Vec<_>>();
    let durable_census_before = durable_tier_census(durable, &expected_cohort_ids)?;
    if !durable_census_before.exact || durable_census_before != onboarding.durable_census {
        return Err("durable tier no longer matches the exact onboarding census".to_owned());
    }
    let rebuild_before_io = IoObservation::current()?;
    let rebuild_started = Instant::now();
    let loaded = inventory
        .cohort_configs
        .par_iter()
        .zip(&onboarding.durable)
        .map(|(config, row)| {
            if config.identity.cohort_id != row.cohort_id {
                return Err("onboarding cohort order changed".to_owned());
            }
            let directory = durable.join(format!("cohort-{:08x}", row.cohort_id));
            let coefficient_path = directory.join("coefficients.bin");
            let root_path = directory.join("root.bin");
            if sha256(&coefficient_path)? != row.coefficient_sha256
                || sha256(&root_path)? != row.root_sha256
            {
                return Err("durable X4c digest mismatch".to_owned());
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
                    name: "durable-real-weight",
                    config: config.clone(),
                    coefficients,
                },
                root,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let (materials, roots): (Vec<_>, Vec<_>) = loaded.into_iter().unzip();
    let evaluations = rebuild_evaluation_tables(&inventory, &materials)?;
    let cohorts = materials
        .into_par_iter()
        .zip(roots.par_iter().copied())
        .map(|(material, root)| {
            X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
                material.config,
                material.coefficients,
                root,
            )
            .map_err(|error| format!("parallel fresh rebuild: {error:?}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let rebuild_roots = cohorts.iter().map(|cohort| hex(&cohort.root())).collect::<Vec<_>>();
    let rebuild_roots_equal_onboarding = rebuild_roots == onboarding.warmup_root_set;
    if !rebuild_roots_equal_onboarding {
        return Err("fresh rebuild roots differ from onboarding".to_owned());
    }
    let mut rebuild_cohorts = Vec::with_capacity(cohorts.len());
    for ((cohort, durable_row), expected_root) in
        cohorts.iter().zip(&onboarding.durable).zip(&onboarding.warmup_root_set)
    {
        let root = hex(&cohort.root());
        let host_oracle_bytes =
            cohort.host_oracle_bytes().map_err(|error| format!("host oracle census: {error:?}"))?;
        let host_outer_cache_bytes = cohort
            .host_outer_cache_bytes()
            .map_err(|error| format!("host outer-cache census: {error:?}"))?;
        let root_equal = &root == expected_root;
        rebuild_cohorts.push(RebuildCohortRow {
            cohort_id: durable_row.cohort_id,
            coefficient_bytes_read: durable_row.coefficient_bytes,
            host_oracle_bytes,
            host_outer_cache_bytes,
            root,
            expected_root: expected_root.clone(),
            root_equal,
            accepted: root_equal,
        });
    }
    let rebuild_coefficient_bytes =
        rebuild_cohorts.iter().map(|row| row.coefficient_bytes_read).sum::<u64>();
    let evaluation_table_bytes = evaluations
        .slots
        .iter()
        .flat_map(|slots| slots.iter().flatten())
        .map(|table| table.len() as u64 * 16)
        .sum::<u64>();
    let rebuild_host_oracle_bytes =
        rebuild_cohorts.iter().map(|row| row.host_oracle_bytes).sum::<u64>();
    let rebuild_host_outer_cache_bytes =
        rebuild_cohorts.iter().map(|row| row.host_outer_cache_bytes).sum::<u64>();
    let durable_census_after = durable_tier_census(durable, &expected_cohort_ids)?;
    let durable_census_stable =
        durable_census_before == durable_census_after && durable_census_after.exact;
    let rebuild = RebuildRow {
        wall_s: rebuild_started.elapsed().as_secs_f64(),
        io: IoObservation::current()?.delta(&rebuild_before_io)?,
        parallel_task_count: 5,
        rayon_workers: rayon::current_num_threads(),
        cohorts: rebuild_cohorts,
        coefficient_bytes_read: rebuild_coefficient_bytes,
        evaluation_table_bytes,
        host_oracle_bytes: rebuild_host_oracle_bytes,
        host_outer_cache_bytes: rebuild_host_outer_cache_bytes,
        roots_equal_onboarding: rebuild_roots_equal_onboarding,
        durable_census_before,
        durable_census_after,
        durable_census_stable,
        accepted: rebuild_coefficient_bytes == X4C_GPT2_DURABLE_COEFFICIENT_BYTES
            && evaluation_table_bytes == X4C_GPT2_DURABLE_COEFFICIENT_BYTES
            && rebuild_host_oracle_bytes == X4C_GPT2_HOST_ORACLE_BYTES
            && rebuild_host_outer_cache_bytes == X4C_GPT2_HOST_OUTER_CACHE_BYTES
            && rebuild_roots_equal_onboarding
            && durable_census_stable,
    };
    if !rebuild.accepted {
        return Err("fresh rebuild exact byte/root/census gate failed".to_owned());
    }

    let workload = workload(&args.weights)?;
    let (mock, _, model_sub_corrs, model_full_corrs) = mock_model_outputs(&workload)?;
    inventory.validate_parent_domains(&mock)?;
    let required_sub_corrs = model_sub_corrs;
    let required_full_corrs = model_full_corrs
        .checked_add(X4C_GPT2_FULL_CORRELATIONS)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| "real-PCG count overflows".to_owned())?;

    let mut backend = Backend::cuda_resident_with_timing(ResidentTimingPolicy::WallOnlyCounters)
        .map_err(|error| format!("initialize resident CUDA: {error}"))?;
    let resident_model = upload_resident_model(&workload.model, &mut backend)
        .map_err(|error| format!("upload model: {error}"))?;
    let resident_prefill = forward_model_tokens_resident(
        &resident_model,
        &workload.model.p.tokens[..100],
        &mut backend,
    )
    .map_err(|error| format!("resident prefill: {error}"))?;
    let prefill_logits = backend
        .download_device(
            resident_prefill.logits().buffer(),
            resident_prefill.logits().offset(),
            VOCAB,
        )
        .map_err(|error| format!("download resident prefill logits: {error}"))?;
    let cpu_cuda_prefill_logits_equal = prefill_logits == workload.prefill.logits;
    let resident_source =
        forward_model_tokens_resident(&resident_model, &workload.sequence, &mut backend)
            .map_err(|error| format!("resident full response: {error}"))?;
    let resident_band =
        band_model_witness_resident(&resident_model, &resident_source, 100, 50, &mut backend)
            .map_err(|error| format!("resident band: {error}"))?;
    let band_logits = backend
        .download_device(
            resident_band.logits().buffer(),
            resident_band.logits().offset(),
            50 * VOCAB,
        )
        .map_err(|error| format!("download resident band logits: {error}"))?;
    let cpu_cuda_band_logits_equal = band_logits == workload.band.logits;
    if !cpu_cuda_prefill_logits_equal || !cpu_cuda_band_logits_equal {
        return Err("CPU/CUDA real-weight witness differential failed".to_owned());
    }
    let error = backend
        .upload_new_device(&[0u32])
        .map_err(|error| format!("resident proof error word: {error}"))?;

    let connection_store = ConnectionStore::new(connection_path)
        .map_err(|error| format!("connection store: {error}"))?;
    let authorization_store = ResponseAuthorizationStore::new(authorization_path)
        .map_err(|error| format!("authorization store: {error}"))?;
    let random = |label: &str| -> Result<[u8; 32], String> {
        let mut value = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut value)
            .map_err(|error| format!("OS randomness for {label}: {error}"))?;
        Ok(value)
    };
    let binding = ConnectionBinding::new(
        random("connection id")?,
        random("authenticated channel id")?,
        FaseDStagePlan::TerminalOne,
    )
    .map_err(|error| format!("connection binding: {error}"))?;
    let mut connection = open_fase_d_connection_with_ggm_prg(
        &connection_store,
        binding,
        None,
        FaseDParams::production(FaseDStagePlan::TerminalOne),
        GgmPrg::Aes128Mmo,
    )
    .map_err(|error| format!("open fase-D connection: {error}"))?;
    connection
        .spool_terminal_one_correlations()
        .map_err(|error| format!("spool fase-D correlations: {error}"))?;
    let selected_tape = selected_tape()?;
    let mut runtime = X4cCudaArenaRuntimeV4::production(&mut backend)
        .map_err(|error| format!("X4c runtime: {error:?}"))?;
    let mut candidates = Vec::new();
    for ordinal in 0..4u64 {
        let epoch =
            args.epoch_base.checked_add(ordinal).ok_or_else(|| "epoch overflows".to_owned())?;
        let challenge_seed = random("verifier challenge seed")?;
        let challenge_seed_digest = *blake3::hash(&challenge_seed).as_bytes();
        let response_nonce = random("real-PCG authorization nonce")?;
        let session = binding
            .response_binding(response_nonce)
            .map_err(|error| format!("response binding: {error}"))?;
        let freshness = X4ResponseFreshnessBinding::new(
            session,
            // The actual root is epoch-bound; derive it before authorization
            // from the already rebuilt immutable cohort roots.
            {
                let leaves = inventory
                    .blocks
                    .iter()
                    .map(|block| {
                        let weight = match block.descriptor.cohort_id {
                            0xA500_0001 => 0,
                            0xA500_0002 => 1,
                            _ => 2,
                        };
                        let auxiliary = if block.ell() == 17 { 3 } else { 4 };
                        volta_pcs::x4::ManifestLeafFrame {
                            descriptor_digest: block.descriptor_digest,
                            ordered_roots: vec![cohorts[weight].root(), cohorts[auxiliary].root()],
                        }
                    })
                    .collect();
                volta_pcs::x4::ManifestTreeV4::build(
                    volta_pcs::x4::manifest_id_digest_v4(
                        inventory.model_config_digest,
                        inventory.weights_digest,
                        epoch,
                    ),
                    leaves,
                )
                .map_err(|error| format!("pre-authorize manifest: {error:?}"))?
                .root()
            },
            epoch,
            challenge_seed_digest,
        )
        .map_err(|error| format!("X4 freshness binding: {error}"))?;
        let freshness_binding_digest = freshness.digest_hex();
        let burn = connection
            .connection
            .begin_x4_response(&authorization_store, freshness)
            .map_err(|error| format!("persist X4 response freshness: {error}"))?;
        let freshness_markers_persisted = burn.epoch_marker_path().is_file()
            && burn.challenge_marker_path().is_file()
            && burn.authorization.marker_path().is_file();
        let tensor_tag = *blake3::hash(
            &[b"volta-zk/x4c/gpt2-response-domain/v1".as_slice(), &ordinal.to_le_bytes()].concat(),
        )
        .as_bytes();
        let domain = CorrelationDomain::new(
            binding.connection_id,
            response_nonce,
            ordinal as u32,
            0,
            ordinal,
            tensor_tag,
        )
        .map_err(|error| format!("response correlation domain: {error}"))?;
        let pools = connection
            .allocate_pcg_pools(
                1,
                required_sub_corrs as usize,
                required_full_corrs as usize,
                domain,
            )
            .map_err(|error| format!("allocate response PCG pools: {error}"))?;
        let mut stream = CorrelationStream::from_pcg_pool(pools.prover);
        let mut verifier = VerifierCtx::from_pcg_pool(pools.verifier_delta, pools.verifier);
        let mut prover_tx = Transcript::new(challenge_seed);
        let mut verifier_tx = Transcript::new(challenge_seed);
        let complete_e2e_started = Instant::now();
        let model_started = Instant::now();
        let model_backend = runtime
            .backend_between_responses()
            .map_err(|error| format!("borrow model backend: {error:?}"))?;
        model_backend
            .begin_measurement()
            .map_err(|error| format!("begin model measurement: {error}"))?;
        let resident_chunks =
            [ResidentChunkRef { band: &resident_band, logits: &[], seq: &workload.sequence }];
        let (proof, prover_output, prod, zero) = prove_response_resident_private_logits(
            &workload.model,
            &resident_model,
            &resident_prefill,
            &resident_chunks,
            DeviceSlice::new(&error, 0, 1)
                .map_err(|error| format!("proof error slice: {error}"))?,
            &mut stream,
            &mut prover_tx,
            model_backend,
        )
        .map_err(|error| format!("resident real-weight model proof: {error}"))?;
        model_backend
            .finish_measurement()
            .map_err(|error| format!("finish model measurement: {error}"))?;
        let model_prove_s = model_started.elapsed().as_secs_f64();
        inventory.validate_parent_domains(&prover_output)?;
        let public = [PrivateChunkPub { q: 50, seq: &workload.sequence }];
        let model_verify_started = Instant::now();
        let (verifier_output, kprod, kzero) = verify_response_private_logits(
            &workload.model,
            100,
            &public,
            &proof,
            &mut verifier,
            &mut verifier_tx,
        )
        .ok_or_else(|| "real-weight model proof rejected".to_owned())?;
        let model_verify_s = model_verify_started.elapsed().as_secs_f64();
        let before_io = IoObservation::current()?;
        runtime
            .begin_response_measurement()
            .map_err(|error| format!("begin X4c response measurement: {error:?}"))?;
        let pcs_started = Instant::now();
        let result = match execute_real_weight_x4c(
            &workload.model,
            &inventory,
            &cohorts,
            &evaluations,
            epoch,
            burn.freshness_record_digest_bytes,
            selected_tape.clone(),
            &prover_output,
            &verifier_output,
            &mut stream,
            &mut verifier,
            &mut prover_tx,
            &mut verifier_tx,
            &mut runtime,
            X4cSealConfigV4::production(clean_source, ordinal)
                .map_err(|error| format!("seal config: {error:?}"))?,
        ) {
            Ok(result) => result,
            Err(error) => {
                let finish = runtime.finish_response_measurement();
                return Err(format!(
                    "real-weight X4c execution: {error}; backend_finish_after_error={finish:?}"
                ));
            }
        };
        let pcs_total_s = pcs_started.elapsed().as_secs_f64();
        let backend_stats = runtime
            .finish_response_measurement()
            .map_err(|error| format!("finish X4c response measurement: {error:?}"))?;
        let closure_ok = close_model_response(
            &prod,
            &zero,
            &kprod,
            &kzero,
            &mut stream,
            &mut verifier,
            &mut prover_tx,
            &mut verifier_tx,
        );
        let process_io = IoObservation::current()?.delta(&before_io)?;
        let complete_e2e_wall_s = complete_e2e_started.elapsed().as_secs_f64();
        let transcript_bytes_equal = prover_tx.total_bytes() == verifier_tx.total_bytes();
        let transcript_ledger_equal = prover_tx.ledger() == verifier_tx.ledger();
        let prover_correlation_digest = stream
            .allocation_digest_hex()
            .ok_or_else(|| "real-PCG prover allocation digest missing".to_owned())?;
        let verifier_correlation_digest = verifier
            .allocation_digest_hex()
            .ok_or_else(|| "real-PCG verifier allocation digest missing".to_owned())?;
        let prover_verifier_correlation_digest_equal =
            prover_correlation_digest == verifier_correlation_digest;
        let x4c = &result.x4c_metrics;
        let expected_h2d_bytes = x4c
            .global_open
            .combined_codeword_symbols
            .checked_mul(16)
            .and_then(|bytes| {
                bytes.checked_add(x4c.execution.direct_fold_diagnostic_index_h2d_bytes)
            })
            .and_then(|bytes| bytes.checked_add(x4c.execution.query_gather_operation_h2d_bytes))
            .and_then(|bytes| bytes.checked_add(x4c.execution.canonical_template_h2d_bytes))
            .ok_or_else(|| "expected X4c H2D bytes overflow".to_owned())?;
        let expected_d2h_bytes = 27u64
            .checked_mul(32)
            .and_then(|bytes| {
                bytes.checked_add(x4c.execution.direct_fold_diagnostic_value_d2h_bytes)
            })
            .and_then(|bytes| bytes.checked_add(x4c.execution.canonical_opening_d2h_bytes))
            .ok_or_else(|| "expected X4c D2H bytes overflow".to_owned())?;
        let traffic_exact = backend_stats.h2d_bytes == expected_h2d_bytes
            && backend_stats.d2h_bytes == expected_d2h_bytes
            && backend_stats.explicit_d2d_copy_bytes == 0
            && backend_stats.device_generated_bytes == 0
            && backend_stats.resident_alloc_requests == 1
            && backend_stats.resident_free_requests == 1
            && backend_stats.x4c_arena_reset_calls == 1
            && backend_stats.x4c_arena_reset_bytes == x4c.proof_ready_arena.arena_capacity_bytes
            && backend_stats.device_zeroed_bytes == x4c.proof_ready_arena.arena_capacity_bytes
            && backend_stats.pinned_allocation_calls == 0
            && backend_stats.pinned_alloc_requests == 0
            && backend_stats.pinned_reuse_hits == 0
            && backend_stats.pinned_free_requests == 0
            && backend_stats.pinned_physical_free_calls == 0
            && backend_stats.timing_event_api_calls == 0
            && backend_stats.timing_records == 0;
        let direct_fold_comparisons =
            x4c.parity.iter().map(|row| row.result.comparison_count).sum::<u64>();
        let direct_fold_mismatches =
            x4c.parity.iter().map(|row| row.result.mismatch_count).sum::<u64>();
        let zero_response_staging =
            x4c.io == X4cResponseIoCountersV4::default() && process_io.response_window_exact;
        let response_window_io_exact = process_io.response_window_exact;
        let complete_pcs_bytes = result.encoded_pcs.len() as u64;
        let verifier_accepted = closure_ok;
        let candidate_pass = verifier_accepted
            && freshness_markers_persisted
            && transcript_bytes_equal
            && transcript_ledger_equal
            && stream.counters == verifier.counters
            && stream.counters.sub_corrs == required_sub_corrs
            && stream.counters.full_corrs == required_full_corrs
            && prover_verifier_correlation_digest_equal
            && complete_pcs_bytes == X4C_GPT2_PCS_BYTES
            && x4c.execution.query_gather_calls == 1
            && direct_fold_comparisons == 1_592
            && direct_fold_mismatches == 0
            && x4c.sampling_soundness_credit_bits == 0
            && zero_response_staging
            && traffic_exact;
        if !candidate_pass {
            connection
                .connection
                .malicious_check_failed()
                .map_err(|error| format!("burn rejected response: {error}"))?;
            return Err("real-weight X4c candidate hard gate failed".to_owned());
        }
        let connection_audit = connection
            .connection
            .finish_response_success()
            .map_err(|error| format!("finish response: {error}"))?;
        let expected_raw_correlations = required_sub_corrs
            .checked_add(
                required_full_corrs
                    .checked_mul(2)
                    .ok_or_else(|| "raw full-correlation count overflow".to_owned())?,
            )
            .ok_or_else(|| "raw correlation count overflow".to_owned())?;
        if connection_audit.correlations_consumed != expected_raw_correlations {
            return Err("real-PCG connection audit correlation count changed".to_owned());
        }
        let proof_ready_wall_s =
            result.x4c_metrics.lifecycle_walls.proof_ready_wall_ns as f64 / 1e9;
        let session_reusable_wall_s =
            result.x4c_metrics.lifecycle_walls.session_reusable_wall_ns as f64 / 1e9;
        let seal_wall_s = result.seal_wall_ns as f64 / 1e9;
        let open_wall_s = result.open_wall_ns as f64 / 1e9;
        let verify_wall_s = result.verify_wall_ns as f64 / 1e9;
        let model_root = hex(&result.model_root);
        let metrics = result.x4c_metrics.into();
        let backend = backend_stats.into();
        candidates.push(CandidateRow {
            role: if ordinal == 0 { "warmup".to_owned() } else { format!("measured-{ordinal}") },
            ordinal,
            measured: ordinal != 0,
            epoch,
            challenge_seed_digest: hex(&challenge_seed_digest),
            response_nonce_digest: connection_audit.response_nonce_digest.clone(),
            freshness_binding_digest,
            freshness_record_digest: burn.freshness_record_digest,
            authorization_record_digest: burn.authorization.record_digest,
            freshness_markers_persisted,
            model_root,
            model_prove_s,
            model_verify_s,
            pcs_total_s,
            seal_wall_s,
            open_wall_s,
            verify_wall_s,
            proof_ready_wall_s,
            session_reusable_wall_s,
            complete_e2e_wall_s,
            complete_pcs_bytes,
            response_bytes: X4C_GPT2_RESPONSE_BYTES,
            sub_correlations: stream.counters.sub_corrs,
            full_correlations: stream.counters.full_corrs,
            expected_sub_correlations: required_sub_corrs,
            expected_full_correlations: required_full_corrs,
            correlation_allocation_digest: prover_correlation_digest,
            prover_verifier_correlation_digest_equal,
            transcript_bytes_equal,
            transcript_ledger_equal,
            process_io,
            response_window_io_exact,
            backend,
            metrics,
            expected_h2d_bytes,
            expected_d2h_bytes,
            traffic_exact,
            zero_response_staging,
            verifier_accepted,
            connection_audit,
            accepted: candidate_pass,
        });
    }
    let baseline_pinned_allocations = candidates
        .last()
        .ok_or_else(|| "missing X4c candidate".to_owned())?
        .metrics
        .session_reusable_arena
        .baseline_active_pinned_allocations;
    let baseline_pinned_bytes = candidates
        .last()
        .ok_or_else(|| "missing X4c candidate".to_owned())?
        .metrics
        .session_reusable_arena
        .baseline_active_pinned_bytes;
    let release_started = Instant::now();
    runtime.release_pinned_pool().map_err(|error| format!("release X4c pinned pool: {error:?}"))?;
    let pinned_pool_release_wall_s = release_started.elapsed().as_secs_f64();
    let final_backend = runtime
        .backend_between_responses()
        .map_err(|error| format!("borrow backend after X4c pool release: {error:?}"))?;
    let final_pinned = final_backend
        .pinned_memory_stats()
        .map_err(|error| format!("final pinned ownership census: {error}"))?;
    let final_control = final_backend
        .x4c_control_state()
        .map_err(|error| format!("final CUDA control census: {error}"))?;
    let pinned_pool_release_restored_ownership = final_pinned.active_allocations
        == baseline_pinned_allocations
        && final_pinned.active_bytes == baseline_pinned_bytes
        && final_pinned.in_flight_allocations == 0
        && final_control.stream_state == CudaStreamState::Idle
        && final_control.outstanding_cuda_operations == 0
        && !final_control.measurement_active
        && !final_control.measurement_poisoned;
    let measured = &candidates[1..];
    let selected_upper_median_open_wall_s =
        upper_median(measured.iter().map(|candidate| candidate.open_wall_s).collect());
    let selected_upper_median_verify_wall_s =
        upper_median(measured.iter().map(|candidate| candidate.verify_wall_s).collect());
    let selected_upper_median_proof_ready_wall_s =
        upper_median(measured.iter().map(|candidate| candidate.proof_ready_wall_s).collect());
    let selected_upper_median_session_reusable_wall_s =
        upper_median(measured.iter().map(|candidate| candidate.session_reusable_wall_s).collect());
    let selected_upper_median_complete_e2e_wall_s =
        upper_median(measured.iter().map(|candidate| candidate.complete_e2e_wall_s).collect());
    let open_pass = selected_upper_median_open_wall_s <= 1.50;
    let verify_pass = selected_upper_median_verify_wall_s <= 0.25;
    let overall_pass = candidates.len() == 4
        && candidates.iter().all(|candidate| candidate.accepted)
        && pinned_pool_release_restored_ownership
        && open_pass
        && verify_pass
        && workload.golden_match
        && cpu_cuda_prefill_logits_equal
        && cpu_cuda_band_logits_equal
        && rebuild.accepted;
    let all_candidates_accepted = candidates.iter().all(|candidate| candidate.accepted);
    let zero_response_staging = candidates.iter().all(|candidate| candidate.zero_response_staging);
    let exact_communication = candidates.iter().all(|candidate| {
        candidate.complete_pcs_bytes == X4C_GPT2_PCS_BYTES
            && candidate.response_bytes == X4C_GPT2_RESPONSE_BYTES
    });
    let diagnostic_comparisons = candidates
        .iter()
        .map(|candidate| candidate.metrics.execution.diagnostic_comparisons)
        .min()
        .unwrap_or(0);
    let diagnostic_soundness_credit_bits = candidates
        .iter()
        .map(|candidate| candidate.metrics.sampling_soundness_credit_bits)
        .max()
        .unwrap_or(u64::MAX);
    let record = OnlineRecord {
        schema: SCHEMA,
        milestone: "X4c-GPT2-real-weight-online".to_owned(),
        git_sha,
        git_dirty: false,
        profile: PROFILE.to_owned(),
        protocol: PROTOCOL.to_owned(),
        onboarding_path: onboarding_path.display().to_string(),
        onboarding_sha256: observed_onboarding_sha256,
        onboarding_sha256_exact: true,
        onboarding_git_sha: onboarding.git_sha,
        clean_source_sha256: clean_source_sha256.to_owned(),
        selected_query_tape_blake3: SELECTED_TAPE_DIGEST.to_owned(),
        input_bin_sha256: GPT2_BIN_SHA256.to_owned(),
        input_json_sha256: GPT2_JSON_SHA256.to_owned(),
        input_params_sha256: GPT2_PARAMS_SHA256.to_owned(),
        golden_p5_sha256: GOLDEN_P5_SHA256.to_owned(),
        golden_p6_sha256: GOLDEN_P6_SHA256.to_owned(),
        model_safetensors_sha256: SAFETENSORS_SHA256.to_owned(),
        prefill_tokens: 100,
        decode_tokens: 50,
        pcg_prg: "aes128-mmo".to_owned(),
        pcg_stage_plan: "terminal-one".to_owned(),
        model_sub_correlations: model_sub_corrs,
        model_full_correlations: model_full_corrs,
        x4c_full_correlations: X4C_GPT2_FULL_CORRELATIONS,
        closure_full_correlations: 2,
        golden_match: workload.golden_match,
        cpu_cuda_prefill_logits_equal,
        cpu_cuda_band_logits_equal,
        rebuild,
        rebuild_roots,
        rebuild_roots_equal_onboarding,
        rebuild_parallel_tasks: 5,
        warmup_count: 1,
        measured_count: 3,
        candidates,
        selected_upper_median_open_wall_s,
        selected_upper_median_verify_wall_s,
        selected_upper_median_proof_ready_wall_s,
        selected_upper_median_session_reusable_wall_s,
        selected_upper_median_complete_e2e_wall_s,
        open_ceiling_s: 1.50,
        verify_ceiling_s: 0.25,
        open_pass,
        verify_pass,
        pinned_pool_release_wall_s,
        pinned_pool_release_restored_ownership,
        pcs_bytes: X4C_GPT2_PCS_BYTES,
        response_bytes: X4C_GPT2_RESPONSE_BYTES,
        rate: "1/8".to_owned(),
        query_count: 111,
        all_candidates_accepted,
        zero_response_staging,
        exact_communication,
        diagnostic_comparisons,
        diagnostic_soundness_credit_bits,
        protocol_or_parameter_change: false,
        root_or_proof_format_change: false,
        lean_or_soundness_change: false,
        overall_pass,
    };
    write_append_only(output, &record)?;
    if !overall_pass {
        return Err("real-weight online hard gate failed".to_owned());
    }
    Ok(())
}

fn preflight(args: &Args) -> Result<(), String> {
    validate_x4c_frozen_surface_v4("1/8", 111, X4C_GPT2_PCS_BYTES, X4C_GPT2_RESPONSE_BYTES)
        .map_err(|error| format!("frozen X4c surface: {error:?}"))?;
    verify_inputs(&args.weights)?;
    if selected_tape()?.draw_count() != 111 {
        return Err("selected tape is not 111 draws".to_owned());
    }
    // Compile/local preflight deliberately does not execute a production-size
    // proof or materialize the 9.6-GB durable tier.
    Ok(())
}

fn main() {
    let args = parse_args();
    let result = match args.mode {
        Mode::Preflight => preflight(&args),
        Mode::Onboard => onboard(&args),
        Mode::Online => online(&args),
    };
    if let Err(error) = result {
        eprintln!("x4c_gpt2_e2e_record HARD STOP: {error}");
        std::process::exit(1);
    }
}
