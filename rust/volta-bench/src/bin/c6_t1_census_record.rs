//! Local-only, append-only C6 census of the frozen GPT-2 T1 `100+50`
//! response.  This driver executes the unchanged model prover/verifier and
//! both response-wide MAC closures with the optional logical schedule audit.
//! It performs no PCS/backend work and has no provider mode.

use serde::Serialize;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use volta_field::{Fp, Fp2};
use volta_gpt2::{
    argmax, band_model_witness, decode_step, forward_model, forward_model_tokens, load_model,
    Gpt2Model, KvCache,
};
use volta_mac::{
    begin_c6_prover_trace, begin_c6_runtime_instance_capture_diagnostic, begin_c6_verifier_trace,
    compile_c6_operation_trace_for_role, finish_c6_prover_trace, finish_c6_verifier_trace,
    fresh_zero_mask, normalize_c6_operation_trace_debug_block, zero_batch_prover,
    zero_batch_verify, zero_mask_key, C6InstanceExtractionRole, CorrelationStream, Transcript,
    VerifierCtx,
};
use volta_proto::logup::Doms;
use volta_proto::{
    audit_c6_t1_source_census, c6_t1_trace_source_manifest, layer_dom_base, prod_batch_prover,
    prod_batch_verify, prove_response_private_logits, replay_c6_source_coordinate,
    replay_c6_subfield_coordinate, verify_response_private_logits, C6PairedSourceWitness,
    C6PairedSubfieldWitness, C6SourceCoordinate, C6T1CensusInput, ChunkRef, PrivateChunkPub,
    C6_PAIRED_PCG_SETUP_BYTES, C6_SETUP_CAP_BYTES, C6_T1_COMPLETE_ALLOCATION_SCHEDULE_DIGEST_HEX,
    C6_T1_CORRECTION_SCHEDULE_DIGEST_HEX, C6_T1_FINAL_PRODUCT_TRIPLES, C6_T1_FULL_CORRECTION_BYTES,
    C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX, C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES,
    C6_T1_MODEL_LOCAL_PRODUCT_TRIPLES, C6_T1_MODEL_PRODUCT_MESSAGE_BYTES,
    C6_T1_SOURCE_SCHEDULE_DIGEST_HEX, C6_T1_SUB_CORRECTION_BYTES,
};

const GPT2_PROMPT_TOKENS: usize = 100;
const GPT2_DECODE_TOKENS: usize = 50;
const GOLDEN_P6_HEADER_BYTES: usize = 16;
const GOLDEN_P6_BYTES: usize =
    GOLDEN_P6_HEADER_BYTES + 4 * GPT2_DECODE_TOKENS + 8 * GPT2_DECODE_TOKENS;
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";
const C6_SETUP_MANIFEST_FIXED_BYTES: u64 = 437;

struct Args {
    weights: PathBuf,
    output: Option<PathBuf>,
    diagnostic: bool,
    subfield_witness: bool,
    source_witness: bool,
    operation_trace: bool,
    operation_trace_debug_block: Option<u64>,
    transcript_seed_byte: u8,
}

fn args() -> Result<Args, String> {
    let mut weights = PathBuf::from("../benchmarks/weights");
    let mut output = None;
    let mut diagnostic = false;
    let mut subfield_witness = false;
    let mut source_witness = false;
    let mut operation_trace = false;
    let mut operation_trace_debug_block = None;
    let mut transcript_seed_byte = 0x18;
    let mut values = env::args().skip(1);
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--weights" => {
                weights = PathBuf::from(
                    values.next().ok_or_else(|| "--weights requires a path".to_owned())?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    values.next().ok_or_else(|| "--output requires a path".to_owned())?,
                ));
            }
            "--diagnostic" => diagnostic = true,
            "--subfield-witness" => subfield_witness = true,
            "--source-witness" => source_witness = true,
            "--operation-trace" => operation_trace = true,
            "--operation-trace-debug-block" => {
                operation_trace_debug_block = Some(
                    values
                        .next()
                        .ok_or_else(|| {
                            "--operation-trace-debug-block requires an integer".to_owned()
                        })?
                        .parse()
                        .map_err(|_| {
                            "--operation-trace-debug-block requires a u64 integer".to_owned()
                        })?,
                );
            }
            "--transcript-seed-byte" => {
                transcript_seed_byte = values
                    .next()
                    .ok_or_else(|| "--transcript-seed-byte requires an integer".to_owned())?
                    .parse()
                    .map_err(|_| "--transcript-seed-byte requires a u8 integer".to_owned())?;
            }
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    if diagnostic == output.is_some() {
        return Err("choose exactly one of --diagnostic or --output PATH".to_owned());
    }
    if [subfield_witness, source_witness, operation_trace]
        .into_iter()
        .filter(|enabled| *enabled)
        .count()
        > 1
    {
        return Err(
            "--subfield-witness, --source-witness and --operation-trace are mutually exclusive"
                .to_owned(),
        );
    }
    if operation_trace_debug_block.is_some() && !operation_trace {
        return Err("--operation-trace-debug-block requires --operation-trace".to_owned());
    }
    if operation_trace_debug_block.is_some() && !diagnostic {
        return Err("--operation-trace-debug-block is diagnostic-only".to_owned());
    }
    Ok(Args {
        weights,
        output,
        diagnostic,
        subfield_witness,
        source_witness,
        operation_trace,
        operation_trace_debug_block,
        transcript_seed_byte,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("run sha256sum for {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("sha256sum failed for {}", path.display()));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| "sha256sum output is not UTF-8".to_owned())?
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "sha256sum emitted no digest".to_owned())
}

fn verify_inputs(weights: &Path) -> Result<(), String> {
    for (name, expected) in [
        ("gpt2s-q.bin", GPT2_BIN_SHA256),
        ("gpt2s-q.json", GPT2_JSON_SHA256),
        ("gpt2s-q.params", GPT2_PARAMS_SHA256),
        ("golden-p6.bin", GOLDEN_P6_SHA256),
    ] {
        let observed = sha256(&weights.join(name))?;
        if observed != expected {
            return Err(format!("{name} digest changed: expected {expected}, got {observed}"));
        }
    }
    Ok(())
}

fn git_sha_and_tracked_clean() -> Result<(String, Vec<String>), String> {
    let diff = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
        .map_err(|error| format!("git status: {error}"))?;
    if !diff.status.success() {
        return Err("git status failed".to_owned());
    }
    let status =
        String::from_utf8(diff.stdout).map_err(|_| "git status is not UTF-8".to_owned())?;
    let mut ignored_user_untracked = Vec::new();
    for line in status.lines() {
        if line == "?? docs/conversation-notes-vllm-gpt-oss.md" {
            ignored_user_untracked.push(line[3..].to_owned());
        } else {
            return Err(format!("record mode requires a clean tracked tree; found {line}"));
        }
    }
    let sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("git rev-parse: {error}"))?;
    if !sha.status.success() {
        return Err("git rev-parse failed".to_owned());
    }
    let sha = String::from_utf8(sha.stdout).map_err(|_| "git SHA is not UTF-8".to_owned())?;
    Ok((sha.trim().to_owned(), ignored_user_untracked))
}

fn unix_time_s() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))
        .map(|duration| duration.as_secs())
}

fn parse_golden_tokens(bytes: &[u8]) -> Result<Vec<u32>, String> {
    if bytes.len() != GOLDEN_P6_BYTES || &bytes[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6 has wrong canonical framing".to_owned());
    }
    let prompt = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let decode = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if (prompt, decode) != (GPT2_PROMPT_TOKENS, GPT2_DECODE_TOKENS) {
        return Err("golden-p6 has wrong canonical geometry".to_owned());
    }
    Ok((0..GPT2_DECODE_TOKENS)
        .map(|index| {
            let offset = GOLDEN_P6_HEADER_BYTES + 4 * index;
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        })
        .collect())
}

struct Workload {
    model: Gpt2Model,
    prefill: volta_gpt2::ModelWitness,
    band: volta_gpt2::BandModelWitness,
    sequence: Vec<u32>,
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
    let golden = parse_golden_tokens(
        &fs::read(weights.join("golden-p6.bin"))
            .map_err(|error| format!("read golden-p6: {error}"))?,
    )?;
    if generated != golden {
        return Err("C6 census decode differs from frozen golden-p6".to_owned());
    }
    let mut sequence = model.p.tokens[..GPT2_PROMPT_TOKENS].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let band = band_model_witness(&model, &full, GPT2_PROMPT_TOKENS);
    Ok(Workload { model, prefill, band, sequence })
}

fn reconcile_transcript_ledger(
    expected: &BTreeMap<&'static str, u64>,
    verifier: &mut Transcript,
) -> Result<(), String> {
    for (&label, &verifier_bytes) in verifier.ledger() {
        if verifier_bytes > expected.get(label).copied().unwrap_or(0) {
            return Err(format!("verifier transcript exceeds prover at {label}"));
        }
    }
    let missing = expected
        .iter()
        .filter_map(|(&label, &prover_bytes)| {
            let verifier_bytes = verifier.ledger().get(label).copied().unwrap_or(0);
            (prover_bytes > verifier_bytes).then_some((label, prover_bytes - verifier_bytes))
        })
        .collect::<Vec<_>>();
    for (label, bytes) in missing {
        verifier.append(label, bytes);
    }
    if expected != verifier.ledger() {
        return Err("model transcript replay did not reconcile".to_owned());
    }
    Ok(())
}

fn model_full_correction_bytes(tx: &Transcript) -> Result<u64, String> {
    let mut bytes = 0u64;
    for (&label, &count) in tx.ledger() {
        match label {
            "auth_corrections" | "prod_check_m0_m1" => {}
            "t1_eq_claim_pair" if count == 0 => {}
            _ if label.contains("correction") => {
                bytes = bytes
                    .checked_add(count)
                    .ok_or_else(|| "full correction byte count overflows".to_owned())?;
            }
            _ => return Err(format!("unclassified non-correction T1 transcript label {label}")),
        }
    }
    Ok(bytes)
}

#[derive(Serialize)]
struct CounterRow {
    sub_correlations: u64,
    full_correlations: u64,
    domains: u64,
}

impl From<volta_mac::CorrCounters> for CounterRow {
    fn from(value: volta_mac::CorrCounters) -> Self {
        Self {
            sub_correlations: value.sub_corrs,
            full_correlations: value.full_corrs,
            domains: value.domains,
        }
    }
}

#[derive(Serialize)]
struct CapacityRow {
    leaf_aligned_slots: u64,
    closure_workspace_live_upper_bound: u64,
    slot_entries: u64,
    total_padded_entries: u64,
    total_live_upper_bound: u64,
    padded_headroom: u64,
}

#[derive(Serialize)]
struct SubfieldWitnessRow {
    reference_only: bool,
    pcg_backend: String,
    second_coordinate_model_rerun: bool,
    leaf_count: u64,
    hidden_correction_bytes_per_coordinate: u64,
    secret_witness_bytes_per_coordinate: u64,
    plaintext_digest: String,
    coordinate_witness_digests: [String; 2],
    coordinate_correction_digests: [String; 2],
    pair_digest: String,
}

#[derive(Serialize)]
struct SourceWitnessRow {
    reference_only: bool,
    pcg_backend: String,
    second_coordinate_model_rerun: bool,
    product_masks_independent_between_coordinates: bool,
    tape_ids: [String; 2],
    subfield_leaf_count: u64,
    direct_fullfield_leaf_count: u64,
    product_mask_leaf_count: u64,
    fullfield_leaf_count: u64,
    hidden_subfield_correction_bytes_per_coordinate: u64,
    hidden_direct_fullfield_correction_bytes_per_coordinate: u64,
    secret_subfield_witness_bytes_per_coordinate: u64,
    secret_fullfield_witness_bytes_per_coordinate: u64,
    subfield_plaintext_digest: String,
    direct_fullfield_plaintext_digest: String,
    coordinate_fullfield_plaintext_digests: [String; 2],
    coordinate_subfield_witness_digests: [String; 2],
    coordinate_fullfield_witness_digests: [String; 2],
    coordinate_subfield_correction_digests: [String; 2],
    coordinate_fullfield_correction_digests: [String; 2],
    pair_digest: String,
}

#[derive(Serialize)]
struct Record {
    schema: u64,
    milestone: String,
    created_unix_s: u64,
    git_sha: String,
    git_dirty: bool,
    ignored_user_untracked_paths: Vec<String>,
    diagnostic: bool,
    pod_contacted: bool,
    prompt_tokens: usize,
    decode_tokens: usize,
    transcript_seed_byte: u8,
    golden_match: bool,
    prover_verifier_schedule_equal: bool,
    model_counters: CounterRow,
    total_counters: CounterRow,
    model_draw_count: u64,
    direct_subfield_leaves: u64,
    direct_fullfield_leaves: u64,
    direct_correction_leaves: u64,
    product_mask_leaves: u64,
    total_leaves: u64,
    local_product_closures: u64,
    total_product_closures: u64,
    final_product_triples: u64,
    total_product_triples: u64,
    zero_closures: u64,
    model_transcript_bytes: u64,
    complete_mac_transcript_bytes: u64,
    model_sub_correction_bytes: u64,
    model_full_correction_bytes: u64,
    model_product_message_bytes: u64,
    other_model_transcript_bytes: u64,
    model_raw_correlations: u64,
    complete_mac_raw_correlations: u64,
    reserved_raw_correlations: u64,
    old_pcs_raw_reserve: u64,
    model_allocation_schedule_digest: String,
    allocation_schedule_digest: String,
    source_schedule_digest: String,
    correction_schedule_digest: String,
    model_transcript_ledger: BTreeMap<String, u64>,
    residual_capacity: CapacityRow,
    #[serde(skip_serializing_if = "Option::is_none")]
    subfield_witness: Option<SubfieldWitnessRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_witness: Option<SourceWitnessRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_trace: Option<OperationTraceRow>,
    source_sha256: BTreeMap<String, String>,
    all_pass: bool,
}

#[derive(Serialize)]
struct OperationTraceRow {
    diagnostic_only: bool,
    independent_verifier_trace_pending: bool,
    program_identity_equal: bool,
    parameterized_topology_identity_equal: bool,
    parameterized_instance_identity_equal: bool,
    source_count: u64,
    canonical_plan_version: u32,
    canonical_node_count: u64,
    prover_raw_operation_count: u64,
    verifier_raw_operation_count: u64,
    prover_reachable_operation_count: u64,
    verifier_reachable_operation_count: u64,
    prover_omitted_operation_count: u64,
    verifier_omitted_operation_count: u64,
    product_closures: u64,
    product_triples: u64,
    zero_roots: u64,
    program_digest: String,
    public_input_count: u64,
    scalar_input_count: u64,
    topology_digest: String,
    instance_digest: String,
    product_phase_node_count: u64,
    node_kinds: OperationNodeKindRow,
    candidate_encoding: OperationPlanEncodingRow,
    specialized_encoding_projection: OperationPlanSpecializedEncodingRow,
    instance_extraction: OperationInstanceExtractionRow,
}

#[derive(Serialize)]
struct OperationNodeKindRow {
    source: u64,
    structural_zero: u64,
    public_input: u64,
    add: u64,
    sub: u64,
    scale: u64,
}

#[derive(Serialize)]
struct OperationPlanEncodingRow {
    materialized_artifact: bool,
    production_decoder_implemented: bool,
    setup_fit_credit: bool,
    header_bytes: u64,
    packed_opcode_bytes: u64,
    source_payload_bytes: u64,
    linear_operand_payload_bytes: u64,
    terminal_payload_bytes: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
struct OperationPlanSpecializedEncodingRow {
    materialized_artifact: bool,
    production_decoder_implemented: bool,
    setup_fit_credit: bool,
    prover_verifier_artifact_equal: bool,
    decoder_roundtrip: bool,
    artifact_digest: String,
    first_exchange_bytes_with_artifact: u64,
    first_exchange_cap_bytes: u64,
    first_exchange_headroom_bytes: u64,
    header_bytes: u64,
    packed_opcode_bytes: u64,
    source_delta_payload_bytes: u64,
    operand_unit_flag_bytes: u64,
    nonunit_operand_payload_bytes: u64,
    terminal_payload_bytes: u64,
    total_bytes: u64,
    source_successor_count: u64,
    operand_count: u64,
    unit_operand_count: u64,
}

#[derive(Serialize)]
struct OperationInstanceExtractionRow {
    materialized_artifacts: bool,
    ordinary_decoder_implemented: bool,
    instance_digest_reconstructed: bool,
    verifier_map_counted_in_client_setup: bool,
    first_exchange_bytes_with_client_artifacts: u64,
    first_exchange_cap_bytes: u64,
    first_exchange_headroom_bytes: u64,
    prover: OperationInstanceExtractionRoleRow,
    verifier: OperationInstanceExtractionRoleRow,
    runtime_capture: OperationRuntimeInstanceCaptureRow,
}

#[derive(Serialize)]
struct OperationInstanceExtractionRoleRow {
    role: &'static str,
    artifact_digest: String,
    raw_public_input_count: u64,
    raw_scalar_input_count: u64,
    canonical_public_input_count: u64,
    canonical_scalar_input_count: u64,
    public_run_count: u64,
    scalar_run_count: u64,
    header_bytes: u64,
    public_map_bytes: u64,
    scalar_map_bytes: u64,
    total_bytes: u64,
    map_digest: String,
}

#[derive(Serialize)]
struct OperationRuntimeInstanceCaptureRow {
    recorder_implemented_in_ordinary_build: bool,
    same_pass_diagnostic_capture: bool,
    timing_credit: bool,
    prover: OperationRuntimeInstanceCaptureRoleRow,
    verifier: OperationRuntimeInstanceCaptureRoleRow,
}

#[derive(Serialize)]
struct OperationRuntimeInstanceCaptureRoleRow {
    role: &'static str,
    raw_public_input_count: u64,
    raw_scalar_input_count: u64,
    reconstructed_instance_digest: String,
}

fn run(args: &Args) -> Result<Record, String> {
    let (git_sha, ignored_user_untracked_paths, git_dirty) = if args.diagnostic {
        let sha = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|error| format!("git rev-parse: {error}"))?;
        (
            String::from_utf8(sha.stdout)
                .map_err(|_| "git SHA is not UTF-8".to_owned())?
                .trim()
                .to_owned(),
            Vec::new(),
            true,
        )
    } else {
        let (sha, ignored) = git_sha_and_tracked_clean()?;
        (sha, ignored, false)
    };

    let workload = workload(&args.weights)?;
    let chunks = [ChunkRef { band: &workload.band, seq: &workload.sequence }];
    let public = [PrivateChunkPub { q: workload.band.q, seq: &workload.sequence }];
    let mut prover = CorrelationStream::new([0x42; 32]);
    let mut verifier =
        VerifierCtx::new([0x42; 32], Fp2::new(Fp::new(0xD31C_5A17), Fp::new(0x0BAD_CAFE)));
    let collect_source_witness = args.source_witness || args.operation_trace;
    let prover_runtime_instance_capture = if args.operation_trace {
        begin_c6_prover_trace().map_err(|error| error.to_string())?;
        prover.enable_c6_operation_trace()?;
        Some(
            begin_c6_runtime_instance_capture_diagnostic(C6InstanceExtractionRole::Prover)
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    if collect_source_witness {
        prover.enable_c6_source_witness_collection()?;
    } else if args.subfield_witness {
        prover.enable_c6_subfield_witness_collection()?;
    } else {
        prover.enable_schedule_audit()?;
    }
    verifier.enable_schedule_audit()?;
    let mut prover_tx = Transcript::new([args.transcript_seed_byte; 32]);
    let mut verifier_tx = Transcript::new([args.transcript_seed_byte; 32]);

    let (proof, output, prod, zero) = prove_response_private_logits(
        &workload.model,
        &workload.prefill,
        &chunks,
        &mut prover,
        &mut prover_tx,
    );
    let model_counters = output.corr_counters;
    let model_schedule =
        prover.schedule_audit().ok_or_else(|| "missing prover model schedule audit".to_owned())?;
    let model_draw_count = model_schedule.draws.len();
    let model_allocation_schedule_digest = hex(&model_schedule.digest);
    let model_transcript_bytes = prover_tx.total_bytes();
    let model_sub_correction_bytes = prover_tx.bytes_for("auth_corrections");
    let model_product_message_bytes = prover_tx.bytes_for("prod_check_m0_m1");
    let model_full_correction_bytes = model_full_correction_bytes(&prover_tx)?;
    let model_transcript_prefix = prover_tx.ledger().clone();
    let model_transcript_ledger =
        prover_tx.ledger().iter().map(|(&label, &bytes)| (label.to_owned(), bytes)).collect();

    if model_allocation_schedule_digest != C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX {
        return Err(format!(
            "C6 model allocation schedule digest changed: expected {}, got {}",
            C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX, model_allocation_schedule_digest
        ));
    }

    let mut prover_doms = Doms::new(layer_dom_base(255));
    let challenge = prover_tx.challenge_fp2();
    let product_mask_domain = prover_doms.take(1);
    let product_mask = prover.draw_product_mask(product_mask_domain, prod.len());
    let product_proof = prod_batch_prover(&prod, challenge, product_mask, &mut prover_tx);
    let product_triples = prod.len();
    drop(prod);

    let zero_mask_domain = prover_doms.take(1);
    let zero_corr = prover.draw_fulls(zero_mask_domain, 1)[0];
    prover.record_c6_fullfield_plaintexts(zero_mask_domain, &[Fp2::ZERO])?;
    let (zero_mask, zero_mask_correction) = fresh_zero_mask(zero_corr, &mut prover_tx);
    let zero_challenge = prover_tx.challenge_fp2();
    let zero_opened_tag = zero_batch_prover(&zero, &zero_mask, zero_challenge, &mut prover_tx);
    let zero_closures = zero.len();
    drop(zero);

    let raw_prover_trace = if args.operation_trace {
        Some(finish_c6_prover_trace().map_err(|error| error.to_string())?)
    } else {
        None
    };

    let prover_schedule =
        prover.schedule_audit().ok_or_else(|| "missing closed prover audit".to_owned())?;
    let expected_census = audit_c6_t1_source_census(C6T1CensusInput {
        prover_schedule: &prover_schedule,
        verifier_schedule: &prover_schedule,
        model_draw_count,
        model_counters,
        model_transcript_bytes,
        model_sub_correction_bytes,
        model_full_correction_bytes,
        product_mask_domain,
        zero_mask_domain,
        product_triples,
        zero_closures,
    })
    .map_err(|error| error.to_string())?;
    let trace_manifest = if args.operation_trace {
        Some(
            c6_t1_trace_source_manifest(&prover_schedule, &expected_census)
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    let (prover_plan, prover_artifact, prover_instance_extraction, prover_runtime_instance) =
        match (raw_prover_trace, prover_runtime_instance_capture) {
            (Some(trace), Some(runtime_capture)) => {
                let manifest = trace_manifest
                    .as_ref()
                    .ok_or_else(|| "missing C6 trace manifest".to_owned())?;
                match args.operation_trace_debug_block {
                    Some(block) => {
                        let plan =
                            normalize_c6_operation_trace_debug_block(&trace, manifest, block)
                                .map_err(|error| {
                                    format!("C6 prover operation-plan normalization: {error}")
                                })?;
                        drop(runtime_capture);
                        (Some(plan), None, None, None)
                    }
                    None => {
                        let compiled = compile_c6_operation_trace_for_role(
                            &trace,
                            manifest,
                            C6InstanceExtractionRole::Prover,
                        )
                        .map_err(|error| {
                            format!("C6 prover operation-plan compilation: {error}")
                        })?;
                        let decoded = compiled
                            .artifact
                            .decode(manifest)
                            .map_err(|error| format!("C6 prover plan artifact decode: {error}"))?;
                        if decoded.topology != compiled.plan.topology
                            || decoded.node_kinds != compiled.plan.diagnostics.node_kinds
                            || decoded.product_phase_node_count
                                != compiled.plan.diagnostics.product_phase_node_count
                            || decoded.encoding
                                != compiled.plan.diagnostics.specialized_encoding_projection
                        {
                            return Err(
                                "C6 prover plan artifact roundtrip differs from compilation"
                                    .to_owned(),
                            );
                        }
                        let extraction = compiled
                            .instance_extraction
                            .decode(compiled.plan.topology)
                            .map_err(|error| {
                                format!("C6 prover instance-extraction artifact decode: {error}")
                            })?;
                        if extraction.role() != C6InstanceExtractionRole::Prover {
                            return Err("C6 prover instance-extraction role changed".to_owned());
                        }
                        let runtime =
                            runtime_capture.finish(&compiled.artifact, &extraction).map_err(
                                |error| format!("C6 prover runtime instance extraction: {error}"),
                            )?;
                        if runtime.instance_identity() != compiled.plan.instance {
                            return Err(
                            "C6 prover runtime recorder changed the canonical instance identity"
                                .to_owned(),
                        );
                        }
                        let runtime_row = OperationRuntimeInstanceCaptureRoleRow {
                            role: "prover",
                            raw_public_input_count: u64::try_from(runtime.raw_public_input_count())
                                .map_err(|_| {
                                    "C6 prover runtime public count exceeds u64".to_owned()
                                })?,
                            raw_scalar_input_count: u64::try_from(runtime.raw_scalar_input_count())
                                .map_err(|_| {
                                    "C6 prover runtime scalar count exceeds u64".to_owned()
                                })?,
                            reconstructed_instance_digest: hex(&runtime
                                .instance_identity()
                                .instance_digest),
                        };
                        (
                            Some(compiled.plan),
                            Some(compiled.artifact),
                            Some(compiled.instance_extraction),
                            Some(runtime_row),
                        )
                    }
                }
            }
            (None, None) => (None, None, None, None),
            _ => return Err("C6 prover trace/runtime-capture lifecycle is asymmetric".to_owned()),
        };

    let verifier_runtime_instance_capture = if args.operation_trace {
        begin_c6_verifier_trace().map_err(|error| error.to_string())?;
        verifier.enable_c6_operation_trace()?;
        Some(
            begin_c6_runtime_instance_capture_diagnostic(C6InstanceExtractionRole::Verifier)
                .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    let (_, kprod, kzero) = verify_response_private_logits(
        &workload.model,
        workload.prefill.t,
        &public,
        &proof,
        &mut verifier,
        &mut verifier_tx,
    )
    .ok_or_else(|| "C6 census model verifier rejected".to_owned())?;
    reconcile_transcript_ledger(&model_transcript_prefix, &mut verifier_tx)?;
    let verifier_model_schedule = verifier
        .schedule_audit()
        .ok_or_else(|| "missing verifier model schedule audit".to_owned())?;
    if model_schedule != verifier_model_schedule {
        return Err("C6 model prover/verifier schedules differ".to_owned());
    }

    let mut verifier_doms = Doms::new(layer_dom_base(255));
    if challenge != verifier_tx.challenge_fp2() {
        return Err("C6 closure challenge mismatch".to_owned());
    }
    if product_mask_domain != verifier_doms.take(1) {
        return Err("C6 product-mask domain mismatch".to_owned());
    }
    let product_key = verifier.expand_product_mask_verifier_key(product_mask_domain, kprod.len());
    verifier_tx.append("prod_check_m0_m1", 32);
    if !prod_batch_verify(&kprod, product_key, verifier.delta, challenge, &product_proof) {
        return Err("C6 census ProductClosure rejected".to_owned());
    }
    if zero_mask_domain != verifier_doms.take(1) {
        return Err("C6 zero-mask domain mismatch".to_owned());
    }
    let zero_full_key = verifier.expand_full_verifier_keys(zero_mask_domain, 1)[0];
    verifier_tx.append("mask_correction", 16);
    let zero_key = zero_mask_key(&verifier, zero_full_key, zero_mask_correction);
    if zero_challenge != verifier_tx.challenge_fp2() {
        return Err("C6 ZeroBatch challenge mismatch".to_owned());
    }
    verifier_tx.append("zero_batch_tag", 16);
    if !zero_batch_verify(&kzero, zero_key, zero_challenge, zero_opened_tag) {
        return Err("C6 census ZeroBatch rejected".to_owned());
    }
    if prover_tx.total_bytes() != verifier_tx.total_bytes()
        || prover_tx.ledger() != verifier_tx.ledger()
    {
        return Err("C6 closed transcripts differ".to_owned());
    }

    let raw_verifier_trace = if args.operation_trace {
        Some(finish_c6_verifier_trace().map_err(|error| error.to_string())?)
    } else {
        None
    };
    let verifier_schedule =
        verifier.schedule_audit().ok_or_else(|| "missing closed verifier audit".to_owned())?;
    let census = audit_c6_t1_source_census(C6T1CensusInput {
        prover_schedule: &prover_schedule,
        verifier_schedule: &verifier_schedule,
        model_draw_count,
        model_counters,
        model_transcript_bytes,
        model_sub_correction_bytes,
        model_full_correction_bytes,
        product_mask_domain,
        zero_mask_domain,
        product_triples,
        zero_closures,
    })
    .map_err(|error| error.to_string())?;
    if census != expected_census {
        return Err("C6 independent verifier changed the accepted source census".to_owned());
    }

    let operation_trace = match (
        prover_plan,
        prover_artifact,
        prover_instance_extraction,
        prover_runtime_instance,
        raw_verifier_trace,
        verifier_runtime_instance_capture,
    ) {
        (
            Some(prover_plan),
            prover_artifact,
            prover_instance_extraction,
            prover_runtime_instance,
            Some(verifier_trace),
            Some(verifier_runtime_capture),
        ) => {
            let accepted_manifest = c6_t1_trace_source_manifest(&prover_schedule, &census)
                .map_err(|error| error.to_string())?;
            if trace_manifest.as_ref() != Some(&accepted_manifest) {
                return Err("C6 trace manifest changed after independent verification".to_owned());
            }
            let (
                verifier_plan,
                verifier_artifact,
                verifier_instance_extraction,
                verifier_runtime_instance,
            ) = match args.operation_trace_debug_block {
                Some(block) => {
                    let plan = normalize_c6_operation_trace_debug_block(
                        &verifier_trace,
                        &accepted_manifest,
                        block,
                    )
                    .map_err(|error| {
                        format!("C6 verifier operation-plan normalization: {error}")
                    })?;
                    drop(verifier_runtime_capture);
                    (plan, None, None, None)
                }
                None => {
                    let compiled = compile_c6_operation_trace_for_role(
                        &verifier_trace,
                        &accepted_manifest,
                        C6InstanceExtractionRole::Verifier,
                    )
                    .map_err(|error| format!("C6 verifier operation-plan compilation: {error}"))?;
                    let decoded = compiled
                        .artifact
                        .decode(&accepted_manifest)
                        .map_err(|error| format!("C6 verifier plan artifact decode: {error}"))?;
                    if decoded.topology != compiled.plan.topology
                        || decoded.node_kinds != compiled.plan.diagnostics.node_kinds
                        || decoded.product_phase_node_count
                            != compiled.plan.diagnostics.product_phase_node_count
                        || decoded.encoding
                            != compiled.plan.diagnostics.specialized_encoding_projection
                    {
                        return Err("C6 verifier plan artifact roundtrip differs from compilation"
                            .to_owned());
                    }
                    let extraction = compiled
                        .instance_extraction
                        .decode(compiled.plan.topology)
                        .map_err(|error| {
                            format!("C6 verifier instance-extraction artifact decode: {error}")
                        })?;
                    if extraction.role() != C6InstanceExtractionRole::Verifier {
                        return Err("C6 verifier instance-extraction role changed".to_owned());
                    }
                    let runtime =
                        verifier_runtime_capture.finish(&compiled.artifact, &extraction).map_err(
                            |error| format!("C6 verifier runtime instance extraction: {error}"),
                        )?;
                    if runtime.instance_identity() != compiled.plan.instance {
                        return Err(
                            "C6 verifier runtime recorder changed the canonical instance identity"
                                .to_owned(),
                        );
                    }
                    let runtime_row = OperationRuntimeInstanceCaptureRoleRow {
                        role: "verifier",
                        raw_public_input_count: u64::try_from(runtime.raw_public_input_count())
                            .map_err(|_| {
                                "C6 verifier runtime public count exceeds u64".to_owned()
                            })?,
                        raw_scalar_input_count: u64::try_from(runtime.raw_scalar_input_count())
                            .map_err(|_| {
                                "C6 verifier runtime scalar count exceeds u64".to_owned()
                            })?,
                        reconstructed_instance_digest: hex(&runtime
                            .instance_identity()
                            .instance_digest),
                    };
                    (
                        compiled.plan,
                        Some(compiled.artifact),
                        Some(compiled.instance_extraction),
                        Some(runtime_row),
                    )
                }
            };
            let identity = prover_plan.identity;
            let topology = prover_plan.topology;
            let instance = prover_plan.instance;
            if identity != verifier_plan.identity
                || topology != verifier_plan.topology
                || instance != verifier_plan.instance
            {
                let prover_blocks = &prover_plan.diagnostics.canonical_node_block_digests;
                let verifier_blocks = &verifier_plan.diagnostics.canonical_node_block_digests;
                let first_block_mismatch = prover_blocks
                    .iter()
                    .zip(verifier_blocks)
                    .position(|(prover, verifier)| prover != verifier)
                    .or_else(|| {
                        (prover_blocks.len() != verifier_blocks.len())
                            .then_some(prover_blocks.len().min(verifier_blocks.len()))
                    });
                return Err(format!(
                    "C6 prover/verifier canonical program identity differs: exact={}/{}, topology={}/{}, instance={}/{}; canonical_nodes={}/{}, raw_ops={}/{}, reachable_ops={}/{}, first_64_node_block_mismatch={:?}, node_digests={}/{}, root_digests={}/{}, captured_prover={:?}, captured_verifier={:?}",
                    hex(&identity.program_digest),
                    hex(&verifier_plan.identity.program_digest),
                    hex(&topology.topology_digest),
                    hex(&verifier_plan.topology.topology_digest),
                    hex(&instance.instance_digest),
                    hex(&verifier_plan.instance.instance_digest),
                    identity.canonical_node_count,
                    verifier_plan.identity.canonical_node_count,
                    prover_plan.diagnostics.raw_operation_count,
                    verifier_plan.diagnostics.raw_operation_count,
                    prover_plan.diagnostics.reachable_operation_count,
                    verifier_plan.diagnostics.reachable_operation_count,
                    first_block_mismatch,
                    hex(&prover_plan.diagnostics.node_digest),
                    hex(&verifier_plan.diagnostics.node_digest),
                    hex(&prover_plan.diagnostics.root_digest),
                    hex(&verifier_plan.diagnostics.root_digest),
                    prover_plan.diagnostics.captured_canonical_nodes,
                    verifier_plan.diagnostics.captured_canonical_nodes,
                ));
            }
            if prover_plan.diagnostics.node_kinds != verifier_plan.diagnostics.node_kinds
                || prover_plan.diagnostics.product_phase_node_count
                    != verifier_plan.diagnostics.product_phase_node_count
                || prover_plan.diagnostics.candidate_encoding
                    != verifier_plan.diagnostics.candidate_encoding
                || prover_plan.diagnostics.specialized_encoding_projection
                    != verifier_plan.diagnostics.specialized_encoding_projection
            {
                return Err(
                    "C6 prover/verifier parameterized plan census or encoding differs".to_owned()
                );
            }
            let (
                materialized_artifact,
                prover_verifier_artifact_equal,
                decoder_roundtrip,
                artifact_digest,
                plan_artifact_bytes,
                first_exchange_bytes_with_artifact,
                first_exchange_headroom_bytes,
            ) = match (prover_artifact.as_ref(), verifier_artifact.as_ref()) {
                (Some(prover), Some(verifier)) => {
                    if prover != verifier {
                        return Err("C6 prover/verifier canonical plan artifacts differ".to_owned());
                    }
                    let decoded = prover
                        .decode(&accepted_manifest)
                        .map_err(|error| format!("C6 accepted plan artifact decode: {error}"))?;
                    if decoded.topology != topology
                        || decoded.encoding
                            != prover_plan.diagnostics.specialized_encoding_projection
                    {
                        return Err(
                            "C6 accepted plan artifact differs from canonical identity".to_owned()
                        );
                    }
                    let artifact_bytes = u64::try_from(prover.len())
                        .map_err(|_| "C6 plan artifact length exceeds u64".to_owned())?;
                    let first_exchange = C6_PAIRED_PCG_SETUP_BYTES
                        .checked_add(C6_SETUP_MANIFEST_FIXED_BYTES)
                        .and_then(|bytes| bytes.checked_add(artifact_bytes))
                        .ok_or_else(|| "C6 first exchange with plan overflows".to_owned())?;
                    let headroom = C6_SETUP_CAP_BYTES.checked_sub(first_exchange).ok_or_else(|| {
                        format!(
                            "C6 materialized plan exceeds setup cap: {first_exchange} > {C6_SETUP_CAP_BYTES}"
                        )
                    })?;
                    (
                        true,
                        true,
                        true,
                        hex(blake3::hash(prover.as_bytes()).as_bytes()),
                        artifact_bytes,
                        first_exchange,
                        headroom,
                    )
                }
                (None, None) if args.operation_trace_debug_block.is_some() => {
                    (false, false, false, String::new(), 0, 0, 0)
                }
                _ => {
                    return Err(
                        "C6 prover/verifier plan artifact lifecycle is asymmetric".to_owned()
                    );
                }
            };
            let instance_extraction = match (
                prover_instance_extraction.as_ref(),
                verifier_instance_extraction.as_ref(),
                prover_runtime_instance,
                verifier_runtime_instance,
            ) {
                (Some(prover), Some(verifier), Some(prover_runtime), Some(verifier_runtime)) => {
                    let prover_decoded = prover.decode(topology).map_err(|error| {
                        format!("C6 accepted prover instance-extraction decode: {error}")
                    })?;
                    let verifier_decoded = verifier.decode(topology).map_err(|error| {
                        format!("C6 accepted verifier instance-extraction decode: {error}")
                    })?;
                    if prover_decoded.role() != C6InstanceExtractionRole::Prover
                        || verifier_decoded.role() != C6InstanceExtractionRole::Verifier
                        || prover_decoded.topology_digest() != topology.topology_digest
                        || verifier_decoded.topology_digest() != topology.topology_digest
                        || prover_decoded.census().canonical_public_input_count
                            != topology.public_input_count
                        || verifier_decoded.census().canonical_public_input_count
                            != topology.public_input_count
                        || prover_decoded.census().canonical_scalar_input_count
                            != topology.scalar_input_count
                        || verifier_decoded.census().canonical_scalar_input_count
                            != topology.scalar_input_count
                    {
                        return Err(
                            "C6 accepted instance-extraction artifact differs from topology"
                                .to_owned(),
                        );
                    }
                    let first_exchange = C6_PAIRED_PCG_SETUP_BYTES
                        .checked_add(C6_SETUP_MANIFEST_FIXED_BYTES)
                        .and_then(|bytes| bytes.checked_add(plan_artifact_bytes))
                        .and_then(|bytes| bytes.checked_add(verifier_decoded.census().total_bytes))
                        .ok_or_else(|| {
                            "C6 first exchange with instance extraction overflows".to_owned()
                        })?;
                    let headroom =
                        C6_SETUP_CAP_BYTES.checked_sub(first_exchange).ok_or_else(|| {
                            format!(
                                "C6 verifier instance extraction exceeds setup cap: {first_exchange} > {C6_SETUP_CAP_BYTES}"
                            )
                        })?;
                    let role_row = |role: &'static str,
                                    artifact: &volta_mac::C6InstanceExtractionArtifact,
                                    decoded: &volta_mac::C6DecodedInstanceExtractionPlan| {
                        let census = decoded.census();
                        OperationInstanceExtractionRoleRow {
                            role,
                            artifact_digest: hex(
                                blake3::hash(artifact.as_bytes()).as_bytes(),
                            ),
                            raw_public_input_count: u64::from(census.raw_public_input_count),
                            raw_scalar_input_count: u64::from(census.raw_scalar_input_count),
                            canonical_public_input_count: u64::from(
                                census.canonical_public_input_count,
                            ),
                            canonical_scalar_input_count: u64::from(
                                census.canonical_scalar_input_count,
                            ),
                            public_run_count: u64::from(census.public_run_count),
                            scalar_run_count: u64::from(census.scalar_run_count),
                            header_bytes: census.header_bytes,
                            public_map_bytes: census.public_map_bytes,
                            scalar_map_bytes: census.scalar_map_bytes,
                            total_bytes: census.total_bytes,
                            map_digest: hex(&census.map_digest),
                        }
                    };
                    OperationInstanceExtractionRow {
                        materialized_artifacts: true,
                        ordinary_decoder_implemented: true,
                        instance_digest_reconstructed: true,
                        verifier_map_counted_in_client_setup: true,
                        first_exchange_bytes_with_client_artifacts: first_exchange,
                        first_exchange_cap_bytes: C6_SETUP_CAP_BYTES,
                        first_exchange_headroom_bytes: headroom,
                        prover: role_row("prover", prover, &prover_decoded),
                        verifier: role_row("verifier", verifier, &verifier_decoded),
                        runtime_capture: OperationRuntimeInstanceCaptureRow {
                            recorder_implemented_in_ordinary_build: true,
                            same_pass_diagnostic_capture: true,
                            timing_credit: false,
                            prover: prover_runtime,
                            verifier: verifier_runtime,
                        },
                    }
                }
                (None, None, None, None) if args.operation_trace_debug_block.is_some() => {
                    let empty_role = |role| OperationInstanceExtractionRoleRow {
                        role,
                        artifact_digest: String::new(),
                        raw_public_input_count: 0,
                        raw_scalar_input_count: 0,
                        canonical_public_input_count: 0,
                        canonical_scalar_input_count: 0,
                        public_run_count: 0,
                        scalar_run_count: 0,
                        header_bytes: 0,
                        public_map_bytes: 0,
                        scalar_map_bytes: 0,
                        total_bytes: 0,
                        map_digest: String::new(),
                    };
                    OperationInstanceExtractionRow {
                        materialized_artifacts: false,
                        ordinary_decoder_implemented: true,
                        instance_digest_reconstructed: false,
                        verifier_map_counted_in_client_setup: false,
                        first_exchange_bytes_with_client_artifacts: 0,
                        first_exchange_cap_bytes: C6_SETUP_CAP_BYTES,
                        first_exchange_headroom_bytes: 0,
                        prover: empty_role("prover"),
                        verifier: empty_role("verifier"),
                        runtime_capture: OperationRuntimeInstanceCaptureRow {
                            recorder_implemented_in_ordinary_build: true,
                            same_pass_diagnostic_capture: false,
                            timing_credit: false,
                            prover: OperationRuntimeInstanceCaptureRoleRow {
                                role: "prover",
                                raw_public_input_count: 0,
                                raw_scalar_input_count: 0,
                                reconstructed_instance_digest: String::new(),
                            },
                            verifier: OperationRuntimeInstanceCaptureRoleRow {
                                role: "verifier",
                                raw_public_input_count: 0,
                                raw_scalar_input_count: 0,
                                reconstructed_instance_digest: String::new(),
                            },
                        },
                    }
                }
                _ => {
                    return Err(
                        "C6 prover/verifier instance-extraction lifecycle is asymmetric".to_owned()
                    );
                }
            };
            if u64::from(identity.source_count) != census.total_leaves
                || u64::from(identity.product_closure_count) != census.total_product_closures
                || identity.product_triple_count != census.total_product_triples
                || u64::from(identity.zero_root_count) != census.zero_closures
                || identity.source_schedule_digest != census.source_schedule_digest
            {
                return Err(format!(
                "C6 canonical operation-plan census changed: sources={}, closures={}, triples={}, zero_roots={}",
                identity.source_count,
                identity.product_closure_count,
                identity.product_triple_count,
                identity.zero_root_count
            ));
            }
            Some(OperationTraceRow {
                diagnostic_only: true,
                independent_verifier_trace_pending: false,
                program_identity_equal: true,
                parameterized_topology_identity_equal: true,
                parameterized_instance_identity_equal: true,
                source_count: u64::from(identity.source_count),
                canonical_plan_version: identity.version,
                canonical_node_count: u64::from(identity.canonical_node_count),
                prover_raw_operation_count: prover_plan.diagnostics.raw_operation_count,
                verifier_raw_operation_count: verifier_plan.diagnostics.raw_operation_count,
                prover_reachable_operation_count: prover_plan.diagnostics.reachable_operation_count,
                verifier_reachable_operation_count: verifier_plan
                    .diagnostics
                    .reachable_operation_count,
                prover_omitted_operation_count: prover_plan.diagnostics.omitted_operation_count,
                verifier_omitted_operation_count: verifier_plan.diagnostics.omitted_operation_count,
                product_closures: u64::from(identity.product_closure_count),
                product_triples: identity.product_triple_count,
                zero_roots: u64::from(identity.zero_root_count),
                program_digest: hex(&identity.program_digest),
                public_input_count: u64::from(topology.public_input_count),
                scalar_input_count: u64::from(topology.scalar_input_count),
                topology_digest: hex(&topology.topology_digest),
                instance_digest: hex(&instance.instance_digest),
                product_phase_node_count: prover_plan.diagnostics.product_phase_node_count,
                node_kinds: OperationNodeKindRow {
                    source: prover_plan.diagnostics.node_kinds.source,
                    structural_zero: prover_plan.diagnostics.node_kinds.structural_zero,
                    public_input: prover_plan.diagnostics.node_kinds.public_input,
                    add: prover_plan.diagnostics.node_kinds.add,
                    sub: prover_plan.diagnostics.node_kinds.sub,
                    scale: prover_plan.diagnostics.node_kinds.scale,
                },
                candidate_encoding: OperationPlanEncodingRow {
                    materialized_artifact: false,
                    production_decoder_implemented: false,
                    setup_fit_credit: false,
                    header_bytes: prover_plan.diagnostics.candidate_encoding.header_bytes,
                    packed_opcode_bytes: prover_plan
                        .diagnostics
                        .candidate_encoding
                        .packed_opcode_bytes,
                    source_payload_bytes: prover_plan
                        .diagnostics
                        .candidate_encoding
                        .source_payload_bytes,
                    linear_operand_payload_bytes: prover_plan
                        .diagnostics
                        .candidate_encoding
                        .linear_operand_payload_bytes,
                    terminal_payload_bytes: prover_plan
                        .diagnostics
                        .candidate_encoding
                        .terminal_payload_bytes,
                    total_bytes: prover_plan.diagnostics.candidate_encoding.total_bytes,
                },
                specialized_encoding_projection: OperationPlanSpecializedEncodingRow {
                    materialized_artifact,
                    production_decoder_implemented: true,
                    setup_fit_credit: materialized_artifact
                        && first_exchange_bytes_with_artifact <= C6_SETUP_CAP_BYTES,
                    prover_verifier_artifact_equal,
                    decoder_roundtrip,
                    artifact_digest,
                    first_exchange_bytes_with_artifact,
                    first_exchange_cap_bytes: C6_SETUP_CAP_BYTES,
                    first_exchange_headroom_bytes,
                    header_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .header_bytes,
                    packed_opcode_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .packed_opcode_bytes,
                    source_delta_payload_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .source_delta_payload_bytes,
                    operand_unit_flag_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .operand_unit_flag_bytes,
                    nonunit_operand_payload_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .nonunit_operand_payload_bytes,
                    terminal_payload_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .terminal_payload_bytes,
                    total_bytes: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .total_bytes,
                    source_successor_count: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .source_successor_count,
                    operand_count: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .operand_count,
                    unit_operand_count: prover_plan
                        .diagnostics
                        .specialized_encoding_projection
                        .unit_operand_count,
                },
                instance_extraction,
            })
        }
        (None, None, None, None, None, None) => None,
        _ => return Err("C6 prover/verifier trace lifecycle is asymmetric".to_owned()),
    };

    let subfield_witness = if args.subfield_witness {
        let primary = prover.finish_c6_subfield_witness_collection()?;
        let mut secondary = CorrelationStream::new([0x43; 32]);
        let secondary = replay_c6_subfield_coordinate(&primary, &prover_schedule, &mut secondary)
            .map_err(|error| error.to_string())?;
        let pair = C6PairedSubfieldWitness::new(
            [[0xC0; 32], [0xC1; 32]],
            [primary, secondary],
            &prover_schedule,
        )
        .map_err(|error| error.to_string())?;
        let coordinates = pair.coordinates();
        Some(SubfieldWitnessRow {
            reference_only: true,
            pcg_backend: "mock-chacha8-local-only".to_owned(),
            second_coordinate_model_rerun: false,
            leaf_count: pair.leaf_count() as u64,
            hidden_correction_bytes_per_coordinate: (pair.leaf_count() as u64)
                .checked_mul(8)
                .ok_or_else(|| "C6 subfield correction bytes overflow".to_owned())?,
            secret_witness_bytes_per_coordinate: (pair.leaf_count() as u64)
                .checked_mul(32)
                .ok_or_else(|| "C6 subfield witness bytes overflow".to_owned())?,
            plaintext_digest: hex(&pair.plaintext_digest()),
            coordinate_witness_digests: [
                hex(&coordinates[0].witness_digest),
                hex(&coordinates[1].witness_digest),
            ],
            coordinate_correction_digests: [
                hex(&coordinates[0].correction_digest),
                hex(&coordinates[1].correction_digest),
            ],
            pair_digest: hex(&pair.pair_digest()),
        })
    } else {
        None
    };

    let source_witness = if collect_source_witness {
        let primary_subfield = prover.finish_c6_subfield_witness_collection()?;
        let primary_fullfield = prover.finish_c6_fullfield_witness_collection()?;
        let primary =
            C6SourceCoordinate::new(primary_subfield, primary_fullfield, &prover_schedule)
                .map_err(|error| error.to_string())?;
        let mut secondary_stream = CorrelationStream::new([0x43; 32]);
        let secondary =
            replay_c6_source_coordinate(&primary, &prover_schedule, &mut secondary_stream)
                .map_err(|error| error.to_string())?;
        let pair = C6PairedSourceWitness::new(
            [[0xD0; 32], [0xD1; 32]],
            [primary, secondary],
            &prover_schedule,
        )
        .map_err(|error| error.to_string())?;
        let subfield_leaf_count = u64::try_from(pair.subfield_leaf_count())
            .map_err(|_| "C6 source subfield count exceeds u64".to_owned())?;
        let direct_fullfield_leaf_count = u64::try_from(pair.direct_fullfield_leaf_count())
            .map_err(|_| "C6 source direct full-field count exceeds u64".to_owned())?;
        let product_mask_leaf_count = u64::try_from(pair.product_mask_leaf_count())
            .map_err(|_| "C6 source ProductMask count exceeds u64".to_owned())?;
        let fullfield_leaf_count = u64::try_from(pair.fullfield_leaf_count())
            .map_err(|_| "C6 source full-field count exceeds u64".to_owned())?;
        if subfield_leaf_count != census.direct_subfield_leaves
            || direct_fullfield_leaf_count != census.direct_fullfield_leaves
            || product_mask_leaf_count != census.product_mask_leaves
            || fullfield_leaf_count
                != census
                    .direct_fullfield_leaves
                    .checked_add(census.product_mask_leaves)
                    .ok_or_else(|| "C6 census full-field count overflows".to_owned())?
        {
            return Err("C6 paired source witness leaf census changed".to_owned());
        }
        let coordinates = pair.coordinates();
        let tape_ids = pair.tape_ids();
        Some(SourceWitnessRow {
            reference_only: true,
            pcg_backend: "mock-chacha8-local-only".to_owned(),
            second_coordinate_model_rerun: false,
            product_masks_independent_between_coordinates: true,
            tape_ids: [hex(&tape_ids[0]), hex(&tape_ids[1])],
            subfield_leaf_count,
            direct_fullfield_leaf_count,
            product_mask_leaf_count,
            fullfield_leaf_count,
            hidden_subfield_correction_bytes_per_coordinate: subfield_leaf_count
                .checked_mul(8)
                .ok_or_else(|| "C6 source subfield correction bytes overflow".to_owned())?,
            hidden_direct_fullfield_correction_bytes_per_coordinate: direct_fullfield_leaf_count
                .checked_mul(16)
                .ok_or_else(|| "C6 source full-field correction bytes overflow".to_owned())?,
            secret_subfield_witness_bytes_per_coordinate: subfield_leaf_count
                .checked_mul(32)
                .ok_or_else(|| "C6 source subfield witness bytes overflow".to_owned())?,
            secret_fullfield_witness_bytes_per_coordinate: fullfield_leaf_count
                .checked_mul(48)
                .ok_or_else(|| "C6 source full-field witness bytes overflow".to_owned())?,
            subfield_plaintext_digest: hex(&coordinates[0].subfield().plaintext_digest),
            direct_fullfield_plaintext_digest: hex(&pair.direct_fullfield_plaintext_digest()),
            coordinate_fullfield_plaintext_digests: [
                hex(&coordinates[0].fullfield().plaintext_digest),
                hex(&coordinates[1].fullfield().plaintext_digest),
            ],
            coordinate_subfield_witness_digests: [
                hex(&coordinates[0].subfield().witness_digest),
                hex(&coordinates[1].subfield().witness_digest),
            ],
            coordinate_fullfield_witness_digests: [
                hex(&coordinates[0].fullfield().witness_digest),
                hex(&coordinates[1].fullfield().witness_digest),
            ],
            coordinate_subfield_correction_digests: [
                hex(&coordinates[0].subfield().correction_digest),
                hex(&coordinates[1].subfield().correction_digest),
            ],
            coordinate_fullfield_correction_digests: [
                hex(&coordinates[0].fullfield().correction_digest),
                hex(&coordinates[1].fullfield().correction_digest),
            ],
            pair_digest: hex(&pair.pair_digest()),
        })
    } else {
        None
    };

    if model_product_message_bytes != C6_T1_MODEL_PRODUCT_MESSAGE_BYTES
        || model_sub_correction_bytes != C6_T1_SUB_CORRECTION_BYTES
        || model_full_correction_bytes != C6_T1_FULL_CORRECTION_BYTES
        || census.local_product_closures != C6_T1_MODEL_LOCAL_PRODUCT_CLOSURES
        || census.total_product_triples
            != C6_T1_MODEL_LOCAL_PRODUCT_TRIPLES + C6_T1_FINAL_PRODUCT_TRIPLES
    {
        return Err("C6 census typed transcript reconciliation changed".to_owned());
    }
    let allocation_schedule_digest = hex(&census.allocation_schedule_digest);
    let source_schedule_digest = hex(&census.source_schedule_digest);
    let correction_schedule_digest = hex(&census.correction_schedule_digest);
    for (label, observed, expected) in [
        (
            "complete allocation",
            allocation_schedule_digest.as_str(),
            C6_T1_COMPLETE_ALLOCATION_SCHEDULE_DIGEST_HEX,
        ),
        ("source", source_schedule_digest.as_str(), C6_T1_SOURCE_SCHEDULE_DIGEST_HEX),
        ("correction", correction_schedule_digest.as_str(), C6_T1_CORRECTION_SCHEDULE_DIGEST_HEX),
    ] {
        if observed != expected {
            return Err(format!(
                "C6 {label} schedule digest changed: expected {expected}, got {observed}"
            ));
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut source_sha256 = BTreeMap::new();
    for relative in [
        "rust/volta-mac/src/corr.rs",
        "rust/volta-proto/src/prod_check.rs",
        "rust/volta-proto/src/c6_census.rs",
        "rust/volta-proto/src/c6_subfield.rs",
        "rust/volta-bench/src/bin/c6_t1_census_record.rs",
        "docs/c6-delta-residual-inline-design.md",
    ] {
        source_sha256.insert(relative.to_owned(), sha256(&root.join(relative))?);
    }
    if collect_source_witness {
        let relative = "rust/volta-proto/src/c6_source.rs";
        source_sha256.insert(relative.to_owned(), sha256(&root.join(relative))?);
    }
    if args.operation_trace {
        for relative in ["rust/volta-mac/src/c6_trace.rs", "rust/volta-mac/src/authed.rs"] {
            source_sha256.insert(relative.to_owned(), sha256(&root.join(relative))?);
        }
    }
    Ok(Record {
        schema: if args.operation_trace {
            10
        } else if args.source_witness {
            3
        } else if args.subfield_witness {
            2
        } else {
            1
        },
        milestone: if args.operation_trace {
            "C6-T1-runtime-instance-recorder".to_owned()
        } else if args.source_witness {
            "C6-T1-paired-source-witness-reference".to_owned()
        } else if args.subfield_witness {
            "C6-T1-paired-subfield-witness-reference".to_owned()
        } else {
            "C6-T1-production-source-census".to_owned()
        },
        created_unix_s: unix_time_s()?,
        git_sha,
        git_dirty,
        ignored_user_untracked_paths,
        diagnostic: args.diagnostic,
        pod_contacted: false,
        prompt_tokens: GPT2_PROMPT_TOKENS,
        decode_tokens: GPT2_DECODE_TOKENS,
        transcript_seed_byte: args.transcript_seed_byte,
        golden_match: true,
        prover_verifier_schedule_equal: prover_schedule == verifier_schedule,
        model_counters: census.model_counters.into(),
        total_counters: census.total_counters.into(),
        model_draw_count: census.model_draw_count,
        direct_subfield_leaves: census.direct_subfield_leaves,
        direct_fullfield_leaves: census.direct_fullfield_leaves,
        direct_correction_leaves: census.direct_correction_leaves,
        product_mask_leaves: census.product_mask_leaves,
        total_leaves: census.total_leaves,
        local_product_closures: census.local_product_closures,
        total_product_closures: census.total_product_closures,
        final_product_triples: census.final_product_triples,
        total_product_triples: census.total_product_triples,
        zero_closures: census.zero_closures,
        model_transcript_bytes: census.model_transcript_bytes,
        complete_mac_transcript_bytes: census.complete_mac_transcript_bytes,
        model_sub_correction_bytes: census.model_sub_correction_bytes,
        model_full_correction_bytes: census.model_full_correction_bytes,
        model_product_message_bytes: census.model_product_message_bytes,
        other_model_transcript_bytes: census.other_model_transcript_bytes,
        model_raw_correlations: census.model_raw_correlations,
        complete_mac_raw_correlations: census.complete_mac_raw_correlations,
        reserved_raw_correlations: census.reserved_raw_correlations,
        old_pcs_raw_reserve: census.old_pcs_raw_reserve,
        model_allocation_schedule_digest,
        allocation_schedule_digest,
        source_schedule_digest,
        correction_schedule_digest,
        model_transcript_ledger,
        residual_capacity: CapacityRow {
            leaf_aligned_slots: census.residual_capacity.leaf_aligned_slots,
            closure_workspace_live_upper_bound: census
                .residual_capacity
                .closure_workspace_live_upper_bound,
            slot_entries: census.residual_capacity.slot_entries,
            total_padded_entries: census.residual_capacity.total_padded_entries,
            total_live_upper_bound: census.residual_capacity.total_live_upper_bound,
            padded_headroom: census.residual_capacity.padded_headroom,
        },
        subfield_witness,
        source_witness,
        operation_trace,
        source_sha256,
        all_pass: true,
    })
}

fn write_append_only(path: &Path, record: &Record) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create append-only record {}: {error}", path.display()))?;
    let bytes =
        serde_json::to_vec_pretty(record).map_err(|error| format!("serialize record: {error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_data())
        .map_err(|error| format!("persist record {}: {error}", path.display()))
}

fn main() {
    let args = args().unwrap_or_else(|error| panic!("c6_t1_census_record arguments: {error}"));
    let record = run(&args).unwrap_or_else(|error| panic!("C6 T1 census HARD STOP: {error}"));
    if let Some(path) = &args.output {
        write_append_only(path, &record)
            .unwrap_or_else(|error| panic!("C6 T1 census record write failed: {error}"));
        eprintln!(
            "C6 T1 census PASS: leaves={} product_masks={} schedule={}",
            record.total_leaves, record.product_mask_leaves, record.allocation_schedule_digest
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&record).expect("serialize diagnostic"));
    }
}
