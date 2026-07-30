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
    begin_c6_prover_trace, finish_c6_prover_trace, zero_batch_exchange, CorrelationStream,
    Transcript, VerifierCtx,
};
use volta_proto::logup::Doms;
use volta_proto::{
    audit_c6_t1_source_census, layer_dom_base, prod_batch_prover, prod_batch_verify,
    prove_response_private_logits, replay_c6_source_coordinate, replay_c6_subfield_coordinate,
    verify_response_private_logits, C6PairedSourceWitness, C6PairedSubfieldWitness,
    C6SourceCoordinate, C6T1CensusInput, ChunkRef, PrivateChunkPub,
    C6_T1_COMPLETE_ALLOCATION_SCHEDULE_DIGEST_HEX, C6_T1_CORRECTION_SCHEDULE_DIGEST_HEX,
    C6_T1_FINAL_PRODUCT_TRIPLES, C6_T1_FULL_CORRECTION_BYTES,
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

struct Args {
    weights: PathBuf,
    output: Option<PathBuf>,
    diagnostic: bool,
    subfield_witness: bool,
    source_witness: bool,
    operation_trace: bool,
}

fn args() -> Result<Args, String> {
    let mut weights = PathBuf::from("../benchmarks/weights");
    let mut output = None;
    let mut diagnostic = false;
    let mut subfield_witness = false;
    let mut source_witness = false;
    let mut operation_trace = false;
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
    if operation_trace && !diagnostic {
        return Err(
            "--operation-trace is diagnostic-only until canonical DAG normalization closes"
                .to_owned(),
        );
    }
    Ok(Args { weights, output, diagnostic, subfield_witness, source_witness, operation_trace })
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

fn reconcile_transcripts(prover: &Transcript, verifier: &mut Transcript) -> Result<(), String> {
    for (&label, &verifier_bytes) in verifier.ledger() {
        if verifier_bytes > prover.ledger().get(label).copied().unwrap_or(0) {
            return Err(format!("verifier transcript exceeds prover at {label}"));
        }
    }
    let missing = prover
        .ledger()
        .iter()
        .filter_map(|(&label, &prover_bytes)| {
            let verifier_bytes = verifier.ledger().get(label).copied().unwrap_or(0);
            (prover_bytes > verifier_bytes).then_some((label, prover_bytes - verifier_bytes))
        })
        .collect::<Vec<_>>();
    for (label, bytes) in missing {
        verifier.append(label, bytes);
    }
    if prover.total_bytes() != verifier.total_bytes() || prover.ledger() != verifier.ledger() {
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
    source_count: u64,
    operation_node_count: u64,
    product_closures: u64,
    product_triples: u64,
    zero_roots: u64,
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
    if args.operation_trace {
        begin_c6_prover_trace().map_err(|error| error.to_string())?;
        prover.enable_c6_operation_trace()?;
    }
    if collect_source_witness {
        prover.enable_c6_source_witness_collection()?;
    } else if args.subfield_witness {
        prover.enable_c6_subfield_witness_collection()?;
    } else {
        prover.enable_schedule_audit()?;
    }
    verifier.enable_schedule_audit()?;
    let mut prover_tx = Transcript::new([0x18; 32]);
    let mut verifier_tx = Transcript::new([0x18; 32]);

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
    let model_transcript_ledger =
        prover_tx.ledger().iter().map(|(&label, &bytes)| (label.to_owned(), bytes)).collect();

    let (_, kprod, kzero) = verify_response_private_logits(
        &workload.model,
        workload.prefill.t,
        &public,
        &proof,
        &mut verifier,
        &mut verifier_tx,
    )
    .ok_or_else(|| "C6 census model verifier rejected".to_owned())?;
    reconcile_transcripts(&prover_tx, &mut verifier_tx)?;
    if prover.schedule_audit() != verifier.schedule_audit() {
        return Err("C6 model prover/verifier schedules differ".to_owned());
    }
    if model_allocation_schedule_digest != C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX {
        return Err(format!(
            "C6 model allocation schedule digest changed: expected {}, got {}",
            C6_T1_MODEL_ALLOCATION_SCHEDULE_DIGEST_HEX, model_allocation_schedule_digest
        ));
    }

    let mut prover_doms = Doms::new(layer_dom_base(255));
    let mut verifier_doms = Doms::new(layer_dom_base(255));
    let challenge = prover_tx.challenge_fp2();
    if challenge != verifier_tx.challenge_fp2() {
        return Err("C6 closure challenge mismatch".to_owned());
    }
    let product_mask_domain = prover_doms.take(1);
    if product_mask_domain != verifier_doms.take(1) {
        return Err("C6 product-mask domain mismatch".to_owned());
    }
    let product_mask = prover.draw_product_mask(product_mask_domain, prod.len());
    let product_key = verifier.expand_product_mask_key(product_mask_domain, kprod.len());
    let product_proof = prod_batch_prover(&prod, challenge, product_mask, &mut prover_tx);
    verifier_tx.append("prod_check_m0_m1", 32);
    if !prod_batch_verify(&kprod, product_key, verifier.delta, challenge, &product_proof) {
        return Err("C6 census ProductClosure rejected".to_owned());
    }
    let zero_mask_domain = prover_doms.take(1);
    if zero_mask_domain != verifier_doms.take(1) {
        return Err("C6 zero-mask domain mismatch".to_owned());
    }
    if !zero_batch_exchange(
        &zero,
        &kzero,
        &mut prover,
        &mut verifier,
        zero_mask_domain,
        &mut prover_tx,
    ) {
        return Err("C6 census ZeroBatch rejected".to_owned());
    }
    verifier_tx.append("mask_correction", 16);
    let _ = verifier_tx.challenge_fp2();
    verifier_tx.append("zero_batch_tag", 16);
    if prover_tx.total_bytes() != verifier_tx.total_bytes()
        || prover_tx.ledger() != verifier_tx.ledger()
    {
        return Err("C6 closed transcripts differ".to_owned());
    }

    let operation_trace = if args.operation_trace {
        let trace = finish_c6_prover_trace().map_err(|error| error.to_string())?;
        let product_triples = trace.products.iter().try_fold(0u64, |sum, closure| {
            sum.checked_add(
                u64::try_from(closure.triples.len())
                    .map_err(|_| "C6 operation-trace triple count exceeds u64".to_owned())?,
            )
            .ok_or_else(|| "C6 operation-trace triple count overflows".to_owned())
        })?;
        let source_count = u64::from(trace.source_count);
        let operation_node_count = u64::try_from(trace.nodes.len())
            .map_err(|_| "C6 operation-trace node count exceeds u64".to_owned())?;
        let product_closures = u64::try_from(trace.products.len())
            .map_err(|_| "C6 operation-trace closure count exceeds u64".to_owned())?;
        let zero_roots = u64::try_from(trace.zero_roots.len())
            .map_err(|_| "C6 operation-trace zero-root count exceeds u64".to_owned())?;
        if source_count != 4_975_525
            || product_closures != 673
            || product_triples != 22_339
            || zero_roots != 8_170
        {
            return Err(format!(
                "C6 operation-trace census changed: sources={source_count}, closures={product_closures}, triples={product_triples}, zero_roots={zero_roots}"
            ));
        }
        Some(OperationTraceRow {
            diagnostic_only: true,
            source_count,
            operation_node_count,
            product_closures,
            product_triples,
            zero_roots,
        })
    } else {
        None
    };

    let prover_schedule =
        prover.schedule_audit().ok_or_else(|| "missing closed prover audit".to_owned())?;
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
        product_triples: prod.len(),
        zero_closures: zero.len(),
    })
    .map_err(|error| error.to_string())?;

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
            4
        } else if args.source_witness {
            3
        } else if args.subfield_witness {
            2
        } else {
            1
        },
        milestone: if args.operation_trace {
            "C6-T1-operation-trace-diagnostic".to_owned()
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
