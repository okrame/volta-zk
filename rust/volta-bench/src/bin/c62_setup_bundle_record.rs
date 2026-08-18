//! Create the 17 exact-context operation-plan profiles used by C6.2.
//!
//! This is a local setup tool. It uses mock correlations only to compile the
//! response relation. It does not create a proof record or contact a pod.

use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use volta_field::{Fp, Fp2, FpStream};
use volta_gpt2::{
    band_model_witness, forward_model, forward_model_tokens, generate, load_model,
    Gpt2VerifierModel, KvCache, H, L,
};
use volta_mac::{
    begin_c6_prover_trace, begin_c6_verifier_trace,
    compile_c6_operation_trace_for_role_with_target_profile, finish_c6_prover_trace,
    finish_c6_verifier_trace, C6InstanceExtractionRole, C6NativeTargetProfileArtifact,
    C6TraceSourceManifest, CorrScheduleRole, CorrelationStream, Transcript,
    TranscriptChallengeChannel, TranscriptChallengeRequest, TranscriptChallengeResponse,
    VerifierCtx,
};
use volta_proto::c6_cache_fold::{
    begin_c6_cache_fold_trace, C6CacheFoldKind, C6CacheFoldParty, C6CacheFoldTargetInlineProver,
    C6CacheFoldTargetInlineVerifier, C6CacheFoldTargetPublicSchedule,
};
use volta_proto::c6_source::{C6SourceScheduleProverFollower, C6SourceScheduleVerifierFollower};
use volta_proto::logup::Doms;
use volta_proto::model_proof::{
    prove_response_continuation_private_logits_c6_cache_inline,
    verify_response_continuation_private_logits_c6_cache_inline_from_profile,
};
use volta_proto::{
    c62_retained_response_byte_census, c6_gpt2_native_target_profile, layer_dom_base,
    prod_batch_prover, prod_batch_verify, prove_response_private_logits_c6_cache_inline,
    verify_response_private_logits_c6_cache_inline_from_profile, ChunkRef, PrivateChunkPub,
    C6RetainedResponseProof,
    C62_CONTINUATION_1024_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_1024_RESPONSE_SUB_CORRELATIONS,
    C62_CONTINUATION_256_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_256_RESPONSE_SUB_CORRELATIONS,
    C62_CONTINUATION_512_RESPONSE_FULL_CORRELATIONS,
    C62_CONTINUATION_512_RESPONSE_SUB_CORRELATIONS,
    C62_GENESIS_RESPONSE_FULL_CORRELATIONS, C62_GENESIS_RESPONSE_SUB_CORRELATIONS,
};

const PROFILE_CONTEXTS: [usize; 17] =
    [0, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900];
const PLAN_MAX_BYTES: usize = 63_994_751;

struct CountingChallengeChannel {
    stream: FpStream,
    count: Arc<AtomicU64>,
}

impl CountingChallengeChannel {
    fn new(seed: [u8; 32], count: Arc<AtomicU64>) -> Self {
        Self { stream: FpStream::from_seed(seed), count }
    }
}

impl TranscriptChallengeChannel for CountingChallengeChannel {
    fn challenge(
        &mut self,
        _provider_move: Vec<u8>,
        _provider_semantic_bytes: usize,
        request: TranscriptChallengeRequest,
    ) -> Result<TranscriptChallengeResponse, String> {
        self.count.fetch_add(1, Ordering::Relaxed);
        Ok(match request {
            TranscriptChallengeRequest::Fp => {
                TranscriptChallengeResponse::Fp(self.stream.next_fp().value())
            }
            TranscriptChallengeRequest::Fp2 => {
                let value = self.stream.next_fp2();
                TranscriptChallengeResponse::Fp2([value.c0.value(), value.c1.value()])
            }
            TranscriptChallengeRequest::Bits(width) => {
                let value = self.stream.next_fp().value();
                TranscriptChallengeResponse::Bits(if width == 64 {
                    value
                } else {
                    value & ((1u64 << width) - 1)
                })
            }
        })
    }
}

#[derive(Serialize)]
struct FileRow {
    name: &'static str,
    bytes: u64,
    blake3: String,
}

#[derive(Serialize)]
struct SetupRecord {
    schema: u64,
    profile: &'static str,
    source_count: u32,
    source_schedule_digest: String,
    product_mask_sources: Vec<u32>,
    topology_digest: String,
    native_profile_digest: String,
    files: Vec<FileRow>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn parse_args(
) -> Result<(PathBuf, PathBuf, bool, bool, bool, bool, Option<usize>, Option<usize>), String> {
    let mut weights = None;
    let mut setup_root = None;
    let mut discover_topology = false;
    let mut fiat_shamir_census = false;
    let mut unbounded_challenge_census = false;
    let mut retained_byte_census = false;
    let mut resume_from = None;
    let mut stop_after = None;
    let mut values = std::env::args().skip(1);
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--weights" => {
                weights = Some(PathBuf::from(
                    values.next().ok_or_else(|| "--weights requires a path".to_owned())?,
                ));
            }
            "--setup-root" => {
                setup_root = Some(PathBuf::from(
                    values.next().ok_or_else(|| "--setup-root requires a path".to_owned())?,
                ));
            }
            "--discover-topology" => discover_topology = true,
            "--fiat-shamir-census" => fiat_shamir_census = true,
            "--unbounded-challenge-census" => unbounded_challenge_census = true,
            "--retained-byte-census" => retained_byte_census = true,
            "--resume-from" => {
                resume_from = Some(
                    values
                        .next()
                        .ok_or_else(|| "--resume-from requires a context".to_owned())?
                        .parse::<usize>()
                        .map_err(|_| "--resume-from is not a context".to_owned())?,
                );
            }
            "--stop-after" => {
                stop_after = Some(
                    values
                        .next()
                        .ok_or_else(|| "--stop-after requires a context".to_owned())?
                        .parse::<usize>()
                        .map_err(|_| "--stop-after is not a context".to_owned())?,
                );
            }
            _ => return Err(format!("unknown argument {argument}")),
        }
    }
    Ok((
        weights.ok_or_else(|| "--weights is required".to_owned())?,
        setup_root.ok_or_else(|| "--setup-root is required".to_owned())?,
        discover_topology,
        fiat_shamir_census,
        unbounded_challenge_census,
        retained_byte_census,
        resume_from,
        stop_after,
    ))
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("fsync {}: {error}", path.display()))
}

#[allow(clippy::too_many_arguments)]
fn write_profile(
    root: &Path,
    source_manifest: &C6TraceSourceManifest,
    topology_digest: [u8; 32],
    plan: &[u8],
    prover_extraction: &[u8],
    verifier_extraction: &[u8],
    native_profile: &[u8],
) -> Result<(), String> {
    fs::create_dir(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    let payloads = [
        ("operation-plan.bin", plan),
        ("prover-extraction.bin", prover_extraction),
        ("verifier-extraction.bin", verifier_extraction),
        ("native-target-profile.bin", native_profile),
    ];
    let mut files = Vec::with_capacity(payloads.len());
    for (name, bytes) in payloads {
        write_create_new(&root.join(name), bytes)?;
        files.push(FileRow {
            name,
            bytes: u64::try_from(bytes.len()).map_err(|_| format!("{name} length exceeds u64"))?,
            blake3: hex(blake3::hash(bytes).as_bytes()),
        });
    }
    let record = SetupRecord {
        schema: 1,
        profile: "C6.2-exact-context-installed-setup-v1",
        source_count: source_manifest.source_count,
        source_schedule_digest: hex(&source_manifest.source_schedule_digest),
        product_mask_sources: source_manifest.product_mask_sources.clone(),
        topology_digest: hex(&topology_digest),
        native_profile_digest: hex(blake3::hash(native_profile).as_bytes()),
        files,
    };
    let manifest = serde_json::to_vec_pretty(&record)
        .map_err(|error| format!("encode setup manifest: {error}"))?;
    write_create_new(&root.join("manifest.json"), &manifest)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync {}: {error}", root.display()))
}

fn expected_topology(old_context: usize) -> (u32, u32, u32, u32, u32, u64, u32) {
    match old_context {
        0 => (5_119_131, 17_894_474, 2_093, 6_458_502, 673, 29_620, 10_909),
        150 | 200 => (1_992_912, 7_082_024, 2_093, 2_599_883, 673, 27_073, 10_060),
        250..=450 if old_context % 50 == 0 => {
            (1_997_712, 7_104_920, 2_093, 2_611_091, 673, 27_361, 10_156)
        }
        500..=900 if old_context % 50 == 0 => {
            (2_002_704, 7_128_872, 2_093, 2_622_875, 673, 27_649, 10_252)
        }
        _ => unreachable!("profile table is fixed"),
    }
}

fn expected_correlations(old_context: usize) -> (u64, u64) {
    match old_context {
        0 => (
            C62_GENESIS_RESPONSE_SUB_CORRELATIONS as u64,
            C62_GENESIS_RESPONSE_FULL_CORRELATIONS as u64,
        ),
        150 | 200 => (
            C62_CONTINUATION_256_RESPONSE_SUB_CORRELATIONS as u64,
            C62_CONTINUATION_256_RESPONSE_FULL_CORRELATIONS as u64,
        ),
        250..=450 if old_context % 50 == 0 => (
            C62_CONTINUATION_512_RESPONSE_SUB_CORRELATIONS as u64,
            C62_CONTINUATION_512_RESPONSE_FULL_CORRELATIONS as u64,
        ),
        500..=900 if old_context % 50 == 0 => (
            C62_CONTINUATION_1024_RESPONSE_SUB_CORRELATIONS as u64,
            C62_CONTINUATION_1024_RESPONSE_FULL_CORRELATIONS as u64,
        ),
        _ => unreachable!("profile table is fixed"),
    }
}

fn compile_profile(
    model: &volta_gpt2::Gpt2Model,
    sequence: &[u32],
    old_context: usize,
    output: &Path,
    discover_topology: bool,
    fiat_shamir_census: bool,
    unbounded_challenge_census: bool,
    retained_byte_census: bool,
) -> Result<(), String> {
    let statement_digest = [0xA1; 32];
    let transcript_seed = [0xA2; 32];
    let primary_seed = [0xA3; 32];
    let secondary_seed = [0xA4; 32];
    let deltas =
        [Fp2::new(Fp::new(0xA501), Fp::new(0xA502)), Fp2::new(Fp::new(0xA601), Fp::new(0xA602))];
    let schedule = C6CacheFoldTargetPublicSchedule::new(
        (0..2 * L)
            .flat_map(|_| {
                std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                    .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
            })
            .collect(),
    )
    .map_err(|error| error.to_string())?;

    let mut primary = CorrelationStream::new(primary_seed);
    begin_c6_prover_trace().map_err(|error| error.to_string())?;
    primary.enable_c6_operation_trace().map_err(|error| error.to_string())?;
    primary.enable_c6_source_witness_collection().map_err(|error| error.to_string())?;
    let mut secondary = CorrelationStream::new(secondary_seed);
    let mut follower =
        C6SourceScheduleProverFollower::start(&mut secondary).map_err(|error| error.to_string())?;
    if fiat_shamir_census && unbounded_challenge_census {
        return Err("Fiat-Shamir and unbounded challenge censuses are mutually exclusive".into());
    }
    let prover_challenge_count = Arc::new(AtomicU64::new(0));
    let verifier_challenge_count = Arc::new(AtomicU64::new(0));
    let mut prover_tx = if fiat_shamir_census {
        Transcript::new_fiat_shamir(transcript_seed)?
    } else if unbounded_challenge_census {
        Transcript::new_interactive(Box::new(CountingChallengeChannel::new(
            transcript_seed,
            Arc::clone(&prover_challenge_count),
        )))
    } else {
        Transcript::new(transcript_seed)
    };
    let mut builder = C6CacheFoldTargetInlineProver::start_public(
        statement_digest,
        schedule.clone(),
        &mut prover_tx,
    )
    .map_err(|error| error.to_string())?;
    let cache_trace =
        begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).map_err(|error| error.to_string())?;
    let (proof, prover_out, products, zero_roots, _, _) = if old_context == 0 {
        let prefill = forward_model(model, 100);
        let full = forward_model_tokens(model, sequence);
        let decode = band_model_witness(model, &full, 100);
        prove_response_private_logits_c6_cache_inline(
            model,
            &prefill,
            &[ChunkRef { band: &decode, seq: sequence }],
            &mut primary,
            &mut secondary,
            &mut follower,
            &mut builder,
            &mut prover_tx,
        )
    } else {
        let first_full = forward_model_tokens(model, &sequence[..old_context + 25]);
        let full = forward_model_tokens(model, sequence);
        let first = band_model_witness(model, &first_full, old_context - 1);
        let second = band_model_witness(model, &full, old_context + 25);
        prove_response_continuation_private_logits_c6_cache_inline(
            model,
            &full,
            &first,
            &second,
            sequence,
            &mut primary,
            &mut secondary,
            &mut follower,
            &mut builder,
            &mut prover_tx,
        )
    };
    let cache_snapshot = cache_trace.finish().map_err(|error| error.to_string())?;
    let (frame, provider_fixed) = builder
        .finish_before_successor_root_with_identity(cache_snapshot.identity, &mut prover_tx)
        .map_err(|error| error.to_string())?;
    let mut product_doms = Doms::new(layer_dom_base(255));
    let product_challenge = prover_tx.challenge_fp2();
    let product_domain = product_doms.take(1);
    let product_mask = primary.draw_product_mask(product_domain, products.len());
    let product_proof =
        prod_batch_prover(&products, product_challenge, product_mask, &mut prover_tx);
    let compact_retained = if retained_byte_census {
        let census = c62_retained_response_byte_census(&proof, &product_proof)
            .map_err(|error| error.to_string())?;
        eprintln!(
            "C62_RETAINED_BYTE_CENSUS context={old_context} full_model={} compact_model={} product={} extensions={:?} layer_sections={:?} non_layer_model={} subfield_payload={} subfield_vectors={} floor_without_subfield_payload={} total_before_digest={} framed={}",
            census.model_bytes,
            census.compact_model_bytes,
            census.product_bytes,
            census.extension_bytes,
            census.layer_sections,
            census.non_layer_model_bytes,
            census.subfield_correction_payload_bytes,
            census.subfield_correction_vector_count,
            census.bytes_without_subfield_correction_payload,
            census.bytes_before_padding_and_digest,
            census.bytes_before_padding_and_digest + 32,
        );
        let encoded = C6RetainedResponseProof::encode_c62_parts(&proof, &product_proof)
            .map_err(|error| error.to_string())?;
        Some(C6RetainedResponseProof::decode_c62(&encoded).map_err(|error| error.to_string())?)
    } else {
        None
    };
    zero_roots.record_operation_trace_ownership().map_err(|error| error.to_string())?;
    let prover_trace = finish_c6_prover_trace().map_err(|error| error.to_string())?;
    follower.sync_primary(&primary, &mut secondary).map_err(|error| error.to_string())?;
    let source_schedule =
        primary.schedule_audit().ok_or_else(|| "provider source schedule is absent".to_owned())?;
    let mut source_count = 0u64;
    let mut product_mask_sources = Vec::new();
    for draw in &source_schedule.draws {
        if draw.role == CorrScheduleRole::ProductMask {
            product_mask_sources.push(
                u32::try_from(source_count)
                    .map_err(|_| "product-mask source offset exceeds u32".to_owned())?,
            );
        }
        source_count = source_count
            .checked_add(draw.count)
            .ok_or_else(|| "source count overflows".to_owned())?;
    }
    let source_manifest = C6TraceSourceManifest::new(
        u32::try_from(source_count).map_err(|_| "source count exceeds u32".to_owned())?,
        source_schedule.digest,
        product_mask_sources,
    )
    .map_err(|error| error.to_string())?;
    let prover_targets = c6_gpt2_native_target_profile(
        prover_out
            .weight_claims
            .iter()
            .map(|claim| (claim.point.len(), claim.value.c6_trace_token())),
        prover_out
            .embed_claims
            .iter()
            .map(|claim| (claim.point.len(), claim.value.c6_trace_token())),
    )
    .map_err(|error| error.to_string())?;
    let (prover_compiled, prover_native) = compile_c6_operation_trace_for_role_with_target_profile(
        &prover_trace,
        &source_manifest,
        C6InstanceExtractionRole::Prover,
        &prover_targets,
    )
    .map_err(|error| error.to_string())?;

    let mut primary_v = VerifierCtx::new(primary_seed, deltas[0]);
    begin_c6_verifier_trace().map_err(|error| error.to_string())?;
    primary_v.enable_c6_operation_trace().map_err(|error| error.to_string())?;
    primary_v.enable_schedule_audit().map_err(|error| error.to_string())?;
    let mut secondary_v = VerifierCtx::new(secondary_seed, deltas[1]);
    let mut verifier_follower = C6SourceScheduleVerifierFollower::start(&mut secondary_v)
        .map_err(|error| error.to_string())?;
    let mut verifier_tx = if fiat_shamir_census {
        Transcript::new_fiat_shamir(transcript_seed)?
    } else if unbounded_challenge_census {
        Transcript::new_interactive(Box::new(CountingChallengeChannel::new(
            transcript_seed,
            Arc::clone(&verifier_challenge_count),
        )))
    } else {
        Transcript::new(transcript_seed)
    };
    if let Some(retained) = &compact_retained {
        verifier_tx.install_c62_subfield_digest_overrides(
            retained
                .c62_subfield_digest_overrides()
                .map_err(|error| error.to_string())?,
        )?;
        primary_v.enable_compact_subfield_replay().map_err(str::to_owned)?;
        secondary_v.enable_compact_subfield_replay().map_err(str::to_owned)?;
    }
    let mut cursor =
        C6CacheFoldTargetInlineVerifier::start_public(&frame, schedule, deltas, &mut verifier_tx)
            .map_err(|error| error.to_string())?;
    let verifier_cache_trace =
        begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).map_err(|error| error.to_string())?;
    let verifier_model = Gpt2VerifierModel::from_model(model).map_err(|error| error.to_string())?;
    let verifier_proof = compact_retained.as_ref().map_or(&proof, |retained| &retained.model);
    let (verifier_out, product_keys, verifier_zero_roots, _, _, _) = if old_context == 0 {
        verify_response_private_logits_c6_cache_inline_from_profile(
            &verifier_model,
            100,
            &[PrivateChunkPub { q: 50, seq: sequence }],
            verifier_proof,
            &mut primary_v,
            &mut secondary_v,
            &mut verifier_follower,
            &mut cursor,
            &mut verifier_tx,
        )
    } else {
        verify_response_continuation_private_logits_c6_cache_inline_from_profile(
            &verifier_model,
            old_context - 1,
            sequence,
            verifier_proof,
            &mut primary_v,
            &mut secondary_v,
            &mut verifier_follower,
            &mut cursor,
            &mut verifier_tx,
        )
    }
    .ok_or_else(|| "independent setup verifier rejected the model proof".to_owned())?;
    if compact_retained.is_some() {
        verifier_tx.finish_c62_subfield_digest_overrides()?;
    }
    let verifier_snapshot = verifier_cache_trace.finish().map_err(|error| error.to_string())?;
    let verifier_fixed = cursor
        .finish_before_successor_root_with_identity(verifier_snapshot.identity, &mut verifier_tx)
        .map_err(|error| error.to_string())?;
    let verifier_challenge = verifier_tx.challenge_fp2();
    let mut verifier_doms = Doms::new(layer_dom_base(255));
    let verifier_domain = verifier_doms.take(1);
    let product_key =
        primary_v.expand_product_mask_verifier_key(verifier_domain, product_keys.len());
    verifier_tx.append_fp2s("prod_check_m0_m1", &[product_proof.m0, product_proof.m1]);
    let product_ok = prod_batch_verify(
        &product_keys,
        product_key,
        primary_v.delta,
        product_challenge,
        &product_proof,
    );
    if verifier_challenge != product_challenge
        || verifier_domain != product_domain
        || (compact_retained.is_none() && !product_ok)
    {
        return Err("setup product closure differs across roles".to_owned());
    }
    verifier_zero_roots.record_operation_trace_ownership().map_err(|error| error.to_string())?;
    let verifier_trace = finish_c6_verifier_trace().map_err(|error| error.to_string())?;
    let verifier_targets = c6_gpt2_native_target_profile(
        verifier_out.weight_keys.iter().map(|(point, key)| (point.len(), key.c6_trace_token())),
        verifier_out.embed_keys.iter().map(|(point, key)| (point.len(), key.c6_trace_token())),
    )
    .map_err(|error| error.to_string())?;
    let (verifier_compiled, verifier_native) =
        compile_c6_operation_trace_for_role_with_target_profile(
            &verifier_trace,
            &source_manifest,
            C6InstanceExtractionRole::Verifier,
            &verifier_targets,
        )
        .map_err(|error| error.to_string())?;

    let topology = prover_compiled.plan.topology;
    let measured = (
        topology.source_count,
        topology.canonical_node_count,
        topology.public_input_count,
        topology.scalar_input_count,
        topology.product_closure_count,
        topology.product_triple_count,
        topology.zero_root_count,
    );
    eprintln!(
        "C62_CORRELATIONS context={old_context} primary=({}, {}) secondary=({}, {})",
        primary.counters.sub_corrs,
        primary.counters.full_corrs,
        secondary.counters.sub_corrs,
        secondary.counters.full_corrs,
    );
    let expected_correlations = expected_correlations(old_context);
    if (primary.counters.sub_corrs, primary.counters.full_corrs) != expected_correlations
        || (secondary.counters.sub_corrs, secondary.counters.full_corrs) != expected_correlations
    {
        return Err(format!(
            "setup profile {old_context} correlation census changed: expected {expected_correlations:?}"
        ));
    }
    if topology.version != 2 {
        return Err(format!(
            "setup profile {old_context} has operation-plan version {}",
            topology.version
        ));
    }
    eprintln!("C62_TOPOLOGY context={old_context} measured={measured:?}");
    if !discover_topology && measured != expected_topology(old_context) {
        return Err(format!(
            "setup profile {old_context} topology changed: expected {:?}, got {measured:?}",
            expected_topology(old_context)
        ));
    }
    if prover_compiled.plan.identity != verifier_compiled.plan.identity {
        return Err(format!(
            "setup profile {old_context} has different plan identities across roles"
        ));
    }
    if topology != verifier_compiled.plan.topology {
        return Err(format!("setup profile {old_context} has different topologies across roles"));
    }
    if prover_compiled.artifact.as_bytes() != verifier_compiled.artifact.as_bytes() {
        return Err(format!(
            "setup profile {old_context} has different plan artifacts across roles"
        ));
    }
    if prover_compiled.artifact.is_empty() || prover_compiled.artifact.len() > PLAN_MAX_BYTES {
        return Err(format!(
            "setup profile {old_context} plan length is outside 1..={PLAN_MAX_BYTES}: got {}",
            prover_compiled.artifact.len()
        ));
    }
    if prover_native != verifier_native {
        return Err(format!(
            "setup profile {old_context} has different native targets across roles"
        ));
    }
    if cache_snapshot.identity != verifier_snapshot.identity {
        return Err(format!(
            "setup profile {old_context} has different cache-trace identities across roles"
        ));
    }
    if provider_fixed != verifier_fixed {
        return Err(format!(
            "setup profile {old_context} has different fixed cache frames across roles"
        ));
    }
    if prover_tx.ledger() != verifier_tx.ledger() {
        return Err(format!(
            "setup profile {old_context} has different transcript ledgers across roles"
        ));
    }
    if fiat_shamir_census {
        prover_tx.canonical_binding_digest()?;
        verifier_tx.canonical_binding_digest()?;
    }
    if unbounded_challenge_census {
        let prover_count = prover_challenge_count.load(Ordering::Relaxed);
        let verifier_count = verifier_challenge_count.load(Ordering::Relaxed);
        if prover_count != verifier_count {
            return Err(format!(
                "challenge census differs across roles: prover {prover_count}, verifier {verifier_count}"
            ));
        }
        eprintln!("C62_CHALLENGE_CENSUS context={old_context} challenges={prover_count}");
    }
    if retained_byte_census {
        eprintln!("C62_COMPACT_REPLAY context={old_context} status=pass");
        return Ok(());
    }
    let native_artifact = C6NativeTargetProfileArtifact::encode(&prover_native, topology)
        .map_err(|error| error.to_string())?;
    let (_, decoded_native) = C6NativeTargetProfileArtifact::decode(
        native_artifact.as_bytes(),
        verifier_compiled.plan.topology,
    )
    .map_err(|error| error.to_string())?;
    if decoded_native != verifier_native {
        return Err("native target artifact differs after decode".to_owned());
    }
    write_profile(
        output,
        &source_manifest,
        topology.topology_digest,
        prover_compiled.artifact.as_bytes(),
        prover_compiled.instance_extraction.as_bytes(),
        verifier_compiled.instance_extraction.as_bytes(),
        native_artifact.as_bytes(),
    )
}

fn compile_profiles_in_fresh_processes(
    weights: &Path,
    setup_root: &Path,
    discover_topology: bool,
    fiat_shamir_census: bool,
    unbounded_challenge_census: bool,
    retained_byte_census: bool,
    start_index: usize,
    stop_index: usize,
) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("locate setup generator executable: {error}"))?;
    for &context in &PROFILE_CONTEXTS[start_index..=stop_index] {
        let mut command = Command::new(&executable);
        command
            .arg("--weights")
            .arg(weights)
            .arg("--setup-root")
            .arg(setup_root)
            .arg("--resume-from")
            .arg(context.to_string())
            .arg("--stop-after")
            .arg(context.to_string());
        if discover_topology {
            command.arg("--discover-topology");
        }
        if fiat_shamir_census {
            command.arg("--fiat-shamir-census");
        }
        if unbounded_challenge_census {
            command.arg("--unbounded-challenge-census");
        }
        if retained_byte_census {
            command.arg("--retained-byte-census");
        }
        let status = command
            .status()
            .map_err(|error| format!("start setup worker for context {context}: {error}"))?;
        if !status.success() {
            return Err(format!("setup worker for context {context} exited with {status}"));
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let (
        weights,
        setup_root,
        discover_topology,
        fiat_shamir_census,
        unbounded_challenge_census,
        retained_byte_census,
        resume_from,
        stop_after,
    ) = parse_args()?;
    let start_index = match resume_from {
        None => 0,
        Some(context) => PROFILE_CONTEXTS
            .iter()
            .position(|candidate| *candidate == context)
            .ok_or_else(|| "resume context is not a registered C6.2 profile".to_owned())?,
    };
    let stop_index = match stop_after {
        None => PROFILE_CONTEXTS.len() - 1,
        Some(context) => PROFILE_CONTEXTS
            .iter()
            .position(|candidate| *candidate == context)
            .ok_or_else(|| "stop context is not a registered C6.2 profile".to_owned())?,
    };
    if stop_index < start_index {
        return Err("stop context precedes the resume context".to_owned());
    }
    if stop_index > start_index {
        return compile_profiles_in_fresh_processes(
            &weights,
            &setup_root,
            discover_topology,
            fiat_shamir_census,
            unbounded_challenge_census,
            retained_byte_census,
            start_index,
            stop_index,
        );
    }
    if start_index == 0 {
        if setup_root.exists() {
            return Err(format!("{} must not exist", setup_root.display()));
        }
    } else if !setup_root.is_dir() {
        return Err(format!("{} is not an existing setup directory", setup_root.display()));
    } else {
        let mut actual = fs::read_dir(&setup_root)
            .map_err(|error| format!("read {}: {error}", setup_root.display()))?
            .map(|entry| {
                entry.map_err(|error| format!("read setup entry: {error}")).and_then(|entry| {
                    if !entry
                        .file_type()
                        .map_err(|error| format!("stat setup entry: {error}"))?
                        .is_dir()
                    {
                        return Err("setup root contains a non-directory entry".to_owned());
                    }
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "setup root contains a non-UTF8 entry".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        let mut expected = PROFILE_CONTEXTS[..start_index]
            .iter()
            .map(|context| format!("context-{context:03}"))
            .collect::<Vec<_>>();
        expected.sort();
        if actual != expected {
            return Err("resume setup profile census differs from the exact prefix".to_owned());
        }
    }
    let model = load_model(&weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout().map_err(|error| error.to_string())?;
    eprintln!("building deterministic response sequence");
    let prefill = forward_model(&model, 100);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, 100);
    let (generated, _) = generate(&model, &mut cache, &prefill.logits, 100, 850);
    let mut sequence = model.p.tokens[..100].to_vec();
    sequence.extend_from_slice(&generated);
    let golden = fs::read(weights.join("golden-p6.bin"))
        .map_err(|error| format!("read golden-p6.bin: {error}"))?;
    if golden.len() < 16 + 4 * 50 || &golden[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6.bin has invalid framing".to_owned());
    }
    let golden_tokens = golden[16..16 + 4 * 50]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("fixed token width")))
        .collect::<Vec<_>>();
    if generated[..50] != golden_tokens {
        return Err("generated prefix differs from golden-p6.bin".to_owned());
    }
    if start_index == 0 {
        fs::create_dir(&setup_root)
            .map_err(|error| format!("create {}: {error}", setup_root.display()))?;
    }
    for old_context in
        PROFILE_CONTEXTS.into_iter().skip(start_index).take(stop_index - start_index + 1)
    {
        let name = format!("context-{old_context:03}");
        eprintln!("compiling setup profile {name}");
        let new_context = if old_context == 0 { 150 } else { old_context + 50 };
        compile_profile(
            &model,
            &sequence[..new_context],
            old_context,
            &setup_root.join(&name),
            discover_topology,
            fiat_shamir_census,
            unbounded_challenge_census,
            retained_byte_census,
        )?;
        eprintln!("completed setup profile {name}");
    }
    File::open(&setup_root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync {}: {error}", setup_root.display()))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("c62_setup_bundle_record FAILED: {error}");
        std::process::exit(1);
    }
}
