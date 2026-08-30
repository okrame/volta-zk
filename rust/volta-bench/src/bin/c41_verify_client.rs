//! CPU-only verifier replay for one party-separated C4.1 response.

use serde::Serialize;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use volta_gpt2::decode_verifier_model_canonical;
use volta_mac::{
    zero_batch_verify, zero_mask_key, Transcript, VerifierCtx, C41_FIAT_SHAMIR_MAX_CHALLENGES,
};
use volta_pcg::{ResponseAuthorizationStore, VerifierPcgPool};
use volta_pcs::{
    decode_multi_open_canonical, layout_gpt2_embed_c3, layout_gpt2_weights_c3, verify_multi_open,
    C3_EMBED, C3_WEIGHTS,
};
use volta_proto::c41_folded_tole::{C41VerifierDiagnostics, C41VerifierResponseState};
use volta_proto::logup::Doms;
use volta_proto::{
    decode_model_proof_c41_canonical, layer_dom_base, prod_batch_verify,
    verify_response_private_logits_c41_from_profile, C41ModelSetupArtifact,
    C41ResponseClosureProof, C41ResponseProofEnvelope, C41ResponseStatement, C41VerifierBundle,
    PrivateChunkPub, C41_RESPONSE_ENVELOPE_MAX_BYTES,
};

type AnyError = Box<dyn Error + Send + Sync>;

#[derive(Clone)]
struct Args {
    verifier_bundle: PathBuf,
    model_setup: PathBuf,
    statement: PathBuf,
    proof: PathBuf,
    expected_model_setup_blake3: String,
    expected_proof_bytes: u64,
    expected_proof_blake3: String,
    expected_git_sha: String,
    expected_fs_challenges: u64,
    expected_fs_context_digest: String,
    output: PathBuf,
    authorization_store: Option<PathBuf>,
    benchmark_replay: bool,
    threads: usize,
}

#[derive(Serialize)]
struct Record {
    schema: u32,
    profile: &'static str,
    git_sha: String,
    git_dirty: bool,
    os: &'static str,
    arch: &'static str,
    accepted: bool,
    benchmark_replay: bool,
    response_index: u64,
    threads: usize,
    proof_bytes: u64,
    proof_blake3: String,
    proof_gate_bytes: u64,
    proof_gate_pass: bool,
    expected_model_setup_blake3: String,
    verifier_bundle_bytes: u64,
    verifier_seed_state_bytes: u64,
    materialized_verifier_lot_bytes: u64,
    full_query_bytes: u64,
    bundle_read_decode_s: f64,
    process_wall_s: f64,
    proof_read_s: f64,
    envelope_decode_s: f64,
    component_decode_s: f64,
    fiat_shamir_context_s: f64,
    model_and_seed_stream_fold_s: f64,
    descriptor_build_s: f64,
    query_chunk_build_s: f64,
    seed_expand_and_stream_fold_s: f64,
    degree12_close_s: f64,
    streamed_chunks: usize,
    query_chunk_peak_bytes: u64,
    weights_pcs_s: f64,
    embed_pcs_s: f64,
    product_zero_close_s: f64,
    verifier_core_s: f64,
    verifier_total_s: f64,
    fiat_shamir_challenges: u64,
    canonical_transcript_digest: String,
    ordinary_sub_corrs_consumed: u64,
    ordinary_full_corrs_consumed: u64,
    peak_rss_bytes: u64,
    peak_rss_gate_bytes: u64,
    peak_rss_gate_pass: bool,
    verifier_time_gate: &'static str,
    major_faults: i64,
    minor_faults: i64,
}

fn usage() -> ! {
    eprintln!(
        "usage: c41_verify_client --verifier-bundle FILE --model-setup FILE --statement FILE \
         --expected-model-setup-blake3 HEX --proof FILE --expected-proof-bytes N \
         --expected-proof-blake3 HEX --expected-git-sha SHA \
         --expected-fs-challenges N --expected-fs-context-digest HEX --output FILE \
         (--authorization-store DIR|--benchmark-replay) [--threads 1|4]"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut verifier_bundle = None;
    let mut model_setup = None;
    let mut statement = None;
    let mut proof = None;
    let mut expected_model_setup_blake3 = None;
    let mut expected_proof_bytes = None;
    let mut expected_proof_blake3 = None;
    let mut expected_git_sha = None;
    let mut expected_fs_challenges = None;
    let mut expected_fs_context_digest = None;
    let mut output = None;
    let mut authorization_store = None;
    let mut benchmark_replay = false;
    let mut threads = 4;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value =
            |args: &mut std::iter::Skip<std::env::Args>| args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--verifier-bundle" => verifier_bundle = Some(PathBuf::from(value(&mut args))),
            "--model-setup" => model_setup = Some(PathBuf::from(value(&mut args))),
            "--statement" => statement = Some(PathBuf::from(value(&mut args))),
            "--proof" => proof = Some(PathBuf::from(value(&mut args))),
            "--expected-model-setup-blake3" => expected_model_setup_blake3 = Some(value(&mut args)),
            "--expected-proof-bytes" => {
                expected_proof_bytes = Some(value(&mut args).parse().unwrap_or_else(|_| usage()))
            }
            "--expected-proof-blake3" => expected_proof_blake3 = Some(value(&mut args)),
            "--expected-git-sha" => expected_git_sha = Some(value(&mut args)),
            "--expected-fs-challenges" => {
                expected_fs_challenges = Some(value(&mut args).parse().unwrap_or_else(|_| usage()))
            }
            "--expected-fs-context-digest" => expected_fs_context_digest = Some(value(&mut args)),
            "--output" => output = Some(PathBuf::from(value(&mut args))),
            "--authorization-store" => authorization_store = Some(PathBuf::from(value(&mut args))),
            "--benchmark-replay" => benchmark_replay = true,
            "--threads" => threads = value(&mut args).parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    if !matches!(threads, 1 | 4)
        || benchmark_replay == authorization_store.is_some()
        || output.is_none()
    {
        usage();
    }
    Args {
        verifier_bundle: verifier_bundle.unwrap_or_else(|| usage()),
        model_setup: model_setup.unwrap_or_else(|| usage()),
        statement: statement.unwrap_or_else(|| usage()),
        proof: proof.unwrap_or_else(|| usage()),
        expected_model_setup_blake3: checked_blake3_hex(
            expected_model_setup_blake3.unwrap_or_else(|| usage()),
        ),
        expected_proof_bytes: expected_proof_bytes.unwrap_or_else(|| usage()),
        expected_proof_blake3: checked_blake3_hex(expected_proof_blake3.unwrap_or_else(|| usage())),
        expected_git_sha: checked_git_sha(expected_git_sha.unwrap_or_else(|| usage())),
        expected_fs_challenges: expected_fs_challenges.unwrap_or_else(|| usage()),
        expected_fs_context_digest: checked_blake3_hex(
            expected_fs_context_digest.unwrap_or_else(|| usage()),
        ),
        output: output.unwrap(),
        authorization_store,
        benchmark_replay,
        threads,
    }
}

fn checked_git_sha(value: String) -> String {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        usage();
    }
    value.to_ascii_lowercase()
}

fn checked_blake3_hex(value: String) -> String {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        usage();
    }
    value
}

fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, AnyError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() > cap {
        return Err(format!("{} exceeds its byte cap", path.display()).into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(format!("{} exceeds its byte cap", path.display()).into());
    }
    Ok(bytes)
}

fn usage_snapshot() -> libc::rusage {
    let mut usage = std::mem::MaybeUninit::zeroed();
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(status, 0, "getrusage failed");
    unsafe { usage.assume_init() }
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), AnyError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git_state() -> Result<(String, bool), AnyError> {
    let sha = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["rev-parse", "HEAD"])
        .output()?;
    let status = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()?;
    if !sha.status.success() || !status.status.success() {
        return Err("cannot resolve verifier git provenance".into());
    }
    Ok((String::from_utf8(sha.stdout)?.trim().to_owned(), !status.stdout.is_empty()))
}

fn verify(args: &Args) -> Result<Record, AnyError> {
    let process_started = Instant::now();
    let bundle_started = Instant::now();
    let bundle_bytes = read_bounded(&args.verifier_bundle, 128_000_000)?;
    let verifier_bundle_bytes = bundle_bytes.len() as u64;
    let bundle = C41VerifierBundle::decode(&bundle_bytes)?;
    drop(bundle_bytes);
    bundle.context.validate_production()?;
    let model_setup_bytes = read_bounded(&args.model_setup, 512)?;
    if blake3::hash(&model_setup_bytes).to_hex().as_str() != args.expected_model_setup_blake3 {
        return Err(
            "C4.1 model-setup artifact digest differs from the pinned initialization".into()
        );
    }
    let model_setup = C41ModelSetupArtifact::decode(&model_setup_bytes)?;
    let statement = C41ResponseStatement::decode(&read_bounded(&args.statement, 1_000_000)?)?;
    let verifier_model = decode_verifier_model_canonical(&bundle.verifier_model)?;
    if model_setup.model_binding_digest != bundle.context.model_binding_digest
        || model_setup.quantization_digest != bundle.context.quantization_digest
        || model_setup.pcs_parameter_digest != bundle.context.pcs_parameter_digest
        || model_setup.verifier_model_digest != *blake3::hash(&bundle.verifier_model).as_bytes()
    {
        return Err("C4.1 model setup does not match the verifier inventory".into());
    }
    let bundle_read_decode_s = bundle_started.elapsed().as_secs_f64();

    let fs_context = bundle.context.fiat_shamir_context(statement.digest()?)?;
    let context_digest = fs_context.digest()?;
    if blake3::Hash::from(context_digest).to_hex().as_str() != args.expected_fs_context_digest {
        return Err("C41FS1 context differs from the provider artifact manifest".into());
    }
    if !args.benchmark_replay {
        let store = ResponseAuthorizationStore::new(
            args.authorization_store.as_ref().expect("validated authorization store"),
        )?;
        store.reserve(&fs_context.response_authorization_binding()?)?;
    }
    let proof_to_verdict_started = Instant::now();
    let proof_read_started = Instant::now();
    let proof_bytes = read_bounded(&args.proof, C41_RESPONSE_ENVELOPE_MAX_BYTES)?;
    let proof_read_s = proof_read_started.elapsed().as_secs_f64();
    let proof_digest = blake3::hash(&proof_bytes);
    if proof_bytes.len() as u64 != args.expected_proof_bytes
        || proof_digest.to_hex().as_str() != args.expected_proof_blake3
    {
        return Err("C4.1 proof length or digest differs from the authenticated transfer".into());
    }
    if proof_bytes.len() >= 70_000_000 {
        return Err("C4.1 proof violates the <70 MB gate".into());
    }
    let envelope_started = Instant::now();
    let envelope = C41ResponseProofEnvelope::decode(&proof_bytes)?;
    let envelope_decode_s = envelope_started.elapsed().as_secs_f64();
    let component_started = Instant::now();
    let proof = decode_model_proof_c41_canonical(envelope.model())?;
    let closure = C41ResponseClosureProof::decode(envelope.closure())?;
    let phases = 1 + statement.chunk_rows.len();
    let weights_pcs =
        decode_multi_open_canonical(envelope.weights_pcs(), &C3_WEIGHTS, 4 * 12 * phases)?;
    let embed_pcs = decode_multi_open_canonical(envelope.embed_pcs(), &C3_EMBED, 3 * phases)?;
    let component_decode_s = component_started.elapsed().as_secs_f64();

    let context_started = Instant::now();
    let mut tx = Transcript::new_c41_fiat_shamir(context_digest)?;
    let fiat_shamir_context_s = context_started.elapsed().as_secs_f64();

    let mut vc = VerifierCtx::from_pcg_pool(
        bundle.delta,
        VerifierPcgPool {
            sub_keys: bundle.correlations.sub_keys,
            full_keys: bundle.correlations.full_keys,
        },
    );
    let c41 = proof.c41.as_ref().ok_or("C4.1 model proof has no folded response")?;
    let diagnostics = Arc::new(Mutex::new(C41VerifierDiagnostics::default()));
    let state = C41VerifierResponseState::new_seed_streaming_with_diagnostics(
        bundle.typed,
        bundle.context.public_incidence_seed,
        bundle.context.first_global_bit as usize,
        bundle.context.cells as usize,
        c41,
        bundle.delta,
        diagnostics.clone(),
    )?;
    if !state.is_seed_streaming() || state.persistent_seed_bytes() != 4_145_152 {
        return Err("C4.1 verifier selected a non-streaming or wrong-size state".into());
    }
    let chunks = statement
        .chunk_rows
        .iter()
        .map(|rows| PrivateChunkPub { q: *rows as usize, seq: statement.tokens.as_slice() })
        .collect::<Vec<_>>();
    let core_started = Instant::now();
    let model_started = Instant::now();
    let (out, kprod, kzero) = verify_response_private_logits_c41_from_profile(
        &verifier_model,
        statement.prefill_tokens as usize,
        &chunks,
        &proof,
        state,
        &mut vc,
        &mut tx,
    )
    .ok_or("C4.1 model/seed-stream verifier rejected")?;
    let model_and_seed_stream_fold_s = model_started.elapsed().as_secs_f64();

    let weights_started = Instant::now();
    let weights_layout = layout_gpt2_weights_c3();
    let weight_claims = out
        .weight_keys
        .iter()
        .enumerate()
        .map(|(index, (point, key))| {
            let phase_slot = index % (4 * 12);
            (weights_layout.block_claim(phase_slot / 4, phase_slot % 4, point), *key)
        })
        .collect::<Vec<_>>();
    let mut weight_domains = Doms::new(layer_dom_base(242));
    let weight_s = weight_domains.take(1);
    let weight_z = weight_domains.take(1);
    if !verify_multi_open(
        &model_setup.weights_root,
        &C3_WEIGHTS,
        &weight_claims,
        &weights_pcs,
        &mut vc,
        weight_s,
        weight_z,
        &mut tx,
    ) {
        return Err("C4.1 weights PCS rejected".into());
    }
    let weights_pcs_s = weights_started.elapsed().as_secs_f64();

    let embed_started = Instant::now();
    let embed_layout = layout_gpt2_embed_c3();
    let embed_claims = out
        .embed_keys
        .iter()
        .enumerate()
        .map(|(index, (point, key))| {
            (embed_layout.block_claim(if index % 3 == 2 { 1 } else { 0 }, point), *key)
        })
        .collect::<Vec<_>>();
    let mut embed_domains = Doms::new(layer_dom_base(253));
    let embed_s = embed_domains.take(1);
    let embed_z = embed_domains.take(1);
    if !verify_multi_open(
        &model_setup.embed_root,
        &C3_EMBED,
        &embed_claims,
        &embed_pcs,
        &mut vc,
        embed_s,
        embed_z,
        &mut tx,
    ) {
        return Err("C4.1 embedding PCS rejected".into());
    }
    let embed_pcs_s = embed_started.elapsed().as_secs_f64();

    let close_started = Instant::now();
    let chi = tx.challenge_fp2();
    let mut close_domains = Doms::new(layer_dom_base(255));
    let product_domain = close_domains.take(1);
    let product_mask = vc.expand_product_mask_verifier_key(product_domain, kprod.len());
    tx.append_fp2s("prod_check_m0_m1", &[closure.product.m0, closure.product.m1]);
    if !prod_batch_verify(&kprod, product_mask, bundle.delta, chi, &closure.product) {
        return Err("C4.1 product close rejected".into());
    }
    let zero_domain = close_domains.take(1);
    let zero_full_key = vc.expand_full_verifier_keys(zero_domain, 1)[0];
    tx.append_fp2s("mask_correction", &[closure.zero_mask_correction]);
    let zero_key = zero_mask_key(&vc, zero_full_key, closure.zero_mask_correction);
    let zero_challenge = tx.challenge_fp2();
    tx.append_fp2s("zero_batch_tag", &[closure.zero_batch_tag]);
    if !zero_batch_verify(&kzero, zero_key, zero_challenge, closure.zero_batch_tag) {
        return Err("C4.1 zero close rejected".into());
    }
    let product_zero_close_s = close_started.elapsed().as_secs_f64();
    let verifier_core_s = core_started.elapsed().as_secs_f64();
    let diagnostics = diagnostics.lock().expect("C4.1 verifier diagnostics mutex poisoned").clone();

    let challenges = tx.fiat_shamir_challenge_count().ok_or("C4.1 verifier did not use C41FS1")?;
    if challenges == 0 || challenges > C41_FIAT_SHAMIR_MAX_CHALLENGES {
        return Err("C41FS1 exact challenge census is outside its admission cap".into());
    }
    if challenges != args.expected_fs_challenges {
        return Err("C41FS1 challenge census differs from the provider artifact manifest".into());
    }
    let canonical = tx.canonical_binding_digest()?;
    if vc.counters.sub_corrs != bundle.context.ordinary_sub_corrs
        || vc.counters.full_corrs != bundle.context.ordinary_full_corrs
    {
        return Err("C4.1 verifier correlation census differs from its bundle".into());
    }
    let usage = usage_snapshot();
    let peak_rss_bytes = usage.ru_maxrss as u64 * 1024;
    Ok(Record {
        schema: 1,
        profile: "C4.1-seed-only-streaming-client-v1",
        git_sha: args.expected_git_sha.clone(),
        git_dirty: false,
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        accepted: true,
        benchmark_replay: args.benchmark_replay,
        response_index: bundle.context.response_index,
        threads: args.threads,
        proof_bytes: proof_bytes.len() as u64,
        proof_blake3: proof_digest.to_hex().to_string(),
        proof_gate_bytes: 70_000_000,
        proof_gate_pass: proof_bytes.len() < 70_000_000,
        expected_model_setup_blake3: args.expected_model_setup_blake3.clone(),
        verifier_bundle_bytes,
        verifier_seed_state_bytes: 4_145_152,
        materialized_verifier_lot_bytes: 0,
        full_query_bytes: 0,
        bundle_read_decode_s,
        process_wall_s: process_started.elapsed().as_secs_f64(),
        proof_read_s,
        envelope_decode_s,
        component_decode_s,
        fiat_shamir_context_s,
        model_and_seed_stream_fold_s,
        descriptor_build_s: diagnostics.descriptor_build_s,
        query_chunk_build_s: diagnostics.query_chunk_build_s,
        seed_expand_and_stream_fold_s: diagnostics.seed_expand_and_stream_fold_s,
        degree12_close_s: diagnostics.degree12_close_s,
        streamed_chunks: diagnostics.chunks,
        query_chunk_peak_bytes: diagnostics.query_chunk_peak_bytes,
        weights_pcs_s,
        embed_pcs_s,
        product_zero_close_s,
        verifier_core_s,
        verifier_total_s: proof_to_verdict_started.elapsed().as_secs_f64(),
        fiat_shamir_challenges: challenges,
        canonical_transcript_digest: blake3::Hash::from(canonical).to_hex().to_string(),
        ordinary_sub_corrs_consumed: vc.counters.sub_corrs,
        ordinary_full_corrs_consumed: vc.counters.full_corrs,
        peak_rss_bytes,
        peak_rss_gate_bytes: 2_000_000_000,
        peak_rss_gate_pass: peak_rss_bytes < 2_000_000_000,
        verifier_time_gate: "open-first-empirical-run",
        major_faults: usage.ru_majflt,
        minor_faults: usage.ru_minflt,
    })
}

fn main() -> Result<(), AnyError> {
    let args = parse_args();
    let (git_before, dirty_before) = git_state()?;
    if dirty_before || git_before != args.expected_git_sha {
        return Err("C4.1 verifier requires the clean expected git revision".into());
    }
    let pool = rayon::ThreadPoolBuilder::new().num_threads(args.threads).build()?;
    let record = pool.install(|| verify(&args))?;
    let (git_after, dirty_after) = git_state()?;
    if dirty_after || git_after != git_before {
        return Err("C4.1 verifier git revision changed during verification".into());
    }
    let encoded = serde_json::to_vec_pretty(&record)?;
    write_create_new(&args.output, &encoded)?;
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}
