//! Create one production C4.1 response inventory and split it by party.

use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use std::error::Error;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use volta_gpt2::{encode_verifier_model_canonical, load_model, Gpt2VerifierModel, L};
use volta_mac::{CorrelationStream, Transcript, VerifierCtx};
use volta_pcg::{
    expand_phase_b_production_with_ggm_prg, GgmPrg, PhaseAParams, ResponseAuthorizationStore,
    SessionBinding,
};
use volta_pcs::{
    commit, layout_gpt2_embed_c3, layout_gpt2_weights_c3, LigeroParams, C3_EMBED, C3_WEIGHTS,
};
use volta_proto::c41_folded_tole::{c41_materialize_packed_keys, c41_typed_setup_exchange};
use volta_proto::{
    cattn_permuted, C41MaterializedVerifierLot, C41ModelSetupArtifact, C41PartySetupContext,
    C41ProviderBundle, C41VerifierBundle, C41_PRODUCTION_CELLS, C41_PRODUCTION_ORDINARY_FULL_CORRS,
    C41_PRODUCTION_ORDINARY_SUB_CORRS, C41_PRODUCTION_SEED_ROWS, C41_PRODUCTION_TOTAL_FULL_CORRS,
    C41_PRODUCTION_TOTAL_SUB_CORRS, C41_PRODUCTION_TYPED_SUB_CORRS,
};

#[derive(Serialize)]
struct ArtifactRow {
    name: &'static str,
    bytes: usize,
    blake3: String,
    secret: bool,
}

#[derive(Serialize)]
struct Manifest {
    schema: u32,
    profile: &'static str,
    git_sha: String,
    git_dirty: bool,
    real_aes_pcg: bool,
    response_index: u64,
    cells: usize,
    seed_rows: usize,
    total_sub_corrs: usize,
    total_full_corrs: usize,
    ordinary_sub_corrs: usize,
    ordinary_full_corrs: usize,
    model_initialization_wall_s: f64,
    pcg_setup_wall_s: f64,
    typed_setup_wall_s: f64,
    verifier_lot_materialize_wall_s: f64,
    materialized_verifier_lot_payload_bytes: u64,
    setup_comm_bytes: u64,
    typed_setup_comm_bytes: u64,
    conditional_soundness_bits: f64,
    conditional_weight_zk_bits: f64,
    artifacts: Vec<ArtifactRow>,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git_sha() -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Err("cannot resolve the C4.1 setup git revision".into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn git_dirty() -> Result<bool, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository_root())
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()?;
    if !output.status.success() {
        return Err("cannot inspect the C4.1 setup worktree".into());
    }
    Ok(!output.stdout.is_empty())
}

fn usage() -> ! {
    eprintln!(
        "usage: c41_party_setup --weights DIR --output DIR --authorization-store DIR [--response-index N]"
    );
    std::process::exit(2);
}

fn parse_args() -> (PathBuf, PathBuf, PathBuf, u64) {
    let mut weights = None;
    let mut output = None;
    let mut authorization_store = None;
    let mut response_index = 0u64;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value =
            |args: &mut std::iter::Skip<std::env::Args>| args.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "--weights" => weights = Some(PathBuf::from(value(&mut args))),
            "--output" => output = Some(PathBuf::from(value(&mut args))),
            "--authorization-store" => authorization_store = Some(PathBuf::from(value(&mut args))),
            "--response-index" => {
                response_index = value(&mut args).parse().unwrap_or_else(|_| usage())
            }
            _ => usage(),
        }
    }
    (
        weights.unwrap_or_else(|| usage()),
        output.unwrap_or_else(|| usage()),
        authorization_store.unwrap_or_else(|| usage()),
        response_index,
    )
}

fn random_identity(label: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut value = [0u8; 32];
    OsRng.try_fill_bytes(&mut value)?;
    if value == [0; 32] {
        return Err(format!("OS entropy returned zero for {label}").into());
    }
    Ok(value)
}

fn model_binding_digest(weights: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    let mut file = File::open(weights.join("gpt2s-q.bin"))?;
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c4.1/model-artifact/v1");
    let mut buffer = [0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn pcs_parameter_digest(layer: LigeroParams, embed: LigeroParams) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c4.1/pcs-parameters/v1");
    for params in [layer, embed] {
        for value in [
            params.rows as u64,
            params.col_bits as u64,
            params.pad as u64,
            params.code_bits as u64,
            params.n_queries as u64,
        ] {
            hasher.update(&value.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn session_binding_digest(binding: SessionBinding) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c4.1/session-binding/v1");
    hasher.update(&binding.session_id);
    hasher.update(&binding.channel_id);
    hasher.update(&binding.response_authorization_nonce);
    *hasher.finalize().as_bytes()
}

fn create_output(root: &Path) -> Result<(), Box<dyn Error>> {
    if !root.is_absolute() {
        return Err("C4.1 secret setup output must be an absolute path".into());
    }
    let parent = root.parent().ok_or("C4.1 setup output has no parent")?.canonicalize()?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize()?;
    if parent.starts_with(repository) {
        return Err("C4.1 secret setup output must stay outside the repository".into());
    }
    DirBuilder::new().mode(0o700).create(root)?;
    Ok(())
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o644).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let (weights, output, authorization_store, response_index) = parse_args();
    let setup_git_sha = git_sha()?;
    if git_dirty()? {
        return Err("C4.1 production setup requires a clean worktree".into());
    }
    if !weights.join("gpt2s-q.bin").is_file() {
        return Err("frozen GPT-2 weight artifact is missing".into());
    }
    create_output(&output)?;

    let model = load_model(&weights)?;
    let verifier_model = encode_verifier_model_canonical(&Gpt2VerifierModel::from_model(&model)?)?;
    let model_initialization_started = Instant::now();
    let weights_layout = layout_gpt2_weights_c3();
    let mut flat_weights = vec![0i16; weights_layout.total_len];
    for layer in 0..L {
        let weights = &model.layers[layer].0;
        let c_attn = cattn_permuted(&weights.c_attn);
        weights_layout.place_layer(
            &mut flat_weights,
            layer,
            [&c_attn, &weights.attn_proj, &weights.ffn_up, &weights.ffn_down],
        );
    }
    let (weights_commitment, weights_matrix) = commit(&flat_weights, &C3_WEIGHTS, [0x51; 32]);
    drop((flat_weights, weights_matrix));
    let embed_layout = layout_gpt2_embed_c3();
    let flat_embed = embed_layout.place(&[&model.wte, &model.wpe]);
    let (embed_commitment, embed_matrix) = commit(&flat_embed, &C3_EMBED, [0x52; 32]);
    drop((flat_embed, embed_matrix));
    let model_initialization_wall_s = model_initialization_started.elapsed().as_secs_f64();
    let binding = SessionBinding::new(
        random_identity("PCG session")?,
        random_identity("authenticated channel")?,
        random_identity("response authorization")?,
    )?;
    let store = ResponseAuthorizationStore::new(authorization_store)?;
    let pcg_started = Instant::now();
    let production = expand_phase_b_production_with_ggm_prg(
        &store,
        binding,
        C41_PRODUCTION_TOTAL_SUB_CORRS,
        C41_PRODUCTION_TOTAL_FULL_CORRS,
        PhaseAParams::for_counts(C41_PRODUCTION_TOTAL_SUB_CORRS, C41_PRODUCTION_TOTAL_FULL_CORRS),
        GgmPrg::Aes128Mmo,
    )?;
    let pcg_setup_wall_s = pcg_started.elapsed().as_secs_f64();
    if !production.expansion.consistency.ok || !production.expansion.setup.params.production_ready {
        return Err("production PCG expansion did not pass its malicious check".into());
    }
    let setup_comm_bytes = production.expansion.setup.comm.total_bytes;
    let delta = production.expansion.verifier_delta;
    let mut prover_pool = production.expansion.prover;
    let mut verifier_pool = production.expansion.verifier;
    let ordinary_prover_subs = prover_pool.subs.split_off(C41_PRODUCTION_TYPED_SUB_CORRS);
    let ordinary_verifier_subs = verifier_pool.sub_keys.split_off(C41_PRODUCTION_TYPED_SUB_CORRS);
    let ordinary_prover_fulls = prover_pool.fulls.split_off(1);
    let ordinary_verifier_fulls = verifier_pool.full_keys.split_off(1);

    let mut prover_stream = CorrelationStream::from_pcg_pool(prover_pool);
    let mut verifier_ctx = VerifierCtx::from_pcg_pool(delta, verifier_pool);
    let public_seed = random_identity("public incidence seed")?;
    let transcript_seed = random_identity("typed setup transcript")?;
    let mut prover_tx = Transcript::new(transcript_seed);
    let mut verifier_tx = Transcript::new(transcript_seed);
    let typed_started = Instant::now();
    let exchange = c41_typed_setup_exchange(
        random_identity("secret typed seed")?,
        public_seed,
        C41_PRODUCTION_SEED_ROWS,
        0x4_1000,
        0x5_1000,
        &mut prover_stream,
        &mut verifier_ctx,
        &mut prover_tx,
        &mut verifier_tx,
    )?;
    let typed_setup_wall_s = typed_started.elapsed().as_secs_f64();
    if prover_stream.counters.sub_corrs != C41_PRODUCTION_TYPED_SUB_CORRS as u64
        || prover_stream.counters.full_corrs != 1
        || prover_stream.counters != verifier_ctx.counters
    {
        return Err("typed setup did not consume its exact PCG prefix".into());
    }
    let setup_proof = exchange.proof.encode()?;
    let materialize_started = Instant::now();
    let materialized_lot = c41_materialize_packed_keys(
        public_seed,
        delta,
        &exchange.verifier,
        0,
        C41_PRODUCTION_CELLS,
    )?;
    let verifier_lot_materialize_wall_s = materialize_started.elapsed().as_secs_f64();
    let context = C41PartySetupContext {
        model_binding_digest: model_binding_digest(&weights)?,
        setup_digest: *blake3::hash(&setup_proof).as_bytes(),
        quantization_digest: *blake3::hash(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/quantization-spec.md"
        )))
        .as_bytes(),
        connection_binding: session_binding_digest(binding),
        public_incidence_seed: public_seed,
        pcs_parameter_digest: pcs_parameter_digest(C3_WEIGHTS, C3_EMBED),
        response_index,
        cells: C41_PRODUCTION_CELLS as u64,
        first_global_bit: 0,
        ordinary_sub_corrs: C41_PRODUCTION_ORDINARY_SUB_CORRS as u64,
        ordinary_full_corrs: C41_PRODUCTION_ORDINARY_FULL_CORRS as u64,
    };
    context.validate_production()?;
    let model_setup = C41ModelSetupArtifact {
        model_binding_digest: context.model_binding_digest,
        quantization_digest: context.quantization_digest,
        pcs_parameter_digest: context.pcs_parameter_digest,
        verifier_model_digest: *blake3::hash(&verifier_model).as_bytes(),
        weights_root: weights_commitment.root,
        embed_root: embed_commitment.root,
    }
    .encode()?;
    let provider = C41ProviderBundle {
        context,
        correlations: volta_pcg::ProverPcgPool {
            subs: ordinary_prover_subs,
            fulls: ordinary_prover_fulls,
        },
        typed: exchange.prover,
    }
    .encode()?;
    let verifier = C41VerifierBundle {
        context,
        delta,
        correlations: volta_pcg::VerifierPcgPool {
            sub_keys: ordinary_verifier_subs,
            full_keys: ordinary_verifier_fulls,
        },
        typed: exchange.verifier,
        verifier_model,
    }
    .encode()?;
    let verifier_lot = C41MaterializedVerifierLot { context, lot: materialized_lot }.encode()?;
    C41ProviderBundle::decode(&provider)?.context.validate_production()?;
    C41VerifierBundle::decode(&verifier)?.context.validate_production()?;
    C41MaterializedVerifierLot::decode(&verifier_lot)?.context.validate_production()?;

    let provider_name = "provider.bundle";
    let verifier_name = "verifier.bundle";
    let model_setup_name = "model-setup.bin";
    let verifier_lot_name = "verifier-lot.bin";
    write_secret(&output.join(provider_name), &provider)?;
    write_secret(&output.join(verifier_name), &verifier)?;
    write_secret(&output.join(verifier_lot_name), &verifier_lot)?;
    write_public(&output.join(model_setup_name), &model_setup)?;
    let artifacts = vec![
        ArtifactRow {
            name: provider_name,
            bytes: provider.len(),
            blake3: blake3::hash(&provider).to_hex().to_string(),
            secret: true,
        },
        ArtifactRow {
            name: verifier_lot_name,
            bytes: verifier_lot.len(),
            blake3: blake3::hash(&verifier_lot).to_hex().to_string(),
            secret: true,
        },
        ArtifactRow {
            name: model_setup_name,
            bytes: model_setup.len(),
            blake3: blake3::hash(&model_setup).to_hex().to_string(),
            secret: false,
        },
        ArtifactRow {
            name: verifier_name,
            bytes: verifier.len(),
            blake3: blake3::hash(&verifier).to_hex().to_string(),
            secret: true,
        },
    ];
    if git_sha()? != setup_git_sha || git_dirty()? {
        return Err("C4.1 repository revision changed during setup".into());
    }
    let manifest = serde_json::to_vec_pretty(&Manifest {
        schema: 1,
        profile: "C41SC1-party-separated-real-AES-v1",
        git_sha: setup_git_sha,
        git_dirty: false,
        real_aes_pcg: true,
        response_index,
        cells: C41_PRODUCTION_CELLS,
        seed_rows: C41_PRODUCTION_SEED_ROWS,
        total_sub_corrs: C41_PRODUCTION_TOTAL_SUB_CORRS,
        total_full_corrs: C41_PRODUCTION_TOTAL_FULL_CORRS,
        ordinary_sub_corrs: C41_PRODUCTION_ORDINARY_SUB_CORRS,
        ordinary_full_corrs: C41_PRODUCTION_ORDINARY_FULL_CORRS,
        model_initialization_wall_s,
        pcg_setup_wall_s,
        typed_setup_wall_s,
        verifier_lot_materialize_wall_s,
        materialized_verifier_lot_payload_bytes: (2
            * C41_PRODUCTION_CELLS
            * std::mem::size_of::<volta_field::Fp2>())
            as u64,
        setup_comm_bytes,
        typed_setup_comm_bytes: exchange.metrics.total_typed_setup_bytes,
        conditional_soundness_bits: exchange.metrics.conditional_soundness_bits,
        conditional_weight_zk_bits: exchange.metrics.conditional_weight_zk_bits,
        artifacts,
    })?;
    write_public(&output.join("manifest.json"), &manifest)?;
    File::open(&output)?.sync_all()?;
    println!("{}", String::from_utf8(manifest)?);
    Ok(())
}
