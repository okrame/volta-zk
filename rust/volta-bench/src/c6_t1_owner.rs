//! Frozen GPT-2 `100+50` workload owner shared by C6 record and production
//! drivers.
//!
//! Construction performs the canonical forward exactly once and checks the
//! generated decode against the registered golden artifact.  The owner is
//! deliberately not `Clone`: downstream C6 stages borrow or consume this
//! same allocation instead of rebuilding the response under another PCG
//! attempt.

use std::fs;
use std::path::Path;
use std::process::Command;

#[cfg(feature = "c6-trace")]
use volta_accel::{Backend, BackendKind};
use volta_gpt2::{
    argmax, band_model_witness, decode_step, forward_model, forward_model_tokens, load_model,
    BandModelWitness, Gpt2Model, KvCache, ModelWitness,
};

#[cfg(feature = "c6-trace")]
use volta_mac::{
    C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan, ProverAuthed, Transcript,
    VerifierKey,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_authenticated_whir_p3::{
    create_c61_production_coefficient_owner, C61ProductionCoefficientOwner,
    C61SignedCoefficientPlacement,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_public_compression::C61NativeComponent;
#[cfg(feature = "c6-trace")]
use volta_pcs::{
    commit_resident, free_resident_matrix, layout_gpt2_embed_c3, layout_gpt2_weights_c3,
    open_multi_zk_resident, verify_multi_open, BlockClaim, C6HiddenUBundleWitness,
    C6HiddenUFamilyWitness, C6PersistentCacheStateWitness, Commitment, MultiOpenProof, C3_EMBED,
    C3_WEIGHTS,
};
#[cfg(feature = "c6-trace")]
use volta_proto::{
    build_c6_t1_production_response_owner, cattn_permuted, C6ProductionPairedPcgAttempt,
    C6T1ProductionResponseOwner,
};

#[cfg(feature = "c6-trace")]
use crate::c6_t1_live_sources::materialize_c6_t1_genesis_cache_states;

pub const C6_T1_PROMPT_TOKENS: usize = 100;
pub const C6_T1_DECODE_TOKENS: usize = 50;

const GOLDEN_HEADER_BYTES: usize = 16;
const GOLDEN_BYTES: usize = GOLDEN_HEADER_BYTES + 4 * C6_T1_DECODE_TOKENS + 8 * C6_T1_DECODE_TOKENS;
const GPT2_BIN_SHA256: &str = "bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a";
const GPT2_JSON_SHA256: &str = "98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c";
const GPT2_PARAMS_SHA256: &str = "264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac";
const GOLDEN_P6_SHA256: &str = "e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862";

/// Same-allocation owner for the frozen witness generator output.
pub struct C6T1WorkloadOwner {
    model: Gpt2Model,
    prefill: ModelWitness,
    decode: BandModelWitness,
    sequence: Vec<u32>,
}

impl C6T1WorkloadOwner {
    pub fn model(&self) -> &Gpt2Model {
        &self.model
    }

    pub fn prefill(&self) -> &ModelWitness {
        &self.prefill
    }

    pub fn decode(&self) -> &BandModelWitness {
        &self.decode
    }

    pub fn sequence(&self) -> &[u32] {
        &self.sequence
    }
}

/// Same-allocation workload, response proof/runtime and exact cache-state
/// owners. The production runner moves this object forward; no constructor
/// accepts detached claims, cache slabs, or a second witness pass.
#[cfg(feature = "c6-trace")]
pub struct C6T1ProductionOwnerExport {
    workload: C6T1WorkloadOwner,
    response: C6T1ProductionResponseOwner,
    native_claims: C6T1NativeClaimOwner,
    predecessor_cache: C6PersistentCacheStateWitness,
    successor_cache: C6PersistentCacheStateWitness,
}

/// Exact ordered model/embedding claim boundary exported from the one T1
/// response.  The points are translated once into the consolidated C3
/// commitment domains; authenticated targets and verifier keys remain the
/// objects emitted by that response rather than caller-supplied values.
#[cfg(feature = "c6-trace")]
pub struct C6T1NativeClaimOwner {
    model_claims: Vec<BlockClaim>,
    embedding_claims: Vec<BlockClaim>,
    primary_model_targets: Vec<ProverAuthed>,
    primary_embedding_targets: Vec<ProverAuthed>,
    primary_model_keys: Vec<VerifierKey>,
    primary_embedding_keys: Vec<VerifierKey>,
}

/// Prover-private randomness fixed independently of transcript challenges and
/// the verifier MAC secrets.  Commitment padding seeds are setup-owned;
/// opening-mask seeds are response-fresh and role-separated.
#[cfg(feature = "c6-trace")]
#[derive(Clone, Copy)]
pub struct C6T1HiddenUEntropy {
    pub model_pad_seed: [u8; 32],
    pub embedding_pad_seed: [u8; 32],
    pub model_mask_seed: [u8; 32],
    pub embedding_mask_seed: [u8; 32],
}

/// Exact retained legacy openings and the hidden-u witnesses derived from
/// those same proof objects.  The enclosing response owner remains present,
/// so no caller can attach a detached 96/6 schedule after this boundary.
#[cfg(feature = "c6-trace")]
pub struct C6T1HiddenUOwner {
    response: C6T1ProductionOwnerExport,
    model_commitment: Commitment,
    embedding_commitment: Commitment,
    model_opening: MultiOpenProof,
    embedding_opening: MultiOpenProof,
    hidden_bundle: C6HiddenUBundleWitness,
}

/// Hidden-u response owner plus the two durable native coefficient sources.
/// The D28/D27 files are derived directly from the same model allocation and
/// are the only coefficient loader admitted by the exact four-chain runner.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C6T1PersistedNativeOwner {
    hidden: C6T1HiddenUOwner,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C6T1PersistedNativeOwner {
    pub fn hidden(&self) -> &C6T1HiddenUOwner {
        &self.hidden
    }

    pub fn model_coefficients(&self) -> &C61ProductionCoefficientOwner {
        &self.model_coefficients
    }

    pub fn embedding_coefficients(&self) -> &C61ProductionCoefficientOwner {
        &self.embedding_coefficients
    }

    pub fn into_parts(
        self,
    ) -> (C6T1HiddenUOwner, C61ProductionCoefficientOwner, C61ProductionCoefficientOwner) {
        (self.hidden, self.model_coefficients, self.embedding_coefficients)
    }
}

#[cfg(feature = "c6-trace")]
impl C6T1HiddenUOwner {
    pub fn response(&self) -> &C6T1ProductionOwnerExport {
        &self.response
    }

    pub fn model_commitment(&self) -> &Commitment {
        &self.model_commitment
    }

    pub fn embedding_commitment(&self) -> &Commitment {
        &self.embedding_commitment
    }

    pub fn model_opening(&self) -> &MultiOpenProof {
        &self.model_opening
    }

    pub fn embedding_opening(&self) -> &MultiOpenProof {
        &self.embedding_opening
    }

    pub fn hidden_bundle(&self) -> &C6HiddenUBundleWitness {
        &self.hidden_bundle
    }

    pub fn into_parts(
        self,
    ) -> (
        C6T1ProductionOwnerExport,
        Commitment,
        Commitment,
        MultiOpenProof,
        MultiOpenProof,
        C6HiddenUBundleWitness,
    ) {
        (
            self.response,
            self.model_commitment,
            self.embedding_commitment,
            self.model_opening,
            self.embedding_opening,
            self.hidden_bundle,
        )
    }
}

#[cfg(feature = "c6-trace")]
impl C6T1NativeClaimOwner {
    fn from_response(response: &C6T1ProductionResponseOwner) -> Result<Self, String> {
        let output = response.prover_output();
        let verifier = response.verifier_output();
        if output.weight_claims.len() != 96
            || output.embed_claims.len() != 6
            || verifier.weight_keys.len() != 96
            || verifier.embed_keys.len() != 6
        {
            return Err("C6SPR12 native claim owner has the wrong 96/6 census".to_owned());
        }

        let model_layout = layout_gpt2_weights_c3();
        let model_claims = output
            .weight_claims
            .iter()
            .enumerate()
            .map(|(index, claim)| {
                let phase_slot = index % (4 * volta_gpt2::L);
                model_layout.block_claim(phase_slot / 4, phase_slot % 4, &claim.point)
            })
            .collect::<Vec<_>>();
        let embedding_layout = layout_gpt2_embed_c3();
        let embedding_claims = output
            .embed_claims
            .iter()
            .enumerate()
            .map(|(index, claim)| {
                embedding_layout.block_claim(if index % 3 == 2 { 1 } else { 0 }, &claim.point)
            })
            .collect::<Vec<_>>();
        if verifier
            .weight_keys
            .iter()
            .zip(&model_claims)
            .any(|((point, _), claim)| point != &claim.point)
            || verifier
                .embed_keys
                .iter()
                .zip(&embedding_claims)
                .any(|((point, _), claim)| point != &claim.point)
        {
            return Err("C6SPR12 prover/verifier native claim points differ".to_owned());
        }

        Ok(Self {
            model_claims,
            embedding_claims,
            primary_model_targets: output.weight_claims.iter().map(|claim| claim.value).collect(),
            primary_embedding_targets: output
                .embed_claims
                .iter()
                .map(|claim| claim.value)
                .collect(),
            primary_model_keys: verifier.weight_keys.iter().map(|(_, key)| *key).collect(),
            primary_embedding_keys: verifier.embed_keys.iter().map(|(_, key)| *key).collect(),
        })
    }

    pub fn model_claims(&self) -> &[BlockClaim] {
        &self.model_claims
    }

    pub fn embedding_claims(&self) -> &[BlockClaim] {
        &self.embedding_claims
    }

    pub fn primary_model_targets(&self) -> &[ProverAuthed] {
        &self.primary_model_targets
    }

    pub fn primary_embedding_targets(&self) -> &[ProverAuthed] {
        &self.primary_embedding_targets
    }

    pub fn primary_model_keys(&self) -> &[VerifierKey] {
        &self.primary_model_keys
    }

    pub fn primary_embedding_keys(&self) -> &[VerifierKey] {
        &self.primary_embedding_keys
    }
}

#[cfg(feature = "c6-trace")]
impl C6T1ProductionOwnerExport {
    pub fn workload(&self) -> &C6T1WorkloadOwner {
        &self.workload
    }

    pub fn response(&self) -> &C6T1ProductionResponseOwner {
        &self.response
    }

    pub fn native_claims(&self) -> &C6T1NativeClaimOwner {
        &self.native_claims
    }

    pub fn predecessor_cache(&self) -> &C6PersistentCacheStateWitness {
        &self.predecessor_cache
    }

    pub fn successor_cache(&self) -> &C6PersistentCacheStateWitness {
        &self.successor_cache
    }

    /// Move the one-response owners into the downstream full-chain runner.
    /// No field is cloneable here: the exact response, its native claims and
    /// both cache states continue along one linear ownership path.
    pub fn into_parts(
        self,
    ) -> (
        C6T1WorkloadOwner,
        C6T1ProductionResponseOwner,
        C6T1NativeClaimOwner,
        C6PersistentCacheStateWitness,
        C6PersistentCacheStateWitness,
    ) {
        (
            self.workload,
            self.response,
            self.native_claims,
            self.predecessor_cache,
            self.successor_cache,
        )
    }
}

/// Consume the frozen workload owner into the production response lifecycle.
/// Cache states are derived from the already-owned K/V slabs before the same
/// model witness is passed to the real/AES-PCG response constructor.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn execute_c6_t1_production_owner_export(
    workload: C6T1WorkloadOwner,
    statement_digest: [u8; 32],
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1ProductionOwnerExport, String> {
    let (predecessor_cache, successor_cache) =
        materialize_c6_t1_genesis_cache_states(workload.prefill(), workload.decode())?;
    let response = build_c6_t1_production_response_owner(
        workload.model(),
        workload.prefill(),
        workload.decode(),
        workload.sequence(),
        statement_digest,
        installed_plans,
        extraction_maps,
        attempt,
        provider_transcript,
        verifier_transcript,
    )?;
    let native_claims = C6T1NativeClaimOwner::from_response(&response)?;
    Ok(C6T1ProductionOwnerExport {
        workload,
        response,
        native_claims,
        predecessor_cache,
        successor_cache,
    })
}

/// Extend the exact response owner with both retained C3 multi-openings and
/// the hidden-u bundle derived from those proof objects.  Both openings run
/// on the already-live primary real-PCG tape; the verifier mirror consumes
/// the corresponding primary context before this owner is released.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn attach_c6_t1_hidden_u_owner(
    response: C6T1ProductionOwnerExport,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    entropy: C6T1HiddenUEntropy,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1HiddenUOwner, String> {
    let seeds = [
        entropy.model_pad_seed,
        entropy.embedding_pad_seed,
        entropy.model_mask_seed,
        entropy.embedding_mask_seed,
    ];
    if backend.kind() != BackendKind::CudaResident
        || seeds.iter().any(|seed| *seed == [0; 32])
        || (0..seeds.len()).any(|left| seeds[left + 1..].contains(&seeds[left]))
    {
        return Err(
            "C6SPR12 hidden-u owner requires CUDA-resident execution and four separated nonzero seeds"
                .to_owned(),
        );
    }
    if !attempt.prover_streams_array_mut()[0].uses_pooled_pcg() {
        return Err("C6SPR12 hidden-u owner forbids mock PCG state".to_owned());
    }

    let model_layout = layout_gpt2_weights_c3();
    let mut model_coefficients = Vec::new();
    model_coefficients
        .try_reserve_exact(model_layout.total_len)
        .map_err(|_| "C6SPR12 model coefficient allocation failed".to_owned())?;
    model_coefficients.resize(model_layout.total_len, 0i16);
    for layer in 0..volta_gpt2::L {
        let weights = &response.workload().model().layers[layer].0;
        let c_attn = cattn_permuted(&weights.c_attn);
        model_layout.place_layer(
            &mut model_coefficients,
            layer,
            [&c_attn, &weights.attn_proj, &weights.ffn_up, &weights.ffn_down],
        );
    }
    let model_claims = response
        .native_claims()
        .model_claims()
        .iter()
        .cloned()
        .zip(response.native_claims().primary_model_targets().iter().copied())
        .collect::<Vec<_>>();
    let (model_commitment, model_matrix) =
        commit_resident(&model_coefficients, &C3_WEIGHTS, entropy.model_pad_seed, backend)
            .map_err(|error| format!("C6SPR12 resident model commitment: {error}"))?;
    drop(model_coefficients);
    let mut model_domains =
        volta_proto::logup::Doms::new(volta_proto::block_proof::layer_dom_base(242));
    let model_domain_s = model_domains.take(1);
    let model_domain_zb = model_domains.take(1);
    let model_opening_result = open_multi_zk_resident(
        &model_matrix,
        &model_claims,
        &mut attempt.prover_streams_array_mut()[0],
        model_domain_s,
        model_domain_zb,
        entropy.model_mask_seed,
        provider_transcript,
        backend,
    );
    let model_cleanup = free_resident_matrix(model_matrix, backend);
    let (model_opening, _) =
        model_opening_result.map_err(|error| format!("C6SPR12 resident model opening: {error}"))?;
    model_cleanup.map_err(|error| format!("C6SPR12 resident model cleanup: {error:?}"))?;

    let embedding_layout = layout_gpt2_embed_c3();
    let embedding_coefficients = embedding_layout
        .place(&[&response.workload().model().wte, &response.workload().model().wpe]);
    let embedding_claims = response
        .native_claims()
        .embedding_claims()
        .iter()
        .cloned()
        .zip(response.native_claims().primary_embedding_targets().iter().copied())
        .collect::<Vec<_>>();
    let (embedding_commitment, embedding_matrix) =
        commit_resident(&embedding_coefficients, &C3_EMBED, entropy.embedding_pad_seed, backend)
            .map_err(|error| format!("C6SPR12 resident embedding commitment: {error}"))?;
    drop(embedding_coefficients);
    let mut embedding_domains =
        volta_proto::logup::Doms::new(volta_proto::block_proof::layer_dom_base(253));
    let embedding_domain_s = embedding_domains.take(1);
    let embedding_domain_zb = embedding_domains.take(1);
    let embedding_opening_result = open_multi_zk_resident(
        &embedding_matrix,
        &embedding_claims,
        &mut attempt.prover_streams_array_mut()[0],
        embedding_domain_s,
        embedding_domain_zb,
        entropy.embedding_mask_seed,
        provider_transcript,
        backend,
    );
    let embedding_cleanup = free_resident_matrix(embedding_matrix, backend);
    let (embedding_opening, _) = embedding_opening_result
        .map_err(|error| format!("C6SPR12 resident embedding opening: {error}"))?;
    embedding_cleanup.map_err(|error| format!("C6SPR12 resident embedding cleanup: {error:?}"))?;

    let model_verifier_claims = response
        .native_claims()
        .model_claims()
        .iter()
        .cloned()
        .zip(response.native_claims().primary_model_keys().iter().copied())
        .collect::<Vec<_>>();
    let embedding_verifier_claims = response
        .native_claims()
        .embedding_claims()
        .iter()
        .cloned()
        .zip(response.native_claims().primary_embedding_keys().iter().copied())
        .collect::<Vec<_>>();
    let verifier_context = &mut attempt.verifier_contexts_array_mut()[0];
    if !verify_multi_open(
        &model_commitment.root,
        &C3_WEIGHTS,
        &model_verifier_claims,
        &model_opening,
        verifier_context,
        model_domain_s,
        model_domain_zb,
        verifier_transcript,
    ) || !verify_multi_open(
        &embedding_commitment.root,
        &C3_EMBED,
        &embedding_verifier_claims,
        &embedding_opening,
        verifier_context,
        embedding_domain_s,
        embedding_domain_zb,
        verifier_transcript,
    ) {
        return Err("C6SPR12 retained hidden-u multi-opening verification failed".to_owned());
    }

    let model_hidden = C6HiddenUFamilyWitness::from_retained_multi_open(
        volta_pcs::C6HiddenULayout::production_weights(),
        response.native_claims().model_claims(),
        &model_opening,
    )
    .map_err(|error| error.to_string())?;
    let embedding_hidden = C6HiddenUFamilyWitness::from_retained_multi_open(
        volta_pcs::C6HiddenULayout::production_embed(),
        response.native_claims().embedding_claims(),
        &embedding_opening,
    )
    .map_err(|error| error.to_string())?;
    let hidden_bundle = C6HiddenUBundleWitness::production(model_hidden, embedding_hidden)
        .map_err(|error| error.to_string())?;

    Ok(C6T1HiddenUOwner {
        response,
        model_commitment,
        embedding_commitment,
        model_opening,
        embedding_opening,
        hidden_bundle,
    })
}

/// Persist the exact D28 model and D27 embedding polynomials without first
/// materializing either padded Goldilocks vector. Tensor rows are written at
/// their consolidated C3 offsets; sparse-file gaps and suffixes are the
/// canonical zero padding consumed by both native repetitions.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn persist_c6_t1_native_coefficient_owners(
    hidden: C6T1HiddenUOwner,
    root: &Path,
    session_digest: [u8; 32],
) -> Result<C6T1PersistedNativeOwner, String> {
    if session_digest == [0; 32] || !root.is_dir() {
        return Err("C6SPR12 native coefficient root/session preflight failed".to_owned());
    }
    let model = hidden.response().workload().model();
    let model_layout = layout_gpt2_weights_c3();
    let c_attn =
        model.layers.iter().map(|layer| cattn_permuted(&layer.0.c_attn)).collect::<Vec<_>>();
    let mut model_placements = Vec::with_capacity(4 * volta_gpt2::L);
    for layer in 0..volta_gpt2::L {
        let weights = &model.layers[layer].0;
        let values: [&[i16]; 4] =
            [&c_attn[layer], &weights.attn_proj, &weights.ffn_up, &weights.ffn_down];
        for (slot, values) in model_layout.layer.tensors.iter().zip(values) {
            model_placements.push(C61SignedCoefficientPlacement::new(
                values,
                slot.k,
                slot.n,
                layer * model_layout.layer_stride + slot.offset,
                slot.n_pad,
            )?);
        }
    }
    let model_coefficients = create_c61_production_coefficient_owner(
        &root.join("model"),
        C61NativeComponent::Model,
        session_digest,
        &model_placements,
    )?;
    drop(model_placements);
    drop(c_attn);

    let embedding_layout = layout_gpt2_embed_c3();
    let embedding_values: [&[i16]; 2] = [&model.wte, &model.wpe];
    let embedding_placements = embedding_layout
        .tensors
        .iter()
        .zip(embedding_values)
        .map(|(slot, values)| {
            C61SignedCoefficientPlacement::new(values, slot.k, slot.n, slot.offset, slot.n_pad)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let embedding_coefficients = create_c61_production_coefficient_owner(
        &root.join("embedding"),
        C61NativeComponent::Embedding,
        session_digest,
        &embedding_placements,
    )?;
    drop(embedding_placements);

    Ok(C6T1PersistedNativeOwner { hidden, model_coefficients, embedding_coefficients })
}

/// Load, validate and execute the exact frozen T1 witness generator once.
pub fn build_c6_t1_workload_owner(weights: &Path) -> Result<C6T1WorkloadOwner, String> {
    verify_inputs(weights)?;
    let model = load_model(weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout()?;
    let prefill = forward_model(&model, C6_T1_PROMPT_TOKENS);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, C6_T1_PROMPT_TOKENS);
    let mut generated = Vec::with_capacity(C6_T1_DECODE_TOKENS);
    let mut next = argmax(&prefill.logits);
    for position in 0..C6_T1_DECODE_TOKENS {
        generated.push(next);
        next = argmax(&decode_step(&model, &mut cache, next, C6_T1_PROMPT_TOKENS + position));
    }
    let golden = parse_golden_tokens(
        &fs::read(weights.join("golden-p6.bin"))
            .map_err(|error| format!("read golden-p6: {error}"))?,
    )?;
    if generated != golden {
        return Err("C6 T1 decode differs from frozen golden-p6".to_owned());
    }
    let mut sequence = model.p.tokens[..C6_T1_PROMPT_TOKENS].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let decode = band_model_witness(&model, &full, C6_T1_PROMPT_TOKENS);
    if prefill.t != C6_T1_PROMPT_TOKENS
        || decode.t0 != C6_T1_PROMPT_TOKENS
        || decode.q != C6_T1_DECODE_TOKENS
    {
        return Err("C6 T1 witness generator changed its frozen geometry".to_owned());
    }
    Ok(C6T1WorkloadOwner { model, prefill, decode, sequence })
}

fn verify_inputs(weights: &Path) -> Result<(), String> {
    for (name, expected) in [
        ("gpt2s-q.bin", GPT2_BIN_SHA256),
        ("gpt2s-q.json", GPT2_JSON_SHA256),
        ("gpt2s-q.params", GPT2_PARAMS_SHA256),
        ("golden-p6.bin", GOLDEN_P6_SHA256),
    ] {
        let observed = c6_t1_sha256_file(&weights.join(name))?;
        if observed != expected {
            return Err(format!("{name} digest changed: expected {expected}, got {observed}"));
        }
    }
    Ok(())
}

/// Canonical file digest helper shared with the append-only census record.
pub fn c6_t1_sha256_file(path: &Path) -> Result<String, String> {
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

fn parse_golden_tokens(bytes: &[u8]) -> Result<Vec<u32>, String> {
    if bytes.len() != GOLDEN_BYTES || &bytes[..8] != b"VGOLD2\0\0" {
        return Err("golden-p6 has wrong canonical framing".to_owned());
    }
    let prompt = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let decode = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if (prompt, decode) != (C6_T1_PROMPT_TOKENS, C6_T1_DECODE_TOKENS) {
        return Err("golden-p6 has wrong canonical geometry".to_owned());
    }
    Ok((0..C6_T1_DECODE_TOKENS)
        .map(|index| {
            let offset = GOLDEN_HEADER_BYTES + 4 * index;
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
        })
        .collect())
}
