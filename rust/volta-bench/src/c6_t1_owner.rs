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
    C6CanonicalTargetProfile, C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan,
    ProverAuthed, Transcript, VerifierKey,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_authenticated_whir_p3::{
    create_c61_production_coefficient_owner, C61ProductionCoefficientOwner,
    C61ProductionCoefficientSessionBinding, C61SignedCoefficientPlacement,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_public_compression::C61NativeComponent;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::{
    build_c61_production_model_embedding_public_statement, C61NativeChainId,
    C61NativeCommitmentDescriptor, C61NativeVerifierChainStatement, C61_EMBEDDING_POLYNOMIAL_LOG2,
    C61_MODEL_POLYNOMIAL_LOG2,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::{
    commit_resident, free_resident_matrix, layout_gpt2_embed_c3, layout_gpt2_weights_c3,
    open_multi_zk_resident, verify_multi_open, BlockClaim, C6HiddenUBundleWitness,
    C6HiddenUFamilyWitness, C6PersistentCacheStateWitness, Commitment, MultiOpenProof, C3_EMBED,
    C3_WEIGHTS,
};
#[cfg(feature = "c6-trace")]
use volta_proto::{
    build_c6_t1_production_response_owner, build_c62_continuation_production_response_owner,
    cattn_permuted, C6PairedNativeTargetValues, C6ProductionPairedPcgAttempt,
    C6T1ProductionResponseOwner,
    C6T1ProductionResponseVerifierReplay,
};

#[cfg(feature = "c6-trace")]
use crate::c6_t1_live_sources::{
    materialize_c6_t1_genesis_cache_states, materialize_c62_continuation_cache_states,
};

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

/// Same-allocation owner for one accepted-prefix continuation.
pub struct C62ContinuationWorkloadOwner {
    model: Gpt2Model,
    full: ModelWitness,
    first: BandModelWitness,
    second: BandModelWitness,
    sequence: Vec<u32>,
    old_context: usize,
}

impl C62ContinuationWorkloadOwner {
    pub fn model(&self) -> &Gpt2Model {
        &self.model
    }

    pub fn full(&self) -> &ModelWitness {
        &self.full
    }

    pub fn first(&self) -> &BandModelWitness {
        &self.first
    }

    pub fn second(&self) -> &BandModelWitness {
        &self.second
    }

    pub fn sequence(&self) -> &[u32] {
        &self.sequence
    }

    pub fn old_context(&self) -> usize {
        self.old_context
    }
}

/// Workload owner admitted by the C6.2 campaign path.
pub enum C62CampaignWorkloadOwner {
    Genesis(C6T1WorkloadOwner),
    Continuation(C62ContinuationWorkloadOwner),
}

impl From<C6T1WorkloadOwner> for C62CampaignWorkloadOwner {
    fn from(value: C6T1WorkloadOwner) -> Self {
        Self::Genesis(value)
    }
}

impl From<C62ContinuationWorkloadOwner> for C62CampaignWorkloadOwner {
    fn from(value: C62ContinuationWorkloadOwner) -> Self {
        Self::Continuation(value)
    }
}

impl C62CampaignWorkloadOwner {
    pub fn model(&self) -> &Gpt2Model {
        match self {
            Self::Genesis(workload) => workload.model(),
            Self::Continuation(workload) => workload.model(),
        }
    }

    pub fn sequence(&self) -> &[u32] {
        match self {
            Self::Genesis(workload) => workload.sequence(),
            Self::Continuation(workload) => workload.sequence(),
        }
    }

    pub fn old_context(&self) -> usize {
        match self {
            Self::Genesis(_) => 0,
            Self::Continuation(workload) => workload.old_context(),
        }
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

/// C6.2 response owner after its cache states were consumed by the early
/// cache precommit.  This type cannot carry a second cache source.
#[cfg(feature = "c6-trace")]
pub struct C62T1ProductionOwnerExport {
    workload: C62CampaignWorkloadOwner,
    response: C6T1ProductionResponseOwner,
    native_claims: C6T1NativeClaimOwner,
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

/// Verifier-only counterpart rebuilt from the strict retained-response replay.
/// The replay already exposes the global C3 points, so this owner neither
/// reconstructs a provider block schedule nor accepts detached keys.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C6T1NativeVerifierClaimOwner {
    model_claims: Vec<BlockClaim>,
    embedding_claims: Vec<BlockClaim>,
    model_keys: Vec<VerifierKey>,
    embedding_keys: Vec<VerifierKey>,
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

/// Linear response owner plus the two durable native coefficient sources.
/// The D28/D27 files are derived directly from the same model allocation and
/// are the only coefficient loader admitted by the exact four-chain runner.
/// No retained Ligero opening or hidden-u witness is constructed on this path.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C6T1PersistedNativeOwner {
    response: C6T1ProductionOwnerExport,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62T1PersistedNativeOwner {
    response: C62T1ProductionOwnerExport,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C6T1PersistedNativeOwner {
    pub fn response(&self) -> &C6T1ProductionOwnerExport {
        &self.response
    }

    pub fn model_coefficients(&self) -> &C61ProductionCoefficientOwner {
        &self.model_coefficients
    }

    pub fn embedding_coefficients(&self) -> &C61ProductionCoefficientOwner {
        &self.embedding_coefficients
    }

    pub fn into_parts(
        self,
    ) -> (C6T1ProductionOwnerExport, C61ProductionCoefficientOwner, C61ProductionCoefficientOwner)
    {
        (self.response, self.model_coefficients, self.embedding_coefficients)
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C62T1PersistedNativeOwner {
    pub fn into_parts(
        self,
    ) -> (C62T1ProductionOwnerExport, C61ProductionCoefficientOwner, C61ProductionCoefficientOwner)
    {
        (self.response, self.model_coefficients, self.embedding_coefficients)
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

    #[cfg(feature = "c61-p3-authenticated-reference")]
    pub fn production_paired_targets(
        &self,
        profile: &C6CanonicalTargetProfile,
        paired: &C6PairedNativeTargetValues,
    ) -> Result<([Vec<ProverAuthed>; 2], [Vec<ProverAuthed>; 2]), String> {
        if paired.inference_profile_digest() != profile.inference_profile_digest
            || paired.cohorts().len() != profile.cohorts.len()
        {
            return Err("C6ICT2 native target owner/profile binding differs".to_owned());
        }
        let coordinates = [
            paired.coordinate_targets(0).map_err(|error| error.to_string())?,
            paired.coordinate_targets(1).map_err(|error| error.to_string())?,
        ];
        let mut model = None;
        let mut embedding = None;
        for (index, cohort) in profile.cohorts.iter().enumerate() {
            match cohort.chain_slot {
                slot if slot == C61NativeComponent::Model as u16 && model.is_none() => {
                    model = Some(index)
                }
                slot if slot == C61NativeComponent::Embedding as u16 && embedding.is_none() => {
                    embedding = Some(index)
                }
                _ => {
                    return Err("C6ICT2 native target profile has an unsupported cohort".to_owned())
                }
            }
        }
        let model = model.ok_or_else(|| "C6ICT2 native target profile omits model".to_owned())?;
        let embedding =
            embedding.ok_or_else(|| "C6ICT2 native target profile omits embedding".to_owned())?;
        if coordinates[0][model].len() != 96
            || coordinates[0][embedding].len() != 6
            || self.primary_model_targets.len() != 96
            || self.primary_embedding_targets.len() != 6
            || coordinates[0][model]
                .iter()
                .zip(&self.primary_model_targets)
                .any(|(evaluated, live)| evaluated.x != live.x)
            || coordinates[0][embedding]
                .iter()
                .zip(&self.primary_embedding_targets)
                .any(|(evaluated, live)| evaluated.x != live.x)
        {
            return Err(
                "C6ICT2 paired target plaintext differs from the live response".to_owned()
            );
        }
        // Tape zero is the authentication already emitted and checked by the
        // response.  The installed evaluator links its plaintext to tape one;
        // it is not a second authority for the response-side MAC share.
        Ok((
            [self.primary_model_targets.clone(), coordinates[1][model].clone()],
            [self.primary_embedding_targets.clone(), coordinates[1][embedding].clone()],
        ))
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C6T1NativeVerifierClaimOwner {
    pub fn from_disk_response(
        response: &C6T1ProductionResponseVerifierReplay,
    ) -> Result<Self, String> {
        let output = response.output();
        if output.weight_keys.len() != 96
            || output.embed_keys.len() != 6
            || output
                .weight_keys
                .iter()
                .any(|(point, _)| point.len() != usize::from(C61_MODEL_POLYNOMIAL_LOG2))
            || output
                .embed_keys
                .iter()
                .any(|(point, _)| point.len() != usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2))
        {
            return Err("C6ICT5 disk native claim owner has the wrong 96+6 geometry".to_owned());
        }
        Ok(Self {
            model_claims: output
                .weight_keys
                .iter()
                .map(|(point, _)| BlockClaim { offset: 0, point: point.clone() })
                .collect(),
            embedding_claims: output
                .embed_keys
                .iter()
                .map(|(point, _)| BlockClaim { offset: 0, point: point.clone() })
                .collect(),
            model_keys: output.weight_keys.iter().map(|(_, key)| *key).collect(),
            embedding_keys: output.embed_keys.iter().map(|(_, key)| *key).collect(),
        })
    }

    pub fn statement(
        &self,
        id: C61NativeChainId,
        commitment: C61NativeCommitmentDescriptor,
    ) -> Result<C61NativeVerifierChainStatement, String> {
        let (claims, keys) = match id.component {
            C61NativeComponent::Model => (&self.model_claims, &self.model_keys),
            C61NativeComponent::Embedding => (&self.embedding_claims, &self.embedding_keys),
            C61NativeComponent::Compiler => {
                return Err("C6ICT5 disk claim owner rejects compiler chains".to_owned())
            }
        };
        let public = build_c61_production_model_embedding_public_statement(id, commitment, claims)
            .map_err(|error| error.to_string())?;
        C61NativeVerifierChainStatement::new(public, keys.clone())
            .map_err(|error| error.to_string())
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

#[cfg(feature = "c6-trace")]
impl C62T1ProductionOwnerExport {
    pub fn workload(&self) -> &C62CampaignWorkloadOwner {
        &self.workload
    }

    pub fn native_claims(&self) -> &C6T1NativeClaimOwner {
        &self.native_claims
    }

    pub fn into_parts(
        self,
    ) -> (C62CampaignWorkloadOwner, C6T1ProductionResponseOwner, C6T1NativeClaimOwner) {
        (self.workload, self.response, self.native_claims)
    }
}

/// Materialize the two genesis cache owners before the C6.2 response starts.
#[cfg(feature = "c6-trace")]
pub fn materialize_c62_t1_cache_states(
    workload: &C62CampaignWorkloadOwner,
) -> Result<(C6PersistentCacheStateWitness, C6PersistentCacheStateWitness), String> {
    match workload {
        C62CampaignWorkloadOwner::Genesis(workload) => {
            materialize_c6_t1_genesis_cache_states(workload.prefill(), workload.decode())
        }
        C62CampaignWorkloadOwner::Continuation(workload) => {
            materialize_c62_continuation_cache_states(
                workload.full(),
                u16::try_from(workload.old_context())
                    .map_err(|_| "C6.2 old context exceeds u16".to_owned())?,
            )
        }
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

/// Consume the frozen workload into the C6.2 response after its exact cache
/// states were consumed by the typed precommit owner.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn execute_c62_t1_production_owner_export(
    workload: C62CampaignWorkloadOwner,
    statement_digest: [u8; 32],
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C62T1ProductionOwnerExport, String> {
    let response = match &workload {
        C62CampaignWorkloadOwner::Genesis(workload) => build_c6_t1_production_response_owner(
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
        )?,
        C62CampaignWorkloadOwner::Continuation(workload) => {
            build_c62_continuation_production_response_owner(
                workload.model(),
                workload.full(),
                workload.first(),
                workload.second(),
                workload.sequence(),
                statement_digest,
                installed_plans,
                extraction_maps,
                attempt,
                provider_transcript,
                verifier_transcript,
            )?
        }
    };
    let native_claims = C6T1NativeClaimOwner::from_response(&response)?;
    Ok(C62T1ProductionOwnerExport { workload, response, native_claims })
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
    response: C6T1ProductionOwnerExport,
    root: &Path,
    session: C61ProductionCoefficientSessionBinding,
) -> Result<C6T1PersistedNativeOwner, String> {
    let session_digest = session.context_digest();
    let (model_coefficients, embedding_coefficients) =
        persist_c6_t1_native_coefficients(response.workload().model(), root, session_digest)?;
    Ok(C6T1PersistedNativeOwner { response, model_coefficients, embedding_coefficients })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn persist_c62_t1_native_coefficient_owners(
    response: C62T1ProductionOwnerExport,
    root: &Path,
    session: C61ProductionCoefficientSessionBinding,
) -> Result<C62T1PersistedNativeOwner, String> {
    let session_digest = session.context_digest();
    let (model_coefficients, embedding_coefficients) =
        persist_c6_t1_native_coefficients(response.workload().model(), root, session_digest)?;
    Ok(C62T1PersistedNativeOwner { response, model_coefficients, embedding_coefficients })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn create_c62_provider_fixed_coefficient_owners(
    model: &Gpt2Model,
    root: &Path,
    session_digest: [u8; 32],
) -> Result<(C61ProductionCoefficientOwner, C61ProductionCoefficientOwner), String> {
    persist_c6_t1_native_coefficients(model, root, session_digest)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn persist_c6_t1_native_coefficients(
    model: &Gpt2Model,
    root: &Path,
    session_digest: [u8; 32],
) -> Result<(C61ProductionCoefficientOwner, C61ProductionCoefficientOwner), String> {
    if !root.is_dir() {
        return Err("C6SPR12 native coefficient root/session preflight failed".to_owned());
    }
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

    Ok((model_coefficients, embedding_coefficients))
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

/// Load and validate one chained C6.2 continuation witness.
pub fn build_c62_continuation_workload_owner(
    weights: &Path,
    sequence: Vec<u32>,
    old_context: usize,
) -> Result<C62ContinuationWorkloadOwner, String> {
    verify_inputs(weights)?;
    let model = load_model(weights).map_err(|error| format!("load model: {error}"))?;
    model.validate_layout()?;
    if old_context < 150
        || old_context > 900
        || old_context % 50 != 0
        || sequence.len() != old_context + 50
        || sequence.len() > 1_024
        || sequence[..C6_T1_PROMPT_TOKENS] != model.p.tokens[..C6_T1_PROMPT_TOKENS]
    {
        return Err("C6.2 continuation workload geometry differs".to_owned());
    }
    let first_full = forward_model_tokens(&model, &sequence[..old_context + 25]);
    let full = forward_model_tokens(&model, &sequence);
    let first = band_model_witness(&model, &first_full, old_context - 1);
    let second = band_model_witness(&model, &full, old_context + 25);
    if first.t0 != old_context - 1
        || first.q != 26
        || second.t0 != old_context + 25
        || second.q != 25
        || full.t != old_context + 50
    {
        return Err("C6.2 continuation witness generator changed its geometry".to_owned());
    }
    Ok(C62ContinuationWorkloadOwner { model, full, first, second, sequence, old_context })
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

#[cfg(test)]
mod tests {
    #[test]
    fn paired_native_targets_retain_live_tape_zero_and_link_plaintexts() {
        let source = include_str!("c6_t1_owner.rs");
        let body = source
            .split_once("pub fn production_paired_targets(")
            .unwrap()
            .1
            .split_once("\n    }\n}")
            .unwrap()
            .0;
        assert!(body.contains("evaluated.x != live.x"));
        assert!(body.contains("self.primary_model_targets.clone()"));
        assert!(body.contains("self.primary_embedding_targets.clone()"));
        assert!(!body.contains("coordinates[0][model].clone()"));
        assert!(!body.contains("coordinates[0][embedding].clone()"));
    }

    #[test]
    fn native_persistence_source_guard_bypasses_hidden_u_owner() {
        let source = include_str!("c6_t1_owner.rs");
        let owner = source
            .split("pub struct C6T1PersistedNativeOwner")
            .nth(1)
            .unwrap()
            .split("impl C6T1PersistedNativeOwner")
            .next()
            .unwrap();
        assert!(owner.contains("response: C6T1ProductionOwnerExport"));
        assert!(!owner.contains("C6T1HiddenUOwner"));

        let persistence = source
            .split("pub fn persist_c6_t1_native_coefficient_owners")
            .nth(1)
            .unwrap()
            .split("pub fn persist_c62_t1_native_coefficient_owners")
            .next()
            .unwrap();
        assert!(persistence.contains("response: C6T1ProductionOwnerExport"));
        assert!(persistence.contains("session: C61ProductionCoefficientSessionBinding"));
        assert!(!persistence.contains("session_digest: [u8; 32]"));
        assert!(persistence.contains("response.workload().model()"));
        assert!(!persistence.contains("C6T1HiddenUOwner"));
        assert!(!persistence.contains("hidden_bundle"));
        assert!(!persistence.contains("attach_c6_t1_hidden_u_owner"));

        let c62_persistence = source
            .split("pub fn persist_c62_t1_native_coefficient_owners")
            .nth(1)
            .unwrap()
            .split("fn persist_c6_t1_native_coefficients")
            .next()
            .unwrap();
        assert!(c62_persistence.contains("response: C62T1ProductionOwnerExport"));
        assert!(c62_persistence.contains("session: C61ProductionCoefficientSessionBinding"));
        assert!(!c62_persistence.contains("session_digest: [u8; 32]"));
        assert!(c62_persistence.contains("response.workload().model()"));
        assert!(!c62_persistence.contains("C6T1HiddenUOwner"));
    }
}
