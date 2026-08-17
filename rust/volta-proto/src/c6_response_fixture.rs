//! Feature-only complete-response fixture for the sealed C6 residual path.
//!
//! This module deliberately keeps the historical model proof on both roles
//! while exporting only the installed residual compiler state, live witness
//! prefixes and continued correlation/transcript state needed by C6RSC3.

use std::path::PathBuf;
use std::time::Instant;

use volta_field::{Fp, Fp2};
use volta_gpt2::Gpt2VerifierModel;
use volta_gpt2::{
    band_model_witness, forward_model, forward_model_tokens, generate, load_model, KvCache, D, H, L,
};
use volta_mac::{
    begin_c6_prover_trace, begin_c6_runtime_instance_capture, begin_c6_verifier_trace,
    compile_c6_operation_trace_for_role_with_target_profile,
    derive_c6_runtime_instance_from_trace_diagnostic, finish_c6_prover_trace,
    finish_c6_verifier_trace, take_c6_product_closure_messages, C6CanonicalTargetProfile,
    C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan, C6InstanceExtractionRole,
    C6NativeTargetProfileArtifact, C6RuntimeInstanceValues, C6TraceSourceManifest,
    C6TraceTargetCohort, C6TraceTargetProfile, C6TraceToken, CorrScheduleAudit, CorrScheduleRole,
    CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

use crate::block_proof::layer_dom_base;
use crate::c6::C6PairedDeltaResidual;
use crate::c6_cache_fold::{
    begin_c6_cache_fold_trace, C6CacheFoldAppendSourcePlan, C6CacheFoldKind,
    C6CacheFoldPairedVerifierTargets, C6CacheFoldParty, C6CacheFoldTargetCorrectionFrame,
    C6CacheFoldTargetFixedCorrections, C6CacheFoldTargetInlineProver,
    C6CacheFoldTargetInlineVerifier, C6CacheFoldTargetProverOwner,
    C6CacheFoldTargetPublicCorrectionFrame, C6CacheFoldTargetPublicSchedule,
    C6CacheFoldTraceSnapshot, C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES,
};
use crate::c6_production_pcg::{C6ProductionPairedPcgAttempt, C6ProductionPairedSourceWitness};
use crate::c6_residual::{
    C6CompiledLinearResidual, C6CompiledNativeTargetFunctional,
    C6InstalledClosureEvaluationMemoryCensus, C6PairedNativeTargetValues,
    C6PairedResidualAuxiliaryWitness, C6PairedResidualClosureWitness, C6PairedResidualLeafWitness,
    C6ResidualClaimsBoundContext, C6ResidualDirectAlphaPoints, C6ResidualDirectPostClaimPoints,
    C6ResidualError, C6ResidualFusedWitnessView, C6ResidualProductClaimCoordinate,
    C6ResidualProductPublicClaim, C6ResidualRelationChallenges, C6ResidualRelationManifest,
    C6ResidualRelationRootBound, C6ResidualRetainedChallenges, C6_RESIDUAL_TRACE_FIXTURE_LOCK,
};
use crate::c6_source::{
    C6PairedSourceWitness, C6SourceCoordinate, C6SourceScheduleProverFollower,
    C6SourceScheduleVerifierFollower,
};
use crate::logup::Doms;
use crate::model_proof::{
    prove_response_c6_cache_inline,
    prove_response_continuation_private_logits_c6_cache_inline,
    prove_response_private_logits_c6_cache_inline, verify_response_c6_cache_inline_from_profile,
    verify_response_continuation_private_logits_c6_cache_inline_from_profile,
    verify_response_private_logits_c6_cache_inline_from_profile, C6GrandResidualProverRoots,
    C6GrandResidualVerifierRoots, ChunkPub, ChunkRef, ModelOut, ModelOutV, ModelProof,
    PrivateChunkPub,
};
use crate::model_proof_codec::C6RetainedResponseProof;
use crate::model_proof_codec::{decode_model_proof_canonical, encode_model_proof_canonical};
use crate::prod_check::{prod_batch_prover, prod_batch_verify, ProdProof};

const RESPONSE_T: usize = 4;
const RESPONSE_Q: usize = 2;
const RESPONSE_LEAF_LOG2: u8 = 20;
const RESPONSE_AUXILIARY_LOG2: u8 = 15;
const RESPONSE_PRODUCTION_LEAF_LOG2: u8 = 23;
const RESPONSE_PRODUCTION_AUXILIARY_LOG2: u8 = 15;
const C6_GPT2_MODEL_TARGET_COHORT: u32 = 1;
const C6_GPT2_EMBED_TARGET_COHORT: u32 = 2;
const C6_GPT2_MODEL_CHAIN_SLOT: u16 = 1;
const C6_GPT2_EMBED_CHAIN_SLOT: u16 = 2;
const C6_GPT2_MODEL_POLYNOMIAL_LOG2: u8 = 28;
const C6_GPT2_EMBED_POLYNOMIAL_LOG2: u8 = 27;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResponseResidualCensus {
    pub source_groups: u64,
    pub corrected_targets: u64,
    pub source_cells: u64,
    pub verifier_linear_auxiliary_source_cells: u64,
    pub scheduled_sources: u32,
    pub product_closures: u32,
    pub product_triples: u64,
    pub zero_roots: u32,
    pub native_target_cohorts: u32,
    pub native_targets: u32,
    pub native_target_setup_bytes: u64,
    pub native_functional_sources: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ResponseResidualTiming {
    pub provider_response_and_residual_ns: u64,
    pub verifier_response_and_residual_ns: u64,
}

pub struct C6ResponseResidualFixture {
    provider_operation_plan: C6InstalledOperationPlan,
    provider_extraction: C6DecodedInstanceExtractionPlan,
    provider_runtime: C6RuntimeInstanceValues,
    provider_linear: C6CompiledLinearResidual,
    verifier_operation_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    verifier_runtime: C6RuntimeInstanceValues,
    verifier_linear: C6CompiledLinearResidual,
    relation: C6ResidualRelationChallenges,
    leaf: C6PairedResidualLeafWitness,
    closure: C6PairedResidualClosureWitness,
    auxiliary: C6PairedResidualAuxiliaryWitness,
    provider_streams: [CorrelationStream; 2],
    verifier_contexts: [VerifierCtx; 2],
    provider_transcript: Transcript,
    verifier_transcript: Transcript,
    cache_fold_target_frame: Vec<u8>,
    native_target_profile: C6CanonicalTargetProfile,
    native_target_artifact: Vec<u8>,
    closure_memory: C6InstalledClosureEvaluationMemoryCensus,
    census: C6ResponseResidualCensus,
    timing: C6ResponseResidualTiming,
}

pub struct C6ResponseResidualProviderInputs<'a> {
    pub operation_plan: &'a C6InstalledOperationPlan,
    pub extraction: &'a C6DecodedInstanceExtractionPlan,
    pub runtime: &'a C6RuntimeInstanceValues,
    pub linear: &'a C6CompiledLinearResidual,
    pub relation: &'a C6ResidualRelationChallenges,
    pub witness: C6ResidualFusedWitnessView<'a>,
    pub streams: &'a mut [CorrelationStream; 2],
    pub transcript: &'a mut Transcript,
}

pub struct C6ResponseResidualVerifierInputs<'a> {
    pub operation_plan: &'a C6InstalledOperationPlan,
    pub extraction: &'a C6DecodedInstanceExtractionPlan,
    pub runtime: &'a C6RuntimeInstanceValues,
    pub linear: &'a C6CompiledLinearResidual,
    pub relation: &'a C6ResidualRelationChallenges,
    pub contexts: &'a mut [VerifierCtx; 2],
    pub transcript: &'a mut Transcript,
}

/// Installed role owner captured in the same production T1 response pass.
/// The runtime values are accepted only through the preinstalled extraction
/// map; the diagnostic trace-to-runtime reconstruction is unreachable here.
pub struct C6T1InstalledRoleOwner {
    operation_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    runtime: C6RuntimeInstanceValues,
}

/// Verifier-only replay of the retained T1 response from canonical disk
/// bytes. It contains no model witness, provider authentication tag or
/// provider correlation stream and continues the caller-owned verifier
/// contexts/transcript into the residual/compiler stages.
pub struct C6T1ProductionResponseVerifierReplay {
    output: ModelOutV,
    zero_roots: C6GrandResidualVerifierRoots,
    product_challenge: Fp2,
    product_mask_domain: u64,
    product_messages: Vec<[Fp2; 2]>,
    source_schedule: CorrScheduleAudit,
    source_manifest: C6TraceSourceManifest,
    installed: C6T1InstalledRoleOwner,
    cache_snapshot: C6CacheFoldTraceSnapshot,
    cache_targets: C6CacheFoldPairedVerifierTargets,
    cache_target_fixed: C6CacheFoldTargetFixedCorrections,
    cache_append_sources: C6CacheFoldAppendSourcePlan,
    cache_metrics: crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics,
}

impl C6T1ProductionResponseVerifierReplay {
    pub fn output(&self) -> &ModelOutV {
        &self.output
    }

    pub fn zero_roots(&self) -> &C6GrandResidualVerifierRoots {
        &self.zero_roots
    }

    pub fn product_challenge(&self) -> Fp2 {
        self.product_challenge
    }

    pub fn product_mask_domain(&self) -> u64 {
        self.product_mask_domain
    }

    pub fn product_messages(&self) -> &[[Fp2; 2]] {
        &self.product_messages
    }

    pub fn source_schedule(&self) -> &CorrScheduleAudit {
        &self.source_schedule
    }

    pub fn source_manifest(&self) -> &C6TraceSourceManifest {
        &self.source_manifest
    }

    pub fn installed(&self) -> &C6T1InstalledRoleOwner {
        &self.installed
    }

    pub fn cache_snapshot(&self) -> &C6CacheFoldTraceSnapshot {
        &self.cache_snapshot
    }

    pub fn cache_targets(&self) -> &C6CacheFoldPairedVerifierTargets {
        &self.cache_targets
    }

    pub fn cache_target_fixed(&self) -> &C6CacheFoldTargetFixedCorrections {
        &self.cache_target_fixed
    }

    pub fn cache_append_sources(&self) -> &C6CacheFoldAppendSourcePlan {
        &self.cache_append_sources
    }

    pub fn cache_metrics(&self) -> crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics {
        self.cache_metrics
    }
}

/// Disk-only continuation of the retained response through the zero
/// challenge and installed residual linear form. It owns no provider witness,
/// tag or correlation stream.
pub struct C6T1DiskResidualOwner {
    response: C6T1ProductionResponseVerifierReplay,
    manifest: C6ResidualRelationManifest,
    retained: C6ResidualRetainedChallenges,
    verifier_linear: C6CompiledLinearResidual,
}

/// Disk verifier after alpha and the complete two-coordinate public-claims
/// frame are bound, but before terminal/atomic points are released.
pub struct C6T1DiskResidualClaimsOwner {
    response: C6T1ProductionResponseVerifierReplay,
    verifier_linear: C6CompiledLinearResidual,
    claims: C6ResidualClaimsBoundContext,
}

/// Disk verifier after the exact direct residual relation is complete.
pub struct C6T1DiskResidualBoundOwner {
    response: C6T1ProductionResponseVerifierReplay,
    verifier_linear: C6CompiledLinearResidual,
    relation: C6ResidualRelationChallenges,
}

impl C6T1DiskResidualOwner {
    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        &self.manifest
    }

    pub fn response(&self) -> &C6T1ProductionResponseVerifierReplay {
        &self.response
    }

    pub fn bind_direct_alpha(
        self,
        root: C6ResidualRelationRootBound,
        alpha: C6ResidualDirectAlphaPoints,
        coordinate_one: C6ResidualProductClaimCoordinate,
        residual: C6PairedDeltaResidual,
    ) -> Result<C6T1DiskResidualClaimsOwner, C6ResidualError> {
        if root.manifest() != &self.manifest
            || coordinate_one.coordinate() != 1
            || coordinate_one.manifest_digest() != self.manifest.digest()
        {
            return Err(C6ResidualError::new(
                "C6ICT4 disk residual root/coordinate differs from its manifest",
            ));
        }
        let products = assemble_c6_disk_product_public_claims(
            &self.manifest,
            self.response.product_messages(),
            &coordinate_one,
        )?;
        let claims = root.release_direct_alpha_points(self.retained, alpha)?.commit_public_claims(
            self.verifier_linear.linear_form_digest(),
            products,
            residual,
        )?;
        Ok(C6T1DiskResidualClaimsOwner {
            response: self.response,
            verifier_linear: self.verifier_linear,
            claims,
        })
    }
}

fn assemble_c6_disk_product_public_claims(
    manifest: &C6ResidualRelationManifest,
    coordinate_zero_messages: &[[Fp2; 2]],
    coordinate_one: &C6ResidualProductClaimCoordinate,
) -> Result<Vec<C6ResidualProductPublicClaim>, C6ResidualError> {
    if coordinate_one.coordinate() != 1 || coordinate_one.manifest_digest() != manifest.digest() {
        return Err(C6ResidualError::new(
            "C6ICT4 disk public claims use another coordinate/manifest",
        ));
    }
    let coordinate_zero =
        C6ResidualProductClaimCoordinate::new(manifest, 0, coordinate_zero_messages.to_vec())?;
    Ok(coordinate_zero
        .messages()
        .iter()
        .copied()
        .zip(coordinate_one.messages().iter().copied())
        .map(|(zero, one)| C6ResidualProductPublicClaim { messages: [zero, one] })
        .collect())
}

impl C6T1DiskResidualClaimsOwner {
    pub fn claims_digest(&self) -> [u8; 32] {
        self.claims.claims().digest()
    }

    pub fn bind_direct_postclaim(
        self,
        postclaim: C6ResidualDirectPostClaimPoints,
    ) -> Result<C6T1DiskResidualBoundOwner, C6ResidualError> {
        let relation = self.claims.release_direct_postclaim_points(
            self.response.installed().operation_plan(),
            postclaim,
        )?;
        relation.validate_installed_operation_plan(self.response.installed().operation_plan())?;
        Ok(C6T1DiskResidualBoundOwner {
            response: self.response,
            verifier_linear: self.verifier_linear,
            relation,
        })
    }
}

impl C6T1DiskResidualBoundOwner {
    pub fn response(&self) -> &C6T1ProductionResponseVerifierReplay {
        &self.response
    }

    pub fn verifier_linear(&self) -> &C6CompiledLinearResidual {
        &self.verifier_linear
    }

    pub fn relation(&self) -> &C6ResidualRelationChallenges {
        &self.relation
    }
}

/// Provider-only response result awaiting client source sealing and verifier
/// replay. Its constructor accepts no verifier context, Delta, seed or paired
/// attempt owner; the retained proof has already crossed its canonical byte
/// boundary.
pub struct C6T1ProductionResponseProviderPending {
    retained: C6RetainedResponseProof,
    prover_output: ModelOut,
    prover_zero_roots: C6GrandResidualProverRoots,
    product_challenge: Fp2,
    product_mask_domain: u64,
    product_messages: Vec<[Fp2; 2]>,
    source_schedule: CorrScheduleAudit,
    source_manifest: C6TraceSourceManifest,
    source_coordinates: [C6SourceCoordinate; 2],
    installed: C6T1InstalledRoleOwner,
    cache_target_frame: C6CacheFoldTargetCorrectionFrame,
    cache_target_fixed: C6CacheFoldTargetFixedCorrections,
    cache_snapshot: C6CacheFoldTraceSnapshot,
    cache_target_owner: C6CacheFoldTargetProverOwner,
    cache_append_sources: C6CacheFoldAppendSourcePlan,
    cache_metrics: crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics,
}

impl C6T1ProductionResponseProviderPending {
    pub fn retained(&self) -> &C6RetainedResponseProof {
        &self.retained
    }

    pub fn encoded_retained_response(&self) -> Result<Vec<u8>, String> {
        self.retained.encode().map_err(|error| error.to_string())
    }

    pub fn encoded_c62_retained_response(&self) -> Result<Vec<u8>, String> {
        self.retained.encode_c62().map_err(|error| error.to_string())
    }

    pub fn cache_target_frame_bytes(&self) -> Result<Vec<u8>, String> {
        self.cache_target_frame.encode().map_err(|error| error.to_string())
    }

    pub fn source_schedule(&self) -> &CorrScheduleAudit {
        &self.source_schedule
    }

    pub fn source_manifest(&self) -> &C6TraceSourceManifest {
        &self.source_manifest
    }

    pub fn installed(&self) -> &C6T1InstalledRoleOwner {
        &self.installed
    }
}

impl C6T1InstalledRoleOwner {
    pub fn operation_plan(&self) -> &C6InstalledOperationPlan {
        &self.operation_plan
    }

    pub fn extraction(&self) -> &C6DecodedInstanceExtractionPlan {
        &self.extraction
    }

    pub fn runtime(&self) -> &C6RuntimeInstanceValues {
        &self.runtime
    }
}

/// Production response continuation before the six wrapper roots are fixed.
/// The zero challenge is drawn in lockstep from the already-live response
/// transcripts; callers cannot inject it or rebuild the residual witness from
/// a detached runtime.  Direct-MLE points remain unavailable until a PCS root
/// token is supplied to [`Self::bind_direct_alpha`].
pub struct C6T1ProductionResidualOwner {
    response: C6T1ProductionResponseOwner,
    manifest: C6ResidualRelationManifest,
    retained: C6ResidualRetainedChallenges,
    provider_linear: C6CompiledLinearResidual,
    verifier_linear: C6CompiledLinearResidual,
    leaf: C6PairedResidualLeafWitness,
    closure: C6PairedResidualClosureWitness,
    auxiliary: C6PairedResidualAuxiliaryWitness,
    native_targets: C6PairedNativeTargetValues,
    closure_memory: C6InstalledClosureEvaluationMemoryCensus,
}

/// Same owners after roots and alpha are fixed and the exact public claims
/// have been compiled, but before any terminal/atomic point is released.
pub struct C6T1ProductionResidualClaimsOwner {
    response: C6T1ProductionResponseOwner,
    provider_linear: C6CompiledLinearResidual,
    verifier_linear: C6CompiledLinearResidual,
    claims: C6ResidualClaimsBoundContext,
    coordinate_one: C6ResidualProductClaimCoordinate,
    leaf: C6PairedResidualLeafWitness,
    closure: C6PairedResidualClosureWitness,
    auxiliary: C6PairedResidualAuxiliaryWitness,
    native_targets: C6PairedNativeTargetValues,
    closure_memory: C6InstalledClosureEvaluationMemoryCensus,
}

/// Same owners after the fixed-root token and both ordered direct-MLE
/// challenge families have closed the response-dependent relation.
pub struct C6T1ProductionResidualBoundOwner {
    response: C6T1ProductionResponseOwner,
    provider_linear: C6CompiledLinearResidual,
    verifier_linear: C6CompiledLinearResidual,
    relation: C6ResidualRelationChallenges,
    leaf: C6PairedResidualLeafWitness,
    closure: C6PairedResidualClosureWitness,
    auxiliary: C6PairedResidualAuxiliaryWitness,
    native_targets: C6PairedNativeTargetValues,
    closure_memory: C6InstalledClosureEvaluationMemoryCensus,
}

impl C6T1ProductionResidualOwner {
    pub fn response(&self) -> &C6T1ProductionResponseOwner {
        &self.response
    }

    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        &self.manifest
    }

    pub fn leaf(&self) -> &C6PairedResidualLeafWitness {
        &self.leaf
    }

    pub fn closure(&self) -> &C6PairedResidualClosureWitness {
        &self.closure
    }

    pub fn auxiliary(&self) -> &C6PairedResidualAuxiliaryWitness {
        &self.auxiliary
    }

    pub fn closure_memory_census(&self) -> C6InstalledClosureEvaluationMemoryCensus {
        self.closure_memory
    }

    pub fn bind_direct_alpha(
        self,
        root: C6ResidualRelationRootBound,
        alpha: C6ResidualDirectAlphaPoints,
    ) -> Result<C6T1ProductionResidualClaimsOwner, C6ResidualError> {
        if root.manifest() != &self.manifest {
            return Err(C6ResidualError::new(
                "C6 production residual root token differs from its same-pass manifest",
            ));
        }
        let claims = root
            .release_direct_alpha_points(self.retained, alpha)?
            .commit_public_claims_from_live(
                self.response.provider().operation_plan(),
                &self.provider_linear,
                &self.leaf,
                &self.auxiliary,
            )?;
        let coordinate_zero = claims.claims().product_coordinate(&self.manifest, 0)?;
        if coordinate_zero.messages() != self.response.product_messages() {
            return Err(C6ResidualError::new(
                "C6 production residual coordinate zero differs from retained ProductClosure messages",
            ));
        }
        let coordinate_one = claims.claims().product_coordinate(&self.manifest, 1)?;
        Ok(C6T1ProductionResidualClaimsOwner {
            response: self.response,
            provider_linear: self.provider_linear,
            verifier_linear: self.verifier_linear,
            claims,
            coordinate_one,
            leaf: self.leaf,
            closure: self.closure,
            auxiliary: self.auxiliary,
            native_targets: self.native_targets,
            closure_memory: self.closure_memory,
        })
    }
}

impl C6T1ProductionResidualClaimsOwner {
    pub fn response(&self) -> &C6T1ProductionResponseOwner {
        &self.response
    }

    pub fn coordinate_one(&self) -> &C6ResidualProductClaimCoordinate {
        &self.coordinate_one
    }

    pub fn claims_digest(&self) -> [u8; 32] {
        self.claims.claims().digest()
    }

    pub fn bind_direct_postclaim(
        self,
        postclaim: C6ResidualDirectPostClaimPoints,
    ) -> Result<C6T1ProductionResidualBoundOwner, C6ResidualError> {
        let relation = self.claims.release_direct_postclaim_points(
            self.response.provider().operation_plan(),
            postclaim,
        )?;
        relation.validate_installed_operation_plan(self.response.verifier().operation_plan())?;
        Ok(C6T1ProductionResidualBoundOwner {
            response: self.response,
            provider_linear: self.provider_linear,
            verifier_linear: self.verifier_linear,
            relation,
            leaf: self.leaf,
            closure: self.closure,
            auxiliary: self.auxiliary,
            native_targets: self.native_targets,
            closure_memory: self.closure_memory,
        })
    }
}

impl C6T1ProductionResidualBoundOwner {
    pub fn response(&self) -> &C6T1ProductionResponseOwner {
        &self.response
    }

    pub fn provider_linear(&self) -> &C6CompiledLinearResidual {
        &self.provider_linear
    }

    pub fn verifier_linear(&self) -> &C6CompiledLinearResidual {
        &self.verifier_linear
    }

    pub fn relation(&self) -> &C6ResidualRelationChallenges {
        &self.relation
    }

    pub fn leaf(&self) -> &C6PairedResidualLeafWitness {
        &self.leaf
    }

    pub fn closure(&self) -> &C6PairedResidualClosureWitness {
        &self.closure
    }

    pub fn auxiliary(&self) -> &C6PairedResidualAuxiliaryWitness {
        &self.auxiliary
    }

    pub fn native_targets(&self) -> &C6PairedNativeTargetValues {
        &self.native_targets
    }

    pub fn closure_memory_census(&self) -> C6InstalledClosureEvaluationMemoryCensus {
        self.closure_memory
    }
}

/// Exact response owners exported before any public-compression chain is
/// constructed. Nothing in this object is clonable or reconstructed from a
/// digest: model claims, verifier keys, paired source witness, installed
/// runtime values and cache-fold corrections all originate in one execution.
pub struct C6T1ProductionResponseOwner {
    model_proof: ModelProof,
    prover_output: ModelOut,
    verifier_output: ModelOutV,
    product_proof: ProdProof,
    product_challenge: Fp2,
    product_mask_domain: u64,
    product_messages: Vec<[Fp2; 2]>,
    prover_zero_roots: C6GrandResidualProverRoots,
    verifier_zero_roots: C6GrandResidualVerifierRoots,
    paired_sources: C6ProductionPairedSourceWitness,
    source_schedule: CorrScheduleAudit,
    source_manifest: C6TraceSourceManifest,
    provider: C6T1InstalledRoleOwner,
    verifier: C6T1InstalledRoleOwner,
    cache_target_frame: C6CacheFoldTargetCorrectionFrame,
    cache_target_fixed: C6CacheFoldTargetFixedCorrections,
    cache_snapshot: C6CacheFoldTraceSnapshot,
    cache_target_owner: C6CacheFoldTargetProverOwner,
    cache_append_sources: C6CacheFoldAppendSourcePlan,
    provider_cache_metrics: crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics,
    verifier_cache_metrics: crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics,
}

impl C6T1ProductionResponseOwner {
    pub fn model_proof(&self) -> &ModelProof {
        &self.model_proof
    }

    pub fn prover_output(&self) -> &ModelOut {
        &self.prover_output
    }

    pub fn verifier_output(&self) -> &ModelOutV {
        &self.verifier_output
    }

    pub fn product_proof(&self) -> &ProdProof {
        &self.product_proof
    }

    pub fn encoded_retained_response(&self) -> Result<Vec<u8>, String> {
        crate::C6RetainedResponseProof::encode_parts(&self.model_proof, &self.product_proof)
            .map_err(|error| error.to_string())
    }

    pub fn encoded_c62_retained_response(&self) -> Result<Vec<u8>, String> {
        crate::C6RetainedResponseProof::encode_c62_parts(&self.model_proof, &self.product_proof)
            .map_err(|error| error.to_string())
    }

    pub fn product_challenge(&self) -> Fp2 {
        self.product_challenge
    }

    pub fn product_mask_domain(&self) -> u64 {
        self.product_mask_domain
    }

    pub fn product_messages(&self) -> &[[Fp2; 2]] {
        &self.product_messages
    }

    pub fn paired_sources(&self) -> &C6ProductionPairedSourceWitness {
        &self.paired_sources
    }

    pub fn source_schedule(&self) -> &CorrScheduleAudit {
        &self.source_schedule
    }

    pub fn source_manifest(&self) -> &C6TraceSourceManifest {
        &self.source_manifest
    }

    pub fn provider(&self) -> &C6T1InstalledRoleOwner {
        &self.provider
    }

    pub fn verifier(&self) -> &C6T1InstalledRoleOwner {
        &self.verifier
    }

    pub fn cache_target_frame(&self) -> &C6CacheFoldTargetCorrectionFrame {
        &self.cache_target_frame
    }

    pub fn cache_target_fixed(&self) -> &C6CacheFoldTargetFixedCorrections {
        &self.cache_target_fixed
    }

    pub fn cache_snapshot(&self) -> &C6CacheFoldTraceSnapshot {
        &self.cache_snapshot
    }

    pub fn cache_target_owner(&self) -> &C6CacheFoldTargetProverOwner {
        &self.cache_target_owner
    }

    pub fn cache_append_sources(&self) -> &C6CacheFoldAppendSourcePlan {
        &self.cache_append_sources
    }

    pub fn zero_root_count(&self) -> usize {
        debug_assert_eq!(self.prover_zero_roots.len(), self.verifier_zero_roots.len());
        self.prover_zero_roots.len()
    }

    pub fn provider_cache_metrics(&self) -> crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics {
        self.provider_cache_metrics
    }

    pub fn verifier_cache_metrics(&self) -> crate::c6_cache_fold::C6CacheFoldOnlineLayerMetrics {
        self.verifier_cache_metrics
    }
}

/// Consume the same-pass T1 response into the production-capacity residual
/// witness before wrapper-root commitment.  The only new challenge is drawn
/// from both continued transcripts and must agree; no seed or zero-root
/// weight can be supplied by the provider-facing caller.
pub fn prepare_c6_t1_production_residual_owner(
    response: C6T1ProductionResponseOwner,
    native_profile: &C6CanonicalTargetProfile,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1ProductionResidualOwner, C6ResidualError> {
    if provider_transcript.ledger() != verifier_transcript.ledger()
        || provider_transcript.total_bytes() != verifier_transcript.total_bytes()
    {
        return Err(C6ResidualError::new(
            "C6 production residual continuation transcripts already differ",
        ));
    }
    let provider_zero_challenge = provider_transcript.challenge_fp2();
    let verifier_zero_challenge = verifier_transcript.challenge_fp2();
    if provider_zero_challenge != verifier_zero_challenge {
        return Err(C6ResidualError::new(
            "C6 production residual zero challenge differs across roles",
        ));
    }

    let manifest = C6ResidualRelationManifest::new_with_geometry(
        response.provider().operation_plan(),
        response.provider().extraction(),
        response.provider().runtime(),
        RESPONSE_PRODUCTION_LEAF_LOG2,
        RESPONSE_PRODUCTION_AUXILIARY_LOG2,
        true,
    )?;
    let verifier_manifest = C6ResidualRelationManifest::new_with_geometry(
        response.verifier().operation_plan(),
        response.verifier().extraction(),
        response.verifier().runtime(),
        RESPONSE_PRODUCTION_LEAF_LOG2,
        RESPONSE_PRODUCTION_AUXILIARY_LOG2,
        true,
    )?;
    if verifier_manifest != manifest {
        return Err(C6ResidualError::new(
            "C6 production residual manifests differ across installed roles",
        ));
    }
    let product_challenges =
        vec![response.product_challenge(); response.provider().operation_plan().products().len()];
    let retained =
        C6ResidualRetainedChallenges::new(&manifest, product_challenges, provider_zero_challenge)?;
    let zero_weights =
        retained.zero_weights(response.provider().operation_plan().zero_roots().len());
    let provider_linear = C6CompiledLinearResidual::compile(
        response.provider().operation_plan(),
        response.provider().extraction(),
        response.provider().runtime(),
        &zero_weights,
    )?;
    let verifier_linear = C6CompiledLinearResidual::compile(
        response.verifier().operation_plan(),
        response.verifier().extraction(),
        response.verifier().runtime(),
        &zero_weights,
    )?;
    if provider_linear.linear_form_digest() != verifier_linear.linear_form_digest() {
        return Err(C6ResidualError::new(
            "C6 production residual linear forms differ across installed roles",
        ));
    }
    let leaf = provider_linear.build_production_paired_residual_leaf_witness(
        response.paired_sources(),
        response.source_schedule(),
    )?;
    let closure_evaluation = provider_linear
        .evaluate_installed_paired_closure_with_native_targets(
            response.provider().operation_plan(),
            response.provider().extraction(),
            response.provider().runtime(),
            response.paired_sources().source(),
            response.source_schedule(),
            native_profile,
        )?;
    let closure_memory = closure_evaluation.memory_census();
    let (closure, native_targets) = closure_evaluation.into_closure_and_native_targets()?;
    let auxiliary = closure.transpose_auxiliary_lanes()?;
    C6ResidualFusedWitnessView::new(&manifest, &leaf, &closure, &auxiliary)?;
    Ok(C6T1ProductionResidualOwner {
        response,
        manifest,
        retained,
        provider_linear,
        verifier_linear,
        leaf,
        closure,
        auxiliary,
        native_targets,
        closure_memory,
    })
}

/// Continue a strict disk response replay into the same installed residual
/// manifest and zero-challenge schedule as the live provider. The challenge
/// comes from either the C6.1 replay endpoint or the C6.2 Fiat--Shamir state.
pub fn prepare_c6_t1_disk_residual_owner(
    response: C6T1ProductionResponseVerifierReplay,
    transcript: &mut Transcript,
) -> Result<C6T1DiskResidualOwner, C6ResidualError> {
    if !transcript.is_interactive() && !transcript.is_fiat_shamir() {
        return Err(C6ResidualError::new(
            "disk residual requires a C6.1 replay or C6.2 Fiat--Shamir transcript",
        ));
    }
    let zero_challenge = transcript.challenge_fp2();
    if let Some(error) = transcript.interactive_error() {
        return Err(C6ResidualError::new(format!(
            "C6ICT4 disk zero-challenge replay failed: {error}"
        )));
    }
    let manifest = C6ResidualRelationManifest::new_with_geometry(
        response.installed().operation_plan(),
        response.installed().extraction(),
        response.installed().runtime(),
        RESPONSE_PRODUCTION_LEAF_LOG2,
        RESPONSE_PRODUCTION_AUXILIARY_LOG2,
        true,
    )?;
    let product_challenges =
        vec![response.product_challenge(); response.installed().operation_plan().products().len()];
    let retained =
        C6ResidualRetainedChallenges::new(&manifest, product_challenges, zero_challenge)?;
    let zero_weights =
        retained.zero_weights(response.installed().operation_plan().zero_roots().len());
    let verifier_linear = C6CompiledLinearResidual::compile(
        response.installed().operation_plan(),
        response.installed().extraction(),
        response.installed().runtime(),
        &zero_weights,
    )?;
    Ok(C6T1DiskResidualOwner { response, manifest, retained, verifier_linear })
}

#[derive(Clone, Copy)]
enum C6ProductionResponseVerifierProfile {
    Genesis,
    Continuation { base_t0: usize },
}

/// Re-run only the designated-verifier half of one response from canonical
/// client inputs. The correction frame is decoded before its omitted runtime
/// identity is reconstructed and bound by the live trace.
#[allow(clippy::too_many_arguments)]
fn replay_c6_production_response_verifier(
    model: &Gpt2VerifierModel,
    sequence: &[u32],
    profile: C6ProductionResponseVerifierProfile,
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    cache_target_frame_bytes: &[u8],
    retained: &C6RetainedResponseProof,
    contexts: &mut [VerifierCtx; 2],
    transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseVerifierReplay, String> {
    let valid_profile = match profile {
        C6ProductionResponseVerifierProfile::Genesis => sequence.len() == 150,
        C6ProductionResponseVerifierProfile::Continuation { base_t0 } => {
            let old_len = base_t0.checked_add(1);
            old_len.is_some_and(|old_len| {
                old_len >= 150
                    && old_len <= 900
                    && old_len % 50 == 0
                    && sequence.len() == old_len + 50
            })
        }
    };
    if statement_digest == [0; 32]
        || !valid_profile
        || extraction.role() != C6InstanceExtractionRole::Verifier
        || extraction.topology_digest() != installed_plan.topology().topology_digest
        || contexts.iter().any(|context| !context.uses_pooled_pcg())
    {
        return Err("C6.2 disk verifier response profile/PCG mismatch".to_owned());
    }
    let public_schedule = C6CacheFoldTargetPublicSchedule::new(
        (0..2 * L)
            .flat_map(|_| {
                std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                    .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
            })
            .collect(),
    )
    .map_err(|error| error.to_string())?;
    let cache_target_frame =
        C6CacheFoldTargetPublicCorrectionFrame::decode(statement_digest, cache_target_frame_bytes)
            .map_err(|error| error.to_string())?;
    let deltas = [contexts[0].delta, contexts[1].delta];
    let [primary, secondary] = contexts;
    begin_c6_verifier_trace().map_err(|error| error.to_string())?;
    primary.enable_c6_operation_trace().map_err(|error| error.to_string())?;
    primary.enable_schedule_audit().map_err(|error| error.to_string())?;
    let runtime_capture =
        begin_c6_runtime_instance_capture(&extraction).map_err(|error| error.to_string())?;
    let mut follower =
        C6SourceScheduleVerifierFollower::start(secondary).map_err(|error| error.to_string())?;
    let mut target_cursor = C6CacheFoldTargetInlineVerifier::start_decoded_public(
        &cache_target_frame,
        public_schedule,
        deltas,
        transcript,
    )
    .map_err(|error| error.to_string())?;
    let cache_trace =
        begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).map_err(|error| error.to_string())?;
    let (output, product_keys, zero_roots, cache_metrics, cache_append_sources, cache_target_terms) =
        match profile {
            C6ProductionResponseVerifierProfile::Genesis => {
                let public = [PrivateChunkPub { q: 50, seq: sequence }];
                verify_response_private_logits_c6_cache_inline_from_profile(
                    model,
                    100,
                    &public,
                    &retained.model,
                    primary,
                    secondary,
                    &mut follower,
                    &mut target_cursor,
                    transcript,
                )
            }
            C6ProductionResponseVerifierProfile::Continuation { base_t0 } => {
                verify_response_continuation_private_logits_c6_cache_inline_from_profile(
                    model,
                    base_t0,
                    sequence,
                    &retained.model,
                    primary,
                    secondary,
                    &mut follower,
                    &mut target_cursor,
                    transcript,
                )
            }
        }
        .ok_or_else(|| "C6.2 disk verifier retained response rejected".to_owned())?;
    let cache_snapshot = cache_trace.finish().map_err(|error| error.to_string())?;
    let cache_targets =
        C6CacheFoldPairedVerifierTargets::from_online_replay(&cache_snapshot, cache_target_terms)
            .map_err(|error| error.to_string())?;
    let cache_target_fixed = target_cursor
        .finish_before_successor_root_with_identity(cache_snapshot.identity, transcript)
        .map_err(|error| error.to_string())?;
    let mut doms = Doms::new(layer_dom_base(255));
    let product_challenge = transcript.challenge_fp2();
    let product_mask_domain = doms.take(1);
    transcript.append_fp2s("prod_check_m0_m1", &[retained.product.m0, retained.product.m1]);
    if !prod_batch_verify(
        &product_keys,
        primary.expand_product_mask_verifier_key(product_mask_domain, product_keys.len()),
        primary.delta,
        product_challenge,
        &retained.product,
    ) {
        return Err("C6.1 disk verifier ProductClosure batch rejected".to_owned());
    }
    let installed_final_product_triples = installed_plan
        .products()
        .last()
        .ok_or_else(|| "C6.2 disk verifier installed product closures are empty".to_owned())?
        .triples()
        .len();
    if product_keys.len() != installed_final_product_triples
        || zero_roots.len() as u32 != installed_plan.topology().zero_root_count
        || output.weight_keys.len() != 96
        || output.embed_keys.len() != 6
    {
        return Err("C6.1 disk verifier response census changed".to_owned());
    }
    zero_roots.record_operation_trace_ownership().map_err(|error| error.to_string())?;
    let product_messages = take_c6_product_closure_messages().map_err(|error| error.to_string())?;
    let _operation_trace = finish_c6_verifier_trace().map_err(|error| error.to_string())?;
    let runtime = runtime_capture
        .finish_installed(&installed_plan, &extraction)
        .map_err(|error| error.to_string())?;
    follower.sync_primary(primary, secondary).map_err(|error| error.to_string())?;
    let source_schedule = primary
        .schedule_audit()
        .filter(|schedule| secondary.schedule_audit() == Some(schedule.clone()))
        .ok_or_else(|| "C6.1 disk verifier source schedules differ/are absent".to_owned())?;
    let mut next_source = 0u64;
    let mut product_mask_sources = Vec::new();
    for draw in &source_schedule.draws {
        if draw.role == CorrScheduleRole::ProductMask {
            product_mask_sources.push(
                u32::try_from(next_source)
                    .map_err(|_| "C6.1 disk verifier product-mask source exceeds u32")?,
            );
        }
        next_source = next_source
            .checked_add(draw.count)
            .ok_or_else(|| "C6.1 disk verifier source census overflows".to_owned())?;
    }
    let source_manifest = C6TraceSourceManifest::new(
        u32::try_from(next_source).map_err(|_| "C6.1 disk verifier source manifest exceeds u32")?,
        source_schedule.digest,
        product_mask_sources,
    )
    .map_err(|error| error.to_string())?;
    if product_messages.len() != installed_plan.products().len() {
        return Err("C6.2 disk verifier ProductClosure message census changed".to_owned());
    }
    Ok(C6T1ProductionResponseVerifierReplay {
        output,
        zero_roots,
        product_challenge,
        product_mask_domain,
        product_messages,
        source_schedule,
        source_manifest,
        installed: C6T1InstalledRoleOwner { operation_plan: installed_plan, extraction, runtime },
        cache_snapshot,
        cache_targets,
        cache_target_fixed,
        cache_append_sources,
        cache_metrics,
    })
}

/// Replay the designated-verifier half of the genesis response.
#[allow(clippy::too_many_arguments)]
pub fn replay_c6_t1_production_response_verifier(
    model: &Gpt2VerifierModel,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    cache_target_frame_bytes: &[u8],
    retained: &C6RetainedResponseProof,
    contexts: &mut [VerifierCtx; 2],
    transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseVerifierReplay, String> {
    replay_c6_production_response_verifier(
        model,
        sequence,
        C6ProductionResponseVerifierProfile::Genesis,
        statement_digest,
        installed_plan,
        extraction,
        cache_target_frame_bytes,
        retained,
        contexts,
        transcript,
    )
}

/// Replay the designated-verifier half of one continuation response.
#[allow(clippy::too_many_arguments)]
pub fn replay_c62_continuation_production_response_verifier(
    model: &Gpt2VerifierModel,
    sequence: &[u32],
    old_context: usize,
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    cache_target_frame_bytes: &[u8],
    retained: &C6RetainedResponseProof,
    contexts: &mut [VerifierCtx; 2],
    transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseVerifierReplay, String> {
    let base_t0 = old_context
        .checked_sub(1)
        .ok_or_else(|| "C6.2 continuation old context is zero".to_owned())?;
    replay_c6_production_response_verifier(
        model,
        sequence,
        C6ProductionResponseVerifierProfile::Continuation { base_t0 },
        statement_digest,
        installed_plan,
        extraction,
        cache_target_frame_bytes,
        retained,
        contexts,
        transcript,
    )
}

#[derive(Clone, Copy)]
enum C6ProductionResponseProverProfile<'a> {
    Genesis {
        prefill: &'a volta_gpt2::ModelWitness,
        decode: &'a volta_gpt2::BandModelWitness,
    },
    Continuation {
        full: &'a volta_gpt2::ModelWitness,
        first: &'a volta_gpt2::BandModelWitness,
        second: &'a volta_gpt2::BandModelWitness,
    },
}

/// Execute only the provider half of one private-logit response. The type
/// boundary excludes verifier contexts, Delta, verifier entropy and the
/// paired-attempt owner.
#[allow(clippy::too_many_arguments)]
fn prove_c6_production_response_provider(
    model: &volta_gpt2::Gpt2Model,
    profile: C6ProductionResponseProverProfile<'_>,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    streams: &mut [CorrelationStream; 2],
    provider_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseProviderPending, String> {
    let valid_profile = match profile {
        C6ProductionResponseProverProfile::Genesis { prefill, decode } => {
            prefill.t == 100
                && decode.t0 == 100
                && decode.q == 50
                && sequence.len() == 150
        }
        C6ProductionResponseProverProfile::Continuation { full, first, second } => {
            let old_len = first.t0.checked_add(1);
            old_len.is_some_and(|old_len| {
                old_len >= 150
                    && old_len <= 900
                    && old_len % 50 == 0
                    && first.q == 26
                    && second.t0 == old_len + 25
                    && second.q == 25
                    && full.t == old_len + 50
                    && sequence.len() == full.t
            })
        }
    };
    if statement_digest == [0; 32]
        || !valid_profile
        || extraction.role() != C6InstanceExtractionRole::Prover
        || extraction.topology_digest() != installed_plan.topology().topology_digest
    {
        return Err("C6.2 provider response profile mismatch".to_owned());
    }
    let public_schedule = C6CacheFoldTargetPublicSchedule::new(
        (0..2 * L)
            .flat_map(|_| {
                std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                    .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
            })
            .collect(),
    )
    .map_err(|error| error.to_string())?;
    let (
        model_proof,
        prover_output,
        products,
        prover_zero_roots,
        provider_cache_metrics,
        product_proof,
        product_challenge,
        product_mask_domain,
        product_messages,
        cache_target_frame,
        cache_target_fixed,
        cache_snapshot,
        cache_target_owner,
        cache_append_sources,
        source_schedule,
        coordinates,
        provider_runtime,
    ) = {
        if streams.iter().any(|stream| !stream.uses_pooled_pcg()) {
            return Err("C6ICT3 provider response received mock prover tapes".to_owned());
        }
        let [primary, secondary] = streams;
        begin_c6_prover_trace().map_err(|error| error.to_string())?;
        primary.enable_c6_operation_trace().map_err(|error| error.to_string())?;
        primary.enable_c6_source_witness_collection().map_err(|error| error.to_string())?;
        let runtime_capture =
            begin_c6_runtime_instance_capture(&extraction).map_err(|error| error.to_string())?;
        let mut follower =
            C6SourceScheduleProverFollower::start(secondary).map_err(|error| error.to_string())?;
        let mut target_builder = C6CacheFoldTargetInlineProver::start_public(
            statement_digest,
            public_schedule.clone(),
            provider_transcript,
        )
        .map_err(|error| error.to_string())?;
        let cache_trace = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover)
            .map_err(|error| error.to_string())?;
        let (proof, output, products, zero_roots, metrics, append_sources) = match profile {
            C6ProductionResponseProverProfile::Genesis { prefill, decode } => {
                let chunks = [ChunkRef { band: decode, seq: sequence }];
                prove_response_private_logits_c6_cache_inline(
                    model,
                    prefill,
                    &chunks,
                    primary,
                    secondary,
                    &mut follower,
                    &mut target_builder,
                    provider_transcript,
                )
            }
            C6ProductionResponseProverProfile::Continuation { full, first, second } => {
                prove_response_continuation_private_logits_c6_cache_inline(
                    model,
                    full,
                    first,
                    second,
                    sequence,
                    primary,
                    secondary,
                    &mut follower,
                    &mut target_builder,
                    provider_transcript,
                )
            }
        };
        let cache_snapshot = cache_trace.finish().map_err(|error| error.to_string())?;
        let (target_frame, target_owner) = target_builder
            .finish_before_successor_root_with_owner(cache_snapshot.identity, provider_transcript)
            .map_err(|error| error.to_string())?;
        let target_fixed = target_owner.fixed().clone();
        let mut doms = Doms::new(layer_dom_base(255));
        let chi = provider_transcript.challenge_fp2();
        let product_domain = doms.take(1);
        let product_mask = primary.draw_product_mask(product_domain, products.len());
        let product_proof = prod_batch_prover(&products, chi, product_mask, provider_transcript);
        zero_roots.record_operation_trace_ownership().map_err(|error| error.to_string())?;
        let product_messages =
            take_c6_product_closure_messages().map_err(|error| error.to_string())?;
        let _operation_trace = finish_c6_prover_trace().map_err(|error| error.to_string())?;
        let runtime = runtime_capture
            .finish_installed(&installed_plan, &extraction)
            .map_err(|error| error.to_string())?;
        follower.sync_primary(primary, secondary).map_err(|error| error.to_string())?;
        let schedule = primary
            .schedule_audit()
            .ok_or_else(|| "C6SPR12 production prover schedule audit is absent".to_owned())?;
        let primary_coordinate = C6SourceCoordinate::new(
            primary.finish_c6_subfield_witness_collection().map_err(|error| error.to_string())?,
            primary.finish_c6_fullfield_witness_collection().map_err(|error| error.to_string())?,
            &schedule,
        )
        .map_err(|error| error.to_string())?;
        let secondary_coordinate = follower
            .finish_coordinate(&primary_coordinate, &schedule, secondary)
            .map_err(|error| error.to_string())?;
        (
            proof,
            output,
            products,
            zero_roots,
            metrics,
            product_proof,
            chi,
            product_domain,
            product_messages,
            target_frame,
            target_fixed,
            cache_snapshot,
            target_owner,
            append_sources,
            schedule,
            [primary_coordinate, secondary_coordinate],
            runtime,
        )
    };
    let installed_final_product_triples = installed_plan
        .products()
        .last()
        .ok_or_else(|| "C6SPR12 installed product closures are empty".to_owned())?
        .triples()
        .len();
    if products.len() != installed_final_product_triples
        || product_messages.len() != installed_plan.products().len()
        || prover_zero_roots.len() as u32 != installed_plan.topology().zero_root_count
        || prover_output.weight_claims.len() != 96
        || prover_output.embed_claims.len() != 6
    {
        return Err(format!(
            "C6SPR12 exact provider claim/closure census changed: actual final_triples={} closures={} zero_roots={} weight_claims={} embed_claims={}; installed final_triples={} total_triples={} closures={} zero_roots={}",
            products.len(),
            product_messages.len(),
            prover_zero_roots.len(),
            prover_output.weight_claims.len(),
            prover_output.embed_claims.len(),
            installed_final_product_triples,
            installed_plan.topology().product_triple_count,
            installed_plan.products().len(),
            installed_plan.topology().zero_root_count,
        ));
    }
    // Cross the exact byte boundary consumed by both live and disk replay.
    // No in-memory provider proof object survives this point.
    let retained = C6RetainedResponseProof::decode(
        &C6RetainedResponseProof::encode_parts(&model_proof, &product_proof)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut next_source = 0u64;
    let mut product_mask_sources = Vec::new();
    for draw in &source_schedule.draws {
        if draw.role == CorrScheduleRole::ProductMask {
            product_mask_sources.push(
                u32::try_from(next_source)
                    .map_err(|_| "C6SPR12 product-mask source exceeds u32".to_owned())?,
            );
        }
        next_source = next_source
            .checked_add(draw.count)
            .ok_or_else(|| "C6SPR12 source census overflows".to_owned())?;
    }
    let source_manifest = C6TraceSourceManifest::new(
        u32::try_from(next_source).map_err(|_| "C6SPR12 source manifest exceeds u32".to_owned())?,
        source_schedule.digest,
        product_mask_sources,
    )
    .map_err(|error| error.to_string())?;
    Ok(C6T1ProductionResponseProviderPending {
        retained,
        prover_output,
        prover_zero_roots,
        product_challenge,
        product_mask_domain,
        product_messages,
        source_schedule,
        source_manifest,
        source_coordinates: coordinates,
        installed: C6T1InstalledRoleOwner {
            operation_plan: installed_plan,
            extraction,
            runtime: provider_runtime,
        },
        cache_target_frame,
        cache_target_fixed,
        cache_snapshot,
        cache_target_owner,
        cache_append_sources,
        cache_metrics: provider_cache_metrics,
    })
}

/// Execute the provider half of the genesis `100+50` response.
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_t1_production_response_provider(
    model: &volta_gpt2::Gpt2Model,
    prefill: &volta_gpt2::ModelWitness,
    decode: &volta_gpt2::BandModelWitness,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    streams: &mut [CorrelationStream; 2],
    provider_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseProviderPending, String> {
    prove_c6_production_response_provider(
        model,
        C6ProductionResponseProverProfile::Genesis { prefill, decode },
        sequence,
        statement_digest,
        installed_plan,
        extraction,
        streams,
        provider_transcript,
    )
}

/// Execute the provider half of one `old+50` continuation response.
#[allow(clippy::too_many_arguments)]
pub fn prove_c62_continuation_production_response_provider(
    model: &volta_gpt2::Gpt2Model,
    full: &volta_gpt2::ModelWitness,
    first: &volta_gpt2::BandModelWitness,
    second: &volta_gpt2::BandModelWitness,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plan: C6InstalledOperationPlan,
    extraction: C6DecodedInstanceExtractionPlan,
    streams: &mut [CorrelationStream; 2],
    provider_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseProviderPending, String> {
    prove_c6_production_response_provider(
        model,
        C6ProductionResponseProverProfile::Continuation { full, first, second },
        sequence,
        statement_digest,
        installed_plan,
        extraction,
        streams,
        provider_transcript,
    )
}

/// Coordinate the provider-only response with client source sealing and the
/// strict verifier replay. This compatibility owner keeps the downstream C6.1
/// ownership graph unchanged while enforcing the new process-facing boundary.
#[allow(clippy::too_many_arguments)]
fn build_c6_production_response_owner(
    model: &volta_gpt2::Gpt2Model,
    prover_profile: C6ProductionResponseProverProfile<'_>,
    verifier_profile: C6ProductionResponseVerifierProfile,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseOwner, String> {
    let [provider_plan, verifier_plan] = installed_plans;
    let [provider_extraction, verifier_extraction] = extraction_maps;
    if provider_plan.topology() != verifier_plan.topology()
        || verifier_extraction.role() != C6InstanceExtractionRole::Verifier
        || verifier_extraction.topology_digest() != verifier_plan.topology().topology_digest
    {
        return Err("C6ICT3 provider/verifier installed topology mismatch".to_owned());
    }
    let C6T1ProductionResponseProviderPending {
        retained,
        prover_output,
        prover_zero_roots,
        product_challenge,
        product_mask_domain,
        product_messages: provider_product_messages,
        source_schedule,
        source_manifest,
        source_coordinates,
        installed: provider,
        cache_target_frame,
        cache_target_fixed,
        cache_snapshot,
        cache_target_owner,
        cache_append_sources,
        cache_metrics: provider_cache_metrics,
    } = prove_c6_production_response_provider(
        model,
        prover_profile,
        sequence,
        statement_digest,
        provider_plan,
        provider_extraction,
        attempt.prover_streams_array_mut(),
        provider_transcript,
    )?;
    let paired_sources =
        attempt.seal_sources(source_coordinates, &source_schedule, source_schedule.digest)?;
    let cache_target_frame_bytes =
        cache_target_frame.encode().map_err(|error| error.to_string())?;
    let verifier_model = volta_gpt2::Gpt2VerifierModel::from_model(model)?;
    let verifier = replay_c6_production_response_verifier(
        &verifier_model,
        sequence,
        verifier_profile,
        statement_digest,
        verifier_plan,
        verifier_extraction,
        &cache_target_frame_bytes,
        &retained,
        attempt.verifier_contexts_array_mut(),
        verifier_transcript,
    )?;

    let provider_binding = provider_transcript
        .canonical_binding_digest()
        .map_err(|error| format!("C6ICT3 provider transcript is noncanonical: {error}"))?;
    let verifier_binding = verifier_transcript
        .canonical_binding_digest()
        .map_err(|error| format!("C6ICT3 verifier transcript is noncanonical: {error}"))?;
    if provider_binding != verifier_binding {
        #[cfg(debug_assertions)]
        return Err(format!(
            "C6ICT3 production transcript divergence: {}",
            provider_transcript
                .debug_first_canonical_divergence(verifier_transcript)
                .unwrap_or_else(|| "binding digests differ after equal debug events".to_owned())
        ));
        #[cfg(not(debug_assertions))]
        return Err("C6ICT3 production transcript binding differs across roles".to_owned());
    }
    if verifier.output.weight_keys.len() != 96
        || verifier.output.embed_keys.len() != 6
        || verifier.zero_roots.len() != prover_zero_roots.len()
        || verifier.product_challenge != product_challenge
        || verifier.product_mask_domain != product_mask_domain
        || verifier.product_messages != provider_product_messages
        || verifier.cache_target_fixed != cache_target_fixed
        || verifier.installed.runtime.instance_identity() != provider.runtime.instance_identity()
        || verifier.source_schedule != source_schedule
        || verifier.source_manifest != source_manifest
        || provider_transcript.ledger() != verifier_transcript.ledger()
        || provider_transcript.total_bytes() != verifier_transcript.total_bytes()
    {
        return Err("C6ICT3 split response owner differential failed".to_owned());
    }

    let C6RetainedResponseProof { model: model_proof, product: product_proof } = retained;
    let C6T1ProductionResponseVerifierReplay {
        output: verifier_output,
        zero_roots: verifier_zero_roots,
        product_challenge: _,
        product_mask_domain: _,
        product_messages,
        source_schedule: _,
        source_manifest: _,
        installed: verifier,
        cache_target_fixed: _,
        cache_snapshot: verifier_cache_snapshot,
        cache_targets: _,
        cache_append_sources: verifier_cache_append_sources,
        cache_metrics: verifier_cache_metrics,
    } = verifier;
    if verifier_cache_snapshot.identity != cache_snapshot.identity
        || verifier_cache_snapshot.records != cache_snapshot.records
        || verifier_cache_snapshot.factors != cache_snapshot.factors
        || verifier_cache_append_sources != cache_append_sources
    {
        return Err("C6ICT5 provider/verifier cache trace schedule diverged".to_owned());
    }
    Ok(C6T1ProductionResponseOwner {
        model_proof,
        prover_output,
        verifier_output,
        product_proof,
        product_challenge,
        product_mask_domain,
        product_messages,
        prover_zero_roots,
        verifier_zero_roots,
        paired_sources,
        source_schedule,
        source_manifest,
        provider,
        verifier,
        cache_target_frame,
        cache_target_fixed,
        cache_snapshot,
        cache_target_owner,
        cache_append_sources,
        provider_cache_metrics,
        verifier_cache_metrics,
    })
}

/// Build the paired provider and designated-verifier owner for genesis.
#[allow(clippy::too_many_arguments)]
pub fn build_c6_t1_production_response_owner(
    model: &volta_gpt2::Gpt2Model,
    prefill: &volta_gpt2::ModelWitness,
    decode: &volta_gpt2::BandModelWitness,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseOwner, String> {
    build_c6_production_response_owner(
        model,
        C6ProductionResponseProverProfile::Genesis { prefill, decode },
        C6ProductionResponseVerifierProfile::Genesis,
        sequence,
        statement_digest,
        installed_plans,
        extraction_maps,
        attempt,
        provider_transcript,
        verifier_transcript,
    )
}

/// Build the paired owner for one continuation with 50 new tokens.
#[allow(clippy::too_many_arguments)]
pub fn build_c62_continuation_production_response_owner(
    model: &volta_gpt2::Gpt2Model,
    full: &volta_gpt2::ModelWitness,
    first: &volta_gpt2::BandModelWitness,
    second: &volta_gpt2::BandModelWitness,
    sequence: &[u32],
    statement_digest: [u8; 32],
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    provider_transcript: &mut Transcript,
    verifier_transcript: &mut Transcript,
) -> Result<C6T1ProductionResponseOwner, String> {
    let old_context = first
        .t0
        .checked_add(1)
        .ok_or_else(|| "C6.2 continuation old context overflows".to_owned())?;
    build_c6_production_response_owner(
        model,
        C6ProductionResponseProverProfile::Continuation { full, first, second },
        C6ProductionResponseVerifierProfile::Continuation { base_t0: old_context - 1 },
        sequence,
        statement_digest,
        installed_plans,
        extraction_maps,
        attempt,
        provider_transcript,
        verifier_transcript,
    )
}

impl C6ResponseResidualFixture {
    pub fn manifest(&self) -> &C6ResidualRelationManifest {
        self.relation.manifest()
    }

    pub fn closure_memory_census(&self) -> C6InstalledClosureEvaluationMemoryCensus {
        self.closure_memory
    }

    pub fn census(&self) -> C6ResponseResidualCensus {
        self.census
    }

    pub fn timing(&self) -> C6ResponseResidualTiming {
        self.timing
    }

    pub fn cache_fold_target_frame(&self) -> &[u8] {
        &self.cache_fold_target_frame
    }

    pub fn native_target_profile(&self) -> &C6CanonicalTargetProfile {
        &self.native_target_profile
    }

    pub fn native_target_artifact(&self) -> &[u8] {
        &self.native_target_artifact
    }

    pub fn provider_inputs(
        &mut self,
    ) -> Result<C6ResponseResidualProviderInputs<'_>, C6ResidualError> {
        let witness = C6ResidualFusedWitnessView::new(
            self.relation.manifest(),
            &self.leaf,
            &self.closure,
            &self.auxiliary,
        )?;
        Ok(C6ResponseResidualProviderInputs {
            operation_plan: &self.provider_operation_plan,
            extraction: &self.provider_extraction,
            runtime: &self.provider_runtime,
            linear: &self.provider_linear,
            relation: &self.relation,
            witness,
            streams: &mut self.provider_streams,
            transcript: &mut self.provider_transcript,
        })
    }

    pub fn verifier_inputs(&mut self) -> C6ResponseResidualVerifierInputs<'_> {
        C6ResponseResidualVerifierInputs {
            operation_plan: &self.verifier_operation_plan,
            extraction: &self.verifier_extraction,
            runtime: &self.verifier_runtime,
            linear: &self.verifier_linear,
            relation: &self.relation,
            contexts: &mut self.verifier_contexts,
            transcript: &mut self.verifier_transcript,
        }
    }

    pub fn continued_protocol_states_match(&self) -> bool {
        const SEALED_LABELS: [&str; 4] = [
            "c6_residual_blind_framing",
            "c6_residual_blind_round_corrections",
            "c6_residual_pending_transfers",
            "c6_residual_product_corrections",
        ];
        self.provider_streams
            .iter()
            .zip(&self.verifier_contexts)
            .all(|(stream, context)| stream.counters == context.counters)
            && SEALED_LABELS.iter().all(|label| {
                self.provider_transcript.bytes_for(label)
                    == self.verifier_transcript.bytes_for(label)
            })
    }
}

/// Build the complete `T=4,Q=2` CPU response and return the independently
/// compiled provider/verifier residual inputs.  `None` means the generated
/// GPT-2 weight artifact is not installed locally.
pub fn build_c6_response_residual_fixture(
) -> Result<Option<C6ResponseResidualFixture>, C6ResidualError> {
    build_c6_response_residual_fixture_with_geometry(RESPONSE_LEAF_LOG2, RESPONSE_AUXILIARY_LOG2)
}

/// Build the same complete response with the frozen final C6RSC3 polynomial
/// capacities. This is a local CPU gate: it does not claim the production T1
/// topology flag or any provider/hardware credit.
pub fn build_c6_response_residual_fixture_production_geometry(
) -> Result<Option<C6ResponseResidualFixture>, C6ResidualError> {
    build_c6_response_residual_fixture_with_geometry(
        RESPONSE_PRODUCTION_LEAF_LOG2,
        RESPONSE_PRODUCTION_AUXILIARY_LOG2,
    )
}

/// GPT-2 is an adapter into the generic native-target bridge, not part of the
/// bridge statement. A future model supplies the same typed cohort metadata
/// and exact trace tokens with its own response-independent layout digest.
pub fn c6_gpt2_native_target_profile(
    weight_targets: impl IntoIterator<Item = (usize, C6TraceToken)>,
    embed_targets: impl IntoIterator<Item = (usize, C6TraceToken)>,
) -> Result<C6TraceTargetProfile, C6ResidualError> {
    let weight_targets = weight_targets.into_iter().collect::<Vec<_>>();
    let embed_targets = embed_targets.into_iter().collect::<Vec<_>>();
    if weight_targets.len() != 8 * L || embed_targets.len() != 6 {
        return Err(C6ResidualError::new(
            "C6 GPT-2 native-target adapter received a noncanonical claim census",
        ));
    }

    let mut weight_layout =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/gpt2-native-model-target-layout/v1");
    weight_layout.update(&(L as u32).to_le_bytes());
    weight_layout.update(&2u32.to_le_bytes());
    for (ordinal, (point_arity, _)) in weight_targets.iter().enumerate() {
        let phase = ordinal / (4 * L);
        let within_phase = ordinal % (4 * L);
        let layer = within_phase / 4;
        let matrix = within_phase % 4;
        weight_layout.update(&(phase as u32).to_le_bytes());
        weight_layout.update(&(layer as u32).to_le_bytes());
        weight_layout.update(&(matrix as u32).to_le_bytes());
        weight_layout.update(
            &u32::try_from(*point_arity)
                .map_err(|_| C6ResidualError::new("C6 GPT-2 weight point arity exceeds u32"))?
                .to_le_bytes(),
        );
    }
    let weight_layout_digest = *weight_layout.finalize().as_bytes();

    let mut embed_layout =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/gpt2-native-embed-target-layout/v1");
    embed_layout.update(&2u32.to_le_bytes());
    for (ordinal, (point_arity, _)) in embed_targets.iter().enumerate() {
        let phase = ordinal / 3;
        let commitment = ordinal % 3;
        embed_layout.update(&(phase as u32).to_le_bytes());
        embed_layout.update(&(commitment as u32).to_le_bytes());
        embed_layout.update(
            &u32::try_from(*point_arity)
                .map_err(|_| C6ResidualError::new("C6 GPT-2 embed point arity exceeds u32"))?
                .to_le_bytes(),
        );
    }
    let embed_layout_digest = *embed_layout.finalize().as_bytes();

    let mut profile =
        blake3::Hasher::new_derive_key("volta-zk/c6.1/gpt2-native-target-inference-profile/v1");
    profile.update(&(L as u32).to_le_bytes());
    profile.update(&(D as u32).to_le_bytes());
    profile.update(&(H as u32).to_le_bytes());
    profile.update(&weight_layout_digest);
    profile.update(&embed_layout_digest);
    let inference_profile_digest = *profile.finalize().as_bytes();

    Ok(C6TraceTargetProfile {
        inference_profile_digest,
        cohorts: vec![
            C6TraceTargetCohort {
                cohort_id: C6_GPT2_MODEL_TARGET_COHORT,
                chain_slot: C6_GPT2_MODEL_CHAIN_SLOT,
                polynomial_log2: C6_GPT2_MODEL_POLYNOMIAL_LOG2,
                claim_layout_digest: weight_layout_digest,
                targets: weight_targets.into_iter().map(|(_, token)| token).collect(),
            },
            C6TraceTargetCohort {
                cohort_id: C6_GPT2_EMBED_TARGET_COHORT,
                chain_slot: C6_GPT2_EMBED_CHAIN_SLOT,
                polynomial_log2: C6_GPT2_EMBED_POLYNOMIAL_LOG2,
                claim_layout_digest: embed_layout_digest,
                targets: embed_targets.into_iter().map(|(_, token)| token).collect(),
            },
        ],
    })
}

fn build_c6_response_residual_fixture_with_geometry(
    leaf_log2: u8,
    auxiliary_log2: u8,
) -> Result<Option<C6ResponseResidualFixture>, C6ResidualError> {
    let _fixture_guard = C6_RESIDUAL_TRACE_FIXTURE_LOCK
        .lock()
        .map_err(|_| C6ResidualError::new("C6 response fixture lock is poisoned"))?;
    let weights = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/weights");
    if !weights.join("gpt2s-q.bin").exists() {
        return Ok(None);
    }
    let model = load_model(&weights).map_err(trace_error)?;
    let prefill = forward_model(&model, RESPONSE_T);
    let kv = prefill
        .layers
        .iter()
        .map(|layer| (layer.k.as_slice(), layer.v.as_slice()))
        .collect::<Vec<_>>();
    let mut cache = KvCache::from_prefill(&kv, RESPONSE_T);
    let (generated, _) = generate(&model, &mut cache, &prefill.logits, RESPONSE_T, RESPONSE_Q);
    let mut sequence = model.p.tokens[..RESPONSE_T].to_vec();
    sequence.extend_from_slice(&generated);
    let full = forward_model_tokens(&model, &sequence);
    let band = band_model_witness(&model, &full, RESPONSE_T);
    let chunks_p = [ChunkRef { band: &band, seq: &sequence }];
    let chunks_v = [ChunkPub { q: RESPONSE_Q, logits: &band.logits, seq: &sequence }];

    let primary_seed = [0x61; 32];
    let secondary_seed = [0x62; 32];
    let transcript_seed = [0x63; 32];
    let statement_digest = [0x64; 32];
    let deltas =
        [Fp2::new(Fp::new(0x6101), Fp::new(0x6102)), Fp2::new(Fp::new(0x6201), Fp::new(0x6202))];
    let public_schedule = C6CacheFoldTargetPublicSchedule::new(
        (0..2 * L)
            .flat_map(|_| {
                std::iter::repeat_n(C6CacheFoldKind::ValueColumns, H)
                    .chain(std::iter::repeat_n(C6CacheFoldKind::KeyRows, H))
            })
            .collect(),
    )
    .map_err(trace_error)?;

    let provider_start = Instant::now();
    let mut primary_stream = CorrelationStream::new(primary_seed);
    begin_c6_prover_trace().map_err(trace_error)?;
    primary_stream.enable_c6_operation_trace().map_err(trace_error)?;
    primary_stream.enable_c6_source_witness_collection().map_err(trace_error)?;
    let mut secondary_stream = CorrelationStream::new(secondary_seed);
    let mut prover_follower =
        C6SourceScheduleProverFollower::start(&mut secondary_stream).map_err(trace_error)?;
    let mut prover_tx = Transcript::new(transcript_seed);
    let mut target_builder = C6CacheFoldTargetInlineProver::start_public(
        statement_digest,
        public_schedule.clone(),
        &mut prover_tx,
    )
    .map_err(trace_error)?;
    let prover_trace_guard =
        begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).map_err(trace_error)?;
    let (proof, prover_out, products, grand_residual_roots, prover_metrics, _append_sources) =
        prove_response_c6_cache_inline(
            &model,
            &prefill,
            &chunks_p,
            &mut primary_stream,
            &mut secondary_stream,
            &mut prover_follower,
            &mut target_builder,
            &mut prover_tx,
        );
    let prover_trace = prover_trace_guard.finish().map_err(trace_error)?;
    let (target_frame, prover_fixed) = target_builder
        .finish_before_successor_root_with_identity(prover_trace.identity, &mut prover_tx)
        .map_err(trace_error)?;

    let mut product_doms_p = Doms::new(layer_dom_base(255));
    let chi = prover_tx.challenge_fp2();
    let product_domain = product_doms_p.take(1);
    let product_mask = primary_stream.draw_product_mask(product_domain, products.len());
    let product_proof = prod_batch_prover(&products, chi, product_mask, &mut prover_tx);
    grand_residual_roots.record_operation_trace_ownership().map_err(trace_error)?;
    let zero_challenge = prover_tx.challenge_fp2();
    let prover_operation_trace = finish_c6_prover_trace().map_err(trace_error)?;
    let prover_target_profile = c6_gpt2_native_target_profile(
        prover_out
            .weight_claims
            .iter()
            .map(|claim| (claim.point.len(), claim.value.c6_trace_token())),
        prover_out
            .embed_claims
            .iter()
            .map(|claim| (claim.point.len(), claim.value.c6_trace_token())),
    )?;

    prover_follower.sync_primary(&primary_stream, &mut secondary_stream).map_err(trace_error)?;
    let primary_schedule = primary_stream
        .schedule_audit()
        .ok_or_else(|| C6ResidualError::new("C6 response primary schedule audit is absent"))?;
    let primary_coordinate = C6SourceCoordinate::new(
        primary_stream.finish_c6_subfield_witness_collection().map_err(trace_error)?,
        primary_stream.finish_c6_fullfield_witness_collection().map_err(trace_error)?,
        &primary_schedule,
    )
    .map_err(trace_error)?;
    let secondary_coordinate = prover_follower
        .finish_coordinate(&primary_coordinate, &primary_schedule, &mut secondary_stream)
        .map_err(trace_error)?;
    let paired_sources = C6PairedSourceWitness::new(
        [[0x65; 32], [0x66; 32]],
        [primary_coordinate, secondary_coordinate],
        &primary_schedule,
        primary_schedule.digest,
    )
    .map_err(trace_error)?;
    let mut next_source = 0u64;
    let mut product_mask_sources = Vec::new();
    for draw in &primary_schedule.draws {
        if draw.role == CorrScheduleRole::ProductMask {
            product_mask_sources.push(
                u32::try_from(next_source)
                    .map_err(|_| C6ResidualError::new("C6 response product mask exceeds u32"))?,
            );
        }
        next_source = next_source
            .checked_add(draw.count)
            .ok_or_else(|| C6ResidualError::new("C6 response source census overflows"))?;
    }
    let source_manifest = C6TraceSourceManifest::new(
        u32::try_from(next_source)
            .map_err(|_| C6ResidualError::new("C6 response source census exceeds u32"))?,
        primary_schedule.digest,
        product_mask_sources,
    )
    .map_err(trace_error)?;
    let (prover_compiled, prover_native_targets) =
        compile_c6_operation_trace_for_role_with_target_profile(
            &prover_operation_trace,
            &source_manifest,
            C6InstanceExtractionRole::Prover,
            &prover_target_profile,
        )
        .map_err(trace_error)?;
    let provider_extraction = prover_compiled
        .instance_extraction
        .decode(prover_compiled.plan.topology)
        .map_err(trace_error)?;
    let provider_runtime = derive_c6_runtime_instance_from_trace_diagnostic(
        &prover_operation_trace,
        &prover_compiled.artifact,
        &provider_extraction,
        prover_compiled.plan.instance,
    )
    .map_err(trace_error)?;
    let provider_operation_plan =
        prover_compiled.artifact.install(&source_manifest).map_err(trace_error)?;
    let manifest = C6ResidualRelationManifest::new_with_geometry(
        &provider_operation_plan,
        &provider_extraction,
        &provider_runtime,
        leaf_log2,
        auxiliary_log2,
        false,
    )?;
    let retained = C6ResidualRetainedChallenges::new(
        &manifest,
        vec![chi; provider_operation_plan.products().len()],
        zero_challenge,
    )?;
    let zero_weights = retained.zero_weights(provider_operation_plan.zero_roots().len());
    let provider_linear = C6CompiledLinearResidual::compile(
        &provider_operation_plan,
        &provider_extraction,
        &provider_runtime,
        &zero_weights,
    )?;
    let leaf =
        provider_linear.build_paired_residual_leaf_witness(&paired_sources, &primary_schedule)?;
    let closure_evaluation = provider_linear.evaluate_installed_paired_closure(
        &provider_operation_plan,
        &provider_extraction,
        &provider_runtime,
        &paired_sources,
        &primary_schedule,
    )?;
    let closure_memory = closure_evaluation.memory_census();
    let closure = closure_evaluation.into_closure();
    let auxiliary = closure.transpose_auxiliary_lanes()?;
    let relation = C6ResidualRelationRootBound::bind_fixed_roots(manifest, [0x71; 32], [0x72; 32])?
        .release_base_share_seed(retained, [0x73; 32])?
        .commit_public_claims_from_live(
            &provider_operation_plan,
            &provider_linear,
            &leaf,
            &auxiliary,
        )?
        .release_relation_seed(&provider_operation_plan, [0x74; 32])?;
    let provider_response_and_residual_ns = u64::try_from(provider_start.elapsed().as_nanos())
        .map_err(|_| C6ResidualError::new("C6 provider diagnostic wall exceeds u64 ns"))?;

    let proof =
        decode_model_proof_canonical(&encode_model_proof_canonical(&proof).map_err(trace_error)?)
            .map_err(trace_error)?;
    let verifier_model = volta_gpt2::Gpt2VerifierModel::from_model(&model).map_err(trace_error)?;

    let verifier_start = Instant::now();
    let mut primary_verifier = VerifierCtx::new(primary_seed, deltas[0]);
    begin_c6_verifier_trace().map_err(trace_error)?;
    primary_verifier.enable_c6_operation_trace().map_err(trace_error)?;
    primary_verifier.enable_schedule_audit().map_err(trace_error)?;
    let mut secondary_verifier = VerifierCtx::new(secondary_seed, deltas[1]);
    let mut verifier_follower =
        C6SourceScheduleVerifierFollower::start(&mut secondary_verifier).map_err(trace_error)?;
    let mut verifier_tx = Transcript::new(transcript_seed);
    let mut target_cursor = C6CacheFoldTargetInlineVerifier::start_public(
        &target_frame,
        public_schedule,
        deltas,
        &mut verifier_tx,
    )
    .map_err(trace_error)?;
    let verifier_trace_guard =
        begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).map_err(trace_error)?;
    let (
        verifier_out,
        product_keys,
        verifier_residual_roots,
        verifier_metrics,
        _verifier_append_sources,
        _verifier_cache_targets,
    ) = verify_response_c6_cache_inline_from_profile(
        &verifier_model,
        RESPONSE_T,
        &prefill.logits,
        &chunks_v,
        &proof,
        &mut primary_verifier,
        &mut secondary_verifier,
        &mut verifier_follower,
        &mut target_cursor,
        &mut verifier_tx,
    )
    .ok_or_else(|| C6ResidualError::new("C6 response-wide model proof did not verify"))?;
    let verifier_trace = verifier_trace_guard.finish().map_err(trace_error)?;
    let verifier_fixed = target_cursor
        .finish_before_successor_root_with_identity(verifier_trace.identity, &mut verifier_tx)
        .map_err(trace_error)?;
    let mut product_doms_v = Doms::new(layer_dom_base(255));
    let verifier_chi = verifier_tx.challenge_fp2();
    verifier_tx.append_fp2s("prod_check_m0_m1", &[product_proof.m0, product_proof.m1]);
    if chi != verifier_chi
        || product_domain != product_doms_v.take(1)
        || !prod_batch_verify(
            &product_keys,
            primary_verifier.expand_product_mask_verifier_key(product_domain, product_keys.len()),
            deltas[0],
            chi,
            &product_proof,
        )
    {
        return Err(C6ResidualError::new("C6 response ProductClosure batch differs across roles"));
    }
    verifier_residual_roots.record_operation_trace_ownership().map_err(trace_error)?;
    if zero_challenge != verifier_tx.challenge_fp2() {
        return Err(C6ResidualError::new("C6 response zero challenge differs across roles"));
    }
    let verifier_operation_trace = finish_c6_verifier_trace().map_err(trace_error)?;
    let verifier_target_profile = c6_gpt2_native_target_profile(
        verifier_out.weight_keys.iter().map(|(point, key)| (point.len(), key.c6_trace_token())),
        verifier_out.embed_keys.iter().map(|(point, key)| (point.len(), key.c6_trace_token())),
    )?;
    let (verifier_compiled, verifier_native_targets) =
        compile_c6_operation_trace_for_role_with_target_profile(
            &verifier_operation_trace,
            &source_manifest,
            C6InstanceExtractionRole::Verifier,
            &verifier_target_profile,
        )
        .map_err(trace_error)?;
    let verifier_extraction = verifier_compiled
        .instance_extraction
        .decode(verifier_compiled.plan.topology)
        .map_err(trace_error)?;
    let verifier_runtime = derive_c6_runtime_instance_from_trace_diagnostic(
        &verifier_operation_trace,
        &verifier_compiled.artifact,
        &verifier_extraction,
        verifier_compiled.plan.instance,
    )
    .map_err(trace_error)?;
    let verifier_operation_plan =
        verifier_compiled.artifact.install(&source_manifest).map_err(trace_error)?;
    let verifier_linear = C6CompiledLinearResidual::compile(
        &verifier_operation_plan,
        &verifier_extraction,
        &verifier_runtime,
        &zero_weights,
    )?;
    let verifier_response_and_residual_ns = u64::try_from(verifier_start.elapsed().as_nanos())
        .map_err(|_| C6ResidualError::new("C6 verifier diagnostic wall exceeds u64 ns"))?;
    let native_target_artifact = C6NativeTargetProfileArtifact::encode(
        &prover_native_targets,
        prover_compiled.plan.topology,
    )
    .map_err(trace_error)?;
    let (_, decoded_native_targets) = C6NativeTargetProfileArtifact::decode(
        native_target_artifact.as_bytes(),
        verifier_compiled.plan.topology,
    )
    .map_err(trace_error)?;

    // Diagnostic stand-in for the already fixed native-body batching
    // challenges. Each cohort uses powers of one rho; zeta is sampled only
    // after both complete weight vectors exist.
    let mut native_challenges = Transcript::new([0x67; 32]);
    let mut native_claim_weights = Vec::with_capacity(prover_native_targets.cohorts.len());
    for cohort in &prover_native_targets.cohorts {
        native_challenges.append("c6_native_body_fixed_diagnostic", 0);
        let rho = native_challenges.challenge_fp2();
        let mut power = Fp2::ONE;
        let mut weights = Vec::with_capacity(cohort.canonical_nodes.len());
        for _ in &cohort.canonical_nodes {
            weights.push(power);
            power = power * rho;
        }
        native_claim_weights.push(weights);
    }
    let zeta = native_challenges.challenge_fp2();
    let mut zeta_power = Fp2::ONE;
    let native_cohort_weights = (0..prover_native_targets.cohorts.len())
        .map(|_| {
            let weight = zeta_power;
            zeta_power = zeta_power * zeta;
            weight
        })
        .collect::<Vec<_>>();
    let provider_native_functional = C6CompiledNativeTargetFunctional::compile(
        &provider_operation_plan,
        &provider_extraction,
        &provider_runtime,
        &prover_native_targets,
        &native_claim_weights,
        &native_cohort_weights,
    )?;
    let verifier_native_functional = C6CompiledNativeTargetFunctional::compile(
        &verifier_operation_plan,
        &verifier_extraction,
        &verifier_runtime,
        &verifier_native_targets,
        &native_claim_weights,
        &native_cohort_weights,
    )?;
    let provider_native_primary =
        provider_native_functional.fold_prover_coordinate(&paired_sources, &primary_schedule, 0)?;
    let provider_native_secondary =
        provider_native_functional.fold_prover_coordinate(&paired_sources, &primary_schedule, 1)?;
    let verifier_native_primary = verifier_native_functional
        .fold_verifier_coordinate_from_sources_diagnostic(
            &paired_sources,
            &primary_schedule,
            0,
            deltas[0],
        )?;
    let verifier_native_secondary = verifier_native_functional
        .fold_verifier_coordinate_from_sources_diagnostic(
            &paired_sources,
            &primary_schedule,
            1,
            deltas[1],
        )?;
    let prover_claim_cohorts = [&prover_out.weight_claims[..], &prover_out.embed_claims[..]];
    let verifier_key_cohorts = [&verifier_out.weight_keys[..], &verifier_out.embed_keys[..]];
    let mut direct_prover_primary = ProverAuthed::ZERO;
    let mut direct_verifier_primary = VerifierKey::ZERO;
    for (((prover_claims, verifier_keys), weights), &cohort_weight) in prover_claim_cohorts
        .into_iter()
        .zip(verifier_key_cohorts)
        .zip(&native_claim_weights)
        .zip(&native_cohort_weights)
    {
        for ((claim, (_, key)), &weight) in prover_claims.iter().zip(verifier_keys).zip(weights) {
            let coefficient = cohort_weight * weight;
            direct_prover_primary = direct_prover_primary.add(claim.value.scale(coefficient));
            direct_verifier_primary = direct_verifier_primary.add(key.scale(coefficient));
        }
    }

    let expected_source_cells = (2 * L * (2 * RESPONSE_T + RESPONSE_Q) * D) as u64;
    let expected_auxiliary_cells = (2 * L * (RESPONSE_T + RESPONSE_Q) * D) as u64;
    if prover_trace.identity != verifier_trace.identity
        || prover_trace.records != verifier_trace.records
        || prover_trace.factors != verifier_trace.factors
        || prover_trace.identity.fold_count != 576
        || prover_fixed != verifier_fixed
        || target_frame.encode().map_err(trace_error)?.len() as u64
            != C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES
        || prover_out.weight_claims.len() != 8 * L
        || verifier_out.weight_keys.len() != 8 * L
        || products.len() != product_keys.len()
        || grand_residual_roots.len() != verifier_residual_roots.len()
        || prover_compiled.plan.identity != verifier_compiled.plan.identity
        || prover_compiled.plan.topology != verifier_compiled.plan.topology
        || prover_compiled.plan.instance != verifier_compiled.plan.instance
        || prover_native_targets != verifier_native_targets
        || decoded_native_targets != verifier_native_targets
        || prover_native_targets.cohorts.len() != 2
        || prover_native_targets.target_count() != 8 * L + 6
        || provider_native_functional.functional_digest()
            != verifier_native_functional.functional_digest()
        || provider_native_primary.value != direct_prover_primary
        || verifier_native_primary.key != direct_verifier_primary
        || provider_native_primary.value.x != provider_native_secondary.value.x
        || verifier_native_secondary.key
            != VerifierKey::new(
                provider_native_secondary.value.m + deltas[1] * provider_native_secondary.value.x,
            )
        || provider_linear.linear_form_digest() != verifier_linear.linear_form_digest()
        || prover_metrics.source_groups != (2 * 2 * L) as u64
        || prover_metrics.corrected_targets != 576
        || prover_metrics.source_cells != expected_source_cells
        || prover_metrics.coefficient_applications != expected_source_cells
        || prover_metrics.linear_auxiliary_source_cells != 0
        || verifier_metrics.source_groups != prover_metrics.source_groups
        || verifier_metrics.corrected_targets != prover_metrics.corrected_targets
        || verifier_metrics.source_cells != expected_source_cells
        || verifier_metrics.coefficient_applications != expected_source_cells
        || verifier_metrics.linear_auxiliary_source_cells != expected_auxiliary_cells
    {
        return Err(C6ResidualError::new(
            "C6 complete response residual fixture failed its role/census differential",
        ));
    }
    verifier_follower
        .sync_primary(&primary_verifier, &mut secondary_verifier)
        .map_err(trace_error)?;
    let prover_binding = prover_tx.canonical_binding_digest();
    let verifier_binding = verifier_tx.canonical_binding_digest();
    let prover_binding = prover_binding.map_err(|error| {
        C6ResidualError::new(format!("C6ICT3 provider transcript is noncanonical: {error}"))
    })?;
    let verifier_binding = verifier_binding.map_err(|error| {
        C6ResidualError::new(format!("C6ICT3 verifier transcript is noncanonical: {error}"))
    })?;
    if prover_binding != verifier_binding {
        #[cfg(debug_assertions)]
        return Err(C6ResidualError::new(format!(
            "C6ICT3 scaled transcript divergence: {}",
            prover_tx
                .debug_first_canonical_divergence(&verifier_tx)
                .unwrap_or_else(|| "binding digests differ after equal debug events".to_owned())
        )));
        #[cfg(not(debug_assertions))]
        return Err(C6ResidualError::new("C6ICT3 scaled transcript binding differs across roles"));
    }
    if primary_verifier.schedule_audit() != Some(primary_schedule)
        || secondary_stream.schedule_audit() != secondary_verifier.schedule_audit()
        || primary_stream.counters != primary_verifier.counters
        || secondary_stream.counters != secondary_verifier.counters
        || prover_tx.challenge_fp2() != verifier_tx.challenge_fp2()
    {
        return Err(C6ResidualError::new(
            "C6 complete response continuation state differs across roles",
        ));
    }

    let topology = provider_operation_plan.topology();
    let cache_fold_target_frame = target_frame.encode().map_err(trace_error)?;
    let residual_seeds = [[0x81; 32], [0x82; 32]];
    let residual_deltas =
        [Fp2::new(Fp::new(0x8101), Fp::new(0x8102)), Fp2::new(Fp::new(0x8201), Fp::new(0x8202))];
    Ok(Some(C6ResponseResidualFixture {
        provider_operation_plan,
        provider_extraction,
        provider_runtime,
        provider_linear,
        verifier_operation_plan,
        verifier_extraction,
        verifier_runtime,
        verifier_linear,
        relation,
        leaf,
        closure,
        auxiliary,
        provider_streams: residual_seeds.map(CorrelationStream::new),
        verifier_contexts: [
            VerifierCtx::new(residual_seeds[0], residual_deltas[0]),
            VerifierCtx::new(residual_seeds[1], residual_deltas[1]),
        ],
        provider_transcript: prover_tx,
        verifier_transcript: verifier_tx,
        cache_fold_target_frame,
        native_target_profile: prover_native_targets,
        native_target_artifact: native_target_artifact.as_bytes().to_vec(),
        closure_memory,
        census: C6ResponseResidualCensus {
            source_groups: prover_metrics.source_groups,
            corrected_targets: prover_metrics.corrected_targets,
            source_cells: prover_metrics.source_cells,
            verifier_linear_auxiliary_source_cells: verifier_metrics.linear_auxiliary_source_cells,
            scheduled_sources: topology.source_count,
            product_closures: topology.product_closure_count,
            product_triples: topology.product_triple_count,
            zero_roots: topology.zero_root_count,
            native_target_cohorts: 2,
            native_targets: u32::try_from(8 * L + 6)
                .map_err(|_| C6ResidualError::new("C6 native target census exceeds u32"))?,
            native_target_setup_bytes: native_target_artifact.census().total_bytes,
            native_functional_sources: u32::try_from(
                provider_native_functional.leaf_coefficients().len(),
            )
            .map_err(|_| C6ResidualError::new("C6 native functional source count exceeds u32"))?,
        },
        timing: C6ResponseResidualTiming {
            provider_response_and_residual_ns,
            verifier_response_and_residual_ns,
        },
    }))
}

fn trace_error(error: impl std::fmt::Display) -> C6ResidualError {
    C6ResidualError::new(error.to_string())
}

#[cfg(test)]
mod transcript_tests {
    use super::*;

    #[test]
    fn provider_entry_point_excludes_verifier_capabilities() {
        let source = include_str!("c6_response_fixture.rs");
        let signature = source
            .split_once("pub fn prove_c6_t1_production_response_provider(")
            .unwrap()
            .1
            .split_once('{')
            .unwrap()
            .0;
        assert!(signature.contains("streams: &mut [CorrelationStream; 2]"));
        for forbidden in [
            "C6ProductionPairedPcgAttempt",
            "VerifierCtx",
            "verifier_transcript",
            "verifier_seed",
            "delta",
        ] {
            assert!(!signature.contains(forbidden), "provider signature contains {forbidden}");
        }
    }

    #[test]
    fn live_product_census_uses_the_final_installed_closure() {
        let source = include_str!("c6_response_fixture.rs");
        assert_eq!(source.matches("installed_final_product_triples").count(), 6);
        assert_eq!(source.matches(".products()\n        .last()").count(), 2);
        let stale_prover = [
            "products.len() as u64 != installed_plan.topology()",
            ".product_triple_count",
        ]
        .concat();
        let stale_verifier = [
            "product_keys.len() as u64 != installed_plan.topology()",
            ".product_triple_count",
        ]
        .concat();
        assert!(!source.contains(&stale_prover));
        assert!(!source.contains(&stale_verifier));
    }

    #[test]
    fn production_response_retains_exact_cache_replay_owners() {
        let source = include_str!("c6_response_fixture.rs");
        let provider = source
            .split_once("pub fn prove_c6_t1_production_response_provider(")
            .unwrap()
            .1
            .split_once("/// Coordinate the provider-only response")
            .unwrap()
            .0;
        for required in [
            "finish_before_successor_root_with_owner",
            "cache_snapshot",
            "cache_target_owner",
            "cache_append_sources",
        ] {
            assert!(provider.contains(required));
        }
        assert!(!provider.contains("finish_before_successor_root_with_identity("));
    }

    #[test]
    fn disk_product_claim_join_matches_the_live_claim_frame() {
        let fixture = crate::build_c6_residual_direct_fused_scaled_fixture().unwrap();
        let coordinate_zero =
            fixture.relation().claims().product_coordinate(fixture.manifest(), 0).unwrap();
        let coordinate_one =
            fixture.relation().claims().product_coordinate(fixture.manifest(), 1).unwrap();
        assert_eq!(
            assemble_c6_disk_product_public_claims(
                fixture.manifest(),
                coordinate_zero.messages(),
                &coordinate_one,
            )
            .unwrap(),
            fixture.relation().claims().products()
        );

        let wrong_coordinate =
            fixture.relation().claims().product_coordinate(fixture.manifest(), 0).unwrap();
        assert!(assemble_c6_disk_product_public_claims(
            fixture.manifest(),
            coordinate_zero.messages(),
            &wrong_coordinate,
        )
        .is_err());
    }

    #[test]
    fn complete_response_has_exact_canonical_transcript_parity() {
        let fixture = build_c6_response_residual_fixture().unwrap();
        assert!(fixture.is_some(), "registered GPT-2 weights are required for C6ICT3");
    }
}
