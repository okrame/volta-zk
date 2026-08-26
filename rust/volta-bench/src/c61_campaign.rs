//! Strict local setup loader for the owner-authorized C6.1 campaign.
//!
//! The directory is produced create-new by `c6_t1_census_record`. It is a
//! run artifact, not additional protocol wire framing: the contained plan,
//! extraction maps and C6NTO1 bytes are the setup objects already counted by
//! the C6.1 budget.

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use std::sync::Arc;
#[cfg(feature = "c6-trace")]
use volta_accel::{Backend, DeviceSlice};
use volta_gpt2::{
    decode_verifier_model_canonical, encode_verifier_model_canonical, Gpt2VerifierModel,
};
#[cfg(feature = "c6-trace")]
use volta_mac::VerifierCtx;
use volta_mac::{
    C6CanonicalTargetProfile, C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan,
    C6InstanceExtractionArtifact, C6InstanceExtractionRole, C6NativeTargetProfileArtifact,
    C6OperationPlanArtifact, C6OperationPlanTopologyIdentity, C6TraceSourceManifest, Transcript,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcg::ProductionFaseDConnection;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_authenticated_whir::{
    C62ResponseCompilerBinding, C63AuthenticatedWhirMaskRange, C64AuthenticatedWhirMaskRange,
};
use volta_pcs::c61_authenticated_whir_p3::C61CompilerVerifierProfile;
#[cfg(feature = "c61-p3-authenticated-reference")]
use volta_pcs::c61_authenticated_whir_p3::{
    c62_authenticated_p3_parameter_digest, decode_c62_production_compiler_commitment_descriptors,
    decode_c62_production_native_commitment_descriptor, decode_c62_production_public_argument,
    prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt,
    prepare_c62_authenticated_whir_p3_production_joint_four_chains_fiat_shamir_in_attempt,
    prepare_c62_production_joint_native_verifier_bodies,
    run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt,
    run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt,
    verify_c62_authenticated_whir_p3_primary_chain_fiat_shamir_in_attempt,
    verify_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt,
    C61JointNativeTailRole, C61ProductionCoefficientOwner, C61ProductionCoefficientSessionBinding,
    C61ProductionCommittedChainExecution, C61ProductionCommittedChainProof,
    C61ProductionJointNativeProverBodiesFixed, C61ProductionPersistedResourceAdmission,
    C61ProductionResponseClaimSchedule, C61ProviderJointSessionBinding, C61ProviderSessionBinding,
    C62FiatShamirJointContext, C62FiatShamirLaneContext, C62FiatShamirPublicContext,
    C62ProductionCommittedChainProof, C62ProductionGpuWhir,
    C62ProductionJointNativeProverBodiesFixed, C62ProductionNativeChainProof,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_public_compression::C61NativeComponent;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c62_gpu_whir::C62GpuMmcs;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c6_blind_round_coordinator::{
    assemble_c61_native_exact_production_nbr2_certificate,
    assemble_c62_native_exact_production_nbr2_certificate,
    assemble_c63_exact_production_components, assemble_c64_exact_production_components,
    decode_c62_native_exact_production_blind_envelope,
    finish_c61_native_production_blind_with_persisted_nbr2_link,
    finish_c62_native_decoded_nbr2_verifier,
    finish_c62_native_production_blind_with_persisted_nbr2_link,
    finish_c63_production_blind_with_persisted_link, finish_c63_resident_sketch_suffix,
    finish_c64_production_blind_with_projected_residual, finish_c64_resident_sketch_suffix,
    materialize_c61_native_cache_append_owner, materialize_c61_native_cache_append_verifier_owner,
    prepare_c61_native_decoded_blind_verifier, prepare_c61_native_terminal_compiler,
    prepare_c63_decoded_blind_verifier, prepare_c63_resident_sketch_suffix,
    prepare_c63_terminal_compiler, prepare_c64_terminal_compiler,
    prove_c61_native_production_blind_components, prove_c63_production_blind_components,
    prove_c64_production_blind_components, verify_c63_complete_decoded_response,
    verify_c64_complete_decoded_response, C61NativeExactProductionNbr2Certificate,
    C61NativeProductionBlindProverOutput, C62ExactProductionNbr2VerifierOutput,
    C62NativeExactProductionNbr2Certificate, C63CompleteProductionVerifierOutput,
    C63ProductionBlindProverOutput, C64CompleteProductionVerifierOutput,
    C64ProductionBlindProverOutput,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::C61ProductionResidualRelationBound;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::{
    build_c61_production_arithmetic_frame, c64_projected_residual_binding_digest,
    prepare_c64_projected_residual_precommit, prepare_c6_blind_residual_statement_fused,
    replay_c64_projected_residual_precommit, C61ArithmeticFrame, C62PublicArgument,
    C63SparseSetupReference, C63SparseSketchReference, C63VerifierSketchState,
    C64DecodedResponseTail, C6BlindResidualFusedCompilerContext,
    C6BlindResidualPendingTransferFrame, C6BlindResidualStatement, C6BlindResidualSumcheckProof,
    C6Nbr2CorrectionFunctional,
};
use volta_pcs::{
    c61_response_transcript_context_digest, c63_pack_resident_append_corrections,
    c6_wrapper_profile_digest, decode_c63_response_tail,
    finish_production_c62_native_live_wrapper_roots_cuda,
    install_production_c61_native_live_wrapper_roots_verifier,
    install_production_c63_authenticated_sketch_live_wrapper_roots_verifier,
    materialize_production_c61_native_live_wrapper_roots_cuda,
    materialize_production_c63_authenticated_sketch_live_wrapper_roots_cuda,
    precommit_production_c62_native_cache_roots_cuda,
    spawn_c61_private_entropy_duplex_transcript_broker, C61EqualityDrawn, C61InteractiveTape,
    C61InteractiveTapeBundle, C61JointPublicArgument, C61PrivateEntropyBrokerHandle,
    C61ResponseStatementBinding, C61StatementBinding, C62PersistedNativeCachePrecommit,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use volta_pcs::{
    spawn_c61_private_entropy_transcript_broker, C61AuthenticatedWhirMaskRange, C61NativeChainId,
    C61PrivateEntropyEndpoint, C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE,
    C61_EMBEDDING_POLYNOMIAL_LOG2, C61_INTERACTIVE_TAPE_LANES, C61_MODEL_POLYNOMIAL_LOG2,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::{
    C61NativeLiveWrapperSources, C63GpuSetupOwner, C63GpuStateOwner, C63GpuTileMetadata,
    C6LiveWrapperMaskSeed, C6PersistedLiveWrapperRootBinding, C6PersistentCacheStateWitness,
    C6PersistentCacheStaticProfile, C6VerifierLiveWrapperRootBinding,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_proto::c6_residual::{C6CompiledNativeTargetFunctional, C6NativeTargetProverBridgeFold};
#[cfg(feature = "c6-trace")]
use volta_proto::{
    prepare_c6_t1_disk_residual_owner, prepare_c6_t1_production_residual_owner,
    replay_c62_continuation_production_response_verifier,
    replay_c6_t1_production_response_verifier, C6ProductionPairedPcgAttempt,
    C6ResidualProductClaimCoordinate, C6RetainedResponseProof, C6T1DiskResidualOwner,
    C6T1ProductionResidualBoundOwner, C6T1ProductionResidualOwner,
    C6T1ProductionResponseVerifierReplay,
};
use volta_proto::{
    C61NativeFinalCertificate, C61NativeWrapperCommitments, C61PublicWorkloadInstance,
    C61PublicWorkloadPreimage, C6BoundProductionVerifierReplay, C6CacheHead, C6ClientAttempt,
    C6ProposedCacheHead, C6SetupManifest, C61_NATIVE_CERTIFICATE_VERSION,
    C61_NATIVE_WRAPPER_QUERIES,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_proto::{
    C62NativeFinalCertificate, C62NativeWrapperCommitments, C63NativeFinalCertificate,
    C63NativeWrapperCommitments, C62_NATIVE_CERTIFICATE_VERSION, C62_NATIVE_WRAPPER_QUERIES,
    C63_NATIVE_CERTIFICATE_VERSION, C63_NATIVE_WRAPPER_QUERIES, C64_NATIVE_CERTIFICATE_VERSION,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_proto::{C6ResidualFusedCoefficientArena, C6ResidualFusedWitnessView};

#[cfg(feature = "c6-trace")]
use crate::c6_t1_owner::{
    execute_c62_t1_production_owner_export, execute_c6_t1_production_owner_export,
    materialize_c62_t1_cache_states, persist_c6_t1_native_coefficient_owners,
    C62CampaignWorkloadOwner, C62T1ProductionOwnerExport, C6T1NativeClaimOwner,
    C6T1NativeVerifierClaimOwner, C6T1ProductionOwnerExport, C6T1WorkloadOwner,
};

const CAMPAIGN_ARTIFACT_PROFILE: &str = "C6.1-C6PA2-C6NBR3-C6ICT5-native-campaign-v7";
const CAMPAIGN_BACKEND: &str = "cuda-resident";
const CAMPAIGN_PCG: &str = "real-aes128-mmo";
const CAMPAIGN_FILE_NAMES: [&str; 5] = [
    "certificate.bin",
    "verifier-replay.bin",
    "challenge-tapes.bin",
    "setup-manifest.bin",
    "public-instance.bin",
];
const C62_CAMPAIGN_ARTIFACT_PROFILE: &str =
    "C6.2-C62PA1-C62PIF1-C6NBR2-Fiat-Shamir-native-campaign-v1";
const C63_CAMPAIGN_ARTIFACT_PROFILE: &str =
    "C6.3-C62PA1-C63PUB3-C63PIF2-authenticated-sketch-campaign-v1";
const C64_CAMPAIGN_ARTIFACT_PROFILE: &str =
    "C6.4-C62PA1-C63PUB3-C64PIF1-projected-residual-campaign-v1";
const C62_CAMPAIGN_FILE_NAMES: [&str; 4] =
    ["certificate.bin", "verifier-replay.bin", "setup-manifest.bin", "public-instance.bin"];
const CAMPAIGN_CLIENT_PARAMETERS_MAGIC: &[u8; 8] = b"C61CP4\0\0";
const CAMPAIGN_CLIENT_PARAMETERS_VERSION: u16 = 4;
const CAMPAIGN_CLIENT_PARAMETER_COMPONENTS: usize = 7;
const C62_CAMPAIGN_CLIENT_PARAMETERS_MAGIC: &[u8; 8] = b"C62CP1\0\0";
const C62_CAMPAIGN_CLIENT_PARAMETERS_VERSION: u16 = 1;
const C62_CAMPAIGN_PROFILE_MAGIC: &[u8; 8] = b"C62SP1\0\0";
const C62_CAMPAIGN_PROFILE_VERSION: u16 = 1;
const C62_CAMPAIGN_CLIENT_PARAMETERS_ZSTD_LEVEL: i32 = 3;
const C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES: usize = 8 + 2 + 2 + 8 + 8 + 32 + 32;
const C62_CAMPAIGN_CLIENT_PARAMETERS_TRAILER_BYTES: usize = 32;
pub const C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES: usize = 65_139_022;
pub const C62_CAMPAIGN_SETUP_MAX_BYTES: u64 = 141_882_261;
const C62_CAMPAIGN_PROFILE_BUNDLE_MAGIC: &[u8; 8] = b"C62MP1\0\0";
const C62_CAMPAIGN_PROFILE_BUNDLE_VERSION: u16 = 1;
const C62_CAMPAIGN_PROFILE_COUNT: usize = 17;
const C62_CAMPAIGN_PROFILE_IDS: [u32; C62_CAMPAIGN_PROFILE_COUNT] =
    [0, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900];
const C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES: usize =
    8 + 2 + 2 + (4 + 8 + 32) * C62_CAMPAIGN_PROFILE_COUNT;
const C64_CAMPAIGN_PROFILE_BUNDLE_MAGIC: &[u8; 8] = b"C64MP1\0\0";
const C64_CAMPAIGN_PROFILE_BUNDLE_VERSION: u16 = 1;
const C64_CAMPAIGN_PROFILE_COUNT: usize = 2;
const C64_CAMPAIGN_PROFILE_IDS: [u32; C64_CAMPAIGN_PROFILE_COUNT] = [0, 150];
const C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES: usize =
    8 + 2 + 2 + (4 + 8 + 32) * C64_CAMPAIGN_PROFILE_COUNT;
const C61_CANONICAL_OPERATION_PLAN_BYTES: usize = 63_994_751;
const C61_CLIENT_PARAMETER_ALLOCATION_BYTES: usize = 8_000_000;
const C6_SETUP_BASE_CLIENT_PARAMETER_BYTES: usize = 128;
pub const C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES: usize = C61_CANONICAL_OPERATION_PLAN_BYTES
    + C61_CLIENT_PARAMETER_ALLOCATION_BYTES
    + C6_SETUP_BASE_CLIENT_PARAMETER_BYTES;
const C62_CAMPAIGN_PROFILE_MAX_BYTES: usize = C61_CANONICAL_OPERATION_PLAN_BYTES
    + C61_CLIENT_PARAMETER_ALLOCATION_BYTES
    + C6_SETUP_BASE_CLIENT_PARAMETER_BYTES;
const C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES: usize = C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
    + C62_CAMPAIGN_PROFILE_COUNT * C62_CAMPAIGN_PROFILE_MAX_BYTES;
const C64_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES: usize = C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
    + C64_CAMPAIGN_PROFILE_COUNT * C62_CAMPAIGN_PROFILE_MAX_BYTES;
pub const C61_CAMPAIGN_SETUP_BYTES: u64 = 148_738_118;
const VERIFIER_MODEL_SETUP_MAX_BYTES: usize = 1_000_000;
const PUBLIC_INSTANCE_MAX_BYTES: usize = 160 + 4 * 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupFileRow {
    name: String,
    bytes: u64,
    blake3: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRecord {
    schema: u64,
    profile: String,
    source_count: u32,
    source_schedule_digest: String,
    product_mask_sources: Vec<u32>,
    topology_digest: String,
    native_profile_digest: String,
    files: Vec<SetupFileRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignFileRow {
    name: String,
    bytes: u64,
    blake3: String,
    confidential: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignArtifactRecord {
    schema: u64,
    profile: String,
    source_git_commit: String,
    git_dirty: bool,
    backend: String,
    pcg: String,
    certificate_digest: String,
    setup_manifest_digest: String,
    wrapper_statement_digest: String,
    public_argument_statement_digest: String,
    response_statement_digest: String,
    wire_bytes: u64,
    files: Vec<CampaignFileRow>,
}

pub struct C61CampaignArtifact {
    pub certificate: C61NativeFinalCertificate,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub challenge_tapes: C61InteractiveTapeBundle,
    pub setup_manifest: C6SetupManifest,
    pub verifier_model: Gpt2VerifierModel,
    pub source_manifest: C6TraceSourceManifest,
    pub verifier_plan: C6InstalledOperationPlan,
    pub verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub native_profile: C6CanonicalTargetProfile,
    pub compiler_profile: C61CompilerVerifierProfile,
    pub quantization_digest: [u8; 32],
    pub public_instance: C61PublicWorkloadInstance,
    pub public_argument: C61JointPublicArgument,
    pub source_git_commit: String,
    pub wire_bytes: u64,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignArtifact {
    pub certificate: C62NativeFinalCertificate,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub setup_manifest: C6SetupManifest,
    pub verifier_model: Gpt2VerifierModel,
    pub source_manifest: C6TraceSourceManifest,
    pub operation_plan_artifact: C6OperationPlanArtifact,
    pub verifier_extraction_artifact: C6InstanceExtractionArtifact,
    pub verifier_plan: C6InstalledOperationPlan,
    pub verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub verifier_extraction_setup_bytes: u64,
    pub native_profile: C6CanonicalTargetProfile,
    pub compiler_profile: C61CompilerVerifierProfile,
    pub quantization_digest: [u8; 32],
    pub public_instance: C61PublicWorkloadInstance,
    pub public_argument: C62PublicArgument,
    pub source_git_commit: String,
    pub wire_bytes: u64,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignArtifact {
    pub certificate: C63NativeFinalCertificate,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub setup_manifest: C6SetupManifest,
    pub verifier_model: Gpt2VerifierModel,
    pub source_manifest: C6TraceSourceManifest,
    pub operation_plan_artifact: C6OperationPlanArtifact,
    pub verifier_extraction_artifact: C6InstanceExtractionArtifact,
    pub verifier_plan: C6InstalledOperationPlan,
    pub verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub verifier_extraction_setup_bytes: u64,
    pub native_profile: C6CanonicalTargetProfile,
    pub compiler_profile: C61CompilerVerifierProfile,
    pub quantization_digest: [u8; 32],
    pub public_instance: C61PublicWorkloadInstance,
    pub inherited_public_argument: C62PublicArgument,
    pub source_git_commit: String,
    pub wire_bytes: u64,
}

pub(crate) struct DecodedCampaignClientParameters {
    pub(crate) verifier_model: Gpt2VerifierModel,
    pub(crate) source_manifest: C6TraceSourceManifest,
    pub(crate) operation_plan_artifact: C6OperationPlanArtifact,
    pub(crate) verifier_extraction_artifact: C6InstanceExtractionArtifact,
    pub(crate) verifier_plan: C6InstalledOperationPlan,
    pub(crate) verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub(crate) verifier_extraction_setup_bytes: u64,
    pub(crate) native_profile: C6CanonicalTargetProfile,
    pub(crate) compiler_profile: C61CompilerVerifierProfile,
    pub(crate) quantization_digest: [u8; 32],
}

struct CampaignPayloads {
    certificate: Vec<u8>,
    verifier_replay: Vec<u8>,
    challenge_tapes: Vec<u8>,
    setup_manifest: Vec<u8>,
    public_instance: Vec<u8>,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
struct C62CampaignPayloads {
    certificate: Vec<u8>,
    verifier_replay: Vec<u8>,
    setup_manifest: Vec<u8>,
    public_instance: Vec<u8>,
}

pub struct C61CampaignInstalledSetup {
    pub source_manifest: C6TraceSourceManifest,
    pub provider_plan: C6InstalledOperationPlan,
    pub verifier_plan: C6InstalledOperationPlan,
    pub provider_extraction: C6DecodedInstanceExtractionPlan,
    pub verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub native_profile: C6CanonicalTargetProfile,
    pub compiler_profile: C61CompilerVerifierProfile,
    pub operation_plan_artifact: C6OperationPlanArtifact,
    pub verifier_extraction_artifact: C6InstanceExtractionArtifact,
    pub native_profile_artifact: C6NativeTargetProfileArtifact,
    pub plan_bytes: u64,
    pub extraction_bytes: u64,
    pub native_profile_bytes: u64,
}

/// Client-owned global response transcript for one reserved attempt. The
/// provider and live verifier receive endpoint-backed transcripts only; the
/// entropy seed and broker handle never cross this boundary.
pub struct C61CampaignResponseTranscriptSession {
    context_digest: [u8; 32],
    provider: Transcript,
    verifier: Transcript,
    broker: C61PrivateEntropyBrokerHandle,
}

impl C61CampaignResponseTranscriptSession {
    pub fn start(
        attempt: C6ClientAttempt,
        statement: &C61ResponseStatementBinding,
    ) -> Result<Self, String> {
        let mut verifier_seed = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut verifier_seed)
            .map_err(|error| format!("C6ICT3 response verifier entropy unavailable: {error}"))?;
        Self::start_with_seed(attempt, statement.digest(), verifier_seed)
    }

    fn start_with_seed(
        attempt: C6ClientAttempt,
        statement_digest: [u8; 32],
        verifier_seed: [u8; 32],
    ) -> Result<Self, String> {
        if verifier_seed == [0; 32] {
            return Err("C6ICT3 response verifier entropy is zero".to_owned());
        }
        let context_digest = c61_response_transcript_context_digest(attempt, statement_digest)?;
        let (provider, verifier, broker) =
            spawn_c61_private_entropy_duplex_transcript_broker(verifier_seed, 0, context_digest)
                .map_err(|error| error.to_string())?;
        Ok(Self {
            context_digest,
            provider: Transcript::new_interactive(Box::new(provider)),
            verifier: Transcript::new_interactive(Box::new(verifier)),
            broker,
        })
    }

    pub fn transcripts(&mut self) -> (&mut Transcript, &mut Transcript) {
        (&mut self.provider, &mut self.verifier)
    }

    pub fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub fn finish_certificate(
        self,
        certificate: &C61NativeFinalCertificate,
    ) -> Result<C61InteractiveTape, String> {
        let payload = certificate.encode().map_err(|error| error.to_string())?;
        self.finish_payload(&payload)
    }

    fn finish_payload(mut self, payload: &[u8]) -> Result<C61InteractiveTape, String> {
        if payload.is_empty() {
            return Err("C6ICT3 response final payload is empty".to_owned());
        }
        let provider_result = self.provider.finish_interactive(payload);
        let verifier_result = if provider_result.is_ok() {
            self.verifier.finish_interactive(payload)
        } else {
            Ok(())
        };
        drop(self.provider);
        drop(self.verifier);
        let broker_result = self.broker.finish();
        provider_result?;
        verifier_result?;
        broker_result
    }
}

/// Paired C6.2 response transcripts with no challenge transport.
///
/// The provider and designated verifier restore the same challenge stream
/// from public attempt and statement data.
pub struct C62CampaignResponseTranscriptSession {
    context_digest: [u8; 32],
    provider: Transcript,
    verifier: Transcript,
}

fn c62_campaign_response_transcript_context_digest(
    attempt: C6ClientAttempt,
    statement_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
    attempt.workload.validate().map_err(|error| error.to_string())?;
    if attempt.setup_manifest_digest == [0; 32]
        || attempt.old_head_digest == [0; 32]
        || attempt.nonce == [0; 32]
        || statement_digest == [0; 32]
    {
        return Err("C6.2 response Fiat--Shamir context contains a zero binding".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/response-transcript-context/v1");
    hasher.update(&attempt.slot.to_le_bytes());
    hasher.update(&attempt.nonce);
    hasher.update(&attempt.setup_manifest_digest);
    hasher.update(&attempt.old_head_digest);
    hasher.update(&attempt.predecessor_certificate_digest);
    for range in attempt.correlation_ranges.coordinates {
        hasher.update(&range.stage.to_le_bytes());
        hasher.update(&range.start.to_le_bytes());
        hasher.update(&range.count.to_le_bytes());
    }
    hasher.update(&attempt.workload.digest());
    hasher.update(&statement_digest);
    Ok(*hasher.finalize().as_bytes())
}

impl C62CampaignResponseTranscriptSession {
    pub fn start(
        attempt: C6ClientAttempt,
        statement: &C61ResponseStatementBinding,
    ) -> Result<Self, String> {
        let context_digest =
            c62_campaign_response_transcript_context_digest(attempt, statement.digest())?;
        Ok(Self {
            context_digest,
            provider: Transcript::new_fiat_shamir(context_digest)?,
            verifier: Transcript::new_fiat_shamir(context_digest)?,
        })
    }

    pub fn transcripts(&mut self) -> (&mut Transcript, &mut Transcript) {
        (&mut self.provider, &mut self.verifier)
    }

    pub fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    pub fn verify_synchronized(&self) -> Result<(), String> {
        if self.provider.canonical_binding_digest()? != self.verifier.canonical_binding_digest()?
            || self.provider.ledger() != self.verifier.ledger()
            || self.provider.total_bytes() != self.verifier.total_bytes()
        {
            return Err("C6.2 response Fiat--Shamir transcripts diverged".to_owned());
        }
        Ok(())
    }
}

/// Provider-visible endpoints and durable attempt bindings for the six
/// native chains plus their post-body joint challenge. Verifier entropy and
/// broker handles remain in [`C61CampaignNativeTranscriptSession`].
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61CampaignFourChainTranscriptEndpoints {
    pub four_chain_bindings: [C61ProviderSessionBinding; 4],
    pub four_chain_endpoints: [C61PrivateEntropyEndpoint; 4],
    pub four_chain_mask_ranges: [C61AuthenticatedWhirMaskRange; 4],
    pub joint_binding: C61ProviderJointSessionBinding,
    pub joint_endpoint: C61PrivateEntropyEndpoint,
    coefficient_session: C61ProductionCoefficientSessionBinding,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C61CampaignFourChainTranscriptEndpoints {
    pub fn coefficient_session(&self) -> C61ProductionCoefficientSessionBinding {
        self.coefficient_session
    }
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61CampaignCompilerTranscriptEndpoints {
    pub compiler_bindings: [C61ProviderSessionBinding; 2],
    pub compiler_endpoints: [C61PrivateEntropyEndpoint; 2],
    pub compiler_mask_ranges: [C61AuthenticatedWhirMaskRange; 2],
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61CampaignNativeTranscriptEndpoints {
    pub four_chain: C61CampaignFourChainTranscriptEndpoints,
    pub compiler: C61CampaignCompilerTranscriptEndpoints,
}

/// Client-owned challenge transport for exactly four model/embed lanes, one
/// joint lane and two compiler lanes. It is linear: all provider endpoints
/// are moved out at start and all seven broker handles are consumed at seal.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C61CampaignNativeTranscriptSession {
    contexts: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
    brokers: [C61PrivateEntropyBrokerHandle; C61_INTERACTIVE_TAPE_LANES],
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C61CampaignNativeTranscriptSession {
    pub fn start(
        attempt: C6ClientAttempt,
        profile: &C6CanonicalTargetProfile,
    ) -> Result<(C61CampaignNativeTranscriptEndpoints, Self), String> {
        let mut verifier_seeds = [[0u8; 32]; C61_INTERACTIVE_TAPE_LANES];
        for index in 0..C61_INTERACTIVE_TAPE_LANES {
            OsRng
                .try_fill_bytes(&mut verifier_seeds[index])
                .map_err(|error| format!("C6ICT5 native verifier entropy unavailable: {error}"))?;
            if verifier_seeds[index] == [0; 32]
                || verifier_seeds[..index].contains(&verifier_seeds[index])
            {
                return Err("C6ICT5 native verifier entropy is zero or duplicated".to_owned());
            }
        }
        Self::start_with_seeds(attempt, profile, verifier_seeds)
    }

    fn start_with_seeds(
        attempt: C6ClientAttempt,
        profile: &C6CanonicalTargetProfile,
        verifier_seeds: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
    ) -> Result<(C61CampaignNativeTranscriptEndpoints, Self), String> {
        if verifier_seeds.contains(&[0; 32])
            || (0..verifier_seeds.len())
                .any(|index| verifier_seeds[..index].contains(&verifier_seeds[index]))
        {
            return Err("C6ICT5 native verifier entropy is zero or duplicated".to_owned());
        }
        let mask_ranges = c61_campaign_native_mask_ranges(attempt)?;
        let ids = C61NativeChainId::ordered();
        let bindings: [C61ProviderSessionBinding; 6] = (0..6)
            .map(|index| {
                C61ProviderSessionBinding::from_reserved_attempt(
                    attempt,
                    ids[index],
                    mask_ranges[index],
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6ICT5 native binding census differs".to_owned())?;
        let joint_binding =
            C61ProviderJointSessionBinding::from_reserved_attempt(attempt, profile)?;
        let coefficient_session = C61ProductionCoefficientSessionBinding::from_four_chain_bindings(
            [bindings[0], bindings[1], bindings[2], bindings[3]],
            [mask_ranges[0], mask_ranges[1], mask_ranges[2], mask_ranges[3]],
        )?;
        let mut contexts = [[0u8; 32]; C61_INTERACTIVE_TAPE_LANES];
        for index in 0..6 {
            contexts[index] = bindings[index].context_digest();
        }
        contexts[6] = joint_binding.context_digest();
        if contexts.contains(&[0; 32])
            || (0..contexts.len()).any(|index| contexts[..index].contains(&contexts[index]))
        {
            return Err("C6ICT5 native transcript context is zero or duplicated".to_owned());
        }
        let dimensions = [
            usize::from(C61_MODEL_POLYNOMIAL_LOG2),
            usize::from(C61_MODEL_POLYNOMIAL_LOG2),
            usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2),
            usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2),
            28,
            28,
            0,
        ];
        let mut endpoints = Vec::with_capacity(C61_INTERACTIVE_TAPE_LANES);
        let mut brokers = Vec::with_capacity(C61_INTERACTIVE_TAPE_LANES);
        for index in 0..C61_INTERACTIVE_TAPE_LANES {
            let (endpoint, broker) = spawn_c61_private_entropy_transcript_broker(
                verifier_seeds[index],
                dimensions[index],
                contexts[index],
            )
            .map_err(|error| error.to_string())?;
            endpoints.push(endpoint);
            brokers.push(broker);
        }
        let [model0, model1, embed0, embed1, compiler0, compiler1, joint] =
            endpoints.try_into().map_err(|_| "C6ICT5 native endpoint census differs".to_owned())?;
        let brokers =
            brokers.try_into().map_err(|_| "C6ICT5 native broker census differs".to_owned())?;
        Ok((
            C61CampaignNativeTranscriptEndpoints {
                four_chain: C61CampaignFourChainTranscriptEndpoints {
                    four_chain_bindings: [bindings[0], bindings[1], bindings[2], bindings[3]],
                    four_chain_endpoints: [model0, model1, embed0, embed1],
                    four_chain_mask_ranges: [
                        mask_ranges[0],
                        mask_ranges[1],
                        mask_ranges[2],
                        mask_ranges[3],
                    ],
                    joint_binding,
                    joint_endpoint: joint,
                    coefficient_session,
                },
                compiler: C61CampaignCompilerTranscriptEndpoints {
                    compiler_bindings: [bindings[4], bindings[5]],
                    compiler_endpoints: [compiler0, compiler1],
                    compiler_mask_ranges: [mask_ranges[4], mask_ranges[5]],
                },
            },
            Self { contexts, brokers },
        ))
    }

    pub fn finish(
        self,
        attempt: C6ClientAttempt,
        certificate_digest: [u8; 32],
        response_tape: C61InteractiveTape,
        expected_response_context: [u8; 32],
    ) -> Result<C61InteractiveTapeBundle, String> {
        let tapes = self
            .brokers
            .into_iter()
            .map(C61PrivateEntropyBrokerHandle::finish)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6ICT5 native tape census differs".to_owned())?;
        C61InteractiveTapeBundle::from_completed_attempt(
            attempt,
            certificate_digest,
            tapes,
            response_tape,
            self.contexts,
            expected_response_context,
        )
    }
}

/// C6.2 attempt bindings before the wrapper roots and relation are known.
///
/// This owner supplies the durable coefficient-session identity. It creates
/// all six typed Fiat--Shamir lane contexts after the public roots exist.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C62CampaignNativeBindings {
    bindings: [C61ProviderSessionBinding; 6],
    mask_ranges: [C61AuthenticatedWhirMaskRange; 6],
    coefficient_session: C61ProductionCoefficientSessionBinding,
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub struct C62CampaignNativeContexts {
    pub lane_contexts: [C62FiatShamirLaneContext; 6],
    pub joint_context: C62FiatShamirJointContext,
    pub mask_ranges: [C61AuthenticatedWhirMaskRange; 6],
    pub public_context_digest: [u8; 32],
}

#[cfg(feature = "c61-p3-authenticated-reference")]
impl C62CampaignNativeBindings {
    pub fn start(attempt: C6ClientAttempt) -> Result<Self, String> {
        let mask_ranges = c61_campaign_native_mask_ranges(attempt)?;
        let ids = C61NativeChainId::ordered();
        let bindings: [C61ProviderSessionBinding; 6] = (0..6)
            .map(|index| {
                C61ProviderSessionBinding::from_reserved_attempt(
                    attempt,
                    ids[index],
                    mask_ranges[index],
                )
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6.2 native binding census differs".to_owned())?;
        let coefficient_session = C61ProductionCoefficientSessionBinding::from_four_chain_bindings(
            [bindings[0], bindings[1], bindings[2], bindings[3]],
            [mask_ranges[0], mask_ranges[1], mask_ranges[2], mask_ranges[3]],
        )?;
        Ok(Self { bindings, mask_ranges, coefficient_session })
    }

    pub fn coefficient_session(&self) -> C61ProductionCoefficientSessionBinding {
        self.coefficient_session
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bind_public_context(
        self,
        attempt: C6ClientAttempt,
        profile: &C6CanonicalTargetProfile,
        compiler_profile: &C61CompilerVerifierProfile,
        response_statement_digest: [u8; 32],
        wrapper_statement_digest: [u8; 32],
        residual_relation_digest: [u8; 32],
        proposed_successor_head_digest: [u8; 32],
        source_binding_digest: [u8; 32],
    ) -> Result<C62CampaignNativeContexts, String> {
        let parameter_digests = [
            c62_authenticated_p3_parameter_digest(usize::from(C61_MODEL_POLYNOMIAL_LOG2))?,
            c62_authenticated_p3_parameter_digest(usize::from(C61_MODEL_POLYNOMIAL_LOG2))?,
            c62_authenticated_p3_parameter_digest(usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2))?,
            c62_authenticated_p3_parameter_digest(usize::from(C61_EMBEDDING_POLYNOMIAL_LOG2))?,
            compiler_profile.digest(),
            compiler_profile.digest(),
        ];
        let ids = C61NativeChainId::ordered();
        let mut security = blake3::Hasher::new_derive_key("volta-zk/c6.2/security-profile/v1");
        security.update(b"C62FS1");
        security.update(b"C62AWP1");
        security.update(b"C62JVR1");
        security.update(b"C62PA1");
        security.update(&compiler_profile.digest());
        for digest in parameter_digests {
            security.update(&digest);
        }
        let security_profile_digest = *security.finalize().as_bytes();

        let mut census = blake3::Hasher::new_derive_key("volta-zk/c6.2/lane-census/v1");
        for index in 0..6 {
            census.update(&(ids[index].component as u16).to_le_bytes());
            census.update(&[ids[index].repetition, self.mask_ranges[index].stage]);
            census.update(&self.mask_ranges[index].slot.to_le_bytes());
            census.update(&self.mask_ranges[index].range_start.to_le_bytes());
            census.update(&parameter_digests[index]);
        }
        let lane_census_digest = *census.finalize().as_bytes();
        let public = C62FiatShamirPublicContext::from_reserved_attempt(
            attempt,
            profile,
            security_profile_digest,
            [response_statement_digest, wrapper_statement_digest, residual_relation_digest],
            proposed_successor_head_digest,
            source_binding_digest,
            lane_census_digest,
        )?;
        let lane_contexts: [Result<C62FiatShamirLaneContext, String>; 6] =
            std::array::from_fn(|index| {
                public.lane(
                    self.bindings[index],
                    parameter_digests[index],
                    ids[index],
                    self.mask_ranges[index],
                )
            });
        let lane_contexts = lane_contexts
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| "C6.2 Fiat--Shamir lane census differs".to_owned())?;
        Ok(C62CampaignNativeContexts {
            lane_contexts,
            joint_context: public.joint(),
            mask_ranges: self.mask_ranges,
            public_context_digest: public.digest(),
        })
    }
}

/// Derive the sole legal three-mask subrange on each MAC tape directly from
/// the durable reservation. Model, embedding and compiler consume ordinals
/// 0, 1 and 2 of that same range; callers cannot assign per-chain ranges.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn c61_campaign_native_mask_ranges(
    attempt: C6ClientAttempt,
) -> Result<[C61AuthenticatedWhirMaskRange; 6], String> {
    attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
    let slot = u16::try_from(attempt.slot)
        .map_err(|_| "C6ICT5 native mask slot exceeds u16".to_owned())?;
    let mut per_tape = Vec::with_capacity(2);
    for range in attempt.correlation_ranges.coordinates {
        let stage = u8::try_from(range.stage)
            .map_err(|_| "C6ICT5 native mask stage exceeds u8".to_owned())?;
        let range_start = u32::try_from(range.start)
            .map_err(|_| "C6ICT5 native mask range start exceeds u32".to_owned())?;
        if range.count < C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u64
            || range_start.checked_add(C61_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32).is_none()
        {
            return Err("C6ICT5 native mask range is too short or overflows".to_owned());
        }
        per_tape.push(C61AuthenticatedWhirMaskRange { stage, slot, range_start });
    }
    let [tape0, tape1]: [_; 2] =
        per_tape.try_into().map_err(|_| "C6ICT5 native mask tape census differs".to_owned())?;
    Ok([tape0, tape1, tape0, tape1, tape0, tape1])
}

/// Derive the sole C6.3 four-mask range. Tape separation is encoded by the
/// C6.3 authentication domain, so both tapes share this reserved ordinal span.
#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn c63_campaign_mask_range(
    attempt: C6ClientAttempt,
) -> Result<C63AuthenticatedWhirMaskRange, String> {
    attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
    let slot =
        u16::try_from(attempt.slot).map_err(|_| "C6.3 WHIR mask slot exceeds u16".to_owned())?;
    let [first, second] = attempt.correlation_ranges.coordinates;
    if first.stage != second.stage
        || first.start != second.start
        || first.count < volta_pcs::C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u64
        || second.count < volta_pcs::C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u64
    {
        return Err("C6.3 WHIR mask reservation differs between tapes".to_owned());
    }
    let range = C63AuthenticatedWhirMaskRange {
        stage: u8::try_from(first.stage)
            .map_err(|_| "C6.3 WHIR mask stage exceeds u8".to_owned())?,
        slot,
        range_start: u32::try_from(first.start)
            .map_err(|_| "C6.3 WHIR mask range start exceeds u32".to_owned())?,
    };
    range.end().map_err(|error| error.to_string())?;
    Ok(range)
}

#[cfg(feature = "c61-p3-authenticated-reference")]
pub fn c64_campaign_mask_range(
    attempt: C6ClientAttempt,
) -> Result<C64AuthenticatedWhirMaskRange, String> {
    attempt.correlation_ranges.validate().map_err(|error| error.to_string())?;
    let slot =
        u16::try_from(attempt.slot).map_err(|_| "C6.4 WHIR mask slot exceeds u16".to_owned())?;
    let [first, second] = attempt.correlation_ranges.coordinates;
    let required = (volta_pcs::C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE
        + volta_pcs::C64_AUTHENTICATED_WHIR_MASKS_PER_TAPE) as u64;
    if first.stage != second.stage
        || first.start != second.start
        || first.count < required
        || second.count < required
    {
        return Err("C6.4 WHIR mask reservation differs between tapes".to_owned());
    }
    let range_start = u32::try_from(first.start)
        .map_err(|_| "C6.4 WHIR mask range start exceeds u32".to_owned())?
        .checked_add(volta_pcs::C63_AUTHENTICATED_WHIR_MASKS_PER_TAPE as u32)
        .ok_or_else(|| "C6.4 WHIR mask range start overflows".to_owned())?;
    let range = C64AuthenticatedWhirMaskRange {
        stage: u8::try_from(first.stage)
            .map_err(|_| "C6.4 WHIR mask stage exceeds u8".to_owned())?,
        slot,
        range_start,
    };
    range.end().map_err(|error| error.to_string())?;
    Ok(range)
}

/// Consume the canonical T1 workload through the campaign-owned duplex
/// response session. The response executor receives only the two endpoint
/// transcripts; verifier entropy and the broker remain private to `session`.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn execute_c61_campaign_response_owner(
    workload: C6T1WorkloadOwner,
    statement: &C61ResponseStatementBinding,
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    session: &mut C61CampaignResponseTranscriptSession,
) -> Result<C6T1ProductionOwnerExport, String> {
    let (provider, verifier) = session.transcripts();
    execute_c6_t1_production_owner_export(
        workload,
        statement.digest(),
        installed_plans,
        extraction_maps,
        attempt,
        provider,
        verifier,
    )
}

#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn execute_c62_campaign_response_owner(
    workload: C62CampaignWorkloadOwner,
    statement: &C61ResponseStatementBinding,
    installed_plans: [C6InstalledOperationPlan; 2],
    extraction_maps: [C6DecodedInstanceExtractionPlan; 2],
    attempt: &mut C6ProductionPairedPcgAttempt,
    session: &mut C62CampaignResponseTranscriptSession,
) -> Result<C62T1ProductionOwnerExport, String> {
    let (provider, verifier) = session.transcripts();
    execute_c62_t1_production_owner_export(
        workload,
        statement.digest(),
        installed_plans,
        extraction_maps,
        attempt,
        provider,
        verifier,
    )
}

/// Derive the post-response wrapper base from the same live response and
/// setup-owned compiler identities that will be consumed by the residual
/// relation. No digest-valued production input is accepted.
#[cfg(feature = "c6-trace")]
pub fn build_c61_campaign_live_wrapper_statement(
    response_statement: C61ResponseStatementBinding,
    workload: &C61PublicWorkloadPreimage,
    residual: &C6T1ProductionResidualOwner,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C61StatementBinding, String> {
    let retained = residual.response().encoded_retained_response()?;
    let retained = volta_proto::C61RetainedResponseBinding::from_bytes(&retained)
        .map_err(|error| error.to_string())?;
    C61StatementBinding::bind_production_response_prefix(
        response_statement,
        retained,
        workload,
        residual.manifest(),
        native_profile,
        compiler_profile,
    )
    .map_err(|error| error.to_string())
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn build_c62_campaign_live_wrapper_statement(
    response_statement: C61ResponseStatementBinding,
    workload: &C61PublicWorkloadPreimage,
    residual: &C6T1ProductionResidualOwner,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C61StatementBinding, String> {
    let retained = residual.response().encoded_c62_retained_response()?;
    let retained = volta_proto::C61RetainedResponseBinding::from_c62_bytes(&retained)
        .map_err(|error| error.to_string())?;
    C61StatementBinding::bind_production_response_prefix(
        response_statement,
        retained,
        workload,
        residual.manifest(),
        native_profile,
        compiler_profile,
    )
    .map_err(|error| error.to_string())
}

/// Reconstruct the identical wrapper base after strict disk response replay.
/// The retained-prefix binding comes only from the decoded certificate.
#[cfg(feature = "c6-trace")]
pub fn build_c61_campaign_disk_wrapper_statement(
    response_statement: C61ResponseStatementBinding,
    certificate: &C61NativeFinalCertificate,
    public_instance: &C61PublicWorkloadInstance,
    residual: &C6T1DiskResidualOwner,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C61StatementBinding, String> {
    if response_statement.digest() != public_instance.response_statement_digest() {
        return Err("C6ICT4 disk response statement differs from the public instance".to_owned());
    }
    C61StatementBinding::bind_production_response_prefix(
        response_statement,
        certificate.retained_response_binding(),
        public_instance.preimage(),
        residual.manifest(),
        native_profile,
        compiler_profile,
    )
    .map_err(|error| error.to_string())
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn build_c62_campaign_disk_wrapper_statement(
    response_statement: C61ResponseStatementBinding,
    certificate: &C62NativeFinalCertificate,
    public_instance: &C61PublicWorkloadInstance,
    residual: &C6T1DiskResidualOwner,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C61StatementBinding, String> {
    if response_statement.digest() != public_instance.response_statement_digest() {
        return Err("C6.2 disk response statement differs from public instance".to_owned());
    }
    C61StatementBinding::bind_production_response_prefix(
        response_statement,
        certificate.retained_response_binding(),
        public_instance.preimage(),
        residual.manifest(),
        native_profile,
        compiler_profile,
    )
    .map_err(|error| error.to_string())
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn build_c63_campaign_disk_wrapper_statement(
    response_statement: C61ResponseStatementBinding,
    certificate: &C63NativeFinalCertificate,
    public_instance: &C61PublicWorkloadInstance,
    residual: &C6T1DiskResidualOwner,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C61StatementBinding, String> {
    if response_statement.digest() != public_instance.response_statement_digest() {
        return Err("C6.3 disk response statement differs from public instance".to_owned());
    }
    C61StatementBinding::bind_production_response_prefix(
        response_statement,
        certificate.retained_response_binding(),
        public_instance.preimage(),
        residual.manifest(),
        native_profile,
        compiler_profile,
    )
    .map_err(|error| error.to_string())
}

/// Linear live owner after the four persisted roots and exact residual
/// relation have been fixed on both response transcripts.
#[cfg(feature = "c6-trace")]
pub struct C61CampaignLiveResidualRooted {
    pub provider_roots: C6PersistedLiveWrapperRootBinding,
    pub verifier_roots: C6VerifierLiveWrapperRootBinding,
    pub relation: C61ProductionResidualRelationBound,
    pub session_digest: [u8; 32],
}

/// Root-only continuation retained after the response-dependent relation is
/// consumed by the exact prover. It cannot carry or recreate residual claims.
#[cfg(feature = "c6-trace")]
pub struct C61CampaignLiveRoots {
    pub provider_roots: C6PersistedLiveWrapperRootBinding,
    pub verifier_roots: C6VerifierLiveWrapperRootBinding,
    pub session_digest: [u8; 32],
}

#[cfg(feature = "c6-trace")]
impl C61CampaignLiveResidualRooted {
    pub fn into_parts(self) -> (C61CampaignLiveRoots, C61ProductionResidualRelationBound) {
        (
            C61CampaignLiveRoots {
                provider_roots: self.provider_roots,
                verifier_roots: self.verifier_roots,
                session_digest: self.session_digest,
            },
            self.relation,
        )
    }
}

/// Exact global blind result plus the two statements needed by its strict
/// codec. Both are produced from one residual owner and four-root session.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C61CampaignNativeBlindOwner {
    blind: C61NativeProductionBlindProverOutput,
    statements: [C6BlindResidualStatement; 2],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignNativeBlindOwner {
    blind: C63ProductionBlindProverOutput,
    statements: [C6BlindResidualStatement; 2],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C64CampaignNativeBlindOwner {
    blind: C64ProductionBlindProverOutput,
    statements: [C6BlindResidualStatement; 2],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C64CampaignNativeBlindOwner {
    fn into_parts(self) -> (C64ProductionBlindProverOutput, [C6BlindResidualStatement; 2]) {
        (self.blind, self.statements)
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C63CampaignNativeBlindOwner {
    fn into_parts(self) -> (C63ProductionBlindProverOutput, [C6BlindResidualStatement; 2]) {
        (self.blind, self.statements)
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C61CampaignNativeBlindOwner {
    pub fn into_parts(
        self,
    ) -> (C61NativeProductionBlindProverOutput, [C6BlindResidualStatement; 2]) {
        (self.blind, self.statements)
    }
}

/// Execute the hidden-free residual/cache blind prefix from the exact
/// response, relation and persisted cache cohorts. Cache readers, append
/// authentications, statements and fused witness state are not caller inputs.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prove_c61_campaign_native_blind(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    workload: &C61PublicWorkloadPreimage,
    attempt: &mut C6ProductionPairedPcgAttempt,
    transcript: &mut Transcript,
) -> Result<C61CampaignNativeBlindOwner, String> {
    let cohorts = roots.provider_roots.cohorts();
    if cohorts.len() != 4 || roots.provider_roots.session_digest() != roots.session_digest {
        return Err("C6ICT5 native blind root/session census differs".to_owned());
    }
    let predecessor = cohorts[0].open_semantic_cache().map_err(|error| error.to_string())?;
    let successor = cohorts[1].open_semantic_cache().map_err(|error| error.to_string())?;
    let old_len = u16::try_from(workload.workload().old_context)
        .map_err(|_| "C6ICT5 native blind old cache length exceeds u16")?;
    let new_len = u16::try_from(workload.workload().new_context)
        .map_err(|_| "C6ICT5 native blind new cache length exceeds u16")?;
    let response = residual.response();
    let streams = attempt.prover_streams_array_mut();
    let append = materialize_c61_native_cache_append_owner(
        response.cache_append_sources(),
        &successor,
        old_len,
        new_len,
        streams,
    )?;
    let compiler = C6BlindResidualFusedCompilerContext::new(
        response.provider().operation_plan(),
        response.provider().extraction(),
        response.provider().runtime(),
        residual.provider_linear(),
        residual.relation(),
    );
    let witness = C6ResidualFusedWitnessView::new(
        residual.relation().manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
    )
    .map_err(|error| error.to_string())?;
    let arena = C6ResidualFusedCoefficientArena::new(residual.relation().manifest());
    let statements: [C6BlindResidualStatement; 2] = (0..2u8)
        .map(|repetition| prepare_c6_blind_residual_statement_fused(compiler, repetition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "C6ICT5 native blind statement census differs".to_owned())?;
    let blind = prove_c61_native_production_blind_components(
        roots.provider_roots.fixed(),
        roots.provider_roots.fixed().statement_digest(),
        response.cache_snapshot(),
        response.cache_target_owner().targets(),
        response.cache_target_owner().fixed(),
        &predecessor,
        &successor,
        old_len,
        new_len,
        &append,
        &statements,
        compiler,
        witness,
        &arena,
        streams,
        transcript,
    )?;
    Ok(C61CampaignNativeBlindOwner { blind, statements })
}

/// Execute only the residual blind prefix. The cache is authenticated by the
/// resident C6.3 state and cannot re-enter as a dense participant here.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prove_c63_campaign_native_blind(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    attempt: &mut C6ProductionPairedPcgAttempt,
    transcript: &mut Transcript,
) -> Result<C63CampaignNativeBlindOwner, String> {
    if roots.provider_roots.cohorts().len() != 2
        || roots.provider_roots.session_digest() != roots.session_digest
    {
        return Err("C6.3 blind root or session census differs".to_owned());
    }
    let response = residual.response();
    let compiler = C6BlindResidualFusedCompilerContext::new(
        response.provider().operation_plan(),
        response.provider().extraction(),
        response.provider().runtime(),
        residual.provider_linear(),
        residual.relation(),
    );
    let witness = C6ResidualFusedWitnessView::new(
        residual.relation().manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
    )
    .map_err(|error| error.to_string())?;
    let arena = C6ResidualFusedCoefficientArena::new(residual.relation().manifest());
    let statements: [C6BlindResidualStatement; 2] = (0..2u8)
        .map(|repetition| prepare_c6_blind_residual_statement_fused(compiler, repetition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "C6.3 blind statement census differs".to_owned())?;
    let blind = prove_c63_production_blind_components(
        &statements,
        compiler,
        witness,
        &arena,
        attempt.prover_streams_array_mut(),
        transcript,
    )?;
    Ok(C63CampaignNativeBlindOwner { blind, statements })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prove_c64_campaign_native_blind(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    functional: &C62CampaignNativeFunctionalOwner,
    mmcs: &C62GpuMmcs,
    attempt: &mut C6ProductionPairedPcgAttempt,
    transcript: &mut Transcript,
) -> Result<C64CampaignNativeBlindOwner, String> {
    use rand_010::SeedableRng;

    if roots.provider_roots.cohorts().len() != 2
        || roots.provider_roots.session_digest() != roots.session_digest
    {
        return Err("C6.4 blind root or session census differs".to_owned());
    }
    let response = residual.response();
    let compiler = C6BlindResidualFusedCompilerContext::new(
        response.provider().operation_plan(),
        response.provider().extraction(),
        response.provider().runtime(),
        residual.provider_linear(),
        residual.relation(),
    );
    let witness = C6ResidualFusedWitnessView::new(
        residual.relation().manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
    )
    .map_err(|error| error.to_string())?;
    let arena = C6ResidualFusedCoefficientArena::new(residual.relation().manifest());
    let statements: [C6BlindResidualStatement; 2] = (0..2u8)
        .map(|repetition| prepare_c6_blind_residual_statement_fused(compiler, repetition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "C6.4 blind statement census differs".to_owned())?;
    let binding_digest = c64_projected_residual_binding_digest(
        roots.provider_roots.fixed().binding_digest(),
        functional.outer_statement_digest(),
        residual.relation().digest(),
        roots.provider_roots.source_binding_digest(),
    )?;
    let mut entropy = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|error| format!("C6.4 precommit entropy unavailable: {error}"))?;
    let mut rng = rand_010::rngs::StdRng::from_seed(entropy);
    let precommit = prepare_c64_projected_residual_precommit(
        mmcs,
        binding_digest,
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
        transcript,
        &mut rng,
    )?;
    let blind = prove_c64_production_blind_components(
        precommit,
        &statements,
        compiler,
        witness,
        &arena,
        attempt.prover_streams_array_mut(),
        transcript,
    )?;
    Ok(C64CampaignNativeBlindOwner { blind, statements })
}

/// Exact response-owned four-chain output. Primary and secondary executions
/// remain together until the joint functional consumes this owner.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C61CampaignNativeFourChainOwner {
    primary: [C61ProductionCommittedChainExecution; 2],
    joint: C61ProductionJointNativeProverBodiesFixed,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C61CampaignNativeFourChainOwner {
    fn into_parts(
        self,
    ) -> ([C61ProductionCommittedChainExecution; 2], C61ProductionJointNativeProverBodiesFixed)
    {
        (self.primary, self.joint)
    }
}

/// Run the four exact model/embed chains from the same response-owned claim
/// schedule, paired residual targets and session-bound coefficient files.
/// No detached claim, target, coefficient vector, seed or transcript enters.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c61_campaign_native_four_chains(
    native_claims: C6T1NativeClaimOwner,
    residual: &C6T1ProductionResidualBoundOwner,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    profile: &C6CanonicalTargetProfile,
    endpoints: C61CampaignFourChainTranscriptEndpoints,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    spill_root: &Path,
) -> Result<C61CampaignNativeFourChainOwner, String> {
    let expected_session = endpoints.coefficient_session().context_digest();
    if model_coefficients.component() != C61NativeComponent::Model
        || embedding_coefficients.component() != C61NativeComponent::Embedding
        || model_coefficients.session_digest() != expected_session
        || embedding_coefficients.session_digest() != expected_session
    {
        return Err("C6ICT5 coefficient owner/session binding differs".to_owned());
    }
    let claim_schedule = C61ProductionResponseClaimSchedule::new(
        native_claims.model_claims(),
        native_claims.embedding_claims(),
    )?;
    let claim_schedule_digest = claim_schedule.digest();
    let (model_targets, embedding_targets) =
        native_claims.production_paired_targets(profile, residual.native_targets())?;
    let model_coefficient_digest = model_coefficients.coefficient_digest();
    let embedding_coefficient_digest = embedding_coefficients.coefficient_digest();
    let C61CampaignFourChainTranscriptEndpoints {
        four_chain_bindings,
        four_chain_endpoints,
        four_chain_mask_ranges,
        joint_binding,
        joint_endpoint,
        coefficient_session: _,
    } = endpoints;
    let chain_root = spill_root.join("four-chain");
    fs::create_dir(&chain_root)
        .map_err(|error| format!("create C6ICT5 four-chain spill root: {error}"))?;
    let prepared =
        prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt(
            move |component, repetition| match component {
                C61NativeComponent::Model => model_coefficients.load_for(component, repetition),
                C61NativeComponent::Embedding => {
                    embedding_coefficients.load_for(component, repetition)
                }
                C61NativeComponent::Compiler => {
                    Err("C6ICT5 four-chain loader rejects compiler coefficients".to_owned())
                }
            },
            model_coefficient_digest,
            embedding_coefficient_digest,
            claim_schedule,
            model_targets,
            embedding_targets,
            profile,
            four_chain_bindings,
            four_chain_endpoints,
            joint_binding,
            joint_endpoint,
            &chain_root,
            admission,
            backend,
            attempt.prover_streams_array_mut(),
            four_chain_mask_ranges,
        )?;
    if prepared.model_coefficient_digest != model_coefficient_digest
        || prepared.embedding_coefficient_digest != embedding_coefficient_digest
        || prepared.claim_schedule_digest != claim_schedule_digest
    {
        return Err("C6ICT5 four-chain output differs from its exact owners".to_owned());
    }
    Ok(C61CampaignNativeFourChainOwner { primary: prepared.primary, joint: prepared.joint })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignNativeFourChainOwner {
    primary: [C61ProductionCommittedChainExecution; 2],
    joint: C62ProductionJointNativeProverBodiesFixed,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C62CampaignNativeFourChainOwner {
    fn into_parts(
        self,
    ) -> ([C61ProductionCommittedChainExecution; 2], C62ProductionJointNativeProverBodiesFixed)
    {
        (self.primary, self.joint)
    }
}

/// Run all four model and embedding chains from public C62FS1 contexts.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c62_campaign_native_four_chains(
    native_claims: C6T1NativeClaimOwner,
    residual: &C6T1ProductionResidualBoundOwner,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    profile: &C6CanonicalTargetProfile,
    contexts: &C62CampaignNativeContexts,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    spill_root: &Path,
) -> Result<C62CampaignNativeFourChainOwner, String> {
    let claim_schedule = C61ProductionResponseClaimSchedule::new(
        native_claims.model_claims(),
        native_claims.embedding_claims(),
    )?;
    let claim_schedule_digest = claim_schedule.digest();
    let (model_targets, embedding_targets) =
        native_claims.production_paired_targets(profile, residual.native_targets())?;
    let model_coefficient_digest = model_coefficients.coefficient_digest();
    let embedding_coefficient_digest = embedding_coefficients.coefficient_digest();
    let chain_root = spill_root.join("four-chain");
    fs::create_dir(&chain_root)
        .map_err(|error| format!("create C6.2 four-chain spill root: {error}"))?;
    let prepared =
        prepare_c62_authenticated_whir_p3_production_joint_four_chains_fiat_shamir_in_attempt(
            move |component, repetition| match component {
                C61NativeComponent::Model => model_coefficients.load_for(component, repetition),
                C61NativeComponent::Embedding => {
                    embedding_coefficients.load_for(component, repetition)
                }
                C61NativeComponent::Compiler => {
                    Err("C6.2 four-chain loader rejects compiler coefficients".to_owned())
                }
            },
            model_coefficient_digest,
            embedding_coefficient_digest,
            claim_schedule,
            model_targets,
            embedding_targets,
            profile,
            [
                contexts.lane_contexts[0],
                contexts.lane_contexts[1],
                contexts.lane_contexts[2],
                contexts.lane_contexts[3],
            ],
            contexts.joint_context,
            &chain_root,
            admission,
            backend,
            gpu,
            attempt.prover_streams_array_mut(),
            [
                contexts.mask_ranges[0],
                contexts.mask_ranges[1],
                contexts.mask_ranges[2],
                contexts.mask_ranges[3],
            ],
        )?;
    if prepared.model_coefficient_digest != model_coefficient_digest
        || prepared.embedding_coefficient_digest != embedding_coefficient_digest
        || prepared.claim_schedule_digest != claim_schedule_digest
    {
        return Err("C6.2 four-chain output differs from its exact owners".to_owned());
    }
    Ok(C62CampaignNativeFourChainOwner { primary: prepared.primary, joint: prepared.joint })
}

/// Provider-only joint functional derived after every secondary native body
/// is fixed. The contained correction is the tape-1 source correction fold,
/// not a difference chosen from native target aggregates.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C61CampaignNativeFunctionalOwner {
    primary: [C61ProductionCommittedChainExecution; 2],
    functional: C6CompiledNativeTargetFunctional,
    joint: C61ProductionJointNativeProverBodiesFixed,
    bridge: C6NativeTargetProverBridgeFold,
    native_profile_digest: [u8; 32],
    body_schedule_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C61CampaignNativeFunctionalOwner {
    pub fn into_parts(
        self,
    ) -> (
        [C61ProductionCommittedChainExecution; 2],
        C6CompiledNativeTargetFunctional,
        C61ProductionJointNativeProverBodiesFixed,
        C6NativeTargetProverBridgeFold,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.primary,
            self.functional,
            self.joint,
            self.bridge,
            self.native_profile_digest,
            self.body_schedule_digest,
            self.outer_statement_digest,
        )
    }
}

/// Compile the exact post-body 96+6 functional and its tape-1 bridge from the
/// same installed response owner. No coefficient, correction, digest or
/// authenticated base fold is accepted from the caller.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prepare_c61_campaign_native_functional(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    profile: &C6CanonicalTargetProfile,
    profile_artifact: &C6NativeTargetProfileArtifact,
    four_chain: C61CampaignNativeFourChainOwner,
) -> Result<C61CampaignNativeFunctionalOwner, String> {
    let (primary, joint) = four_chain.into_parts();
    let response = residual.response();
    let operation_plan = response.provider().operation_plan();
    let (_, decoded_profile) = C6NativeTargetProfileArtifact::decode(
        profile_artifact.as_bytes(),
        operation_plan.topology(),
    )
    .map_err(|error| error.to_string())?;
    if &decoded_profile != profile
        || profile.source_schedule_digest != response.source_schedule().digest
        || roots.provider_roots.fixed().statement_digest()
            != roots.verifier_roots.fixed().statement_digest()
    {
        return Err("C6ICT5 native functional setup/response/root binding differs".to_owned());
    }
    let claim_weights =
        joint.claim_weights().into_iter().map(<[volta_field::Fp2]>::to_vec).collect::<Vec<_>>();
    let challenge = joint.challenge();
    let functional = C6CompiledNativeTargetFunctional::compile(
        operation_plan,
        response.provider().extraction(),
        response.provider().runtime(),
        profile,
        &claim_weights,
        &challenge.cohort_weights,
    )
    .map_err(|error| error.to_string())?;
    let bridge = functional
        .fold_prover_bridge_coordinate(
            response.paired_sources().source(),
            response.source_schedule(),
            1,
        )
        .map_err(|error| error.to_string())?;
    if bridge.coordinate != 1 || bridge.functional_digest != functional.functional_digest() {
        return Err("C6ICT5 native functional tape-1 bridge differs".to_owned());
    }
    let native_profile_digest = *blake3::hash(profile_artifact.as_bytes()).as_bytes();
    let body_schedule_digest = challenge.schedule_digest;
    let outer_statement_digest = volta_pcs::c61_joint_public_statement_digest(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        body_schedule_digest,
        functional.functional_digest(),
    )
    .map_err(|error| error.to_string())?;
    Ok(C61CampaignNativeFunctionalOwner {
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        outer_statement_digest,
    })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignNativeFunctionalOwner {
    primary: [C61ProductionCommittedChainExecution; 2],
    functional: C6CompiledNativeTargetFunctional,
    joint: C62ProductionJointNativeProverBodiesFixed,
    bridge: C6NativeTargetProverBridgeFold,
    native_profile_digest: [u8; 32],
    body_schedule_digest: [u8; 32],
    response_binding_digest: [u8; 32],
    root_binding_digest: [u8; 32],
    outer_statement_digest: [u8; 32],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C62CampaignNativeFunctionalOwner {
    fn outer_statement_digest(&self) -> [u8; 32] {
        self.outer_statement_digest
    }

    #[allow(clippy::type_complexity)]
    fn into_parts(
        self,
    ) -> (
        [C61ProductionCommittedChainExecution; 2],
        C6CompiledNativeTargetFunctional,
        C62ProductionJointNativeProverBodiesFixed,
        C6NativeTargetProverBridgeFold,
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        (
            self.primary,
            self.functional,
            self.joint,
            self.bridge,
            self.native_profile_digest,
            self.body_schedule_digest,
            self.response_binding_digest,
            self.root_binding_digest,
            self.outer_statement_digest,
        )
    }
}

fn c62_campaign_response_binding_digest(
    response_statement_digest: [u8; 32],
    retained_response: &[u8],
    source_schedule_digest: [u8; 32],
    residual_relation_digest: [u8; 32],
) -> Result<[u8; 32], String> {
    if response_statement_digest == [0; 32]
        || retained_response.is_empty()
        || source_schedule_digest == [0; 32]
        || residual_relation_digest == [0; 32]
    {
        return Err("C6.2 response binding contains an empty component".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/response-binding/v1");
    hasher.update(&response_statement_digest);
    hasher.update(blake3::hash(retained_response).as_bytes());
    hasher.update(&source_schedule_digest);
    hasher.update(&residual_relation_digest);
    Ok(*hasher.finalize().as_bytes())
}

/// Compile the C62JVR1 functional after all secondary bodies are fixed.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c62_campaign_native_functional(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    profile: &C6CanonicalTargetProfile,
    profile_artifact: &C6NativeTargetProfileArtifact,
    response_statement_digest: [u8; 32],
    four_chain: C62CampaignNativeFourChainOwner,
) -> Result<C62CampaignNativeFunctionalOwner, String> {
    let (primary, joint) = four_chain.into_parts();
    let response = residual.response();
    let operation_plan = response.provider().operation_plan();
    let (_, decoded_profile) = C6NativeTargetProfileArtifact::decode(
        profile_artifact.as_bytes(),
        operation_plan.topology(),
    )
    .map_err(|error| error.to_string())?;
    if &decoded_profile != profile
        || profile.source_schedule_digest != response.source_schedule().digest
        || roots.provider_roots.fixed().statement_digest()
            != roots.verifier_roots.fixed().statement_digest()
    {
        return Err("C6.2 native functional setup, response, or root binding differs".to_owned());
    }
    let claim_weights =
        joint.claim_weights().into_iter().map(<[volta_field::Fp2]>::to_vec).collect::<Vec<_>>();
    let challenge = joint.challenge();
    let functional = C6CompiledNativeTargetFunctional::compile(
        operation_plan,
        response.provider().extraction(),
        response.provider().runtime(),
        profile,
        &claim_weights,
        &challenge.cohort_weights,
    )
    .map_err(|error| error.to_string())?;
    let bridge = functional
        .fold_prover_bridge_coordinate(
            response.paired_sources().source(),
            response.source_schedule(),
            1,
        )
        .map_err(|error| error.to_string())?;
    if bridge.coordinate != 1 || bridge.functional_digest != functional.functional_digest() {
        return Err("C6.2 native functional tape-1 bridge differs".to_owned());
    }
    let native_profile_digest = *blake3::hash(profile_artifact.as_bytes()).as_bytes();
    let body_schedule_digest = challenge.schedule_digest;
    let retained_response = response.encoded_c62_retained_response()?;
    let response_binding_digest = c62_campaign_response_binding_digest(
        response_statement_digest,
        &retained_response,
        response.source_schedule().digest,
        residual.relation().digest(),
    )?;
    let root_binding_digest = roots.provider_roots.fixed().binding_digest();
    let outer_statement_digest = volta_pcs::c62_public_statement_digest(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        body_schedule_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
    )
    .map_err(|error| error.to_string())?;
    Ok(C62CampaignNativeFunctionalOwner {
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        response_binding_digest,
        root_binding_digest,
        outer_statement_digest,
    })
}

/// Complete the native/compiler/C6NBR2 provider suffix under one exact
/// response attempt. Every digest, coefficient, correction, terminal value
/// and compiler relation is derived from preceding typed owners.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn finish_c61_campaign_native_proof(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    blind: C61CampaignNativeBlindOwner,
    equality: C61EqualityDrawn,
    functional: C61CampaignNativeFunctionalOwner,
    profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
    compiler_endpoints: C61CampaignCompilerTranscriptEndpoints,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    spill_root: &Path,
    transcript: &mut Transcript,
) -> Result<C61NativeExactProductionNbr2Certificate, String> {
    let (blind, statements) = blind.into_parts();
    let terminal = prepare_c61_native_terminal_compiler(&blind, equality, transcript)?;
    let (
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        outer_statement_digest,
    ) = functional.into_parts();
    if joint.challenge().schedule_digest != body_schedule_digest
        || bridge.functional_digest != functional.functional_digest()
    {
        return Err("C6ICT5 native suffix functional schedule differs".to_owned());
    }
    let response = residual.response();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.provider_roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        roots.provider_roots.source_binding_digest(),
        response.source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        bridge.correction,
    )
    .map_err(|error| error.to_string())?;
    let native = joint.prepare_nbr2_link(bridge.base_value, bridge.correction, nbr2.digest())?;

    let C61CampaignCompilerTranscriptEndpoints {
        compiler_bindings,
        compiler_endpoints,
        compiler_mask_ranges,
    } = compiler_endpoints;
    let compiler_roots = [spill_root.join("compiler0"), spill_root.join("compiler1")];
    let link_root = spill_root.join("native-link");
    for path in compiler_roots.iter().chain(std::iter::once(&link_root)) {
        fs::create_dir(path).map_err(|error| format!("create C6ICT5 spill lane: {error}"))?;
    }
    let inputs = terminal.inputs();
    if inputs.relation_challenges_digest() != residual.relation().digest()
        || compiler_profile.operation_plan_digest()
            != response.provider().operation_plan().artifact_digest()
    {
        return Err("C6ICT5 compiler setup/relation differs from terminal owner".to_owned());
    }
    let ids = C61NativeChainId::ordered();
    let compiler = {
        let (stream0, stream1) = attempt.prover_streams_mut();
        let [binding0, binding1] = compiler_bindings;
        let [endpoint0, endpoint1] = compiler_endpoints;
        let [range0, range1] = compiler_mask_ranges;
        [
            run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                binding0,
                &compiler_roots[0],
                admission,
                stream0,
                endpoint0,
                ids[4],
                range0,
            )?,
            run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                binding1,
                &compiler_roots[1],
                admission,
                stream1,
                endpoint1,
                ids[5],
                range1,
            )?,
        ]
    };
    let canonical_runtime = response
        .provider()
        .runtime()
        .canonical_runtime_values(response.provider().extraction())
        .map_err(|error| error.to_string())?;
    let arithmetic = build_c61_production_arithmetic_frame(
        terminal.ready(),
        outer_statement_digest,
        &canonical_runtime,
        inputs.functional_fold(),
    )
    .map_err(|error| error.to_string())?;
    let proof = finish_c61_native_production_blind_with_persisted_nbr2_link(
        &roots.provider_roots,
        blind,
        &nbr2,
        &terminal,
        native,
        attempt.prover_streams_array_mut(),
        backend,
        &link_root,
        roots.session_digest,
        transcript,
    )?;
    let cache_fold_target_frame =
        response.cache_target_frame().encode().map_err(|error| error.to_string())?;
    assemble_c61_native_exact_production_nbr2_certificate(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        functional.functional_digest(),
        profile,
        primary,
        compiler,
        arithmetic,
        &statements,
        &cache_fold_target_frame,
        roots.provider_roots.fixed(),
        proof,
    )
}

/// Complete the C6.2 compiler, C62JVR1, and C6NBR2 suffix.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn finish_c62_campaign_native_proof(
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    blind: C61CampaignNativeBlindOwner,
    equality: C61EqualityDrawn,
    functional: C62CampaignNativeFunctionalOwner,
    profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
    contexts: &C62CampaignNativeContexts,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    spill_root: &Path,
    transcript: &mut Transcript,
) -> Result<C62NativeExactProductionNbr2Certificate, String> {
    let (blind, statements) = blind.into_parts();
    let terminal = prepare_c61_native_terminal_compiler(&blind, equality, transcript)?;
    let (
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        response_binding_digest,
        root_binding_digest,
        outer_statement_digest,
    ) = functional.into_parts();
    if joint.challenge().schedule_digest != body_schedule_digest
        || bridge.functional_digest != functional.functional_digest()
    {
        return Err("C6.2 native suffix functional schedule differs".to_owned());
    }
    let response = residual.response();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.provider_roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        roots.provider_roots.source_binding_digest(),
        response.source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        bridge.correction,
    )
    .map_err(|error| error.to_string())?;
    let binding = C62ResponseCompilerBinding {
        schedule_digest: body_schedule_digest,
        response_binding_digest,
        functional_digest: functional.functional_digest(),
        nbr2_statement_digest: nbr2.digest(),
        root_binding_digest,
        compiler_correction: bridge.correction,
    };
    binding.validate().map_err(|error| error.to_string())?;
    let native = joint.prepare_nbr2_link(bridge.base_value, binding)?;

    let compiler_roots = [spill_root.join("compiler0"), spill_root.join("compiler1")];
    let link_root = spill_root.join("native-link");
    for path in compiler_roots.iter().chain(std::iter::once(&link_root)) {
        fs::create_dir(path).map_err(|error| format!("create C6.2 spill lane: {error}"))?;
    }
    let inputs = terminal.inputs();
    if inputs.relation_challenges_digest() != residual.relation().digest()
        || compiler_profile.operation_plan_digest()
            != response.provider().operation_plan().artifact_digest()
    {
        return Err("C6.2 compiler setup or relation differs from terminal owner".to_owned());
    }
    let ids = C61NativeChainId::ordered();
    let compiler = {
        let (stream0, stream1) = attempt.prover_streams_mut();
        [
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[4],
                &compiler_roots[0],
                admission,
                gpu,
                stream0,
                ids[4],
                contexts.mask_ranges[4],
            )?,
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[5],
                &compiler_roots[1],
                admission,
                gpu,
                stream1,
                ids[5],
                contexts.mask_ranges[5],
            )?,
        ]
    };
    let canonical_runtime = response
        .provider()
        .runtime()
        .canonical_runtime_values(response.provider().extraction())
        .map_err(|error| error.to_string())?;
    let arithmetic = build_c61_production_arithmetic_frame(
        terminal.ready(),
        outer_statement_digest,
        &canonical_runtime,
        inputs.functional_fold(),
    )
    .map_err(|error| error.to_string())?;
    let proof = finish_c62_native_production_blind_with_persisted_nbr2_link(
        &roots.provider_roots,
        blind,
        &nbr2,
        &terminal,
        native,
        attempt.prover_streams_array_mut(),
        backend,
        &link_root,
        roots.session_digest,
        transcript,
    )?;
    let cache_fold_target_frame =
        response.cache_target_frame().encode().map_err(|error| error.to_string())?;
    let product_coordinate_one = residual
        .relation()
        .claims()
        .product_coordinate(residual.relation().manifest(), 1)
        .map_err(|error| error.to_string())?
        .payload_bytes();
    assemble_c62_native_exact_production_nbr2_certificate(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        compiler,
        arithmetic,
        &product_coordinate_one,
        &statements,
        &cache_fold_target_frame,
        roots.provider_roots.fixed(),
        proof,
    )
}

/// Complete the inherited native/compiler proof and the resident C6.3
/// authenticated-sketch suffix under one correlation cursor.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn finish_c63_campaign_native_proof(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    mmcs: &C62GpuMmcs,
    predecessor_verifier: &C63VerifierSketchState,
    predecessor_provider: Option<Arc<C63GpuStateOwner>>,
    successor: Arc<C63GpuStateOwner>,
    public_attempt: C6ClientAttempt,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    blind: C63CampaignNativeBlindOwner,
    equality: C61EqualityDrawn,
    functional: C62CampaignNativeFunctionalOwner,
    profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
    contexts: &C62CampaignNativeContexts,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    spill_root: &Path,
    transcript: &mut Transcript,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use rand_010::SeedableRng;

    let (blind, statements) = blind.into_parts();
    let terminal = prepare_c63_terminal_compiler(&blind, equality, transcript)?;
    let (
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        response_binding_digest,
        root_binding_digest,
        outer_statement_digest,
    ) = functional.into_parts();
    if joint.challenge().schedule_digest != body_schedule_digest
        || bridge.functional_digest != functional.functional_digest()
    {
        return Err("C6.3 native suffix functional schedule differs".to_owned());
    }
    let response = residual.response();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.provider_roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        roots.provider_roots.source_binding_digest(),
        response.source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        bridge.correction,
    )
    .map_err(|error| error.to_string())?;
    let binding = C62ResponseCompilerBinding {
        schedule_digest: body_schedule_digest,
        response_binding_digest,
        functional_digest: functional.functional_digest(),
        nbr2_statement_digest: nbr2.digest(),
        root_binding_digest,
        compiler_correction: bridge.correction,
    };
    binding.validate().map_err(|error| error.to_string())?;
    let native = joint.prepare_nbr2_link(bridge.base_value, binding)?;

    let compiler_roots = [spill_root.join("compiler0"), spill_root.join("compiler1")];
    let link_root = spill_root.join("native-link");
    for path in compiler_roots.iter().chain(std::iter::once(&link_root)) {
        fs::create_dir(path).map_err(|error| format!("create C6.3 spill lane: {error}"))?;
    }
    let inputs = terminal.inputs();
    if inputs.relation_challenges_digest() != residual.relation().digest()
        || compiler_profile.operation_plan_digest()
            != response.provider().operation_plan().artifact_digest()
    {
        return Err("C6.3 compiler setup or relation differs from terminal owner".to_owned());
    }
    let ids = C61NativeChainId::ordered();
    let compiler = {
        let (stream0, stream1) = attempt.prover_streams_mut();
        [
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[4],
                &compiler_roots[0],
                admission,
                gpu,
                stream0,
                ids[4],
                contexts.mask_ranges[4],
            )?,
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[5],
                &compiler_roots[1],
                admission,
                gpu,
                stream1,
                ids[5],
                contexts.mask_ranges[5],
            )?,
        ]
    };
    let canonical_runtime = response
        .provider()
        .runtime()
        .canonical_runtime_values(response.provider().extraction())
        .map_err(|error| error.to_string())?;
    let arithmetic = build_c61_production_arithmetic_frame(
        terminal.ready(),
        outer_statement_digest,
        &canonical_runtime,
        inputs.functional_fold(),
    )
    .map_err(|error| error.to_string())?;

    let mut entropy = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|error| format!("C6.3 WHIR entropy unavailable: {error}"))?;
    let mut rng = rand_010::rngs::StdRng::from_seed(entropy);
    let profile_digest = sparse_setup.production_profile_digest()?;
    let (prepared_suffix, source_claims) = prepare_c63_resident_sketch_suffix(
        mmcs.clone(),
        h,
        public_attempt,
        setup,
        roots.provider_roots.fixed(),
        outer_statement_digest,
        profile_digest,
        roots.provider_roots.source_binding_digest(),
        predecessor_verifier,
        predecessor_provider,
        Arc::clone(&successor),
        response.cache_append_sources(),
        response.source_schedule(),
        response.paired_sources(),
        attempt.prover_streams_array_mut(),
        transcript,
        &mut rng,
    )?;
    let proof = finish_c63_production_blind_with_persisted_link(
        &roots.provider_roots,
        blind,
        &nbr2,
        source_claims,
        &terminal,
        native,
        attempt.prover_streams_array_mut(),
        backend,
        &link_root,
        roots.session_digest,
        transcript,
    )?;
    let suffix = finish_c63_resident_sketch_suffix(
        prepared_suffix,
        &proof,
        c63_campaign_mask_range(public_attempt)?,
        attempt.prover_streams_array_mut(),
        &mut rng,
    )?;
    let (sketch_public_argument, sparse_h_closure, terminal_proofs) = suffix.into_parts();
    let response_cache_fold_targets =
        response.cache_target_frame().encode().map_err(|error| error.to_string())?;
    let product_coordinate_one = residual
        .relation()
        .claims()
        .product_coordinate(residual.relation().manifest(), 1)
        .map_err(|error| error.to_string())?
        .payload_bytes();
    let (inherited, proof_envelope) = assemble_c63_exact_production_components(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        compiler,
        arithmetic,
        &product_coordinate_one,
        &response_cache_fold_targets,
        &statements,
        roots.provider_roots.fixed(),
        proof,
        &sparse_h_closure,
        terminal_proofs,
    )?;
    Ok((inherited.encoded().to_vec(), sketch_public_argument, proof_envelope))
}

/// Complete C6.4 with the inherited cache sketch and the precommitted
/// projected-residual proof. The historical residual output-link is absent.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn finish_c64_campaign_native_proof(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    mmcs: &C62GpuMmcs,
    predecessor_verifier: &C63VerifierSketchState,
    predecessor_provider: Option<Arc<C63GpuStateOwner>>,
    successor: Arc<C63GpuStateOwner>,
    public_attempt: C6ClientAttempt,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    blind: C64CampaignNativeBlindOwner,
    equality: C61EqualityDrawn,
    functional: C62CampaignNativeFunctionalOwner,
    profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
    contexts: &C62CampaignNativeContexts,
    admission: C61ProductionPersistedResourceAdmission,
    attempt: &mut C6ProductionPairedPcgAttempt,
    gpu: &C62ProductionGpuWhir,
    spill_root: &Path,
    transcript: &mut Transcript,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    use rand_010::SeedableRng;

    let (blind, statements) = blind.into_parts();
    let terminal = prepare_c64_terminal_compiler(&blind, equality, transcript)?;
    let (
        primary,
        functional,
        joint,
        bridge,
        native_profile_digest,
        body_schedule_digest,
        response_binding_digest,
        root_binding_digest,
        outer_statement_digest,
    ) = functional.into_parts();
    if joint.challenge().schedule_digest != body_schedule_digest
        || bridge.functional_digest != functional.functional_digest()
    {
        return Err("C6.4 native suffix functional schedule differs".to_owned());
    }
    let response = residual.response();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.provider_roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        roots.provider_roots.source_binding_digest(),
        response.source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        bridge.correction,
    )
    .map_err(|error| error.to_string())?;
    let binding = C62ResponseCompilerBinding {
        schedule_digest: body_schedule_digest,
        response_binding_digest,
        functional_digest: functional.functional_digest(),
        nbr2_statement_digest: nbr2.digest(),
        root_binding_digest,
        compiler_correction: bridge.correction,
    };
    binding.validate().map_err(|error| error.to_string())?;
    let native = joint.prepare_nbr2_link(bridge.base_value, binding)?;

    let compiler_roots = [spill_root.join("compiler0"), spill_root.join("compiler1")];
    for path in &compiler_roots {
        fs::create_dir(path).map_err(|error| format!("create C6.4 spill lane: {error}"))?;
    }
    let inputs = terminal.inputs();
    if inputs.relation_challenges_digest() != residual.relation().digest()
        || compiler_profile.operation_plan_digest()
            != response.provider().operation_plan().artifact_digest()
    {
        return Err("C6.4 compiler setup or relation differs from terminal owner".to_owned());
    }
    let ids = C61NativeChainId::ordered();
    let compiler = {
        let (stream0, stream1) = attempt.prover_streams_mut();
        [
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[4],
                &compiler_roots[0],
                admission,
                gpu,
                stream0,
                ids[4],
                contexts.mask_ranges[4],
            )?,
            run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
                response.provider().operation_plan(),
                compiler_profile.terminal_metadata().clone(),
                response.provider().extraction(),
                response.provider().runtime(),
                residual.relation(),
                inputs.leaf_points(),
                inputs.auxiliary_points(),
                *inputs.terminal_functionals(),
                inputs.output_beta(),
                inputs.relation_root(),
                contexts.lane_contexts[5],
                &compiler_roots[1],
                admission,
                gpu,
                stream1,
                ids[5],
                contexts.mask_ranges[5],
            )?,
        ]
    };
    let canonical_runtime = response
        .provider()
        .runtime()
        .canonical_runtime_values(response.provider().extraction())
        .map_err(|error| error.to_string())?;
    let arithmetic = build_c61_production_arithmetic_frame(
        terminal.ready(),
        outer_statement_digest,
        &canonical_runtime,
        inputs.functional_fold(),
    )
    .map_err(|error| error.to_string())?;

    let mut entropy = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|error| format!("C6.4 WHIR entropy unavailable: {error}"))?;
    let mut rng = rand_010::rngs::StdRng::from_seed(entropy);
    let profile_digest = sparse_setup.production_profile_digest()?;
    let (prepared_suffix, source_claims) = prepare_c63_resident_sketch_suffix(
        mmcs.clone(),
        h,
        public_attempt,
        setup,
        roots.provider_roots.fixed(),
        outer_statement_digest,
        profile_digest,
        roots.provider_roots.source_binding_digest(),
        predecessor_verifier,
        predecessor_provider,
        Arc::clone(&successor),
        response.cache_append_sources(),
        response.source_schedule(),
        response.paired_sources(),
        attempt.prover_streams_array_mut(),
        transcript,
        &mut rng,
    )?;
    let proof = finish_c64_production_blind_with_projected_residual(
        &roots.provider_roots,
        blind,
        &nbr2,
        source_claims,
        &terminal,
        native,
        c64_campaign_mask_range(public_attempt)?,
        attempt.prover_streams_array_mut(),
        roots.session_digest,
        transcript,
        &mut rng,
    )?;
    let suffix = finish_c64_resident_sketch_suffix(
        prepared_suffix,
        &proof,
        c63_campaign_mask_range(public_attempt)?,
        attempt.prover_streams_array_mut(),
        &mut rng,
    )?;
    let (sketch_public_argument, sparse_h_closure, cache_terminal_proofs) = suffix.into_parts();
    let response_cache_fold_targets =
        response.cache_target_frame().encode().map_err(|error| error.to_string())?;
    let product_coordinate_one = residual
        .relation()
        .claims()
        .product_coordinate(residual.relation().manifest(), 1)
        .map_err(|error| error.to_string())?
        .payload_bytes();
    let (inherited, proof_envelope) = assemble_c64_exact_production_components(
        roots.provider_roots.fixed().statement_digest(),
        native_profile_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
        profile,
        primary,
        compiler,
        arithmetic,
        &product_coordinate_one,
        &response_cache_fold_targets,
        &statements,
        proof,
        sparse_h_closure,
        cache_terminal_proofs,
    )?;
    Ok((inherited.encoded().to_vec(), sketch_public_argument, proof_envelope))
}

/// Exact native provider output after the response, four-root wrapper,
/// C6NBR2 receipt and C6PA2 assembly have all been consumed once.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C61CampaignSealedNativeOutput {
    pub certificate: C61NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
}

/// Seal the strict native certificate directly from the live residual owner
/// and receipt-gated exact assembly. No caller supplies retained bytes,
/// public-argument bytes, residual scalars, wrapper roots or source binding.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_c61_campaign_native_output(
    setup: &C6SetupManifest,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    response_statement: &C61ResponseStatementBinding,
    workload: C61PublicWorkloadPreimage,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    exact: C61NativeExactProductionNbr2Certificate,
) -> Result<C61CampaignSealedNativeOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    old_head.validate().map_err(|error| error.to_string())?;
    let setup_digest = setup.digest().map_err(|error| error.to_string())?;
    let fixed = roots.provider_roots.fixed();
    let commitments = fixed.commitments();
    if commitments.len() != 4
        || roots.verifier_roots.fixed().statement_digest() != fixed.statement_digest()
        || roots.verifier_roots.fixed().binding_digest() != fixed.binding_digest()
        || roots
            .verifier_roots
            .fixed()
            .commitments()
            .iter()
            .map(|commitment| commitment.root)
            .ne(commitments.iter().map(|commitment| commitment.root))
        || setup_digest != attempt.setup_manifest_digest
        || old_head.digest() != attempt.old_head_digest
        || workload.workload() != attempt.workload
        || response_statement.digest() == fixed.statement_digest()
    {
        return Err("C6ICT5 native seal input binding mismatch".to_owned());
    }
    let wrapper_roots: [[u8; 32]; 4] = commitments
        .iter()
        .map(|commitment| commitment.root)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "C6ICT5 native seal root census differs")?;
    if old_head.cache_root != wrapper_roots[0] || proposed_head.cache_root() != wrapper_roots[1] {
        return Err("C6ICT5 native seal cache roots differ from the transition heads".to_owned());
    }

    let public_argument_statement_digest = exact.public_argument().argument().statement_digest();
    validate_campaign_statement_domains(
        response_statement.digest(),
        fixed.statement_digest(),
        public_argument_statement_digest,
    )?;
    let public_instance = workload
        .bind_statements(response_statement.digest(), public_argument_statement_digest)
        .map_err(|error| error.to_string())?;
    let retained_response = residual.response().encoded_retained_response()?;
    let mut retained_transcript =
        Vec::with_capacity(retained_response.len() + exact.encoded_public_argument().len());
    retained_transcript.extend_from_slice(&retained_response);
    retained_transcript.extend_from_slice(exact.encoded_public_argument());
    let relation = residual.relation();
    let mut certificate = C61NativeFinalCertificate {
        version: C61_NATIVE_CERTIFICATE_VERSION,
        wrapper_queries: C61_NATIVE_WRAPPER_QUERIES,
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        setup_manifest_digest: setup_digest,
        connection_id: setup.connection_id,
        nonce: attempt.nonce,
        slot: attempt.slot,
        correlation_ranges: attempt.correlation_ranges,
        predecessor_certificate_digest: attempt.predecessor_certificate_digest,
        old_head,
        new_head: C6CacheHead {
            epoch: proposed_head.epoch(),
            cache_len: proposed_head.cache_len(),
            cache_root: proposed_head.cache_root(),
            producer_transition_digest: [0; 32],
        },
        workload: attempt.workload,
        public_output_digest: public_instance.preimage().public_output_digest(),
        wrapper: C61NativeWrapperCommitments {
            statement_digest: fixed.statement_digest(),
            residual_root: wrapper_roots[2],
            auxiliary_root: wrapper_roots[3],
            source_binding_digest: roots.provider_roots.source_binding_digest(),
        },
        residual: relation.claims().residual(),
        retained_transcript_digest: [0; 32],
        proof_envelope_digest: [0; 32],
        transition_statement_digest: [0; 32],
        retained_transcript,
        proof_envelope: exact.encoded_proof_envelope().to_vec(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let encoded = certificate.encode().map_err(|error| error.to_string())?;
    certificate = C61NativeFinalCertificate::decode(&encoded).map_err(|error| error.to_string())?;
    if !proposed_head.matches_final(certificate.new_head)
        || certificate.wrapper_roots() != wrapper_roots
        || certificate.public_argument() != exact.encoded_public_argument()
        || certificate.proof_envelope != exact.encoded_proof_envelope()
    {
        return Err("C6ICT5 native seal strict round trip differs from live owners".to_owned());
    }
    Ok(C61CampaignSealedNativeOutput { certificate, public_instance })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignSealedNativeOutput {
    pub certificate: C62NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
}

/// Seal C62NFC1 from the live C6.2 owners.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_c62_campaign_native_output(
    setup: &C6SetupManifest,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    response_statement: &C61ResponseStatementBinding,
    workload: C61PublicWorkloadPreimage,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    exact: C62NativeExactProductionNbr2Certificate,
) -> Result<C62CampaignSealedNativeOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    old_head.validate().map_err(|error| error.to_string())?;
    let setup_digest = setup.digest().map_err(|error| error.to_string())?;
    let fixed = roots.provider_roots.fixed();
    let commitments = fixed.commitments();
    if commitments.len() != 4
        || roots.verifier_roots.fixed().statement_digest() != fixed.statement_digest()
        || roots.verifier_roots.fixed().binding_digest() != fixed.binding_digest()
        || roots
            .verifier_roots
            .fixed()
            .commitments()
            .iter()
            .map(|commitment| commitment.root)
            .ne(commitments.iter().map(|commitment| commitment.root))
        || setup_digest != attempt.setup_manifest_digest
        || old_head.digest() != attempt.old_head_digest
        || workload.workload() != attempt.workload
        || response_statement.digest() == fixed.statement_digest()
    {
        return Err("C6.2 native seal input binding mismatch".to_owned());
    }
    let wrapper_roots: [[u8; 32]; 4] = commitments
        .iter()
        .map(|commitment| commitment.root)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "C6.2 native seal root census differs")?;
    if old_head.cache_root != wrapper_roots[0] || proposed_head.cache_root() != wrapper_roots[1] {
        return Err("C6.2 native seal cache roots differ from transition heads".to_owned());
    }
    let public_argument_statement_digest = exact.public_argument().argument().statement_digest();
    validate_campaign_statement_domains(
        response_statement.digest(),
        fixed.statement_digest(),
        public_argument_statement_digest,
    )?;
    let public_instance = workload
        .bind_statements(response_statement.digest(), public_argument_statement_digest)
        .map_err(|error| error.to_string())?;
    let retained_response = residual.response().encoded_c62_retained_response()?;
    let mut retained_transcript =
        Vec::with_capacity(retained_response.len() + exact.encoded_public_argument().len());
    retained_transcript.extend_from_slice(&retained_response);
    retained_transcript.extend_from_slice(exact.encoded_public_argument());
    let relation = residual.relation();
    let mut certificate = C62NativeFinalCertificate {
        version: C62_NATIVE_CERTIFICATE_VERSION,
        wrapper_queries: C62_NATIVE_WRAPPER_QUERIES,
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        setup_manifest_digest: setup_digest,
        connection_id: setup.connection_id,
        nonce: attempt.nonce,
        slot: attempt.slot,
        correlation_ranges: attempt.correlation_ranges,
        predecessor_certificate_digest: attempt.predecessor_certificate_digest,
        old_head,
        new_head: C6CacheHead {
            epoch: proposed_head.epoch(),
            cache_len: proposed_head.cache_len(),
            cache_root: proposed_head.cache_root(),
            producer_transition_digest: [0; 32],
        },
        workload: attempt.workload,
        public_output_digest: public_instance.preimage().public_output_digest(),
        wrapper: C62NativeWrapperCommitments {
            statement_digest: fixed.statement_digest(),
            residual_root: wrapper_roots[2],
            auxiliary_root: wrapper_roots[3],
            source_binding_digest: roots.provider_roots.source_binding_digest(),
        },
        residual: relation.claims().residual(),
        retained_transcript_digest: [0; 32],
        proof_envelope_digest: [0; 32],
        transition_statement_digest: [0; 32],
        retained_transcript,
        proof_envelope: exact.encoded_proof_envelope().to_vec(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let encoded = certificate.encode().map_err(|error| error.to_string())?;
    certificate = C62NativeFinalCertificate::decode(&encoded).map_err(|error| error.to_string())?;
    if !proposed_head.matches_final(certificate.new_head)
        || certificate.wrapper_roots() != wrapper_roots
        || certificate.public_argument() != exact.encoded_public_argument()
        || certificate.proof_envelope != exact.encoded_proof_envelope()
    {
        return Err("C6.2 native seal strict round trip differs from live owners".to_owned());
    }
    Ok(C62CampaignSealedNativeOutput { certificate, public_instance })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignSealedNativeOutput {
    pub certificate: C63NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
}

/// Seal the C6.3 certificate from the two live wrapper roots and the two
/// public arguments. The final state head is derived by the certificate codec.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_c63_campaign_native_output(
    setup: &C6SetupManifest,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    response_statement: &C61ResponseStatementBinding,
    workload: C61PublicWorkloadPreimage,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    inherited_public_argument: Vec<u8>,
    sketch_public_argument: Vec<u8>,
    proof_envelope: Vec<u8>,
) -> Result<C63CampaignSealedNativeOutput, String> {
    seal_c63_or_c64_campaign_native_output(
        setup,
        attempt,
        old_head,
        response_statement,
        workload,
        roots,
        residual,
        inherited_public_argument,
        sketch_public_argument,
        proof_envelope,
        C63_NATIVE_CERTIFICATE_VERSION,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_c64_campaign_native_output(
    setup: &C6SetupManifest,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    response_statement: &C61ResponseStatementBinding,
    workload: C61PublicWorkloadPreimage,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    inherited_public_argument: Vec<u8>,
    sketch_public_argument: Vec<u8>,
    proof_envelope: Vec<u8>,
) -> Result<C63CampaignSealedNativeOutput, String> {
    seal_c63_or_c64_campaign_native_output(
        setup,
        attempt,
        old_head,
        response_statement,
        workload,
        roots,
        residual,
        inherited_public_argument,
        sketch_public_argument,
        proof_envelope,
        C64_NATIVE_CERTIFICATE_VERSION,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
fn seal_c63_or_c64_campaign_native_output(
    setup: &C6SetupManifest,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    response_statement: &C61ResponseStatementBinding,
    workload: C61PublicWorkloadPreimage,
    roots: &C61CampaignLiveRoots,
    residual: &C6T1ProductionResidualBoundOwner,
    inherited_public_argument: Vec<u8>,
    sketch_public_argument: Vec<u8>,
    proof_envelope: Vec<u8>,
    version: u16,
) -> Result<C63CampaignSealedNativeOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    old_head.validate().map_err(|error| error.to_string())?;
    let setup_digest = setup.digest().map_err(|error| error.to_string())?;
    let fixed = roots.provider_roots.fixed();
    let commitments = fixed.commitments();
    if commitments.len() != 2
        || roots.verifier_roots.fixed().statement_digest() != fixed.statement_digest()
        || roots.verifier_roots.fixed().binding_digest() != fixed.binding_digest()
        || roots
            .verifier_roots
            .fixed()
            .commitments()
            .iter()
            .map(|commitment| commitment.root)
            .ne(commitments.iter().map(|commitment| commitment.root))
        || setup_digest != attempt.setup_manifest_digest
        || old_head.digest() != attempt.old_head_digest
        || workload.workload() != attempt.workload
        || response_statement.digest() == fixed.statement_digest()
    {
        return Err("C6.3 native seal input binding mismatch".to_owned());
    }
    let wrapper_roots: [[u8; 32]; 2] = commitments
        .iter()
        .map(|commitment| commitment.root)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "C6.3 native seal root census differs".to_owned())?;
    let inherited =
        C62PublicArgument::decode(&inherited_public_argument).map_err(|error| error.to_string())?;
    let public_argument_statement_digest = inherited.statement_digest();
    validate_campaign_statement_domains(
        response_statement.digest(),
        fixed.statement_digest(),
        public_argument_statement_digest,
    )?;
    let public_instance = workload
        .bind_statements(response_statement.digest(), public_argument_statement_digest)
        .map_err(|error| error.to_string())?;
    let retained_response = residual.response().encoded_c62_retained_response()?;
    let mut retained_transcript = Vec::with_capacity(
        retained_response.len() + inherited_public_argument.len() + sketch_public_argument.len(),
    );
    retained_transcript.extend_from_slice(&retained_response);
    retained_transcript.extend_from_slice(&inherited_public_argument);
    retained_transcript.extend_from_slice(&sketch_public_argument);
    let relation = residual.relation();
    let mut certificate = C63NativeFinalCertificate {
        version,
        wrapper_queries: C63_NATIVE_WRAPPER_QUERIES,
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        setup_manifest_digest: setup_digest,
        connection_id: setup.connection_id,
        nonce: attempt.nonce,
        slot: attempt.slot,
        correlation_ranges: attempt.correlation_ranges,
        predecessor_certificate_digest: attempt.predecessor_certificate_digest,
        old_head,
        new_head: C6CacheHead {
            epoch: old_head.epoch + 1,
            cache_len: attempt.workload.new_context,
            cache_root: [0; 32],
            producer_transition_digest: [0; 32],
        },
        workload: attempt.workload,
        public_output_digest: public_instance.preimage().public_output_digest(),
        wrapper: C63NativeWrapperCommitments {
            statement_digest: fixed.statement_digest(),
            residual_root: wrapper_roots[0],
            auxiliary_root: wrapper_roots[1],
            source_binding_digest: roots.provider_roots.source_binding_digest(),
        },
        residual: relation.claims().residual(),
        retained_transcript_digest: [0; 32],
        proof_envelope_digest: [0; 32],
        transition_statement_digest: [0; 32],
        retained_transcript,
        proof_envelope: proof_envelope.clone(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let encoded = certificate.encode().map_err(|error| error.to_string())?;
    certificate = C63NativeFinalCertificate::decode(&encoded).map_err(|error| error.to_string())?;
    if certificate.wrapper.residual_root != wrapper_roots[0]
        || certificate.wrapper.auxiliary_root != wrapper_roots[1]
        || certificate.inherited_public_argument() != inherited_public_argument
        || certificate.sketch_public_argument() != sketch_public_argument
        || certificate.proof_envelope != proof_envelope
    {
        return Err("C6.3 native seal strict round trip differs from live owners".to_owned());
    }
    Ok(C63CampaignSealedNativeOutput { certificate, public_instance })
}

/// Complete live provider result plus the client-private state required for
/// independent disk verification. Only `certificate` is provider wire.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C61CampaignLiveProductionOutput {
    pub certificate: C61NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub challenge_tapes: C61InteractiveTapeBundle,
}

/// Execute one exact C6.1 response from the reserved real-PCG attempt through
/// native C6PA2 sealing. Every intermediate response, residual, cache,
/// coefficient, transcript and proof owner moves along one call graph.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn run_c61_campaign_live_production(
    setup: &C6SetupManifest,
    installed: C61CampaignInstalledSetup,
    workload_owner: C6T1WorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    mut attempt: C6ProductionPairedPcgAttempt,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    run_root: &Path,
) -> Result<C61CampaignLiveProductionOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    if !run_root.is_dir()
        || fs::read_dir(run_root)
            .map_err(|error| format!("read C6ICT5 live run root: {error}"))?
            .next()
            .is_some()
    {
        return Err("C6ICT5 live run root must be an existing empty directory".to_owned());
    }
    let reservation = attempt.reservation();
    let public_attempt = C6ClientAttempt {
        slot: reservation.slot,
        nonce: reservation.nonce,
        setup_manifest_digest: reservation.setup_manifest_digest,
        old_head_digest: reservation.old_head_digest,
        predecessor_certificate_digest: reservation.predecessor_certificate_digest,
        correlation_ranges: reservation.correlation_ranges,
        workload: reservation.workload,
    };
    if reservation.connection_id != setup.connection_id
        || public_workload.workload() != public_attempt.workload
        || public_workload.public_tokens() != workload_owner.sequence()
    {
        return Err("C6ICT5 live setup/attempt/workload owners differ".to_owned());
    }
    let C61CampaignInstalledSetup {
        source_manifest: _,
        provider_plan,
        verifier_plan,
        provider_extraction,
        verifier_extraction,
        native_profile,
        compiler_profile,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        native_profile_artifact,
        plan_bytes: _,
        extraction_bytes: _,
        native_profile_bytes: _,
    } = installed;
    let response_statement = build_c61_campaign_response_statement(
        setup,
        &provider_plan,
        public_attempt,
        old_head,
        proposed_head,
        &public_workload,
    )?;
    let mut response_session =
        C61CampaignResponseTranscriptSession::start(public_attempt, &response_statement)?;
    let response = execute_c61_campaign_response_owner(
        workload_owner,
        &response_statement,
        [provider_plan, verifier_plan],
        [provider_extraction, verifier_extraction],
        &mut attempt,
        &mut response_session,
    )?;
    let replay_owner = attempt.take_verifier_replay_owner(response_statement.digest())?;
    let (native_endpoints, native_session) =
        C61CampaignNativeTranscriptSession::start(public_attempt, &native_profile)?;

    let coefficient_root = run_root.join("coefficients");
    let wrapper_root = run_root.join("wrapper");
    let proof_root = run_root.join("proof");
    for path in [&coefficient_root, &wrapper_root, &proof_root] {
        fs::create_dir(path).map_err(|error| format!("create C6ICT5 run lane: {error}"))?;
    }
    let persisted = persist_c6_t1_native_coefficient_owners(
        response,
        &coefficient_root,
        native_endpoints.four_chain.coefficient_session(),
    )?;
    let (response, model_coefficients, embedding_coefficients) = persisted.into_parts();
    let (returned_workload, response, native_claims, predecessor, successor) =
        response.into_parts();
    if returned_workload.sequence() != public_workload.public_tokens() {
        return Err("C6ICT5 persisted response workload changed".to_owned());
    }
    drop(returned_workload);
    let residual = {
        let (provider, verifier) = response_session.transcripts();
        prepare_c6_t1_production_residual_owner(response, &native_profile, provider, verifier)
            .map_err(|error| error.to_string())?
    };
    let wrapper_statement = build_c61_campaign_live_wrapper_statement(
        response_statement.clone(),
        &public_workload,
        &residual,
        &native_profile,
        &compiler_profile,
    )?;
    let rooted = bind_c61_campaign_live_residual_roots(
        setup,
        wrapper_statement,
        &public_workload,
        predecessor,
        successor,
        residual,
        backend,
        &wrapper_root,
        &mut response_session,
    )?;
    let (roots, relation) = rooted.into_parts();
    let (equality, residual) = relation.into_parts();
    let C61CampaignNativeTranscriptEndpoints { four_chain, compiler } = native_endpoints;
    let four_chain = prepare_c61_campaign_native_four_chains(
        native_claims,
        &residual,
        model_coefficients,
        embedding_coefficients,
        &native_profile,
        four_chain,
        admission,
        &mut attempt,
        backend,
        &proof_root,
    )?;
    let functional = prepare_c61_campaign_native_functional(
        &roots,
        &residual,
        &native_profile,
        &native_profile_artifact,
        four_chain,
    )?;
    let blind = {
        let (provider, _) = response_session.transcripts();
        prove_c61_campaign_native_blind(
            &roots,
            &residual,
            &public_workload,
            &mut attempt,
            provider,
        )?
    };
    let exact = {
        let (provider, _) = response_session.transcripts();
        finish_c61_campaign_native_proof(
            &roots,
            &residual,
            blind,
            equality,
            functional,
            &native_profile,
            &compiler_profile,
            compiler,
            admission,
            &mut attempt,
            backend,
            &proof_root,
            provider,
        )?
    };
    let sealed = seal_c61_campaign_native_output(
        setup,
        public_attempt,
        old_head,
        proposed_head,
        &response_statement,
        public_workload,
        &roots,
        &residual,
        exact,
    )?;
    let certificate_digest = sealed.certificate.digest().map_err(|error| error.to_string())?;
    let response_context = response_session.context_digest();
    let response_tape = response_session.finish_certificate(&sealed.certificate)?;
    let challenge_tapes = native_session.finish(
        public_attempt,
        certificate_digest,
        response_tape,
        response_context,
    )?;
    let verifier_replay = replay_owner.bind_certificate(certificate_digest)?;
    attempt.finish_success()?;
    Ok(C61CampaignLiveProductionOutput {
        certificate: sealed.certificate,
        public_instance: sealed.public_instance,
        verifier_replay,
        challenge_tapes,
    })
}

/// Complete one C6.2 provider attempt without challenge transport.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignCachePrecommitOwner {
    workload_owner: C62CampaignWorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    cache_precommit: C62PersistedNativeCachePrecommit,
    run_root: PathBuf,
}

/// Pre-response C6.3 transition intent. The provisional head is used only by
/// the inherited response statement; the final certificate derives its real
/// state head from the accepted sketch roots.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignTransitionOwner {
    workload_owner: C62CampaignWorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    old_head: C6CacheHead,
    response_head_intent: C6ProposedCacheHead,
    predecessor_provider: Option<Arc<C63GpuStateOwner>>,
    predecessor_verifier: C63VerifierSketchState,
    run_root: PathBuf,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C63CampaignTransitionOwner {
    pub fn old_head(&self) -> C6CacheHead {
        self.old_head
    }

    pub fn response_head_intent(&self) -> C6ProposedCacheHead {
        self.response_head_intent
    }

    pub fn workload(&self) -> volta_proto::C6Workload {
        self.public_workload.workload()
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn c63_campaign_genesis_head(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    state: &C63VerifierSketchState,
) -> Result<C6CacheHead, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let profile_digest = sparse_setup.production_profile_digest()?;
    if state.epoch() != 0
        || state.accepted_len() != 0
        || state.profile_digest() != profile_digest
        || state.correction_root() == [0; 32]
        || state.encoded_sketch_root() == [0; 32]
    {
        return Err("C6.3 genesis sketch state differs from setup".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.3/genesis-state-head/v1");
    hasher.update(&setup.digest().map_err(|error| error.to_string())?);
    hasher.update(&setup.connection_id);
    hasher.update(&profile_digest);
    hasher.update(&state.correction_root());
    hasher.update(&state.encoded_sketch_root());
    let head = C6CacheHead {
        epoch: 0,
        cache_len: 0,
        cache_root: *hasher.finalize().as_bytes(),
        producer_transition_digest: [0; 32],
    };
    head.validate().map_err(|error| error.to_string())?;
    Ok(head)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn c63_campaign_response_head_intent(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    old_head: C6CacheHead,
    workload: &C61PublicWorkloadPreimage,
    predecessor: &C63VerifierSketchState,
) -> Result<C6ProposedCacheHead, String> {
    setup.validate().map_err(|error| error.to_string())?;
    old_head.validate().map_err(|error| error.to_string())?;
    let profile_digest = sparse_setup.production_profile_digest()?;
    if predecessor.profile_digest() != profile_digest
        || u32::from(predecessor.accepted_len()) != old_head.cache_len
        || predecessor.epoch() != old_head.epoch
        || workload.workload().old_context != old_head.cache_len
    {
        return Err("C6.3 response intent predecessor differs".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.3/response-head-intent/v1");
    hasher.update(&setup.digest().map_err(|error| error.to_string())?);
    hasher.update(&old_head.digest());
    hasher.update(&workload.digest());
    hasher.update(&profile_digest);
    hasher.update(&predecessor.correction_root());
    hasher.update(&predecessor.encoded_sketch_root());
    let root = *hasher.finalize().as_bytes();
    C6ProposedCacheHead::successor(old_head, workload.workload(), root)
        .map_err(|error| error.to_string())
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn prepare_c63_campaign_transition_inner<W: Into<C62CampaignWorkloadOwner>>(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    workload_owner: W,
    public_workload: C61PublicWorkloadPreimage,
    predecessor_provider: Option<Arc<C63GpuStateOwner>>,
    predecessor_verifier: C63VerifierSketchState,
    expected_old_head: Option<C6CacheHead>,
    run_root: &Path,
) -> Result<C63CampaignTransitionOwner, String> {
    let workload_owner = validate_c62_campaign_cache_precommit_inputs(
        setup,
        workload_owner,
        &public_workload,
        run_root,
    )?;
    let profile_digest = sparse_setup.production_profile_digest()?;
    let old_head = match (expected_old_head, predecessor_provider.as_deref()) {
        (None, None) => c63_campaign_genesis_head(setup, sparse_setup, &predecessor_verifier)?,
        (Some(head), Some(provider))
            if provider.profile_digest() == profile_digest
                && provider.epoch() == predecessor_verifier.epoch()
                && provider.accepted_len() == predecessor_verifier.accepted_len()
                && provider.correction_root() == predecessor_verifier.correction_root()
                && provider.encoded_sketch_root() == predecessor_verifier.encoded_sketch_root() =>
        {
            head.validate().map_err(|error| error.to_string())?;
            head
        }
        _ => return Err("C6.3 provider/verifier predecessor ownership differs".to_owned()),
    };
    let response_head_intent = c63_campaign_response_head_intent(
        setup,
        sparse_setup,
        old_head,
        &public_workload,
        &predecessor_verifier,
    )?;
    Ok(C63CampaignTransitionOwner {
        workload_owner,
        public_workload,
        old_head,
        response_head_intent,
        predecessor_provider,
        predecessor_verifier,
        run_root: run_root.to_path_buf(),
    })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn prepare_c63_campaign_genesis_transition<W: Into<C62CampaignWorkloadOwner>>(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    workload_owner: W,
    public_workload: C61PublicWorkloadPreimage,
    predecessor_verifier: C63VerifierSketchState,
    run_root: &Path,
) -> Result<C63CampaignTransitionOwner, String> {
    prepare_c63_campaign_transition_inner(
        setup,
        sparse_setup,
        workload_owner,
        public_workload,
        None,
        predecessor_verifier,
        None,
        run_root,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn prepare_c63_campaign_continuation_transition(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    workload_owner: crate::c6_t1_owner::C62ContinuationWorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    predecessor_provider: Arc<C63GpuStateOwner>,
    predecessor_verifier: C63VerifierSketchState,
    old_head: C6CacheHead,
    run_root: &Path,
) -> Result<C63CampaignTransitionOwner, String> {
    prepare_c63_campaign_transition_inner(
        setup,
        sparse_setup,
        workload_owner,
        public_workload,
        Some(predecessor_provider),
        predecessor_verifier,
        Some(old_head),
        run_root,
    )
}

/// Build the proposed resident successor directly from the response-owned
/// one-time corrections. Temporary upload buffers are always released.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn propose_c63_campaign_successor_state(
    sparse_setup: &C63SparseSetupReference,
    gpu_setup: &C63GpuSetupOwner,
    mmcs: &C62GpuMmcs,
    predecessor: Option<&C63GpuStateOwner>,
    predecessor_verifier: &C63VerifierSketchState,
    residual: &C6T1ProductionResidualBoundOwner,
    workload: volta_proto::C6Workload,
) -> Result<Arc<C63GpuStateOwner>, String> {
    let old_len = u16::try_from(workload.old_context)
        .map_err(|_| "C6.3 old context exceeds u16".to_owned())?;
    let new_len = u16::try_from(workload.new_context)
        .map_err(|_| "C6.3 new context exceeds u16".to_owned())?;
    let epoch = predecessor_verifier
        .epoch()
        .checked_add(1)
        .ok_or_else(|| "C6.3 successor epoch overflows".to_owned())?;
    let profile_digest = sparse_setup.production_profile_digest()?;
    if predecessor_verifier.profile_digest() != profile_digest
        || predecessor_verifier.accepted_len() != old_len
        || predecessor.map(C63GpuStateOwner::accepted_len) != (old_len != 0).then_some(old_len)
    {
        return Err("C6.3 proposed state predecessor differs".to_owned());
    }
    let response = residual.response();
    let packed = c63_pack_resident_append_corrections(
        old_len,
        new_len,
        response.source_schedule().digest,
        response.cache_append_sources(),
        response.source_schedule(),
        response.paired_sources(),
    )?;
    let metadata = vec![
        C63GpuTileMetadata {
            birth_epoch: epoch,
            allocation_binding_digest: response.paired_sources().allocation_binding_digest(),
            source_schedule_digest: response.source_schedule().digest,
        };
        usize::from(new_len - old_len)
    ];
    let backend = mmcs.backend();
    let (tape0, tape1) = {
        let mut locked = backend.lock().map_err(|_| "C6.3 CUDA lock".to_owned())?;
        let tape0 = locked.upload_new_device(&packed[0]).map_err(|error| error.to_string())?;
        let tape1 = match locked.upload_new_device(&packed[1]) {
            Ok(value) => value,
            Err(error) => {
                let _ = locked.free_device(tape0);
                return Err(error.to_string());
            }
        };
        (tape0, tape1)
    };
    let proposed = C63GpuStateOwner::propose_append(
        gpu_setup,
        predecessor,
        profile_digest,
        epoch,
        DeviceSlice::new(&tape0, 0, tape0.len()).map_err(|error| error.to_string())?,
        DeviceSlice::new(&tape1, 0, tape1.len()).map_err(|error| error.to_string())?,
        &metadata,
    )
    .map_err(|error| error.to_string());
    let cleanup = {
        let mut locked = backend.lock().map_err(|_| "C6.3 CUDA cleanup lock".to_owned())?;
        let first = locked.free_device(tape0);
        let second = locked.free_device(tape1);
        first.and(second).map_err(|error| error.to_string())
    };
    match (proposed, cleanup) {
        (Ok(state), Ok(())) => Ok(Arc::new(state)),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
impl C62CampaignCachePrecommitOwner {
    pub fn old_head(&self) -> C6CacheHead {
        self.old_head
    }

    pub fn proposed_head(&self) -> C6ProposedCacheHead {
        self.proposed_head
    }

    pub fn workload(&self) -> volta_proto::C6Workload {
        self.public_workload.workload()
    }
}

/// Create the two real cache roots before the client reserves the attempt.
///
/// The roots come from the same workload allocation that the response will
/// later consume.  This removes the circular proposed-root input.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn validate_c62_campaign_cache_precommit_inputs<W: Into<C62CampaignWorkloadOwner>>(
    setup: &C6SetupManifest,
    workload_owner: W,
    public_workload: &C61PublicWorkloadPreimage,
    run_root: &Path,
) -> Result<C62CampaignWorkloadOwner, String> {
    let workload_owner = workload_owner.into();
    let workload = public_workload.workload();
    if !run_root.is_dir() {
        return Err("C6.2 cache precommit run root is not a directory".to_owned());
    }
    if fs::read_dir(run_root)
        .map_err(|error| format!("read C6.2 precommit run root: {error}"))?
        .next()
        .is_some()
    {
        return Err("C6.2 cache precommit run root is not empty".to_owned());
    }
    if public_workload.model_family_digest() != setup.model_digest {
        return Err("C6.2 cache precommit model digest mismatch".to_owned());
    }
    if public_workload.public_tokens() != workload_owner.sequence() {
        return Err("C6.2 cache precommit public token sequence mismatch".to_owned());
    }
    if workload.decode_tokens != 50 {
        return Err("C6.2 cache precommit decode count mismatch".to_owned());
    }
    if workload.old_context as usize != workload_owner.old_context() {
        return Err("C6.2 cache precommit old context mismatch".to_owned());
    }
    if c62_cache_precommit_expected_new_context(workload) != Some(workload.new_context) {
        return Err("C6.2 cache precommit new context mismatch".to_owned());
    }
    if workload.old_context == 0 && workload.prompt_tokens != 100 {
        return Err("C6.2 cache precommit genesis prompt count mismatch".to_owned());
    }
    if workload.old_context != 0 && workload.prompt_tokens != 0 {
        return Err("C6.2 cache precommit continuation prompt count mismatch".to_owned());
    }
    Ok(workload_owner)
}

fn c62_cache_precommit_expected_new_context(workload: volta_proto::C6Workload) -> Option<u32> {
    if workload.old_context == 0 {
        workload.prompt_tokens.checked_add(workload.decode_tokens)
    } else {
        workload.old_context.checked_add(workload.decode_tokens)
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn prepare_c62_campaign_cache_precommit_inner(
    setup: &C6SetupManifest,
    workload_owner: C62CampaignWorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    expected_old_head: Option<C6CacheHead>,
    backend: &mut Backend,
    run_root: &Path,
) -> Result<C62CampaignCachePrecommitOwner, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let workload_owner = validate_c62_campaign_cache_precommit_inputs(
        setup,
        workload_owner,
        &public_workload,
        run_root,
    )?;
    let workload = public_workload.workload();
    let wrapper_root = run_root.join("wrapper");
    fs::create_dir(&wrapper_root)
        .map_err(|error| format!("create C6.2 precommit wrapper lane: {error}"))?;
    let (predecessor, successor) = materialize_c62_t1_cache_states(&workload_owner)?;
    let cache_profile = C6PersistentCacheStaticProfile {
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        wrapper_profile_digest: c6_wrapper_profile_digest(),
    };
    let cache_precommit = precommit_production_c62_native_cache_roots_cuda(
        &cache_profile,
        predecessor,
        successor,
        u16::try_from(workload.old_context)
            .map_err(|_| "C6.2 precommit old context exceeds u16".to_owned())?,
        u16::try_from(workload.new_context)
            .map_err(|_| "C6.2 precommit new context exceeds u16".to_owned())?,
        backend,
        &wrapper_root,
    )
    .map_err(|error| error.to_string())?;
    let [predecessor_root, successor_root] = cache_precommit.roots();
    if predecessor_root == successor_root {
        return Err("C6.2 predecessor and successor cache roots are equal".to_owned());
    }
    let old_head = match expected_old_head {
        None => C6CacheHead {
            epoch: 0,
            cache_len: 0,
            cache_root: predecessor_root,
            producer_transition_digest: [0; 32],
        },
        Some(old_head) => {
            if old_head.cache_len != workload.old_context
                || old_head.cache_root != predecessor_root
                || old_head.epoch == 0
                || old_head.producer_transition_digest == [0; 32]
            {
                return Err("C6.2 continuation predecessor head differs from its cache".to_owned());
            }
            old_head
        }
    };
    old_head.validate().map_err(|error| error.to_string())?;
    let proposed_head = C6ProposedCacheHead::successor(old_head, workload, successor_root)
        .map_err(|error| error.to_string())?;
    Ok(C62CampaignCachePrecommitOwner {
        workload_owner,
        public_workload,
        old_head,
        proposed_head,
        cache_precommit,
        run_root: run_root.to_path_buf(),
    })
}

pub fn prepare_c62_campaign_cache_precommit<W: Into<C62CampaignWorkloadOwner>>(
    setup: &C6SetupManifest,
    workload_owner: W,
    public_workload: C61PublicWorkloadPreimage,
    backend: &mut Backend,
    run_root: &Path,
) -> Result<C62CampaignCachePrecommitOwner, String> {
    prepare_c62_campaign_cache_precommit_inner(
        setup,
        workload_owner.into(),
        public_workload,
        None,
        backend,
        run_root,
    )
}

pub fn prepare_c62_campaign_continuation_cache_precommit(
    setup: &C6SetupManifest,
    workload_owner: crate::c6_t1_owner::C62ContinuationWorkloadOwner,
    public_workload: C61PublicWorkloadPreimage,
    old_head: C6CacheHead,
    backend: &mut Backend,
    run_root: &Path,
) -> Result<C62CampaignCachePrecommitOwner, String> {
    prepare_c62_campaign_cache_precommit_inner(
        setup,
        workload_owner.into(),
        public_workload,
        Some(old_head),
        backend,
        run_root,
    )
}

/// Complete one C6.2 provider attempt without challenge transport.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignLiveProductionOutput {
    pub certificate: C62NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub response_context_digest: [u8; 32],
    pub native_public_context_digest: [u8; 32],
    pub connections: [ProductionFaseDConnection; 2],
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn run_c62_campaign_live_production(
    setup: &C6SetupManifest,
    installed: C61CampaignInstalledSetup,
    precommit: C62CampaignCachePrecommitOwner,
    mut attempt: C6ProductionPairedPcgAttempt,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
) -> Result<C62CampaignLiveProductionOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let C62CampaignCachePrecommitOwner {
        workload_owner,
        public_workload,
        old_head,
        proposed_head,
        cache_precommit,
        run_root,
    } = precommit;
    let reservation = attempt.reservation();
    let public_attempt = C6ClientAttempt {
        slot: reservation.slot,
        nonce: reservation.nonce,
        setup_manifest_digest: reservation.setup_manifest_digest,
        old_head_digest: reservation.old_head_digest,
        predecessor_certificate_digest: reservation.predecessor_certificate_digest,
        correlation_ranges: reservation.correlation_ranges,
        workload: reservation.workload,
    };
    if reservation.connection_id != setup.connection_id
        || reservation.old_head_digest != old_head.digest()
        || public_workload.workload() != public_attempt.workload
        || public_workload.public_tokens() != workload_owner.sequence()
    {
        return Err("C6.2 live setup, attempt, or workload owners differ".to_owned());
    }
    let wrapper_root = run_root.join("wrapper");
    let run_entries = fs::read_dir(&run_root)
        .map_err(|error| format!("read C6.2 live run root: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read C6.2 live run entry: {error}"))?;
    if run_entries.len() != 1 || run_entries[0].file_name() != "wrapper" || !wrapper_root.is_dir() {
        return Err("C6.2 live run root differs from the cache precommit".to_owned());
    }
    let C61CampaignInstalledSetup {
        source_manifest: _,
        provider_plan,
        verifier_plan,
        provider_extraction,
        verifier_extraction,
        native_profile,
        compiler_profile,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        native_profile_artifact,
        plan_bytes: _,
        extraction_bytes: _,
        native_profile_bytes: _,
    } = installed;
    let response_statement = build_c62_campaign_response_statement(
        setup,
        &provider_plan,
        public_attempt,
        old_head,
        proposed_head,
        &public_workload,
    )?;
    let mut response_session =
        C62CampaignResponseTranscriptSession::start(public_attempt, &response_statement)?;
    let response_context_digest = response_session.context_digest();
    let response = execute_c62_campaign_response_owner(
        workload_owner,
        &response_statement,
        [provider_plan, verifier_plan],
        [provider_extraction, verifier_extraction],
        &mut attempt,
        &mut response_session,
    )?;
    let replay_owner = attempt.take_verifier_replay_owner(response_statement.digest())?;
    let native_bindings = C62CampaignNativeBindings::start(public_attempt)?;

    let proof_root = run_root.join("proof");
    fs::create_dir(&proof_root).map_err(|error| format!("create C6.2 proof lane: {error}"))?;
    let (returned_workload, response, native_claims) = response.into_parts();
    if returned_workload.sequence() != public_workload.public_tokens() {
        return Err("C6.2 persisted response workload changed".to_owned());
    }
    drop(returned_workload);
    let residual = {
        let (provider, verifier) = response_session.transcripts();
        prepare_c6_t1_production_residual_owner(response, &native_profile, provider, verifier)
            .map_err(|error| error.to_string())?
    };
    // Fail before wrapper spill if the installed target map does not link the
    // live response plaintexts to the independent second MAC coordinate.
    drop(native_claims.production_paired_targets(&native_profile, residual.native_targets())?);
    let wrapper_statement = build_c62_campaign_live_wrapper_statement(
        response_statement.clone(),
        &public_workload,
        &residual,
        &native_profile,
        &compiler_profile,
    )?;
    let wrapper_statement_digest = wrapper_statement.digest();
    let rooted = bind_c62_campaign_live_residual_roots(
        setup,
        wrapper_statement,
        &public_workload,
        cache_precommit,
        residual,
        backend,
        &wrapper_root,
        &mut response_session,
    )?;
    response_session.verify_synchronized()?;
    let (roots, relation) = rooted.into_parts();
    let (equality, residual) = relation.into_parts();
    let contexts = native_bindings.bind_public_context(
        public_attempt,
        &native_profile,
        &compiler_profile,
        response_statement.digest(),
        wrapper_statement_digest,
        residual.relation().digest(),
        proposed_head.digest(),
        roots.provider_roots.source_binding_digest(),
    )?;
    let native_public_context_digest = contexts.public_context_digest;
    let four_chain = prepare_c62_campaign_native_four_chains(
        native_claims,
        &residual,
        model_coefficients,
        embedding_coefficients,
        &native_profile,
        &contexts,
        admission,
        &mut attempt,
        backend,
        gpu,
        &proof_root,
    )?;
    let functional = prepare_c62_campaign_native_functional(
        &roots,
        &residual,
        &native_profile,
        &native_profile_artifact,
        response_statement.digest(),
        four_chain,
    )?;
    let blind = {
        let (provider, _) = response_session.transcripts();
        prove_c61_campaign_native_blind(
            &roots,
            &residual,
            &public_workload,
            &mut attempt,
            provider,
        )?
    };
    let exact = {
        let (provider, _) = response_session.transcripts();
        finish_c62_campaign_native_proof(
            &roots,
            &residual,
            blind,
            equality,
            functional,
            &native_profile,
            &compiler_profile,
            &contexts,
            admission,
            &mut attempt,
            backend,
            gpu,
            &proof_root,
            provider,
        )?
    };
    let sealed = seal_c62_campaign_native_output(
        setup,
        public_attempt,
        old_head,
        proposed_head,
        &response_statement,
        public_workload,
        &roots,
        &residual,
        exact,
    )?;
    let certificate_digest = sealed.certificate.digest().map_err(|error| error.to_string())?;
    let verifier_replay = replay_owner.bind_certificate(certificate_digest)?;
    let connections = attempt.finish_success()?;
    Ok(C62CampaignLiveProductionOutput {
        certificate: sealed.certificate,
        public_instance: sealed.public_instance,
        verifier_replay,
        response_context_digest,
        native_public_context_digest,
        connections,
    })
}

/// Complete one C6.3 provider transition and retain only the proposed GPU
/// successor. Promotion remains a client action after CPU verification.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignLiveProductionOutput {
    pub certificate: C63NativeFinalCertificate,
    pub public_instance: C61PublicWorkloadInstance,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub response_context_digest: [u8; 32],
    pub native_public_context_digest: [u8; 32],
    pub connections: [ProductionFaseDConnection; 2],
    pub successor_provider: Arc<C63GpuStateOwner>,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub type C64CampaignLiveProductionOutput = C63CampaignLiveProductionOutput;

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
enum C63OrC64CampaignBlindOwner {
    C63(C63CampaignNativeBlindOwner),
    C64(C64CampaignNativeBlindOwner),
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn run_c63_campaign_live_production(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    installed: C61CampaignInstalledSetup,
    transition: C63CampaignTransitionOwner,
    attempt: C6ProductionPairedPcgAttempt,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    mmcs: &C62GpuMmcs,
    gpu_setup: &C63GpuSetupOwner,
) -> Result<C63CampaignLiveProductionOutput, String> {
    run_c63_or_c64_campaign_live_production(
        setup,
        sparse_setup,
        h,
        installed,
        transition,
        attempt,
        model_coefficients,
        embedding_coefficients,
        admission,
        backend,
        gpu,
        mmcs,
        gpu_setup,
        false,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn run_c64_campaign_live_production(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    installed: C61CampaignInstalledSetup,
    transition: C63CampaignTransitionOwner,
    attempt: C6ProductionPairedPcgAttempt,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    mmcs: &C62GpuMmcs,
    gpu_setup: &C63GpuSetupOwner,
) -> Result<C64CampaignLiveProductionOutput, String> {
    run_c63_or_c64_campaign_live_production(
        setup,
        sparse_setup,
        h,
        installed,
        transition,
        attempt,
        model_coefficients,
        embedding_coefficients,
        admission,
        backend,
        gpu,
        mmcs,
        gpu_setup,
        true,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
fn run_c63_or_c64_campaign_live_production(
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    installed: C61CampaignInstalledSetup,
    transition: C63CampaignTransitionOwner,
    mut attempt: C6ProductionPairedPcgAttempt,
    model_coefficients: C61ProductionCoefficientOwner,
    embedding_coefficients: C61ProductionCoefficientOwner,
    admission: C61ProductionPersistedResourceAdmission,
    backend: &mut Backend,
    gpu: &C62ProductionGpuWhir,
    mmcs: &C62GpuMmcs,
    gpu_setup: &C63GpuSetupOwner,
    c64: bool,
) -> Result<C63CampaignLiveProductionOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let C63CampaignTransitionOwner {
        workload_owner,
        public_workload,
        old_head,
        response_head_intent,
        predecessor_provider,
        predecessor_verifier,
        run_root,
    } = transition;
    let reservation = attempt.reservation();
    let public_attempt = C6ClientAttempt {
        slot: reservation.slot,
        nonce: reservation.nonce,
        setup_manifest_digest: reservation.setup_manifest_digest,
        old_head_digest: reservation.old_head_digest,
        predecessor_certificate_digest: reservation.predecessor_certificate_digest,
        correlation_ranges: reservation.correlation_ranges,
        workload: reservation.workload,
    };
    if reservation.connection_id != setup.connection_id
        || reservation.old_head_digest != old_head.digest()
        || public_workload.workload() != public_attempt.workload
        || public_workload.public_tokens() != workload_owner.sequence()
    {
        return Err("C6.3 live setup, attempt, or workload owners differ".to_owned());
    }
    if !run_root.is_dir()
        || fs::read_dir(&run_root)
            .map_err(|error| format!("read C6.3 live run root: {error}"))?
            .next()
            .is_some()
    {
        return Err("C6.3 live run root must be an existing empty directory".to_owned());
    }
    let wrapper_root = run_root.join("wrapper");
    let proof_root = run_root.join("proof");
    fs::create_dir(&wrapper_root).map_err(|error| format!("create C6.3 wrapper lane: {error}"))?;
    fs::create_dir(&proof_root).map_err(|error| format!("create C6.3 proof lane: {error}"))?;
    let C61CampaignInstalledSetup {
        source_manifest: _,
        provider_plan,
        verifier_plan,
        provider_extraction,
        verifier_extraction,
        native_profile,
        compiler_profile,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        native_profile_artifact,
        plan_bytes: _,
        extraction_bytes: _,
        native_profile_bytes: _,
    } = installed;
    let response_statement = build_c62_campaign_response_statement(
        setup,
        &provider_plan,
        public_attempt,
        old_head,
        response_head_intent,
        &public_workload,
    )?;
    let mut response_session =
        C62CampaignResponseTranscriptSession::start(public_attempt, &response_statement)?;
    let response_context_digest = response_session.context_digest();
    let response = execute_c62_campaign_response_owner(
        workload_owner,
        &response_statement,
        [provider_plan, verifier_plan],
        [provider_extraction, verifier_extraction],
        &mut attempt,
        &mut response_session,
    )?;
    let replay_owner = attempt.take_verifier_replay_owner(response_statement.digest())?;
    let native_bindings = C62CampaignNativeBindings::start(public_attempt)?;
    let (returned_workload, response, native_claims) = response.into_parts();
    if returned_workload.sequence() != public_workload.public_tokens() {
        return Err("C6.3 persisted response workload changed".to_owned());
    }
    drop(returned_workload);
    let residual = {
        let (provider, verifier) = response_session.transcripts();
        prepare_c6_t1_production_residual_owner(response, &native_profile, provider, verifier)
            .map_err(|error| error.to_string())?
    };
    drop(native_claims.production_paired_targets(&native_profile, residual.native_targets())?);
    let wrapper_statement = build_c62_campaign_live_wrapper_statement(
        response_statement.clone(),
        &public_workload,
        &residual,
        &native_profile,
        &compiler_profile,
    )?;
    let wrapper_statement_digest = wrapper_statement.digest();
    let rooted = bind_c63_campaign_live_residual_roots(
        setup,
        wrapper_statement,
        &public_workload,
        residual,
        backend,
        &wrapper_root,
        &mut response_session,
    )?;
    response_session.verify_synchronized()?;
    let (roots, relation) = rooted.into_parts();
    let (equality, residual) = relation.into_parts();
    let contexts = native_bindings.bind_public_context(
        public_attempt,
        &native_profile,
        &compiler_profile,
        response_statement.digest(),
        wrapper_statement_digest,
        residual.relation().digest(),
        response_head_intent.digest(),
        roots.provider_roots.source_binding_digest(),
    )?;
    let native_public_context_digest = contexts.public_context_digest;
    let four_chain = prepare_c62_campaign_native_four_chains(
        native_claims,
        &residual,
        model_coefficients,
        embedding_coefficients,
        &native_profile,
        &contexts,
        admission,
        &mut attempt,
        backend,
        gpu,
        &proof_root,
    )?;
    let functional = prepare_c62_campaign_native_functional(
        &roots,
        &residual,
        &native_profile,
        &native_profile_artifact,
        response_statement.digest(),
        four_chain,
    )?;
    let blind = {
        let (provider, _) = response_session.transcripts();
        if c64 {
            C63OrC64CampaignBlindOwner::C64(prove_c64_campaign_native_blind(
                &roots,
                &residual,
                &functional,
                mmcs,
                &mut attempt,
                provider,
            )?)
        } else {
            C63OrC64CampaignBlindOwner::C63(prove_c63_campaign_native_blind(
                &roots,
                &residual,
                &mut attempt,
                provider,
            )?)
        }
    };
    let successor_provider = propose_c63_campaign_successor_state(
        sparse_setup,
        gpu_setup,
        mmcs,
        predecessor_provider.as_deref(),
        &predecessor_verifier,
        &residual,
        public_attempt.workload,
    )?;
    let (inherited_public_argument, sketch_public_argument, proof_envelope) = {
        let (provider, _) = response_session.transcripts();
        match blind {
            C63OrC64CampaignBlindOwner::C63(blind) => finish_c63_campaign_native_proof(
                setup,
                sparse_setup,
                h,
                mmcs,
                &predecessor_verifier,
                predecessor_provider,
                Arc::clone(&successor_provider),
                public_attempt,
                &roots,
                &residual,
                blind,
                equality,
                functional,
                &native_profile,
                &compiler_profile,
                &contexts,
                admission,
                &mut attempt,
                backend,
                gpu,
                &proof_root,
                provider,
            )?,
            C63OrC64CampaignBlindOwner::C64(blind) => finish_c64_campaign_native_proof(
                setup,
                sparse_setup,
                h,
                mmcs,
                &predecessor_verifier,
                predecessor_provider,
                Arc::clone(&successor_provider),
                public_attempt,
                &roots,
                &residual,
                blind,
                equality,
                functional,
                &native_profile,
                &compiler_profile,
                &contexts,
                admission,
                &mut attempt,
                gpu,
                &proof_root,
                provider,
            )?,
        }
    };
    let seal = if c64 { seal_c64_campaign_native_output } else { seal_c63_campaign_native_output };
    let sealed = seal(
        setup,
        public_attempt,
        old_head,
        &response_statement,
        public_workload,
        &roots,
        &residual,
        inherited_public_argument,
        sketch_public_argument,
        proof_envelope,
    )?;
    let certificate_digest = sealed.certificate.digest().map_err(|error| error.to_string())?;
    let verifier_replay = replay_owner.bind_certificate(certificate_digest)?;
    let connections = attempt.finish_success()?;
    Ok(C63CampaignLiveProductionOutput {
        certificate: sealed.certificate,
        public_instance: sealed.public_instance,
        verifier_replay,
        response_context_digest,
        native_public_context_digest,
        connections,
        successor_provider,
    })
}

/// Commit the four exact wrapper cohorts, install the same roots on the live
/// verifier and consume the production residual owner through coordinate 1.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn bind_c61_campaign_live_residual_roots(
    setup: &C6SetupManifest,
    statement: C61StatementBinding,
    workload: &C61PublicWorkloadPreimage,
    predecessor: C6PersistentCacheStateWitness,
    successor: C6PersistentCacheStateWitness,
    residual: C6T1ProductionResidualOwner,
    backend: &mut Backend,
    spill_root: &Path,
    response_session: &mut C61CampaignResponseTranscriptSession,
) -> Result<C61CampaignLiveResidualRooted, String> {
    setup.validate().map_err(|error| error.to_string())?;
    if statement.public_output_digest() != workload.public_output_digest() {
        return Err("C6ICT4 rooted residual workload differs from wrapper base".to_owned());
    }
    let cache_profile = C6PersistentCacheStaticProfile {
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        wrapper_profile_digest: c6_wrapper_profile_digest(),
    };
    cache_profile.validate().map_err(|error| error.to_string())?;
    let old_len = u16::try_from(workload.workload().old_context)
        .map_err(|_| "C6ICT4 old cache length exceeds u16")?;
    let new_len = u16::try_from(workload.workload().new_context)
        .map_err(|_| "C6ICT4 new cache length exceeds u16")?;
    let sources = C61NativeLiveWrapperSources::production(
        statement.digest(),
        &cache_profile,
        predecessor,
        successor,
        old_len,
        new_len,
        residual.manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
    )
    .map_err(|error| error.to_string())?;
    let mask_seed = C6LiveWrapperMaskSeed::random();
    let mut session_hasher =
        blake3::Hasher::new_derive_key("volta-zk/c61/campaign-wrapper-session/v1");
    session_hasher.update(&statement.response_statement_digest());
    session_hasher.update(&statement.digest());
    session_hasher.update(&mask_seed.commitment());
    let session_digest = *session_hasher.finalize().as_bytes();
    let (provider_transcript, verifier_transcript) = response_session.transcripts();
    let provider_roots = materialize_production_c61_native_live_wrapper_roots_cuda(
        sources,
        mask_seed,
        backend,
        spill_root,
        session_digest,
        provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let root_values: Vec<[u8; 32]> =
        provider_roots.fixed().commitments().iter().map(|item| item.root).collect();
    let roots: [[u8; 32]; 4] =
        root_values.try_into().map_err(|_| "C6ICT4 persisted wrapper root census differs")?;
    let verifier_roots = install_production_c61_native_live_wrapper_roots_verifier(
        statement.digest(),
        &cache_profile,
        roots,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    let root = provider_roots
        .bind_residual_relation(
            residual.manifest().clone(),
            residual.leaf(),
            residual.closure(),
            residual.auxiliary(),
        )
        .map_err(|error| error.to_string())?;
    let relation = volta_pcs::bind_c61_production_residual_relation(
        statement,
        residual,
        root,
        provider_transcript,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok(C61CampaignLiveResidualRooted { provider_roots, verifier_roots, relation, session_digest })
}

/// Commit and install the four wrapper roots under paired C6.2
/// Fiat--Shamir transcripts.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn bind_c62_campaign_live_residual_roots(
    setup: &C6SetupManifest,
    statement: C61StatementBinding,
    workload: &C61PublicWorkloadPreimage,
    cache_precommit: C62PersistedNativeCachePrecommit,
    residual: C6T1ProductionResidualOwner,
    backend: &mut Backend,
    spill_root: &Path,
    response_session: &mut C62CampaignResponseTranscriptSession,
) -> Result<C61CampaignLiveResidualRooted, String> {
    setup.validate().map_err(|error| error.to_string())?;
    if statement.public_output_digest() != workload.public_output_digest() {
        return Err("C6.2 rooted residual workload differs from wrapper base".to_owned());
    }
    let cache_profile = C6PersistentCacheStaticProfile {
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        wrapper_profile_digest: c6_wrapper_profile_digest(),
    };
    cache_profile.validate().map_err(|error| error.to_string())?;
    let mut session_hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.2/campaign-wrapper-session/v1");
    session_hasher.update(&statement.response_statement_digest());
    session_hasher.update(&statement.digest());
    session_hasher.update(&cache_precommit.mask_seed_commitment());
    let session_digest = *session_hasher.finalize().as_bytes();
    let (provider_transcript, verifier_transcript) = response_session.transcripts();
    let provider_roots = finish_production_c62_native_live_wrapper_roots_cuda(
        cache_precommit,
        statement.digest(),
        residual.manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
        backend,
        spill_root,
        session_digest,
        provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let root_values: Vec<[u8; 32]> =
        provider_roots.fixed().commitments().iter().map(|item| item.root).collect();
    let roots: [[u8; 32]; 4] =
        root_values.try_into().map_err(|_| "C6.2 persisted wrapper root census differs")?;
    let verifier_roots = install_production_c61_native_live_wrapper_roots_verifier(
        statement.digest(),
        &cache_profile,
        roots,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    let root = provider_roots
        .bind_residual_relation(
            residual.manifest().clone(),
            residual.leaf(),
            residual.closure(),
            residual.auxiliary(),
        )
        .map_err(|error| error.to_string())?;
    let relation = volta_pcs::bind_c61_production_residual_relation(
        statement,
        residual,
        root,
        provider_transcript,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok(C61CampaignLiveResidualRooted { provider_roots, verifier_roots, relation, session_digest })
}

/// Commit and install only the residual and auxiliary wrapper cohorts. The
/// predecessor and successor cache roots live in the authenticated sketch.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn bind_c63_campaign_live_residual_roots(
    setup: &C6SetupManifest,
    statement: C61StatementBinding,
    workload: &C61PublicWorkloadPreimage,
    residual: C6T1ProductionResidualOwner,
    backend: &mut Backend,
    spill_root: &Path,
    response_session: &mut C62CampaignResponseTranscriptSession,
) -> Result<C61CampaignLiveResidualRooted, String> {
    setup.validate().map_err(|error| error.to_string())?;
    if statement.public_output_digest() != workload.public_output_digest() {
        return Err("C6.3 rooted residual workload differs from wrapper base".to_owned());
    }
    let mask_seed = C6LiveWrapperMaskSeed::random();
    let mut session_hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.3/campaign-wrapper-session/v1");
    session_hasher.update(&statement.response_statement_digest());
    session_hasher.update(&statement.digest());
    session_hasher.update(&mask_seed.commitment());
    let session_digest = *session_hasher.finalize().as_bytes();
    let (provider_transcript, verifier_transcript) = response_session.transcripts();
    let provider_roots = materialize_production_c63_authenticated_sketch_live_wrapper_roots_cuda(
        statement.digest(),
        residual.manifest(),
        residual.leaf(),
        residual.closure(),
        residual.auxiliary(),
        mask_seed,
        backend,
        spill_root,
        session_digest,
        provider_transcript,
    )
    .map_err(|error| error.to_string())?;
    let roots: [[u8; 32]; 2] = provider_roots
        .fixed()
        .commitments()
        .iter()
        .map(|item| item.root)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "C6.3 persisted wrapper root census differs".to_owned())?;
    let verifier_roots = install_production_c63_authenticated_sketch_live_wrapper_roots_verifier(
        statement.digest(),
        roots,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    let root = provider_roots
        .bind_residual_relation(
            residual.manifest().clone(),
            residual.leaf(),
            residual.closure(),
            residual.auxiliary(),
        )
        .map_err(|error| error.to_string())?;
    let relation = volta_pcs::bind_c61_production_residual_relation(
        statement,
        residual,
        root,
        provider_transcript,
        verifier_transcript,
    )
    .map_err(|error| error.to_string())?;
    Ok(C61CampaignLiveResidualRooted { provider_roots, verifier_roots, relation, session_digest })
}

/// Response-verifier state reconstructed only from decoded campaign inputs.
/// The live contexts and transcript continue into the global blind verifier;
/// final tape sealing occurs only after the complete certificate is checked.
#[cfg(feature = "c6-trace")]
pub struct C61CampaignResponseVerifierReplay {
    response: C6T1ProductionResponseVerifierReplay,
    contexts: [VerifierCtx; 2],
    transcript: Transcript,
}

#[cfg(feature = "c6-trace")]
impl C61CampaignResponseVerifierReplay {
    pub fn response(&self) -> &C6T1ProductionResponseVerifierReplay {
        &self.response
    }

    pub fn contexts_and_transcript(&mut self) -> (&mut [VerifierCtx; 2], &mut Transcript) {
        (&mut self.contexts, &mut self.transcript)
    }

    pub fn into_parts(
        self,
    ) -> (C6T1ProductionResponseVerifierReplay, [VerifierCtx; 2], Transcript) {
        (self.response, self.contexts, self.transcript)
    }
}

/// Replay the exact response prefix without retained provider state. The
/// caller moves the one installed verifier plan/extraction out of the loaded
/// campaign artifact; no setup-sized clone or witness reconstruction occurs.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn replay_c61_campaign_response_verifier(
    certificate: &C61NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    challenge_tapes: &C61InteractiveTapeBundle,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    expected_source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
) -> Result<C61CampaignResponseVerifierReplay, String> {
    let inner = certificate;
    let certificate_digest = inner.digest().map_err(|error| error.to_string())?;
    let attempt = C6ClientAttempt {
        slot: inner.slot,
        nonce: inner.nonce,
        setup_manifest_digest: inner.setup_manifest_digest,
        old_head_digest: inner.old_head.digest(),
        predecessor_certificate_digest: inner.predecessor_certificate_digest,
        correlation_ranges: inner.correlation_ranges,
        workload: inner.workload,
    };
    challenge_tapes.validate_attempt(attempt, certificate_digest)?;
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || public_instance.public_tokens().len() != 150
    {
        return Err("C6ICT3 disk response binding/profile mismatch".to_owned());
    }
    let context_digest = c61_response_transcript_context_digest(
        attempt,
        public_instance.response_statement_digest(),
    )?;
    let mut transcript = challenge_tapes.response_tape().replay_transcript(0, context_digest)?;
    let retained = C6RetainedResponseProof::decode(certificate.retained_response())
        .map_err(|error| error.to_string())?;
    let mut contexts = verifier_replay.fresh_contexts(certificate_digest)?;
    let response = replay_c6_t1_production_response_verifier(
        verifier_model,
        public_instance.public_tokens(),
        public_instance.response_statement_digest(),
        verifier_plan,
        verifier_extraction,
        certificate.decoded_proof_envelope().cache_fold_targets(),
        &retained,
        &mut contexts,
        &mut transcript,
    )?;
    if response.source_manifest() != expected_source_manifest {
        return Err("C6ICT3 disk response source manifest differs from setup".to_owned());
    }
    Ok(C61CampaignResponseVerifierReplay { response, contexts, transcript })
}

/// Replay the C6.2 response with a restored public Fiat--Shamir state.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn replay_c62_campaign_response_verifier(
    certificate: &C62NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    expected_source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
) -> Result<C61CampaignResponseVerifierReplay, String> {
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let attempt = C6ClientAttempt {
        slot: certificate.slot,
        nonce: certificate.nonce,
        setup_manifest_digest: certificate.setup_manifest_digest,
        old_head_digest: certificate.old_head.digest(),
        predecessor_certificate_digest: certificate.predecessor_certificate_digest,
        correlation_ranges: certificate.correlation_ranges,
        workload: certificate.workload,
    };
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || public_instance.public_tokens().len()
            != usize::try_from(public_instance.workload().new_context).expect("u32 fits usize")
    {
        return Err("C6.2 disk response binding or profile mismatch".to_owned());
    }
    let context_digest = c62_campaign_response_transcript_context_digest(
        attempt,
        public_instance.response_statement_digest(),
    )?;
    let mut transcript = Transcript::new_fiat_shamir(context_digest)?;
    let retained = C6RetainedResponseProof::decode_c62(certificate.retained_response())
        .map_err(|error| error.to_string())?;
    let mut contexts = verifier_replay.fresh_contexts(certificate_digest)?;
    let response = if public_instance.workload().old_context == 0 {
        replay_c6_t1_production_response_verifier(
            verifier_model,
            public_instance.public_tokens(),
            public_instance.response_statement_digest(),
            verifier_plan,
            verifier_extraction,
            certificate.decoded_proof_envelope().cache_fold_targets(),
            &retained,
            &mut contexts,
            &mut transcript,
        )?
    } else {
        replay_c62_continuation_production_response_verifier(
            verifier_model,
            public_instance.public_tokens(),
            usize::try_from(public_instance.workload().old_context).expect("u32 fits usize"),
            public_instance.response_statement_digest(),
            verifier_plan,
            verifier_extraction,
            certificate.decoded_proof_envelope().cache_fold_targets(),
            &retained,
            &mut contexts,
            &mut transcript,
        )?
    };
    if response.source_manifest() != expected_source_manifest {
        return Err("C6.2 disk response source manifest differs from setup".to_owned());
    }
    Ok(C61CampaignResponseVerifierReplay { response, contexts, transcript })
}

/// Replay the inherited response prefix using the explicit response-local
/// target frame carried by the C6.3 envelope.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn replay_c63_campaign_response_verifier(
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    expected_source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
) -> Result<C61CampaignResponseVerifierReplay, String> {
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let attempt = C6ClientAttempt {
        slot: certificate.slot,
        nonce: certificate.nonce,
        setup_manifest_digest: certificate.setup_manifest_digest,
        old_head_digest: certificate.old_head.digest(),
        predecessor_certificate_digest: certificate.predecessor_certificate_digest,
        correlation_ranges: certificate.correlation_ranges,
        workload: certificate.workload,
    };
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || public_instance.public_tokens().len()
            != usize::try_from(public_instance.workload().new_context).expect("u32 fits usize")
    {
        return Err("C6.3 disk response binding or profile mismatch".to_owned());
    }
    let context_digest = c62_campaign_response_transcript_context_digest(
        attempt,
        public_instance.response_statement_digest(),
    )?;
    let mut transcript = Transcript::new_fiat_shamir(context_digest)?;
    let retained = C6RetainedResponseProof::decode_c62(certificate.retained_response())
        .map_err(|error| error.to_string())?;
    let mut contexts = verifier_replay.fresh_contexts(certificate_digest)?;
    let targets = certificate.decoded_proof_envelope().response_cache_fold_targets().to_vec();
    let response = if public_instance.workload().old_context == 0 {
        replay_c6_t1_production_response_verifier(
            verifier_model,
            public_instance.public_tokens(),
            public_instance.response_statement_digest(),
            verifier_plan,
            verifier_extraction,
            &targets,
            &retained,
            &mut contexts,
            &mut transcript,
        )?
    } else {
        replay_c62_continuation_production_response_verifier(
            verifier_model,
            public_instance.public_tokens(),
            usize::try_from(public_instance.workload().old_context).expect("u32 fits usize"),
            public_instance.response_statement_digest(),
            verifier_plan,
            verifier_extraction,
            &targets,
            &retained,
            &mut contexts,
            &mut transcript,
        )?
    };
    if response.source_manifest() != expected_source_manifest {
        return Err("C6.3 disk response source manifest differs from setup".to_owned());
    }
    Ok(C61CampaignResponseVerifierReplay { response, contexts, transcript })
}

/// Result of the complete designated-verifier replay for one C6.2
/// certificate.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C62CampaignVerifierOutput {
    pub exact: C62ExactProductionNbr2VerifierOutput,
    pub certificate_digest: [u8; 32],
    pub public_argument_bytes: u64,
    pub proof_envelope_bytes: u64,
}

/// Verify the response, wrapper, blind proof, six WHIR chains, C62JVR1, and
/// C6NBR2 from decoded client state and provider bytes.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn verify_c62_campaign_e2e(
    certificate: &C62NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup: &C6SetupManifest,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    verifier_extraction_setup_bytes: u64,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C62CampaignVerifierOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    certificate.encode().map_err(|error| error.to_string())?;
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let setup_digest = setup.digest().map_err(|error| error.to_string())?;
    if certificate.setup_manifest_digest != setup_digest
        || certificate.model_digest != public_instance.model_family_digest()
        || certificate.workload != public_instance.workload()
        || certificate.public_output_digest != public_instance.preimage().public_output_digest()
        || certificate.public_argument()
            != C62PublicArgument::decode(certificate.public_argument())
                .map_err(|error| error.to_string())?
                .encode()
                .map_err(|error| error.to_string())?
    {
        return Err("C6.2 verifier certificate, setup, or public instance differs".to_owned());
    }
    let proposed_head = C6ProposedCacheHead::successor(
        certificate.old_head,
        certificate.workload,
        certificate.new_head.cache_root,
    )
    .map_err(|error| error.to_string())?;
    let attempt = C6ClientAttempt {
        slot: certificate.slot,
        nonce: certificate.nonce,
        setup_manifest_digest: certificate.setup_manifest_digest,
        old_head_digest: certificate.old_head.digest(),
        predecessor_certificate_digest: certificate.predecessor_certificate_digest,
        correlation_ranges: certificate.correlation_ranges,
        workload: certificate.workload,
    };
    let response_statement = build_c62_campaign_response_statement(
        setup,
        &verifier_plan,
        attempt,
        certificate.old_head,
        proposed_head,
        public_instance.preimage(),
    )?;
    if response_statement.digest() != public_instance.response_statement_digest() {
        return Err("C6.2 verifier response statement differs from public instance".to_owned());
    }
    let verifier_topology = verifier_plan.topology();
    let replay = replay_c62_campaign_response_verifier(
        certificate,
        verifier_replay,
        verifier_model,
        public_instance,
        source_manifest,
        verifier_plan,
        verifier_extraction,
    )?;
    let (response, mut contexts, mut transcript) = replay.into_parts();
    let disk_residual =
        prepare_c6_t1_disk_residual_owner(response, &mut transcript).map_err(|e| e.to_string())?;
    let wrapper_statement = build_c62_campaign_disk_wrapper_statement(
        response_statement.clone(),
        certificate,
        public_instance,
        &disk_residual,
        native_profile,
        compiler_profile,
    )?;
    let wrapper_statement_digest = wrapper_statement.digest();
    if wrapper_statement_digest != certificate.wrapper.statement_digest {
        return Err("C6.2 disk wrapper statement differs from certificate".to_owned());
    }
    let cache_profile = C6PersistentCacheStaticProfile {
        protocol_digest: setup.protocol_digest,
        model_digest: setup.model_digest,
        params_digest: setup.params_digest,
        wrapper_profile_digest: c6_wrapper_profile_digest(),
    };
    let roots = install_production_c61_native_live_wrapper_roots_verifier(
        wrapper_statement_digest,
        &cache_profile,
        certificate.wrapper_roots(),
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let root = roots
        .bind_residual_relation(disk_residual.manifest().clone())
        .map_err(|error| error.to_string())?;
    let envelope = certificate.decoded_proof_envelope();
    let coordinate_one = C6ResidualProductClaimCoordinate::decode_payload(
        disk_residual.manifest(),
        1,
        envelope.product_coordinate_one(),
    )
    .map_err(|error| error.to_string())?;
    let relation = volta_pcs::bind_c61_disk_residual_relation(
        wrapper_statement,
        disk_residual,
        root,
        coordinate_one,
        certificate.residual,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let (equality, residual) = relation.into_parts();
    let native_bindings = C62CampaignNativeBindings::start(attempt)?;
    let native_contexts = native_bindings.bind_public_context(
        attempt,
        native_profile,
        compiler_profile,
        response_statement.digest(),
        wrapper_statement_digest,
        residual.relation().digest(),
        proposed_head.digest(),
        certificate.wrapper.source_binding_digest,
    )?;

    let raw_argument =
        C62PublicArgument::decode(certificate.public_argument()).map_err(|e| e.to_string())?;
    let arithmetic =
        C61ArithmeticFrame::decode(raw_argument.arithmetic()).map_err(|e| e.to_string())?;
    let native_claims = C6T1NativeVerifierClaimOwner::from_disk_response(residual.response())?;
    let ids = C61NativeChainId::ordered();
    let model_primary = native_claims.statement(
        ids[0],
        decode_c62_production_native_commitment_descriptor(
            ids[0],
            &raw_argument.native_chains()[0],
        )?,
    )?;
    let model_secondary = native_claims.statement(
        ids[1],
        decode_c62_production_native_commitment_descriptor(
            ids[1],
            &raw_argument.native_chains()[1],
        )?,
    )?;
    let embedding_primary = native_claims.statement(
        ids[2],
        decode_c62_production_native_commitment_descriptor(
            ids[2],
            &raw_argument.native_chains()[2],
        )?,
    )?;
    let embedding_secondary = native_claims.statement(
        ids[3],
        decode_c62_production_native_commitment_descriptor(
            ids[3],
            &raw_argument.native_chains()[3],
        )?,
    )?;
    let secondary_proofs = [
        C62ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[1],
            model_secondary.public(),
            C61JointNativeTailRole::Correction,
        )?,
        C62ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[3],
            embedding_secondary.public(),
            C61JointNativeTailRole::ZeroOpenTag,
        )?,
    ];
    let secondary_statements = [model_secondary, embedding_secondary];
    let secondary_fixed = prepare_c62_production_joint_native_verifier_bodies(
        native_profile,
        &secondary_statements,
        &secondary_proofs,
        &[native_contexts.lane_contexts[1], native_contexts.lane_contexts[3]],
        &[native_contexts.mask_ranges[1], native_contexts.mask_ranges[3]],
        native_contexts.joint_context,
    )?;
    verify_c62_authenticated_whir_p3_primary_chain_fiat_shamir_in_attempt(
        &model_primary,
        &C61ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[0],
            model_primary.public(),
        )?,
        &mut contexts[0],
        native_contexts.lane_contexts[0],
        native_contexts.mask_ranges[0],
    )?;
    verify_c62_authenticated_whir_p3_primary_chain_fiat_shamir_in_attempt(
        &embedding_primary,
        &C61ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[2],
            embedding_primary.public(),
        )?,
        &mut contexts[0],
        native_contexts.lane_contexts[2],
        native_contexts.mask_ranges[2],
    )?;
    let claim_weights = secondary_fixed
        .claim_weights()
        .into_iter()
        .map(<[volta_field::Fp2]>::to_vec)
        .collect::<Vec<_>>();
    let functional = C6CompiledNativeTargetFunctional::compile(
        residual.response().installed().operation_plan(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        native_profile,
        &claim_weights,
        &secondary_fixed.challenge().cohort_weights,
    )
    .map_err(|error| error.to_string())?;
    let native_profile_artifact =
        C6NativeTargetProfileArtifact::encode(native_profile, verifier_topology)
            .map_err(|error| error.to_string())?;
    let native_profile_digest = *blake3::hash(native_profile_artifact.as_bytes()).as_bytes();
    let response_binding_digest = c62_campaign_response_binding_digest(
        response_statement.digest(),
        certificate.retained_response(),
        residual.response().source_schedule().digest,
        residual.relation().digest(),
    )?;
    let root_binding_digest = roots.fixed().binding_digest();
    let outer_statement_digest = volta_pcs::c62_public_statement_digest(
        roots.fixed().statement_digest(),
        native_profile_digest,
        secondary_fixed.challenge().schedule_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
    )
    .map_err(|error| error.to_string())?;
    if outer_statement_digest != raw_argument.statement_digest()
        || outer_statement_digest != public_instance.public_argument_statement_digest()
        || arithmetic.statement_digest != outer_statement_digest
    {
        return Err("C6.2 public argument statement binding differs".to_owned());
    }
    let compiler_correction = secondary_fixed.pending_correction();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        certificate.wrapper.source_binding_digest,
        residual.response().source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        compiler_correction,
    )
    .map_err(|error| error.to_string())?;
    let base_fold = functional
        .replay_verifier_base_coordinate(1, residual.response().source_schedule(), &mut contexts[1])
        .map_err(|error| error.to_string())?;
    let binding = C62ResponseCompilerBinding {
        schedule_digest: secondary_fixed.challenge().schedule_digest,
        response_binding_digest,
        functional_digest: functional.functional_digest(),
        nbr2_statement_digest: nbr2.digest(),
        root_binding_digest,
        compiler_correction,
    };
    let native = secondary_fixed.prepare_nbr2_link(base_fold.key, binding, &mut contexts[1])?;

    let blind_compiler = C6BlindResidualFusedCompilerContext::new(
        residual.response().installed().operation_plan(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.verifier_linear(),
        residual.relation(),
    );
    let statements: [C6BlindResidualStatement; 2] = (0..2u8)
        .map(|repetition| prepare_c6_blind_residual_statement_fused(blind_compiler, repetition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "C6.2 blind statement census differs".to_owned())?;
    let blind_proof = decode_c62_native_exact_production_blind_envelope(
        &envelope,
        &statements,
        roots.fixed().statement_digest(),
        roots.fixed(),
    )?;
    let old_len = u16::try_from(certificate.workload.old_context)
        .map_err(|_| "C6.2 old cache length exceeds u16")?;
    let new_len = u16::try_from(certificate.workload.new_context)
        .map_err(|_| "C6.2 new cache length exceeds u16")?;
    let append = materialize_c61_native_cache_append_verifier_owner(
        residual.response().cache_append_sources(),
        old_len,
        new_len,
        &mut contexts,
    )?;
    let canonical_runtime = residual
        .response()
        .installed()
        .runtime()
        .canonical_runtime_values(residual.response().installed().extraction())
        .map_err(|error| error.to_string())?;
    let blind = prepare_c61_native_decoded_blind_verifier(
        &roots,
        roots.fixed().statement_digest(),
        residual.response().cache_snapshot(),
        residual.response().cache_targets(),
        residual.response().cache_target_fixed(),
        old_len,
        new_len,
        &append,
        &statements,
        &blind_proof,
        residual.relation(),
        equality,
        &arithmetic,
        &canonical_runtime,
        &mut contexts,
        &mut transcript,
    )?;
    let compiler0 = blind.compiler_public_statement(
        residual.response().installed().operation_plan(),
        compiler_profile.terminal_metadata(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.relation(),
        decode_c62_production_compiler_commitment_descriptors(
            ids[4],
            &raw_argument.native_chains()[4],
        )?,
        ids[4],
    )?;
    let compiler1 = blind.compiler_public_statement(
        residual.response().installed().operation_plan(),
        compiler_profile.terminal_metadata(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.relation(),
        decode_c62_production_compiler_commitment_descriptors(
            ids[5],
            &raw_argument.native_chains()[5],
        )?,
        ids[5],
    )?;
    let public_statements = [
        model_primary.public().clone(),
        secondary_statements[0].public().clone(),
        embedding_primary.public().clone(),
        secondary_statements[1].public().clone(),
        compiler0.clone(),
        compiler1.clone(),
    ];
    let (decoded_argument, artifacts, decoded_arithmetic) = decode_c62_production_public_argument(
        certificate.public_argument(),
        &public_statements,
        native_profile,
        native.challenge().schedule_digest,
        functional.functional_digest(),
    )?;
    if decoded_argument != raw_argument || decoded_arithmetic != arithmetic {
        return Err("C6.2 typed public argument decode differs from strict predecode".to_owned());
    }
    for index in 4..6 {
        let proof = match artifacts[index].proof() {
            C62ProductionNativeChainProof::Compiler(proof) => proof,
            _ => return Err("C6.2 compiler artifact has another role".to_owned()),
        };
        verify_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
            compiler_profile,
            verifier_extraction_setup_bytes,
            &public_statements[index],
            residual.relation(),
            &proof.inner().encode()?,
            &mut contexts[index - 4],
            native_contexts.lane_contexts[index],
            ids[index],
            native_contexts.mask_ranges[index],
        )?;
    }
    let exact = finish_c62_native_decoded_nbr2_verifier(
        &roots,
        blind,
        &blind_proof,
        outer_statement_digest,
        &nbr2,
        native,
        &mut contexts,
        &mut transcript,
    )?;
    if exact.bound_slots() != 2 * 28 || exact.joint_native().cohort_count != 2 {
        return Err("C6.2 final verifier census differs".to_owned());
    }
    Ok(C62CampaignVerifierOutput {
        exact,
        certificate_digest,
        public_argument_bytes: certificate.public_argument().len() as u64,
        proof_envelope_bytes: certificate.proof_envelope.len() as u64,
    })
}

/// Result of one complete CPU-only C6.3 verifier replay.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C63CampaignVerifierOutput {
    pub complete: C63CompleteProductionVerifierOutput,
    pub certificate_digest: [u8; 32],
    pub inherited_public_argument_bytes: u64,
    pub sketch_public_argument_bytes: u64,
    pub proof_envelope_bytes: u64,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub struct C64CampaignVerifierOutput {
    pub complete: C64CompleteProductionVerifierOutput,
    pub certificate_digest: [u8; 32],
    pub inherited_public_argument_bytes: u64,
    pub sketch_public_argument_bytes: u64,
    pub proof_envelope_bytes: u64,
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
enum C63OrC64CampaignVerifierOutput {
    C63(C63CampaignVerifierOutput),
    C64(C64CampaignVerifierOutput),
}

/// Verify response, residual wrapper, inherited six chains, exact source
/// link, sparse closure and all eight C6.3 WHIR bodies on ordinary CPU state.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn verify_c63_campaign_e2e(
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    predecessor_state: &C63VerifierSketchState,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    verifier_extraction_setup_bytes: u64,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C63CampaignVerifierOutput, String> {
    match verify_c63_or_c64_campaign_e2e(
        certificate,
        verifier_replay,
        setup,
        sparse_setup,
        h,
        predecessor_state,
        verifier_model,
        public_instance,
        source_manifest,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        native_profile,
        compiler_profile,
        false,
    )? {
        C63OrC64CampaignVerifierOutput::C63(output) => Ok(output),
        C63OrC64CampaignVerifierOutput::C64(_) => unreachable!("C6.3 verifier mode"),
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
pub fn verify_c64_campaign_e2e(
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    predecessor_state: &C63VerifierSketchState,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    verifier_extraction_setup_bytes: u64,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
) -> Result<C64CampaignVerifierOutput, String> {
    match verify_c63_or_c64_campaign_e2e(
        certificate,
        verifier_replay,
        setup,
        sparse_setup,
        h,
        predecessor_state,
        verifier_model,
        public_instance,
        source_manifest,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        native_profile,
        compiler_profile,
        true,
    )? {
        C63OrC64CampaignVerifierOutput::C64(output) => Ok(output),
        C63OrC64CampaignVerifierOutput::C63(_) => unreachable!("C6.4 verifier mode"),
    }
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
fn verify_c63_or_c64_campaign_e2e(
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup: &C6SetupManifest,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    predecessor_state: &C63VerifierSketchState,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    verifier_extraction_setup_bytes: u64,
    native_profile: &C6CanonicalTargetProfile,
    compiler_profile: &C61CompilerVerifierProfile,
    c64: bool,
) -> Result<C63OrC64CampaignVerifierOutput, String> {
    setup.validate().map_err(|error| error.to_string())?;
    certificate.encode().map_err(|error| error.to_string())?;
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let setup_digest = setup.digest().map_err(|error| error.to_string())?;
    let inherited = C62PublicArgument::decode(certificate.inherited_public_argument())
        .map_err(|error| error.to_string())?;
    if certificate.version
        != if c64 { C64_NATIVE_CERTIFICATE_VERSION } else { C63_NATIVE_CERTIFICATE_VERSION }
        || certificate.setup_manifest_digest != setup_digest
        || certificate.model_digest != public_instance.model_family_digest()
        || certificate.workload != public_instance.workload()
        || certificate.public_output_digest != public_instance.preimage().public_output_digest()
        || inherited.encode().map_err(|error| error.to_string())?
            != certificate.inherited_public_argument()
        || predecessor_state.profile_digest() != sparse_setup.production_profile_digest()?
        || predecessor_state.epoch() != certificate.old_head.epoch
        || u32::from(predecessor_state.accepted_len()) != certificate.old_head.cache_len
    {
        return Err("C6.3 verifier certificate, setup, or predecessor differs".to_owned());
    }
    let attempt = C6ClientAttempt {
        slot: certificate.slot,
        nonce: certificate.nonce,
        setup_manifest_digest: certificate.setup_manifest_digest,
        old_head_digest: certificate.old_head.digest(),
        predecessor_certificate_digest: certificate.predecessor_certificate_digest,
        correlation_ranges: certificate.correlation_ranges,
        workload: certificate.workload,
    };
    let response_head_intent = c63_campaign_response_head_intent(
        setup,
        sparse_setup,
        certificate.old_head,
        public_instance.preimage(),
        predecessor_state,
    )?;
    let response_statement = build_c62_campaign_response_statement(
        setup,
        &verifier_plan,
        attempt,
        certificate.old_head,
        response_head_intent,
        public_instance.preimage(),
    )?;
    if response_statement.digest() != public_instance.response_statement_digest() {
        return Err("C6.3 verifier response statement differs from public instance".to_owned());
    }
    let verifier_topology = verifier_plan.topology();
    let replay = replay_c63_campaign_response_verifier(
        certificate,
        verifier_replay,
        verifier_model,
        public_instance,
        source_manifest,
        verifier_plan,
        verifier_extraction,
    )?;
    let (response, mut contexts, mut transcript) = replay.into_parts();
    let disk_residual =
        prepare_c6_t1_disk_residual_owner(response, &mut transcript).map_err(|e| e.to_string())?;
    let wrapper_statement = build_c63_campaign_disk_wrapper_statement(
        response_statement.clone(),
        certificate,
        public_instance,
        &disk_residual,
        native_profile,
        compiler_profile,
    )?;
    let wrapper_statement_digest = wrapper_statement.digest();
    if wrapper_statement_digest != certificate.wrapper.statement_digest {
        return Err("C6.3 disk wrapper statement differs from certificate".to_owned());
    }
    let roots = install_production_c63_authenticated_sketch_live_wrapper_roots_verifier(
        wrapper_statement_digest,
        [certificate.wrapper.residual_root, certificate.wrapper.auxiliary_root],
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let root = roots
        .bind_residual_relation(disk_residual.manifest().clone())
        .map_err(|error| error.to_string())?;
    let (
        residual_sumcheck,
        product_coordinate_one,
        residual_pending_corrections,
        source_functional_corrections,
        authenticated_output_link,
        sparse_h_closure,
        cache_whir_terminal_tags,
        projected_residual,
    ) = if c64 {
        let tail = C64DecodedResponseTail::decode(&certificate.proof_envelope)?;
        (
            tail.residual_sumcheck,
            tail.product_coordinate_one,
            tail.residual_pending_corrections,
            tail.source_functional_corrections,
            None,
            tail.sparse_h_closure,
            tail.cache_whir_terminal_tags,
            Some(tail.projected_residual),
        )
    } else {
        let tail = decode_c63_response_tail(roots.fixed(), &certificate.proof_envelope)?;
        (
            tail.envelope.residual_sumcheck().to_vec(),
            tail.envelope.product_coordinate_one().to_vec(),
            tail.envelope.residual_pending_corrections().to_vec(),
            tail.source_functional_corrections,
            Some(tail.authenticated_output_link),
            tail.sparse_h_closure,
            tail.whir_terminal_tags,
            None,
        )
    };
    let coordinate_one = C6ResidualProductClaimCoordinate::decode_payload(
        disk_residual.manifest(),
        1,
        &product_coordinate_one,
    )
    .map_err(|error| error.to_string())?;
    let relation = volta_pcs::bind_c61_disk_residual_relation(
        wrapper_statement,
        disk_residual,
        root,
        coordinate_one,
        certificate.residual,
        &mut transcript,
    )
    .map_err(|error| error.to_string())?;
    let (equality, residual) = relation.into_parts();
    let native_bindings = C62CampaignNativeBindings::start(attempt)?;
    let native_contexts = native_bindings.bind_public_context(
        attempt,
        native_profile,
        compiler_profile,
        response_statement.digest(),
        wrapper_statement_digest,
        residual.relation().digest(),
        response_head_intent.digest(),
        certificate.wrapper.source_binding_digest,
    )?;

    let raw_argument = inherited;
    let arithmetic =
        C61ArithmeticFrame::decode(raw_argument.arithmetic()).map_err(|e| e.to_string())?;
    let native_claims = C6T1NativeVerifierClaimOwner::from_disk_response(residual.response())?;
    let ids = C61NativeChainId::ordered();
    let model_primary = native_claims.statement(
        ids[0],
        decode_c62_production_native_commitment_descriptor(
            ids[0],
            &raw_argument.native_chains()[0],
        )?,
    )?;
    let model_secondary = native_claims.statement(
        ids[1],
        decode_c62_production_native_commitment_descriptor(
            ids[1],
            &raw_argument.native_chains()[1],
        )?,
    )?;
    let embedding_primary = native_claims.statement(
        ids[2],
        decode_c62_production_native_commitment_descriptor(
            ids[2],
            &raw_argument.native_chains()[2],
        )?,
    )?;
    let embedding_secondary = native_claims.statement(
        ids[3],
        decode_c62_production_native_commitment_descriptor(
            ids[3],
            &raw_argument.native_chains()[3],
        )?,
    )?;
    let secondary_proofs = [
        C62ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[1],
            model_secondary.public(),
            C61JointNativeTailRole::Correction,
        )?,
        C62ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[3],
            embedding_secondary.public(),
            C61JointNativeTailRole::ZeroOpenTag,
        )?,
    ];
    let secondary_statements = [model_secondary, embedding_secondary];
    let secondary_fixed = prepare_c62_production_joint_native_verifier_bodies(
        native_profile,
        &secondary_statements,
        &secondary_proofs,
        &[native_contexts.lane_contexts[1], native_contexts.lane_contexts[3]],
        &[native_contexts.mask_ranges[1], native_contexts.mask_ranges[3]],
        native_contexts.joint_context,
    )?;
    verify_c62_authenticated_whir_p3_primary_chain_fiat_shamir_in_attempt(
        &model_primary,
        &C61ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[0],
            model_primary.public(),
        )?,
        &mut contexts[0],
        native_contexts.lane_contexts[0],
        native_contexts.mask_ranges[0],
    )?;
    verify_c62_authenticated_whir_p3_primary_chain_fiat_shamir_in_attempt(
        &embedding_primary,
        &C61ProductionCommittedChainProof::decode(
            &raw_argument.native_chains()[2],
            embedding_primary.public(),
        )?,
        &mut contexts[0],
        native_contexts.lane_contexts[2],
        native_contexts.mask_ranges[2],
    )?;
    let claim_weights = secondary_fixed
        .claim_weights()
        .into_iter()
        .map(<[volta_field::Fp2]>::to_vec)
        .collect::<Vec<_>>();
    let functional = C6CompiledNativeTargetFunctional::compile(
        residual.response().installed().operation_plan(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        native_profile,
        &claim_weights,
        &secondary_fixed.challenge().cohort_weights,
    )
    .map_err(|error| error.to_string())?;
    let native_profile_artifact =
        C6NativeTargetProfileArtifact::encode(native_profile, verifier_topology)
            .map_err(|error| error.to_string())?;
    let native_profile_digest = *blake3::hash(native_profile_artifact.as_bytes()).as_bytes();
    let response_binding_digest = c62_campaign_response_binding_digest(
        response_statement.digest(),
        certificate.retained_response(),
        residual.response().source_schedule().digest,
        residual.relation().digest(),
    )?;
    let root_binding_digest = roots.fixed().binding_digest();
    let outer_statement_digest = volta_pcs::c62_public_statement_digest(
        roots.fixed().statement_digest(),
        native_profile_digest,
        secondary_fixed.challenge().schedule_digest,
        functional.functional_digest(),
        response_binding_digest,
        root_binding_digest,
    )
    .map_err(|error| error.to_string())?;
    if outer_statement_digest != raw_argument.statement_digest()
        || outer_statement_digest != public_instance.public_argument_statement_digest()
        || arithmetic.statement_digest != outer_statement_digest
    {
        return Err("C6.3 inherited public argument statement binding differs".to_owned());
    }
    let compiler_correction = secondary_fixed.pending_correction();
    let nbr2 = C6Nbr2CorrectionFunctional::new(
        roots.fixed(),
        outer_statement_digest,
        residual.relation().manifest().digest(),
        certificate.wrapper.source_binding_digest,
        residual.response().source_schedule().digest,
        native_profile_digest,
        functional.functional_digest(),
        functional.leaf_coefficients(),
        compiler_correction,
    )
    .map_err(|error| error.to_string())?;
    let base_fold = functional
        .replay_verifier_base_coordinate(1, residual.response().source_schedule(), &mut contexts[1])
        .map_err(|error| error.to_string())?;
    let binding = C62ResponseCompilerBinding {
        schedule_digest: secondary_fixed.challenge().schedule_digest,
        response_binding_digest,
        functional_digest: functional.functional_digest(),
        nbr2_statement_digest: nbr2.digest(),
        root_binding_digest,
        compiler_correction,
    };
    let native = secondary_fixed.prepare_nbr2_link(base_fold.key, binding, &mut contexts[1])?;

    let blind_compiler = C6BlindResidualFusedCompilerContext::new(
        residual.response().installed().operation_plan(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.verifier_linear(),
        residual.relation(),
    );
    let statements: [C6BlindResidualStatement; 2] = (0..2u8)
        .map(|repetition| prepare_c6_blind_residual_statement_fused(blind_compiler, repetition))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "C6.3 blind statement census differs".to_owned())?;
    let residual_proof = C6BlindResidualSumcheckProof::decode(&statements, &residual_sumcheck)
        .map_err(|error| error.to_string())?;
    let residual_frame = C6BlindResidualPendingTransferFrame::decode(&residual_pending_corrections)
        .map_err(|error| error.to_string())?;
    let old_len = u16::try_from(certificate.workload.old_context)
        .map_err(|_| "C6.3 old cache length exceeds u16")?;
    let canonical_runtime = residual
        .response()
        .installed()
        .runtime()
        .canonical_runtime_values(residual.response().installed().extraction())
        .map_err(|error| error.to_string())?;
    let projected_weights = if let Some(projected) = projected_residual.as_ref() {
        let binding_digest = c64_projected_residual_binding_digest(
            roots.fixed().binding_digest(),
            outer_statement_digest,
            residual.relation().digest(),
            certificate.wrapper.source_binding_digest,
        )?;
        Some(replay_c64_projected_residual_precommit(
            binding_digest,
            projected.roots,
            &mut transcript,
        )?)
    } else {
        None
    };
    let blind = prepare_c63_decoded_blind_verifier(
        &roots,
        &statements,
        &residual_proof,
        &residual_frame,
        residual.relation(),
        equality,
        &arithmetic,
        &canonical_runtime,
        &mut contexts,
        &mut transcript,
    )?;
    let compiler0 = blind.compiler_public_statement(
        residual.response().installed().operation_plan(),
        compiler_profile.terminal_metadata(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.relation(),
        decode_c62_production_compiler_commitment_descriptors(
            ids[4],
            &raw_argument.native_chains()[4],
        )?,
        ids[4],
    )?;
    let compiler1 = blind.compiler_public_statement(
        residual.response().installed().operation_plan(),
        compiler_profile.terminal_metadata(),
        residual.response().installed().extraction(),
        residual.response().installed().runtime(),
        residual.relation(),
        decode_c62_production_compiler_commitment_descriptors(
            ids[5],
            &raw_argument.native_chains()[5],
        )?,
        ids[5],
    )?;
    let public_statements = [
        model_primary.public().clone(),
        secondary_statements[0].public().clone(),
        embedding_primary.public().clone(),
        secondary_statements[1].public().clone(),
        compiler0.clone(),
        compiler1.clone(),
    ];
    let (decoded_argument, artifacts, decoded_arithmetic) = decode_c62_production_public_argument(
        certificate.inherited_public_argument(),
        &public_statements,
        native_profile,
        native.challenge().schedule_digest,
        functional.functional_digest(),
    )?;
    if decoded_argument != raw_argument || decoded_arithmetic != arithmetic {
        return Err("C6.3 typed inherited argument differs from strict predecode".to_owned());
    }
    for index in 4..6 {
        let proof = match artifacts[index].proof() {
            C62ProductionNativeChainProof::Compiler(proof) => proof,
            _ => return Err("C6.3 compiler artifact has another role".to_owned()),
        };
        verify_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(
            compiler_profile,
            verifier_extraction_setup_bytes,
            &public_statements[index],
            residual.relation(),
            &proof.inner().encode()?,
            &mut contexts[index - 4],
            native_contexts.lane_contexts[index],
            ids[index],
            native_contexts.mask_ranges[index],
        )?;
    }
    if c64 {
        let projected = projected_residual
            .as_ref()
            .ok_or_else(|| "C6.4 projected residual frame is absent".to_owned())?;
        let precommit_binding_digest = c64_projected_residual_binding_digest(
            roots.fixed().binding_digest(),
            outer_statement_digest,
            residual.relation().digest(),
            certificate.wrapper.source_binding_digest,
        )?;
        let complete = verify_c64_complete_decoded_response(
            &roots,
            blind,
            outer_statement_digest,
            &nbr2,
            certificate.wrapper.source_binding_digest,
            old_len,
            residual.response().cache_append_sources(),
            residual.response().source_schedule(),
            &source_functional_corrections,
            native,
            certificate.sketch_public_argument(),
            attempt,
            h,
            &sparse_h_closure,
            predecessor_state,
            cache_whir_terminal_tags,
            c63_campaign_mask_range(attempt)?,
            projected,
            precommit_binding_digest,
            projected_weights.ok_or_else(|| "C6.4 projection weights are absent".to_owned())?,
            c64_campaign_mask_range(attempt)?,
            &mut contexts,
            &mut transcript,
        )?;
        if complete.joint_native().cohort_count != 2
            || complete.successor_state().epoch() != certificate.new_head.epoch
            || u32::from(complete.successor_state().accepted_len())
                != certificate.new_head.cache_len
        {
            return Err("C6.4 final verifier census or successor differs".to_owned());
        }
        Ok(C63OrC64CampaignVerifierOutput::C64(C64CampaignVerifierOutput {
            complete,
            certificate_digest,
            inherited_public_argument_bytes: certificate.inherited_public_argument().len() as u64,
            sketch_public_argument_bytes: certificate.sketch_public_argument().len() as u64,
            proof_envelope_bytes: certificate.proof_envelope.len() as u64,
        }))
    } else {
        let complete = verify_c63_complete_decoded_response(
            &roots,
            blind,
            authenticated_output_link
                .as_ref()
                .ok_or_else(|| "C6.3 authenticated output link is absent".to_owned())?,
            outer_statement_digest,
            &nbr2,
            certificate.wrapper.source_binding_digest,
            old_len,
            residual.response().cache_append_sources(),
            residual.response().source_schedule(),
            &source_functional_corrections,
            native,
            certificate.sketch_public_argument(),
            attempt,
            h,
            &sparse_h_closure,
            predecessor_state,
            cache_whir_terminal_tags,
            c63_campaign_mask_range(attempt)?,
            &mut contexts,
            &mut transcript,
        )?;
        if complete.inherited().inherited().bound_slots() != 2 * 40
            || complete.inherited().inherited().joint_native().cohort_count != 2
            || complete.successor_state().epoch() != certificate.new_head.epoch
            || u32::from(complete.successor_state().accepted_len())
                != certificate.new_head.cache_len
        {
            return Err("C6.3 final verifier census or successor differs".to_owned());
        }
        Ok(C63OrC64CampaignVerifierOutput::C63(C63CampaignVerifierOutput {
            complete,
            certificate_digest,
            inherited_public_argument_bytes: certificate.inherited_public_argument().len() as u64,
            sketch_public_argument_bytes: certificate.sketch_public_argument().len() as u64,
            proof_envelope_bytes: certificate.proof_envelope.len() as u64,
        }))
    }
}

/// Consume one strict disk artifact through the complete C6.2 verifier.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn verify_c62_loaded_campaign_e2e(
    artifact: C62CampaignArtifact,
) -> Result<C62CampaignVerifierOutput, String> {
    let C62CampaignArtifact {
        certificate,
        verifier_replay,
        setup_manifest,
        verifier_model,
        source_manifest,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        native_profile,
        compiler_profile,
        public_instance,
        public_argument: _,
        quantization_digest: _,
        source_git_commit: _,
        wire_bytes: _,
    } = artifact;
    verify_c62_campaign_e2e(
        &certificate,
        &verifier_replay,
        &setup_manifest,
        &verifier_model,
        &public_instance,
        &source_manifest,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        &native_profile,
        &compiler_profile,
    )
}

/// Consume one strict disk artifact through the complete C6.3 CPU verifier.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn verify_c63_loaded_campaign_e2e(
    artifact: C63CampaignArtifact,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    predecessor_state: &C63VerifierSketchState,
) -> Result<C63CampaignVerifierOutput, String> {
    let C63CampaignArtifact {
        certificate,
        verifier_replay,
        setup_manifest,
        verifier_model,
        source_manifest,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        native_profile,
        compiler_profile,
        quantization_digest: _,
        public_instance,
        inherited_public_argument: _,
        source_git_commit: _,
        wire_bytes: _,
    } = artifact;
    verify_c63_campaign_e2e(
        &certificate,
        &verifier_replay,
        &setup_manifest,
        sparse_setup,
        h,
        predecessor_state,
        &verifier_model,
        &public_instance,
        &source_manifest,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        &native_profile,
        &compiler_profile,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn verify_c64_loaded_campaign_e2e(
    artifact: C63CampaignArtifact,
    sparse_setup: &C63SparseSetupReference,
    h: &C63SparseSketchReference,
    predecessor_state: &C63VerifierSketchState,
) -> Result<C64CampaignVerifierOutput, String> {
    let C63CampaignArtifact {
        certificate,
        verifier_replay,
        setup_manifest,
        verifier_model,
        source_manifest,
        operation_plan_artifact: _,
        verifier_extraction_artifact: _,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        native_profile,
        compiler_profile,
        quantization_digest: _,
        public_instance,
        inherited_public_argument: _,
        source_git_commit: _,
        wire_bytes: _,
    } = artifact;
    verify_c64_campaign_e2e(
        &certificate,
        &verifier_replay,
        &setup_manifest,
        sparse_setup,
        h,
        predecessor_state,
        &verifier_model,
        &public_instance,
        &source_manifest,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes,
        &native_profile,
        &compiler_profile,
    )
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || value.bytes().any(|byte| !byte.is_ascii_hexdigit()) {
        return Err(format!("{label} is not a 32-byte hexadecimal digest"));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16)
            .map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    Ok(digest)
}

fn load_file(root: &Path, row: &SetupFileRow) -> Result<Vec<u8>, String> {
    if row.name.contains('/') || row.name.contains('\\') || row.name.starts_with('.') {
        return Err("C6.1 setup manifest contains a noncanonical file name".to_owned());
    }
    let bytes = fs::read(root.join(&row.name))
        .map_err(|error| format!("read C6.1 setup {}: {error}", row.name))?;
    if u64::try_from(bytes.len()).ok() != Some(row.bytes)
        || *blake3::hash(&bytes).as_bytes() != parse_hex_32(&row.blake3, "setup file digest")?
    {
        return Err(format!("C6.1 setup file {} differs from its manifest", row.name));
    }
    Ok(bytes)
}

fn load_campaign_installed_setup(
    root: &Path,
    expected_profile: &str,
    protocol_label: &str,
) -> Result<C61CampaignInstalledSetup, String> {
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|error| format!("read {protocol_label} setup manifest: {error}"))?;
    let record: SetupRecord = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("decode {protocol_label} setup manifest: {error}"))?;
    if record.schema != 1 || record.profile != expected_profile || record.files.len() != 4 {
        return Err(format!(
            "{protocol_label} setup manifest schema, profile, or file census differs"
        ));
    }
    let expected_names = [
        "operation-plan.bin",
        "prover-extraction.bin",
        "verifier-extraction.bin",
        "native-target-profile.bin",
    ];
    if record.files.iter().map(|row| row.name.as_str()).ne(expected_names) {
        return Err("C6.1 setup files are not in canonical order".to_owned());
    }
    let source_manifest = C6TraceSourceManifest::new(
        record.source_count,
        parse_hex_32(&record.source_schedule_digest, "source schedule digest")?,
        record.product_mask_sources,
    )
    .map_err(|error| error.to_string())?;
    let plan_bytes = load_file(root, &record.files[0])?;
    let prover_extraction_bytes = load_file(root, &record.files[1])?;
    let verifier_extraction_bytes = load_file(root, &record.files[2])?;
    let native_profile_bytes = load_file(root, &record.files[3])?;

    let plan = C6OperationPlanArtifact::parse(plan_bytes, &source_manifest)
        .map_err(|error| format!("parse C6.1 operation plan: {error}"))?;
    let decoded = plan
        .decode(&source_manifest)
        .map_err(|error| format!("decode C6.1 operation plan: {error}"))?;
    let topology = decoded.topology;
    if topology.topology_digest != parse_hex_32(&record.topology_digest, "topology digest")? {
        return Err("C6.1 setup topology differs from its manifest".to_owned());
    }
    let provider_extraction_artifact =
        C6InstanceExtractionArtifact::parse(prover_extraction_bytes, topology)
            .map_err(|error| format!("parse C6.1 provider extraction: {error}"))?;
    let provider_extraction = provider_extraction_artifact
        .decode(topology)
        .map_err(|error| format!("decode C6.1 provider extraction: {error}"))?;
    let verifier_extraction_artifact =
        C6InstanceExtractionArtifact::parse(verifier_extraction_bytes, topology)
            .map_err(|error| format!("parse C6.1 verifier extraction: {error}"))?;
    let verifier_extraction = verifier_extraction_artifact
        .decode(topology)
        .map_err(|error| format!("decode C6.1 verifier extraction: {error}"))?;
    if provider_extraction.role() != C6InstanceExtractionRole::Prover
        || verifier_extraction.role() != C6InstanceExtractionRole::Verifier
    {
        return Err("C6.1 setup extraction roles differ".to_owned());
    }
    let (native_profile_artifact, native_profile) =
        C6NativeTargetProfileArtifact::decode(&native_profile_bytes, topology)
            .map_err(|error| format!("decode C6.1 native-target profile: {error}"))?;
    if *blake3::hash(&native_profile_bytes).as_bytes()
        != parse_hex_32(&record.native_profile_digest, "native profile digest")?
    {
        return Err("C6.1 native-target profile digest differs".to_owned());
    }

    let plan_len = u64::try_from(plan.len()).map_err(|_| "C6.1 plan length exceeds u64")?;
    let extraction_len = record.files[1]
        .bytes
        .checked_add(record.files[2].bytes)
        .ok_or_else(|| "C6.1 extraction byte count overflows".to_owned())?;
    let native_len = u64::try_from(native_profile_bytes.len())
        .map_err(|_| "C6.1 native profile length exceeds u64")?;
    let provider_plan = plan
        .clone()
        .install(&source_manifest)
        .map_err(|error| format!("install C6.1 provider plan: {error}"))?;
    let verifier_plan = plan
        .clone()
        .install(&source_manifest)
        .map_err(|error| format!("install C6.1 verifier plan: {error}"))?;
    let terminal_metadata = volta_mac::C6OperationPlanTerminalMetadata::from_installed(
        &verifier_plan,
        &source_manifest,
    )
    .map_err(|error| format!("build C6.1 compiler verifier metadata: {error}"))?;
    let compiler_profile = if protocol_label == "C6.2" {
        C61CompilerVerifierProfile::new_c62(terminal_metadata)?
    } else {
        C61CompilerVerifierProfile::new(terminal_metadata)?
    };
    Ok(C61CampaignInstalledSetup {
        source_manifest,
        provider_plan,
        verifier_plan,
        provider_extraction,
        verifier_extraction,
        native_profile,
        compiler_profile,
        operation_plan_artifact: plan,
        verifier_extraction_artifact,
        native_profile_artifact,
        plan_bytes: plan_len,
        extraction_bytes: extraction_len,
        native_profile_bytes: native_len,
    })
}

/// Load one historical C6.1 installed profile.
pub fn load_c61_campaign_installed_setup(root: &Path) -> Result<C61CampaignInstalledSetup, String> {
    load_campaign_installed_setup(root, "C6.1-T1-installed-setup-v1", "C6.1")
}

/// Load one C6.2 exact-context installed profile.
pub fn load_c62_campaign_installed_setup(root: &Path) -> Result<C61CampaignInstalledSetup, String> {
    load_campaign_installed_setup(root, "C6.2-exact-context-installed-setup-v1", "C6.2")
}

fn encode_source_manifest(manifest: &C6TraceSourceManifest) -> Result<Vec<u8>, String> {
    let count = u32::try_from(manifest.product_mask_sources.len())
        .map_err(|_| "C6.1 source-mask census exceeds u32".to_owned())?;
    let mut bytes = Vec::with_capacity(40 + manifest.product_mask_sources.len() * 4);
    bytes.extend_from_slice(&manifest.source_count.to_le_bytes());
    bytes.extend_from_slice(&manifest.source_schedule_digest);
    bytes.extend_from_slice(&count.to_le_bytes());
    for source in &manifest.product_mask_sources {
        bytes.extend_from_slice(&source.to_le_bytes());
    }
    Ok(bytes)
}

fn decode_source_manifest(bytes: &[u8]) -> Result<C6TraceSourceManifest, String> {
    if bytes.len() < 40 || (bytes.len() - 40) % 4 != 0 {
        return Err("C6.1 client source-manifest length mismatch".to_owned());
    }
    let source_count = u32::from_le_bytes(bytes[0..4].try_into().expect("fixed width"));
    let mut source_schedule_digest = [0; 32];
    source_schedule_digest.copy_from_slice(&bytes[4..36]);
    let count = usize::try_from(u32::from_le_bytes(bytes[36..40].try_into().expect("fixed width")))
        .expect("u32 fits usize");
    if bytes.len() != 40 + count * 4 {
        return Err("C6.1 client source-manifest census mismatch".to_owned());
    }
    let product_mask_sources = bytes[40..]
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("fixed width")))
        .collect();
    let manifest =
        C6TraceSourceManifest::new(source_count, source_schedule_digest, product_mask_sources)
            .map_err(|error| error.to_string())?;
    if encode_source_manifest(&manifest)? != bytes {
        return Err("C6.1 client source-manifest is noncanonical".to_owned());
    }
    Ok(manifest)
}

/// Pack every response-independent verifier object into the exact setup
/// allocation. The provider extraction map is deliberately absent.
fn encode_campaign_client_parameters_with_plan_limit(
    installed: &C61CampaignInstalledSetup,
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
    magic: &[u8; 8],
    version: u16,
    exact_plan_bytes: Option<usize>,
    allocation_bytes: Option<usize>,
) -> Result<Vec<u8>, String> {
    if exact_plan_bytes.is_some_and(|expected| installed.operation_plan_artifact.len() != expected)
        || installed.operation_plan_artifact.is_empty()
        || installed.operation_plan_artifact.len() > C61_CANONICAL_OPERATION_PLAN_BYTES
        || quantization_digest == [0; 32]
    {
        return Err("campaign operation-plan byte census mismatch".to_owned());
    }
    let source_manifest = encode_source_manifest(&installed.source_manifest)?;
    let verifier_model =
        encode_verifier_model_canonical(verifier_model).map_err(|error| error.to_string())?;
    if verifier_model.len() > VERIFIER_MODEL_SETUP_MAX_BYTES {
        return Err("C6.1 verifier model exceeds its setup allocation".to_owned());
    }
    let compiler_profile = installed.compiler_profile.encode()?;
    let components: [&[u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS] = [
        &source_manifest,
        installed.operation_plan_artifact.as_bytes(),
        installed.verifier_extraction_artifact.as_bytes(),
        installed.native_profile_artifact.as_bytes(),
        &verifier_model,
        &quantization_digest,
        &compiler_profile,
    ];
    let header_bytes = magic.len() + 4 + CAMPAIGN_CLIENT_PARAMETER_COMPONENTS * (8 + 32);
    let used = components.iter().try_fold(header_bytes, |total, component| {
        total
            .checked_add(component.len())
            .ok_or_else(|| "C6.1 client-parameter length overflows".to_owned())
    })?;
    if used > allocation_bytes.unwrap_or(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES) {
        return Err("client parameters exceed their setup allocation".to_owned());
    }
    let mut bytes = Vec::with_capacity(allocation_bytes.unwrap_or(used));
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    for component in &components {
        bytes.extend_from_slice(
            &u64::try_from(component.len())
                .map_err(|_| "C6.1 client-parameter component exceeds u64".to_owned())?
                .to_le_bytes(),
        );
    }
    for component in &components {
        bytes.extend_from_slice(blake3::hash(component).as_bytes());
    }
    for component in components {
        bytes.extend_from_slice(component);
    }
    if let Some(allocation_bytes) = allocation_bytes {
        bytes.resize(allocation_bytes, 0);
    }
    Ok(bytes)
}

pub fn encode_c61_campaign_client_parameters(
    installed: &C61CampaignInstalledSetup,
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    encode_campaign_client_parameters_with_plan_limit(
        installed,
        verifier_model,
        quantization_digest,
        CAMPAIGN_CLIENT_PARAMETERS_MAGIC,
        CAMPAIGN_CLIENT_PARAMETERS_VERSION,
        Some(C61_CANONICAL_OPERATION_PLAN_BYTES),
        Some(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES),
    )
}

fn c62_client_parameter_outer_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher =
        blake3::Hasher::new_derive_key("volta-zk/c6.2/client-parameters/zstd-envelope/v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn encode_c62_client_parameter_envelope(inner: &[u8]) -> Result<Vec<u8>, String> {
    let compressed = zstd::bulk::compress(inner, C62_CAMPAIGN_CLIENT_PARAMETERS_ZSTD_LEVEL)
        .map_err(|error| format!("compress C6.2 client parameters: {error}"))?;
    let encoded_len = C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES
        .checked_add(compressed.len())
        .and_then(|length| length.checked_add(C62_CAMPAIGN_CLIENT_PARAMETERS_TRAILER_BYTES))
        .ok_or_else(|| "C6.2 client-parameter envelope length overflows".to_owned())?;
    let mut bytes = Vec::with_capacity(encoded_len);
    bytes.extend_from_slice(C62_CAMPAIGN_CLIENT_PARAMETERS_MAGIC);
    bytes.extend_from_slice(&C62_CAMPAIGN_CLIENT_PARAMETERS_VERSION.to_le_bytes());
    bytes.extend_from_slice(
        &u16::try_from(C62_CAMPAIGN_CLIENT_PARAMETERS_ZSTD_LEVEL)
            .map_err(|_| "C6.2 Zstandard level exceeds u16".to_owned())?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u64::try_from(inner.len())
            .map_err(|_| "C6.2 inner client parameters exceed u64".to_owned())?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u64::try_from(compressed.len())
            .map_err(|_| "C6.2 compressed client parameters exceed u64".to_owned())?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(blake3::hash(inner).as_bytes());
    bytes.extend_from_slice(blake3::hash(&compressed).as_bytes());
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(&c62_client_parameter_outer_digest(&bytes));
    if bytes.len() != encoded_len {
        return Err("C6.2 client-parameter envelope census changed".to_owned());
    }
    Ok(bytes)
}

fn decode_c62_client_parameter_envelope(
    bytes: &[u8],
    expected_inner_bytes: Option<usize>,
    inner_max_bytes: usize,
    envelope_max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let minimum =
        C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES + C62_CAMPAIGN_CLIENT_PARAMETERS_TRAILER_BYTES;
    if bytes.len() < minimum
        || bytes.len() > envelope_max_bytes
        || bytes.get(..8) != Some(C62_CAMPAIGN_CLIENT_PARAMETERS_MAGIC)
        || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed C62CP1 version"))
            != C62_CAMPAIGN_CLIENT_PARAMETERS_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().expect("fixed C62CP1 level"))
            != C62_CAMPAIGN_CLIENT_PARAMETERS_ZSTD_LEVEL as u16
    {
        return Err("C6.2 client-parameter envelope header/profile mismatch".to_owned());
    }
    let inner_len = usize::try_from(u64::from_le_bytes(
        bytes[12..20].try_into().expect("fixed C62CP1 inner length"),
    ))
    .map_err(|_| "C6.2 inner client-parameter length exceeds usize".to_owned())?;
    let compressed_len = usize::try_from(u64::from_le_bytes(
        bytes[20..28].try_into().expect("fixed C62CP1 compressed length"),
    ))
    .map_err(|_| "C6.2 compressed client-parameter length exceeds usize".to_owned())?;
    let payload_end = C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES
        .checked_add(compressed_len)
        .ok_or_else(|| "C6.2 compressed client-parameter offset overflows".to_owned())?;
    if inner_len > inner_max_bytes
        || expected_inner_bytes.is_some_and(|expected| inner_len != expected)
        || payload_end.checked_add(C62_CAMPAIGN_CLIENT_PARAMETERS_TRAILER_BYTES)
            != Some(bytes.len())
    {
        return Err("C6.2 client-parameter envelope length mismatch".to_owned());
    }
    let payload = &bytes[C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES..payload_end];
    let inner = zstd::bulk::decompress(payload, inner_len)
        .map_err(|error| format!("decompress C6.2 client parameters: {error}"))?;
    if inner.len() != inner_len
        || bytes[28..60] != *blake3::hash(&inner).as_bytes()
        || bytes[60..92] != *blake3::hash(payload).as_bytes()
        || bytes[payload_end..] != c62_client_parameter_outer_digest(&bytes[..payload_end])
    {
        return Err("C6.2 client-parameter envelope digest mismatch".to_owned());
    }
    if zstd::bulk::compress(&inner, C62_CAMPAIGN_CLIENT_PARAMETERS_ZSTD_LEVEL)
        .map_err(|error| format!("recompress C6.2 client parameters: {error}"))?
        != payload
    {
        return Err("C6.2 client-parameter envelope is noncanonical".to_owned());
    }
    Ok(inner)
}

fn c62_profile_index(old_context: u32) -> Result<usize, String> {
    C62_CAMPAIGN_PROFILE_IDS
        .iter()
        .position(|candidate| *candidate == old_context)
        .ok_or_else(|| "C6.2 workload has no registered setup profile".to_owned())
}

fn c62_installed_profile_matches(index: usize, installed: &C61CampaignInstalledSetup) -> bool {
    c62_profile_topology_matches(index, installed.verifier_plan.topology())
}

fn c62_profile_topology_matches(index: usize, topology: C6OperationPlanTopologyIdentity) -> bool {
    C62_CAMPAIGN_PROFILE_IDS
        .get(index)
        .is_some_and(|&old_context| campaign_profile_topology_matches(old_context, topology))
}

fn campaign_profile_topology_matches(
    old_context: u32,
    topology: C6OperationPlanTopologyIdentity,
) -> bool {
    let measured = (
        topology.source_count,
        topology.canonical_node_count,
        topology.public_input_count,
        topology.scalar_input_count,
        topology.product_closure_count,
        topology.product_triple_count,
        topology.zero_root_count,
    );
    let expected = match old_context {
        0 => (5_119_131, 17_894_474, 2_093, 6_458_502, 673, 29_620, 10_909),
        150 | 200 => (1_992_912, 7_082_024, 2_093, 2_599_883, 673, 27_073, 10_060),
        250..=450 if old_context % 50 == 0 => {
            (1_997_712, 7_104_920, 2_093, 2_611_091, 673, 27_361, 10_156)
        }
        500..=900 if old_context % 50 == 0 => {
            (2_002_704, 7_128_872, 2_093, 2_622_875, 673, 27_649, 10_252)
        }
        _ => return false,
    };
    topology.version == 2 && measured == expected
}

fn encode_c62_campaign_profile_bundle(
    installed: [&C61CampaignInstalledSetup; C62_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut profiles = Vec::with_capacity(C62_CAMPAIGN_PROFILE_COUNT);
    for (index, profile) in installed.into_iter().enumerate() {
        if !c62_installed_profile_matches(index, profile) {
            return Err(format!("C6.2 installed setup profile {index} has the wrong topology"));
        }
        profiles.push(encode_campaign_client_parameters_with_plan_limit(
            profile,
            verifier_model,
            quantization_digest,
            C62_CAMPAIGN_PROFILE_MAGIC,
            C62_CAMPAIGN_PROFILE_VERSION,
            None,
            None,
        )?);
    }
    let profile_bytes = profiles.iter().try_fold(0usize, |total, profile| {
        total.checked_add(profile.len()).ok_or_else(|| "C6.2 profile bundle overflows".to_owned())
    })?;
    let bundle_bytes = C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
        .checked_add(profile_bytes)
        .ok_or_else(|| "C6.2 profile bundle length overflows".to_owned())?;
    let mut bundle = Vec::with_capacity(bundle_bytes);
    bundle.extend_from_slice(C62_CAMPAIGN_PROFILE_BUNDLE_MAGIC);
    bundle.extend_from_slice(&C62_CAMPAIGN_PROFILE_BUNDLE_VERSION.to_le_bytes());
    bundle.extend_from_slice(&(C62_CAMPAIGN_PROFILE_COUNT as u16).to_le_bytes());
    for profile in C62_CAMPAIGN_PROFILE_IDS {
        bundle.extend_from_slice(&profile.to_le_bytes());
    }
    for profile in &profiles {
        bundle.extend_from_slice(
            &u64::try_from(profile.len())
                .map_err(|_| "C6.2 setup profile length exceeds u64".to_owned())?
                .to_le_bytes(),
        );
    }
    for profile in &profiles {
        bundle.extend_from_slice(blake3::hash(profile).as_bytes());
    }
    for profile in profiles {
        bundle.extend_from_slice(&profile);
    }
    if bundle.len() != bundle_bytes || bundle.len() > C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES {
        return Err("C6.2 setup profile bundle byte census changed".to_owned());
    }
    Ok(bundle)
}

fn encode_c64_campaign_profile_bundle(
    installed: [&C61CampaignInstalledSetup; C64_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut profiles = Vec::with_capacity(C64_CAMPAIGN_PROFILE_COUNT);
    for (old_context, profile) in C64_CAMPAIGN_PROFILE_IDS.into_iter().zip(installed) {
        if !campaign_profile_topology_matches(old_context, profile.verifier_plan.topology()) {
            return Err(format!(
                "C6.4 installed setup profile {old_context} has the wrong topology"
            ));
        }
        profiles.push(encode_campaign_client_parameters_with_plan_limit(
            profile,
            verifier_model,
            quantization_digest,
            C62_CAMPAIGN_PROFILE_MAGIC,
            C62_CAMPAIGN_PROFILE_VERSION,
            None,
            None,
        )?);
    }
    let profile_bytes = profiles.iter().try_fold(0usize, |total, profile| {
        total.checked_add(profile.len()).ok_or_else(|| "C6.4 profile bundle overflows".to_owned())
    })?;
    let bundle_bytes = C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
        .checked_add(profile_bytes)
        .ok_or_else(|| "C6.4 profile bundle length overflows".to_owned())?;
    let mut bundle = Vec::with_capacity(bundle_bytes);
    bundle.extend_from_slice(C64_CAMPAIGN_PROFILE_BUNDLE_MAGIC);
    bundle.extend_from_slice(&C64_CAMPAIGN_PROFILE_BUNDLE_VERSION.to_le_bytes());
    bundle.extend_from_slice(&(C64_CAMPAIGN_PROFILE_COUNT as u16).to_le_bytes());
    for profile in C64_CAMPAIGN_PROFILE_IDS {
        bundle.extend_from_slice(&profile.to_le_bytes());
    }
    for profile in &profiles {
        bundle.extend_from_slice(
            &u64::try_from(profile.len())
                .map_err(|_| "C6.4 setup profile length exceeds u64".to_owned())?
                .to_le_bytes(),
        );
    }
    for profile in &profiles {
        bundle.extend_from_slice(blake3::hash(profile).as_bytes());
    }
    for profile in profiles {
        bundle.extend_from_slice(&profile);
    }
    if bundle.len() != bundle_bytes || bundle.len() > C64_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES {
        return Err("C6.4 setup profile bundle byte census changed".to_owned());
    }
    Ok(bundle)
}

fn c62_campaign_profile_bundle_slices(
    bundle: &[u8],
) -> Result<[&[u8]; C62_CAMPAIGN_PROFILE_COUNT], String> {
    if bundle.len() < C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
        || bundle.len() > C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES
        || bundle.get(..8) != Some(C62_CAMPAIGN_PROFILE_BUNDLE_MAGIC)
        || u16::from_le_bytes(bundle[8..10].try_into().expect("fixed profile version"))
            != C62_CAMPAIGN_PROFILE_BUNDLE_VERSION
        || usize::from(u16::from_le_bytes(bundle[10..12].try_into().expect("fixed profile count")))
            != C62_CAMPAIGN_PROFILE_COUNT
    {
        return Err("C6.2 setup profile bundle header or length differs".to_owned());
    }
    let mut cursor = 12;
    for expected in C62_CAMPAIGN_PROFILE_IDS {
        let actual = u32::from_le_bytes(
            bundle[cursor..cursor + 4].try_into().expect("fixed profile identifier"),
        );
        cursor += 4;
        if actual != expected {
            return Err("C6.2 setup profile order differs".to_owned());
        }
    }
    let mut lengths = [0usize; C62_CAMPAIGN_PROFILE_COUNT];
    for length in &mut lengths {
        *length = usize::try_from(u64::from_le_bytes(
            bundle[cursor..cursor + 8].try_into().expect("fixed profile length"),
        ))
        .map_err(|_| "C6.2 setup profile length exceeds usize".to_owned())?;
        cursor += 8;
        if *length == 0 || *length > C62_CAMPAIGN_PROFILE_MAX_BYTES {
            return Err("C6.2 setup profile length is outside its allocation".to_owned());
        }
    }
    let digest_start = cursor;
    cursor += 32 * C62_CAMPAIGN_PROFILE_COUNT;
    debug_assert_eq!(cursor, C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES);
    let mut profiles = Vec::with_capacity(C62_CAMPAIGN_PROFILE_COUNT);
    for (index, length) in lengths.into_iter().enumerate() {
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| "C6.2 setup profile offset overflows".to_owned())?;
        let profile =
            bundle.get(cursor..end).ok_or_else(|| "C6.2 setup profile is truncated".to_owned())?;
        let expected = &bundle[digest_start + 32 * index..digest_start + 32 * (index + 1)];
        if blake3::hash(profile).as_bytes() != expected {
            return Err(format!("C6.2 setup profile {index} digest differs"));
        }
        profiles.push(profile);
        cursor = end;
    }
    if cursor != bundle.len() {
        return Err("C6.2 setup profile bundle has trailing bytes".to_owned());
    }
    let profiles: [&[u8]; C62_CAMPAIGN_PROFILE_COUNT] =
        profiles.try_into().map_err(|_| "C6.2 setup profile census differs".to_owned())?;
    let mut verifier_model_digest = None;
    let mut quantization = None;
    for profile in profiles {
        let components = c62_campaign_client_parameter_components(profile)?;
        let model_digest = *blake3::hash(components[4]).as_bytes();
        if verifier_model_digest.replace(model_digest).is_some_and(|prior| prior != model_digest)
            || quantization
                .replace(components[5])
                .is_some_and(|prior: &[u8]| prior != components[5])
        {
            return Err("C6.2 setup profiles do not share one model and quantization".to_owned());
        }
    }
    Ok(profiles)
}

fn c64_campaign_profile_bundle_slices(
    bundle: &[u8],
) -> Result<[&[u8]; C64_CAMPAIGN_PROFILE_COUNT], String> {
    if bundle.len() < C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES
        || bundle.len() > C64_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES
        || bundle.get(..8) != Some(C64_CAMPAIGN_PROFILE_BUNDLE_MAGIC)
        || u16::from_le_bytes(bundle[8..10].try_into().expect("fixed profile version"))
            != C64_CAMPAIGN_PROFILE_BUNDLE_VERSION
        || usize::from(u16::from_le_bytes(bundle[10..12].try_into().expect("fixed profile count")))
            != C64_CAMPAIGN_PROFILE_COUNT
    {
        return Err("C6.4 setup profile bundle header or length differs".to_owned());
    }
    let mut cursor = 12;
    for expected in C64_CAMPAIGN_PROFILE_IDS {
        let actual = u32::from_le_bytes(
            bundle[cursor..cursor + 4].try_into().expect("fixed profile identifier"),
        );
        cursor += 4;
        if actual != expected {
            return Err("C6.4 setup profile order differs".to_owned());
        }
    }
    let mut lengths = [0usize; C64_CAMPAIGN_PROFILE_COUNT];
    for length in &mut lengths {
        *length = usize::try_from(u64::from_le_bytes(
            bundle[cursor..cursor + 8].try_into().expect("fixed profile length"),
        ))
        .map_err(|_| "C6.4 setup profile length exceeds usize".to_owned())?;
        cursor += 8;
        if *length == 0 || *length > C62_CAMPAIGN_PROFILE_MAX_BYTES {
            return Err("C6.4 setup profile length is outside its allocation".to_owned());
        }
    }
    let digest_start = cursor;
    cursor += 32 * C64_CAMPAIGN_PROFILE_COUNT;
    debug_assert_eq!(cursor, C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES);
    let mut profiles = Vec::with_capacity(C64_CAMPAIGN_PROFILE_COUNT);
    for (index, length) in lengths.into_iter().enumerate() {
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| "C6.4 setup profile offset overflows".to_owned())?;
        let profile =
            bundle.get(cursor..end).ok_or_else(|| "C6.4 setup profile is truncated".to_owned())?;
        let expected = &bundle[digest_start + 32 * index..digest_start + 32 * (index + 1)];
        if blake3::hash(profile).as_bytes() != expected {
            return Err(format!("C6.4 setup profile {index} digest differs"));
        }
        profiles.push(profile);
        cursor = end;
    }
    if cursor != bundle.len() {
        return Err("C6.4 setup profile bundle has trailing bytes".to_owned());
    }
    let profiles: [&[u8]; C64_CAMPAIGN_PROFILE_COUNT] =
        profiles.try_into().map_err(|_| "C6.4 setup profile census differs".to_owned())?;
    let mut verifier_model_digest = None;
    let mut quantization = None;
    for profile in profiles {
        let components = c62_campaign_client_parameter_components(profile)?;
        let model_digest = *blake3::hash(components[4]).as_bytes();
        if verifier_model_digest.replace(model_digest).is_some_and(|prior| prior != model_digest)
            || quantization
                .replace(components[5])
                .is_some_and(|prior: &[u8]| prior != components[5])
        {
            return Err("C6.4 setup profiles do not share one model and quantization".to_owned());
        }
    }
    Ok(profiles)
}

/// Compress 17 variable-length C62SP1 profiles into one C62CP1 bundle.
pub fn encode_c62_campaign_client_parameters(
    installed: [&C61CampaignInstalledSetup; C62_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    let inner = encode_c62_campaign_profile_bundle(installed, verifier_model, quantization_digest)?;
    let encoded = encode_c62_client_parameter_envelope(&inner)?;
    if encoded.len() > C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES {
        return Err("C6.2 client parameters exceed their compressed setup cap".to_owned());
    }
    Ok(encoded)
}

pub fn encode_c64_campaign_client_parameters(
    installed: [&C61CampaignInstalledSetup; C64_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    let inner = encode_c64_campaign_profile_bundle(installed, verifier_model, quantization_digest)?;
    let encoded = encode_c62_client_parameter_envelope(&inner)?;
    if encoded.len() > C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES {
        return Err("C6.4 client parameters exceed their compressed setup cap".to_owned());
    }
    Ok(encoded)
}

/// Build the exact client setup object consumed by both the real/AES PCG
/// reservation and the later disk verifier.
#[allow(clippy::too_many_arguments)]
pub fn build_c61_campaign_setup_manifest(
    installed: &C61CampaignInstalledSetup,
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
    protocol_digest: [u8; 32],
    model_digest: [u8; 32],
    params_digest: [u8; 32],
    connection_id: [u8; 32],
    tape_ids: [[u8; 32]; 2],
) -> Result<C6SetupManifest, String> {
    let client_parameters =
        encode_c61_campaign_client_parameters(installed, verifier_model, quantization_digest)?;
    let setup = C6SetupManifest::production(
        protocol_digest,
        model_digest,
        params_digest,
        connection_id,
        tape_ids,
        client_parameters,
    )
    .map_err(|error| error.to_string())?;
    if setup.first_exchange_bytes().map_err(|error| error.to_string())? != C61_CAMPAIGN_SETUP_BYTES
    {
        return Err("C6.1 constructed setup byte census mismatch".to_owned());
    }
    Ok(setup)
}

/// Build the C6.2 setup with one strict compressed client-parameter object.
#[allow(clippy::too_many_arguments)]
pub fn build_c62_campaign_setup_manifest(
    installed: [&C61CampaignInstalledSetup; C62_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
    protocol_digest: [u8; 32],
    model_digest: [u8; 32],
    params_digest: [u8; 32],
    connection_id: [u8; 32],
    tape_ids: [[u8; 32]; 2],
) -> Result<C6SetupManifest, String> {
    let client_parameters =
        encode_c62_campaign_client_parameters(installed, verifier_model, quantization_digest)?;
    let setup = C6SetupManifest::production(
        protocol_digest,
        model_digest,
        params_digest,
        connection_id,
        tape_ids,
        client_parameters,
    )
    .map_err(|error| error.to_string())?;
    if setup.first_exchange_bytes().map_err(|error| error.to_string())?
        > C62_CAMPAIGN_SETUP_MAX_BYTES
    {
        return Err("C6.2 constructed setup exceeds its compressed cap".to_owned());
    }
    Ok(setup)
}

#[allow(clippy::too_many_arguments)]
pub fn build_c64_campaign_setup_manifest(
    installed: [&C61CampaignInstalledSetup; C64_CAMPAIGN_PROFILE_COUNT],
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
    protocol_digest: [u8; 32],
    model_digest: [u8; 32],
    params_digest: [u8; 32],
    connection_id: [u8; 32],
    tape_ids: [[u8; 32]; 2],
) -> Result<C6SetupManifest, String> {
    let client_parameters =
        encode_c64_campaign_client_parameters(installed, verifier_model, quantization_digest)?;
    let setup = C6SetupManifest::production(
        protocol_digest,
        model_digest,
        params_digest,
        connection_id,
        tape_ids,
        client_parameters,
    )
    .map_err(|error| error.to_string())?;
    if setup.first_exchange_bytes().map_err(|error| error.to_string())?
        > C62_CAMPAIGN_SETUP_MAX_BYTES
    {
        return Err("C6.4 constructed setup exceeds its compressed cap".to_owned());
    }
    Ok(setup)
}

fn campaign_client_parameter_components<'a>(
    bytes: &'a [u8],
    magic: &[u8; 8],
    version: u16,
    exact_total_bytes: Option<usize>,
    exact_plan_bytes: Option<usize>,
) -> Result<[&'a [u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS], String> {
    let header_bytes = magic.len() + 4 + CAMPAIGN_CLIENT_PARAMETER_COMPONENTS * (8 + 32);
    if bytes.len() < header_bytes
        || exact_total_bytes.is_some_and(|expected| bytes.len() != expected)
        || bytes.get(..8) != Some(magic)
        || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed width")) != version
        || bytes[10..12] != [0, 0]
    {
        return Err("C6.1 client-parameter header/profile mismatch".to_owned());
    }
    let mut lengths = [0usize; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS];
    let mut cursor = 12;
    for length in &mut lengths {
        *length = usize::try_from(u64::from_le_bytes(
            bytes[cursor..cursor + 8].try_into().expect("fixed width"),
        ))
        .map_err(|_| "C6.1 client-parameter component exceeds usize".to_owned())?;
        cursor += 8;
    }
    if lengths[1] == 0
        || lengths[1] > C61_CANONICAL_OPERATION_PLAN_BYTES
        || exact_plan_bytes.is_some_and(|expected| lengths[1] != expected)
        || lengths[4] > VERIFIER_MODEL_SETUP_MAX_BYTES
        || lengths[5] != 32
    {
        return Err("C6.1 client-parameter component census mismatch".to_owned());
    }
    let digest_start = cursor;
    cursor = header_bytes;
    let mut components = [&[][..]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS];
    for (index, length) in lengths.into_iter().enumerate() {
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| "C6.1 client-parameter offset overflows".to_owned())?;
        let component = bytes
            .get(cursor..end)
            .ok_or_else(|| "truncated C6.1 client-parameter component".to_owned())?;
        let claimed = &bytes[digest_start + index * 32..digest_start + (index + 1) * 32];
        if blake3::hash(component).as_bytes() != claimed {
            return Err("C6.1 client-parameter component digest mismatch".to_owned());
        }
        components[index] = component;
        cursor = end;
    }
    if exact_total_bytes.is_some() {
        if bytes[cursor..].iter().any(|byte| *byte != 0) {
            return Err("C6.1 client-parameter padding is nonzero".to_owned());
        }
    } else if cursor != bytes.len() {
        return Err("C6.2 client profile has trailing bytes".to_owned());
    }
    Ok(components)
}

fn c61_campaign_client_parameter_components(
    bytes: &[u8],
) -> Result<[&[u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS], String> {
    campaign_client_parameter_components(
        bytes,
        CAMPAIGN_CLIENT_PARAMETERS_MAGIC,
        CAMPAIGN_CLIENT_PARAMETERS_VERSION,
        Some(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES),
        Some(C61_CANONICAL_OPERATION_PLAN_BYTES),
    )
}

fn c62_campaign_client_parameter_components(
    bytes: &[u8],
) -> Result<[&[u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS], String> {
    campaign_client_parameter_components(
        bytes,
        C62_CAMPAIGN_PROFILE_MAGIC,
        C62_CAMPAIGN_PROFILE_VERSION,
        None,
        None,
    )
}

/// Construct the pre-response statement only from identities already fixed
/// by setup, reservation and the typed public workload. In particular the
/// quantization and plan digests are not caller-authored values.
#[allow(clippy::too_many_arguments)]
pub fn build_c61_campaign_response_statement(
    setup: &C6SetupManifest,
    plan: &C6InstalledOperationPlan,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    workload: &C61PublicWorkloadPreimage,
) -> Result<C61ResponseStatementBinding, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let components = c61_campaign_client_parameter_components(&setup.client_parameters)?;
    if *blake3::hash(components[1]).as_bytes() != plan.artifact_digest()
        || workload.model_family_digest() != setup.model_digest
        || workload.workload() != attempt.workload
    {
        return Err(
            "C6ICT4 response statement plan/model/workload differs from installed setup".to_owned()
        );
    }
    let quantization_digest: [u8; 32] =
        components[5].try_into().expect("validated C6.1 quantization digest length");
    C61ResponseStatementBinding::new(
        setup,
        quantization_digest,
        plan,
        attempt,
        old_head,
        proposed_head,
        workload.digest(),
    )
    .map_err(|error| error.to_string())
}

/// Derive the response statement after strict C62CP1 restoration.
#[allow(clippy::too_many_arguments)]
pub fn build_c62_campaign_response_statement(
    setup: &C6SetupManifest,
    plan: &C6InstalledOperationPlan,
    attempt: C6ClientAttempt,
    old_head: C6CacheHead,
    proposed_head: C6ProposedCacheHead,
    workload: &C61PublicWorkloadPreimage,
) -> Result<C61ResponseStatementBinding, String> {
    setup.validate().map_err(|error| error.to_string())?;
    let bundle = decode_c62_client_parameter_envelope(
        &setup.client_parameters,
        None,
        C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES,
        C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES,
    )?;
    let profiles = c62_campaign_profile_bundle_slices(&bundle)?;
    let profile_index = c62_profile_index(workload.workload().old_context)?;
    let inner = profiles[profile_index];
    let components = c62_campaign_client_parameter_components(&inner)?;
    if *blake3::hash(components[1]).as_bytes() != plan.artifact_digest()
        || !c62_profile_topology_matches(profile_index, plan.topology())
        || workload.model_family_digest() != setup.model_digest
        || workload.workload() != attempt.workload
    {
        return Err("C6.2 response statement differs from installed setup".to_owned());
    }
    let quantization_digest: [u8; 32] =
        components[5].try_into().expect("validated C6.2 quantization digest length");
    C61ResponseStatementBinding::new(
        setup,
        quantization_digest,
        plan,
        attempt,
        old_head,
        proposed_head,
        workload.digest(),
    )
    .map_err(|error| error.to_string())
}

fn decode_c61_campaign_client_parameters(
    bytes: &[u8],
) -> Result<DecodedCampaignClientParameters, String> {
    let components = c61_campaign_client_parameter_components(bytes)?;
    decode_campaign_client_parameters_from_components(components)
}

fn decode_c62_campaign_profile(bytes: &[u8]) -> Result<DecodedCampaignClientParameters, String> {
    let components = c62_campaign_client_parameter_components(bytes)?;
    decode_campaign_client_parameters_from_components(components)
}

fn decode_campaign_client_parameters_from_components(
    components: [&[u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS],
) -> Result<DecodedCampaignClientParameters, String> {
    let source_manifest = decode_source_manifest(components[0])?;
    let operation_plan = C6OperationPlanArtifact::parse(components[1].to_vec(), &source_manifest)
        .map_err(|error| format!("decode C6.1 client operation plan: {error}"))?;
    let topology = operation_plan
        .decode(&source_manifest)
        .map_err(|error| format!("inspect C6.1 client operation plan: {error}"))?
        .topology;
    let verifier_extraction_artifact =
        C6InstanceExtractionArtifact::parse(components[2].to_vec(), topology)
            .map_err(|error| format!("parse C6.1 client verifier extraction: {error}"))?;
    let verifier_extraction = verifier_extraction_artifact
        .decode(topology)
        .map_err(|error| format!("decode C6.1 client verifier extraction: {error}"))?;
    if verifier_extraction.role() != C6InstanceExtractionRole::Verifier {
        return Err("C6.1 client setup contains a non-verifier extraction map".to_owned());
    }
    let (_, native_profile) = C6NativeTargetProfileArtifact::decode(components[3], topology)
        .map_err(|error| format!("decode C6.1 client native-target profile: {error}"))?;
    let verifier_model =
        decode_verifier_model_canonical(components[4]).map_err(|error| error.to_string())?;
    let quantization_digest: [u8; 32] =
        components[5].try_into().expect("validated C6.1 quantization digest length");
    if quantization_digest == [0; 32] {
        return Err("C6.1 client setup contains a zero quantization digest".to_owned());
    }
    let verifier_plan = operation_plan
        .clone()
        .install(&source_manifest)
        .map_err(|error| format!("install C6.1 client verifier plan: {error}"))?;
    let compiler_profile = C61CompilerVerifierProfile::decode(
        components[6],
        verifier_plan.topology(),
        &source_manifest,
    )?;
    Ok(DecodedCampaignClientParameters {
        verifier_model,
        source_manifest,
        operation_plan_artifact: operation_plan,
        verifier_extraction_artifact,
        verifier_plan,
        verifier_extraction,
        verifier_extraction_setup_bytes: u64::try_from(components[2].len())
            .map_err(|_| "C6.1 verifier extraction length exceeds u64".to_owned())?,
        native_profile,
        compiler_profile,
        quantization_digest,
    })
}

pub(crate) fn decode_c62_campaign_client_parameters(
    bytes: &[u8],
    old_context: u32,
) -> Result<DecodedCampaignClientParameters, String> {
    let bundle = decode_c62_client_parameter_envelope(
        bytes,
        None,
        C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES,
        C62_CAMPAIGN_CLIENT_PARAMETERS_MAX_BYTES,
    )?;
    if bundle.get(..8) == Some(C64_CAMPAIGN_PROFILE_BUNDLE_MAGIC) {
        let index = C64_CAMPAIGN_PROFILE_IDS
            .iter()
            .position(|&candidate| candidate == old_context)
            .ok_or_else(|| "C6.4 workload has no registered setup profile".to_owned())?;
        let profiles = c64_campaign_profile_bundle_slices(&bundle)?;
        let decoded = decode_c62_campaign_profile(profiles[index])?;
        if !campaign_profile_topology_matches(old_context, decoded.verifier_plan.topology()) {
            return Err("C6.4 selected client setup has the wrong topology".to_owned());
        }
        return Ok(decoded);
    }
    let index = c62_profile_index(old_context)?;
    let profiles = c62_campaign_profile_bundle_slices(&bundle)?;
    let decoded = decode_c62_campaign_profile(profiles[index])?;
    if !c62_profile_topology_matches(index, decoded.verifier_plan.topology()) {
        return Err("C6.2 selected client setup has the wrong topology".to_owned());
    }
    Ok(decoded)
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn validate_source_commit(commit: &str) -> Result<(), String> {
    if commit.len() != 40
        || commit.bytes().any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err("C6.1 campaign source commit is not a full lowercase git digest".to_owned());
    }
    Ok(())
}

fn validate_campaign_statement_domains(
    response: [u8; 32],
    wrapper_base: [u8; 32],
    final_outer: [u8; 32],
) -> Result<(), String> {
    if [response, wrapper_base, final_outer].contains(&[0; 32])
        || response == wrapper_base
        || response == final_outer
        || wrapper_base == final_outer
    {
        return Err(
            "C6.1 response, wrapper-base and final-outer statements are not distinct".to_owned()
        );
    }
    Ok(())
}

fn validate_campaign_bindings(
    certificate: &C61NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    challenge_tapes: &C61InteractiveTapeBundle,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
) -> Result<C61JointPublicArgument, String> {
    let inner = certificate;
    let certificate_digest = inner.digest().map_err(|error| error.to_string())?;
    let setup_manifest_digest = setup_manifest.digest().map_err(|error| error.to_string())?;
    let public_argument = C61JointPublicArgument::decode(certificate.public_argument())
        .map_err(|error| error.to_string())?;
    let wrapper = certificate.wrapper;
    validate_campaign_statement_domains(
        public_instance.response_statement_digest(),
        wrapper.statement_digest,
        public_argument.statement_digest(),
    )?;
    let attempt = C6ClientAttempt {
        slot: inner.slot,
        nonce: inner.nonce,
        setup_manifest_digest: inner.setup_manifest_digest,
        old_head_digest: inner.old_head.digest(),
        predecessor_certificate_digest: inner.predecessor_certificate_digest,
        correlation_ranges: inner.correlation_ranges,
        workload: inner.workload,
    };
    challenge_tapes.validate_attempt(attempt, certificate_digest)?;
    let expected_response_context = c61_response_transcript_context_digest(
        attempt,
        public_instance.response_statement_digest(),
    )?;
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.setup_manifest_digest() != setup_manifest_digest
        || setup_manifest_digest != inner.setup_manifest_digest
        || setup_manifest.protocol_digest != inner.protocol_digest
        || setup_manifest.model_digest != inner.model_digest
        || setup_manifest.params_digest != inner.params_digest
        || setup_manifest.connection_id != inner.connection_id
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || public_argument.statement_digest() != public_instance.public_argument_statement_digest()
        || inner.model_digest != public_instance.model_family_digest()
        || inner.workload != public_instance.workload()
        || challenge_tapes.response_tape().context_digest() != expected_response_context
    {
        return Err(
            "C6.1 campaign objects do not share one certificate/setup/statement/workload binding"
                .to_owned(),
        );
    }
    Ok(public_argument)
}

fn decode_campaign_payloads(payloads: &CampaignPayloads) -> Result<C61CampaignArtifact, String> {
    if payloads.public_instance.len() > PUBLIC_INSTANCE_MAX_BYTES {
        return Err("C6.1 campaign private/setup/public-local artifact size mismatch".to_owned());
    }
    let certificate = C61NativeFinalCertificate::decode(&payloads.certificate)
        .map_err(|error| error.to_string())?;
    let verifier_replay =
        C6BoundProductionVerifierReplay::decode_client_state(&payloads.verifier_replay)?;
    let challenge_tapes = C61InteractiveTapeBundle::decode(&payloads.challenge_tapes)?;
    let setup_manifest =
        C6SetupManifest::decode(&payloads.setup_manifest).map_err(|error| error.to_string())?;
    if setup_manifest.first_exchange_bytes().map_err(|error| error.to_string())?
        != C61_CAMPAIGN_SETUP_BYTES
    {
        return Err("C6.1 campaign setup byte census mismatch".to_owned());
    }
    let client_parameters =
        decode_c61_campaign_client_parameters(&setup_manifest.client_parameters)?;
    let public_instance = C61PublicWorkloadInstance::decode(&payloads.public_instance)
        .map_err(|error| error.to_string())?;
    let public_argument = validate_campaign_bindings(
        &certificate,
        &verifier_replay,
        &challenge_tapes,
        &setup_manifest,
        &public_instance,
    )?;
    Ok(C61CampaignArtifact {
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.1 certificate length exceeds u64")?,
        certificate,
        verifier_replay,
        challenge_tapes,
        setup_manifest,
        verifier_model: client_parameters.verifier_model,
        source_manifest: client_parameters.source_manifest,
        verifier_plan: client_parameters.verifier_plan,
        verifier_extraction: client_parameters.verifier_extraction,
        native_profile: client_parameters.native_profile,
        compiler_profile: client_parameters.compiler_profile,
        quantization_digest: client_parameters.quantization_digest,
        public_instance,
        public_argument,
        source_git_commit: String::new(),
    })
}

fn campaign_rows(payloads: &CampaignPayloads) -> Result<Vec<CampaignFileRow>, String> {
    let payloads = [
        &payloads.certificate,
        &payloads.verifier_replay,
        &payloads.challenge_tapes,
        &payloads.setup_manifest,
        &payloads.public_instance,
    ];
    CAMPAIGN_FILE_NAMES
        .iter()
        .zip(payloads)
        .enumerate()
        .map(|(index, (name, bytes))| {
            Ok(CampaignFileRow {
                name: (*name).to_owned(),
                bytes: u64::try_from(bytes.len())
                    .map_err(|_| "C6.1 campaign file length exceeds u64")?,
                blake3: hex_digest(*blake3::hash(bytes).as_bytes()),
                confidential: index == 1 || index == 2,
            })
        })
        .collect()
}

fn create_file_synced(path: &Path, bytes: &[u8], confidential: bool) -> Result<(), String> {
    let mode = if confidential { 0o600 } else { 0o644 };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("create-new C6.1 campaign {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write C6.1 campaign {}: {error}", path.display()))?;
    file.sync_all().map_err(|error| format!("fsync C6.1 campaign {}: {error}", path.display()))
}

fn create_campaign_directory(
    root: &Path,
    record: &CampaignArtifactRecord,
    payloads: &CampaignPayloads,
) -> Result<(), String> {
    let manifest = serde_json::to_vec(record)
        .map_err(|error| format!("encode C6.1 campaign manifest: {error}"))?;
    fs::create_dir(root).map_err(|error| format!("create-new C6.1 campaign directory: {error}"))?;
    File::open(root.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6.1 campaign parent directory: {error}"))?;
    for (index, bytes) in [
        &payloads.certificate,
        &payloads.verifier_replay,
        &payloads.challenge_tapes,
        &payloads.setup_manifest,
        &payloads.public_instance,
    ]
    .into_iter()
    .enumerate()
    {
        create_file_synced(
            &root.join(CAMPAIGN_FILE_NAMES[index]),
            bytes,
            index == 1 || index == 2,
        )?;
    }
    // The manifest is the completion marker and is deliberately durable last.
    create_file_synced(&root.join("manifest.json"), &manifest, false)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6.1 campaign directory: {error}"))
}

/// Persist one complete provider output plus the exact client replay inputs.
/// Only `certificate.bin` is provider-to-client wire. The replay and public
/// instance are client-private/local; the complete manifest belongs to setup.
#[allow(clippy::too_many_arguments)]
pub fn create_c61_campaign_artifact(
    root: &Path,
    certificate: &C61NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    challenge_tapes: &C61InteractiveTapeBundle,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
) -> Result<(), String> {
    validate_source_commit(source_git_commit)?;
    let public_argument = validate_campaign_bindings(
        certificate,
        verifier_replay,
        challenge_tapes,
        setup_manifest,
        public_instance,
    )?;
    let payloads = CampaignPayloads {
        certificate: certificate.encode().map_err(|error| error.to_string())?,
        verifier_replay: verifier_replay.encode_client_state()?,
        challenge_tapes: challenge_tapes.encode()?,
        setup_manifest: setup_manifest.encode().map_err(|error| error.to_string())?,
        public_instance: public_instance.encode().map_err(|error| error.to_string())?,
    };
    // Exercise the same strict decode path before creating any filesystem state.
    decode_campaign_payloads(&payloads)?;
    let inner = certificate;
    let record = CampaignArtifactRecord {
        schema: 7,
        profile: CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
        source_git_commit: source_git_commit.to_owned(),
        git_dirty: false,
        backend: CAMPAIGN_BACKEND.to_owned(),
        pcg: CAMPAIGN_PCG.to_owned(),
        certificate_digest: hex_digest(inner.digest().map_err(|error| error.to_string())?),
        setup_manifest_digest: hex_digest(inner.setup_manifest_digest),
        wrapper_statement_digest: hex_digest(certificate.wrapper.statement_digest),
        public_argument_statement_digest: hex_digest(public_argument.statement_digest()),
        response_statement_digest: hex_digest(public_instance.response_statement_digest()),
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.1 certificate length exceeds u64")?,
        files: campaign_rows(&payloads)?,
    };
    create_campaign_directory(root, &record, &payloads)
}

fn validate_campaign_directory_census(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("stat C6.1 campaign directory: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("C6.1 campaign root is not a physical directory".to_owned());
    }
    let expected: BTreeSet<String> = CAMPAIGN_FILE_NAMES
        .iter()
        .copied()
        .chain(std::iter::once("manifest.json"))
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<String> = fs::read_dir(root)
        .map_err(|error| format!("read C6.1 campaign directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read C6.1 campaign entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "C6.1 campaign contains a non-UTF8 file name".to_owned())
        })
        .collect::<Result<_, _>>()?;
    if actual != expected {
        return Err("C6.1 campaign directory file census mismatch".to_owned());
    }
    for name in &expected {
        let metadata = fs::symlink_metadata(root.join(name))
            .map_err(|error| format!("stat C6.1 campaign {name}: {error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!("C6.1 campaign {name} is not a physical file"));
        }
    }
    for name in ["verifier-replay.bin", "challenge-tapes.bin"] {
        if fs::metadata(root.join(name))
            .map_err(|error| format!("stat C6.1 private replay {name}: {error}"))?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err(format!("C6.1 private replay {name} is accessible by group/other"));
        }
    }
    Ok(())
}

fn load_campaign_file(root: &Path, row: &CampaignFileRow) -> Result<Vec<u8>, String> {
    let bytes = fs::read(root.join(&row.name))
        .map_err(|error| format!("read C6.1 campaign {}: {error}", row.name))?;
    if u64::try_from(bytes.len()).ok() != Some(row.bytes)
        || hex_digest(*blake3::hash(&bytes).as_bytes()) != row.blake3
    {
        return Err(format!("C6.1 campaign {} differs from its manifest", row.name));
    }
    Ok(bytes)
}

/// Load and cross-bind an exact campaign artifact without retained provider
/// state. This is the only input boundary admitted by the disk verifier.
pub fn load_c61_campaign_artifact(root: &Path) -> Result<C61CampaignArtifact, String> {
    validate_campaign_directory_census(root)?;
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|error| format!("read C6.1 campaign manifest: {error}"))?;
    let record: CampaignArtifactRecord = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("decode C6.1 campaign manifest: {error}"))?;
    if serde_json::to_vec(&record)
        .map_err(|error| format!("re-encode C6.1 campaign manifest: {error}"))?
        != manifest_bytes
    {
        return Err("C6.1 campaign manifest is not canonical compact JSON".to_owned());
    }
    validate_source_commit(&record.source_git_commit)?;
    if record.schema != 7
        || record.profile != CAMPAIGN_ARTIFACT_PROFILE
        || record.git_dirty
        || record.backend != CAMPAIGN_BACKEND
        || record.pcg != CAMPAIGN_PCG
        || record.files.len() != CAMPAIGN_FILE_NAMES.len()
        || record.files.iter().map(|row| row.name.as_str()).ne(CAMPAIGN_FILE_NAMES)
        || record.files.iter().map(|row| row.confidential).ne([false, true, true, false, false])
    {
        return Err("C6.1 campaign manifest profile/backend/PCG/file census mismatch".to_owned());
    }
    let payloads = CampaignPayloads {
        certificate: load_campaign_file(root, &record.files[0])?,
        verifier_replay: load_campaign_file(root, &record.files[1])?,
        challenge_tapes: load_campaign_file(root, &record.files[2])?,
        setup_manifest: load_campaign_file(root, &record.files[3])?,
        public_instance: load_campaign_file(root, &record.files[4])?,
    };
    let mut artifact = decode_campaign_payloads(&payloads)?;
    let inner = &artifact.certificate;
    if record.wire_bytes != artifact.wire_bytes
        || parse_hex_32(&record.certificate_digest, "campaign certificate digest")?
            != inner.digest().map_err(|error| error.to_string())?
        || parse_hex_32(&record.setup_manifest_digest, "campaign setup digest")?
            != inner.setup_manifest_digest
        || parse_hex_32(&record.wrapper_statement_digest, "campaign wrapper-base statement digest")?
            != artifact.certificate.wrapper.statement_digest
        || parse_hex_32(
            &record.public_argument_statement_digest,
            "campaign public-argument statement digest",
        )? != artifact.public_argument.statement_digest()
        || parse_hex_32(&record.response_statement_digest, "campaign response statement digest")?
            != artifact.public_instance.response_statement_digest()
    {
        return Err("C6.1 campaign manifest binding differs from decoded objects".to_owned());
    }
    artifact.source_git_commit = record.source_git_commit;
    Ok(artifact)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn validate_c62_campaign_bindings(
    certificate: &C62NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
) -> Result<C62PublicArgument, String> {
    certificate.encode().map_err(|error| error.to_string())?;
    setup_manifest.validate().map_err(|error| error.to_string())?;
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let setup_manifest_digest = setup_manifest.digest().map_err(|error| error.to_string())?;
    let public_argument = C62PublicArgument::decode(certificate.public_argument())
        .map_err(|error| error.to_string())?;
    validate_campaign_statement_domains(
        public_instance.response_statement_digest(),
        certificate.wrapper.statement_digest,
        public_argument.statement_digest(),
    )?;
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.setup_manifest_digest() != setup_manifest_digest
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || setup_manifest_digest != certificate.setup_manifest_digest
        || setup_manifest.protocol_digest != certificate.protocol_digest
        || setup_manifest.model_digest != certificate.model_digest
        || setup_manifest.params_digest != certificate.params_digest
        || setup_manifest.connection_id != certificate.connection_id
        || public_argument.statement_digest() != public_instance.public_argument_statement_digest()
        || certificate.model_digest != public_instance.model_family_digest()
        || certificate.workload != public_instance.workload()
        || certificate.public_output_digest != public_instance.preimage().public_output_digest()
    {
        return Err(
            "C6.2 campaign objects do not share one certificate, setup, statement, and workload binding"
                .to_owned(),
        );
    }
    Ok(public_argument)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn validate_c63_campaign_bindings(
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
) -> Result<C62PublicArgument, String> {
    certificate.encode().map_err(|error| error.to_string())?;
    setup_manifest.validate().map_err(|error| error.to_string())?;
    let certificate_digest = certificate.digest().map_err(|error| error.to_string())?;
    let setup_manifest_digest = setup_manifest.digest().map_err(|error| error.to_string())?;
    let inherited = C62PublicArgument::decode(certificate.inherited_public_argument())
        .map_err(|error| error.to_string())?;
    validate_campaign_statement_domains(
        public_instance.response_statement_digest(),
        certificate.wrapper.statement_digest,
        inherited.statement_digest(),
    )?;
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.setup_manifest_digest() != setup_manifest_digest
        || verifier_replay.statement_digest() != public_instance.response_statement_digest()
        || setup_manifest_digest != certificate.setup_manifest_digest
        || setup_manifest.protocol_digest != certificate.protocol_digest
        || setup_manifest.model_digest != certificate.model_digest
        || setup_manifest.params_digest != certificate.params_digest
        || setup_manifest.connection_id != certificate.connection_id
        || inherited.statement_digest() != public_instance.public_argument_statement_digest()
        || certificate.model_digest != public_instance.model_family_digest()
        || certificate.workload != public_instance.workload()
        || certificate.public_output_digest != public_instance.preimage().public_output_digest()
    {
        return Err("C6.3 campaign objects do not share one certificate and statement".to_owned());
    }
    Ok(inherited)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn decode_c62_campaign_payloads(
    payloads: &C62CampaignPayloads,
) -> Result<C62CampaignArtifact, String> {
    if payloads.public_instance.len() > PUBLIC_INSTANCE_MAX_BYTES {
        return Err("C6.2 campaign public local artifact size differs".to_owned());
    }
    let certificate = C62NativeFinalCertificate::decode(&payloads.certificate)
        .map_err(|error| error.to_string())?;
    let verifier_replay =
        C6BoundProductionVerifierReplay::decode_client_state(&payloads.verifier_replay)?;
    let setup_manifest =
        C6SetupManifest::decode(&payloads.setup_manifest).map_err(|error| error.to_string())?;
    if setup_manifest.first_exchange_bytes().map_err(|error| error.to_string())?
        > C62_CAMPAIGN_SETUP_MAX_BYTES
    {
        return Err("C6.2 campaign setup exceeds its compressed cap".to_owned());
    }
    let public_instance = C61PublicWorkloadInstance::decode(&payloads.public_instance)
        .map_err(|error| error.to_string())?;
    let client_parameters = decode_c62_campaign_client_parameters(
        &setup_manifest.client_parameters,
        public_instance.workload().old_context,
    )?;
    let public_argument = validate_c62_campaign_bindings(
        &certificate,
        &verifier_replay,
        &setup_manifest,
        &public_instance,
    )?;
    Ok(C62CampaignArtifact {
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.2 certificate length exceeds u64")?,
        certificate,
        verifier_replay,
        setup_manifest,
        verifier_model: client_parameters.verifier_model,
        source_manifest: client_parameters.source_manifest,
        operation_plan_artifact: client_parameters.operation_plan_artifact,
        verifier_extraction_artifact: client_parameters.verifier_extraction_artifact,
        verifier_plan: client_parameters.verifier_plan,
        verifier_extraction: client_parameters.verifier_extraction,
        verifier_extraction_setup_bytes: client_parameters.verifier_extraction_setup_bytes,
        native_profile: client_parameters.native_profile,
        compiler_profile: client_parameters.compiler_profile,
        quantization_digest: client_parameters.quantization_digest,
        public_instance,
        public_argument,
        source_git_commit: String::new(),
    })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn decode_c63_campaign_payloads(
    payloads: &C62CampaignPayloads,
    expected_version: u16,
) -> Result<C63CampaignArtifact, String> {
    if payloads.public_instance.len() > PUBLIC_INSTANCE_MAX_BYTES {
        return Err("C6.3 campaign public local artifact size differs".to_owned());
    }
    let certificate = C63NativeFinalCertificate::decode(&payloads.certificate)
        .map_err(|error| error.to_string())?;
    if certificate.version != expected_version {
        return Err("C6.3/C6.4 campaign certificate version differs".to_owned());
    }
    let verifier_replay =
        C6BoundProductionVerifierReplay::decode_client_state(&payloads.verifier_replay)?;
    let setup_manifest =
        C6SetupManifest::decode(&payloads.setup_manifest).map_err(|error| error.to_string())?;
    if setup_manifest.first_exchange_bytes().map_err(|error| error.to_string())?
        > C62_CAMPAIGN_SETUP_MAX_BYTES
    {
        return Err("C6.3 campaign setup exceeds its compressed cap".to_owned());
    }
    let public_instance = C61PublicWorkloadInstance::decode(&payloads.public_instance)
        .map_err(|error| error.to_string())?;
    let client_parameters = decode_c62_campaign_client_parameters(
        &setup_manifest.client_parameters,
        public_instance.workload().old_context,
    )?;
    let inherited_public_argument = validate_c63_campaign_bindings(
        &certificate,
        &verifier_replay,
        &setup_manifest,
        &public_instance,
    )?;
    Ok(C63CampaignArtifact {
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.3 certificate length exceeds u64")?,
        certificate,
        verifier_replay,
        setup_manifest,
        verifier_model: client_parameters.verifier_model,
        source_manifest: client_parameters.source_manifest,
        operation_plan_artifact: client_parameters.operation_plan_artifact,
        verifier_extraction_artifact: client_parameters.verifier_extraction_artifact,
        verifier_plan: client_parameters.verifier_plan,
        verifier_extraction: client_parameters.verifier_extraction,
        verifier_extraction_setup_bytes: client_parameters.verifier_extraction_setup_bytes,
        native_profile: client_parameters.native_profile,
        compiler_profile: client_parameters.compiler_profile,
        quantization_digest: client_parameters.quantization_digest,
        public_instance,
        inherited_public_argument,
        source_git_commit: String::new(),
    })
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn c62_campaign_rows(payloads: &C62CampaignPayloads) -> Result<Vec<CampaignFileRow>, String> {
    let payloads = [
        &payloads.certificate,
        &payloads.verifier_replay,
        &payloads.setup_manifest,
        &payloads.public_instance,
    ];
    C62_CAMPAIGN_FILE_NAMES
        .iter()
        .zip(payloads)
        .enumerate()
        .map(|(index, (name, bytes))| {
            Ok(CampaignFileRow {
                name: (*name).to_owned(),
                bytes: u64::try_from(bytes.len())
                    .map_err(|_| "C6.2 campaign file length exceeds u64")?,
                blake3: hex_digest(*blake3::hash(bytes).as_bytes()),
                confidential: index == 1,
            })
        })
        .collect()
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn create_c62_campaign_directory(
    root: &Path,
    record: &CampaignArtifactRecord,
    payloads: &C62CampaignPayloads,
) -> Result<(), String> {
    let manifest = serde_json::to_vec(record)
        .map_err(|error| format!("encode C6.2 campaign manifest: {error}"))?;
    fs::create_dir(root).map_err(|error| format!("create-new C6.2 campaign directory: {error}"))?;
    File::open(root.parent().unwrap_or_else(|| Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6.2 campaign parent directory: {error}"))?;
    for (index, bytes) in [
        &payloads.certificate,
        &payloads.verifier_replay,
        &payloads.setup_manifest,
        &payloads.public_instance,
    ]
    .into_iter()
    .enumerate()
    {
        create_file_synced(&root.join(C62_CAMPAIGN_FILE_NAMES[index]), bytes, index == 1)?;
    }
    create_file_synced(&root.join("manifest.json"), &manifest, false)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6.2 campaign directory: {error}"))
}

/// Persist one complete C6.2 output without any challenge tape.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn create_c62_campaign_artifact(
    root: &Path,
    certificate: &C62NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
) -> Result<(), String> {
    validate_source_commit(source_git_commit)?;
    let public_argument = validate_c62_campaign_bindings(
        certificate,
        verifier_replay,
        setup_manifest,
        public_instance,
    )?;
    let payloads = C62CampaignPayloads {
        certificate: certificate.encode().map_err(|error| error.to_string())?,
        verifier_replay: verifier_replay.encode_client_state()?,
        setup_manifest: setup_manifest.encode().map_err(|error| error.to_string())?,
        public_instance: public_instance.encode().map_err(|error| error.to_string())?,
    };
    decode_c62_campaign_payloads(&payloads)?;
    let record = CampaignArtifactRecord {
        schema: 1,
        profile: C62_CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
        source_git_commit: source_git_commit.to_owned(),
        git_dirty: false,
        backend: CAMPAIGN_BACKEND.to_owned(),
        pcg: CAMPAIGN_PCG.to_owned(),
        certificate_digest: hex_digest(certificate.digest().map_err(|error| error.to_string())?),
        setup_manifest_digest: hex_digest(certificate.setup_manifest_digest),
        wrapper_statement_digest: hex_digest(certificate.wrapper.statement_digest),
        public_argument_statement_digest: hex_digest(public_argument.statement_digest()),
        response_statement_digest: hex_digest(public_instance.response_statement_digest()),
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.2 certificate length exceeds u64")?,
        files: c62_campaign_rows(&payloads)?,
    };
    create_c62_campaign_directory(root, &record, &payloads)
}

/// Persist one complete C6.3 output using the existing four-file campaign
/// framing. Only `certificate.bin` is provider wire.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn create_c63_campaign_artifact(
    root: &Path,
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
) -> Result<(), String> {
    create_c63_or_c64_campaign_artifact(
        root,
        certificate,
        verifier_replay,
        setup_manifest,
        public_instance,
        source_git_commit,
        C63_NATIVE_CERTIFICATE_VERSION,
        C63_CAMPAIGN_ARTIFACT_PROFILE,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn create_c64_campaign_artifact(
    root: &Path,
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
) -> Result<(), String> {
    create_c63_or_c64_campaign_artifact(
        root,
        certificate,
        verifier_replay,
        setup_manifest,
        public_instance,
        source_git_commit,
        C64_NATIVE_CERTIFICATE_VERSION,
        C64_CAMPAIGN_ARTIFACT_PROFILE,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
#[allow(clippy::too_many_arguments)]
fn create_c63_or_c64_campaign_artifact(
    root: &Path,
    certificate: &C63NativeFinalCertificate,
    verifier_replay: &C6BoundProductionVerifierReplay,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
    version: u16,
    profile: &str,
) -> Result<(), String> {
    validate_source_commit(source_git_commit)?;
    let inherited = validate_c63_campaign_bindings(
        certificate,
        verifier_replay,
        setup_manifest,
        public_instance,
    )?;
    let payloads = C62CampaignPayloads {
        certificate: certificate.encode().map_err(|error| error.to_string())?,
        verifier_replay: verifier_replay.encode_client_state()?,
        setup_manifest: setup_manifest.encode().map_err(|error| error.to_string())?,
        public_instance: public_instance.encode().map_err(|error| error.to_string())?,
    };
    decode_c63_campaign_payloads(&payloads, version)?;
    let record = CampaignArtifactRecord {
        schema: 1,
        profile: profile.to_owned(),
        source_git_commit: source_git_commit.to_owned(),
        git_dirty: false,
        backend: CAMPAIGN_BACKEND.to_owned(),
        pcg: CAMPAIGN_PCG.to_owned(),
        certificate_digest: hex_digest(certificate.digest().map_err(|error| error.to_string())?),
        setup_manifest_digest: hex_digest(certificate.setup_manifest_digest),
        wrapper_statement_digest: hex_digest(certificate.wrapper.statement_digest),
        public_argument_statement_digest: hex_digest(inherited.statement_digest()),
        response_statement_digest: hex_digest(public_instance.response_statement_digest()),
        wire_bytes: payloads.certificate.len() as u64,
        files: c62_campaign_rows(&payloads)?,
    };
    create_c62_campaign_directory(root, &record, &payloads)
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn validate_c62_campaign_directory_census(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("stat C6.2 campaign directory: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("C6.2 campaign root is not a physical directory".to_owned());
    }
    let expected: BTreeSet<String> = C62_CAMPAIGN_FILE_NAMES
        .iter()
        .copied()
        .chain(std::iter::once("manifest.json"))
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<String> = fs::read_dir(root)
        .map_err(|error| format!("read C6.2 campaign directory: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("read C6.2 campaign entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "C6.2 campaign contains a non-UTF8 file name".to_owned())
        })
        .collect::<Result<_, _>>()?;
    if actual != expected {
        return Err("C6.2 campaign directory file census differs".to_owned());
    }
    for name in &expected {
        let metadata = fs::symlink_metadata(root.join(name))
            .map_err(|error| format!("stat C6.2 campaign {name}: {error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!("C6.2 campaign {name} is not a physical file"));
        }
    }
    if fs::metadata(root.join("verifier-replay.bin"))
        .map_err(|error| format!("stat C6.2 private replay: {error}"))?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err("C6.2 private replay is accessible by group or other".to_owned());
    }
    Ok(())
}

/// Load and cross-bind one exact C6.2 artifact.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn load_c62_campaign_artifact(root: &Path) -> Result<C62CampaignArtifact, String> {
    validate_c62_campaign_directory_census(root)?;
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|error| format!("read C6.2 campaign manifest: {error}"))?;
    let record: CampaignArtifactRecord = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("decode C6.2 campaign manifest: {error}"))?;
    if serde_json::to_vec(&record)
        .map_err(|error| format!("re-encode C6.2 campaign manifest: {error}"))?
        != manifest_bytes
    {
        return Err("C6.2 campaign manifest is not canonical compact JSON".to_owned());
    }
    validate_source_commit(&record.source_git_commit)?;
    if record.schema != 1
        || record.profile != C62_CAMPAIGN_ARTIFACT_PROFILE
        || record.git_dirty
        || record.backend != CAMPAIGN_BACKEND
        || record.pcg != CAMPAIGN_PCG
        || record.files.len() != C62_CAMPAIGN_FILE_NAMES.len()
        || record.files.iter().map(|row| row.name.as_str()).ne(C62_CAMPAIGN_FILE_NAMES)
        || record.files.iter().map(|row| row.confidential).ne([false, true, false, false])
    {
        return Err(
            "C6.2 campaign manifest profile, backend, PCG, or file census differs".to_owned()
        );
    }
    let payloads = C62CampaignPayloads {
        certificate: load_campaign_file(root, &record.files[0])?,
        verifier_replay: load_campaign_file(root, &record.files[1])?,
        setup_manifest: load_campaign_file(root, &record.files[2])?,
        public_instance: load_campaign_file(root, &record.files[3])?,
    };
    let mut artifact = decode_c62_campaign_payloads(&payloads)?;
    if record.wire_bytes != artifact.wire_bytes
        || parse_hex_32(&record.certificate_digest, "C6.2 campaign certificate digest")?
            != artifact.certificate.digest().map_err(|error| error.to_string())?
        || parse_hex_32(&record.setup_manifest_digest, "C6.2 campaign setup digest")?
            != artifact.certificate.setup_manifest_digest
        || parse_hex_32(&record.wrapper_statement_digest, "C6.2 campaign wrapper statement digest")?
            != artifact.certificate.wrapper.statement_digest
        || parse_hex_32(
            &record.public_argument_statement_digest,
            "C6.2 campaign public argument statement digest",
        )? != artifact.public_argument.statement_digest()
        || parse_hex_32(
            &record.response_statement_digest,
            "C6.2 campaign response statement digest",
        )? != artifact.public_instance.response_statement_digest()
    {
        return Err("C6.2 campaign manifest binding differs from decoded objects".to_owned());
    }
    artifact.source_git_commit = record.source_git_commit;
    Ok(artifact)
}

/// Load and cross-bind one exact C6.3 disk artifact.
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn load_c63_campaign_artifact(root: &Path) -> Result<C63CampaignArtifact, String> {
    load_c63_or_c64_campaign_artifact(
        root,
        C63_NATIVE_CERTIFICATE_VERSION,
        C63_CAMPAIGN_ARTIFACT_PROFILE,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
pub fn load_c64_campaign_artifact(root: &Path) -> Result<C63CampaignArtifact, String> {
    load_c63_or_c64_campaign_artifact(
        root,
        C64_NATIVE_CERTIFICATE_VERSION,
        C64_CAMPAIGN_ARTIFACT_PROFILE,
    )
}

#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
fn load_c63_or_c64_campaign_artifact(
    root: &Path,
    version: u16,
    profile: &str,
) -> Result<C63CampaignArtifact, String> {
    validate_c62_campaign_directory_census(root)?;
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|error| format!("read C6.3 campaign manifest: {error}"))?;
    let record: CampaignArtifactRecord = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("decode C6.3 campaign manifest: {error}"))?;
    if serde_json::to_vec(&record)
        .map_err(|error| format!("re-encode C6.3 campaign manifest: {error}"))?
        != manifest_bytes
    {
        return Err("C6.3 campaign manifest is not canonical compact JSON".to_owned());
    }
    validate_source_commit(&record.source_git_commit)?;
    if record.schema != 1
        || record.profile != profile
        || record.git_dirty
        || record.backend != CAMPAIGN_BACKEND
        || record.pcg != CAMPAIGN_PCG
        || record.files.len() != C62_CAMPAIGN_FILE_NAMES.len()
        || record.files.iter().map(|row| row.name.as_str()).ne(C62_CAMPAIGN_FILE_NAMES)
        || record.files.iter().map(|row| row.confidential).ne([false, true, false, false])
    {
        return Err("C6.3 campaign manifest or file census differs".to_owned());
    }
    let payloads = C62CampaignPayloads {
        certificate: load_campaign_file(root, &record.files[0])?,
        verifier_replay: load_campaign_file(root, &record.files[1])?,
        setup_manifest: load_campaign_file(root, &record.files[2])?,
        public_instance: load_campaign_file(root, &record.files[3])?,
    };
    let mut artifact = decode_c63_campaign_payloads(&payloads, version)?;
    if record.wire_bytes != artifact.wire_bytes
        || parse_hex_32(&record.certificate_digest, "C6.3 campaign certificate digest")?
            != artifact.certificate.digest().map_err(|error| error.to_string())?
        || parse_hex_32(&record.setup_manifest_digest, "C6.3 campaign setup digest")?
            != artifact.certificate.setup_manifest_digest
        || parse_hex_32(&record.wrapper_statement_digest, "C6.3 campaign wrapper digest")?
            != artifact.certificate.wrapper.statement_digest
        || parse_hex_32(&record.public_argument_statement_digest, "C6.3 inherited statement")?
            != artifact.inherited_public_argument.statement_digest()
        || parse_hex_32(&record.response_statement_digest, "C6.3 response statement")?
            != artifact.public_instance.response_statement_digest()
    {
        return Err("C6.3 campaign manifest binding differs from decoded objects".to_owned());
    }
    artifact.source_git_commit = record.source_git_commit;
    Ok(artifact)
}

#[cfg(test)]
mod campaign_artifact_tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use volta_field::{Fp, Fp2};
    use volta_proto::{C6CorrelationRange, C6PairedCorrelationRanges, C6Workload};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "volta-c61-campaign-{label}-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn dummy_payloads() -> CampaignPayloads {
        CampaignPayloads {
            certificate: b"certificate".to_vec(),
            verifier_replay: b"private replay".to_vec(),
            challenge_tapes: b"private challenge tapes".to_vec(),
            setup_manifest: b"setup".to_vec(),
            public_instance: b"instance".to_vec(),
        }
    }

    fn dummy_record(payloads: &CampaignPayloads) -> CampaignArtifactRecord {
        CampaignArtifactRecord {
            schema: 7,
            profile: CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
            source_git_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_dirty: false,
            backend: CAMPAIGN_BACKEND.to_owned(),
            pcg: CAMPAIGN_PCG.to_owned(),
            certificate_digest: "11".repeat(32),
            setup_manifest_digest: "22".repeat(32),
            wrapper_statement_digest: "24".repeat(32),
            public_argument_statement_digest: "23".repeat(32),
            response_statement_digest: "33".repeat(32),
            wire_bytes: payloads.certificate.len() as u64,
            files: campaign_rows(payloads).unwrap(),
        }
    }

    fn response_attempt() -> C6ClientAttempt {
        C6ClientAttempt {
            slot: 3,
            nonce: [0x21; 32],
            setup_manifest_digest: [0x22; 32],
            old_head_digest: [0x23; 32],
            predecessor_certificate_digest: [0; 32],
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    C6CorrelationRange { stage: 1, start: 17, count: 19 },
                    C6CorrelationRange { stage: 1, start: 23, count: 19 },
                ],
            },
            workload: C6Workload {
                prompt_tokens: 100,
                decode_tokens: 50,
                old_context: 0,
                new_context: 150,
            },
        }
    }

    #[test]
    fn c62_cache_precommit_context_growth_handles_genesis_and_continuation() {
        assert_eq!(
            c62_cache_precommit_expected_new_context(C6Workload {
                prompt_tokens: 100,
                decode_tokens: 50,
                old_context: 0,
                new_context: 150,
            }),
            Some(150)
        );
        assert_eq!(
            c62_cache_precommit_expected_new_context(C6Workload {
                prompt_tokens: 0,
                decode_tokens: 50,
                old_context: 150,
                new_context: 200,
            }),
            Some(200)
        );
    }

    #[test]
    fn campaign_statement_domains_are_pairwise_distinct() {
        let response = [0x21; 32];
        let wrapper_base = [0x22; 32];
        let final_outer = [0x23; 32];
        validate_campaign_statement_domains(response, wrapper_base, final_outer).unwrap();
        assert!(validate_campaign_statement_domains(response, response, final_outer).is_err());
        assert!(validate_campaign_statement_domains(response, wrapper_base, response).is_err());
        assert!(validate_campaign_statement_domains(response, wrapper_base, wrapper_base).is_err());
        assert!(validate_campaign_statement_domains([0; 32], wrapper_base, final_outer).is_err());
    }

    #[test]
    fn response_session_keeps_entropy_client_side_and_yields_disk_tape() {
        let attempt = response_attempt();
        let statement = [0x24; 32];
        let expected_context = c61_response_transcript_context_digest(attempt, statement).unwrap();
        let mut session =
            C61CampaignResponseTranscriptSession::start_with_seed(attempt, statement, [0x25; 32])
                .unwrap();
        assert_eq!(session.context_digest(), expected_context);
        let (provider, verifier) = session.transcripts();
        provider.append_message("response-round-0", &[1, 2, 3]);
        let first = provider.challenge_fp2();
        verifier.append_message("response-round-0", &[1, 2, 3]);
        assert_eq!(verifier.challenge_fp2(), first);
        provider.append_message("response-round-1", &[4, 5]);
        let second = provider.challenge_fp();
        verifier.append_message("response-round-1", &[4, 5]);
        assert_eq!(verifier.challenge_fp(), second);

        let payload = [0x26; 4096];
        let tape = session.finish_payload(&payload).unwrap();
        let traffic = tape.traffic_census();
        assert_eq!(traffic.challenge_count, 2);
        assert_eq!(traffic.client_challenge_payload_bytes, 24);
        let mut replay = tape.replay_transcript(0, expected_context).unwrap();
        replay.append_message("response-round-0", &[1, 2, 3]);
        assert_eq!(replay.challenge_fp2(), first);
        replay.append_message("response-round-1", &[4, 5]);
        assert_eq!(replay.challenge_fp(), second);
        replay.finish_interactive(&payload).unwrap();
        assert!(tape.replay_transcript(0, [0x27; 32]).is_err());
        assert_ne!(first, Fp2::ZERO);
        assert_ne!(second, Fp::ZERO);

        let source = include_str!("c61_campaign.rs");
        let public_start = source
            .split_once("pub fn start(")
            .unwrap()
            .1
            .split_once("fn start_with_seed")
            .unwrap()
            .0;
        assert!(public_start.contains("OsRng"));
        assert!(!public_start.contains("verifier_seed:"));
    }

    #[cfg(feature = "c61-p3-authenticated-reference")]
    #[test]
    fn native_session_owns_exactly_seven_bound_challenge_lanes() {
        let attempt = response_attempt();
        let profile = C6CanonicalTargetProfile {
            inference_profile_digest: [0x31; 32],
            topology_digest: [0x32; 32],
            source_schedule_digest: [0x33; 32],
            cohorts: vec![
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 1,
                    chain_slot: 1,
                    polynomial_log2: C61_MODEL_POLYNOMIAL_LOG2,
                    claim_layout_digest: [0x34; 32],
                    canonical_nodes: vec![1; 96],
                },
                volta_mac::C6CanonicalTargetCohort {
                    cohort_id: 2,
                    chain_slot: 2,
                    polynomial_log2: C61_EMBEDDING_POLYNOMIAL_LOG2,
                    claim_layout_digest: [0x35; 32],
                    canonical_nodes: vec![2; 6],
                },
            ],
        };
        let ranges = c61_campaign_native_mask_ranges(attempt).unwrap();
        assert_eq!(ranges[0], ranges[2]);
        assert_eq!(ranges[0], ranges[4]);
        assert_eq!(ranges[1], ranges[3]);
        assert_eq!(ranges[1], ranges[5]);
        assert_ne!(ranges[0], ranges[1]);
        let seeds = std::array::from_fn(|index| [0x40 + index as u8; 32]);
        let (endpoints, session) =
            C61CampaignNativeTranscriptSession::start_with_seeds(attempt, &profile, seeds).unwrap();
        let C61CampaignNativeTranscriptEndpoints {
            four_chain:
                C61CampaignFourChainTranscriptEndpoints { four_chain_endpoints, joint_endpoint, .. },
            compiler: C61CampaignCompilerTranscriptEndpoints { compiler_endpoints, .. },
        } = endpoints;
        let mut native_endpoints = Vec::from(four_chain_endpoints);
        native_endpoints.extend(compiler_endpoints);
        native_endpoints.push(joint_endpoint);
        for (index, endpoint) in native_endpoints.into_iter().enumerate() {
            let mut transcript = Transcript::new_interactive(Box::new(endpoint));
            transcript.append_message("native-lane", &[index as u8]);
            let _ = transcript.challenge_fp2();
            transcript.finish_interactive(&[0x60 + index as u8; 64]).unwrap();
        }

        let response_context = [0x70; 32];
        let (response_endpoint, response_broker) =
            spawn_c61_private_entropy_transcript_broker([0x71; 32], 0, response_context).unwrap();
        let mut response_transcript = Transcript::new_interactive(Box::new(response_endpoint));
        response_transcript.append_message("response", &[0x72]);
        let _ = response_transcript.challenge_fp2();
        response_transcript.finish_interactive(&[0x73; 64]).unwrap();
        let response_tape = response_broker.finish().unwrap();

        let certificate_digest = [0x74; 32];
        let bundle =
            session.finish(attempt, certificate_digest, response_tape, response_context).unwrap();
        assert_eq!(bundle.traffic_census().tape_count, 8);
        bundle.validate_attempt(attempt, certificate_digest).unwrap();
        assert_eq!(
            bundle.tapes()[0].context_digest(),
            C61ProviderSessionBinding::from_reserved_attempt(
                attempt,
                C61NativeChainId::ordered()[0],
                ranges[0],
            )
            .unwrap()
            .context_digest()
        );
        assert_eq!(
            bundle.tapes()[6].context_digest(),
            C61ProviderJointSessionBinding::from_reserved_attempt(attempt, &profile)
                .unwrap()
                .context_digest()
        );
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn disk_response_replay_uses_only_tape_certificate_and_client_state() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn replay_c61_campaign_response_verifier(")
            .unwrap()
            .1
            .split_once("fn parse_hex_32")
            .unwrap()
            .0;
        for required in [
            "validate_attempt",
            "response_tape().replay_transcript",
            "C6RetainedResponseProof::decode",
            "fresh_contexts",
            "replay_c6_t1_production_response_verifier",
        ] {
            assert!(body.contains(required), "disk response replay omits {required}");
        }
        for forbidden in
            ["Transcript::new(", "Gpt2Model", "ModelWitness", "CorrelationStream", "provider_seed"]
        {
            assert!(!body.contains(forbidden), "disk response replay contains {forbidden}");
        }
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn campaign_response_call_site_keeps_entropy_in_the_session() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn execute_c61_campaign_response_owner(")
            .unwrap()
            .1
            .split_once("/// Response-verifier state")
            .unwrap()
            .0;
        assert!(body.contains("session.transcripts()"));
        assert!(body.contains("execute_c6_t1_production_owner_export("));
        for forbidden in [
            "verifier_seed",
            "Transcript::new(",
            "spawn_c61_private_entropy",
            "C61PrivateEntropyBrokerHandle",
        ] {
            assert!(!body.contains(forbidden), "campaign response call site contains {forbidden}");
        }
    }

    #[test]
    fn response_statement_builder_derives_plan_quantization_and_workload() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn build_c61_campaign_response_statement(")
            .unwrap()
            .1
            .split_once("fn decode_c61_campaign_client_parameters(")
            .unwrap()
            .0;
        for required in [
            "setup.client_parameters",
            "plan.artifact_digest()",
            "components[5]",
            "workload.model_family_digest()",
            "workload.workload() != attempt.workload",
            "workload.digest()",
        ] {
            assert!(body.contains(required), "response statement omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        assert!(!signature.contains("quantization_digest"));
        assert!(!signature.contains("plan_digest"));
        assert!(!signature.contains("workload_digest"));
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn wrapper_statement_builders_share_only_typed_setup_and_response_objects() {
        let source = include_str!("c61_campaign.rs");
        let live = source
            .split_once("pub fn build_c61_campaign_live_wrapper_statement(")
            .unwrap()
            .1
            .split_once("/// Reconstruct the identical wrapper base")
            .unwrap()
            .0;
        let disk = source
            .split_once("pub fn build_c61_campaign_disk_wrapper_statement(")
            .unwrap()
            .1
            .split_once("/// Response-verifier state")
            .unwrap()
            .0;
        for body in [live, disk] {
            for required in [
                "C61StatementBinding::bind_production_response_prefix(",
                "native_profile",
                "compiler_profile",
                "residual.manifest()",
            ] {
                assert!(body.contains(required), "wrapper statement omits {required}");
            }
            let signature = body.split_once(") -> Result").unwrap().0;
            for forbidden in ["public_output_digest", "compiler_plan_digest", "runtime_root"] {
                assert!(!signature.contains(forbidden), "wrapper signature admits {forbidden}");
            }
        }
        assert!(live.contains("encoded_retained_response()"));
        assert!(disk.contains("certificate.retained_response_binding()"));
        assert!(disk.contains("public_instance.preimage()"));
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn live_residual_roots_are_fixed_on_both_roles_before_alpha() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn bind_c61_campaign_live_residual_roots(")
            .unwrap()
            .1
            .split_once("/// Response-verifier state")
            .unwrap()
            .0;
        let materialize =
            body.find("materialize_production_c61_native_live_wrapper_roots_cuda(").unwrap();
        let install =
            body.find("install_production_c61_native_live_wrapper_roots_verifier(").unwrap();
        let root_bind = body.find(".bind_residual_relation(").unwrap();
        let relation = body.find("bind_c61_production_residual_relation(").unwrap();
        assert!(materialize < install && install < root_bind && root_bind < relation);
        for required in [
            "C6LiveWrapperMaskSeed::random()",
            "response_session.transcripts()",
            "residual.manifest()",
            "residual.leaf()",
            "residual.closure()",
            "residual.auxiliary()",
        ] {
            assert!(body.contains(required), "live residual root join omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        for forbidden in [
            "roots:",
            "mask_seed:",
            "session_digest:",
            "provider_transcript:",
            "verifier_transcript:",
        ] {
            assert!(!signature.contains(forbidden), "live residual signature admits {forbidden}");
        }
        for forbidden in [
            "C6HiddenU",
            "hidden:",
            "production_families(",
            "C6LiveWrapperSources",
            "materialize_production_c6_live_wrapper_roots_cuda(",
            "install_production_c6_live_wrapper_roots_verifier(",
        ] {
            assert!(!body.contains(forbidden), "native campaign body retains {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn native_four_chains_use_only_response_targets_and_session_bound_coefficients() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn prepare_c61_campaign_native_four_chains(")
            .unwrap()
            .1
            .split_once("/// Provider-only joint functional")
            .unwrap()
            .0;
        for required in [
            "endpoints.coefficient_session()",
            "model_coefficients.session_digest()",
            "embedding_coefficients.session_digest()",
            "C61ProductionResponseClaimSchedule::new(",
            "native_claims.model_claims()",
            "native_claims.embedding_claims()",
            "native_claims.production_paired_targets(profile, residual.native_targets())",
            "model_coefficients.load_for(component, repetition)",
            "embedding_coefficients.load_for(component, repetition)",
            "prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt(",
            "attempt.prover_streams_array_mut()",
        ] {
            assert!(body.contains(required), "native four-chain join omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        for forbidden in [
            "model_claims:",
            "embedding_claims:",
            "model_targets:",
            "embedding_targets:",
            "coefficients: Vec",
            "session_digest:",
            "verifier_seed:",
            "joint_challenge:",
        ] {
            assert!(!signature.contains(forbidden), "native four-chain join admits {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn native_functional_comes_only_from_fixed_bodies_and_response_tape_one() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn prepare_c61_campaign_native_functional(")
            .unwrap()
            .1
            .split_once("/// Exact native provider output")
            .unwrap()
            .0;
        for required in [
            "joint.claim_weights()",
            "joint.challenge()",
            "C6CompiledNativeTargetFunctional::compile(",
            "response.provider().operation_plan()",
            "response.provider().extraction()",
            "response.provider().runtime()",
            "response.paired_sources().source()",
            "response.source_schedule()",
            ".fold_prover_bridge_coordinate(",
            "c61_joint_public_statement_digest(",
        ] {
            assert!(body.contains(required), "native functional omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        assert!(signature.contains("four_chain: C61CampaignNativeFourChainOwner"));
        for forbidden in [
            "joint: C61ProductionJointNativeProverBodiesFixed",
            "claim_weights:",
            "cohort_weights:",
            "coefficients:",
            "correction:",
            "functional_digest:",
            "outer_statement_digest:",
        ] {
            assert!(!signature.contains(forbidden), "native functional admits {forbidden}");
        }
        assert!(body.contains("fold_prover_bridge_coordinate(") && body.contains("1,"));
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn native_blind_uses_only_exact_persisted_cache_and_residual_owners() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn prove_c61_campaign_native_blind(")
            .unwrap()
            .1
            .split_once("/// Provider-only joint functional")
            .unwrap()
            .0;
        for required in [
            "cohorts[0].open_semantic_cache()",
            "cohorts[1].open_semantic_cache()",
            "materialize_c61_native_cache_append_owner(",
            "response.cache_append_sources()",
            "response.cache_target_owner().targets()",
            "response.cache_target_owner().fixed()",
            "C6BlindResidualFusedCompilerContext::new(",
            "C6ResidualFusedWitnessView::new(",
            "prepare_c6_blind_residual_statement_fused(",
            "prove_c61_native_production_blind_components(",
            "attempt.prover_streams_array_mut()",
        ] {
            assert!(body.contains(required), "native blind omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        for forbidden in [
            "predecessor:",
            "successor:",
            "append:",
            "cache_targets:",
            "statements:",
            "residual_compiler:",
            "residual_witness:",
        ] {
            assert!(!signature.contains(forbidden), "native blind admits {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn native_suffix_orders_terminal_compiler_nbr2_link_and_exact_assembly() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn finish_c61_campaign_native_proof(")
            .unwrap()
            .1
            .split_once("/// Exact native provider output")
            .unwrap()
            .0;
        let terminal = body.find("prepare_c61_native_terminal_compiler(").unwrap();
        let nbr2 = body.find("C6Nbr2CorrectionFunctional::new(").unwrap();
        let native = body.find("joint.prepare_nbr2_link(").unwrap();
        let compiler = body
            .find("run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt(")
            .unwrap();
        let arithmetic = body.find("build_c61_production_arithmetic_frame(").unwrap();
        let link =
            body.find("finish_c61_native_production_blind_with_persisted_nbr2_link(").unwrap();
        let assembly = body.find("assemble_c61_native_exact_production_nbr2_certificate(").unwrap();
        assert!(terminal < nbr2 && nbr2 < native && native < compiler);
        assert!(compiler < arithmetic && arithmetic < link && link < assembly);
        for required in [
            "functional.leaf_coefficients()",
            "bridge.correction",
            "bridge.base_value",
            "inputs.terminal_functionals()",
            "inputs.relation_root()",
            "canonical_runtime_values(",
            "attempt.prover_streams_mut()",
            "attempt.prover_streams_array_mut()",
            "response.cache_target_frame().encode()",
        ] {
            assert!(body.contains(required), "native suffix omits {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        assert!(!signature.contains("primary: [C61ProductionCommittedChainExecution"));
        for forbidden in [
            "coefficients:",
            "correction:",
            "terminal_functionals:",
            "relation_root:",
            "functional_digest:",
            "outer_statement_digest:",
            "cache_fold_target_frame:",
        ] {
            assert!(!signature.contains(forbidden), "native suffix admits {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn live_runner_has_one_exact_response_to_seal_owner_path() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn run_c61_campaign_live_production(")
            .unwrap()
            .1
            .split_once("/// Commit the four exact wrapper cohorts")
            .unwrap()
            .0;
        let ordered = [
            "build_c61_campaign_response_statement(",
            "C61CampaignResponseTranscriptSession::start(",
            "execute_c61_campaign_response_owner(",
            "take_verifier_replay_owner(",
            "C61CampaignNativeTranscriptSession::start(",
            "persist_c6_t1_native_coefficient_owners(",
            "prepare_c6_t1_production_residual_owner(",
            "build_c61_campaign_live_wrapper_statement(",
            "bind_c61_campaign_live_residual_roots(",
            "prepare_c61_campaign_native_four_chains(",
            "prepare_c61_campaign_native_functional(",
            "prove_c61_campaign_native_blind(",
            "finish_c61_campaign_native_proof(",
            "seal_c61_campaign_native_output(",
            "response_session.finish_certificate(",
            "native_session.finish(",
            "replay_owner.bind_certificate(",
            "attempt.finish_success(",
        ];
        let mut previous = 0;
        for required in ordered {
            let offset =
                body.find(required).unwrap_or_else(|| panic!("live runner omits {required}"));
            assert!(offset >= previous, "live runner reorders {required}");
            previous = offset;
        }
        for required in [
            "public_workload.public_tokens() != workload_owner.sequence()",
            "native_endpoints.four_chain.coefficient_session()",
            "let (equality, residual) = relation.into_parts()",
            "let C61CampaignNativeTranscriptEndpoints { four_chain, compiler }",
            "run_root.join(\"coefficients\")",
            "run_root.join(\"wrapper\")",
            "run_root.join(\"proof\")",
        ] {
            assert!(body.contains(required), "live runner omits ownership gate {required}");
        }
        let signature = body.split_once(") -> Result").unwrap().0;
        for forbidden in [
            "response_statement:",
            "mask_ranges:",
            "native_endpoints:",
            "native_claims:",
            "model_coefficients:",
            "embedding_coefficients:",
            "equality:",
            "blind:",
            "functional:",
            "exact:",
        ] {
            assert!(!signature.contains(forbidden), "live runner admits detached {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn c62_runner_uses_one_early_cache_precommit_and_no_challenge_transport() {
        let source = include_str!("c61_campaign.rs");
        let prepare = source
            .split_once("fn prepare_c62_campaign_cache_precommit_inner(")
            .unwrap()
            .1
            .split_once("pub fn prepare_c62_campaign_cache_precommit<")
            .unwrap()
            .0;
        for required in [
            "materialize_c62_t1_cache_states(&workload_owner)",
            "precommit_production_c62_native_cache_roots_cuda(",
            "cache_precommit.roots()",
            "C6ProposedCacheHead::successor(",
        ] {
            assert!(prepare.contains(required), "C6.2 cache precommit omits {required}");
        }
        for forbidden in ["C6ClientAttempt", "C6ProductionPairedPcgAttempt", "response_statement"] {
            assert!(!prepare.contains(forbidden), "C6.2 early precommit admits {forbidden}");
        }
        let genesis = source
            .split_once("pub fn prepare_c62_campaign_cache_precommit<")
            .unwrap()
            .1
            .split_once("pub fn prepare_c62_campaign_continuation_cache_precommit(")
            .unwrap()
            .0;
        let continuation = source
            .split_once("pub fn prepare_c62_campaign_continuation_cache_precommit(")
            .unwrap()
            .1
            .split_once("/// Complete one C6.2 provider attempt")
            .unwrap()
            .0;
        assert!(genesis.contains("prepare_c62_campaign_cache_precommit_inner("));
        assert!(genesis.contains("None,"));
        assert!(continuation.contains("prepare_c62_campaign_cache_precommit_inner("));
        assert!(continuation.contains("Some(old_head),"));

        let runner = source
            .split_once("pub fn run_c62_campaign_live_production(")
            .unwrap()
            .1
            .split_once("/// Commit the four exact wrapper cohorts")
            .unwrap()
            .0;
        let ordered = [
            "build_c62_campaign_response_statement(",
            "C62CampaignResponseTranscriptSession::start(",
            "execute_c62_campaign_response_owner(",
            "prepare_c6_t1_production_residual_owner(",
            "build_c62_campaign_live_wrapper_statement(",
            "bind_c62_campaign_live_residual_roots(",
            "prepare_c62_campaign_native_four_chains(",
            "prepare_c62_campaign_native_functional(",
            "finish_c62_campaign_native_proof(",
            "seal_c62_campaign_native_output(",
            "replay_owner.bind_certificate(",
            "attempt.finish_success()",
        ];
        let mut previous = 0;
        for required in ordered {
            let offset =
                runner.find(required).unwrap_or_else(|| panic!("C6.2 runner omits {required}"));
            assert!(offset >= previous, "C6.2 runner reorders {required}");
            previous = offset;
        }
        let signature = runner.split_once(") -> Result").unwrap().0;
        assert!(signature.contains("precommit: C62CampaignCachePrecommitOwner"));
        assert!(signature.contains("model_coefficients: C61ProductionCoefficientOwner"));
        assert!(signature.contains("gpu: &C62ProductionGpuWhir"));
        for forbidden in [
            "workload_owner:",
            "public_workload:",
            "old_head:",
            "proposed_head:",
            "run_root:",
            "challenge_tapes",
            "broker",
        ] {
            assert!(!signature.contains(forbidden), "C6.2 runner admits {forbidden}");
        }

        let roots = source
            .split_once("pub fn bind_c62_campaign_live_residual_roots(")
            .unwrap()
            .1
            .split_once("/// Response-verifier state")
            .unwrap()
            .0;
        assert!(roots.contains("finish_production_c62_native_live_wrapper_roots_cuda("));
        assert!(!roots.contains("C6LiveWrapperMaskSeed::random()"));
        assert!(!roots.contains("materialize_production_c61_native_live_wrapper_roots_cuda("));
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn c62_joint_relation_binds_response_compiler_and_receipt_in_order() {
        let source = include_str!("c61_campaign.rs");
        let functional = source
            .split_once("pub fn prepare_c62_campaign_native_functional(")
            .unwrap()
            .1
            .split_once("/// Complete the native/compiler/C6NBR2 provider suffix")
            .unwrap()
            .0;
        let ordered = [
            "joint.claim_weights()",
            "C6CompiledNativeTargetFunctional::compile(",
            ".fold_prover_bridge_coordinate(",
            "response.paired_sources().source()",
            "c62_campaign_response_binding_digest(",
            "c62_public_statement_digest(",
        ];
        let mut previous = 0;
        for required in ordered {
            let offset = functional
                .find(required)
                .unwrap_or_else(|| panic!("C6.2 functional omits {required}"));
            assert!(offset >= previous, "C6.2 functional reorders {required}");
            previous = offset;
        }
        let signature = functional.split_once(") -> Result").unwrap().0;
        assert!(functional.contains("response.encoded_c62_retained_response()?"));
        assert!(!functional.contains("response.encoded_retained_response()?"));
        for forbidden in [
            "claim_weights:",
            "cohort_weights:",
            "response_target:",
            "compiler_correction:",
            "functional_digest:",
        ] {
            assert!(!signature.contains(forbidden), "C6.2 functional admits {forbidden}");
        }

        let suffix = source
            .split_once("pub fn finish_c62_campaign_native_proof(")
            .unwrap()
            .1
            .split_once("/// Exact native provider output")
            .unwrap()
            .0;
        let nbr2 = suffix.find("C6Nbr2CorrectionFunctional::new(").unwrap();
        let binding = suffix.find("C62ResponseCompilerBinding").unwrap();
        let relation = suffix.find("joint.prepare_nbr2_link(").unwrap();
        let compiler = suffix
            .find("run_c62_authenticated_whir_p3_production_compiler_fiat_shamir_in_attempt(")
            .unwrap();
        let receipt =
            suffix.find("finish_c62_native_production_blind_with_persisted_nbr2_link(").unwrap();
        assert!(nbr2 < binding && binding < relation && relation < compiler && compiler < receipt);
        let signature = suffix.split_once(") -> Result").unwrap().0;
        for forbidden in ["binding:", "eta:", "challenge:", "response_target:"] {
            assert!(!signature.contains(forbidden), "C6.2 suffix admits {forbidden}");
        }
    }

    #[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
    #[test]
    fn native_seal_consumes_only_exact_live_owners_and_round_trips() {
        let source = include_str!("c61_campaign.rs");
        let body = source
            .split_once("pub fn seal_c61_campaign_native_output(")
            .unwrap()
            .1
            .split_once("/// Commit the four exact wrapper cohorts")
            .unwrap()
            .0;
        let signature = body.split_once(") -> Result").unwrap().0;
        for required in [
            "C61CampaignLiveRoots",
            "C6T1ProductionResidualBoundOwner",
            "C61NativeExactProductionNbr2Certificate",
        ] {
            assert!(signature.contains(required), "native seal omits typed owner {required}");
        }
        for forbidden in [
            "retained_transcript: Vec",
            "proof_envelope: Vec",
            "public_argument: Vec",
            "residual: C6PairedDeltaResidual",
            "source_binding_digest: [u8; 32]",
        ] {
            assert!(!signature.contains(forbidden), "native seal admits detached {forbidden}");
        }
        for required in [
            "residual.response().encoded_retained_response()",
            "exact.encoded_public_argument()",
            "exact.encoded_proof_envelope()",
            "relation.claims().residual()",
            "roots.provider_roots.source_binding_digest()",
            ".seal()",
            "C61NativeFinalCertificate::decode(&encoded)",
        ] {
            assert!(body.contains(required), "native seal omits {required}");
        }
        for forbidden in ["C6FinalCertificate", "C6ResponseProofEnvelope", "HiddenU"] {
            assert!(!body.contains(forbidden), "native seal retains {forbidden}");
        }
    }

    #[test]
    fn setup_allocation_and_source_manifest_codec_are_exact() {
        assert_eq!(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES, 71_994_879);
        let setup = C6SetupManifest::production(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [[5; 32], [6; 32]],
            vec![7],
        )
        .unwrap();
        let setup_framing = setup.encode().unwrap().len() - 1;
        assert_eq!(setup_framing, 309);
        assert_eq!(
            setup.paired_pcg_setup_bytes().unwrap()
                + u64::try_from(setup_framing + C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES).unwrap(),
            C61_CAMPAIGN_SETUP_BYTES,
        );

        let manifest = C6TraceSourceManifest::new(17, [8; 32], vec![1, 5, 16]).unwrap();
        let encoded = encode_source_manifest(&manifest).unwrap();
        assert_eq!(decode_source_manifest(&encoded).unwrap(), manifest);
        let mut reordered = encoded;
        reordered[40..44].copy_from_slice(&5u32.to_le_bytes());
        assert!(decode_source_manifest(&reordered).is_err());
    }

    #[test]
    fn c62_client_parameter_envelope_is_strict_and_canonical() {
        let mut inner = Vec::with_capacity(1 << 20);
        for index in 0..(1 << 15) {
            inner.extend_from_slice(&(index % 17u32).to_le_bytes());
            inner.extend_from_slice(&[0x7e, 0, 0x7e, 0]);
        }
        let encoded = encode_c62_client_parameter_envelope(&inner).unwrap();
        assert_eq!(encoded[..8], *C62_CAMPAIGN_CLIENT_PARAMETERS_MAGIC);
        assert_eq!(
            decode_c62_client_parameter_envelope(
                &encoded,
                Some(inner.len()),
                inner.len(),
                encoded.len(),
            )
            .unwrap(),
            inner
        );

        let mut changed_payload = encoded.clone();
        changed_payload[C62_CAMPAIGN_CLIENT_PARAMETERS_HEADER_BYTES] ^= 1;
        assert!(decode_c62_client_parameter_envelope(
            &changed_payload,
            Some(inner.len()),
            inner.len(),
            encoded.len(),
        )
        .is_err());

        let mut changed_level = encoded.clone();
        changed_level[10..12].copy_from_slice(&4u16.to_le_bytes());
        assert!(decode_c62_client_parameter_envelope(
            &changed_level,
            Some(inner.len()),
            inner.len(),
            encoded.len(),
        )
        .is_err());
        assert!(decode_c62_client_parameter_envelope(
            &encoded,
            Some(inner.len() + 1),
            inner.len() + 1,
            encoded.len(),
        )
        .is_err());
        assert!(decode_c61_campaign_client_parameters(&encoded).is_err());
    }

    #[test]
    fn c62_setup_profile_selection_is_total_only_on_the_registered_session() {
        assert_eq!(C62_CAMPAIGN_PROFILE_COUNT, 17);
        assert_eq!(C62_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES, 760);
        assert_eq!(
            C62_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES,
            760 + 17 * C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES,
        );
        let source = include_str!("c61_campaign.rs");
        let matcher = source
            .split_once("fn c62_profile_topology_matches(")
            .unwrap()
            .1
            .split_once("fn encode_c62_campaign_profile_bundle(")
            .unwrap()
            .0;
        for registered in [
            "5_119_131, 17_894_474",
            "1_992_912, 7_082_024",
            "1_997_712, 7_104_920",
            "2_002_704, 7_128_872",
        ] {
            assert!(matcher.contains(registered));
        }
        for stale in ["4_976_100, 17_189_671", "4_976_101, 28_845_631"] {
            assert!(!matcher.contains(stale));
        }
        for (old_context, expected) in
            [(0, 0), (150, 1), (200, 2), (250, 3), (450, 7), (500, 8), (900, 16)]
        {
            assert_eq!(c62_profile_index(old_context).unwrap(), expected);
        }
        for old_context in [1, 149, 201, 451, 901, 950] {
            assert!(c62_profile_index(old_context).is_err());
        }
    }

    #[test]
    fn c64_setup_profile_selection_is_exactly_zero_and_150() {
        assert_eq!(C64_CAMPAIGN_PROFILE_COUNT, 2);
        assert_eq!(C64_CAMPAIGN_PROFILE_IDS, [0, 150]);
        assert_eq!(C64_CAMPAIGN_PROFILE_BUNDLE_HEADER_BYTES, 100);
        assert_eq!(
            C64_CAMPAIGN_PROFILE_BUNDLE_MAX_BYTES,
            100 + 2 * C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES,
        );
        for context in [0, 150] {
            assert!(C64_CAMPAIGN_PROFILE_IDS.contains(&context));
        }
        for context in [50, 100, 200, 900] {
            assert!(!C64_CAMPAIGN_PROFILE_IDS.contains(&context));
        }
    }

    #[test]
    fn campaign_directory_is_create_new_manifest_last_and_private() {
        let root = test_root("create-new");
        let payloads = dummy_payloads();
        let record = dummy_record(&payloads);
        create_campaign_directory(&root, &record, &payloads).unwrap();
        validate_campaign_directory_census(&root).unwrap();
        assert_eq!(fs::read(root.join("verifier-replay.bin")).unwrap(), payloads.verifier_replay);
        assert_eq!(fs::read(root.join("challenge-tapes.bin")).unwrap(), payloads.challenge_tapes);
        assert!(create_campaign_directory(&root, &record, &payloads).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn campaign_census_rejects_extra_symlink_and_replay_permissions() {
        let root = test_root("mutations");
        let payloads = dummy_payloads();
        let record = dummy_record(&payloads);
        create_campaign_directory(&root, &record, &payloads).unwrap();

        create_file_synced(&root.join("extra.bin"), b"extra", false).unwrap();
        assert!(validate_campaign_directory_census(&root).is_err());
        fs::remove_file(root.join("extra.bin")).unwrap();

        fs::set_permissions(root.join("verifier-replay.bin"), fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(validate_campaign_directory_census(&root).is_err());
        fs::set_permissions(root.join("verifier-replay.bin"), fs::Permissions::from_mode(0o600))
            .unwrap();

        fs::set_permissions(root.join("challenge-tapes.bin"), fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(validate_campaign_directory_census(&root).is_err());
        fs::set_permissions(root.join("challenge-tapes.bin"), fs::Permissions::from_mode(0o600))
            .unwrap();

        fs::remove_file(root.join("setup-manifest.bin")).unwrap();
        std::os::unix::fs::symlink("certificate.bin", root.join("setup-manifest.bin")).unwrap();
        assert!(validate_campaign_directory_census(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn campaign_manifest_and_file_mutations_fail_closed() {
        let root = test_root("manifest");
        let payloads = dummy_payloads();
        let record = dummy_record(&payloads);
        create_campaign_directory(&root, &record, &payloads).unwrap();
        let mut noncanonical = serde_json::to_vec_pretty(&record).unwrap();
        noncanonical.push(b'\n');
        assert_ne!(serde_json::to_vec(&record).unwrap(), noncanonical);
        let mut wrong = record.files[0].clone();
        wrong.blake3 = "00".repeat(32);
        assert!(load_campaign_file(&root, &wrong).is_err());
        assert!(validate_source_commit("ABC").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
