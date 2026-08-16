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
use std::path::Path;
#[cfg(feature = "c6-trace")]
use volta_accel::Backend;
use volta_gpt2::{
    decode_verifier_model_canonical, encode_verifier_model_canonical, Gpt2VerifierModel,
};
#[cfg(feature = "c6-trace")]
use volta_mac::VerifierCtx;
use volta_mac::{
    C6CanonicalTargetProfile, C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan,
    C6InstanceExtractionArtifact, C6InstanceExtractionRole, C6NativeTargetProfileArtifact,
    C6OperationPlanArtifact, C6TraceSourceManifest, Transcript,
};
use volta_pcs::c61_authenticated_whir_p3::C61CompilerVerifierProfile;
#[cfg(feature = "c61-p3-authenticated-reference")]
use volta_pcs::c61_authenticated_whir_p3::{
    prepare_c61_authenticated_whir_p3_production_joint_four_chains_private_entropy_in_attempt,
    run_c61_authenticated_whir_p3_production_compiler_private_entropy_in_attempt,
    C61ProductionCoefficientOwner, C61ProductionCoefficientSessionBinding,
    C61ProductionCommittedChainExecution, C61ProductionJointNativeProverBodiesFixed,
    C61ProductionPersistedResourceAdmission, C61ProductionResponseClaimSchedule,
    C61ProviderJointSessionBinding, C61ProviderSessionBinding,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c61_public_compression::C61NativeComponent;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::c6_blind_round_coordinator::{
    assemble_c61_native_exact_production_nbr2_certificate,
    finish_c61_native_production_blind_with_persisted_nbr2_link,
    materialize_c61_native_cache_append_owner, prepare_c61_native_terminal_compiler,
    prove_c61_native_production_blind_components, C61NativeExactProductionNbr2Certificate,
    C61NativeProductionBlindProverOutput,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::C61ProductionResidualRelationBound;
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_pcs::{
    build_c61_production_arithmetic_frame, prepare_c6_blind_residual_statement_fused,
    C6BlindResidualFusedCompilerContext, C6BlindResidualStatement, C6Nbr2CorrectionFunctional,
};
use volta_pcs::{
    c61_response_transcript_context_digest, c6_wrapper_profile_digest,
    install_production_c61_native_live_wrapper_roots_verifier,
    materialize_production_c61_native_live_wrapper_roots_cuda,
    spawn_c61_private_entropy_duplex_transcript_broker, C61EqualityDrawn, C61InteractiveTape,
    C61InteractiveTapeBundle, C61JointPublicArgument, C61PrivateEntropyBrokerHandle,
    C61ResponseStatementBinding, C61StatementBinding,
};
#[cfg(feature = "c61-p3-authenticated-reference")]
use volta_pcs::{
    spawn_c61_private_entropy_transcript_broker, C61AuthenticatedWhirMaskRange, C61NativeChainId,
    C61PrivateEntropyEndpoint, C61_EMBEDDING_POLYNOMIAL_LOG2, C61_INTERACTIVE_TAPE_LANES,
    C61_MODEL_POLYNOMIAL_LOG2,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::{
    C61NativeLiveWrapperSources, C6LiveWrapperMaskSeed, C6PersistedLiveWrapperRootBinding,
    C6PersistentCacheStateWitness, C6PersistentCacheStaticProfile,
    C6VerifierLiveWrapperRootBinding,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_proto::c6_residual::{C6CompiledNativeTargetFunctional, C6NativeTargetProverBridgeFold};
#[cfg(feature = "c6-trace")]
use volta_proto::{
    replay_c6_t1_production_response_verifier, C6ProductionPairedPcgAttempt,
    C6RetainedResponseProof, C6T1DiskResidualOwner, C6T1ProductionResidualBoundOwner,
    C6T1ProductionResidualOwner, C6T1ProductionResponseVerifierReplay,
};
use volta_proto::{
    C61NativeFinalCertificate, C61NativeWrapperCommitments, C61PublicWorkloadInstance,
    C61PublicWorkloadPreimage, C6BoundProductionVerifierReplay, C6CacheHead, C6ClientAttempt,
    C6ProposedCacheHead, C6SetupManifest, C61_NATIVE_CERTIFICATE_VERSION,
    C61_NATIVE_WRAPPER_QUERIES, C61_VERIFIER_REPLAY_STATE_BYTES,
};
#[cfg(all(feature = "c6-trace", feature = "c61-p3-authenticated-reference"))]
use volta_proto::{C6ResidualFusedCoefficientArena, C6ResidualFusedWitnessView};

#[cfg(feature = "c6-trace")]
use crate::c6_t1_owner::{
    execute_c6_t1_production_owner_export, C6T1NativeClaimOwner, C6T1ProductionOwnerExport,
    C6T1WorkloadOwner,
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
const CAMPAIGN_CLIENT_PARAMETERS_MAGIC: &[u8; 8] = b"C61CP4\0\0";
const CAMPAIGN_CLIENT_PARAMETERS_VERSION: u16 = 4;
const CAMPAIGN_CLIENT_PARAMETER_COMPONENTS: usize = 7;
const C61_CANONICAL_OPERATION_PLAN_BYTES: usize = 63_994_751;
const C61_CLIENT_PARAMETER_ALLOCATION_BYTES: usize = 8_000_000;
const C6_SETUP_BASE_CLIENT_PARAMETER_BYTES: usize = 128;
pub const C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES: usize = C61_CANONICAL_OPERATION_PLAN_BYTES
    + C61_CLIENT_PARAMETER_ALLOCATION_BYTES
    + C6_SETUP_BASE_CLIENT_PARAMETER_BYTES;
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

struct DecodedCampaignClientParameters {
    verifier_model: Gpt2VerifierModel,
    source_manifest: C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
    native_profile: C6CanonicalTargetProfile,
    compiler_profile: C61CompilerVerifierProfile,
    quantization_digest: [u8; 32],
}

struct CampaignPayloads {
    certificate: Vec<u8>,
    verifier_replay: Vec<u8>,
    challenge_tapes: Vec<u8>,
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
        mask_ranges: [C61AuthenticatedWhirMaskRange; 6],
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
        Self::start_with_seeds(attempt, profile, mask_ranges, verifier_seeds)
    }

    fn start_with_seeds(
        attempt: C6ClientAttempt,
        profile: &C6CanonicalTargetProfile,
        mask_ranges: [C61AuthenticatedWhirMaskRange; 6],
        verifier_seeds: [[u8; 32]; C61_INTERACTIVE_TAPE_LANES],
    ) -> Result<(C61CampaignNativeTranscriptEndpoints, Self), String> {
        if verifier_seeds.contains(&[0; 32])
            || (0..verifier_seeds.len())
                .any(|index| verifier_seeds[..index].contains(&verifier_seeds[index]))
        {
            return Err("C6ICT5 native verifier entropy is zero or duplicated".to_owned());
        }
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
    ) -> (
        [C61ProductionCommittedChainExecution; 2],
        C61ProductionJointNativeProverBodiesFixed,
    ) {
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

pub fn load_c61_campaign_installed_setup(root: &Path) -> Result<C61CampaignInstalledSetup, String> {
    let manifest_bytes = fs::read(root.join("manifest.json"))
        .map_err(|error| format!("read C6.1 setup manifest: {error}"))?;
    let record: SetupRecord = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("decode C6.1 setup manifest: {error}"))?;
    if record.schema != 1
        || record.profile != "C6.1-T1-installed-setup-v1"
        || record.files.len() != 4
    {
        return Err("C6.1 setup manifest schema/profile/census mismatch".to_owned());
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
    let compiler_profile = C61CompilerVerifierProfile::new(terminal_metadata)?;
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
pub fn encode_c61_campaign_client_parameters(
    installed: &C61CampaignInstalledSetup,
    verifier_model: &Gpt2VerifierModel,
    quantization_digest: [u8; 32],
) -> Result<Vec<u8>, String> {
    if installed.operation_plan_artifact.len() != C61_CANONICAL_OPERATION_PLAN_BYTES
        || quantization_digest == [0; 32]
    {
        return Err("C6.1 campaign operation-plan byte census mismatch".to_owned());
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
    let header_bytes = CAMPAIGN_CLIENT_PARAMETERS_MAGIC.len()
        + 4
        + CAMPAIGN_CLIENT_PARAMETER_COMPONENTS * (8 + 32);
    let used = components.iter().try_fold(header_bytes, |total, component| {
        total
            .checked_add(component.len())
            .ok_or_else(|| "C6.1 client-parameter length overflows".to_owned())
    })?;
    if used > C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES {
        return Err("C6.1 client parameters exceed the frozen setup allocation".to_owned());
    }
    let mut bytes = Vec::with_capacity(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES);
    bytes.extend_from_slice(CAMPAIGN_CLIENT_PARAMETERS_MAGIC);
    bytes.extend_from_slice(&CAMPAIGN_CLIENT_PARAMETERS_VERSION.to_le_bytes());
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
    bytes.resize(C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES, 0);
    Ok(bytes)
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

fn c61_campaign_client_parameter_components(
    bytes: &[u8],
) -> Result<[&[u8]; CAMPAIGN_CLIENT_PARAMETER_COMPONENTS], String> {
    let header_bytes = CAMPAIGN_CLIENT_PARAMETERS_MAGIC.len()
        + 4
        + CAMPAIGN_CLIENT_PARAMETER_COMPONENTS * (8 + 32);
    if bytes.len() != C61_CAMPAIGN_CLIENT_PARAMETERS_BYTES
        || bytes.get(..8) != Some(CAMPAIGN_CLIENT_PARAMETERS_MAGIC)
        || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed width"))
            != CAMPAIGN_CLIENT_PARAMETERS_VERSION
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
    if lengths[1] != C61_CANONICAL_OPERATION_PLAN_BYTES
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
    if bytes[cursor..].iter().any(|byte| *byte != 0) {
        return Err("C6.1 client-parameter padding is nonzero".to_owned());
    }
    Ok(components)
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

fn decode_c61_campaign_client_parameters(
    bytes: &[u8],
) -> Result<DecodedCampaignClientParameters, String> {
    let components = c61_campaign_client_parameter_components(bytes)?;

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
        verifier_plan,
        verifier_extraction,
        native_profile,
        compiler_profile,
        quantization_digest,
    })
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
    if payloads.verifier_replay.len() != C61_VERIFIER_REPLAY_STATE_BYTES
        || payloads.public_instance.len() > PUBLIC_INSTANCE_MAX_BYTES
    {
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
        let ranges = std::array::from_fn(|index| C61AuthenticatedWhirMaskRange {
            stage: 7,
            slot: u16::try_from(attempt.slot).unwrap(),
            range_start: 100 + 3 * index as u32,
        });
        let seeds = std::array::from_fn(|index| [0x40 + index as u8; 32]);
        let (endpoints, session) =
            C61CampaignNativeTranscriptSession::start_with_seeds(attempt, &profile, ranges, seeds)
                .unwrap();
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
