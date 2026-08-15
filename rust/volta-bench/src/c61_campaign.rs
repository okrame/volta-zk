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
#[cfg(feature = "c6-trace")]
use volta_pcs::C61ProductionResidualRelationBound;
use volta_pcs::{
    c61_response_transcript_context_digest, c6_wrapper_profile_digest,
    install_production_c6_live_wrapper_roots_verifier,
    materialize_production_c6_live_wrapper_roots_cuda,
    spawn_c61_private_entropy_duplex_transcript_broker, C61InteractiveTape,
    C61InteractiveTapeBundle, C61JointPublicArgument, C61PrivateEntropyBrokerHandle,
    C61ResponseStatementBinding, C61StatementBinding,
};
#[cfg(feature = "c6-trace")]
use volta_pcs::{
    C6HiddenUBundleWitness, C6LiveWrapperMaskSeed, C6LiveWrapperSources,
    C6PersistedLiveWrapperRootBinding, C6PersistentCacheStateWitness,
    C6PersistentCacheStaticProfile, C6VerifierLiveWrapperRootBinding,
};
#[cfg(feature = "c6-trace")]
use volta_proto::{
    replay_c6_t1_production_response_verifier, C6ProductionPairedPcgAttempt,
    C6RetainedResponseProof, C6T1DiskResidualOwner, C6T1ProductionResidualOwner,
    C6T1ProductionResponseVerifierReplay,
};
use volta_proto::{
    C61FinalCertificateEnvelope, C61PublicWorkloadInstance, C61PublicWorkloadPreimage,
    C6BoundProductionVerifierReplay, C6CacheHead, C6ClientAttempt, C6ProposedCacheHead,
    C6SetupManifest, C61_VERIFIER_REPLAY_STATE_BYTES,
};

#[cfg(feature = "c6-trace")]
use crate::c6_t1_owner::{
    execute_c6_t1_production_owner_export, C6T1ProductionOwnerExport, C6T1WorkloadOwner,
};

const CAMPAIGN_ARTIFACT_PROFILE: &str = "C6.1-C6PA2-C6NBR3-C6ICT4-campaign-v6";
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
    pub certificate: C61FinalCertificateEnvelope,
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
        certificate: &C61FinalCertificateEnvelope,
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
    certificate: &C61FinalCertificateEnvelope,
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

/// Linear live owner after the six persisted roots and exact residual
/// relation have been fixed on both response transcripts.
#[cfg(feature = "c6-trace")]
pub struct C61CampaignLiveResidualRooted {
    pub provider_roots: C6PersistedLiveWrapperRootBinding,
    pub verifier_roots: C6VerifierLiveWrapperRootBinding,
    pub relation: C61ProductionResidualRelationBound,
    pub session_digest: [u8; 32],
}

/// Commit the six exact wrapper cohorts, install the same roots on the live
/// verifier and consume the production residual owner through coordinate 1.
#[cfg(feature = "c6-trace")]
#[allow(clippy::too_many_arguments)]
pub fn bind_c61_campaign_live_residual_roots(
    setup: &C6SetupManifest,
    statement: C61StatementBinding,
    workload: &C61PublicWorkloadPreimage,
    predecessor: C6PersistentCacheStateWitness,
    successor: C6PersistentCacheStateWitness,
    hidden: &C6HiddenUBundleWitness,
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
    let (weights, embedding) = hidden.production_families().map_err(|error| error.to_string())?;
    let old_len = u16::try_from(workload.workload().old_context)
        .map_err(|_| "C6ICT4 old cache length exceeds u16")?;
    let new_len = u16::try_from(workload.workload().new_context)
        .map_err(|_| "C6ICT4 new cache length exceeds u16")?;
    let sources = C6LiveWrapperSources::production(
        statement.digest(),
        &cache_profile,
        predecessor,
        successor,
        old_len,
        new_len,
        weights,
        embedding,
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
    let provider_roots = materialize_production_c6_live_wrapper_roots_cuda(
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
    let roots: [[u8; 32]; 6] =
        root_values.try_into().map_err(|_| "C6ICT4 persisted wrapper root census differs")?;
    let verifier_roots = install_production_c6_live_wrapper_roots_verifier(
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
    certificate: &C61FinalCertificateEnvelope,
    verifier_replay: &C6BoundProductionVerifierReplay,
    challenge_tapes: &C61InteractiveTapeBundle,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    expected_source_manifest: &C6TraceSourceManifest,
    verifier_plan: C6InstalledOperationPlan,
    verifier_extraction: C6DecodedInstanceExtractionPlan,
) -> Result<C61CampaignResponseVerifierReplay, String> {
    let inner = certificate.certificate();
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
        certificate.proof_envelope().cache_fold_targets(),
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
    certificate: &C61FinalCertificateEnvelope,
    verifier_replay: &C6BoundProductionVerifierReplay,
    challenge_tapes: &C61InteractiveTapeBundle,
    setup_manifest: &C6SetupManifest,
    public_instance: &C61PublicWorkloadInstance,
) -> Result<C61JointPublicArgument, String> {
    let inner = certificate.certificate();
    let certificate_digest = inner.digest().map_err(|error| error.to_string())?;
    let setup_manifest_digest = setup_manifest.digest().map_err(|error| error.to_string())?;
    let public_argument = C61JointPublicArgument::decode(certificate.public_argument())
        .map_err(|error| error.to_string())?;
    let wrapper = certificate.wrapper_binding().map_err(|error| error.to_string())?;
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
    let certificate = C61FinalCertificateEnvelope::decode(&payloads.certificate)
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
    certificate: &C61FinalCertificateEnvelope,
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
    let inner = certificate.certificate();
    let record = CampaignArtifactRecord {
        schema: 6,
        profile: CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
        source_git_commit: source_git_commit.to_owned(),
        git_dirty: false,
        backend: CAMPAIGN_BACKEND.to_owned(),
        pcg: CAMPAIGN_PCG.to_owned(),
        certificate_digest: hex_digest(inner.digest().map_err(|error| error.to_string())?),
        setup_manifest_digest: hex_digest(inner.setup_manifest_digest),
        wrapper_statement_digest: hex_digest(
            certificate.wrapper_binding().map_err(|error| error.to_string())?.statement_digest,
        ),
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
    if record.schema != 6
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
    let inner = artifact.certificate.certificate();
    if record.wire_bytes != artifact.wire_bytes
        || parse_hex_32(&record.certificate_digest, "campaign certificate digest")?
            != inner.digest().map_err(|error| error.to_string())?
        || parse_hex_32(&record.setup_manifest_digest, "campaign setup digest")?
            != inner.setup_manifest_digest
        || parse_hex_32(&record.wrapper_statement_digest, "campaign wrapper-base statement digest")?
            != artifact
                .certificate
                .wrapper_binding()
                .map_err(|error| error.to_string())?
                .statement_digest
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
            schema: 6,
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
        let materialize = body.find("materialize_production_c6_live_wrapper_roots_cuda(").unwrap();
        let install = body.find("install_production_c6_live_wrapper_roots_verifier(").unwrap();
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
