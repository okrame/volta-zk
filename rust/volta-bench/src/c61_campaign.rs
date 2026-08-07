//! Strict local setup loader for the owner-authorized C6.1 campaign.
//!
//! The directory is produced create-new by `c6_t1_census_record`. It is a
//! run artifact, not additional protocol wire framing: the contained plan,
//! extraction maps and C6NTO1 bytes are the setup objects already counted by
//! the C6.1 budget.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use volta_gpt2::{
    decode_verifier_model_canonical, encode_verifier_model_canonical, Gpt2VerifierModel,
};
use volta_mac::{
    C6CanonicalTargetProfile, C6DecodedInstanceExtractionPlan, C6InstalledOperationPlan,
    C6InstanceExtractionArtifact, C6InstanceExtractionRole, C6NativeTargetProfileArtifact,
    C6OperationPlanArtifact, C6TraceSourceManifest,
};
use volta_pcs::C61JointPublicArgument;
use volta_proto::{
    C61FinalCertificateEnvelope, C61PublicWorkloadInstance, C6BoundProductionVerifierReplay,
    C61_VERIFIER_REPLAY_STATE_BYTES,
};

const CAMPAIGN_ARTIFACT_PROFILE: &str = "C6.1-C6PA2-C6NBR2-campaign-v1";
const CAMPAIGN_BACKEND: &str = "cuda-resident";
const CAMPAIGN_PCG: &str = "real-aes128-mmo";
const CAMPAIGN_FILE_NAMES: [&str; 4] =
    ["certificate.bin", "verifier-replay.bin", "verifier-model.bin", "public-instance.bin"];
const VERIFIER_MODEL_SETUP_MAX_BYTES: usize = 1_000_000;
const PUBLIC_INSTANCE_MAX_BYTES: usize = 128 + 4 * 1_024;

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
    statement_digest: String,
    wire_bytes: u64,
    files: Vec<CampaignFileRow>,
}

pub struct C61CampaignArtifact {
    pub certificate: C61FinalCertificateEnvelope,
    pub verifier_replay: C6BoundProductionVerifierReplay,
    pub verifier_model: Gpt2VerifierModel,
    pub public_instance: C61PublicWorkloadInstance,
    pub public_argument: C61JointPublicArgument,
    pub source_git_commit: String,
    pub wire_bytes: u64,
}

struct CampaignPayloads {
    certificate: Vec<u8>,
    verifier_replay: Vec<u8>,
    verifier_model: Vec<u8>,
    public_instance: Vec<u8>,
}

pub struct C61CampaignInstalledSetup {
    pub source_manifest: C6TraceSourceManifest,
    pub provider_plan: C6InstalledOperationPlan,
    pub verifier_plan: C6InstalledOperationPlan,
    pub provider_extraction: C6DecodedInstanceExtractionPlan,
    pub verifier_extraction: C6DecodedInstanceExtractionPlan,
    pub native_profile: C6CanonicalTargetProfile,
    pub plan_bytes: u64,
    pub extraction_bytes: u64,
    pub native_profile_bytes: u64,
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
    let provider_extraction =
        C6InstanceExtractionArtifact::parse(prover_extraction_bytes, topology)
            .and_then(|artifact| artifact.decode(topology))
            .map_err(|error| format!("decode C6.1 provider extraction: {error}"))?;
    let verifier_extraction =
        C6InstanceExtractionArtifact::parse(verifier_extraction_bytes, topology)
            .and_then(|artifact| artifact.decode(topology))
            .map_err(|error| format!("decode C6.1 verifier extraction: {error}"))?;
    if provider_extraction.role() != C6InstanceExtractionRole::Prover
        || verifier_extraction.role() != C6InstanceExtractionRole::Verifier
    {
        return Err("C6.1 setup extraction roles differ".to_owned());
    }
    let (_, native_profile) =
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
        .install(&source_manifest)
        .map_err(|error| format!("install C6.1 verifier plan: {error}"))?;
    Ok(C61CampaignInstalledSetup {
        source_manifest,
        provider_plan,
        verifier_plan,
        provider_extraction,
        verifier_extraction,
        native_profile,
        plan_bytes: plan_len,
        extraction_bytes: extraction_len,
        native_profile_bytes: native_len,
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

fn validate_campaign_bindings(
    certificate: &C61FinalCertificateEnvelope,
    verifier_replay: &C6BoundProductionVerifierReplay,
    public_instance: &C61PublicWorkloadInstance,
) -> Result<C61JointPublicArgument, String> {
    let inner = certificate.certificate();
    let certificate_digest = inner.digest().map_err(|error| error.to_string())?;
    let public_argument = C61JointPublicArgument::decode(certificate.public_argument())
        .map_err(|error| error.to_string())?;
    if verifier_replay.certificate_digest() != certificate_digest
        || verifier_replay.setup_manifest_digest() != inner.setup_manifest_digest
        || verifier_replay.statement_digest() != public_instance.statement_digest
        || public_argument.statement_digest() != public_instance.statement_digest
        || inner.model_digest != public_instance.model_family_digest
        || inner.workload.old_context != public_instance.old_context
        || inner.workload.prompt_tokens != public_instance.prompt_tokens
        || inner.workload.decode_tokens != public_instance.decode_tokens
        || inner.workload.new_context != public_instance.new_context
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
        || payloads.verifier_model.len() > VERIFIER_MODEL_SETUP_MAX_BYTES
        || payloads.public_instance.len() > PUBLIC_INSTANCE_MAX_BYTES
    {
        return Err("C6.1 campaign private/setup/public-local artifact size mismatch".to_owned());
    }
    let certificate = C61FinalCertificateEnvelope::decode(&payloads.certificate)
        .map_err(|error| error.to_string())?;
    let verifier_replay =
        C6BoundProductionVerifierReplay::decode_client_state(&payloads.verifier_replay)?;
    let verifier_model = decode_verifier_model_canonical(&payloads.verifier_model)
        .map_err(|error| error.to_string())?;
    let public_instance = C61PublicWorkloadInstance::decode(&payloads.public_instance)
        .map_err(|error| error.to_string())?;
    let public_argument =
        validate_campaign_bindings(&certificate, &verifier_replay, &public_instance)?;
    Ok(C61CampaignArtifact {
        wire_bytes: u64::try_from(payloads.certificate.len())
            .map_err(|_| "C6.1 certificate length exceeds u64")?,
        certificate,
        verifier_replay,
        verifier_model,
        public_instance,
        public_argument,
        source_git_commit: String::new(),
    })
}

fn campaign_rows(payloads: &CampaignPayloads) -> Result<Vec<CampaignFileRow>, String> {
    let payloads = [
        &payloads.certificate,
        &payloads.verifier_replay,
        &payloads.verifier_model,
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
                confidential: index == 1,
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
        &payloads.verifier_model,
        &payloads.public_instance,
    ]
    .into_iter()
    .enumerate()
    {
        create_file_synced(&root.join(CAMPAIGN_FILE_NAMES[index]), bytes, index == 1)?;
    }
    // The manifest is the completion marker and is deliberately durable last.
    create_file_synced(&root.join("manifest.json"), &manifest, false)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync C6.1 campaign directory: {error}"))
}

/// Persist one complete provider output plus the exact client replay inputs.
/// Only `certificate.bin` is provider-to-client wire. The replay and public
/// instance are client-private/local; the verifier model belongs to setup.
#[allow(clippy::too_many_arguments)]
pub fn create_c61_campaign_artifact(
    root: &Path,
    certificate: &C61FinalCertificateEnvelope,
    verifier_replay: &C6BoundProductionVerifierReplay,
    verifier_model: &Gpt2VerifierModel,
    public_instance: &C61PublicWorkloadInstance,
    source_git_commit: &str,
) -> Result<(), String> {
    validate_source_commit(source_git_commit)?;
    validate_campaign_bindings(certificate, verifier_replay, public_instance)?;
    let payloads = CampaignPayloads {
        certificate: certificate.encode().map_err(|error| error.to_string())?,
        verifier_replay: verifier_replay.encode_client_state()?,
        verifier_model: encode_verifier_model_canonical(verifier_model)
            .map_err(|error| error.to_string())?,
        public_instance: public_instance.encode().map_err(|error| error.to_string())?,
    };
    // Exercise the same strict decode path before creating any filesystem state.
    decode_campaign_payloads(&payloads)?;
    let inner = certificate.certificate();
    let record = CampaignArtifactRecord {
        schema: 1,
        profile: CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
        source_git_commit: source_git_commit.to_owned(),
        git_dirty: false,
        backend: CAMPAIGN_BACKEND.to_owned(),
        pcg: CAMPAIGN_PCG.to_owned(),
        certificate_digest: hex_digest(inner.digest().map_err(|error| error.to_string())?),
        setup_manifest_digest: hex_digest(inner.setup_manifest_digest),
        statement_digest: hex_digest(public_instance.statement_digest),
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
    if fs::metadata(root.join("verifier-replay.bin"))
        .map_err(|error| format!("stat C6.1 verifier replay: {error}"))?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err("C6.1 verifier replay is accessible by group/other".to_owned());
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
    if record.schema != 1
        || record.profile != CAMPAIGN_ARTIFACT_PROFILE
        || record.git_dirty
        || record.backend != CAMPAIGN_BACKEND
        || record.pcg != CAMPAIGN_PCG
        || record.files.len() != CAMPAIGN_FILE_NAMES.len()
        || record.files.iter().map(|row| row.name.as_str()).ne(CAMPAIGN_FILE_NAMES)
        || record.files.iter().map(|row| row.confidential).ne([false, true, false, false])
    {
        return Err("C6.1 campaign manifest profile/backend/PCG/file census mismatch".to_owned());
    }
    let payloads = CampaignPayloads {
        certificate: load_campaign_file(root, &record.files[0])?,
        verifier_replay: load_campaign_file(root, &record.files[1])?,
        verifier_model: load_campaign_file(root, &record.files[2])?,
        public_instance: load_campaign_file(root, &record.files[3])?,
    };
    let mut artifact = decode_campaign_payloads(&payloads)?;
    let inner = artifact.certificate.certificate();
    if record.wire_bytes != artifact.wire_bytes
        || parse_hex_32(&record.certificate_digest, "campaign certificate digest")?
            != inner.digest().map_err(|error| error.to_string())?
        || parse_hex_32(&record.setup_manifest_digest, "campaign setup digest")?
            != inner.setup_manifest_digest
        || parse_hex_32(&record.statement_digest, "campaign statement digest")?
            != artifact.public_instance.statement_digest
    {
        return Err("C6.1 campaign manifest binding differs from decoded objects".to_owned());
    }
    artifact.source_git_commit = record.source_git_commit;
    Ok(artifact)
}

#[cfg(test)]
mod campaign_artifact_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

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
            verifier_model: b"model".to_vec(),
            public_instance: b"instance".to_vec(),
        }
    }

    fn dummy_record(payloads: &CampaignPayloads) -> CampaignArtifactRecord {
        CampaignArtifactRecord {
            schema: 1,
            profile: CAMPAIGN_ARTIFACT_PROFILE.to_owned(),
            source_git_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_dirty: false,
            backend: CAMPAIGN_BACKEND.to_owned(),
            pcg: CAMPAIGN_PCG.to_owned(),
            certificate_digest: "11".repeat(32),
            setup_manifest_digest: "22".repeat(32),
            statement_digest: "33".repeat(32),
            wire_bytes: payloads.certificate.len() as u64,
            files: campaign_rows(payloads).unwrap(),
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

        fs::remove_file(root.join("verifier-model.bin")).unwrap();
        std::os::unix::fs::symlink("certificate.bin", root.join("verifier-model.bin")).unwrap();
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
