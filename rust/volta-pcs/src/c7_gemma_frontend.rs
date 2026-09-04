//! Static, Gemma-only frontend admission screen for D126.
//!
//! This module binds the current terminal declaration to pinned checkpoint
//! headers and the 60 real public `layer_scalar` values.  It deliberately has
//! no dependency on the historical model compiler.  The 100 prompt token IDs
//! are pinned; missing weight bodies, quantization, 50 decode/golden IDs, B/KV
//! proof layouts and base-GKR rows stay explicit blockers rather than receiving
//! zero-cost or synthetic credit.

use crate::gemma31b_terminal_manifest::{
    declared_gemma31b_terminal_manifest, TerminalPlane, GEMMA31B_PACKED_I16_BYTES,
    GEMMA31B_PRIVATE_LEARNED_TENSORS, GEMMA31B_PUBLIC_LAYER_SCALARS,
    GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX, GEMMA31B_WEIGHT_TERMINALS,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const FRONTEND_SCHEMA: &str = "volta-c7-d126-gemma31b-static-frontend-v1";
pub const SOURCE_METADATA_SCHEMA: &str = "volta-c7-d126-gemma31b-source-metadata-v1";
pub const LAYER_SCALAR_SCHEMA: &str = "volta-c7-d126-gemma31b-layer-scalars-v1";
pub const REFERENCE_SEMANTICS_SCHEMA: &str = "volta-c7-d126-gemma31b-reference-semantics-v1";
pub const WORKLOAD_SCHEMA: &str = "volta-c7-d126-gemma31b-workload-v1";
pub const QUANT_REQUIREMENTS_SCHEMA: &str = "volta-c7-d126-gemma31b-quant-requirements-v1";
pub const MODEL: &str = "google/gemma-4-31B";
pub const REVISION: &str = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89";
pub const CONFIG_SHA256: &str = "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e";
pub const INDEX_SHA256: &str = "d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2";
pub const TOKENIZER_SHA256: &str =
    "12bac982b793c44b03d52a250a9f0d0b666813da566b910c24a6da0695fd11e6";
pub const SOURCE_METADATA_SHA256: &str =
    "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2";
pub const LAYER_SCALAR_CSV_SHA256: &str =
    "52c10c73dad7a8a81f937d4954d3b38b6cf38216393793e23571b3c6017d67af";
pub const ORDERED_LAYER_SCALAR_RAW_SHA256: &str =
    "4d4ddd2f27faee67f141f83903c02bc93864a92402fd2cb9896da2628e6dbb70";
pub const WORKLOAD_SHA256: &str =
    "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b";
pub const QUANT_REQUIREMENTS_SHA256: &str =
    "1c887d530b1b33bb8775f58d139378c3f156e5e519c90f150d13a80be296eaf2";

// Filled from the checked-in bytes and asserted by the focused test.  Unlike
// the SHA-256 sidecars, these are recomputed here with an existing dependency.
pub const SOURCE_METADATA_BLAKE3: &str =
    "65bb4f1ceffc9bea4bd243a2f5070dcf80bdc17da85dae331f3062b5bb32fa37";
pub const LAYER_SCALAR_CSV_BLAKE3: &str =
    "97178b6f4ce035af5de85a9f496b48b034fcb687959b4b32dda6d052c35212c0";
pub const REFERENCE_SEMANTICS_BLAKE3: &str =
    "b8a59904ed30124381de85689242889cc1f37c408e7857a5f07629df7f7d124a";
pub const WORKLOAD_BLAKE3: &str =
    "91a5b6aec3731c27a32c439a4b413581003f4ec3b1958cc79478b439f45ab8a9";
pub const QUANT_REQUIREMENTS_BLAKE3: &str =
    "b26e8efc007e3bc81136565f859e9c1b934f362b573b6ec2cbda342bf3e90153";

pub const SOURCE_METADATA_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-source-metadata-v1.json");
pub const SOURCE_METADATA_SHA256_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-source-metadata-v1.sha256");
pub const SOURCE_METADATA_BLAKE3_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-source-metadata-v1.blake3");
pub const LAYER_SCALAR_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-layer-scalars-v1.csv");
pub const LAYER_SCALAR_SHA256_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-layer-scalars-v1.sha256");
pub const LAYER_SCALAR_BLAKE3_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-layer-scalars-v1.blake3");
pub const REFERENCE_SEMANTICS_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-reference-semantics-v1.txt");
pub const WORKLOAD_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-workload-v1.json");
pub const WORKLOAD_SHA256_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-workload-v1.sha256");
pub const QUANT_REQUIREMENTS_SOURCE: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-quant-requirements-v1.json");
pub const QUANT_REQUIREMENTS_SHA256_SIDECAR: &str =
    include_str!("../../../manifests/c7-d126-gemma31b-quant-requirements-v1.sha256");

const HIDDEN_SIZE: u64 = 5_376;
const INTERMEDIATE_SIZE: u64 = 21_504;
const VOCAB_SIZE: u64 = 262_144;
const LOCAL_QUERY_WIDTH: u64 = 8_192;
const LOCAL_KV_WIDTH: u64 = 4_096;
const GLOBAL_QUERY_WIDTH: u64 = 16_384;
const GLOBAL_KV_WIDTH: u64 = 2_048;
const GLOBAL_LAYERS: u64 = 10;
const LOCAL_LAYERS: u64 = 50;
const LOCAL_KV_HEADS: u64 = 16;
const LOCAL_HEAD_DIM: u64 = 256;
const GLOBAL_KV_HEADS: u64 = 4;
const GLOBAL_HEAD_DIM: u64 = 512;
const BF16_BYTES: u64 = 2;
const I16_BYTES: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CompileError {}

type Result<T> = std::result::Result<T, CompileError>;

fn fail(message: impl Into<String>) -> CompileError {
    CompileError(message.into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReference {
    bytes: u64,
    name: String,
    sha256: String,
    url: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionCredit {
    full_source_bodies_verified: bool,
    gemma_quant_v1: bool,
    runtime_tensor_use: bool,
    source_metadata_and_public_scalar_values: bool,
    workload_token_ids: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShardMetadata {
    bytes: u64,
    header_bytes: u64,
    header_sha256: String,
    lfs_sha256: String,
    name: String,
    tensor_count: usize,
    url: String,
    xet_hash: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TensorMetadata {
    data_offsets: [u64; 2],
    disposition: String,
    dtype: String,
    file_offsets: [u64; 2],
    name: String,
    nbytes: u64,
    shape: Vec<u64>,
    shard: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicLayerScalarMetadata {
    bf16_bits: u16,
    data_offsets: [u64; 2],
    disposition: String,
    dtype: String,
    file_offsets: [u64; 2],
    layer: u8,
    name: String,
    nbytes: u64,
    raw_le_hex: String,
    shape: Vec<u64>,
    shard: String,
    value_hexfloat: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataSummary {
    complete_weight_shards_downloaded: u64,
    forbidden_vision_bridge_scalars: u64,
    forbidden_vision_bridge_tensors: usize,
    framing_bytes: u64,
    ordered_public_layer_scalar_bytes_sha256: String,
    payload_bytes: u64,
    physical_tensors: usize,
    private_text_scalars: u64,
    private_text_tensors: usize,
    public_layer_scalar_values_are_runtime_usage_claims: bool,
    public_layer_scalars: usize,
    weight_shard_bytes_requested: u64,
    weight_tensor_value_bytes_requested: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMetadataArtifact {
    admission_credit: AdmissionCredit,
    config: ArtifactReference,
    index: ArtifactReference,
    model: String,
    public_layer_scalars: Vec<PublicLayerScalarMetadata>,
    revision: String,
    schema: String,
    shards: Vec<ShardMetadata>,
    summary: MetadataSummary,
    tensors: Vec<TensorMetadata>,
    tokenizer: ArtifactReference,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadTokenizer {
    add_special_tokens: bool,
    bytes: u64,
    file: String,
    reference_engine: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadPrompt {
    full_token_count: u32,
    text: String,
    text_utf8_sha256: String,
    token_ids: Vec<u32>,
    token_ids_u32le_sha256: String,
    truncation: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadGeneration {
    decode_tokens: u32,
    early_stop_on_eos: bool,
    output_token_ids_status: String,
    sampling_randomness: String,
    selection: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadLengths {
    batch_size: u32,
    context_capacity_tokens: u32,
    decode_tokens: u32,
    live_tokens: u32,
    max_concurrent_gpu_responses: u32,
    prompt_tokens: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadPadding {
    certificate_bytes: u64,
    device_lane_padding: String,
    kv_capacity_tokens: u32,
    packed_source_bytes: u64,
    persistent_tokens: u32,
    transcript_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadCredit {
    bit_exact_witness: bool,
    decode_token_ids: bool,
    prompt_token_ids: bool,
    runtime_enforcement: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadArtifact {
    credit: WorkloadCredit,
    generation: WorkloadGeneration,
    lengths: WorkloadLengths,
    model: String,
    padding: WorkloadPadding,
    prompt: WorkloadPrompt,
    revision: String,
    schema: String,
    tokenizer: WorkloadTokenizer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorDescriptor {
    pub name: String,
    pub shard: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub data_offsets: [u64; 2],
    pub file_offsets: [u64; 2],
    pub nbytes: u64,
}

impl From<&TensorMetadata> for TensorDescriptor {
    fn from(value: &TensorMetadata) -> Self {
        Self {
            name: value.name.clone(),
            shard: value.shard.clone(),
            dtype: value.dtype.clone(),
            shape: value.shape.clone(),
            data_offsets: value.data_offsets,
            file_offsets: value.file_offsets,
            nbytes: value.nbytes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicLayerScalar {
    pub layer: u8,
    pub name: String,
    pub raw_le_hex: String,
    pub bf16_bits: u16,
    pub value_hexfloat: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightRelationKind {
    Matrix,
    RaggedNormBundle,
    TiedEmbedding,
    FinalNorm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightRelationMetadata {
    pub terminal_ordinal: u16,
    pub owner: String,
    pub kind: WeightRelationKind,
    pub private_sources: Vec<TensorDescriptor>,
    pub public_layer_scalar: Option<PublicLayerScalar>,
    /// Headers and public values are bound, but quantized tensor values are not.
    pub runtime_value_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub batch: u32,
    pub prompt_tokens: u32,
    pub response_tokens: u32,
    pub live_tokens: u32,
    pub context_capacity: u32,
    pub persistent_source_padding_tokens: u32,
    pub persistent_certificate_padding_tokens: u32,
    pub prompt_token_ids_bound: bool,
    pub decode_token_ids_bound: bool,
    pub quantization_bound: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvCapacityRecord {
    pub local_layers: u64,
    pub global_layers: u64,
    pub values_per_token: u64,
    pub live_len: u32,
    pub capacity: u32,
    pub live_bytes: u64,
    pub capacity_bytes: u64,
    pub persistent_padding_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredRecordContract {
    pub id: &'static str,
    pub required_fields: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockedRecordSet {
    pub contract: RequiredRecordContract,
    pub rows_emitted: usize,
    pub credit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontendBlocker {
    pub code: &'static str,
    pub unblock: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontendStatus {
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledGemma31BFrontend {
    pub schema: &'static str,
    pub terminal_manifest_blake3: String,
    pub source_metadata_blake3: String,
    pub layer_scalar_csv_blake3: String,
    pub reference_semantics_blake3: String,
    pub workload_blake3: String,
    pub quant_requirements_blake3: String,
    pub workload: WorkloadRecord,
    pub kv_capacity: KvCapacityRecord,
    pub weight_relations: Vec<WeightRelationMetadata>,
    pub public_layer_scalars: Vec<PublicLayerScalar>,
    pub bkv_layouts: BlockedRecordSet,
    pub base_gkr_cohorts: BlockedRecordSet,
    pub blockers: Vec<FrontendBlocker>,
    pub status: FrontendStatus,
    pub admission_credit: bool,
}

const BKV_REQUIRED_FIELDS: &[&str] = &[
    "plane",
    "relation_digest",
    "physical_root_id",
    "root_multiplicity_scope",
    "terminal_ordinals",
    "live_len",
    "capacity",
    "leaf_symbols",
    "tree_leaves_by_round",
    "query_pairs_by_round",
    "q_by_round",
    "U_by_round",
    "S_by_round",
    "H_by_round",
    "mask_loads_per_root",
];

const BASE_GKR_REQUIRED_FIELDS: &[&str] = &[
    "cohort_id",
    "operator_inventory_digest",
    "covered_operator_ids",
    "K",
    "degrees",
    "sum_d",
    "n",
    "root_numerator",
    "common_point_id",
    "common_point_dimension",
    "hfin_relation_id",
    "pcs_link_ids",
    "transcript_order",
];

fn digest_hex(source: &str) -> String {
    blake3::hash(source.as_bytes()).to_hex().to_string()
}

fn require_blake3(source: &str, expected: &str, label: &str) -> Result<String> {
    let actual = digest_hex(source);
    if actual != expected {
        return Err(fail(format!("{label} BLAKE3 differs: expected {expected}, got {actual}")));
    }
    Ok(actual)
}

fn require_sha256_sidecar(
    sidecar: &str,
    expected_digest: &str,
    expected_filename: &str,
) -> Result<()> {
    let expected = format!("{expected_digest}  {expected_filename}\n");
    if sidecar != expected {
        return Err(fail(format!("{expected_filename} SHA-256 sidecar differs")));
    }
    Ok(())
}

fn require_blake3_sidecar(sidecar: &str, expected_digest: &str, label: &str) -> Result<()> {
    if sidecar != format!("{expected_digest}\n") {
        return Err(fail(format!("{label} BLAKE3 sidecar differs")));
    }
    Ok(())
}

fn require_artifact(
    artifact: &ArtifactReference,
    name: &str,
    bytes: u64,
    sha256: &str,
) -> Result<()> {
    if artifact.name != name
        || artifact.bytes != bytes
        || artifact.sha256 != sha256
        || !artifact.url.starts_with("https://huggingface.co/google/gemma-4-31B/resolve/")
        || !artifact.url.contains(REVISION)
        || !artifact.url.ends_with(name)
    {
        return Err(fail(format!("pinned {name} reference differs")));
    }
    Ok(())
}

fn checked_shape_bytes(shape: &[u64], bytes_per_element: u64, label: &str) -> Result<u64> {
    if shape.is_empty() || shape.contains(&0) {
        return Err(fail(format!("{label} has an empty or zero-sized shape")));
    }
    shape
        .iter()
        .try_fold(bytes_per_element, |total, dimension| total.checked_mul(*dimension))
        .ok_or_else(|| fail(format!("{label} shape byte count overflows")))
}

fn validate_tensor(tensor: &TensorMetadata, shards: &BTreeMap<&str, &ShardMetadata>) -> Result<()> {
    if tensor.dtype != "BF16" {
        return Err(fail(format!("{} is not BF16", tensor.name)));
    }
    let expected_bytes = checked_shape_bytes(&tensor.shape, BF16_BYTES, &tensor.name)?;
    if tensor.nbytes != expected_bytes
        || tensor.data_offsets[1].checked_sub(tensor.data_offsets[0]) != Some(tensor.nbytes)
        || tensor.file_offsets[1].checked_sub(tensor.file_offsets[0]) != Some(tensor.nbytes)
    {
        return Err(fail(format!("{} shape and offsets disagree", tensor.name)));
    }
    let shard = shards
        .get(tensor.shard.as_str())
        .ok_or_else(|| fail(format!("{} names an unknown shard", tensor.name)))?;
    let data_base = 8u64
        .checked_add(shard.header_bytes)
        .ok_or_else(|| fail("safetensors data base overflows"))?;
    if tensor.file_offsets
        != [data_base + tensor.data_offsets[0], data_base + tensor.data_offsets[1]]
        || tensor.file_offsets[1] > shard.bytes
    {
        return Err(fail(format!("{} file offsets differ", tensor.name)));
    }
    Ok(())
}

fn validate_source_metadata(source: &str) -> Result<SourceMetadataArtifact> {
    require_sha256_sidecar(
        SOURCE_METADATA_SHA256_SIDECAR,
        SOURCE_METADATA_SHA256,
        "c7-d126-gemma31b-source-metadata-v1.json",
    )?;
    require_blake3_sidecar(
        SOURCE_METADATA_BLAKE3_SIDECAR,
        SOURCE_METADATA_BLAKE3,
        "source metadata",
    )?;
    require_blake3(source, SOURCE_METADATA_BLAKE3, "source metadata")?;
    let artifact: SourceMetadataArtifact = serde_json::from_str(source)
        .map_err(|error| fail(format!("source metadata JSON: {error}")))?;
    if artifact.schema != SOURCE_METADATA_SCHEMA
        || artifact.model != MODEL
        || artifact.revision != REVISION
    {
        return Err(fail("source metadata identity differs"));
    }
    require_artifact(&artifact.config, "config.json", 4_181, CONFIG_SHA256)?;
    require_artifact(&artifact.index, "model.safetensors.index.json", 120_246, INDEX_SHA256)?;
    require_artifact(&artifact.tokenizer, "tokenizer.json", 32_170_070, TOKENIZER_SHA256)?;
    if artifact.admission_credit.full_source_bodies_verified
        || artifact.admission_credit.gemma_quant_v1
        || artifact.admission_credit.runtime_tensor_use
        || !artifact.admission_credit.source_metadata_and_public_scalar_values
        || artifact.admission_credit.workload_token_ids
    {
        return Err(fail("source metadata admission-credit flags differ"));
    }
    let summary = &artifact.summary;
    if summary.complete_weight_shards_downloaded != 0
        || summary.forbidden_vision_bridge_scalars != 575_743_536
        || summary.forbidden_vision_bridge_tensors != 356
        || summary.framing_bytes != 160_496
        || summary.ordered_public_layer_scalar_bytes_sha256 != ORDERED_LAYER_SCALAR_RAW_SHA256
        || summary.payload_bytes != 62_546_177_752
        || summary.physical_tensors != 1_188
        || summary.private_text_scalars != 30_697_345_280
        || summary.private_text_tensors != GEMMA31B_PRIVATE_LEARNED_TENSORS
        || summary.public_layer_scalar_values_are_runtime_usage_claims
        || summary.public_layer_scalars != GEMMA31B_PUBLIC_LAYER_SCALARS
        || summary.weight_shard_bytes_requested != 160_616
        || summary.weight_tensor_value_bytes_requested != 120
    {
        return Err(fail("source metadata summary differs"));
    }
    if artifact.shards.len() != 2 {
        return Err(fail("source metadata must contain two shards"));
    }
    let shards: BTreeMap<_, _> =
        artifact.shards.iter().map(|shard| (shard.name.as_str(), shard)).collect();
    if shards.len() != 2 {
        return Err(fail("source metadata shard names are duplicated"));
    }
    let expected_shards = [
        (
            "model-00001-of-00002.safetensors",
            49_784_788_364,
            136_896,
            1_009,
            "a58b10bc7e2ec1c7d062896e71f69466c8981440cab7a045510fb997e4b91bc9",
            "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
            "0a57a19d7f8430e9bd73af466cca6032f13677bcee640d0a26234eeff1923473",
        ),
        (
            "model-00002-of-00002.safetensors",
            12_761_549_884,
            23_584,
            179,
            "2b82d9b263de66d77efdc15b56743d5d3b1cfb1ee4587acdd836c54c7eadfb42",
            "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
            "2324e95577e5d990387e6343d68f71675d1885fdba16e94c5d68fbd0b0a68e40",
        ),
    ];
    for (name, bytes, header_bytes, tensor_count, header_sha, lfs_sha, xet_hash) in expected_shards
    {
        let shard = shards.get(name).ok_or_else(|| fail(format!("missing shard {name}")))?;
        if shard.bytes != bytes
            || shard.header_bytes != header_bytes
            || shard.tensor_count != tensor_count
            || shard.header_sha256 != header_sha
            || shard.lfs_sha256 != lfs_sha
            || shard.xet_hash != xet_hash
            || !shard.url.contains(REVISION)
            || !shard.url.ends_with(name)
        {
            return Err(fail(format!("pinned shard {name} differs")));
        }
    }

    if artifact.tensors.len() != 1_188
        || !artifact.tensors.windows(2).all(|pair| pair[0].name < pair[1].name)
    {
        return Err(fail("tensor inventory count or canonical order differs"));
    }
    for tensor in &artifact.tensors {
        validate_tensor(tensor, &shards)?;
    }
    for shard in &artifact.shards {
        let mut rows: Vec<_> =
            artifact.tensors.iter().filter(|tensor| tensor.shard == shard.name).collect();
        rows.sort_by_key(|tensor| tensor.data_offsets[0]);
        if rows.len() != shard.tensor_count {
            return Err(fail(format!("{} tensor count differs", shard.name)));
        }
        let mut cursor = 0;
        for tensor in rows {
            if tensor.data_offsets[0] != cursor {
                return Err(fail(format!("{} data ranges have a gap or overlap", shard.name)));
            }
            cursor = tensor.data_offsets[1];
        }
        if 8 + shard.header_bytes + cursor != shard.bytes {
            return Err(fail(format!("{} data ranges do not fill the shard", shard.name)));
        }
    }
    Ok(artifact)
}

fn parse_raw_le_hex(raw: &str, label: &str) -> Result<u16> {
    if raw.len() != 4 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(fail(format!("{label} raw_le_hex is not four hex digits")));
    }
    let low = u8::from_str_radix(&raw[..2], 16)
        .map_err(|_| fail(format!("{label} raw_le_hex low byte is invalid")))?;
    let high = u8::from_str_radix(&raw[2..], 16)
        .map_err(|_| fail(format!("{label} raw_le_hex high byte is invalid")))?;
    Ok(u16::from_le_bytes([low, high]))
}

fn parse_layer_scalars(source: &str) -> Result<Vec<PublicLayerScalar>> {
    require_sha256_sidecar(
        LAYER_SCALAR_SHA256_SIDECAR,
        LAYER_SCALAR_CSV_SHA256,
        "c7-d126-gemma31b-layer-scalars-v1.csv",
    )?;
    require_blake3_sidecar(
        LAYER_SCALAR_BLAKE3_SIDECAR,
        LAYER_SCALAR_CSV_BLAKE3,
        "layer-scalar CSV",
    )?;
    require_blake3(source, LAYER_SCALAR_CSV_BLAKE3, "layer-scalar CSV")?;
    if !source.ends_with('\n') || source.contains('\r') {
        return Err(fail("layer-scalar CSV is not canonical LF text"));
    }
    let mut lines = source.split_terminator('\n');
    let headers = [
        format!("@schema={LAYER_SCALAR_SCHEMA}"),
        format!("@model={MODEL}"),
        format!("@revision={REVISION}"),
        format!("@source_metadata_sha256={SOURCE_METADATA_SHA256}"),
        format!("@ordered_raw_sha256={ORDERED_LAYER_SCALAR_RAW_SHA256}"),
        "@count=60".to_owned(),
        "@record_columns=layer|name|raw_le_hex|bf16_bits|value_hexfloat".to_owned(),
    ];
    for expected in headers {
        if lines.next() != Some(expected.as_str()) {
            return Err(fail(format!("layer-scalar CSV header differs at {expected}")));
        }
    }
    let mut result = Vec::with_capacity(GEMMA31B_PUBLIC_LAYER_SCALARS);
    for layer in 0..GEMMA31B_PUBLIC_LAYER_SCALARS {
        let line = lines.next().ok_or_else(|| fail(format!("layer scalar {layer} is missing")))?;
        let fields: Vec<_> = line.split(',').collect();
        let expected_name = format!("model.language_model.layers.{layer}.layer_scalar");
        if fields.len() != 5 || fields[0] != layer.to_string() || fields[1] != expected_name {
            return Err(fail(format!("layer scalar {layer} identity/order differs")));
        }
        let bits = fields[3]
            .parse::<u16>()
            .map_err(|_| fail(format!("layer scalar {layer} bf16_bits is invalid")))?;
        if parse_raw_le_hex(fields[2], &expected_name)? != bits
            || !fields[4].starts_with("0x1.")
            || !fields[4].contains('p')
        {
            return Err(fail(format!("layer scalar {layer} value encoding differs")));
        }
        result.push(PublicLayerScalar {
            layer: layer as u8,
            name: expected_name,
            raw_le_hex: fields[2].to_owned(),
            bf16_bits: bits,
            value_hexfloat: fields[4].to_owned(),
        });
    }
    if lines.next().is_some()
        || result.iter().map(|row| row.bf16_bits).collect::<BTreeSet<_>>().len() < 2
    {
        return Err(fail("layer-scalar CSV has trailing rows or constant placeholder values"));
    }
    Ok(result)
}

fn tensor_from_public(value: &PublicLayerScalarMetadata) -> TensorMetadata {
    TensorMetadata {
        data_offsets: value.data_offsets,
        disposition: value.disposition.clone(),
        dtype: value.dtype.clone(),
        file_offsets: value.file_offsets,
        name: value.name.clone(),
        nbytes: value.nbytes,
        shape: value.shape.clone(),
        shard: value.shard.clone(),
    }
}

fn validate_public_scalars(
    artifact: &SourceMetadataArtifact,
    csv: &[PublicLayerScalar],
) -> Result<()> {
    if artifact.public_layer_scalars.len() != GEMMA31B_PUBLIC_LAYER_SCALARS
        || csv.len() != GEMMA31B_PUBLIC_LAYER_SCALARS
    {
        return Err(fail("public layer-scalar count differs"));
    }
    let tensors: BTreeMap<_, _> =
        artifact.tensors.iter().map(|tensor| (tensor.name.as_str(), tensor)).collect();
    for (layer, (metadata, declared)) in artifact.public_layer_scalars.iter().zip(csv).enumerate() {
        let expected_name = format!("model.language_model.layers.{layer}.layer_scalar");
        let tensor = tensors
            .get(expected_name.as_str())
            .ok_or_else(|| fail(format!("missing public tensor {expected_name}")))?;
        if usize::from(metadata.layer) != layer
            || metadata.name != expected_name
            || metadata.disposition != "public_layer_scalar"
            || metadata.dtype != "BF16"
            || metadata.shape != [1]
            || metadata.nbytes != 2
            || tensor_from_public(metadata) != **tensor
            || metadata.raw_le_hex != declared.raw_le_hex
            || metadata.bf16_bits != declared.bf16_bits
            || metadata.value_hexfloat != declared.value_hexfloat
        {
            return Err(fail(format!("public layer scalar {layer} differs between artifacts")));
        }
    }
    Ok(())
}

fn expected_matrix_shape(owner: &str) -> Option<[u64; 2]> {
    let global = owner
        .strip_prefix("weight/layer/")
        .and_then(|tail| tail.split('/').next())
        .and_then(|layer| layer.parse::<usize>().ok())
        .is_some_and(|layer| layer % 6 == 5);
    let role = owner.rsplit('/').next()?;
    match (global, role) {
        (false, "q_proj") => Some([LOCAL_QUERY_WIDTH, HIDDEN_SIZE]),
        (false, "k_proj" | "v_proj") => Some([LOCAL_KV_WIDTH, HIDDEN_SIZE]),
        (false, "o_proj") => Some([HIDDEN_SIZE, LOCAL_QUERY_WIDTH]),
        (true, "q_proj") => Some([GLOBAL_QUERY_WIDTH, HIDDEN_SIZE]),
        (true, "k_eq_v_proj") => Some([GLOBAL_KV_WIDTH, HIDDEN_SIZE]),
        (true, "o_proj") => Some([HIDDEN_SIZE, GLOBAL_QUERY_WIDTH]),
        (_, "gate_proj" | "up_proj") => Some([INTERMEDIATE_SIZE, HIDDEN_SIZE]),
        (_, "down_proj") => Some([HIDDEN_SIZE, INTERMEDIATE_SIZE]),
        _ => None,
    }
}

fn compile_weight_relations(
    artifact: &SourceMetadataArtifact,
    public_scalars: &[PublicLayerScalar],
) -> Result<Vec<WeightRelationMetadata>> {
    let manifest = declared_gemma31b_terminal_manifest().map_err(fail)?;
    let tensors: BTreeMap<_, _> =
        artifact.tensors.iter().map(|tensor| (tensor.name.as_str(), tensor)).collect();
    let scalar_by_name: BTreeMap<_, _> =
        public_scalars.iter().map(|scalar| (scalar.name.as_str(), scalar)).collect();
    let declared_private: BTreeSet<_> = manifest
        .records
        .iter()
        .flat_map(|record| record.private_source_keys.iter().map(String::as_str))
        .collect();
    let declared_public: BTreeSet<_> = manifest
        .records
        .iter()
        .flat_map(|record| record.public_source_keys.iter().map(String::as_str))
        .collect();
    let metadata_private: BTreeSet<_> = artifact
        .tensors
        .iter()
        .filter(|tensor| tensor.disposition == "private_text")
        .map(|tensor| tensor.name.as_str())
        .collect();
    let metadata_public: BTreeSet<_> = artifact
        .tensors
        .iter()
        .filter(|tensor| tensor.disposition == "public_layer_scalar")
        .map(|tensor| tensor.name.as_str())
        .collect();
    let forbidden = artifact
        .tensors
        .iter()
        .filter(|tensor| tensor.disposition == "forbidden_vision_bridge")
        .count();
    if declared_private != metadata_private
        || declared_public != metadata_public
        || forbidden != 356
        || artifact.tensors.iter().any(|tensor| {
            !matches!(
                tensor.disposition.as_str(),
                "private_text" | "public_layer_scalar" | "forbidden_vision_bridge"
            )
        })
    {
        return Err(fail("terminal manifest and source metadata partition differ"));
    }

    let mut relations = Vec::with_capacity(GEMMA31B_WEIGHT_TERMINALS);
    for record in manifest.records.iter().filter(|record| record.plane == TerminalPlane::Weight) {
        let private_sources: Vec<_> = record
            .private_source_keys
            .iter()
            .map(|name| {
                tensors
                    .get(name.as_str())
                    .map(|tensor| TensorDescriptor::from(*tensor))
                    .ok_or_else(|| fail(format!("{} misses source {name}", record.owner)))
            })
            .collect::<Result<_>>()?;
        let public_layer_scalar = match record.public_source_keys.as_slice() {
            [] => None,
            [name] => Some(
                scalar_by_name
                    .get(name.as_str())
                    .ok_or_else(|| fail(format!("{} misses public scalar {name}", record.owner)))?
                    .to_owned()
                    .clone(),
            ),
            _ => return Err(fail(format!("{} has multiple public scalars", record.owner))),
        };
        let kind = if record.owner.ends_with("/norm_bundle") {
            WeightRelationKind::RaggedNormBundle
        } else if record.owner == "weight/tied_embedding" {
            WeightRelationKind::TiedEmbedding
        } else if record.owner == "weight/final_norm" {
            WeightRelationKind::FinalNorm
        } else {
            WeightRelationKind::Matrix
        };
        match kind {
            WeightRelationKind::Matrix => {
                let expected = expected_matrix_shape(&record.owner).ok_or_else(|| {
                    fail(format!("{} has no Gemma matrix geometry", record.owner))
                })?;
                if private_sources.len() != 1
                    || private_sources[0].shape != expected
                    || public_layer_scalar.is_some()
                {
                    return Err(fail(format!("{} matrix shape/binding differs", record.owner)));
                }
            }
            WeightRelationKind::RaggedNormBundle => {
                let layer = record
                    .owner
                    .split('/')
                    .nth(2)
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| fail(format!("{} layer is invalid", record.owner)))?;
                let attention_dim = if layer % 6 == 5 { GLOBAL_HEAD_DIM } else { LOCAL_HEAD_DIM };
                let expected_shapes = [
                    vec![HIDDEN_SIZE],
                    vec![HIDDEN_SIZE],
                    vec![HIDDEN_SIZE],
                    vec![HIDDEN_SIZE],
                    vec![attention_dim],
                    vec![attention_dim],
                ];
                if private_sources.iter().map(|source| &source.shape).ne(expected_shapes.iter())
                    || public_layer_scalar.is_none()
                {
                    return Err(fail(format!("{} ragged norm geometry differs", record.owner)));
                }
            }
            WeightRelationKind::TiedEmbedding => {
                if private_sources.len() != 1
                    || private_sources[0].shape != [VOCAB_SIZE, HIDDEN_SIZE]
                    || public_layer_scalar.is_some()
                {
                    return Err(fail("tied embedding geometry differs"));
                }
            }
            WeightRelationKind::FinalNorm => {
                if private_sources.len() != 1
                    || private_sources[0].shape != [HIDDEN_SIZE]
                    || public_layer_scalar.is_some()
                {
                    return Err(fail("final norm geometry differs"));
                }
            }
        }
        relations.push(WeightRelationMetadata {
            terminal_ordinal: record.ordinal,
            owner: record.owner.clone(),
            kind,
            private_sources,
            public_layer_scalar,
            runtime_value_bound: false,
        });
    }
    if relations.len() != GEMMA31B_WEIGHT_TERMINALS {
        return Err(fail("compiled weight relation count is not 472"));
    }
    let private_bytes = relations.iter().try_fold(0u64, |total, relation| {
        relation.private_sources.iter().try_fold(total, |subtotal, source| {
            subtotal.checked_add(source.nbytes).ok_or_else(|| fail("private byte census overflows"))
        })
    })?;
    if private_bytes != GEMMA31B_PACKED_I16_BYTES {
        return Err(fail("compiled private BF16/i16 byte census differs"));
    }
    Ok(relations)
}

fn compile_workload() -> Result<(WorkloadRecord, KvCapacityRecord)> {
    require_sha256_sidecar(
        WORKLOAD_SHA256_SIDECAR,
        WORKLOAD_SHA256,
        "c7-d126-gemma31b-workload-v1.json",
    )?;
    require_blake3(WORKLOAD_SOURCE, WORKLOAD_BLAKE3, "workload")?;
    let artifact: WorkloadArtifact = serde_json::from_str(WORKLOAD_SOURCE)
        .map_err(|error| fail(format!("workload JSON: {error}")))?;
    if artifact.schema != WORKLOAD_SCHEMA
        || artifact.model != MODEL
        || artifact.revision != REVISION
        || artifact.tokenizer.file != "tokenizer.json"
        || artifact.tokenizer.bytes != 32_170_070
        || artifact.tokenizer.sha256 != TOKENIZER_SHA256
        || artifact.tokenizer.reference_engine != "huggingface-tokenizers-0.22.1"
        || !artifact.tokenizer.add_special_tokens
        || artifact.prompt.text.is_empty()
        || artifact.prompt.text_utf8_sha256
            != "e322cd81e67fbc271c4bd7683ff79677ae6891079bf173fe617ddb9e4f923b19"
        || artifact.prompt.full_token_count != 144
        || artifact.prompt.truncation != "first-100-token-ids-including-bos"
        || artifact.prompt.token_ids_u32le_sha256
            != "f08032f44ff6ca289c3d28d16f1f6911c4628e3b7b986c8e532191542e57287c"
        || artifact.prompt.token_ids.len() != 100
        || artifact.prompt.token_ids.first() != Some(&2)
        || artifact.prompt.token_ids.iter().any(|token| u64::from(*token) >= VOCAB_SIZE)
        || artifact.generation.decode_tokens != 50
        || artifact.generation.selection != "greedy-argmax-lowest-token-id-on-tie"
        || artifact.generation.early_stop_on_eos
        || artifact.generation.sampling_randomness != "none"
        || artifact.generation.output_token_ids_status
            != "blocked-until-GemmaQuantV1-bit-exact-forward"
        || artifact.lengths.prompt_tokens != 100
        || artifact.lengths.decode_tokens != 50
        || artifact.lengths.live_tokens != 150
        || artifact.lengths.context_capacity_tokens != 4_096
        || artifact.lengths.batch_size != 1
        || artifact.lengths.max_concurrent_gpu_responses != 1
        || artifact.padding.persistent_tokens != 0
        || artifact.padding.packed_source_bytes != 0
        || artifact.padding.certificate_bytes != 0
        || artifact.padding.transcript_bytes != 0
        || artifact.padding.kv_capacity_tokens != 4_096
        || artifact.padding.device_lane_padding != "temporary-only-must-be-emitted-and-counted"
        || !artifact.credit.prompt_token_ids
        || artifact.credit.decode_token_ids
        || artifact.credit.bit_exact_witness
        || artifact.credit.runtime_enforcement
    {
        return Err(fail("workload fields or credit differ"));
    }
    let workload = WorkloadRecord {
        batch: 1,
        prompt_tokens: 100,
        response_tokens: 50,
        live_tokens: 150,
        context_capacity: 4_096,
        persistent_source_padding_tokens: 0,
        persistent_certificate_padding_tokens: 0,
        prompt_token_ids_bound: true,
        decode_token_ids_bound: false,
        quantization_bound: false,
    };
    let values_per_token = LOCAL_LAYERS
        .checked_mul(LOCAL_KV_HEADS)
        .and_then(|value| value.checked_mul(LOCAL_HEAD_DIM))
        .and_then(|value| value.checked_mul(2))
        .and_then(|local| {
            GLOBAL_LAYERS
                .checked_mul(GLOBAL_KV_HEADS)
                .and_then(|value| value.checked_mul(GLOBAL_HEAD_DIM))
                .and_then(|value| value.checked_mul(2))
                .and_then(|global| local.checked_add(global))
        })
        .ok_or_else(|| fail("KV values per token overflow"))?;
    let live_bytes = values_per_token
        .checked_mul(u64::from(workload.live_tokens))
        .and_then(|value| value.checked_mul(I16_BYTES))
        .ok_or_else(|| fail("live KV bytes overflow"))?;
    let capacity_bytes = values_per_token
        .checked_mul(u64::from(workload.context_capacity))
        .and_then(|value| value.checked_mul(I16_BYTES))
        .ok_or_else(|| fail("capacity KV bytes overflow"))?;
    Ok((
        workload,
        KvCapacityRecord {
            local_layers: LOCAL_LAYERS,
            global_layers: GLOBAL_LAYERS,
            values_per_token,
            live_len: 150,
            capacity: 4_096,
            live_bytes,
            capacity_bytes,
            persistent_padding_bytes: 0,
        },
    ))
}

fn validate_quant_requirements() -> Result<String> {
    require_sha256_sidecar(
        QUANT_REQUIREMENTS_SHA256_SIDECAR,
        QUANT_REQUIREMENTS_SHA256,
        "c7-d126-gemma31b-quant-requirements-v1.json",
    )?;
    let digest = require_blake3(
        QUANT_REQUIREMENTS_SOURCE,
        QUANT_REQUIREMENTS_BLAKE3,
        "quantization requirements",
    )?;
    let artifact: serde_json::Value = serde_json::from_str(QUANT_REQUIREMENTS_SOURCE)
        .map_err(|error| fail(format!("quantization requirements JSON: {error}")))?;
    let profile = &artifact["profile"];
    let checkpoint = &artifact["checkpoint"];
    let packed = &artifact["packed_output"];
    let workload = &artifact["workload"];
    let scalars = &artifact["public_layer_scalars"];
    let acquisition = &artifact["acquisition_constraints"];
    let missing = artifact["required_uninstantiated"]
        .as_object()
        .ok_or_else(|| fail("quantization missing-field inventory is not an object"))?;
    let expected_missing: BTreeSet<_> = [
        "weight_exponents_by_tensor",
        "activation_exponents_by_operation",
        "rounding_rule",
        "saturation_rule",
        "accumulator_bounds_by_operation",
        "lut_table_schema",
        "lut_table_sha256",
        "calibration_schema",
        "calibration_manifest_sha256",
        "golden_schema",
        "golden_manifest_sha256",
        "rust_python_bit_equality_report_sha256",
    ]
    .into_iter()
    .collect();
    let actual_missing: BTreeSet<_> = missing.keys().map(String::as_str).collect();
    if artifact["schema"] != QUANT_REQUIREMENTS_SCHEMA
        || profile["name"] != "GemmaQuantV1"
        || profile["status"] != "BLOCKED"
        || profile["instantiated"] != false
        || profile["admission_credit"] != false
        || checkpoint["model"] != MODEL
        || checkpoint["revision"] != REVISION
        || checkpoint["source_metadata_sha256"] != SOURCE_METADATA_SHA256
        || packed["scalar_dtype"] != "i16"
        || packed["byte_order"] != "little"
        || packed["zero_point"] != 0
        || packed["bytes"] != GEMMA31B_PACKED_I16_BYTES
        || !packed["sha256"].is_null()
        || workload["sha256"] != WORKLOAD_SHA256
        || scalars["sha256"] != LAYER_SCALAR_CSV_SHA256
        || scalars["ordered_raw_sha256"] != ORDERED_LAYER_SCALAR_RAW_SHA256
        || actual_missing != expected_missing
        || missing.values().any(|value| !value.is_null())
        || acquisition["pod_authorized"] != false
        || acquisition["full_weight_shard_download_authorized"] != false
        || acquisition["historical_quantization_imports_allowed"] != false
    {
        return Err(fail("quantization requirements drifted or were incorrectly promoted"));
    }
    // Twelve named requirement fields plus the packed-output digest are open.
    if missing.len() + usize::from(packed["sha256"].is_null()) != 13 {
        return Err(fail("GemmaQuantV1 missing-field census is not 13"));
    }
    Ok(digest)
}

fn validate_reference_semantics() -> Result<String> {
    let required = [
        format!("@schema={REFERENCE_SEMANTICS_SCHEMA}"),
        "@runtime_commit=c1c34249fa27deefbd4a377dfbf883a39baf5c6d".to_owned(),
        "@runtime_tag=v5.5.0".to_owned(),
        "src/transformers/models/gemma4/modeling_gemma4.py|6a86e03348df5ec104703e7161de9a911137cba500a0be0f133e2850ef0bf935".to_owned(),
        "@corroborating_commit=7b785991bd78626c73b317eb43fdbb6c292f7b9c".to_owned(),
        "gemma/gm/nn/gemma4/_modules.py|aa422c5904a07e11b9076d91b7648fcd175354dea80c6410c92dc3d67574c17f".to_owned(),
        "@dependency_closure=partial".to_owned(),
        "@narrow_semantic_assertion=k_eq_v aliases the projection output before key_norm and parameter-free value_norm; global k_norm remains live".to_owned(),
    ];
    let lines: BTreeSet<_> = REFERENCE_SEMANTICS_SOURCE.lines().collect();
    if !REFERENCE_SEMANTICS_SOURCE.ends_with('\n')
        || required.iter().any(|line| !lines.contains(line.as_str()))
    {
        return Err(fail("reference semantics manifest differs"));
    }
    require_blake3(REFERENCE_SEMANTICS_SOURCE, REFERENCE_SEMANTICS_BLAKE3, "reference semantics")
}

pub fn compile_pinned_gemma31b_frontend() -> Result<CompiledGemma31BFrontend> {
    let metadata_digest =
        require_blake3(SOURCE_METADATA_SOURCE, SOURCE_METADATA_BLAKE3, "source metadata")?;
    let scalar_digest =
        require_blake3(LAYER_SCALAR_SOURCE, LAYER_SCALAR_CSV_BLAKE3, "layer-scalar CSV")?;
    let metadata = validate_source_metadata(SOURCE_METADATA_SOURCE)?;
    let public_layer_scalars = parse_layer_scalars(LAYER_SCALAR_SOURCE)?;
    validate_public_scalars(&metadata, &public_layer_scalars)?;
    let weight_relations = compile_weight_relations(&metadata, &public_layer_scalars)?;
    let reference_semantics_blake3 = validate_reference_semantics()?;
    let (workload, kv_capacity) = compile_workload()?;
    let quant_requirements_blake3 = validate_quant_requirements()?;
    let workload_blake3 = digest_hex(WORKLOAD_SOURCE);
    let terminal_manifest_blake3 = GEMMA31B_TERMINAL_MANIFEST_BLAKE3_HEX
        .strip_suffix('\n')
        .ok_or_else(|| fail("terminal manifest digest sidecar lacks LF"))?
        .to_owned();
    Ok(CompiledGemma31BFrontend {
        schema: FRONTEND_SCHEMA,
        terminal_manifest_blake3,
        source_metadata_blake3: metadata_digest,
        layer_scalar_csv_blake3: scalar_digest,
        reference_semantics_blake3,
        workload_blake3,
        quant_requirements_blake3,
        workload,
        kv_capacity,
        weight_relations,
        public_layer_scalars,
        bkv_layouts: BlockedRecordSet {
            contract: RequiredRecordContract {
                id: "real-bkv-layout-v1",
                required_fields: BKV_REQUIRED_FIELDS,
            },
            rows_emitted: 0,
            credit: false,
        },
        base_gkr_cohorts: BlockedRecordSet {
            contract: RequiredRecordContract {
                id: "base-gkr-cohort-v1",
                required_fields: BASE_GKR_REQUIRED_FIELDS,
            },
            rows_emitted: 0,
            credit: false,
        },
        blockers: vec![
            FrontendBlocker {
                code: "reference_semantics_dependency_closure",
                unblock: "pin every transitively executed text-runtime dependency and kernel",
            },
            FrontendBlocker {
                code: "gemma_quant_v1",
                unblock: "freeze GemmaQuantV1 semantics and bind its digest to every private source",
            },
            FrontendBlocker {
                code: "decode_token_ids",
                unblock: "run the bit-exact GemmaQuantV1 forward and emit the ordered 50 greedy-decode token IDs plus digest",
            },
            FrontendBlocker {
                code: "runtime_tensor_values",
                unblock: "stream both pinned shard bodies and bind quantized values to all 472 relations",
            },
            FrontendBlocker {
                code: "real_bkv_layouts",
                unblock: "emit every physical B/KV root and derive q/U/S/H from its complete query tape",
            },
            FrontendBlocker {
                code: "base_gkr_rows",
                unblock: "compile the complete operator DAG into exhaustive common-point cohort rows",
            },
        ],
        status: FrontendStatus::Blocked,
        admission_credit: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_digests_are_pinned() {
        assert_eq!(digest_hex(SOURCE_METADATA_SOURCE), SOURCE_METADATA_BLAKE3);
        assert_eq!(digest_hex(LAYER_SCALAR_SOURCE), LAYER_SCALAR_CSV_BLAKE3);
        assert_eq!(digest_hex(REFERENCE_SEMANTICS_SOURCE), REFERENCE_SEMANTICS_BLAKE3);
        assert_eq!(digest_hex(WORKLOAD_SOURCE), WORKLOAD_BLAKE3);
        assert_eq!(digest_hex(QUANT_REQUIREMENTS_SOURCE), QUANT_REQUIREMENTS_BLAKE3);
    }

    #[test]
    fn renewed_or_cross_artifact_scalar_drift_still_rejects() {
        let artifact: SourceMetadataArtifact =
            serde_json::from_str(SOURCE_METADATA_SOURCE).unwrap();
        let mut scalars = parse_layer_scalars(LAYER_SCALAR_SOURCE).unwrap();
        scalars[0].bf16_bits ^= 1;
        assert!(validate_public_scalars(&artifact, &scalars).is_err());

        let mutated = SOURCE_METADATA_SOURCE.replacen(
            "\"runtime_tensor_use\": false",
            "\"runtime_tensor_use\": true",
            1,
        );
        assert!(require_blake3(&mutated, SOURCE_METADATA_BLAKE3, "source metadata").is_err());
    }
}
