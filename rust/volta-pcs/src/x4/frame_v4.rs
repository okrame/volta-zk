//! Normative schema-4 wire grammar for `x4-zkdeepfold-ud-e29-v4`.
//!
//! Schema 3 remains in [`super::frame`] for historical verification.  This
//! module has distinct magic, profile and hash domains, admits the response-
//! global fold oracle kind, and replaces the response query section with one
//! packed batch opening.  No schema-4 decoder path falls back to schema 3.

use std::collections::HashSet;

use volta_field::{Fp, Fp2, P};

use super::accounting::{merkle_aux_node_count, projected_query_indices};
use super::frame::{
    self as v3, AuthenticatedOutputLinkFrame, BlockKind, CohortMultiproofFrame, Digest, FrameError,
    M9TransferFrame, ManifestLeafFrame, ManifestNodeFrame, NamespaceKind, ReducedClaimFrame,
    ResponseZeroBatchFrame, TreeRole,
};

pub const MAGIC_V4: [u8; 8] = *b"VOLTAX44";
pub const SCHEMA_V4: u16 = 4;
pub const HEADER_LEN_V4: usize = 16;
pub const PROFILE_NAME_V4: &[u8] = b"x4-zkdeepfold-ud-e29-v4";
pub const PRODUCTION_QUERY_COUNT_V4: usize = 111;

pub const DESCRIPTOR_HASH_CONTEXT_V4: &str = "volta-zk/x4/descriptor/v4";
pub const PCS_LEAF_HASH_CONTEXT_V4: &str = "volta-zk/x4/pcs-leaf/v4";
pub const PCS_NODE_HASH_CONTEXT_V4: &str = "volta-zk/x4/pcs-node/v4";
pub const MANIFEST_LEAF_HASH_CONTEXT_V4: &str = "volta-zk/x4/manifest-leaf/v4";
pub const MANIFEST_NODE_HASH_CONTEXT_V4: &str = "volta-zk/x4/manifest-node/v4";
pub const MANIFEST_ID_HASH_CONTEXT_V4: &str = "volta-zk/x4/manifest-id/v4";
pub const TRANSFER_TEMPLATE_HASH_CONTEXT_V4: &str = "volta-zk/x4/transfer-template/v4";
pub const AUTH_OUTPUT_LINK_SCHEDULE_HASH_CONTEXT_V4: &str =
    "volta-zk/x4/auth-output-link-schedule/v4";
pub const OPENING_SCHEDULE_HASH_CONTEXT_V4: &str = "volta-zk/x4/opening-schedule/v4";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FrameKindV4 {
    Descriptor = 0x01,
    PcsLeaf = 0x02,
    PcsNode = 0x03,
    ManifestLeaf = 0x04,
    ManifestNode = 0x05,
    CohortMultiproof = 0x06,
    ResponseEnvelope = 0x07,
    ReducedClaim = 0x08,
    FoldCommitment = 0x09,
    M9Transfer = 0x0a,
    ResponseZeroBatch = 0x0b,
    AuthenticatedOutputLink = 0x0c,
    PackedBatchOpening = 0x0d,
}

impl FrameKindV4 {
    fn decode(value: u8) -> Result<Self, FrameError> {
        match value {
            0x01 => Ok(Self::Descriptor),
            0x02 => Ok(Self::PcsLeaf),
            0x03 => Ok(Self::PcsNode),
            0x04 => Ok(Self::ManifestLeaf),
            0x05 => Ok(Self::ManifestNode),
            0x06 => Ok(Self::CohortMultiproof),
            0x07 => Ok(Self::ResponseEnvelope),
            0x08 => Ok(Self::ReducedClaim),
            0x09 => Ok(Self::FoldCommitment),
            0x0a => Ok(Self::M9Transfer),
            0x0b => Ok(Self::ResponseZeroBatch),
            0x0c => Ok(Self::AuthenticatedOutputLink),
            0x0d => Ok(Self::PackedBatchOpening),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OracleKindV4 {
    WeightExtension = 0,
    Auxiliary = 1,
    GlobalFoldAggregate = 2,
}

impl OracleKindV4 {
    fn decode(value: u8) -> Result<Self, FrameError> {
        match value {
            0 => Ok(Self::WeightExtension),
            1 => Ok(Self::Auxiliary),
            2 => Ok(Self::GlobalFoldAggregate),
            other => Err(FrameError::UnknownEnum { field: "oracle_kind", value: other }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorFrameV4 {
    pub profile_digest: Digest,
    pub model_config_digest: Digest,
    pub weights_digest: Digest,
    pub namespace_kind: NamespaceKind,
    pub namespace_index: u8,
    pub tensor_id: u16,
    pub block_kind: BlockKind,
    pub block_ordinal: u16,
    pub split_prefix: u8,
    pub mu: u8,
    pub ell: u8,
    pub rate_log2: u8,
    pub source_rows: u32,
    pub source_cols: u32,
    pub padded_rows: u32,
    pub padded_cols: u32,
    pub logical_coeffs: u64,
    pub padded_coeffs: u64,
    pub cohort_id: u32,
    pub slot: u16,
    pub slot_count: u16,
    pub n_w: u64,
    pub n_g: u64,
    pub transfer_template_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PcsLeafPayloadV4 {
    Inner { descriptor_digest: Digest, slot: u16, present: bool, symbols: Vec<Fp2> },
    Outer { inner_root_digest: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsLeafFrameV4 {
    pub cohort_id: u32,
    pub tree_role: TreeRole,
    pub oracle_kind: OracleKindV4,
    pub fold_round: u8,
    pub outer_index: u64,
    pub payload: PcsLeafPayloadV4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsNodeFrameV4 {
    pub cohort_id: u32,
    pub tree_role: TreeRole,
    pub oracle_kind: OracleKindV4,
    pub fold_round: u8,
    pub outer_index: u64,
    pub level: u8,
    pub node_index: u64,
    pub left_digest: Digest,
    pub right_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldCommitmentFrameV4 {
    pub cohort_id: u32,
    pub oracle_kind: OracleKindV4,
    pub fold_round: u8,
    pub input_log2: u8,
    pub output_log2: u8,
    pub root_digest: Digest,
    pub ordered_message_symbols: Vec<Fp2>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialOpeningGroupV4 {
    pub cohort_id: u32,
    pub domain_log2: u8,
    pub slot_count: u16,
    pub touched_slots: Vec<u16>,
    pub opened_symbols: Vec<Fp2>,
    pub inner_sibling_digests: Vec<Digest>,
    pub outer_sibling_digests: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldRoundOpeningV4 {
    pub fold_round: u8,
    pub domain_log2: u8,
    pub opened_symbols: Vec<Fp2>,
    pub outer_sibling_digests: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedBatchOpeningFrameV4 {
    pub opening_schedule_digest: Digest,
    pub initial_groups: Vec<InitialOpeningGroupV4>,
    pub fold_rounds: Vec<FoldRoundOpeningV4>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialOpeningScheduleV4 {
    pub cohort_id: u32,
    pub domain_log2: u8,
    pub slot_count: u16,
    pub touched_slots: Vec<u16>,
    pub root_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedOpeningScheduleV4 {
    pub profile_digest: Digest,
    pub model_root: Digest,
    pub epoch: u64,
    pub initial_groups: Vec<InitialOpeningScheduleV4>,
    pub fold_frames: Vec<FoldCommitmentFrameV4>,
    pub draw_width: u8,
    /// Exact ordered multiset.  Duplicates remain here even though the wire
    /// openings use sorted/deduplicated projected coordinate sets.
    pub query_draws: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestFrameV4 {
    Leaf(ManifestLeafFrame),
    Node(ManifestNodeFrame),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseEnvelopeFrameV4 {
    pub profile_digest: Digest,
    pub model_root: Digest,
    pub epoch: u64,
    pub descriptor_digests: Vec<Digest>,
    pub manifest_frames: Vec<ManifestFrameV4>,
    pub claim_frames: Vec<ReducedClaimFrame>,
    pub ordered_h_symbols: Vec<Fp2>,
    pub m9_frames: Vec<M9TransferFrame>,
    pub authenticated_output_link_frame: AuthenticatedOutputLinkFrame,
    pub fold_frames: Vec<FoldCommitmentFrameV4>,
    pub packed_opening_frame: PackedBatchOpeningFrameV4,
    pub zero_batch_frame: ResponseZeroBatchFrame,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameV4 {
    Descriptor(DescriptorFrameV4),
    PcsLeaf(PcsLeafFrameV4),
    PcsNode(PcsNodeFrameV4),
    ManifestLeaf(ManifestLeafFrame),
    ManifestNode(ManifestNodeFrame),
    CohortMultiproof(CohortMultiproofFrame),
    ResponseEnvelope(ResponseEnvelopeFrameV4),
    ReducedClaim(ReducedClaimFrame),
    FoldCommitment(FoldCommitmentFrameV4),
    M9Transfer(M9TransferFrame),
    ResponseZeroBatch(ResponseZeroBatchFrame),
    AuthenticatedOutputLink(AuthenticatedOutputLinkFrame),
    PackedBatchOpening(PackedBatchOpeningFrameV4),
}

impl FrameV4 {
    pub fn kind(&self) -> FrameKindV4 {
        match self {
            Self::Descriptor(_) => FrameKindV4::Descriptor,
            Self::PcsLeaf(_) => FrameKindV4::PcsLeaf,
            Self::PcsNode(_) => FrameKindV4::PcsNode,
            Self::ManifestLeaf(_) => FrameKindV4::ManifestLeaf,
            Self::ManifestNode(_) => FrameKindV4::ManifestNode,
            Self::CohortMultiproof(_) => FrameKindV4::CohortMultiproof,
            Self::ResponseEnvelope(_) => FrameKindV4::ResponseEnvelope,
            Self::ReducedClaim(_) => FrameKindV4::ReducedClaim,
            Self::FoldCommitment(_) => FrameKindV4::FoldCommitment,
            Self::M9Transfer(_) => FrameKindV4::M9Transfer,
            Self::ResponseZeroBatch(_) => FrameKindV4::ResponseZeroBatch,
            Self::AuthenticatedOutputLink(_) => FrameKindV4::AuthenticatedOutputLink,
            Self::PackedBatchOpening(_) => FrameKindV4::PackedBatchOpening,
        }
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        match self {
            Self::Descriptor(frame) => frame.validate(),
            Self::PcsLeaf(frame) => frame.validate(),
            Self::PcsNode(frame) => frame.validate(),
            Self::ManifestLeaf(frame) => legacy_validate(v3::Frame::ManifestLeaf(frame.clone())),
            Self::ManifestNode(frame) => legacy_validate(v3::Frame::ManifestNode(frame.clone())),
            Self::CohortMultiproof(frame) => {
                legacy_validate(v3::Frame::CohortMultiproof(frame.clone()))
            }
            Self::ResponseEnvelope(frame) => frame.validate(),
            Self::ReducedClaim(frame) => legacy_validate(v3::Frame::ReducedClaim(frame.clone())),
            Self::FoldCommitment(frame) => frame.validate(),
            Self::M9Transfer(frame) => legacy_validate(v3::Frame::M9Transfer(frame.clone())),
            Self::ResponseZeroBatch(frame) => {
                legacy_validate(v3::Frame::ResponseZeroBatch(frame.clone()))
            }
            Self::AuthenticatedOutputLink(frame) => {
                legacy_validate(v3::Frame::AuthenticatedOutputLink(frame.clone()))
            }
            Self::PackedBatchOpening(frame) => frame.validate(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        let body = match self {
            Self::Descriptor(frame) => frame.encode_body()?,
            Self::PcsLeaf(frame) => frame.encode_body()?,
            Self::PcsNode(frame) => frame.encode_body()?,
            Self::ManifestLeaf(frame) => legacy_body(v3::Frame::ManifestLeaf(frame.clone()))?,
            Self::ManifestNode(frame) => legacy_body(v3::Frame::ManifestNode(frame.clone()))?,
            Self::CohortMultiproof(frame) => {
                legacy_body(v3::Frame::CohortMultiproof(frame.clone()))?
            }
            Self::ResponseEnvelope(frame) => frame.encode_body()?,
            Self::ReducedClaim(frame) => legacy_body(v3::Frame::ReducedClaim(frame.clone()))?,
            Self::FoldCommitment(frame) => frame.encode_body()?,
            Self::M9Transfer(frame) => legacy_body(v3::Frame::M9Transfer(frame.clone()))?,
            Self::ResponseZeroBatch(frame) => {
                legacy_body(v3::Frame::ResponseZeroBatch(frame.clone()))?
            }
            Self::AuthenticatedOutputLink(frame) => {
                legacy_body(v3::Frame::AuthenticatedOutputLink(frame.clone()))?
            }
            Self::PackedBatchOpening(frame) => frame.encode_body()?,
        };
        wrap_v4(self.kind(), body)
    }
}

fn legacy_validate(frame: v3::Frame) -> Result<(), FrameError> {
    frame.validate()
}

fn legacy_body(frame: v3::Frame) -> Result<Vec<u8>, FrameError> {
    let encoded = frame.encode()?;
    Ok(encoded[HEADER_LEN_V4..].to_vec())
}

fn decode_legacy_body(kind: u8, body: &[u8]) -> Result<v3::Frame, FrameError> {
    let body_len = u32::try_from(body.len()).map_err(|_| FrameError::Overflow)?;
    let mut encoded = Vec::with_capacity(HEADER_LEN_V4 + body.len());
    encoded.extend_from_slice(&v3::MAGIC);
    encoded.extend_from_slice(&v3::SCHEMA.to_le_bytes());
    encoded.push(kind);
    encoded.push(0);
    encoded.extend_from_slice(&body_len.to_le_bytes());
    encoded.extend_from_slice(body);
    v3::decode(&encoded)
}

pub fn profile_digest_v4() -> Digest {
    *blake3::hash(PROFILE_NAME_V4).as_bytes()
}

fn typed_hash_v4(context: &'static str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub fn hash_descriptor_v4(frame: &DescriptorFrameV4) -> Result<Digest, FrameError> {
    Ok(typed_hash_v4(DESCRIPTOR_HASH_CONTEXT_V4, &FrameV4::Descriptor(frame.clone()).encode()?))
}

pub fn hash_pcs_leaf_v4(frame: &PcsLeafFrameV4) -> Result<Digest, FrameError> {
    Ok(typed_hash_v4(PCS_LEAF_HASH_CONTEXT_V4, &FrameV4::PcsLeaf(frame.clone()).encode()?))
}

pub fn hash_pcs_node_v4(frame: &PcsNodeFrameV4) -> Result<Digest, FrameError> {
    Ok(typed_hash_v4(PCS_NODE_HASH_CONTEXT_V4, &FrameV4::PcsNode(frame.clone()).encode()?))
}

pub fn hash_manifest_leaf_v4(frame: &ManifestLeafFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash_v4(
        MANIFEST_LEAF_HASH_CONTEXT_V4,
        &FrameV4::ManifestLeaf(frame.clone()).encode()?,
    ))
}

pub fn hash_manifest_node_v4(frame: &ManifestNodeFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash_v4(
        MANIFEST_NODE_HASH_CONTEXT_V4,
        &FrameV4::ManifestNode(frame.clone()).encode()?,
    ))
}

pub fn manifest_id_digest_v4(
    model_config_digest: Digest,
    weights_digest: Digest,
    epoch: u64,
) -> Digest {
    let mut input = Vec::with_capacity(104);
    input.extend_from_slice(&profile_digest_v4());
    input.extend_from_slice(&model_config_digest);
    input.extend_from_slice(&weights_digest);
    input.extend_from_slice(&epoch.to_le_bytes());
    typed_hash_v4(MANIFEST_ID_HASH_CONTEXT_V4, &input)
}

pub fn transfer_template_digest_v4(domain_ids: &[u64]) -> Result<Digest, FrameError> {
    require_strictly_increasing(domain_ids, "transfer domain ids")?;
    let mut out = WriterV4::default();
    out.u16(u16::try_from(domain_ids.len()).map_err(|_| FrameError::Overflow)?);
    for domain in domain_ids {
        out.u64(*domain);
    }
    Ok(typed_hash_v4(TRANSFER_TEMPLATE_HASH_CONTEXT_V4, &out.finish()))
}

pub fn authenticated_output_link_schedule_digest_v4(
    epoch: u64,
    claim_frames: &[ReducedClaimFrame],
    descriptor_digests: &[Digest],
    ordered_h_symbols: &[Fp2],
    m9_frames: &[M9TransferFrame],
    round_count: u8,
    round_correlation_domain_ids: &[u64],
) -> Result<Digest, FrameError> {
    if descriptor_digests.len() != ordered_h_symbols.len()
        || descriptor_digests.len() != m9_frames.len()
        || descriptor_digests.len() > usize::from(u16::MAX)
        || claim_frames.len() > u32::MAX as usize
        || round_count > 30
        || round_correlation_domain_ids.len() != 2 * usize::from(round_count)
    {
        return Err(FrameError::Invalid("link schedule geometry"));
    }
    require_strictly_increasing(round_correlation_domain_ids, "link round correlation domain ids")?;
    for (descriptor, m9) in descriptor_digests.iter().zip(m9_frames) {
        if descriptor != &m9.descriptor_digest {
            return Err(FrameError::Invalid("link schedule M9 descriptor order"));
        }
    }

    let mut out = WriterV4::default();
    out.u64(epoch);
    out.u32(u32::try_from(claim_frames.len()).map_err(|_| FrameError::Overflow)?);
    for claim in claim_frames {
        out.nested(&FrameV4::ReducedClaim(claim.clone()))?;
    }
    out.u16(u16::try_from(descriptor_digests.len()).map_err(|_| FrameError::Overflow)?);
    for descriptor in descriptor_digests {
        out.digest(descriptor);
    }
    out.u16(u16::try_from(ordered_h_symbols.len()).map_err(|_| FrameError::Overflow)?);
    for symbol in ordered_h_symbols {
        out.symbol(*symbol);
    }
    for m9 in m9_frames {
        out.nested(&FrameV4::M9Transfer(m9.clone()))?;
    }
    out.u8(round_count);
    for domain in round_correlation_domain_ids {
        out.u64(*domain);
    }
    Ok(typed_hash_v4(AUTH_OUTPUT_LINK_SCHEDULE_HASH_CONTEXT_V4, &out.finish()))
}

pub fn opening_schedule_digest_v4(
    schedule: &PackedOpeningScheduleV4,
) -> Result<Digest, FrameError> {
    schedule.validate()?;
    let mut out = WriterV4::default();
    out.digest(&schedule.profile_digest);
    out.digest(&schedule.model_root);
    out.u64(schedule.epoch);
    out.u16(u16::try_from(schedule.initial_groups.len()).map_err(|_| FrameError::Overflow)?);
    for group in &schedule.initial_groups {
        out.u32(group.cohort_id);
        out.digest(&group.root_digest);
    }
    out.u8(u8::try_from(schedule.fold_frames.len()).map_err(|_| FrameError::Overflow)?);
    for frame in &schedule.fold_frames {
        out.nested(&FrameV4::FoldCommitment(frame.clone()))?;
    }
    out.u16(u16::try_from(schedule.query_draws.len()).map_err(|_| FrameError::Overflow)?);
    out.u8(schedule.draw_width);
    for draw in &schedule.query_draws {
        let draw = u32::try_from(*draw).map_err(|_| FrameError::Overflow)?;
        out.bytes.extend_from_slice(&draw.to_le_bytes());
    }
    Ok(typed_hash_v4(OPENING_SCHEDULE_HASH_CONTEXT_V4, &out.finish()))
}

pub fn decode_v4(bytes: &[u8]) -> Result<FrameV4, FrameError> {
    if bytes.len() < HEADER_LEN_V4 {
        return Err(FrameError::UnexpectedEof);
    }
    if bytes[..8] != MAGIC_V4 {
        return Err(FrameError::BadMagic);
    }
    let schema = u16::from_le_bytes([bytes[8], bytes[9]]);
    if schema != SCHEMA_V4 {
        return Err(FrameError::BadSchema(schema));
    }
    let kind = FrameKindV4::decode(bytes[10])?;
    if bytes[11] != 0 {
        return Err(FrameError::NonZeroFlags(bytes[11]));
    }
    let body_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let expected = HEADER_LEN_V4.checked_add(body_len).ok_or(FrameError::Overflow)?;
    if bytes.len() != expected {
        return Err(FrameError::LengthMismatch);
    }
    let body = &bytes[HEADER_LEN_V4..];
    let mut input = ReaderV4::new(body);
    let frame = match kind {
        FrameKindV4::Descriptor => FrameV4::Descriptor(DescriptorFrameV4::decode_body(&mut input)?),
        FrameKindV4::PcsLeaf => FrameV4::PcsLeaf(PcsLeafFrameV4::decode_body(&mut input)?),
        FrameKindV4::PcsNode => FrameV4::PcsNode(PcsNodeFrameV4::decode_body(&mut input)?),
        FrameKindV4::ManifestLeaf => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::ManifestLeaf(frame) => FrameV4::ManifestLeaf(frame),
            _ => unreachable!(),
        },
        FrameKindV4::ManifestNode => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::ManifestNode(frame) => FrameV4::ManifestNode(frame),
            _ => unreachable!(),
        },
        FrameKindV4::CohortMultiproof => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::CohortMultiproof(frame) => FrameV4::CohortMultiproof(frame),
            _ => unreachable!(),
        },
        FrameKindV4::ResponseEnvelope => {
            FrameV4::ResponseEnvelope(ResponseEnvelopeFrameV4::decode_body(&mut input)?)
        }
        FrameKindV4::ReducedClaim => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::ReducedClaim(frame) => FrameV4::ReducedClaim(frame),
            _ => unreachable!(),
        },
        FrameKindV4::FoldCommitment => {
            FrameV4::FoldCommitment(FoldCommitmentFrameV4::decode_body(&mut input)?)
        }
        FrameKindV4::M9Transfer => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::M9Transfer(frame) => FrameV4::M9Transfer(frame),
            _ => unreachable!(),
        },
        FrameKindV4::ResponseZeroBatch => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::ResponseZeroBatch(frame) => FrameV4::ResponseZeroBatch(frame),
            _ => unreachable!(),
        },
        FrameKindV4::AuthenticatedOutputLink => match decode_legacy_body(kind as u8, body)? {
            v3::Frame::AuthenticatedOutputLink(frame) => FrameV4::AuthenticatedOutputLink(frame),
            _ => unreachable!(),
        },
        FrameKindV4::PackedBatchOpening => {
            FrameV4::PackedBatchOpening(PackedBatchOpeningFrameV4::decode_body(&mut input)?)
        }
    };
    // Legacy decoding consumes its own temporary reader.  All custom kinds
    // must consume this reader exactly.
    if matches!(
        kind,
        FrameKindV4::Descriptor
            | FrameKindV4::PcsLeaf
            | FrameKindV4::PcsNode
            | FrameKindV4::ResponseEnvelope
            | FrameKindV4::FoldCommitment
            | FrameKindV4::PackedBatchOpening
    ) {
        input.finish()?;
    }
    frame.validate()?;
    Ok(frame)
}

fn wrap_v4(kind: FrameKindV4, body: Vec<u8>) -> Result<Vec<u8>, FrameError> {
    let body_len = u32::try_from(body.len()).map_err(|_| FrameError::Overflow)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN_V4 + body.len());
    bytes.extend_from_slice(&MAGIC_V4);
    bytes.extend_from_slice(&SCHEMA_V4.to_le_bytes());
    bytes.push(kind as u8);
    bytes.push(0);
    bytes.extend_from_slice(&body_len.to_le_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

#[derive(Default)]
struct WriterV4 {
    bytes: Vec<u8>,
}

impl WriterV4 {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn digest(&mut self, value: &Digest) {
        self.bytes.extend_from_slice(value);
    }

    fn symbol(&mut self, value: Fp2) {
        self.u64(value.c0.value());
        self.u64(value.c1.value());
    }

    fn nested(&mut self, frame: &FrameV4) -> Result<(), FrameError> {
        self.bytes.extend_from_slice(&frame.encode()?);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct ReaderV4<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ReaderV4<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(count).ok_or(FrameError::Overflow)?;
        if end > self.bytes.len() {
            return Err(FrameError::UnexpectedEof);
        }
        let value = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn digest(&mut self) -> Result<Digest, FrameError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn boolean(&mut self) -> Result<bool, FrameError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(FrameError::InvalidBool(other)),
        }
    }

    fn symbol(&mut self) -> Result<Fp2, FrameError> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(FrameError::NonCanonicalField);
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn count_fits(&self, count: usize, min_item_bytes: usize) -> Result<(), FrameError> {
        let required = count.checked_mul(min_item_bytes).ok_or(FrameError::Overflow)?;
        if required > self.remaining() {
            return Err(FrameError::UnexpectedEof);
        }
        Ok(())
    }

    fn nested(&mut self) -> Result<FrameV4, FrameError> {
        if self.remaining() < HEADER_LEN_V4 {
            return Err(FrameError::UnexpectedEof);
        }
        let header = &self.bytes[self.pos..self.pos + HEADER_LEN_V4];
        let body_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let total = HEADER_LEN_V4.checked_add(body_len).ok_or(FrameError::Overflow)?;
        decode_v4(self.take(total)?)
    }

    fn finish(&self) -> Result<(), FrameError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(FrameError::LengthMismatch)
        }
    }
}

fn decode_namespace_kind(value: u8) -> Result<NamespaceKind, FrameError> {
    match value {
        0 => Ok(NamespaceKind::Global),
        1 => Ok(NamespaceKind::Layer),
        other => Err(FrameError::UnknownEnum { field: "namespace_kind", value: other }),
    }
}

fn decode_block_kind(value: u8) -> Result<BlockKind, FrameError> {
    match value {
        0 => Ok(BlockKind::Fixed),
        1 => Ok(BlockKind::AttentionQ),
        2 => Ok(BlockKind::AttentionK),
        3 => Ok(BlockKind::AttentionV),
        4 => Ok(BlockKind::AttentionO),
        5 => Ok(BlockKind::Router),
        6 => Ok(BlockKind::ExpertGateUp),
        7 => Ok(BlockKind::ExpertDown),
        8 => Ok(BlockKind::EmbeddingHalf),
        9 => Ok(BlockKind::UnembeddingHalf),
        other => Err(FrameError::UnknownEnum { field: "block_kind", value: other }),
    }
}

fn decode_tree_role(value: u8) -> Result<TreeRole, FrameError> {
    match value {
        0 => Ok(TreeRole::Inner),
        1 => Ok(TreeRole::Outer),
        other => Err(FrameError::UnknownEnum { field: "tree_role", value: other }),
    }
}

fn expected_ell_v4(mu: u8) -> u8 {
    let target = PRODUCTION_QUERY_COUNT_V4 as u32 * u32::from(mu) * u32::from(mu) + 1;
    (u32::BITS - (target - 1).leading_zeros()) as u8
}

impl DescriptorFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.profile_digest != profile_digest_v4() {
            return Err(FrameError::Invalid("descriptor profile digest"));
        }
        match self.namespace_kind {
            NamespaceKind::Global if self.namespace_index != 255 => {
                return Err(FrameError::Invalid("global namespace index"));
            }
            NamespaceKind::Layer if self.namespace_index >= 24 => {
                return Err(FrameError::Invalid("layer namespace index"));
            }
            _ => {}
        }
        let is_split =
            matches!(self.block_kind, BlockKind::EmbeddingHalf | BlockKind::UnembeddingHalf);
        if is_split {
            if self.namespace_kind != NamespaceKind::Global || self.split_prefix > 1 {
                return Err(FrameError::Invalid("split block identity"));
            }
        } else if self.split_prefix != 255 {
            return Err(FrameError::Invalid("unsplit block prefix"));
        }
        if !(14..=29).contains(&self.mu) {
            return Err(FrameError::Invalid("descriptor mu"));
        }
        if self.rate_log2 != 3 || self.ell != expected_ell_v4(self.mu) {
            return Err(FrameError::Invalid("descriptor rate/ell"));
        }
        let padded_coeffs = 1u64.checked_shl(u32::from(self.mu)).ok_or(FrameError::Overflow)?;
        let n_w = 1u64.checked_shl(u32::from(self.mu) + 4).ok_or(FrameError::Overflow)?;
        let n_g = 1u64.checked_shl(u32::from(self.ell) + 3).ok_or(FrameError::Overflow)?;
        if self.padded_coeffs != padded_coeffs || self.n_w != n_w || self.n_g != n_g {
            return Err(FrameError::Invalid("descriptor derived geometry"));
        }
        let source_product = u64::from(self.source_rows)
            .checked_mul(u64::from(self.source_cols))
            .ok_or(FrameError::Overflow)?;
        let padded_product = u64::from(self.padded_rows)
            .checked_mul(u64::from(self.padded_cols))
            .ok_or(FrameError::Overflow)?;
        if source_product == 0
            || source_product != self.logical_coeffs
            || padded_product != self.padded_coeffs
            || self.logical_coeffs > self.padded_coeffs
            || self.source_rows > self.padded_rows
            || self.source_cols > self.padded_cols
        {
            return Err(FrameError::Invalid("descriptor axis geometry"));
        }
        if self.slot_count == 0
            || !self.slot_count.is_power_of_two()
            || self.slot >= self.slot_count
        {
            return Err(FrameError::Invalid("descriptor slot"));
        }
        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.digest(&self.profile_digest);
        out.digest(&self.model_config_digest);
        out.digest(&self.weights_digest);
        out.u8(self.namespace_kind as u8);
        out.u8(self.namespace_index);
        out.u16(self.tensor_id);
        out.u8(self.block_kind as u8);
        out.u16(self.block_ordinal);
        out.u8(self.split_prefix);
        out.u8(self.mu);
        out.u8(self.ell);
        out.u8(self.rate_log2);
        out.u32(self.source_rows);
        out.u32(self.source_cols);
        out.u32(self.padded_rows);
        out.u32(self.padded_cols);
        out.u64(self.logical_coeffs);
        out.u64(self.padded_coeffs);
        out.u32(self.cohort_id);
        out.u16(self.slot);
        out.u16(self.slot_count);
        out.u64(self.n_w);
        out.u64(self.n_g);
        out.digest(&self.transfer_template_digest);
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            profile_digest: input.digest()?,
            model_config_digest: input.digest()?,
            weights_digest: input.digest()?,
            namespace_kind: decode_namespace_kind(input.u8()?)?,
            namespace_index: input.u8()?,
            tensor_id: input.u16()?,
            block_kind: decode_block_kind(input.u8()?)?,
            block_ordinal: input.u16()?,
            split_prefix: input.u8()?,
            mu: input.u8()?,
            ell: input.u8()?,
            rate_log2: input.u8()?,
            source_rows: input.u32()?,
            source_cols: input.u32()?,
            padded_rows: input.u32()?,
            padded_cols: input.u32()?,
            logical_coeffs: input.u64()?,
            padded_coeffs: input.u64()?,
            cohort_id: input.u32()?,
            slot: input.u16()?,
            slot_count: input.u16()?,
            n_w: input.u64()?,
            n_g: input.u64()?,
            transfer_template_digest: input.digest()?,
        })
    }
}

impl PcsLeafFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        match (&self.tree_role, &self.payload) {
            (TreeRole::Inner, PcsLeafPayloadV4::Inner { present, symbols, .. }) => {
                if self.outer_index == u64::MAX {
                    return Err(FrameError::Invalid("inner leaf outer index"));
                }
                u16::try_from(symbols.len()).map_err(|_| FrameError::Overflow)?;
                if (*present && symbols.is_empty()) || (!*present && !symbols.is_empty()) {
                    return Err(FrameError::Invalid("inner leaf presence"));
                }
            }
            (TreeRole::Outer, PcsLeafPayloadV4::Outer { .. }) => {
                if self.outer_index == u64::MAX {
                    return Err(FrameError::Invalid("outer leaf index"));
                }
            }
            _ => return Err(FrameError::Invalid("leaf role/payload")),
        }
        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.u32(self.cohort_id);
        out.u8(self.tree_role as u8);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u64(self.outer_index);
        match &self.payload {
            PcsLeafPayloadV4::Inner { descriptor_digest, slot, present, symbols } => {
                out.digest(descriptor_digest);
                out.u16(*slot);
                out.u8(u8::from(*present));
                out.u16(u16::try_from(symbols.len()).map_err(|_| FrameError::Overflow)?);
                for symbol in symbols {
                    out.symbol(*symbol);
                }
            }
            PcsLeafPayloadV4::Outer { inner_root_digest } => out.digest(inner_root_digest),
        }
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        let cohort_id = input.u32()?;
        let tree_role = decode_tree_role(input.u8()?)?;
        let oracle_kind = OracleKindV4::decode(input.u8()?)?;
        let fold_round = input.u8()?;
        let outer_index = input.u64()?;
        let payload = match tree_role {
            TreeRole::Inner => {
                let descriptor_digest = input.digest()?;
                let slot = input.u16()?;
                let present = input.boolean()?;
                let count = usize::from(input.u16()?);
                input.count_fits(count, 16)?;
                let mut symbols = Vec::with_capacity(count);
                for _ in 0..count {
                    symbols.push(input.symbol()?);
                }
                PcsLeafPayloadV4::Inner { descriptor_digest, slot, present, symbols }
            }
            TreeRole::Outer => PcsLeafPayloadV4::Outer { inner_root_digest: input.digest()? },
        };
        Ok(Self { cohort_id, tree_role, oracle_kind, fold_round, outer_index, payload })
    }
}

impl PcsNodeFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        match self.tree_role {
            TreeRole::Inner if self.outer_index == u64::MAX => {
                return Err(FrameError::Invalid("inner node outer index"));
            }
            TreeRole::Outer if self.outer_index != u64::MAX => {
                return Err(FrameError::Invalid("outer node outer index"));
            }
            _ => {}
        }
        if self.level == 0 {
            return Err(FrameError::Invalid("node level"));
        }
        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.u32(self.cohort_id);
        out.u8(self.tree_role as u8);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u64(self.outer_index);
        out.u8(self.level);
        out.u64(self.node_index);
        out.digest(&self.left_digest);
        out.digest(&self.right_digest);
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            cohort_id: input.u32()?,
            tree_role: decode_tree_role(input.u8()?)?,
            oracle_kind: OracleKindV4::decode(input.u8()?)?,
            fold_round: input.u8()?,
            outer_index: input.u64()?,
            level: input.u8()?,
            node_index: input.u64()?,
            left_digest: input.digest()?,
            right_digest: input.digest()?,
        })
    }
}

impl FoldCommitmentFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.input_log2 > 33
            || self.input_log2 == 0
            || self.output_log2 >= self.input_log2
            || self.ordered_message_symbols.is_empty()
        {
            return Err(FrameError::Invalid("fold geometry"));
        }
        u16::try_from(self.ordered_message_symbols.len()).map_err(|_| FrameError::Overflow)?;
        Ok(())
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.u32(self.cohort_id);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u8(self.input_log2);
        out.u8(self.output_log2);
        out.digest(&self.root_digest);
        out.u16(
            u16::try_from(self.ordered_message_symbols.len()).map_err(|_| FrameError::Overflow)?,
        );
        for symbol in &self.ordered_message_symbols {
            out.symbol(*symbol);
        }
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        let cohort_id = input.u32()?;
        let oracle_kind = OracleKindV4::decode(input.u8()?)?;
        let fold_round = input.u8()?;
        let input_log2 = input.u8()?;
        let output_log2 = input.u8()?;
        let root_digest = input.digest()?;
        let count = usize::from(input.u16()?);
        input.count_fits(count, 16)?;
        let mut ordered_message_symbols = Vec::with_capacity(count);
        for _ in 0..count {
            ordered_message_symbols.push(input.symbol()?);
        }
        Ok(Self {
            cohort_id,
            oracle_kind,
            fold_round,
            input_log2,
            output_log2,
            root_digest,
            ordered_message_symbols,
        })
    }
}

impl InitialOpeningGroupV4 {
    fn validate(&self) -> Result<(), FrameError> {
        if !(3..=32).contains(&self.domain_log2)
            || self.slot_count == 0
            || !self.slot_count.is_power_of_two()
            || self.touched_slots.is_empty()
            || self.touched_slots.iter().any(|slot| *slot >= self.slot_count)
            || self.opened_symbols.is_empty()
        {
            return Err(FrameError::Invalid("packed initial-group geometry"));
        }
        require_strictly_increasing(&self.touched_slots, "packed touched slots")?;
        u32::try_from(self.opened_symbols.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.inner_sibling_digests.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.outer_sibling_digests.len()).map_err(|_| FrameError::Overflow)?;
        Ok(())
    }
}

impl FoldRoundOpeningV4 {
    fn validate(&self) -> Result<(), FrameError> {
        if self.fold_round == 0
            || self.fold_round > 30
            || !(3..=32).contains(&self.domain_log2)
            || self.opened_symbols.is_empty()
        {
            return Err(FrameError::Invalid("packed fold-round geometry"));
        }
        u32::try_from(self.opened_symbols.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.outer_sibling_digests.len()).map_err(|_| FrameError::Overflow)?;
        Ok(())
    }
}

impl PackedBatchOpeningFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.initial_groups.is_empty()
            || self.initial_groups.len() > usize::from(u16::MAX)
            || self.fold_rounds.is_empty()
            || self.fold_rounds.len() > 30
        {
            return Err(FrameError::Invalid("packed opening geometry"));
        }
        let mut seen_cohorts = HashSet::with_capacity(self.initial_groups.len());
        for group in &self.initial_groups {
            group.validate()?;
            if !seen_cohorts.insert(group.cohort_id) {
                return Err(FrameError::UnsortedOrDuplicate("packed cohort id"));
            }
        }
        if !self.initial_groups.windows(2).all(|pair| {
            pair[0].domain_log2 > pair[1].domain_log2
                || (pair[0].domain_log2 == pair[1].domain_log2
                    && pair[0].cohort_id < pair[1].cohort_id)
        }) {
            return Err(FrameError::UnsortedOrDuplicate("packed initial groups"));
        }
        for (index, round) in self.fold_rounds.iter().enumerate() {
            round.validate()?;
            if usize::from(round.fold_round) != index + 1 {
                return Err(FrameError::Invalid("packed fold-round order"));
            }
            if index > 0 && self.fold_rounds[index - 1].domain_log2 != round.domain_log2 + 1 {
                return Err(FrameError::Invalid("packed fold-domain order"));
            }
        }
        Ok(())
    }

    pub fn validate_against_schedule(
        &self,
        schedule: &PackedOpeningScheduleV4,
    ) -> Result<(), FrameError> {
        self.validate()?;
        schedule.validate()?;
        if self.opening_schedule_digest != opening_schedule_digest_v4(schedule)?
            || self.initial_groups.len() != schedule.initial_groups.len()
            || self.fold_rounds.len() != schedule.fold_frames.len()
        {
            return Err(FrameError::Invalid("packed opening schedule"));
        }
        for (opening, expected) in self.initial_groups.iter().zip(&schedule.initial_groups) {
            if opening.cohort_id != expected.cohort_id
                || opening.domain_log2 != expected.domain_log2
                || opening.slot_count != expected.slot_count
                || opening.touched_slots != expected.touched_slots
            {
                return Err(FrameError::Invalid("packed initial-group schedule"));
            }
            let indices = projected_query_indices(&schedule.query_draws, expected.domain_log2)
                .map_err(|_| FrameError::Invalid("packed projected indices"))?;
            let opened_count = indices
                .len()
                .checked_mul(expected.touched_slots.len())
                .ok_or(FrameError::Overflow)?;
            let inner_per_coordinate = merkle_aux_node_count(
                expected.slot_count.ilog2() as u8,
                &expected.touched_slots.iter().map(|slot| u64::from(*slot)).collect::<Vec<_>>(),
            )
            .map_err(|_| FrameError::Invalid("packed inner frontier"))?;
            let inner_count = u64::try_from(indices.len())
                .map_err(|_| FrameError::Overflow)?
                .checked_mul(inner_per_coordinate)
                .ok_or(FrameError::Overflow)?;
            let outer_count = merkle_aux_node_count(expected.domain_log2, &indices)
                .map_err(|_| FrameError::Invalid("packed outer frontier"))?;
            if opening.opened_symbols.len() != opened_count
                || opening.inner_sibling_digests.len()
                    != usize::try_from(inner_count).map_err(|_| FrameError::Overflow)?
                || opening.outer_sibling_digests.len()
                    != usize::try_from(outer_count).map_err(|_| FrameError::Overflow)?
            {
                return Err(FrameError::Invalid("packed initial-group counts"));
            }
        }
        for (opening, expected) in self.fold_rounds.iter().zip(&schedule.fold_frames) {
            if expected.oracle_kind != OracleKindV4::GlobalFoldAggregate
                || opening.fold_round != expected.fold_round
                || opening.domain_log2 != expected.output_log2
            {
                return Err(FrameError::Invalid("packed fold schedule"));
            }
            let indices = projected_query_indices(&schedule.query_draws, opening.domain_log2)
                .map_err(|_| FrameError::Invalid("packed projected fold indices"))?;
            let outer_count = merkle_aux_node_count(opening.domain_log2, &indices)
                .map_err(|_| FrameError::Invalid("packed fold frontier"))?;
            if opening.opened_symbols.len() != indices.len()
                || opening.outer_sibling_digests.len()
                    != usize::try_from(outer_count).map_err(|_| FrameError::Overflow)?
            {
                return Err(FrameError::Invalid("packed fold counts"));
            }
        }
        Ok(())
    }

    pub fn byte_components(&self) -> Result<PackedOpeningByteComponentsV4, FrameError> {
        self.validate()?;
        let opened_symbols = self
            .initial_groups
            .iter()
            .map(|group| group.opened_symbols.len())
            .chain(self.fold_rounds.iter().map(|round| round.opened_symbols.len()))
            .try_fold(0u64, |sum, count| {
                sum.checked_add(u64::try_from(count).map_err(|_| FrameError::Overflow)?)
                    .ok_or(FrameError::Overflow)
            })?;
        let initial_inner_siblings = self.initial_groups.iter().try_fold(0u64, |sum, group| {
            sum.checked_add(
                u64::try_from(group.inner_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            )
            .ok_or(FrameError::Overflow)
        })?;
        let initial_outer_siblings = self.initial_groups.iter().try_fold(0u64, |sum, group| {
            sum.checked_add(
                u64::try_from(group.outer_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            )
            .ok_or(FrameError::Overflow)
        })?;
        let fold_outer_siblings = self.fold_rounds.iter().try_fold(0u64, |sum, round| {
            sum.checked_add(
                u64::try_from(round.outer_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            )
            .ok_or(FrameError::Overflow)
        })?;
        let serialized_bytes =
            u64::try_from(FrameV4::PackedBatchOpening(self.clone()).encode()?.len())
                .map_err(|_| FrameError::Overflow)?;
        let payload_bytes = opened_symbols
            .checked_mul(16)
            .and_then(|symbols| {
                initial_inner_siblings
                    .checked_add(initial_outer_siblings)?
                    .checked_add(fold_outer_siblings)?
                    .checked_mul(32)?
                    .checked_add(symbols)
            })
            .ok_or(FrameError::Overflow)?;
        Ok(PackedOpeningByteComponentsV4 {
            opened_symbols,
            initial_inner_siblings,
            initial_outer_siblings,
            fold_outer_siblings,
            metadata_bytes: serialized_bytes
                .checked_sub(payload_bytes)
                .ok_or(FrameError::Overflow)?,
            serialized_bytes,
        })
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.digest(&self.opening_schedule_digest);
        out.u16(u16::try_from(self.initial_groups.len()).map_err(|_| FrameError::Overflow)?);
        for group in &self.initial_groups {
            out.u32(group.cohort_id);
            out.u8(group.domain_log2);
            out.u16(group.slot_count);
            out.u16(u16::try_from(group.touched_slots.len()).map_err(|_| FrameError::Overflow)?);
            for slot in &group.touched_slots {
                out.u16(*slot);
            }
            out.u32(u32::try_from(group.opened_symbols.len()).map_err(|_| FrameError::Overflow)?);
            for symbol in &group.opened_symbols {
                out.symbol(*symbol);
            }
            out.u32(
                u32::try_from(group.inner_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            );
            for digest in &group.inner_sibling_digests {
                out.digest(digest);
            }
            out.u32(
                u32::try_from(group.outer_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            );
            for digest in &group.outer_sibling_digests {
                out.digest(digest);
            }
        }
        out.u8(u8::try_from(self.fold_rounds.len()).map_err(|_| FrameError::Overflow)?);
        for round in &self.fold_rounds {
            out.u8(round.fold_round);
            out.u8(round.domain_log2);
            out.u32(u32::try_from(round.opened_symbols.len()).map_err(|_| FrameError::Overflow)?);
            for symbol in &round.opened_symbols {
                out.symbol(*symbol);
            }
            out.u32(
                u32::try_from(round.outer_sibling_digests.len())
                    .map_err(|_| FrameError::Overflow)?,
            );
            for digest in &round.outer_sibling_digests {
                out.digest(digest);
            }
        }
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        let opening_schedule_digest = input.digest()?;
        let group_count = usize::from(input.u16()?);
        input.count_fits(group_count, 21)?;
        let mut initial_groups = Vec::with_capacity(group_count);
        for _ in 0..group_count {
            let cohort_id = input.u32()?;
            let domain_log2 = input.u8()?;
            let slot_count = input.u16()?;
            let touched_count = usize::from(input.u16()?);
            input.count_fits(touched_count, 2)?;
            let mut touched_slots = Vec::with_capacity(touched_count);
            for _ in 0..touched_count {
                touched_slots.push(input.u16()?);
            }
            let symbol_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
            input.count_fits(symbol_count, 16)?;
            let mut opened_symbols = Vec::with_capacity(symbol_count);
            for _ in 0..symbol_count {
                opened_symbols.push(input.symbol()?);
            }
            let inner_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
            input.count_fits(inner_count, 32)?;
            let mut inner_sibling_digests = Vec::with_capacity(inner_count);
            for _ in 0..inner_count {
                inner_sibling_digests.push(input.digest()?);
            }
            let outer_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
            input.count_fits(outer_count, 32)?;
            let mut outer_sibling_digests = Vec::with_capacity(outer_count);
            for _ in 0..outer_count {
                outer_sibling_digests.push(input.digest()?);
            }
            initial_groups.push(InitialOpeningGroupV4 {
                cohort_id,
                domain_log2,
                slot_count,
                touched_slots,
                opened_symbols,
                inner_sibling_digests,
                outer_sibling_digests,
            });
        }
        let round_count = usize::from(input.u8()?);
        input.count_fits(round_count, 10)?;
        let mut fold_rounds = Vec::with_capacity(round_count);
        for _ in 0..round_count {
            let fold_round = input.u8()?;
            let domain_log2 = input.u8()?;
            let symbol_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
            input.count_fits(symbol_count, 16)?;
            let mut opened_symbols = Vec::with_capacity(symbol_count);
            for _ in 0..symbol_count {
                opened_symbols.push(input.symbol()?);
            }
            let sibling_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
            input.count_fits(sibling_count, 32)?;
            let mut outer_sibling_digests = Vec::with_capacity(sibling_count);
            for _ in 0..sibling_count {
                outer_sibling_digests.push(input.digest()?);
            }
            fold_rounds.push(FoldRoundOpeningV4 {
                fold_round,
                domain_log2,
                opened_symbols,
                outer_sibling_digests,
            });
        }
        Ok(Self { opening_schedule_digest, initial_groups, fold_rounds })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackedOpeningByteComponentsV4 {
    pub opened_symbols: u64,
    pub initial_inner_siblings: u64,
    pub initial_outer_siblings: u64,
    pub fold_outer_siblings: u64,
    pub metadata_bytes: u64,
    pub serialized_bytes: u64,
}

impl PackedOpeningScheduleV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.profile_digest != profile_digest_v4()
            || self.query_draws.len() != PRODUCTION_QUERY_COUNT_V4
            || !(1..=32).contains(&self.draw_width)
            || self.initial_groups.is_empty()
            || self.fold_frames.is_empty()
            || self.fold_frames.len() > 30
        {
            return Err(FrameError::Invalid("opening schedule geometry"));
        }
        let bound = 1u64.checked_shl(u32::from(self.draw_width)).ok_or(FrameError::Overflow)?;
        if self.query_draws.iter().any(|draw| *draw >= bound || *draw > u64::from(u32::MAX)) {
            return Err(FrameError::Invalid("opening schedule draw"));
        }
        if !self.initial_groups.windows(2).all(|pair| {
            pair[0].domain_log2 > pair[1].domain_log2
                || (pair[0].domain_log2 == pair[1].domain_log2
                    && pair[0].cohort_id < pair[1].cohort_id)
        }) {
            return Err(FrameError::UnsortedOrDuplicate("opening schedule initial groups"));
        }
        let mut seen = HashSet::with_capacity(self.initial_groups.len());
        for group in &self.initial_groups {
            if !seen.insert(group.cohort_id)
                || group.slot_count == 0
                || !group.slot_count.is_power_of_two()
                || group.touched_slots.is_empty()
                || group.touched_slots.iter().any(|slot| *slot >= group.slot_count)
            {
                return Err(FrameError::Invalid("opening schedule initial group"));
            }
            require_strictly_increasing(&group.touched_slots, "opening schedule touched slots")?;
        }
        for (index, frame) in self.fold_frames.iter().enumerate() {
            frame.validate()?;
            if frame.oracle_kind != OracleKindV4::GlobalFoldAggregate
                || usize::from(frame.fold_round) != index + 1
                || (index > 0 && self.fold_frames[index - 1].output_log2 != frame.output_log2 + 1)
            {
                return Err(FrameError::Invalid("opening schedule fold order"));
            }
        }
        Ok(())
    }
}

impl ManifestFrameV4 {
    fn validate(&self) -> Result<(), FrameError> {
        match self {
            Self::Leaf(frame) => legacy_validate(v3::Frame::ManifestLeaf(frame.clone())),
            Self::Node(frame) => legacy_validate(v3::Frame::ManifestNode(frame.clone())),
        }
    }

    fn as_frame(&self) -> FrameV4 {
        match self {
            Self::Leaf(frame) => FrameV4::ManifestLeaf(frame.clone()),
            Self::Node(frame) => FrameV4::ManifestNode(frame.clone()),
        }
    }
}

impl ResponseEnvelopeFrameV4 {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.profile_digest != profile_digest_v4() {
            return Err(FrameError::Invalid("response profile digest"));
        }
        u16::try_from(self.descriptor_digests.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.manifest_frames.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.claim_frames.len()).map_err(|_| FrameError::Overflow)?;
        u16::try_from(self.ordered_h_symbols.len()).map_err(|_| FrameError::Overflow)?;
        u16::try_from(self.m9_frames.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.fold_frames.len()).map_err(|_| FrameError::Overflow)?;
        if self.descriptor_digests.is_empty() {
            return Err(FrameError::Invalid("empty response descriptors"));
        }
        require_unique(&self.descriptor_digests, "response descriptors")?;
        if self.claim_frames.len() > 3320
            || self.ordered_h_symbols.len() > 1660
            || self.ordered_h_symbols.len() != self.m9_frames.len()
            || self.descriptor_digests.len() != self.m9_frames.len()
            || usize::from(self.zero_batch_frame.claim_count) != self.m9_frames.len()
            || usize::from(self.authenticated_output_link_frame.relation_count)
                != 2 * self.m9_frames.len()
            || self.fold_frames.is_empty()
            || self.fold_frames.len() > 30
        {
            return Err(FrameError::Invalid("response masked/global schedule"));
        }
        for (descriptor, transfer) in self.descriptor_digests.iter().zip(&self.m9_frames) {
            if descriptor != &transfer.descriptor_digest {
                return Err(FrameError::Invalid("response M9 descriptor order"));
            }
        }
        for frame in &self.manifest_frames {
            frame.validate()?;
        }
        for claim in &self.claim_frames {
            legacy_validate(v3::Frame::ReducedClaim(claim.clone()))?;
            if !self.descriptor_digests.contains(&claim.descriptor_digest) {
                return Err(FrameError::Invalid("claim descriptor"));
            }
        }
        for (index, frame) in self.fold_frames.iter().enumerate() {
            frame.validate()?;
            if frame.oracle_kind != OracleKindV4::GlobalFoldAggregate
                || usize::from(frame.fold_round) != index + 1
            {
                return Err(FrameError::Invalid("response global fold order"));
            }
        }
        for frame in &self.m9_frames {
            legacy_validate(v3::Frame::M9Transfer(frame.clone()))?;
        }
        legacy_validate(v3::Frame::AuthenticatedOutputLink(
            self.authenticated_output_link_frame.clone(),
        ))?;
        legacy_validate(v3::Frame::ResponseZeroBatch(self.zero_batch_frame.clone()))?;
        self.packed_opening_frame.validate()?;
        Ok(())
    }

    pub fn validate_link_schedule(
        &self,
        round_correlation_domain_ids: &[u64],
    ) -> Result<(), FrameError> {
        self.validate()?;
        let expected = authenticated_output_link_schedule_digest_v4(
            self.epoch,
            &self.claim_frames,
            &self.descriptor_digests,
            &self.ordered_h_symbols,
            &self.m9_frames,
            self.authenticated_output_link_frame.round_count,
            round_correlation_domain_ids,
        )?;
        if expected != self.authenticated_output_link_frame.link_schedule_digest {
            return Err(FrameError::Invalid("authenticated-output link schedule digest"));
        }
        Ok(())
    }

    pub fn validate_statement(
        &self,
        expected_model_root: Digest,
        expected_epoch: u64,
        expected_descriptor_digests: &[Digest],
        expected_claim_frames: &[ReducedClaimFrame],
        round_correlation_domain_ids: &[u64],
        opening_schedule: &PackedOpeningScheduleV4,
    ) -> Result<(), FrameError> {
        self.validate_link_schedule(round_correlation_domain_ids)?;
        if self.model_root != expected_model_root
            || self.epoch != expected_epoch
            || self.descriptor_digests != expected_descriptor_digests
            || self.claim_frames != expected_claim_frames
            || self.fold_frames != opening_schedule.fold_frames
            || opening_schedule.model_root != expected_model_root
            || opening_schedule.epoch != expected_epoch
        {
            return Err(FrameError::Invalid("response public statement"));
        }
        self.packed_opening_frame.validate_against_schedule(opening_schedule)
    }

    fn encode_body(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = WriterV4::default();
        out.digest(&self.profile_digest);
        out.digest(&self.model_root);
        out.u64(self.epoch);
        out.u16(u16::try_from(self.descriptor_digests.len()).map_err(|_| FrameError::Overflow)?);
        for descriptor in &self.descriptor_digests {
            out.digest(descriptor);
        }
        out.u32(u32::try_from(self.manifest_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.manifest_frames {
            out.nested(&frame.as_frame())?;
        }
        out.u32(u32::try_from(self.claim_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.claim_frames {
            out.nested(&FrameV4::ReducedClaim(frame.clone()))?;
        }
        out.u16(u16::try_from(self.ordered_h_symbols.len()).map_err(|_| FrameError::Overflow)?);
        for symbol in &self.ordered_h_symbols {
            out.symbol(*symbol);
        }
        out.u16(u16::try_from(self.m9_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.m9_frames {
            out.nested(&FrameV4::M9Transfer(frame.clone()))?;
        }
        out.nested(&FrameV4::AuthenticatedOutputLink(
            self.authenticated_output_link_frame.clone(),
        ))?;
        out.u32(u32::try_from(self.fold_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.fold_frames {
            out.nested(&FrameV4::FoldCommitment(frame.clone()))?;
        }
        // Retain the v3 query-count width, but schema 4 requires exactly one
        // nested kind-0x0d frame and rejects every kind-0x06 query frame.
        out.u32(1);
        out.nested(&FrameV4::PackedBatchOpening(self.packed_opening_frame.clone()))?;
        out.nested(&FrameV4::ResponseZeroBatch(self.zero_batch_frame.clone()))?;
        Ok(out.finish())
    }

    fn decode_body(input: &mut ReaderV4<'_>) -> Result<Self, FrameError> {
        let profile_digest = input.digest()?;
        let model_root = input.digest()?;
        let epoch = input.u64()?;
        let descriptor_count = usize::from(input.u16()?);
        input.count_fits(descriptor_count, 32)?;
        let mut descriptor_digests = Vec::with_capacity(descriptor_count);
        for _ in 0..descriptor_count {
            descriptor_digests.push(input.digest()?);
        }
        let manifest_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(manifest_count, HEADER_LEN_V4)?;
        let mut manifest_frames = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            manifest_frames.push(match input.nested()? {
                FrameV4::ManifestLeaf(frame) => ManifestFrameV4::Leaf(frame),
                FrameV4::ManifestNode(frame) => ManifestFrameV4::Node(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "manifest frame",
                        kind: other.kind() as u8,
                    });
                }
            });
        }
        let claim_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(claim_count, HEADER_LEN_V4)?;
        let mut claim_frames = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            match input.nested()? {
                FrameV4::ReducedClaim(frame) => claim_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "claim frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }
        let h_count = usize::from(input.u16()?);
        input.count_fits(h_count, 16)?;
        let mut ordered_h_symbols = Vec::with_capacity(h_count);
        for _ in 0..h_count {
            ordered_h_symbols.push(input.symbol()?);
        }
        let m9_count = usize::from(input.u16()?);
        input.count_fits(m9_count, HEADER_LEN_V4)?;
        let mut m9_frames = Vec::with_capacity(m9_count);
        for _ in 0..m9_count {
            match input.nested()? {
                FrameV4::M9Transfer(frame) => m9_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "M9 frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }
        let authenticated_output_link_frame = match input.nested()? {
            FrameV4::AuthenticatedOutputLink(frame) => frame,
            other => {
                return Err(FrameError::WrongNestedKind {
                    field: "authenticated-output link frame",
                    kind: other.kind() as u8,
                });
            }
        };
        let fold_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(fold_count, HEADER_LEN_V4)?;
        let mut fold_frames = Vec::with_capacity(fold_count);
        for _ in 0..fold_count {
            match input.nested()? {
                FrameV4::FoldCommitment(frame) => fold_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "fold frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }
        let query_count = input.u32()?;
        if query_count != 1 {
            return Err(FrameError::Invalid("schema-4 query frame count"));
        }
        let packed_opening_frame = match input.nested()? {
            FrameV4::PackedBatchOpening(frame) => frame,
            other => {
                return Err(FrameError::WrongNestedKind {
                    field: "packed query frame",
                    kind: other.kind() as u8,
                });
            }
        };
        let zero_batch_frame = match input.nested()? {
            FrameV4::ResponseZeroBatch(frame) => frame,
            other => {
                return Err(FrameError::WrongNestedKind {
                    field: "ZeroBatch frame",
                    kind: other.kind() as u8,
                });
            }
        };
        Ok(Self {
            profile_digest,
            model_root,
            epoch,
            descriptor_digests,
            manifest_frames,
            claim_frames,
            ordered_h_symbols,
            m9_frames,
            authenticated_output_link_frame,
            fold_frames,
            packed_opening_frame,
            zero_batch_frame,
        })
    }
}

fn require_strictly_increasing<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), FrameError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(FrameError::UnsortedOrDuplicate(field))
    }
}

fn require_unique(values: &[Digest], field: &'static str) -> Result<(), FrameError> {
    let mut seen = HashSet::with_capacity(values.len());
    if values.iter().all(|value| seen.insert(*value)) {
        Ok(())
    } else {
        Err(FrameError::UnsortedOrDuplicate(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::frame::Phase;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value.wrapping_mul(7).wrapping_add(3)))
    }

    fn fold_frame(round: u8, input_log2: u8, output_log2: u8) -> FoldCommitmentFrameV4 {
        FoldCommitmentFrameV4 {
            cohort_id: 0xA500_F001,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: round,
            input_log2,
            output_log2,
            root_digest: [round; 32],
            ordered_message_symbols: vec![symbol(10 + u64::from(round)), symbol(20)],
        }
    }

    fn small_schedule_and_opening() -> (PackedOpeningScheduleV4, PackedBatchOpeningFrameV4) {
        let schedule = PackedOpeningScheduleV4 {
            profile_digest: profile_digest_v4(),
            model_root: [0x44; 32],
            epoch: 17,
            initial_groups: vec![InitialOpeningScheduleV4 {
                cohort_id: 9,
                domain_log2: 4,
                slot_count: 4,
                touched_slots: vec![0, 2],
                root_digest: [0x91; 32],
            }],
            fold_frames: vec![fold_frame(1, 4, 3)],
            draw_width: 5,
            query_draws: (0..PRODUCTION_QUERY_COUNT_V4).map(|index| (index % 32) as u64).collect(),
        };
        let indices = projected_query_indices(&schedule.query_draws, 4).unwrap();
        let inner = usize::try_from(
            u64::try_from(indices.len()).unwrap() * merkle_aux_node_count(2, &[0, 2]).unwrap(),
        )
        .unwrap();
        let outer = usize::try_from(merkle_aux_node_count(4, &indices).unwrap()).unwrap();
        let fold_indices = projected_query_indices(&schedule.query_draws, 3).unwrap();
        let fold_outer = usize::try_from(merkle_aux_node_count(3, &fold_indices).unwrap()).unwrap();
        let mut opening = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: [0; 32],
            initial_groups: vec![InitialOpeningGroupV4 {
                cohort_id: 9,
                domain_log2: 4,
                slot_count: 4,
                touched_slots: vec![0, 2],
                opened_symbols: vec![symbol(31); indices.len() * 2],
                inner_sibling_digests: vec![[0xA1; 32]; inner],
                outer_sibling_digests: vec![[0xA2; 32]; outer],
            }],
            fold_rounds: vec![FoldRoundOpeningV4 {
                fold_round: 1,
                domain_log2: 3,
                opened_symbols: vec![symbol(41); fold_indices.len()],
                outer_sibling_digests: vec![[0xA3; 32]; fold_outer],
            }],
        };
        schedule.validate().unwrap();
        opening.opening_schedule_digest = opening_schedule_digest_v4(&schedule).unwrap();
        (schedule, opening)
    }

    #[test]
    fn packed_schema4_roundtrip_is_canonical_and_schema_separated() {
        let (schedule, opening) = small_schedule_and_opening();
        opening.validate_against_schedule(&schedule).unwrap();
        let frame = FrameV4::PackedBatchOpening(opening.clone());
        let bytes = frame.encode().unwrap();
        assert_eq!(&bytes[..8], &MAGIC_V4);
        assert_eq!(bytes[8..10], SCHEMA_V4.to_le_bytes());
        assert_eq!(bytes[10], FrameKindV4::PackedBatchOpening as u8);
        assert_eq!(decode_v4(&bytes).unwrap(), frame);
        assert!(v3::decode(&bytes).is_err());

        let v3_frame = v3::Frame::M9Transfer(M9TransferFrame {
            descriptor_digest: [7; 32],
            mask_correction_symbol: symbol(5),
        })
        .encode()
        .unwrap();
        assert!(decode_v4(&v3_frame).is_err());
    }

    #[test]
    fn descriptor_and_global_fold_roundtrip_under_v4_only() {
        let descriptor = DescriptorFrameV4 {
            profile_digest: profile_digest_v4(),
            model_config_digest: [1; 32],
            weights_digest: [2; 32],
            namespace_kind: NamespaceKind::Layer,
            namespace_index: 3,
            tensor_id: 17,
            block_kind: BlockKind::AttentionQ,
            block_ordinal: 0,
            split_prefix: 255,
            mu: 14,
            ell: 15,
            rate_log2: 3,
            source_rows: 128,
            source_cols: 128,
            padded_rows: 128,
            padded_cols: 128,
            logical_coeffs: 1 << 14,
            padded_coeffs: 1 << 14,
            cohort_id: 9,
            slot: 0,
            slot_count: 1,
            n_w: 1 << 18,
            n_g: 1 << 18,
            transfer_template_digest: [3; 32],
        };
        for frame in [FrameV4::Descriptor(descriptor), FrameV4::FoldCommitment(fold_frame(1, 4, 3))]
        {
            let bytes = frame.encode().unwrap();
            assert_eq!(decode_v4(&bytes).unwrap(), frame);
            assert!(v3::decode(&bytes).is_err());
        }
    }

    #[test]
    fn response_has_exactly_one_packed_query_and_rejects_kind_06_substitution() {
        let (schedule, opening) = small_schedule_and_opening();
        let descriptor = [0x51; 32];
        let claim = ReducedClaimFrame {
            descriptor_digest: descriptor,
            parent_claim_digest: [0x52; 32],
            phase: Phase::Prefill,
            phase_ordinal: 0,
            point: (0..14).map(|index| symbol(100 + index)).collect(),
            affine_scale: Fp2::ONE,
            auth_domain: 71,
        };
        let m9 =
            M9TransferFrame { descriptor_digest: descriptor, mask_correction_symbol: symbol(73) };
        let domains = [81, 82];
        let link_digest = authenticated_output_link_schedule_digest_v4(
            schedule.epoch,
            std::slice::from_ref(&claim),
            &[descriptor],
            &[symbol(79)],
            std::slice::from_ref(&m9),
            1,
            &domains,
        )
        .unwrap();
        let response = ResponseEnvelopeFrameV4 {
            profile_digest: profile_digest_v4(),
            model_root: schedule.model_root,
            epoch: schedule.epoch,
            descriptor_digests: vec![descriptor],
            manifest_frames: vec![ManifestFrameV4::Leaf(ManifestLeafFrame {
                descriptor_digest: descriptor,
                ordered_roots: vec![[0x61; 32]],
            })],
            claim_frames: vec![claim.clone()],
            ordered_h_symbols: vec![symbol(79)],
            m9_frames: vec![m9],
            authenticated_output_link_frame: AuthenticatedOutputLinkFrame {
                relation_count: 2,
                round_count: 1,
                link_schedule_digest: link_digest,
                ordered_round_correction_symbols: vec![symbol(83), symbol(89)],
                terminal_opened_tag_symbol: symbol(97),
            },
            fold_frames: schedule.fold_frames.clone(),
            packed_opening_frame: opening,
            zero_batch_frame: ResponseZeroBatchFrame {
                claim_count: 1,
                mask_correction_symbol: symbol(101),
                opened_tag_symbol: symbol(103),
            },
        };
        response
            .validate_statement(
                schedule.model_root,
                schedule.epoch,
                &[descriptor],
                &[claim],
                &domains,
                &schedule,
            )
            .unwrap();
        let frame = FrameV4::ResponseEnvelope(response);
        let bytes = frame.encode().unwrap();
        assert_eq!(decode_v4(&bytes).unwrap(), frame);

        let nested_packed = bytes
            .windows(HEADER_LEN_V4)
            .position(|window| window[..8] == MAGIC_V4 && window[10] == 0x0d)
            .expect("nested packed frame");
        let mut wrong_kind = bytes;
        wrong_kind[nested_packed + 10] = 0x06;
        assert!(decode_v4(&wrong_kind).is_err());
    }

    #[test]
    fn packed_schedule_count_order_and_digest_tampers_reject() {
        let (schedule, opening) = small_schedule_and_opening();

        let mut bad = opening.clone();
        bad.opening_schedule_digest[0] ^= 1;
        assert!(bad.validate_against_schedule(&schedule).is_err());

        let mut bad = opening.clone();
        bad.initial_groups[0].opened_symbols.pop();
        assert!(bad.validate_against_schedule(&schedule).is_err());

        let mut bad = opening.clone();
        bad.initial_groups[0].inner_sibling_digests.pop();
        assert!(bad.validate_against_schedule(&schedule).is_err());

        let mut bad = opening.clone();
        bad.fold_rounds[0].outer_sibling_digests.push([0; 32]);
        assert!(bad.validate_against_schedule(&schedule).is_err());

        let mut bad = opening;
        bad.initial_groups[0].touched_slots.swap(0, 1);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn gpt2_packed_codec_matches_every_frozen_count_and_byte() {
        let group_rows = [
            (0xA500_0001, 30, 2, 2, 444, 0, 4778),
            (0xA500_0002, 26, 64, 36, 7992, 666, 3872),
            (0xA500_0003, 24, 16, 13, 2886, 444, 3410),
            (0xA500_0100, 20, 2, 2, 444, 0, 2548),
            (0xA500_0101, 19, 64, 49, 10878, 888, 2346),
        ];
        let initial_groups = group_rows
            .into_iter()
            .map(|(cohort_id, domain_log2, slot_count, touched, symbols, inner, outer)| {
                InitialOpeningGroupV4 {
                    cohort_id,
                    domain_log2,
                    slot_count,
                    touched_slots: (0..touched).collect(),
                    opened_symbols: vec![Fp2::ZERO; symbols],
                    inner_sibling_digests: vec![[0; 32]; inner],
                    outer_sibling_digests: vec![[0; 32]; outer],
                }
            })
            .collect();
        let round_rows = [
            (222, 4570),
            (222, 4334),
            (222, 4094),
            (222, 3872),
            (222, 3648),
            (222, 3410),
            (222, 3202),
            (222, 2998),
            (222, 2778),
            (222, 2548),
            (222, 2346),
            (222, 2112),
            (222, 1858),
            (222, 1654),
            (222, 1428),
            (220, 1178),
            (218, 978),
            (214, 746),
            (214, 552),
            (194, 366),
            (166, 200),
            (146, 80),
            (100, 24),
            (62, 2),
            (32, 0),
            (16, 0),
            (8, 0),
        ];
        let fold_rounds = round_rows
            .into_iter()
            .enumerate()
            .map(|(index, (symbols, siblings))| FoldRoundOpeningV4 {
                fold_round: (index + 1) as u8,
                domain_log2: 29 - index as u8,
                opened_symbols: vec![Fp2::ZERO; symbols],
                outer_sibling_digests: vec![[0; 32]; siblings],
            })
            .collect();
        let opening = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: [0; 32],
            initial_groups,
            fold_rounds,
        };
        let components = opening.byte_components().unwrap();
        assert_eq!(components.opened_symbols, 27_564);
        assert_eq!(components.initial_inner_siblings, 1_998);
        assert_eq!(components.initial_outer_siblings, 16_954);
        assert_eq!(components.fold_outer_siblings, 48_978);
        assert_eq!(
            components.initial_inner_siblings
                + components.initial_outer_siblings
                + components.fold_outer_siblings,
            67_930
        );
        assert_eq!(components.metadata_bytes, 630);
        assert_eq!(components.serialized_bytes, 2_615_414);
        let bytes = FrameV4::PackedBatchOpening(opening.clone()).encode().unwrap();
        assert_eq!(decode_v4(&bytes).unwrap(), FrameV4::PackedBatchOpening(opening));
    }

    #[test]
    fn v4_leaf_and_node_hash_domains_keep_n4_roles_distinct() {
        let leaf = PcsLeafFrameV4 {
            cohort_id: 1,
            tree_role: TreeRole::Outer,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: 1,
            outer_index: 0,
            payload: PcsLeafPayloadV4::Outer { inner_root_digest: [0; 32] },
        };
        let node = PcsNodeFrameV4 {
            cohort_id: 1,
            tree_role: TreeRole::Outer,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: 1,
            outer_index: u64::MAX,
            level: 1,
            node_index: 0,
            left_digest: [0; 32],
            right_digest: [0; 32],
        };
        assert_ne!(hash_pcs_leaf_v4(&leaf).unwrap(), hash_pcs_node_v4(&node).unwrap());
    }
}
