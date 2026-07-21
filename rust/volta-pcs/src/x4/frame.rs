//! Canonical wire grammar for `x4-zkdeepfold-ud-e29-v2`.
//!
//! The byte layout in this file is normative.  It deliberately avoids serde:
//! every width, order, tag and rejection rule is explicit and stable.

use std::collections::HashSet;

use volta_field::{Fp, Fp2, P};

pub type Digest = [u8; 32];

pub const MAGIC: [u8; 8] = *b"VOLTAX42";
pub const SCHEMA: u16 = 2;
pub const HEADER_LEN: usize = 16;
pub const PROFILE_NAME: &[u8] = b"x4-zkdeepfold-ud-e29-v2";

pub const DESCRIPTOR_HASH_CONTEXT: &str = "volta-zk/x4/descriptor/v2";
pub const PCS_LEAF_HASH_CONTEXT: &str = "volta-zk/x4/pcs-leaf/v2";
pub const PCS_NODE_HASH_CONTEXT: &str = "volta-zk/x4/pcs-node/v2";
pub const MANIFEST_LEAF_HASH_CONTEXT: &str = "volta-zk/x4/manifest-leaf/v2";
pub const MANIFEST_NODE_HASH_CONTEXT: &str = "volta-zk/x4/manifest-node/v2";
pub const MANIFEST_ID_HASH_CONTEXT: &str = "volta-zk/x4/manifest-id/v2";
pub const TRANSFER_TEMPLATE_HASH_CONTEXT: &str = "volta-zk/x4/transfer-template/v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    UnexpectedEof,
    BadMagic,
    BadSchema(u16),
    UnknownKind(u8),
    NonZeroFlags(u8),
    LengthMismatch,
    Overflow,
    InvalidBool(u8),
    NonCanonicalField,
    UnknownEnum { field: &'static str, value: u8 },
    Invalid(&'static str),
    UnsortedOrDuplicate(&'static str),
    WrongNestedKind { field: &'static str, kind: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FrameKind {
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
}

impl FrameKind {
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
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

macro_rules! u8_enum {
    ($name:ident, $field:literal, {$($variant:ident = $value:literal),+ $(,)?}) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u8)]
        pub enum $name {
            $($variant = $value),+
        }

        impl $name {
            fn decode(value: u8) -> Result<Self, FrameError> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    other => Err(FrameError::UnknownEnum { field: $field, value: other }),
                }
            }
        }
    };
}

u8_enum!(NamespaceKind, "namespace_kind", { Global = 0, Layer = 1 });
u8_enum!(BlockKind, "block_kind", {
    Fixed = 0,
    AttentionQ = 1,
    AttentionK = 2,
    AttentionV = 3,
    AttentionO = 4,
    Router = 5,
    ExpertGateUp = 6,
    ExpertDown = 7,
    EmbeddingHalf = 8,
    UnembeddingHalf = 9,
});
u8_enum!(TreeRole, "tree_role", { Inner = 0, Outer = 1 });
u8_enum!(OracleKind, "oracle_kind", { WeightExtension = 0, Auxiliary = 1 });
u8_enum!(Phase, "phase", { Prefill = 0, Decode = 1 });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorFrame {
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
pub enum PcsLeafPayload {
    Inner { descriptor_digest: Digest, slot: u16, present: bool, symbols: Vec<Fp2> },
    Outer { inner_root_digest: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsLeafFrame {
    pub cohort_id: u32,
    pub tree_role: TreeRole,
    pub oracle_kind: OracleKind,
    pub fold_round: u8,
    pub outer_index: u64,
    pub payload: PcsLeafPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcsNodeFrame {
    pub cohort_id: u32,
    pub tree_role: TreeRole,
    pub oracle_kind: OracleKind,
    pub fold_round: u8,
    pub outer_index: u64,
    pub level: u8,
    pub node_index: u64,
    pub left_digest: Digest,
    pub right_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestLeafFrame {
    pub descriptor_digest: Digest,
    pub ordered_roots: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestNodeFrame {
    pub manifest_id_digest: Digest,
    pub level: u8,
    pub node_index: u64,
    pub left_digest: Digest,
    pub right_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxNode {
    pub tree_role: TreeRole,
    pub outer_index: u64,
    pub level: u8,
    pub node_index: u64,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortMultiproofFrame {
    pub cohort_id: u32,
    pub oracle_kind: OracleKind,
    pub fold_round: u8,
    pub outer_indices: Vec<u64>,
    pub touched_slots: Vec<u16>,
    pub opened_leaves: Vec<PcsLeafFrame>,
    pub aux_nodes: Vec<AuxNode>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReducedClaimFrame {
    pub descriptor_digest: Digest,
    pub parent_claim_digest: Digest,
    pub phase: Phase,
    pub phase_ordinal: u16,
    pub point: Vec<Fp2>,
    pub affine_scale: Fp2,
    pub auth_domain: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldCommitmentFrame {
    pub cohort_id: u32,
    pub oracle_kind: OracleKind,
    pub fold_round: u8,
    pub input_log2: u8,
    pub output_log2: u8,
    pub root_digest: Digest,
    pub ordered_message_symbols: Vec<Fp2>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M9TransferFrame {
    pub descriptor_digest: Digest,
    pub mask_correction_symbol: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseZeroBatchFrame {
    pub claim_count: u16,
    pub mask_correction_symbol: Fp2,
    pub opened_tag_symbol: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestFrame {
    Leaf(ManifestLeafFrame),
    Node(ManifestNodeFrame),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseEnvelopeFrame {
    pub profile_digest: Digest,
    pub model_root: Digest,
    pub epoch: u64,
    pub descriptor_digests: Vec<Digest>,
    pub manifest_frames: Vec<ManifestFrame>,
    pub claim_frames: Vec<ReducedClaimFrame>,
    pub ordered_h_symbols: Vec<Fp2>,
    pub fold_frames: Vec<FoldCommitmentFrame>,
    pub query_frames: Vec<CohortMultiproofFrame>,
    pub m9_frames: Vec<M9TransferFrame>,
    pub zero_batch_frame: ResponseZeroBatchFrame,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Descriptor(DescriptorFrame),
    PcsLeaf(PcsLeafFrame),
    PcsNode(PcsNodeFrame),
    ManifestLeaf(ManifestLeafFrame),
    ManifestNode(ManifestNodeFrame),
    CohortMultiproof(CohortMultiproofFrame),
    ResponseEnvelope(ResponseEnvelopeFrame),
    ReducedClaim(ReducedClaimFrame),
    FoldCommitment(FoldCommitmentFrame),
    M9Transfer(M9TransferFrame),
    ResponseZeroBatch(ResponseZeroBatchFrame),
}

impl Frame {
    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Descriptor(_) => FrameKind::Descriptor,
            Self::PcsLeaf(_) => FrameKind::PcsLeaf,
            Self::PcsNode(_) => FrameKind::PcsNode,
            Self::ManifestLeaf(_) => FrameKind::ManifestLeaf,
            Self::ManifestNode(_) => FrameKind::ManifestNode,
            Self::CohortMultiproof(_) => FrameKind::CohortMultiproof,
            Self::ResponseEnvelope(_) => FrameKind::ResponseEnvelope,
            Self::ReducedClaim(_) => FrameKind::ReducedClaim,
            Self::FoldCommitment(_) => FrameKind::FoldCommitment,
            Self::M9Transfer(_) => FrameKind::M9Transfer,
            Self::ResponseZeroBatch(_) => FrameKind::ResponseZeroBatch,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        let mut body = Writer::default();
        self.encode_body(&mut body)?;
        wrap_frame(self.kind(), body.finish())
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        match self {
            Self::Descriptor(frame) => frame.validate(),
            Self::PcsLeaf(frame) => frame.validate(),
            Self::PcsNode(frame) => frame.validate(),
            Self::ManifestLeaf(frame) => frame.validate(),
            Self::ManifestNode(frame) => frame.validate(),
            Self::CohortMultiproof(frame) => frame.validate(),
            Self::ResponseEnvelope(frame) => frame.validate(),
            Self::ReducedClaim(frame) => frame.validate(),
            Self::FoldCommitment(frame) => frame.validate(),
            Self::M9Transfer(frame) => frame.validate(),
            Self::ResponseZeroBatch(frame) => frame.validate(),
        }
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        match self {
            Self::Descriptor(frame) => frame.encode_body(out),
            Self::PcsLeaf(frame) => frame.encode_body(out),
            Self::PcsNode(frame) => frame.encode_body(out),
            Self::ManifestLeaf(frame) => frame.encode_body(out),
            Self::ManifestNode(frame) => frame.encode_body(out),
            Self::CohortMultiproof(frame) => frame.encode_body(out),
            Self::ResponseEnvelope(frame) => frame.encode_body(out),
            Self::ReducedClaim(frame) => frame.encode_body(out),
            Self::FoldCommitment(frame) => frame.encode_body(out),
            Self::M9Transfer(frame) => frame.encode_body(out),
            Self::ResponseZeroBatch(frame) => frame.encode_body(out),
        }
    }
}

pub fn profile_digest() -> Digest {
    *blake3::hash(PROFILE_NAME).as_bytes()
}

fn typed_hash(context: &'static str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

pub fn hash_descriptor(frame: &DescriptorFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash(DESCRIPTOR_HASH_CONTEXT, &Frame::Descriptor(frame.clone()).encode()?))
}

pub fn hash_pcs_leaf(frame: &PcsLeafFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash(PCS_LEAF_HASH_CONTEXT, &Frame::PcsLeaf(frame.clone()).encode()?))
}

pub fn hash_pcs_node(frame: &PcsNodeFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash(PCS_NODE_HASH_CONTEXT, &Frame::PcsNode(frame.clone()).encode()?))
}

pub fn hash_manifest_leaf(frame: &ManifestLeafFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash(MANIFEST_LEAF_HASH_CONTEXT, &Frame::ManifestLeaf(frame.clone()).encode()?))
}

pub fn hash_manifest_node(frame: &ManifestNodeFrame) -> Result<Digest, FrameError> {
    Ok(typed_hash(MANIFEST_NODE_HASH_CONTEXT, &Frame::ManifestNode(frame.clone()).encode()?))
}

pub fn manifest_id_digest(
    model_config_digest: Digest,
    weights_digest: Digest,
    epoch: u64,
) -> Digest {
    let mut input = Vec::with_capacity(104);
    input.extend_from_slice(&profile_digest());
    input.extend_from_slice(&model_config_digest);
    input.extend_from_slice(&weights_digest);
    input.extend_from_slice(&epoch.to_le_bytes());
    typed_hash(MANIFEST_ID_HASH_CONTEXT, &input)
}

pub fn transfer_template_digest(domain_ids: &[u64]) -> Result<Digest, FrameError> {
    require_strictly_increasing(domain_ids, "transfer domain ids")?;
    let count = u16::try_from(domain_ids.len()).map_err(|_| FrameError::Overflow)?;
    let mut input = Vec::with_capacity(2 + domain_ids.len() * 8);
    input.extend_from_slice(&count.to_le_bytes());
    for domain in domain_ids {
        input.extend_from_slice(&domain.to_le_bytes());
    }
    Ok(typed_hash(TRANSFER_TEMPLATE_HASH_CONTEXT, &input))
}

pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    if bytes.len() < HEADER_LEN {
        return Err(FrameError::UnexpectedEof);
    }
    if bytes[..8] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    let schema = u16::from_le_bytes([bytes[8], bytes[9]]);
    if schema != SCHEMA {
        return Err(FrameError::BadSchema(schema));
    }
    let kind = FrameKind::decode(bytes[10])?;
    let flags = bytes[11];
    if flags != 0 {
        return Err(FrameError::NonZeroFlags(flags));
    }
    let body_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let expected = HEADER_LEN.checked_add(body_len).ok_or(FrameError::Overflow)?;
    if bytes.len() != expected {
        return Err(FrameError::LengthMismatch);
    }
    let mut input = Reader::new(&bytes[HEADER_LEN..]);
    let frame = decode_body(kind, &mut input)?;
    input.finish()?;
    frame.validate()?;
    Ok(frame)
}

fn decode_body(kind: FrameKind, input: &mut Reader<'_>) -> Result<Frame, FrameError> {
    Ok(match kind {
        FrameKind::Descriptor => Frame::Descriptor(DescriptorFrame::decode_body(input)?),
        FrameKind::PcsLeaf => Frame::PcsLeaf(PcsLeafFrame::decode_body(input)?),
        FrameKind::PcsNode => Frame::PcsNode(PcsNodeFrame::decode_body(input)?),
        FrameKind::ManifestLeaf => Frame::ManifestLeaf(ManifestLeafFrame::decode_body(input)?),
        FrameKind::ManifestNode => Frame::ManifestNode(ManifestNodeFrame::decode_body(input)?),
        FrameKind::CohortMultiproof => {
            Frame::CohortMultiproof(CohortMultiproofFrame::decode_body(input)?)
        }
        FrameKind::ResponseEnvelope => {
            Frame::ResponseEnvelope(ResponseEnvelopeFrame::decode_body(input)?)
        }
        FrameKind::ReducedClaim => Frame::ReducedClaim(ReducedClaimFrame::decode_body(input)?),
        FrameKind::FoldCommitment => {
            Frame::FoldCommitment(FoldCommitmentFrame::decode_body(input)?)
        }
        FrameKind::M9Transfer => Frame::M9Transfer(M9TransferFrame::decode_body(input)?),
        FrameKind::ResponseZeroBatch => {
            Frame::ResponseZeroBatch(ResponseZeroBatchFrame::decode_body(input)?)
        }
    })
}

fn wrap_frame(kind: FrameKind, body: Vec<u8>) -> Result<Vec<u8>, FrameError> {
    let body_len = u32::try_from(body.len()).map_err(|_| FrameError::Overflow)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&SCHEMA.to_le_bytes());
    bytes.push(kind as u8);
    bytes.push(0);
    bytes.extend_from_slice(&body_len.to_le_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
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

    fn nested(&mut self, frame: Frame) -> Result<(), FrameError> {
        self.bytes.extend_from_slice(&frame.encode()?);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
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

    fn nested(&mut self) -> Result<Frame, FrameError> {
        if self.remaining() < HEADER_LEN {
            return Err(FrameError::UnexpectedEof);
        }
        let header = &self.bytes[self.pos..self.pos + HEADER_LEN];
        let body_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let total = HEADER_LEN.checked_add(body_len).ok_or(FrameError::Overflow)?;
        decode(self.take(total)?)
    }

    fn finish(&self) -> Result<(), FrameError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(FrameError::LengthMismatch)
        }
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

fn expected_ell(mu: u8) -> u8 {
    let target = 128u32 * u32::from(mu) * u32::from(mu) + 1;
    (u32::BITS - (target - 1).leading_zeros()) as u8
}

impl DescriptorFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.profile_digest != profile_digest() {
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
        if self.rate_log2 != 3 {
            return Err(FrameError::Invalid("descriptor rate"));
        }
        if self.ell != expected_ell(self.mu) {
            return Err(FrameError::Invalid("descriptor ell"));
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

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
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
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            profile_digest: input.digest()?,
            model_config_digest: input.digest()?,
            weights_digest: input.digest()?,
            namespace_kind: NamespaceKind::decode(input.u8()?)?,
            namespace_index: input.u8()?,
            tensor_id: input.u16()?,
            block_kind: BlockKind::decode(input.u8()?)?,
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

impl PcsLeafFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        match (&self.tree_role, &self.payload) {
            (TreeRole::Inner, PcsLeafPayload::Inner { slot: _, present, symbols, .. }) => {
                if self.outer_index == u64::MAX {
                    return Err(FrameError::Invalid("inner leaf outer index"));
                }
                u16::try_from(symbols.len()).map_err(|_| FrameError::Overflow)?;
                if (*present && symbols.is_empty()) || (!*present && !symbols.is_empty()) {
                    return Err(FrameError::Invalid("inner leaf presence"));
                }
            }
            (TreeRole::Outer, PcsLeafPayload::Outer { .. }) => {
                if self.outer_index == u64::MAX {
                    return Err(FrameError::Invalid("outer leaf index"));
                }
            }
            _ => return Err(FrameError::Invalid("leaf role/payload")),
        }
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.u32(self.cohort_id);
        out.u8(self.tree_role as u8);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u64(self.outer_index);
        match &self.payload {
            PcsLeafPayload::Inner { descriptor_digest, slot, present, symbols } => {
                out.digest(descriptor_digest);
                out.u16(*slot);
                out.u8(u8::from(*present));
                out.u16(u16::try_from(symbols.len()).map_err(|_| FrameError::Overflow)?);
                for symbol in symbols {
                    out.symbol(*symbol);
                }
            }
            PcsLeafPayload::Outer { inner_root_digest } => out.digest(inner_root_digest),
        }
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        let cohort_id = input.u32()?;
        let tree_role = TreeRole::decode(input.u8()?)?;
        let oracle_kind = OracleKind::decode(input.u8()?)?;
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
                PcsLeafPayload::Inner { descriptor_digest, slot, present, symbols }
            }
            TreeRole::Outer => PcsLeafPayload::Outer { inner_root_digest: input.digest()? },
        };
        Ok(Self { cohort_id, tree_role, oracle_kind, fold_round, outer_index, payload })
    }
}

impl PcsNodeFrame {
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

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.u32(self.cohort_id);
        out.u8(self.tree_role as u8);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u64(self.outer_index);
        out.u8(self.level);
        out.u64(self.node_index);
        out.digest(&self.left_digest);
        out.digest(&self.right_digest);
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            cohort_id: input.u32()?,
            tree_role: TreeRole::decode(input.u8()?)?,
            oracle_kind: OracleKind::decode(input.u8()?)?,
            fold_round: input.u8()?,
            outer_index: input.u64()?,
            level: input.u8()?,
            node_index: input.u64()?,
            left_digest: input.digest()?,
            right_digest: input.digest()?,
        })
    }
}

impl ManifestLeafFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.ordered_roots.is_empty() {
            return Err(FrameError::Invalid("manifest roots"));
        }
        u16::try_from(self.ordered_roots.len()).map_err(|_| FrameError::Overflow)?;
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.digest(&self.descriptor_digest);
        out.u16(u16::try_from(self.ordered_roots.len()).map_err(|_| FrameError::Overflow)?);
        for root in &self.ordered_roots {
            out.digest(root);
        }
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        let descriptor_digest = input.digest()?;
        let count = usize::from(input.u16()?);
        input.count_fits(count, 32)?;
        let mut ordered_roots = Vec::with_capacity(count);
        for _ in 0..count {
            ordered_roots.push(input.digest()?);
        }
        Ok(Self { descriptor_digest, ordered_roots })
    }
}

impl ManifestNodeFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.level == 0 {
            return Err(FrameError::Invalid("manifest node level"));
        }
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.digest(&self.manifest_id_digest);
        out.u8(self.level);
        out.u64(self.node_index);
        out.digest(&self.left_digest);
        out.digest(&self.right_digest);
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            manifest_id_digest: input.digest()?,
            level: input.u8()?,
            node_index: input.u64()?,
            left_digest: input.digest()?,
            right_digest: input.digest()?,
        })
    }
}

impl AuxNode {
    fn validate(&self) -> Result<(), FrameError> {
        match self.tree_role {
            TreeRole::Inner if self.outer_index == u64::MAX => {
                return Err(FrameError::Invalid("inner aux outer index"));
            }
            TreeRole::Outer if self.outer_index != u64::MAX => {
                return Err(FrameError::Invalid("outer aux outer index"));
            }
            _ => {}
        }
        Ok(())
    }

    fn sort_key(&self) -> (u8, u64, u8, u64, Digest) {
        (self.tree_role as u8, self.outer_index, self.level, self.node_index, self.digest)
    }
}

impl CohortMultiproofFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        u16::try_from(self.outer_indices.len()).map_err(|_| FrameError::Overflow)?;
        u16::try_from(self.touched_slots.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.opened_leaves.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.aux_nodes.len()).map_err(|_| FrameError::Overflow)?;
        if self.outer_indices.is_empty() || self.touched_slots.is_empty() {
            return Err(FrameError::Invalid("empty cohort multiproof"));
        }
        require_strictly_increasing(&self.outer_indices, "multiproof outer indices")?;
        require_strictly_increasing(&self.touched_slots, "multiproof touched slots")?;

        let expected_leaf_count = self
            .outer_indices
            .len()
            .checked_mul(self.touched_slots.len().checked_add(1).ok_or(FrameError::Overflow)?)
            .ok_or(FrameError::Overflow)?;
        if self.opened_leaves.len() != expected_leaf_count {
            return Err(FrameError::Invalid("multiproof opened leaf count"));
        }

        let mut previous_key = None;
        let mut seen = HashSet::with_capacity(self.opened_leaves.len());
        for leaf in &self.opened_leaves {
            leaf.validate()?;
            if leaf.cohort_id != self.cohort_id
                || leaf.oracle_kind != self.oracle_kind
                || leaf.fold_round != self.fold_round
                || self.outer_indices.binary_search(&leaf.outer_index).is_err()
            {
                return Err(FrameError::Invalid("multiproof leaf context"));
            }
            let (role_order, slot) = match &leaf.payload {
                PcsLeafPayload::Outer { .. } if leaf.tree_role == TreeRole::Outer => (0u8, 0u16),
                PcsLeafPayload::Inner { slot, .. } if leaf.tree_role == TreeRole::Inner => {
                    if self.touched_slots.binary_search(slot).is_err() {
                        return Err(FrameError::Invalid("multiproof leaf slot"));
                    }
                    (1u8, *slot)
                }
                _ => return Err(FrameError::Invalid("multiproof leaf payload")),
            };
            let key = (leaf.outer_index, role_order, slot);
            if previous_key.is_some_and(|previous| previous >= key) || !seen.insert(key) {
                return Err(FrameError::UnsortedOrDuplicate("multiproof opened leaves"));
            }
            previous_key = Some(key);
        }

        for outer_index in &self.outer_indices {
            if !seen.contains(&(*outer_index, 0, 0)) {
                return Err(FrameError::Invalid("missing outer leaf"));
            }
            for slot in &self.touched_slots {
                if !seen.contains(&(*outer_index, 1, *slot)) {
                    return Err(FrameError::Invalid("missing inner leaf"));
                }
            }
        }

        let mut previous_aux = None;
        for node in &self.aux_nodes {
            node.validate()?;
            if node.tree_role == TreeRole::Inner
                && self.outer_indices.binary_search(&node.outer_index).is_err()
            {
                return Err(FrameError::Invalid("multiproof inner aux context"));
            }
            let key = node.sort_key();
            if previous_aux.is_some_and(|previous| previous >= key) {
                return Err(FrameError::UnsortedOrDuplicate("multiproof aux nodes"));
            }
            previous_aux = Some(key);
        }
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.u32(self.cohort_id);
        out.u8(self.oracle_kind as u8);
        out.u8(self.fold_round);
        out.u16(u16::try_from(self.outer_indices.len()).map_err(|_| FrameError::Overflow)?);
        for index in &self.outer_indices {
            out.u64(*index);
        }
        out.u16(u16::try_from(self.touched_slots.len()).map_err(|_| FrameError::Overflow)?);
        for slot in &self.touched_slots {
            out.u16(*slot);
        }
        out.u32(u32::try_from(self.opened_leaves.len()).map_err(|_| FrameError::Overflow)?);
        for leaf in &self.opened_leaves {
            out.nested(Frame::PcsLeaf(leaf.clone()))?;
        }
        out.u32(u32::try_from(self.aux_nodes.len()).map_err(|_| FrameError::Overflow)?);
        for node in &self.aux_nodes {
            out.u8(node.tree_role as u8);
            out.u64(node.outer_index);
            out.u8(node.level);
            out.u64(node.node_index);
            out.digest(&node.digest);
        }
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        let cohort_id = input.u32()?;
        let oracle_kind = OracleKind::decode(input.u8()?)?;
        let fold_round = input.u8()?;
        let query_count = usize::from(input.u16()?);
        input.count_fits(query_count, 8)?;
        let mut outer_indices = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            outer_indices.push(input.u64()?);
        }
        let touched_count = usize::from(input.u16()?);
        input.count_fits(touched_count, 2)?;
        let mut touched_slots = Vec::with_capacity(touched_count);
        for _ in 0..touched_count {
            touched_slots.push(input.u16()?);
        }
        let opened_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(opened_count, HEADER_LEN)?;
        let mut opened_leaves = Vec::with_capacity(opened_count);
        for _ in 0..opened_count {
            match input.nested()? {
                Frame::PcsLeaf(leaf) => opened_leaves.push(leaf),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "opened leaf",
                        kind: other.kind() as u8,
                    });
                }
            }
        }
        let aux_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(aux_count, 50)?;
        let mut aux_nodes = Vec::with_capacity(aux_count);
        for _ in 0..aux_count {
            aux_nodes.push(AuxNode {
                tree_role: TreeRole::decode(input.u8()?)?,
                outer_index: input.u64()?,
                level: input.u8()?,
                node_index: input.u64()?,
                digest: input.digest()?,
            });
        }
        Ok(Self {
            cohort_id,
            oracle_kind,
            fold_round,
            outer_indices,
            touched_slots,
            opened_leaves,
            aux_nodes,
        })
    }
}

impl ReducedClaimFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if !(14..=29).contains(&self.point.len()) {
            return Err(FrameError::Invalid("claim point length"));
        }
        u8::try_from(self.point.len()).map_err(|_| FrameError::Overflow)?;
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.digest(&self.descriptor_digest);
        out.digest(&self.parent_claim_digest);
        out.u8(self.phase as u8);
        out.u16(self.phase_ordinal);
        out.u8(u8::try_from(self.point.len()).map_err(|_| FrameError::Overflow)?);
        for symbol in &self.point {
            out.symbol(*symbol);
        }
        out.symbol(self.affine_scale);
        out.u64(self.auth_domain);
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        let descriptor_digest = input.digest()?;
        let parent_claim_digest = input.digest()?;
        let phase = Phase::decode(input.u8()?)?;
        let phase_ordinal = input.u16()?;
        let point_len = usize::from(input.u8()?);
        input.count_fits(point_len, 16)?;
        let mut point = Vec::with_capacity(point_len);
        for _ in 0..point_len {
            point.push(input.symbol()?);
        }
        Ok(Self {
            descriptor_digest,
            parent_claim_digest,
            phase,
            phase_ordinal,
            point,
            affine_scale: input.symbol()?,
            auth_domain: input.u64()?,
        })
    }
}

impl FoldCommitmentFrame {
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

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
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
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        let cohort_id = input.u32()?;
        let oracle_kind = OracleKind::decode(input.u8()?)?;
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

impl M9TransferFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.digest(&self.descriptor_digest);
        out.symbol(self.mask_correction_symbol);
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self { descriptor_digest: input.digest()?, mask_correction_symbol: input.symbol()? })
    }
}

impl ResponseZeroBatchFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.claim_count > 1660 {
            return Err(FrameError::Invalid("ZeroBatch claim count"));
        }
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.u16(self.claim_count);
        out.symbol(self.mask_correction_symbol);
        out.symbol(self.opened_tag_symbol);
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
        Ok(Self {
            claim_count: input.u16()?,
            mask_correction_symbol: input.symbol()?,
            opened_tag_symbol: input.symbol()?,
        })
    }
}

impl ManifestFrame {
    fn validate(&self) -> Result<(), FrameError> {
        match self {
            Self::Leaf(frame) => frame.validate(),
            Self::Node(frame) => frame.validate(),
        }
    }

    fn as_frame(&self) -> Frame {
        match self {
            Self::Leaf(frame) => Frame::ManifestLeaf(frame.clone()),
            Self::Node(frame) => Frame::ManifestNode(frame.clone()),
        }
    }
}

impl ResponseEnvelopeFrame {
    pub fn validate(&self) -> Result<(), FrameError> {
        if self.profile_digest != profile_digest() {
            return Err(FrameError::Invalid("response profile digest"));
        }
        u16::try_from(self.descriptor_digests.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.manifest_frames.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.claim_frames.len()).map_err(|_| FrameError::Overflow)?;
        u16::try_from(self.ordered_h_symbols.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.fold_frames.len()).map_err(|_| FrameError::Overflow)?;
        u32::try_from(self.query_frames.len()).map_err(|_| FrameError::Overflow)?;
        u16::try_from(self.m9_frames.len()).map_err(|_| FrameError::Overflow)?;
        if self.descriptor_digests.is_empty() {
            return Err(FrameError::Invalid("empty response descriptors"));
        }
        require_unique(&self.descriptor_digests, "response descriptors")?;
        if self.claim_frames.len() > 3320 {
            return Err(FrameError::Invalid("response claim count"));
        }
        if self.ordered_h_symbols.len() > 1660
            || self.ordered_h_symbols.len() != self.m9_frames.len()
            || self.descriptor_digests.len() != self.m9_frames.len()
            || usize::from(self.zero_batch_frame.claim_count) != self.m9_frames.len()
        {
            return Err(FrameError::Invalid("response masked schedule"));
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
            claim.validate()?;
            if !self.descriptor_digests.contains(&claim.descriptor_digest) {
                return Err(FrameError::Invalid("claim descriptor"));
            }
        }
        for frame in &self.fold_frames {
            frame.validate()?;
        }
        for frame in &self.query_frames {
            frame.validate()?;
        }
        for frame in &self.m9_frames {
            frame.validate()?;
        }
        self.zero_batch_frame.validate()?;
        Ok(())
    }

    fn encode_body(&self, out: &mut Writer) -> Result<(), FrameError> {
        out.digest(&self.profile_digest);
        out.digest(&self.model_root);
        out.u64(self.epoch);
        out.u16(u16::try_from(self.descriptor_digests.len()).map_err(|_| FrameError::Overflow)?);
        for descriptor in &self.descriptor_digests {
            out.digest(descriptor);
        }
        out.u32(u32::try_from(self.manifest_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.manifest_frames {
            out.nested(frame.as_frame())?;
        }
        out.u32(u32::try_from(self.claim_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.claim_frames {
            out.nested(Frame::ReducedClaim(frame.clone()))?;
        }
        out.u16(u16::try_from(self.ordered_h_symbols.len()).map_err(|_| FrameError::Overflow)?);
        for symbol in &self.ordered_h_symbols {
            out.symbol(*symbol);
        }
        out.u32(u32::try_from(self.fold_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.fold_frames {
            out.nested(Frame::FoldCommitment(frame.clone()))?;
        }
        out.u32(u32::try_from(self.query_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.query_frames {
            out.nested(Frame::CohortMultiproof(frame.clone()))?;
        }
        out.u16(u16::try_from(self.m9_frames.len()).map_err(|_| FrameError::Overflow)?);
        for frame in &self.m9_frames {
            out.nested(Frame::M9Transfer(frame.clone()))?;
        }
        out.nested(Frame::ResponseZeroBatch(self.zero_batch_frame.clone()))?;
        Ok(())
    }

    fn decode_body(input: &mut Reader<'_>) -> Result<Self, FrameError> {
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
        input.count_fits(manifest_count, HEADER_LEN)?;
        let mut manifest_frames = Vec::with_capacity(manifest_count);
        for _ in 0..manifest_count {
            manifest_frames.push(match input.nested()? {
                Frame::ManifestLeaf(frame) => ManifestFrame::Leaf(frame),
                Frame::ManifestNode(frame) => ManifestFrame::Node(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "manifest frame",
                        kind: other.kind() as u8,
                    });
                }
            });
        }

        let claim_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(claim_count, HEADER_LEN)?;
        let mut claim_frames = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            match input.nested()? {
                Frame::ReducedClaim(frame) => claim_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "claim frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }

        let masked_count = usize::from(input.u16()?);
        input.count_fits(masked_count, 16)?;
        let mut ordered_h_symbols = Vec::with_capacity(masked_count);
        for _ in 0..masked_count {
            ordered_h_symbols.push(input.symbol()?);
        }

        let fold_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(fold_count, HEADER_LEN)?;
        let mut fold_frames = Vec::with_capacity(fold_count);
        for _ in 0..fold_count {
            match input.nested()? {
                Frame::FoldCommitment(frame) => fold_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "fold frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }

        let query_count = usize::try_from(input.u32()?).map_err(|_| FrameError::Overflow)?;
        input.count_fits(query_count, HEADER_LEN)?;
        let mut query_frames = Vec::with_capacity(query_count);
        for _ in 0..query_count {
            match input.nested()? {
                Frame::CohortMultiproof(frame) => query_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "query frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }

        let m9_count = usize::from(input.u16()?);
        input.count_fits(m9_count, HEADER_LEN)?;
        let mut m9_frames = Vec::with_capacity(m9_count);
        for _ in 0..m9_count {
            match input.nested()? {
                Frame::M9Transfer(frame) => m9_frames.push(frame),
                other => {
                    return Err(FrameError::WrongNestedKind {
                        field: "M9 frame",
                        kind: other.kind() as u8,
                    });
                }
            }
        }
        let zero_batch_frame = match input.nested()? {
            Frame::ResponseZeroBatch(frame) => frame,
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
            fold_frames,
            query_frames,
            m9_frames,
            zero_batch_frame,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value + 1))
    }

    fn descriptor(slot: u16, slot_count: u16) -> DescriptorFrame {
        DescriptorFrame {
            profile_digest: profile_digest(),
            model_config_digest: [0x11; 32],
            weights_digest: [0x22; 32],
            namespace_kind: NamespaceKind::Layer,
            namespace_index: 3,
            tensor_id: 17,
            block_kind: BlockKind::AttentionQ,
            block_ordinal: slot,
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
            slot,
            slot_count,
            n_w: 1 << 18,
            n_g: 1 << 18,
            transfer_template_digest: transfer_template_digest(&[7, 11, 19]).unwrap(),
        }
    }

    fn inner_leaf(descriptor_digest: Digest, outer_index: u64, slot: u16) -> PcsLeafFrame {
        PcsLeafFrame {
            cohort_id: 9,
            tree_role: TreeRole::Inner,
            oracle_kind: OracleKind::WeightExtension,
            fold_round: 0,
            outer_index,
            payload: PcsLeafPayload::Inner {
                descriptor_digest,
                slot,
                present: true,
                symbols: vec![symbol(100 + outer_index + u64::from(slot))],
            },
        }
    }

    fn outer_leaf(outer_index: u64) -> PcsLeafFrame {
        PcsLeafFrame {
            cohort_id: 9,
            tree_role: TreeRole::Outer,
            oracle_kind: OracleKind::WeightExtension,
            fold_round: 0,
            outer_index,
            payload: PcsLeafPayload::Outer { inner_root_digest: [outer_index as u8; 32] },
        }
    }

    fn multiproof(descriptor_digests: &[Digest]) -> CohortMultiproofFrame {
        let mut opened_leaves = Vec::new();
        for outer_index in [3, 7] {
            opened_leaves.push(outer_leaf(outer_index));
            for (slot, digest) in descriptor_digests.iter().enumerate() {
                opened_leaves.push(inner_leaf(*digest, outer_index, slot as u16));
            }
        }
        CohortMultiproofFrame {
            cohort_id: 9,
            oracle_kind: OracleKind::WeightExtension,
            fold_round: 0,
            outer_indices: vec![3, 7],
            touched_slots: (0..descriptor_digests.len() as u16).collect(),
            opened_leaves,
            aux_nodes: vec![
                AuxNode {
                    tree_role: TreeRole::Inner,
                    outer_index: 3,
                    level: 1,
                    node_index: 1,
                    digest: [0x31; 32],
                },
                AuxNode {
                    tree_role: TreeRole::Outer,
                    outer_index: u64::MAX,
                    level: 1,
                    node_index: 2,
                    digest: [0x32; 32],
                },
            ],
        }
    }

    fn response(descriptor_frame: &DescriptorFrame) -> ResponseEnvelopeFrame {
        let descriptor_digest = hash_descriptor(descriptor_frame).unwrap();
        ResponseEnvelopeFrame {
            profile_digest: profile_digest(),
            model_root: [0x44; 32],
            epoch: 23,
            descriptor_digests: vec![descriptor_digest],
            manifest_frames: vec![ManifestFrame::Leaf(ManifestLeafFrame {
                descriptor_digest,
                ordered_roots: vec![[0x55; 32], [0x56; 32]],
            })],
            claim_frames: vec![ReducedClaimFrame {
                descriptor_digest,
                parent_claim_digest: [0x66; 32],
                phase: Phase::Prefill,
                phase_ordinal: 0,
                point: (0..14).map(|value| symbol(value + 1)).collect(),
                affine_scale: Fp2::ONE,
                auth_domain: 97,
            }],
            ordered_h_symbols: vec![symbol(200)],
            fold_frames: vec![FoldCommitmentFrame {
                cohort_id: 9,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: 0,
                input_log2: 18,
                output_log2: 17,
                root_digest: [0x77; 32],
                ordered_message_symbols: vec![symbol(201)],
            }],
            query_frames: vec![CohortMultiproofFrame {
                cohort_id: 9,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: 0,
                outer_indices: vec![3],
                touched_slots: vec![0],
                opened_leaves: vec![outer_leaf(3), inner_leaf(descriptor_digest, 3, 0)],
                aux_nodes: vec![],
            }],
            m9_frames: vec![M9TransferFrame {
                descriptor_digest,
                mask_correction_symbol: symbol(202),
            }],
            zero_batch_frame: ResponseZeroBatchFrame {
                claim_count: 1,
                mask_correction_symbol: symbol(203),
                opened_tag_symbol: symbol(204),
            },
        }
    }

    fn assert_roundtrip(frame: Frame) {
        let encoded = frame.encode().unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn all_frame_kinds_are_canonical_roundtrips() {
        let descriptor0 = descriptor(0, 2);
        let descriptor1 = descriptor(1, 2);
        let digest0 = hash_descriptor(&descriptor0).unwrap();
        let digest1 = hash_descriptor(&descriptor1).unwrap();
        let leaf = inner_leaf(digest0, 3, 0);
        let node = PcsNodeFrame {
            cohort_id: 9,
            tree_role: TreeRole::Inner,
            oracle_kind: OracleKind::WeightExtension,
            fold_round: 0,
            outer_index: 3,
            level: 1,
            node_index: 0,
            left_digest: [1; 32],
            right_digest: [2; 32],
        };
        let manifest_leaf =
            ManifestLeafFrame { descriptor_digest: digest0, ordered_roots: vec![[3; 32], [4; 32]] };
        let manifest_node = ManifestNodeFrame {
            manifest_id_digest: [5; 32],
            level: 1,
            node_index: 0,
            left_digest: [6; 32],
            right_digest: [7; 32],
        };
        let claim = ReducedClaimFrame {
            descriptor_digest: digest0,
            parent_claim_digest: [8; 32],
            phase: Phase::Decode,
            phase_ordinal: 2,
            point: vec![Fp2::ZERO; 14],
            affine_scale: Fp2::ONE,
            auth_domain: 99,
        };
        let fold = FoldCommitmentFrame {
            cohort_id: 9,
            oracle_kind: OracleKind::Auxiliary,
            fold_round: 1,
            input_log2: 18,
            output_log2: 17,
            root_digest: [9; 32],
            ordered_message_symbols: vec![symbol(9)],
        };
        let m9 = M9TransferFrame { descriptor_digest: digest0, mask_correction_symbol: symbol(10) };
        let zero = ResponseZeroBatchFrame {
            claim_count: 2,
            mask_correction_symbol: symbol(11),
            opened_tag_symbol: symbol(12),
        };

        for frame in [
            Frame::Descriptor(descriptor0.clone()),
            Frame::PcsLeaf(leaf),
            Frame::PcsLeaf(outer_leaf(3)),
            Frame::PcsNode(node),
            Frame::ManifestLeaf(manifest_leaf),
            Frame::ManifestNode(manifest_node),
            Frame::CohortMultiproof(multiproof(&[digest0, digest1])),
            Frame::ReducedClaim(claim),
            Frame::FoldCommitment(fold),
            Frame::M9Transfer(m9),
            Frame::ResponseZeroBatch(zero),
            Frame::ResponseEnvelope(response(&descriptor0)),
        ] {
            assert_roundtrip(frame);
        }
    }

    #[test]
    fn header_and_canonical_field_tampers_are_rejected() {
        let frame = Frame::M9Transfer(M9TransferFrame {
            descriptor_digest: [1; 32],
            mask_correction_symbol: symbol(7),
        });
        let bytes = frame.encode().unwrap();

        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert_eq!(decode(&bad), Err(FrameError::BadMagic));

        let mut bad = bytes.clone();
        bad[8..10].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(decode(&bad), Err(FrameError::BadSchema(3)));

        let mut bad = bytes.clone();
        bad[10] = 0xff;
        assert_eq!(decode(&bad), Err(FrameError::UnknownKind(0xff)));

        let mut bad = bytes.clone();
        bad[11] = 1;
        assert_eq!(decode(&bad), Err(FrameError::NonZeroFlags(1)));

        let mut bad = bytes.clone();
        bad[12..16].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode(&bad), Err(FrameError::LengthMismatch));

        let mut bad = bytes.clone();
        bad.push(0);
        assert_eq!(decode(&bad), Err(FrameError::LengthMismatch));

        assert_eq!(decode(&bytes[..bytes.len() - 1]), Err(FrameError::LengthMismatch));

        let mut bad = bytes;
        bad[HEADER_LEN + 32..HEADER_LEN + 40].copy_from_slice(&P.to_le_bytes());
        assert_eq!(decode(&bad), Err(FrameError::NonCanonicalField));
    }

    #[test]
    fn enum_boolean_order_and_duplicate_tampers_are_rejected() {
        let mut descriptor_bytes = Frame::Descriptor(descriptor(0, 1)).encode().unwrap();
        descriptor_bytes[HEADER_LEN + 96] = 2;
        assert_eq!(
            decode(&descriptor_bytes),
            Err(FrameError::UnknownEnum { field: "namespace_kind", value: 2 })
        );

        let digest = hash_descriptor(&descriptor(0, 1)).unwrap();
        let mut leaf_bytes = Frame::PcsLeaf(inner_leaf(digest, 3, 0)).encode().unwrap();
        leaf_bytes[HEADER_LEN + 49] = 2;
        assert_eq!(decode(&leaf_bytes), Err(FrameError::InvalidBool(2)));

        let mut proof = multiproof(&[digest]);
        proof.outer_indices = vec![7, 3];
        assert_eq!(
            Frame::CohortMultiproof(proof).encode(),
            Err(FrameError::UnsortedOrDuplicate("multiproof outer indices"))
        );

        let mut envelope = response(&descriptor(0, 1));
        envelope.descriptor_digests.push(envelope.descriptor_digests[0]);
        assert_eq!(
            Frame::ResponseEnvelope(envelope).encode(),
            Err(FrameError::UnsortedOrDuplicate("response descriptors"))
        );
    }

    #[test]
    fn nested_kind_substitution_is_rejected() {
        let descriptor = descriptor(0, 1);
        let mut bytes = Frame::ResponseEnvelope(response(&descriptor)).encode().unwrap();
        // Response fixed prefix through manifest_frame_count: 110 body bytes.
        let manifest_start = HEADER_LEN + 110;
        assert_eq!(bytes[manifest_start + 10], FrameKind::ManifestLeaf as u8);
        bytes[manifest_start + 10] = FrameKind::ReducedClaim as u8;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn descriptor_geometry_and_split_identity_are_strict() {
        let base = descriptor(0, 1);
        assert!(base.validate().is_ok());

        let mut bad = base.clone();
        bad.ell = 14;
        assert_eq!(bad.validate(), Err(FrameError::Invalid("descriptor ell")));

        let mut bad = base.clone();
        bad.logical_coeffs -= 1;
        assert_eq!(bad.validate(), Err(FrameError::Invalid("descriptor axis geometry")));

        let mut split = base;
        split.namespace_kind = NamespaceKind::Global;
        split.namespace_index = 255;
        split.block_kind = BlockKind::EmbeddingHalf;
        split.split_prefix = 1;
        assert!(split.validate().is_ok());
        split.split_prefix = 255;
        assert_eq!(split.validate(), Err(FrameError::Invalid("split block identity")));
    }

    #[test]
    fn v2_hash_domains_are_separated_and_inputs_are_pinned() {
        let descriptor = descriptor(0, 1);
        let descriptor_hash = hash_descriptor(&descriptor).unwrap();
        let leaf = inner_leaf(descriptor_hash, 3, 0);
        let leaf_hash = hash_pcs_leaf(&leaf).unwrap();
        assert_ne!(descriptor_hash, leaf_hash);
        assert_eq!(profile_digest(), *blake3::hash(b"x4-zkdeepfold-ud-e29-v2").as_bytes());

        let ids = [7, 11, 19];
        assert_eq!(transfer_template_digest(&ids), transfer_template_digest(&ids));
        assert_eq!(
            transfer_template_digest(&[7, 7]),
            Err(FrameError::UnsortedOrDuplicate("transfer domain ids"))
        );
        assert_ne!(
            manifest_id_digest([1; 32], [2; 32], 3),
            manifest_id_digest([1; 32], [2; 32], 4)
        );
    }
}
