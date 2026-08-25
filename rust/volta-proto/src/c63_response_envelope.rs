//! Canonical C6.3 designated tail.
//!
//! Cache-source, cache-blind and cache-fold components are absent. The final
//! component is one fixed-layout designated bundle: source-functional
//! corrections, reduced output link, sparse-H closure, then four terminal tags.

use std::fmt;

use crate::{
    C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES, C62_RESPONSE_RESIDUAL_PENDING_BYTES,
    C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
};

pub const C63_RESPONSE_PROOF_ENVELOPE_MAGIC: [u8; 8] = *b"C63PIF2\0";
pub const C63_RESPONSE_PROOF_ENVELOPE_VERSION: u16 = 2;
pub const C63_RESPONSE_PROOF_COMPONENTS: usize = 4;
pub const C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES: u64 = 64;
pub const C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES: u64 = 2_672_044;
pub const C63_RESPONSE_SPARSE_H_CLOSURE_BYTES: u64 = 1_496;
pub const C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES: u64 = 64;
pub const C63_RESPONSE_AUTHENTICATED_SKETCH_LINK_BYTES: u64 =
    C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES
        + C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES
        + C63_RESPONSE_SPARSE_H_CLOSURE_BYTES
        + C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES;

const ENVELOPE_HEADER_BYTES: u64 = 12;
const COMPONENT_HEADER_BYTES: u64 = 40;
const ENVELOPE_DIGEST_BYTES: u64 = 32;
pub const C63_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES: u64 = ENVELOPE_HEADER_BYTES
    + C63_RESPONSE_PROOF_COMPONENTS as u64 * COMPONENT_HEADER_BYTES
    + ENVELOPE_DIGEST_BYTES;
pub const C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES: u64 = C63_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES
    + C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
    + C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES
    + C62_RESPONSE_RESIDUAL_PENDING_BYTES
    + C63_RESPONSE_AUTHENTICATED_SKETCH_LINK_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63ResponseProofEnvelopeError(String);

impl C63ResponseProofEnvelopeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C63ResponseProofEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C63ResponseProofEnvelopeError {}

type Result<T> = std::result::Result<T, C63ResponseProofEnvelopeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum ComponentKind {
    ResidualSumcheck = 1,
    ProductCoordinateOne = 2,
    ResidualPendingCorrections = 3,
    AuthenticatedSketchLink = 4,
}

impl ComponentKind {
    const ORDERED: [Self; C63_RESPONSE_PROOF_COMPONENTS] = [
        Self::ResidualSumcheck,
        Self::ProductCoordinateOne,
        Self::ResidualPendingCorrections,
        Self::AuthenticatedSketchLink,
    ];

    fn max_bytes(self) -> u64 {
        match self {
            Self::ResidualSumcheck => C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
            Self::ProductCoordinateOne => C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES,
            Self::ResidualPendingCorrections => C62_RESPONSE_RESIDUAL_PENDING_BYTES,
            Self::AuthenticatedSketchLink => C63_RESPONSE_AUTHENTICATED_SKETCH_LINK_BYTES,
        }
    }

    fn exact(self) -> bool {
        !matches!(self, Self::ResidualSumcheck)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63ResponseProofEnvelope {
    residual_sumcheck: Vec<u8>,
    product_coordinate_one: Vec<u8>,
    residual_pending_corrections: Vec<u8>,
    source_functional_corrections: Vec<u8>,
    authenticated_output_link: Vec<u8>,
    sparse_h_closure: Vec<u8>,
    whir_terminal_tags: Vec<u8>,
}

impl C63ResponseProofEnvelope {
    pub fn new(
        residual_sumcheck: Vec<u8>,
        product_coordinate_one: Vec<u8>,
        residual_pending_corrections: Vec<u8>,
        source_functional_corrections: Vec<u8>,
        authenticated_output_link: Vec<u8>,
        sparse_h_closure: Vec<u8>,
        whir_terminal_tags: Vec<u8>,
    ) -> Result<Self> {
        let envelope = Self {
            residual_sumcheck,
            product_coordinate_one,
            residual_pending_corrections,
            source_functional_corrections,
            authenticated_output_link,
            sparse_h_closure,
            whir_terminal_tags,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn residual_sumcheck(&self) -> &[u8] {
        &self.residual_sumcheck
    }

    pub fn product_coordinate_one(&self) -> &[u8] {
        &self.product_coordinate_one
    }

    pub fn residual_pending_corrections(&self) -> &[u8] {
        &self.residual_pending_corrections
    }

    pub fn authenticated_output_link(&self) -> &[u8] {
        &self.authenticated_output_link
    }

    pub fn source_functional_corrections(&self) -> &[u8] {
        &self.source_functional_corrections
    }

    pub fn sparse_h_closure(&self) -> &[u8] {
        &self.sparse_h_closure
    }

    pub fn whir_terminal_tags(&self) -> &[u8] {
        &self.whir_terminal_tags
    }

    pub fn encoded_len(&self) -> Result<u64> {
        self.validate()?;
        self.encoded_len_unchecked()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len()? as usize);
        bytes.extend_from_slice(&C63_RESPONSE_PROOF_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&C63_RESPONSE_PROOF_ENVELOPE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C63_RESPONSE_PROOF_COMPONENTS as u16).to_le_bytes());
        for (kind, payload) in self.components() {
            bytes.extend_from_slice(&(kind as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&component_digest(kind, &payload));
            bytes.extend_from_slice(&payload);
        }
        bytes.extend_from_slice(&envelope_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES {
            return Err(C63ResponseProofEnvelopeError::new("C63PIF2 exceeds its cap"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C63_RESPONSE_PROOF_ENVELOPE_MAGIC
            || cursor.u16()? != C63_RESPONSE_PROOF_ENVELOPE_VERSION
            || usize::from(cursor.u16()?) != C63_RESPONSE_PROOF_COMPONENTS
        {
            return Err(C63ResponseProofEnvelopeError::new(
                "C63PIF2 header, version or component census differs",
            ));
        }
        let mut components = Vec::with_capacity(C63_RESPONSE_PROOF_COMPONENTS);
        for expected in ComponentKind::ORDERED {
            if cursor.u16()? != expected as u16 || cursor.u16()? != 0 {
                return Err(C63ResponseProofEnvelopeError::new(
                    "C63PIF2 component kind, order or reserved field differs",
                ));
            }
            let len = cursor.u32()? as usize;
            validate_component_len(expected, len)?;
            let digest = cursor.digest()?;
            let payload = cursor.take(len)?.to_vec();
            if digest != component_digest(expected, &payload) {
                return Err(C63ResponseProofEnvelopeError::new("C63PIF2 component digest differs"));
            }
            components.push(payload);
        }
        let digest_offset = cursor.offset;
        if cursor.digest()? != envelope_digest(&bytes[..digest_offset]) {
            return Err(C63ResponseProofEnvelopeError::new("C63PIF2 digest differs"));
        }
        cursor.finish()?;

        let mut components = components.into_iter();
        let residual_sumcheck = components.next().expect("fixed component census");
        let product_coordinate_one = components.next().expect("fixed component census");
        let residual_pending_corrections = components.next().expect("fixed component census");
        let linked = components.next().expect("fixed component census");
        let source_end = C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES as usize;
        let output_end = source_end + C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES as usize;
        let sparse_end = output_end + C63_RESPONSE_SPARSE_H_CLOSURE_BYTES as usize;
        let envelope = Self::new(
            residual_sumcheck,
            product_coordinate_one,
            residual_pending_corrections,
            linked[..source_end].to_vec(),
            linked[source_end..output_end].to_vec(),
            linked[output_end..sparse_end].to_vec(),
            linked[sparse_end..].to_vec(),
        )?;
        if envelope.encode()?.as_slice() != bytes {
            return Err(C63ResponseProofEnvelopeError::new("noncanonical C63PIF2 encoding"));
        }
        Ok(envelope)
    }

    fn components(&self) -> [(ComponentKind, Vec<u8>); C63_RESPONSE_PROOF_COMPONENTS] {
        let mut linked = Vec::with_capacity(C63_RESPONSE_AUTHENTICATED_SKETCH_LINK_BYTES as usize);
        linked.extend_from_slice(&self.source_functional_corrections);
        linked.extend_from_slice(&self.authenticated_output_link);
        linked.extend_from_slice(&self.sparse_h_closure);
        linked.extend_from_slice(&self.whir_terminal_tags);
        [
            (ComponentKind::ResidualSumcheck, self.residual_sumcheck.clone()),
            (ComponentKind::ProductCoordinateOne, self.product_coordinate_one.clone()),
            (ComponentKind::ResidualPendingCorrections, self.residual_pending_corrections.clone()),
            (ComponentKind::AuthenticatedSketchLink, linked),
        ]
    }

    fn validate(&self) -> Result<()> {
        if self.source_functional_corrections.len() as u64
            != C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES
            || self.authenticated_output_link.len() as u64
                != C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES
            || self.sparse_h_closure.len() as u64 != C63_RESPONSE_SPARSE_H_CLOSURE_BYTES
            || self.whir_terminal_tags.len() as u64 != C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES
        {
            return Err(C63ResponseProofEnvelopeError::new(
                "C63PIF2 linked subcomponent length differs",
            ));
        }
        for (kind, payload) in self.components() {
            validate_component_len(kind, payload.len())?;
        }
        Ok(())
    }

    fn encoded_len_unchecked(&self) -> Result<u64> {
        self.components().iter().try_fold(
            C63_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
            |total, (_, payload)| {
                total
                    .checked_add(payload.len() as u64)
                    .ok_or_else(|| C63ResponseProofEnvelopeError::new("C63PIF2 length overflows"))
            },
        )
    }
}

fn validate_component_len(kind: ComponentKind, len: usize) -> Result<()> {
    let len = len as u64;
    if len > kind.max_bytes() || (kind.exact() && len != kind.max_bytes()) {
        return Err(C63ResponseProofEnvelopeError::new("C63PIF2 component length differs"));
    }
    Ok(())
}

fn component_digest(kind: ComponentKind, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/pi-final-component/v1");
    hasher.update(&(kind as u16).to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn envelope_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/pi-final-envelope/v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| C63ResponseProofEnvelopeError::new("C63PIF2 cursor overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C63ResponseProofEnvelopeError::new("truncated C63PIF2"))?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("digest width"))
    }

    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C63ResponseProofEnvelopeError::new("trailing C63PIF2 bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> C63ResponseProofEnvelope {
        C63ResponseProofEnvelope::new(
            vec![1; C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES as usize],
            vec![2; C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES as usize],
            vec![3; C62_RESPONSE_RESIDUAL_PENDING_BYTES as usize],
            vec![7; C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES as usize],
            vec![4; C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES as usize],
            vec![5; C63_RESPONSE_SPARSE_H_CLOSURE_BYTES as usize],
            vec![6; C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES as usize],
        )
        .unwrap()
    }

    #[test]
    fn c63_tail_is_exact_and_rejects_old_or_malformed_frames() {
        let envelope = fixture();
        let encoded = envelope.encode().unwrap();
        assert_eq!(encoded.len() as u64, C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES);
        assert_eq!(C63ResponseProofEnvelope::decode(&encoded).unwrap(), envelope);

        let mut mutation = encoded.clone();
        mutation[0] ^= 1;
        assert!(C63ResponseProofEnvelope::decode(&mutation).is_err());
        let mut mutation = encoded.clone();
        mutation[20] ^= 1;
        assert!(C63ResponseProofEnvelope::decode(&mutation).is_err());
        assert!(C63ResponseProofEnvelope::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(C63ResponseProofEnvelope::decode(&trailing).is_err());
    }
}
