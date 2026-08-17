//! Canonical C6.2 seven-component proof envelope.
//!
//! C6.2 carries the residual coordinate-one prover message because no
//! interactive challenge tape exists. All other component allocations match
//! the strict hidden-free C6.1 proof.

use std::fmt;

use crate::{
    C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES, C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES,
    C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES, C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES,
    C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES, C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
    C6_T1_TOTAL_PRODUCT_CLOSURES,
};

pub const C62_RESPONSE_PROOF_ENVELOPE_MAGIC: [u8; 8] = *b"C62PIF1\0";
pub const C62_RESPONSE_PROOF_ENVELOPE_VERSION: u16 = 1;
pub const C62_RESPONSE_PROOF_COMPONENTS: usize = 7;
pub const C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES: u64 =
    C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES;
pub const C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES: u64 = C6_T1_TOTAL_PRODUCT_CLOSURES * 32;
pub const C62_RESPONSE_RESIDUAL_PENDING_BYTES: u64 = C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES;
pub const C62_RESPONSE_CACHE_SOURCE_BYTES: u64 = C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES;
pub const C62_RESPONSE_CACHE_BLIND_MAX_BYTES: u64 = C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES;
pub const C62_RESPONSE_CACHE_FOLD_TARGET_BYTES: u64 = C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES;
pub const C62_RESPONSE_AUTHENTICATED_LINK_BYTES: u64 = C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES;

const ENVELOPE_HEADER_BYTES: u64 = 8 + 2 + 2;
const COMPONENT_HEADER_BYTES: u64 = 2 + 2 + 4 + 32;
const ENVELOPE_DIGEST_BYTES: u64 = 32;
pub const C62_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES: u64 = ENVELOPE_HEADER_BYTES
    + C62_RESPONSE_PROOF_COMPONENTS as u64 * COMPONENT_HEADER_BYTES
    + ENVELOPE_DIGEST_BYTES;
pub const C62_RESPONSE_PROOF_ENVELOPE_MAX_BYTES: u64 = C62_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES
    + C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
    + C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES
    + C62_RESPONSE_RESIDUAL_PENDING_BYTES
    + C62_RESPONSE_CACHE_SOURCE_BYTES
    + C62_RESPONSE_CACHE_BLIND_MAX_BYTES
    + C62_RESPONSE_CACHE_FOLD_TARGET_BYTES
    + C62_RESPONSE_AUTHENTICATED_LINK_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C62ResponseProofEnvelopeError(String);

impl C62ResponseProofEnvelopeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C62ResponseProofEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C62ResponseProofEnvelopeError {}

type Result<T> = std::result::Result<T, C62ResponseProofEnvelopeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum ComponentKind {
    ResidualSumcheck = 1,
    ProductCoordinateOne = 2,
    ResidualPendingCorrections = 3,
    CacheSourceBootstrap = 4,
    CacheBlind = 5,
    CacheFoldTargets = 6,
    AuthenticatedOutputLink = 7,
}

impl ComponentKind {
    const ORDERED: [Self; C62_RESPONSE_PROOF_COMPONENTS] = [
        Self::ResidualSumcheck,
        Self::ProductCoordinateOne,
        Self::ResidualPendingCorrections,
        Self::CacheSourceBootstrap,
        Self::CacheBlind,
        Self::CacheFoldTargets,
        Self::AuthenticatedOutputLink,
    ];

    fn max_bytes(self) -> u64 {
        match self {
            Self::ResidualSumcheck => C62_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
            Self::ProductCoordinateOne => C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES,
            Self::ResidualPendingCorrections => C62_RESPONSE_RESIDUAL_PENDING_BYTES,
            Self::CacheSourceBootstrap => C62_RESPONSE_CACHE_SOURCE_BYTES,
            Self::CacheBlind => C62_RESPONSE_CACHE_BLIND_MAX_BYTES,
            Self::CacheFoldTargets => C62_RESPONSE_CACHE_FOLD_TARGET_BYTES,
            Self::AuthenticatedOutputLink => C62_RESPONSE_AUTHENTICATED_LINK_BYTES,
        }
    }

    fn requires_exact_size(self) -> bool {
        !matches!(self, Self::ResidualSumcheck | Self::CacheBlind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C62ResponseProofEnvelope {
    residual_sumcheck: Vec<u8>,
    product_coordinate_one: Vec<u8>,
    residual_pending_corrections: Vec<u8>,
    cache_source_bootstrap: Vec<u8>,
    cache_blind: Vec<u8>,
    cache_fold_targets: Vec<u8>,
    authenticated_output_link: Vec<u8>,
}

impl C62ResponseProofEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        residual_sumcheck: Vec<u8>,
        product_coordinate_one: Vec<u8>,
        residual_pending_corrections: Vec<u8>,
        cache_source_bootstrap: Vec<u8>,
        cache_blind: Vec<u8>,
        cache_fold_targets: Vec<u8>,
        authenticated_output_link: Vec<u8>,
    ) -> Result<Self> {
        let envelope = Self {
            residual_sumcheck,
            product_coordinate_one,
            residual_pending_corrections,
            cache_source_bootstrap,
            cache_blind,
            cache_fold_targets,
            authenticated_output_link,
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

    pub fn cache_source_bootstrap(&self) -> &[u8] {
        &self.cache_source_bootstrap
    }

    pub fn cache_blind(&self) -> &[u8] {
        &self.cache_blind
    }

    pub fn cache_fold_targets(&self) -> &[u8] {
        &self.cache_fold_targets
    }

    pub fn authenticated_output_link(&self) -> &[u8] {
        &self.authenticated_output_link
    }

    pub fn encoded_len(&self) -> Result<u64> {
        self.validate()?;
        self.encoded_len_unchecked()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let encoded_len = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(encoded_len)
                .map_err(|_| C62ResponseProofEnvelopeError::new("C62PIF1 exceeds usize"))?,
        );
        bytes.extend_from_slice(&C62_RESPONSE_PROOF_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&C62_RESPONSE_PROOF_ENVELOPE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C62_RESPONSE_PROOF_COMPONENTS as u16).to_le_bytes());
        for (kind, payload) in self.components() {
            bytes.extend_from_slice(&(kind as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| {
                        C62ResponseProofEnvelopeError::new("C62PIF1 component exceeds u32")
                    })?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&component_digest(kind, payload));
            bytes.extend_from_slice(payload);
        }
        bytes.extend_from_slice(&envelope_digest(&bytes));
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C62_RESPONSE_PROOF_ENVELOPE_MAX_BYTES {
            return Err(C62ResponseProofEnvelopeError::new("C62PIF1 exceeds its cap"));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C62_RESPONSE_PROOF_ENVELOPE_MAGIC
            || cursor.u16()? != C62_RESPONSE_PROOF_ENVELOPE_VERSION
            || usize::from(cursor.u16()?) != C62_RESPONSE_PROOF_COMPONENTS
        {
            return Err(C62ResponseProofEnvelopeError::new(
                "C62PIF1 header, version, or census mismatch",
            ));
        }
        let mut components = Vec::with_capacity(C62_RESPONSE_PROOF_COMPONENTS);
        for expected in ComponentKind::ORDERED {
            if cursor.u16()? != expected as u16 || cursor.u16()? != 0 {
                return Err(C62ResponseProofEnvelopeError::new(
                    "C62PIF1 component kind, order, or reserved field differs",
                ));
            }
            let len = usize::try_from(cursor.u32()?)
                .map_err(|_| C62ResponseProofEnvelopeError::new("C62PIF1 length exceeds usize"))?;
            validate_component_len(expected, len)?;
            let claimed = cursor.digest()?;
            let payload = cursor.take(len)?.to_vec();
            if claimed != component_digest(expected, &payload) {
                return Err(C62ResponseProofEnvelopeError::new(
                    "C62PIF1 component digest mismatch",
                ));
            }
            components.push(payload);
        }
        let digest_offset = cursor.offset;
        if cursor.digest()? != envelope_digest(&bytes[..digest_offset]) {
            return Err(C62ResponseProofEnvelopeError::new("C62PIF1 outer digest mismatch"));
        }
        cursor.finish()?;
        let mut components = components.into_iter();
        let envelope = Self::new(
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
        )?;
        if components.next().is_some() || envelope.encode()?.as_slice() != bytes {
            return Err(C62ResponseProofEnvelopeError::new("noncanonical C62PIF1 encoding"));
        }
        Ok(envelope)
    }

    fn components(&self) -> [(ComponentKind, &[u8]); C62_RESPONSE_PROOF_COMPONENTS] {
        [
            (ComponentKind::ResidualSumcheck, &self.residual_sumcheck),
            (ComponentKind::ProductCoordinateOne, &self.product_coordinate_one),
            (ComponentKind::ResidualPendingCorrections, &self.residual_pending_corrections),
            (ComponentKind::CacheSourceBootstrap, &self.cache_source_bootstrap),
            (ComponentKind::CacheBlind, &self.cache_blind),
            (ComponentKind::CacheFoldTargets, &self.cache_fold_targets),
            (ComponentKind::AuthenticatedOutputLink, &self.authenticated_output_link),
        ]
    }

    fn validate(&self) -> Result<()> {
        for (kind, payload) in self.components() {
            validate_component_len(kind, payload.len())?;
        }
        if self.encoded_len_unchecked()? > C62_RESPONSE_PROOF_ENVELOPE_MAX_BYTES {
            return Err(C62ResponseProofEnvelopeError::new("C62PIF1 exceeds its cap"));
        }
        Ok(())
    }

    fn encoded_len_unchecked(&self) -> Result<u64> {
        self.components().iter().try_fold(
            C62_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
            |total, (_, payload)| {
                total
                    .checked_add(payload.len() as u64)
                    .ok_or_else(|| C62ResponseProofEnvelopeError::new("C62PIF1 length overflows"))
            },
        )
    }
}

fn validate_component_len(kind: ComponentKind, len: usize) -> Result<()> {
    let len = len as u64;
    if len == 0 || len > kind.max_bytes() || (kind.requires_exact_size() && len != kind.max_bytes())
    {
        return Err(C62ResponseProofEnvelopeError::new(format!(
            "C62PIF1 {kind:?} component length violates its allocation"
        )));
    }
    Ok(())
}

fn component_digest(kind: ComponentKind, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/proof-component/v1");
    hasher.update(&(kind as u16).to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn envelope_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.2/proof-envelope/v1");
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
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
            .ok_or_else(|| C62ResponseProofEnvelopeError::new("C62PIF1 cursor overflows"))?;
        if end > self.bytes.len() {
            return Err(C62ResponseProofEnvelopeError::new("truncated C62PIF1"));
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }

    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C62ResponseProofEnvelopeError::new("trailing bytes in C62PIF1"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::C61NativeResponseProofEnvelope;

    fn fixture() -> C62ResponseProofEnvelope {
        C62ResponseProofEnvelope::new(
            vec![1; 64],
            vec![2; C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES as usize],
            vec![3; C62_RESPONSE_RESIDUAL_PENDING_BYTES as usize],
            vec![4; C62_RESPONSE_CACHE_SOURCE_BYTES as usize],
            vec![5; 96],
            vec![6; C62_RESPONSE_CACHE_FOLD_TARGET_BYTES as usize],
            vec![7; C62_RESPONSE_AUTHENTICATED_LINK_BYTES as usize],
        )
        .unwrap()
    }

    #[test]
    fn c62_pif1_round_trip_and_cross_version_are_strict() {
        let envelope = fixture();
        let bytes = envelope.encode().unwrap();
        assert_eq!(bytes.len() as u64, envelope.encoded_len().unwrap());
        assert_eq!(C62ResponseProofEnvelope::decode(&bytes).unwrap(), envelope);
        assert!(C61NativeResponseProofEnvelope::decode(&bytes).is_err());

        let c61 = C61NativeResponseProofEnvelope::new(
            envelope.residual_sumcheck().to_vec(),
            envelope.residual_pending_corrections().to_vec(),
            envelope.cache_source_bootstrap().to_vec(),
            envelope.cache_blind().to_vec(),
            envelope.cache_fold_targets().to_vec(),
            envelope.authenticated_output_link().to_vec(),
        )
        .unwrap()
        .encode()
        .unwrap();
        assert!(C62ResponseProofEnvelope::decode(&c61).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(C62ResponseProofEnvelope::decode(&trailing).is_err());
    }
}
