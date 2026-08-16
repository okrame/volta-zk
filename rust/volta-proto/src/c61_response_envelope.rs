//! Canonical hidden-free C6.1 `pi_final` response envelope.
//!
//! This is a closed six-component grammar. It is domain-separated from the
//! frozen C6 codec and has no compatibility or extension component.

use std::fmt;

pub const C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAGIC: [u8; 8] = *b"C61PIF2\0";
pub const C61_NATIVE_RESPONSE_PROOF_ENVELOPE_VERSION: u16 = 2;
pub const C61_NATIVE_RESPONSE_PROOF_COMPONENTS: usize = 6;

pub const C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES: u64 = 6_900;
pub const C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES: u64 = 1_536;
pub const C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES: u64 = 304;
pub const C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES: u64 = 3_506;
pub const C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES: u64 = 18_480;
pub const C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES: u64 = 3_431_752;

const COMPONENT_HEADER_BYTES: u64 = 2 + 2 + 4 + 32;
const ENVELOPE_HEADER_BYTES: u64 = 8 + 2 + 2;
const ENVELOPE_DIGEST_BYTES: u64 = 32;
pub const C61_NATIVE_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES: u64 = ENVELOPE_HEADER_BYTES
    + C61_NATIVE_RESPONSE_PROOF_COMPONENTS as u64 * COMPONENT_HEADER_BYTES
    + ENVELOPE_DIGEST_BYTES;
pub const C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES: u64 =
    C61_NATIVE_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES
        + C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES
        + C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES
        + C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES
        + C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES
        + C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES
        + C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeResponseProofEnvelopeError(String);

impl C61NativeResponseProofEnvelopeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61NativeResponseProofEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61NativeResponseProofEnvelopeError {}

type Result<T> = std::result::Result<T, C61NativeResponseProofEnvelopeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum ComponentKind {
    ResidualSumcheck = 1,
    ResidualPendingCorrections = 2,
    CacheSourceBootstrap = 3,
    CacheBlind = 4,
    CacheFoldTargets = 5,
    AuthenticatedOutputLink = 6,
}

impl ComponentKind {
    const ORDERED: [Self; C61_NATIVE_RESPONSE_PROOF_COMPONENTS] = [
        Self::ResidualSumcheck,
        Self::ResidualPendingCorrections,
        Self::CacheSourceBootstrap,
        Self::CacheBlind,
        Self::CacheFoldTargets,
        Self::AuthenticatedOutputLink,
    ];

    fn max_bytes(self) -> u64 {
        match self {
            Self::ResidualSumcheck => C61_NATIVE_RESPONSE_RESIDUAL_SUMCHECK_MAX_BYTES,
            Self::ResidualPendingCorrections => C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES,
            Self::CacheSourceBootstrap => C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES,
            Self::CacheBlind => C61_NATIVE_RESPONSE_CACHE_BLIND_MAX_BYTES,
            Self::CacheFoldTargets => C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES,
            Self::AuthenticatedOutputLink => C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES,
        }
    }

    fn requires_exact_size(self) -> bool {
        matches!(
            self,
            Self::ResidualPendingCorrections
                | Self::CacheSourceBootstrap
                | Self::CacheFoldTargets
                | Self::AuthenticatedOutputLink
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeResponseProofEnvelope {
    residual_sumcheck: Vec<u8>,
    residual_pending_corrections: Vec<u8>,
    cache_source_bootstrap: Vec<u8>,
    cache_blind: Vec<u8>,
    cache_fold_targets: Vec<u8>,
    authenticated_output_link: Vec<u8>,
}

impl C61NativeResponseProofEnvelope {
    pub fn new(
        residual_sumcheck: Vec<u8>,
        residual_pending_corrections: Vec<u8>,
        cache_source_bootstrap: Vec<u8>,
        cache_blind: Vec<u8>,
        cache_fold_targets: Vec<u8>,
        authenticated_output_link: Vec<u8>,
    ) -> Result<Self> {
        let envelope = Self {
            residual_sumcheck,
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
        let mut bytes = Vec::with_capacity(usize::try_from(encoded_len).map_err(|_| {
            C61NativeResponseProofEnvelopeError::new("C6.1 envelope exceeds usize")
        })?);
        bytes.extend_from_slice(&C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&C61_NATIVE_RESPONSE_PROOF_ENVELOPE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(C61_NATIVE_RESPONSE_PROOF_COMPONENTS as u16).to_le_bytes());
        for (kind, payload) in self.components() {
            bytes.extend_from_slice(&(kind as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| {
                        C61NativeResponseProofEnvelopeError::new(
                            "C6.1 component length exceeds u32",
                        )
                    })?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&component_digest(kind, payload));
            bytes.extend_from_slice(payload);
        }
        let digest = envelope_digest(&bytes);
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len() as u64, encoded_len);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES {
            return Err(C61NativeResponseProofEnvelopeError::new(
                "C6.1 proof envelope exceeds its cap",
            ));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAGIC
            || cursor.u16()? != C61_NATIVE_RESPONSE_PROOF_ENVELOPE_VERSION
            || usize::from(cursor.u16()?) != C61_NATIVE_RESPONSE_PROOF_COMPONENTS
        {
            return Err(C61NativeResponseProofEnvelopeError::new(
                "C6.1 proof envelope header/version/census mismatch",
            ));
        }

        let mut components = Vec::with_capacity(C61_NATIVE_RESPONSE_PROOF_COMPONENTS);
        for expected_kind in ComponentKind::ORDERED {
            let kind = cursor.u16()?;
            let reserved = cursor.u16()?;
            if kind != expected_kind as u16 || reserved != 0 {
                return Err(C61NativeResponseProofEnvelopeError::new(
                    "C6.1 proof component kind/order/reserved mismatch",
                ));
            }
            let len = usize::try_from(cursor.u32()?).map_err(|_| {
                C61NativeResponseProofEnvelopeError::new("C6.1 component exceeds usize")
            })?;
            validate_component_len(expected_kind, len)?;
            let claimed_digest = cursor.digest()?;
            let payload = cursor.take(len)?.to_vec();
            if claimed_digest != component_digest(expected_kind, &payload) {
                return Err(C61NativeResponseProofEnvelopeError::new(
                    "C6.1 proof component digest mismatch",
                ));
            }
            components.push(payload);
        }

        let digest_offset = cursor.offset;
        let claimed_digest = cursor.digest()?;
        if claimed_digest != envelope_digest(&bytes[..digest_offset]) {
            return Err(C61NativeResponseProofEnvelopeError::new(
                "C6.1 proof envelope digest mismatch",
            ));
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
        )?;
        if components.next().is_some() || envelope.encode()?.as_slice() != bytes {
            return Err(C61NativeResponseProofEnvelopeError::new(
                "noncanonical C6.1 proof envelope encoding",
            ));
        }
        Ok(envelope)
    }

    fn components(&self) -> [(ComponentKind, &[u8]); C61_NATIVE_RESPONSE_PROOF_COMPONENTS] {
        [
            (ComponentKind::ResidualSumcheck, &self.residual_sumcheck),
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
        if self.encoded_len_unchecked()? > C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES {
            return Err(C61NativeResponseProofEnvelopeError::new(
                "C6.1 proof envelope exceeds its cap",
            ));
        }
        Ok(())
    }

    fn encoded_len_unchecked(&self) -> Result<u64> {
        self.components().iter().try_fold(
            C61_NATIVE_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES,
            |total, (_, bytes)| {
                total.checked_add(bytes.len() as u64).ok_or_else(|| {
                    C61NativeResponseProofEnvelopeError::new("C6.1 envelope length overflow")
                })
            },
        )
    }
}

fn validate_component_len(kind: ComponentKind, len: usize) -> Result<()> {
    let len = len as u64;
    if len == 0 || len > kind.max_bytes() || (kind.requires_exact_size() && len != kind.max_bytes())
    {
        return Err(C61NativeResponseProofEnvelopeError::new(format!(
            "C6.1 {kind:?} component length violates its allocation"
        )));
    }
    Ok(())
}

fn component_digest(kind: ComponentKind, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/native-proof-component/v2");
    hasher.update(&(kind as u16).to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn envelope_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c6.1/native-proof-envelope/v2");
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
        let end = self.offset.checked_add(len).ok_or_else(|| {
            C61NativeResponseProofEnvelopeError::new("C6.1 envelope cursor overflow")
        })?;
        if end > self.bytes.len() {
            return Err(C61NativeResponseProofEnvelopeError::new("truncated C6.1 proof envelope"));
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
            return Err(C61NativeResponseProofEnvelopeError::new(
                "trailing bytes in C6.1 proof envelope",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> C61NativeResponseProofEnvelope {
        C61NativeResponseProofEnvelope::new(
            vec![1; 64],
            vec![2; C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES as usize],
            vec![3; C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES as usize],
            vec![4; 96],
            vec![5; C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES as usize],
            vec![6; C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES as usize],
        )
        .unwrap()
    }

    fn rewrite_outer_digest(bytes: &mut [u8]) {
        let digest_offset = bytes.len() - ENVELOPE_DIGEST_BYTES as usize;
        let digest = envelope_digest(&bytes[..digest_offset]);
        bytes[digest_offset..].copy_from_slice(&digest);
    }

    fn component_offsets(bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut cursor = ENVELOPE_HEADER_BYTES as usize;
        let mut offsets = Vec::new();
        for _ in 0..C61_NATIVE_RESPONSE_PROOF_COMPONENTS {
            let len =
                u32::from_le_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
            offsets.push((cursor, cursor + COMPONENT_HEADER_BYTES as usize));
            cursor += COMPONENT_HEADER_BYTES as usize + len;
        }
        offsets
    }

    #[test]
    fn exact_six_component_roofline_and_round_trip_are_stable() {
        assert_eq!(C61_NATIVE_RESPONSE_PROOF_ENVELOPE_OVERHEAD_BYTES, 284);
        assert_eq!(C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES, 3_462_762);
        let envelope = fixture();
        let bytes = envelope.encode().unwrap();
        assert_eq!(C61NativeResponseProofEnvelope::decode(&bytes).unwrap(), envelope);
        assert_eq!(envelope.authenticated_output_link().len() as u64, 3_431_752);
    }

    #[test]
    fn every_header_payload_digest_and_old_magic_fail_closed() {
        let bytes = fixture().encode().unwrap();
        let offsets = component_offsets(&bytes);
        for (header, payload) in offsets {
            for position in [header, header + 2, header + 4, header + 8, payload] {
                let mut changed = bytes.clone();
                changed[position] ^= 1;
                rewrite_outer_digest(&mut changed);
                assert!(C61NativeResponseProofEnvelope::decode(&changed).is_err());
            }
        }
        let mut old_magic = bytes.clone();
        old_magic[..8].copy_from_slice(b"C6PIF1\0\0");
        rewrite_outer_digest(&mut old_magic);
        assert!(C61NativeResponseProofEnvelope::decode(&old_magic).is_err());

        let mut outer_digest = bytes.clone();
        *outer_digest.last_mut().unwrap() ^= 1;
        assert!(C61NativeResponseProofEnvelope::decode(&outer_digest).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(C61NativeResponseProofEnvelope::decode(&trailing).is_err());
    }
}
