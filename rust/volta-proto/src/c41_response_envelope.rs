//! Closed canonical envelope for the complete C4.1 response proof.

use crate::ProdProof;
use std::{fmt, io::Read};
use volta_field::{Fp, Fp2, P};
use volta_pcg::SessionBinding;

pub const C41_RESPONSE_ENVELOPE_MAGIC: [u8; 8] = *b"C41PRF1\0";
pub const C41_RESPONSE_ENVELOPE_VERSION: u16 = 1;
pub const C41_RESPONSE_ENVELOPE_MAX_BYTES: u64 = 70_000_000;
pub const C41_FIAT_SHAMIR_CONTEXT_VERSION: u16 = 1;
const COMPONENTS: usize = 4;
const HEADER_BYTES: u64 = 8 + 2 + 2;
const COMPONENT_HEADER_BYTES: u64 = 2 + 2 + 4 + 32;
const DIGEST_BYTES: u64 = 32;
const CLOSURE_BYTES: usize = 64;

/// Public attempt identity absorbed before the first C41FS1 move. Secret
/// verifier keys and `Delta` are intentionally absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41FiatShamirPublicContext {
    pub model_binding_digest: [u8; 32],
    pub setup_digest: [u8; 32],
    pub quantization_digest: [u8; 32],
    pub statement_digest: [u8; 32],
    pub connection_binding: [u8; 32],
    pub public_incidence_seed: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub response_index: u64,
    pub cells: u64,
}

impl C41FiatShamirPublicContext {
    pub fn digest(self) -> Result<[u8; 32]> {
        if [
            self.model_binding_digest,
            self.setup_digest,
            self.quantization_digest,
            self.statement_digest,
            self.connection_binding,
            self.public_incidence_seed,
            self.pcs_parameter_digest,
        ]
        .contains(&[0; 32])
            || self.cells == 0
        {
            return Err(C41ResponseEnvelopeError::new(
                "C41FS1 public context contains a zero identity or geometry",
            ));
        }
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c4.1/fiat-shamir/context/v1");
        hasher.update(&C41_FIAT_SHAMIR_CONTEXT_VERSION.to_le_bytes());
        hasher.update(&C41_RESPONSE_ENVELOPE_VERSION.to_le_bytes());
        hasher.update(&(COMPONENTS as u16).to_le_bytes());
        hasher.update(&C41_RESPONSE_ENVELOPE_MAX_BYTES.to_le_bytes());
        hasher.update(&self.response_index.to_le_bytes());
        hasher.update(&self.cells.to_le_bytes());
        for digest in [
            self.model_binding_digest,
            self.setup_digest,
            self.quantization_digest,
            self.statement_digest,
            self.connection_binding,
            self.public_incidence_seed,
            self.pcs_parameter_digest,
        ] {
            hasher.update(&digest);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    /// Existing durable PCG burn identity for this response index. The nonce
    /// deliberately excludes proof bytes: a failed proof still consumes the
    /// index, and changing the proof cannot make the index reusable.
    pub fn response_authorization_binding(self) -> Result<SessionBinding> {
        self.digest()?;
        let mut channel = blake3::Hasher::new_derive_key("volta-zk/c4.1/burn-channel/v1");
        channel.update(&self.connection_binding);
        let mut nonce = blake3::Hasher::new_derive_key("volta-zk/c4.1/burn-response-index/v1");
        nonce.update(&self.connection_binding);
        nonce.update(&self.response_index.to_le_bytes());
        SessionBinding::new(
            self.connection_binding,
            *channel.finalize().as_bytes(),
            *nonce.finalize().as_bytes(),
        )
        .map_err(|error| C41ResponseEnvelopeError::new(error.to_string()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41ResponseEnvelopeError(String);

impl C41ResponseEnvelopeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C41ResponseEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C41ResponseEnvelopeError {}

type Result<T> = std::result::Result<T, C41ResponseEnvelopeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum ComponentKind {
    Model = 1,
    WeightsPcs = 2,
    EmbedPcs = 3,
    Closure = 4,
}

impl ComponentKind {
    const ORDERED: [Self; COMPONENTS] =
        [Self::Model, Self::WeightsPcs, Self::EmbedPcs, Self::Closure];
}

#[derive(Debug, PartialEq, Eq)]
pub struct C41ResponseClosureProof {
    pub product: ProdProof,
    pub zero_mask_correction: Fp2,
    pub zero_batch_tag: Fp2,
}

impl C41ResponseClosureProof {
    pub fn encode(&self) -> [u8; CLOSURE_BYTES] {
        let mut bytes = [0u8; CLOSURE_BYTES];
        for (index, value) in
            [self.product.m0, self.product.m1, self.zero_mask_correction, self.zero_batch_tag]
                .into_iter()
                .enumerate()
        {
            let offset = index * 16;
            bytes[offset..offset + 8].copy_from_slice(&value.c0.value().to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&value.c1.value().to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CLOSURE_BYTES {
            return Err(C41ResponseEnvelopeError::new("C4.1 closure length differs"));
        }
        let mut values = Vec::with_capacity(4);
        for encoded in bytes.chunks_exact(16) {
            let c0 = u64::from_le_bytes(encoded[..8].try_into().expect("fixed field width"));
            let c1 = u64::from_le_bytes(encoded[8..].try_into().expect("fixed field width"));
            if c0 >= P || c1 >= P {
                return Err(C41ResponseEnvelopeError::new(
                    "noncanonical C4.1 closure field element",
                ));
            }
            values.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
        }
        Ok(Self {
            product: ProdProof { m0: values[0], m1: values[1] },
            zero_mask_correction: values[2],
            zero_batch_tag: values[3],
        })
    }
}

/// The inner model and PCS components retain their own strict codecs. This
/// type closes their order, lengths and integrity into one proof artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41ResponseProofEnvelope {
    model: Vec<u8>,
    weights_pcs: Vec<u8>,
    embed_pcs: Vec<u8>,
    closure: Vec<u8>,
}

impl C41ResponseProofEnvelope {
    pub fn new(
        model: Vec<u8>,
        weights_pcs: Vec<u8>,
        embed_pcs: Vec<u8>,
        closure: Vec<u8>,
    ) -> Result<Self> {
        let envelope = Self { model, weights_pcs, embed_pcs, closure };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn model(&self) -> &[u8] {
        &self.model
    }

    pub fn weights_pcs(&self) -> &[u8] {
        &self.weights_pcs
    }

    pub fn embed_pcs(&self) -> &[u8] {
        &self.embed_pcs
    }

    pub fn closure(&self) -> &[u8] {
        &self.closure
    }

    pub fn encoded_len(&self) -> Result<u64> {
        self.validate_components()?;
        self.components().iter().try_fold(
            HEADER_BYTES + COMPONENTS as u64 * COMPONENT_HEADER_BYTES + DIGEST_BYTES,
            |total, (_, payload)| {
                total
                    .checked_add(payload.len() as u64)
                    .ok_or_else(|| C41ResponseEnvelopeError::new("C4.1 envelope length overflow"))
            },
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let encoded_len = self.encoded_len()?;
        if encoded_len > C41_RESPONSE_ENVELOPE_MAX_BYTES {
            return Err(C41ResponseEnvelopeError::new("C4.1 proof exceeds 70 MB"));
        }
        let mut bytes = Vec::with_capacity(encoded_len as usize);
        bytes.extend_from_slice(&C41_RESPONSE_ENVELOPE_MAGIC);
        bytes.extend_from_slice(&C41_RESPONSE_ENVELOPE_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(COMPONENTS as u16).to_le_bytes());
        for (kind, payload) in self.components() {
            bytes.extend_from_slice(&(kind as u16).to_le_bytes());
            bytes.extend_from_slice(&0u16.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(payload.len())
                    .map_err(|_| C41ResponseEnvelopeError::new("C4.1 component exceeds u32"))?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(blake3::hash(payload).as_bytes());
            bytes.extend_from_slice(payload);
        }
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C41_RESPONSE_ENVELOPE_MAX_BYTES {
            return Err(C41ResponseEnvelopeError::new("C4.1 proof exceeds 70 MB"));
        }
        let mut input = Reader { bytes, offset: 0 };
        if input.take(8)? != C41_RESPONSE_ENVELOPE_MAGIC
            || input.u16()? != C41_RESPONSE_ENVELOPE_VERSION
            || usize::from(input.u16()?) != COMPONENTS
        {
            return Err(C41ResponseEnvelopeError::new(
                "C4.1 envelope header/version/census differs",
            ));
        }
        let mut components = Vec::with_capacity(COMPONENTS);
        for expected in ComponentKind::ORDERED {
            if input.u16()? != expected as u16 || input.u16()? != 0 {
                return Err(C41ResponseEnvelopeError::new(
                    "C4.1 component kind/order/reserved field differs",
                ));
            }
            let len = input.u32()? as usize;
            let digest: [u8; 32] = input.take(32)?.try_into().expect("fixed digest width");
            let payload = input.take(len)?.to_vec();
            if *blake3::hash(&payload).as_bytes() != digest {
                return Err(C41ResponseEnvelopeError::new("C4.1 component digest differs"));
            }
            components.push(payload);
        }
        let digest_offset = input.offset;
        let digest: [u8; 32] = input.take(32)?.try_into().expect("fixed digest width");
        if *blake3::hash(&bytes[..digest_offset]).as_bytes() != digest
            || input.offset != bytes.len()
        {
            return Err(C41ResponseEnvelopeError::new(
                "C4.1 envelope digest or trailing bytes differ",
            ));
        }
        let mut components = components.into_iter();
        let envelope = Self::new(
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
            components.next().expect("fixed component census"),
        )?;
        if components.next().is_some() || envelope.encode()?.as_slice() != bytes {
            return Err(C41ResponseEnvelopeError::new("noncanonical C4.1 response proof envelope"));
        }
        Ok(envelope)
    }

    /// Bounded verifier-side reader. It buffers at most cap+1 bytes, using the
    /// final byte only to reject an oversized artifact before canonical decode.
    pub fn decode_reader(reader: impl Read) -> Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take(C41_RESPONSE_ENVELOPE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| C41ResponseEnvelopeError::new(error.to_string()))?;
        if bytes.len() as u64 > C41_RESPONSE_ENVELOPE_MAX_BYTES {
            return Err(C41ResponseEnvelopeError::new("C4.1 proof exceeds 70 MB"));
        }
        Self::decode(&bytes)
    }

    fn components(&self) -> [(ComponentKind, &[u8]); COMPONENTS] {
        [
            (ComponentKind::Model, &self.model),
            (ComponentKind::WeightsPcs, &self.weights_pcs),
            (ComponentKind::EmbedPcs, &self.embed_pcs),
            (ComponentKind::Closure, &self.closure),
        ]
    }

    fn validate_components(&self) -> Result<()> {
        if self.model.is_empty()
            || self.weights_pcs.is_empty()
            || self.embed_pcs.is_empty()
            || self.closure.len() != CLOSURE_BYTES
        {
            return Err(C41ResponseEnvelopeError::new("C4.1 component length differs"));
        }
        C41ResponseClosureProof::decode(&self.closure)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        if self.encoded_len()? > C41_RESPONSE_ENVELOPE_MAX_BYTES {
            return Err(C41ResponseEnvelopeError::new("C4.1 proof exceeds 70 MB"));
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8]> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| C41ResponseEnvelopeError::new("truncated C4.1 proof envelope"))?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16 width")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed u32 width")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_pcg::ResponseAuthorizationStore;

    #[test]
    fn c41_response_envelope_and_closure_are_strict() {
        let closure = C41ResponseClosureProof {
            product: ProdProof { m0: Fp2::ONE, m1: Fp2::ZERO },
            zero_mask_correction: Fp2::ONE,
            zero_batch_tag: Fp2::ZERO,
        };
        let closure_bytes = closure.encode();
        assert_eq!(C41ResponseClosureProof::decode(&closure_bytes).unwrap(), closure);
        let envelope =
            C41ResponseProofEnvelope::new(vec![1, 2], vec![3], vec![4, 5], closure_bytes.to_vec())
                .unwrap();
        let bytes = envelope.encode().unwrap();
        assert_eq!(C41ResponseProofEnvelope::decode(&bytes).unwrap(), envelope);
        assert_eq!(
            C41ResponseProofEnvelope::decode_reader(std::io::Cursor::new(&bytes)).unwrap(),
            envelope
        );
        let mut tampered = bytes;
        tampered[52] ^= 1;
        assert!(C41ResponseProofEnvelope::decode(&tampered).is_err());
    }

    #[test]
    fn c41_fiat_shamir_context_binds_every_public_identity() {
        let context = C41FiatShamirPublicContext {
            model_binding_digest: [1; 32],
            setup_digest: [2; 32],
            quantization_digest: [3; 32],
            statement_digest: [4; 32],
            connection_binding: [5; 32],
            public_incidence_seed: [6; 32],
            pcs_parameter_digest: [7; 32],
            response_index: 8,
            cells: 9,
        };
        let digest = context.digest().unwrap();
        assert_ne!(digest, [0; 32]);
        let mut changed = context;
        changed.response_index += 1;
        assert_ne!(digest, changed.digest().unwrap());
        changed = context;
        changed.statement_digest[0] ^= 1;
        assert_ne!(digest, changed.digest().unwrap());
        changed = context;
        changed.setup_digest = [0; 32];
        assert!(changed.digest().is_err());
    }

    #[test]
    fn c41_response_index_is_burned_before_retry() {
        let context = C41FiatShamirPublicContext {
            model_binding_digest: [1; 32],
            setup_digest: [2; 32],
            quantization_digest: [3; 32],
            statement_digest: [4; 32],
            connection_binding: [5; 32],
            public_incidence_seed: [6; 32],
            pcs_parameter_digest: [7; 32],
            response_index: 8,
            cells: 9,
        };
        let root = std::env::temp_dir().join(format!(
            "volta-c41-burn-{}-{}",
            std::process::id(),
            context.response_index
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = ResponseAuthorizationStore::new(&root).unwrap();
        let binding = context.response_authorization_binding().unwrap();
        store.reserve(&binding).unwrap();
        assert!(store.reserve(&binding).unwrap_err().to_string().contains("already burned"));

        let mut next = context;
        next.response_index += 1;
        store.reserve(&next.response_authorization_binding().unwrap()).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
