//! Canonical C6.3 designated-verifier certificate.

use std::fmt;

use crate::c62_certificate::{hash_parts, Decoder, Encoder};
use crate::{
    C61RetainedResponseBinding, C62NativeWrapperCommitments, C63ResponseProofEnvelope, C6CacheHead,
    C6PairedCorrelationRanges, C6PairedDeltaResidual, C6RetainedResponseProof, C6Workload,
    C6_MAX_CONTEXT,
};

pub const C63_RETAINED_NON_PCS_RESPONSE_BYTES: u64 = crate::C62_RETAINED_RESPONSE_BYTES as u64;
pub const C63_INHERITED_PUBLIC_ARGUMENT_BYTES: u64 = 9_210_864;
pub const C63_SKETCH_PUBLIC_ARGUMENT_MAX_BYTES: u64 = 12_276_610;
pub const C63_NATIVE_CERTIFICATE_VERSION: u16 = 3;
pub const C63_NATIVE_WRAPPER_QUERIES: u16 = 86;
pub const C63_NATIVE_CERTIFICATE_FRAMING_BYTES: u64 = 793;
pub const C63_NATIVE_STRICT_PI_FINAL_MAX_BYTES: u64 =
    C63_NATIVE_CERTIFICATE_FRAMING_BYTES + crate::C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES;
pub const C63_CERTIFICATE_CODEC_MAX_BYTES: u64 = C63_NATIVE_CERTIFICATE_FRAMING_BYTES
    + C63_RETAINED_NON_PCS_RESPONSE_BYTES
    + C63_INHERITED_PUBLIC_ARGUMENT_BYTES
    + C63_SKETCH_PUBLIC_ARGUMENT_MAX_BYTES
    + crate::C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES;

const C63_NATIVE_CERTIFICATE_MAGIC: &[u8] = b"VOLTA-C63-CERT-v3";
const C62_PUBLIC_ARGUMENT_MAGIC: &[u8; 8] = b"C62PA1\0\0";
const C62_PUBLIC_ARGUMENT_VERSION: u16 = 1;
const C62_PUBLIC_ARGUMENT_COMPONENTS: u16 = 7;
const C63_PUBLIC_ARGUMENT_MAGIC: &[u8; 8] = b"C63PUB3\0";
const C63_PUBLIC_ARGUMENT_HEADER_BYTES: usize = 216;
const C63_PUBLIC_ARGUMENT_COMPONENTS: u16 = 9;
const C63_PUBLIC_ARGUMENT_COMPONENT_FRAME_BYTES: usize = 40;
const C63_PUBLIC_ARGUMENT_DIGEST_BYTES: usize = 32;
const C63_PUBLIC_ARGUMENT_FRAMING_BYTES: usize = C63_PUBLIC_ARGUMENT_HEADER_BYTES
    + C63_PUBLIC_ARGUMENT_COMPONENTS as usize * C63_PUBLIC_ARGUMENT_COMPONENT_FRAME_BYTES
    + C63_PUBLIC_ARGUMENT_DIGEST_BYTES;
const C63_NATIVE_RETAINED_MAX_BYTES: u64 = C63_RETAINED_NON_PCS_RESPONSE_BYTES
    + C63_INHERITED_PUBLIC_ARGUMENT_BYTES
    + C63_SKETCH_PUBLIC_ARGUMENT_MAX_BYTES;

pub type C63NativeWrapperCommitments = C62NativeWrapperCommitments;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63CertificateError(String);

impl C63CertificateError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C63CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C63CertificateError {}

type Result<T> = std::result::Result<T, C63CertificateError>;

#[derive(Clone, Copy)]
struct PublicHeader {
    epoch: u64,
    old_len: u16,
    accepted_len: u16,
    statement_digest: [u8; 32],
    profile_digest: [u8; 32],
    predecessor_correction_root: [u8; 32],
    predecessor_encoded_sketch_root: [u8; 32],
    correction_root: [u8; 32],
    encoded_sketch_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C63NativeFinalCertificate {
    pub version: u16,
    pub wrapper_queries: u16,
    pub protocol_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub params_digest: [u8; 32],
    pub setup_manifest_digest: [u8; 32],
    pub connection_id: [u8; 32],
    pub nonce: [u8; 32],
    pub slot: u32,
    pub correlation_ranges: C6PairedCorrelationRanges,
    pub predecessor_certificate_digest: [u8; 32],
    pub old_head: C6CacheHead,
    pub new_head: C6CacheHead,
    pub workload: C6Workload,
    pub public_output_digest: [u8; 32],
    pub wrapper: C63NativeWrapperCommitments,
    pub residual: C6PairedDeltaResidual,
    pub retained_transcript_digest: [u8; 32],
    pub proof_envelope_digest: [u8; 32],
    pub transition_statement_digest: [u8; 32],
    pub retained_transcript: Vec<u8>,
    pub proof_envelope: Vec<u8>,
}

impl C63NativeFinalCertificate {
    pub fn seal(mut self) -> Result<Self> {
        let public = parse_public_header(self.sketch_public_argument_unchecked())?;
        self.new_head.cache_root = self.compute_state_head_digest(public);
        self.retained_transcript_digest = c63_retained_digest(&self.retained_transcript);
        self.proof_envelope_digest = c63_proof_digest(&self.proof_envelope);
        self.transition_statement_digest = self.compute_transition_statement_digest();
        self.new_head.producer_transition_digest = self.transition_statement_digest;
        self.validate()?;
        Ok(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C63_CERTIFICATE_CODEC_MAX_BYTES {
            return Err(C63CertificateError::new("C63NFC3 exceeds its codec cap"));
        }
        let mut input = Decoder::new(bytes);
        if read(input.take(C63_NATIVE_CERTIFICATE_MAGIC.len()))? != C63_NATIVE_CERTIFICATE_MAGIC {
            return Err(C63CertificateError::new("wrong C63NFC3 certificate magic"));
        }
        let certificate = Self {
            version: read(input.u16())?,
            wrapper_queries: read(input.u16())?,
            protocol_digest: read(input.digest())?,
            model_digest: read(input.digest())?,
            params_digest: read(input.digest())?,
            setup_manifest_digest: read(input.digest())?,
            connection_id: read(input.digest())?,
            nonce: read(input.digest())?,
            slot: read(input.u32())?,
            correlation_ranges: read(input.paired_ranges())?,
            predecessor_certificate_digest: read(input.digest())?,
            old_head: read(input.cache_head())?,
            new_head: read(input.cache_head())?,
            workload: read(input.workload())?,
            public_output_digest: read(input.digest())?,
            wrapper: C63NativeWrapperCommitments {
                statement_digest: read(input.digest())?,
                residual_root: read(input.digest())?,
                auxiliary_root: read(input.digest())?,
                source_binding_digest: read(input.digest())?,
            },
            residual: read(input.paired_residual())?,
            retained_transcript_digest: read(input.digest())?,
            proof_envelope_digest: read(input.digest())?,
            transition_statement_digest: read(input.digest())?,
            retained_transcript: read(input.blob(C63_NATIVE_RETAINED_MAX_BYTES as usize))?,
            proof_envelope: read(
                input.blob(crate::C63_RESPONSE_PROOF_ENVELOPE_MAX_BYTES as usize),
            )?,
        };
        read(input.finish())?;
        certificate.validate()?;
        if certificate.encode_unchecked() != bytes {
            return Err(C63CertificateError::new("noncanonical C63NFC3 encoding"));
        }
        Ok(certificate)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(hash_parts(b"volta-zk/c6.3/final-certificate/v3", &[&self.encode()?]))
    }

    pub fn encoded_len(&self) -> Result<u64> {
        Ok(self.encode()?.len() as u64)
    }

    pub fn retained_response(&self) -> &[u8] {
        &self.retained_transcript[..C63_RETAINED_NON_PCS_RESPONSE_BYTES as usize]
    }

    pub fn inherited_public_argument(&self) -> &[u8] {
        let start = C63_RETAINED_NON_PCS_RESPONSE_BYTES as usize;
        let end = start + C63_INHERITED_PUBLIC_ARGUMENT_BYTES as usize;
        &self.retained_transcript[start..end]
    }

    pub fn sketch_public_argument(&self) -> &[u8] {
        self.sketch_public_argument_unchecked()
    }

    pub fn retained_response_binding(&self) -> C61RetainedResponseBinding {
        C61RetainedResponseBinding::from_c62_bytes(self.retained_response())
            .expect("validated C63NFC3 has a strict retained response")
    }

    pub fn decoded_proof_envelope(&self) -> C63ResponseProofEnvelope {
        C63ResponseProofEnvelope::decode(&self.proof_envelope)
            .expect("validated C63NFC3 has a strict proof envelope")
    }

    pub fn wrapper_roots(&self) -> [[u8; 32]; 4] {
        self.wrapper.roots(self.old_head.cache_root, self.new_head.cache_root)
    }

    pub fn compute_transition_statement_digest(&self) -> [u8; 32] {
        hash_parts(b"volta-zk/c6.3/transition-statement/v3", &[&self.encode_statement()])
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != C63_NATIVE_CERTIFICATE_VERSION
            || self.wrapper_queries != C63_NATIVE_WRAPPER_QUERIES
        {
            return Err(C63CertificateError::new("wrong C63NFC3 version or query profile"));
        }
        if [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.nonce,
            self.public_output_digest,
            self.retained_transcript_digest,
            self.proof_envelope_digest,
            self.transition_statement_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(C63CertificateError::new("C63NFC3 contains a zero required digest"));
        }
        self.old_head.validate().map_err(|error| C63CertificateError::new(error.to_string()))?;
        self.new_head.validate().map_err(|error| C63CertificateError::new(error.to_string()))?;
        if (self.old_head.epoch == 0 && self.predecessor_certificate_digest != [0; 32])
            || (self.old_head.epoch != 0 && self.predecessor_certificate_digest == [0; 32])
        {
            return Err(C63CertificateError::new("C63NFC3 predecessor differs from genesis"));
        }
        self.correlation_ranges
            .validate()
            .map_err(|error| C63CertificateError::new(error.to_string()))?;
        self.workload.validate().map_err(|error| C63CertificateError::new(error.to_string()))?;
        self.wrapper.validate().map_err(|error| C63CertificateError::new(error.to_string()))?;
        if self.new_head.epoch
            != self
                .old_head
                .epoch
                .checked_add(1)
                .ok_or_else(|| C63CertificateError::new("C63NFC3 cache epoch overflows"))?
            || self.workload.old_context != self.old_head.cache_len
            || self.workload.new_context != self.new_head.cache_len
            || self.new_head.cache_len > C6_MAX_CONTEXT
        {
            return Err(C63CertificateError::new("C63NFC3 does not advance its predecessor"));
        }
        let minimum = C63_RETAINED_NON_PCS_RESPONSE_BYTES
            + C63_INHERITED_PUBLIC_ARGUMENT_BYTES
            + C63_PUBLIC_ARGUMENT_HEADER_BYTES as u64;
        if (self.retained_transcript.len() as u64) < minimum
            || (self.retained_transcript.len() as u64) > C63_NATIVE_RETAINED_MAX_BYTES
        {
            return Err(C63CertificateError::new("C63NFC3 retained partition violates its cap"));
        }
        C6RetainedResponseProof::decode_c62(self.retained_response())
            .map_err(|error| C63CertificateError::new(error.to_string()))?;
        let inherited_statement = c62_public_argument_statement(self.inherited_public_argument())?;
        let public = parse_public_header(self.sketch_public_argument_unchecked())?;
        if public.epoch != self.new_head.epoch
            || u32::from(public.old_len) != self.old_head.cache_len
            || u32::from(public.accepted_len) != self.new_head.cache_len
            || public.statement_digest != inherited_statement
            || self.new_head.cache_root != self.compute_state_head_digest(public)
        {
            return Err(C63CertificateError::new("C63NFC3 public state binding differs"));
        }
        C63ResponseProofEnvelope::decode(&self.proof_envelope)
            .map_err(|error| C63CertificateError::new(error.to_string()))?;
        if self.retained_transcript_digest != c63_retained_digest(&self.retained_transcript)
            || self.proof_envelope_digest != c63_proof_digest(&self.proof_envelope)
        {
            return Err(C63CertificateError::new("C63NFC3 payload digest mismatch"));
        }
        let statement_digest = self.compute_transition_statement_digest();
        if self.transition_statement_digest != statement_digest
            || self.new_head.producer_transition_digest != statement_digest
        {
            return Err(C63CertificateError::new("C63NFC3 transition or head digest mismatch"));
        }
        let encoded_len = self.encode_unchecked().len() as u64;
        let proof_boundary = C63_NATIVE_CERTIFICATE_FRAMING_BYTES
            .checked_add(self.proof_envelope.len() as u64)
            .ok_or_else(|| C63CertificateError::new("C63NFC3 proof boundary overflows"))?;
        if encoded_len > C63_CERTIFICATE_CODEC_MAX_BYTES
            || proof_boundary > C63_NATIVE_STRICT_PI_FINAL_MAX_BYTES
        {
            return Err(C63CertificateError::new("C63NFC3 size cap exceeded"));
        }
        Ok(())
    }

    fn sketch_public_argument_unchecked(&self) -> &[u8] {
        let start =
            (C63_RETAINED_NON_PCS_RESPONSE_BYTES + C63_INHERITED_PUBLIC_ARGUMENT_BYTES) as usize;
        &self.retained_transcript[start..]
    }

    fn compute_state_head_digest(&self, public: PublicHeader) -> [u8; 32] {
        let mut state = Encoder::new();
        state.raw(b"VOLTA-C63-STATE-HEAD-v3");
        for digest in [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.predecessor_certificate_digest,
            self.old_head.cache_root,
            self.old_head.producer_transition_digest,
            public.profile_digest,
            public.predecessor_correction_root,
            public.predecessor_encoded_sketch_root,
            public.correction_root,
            public.encoded_sketch_root,
            self.wrapper.source_binding_digest,
        ] {
            state.digest(digest);
        }
        state.u64(self.old_head.epoch);
        state.u32(self.old_head.cache_len);
        state.u64(public.epoch);
        state.u16(public.accepted_len);
        hash_parts(b"volta-zk/c6.3/state-head/v3", &[&state.finish()])
    }

    fn encode_statement(&self) -> Vec<u8> {
        let mut out = Encoder::new();
        out.raw(b"VOLTA-C63-STATEMENT-v3");
        self.encode_fixed_prefix(&mut out, false);
        out.finish()
    }

    fn encode_unchecked(&self) -> Vec<u8> {
        let mut out = Encoder::new();
        out.raw(C63_NATIVE_CERTIFICATE_MAGIC);
        self.encode_fixed_prefix(&mut out, true);
        out.blob(&self.retained_transcript);
        out.blob(&self.proof_envelope);
        out.finish()
    }

    fn encode_fixed_prefix(&self, out: &mut Encoder, include_transition: bool) {
        out.u16(self.version);
        out.u16(self.wrapper_queries);
        for digest in [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.nonce,
        ] {
            out.digest(digest);
        }
        out.u32(self.slot);
        out.paired_ranges(self.correlation_ranges);
        out.digest(self.predecessor_certificate_digest);
        out.cache_head(self.old_head, true);
        out.cache_head(self.new_head, include_transition);
        out.workload(self.workload);
        out.digest(self.public_output_digest);
        for digest in [
            self.wrapper.statement_digest,
            self.wrapper.residual_root,
            self.wrapper.auxiliary_root,
            self.wrapper.source_binding_digest,
        ] {
            out.digest(digest);
        }
        out.paired_residual(self.residual);
        out.digest(self.retained_transcript_digest);
        out.digest(self.proof_envelope_digest);
        if include_transition {
            out.digest(self.transition_statement_digest);
        }
    }
}

fn parse_public_header(bytes: &[u8]) -> Result<PublicHeader> {
    if bytes.len() < C63_PUBLIC_ARGUMENT_FRAMING_BYTES
        || bytes.len() as u64 > C63_SKETCH_PUBLIC_ARGUMENT_MAX_BYTES
        || bytes.get(..8) != Some(C63_PUBLIC_ARGUMENT_MAGIC)
    {
        return Err(C63CertificateError::new("C63NFC3 sketch public argument differs"));
    }
    let u16_at = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let u64_at = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let digest_at = |offset| bytes[offset..offset + 32].try_into().unwrap();
    if u16_at(8) != 3 || u16_at(10) != C63_PUBLIC_ARGUMENT_COMPONENTS {
        return Err(C63CertificateError::new("C63NFC3 sketch public header differs"));
    }
    let header = PublicHeader {
        epoch: u64_at(12),
        old_len: u16_at(20),
        accepted_len: u16_at(22),
        statement_digest: digest_at(24),
        profile_digest: digest_at(56),
        predecessor_correction_root: digest_at(88),
        predecessor_encoded_sketch_root: digest_at(120),
        correction_root: digest_at(152),
        encoded_sketch_root: digest_at(184),
    };
    if [
        header.statement_digest,
        header.profile_digest,
        header.predecessor_correction_root,
        header.predecessor_encoded_sketch_root,
        header.correction_root,
        header.encoded_sketch_root,
    ]
    .contains(&[0; 32])
    {
        return Err(C63CertificateError::new("C63NFC3 sketch public digest is zero"));
    }
    let mut offset = C63_PUBLIC_ARGUMENT_HEADER_BYTES;
    for expected_kind in 1..=C63_PUBLIC_ARGUMENT_COMPONENTS {
        let frame_end = offset
            .checked_add(C63_PUBLIC_ARGUMENT_COMPONENT_FRAME_BYTES)
            .ok_or_else(|| C63CertificateError::new("C63NFC3 sketch component overflows"))?;
        let frame = bytes
            .get(offset..frame_end)
            .ok_or_else(|| C63CertificateError::new("C63NFC3 sketch component is truncated"))?;
        let kind = u16::from_le_bytes(frame[..2].try_into().unwrap());
        let reserved = u16::from_le_bytes(frame[2..4].try_into().unwrap());
        let len = u32::from_le_bytes(frame[4..8].try_into().unwrap()) as usize;
        let digest: [u8; 32] = frame[8..40].try_into().unwrap();
        let payload_end = frame_end
            .checked_add(len)
            .ok_or_else(|| C63CertificateError::new("C63NFC3 sketch payload overflows"))?;
        let payload = bytes
            .get(frame_end..payload_end)
            .ok_or_else(|| C63CertificateError::new("C63NFC3 sketch payload is truncated"))?;
        if kind != expected_kind
            || reserved != 0
            || digest != c63_public_component_digest(kind, payload)
        {
            return Err(C63CertificateError::new("C63NFC3 sketch component differs"));
        }
        offset = payload_end;
    }
    if offset.checked_add(C63_PUBLIC_ARGUMENT_DIGEST_BYTES) != Some(bytes.len())
        || bytes[offset..] != c63_public_argument_digest(&bytes[..offset])
    {
        return Err(C63CertificateError::new("C63NFC3 sketch argument digest differs"));
    }
    Ok(header)
}

fn c62_public_argument_statement(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() < 44
        || bytes.get(..8) != Some(C62_PUBLIC_ARGUMENT_MAGIC)
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != C62_PUBLIC_ARGUMENT_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().unwrap())
            != C62_PUBLIC_ARGUMENT_COMPONENTS
    {
        return Err(C63CertificateError::new("C63NFC3 inherited public argument differs"));
    }
    let statement: [u8; 32] = bytes[12..44].try_into().unwrap();
    if statement == [0; 32] {
        return Err(C63CertificateError::new(
            "C63NFC3 inherited public statement is zero",
        ));
    }
    Ok(statement)
}

fn c63_public_component_digest(kind: u16, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-component/v3");
    hasher.update(&kind.to_le_bytes());
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn c63_public_argument_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c63/public-argument/v3");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn c63_retained_digest(bytes: &[u8]) -> [u8; 32] {
    hash_parts(b"volta-zk/c6.3/retained-transcript/v3", &[bytes])
}

fn c63_proof_digest(bytes: &[u8]) -> [u8; 32] {
    hash_parts(b"volta-zk/c6.3/proof-envelope/v3", &[bytes])
}

fn read<T>(value: std::result::Result<T, crate::C62CertificateError>) -> Result<T> {
    value.map_err(|_| C63CertificateError::new("malformed C63NFC3 certificate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp2;

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn certificate() -> C63NativeFinalCertificate {
        let mut retained = crate::model_proof_codec::retained_response_c62_test_bytes();
        let mut inherited = vec![0; C63_INHERITED_PUBLIC_ARGUMENT_BYTES as usize];
        inherited[..8].copy_from_slice(C62_PUBLIC_ARGUMENT_MAGIC);
        inherited[8..10].copy_from_slice(&C62_PUBLIC_ARGUMENT_VERSION.to_le_bytes());
        inherited[10..12].copy_from_slice(&C62_PUBLIC_ARGUMENT_COMPONENTS.to_le_bytes());
        inherited[12..44].copy_from_slice(&digest(19));
        retained.extend(inherited);
        let mut sketch = vec![0; C63_PUBLIC_ARGUMENT_HEADER_BYTES];
        sketch[..8].copy_from_slice(C63_PUBLIC_ARGUMENT_MAGIC);
        sketch[8..10].copy_from_slice(&3u16.to_le_bytes());
        sketch[10..12].copy_from_slice(&9u16.to_le_bytes());
        sketch[12..20].copy_from_slice(&1u64.to_le_bytes());
        sketch[20..22].copy_from_slice(&0u16.to_le_bytes());
        sketch[22..24].copy_from_slice(&1u16.to_le_bytes());
        sketch[24..56].copy_from_slice(&digest(19));
        sketch[56..88].copy_from_slice(&digest(20));
        sketch[88..120].copy_from_slice(&digest(21));
        sketch[120..152].copy_from_slice(&digest(22));
        sketch[152..184].copy_from_slice(&digest(26));
        sketch[184..216].copy_from_slice(&digest(27));
        for kind in 1..=C63_PUBLIC_ARGUMENT_COMPONENTS {
            sketch.extend_from_slice(&kind.to_le_bytes());
            sketch.extend_from_slice(&0u16.to_le_bytes());
            sketch.extend_from_slice(&0u32.to_le_bytes());
            sketch.extend_from_slice(&c63_public_component_digest(kind, &[]));
        }
        let sketch_digest = c63_public_argument_digest(&sketch);
        sketch.extend_from_slice(&sketch_digest);
        assert_eq!(sketch.len(), C63_PUBLIC_ARGUMENT_FRAMING_BYTES);
        retained.extend(sketch);
        let proof = C63ResponseProofEnvelope::new(
            vec![0x51],
            vec![0x52; crate::C62_RESPONSE_PRODUCT_COORDINATE_ONE_BYTES as usize],
            vec![0x53; crate::C62_RESPONSE_RESIDUAL_PENDING_BYTES as usize],
            vec![0x58; crate::C62_RESPONSE_CACHE_FOLD_TARGET_BYTES as usize],
            vec![0x57; crate::C63_RESPONSE_SOURCE_FUNCTIONAL_CORRECTIONS_BYTES as usize],
            vec![0x54; crate::C63_RESPONSE_AUTHENTICATED_OUTPUT_LINK_BYTES as usize],
            vec![0x55; crate::C63_RESPONSE_SPARSE_H_CLOSURE_BYTES as usize],
            vec![0x56; crate::C63_RESPONSE_WHIR_TERMINAL_TAGS_BYTES as usize],
        )
        .unwrap()
        .encode()
        .unwrap();
        C63NativeFinalCertificate {
            version: C63_NATIVE_CERTIFICATE_VERSION,
            wrapper_queries: C63_NATIVE_WRAPPER_QUERIES,
            protocol_digest: digest(10),
            model_digest: digest(11),
            params_digest: digest(12),
            setup_manifest_digest: digest(13),
            connection_id: digest(14),
            nonce: digest(15),
            slot: 0,
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    crate::C6CorrelationRange { stage: 1, start: 0, count: 1 },
                    crate::C6CorrelationRange { stage: 1, start: 0, count: 1 },
                ],
            },
            predecessor_certificate_digest: [0; 32],
            old_head: C6CacheHead {
                epoch: 0,
                cache_len: 0,
                cache_root: digest(16),
                producer_transition_digest: [0; 32],
            },
            new_head: C6CacheHead {
                epoch: 1,
                cache_len: 1,
                cache_root: [0; 32],
                producer_transition_digest: [0; 32],
            },
            workload: C6Workload {
                prompt_tokens: 1,
                decode_tokens: 0,
                old_context: 0,
                new_context: 1,
            },
            public_output_digest: digest(18),
            wrapper: C63NativeWrapperCommitments {
                statement_digest: digest(29),
                residual_root: digest(23),
                auxiliary_root: digest(24),
                source_binding_digest: digest(25),
            },
            residual: C6PairedDeltaResidual {
                coordinates: [
                    crate::C6DeltaResidual { correction_rlc: Fp2::ZERO, public_tag_rlc: Fp2::ZERO },
                    crate::C6DeltaResidual { correction_rlc: Fp2::ZERO, public_tag_rlc: Fp2::ZERO },
                ],
            },
            retained_transcript_digest: [0; 32],
            proof_envelope_digest: [0; 32],
            transition_statement_digest: [0; 32],
            retained_transcript: retained,
            proof_envelope: proof,
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn c63_final_certificate_round_trip_binds_both_state_roots() {
        let certificate = certificate();
        assert_ne!(certificate.wrapper.statement_digest, digest(19));
        let sketch = certificate.sketch_public_argument_unchecked();
        assert_eq!(sketch.len(), C63_PUBLIC_ARGUMENT_FRAMING_BYTES);
        assert!(parse_public_header(&sketch[..C63_PUBLIC_ARGUMENT_HEADER_BYTES]).is_err());
        let mut changed_component = sketch.to_vec();
        changed_component[C63_PUBLIC_ARGUMENT_HEADER_BYTES + 8] ^= 1;
        assert!(parse_public_header(&changed_component).is_err());
        let bytes = certificate.encode().unwrap();
        assert_eq!(C63NativeFinalCertificate::decode(&bytes).unwrap(), certificate);
        assert_eq!(
            bytes.len() as u64
                - certificate.retained_transcript.len() as u64
                - certificate.proof_envelope.len() as u64,
            C63_NATIVE_CERTIFICATE_FRAMING_BYTES,
        );
        assert_eq!(C63_CERTIFICATE_CODEC_MAX_BYTES, 28_710_631);
        assert!(crate::C62NativeFinalCertificate::decode(&bytes).is_err());

        let mut wrong_join = certificate.clone();
        wrong_join.retained_transcript
            [C63_RETAINED_NON_PCS_RESPONSE_BYTES as usize + 12] ^= 1;
        assert!(wrong_join.seal().is_err());

        let mut changed = bytes;
        let correction_root = C63_NATIVE_CERTIFICATE_FRAMING_BYTES as usize
            + C63_RETAINED_NON_PCS_RESPONSE_BYTES as usize
            + C63_INHERITED_PUBLIC_ARGUMENT_BYTES as usize
            + 152;
        changed[correction_root] ^= 1;
        assert!(C63NativeFinalCertificate::decode(&changed).is_err());
    }

    #[test]
    fn c63_certificate_uses_durable_slot_lifecycle() {
        let certificate = certificate();
        let root = std::env::temp_dir().join(format!(
            "volta-c63-slot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let store = crate::C6SlotStore::open(&root).unwrap();
        let reservation = crate::C6SlotReservation {
            connection_id: certificate.connection_id,
            setup_manifest_digest: certificate.setup_manifest_digest,
            slot: certificate.slot,
            nonce: certificate.nonce,
            old_head_digest: certificate.old_head.digest(),
            predecessor_certificate_digest: certificate.predecessor_certificate_digest,
            correlation_ranges: certificate.correlation_ranges,
            workload: certificate.workload,
        };
        let mut slot = store.reserve(reservation).unwrap();
        slot.start().unwrap();
        let expected = certificate.encode().unwrap();
        let certificate_digest = slot.produce_c63(&certificate).unwrap();
        assert_eq!(slot.retransmit_c63().unwrap(), expected);
        assert_eq!(slot.produce_c63(&certificate).unwrap(), certificate_digest);
        slot.acknowledge(certificate_digest).unwrap();
        drop(slot);
        let reopened = store.open_slot(certificate.connection_id, certificate.slot).unwrap();
        assert_eq!(reopened.retransmit_c63().unwrap(), expected);
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }
}
