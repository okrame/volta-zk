//! Canonical native C6.1 certificate with four wrapper roots and C61PIF2.

use std::fmt;
use volta_field::{Fp, Fp2, P};

use crate::{
    C61NativeResponseProofEnvelope, C6CacheHead, C6CorrelationRange, C6PairedCorrelationRanges,
    C6PairedDeltaResidual, C6RetainedResponseProof, C6Workload, C6_MAX_CONTEXT,
};

pub const C61_RETAINED_NON_PCS_RESPONSE_BYTES: u64 = 2_921_744;
pub const C61_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES: u64 = 15_157_896;
pub const C61_CERTIFICATE_STRICT_MAX_BYTES: u64 = 21_999_999;
pub const C61_NATIVE_CERTIFICATE_VERSION: u16 = 1;
pub const C61_NATIVE_WRAPPER_QUERIES: u16 = 86;
pub const C61_NATIVE_CERTIFICATE_FRAMING_BYTES: u64 = 793;
pub const C61_NATIVE_STRICT_PI_FINAL_MAX_BYTES: u64 =
    C61_NATIVE_CERTIFICATE_FRAMING_BYTES + crate::C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES;

const C61_NATIVE_CERTIFICATE_MAGIC: &[u8] = b"VOLTA-C61-CERT-v1";
const C61_NATIVE_RETAINED_MAX_BYTES: u64 =
    C61_RETAINED_NON_PCS_RESPONSE_BYTES + C61_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61CertificateError(String);

impl C61CertificateError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61CertificateError {}

type Result<T> = std::result::Result<T, C61CertificateError>;

/// Exact C6.1 wrapper commitments. The cache roots live in the transition
/// heads; the other two native roots and one source binding live here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61NativeWrapperCommitments {
    pub statement_digest: [u8; 32],
    pub residual_root: [u8; 32],
    pub auxiliary_root: [u8; 32],
    pub source_binding_digest: [u8; 32],
}

impl C61NativeWrapperCommitments {
    pub fn roots(self, old_cache_root: [u8; 32], new_cache_root: [u8; 32]) -> [[u8; 32]; 4] {
        [old_cache_root, new_cache_root, self.residual_root, self.auxiliary_root]
    }

    fn validate(self) -> Result<()> {
        if [
            self.statement_digest,
            self.residual_root,
            self.auxiliary_root,
            self.source_binding_digest,
        ]
        .contains(&[0; 32])
        {
            return Err(C61CertificateError::new("C6.1 native wrapper contains a zero digest"));
        }
        Ok(())
    }
}

/// Native C6.1 certificate schema. It is not an interpretation of a C6
/// certificate: its magic, statement hashes, six-component proof grammar and
/// four-root wrapper are all distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61NativeFinalCertificate {
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
    pub wrapper: C61NativeWrapperCommitments,
    pub residual: C6PairedDeltaResidual,
    pub retained_transcript_digest: [u8; 32],
    pub proof_envelope_digest: [u8; 32],
    pub transition_statement_digest: [u8; 32],
    pub retained_transcript: Vec<u8>,
    pub proof_envelope: Vec<u8>,
}

impl C61NativeFinalCertificate {
    /// Seal payload and transition digests after every public field and both
    /// payloads have been fixed. No caller-supplied digest survives.
    pub fn seal(mut self) -> Result<Self> {
        self.retained_transcript_digest = c61_native_retained_digest(&self.retained_transcript);
        self.proof_envelope_digest = c61_native_proof_digest(&self.proof_envelope);
        self.transition_statement_digest = self.compute_transition_statement_digest();
        self.new_head.producer_transition_digest = self.transition_statement_digest;
        self.validate()?;
        Ok(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() as u64 > C61_CERTIFICATE_STRICT_MAX_BYTES {
            return Err(C61CertificateError::new("C6.1 native certificate exceeds 22 MB"));
        }
        let mut input = NativeDecoder::new(bytes);
        if input.take(C61_NATIVE_CERTIFICATE_MAGIC.len())? != C61_NATIVE_CERTIFICATE_MAGIC {
            return Err(C61CertificateError::new("wrong C6.1 native certificate magic"));
        }
        let certificate = Self {
            version: input.u16()?,
            wrapper_queries: input.u16()?,
            protocol_digest: input.digest()?,
            model_digest: input.digest()?,
            params_digest: input.digest()?,
            setup_manifest_digest: input.digest()?,
            connection_id: input.digest()?,
            nonce: input.digest()?,
            slot: input.u32()?,
            correlation_ranges: input.paired_ranges()?,
            predecessor_certificate_digest: input.digest()?,
            old_head: input.cache_head()?,
            new_head: input.cache_head()?,
            workload: input.workload()?,
            public_output_digest: input.digest()?,
            wrapper: C61NativeWrapperCommitments {
                statement_digest: input.digest()?,
                residual_root: input.digest()?,
                auxiliary_root: input.digest()?,
                source_binding_digest: input.digest()?,
            },
            residual: input.paired_residual()?,
            retained_transcript_digest: input.digest()?,
            proof_envelope_digest: input.digest()?,
            transition_statement_digest: input.digest()?,
            retained_transcript: input.blob(C61_NATIVE_RETAINED_MAX_BYTES as usize)?,
            proof_envelope: input
                .blob(crate::C61_NATIVE_RESPONSE_PROOF_ENVELOPE_MAX_BYTES as usize)?,
        };
        input.finish()?;
        certificate.validate()?;
        if certificate.encode_unchecked() != bytes {
            return Err(C61CertificateError::new("noncanonical C6.1 native certificate encoding"));
        }
        Ok(certificate)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(c61_hash_parts(b"volta-zk/c6.1/native-final-certificate/v1", &[&self.encode()?]))
    }

    pub fn encoded_len(&self) -> Result<u64> {
        Ok(self.encode()?.len() as u64)
    }

    pub fn retained_response(&self) -> &[u8] {
        &self.retained_transcript[..C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize]
    }

    pub fn retained_response_binding(&self) -> C61RetainedResponseBinding {
        C61RetainedResponseBinding::from_bytes(self.retained_response())
            .expect("validated C6.1 native certificate has a strict retained response")
    }

    pub fn public_argument(&self) -> &[u8] {
        &self.retained_transcript[C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize..]
    }

    pub fn decoded_proof_envelope(&self) -> C61NativeResponseProofEnvelope {
        C61NativeResponseProofEnvelope::decode(&self.proof_envelope)
            .expect("validated C6.1 native certificate has a strict proof envelope")
    }

    pub fn wrapper_roots(&self) -> [[u8; 32]; 4] {
        self.wrapper.roots(self.old_head.cache_root, self.new_head.cache_root)
    }

    pub fn compute_transition_statement_digest(&self) -> [u8; 32] {
        c61_hash_parts(b"volta-zk/c6.1/native-transition-statement/v1", &[&self.encode_statement()])
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != C61_NATIVE_CERTIFICATE_VERSION
            || self.wrapper_queries != C61_NATIVE_WRAPPER_QUERIES
        {
            return Err(C61CertificateError::new(
                "wrong C6.1 native certificate version/query profile",
            ));
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
            return Err(C61CertificateError::new("zero required C6.1 native certificate digest"));
        }
        self.old_head.validate().map_err(|error| C61CertificateError::new(error.to_string()))?;
        self.new_head.validate().map_err(|error| C61CertificateError::new(error.to_string()))?;
        if (self.old_head.epoch == 0 && self.predecessor_certificate_digest != [0; 32])
            || (self.old_head.epoch != 0 && self.predecessor_certificate_digest == [0; 32])
        {
            return Err(C61CertificateError::new(
                "C6.1 native predecessor digest differs from genesis status",
            ));
        }
        self.correlation_ranges
            .validate()
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        self.workload.validate().map_err(|error| C61CertificateError::new(error.to_string()))?;
        self.wrapper.validate()?;
        if self.new_head.epoch
            != self
                .old_head
                .epoch
                .checked_add(1)
                .ok_or_else(|| C61CertificateError::new("C6.1 native cache epoch overflows"))?
            || self.workload.old_context != self.old_head.cache_len
            || self.workload.new_context != self.new_head.cache_len
            || self.new_head.cache_len > C6_MAX_CONTEXT
        {
            return Err(C61CertificateError::new(
                "C6.1 native certificate does not advance its predecessor",
            ));
        }
        if self.retained_transcript.len() <= C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize
            || self.retained_transcript.len() as u64 > C61_NATIVE_RETAINED_MAX_BYTES
        {
            return Err(C61CertificateError::new(
                "C6.1 native retained/public partition violates its cap",
            ));
        }
        C6RetainedResponseProof::decode(self.retained_response())
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        C61NativeResponseProofEnvelope::decode(&self.proof_envelope)
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        if self.retained_transcript_digest != c61_native_retained_digest(&self.retained_transcript)
            || self.proof_envelope_digest != c61_native_proof_digest(&self.proof_envelope)
        {
            return Err(C61CertificateError::new("C6.1 native payload digest mismatch"));
        }
        let statement_digest = self.compute_transition_statement_digest();
        if self.transition_statement_digest != statement_digest
            || self.new_head.producer_transition_digest != statement_digest
        {
            return Err(C61CertificateError::new("C6.1 native transition/head digest mismatch"));
        }
        let encoded_len = self.encode_unchecked().len() as u64;
        let proof_boundary = C61_NATIVE_CERTIFICATE_FRAMING_BYTES
            .checked_add(self.proof_envelope.len() as u64)
            .ok_or_else(|| C61CertificateError::new("C6.1 native proof boundary overflows"))?;
        if encoded_len > C61_CERTIFICATE_STRICT_MAX_BYTES
            || proof_boundary > C61_NATIVE_STRICT_PI_FINAL_MAX_BYTES
        {
            return Err(C61CertificateError::new("C6.1 native certificate cap exceeded"));
        }
        Ok(())
    }

    fn encode_statement(&self) -> Vec<u8> {
        let mut out = NativeEncoder::new();
        out.raw(b"VOLTA-C61-STATEMENT-v1");
        self.encode_fixed_prefix(&mut out, false);
        out.finish()
    }

    fn encode_unchecked(&self) -> Vec<u8> {
        let mut out = NativeEncoder::new();
        out.raw(C61_NATIVE_CERTIFICATE_MAGIC);
        self.encode_fixed_prefix(&mut out, true);
        out.blob(&self.retained_transcript);
        out.blob(&self.proof_envelope);
        out.finish()
    }

    fn encode_fixed_prefix(&self, out: &mut NativeEncoder, include_transition: bool) {
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

fn c61_native_retained_digest(bytes: &[u8]) -> [u8; 32] {
    c61_hash_parts(b"volta-zk/c6.1/native-retained-transcript/v1", &[bytes])
}

fn c61_native_proof_digest(bytes: &[u8]) -> [u8; 32] {
    c61_hash_parts(b"volta-zk/c6.1/native-proof-envelope/v1", &[bytes])
}

fn c61_hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Default)]
struct NativeEncoder {
    bytes: Vec<u8>,
}

impl NativeEncoder {
    fn new() -> Self {
        Self::default()
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }

    fn digest(&mut self, value: [u8; 32]) {
        self.raw(&value);
    }

    fn fp2(&mut self, value: Fp2) {
        self.u64(value.c0.value());
        self.u64(value.c1.value());
    }

    fn paired_ranges(&mut self, ranges: C6PairedCorrelationRanges) {
        for range in ranges.coordinates {
            self.u32(range.stage);
            self.u64(range.start);
            self.u64(range.count);
        }
    }

    fn cache_head(&mut self, head: C6CacheHead, include_transition: bool) {
        self.u64(head.epoch);
        self.u32(head.cache_len);
        self.digest(head.cache_root);
        if include_transition {
            self.digest(head.producer_transition_digest);
        }
    }

    fn workload(&mut self, workload: C6Workload) {
        self.u32(workload.prompt_tokens);
        self.u32(workload.decode_tokens);
        self.u32(workload.old_context);
        self.u32(workload.new_context);
    }

    fn paired_residual(&mut self, residual: C6PairedDeltaResidual) {
        for coordinate in residual.coordinates {
            self.fp2(coordinate.correction_rlc);
            self.fp2(coordinate.public_tag_rlc);
        }
    }

    fn blob(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.raw(bytes);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct NativeDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NativeDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| C61CertificateError::new("C6.1 native decoder offset overflow"))?;
        if end > self.bytes.len() {
            return Err(C61CertificateError::new("truncated C6.1 native certificate"));
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }

    fn digest(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }

    fn fp2(&mut self) -> Result<Fp2> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(C61CertificateError::new(
                "noncanonical Goldilocks element in C6.1 native certificate",
            ));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn paired_ranges(&mut self) -> Result<C6PairedCorrelationRanges> {
        let mut next = || -> Result<C6CorrelationRange> {
            Ok(C6CorrelationRange { stage: self.u32()?, start: self.u64()?, count: self.u64()? })
        };
        Ok(C6PairedCorrelationRanges { coordinates: [next()?, next()?] })
    }

    fn cache_head(&mut self) -> Result<C6CacheHead> {
        Ok(C6CacheHead {
            epoch: self.u64()?,
            cache_len: self.u32()?,
            cache_root: self.digest()?,
            producer_transition_digest: self.digest()?,
        })
    }

    fn workload(&mut self) -> Result<C6Workload> {
        Ok(C6Workload {
            prompt_tokens: self.u32()?,
            decode_tokens: self.u32()?,
            old_context: self.u32()?,
            new_context: self.u32()?,
        })
    }

    fn paired_residual(&mut self) -> Result<C6PairedDeltaResidual> {
        Ok(C6PairedDeltaResidual { coordinates: [self.delta_residual()?, self.delta_residual()?] })
    }

    fn delta_residual(&mut self) -> Result<crate::C6DeltaResidual> {
        Ok(crate::C6DeltaResidual { correction_rlc: self.fp2()?, public_tag_rlc: self.fp2()? })
    }

    fn blob(&mut self, max_len: usize) -> Result<Vec<u8>> {
        let len = usize::try_from(self.u64()?)
            .map_err(|_| C61CertificateError::new("C6.1 native blob exceeds usize"))?;
        if len > max_len {
            return Err(C61CertificateError::new("C6.1 native blob exceeds its cap"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C61CertificateError::new("trailing bytes in C6.1 native certificate"));
        }
        Ok(())
    }
}

/// Strict digest of the retained response prefix only. It cannot be formed
/// from the later C6PA2 suffix or an arbitrary byte string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61RetainedResponseBinding {
    digest: [u8; 32],
}

impl C61RetainedResponseBinding {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize {
            return Err(C61CertificateError::new(
                "C6.1 retained response prefix has the wrong length",
            ));
        }
        C6RetainedResponseProof::decode(bytes)
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c61/retained-response-prefix/v1");
        hasher.update(bytes);
        Ok(Self { digest: *hasher.finalize().as_bytes() })
    }

    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

#[cfg(test)]
mod wrapper_wire_tests {
    use super::*;

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn native_certificate() -> C61NativeFinalCertificate {
        let mut retained_transcript = crate::model_proof_codec::retained_response_test_bytes();
        retained_transcript.push(0xa5);
        let proof_envelope = C61NativeResponseProofEnvelope::new(
            vec![0x51],
            vec![0x52; crate::C61_NATIVE_RESPONSE_RESIDUAL_PENDING_BYTES as usize],
            vec![0x53; crate::C61_NATIVE_RESPONSE_CACHE_SOURCE_BYTES as usize],
            vec![0x54],
            vec![0x55; crate::C61_NATIVE_RESPONSE_CACHE_FOLD_TARGET_BYTES as usize],
            vec![0x56; crate::C61_NATIVE_RESPONSE_AUTHENTICATED_LINK_BYTES as usize],
        )
        .unwrap()
        .encode()
        .unwrap();
        C61NativeFinalCertificate {
            version: C61_NATIVE_CERTIFICATE_VERSION,
            wrapper_queries: C61_NATIVE_WRAPPER_QUERIES,
            protocol_digest: digest(10),
            model_digest: digest(11),
            params_digest: digest(12),
            setup_manifest_digest: digest(13),
            connection_id: digest(14),
            nonce: digest(15),
            slot: 0,
            correlation_ranges: C6PairedCorrelationRanges {
                coordinates: [
                    C6CorrelationRange { stage: 1, start: 0, count: 458 },
                    C6CorrelationRange { stage: 1, start: 0, count: 458 },
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
                cache_root: digest(17),
                producer_transition_digest: [0; 32],
            },
            workload: C6Workload {
                prompt_tokens: 1,
                decode_tokens: 0,
                old_context: 0,
                new_context: 1,
            },
            public_output_digest: digest(18),
            wrapper: C61NativeWrapperCommitments {
                statement_digest: digest(19),
                residual_root: digest(20),
                auxiliary_root: digest(21),
                source_binding_digest: digest(22),
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
            retained_transcript,
            proof_envelope,
        }
        .seal()
        .unwrap()
    }

    #[test]
    fn native_certificate_has_exact_four_root_793_byte_framing() {
        let certificate = native_certificate();
        let bytes = certificate.encode().unwrap();
        assert_eq!(C61NativeFinalCertificate::decode(&bytes).unwrap(), certificate);
        assert_eq!(
            bytes.len() as u64
                - certificate.retained_transcript.len() as u64
                - certificate.proof_envelope.len() as u64,
            C61_NATIVE_CERTIFICATE_FRAMING_BYTES
        );
        assert_eq!(C61_NATIVE_CERTIFICATE_FRAMING_BYTES, 793);
        assert_eq!(C61_NATIVE_STRICT_PI_FINAL_MAX_BYTES, 3_463_555);
        assert_eq!(certificate.wrapper_roots(), [digest(16), digest(17), digest(20), digest(21)]);
        assert!(crate::C6FinalCertificate::decode(&bytes).is_err());
    }

    #[test]
    fn native_certificate_rejects_old_magic_root_and_payload_mutations() {
        let certificate = native_certificate();
        let bytes = certificate.encode().unwrap();

        let mut old_magic = bytes.clone();
        old_magic[..C61_NATIVE_CERTIFICATE_MAGIC.len()].copy_from_slice(b"VOLTA-C6-CERT-v2\0");
        assert!(C61NativeFinalCertificate::decode(&old_magic).is_err());

        let mut missing_root = certificate.clone();
        missing_root.wrapper.auxiliary_root = [0; 32];
        assert!(missing_root.seal().is_err());

        let mut changed_proof = bytes;
        let proof_offset = changed_proof.len() - certificate.proof_envelope.len();
        changed_proof[proof_offset] ^= 1;
        assert!(C61NativeFinalCertificate::decode(&changed_proof).is_err());
    }

    #[test]
    fn native_certificate_source_has_no_c6_adapter_or_six_root_fields() {
        let source = include_str!("c61_certificate.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "C61FinalCertificateEnvelope",
            "C61WrapperWireBinding",
            "C6FinalCertificate",
            "C6ResponseProofEnvelope",
            "from_c6_certificate",
            "weights_u_root",
            "embed_u_root",
            "correction_roots",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
