//! Wire-neutral C6.1 partition of the canonical C6 certificate.
//!
//! C6.1 preserves the 857-byte outer certificate framing.  The historical
//! `retained_transcript` blob is reinterpreted as one exact retained non-PCS
//! response prefix followed by the self-framed C6PA2 public argument.  The
//! seven-component C6PIF1 envelope remains the `wrapper_proof` blob.  Inner
//! response and C6PA2 decoders still own their semantic validation.

use std::fmt;

use crate::{
    C6FinalCertificate, C6ResponseProofEnvelope, C6RetainedResponseProof, C6WrapperCommitments,
};

pub const C61_RETAINED_NON_PCS_RESPONSE_BYTES: u64 = 2_921_744;
pub const C61_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES: u64 = 15_157_896;
pub const C61_CERTIFICATE_STRICT_MAX_BYTES: u64 = 21_999_999;

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

/// Strict outer C6.1 certificate after the wire-neutral payload partition has
/// been checked.  The wrapped C6 certificate is immutable through this API,
/// so the validated split cannot drift after construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61FinalCertificateEnvelope {
    certificate: C6FinalCertificate,
    proof_envelope: C6ResponseProofEnvelope,
}

/// Wire-neutral interpretation of the historical C6 cache/wrapper fields.
/// The two cache roots already live in the transition heads. The four
/// remaining production cohort roots occupy four legacy wrapper-root slots,
/// leaving the final 32-byte slot for the combined live-source binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C61WrapperWireBinding {
    pub statement_digest: [u8; 32],
    pub roots: [[u8; 32]; 6],
    pub source_binding_digest: [u8; 32],
}

impl C61WrapperWireBinding {
    pub fn new(
        statement_digest: [u8; 32],
        roots: [[u8; 32]; 6],
        source_binding_digest: [u8; 32],
    ) -> Result<Self> {
        let binding = Self { statement_digest, roots, source_binding_digest };
        if binding.statement_digest == [0; 32]
            || binding.source_binding_digest == [0; 32]
            || binding.roots.contains(&[0; 32])
        {
            return Err(C61CertificateError::new(
                "C6.1 wrapper wire binding contains a zero digest",
            ));
        }
        Ok(binding)
    }

    pub fn from_certificate(certificate: &C6FinalCertificate) -> Result<Self> {
        Self::from_parts(
            certificate.old_head.cache_root,
            certificate.new_head.cache_root,
            certificate.wrapper,
        )
    }

    pub fn from_parts(
        old_cache_root: [u8; 32],
        new_cache_root: [u8; 32],
        wrapper: C6WrapperCommitments,
    ) -> Result<Self> {
        Self::new(
            wrapper.prequery_statement_digest,
            [
                old_cache_root,
                new_cache_root,
                wrapper.correction_roots[0],
                wrapper.weights_u_root,
                wrapper.embed_u_root,
                wrapper.correction_roots[1],
            ],
            wrapper.cache_witness_root,
        )
    }

    pub fn wrapper_commitments(self) -> C6WrapperCommitments {
        C6WrapperCommitments {
            prequery_statement_digest: self.statement_digest,
            correction_roots: [self.roots[2], self.roots[5]],
            weights_u_root: self.roots[3],
            embed_u_root: self.roots[4],
            cache_witness_root: self.source_binding_digest,
        }
    }
}

impl C61FinalCertificateEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let certificate = C6FinalCertificate::decode(bytes)
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        Self::from_c6_certificate(certificate)
    }

    pub fn from_c6_certificate(certificate: C6FinalCertificate) -> Result<Self> {
        let encoded_len = certificate
            .encoded_len()
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        let retained_prefix = usize::try_from(C61_RETAINED_NON_PCS_RESPONSE_BYTES)
            .map_err(|_| C61CertificateError::new("C6.1 retained prefix exceeds usize"))?;
        if retained_prefix != crate::C6_RETAINED_RESPONSE_BYTES {
            return Err(C61CertificateError::new(
                "C6.1 retained allocation differs from its canonical codec",
            ));
        }
        if encoded_len > C61_CERTIFICATE_STRICT_MAX_BYTES
            || certificate.retained_transcript.len() <= retained_prefix
        {
            return Err(C61CertificateError::new(
                "C6.1 certificate cap or retained/public partition mismatch",
            ));
        }
        C6RetainedResponseProof::decode(&certificate.retained_transcript[..retained_prefix])
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        let public_argument_len = certificate.retained_transcript.len() - retained_prefix;
        if public_argument_len as u64 > C61_PUBLIC_ARGUMENT_ABSOLUTE_MAX_BYTES {
            return Err(C61CertificateError::new(
                "C6.1 public argument exceeds its absolute wire allocation",
            ));
        }
        let framing = encoded_len
            .checked_sub(certificate.retained_transcript.len() as u64)
            .and_then(|value| value.checked_sub(certificate.wrapper_proof.len() as u64))
            .ok_or_else(|| C61CertificateError::new("C6.1 certificate framing underflows"))?;
        if framing != crate::C6_CERTIFICATE_NEW_PAYLOAD_FRAMING_BYTES {
            return Err(C61CertificateError::new(
                "C6.1 certificate outer framing differs from the frozen 857 bytes",
            ));
        }
        let proof_envelope = C6ResponseProofEnvelope::decode(&certificate.wrapper_proof)
            .map_err(|error| C61CertificateError::new(error.to_string()))?;
        Ok(Self { certificate, proof_envelope })
    }

    pub fn certificate(&self) -> &C6FinalCertificate {
        &self.certificate
    }

    pub fn retained_response(&self) -> &[u8] {
        &self.certificate.retained_transcript[..C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize]
    }

    pub fn public_argument(&self) -> &[u8] {
        &self.certificate.retained_transcript[C61_RETAINED_NON_PCS_RESPONSE_BYTES as usize..]
    }

    pub fn proof_envelope(&self) -> &C6ResponseProofEnvelope {
        &self.proof_envelope
    }

    pub fn wrapper_binding(&self) -> Result<C61WrapperWireBinding> {
        C61WrapperWireBinding::from_certificate(&self.certificate)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.certificate.encode().map_err(|error| C61CertificateError::new(error.to_string()))
    }
}

#[cfg(test)]
mod wrapper_wire_tests {
    use super::*;

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    #[test]
    fn wrapper_wire_binding_round_trips_all_six_roots_and_source_binding() {
        let roots = [digest(1), digest(2), digest(3), digest(4), digest(5), digest(6)];
        let binding = C61WrapperWireBinding::new(digest(7), roots, digest(8)).unwrap();
        assert_eq!(
            C61WrapperWireBinding::from_parts(roots[0], roots[1], binding.wrapper_commitments())
                .unwrap(),
            binding
        );
    }

    #[test]
    fn wrapper_wire_binding_rejects_zero_statement_source_or_root() {
        let roots = [digest(1), digest(2), digest(3), digest(4), digest(5), digest(6)];
        assert!(C61WrapperWireBinding::new([0; 32], roots, digest(8)).is_err());
        assert!(C61WrapperWireBinding::new(digest(7), roots, [0; 32]).is_err());
        let mut missing = roots;
        missing[5] = [0; 32];
        assert!(C61WrapperWireBinding::new(digest(7), missing, digest(8)).is_err());
    }
}
