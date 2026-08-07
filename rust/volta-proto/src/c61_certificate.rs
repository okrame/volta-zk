//! Wire-neutral C6.1 partition of the canonical C6 certificate.
//!
//! C6.1 preserves the 857-byte outer certificate framing.  The historical
//! `retained_transcript` blob is reinterpreted as one exact retained non-PCS
//! response prefix followed by the self-framed C6PA2 public argument.  The
//! seven-component C6PIF1 envelope remains the `wrapper_proof` blob.  Inner
//! response and C6PA2 decoders still own their semantic validation.

use std::fmt;

use crate::{C6FinalCertificate, C6ResponseProofEnvelope, C6RetainedResponseProof};

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

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.certificate.encode().map_err(|error| C61CertificateError::new(error.to_string()))
    }
}
