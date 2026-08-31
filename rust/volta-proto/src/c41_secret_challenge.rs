//! Strict C41SC1 request/response artifacts for the one private bridge coin.

use crate::C41FiatShamirPublicContext;
use std::fmt;
use volta_field::{Fp, Fp2, P};
use volta_mac::{C41SecretChallengeFrontier, C41_FIAT_SHAMIR_MAX_CHALLENGES};

const REQUEST_MAGIC: [u8; 8] = *b"C41SCR1\0";
const RESPONSE_MAGIC: [u8; 8] = *b"C41SCP1\0";
const VERSION: u16 = 1;
pub const C41_SECRET_CHALLENGE_REQUEST_BYTES: usize = 330;
pub const C41_SECRET_CHALLENGE_RESPONSE_BYTES: usize = 90;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41SecretChallengeError(String);

impl C41SecretChallengeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C41SecretChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C41SecretChallengeError {}

type Result<T> = std::result::Result<T, C41SecretChallengeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41SecretChallengeRequest {
    pub context: C41FiatShamirPublicContext,
    pub frontier_digest: [u8; 32],
    pub fiat_shamir_challenges: u64,
    pub transcript_bytes: u64,
}

impl C41SecretChallengeRequest {
    pub fn from_frontier(
        context: C41FiatShamirPublicContext,
        frontier: C41SecretChallengeFrontier,
    ) -> Result<Self> {
        if context.digest().map_err(|error| C41SecretChallengeError::new(error.to_string()))?
            != frontier.context_digest
        {
            return Err(C41SecretChallengeError::new(
                "C41SC1 frontier uses a different public context",
            ));
        }
        let request = Self {
            context,
            frontier_digest: frontier.transcript_digest,
            fiat_shamir_challenges: frontier.fiat_shamir_challenges,
            transcript_bytes: frontier.transcript_bytes,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(C41_SECRET_CHALLENGE_REQUEST_BYTES);
        out.extend_from_slice(&REQUEST_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for digest in [
            self.context.model_binding_digest,
            self.context.setup_digest,
            self.context.quantization_digest,
            self.context.statement_digest,
            self.context.connection_binding,
            self.context.public_incidence_seed,
            self.context.pcs_parameter_digest,
        ] {
            out.extend_from_slice(&digest);
        }
        out.extend_from_slice(&self.context.response_index.to_le_bytes());
        out.extend_from_slice(&self.context.cells.to_le_bytes());
        out.extend_from_slice(&self.frontier_digest);
        out.extend_from_slice(&self.fiat_shamir_challenges.to_le_bytes());
        out.extend_from_slice(&self.transcript_bytes.to_le_bytes());
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        debug_assert_eq!(out.len(), C41_SECRET_CHALLENGE_REQUEST_BYTES);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C41_SECRET_CHALLENGE_REQUEST_BYTES
            || bytes[..8] != REQUEST_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version")) != VERSION
            || bytes[C41_SECRET_CHALLENGE_REQUEST_BYTES - 32..]
                != *blake3::hash(&bytes[..C41_SECRET_CHALLENGE_REQUEST_BYTES - 32]).as_bytes()
        {
            return Err(C41SecretChallengeError::new("invalid C41SC1 challenge-request framing"));
        }
        let mut offset = 10;
        let context = C41FiatShamirPublicContext {
            model_binding_digest: read_digest(bytes, &mut offset),
            setup_digest: read_digest(bytes, &mut offset),
            quantization_digest: read_digest(bytes, &mut offset),
            statement_digest: read_digest(bytes, &mut offset),
            connection_binding: read_digest(bytes, &mut offset),
            public_incidence_seed: read_digest(bytes, &mut offset),
            pcs_parameter_digest: read_digest(bytes, &mut offset),
            response_index: read_u64(bytes, &mut offset),
            cells: read_u64(bytes, &mut offset),
        };
        let frontier_digest = read_digest(bytes, &mut offset);
        let request = Self {
            context,
            frontier_digest,
            fiat_shamir_challenges: read_u64(bytes, &mut offset),
            transcript_bytes: read_u64(bytes, &mut offset),
        };
        debug_assert_eq!(offset, C41_SECRET_CHALLENGE_REQUEST_BYTES - 32);
        request.validate()?;
        if request.encode()?.as_slice() != bytes {
            return Err(C41SecretChallengeError::new("noncanonical C41SC1 challenge request"));
        }
        Ok(request)
    }

    pub fn digest(self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    fn validate(self) -> Result<()> {
        self.context.digest().map_err(|error| C41SecretChallengeError::new(error.to_string()))?;
        if self.frontier_digest == [0; 32]
            || self.fiat_shamir_challenges == 0
            || self.fiat_shamir_challenges >= C41_FIAT_SHAMIR_MAX_CHALLENGES
            || self.transcript_bytes == 0
            || self.transcript_bytes >= 70_000_000
        {
            return Err(C41SecretChallengeError::new("invalid C41SC1 challenge frontier census"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41SecretChallengeResponse {
    pub request_digest: [u8; 32],
    pub challenge: Fp2,
}

impl C41SecretChallengeResponse {
    pub fn new(request: C41SecretChallengeRequest, challenge: Fp2) -> Result<Self> {
        Ok(Self { request_digest: request.digest()?, challenge })
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        if self.request_digest == [0; 32] {
            return Err(C41SecretChallengeError::new("zero C41SC1 challenge-request digest"));
        }
        let mut out = Vec::with_capacity(C41_SECRET_CHALLENGE_RESPONSE_BYTES);
        out.extend_from_slice(&RESPONSE_MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&self.challenge.c0.value().to_le_bytes());
        out.extend_from_slice(&self.challenge.c1.value().to_le_bytes());
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        debug_assert_eq!(out.len(), C41_SECRET_CHALLENGE_RESPONSE_BYTES);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != C41_SECRET_CHALLENGE_RESPONSE_BYTES
            || bytes[..8] != RESPONSE_MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version")) != VERSION
            || bytes[C41_SECRET_CHALLENGE_RESPONSE_BYTES - 32..]
                != *blake3::hash(&bytes[..C41_SECRET_CHALLENGE_RESPONSE_BYTES - 32]).as_bytes()
        {
            return Err(C41SecretChallengeError::new("invalid C41SC1 challenge-response framing"));
        }
        let request_digest = bytes[10..42].try_into().expect("fixed request digest");
        let c0 = u64::from_le_bytes(bytes[42..50].try_into().expect("fixed Fp limb"));
        let c1 = u64::from_le_bytes(bytes[50..58].try_into().expect("fixed Fp limb"));
        if request_digest == [0; 32] || c0 >= P || c1 >= P {
            return Err(C41SecretChallengeError::new("noncanonical C41SC1 challenge response"));
        }
        let response = Self { request_digest, challenge: Fp2::new(Fp::new(c0), Fp::new(c1)) };
        if response.encode()?.as_slice() != bytes {
            return Err(C41SecretChallengeError::new("noncanonical C41SC1 challenge response"));
        }
        Ok(response)
    }

    pub fn validate_request(self, request: C41SecretChallengeRequest) -> Result<Fp2> {
        if self.request_digest != request.digest()? {
            return Err(C41SecretChallengeError::new("C41SC1 response binds a different request"));
        }
        Ok(self.challenge)
    }
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let value = u64::from_le_bytes(bytes[*offset..*offset + 8].try_into().expect("fixed u64"));
    *offset += 8;
    value
}

fn read_digest(bytes: &[u8], offset: &mut usize) -> [u8; 32] {
    let value = bytes[*offset..*offset + 32].try_into().expect("fixed digest");
    *offset += 32;
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> C41FiatShamirPublicContext {
        C41FiatShamirPublicContext {
            model_binding_digest: [1; 32],
            setup_digest: [2; 32],
            quantization_digest: [3; 32],
            statement_digest: [4; 32],
            connection_binding: [5; 32],
            public_incidence_seed: [6; 32],
            pcs_parameter_digest: [7; 32],
            response_index: 8,
            cells: 9,
        }
    }

    #[test]
    fn strict_request_response_roundtrip_rejects_tampering() {
        let context = context();
        let request = C41SecretChallengeRequest::from_frontier(
            context,
            C41SecretChallengeFrontier {
                context_digest: context.digest().unwrap(),
                transcript_digest: [11; 32],
                fiat_shamir_challenges: 12,
                transcript_bytes: 13,
            },
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        assert_eq!(C41SecretChallengeRequest::decode(&encoded).unwrap(), request);
        let response =
            C41SecretChallengeResponse::new(request, Fp2::new(Fp::new(17), Fp::new(19))).unwrap();
        let encoded_response = response.encode().unwrap();
        assert_eq!(
            C41SecretChallengeResponse::decode(&encoded_response)
                .unwrap()
                .validate_request(request)
                .unwrap(),
            response.challenge
        );

        let mut tampered = encoded;
        tampered[100] ^= 1;
        assert!(C41SecretChallengeRequest::decode(&tampered).is_err());
        let mut tampered = encoded_response;
        tampered[50..58].copy_from_slice(&P.to_le_bytes());
        assert!(C41SecretChallengeResponse::decode(&tampered).is_err());
    }
}
