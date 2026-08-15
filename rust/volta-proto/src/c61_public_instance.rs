//! Canonical client-local public workload input for C6.1 campaign replay.
//!
//! This artifact is not provider-to-client wire: it records tokens already
//! known to the client so an independent disk verifier can reconstruct the
//! exact public response statement without retaining prover objects.

use std::fmt;

use crate::C6Workload;

const MAGIC: &[u8] = b"C61PI2\0\0";
const VERSION: u16 = 2;
const MAX_CONTEXT: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicWorkloadInstance {
    response_statement_digest: [u8; 32],
    public_argument_statement_digest: [u8; 32],
    preimage: C61PublicWorkloadPreimage,
}

/// Client-known workload fields before either statement digest is fixed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicWorkloadPreimage {
    model_family_digest: [u8; 32],
    workload: C6Workload,
    public_tokens: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicInstanceError(String);

impl C61PublicInstanceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C61PublicInstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C61PublicInstanceError {}

type Result<T> = std::result::Result<T, C61PublicInstanceError>;

impl C61PublicWorkloadPreimage {
    pub fn new(
        model_family_digest: [u8; 32],
        workload: C6Workload,
        public_tokens: Vec<u32>,
    ) -> Result<Self> {
        workload.validate().map_err(|error| C61PublicInstanceError::new(error.to_string()))?;
        if model_family_digest == [0; 32]
            || workload.new_context as usize > MAX_CONTEXT
            || public_tokens.len() != workload.new_context as usize
        {
            return Err(C61PublicInstanceError::new("invalid C6.1 public workload instance"));
        }
        Ok(Self { model_family_digest, workload, public_tokens })
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c61/public-workload-preimage/v1");
        hasher.update(&self.model_family_digest);
        for value in [
            self.workload.old_context,
            self.workload.prompt_tokens,
            self.workload.decode_tokens,
            self.workload.new_context,
            self.public_tokens.len() as u32,
        ] {
            hasher.update(&value.to_le_bytes());
        }
        for token in &self.public_tokens {
            hasher.update(&token.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    pub fn model_family_digest(&self) -> [u8; 32] {
        self.model_family_digest
    }

    pub fn workload(&self) -> C6Workload {
        self.workload
    }

    pub fn public_tokens(&self) -> &[u32] {
        &self.public_tokens
    }

    pub fn bind_statements(
        self,
        response_statement_digest: [u8; 32],
        public_argument_statement_digest: [u8; 32],
    ) -> Result<C61PublicWorkloadInstance> {
        let instance = C61PublicWorkloadInstance {
            response_statement_digest,
            public_argument_statement_digest,
            preimage: self,
        };
        instance.validate()?;
        Ok(instance)
    }
}

impl C61PublicWorkloadInstance {
    pub fn validate(&self) -> Result<()> {
        C61PublicWorkloadPreimage::new(
            self.preimage.model_family_digest,
            self.preimage.workload,
            self.preimage.public_tokens.clone(),
        )?;
        if self.response_statement_digest == [0; 32]
            || self.public_argument_statement_digest == [0; 32]
            || self.response_statement_digest == self.public_argument_statement_digest
        {
            return Err(C61PublicInstanceError::new("invalid C6.1 statement split"));
        }
        Ok(())
    }

    pub fn response_statement_digest(&self) -> [u8; 32] {
        self.response_statement_digest
    }

    pub fn public_argument_statement_digest(&self) -> [u8; 32] {
        self.public_argument_statement_digest
    }

    pub fn model_family_digest(&self) -> [u8; 32] {
        self.preimage.model_family_digest
    }

    pub fn workload(&self) -> C6Workload {
        self.preimage.workload
    }

    pub fn public_tokens(&self) -> &[u32] {
        &self.preimage.public_tokens
    }

    pub fn preimage_digest(&self) -> [u8; 32] {
        self.preimage.digest()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(160 + 4 * self.preimage.public_tokens.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.response_statement_digest);
        bytes.extend_from_slice(&self.public_argument_statement_digest);
        bytes.extend_from_slice(&self.preimage.model_family_digest);
        for value in [
            self.preimage.workload.old_context,
            self.preimage.workload.prompt_tokens,
            self.preimage.workload.decode_tokens,
            self.preimage.workload.new_context,
            u32::try_from(self.preimage.public_tokens.len())
                .map_err(|_| C61PublicInstanceError::new("public token count exceeds u32"))?,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for token in &self.preimage.public_tokens {
            bytes.extend_from_slice(&token.to_le_bytes());
        }
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        const FIXED_WITHOUT_TOKENS: usize = 8 + 2 + 2 + 3 * 32 + 5 * 4 + 32;
        if bytes.len() < FIXED_WITHOUT_TOKENS {
            return Err(C61PublicInstanceError::new("truncated C6.1 public instance"));
        }
        let (body, claimed_digest) = bytes.split_at(bytes.len() - 32);
        if blake3::hash(body).as_bytes() != claimed_digest
            || &body[..MAGIC.len()] != MAGIC
            || u16::from_le_bytes(body[8..10].try_into().expect("fixed width")) != VERSION
            || u16::from_le_bytes(body[10..12].try_into().expect("fixed width")) != 0
        {
            return Err(C61PublicInstanceError::new(
                "C6.1 public instance header or digest mismatch",
            ));
        }
        let mut offset = 12;
        let mut digest = || {
            let value = body[offset..offset + 32].try_into().expect("fixed digest width");
            offset += 32;
            value
        };
        let response_statement_digest = digest();
        let public_argument_statement_digest = digest();
        let model_family_digest = digest();
        let mut u32_value = || {
            let value =
                u32::from_le_bytes(body[offset..offset + 4].try_into().expect("fixed width"));
            offset += 4;
            value
        };
        let old_context = u32_value();
        let prompt_tokens = u32_value();
        let decode_tokens = u32_value();
        let new_context = u32_value();
        let token_count = usize::try_from(u32_value()).expect("u32 fits usize");
        let expected_len = FIXED_WITHOUT_TOKENS
            .checked_add(
                token_count
                    .checked_mul(4)
                    .ok_or_else(|| C61PublicInstanceError::new("public token bytes overflow"))?,
            )
            .ok_or_else(|| C61PublicInstanceError::new("public instance bytes overflow"))?;
        if token_count > MAX_CONTEXT || bytes.len() != expected_len {
            return Err(C61PublicInstanceError::new("public token census mismatch"));
        }
        let public_tokens = (0..token_count)
            .map(|_| {
                let value =
                    u32::from_le_bytes(body[offset..offset + 4].try_into().expect("fixed width"));
                offset += 4;
                value
            })
            .collect();
        if offset != body.len() {
            return Err(C61PublicInstanceError::new("trailing C6.1 public instance bytes"));
        }
        let preimage = C61PublicWorkloadPreimage::new(
            model_family_digest,
            C6Workload { old_context, prompt_tokens, decode_tokens, new_context },
            public_tokens,
        )?;
        let instance = preimage
            .bind_statements(response_statement_digest, public_argument_statement_digest)?;
        instance.validate()?;
        if instance.encode()? != bytes {
            return Err(C61PublicInstanceError::new("noncanonical C6.1 public instance encoding"));
        }
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance() -> C61PublicWorkloadInstance {
        C61PublicWorkloadPreimage::new(
            [0x32; 32],
            C6Workload { old_context: 0, prompt_tokens: 100, decode_tokens: 50, new_context: 150 },
            (0..150).collect(),
        )
        .unwrap()
        .bind_statements([0x31; 32], [0x33; 32])
        .unwrap()
    }

    #[test]
    fn public_instance_codec_is_strict_and_model_independent() {
        let instance = instance();
        let bytes = instance.encode().unwrap();
        assert_eq!(C61PublicWorkloadInstance::decode(&bytes).unwrap(), instance);

        let mut mutation = bytes.clone();
        mutation[40] ^= 1;
        assert!(C61PublicWorkloadInstance::decode(&mutation).is_err());
        assert!(C61PublicWorkloadInstance::decode(&bytes[..bytes.len() - 1]).is_err());

        assert!(C61PublicWorkloadPreimage::new(
            [0x32; 32],
            C6Workload { old_context: 0, prompt_tokens: 100, decode_tokens: 50, new_context: 151 },
            (0..150).collect(),
        )
        .is_err());
        assert!(instance.preimage.clone().bind_statements([0x31; 32], [0x31; 32]).is_err());

        let maximum = C61PublicWorkloadPreimage::new(
            [0x41; 32],
            C6Workload {
                old_context: 0,
                prompt_tokens: 1_024,
                decode_tokens: 0,
                new_context: 1_024,
            },
            (0..1_024).collect(),
        )
        .unwrap()
        .bind_statements([0x42; 32], [0x43; 32])
        .unwrap();
        assert_eq!(maximum.encode().unwrap().len(), 160 + 4 * 1_024);
    }
}
