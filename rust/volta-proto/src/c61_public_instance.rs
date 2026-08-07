//! Canonical client-local public workload input for C6.1 campaign replay.
//!
//! This artifact is not provider-to-client wire: it records tokens already
//! known to the client so an independent disk verifier can reconstruct the
//! exact public response statement without retaining prover objects.

use std::fmt;

const MAGIC: &[u8] = b"C61PI1\0\0";
const VERSION: u16 = 1;
const MAX_CONTEXT: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C61PublicWorkloadInstance {
    pub statement_digest: [u8; 32],
    pub model_family_digest: [u8; 32],
    pub old_context: u32,
    pub prompt_tokens: u32,
    pub decode_tokens: u32,
    pub new_context: u32,
    pub public_tokens: Vec<u32>,
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

impl C61PublicWorkloadInstance {
    pub fn validate(&self) -> Result<()> {
        let expected_new = self
            .old_context
            .checked_add(self.prompt_tokens)
            .and_then(|value| value.checked_add(self.decode_tokens))
            .ok_or_else(|| C61PublicInstanceError::new("C6.1 public workload overflows"))?;
        if self.statement_digest == [0; 32]
            || self.model_family_digest == [0; 32]
            || expected_new != self.new_context
            || self.new_context as usize > MAX_CONTEXT
            || self.public_tokens.len() != self.new_context as usize
        {
            return Err(C61PublicInstanceError::new("invalid C6.1 public workload instance"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(96 + 4 * self.public_tokens.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        bytes.extend_from_slice(&self.model_family_digest);
        for value in [
            self.old_context,
            self.prompt_tokens,
            self.decode_tokens,
            self.new_context,
            u32::try_from(self.public_tokens.len())
                .map_err(|_| C61PublicInstanceError::new("public token count exceeds u32"))?,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for token in &self.public_tokens {
            bytes.extend_from_slice(&token.to_le_bytes());
        }
        let digest = blake3::hash(&bytes);
        bytes.extend_from_slice(digest.as_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        const FIXED_WITHOUT_TOKENS: usize = 8 + 2 + 2 + 2 * 32 + 5 * 4 + 32;
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
        let statement_digest = digest();
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
        let instance = Self {
            statement_digest,
            model_family_digest,
            old_context,
            prompt_tokens,
            decode_tokens,
            new_context,
            public_tokens,
        };
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
        C61PublicWorkloadInstance {
            statement_digest: [0x31; 32],
            model_family_digest: [0x32; 32],
            old_context: 0,
            prompt_tokens: 100,
            decode_tokens: 50,
            new_context: 150,
            public_tokens: (0..150).collect(),
        }
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

        let mut wrong_geometry = instance;
        wrong_geometry.new_context += 1;
        assert!(wrong_geometry.encode().is_err());
    }
}
