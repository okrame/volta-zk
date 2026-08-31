//! Strict party-separated setup artifacts for the C4.1 response protocol.

use crate::c41_folded_tole::{
    C41SetupVerifierLot, C41TypedSetupProverState, C41TypedSetupVerifierState,
};
use crate::C41FiatShamirPublicContext;
use std::{fmt, io::Read};
use volta_field::{Fp, Fp2, P};
use volta_pcg::{FullVole, ProverPcgPool, SubVole, VerifierPcgPool};

pub const C41_PRODUCTION_CELLS: usize = 3_110_400;
pub const C41_PRODUCTION_SEED_ROWS: usize = 253;
pub const C41_PRODUCTION_TOTAL_SUB_CORRS: usize = 2_040_886;
pub const C41_PRODUCTION_TOTAL_FULL_CORRS: usize = 226_981;
pub const C41_PRODUCTION_TYPED_SUB_CORRS: usize = C41_PRODUCTION_SEED_ROWS * 1024;
pub const C41_PRODUCTION_ORDINARY_SUB_CORRS: usize =
    C41_PRODUCTION_TOTAL_SUB_CORRS - C41_PRODUCTION_TYPED_SUB_CORRS;
pub const C41_PRODUCTION_ORDINARY_FULL_CORRS: usize = C41_PRODUCTION_TOTAL_FULL_CORRS - 1;

const VERSION: u16 = 1;
const PROVIDER_MAGIC: [u8; 8] = *b"C41PVB1\0";
const VERIFIER_MAGIC: [u8; 8] = *b"C41VFB1\0";
const VERIFIER_LOT_MAGIC: [u8; 8] = *b"C41VLT1\0";
const STATEMENT_MAGIC: [u8; 8] = *b"C41ST1\0\0";
const MODEL_SETUP_MAGIC: [u8; 8] = *b"C41MS1\0\0";
const DIGEST_BYTES: usize = 32;
const MAX_BUNDLE_BYTES: u64 = 128_000_000;
pub const C41_MATERIALIZED_VERIFIER_LOT_MAX_BYTES: u64 = 100_000_000;
const MAX_STATEMENT_BYTES: u64 = 1_000_000;
const MAX_VERIFIER_MODEL_BYTES: usize = 1_000_000;
const MAX_CORRELATIONS: usize = 10_000_000;
const MAX_SEED_ROWS: usize = u16::MAX as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41PartyBundleError(String);

impl C41PartyBundleError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C41PartyBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C41PartyBundleError {}

type Result<T> = std::result::Result<T, C41PartyBundleError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41PartySetupContext {
    pub model_binding_digest: [u8; 32],
    pub setup_digest: [u8; 32],
    pub quantization_digest: [u8; 32],
    pub connection_binding: [u8; 32],
    pub public_incidence_seed: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub response_index: u64,
    pub cells: u64,
    pub first_global_bit: u64,
    pub ordinary_sub_corrs: u64,
    pub ordinary_full_corrs: u64,
}

impl C41PartySetupContext {
    pub fn fiat_shamir_context(
        self,
        statement_digest: [u8; 32],
    ) -> Result<C41FiatShamirPublicContext> {
        let context = C41FiatShamirPublicContext {
            model_binding_digest: self.model_binding_digest,
            setup_digest: self.setup_digest,
            quantization_digest: self.quantization_digest,
            statement_digest,
            connection_binding: self.connection_binding,
            public_incidence_seed: self.public_incidence_seed,
            pcs_parameter_digest: self.pcs_parameter_digest,
            response_index: self.response_index,
            cells: self.cells,
        };
        context.digest().map_err(|error| C41PartyBundleError::new(error.to_string()))?;
        Ok(context)
    }

    pub fn validate_production(self) -> Result<()> {
        self.validate()?;
        if self.cells as usize != C41_PRODUCTION_CELLS
            || self.first_global_bit != 0
            || self.ordinary_sub_corrs as usize != C41_PRODUCTION_ORDINARY_SUB_CORRS
            || self.ordinary_full_corrs as usize != C41_PRODUCTION_ORDINARY_FULL_CORRS
        {
            return Err(C41PartyBundleError::new("C4.1 production bundle census differs"));
        }
        Ok(())
    }

    fn validate(self) -> Result<()> {
        if self.cells == 0
            || self.cells > C41_PRODUCTION_CELLS as u64
            || self.first_global_bit > usize::MAX as u64
            || self.ordinary_sub_corrs == 0
            || self.ordinary_full_corrs == 0
            || self.ordinary_sub_corrs > MAX_CORRELATIONS as u64
            || self.ordinary_full_corrs > MAX_CORRELATIONS as u64
        {
            return Err(C41PartyBundleError::new("invalid C4.1 party-bundle geometry"));
        }
        self.fiat_shamir_context([1; 32])?;
        Ok(())
    }
}

/// Provider-only material. It contains no verifier key and no `Delta`.
pub struct C41ProviderBundle {
    pub context: C41PartySetupContext,
    pub correlations: ProverPcgPool,
    pub typed: C41TypedSetupProverState,
}

impl C41ProviderBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let count = self.typed.rows * 1024;
        let mut out = Writer(PROVIDER_MAGIC.to_vec());
        out.u16(VERSION);
        write_context(&mut out, self.context);
        out.u32(self.typed.rows as u32)?;
        let mut packed = vec![0u8; count.div_ceil(8)];
        for (index, bit) in self.typed.bits.iter().copied().enumerate() {
            if bit > 1 {
                return Err(C41PartyBundleError::new("non-bit C4.1 provider seed"));
            }
            packed[index / 8] |= bit << (index % 8);
        }
        out.bytes(&packed);
        for value in &self.typed.tags {
            out.fp2(*value)?;
        }
        for value in &self.correlations.subs {
            out.fp(value.r)?;
            out.fp2(value.m)?;
        }
        for value in &self.correlations.fulls {
            out.fp2(value.x)?;
            out.fp2(value.m)?;
        }
        out.finish(MAX_BUNDLE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload = checked_payload(bytes, MAX_BUNDLE_BYTES)?;
        let mut input = Reader { bytes: payload, offset: 0 };
        if input.take(8)? != PROVIDER_MAGIC || input.u16()? != VERSION {
            return Err(C41PartyBundleError::new("wrong C4.1 provider bundle header"));
        }
        let context = read_context(&mut input)?;
        let rows = input.u32()? as usize;
        checked_rows(rows)?;
        let count = rows * 1024;
        let packed = input.take(count.div_ceil(8))?;
        if count % 8 != 0 && packed[packed.len() - 1] >> (count % 8) != 0 {
            return Err(C41PartyBundleError::new("noncanonical C4.1 packed seed tail"));
        }
        let bits = (0..count).map(|index| (packed[index / 8] >> (index % 8)) & 1).collect();
        let tags = (0..count).map(|_| input.fp2()).collect::<Result<Vec<_>>>()?;
        let subs = (0..context.ordinary_sub_corrs as usize)
            .map(|_| Ok(SubVole { r: input.fp()?, m: input.fp2()? }))
            .collect::<Result<Vec<_>>>()?;
        let fulls = (0..context.ordinary_full_corrs as usize)
            .map(|_| Ok(FullVole { x: input.fp2()?, m: input.fp2()? }))
            .collect::<Result<Vec<_>>>()?;
        input.finish()?;
        let bundle = Self {
            context,
            correlations: ProverPcgPool { subs, fulls },
            typed: C41TypedSetupProverState { bits, tags, rows },
        };
        bundle.validate()?;
        if bundle.encode()? != bytes {
            return Err(C41PartyBundleError::new("noncanonical C4.1 provider bundle"));
        }
        Ok(bundle)
    }

    pub fn decode_reader(reader: impl Read) -> Result<Self> {
        Self::decode(&bounded_read(reader, MAX_BUNDLE_BYTES)?)
    }

    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        checked_rows(self.typed.rows)?;
        let count = self.typed.rows * 1024;
        if self.typed.bits.len() != count
            || self.typed.tags.len() != count
            || self.typed.bits.iter().any(|bit| *bit > 1)
            || self.correlations.subs.len() as u64 != self.context.ordinary_sub_corrs
            || self.correlations.fulls.len() as u64 != self.context.ordinary_full_corrs
        {
            return Err(C41PartyBundleError::new("C4.1 provider bundle census differs"));
        }
        Ok(())
    }
}

/// Client-only material. It contains no prover seed bit, tag, mask or share.
pub struct C41VerifierBundle {
    pub context: C41PartySetupContext,
    pub delta: Fp2,
    pub correlations: VerifierPcgPool,
    pub typed: C41TypedSetupVerifierState,
    pub verifier_model: Vec<u8>,
}

impl C41VerifierBundle {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Writer(VERIFIER_MAGIC.to_vec());
        out.u16(VERSION);
        write_context(&mut out, self.context);
        out.u32(self.typed.rows as u32)?;
        out.u32(self.verifier_model.len() as u32)?;
        out.fp2(self.delta)?;
        out.bytes(&self.verifier_model);
        for value in &self.typed.keys {
            out.fp2(*value)?;
        }
        for value in &self.correlations.sub_keys {
            out.fp2(*value)?;
        }
        for value in &self.correlations.full_keys {
            out.fp2(*value)?;
        }
        out.finish(MAX_BUNDLE_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload = checked_payload(bytes, MAX_BUNDLE_BYTES)?;
        let mut input = Reader { bytes: payload, offset: 0 };
        if input.take(8)? != VERIFIER_MAGIC || input.u16()? != VERSION {
            return Err(C41PartyBundleError::new("wrong C4.1 verifier bundle header"));
        }
        let context = read_context(&mut input)?;
        let rows = input.u32()? as usize;
        checked_rows(rows)?;
        let verifier_model_len = input.u32()? as usize;
        if verifier_model_len == 0 || verifier_model_len > MAX_VERIFIER_MODEL_BYTES {
            return Err(C41PartyBundleError::new("C4.1 verifier-model length differs"));
        }
        let delta = input.fp2()?;
        let verifier_model = input.take(verifier_model_len)?.to_vec();
        let keys = (0..rows * 1024).map(|_| input.fp2()).collect::<Result<Vec<_>>>()?;
        let sub_keys = (0..context.ordinary_sub_corrs as usize)
            .map(|_| input.fp2())
            .collect::<Result<Vec<_>>>()?;
        let full_keys = (0..context.ordinary_full_corrs as usize)
            .map(|_| input.fp2())
            .collect::<Result<Vec<_>>>()?;
        input.finish()?;
        let bundle = Self {
            context,
            delta,
            correlations: VerifierPcgPool { sub_keys, full_keys },
            typed: C41TypedSetupVerifierState { keys, rows },
            verifier_model,
        };
        bundle.validate()?;
        if bundle.encode()? != bytes {
            return Err(C41PartyBundleError::new("noncanonical C4.1 verifier bundle"));
        }
        Ok(bundle)
    }

    pub fn decode_reader(reader: impl Read) -> Result<Self> {
        Self::decode(&bounded_read(reader, MAX_BUNDLE_BYTES)?)
    }

    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        checked_rows(self.typed.rows)?;
        if self.delta == Fp2::ZERO
            || self.typed.keys.len() != self.typed.rows * 1024
            || self.correlations.sub_keys.len() as u64 != self.context.ordinary_sub_corrs
            || self.correlations.full_keys.len() as u64 != self.context.ordinary_full_corrs
            || self.verifier_model.is_empty()
            || self.verifier_model.len() > MAX_VERIFIER_MODEL_BYTES
        {
            return Err(C41PartyBundleError::new("C4.1 verifier bundle census differs"));
        }
        Ok(())
    }
}

/// Verifier-secret C41SC1 setup artifact. It is retained locally and never
/// contributes proof bytes or setup traffic.
pub struct C41MaterializedVerifierLot {
    pub context: C41PartySetupContext,
    pub lot: C41SetupVerifierLot,
}

impl C41MaterializedVerifierLot {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Writer(VERIFIER_LOT_MAGIC.to_vec());
        out.u16(VERSION);
        write_context(&mut out, self.context);
        for value in &self.lot.a_keys {
            out.fp2(*value)?;
        }
        for value in &self.lot.b_keys {
            out.fp2(*value)?;
        }
        out.finish(C41_MATERIALIZED_VERIFIER_LOT_MAX_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload = checked_payload(bytes, C41_MATERIALIZED_VERIFIER_LOT_MAX_BYTES)?;
        let mut input = Reader { bytes: payload, offset: 0 };
        if input.take(8)? != VERIFIER_LOT_MAGIC || input.u16()? != VERSION {
            return Err(C41PartyBundleError::new("wrong C41SC1 verifier-lot header"));
        }
        let context = read_context(&mut input)?;
        let cells = usize::try_from(context.cells)
            .map_err(|_| C41PartyBundleError::new("C41SC1 verifier-lot cells exceed usize"))?;
        let a_keys = (0..cells).map(|_| input.fp2()).collect::<Result<Vec<_>>>()?;
        let b_keys = (0..cells).map(|_| input.fp2()).collect::<Result<Vec<_>>>()?;
        input.finish()?;
        let artifact = Self { context, lot: C41SetupVerifierLot { a_keys, b_keys } };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn decode_reader(reader: impl Read) -> Result<Self> {
        Self::decode(&bounded_read(reader, C41_MATERIALIZED_VERIFIER_LOT_MAX_BYTES)?)
    }

    fn validate(&self) -> Result<()> {
        self.context.validate()?;
        let cells = self.context.cells as usize;
        if self.lot.a_keys.len() != cells || self.lot.b_keys.len() != cells {
            return Err(C41PartyBundleError::new("C41SC1 verifier-lot census differs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C41ResponseStatement {
    pub prefill_tokens: u32,
    pub tokens: Vec<u32>,
    pub chunk_rows: Vec<u32>,
}

impl C41ResponseStatement {
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key("volta-zk/c4.1/response-statement/v1");
        hasher.update(&u64::from(self.prefill_tokens).to_le_bytes());
        hasher.update(&(self.tokens.len() as u64).to_le_bytes());
        for token in &self.tokens {
            hasher.update(&token.to_le_bytes());
        }
        hasher.update(&(self.chunk_rows.len() as u64).to_le_bytes());
        for rows in &self.chunk_rows {
            hasher.update(&u64::from(*rows).to_le_bytes());
        }
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Writer(STATEMENT_MAGIC.to_vec());
        out.u16(VERSION);
        out.u32(self.prefill_tokens)?;
        out.u32(self.tokens.len() as u32)?;
        out.u32(self.chunk_rows.len() as u32)?;
        for token in &self.tokens {
            out.u32(*token)?;
        }
        for rows in &self.chunk_rows {
            out.u32(*rows)?;
        }
        out.finish(MAX_STATEMENT_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload = checked_payload(bytes, MAX_STATEMENT_BYTES)?;
        let mut input = Reader { bytes: payload, offset: 0 };
        if input.take(8)? != STATEMENT_MAGIC || input.u16()? != VERSION {
            return Err(C41PartyBundleError::new("wrong C4.1 statement header"));
        }
        let prefill_tokens = input.u32()?;
        let token_len = input.u32()? as usize;
        let chunks = input.u32()? as usize;
        if token_len > 1024 || chunks > 128 {
            return Err(C41PartyBundleError::new("C4.1 statement count exceeds cap"));
        }
        let tokens = (0..token_len).map(|_| input.u32()).collect::<Result<Vec<_>>>()?;
        let chunk_rows = (0..chunks).map(|_| input.u32()).collect::<Result<Vec<_>>>()?;
        input.finish()?;
        let statement = Self { prefill_tokens, tokens, chunk_rows };
        statement.validate()?;
        if statement.encode()? != bytes {
            return Err(C41PartyBundleError::new("noncanonical C4.1 response statement"));
        }
        Ok(statement)
    }

    pub fn decode_reader(reader: impl Read) -> Result<Self> {
        Self::decode(&bounded_read(reader, MAX_STATEMENT_BYTES)?)
    }

    fn validate(&self) -> Result<()> {
        let rows = self.chunk_rows.iter().try_fold(u64::from(self.prefill_tokens), |sum, rows| {
            if *rows == 0 {
                None
            } else {
                sum.checked_add(u64::from(*rows))
            }
        });
        if self.prefill_tokens == 0
            || self.tokens.is_empty()
            || self.chunk_rows.is_empty()
            || self.tokens.iter().any(|token| *token >= 50_257)
            || rows != Some(self.tokens.len() as u64)
        {
            return Err(C41PartyBundleError::new("invalid C4.1 response statement"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C41ModelSetupArtifact {
    pub model_binding_digest: [u8; 32],
    pub quantization_digest: [u8; 32],
    pub pcs_parameter_digest: [u8; 32],
    pub verifier_model_digest: [u8; 32],
    pub weights_root: [u8; 32],
    pub embed_root: [u8; 32],
}

impl C41ModelSetupArtifact {
    pub fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Writer(MODEL_SETUP_MAGIC.to_vec());
        out.u16(VERSION);
        for digest in [
            self.model_binding_digest,
            self.quantization_digest,
            self.pcs_parameter_digest,
            self.verifier_model_digest,
            self.weights_root,
            self.embed_root,
        ] {
            out.bytes(&digest);
        }
        out.finish(512)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload = checked_payload(bytes, 512)?;
        let mut input = Reader { bytes: payload, offset: 0 };
        if input.take(8)? != MODEL_SETUP_MAGIC || input.u16()? != VERSION {
            return Err(C41PartyBundleError::new("wrong C4.1 model-setup header"));
        }
        let mut digest =
            || -> Result<[u8; 32]> { Ok(input.take(32)?.try_into().expect("fixed digest width")) };
        let artifact = Self {
            model_binding_digest: digest()?,
            quantization_digest: digest()?,
            pcs_parameter_digest: digest()?,
            verifier_model_digest: digest()?,
            weights_root: digest()?,
            embed_root: digest()?,
        };
        input.finish()?;
        artifact.validate()?;
        if artifact.encode()? != bytes {
            return Err(C41PartyBundleError::new("noncanonical C4.1 model setup"));
        }
        Ok(artifact)
    }

    fn validate(self) -> Result<()> {
        if [
            self.model_binding_digest,
            self.quantization_digest,
            self.pcs_parameter_digest,
            self.verifier_model_digest,
            self.weights_root,
            self.embed_root,
        ]
        .contains(&[0; 32])
        {
            return Err(C41PartyBundleError::new("zero C4.1 model-setup identity"));
        }
        Ok(())
    }
}

fn checked_rows(rows: usize) -> Result<()> {
    if rows == 0 || rows > MAX_SEED_ROWS || rows.checked_mul(1024).is_none() {
        Err(C41PartyBundleError::new("invalid C4.1 typed seed row count"))
    } else {
        Ok(())
    }
}

fn write_context(out: &mut Writer, context: C41PartySetupContext) {
    for digest in [
        context.model_binding_digest,
        context.setup_digest,
        context.quantization_digest,
        context.connection_binding,
        context.public_incidence_seed,
        context.pcs_parameter_digest,
    ] {
        out.bytes(&digest);
    }
    for value in [
        context.response_index,
        context.cells,
        context.first_global_bit,
        context.ordinary_sub_corrs,
        context.ordinary_full_corrs,
    ] {
        out.u64(value);
    }
}

fn read_context(input: &mut Reader<'_>) -> Result<C41PartySetupContext> {
    let mut digest =
        || -> Result<[u8; 32]> { Ok(input.take(32)?.try_into().expect("fixed digest width")) };
    let context = C41PartySetupContext {
        model_binding_digest: digest()?,
        setup_digest: digest()?,
        quantization_digest: digest()?,
        connection_binding: digest()?,
        public_incidence_seed: digest()?,
        pcs_parameter_digest: digest()?,
        response_index: input.u64()?,
        cells: input.u64()?,
        first_global_bit: input.u64()?,
        ordinary_sub_corrs: input.u64()?,
        ordinary_full_corrs: input.u64()?,
    };
    context.validate()?;
    Ok(context)
}

fn bounded_read(mut reader: impl Read, cap: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| C41PartyBundleError::new(error.to_string()))?;
    if bytes.len() as u64 > cap {
        return Err(C41PartyBundleError::new("C4.1 artifact exceeds byte cap"));
    }
    Ok(bytes)
}

fn checked_payload(bytes: &[u8], cap: u64) -> Result<&[u8]> {
    if bytes.len() < DIGEST_BYTES || bytes.len() as u64 > cap {
        return Err(C41PartyBundleError::new("C4.1 artifact length differs"));
    }
    let split = bytes.len() - DIGEST_BYTES;
    if bytes[split..] != *blake3::hash(&bytes[..split]).as_bytes() {
        return Err(C41PartyBundleError::new("C4.1 artifact digest differs"));
    }
    Ok(&bytes[..split])
}

struct Writer(Vec<u8>);

impl Writer {
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) -> Result<()> {
        self.bytes(&value.to_le_bytes());
        Ok(())
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn fp(&mut self, value: Fp) -> Result<()> {
        if value.value() >= P {
            return Err(C41PartyBundleError::new("noncanonical C4.1 field element"));
        }
        self.u64(value.value());
        Ok(())
    }

    fn fp2(&mut self, value: Fp2) -> Result<()> {
        self.fp(value.c0)?;
        self.fp(value.c1)
    }

    fn finish(mut self, cap: u64) -> Result<Vec<u8>> {
        let digest = blake3::hash(&self.0);
        self.bytes(digest.as_bytes());
        if self.0.len() as u64 > cap {
            return Err(C41PartyBundleError::new("C4.1 artifact exceeds byte cap"));
        }
        Ok(self.0)
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
            .ok_or_else(|| C41PartyBundleError::new("truncated C4.1 party artifact"))?;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed u16 width")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed u32 width")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed u64 width")))
    }

    fn fp(&mut self) -> Result<Fp> {
        let value = self.u64()?;
        if value >= P {
            return Err(C41PartyBundleError::new("noncanonical C4.1 field element"));
        }
        Ok(Fp::new(value))
    }

    fn fp2(&mut self) -> Result<Fp2> {
        Ok(Fp2::new(self.fp()?, self.fp()?))
    }

    fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(C41PartyBundleError::new("trailing C4.1 party artifact bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> C41PartySetupContext {
        C41PartySetupContext {
            model_binding_digest: [1; 32],
            setup_digest: [2; 32],
            quantization_digest: [3; 32],
            connection_binding: [4; 32],
            public_incidence_seed: [5; 32],
            pcs_parameter_digest: [6; 32],
            response_index: 7,
            cells: 8,
            first_global_bit: 0,
            ordinary_sub_corrs: 2,
            ordinary_full_corrs: 1,
        }
    }

    #[test]
    fn party_bundles_are_strict_and_role_separated() {
        let provider = C41ProviderBundle {
            context: context(),
            correlations: ProverPcgPool {
                subs: vec![
                    SubVole { r: Fp::ONE, m: Fp2::ONE },
                    SubVole { r: Fp::ZERO, m: Fp2::new(Fp::new(2), Fp::new(3)) },
                ],
                fulls: vec![FullVole { x: Fp2::ONE, m: Fp2::ZERO }],
            },
            typed: C41TypedSetupProverState {
                bits: (0..1024).map(|index| (index & 1) as u8).collect(),
                tags: vec![Fp2::ONE; 1024],
                rows: 1,
            },
        };
        let encoded = provider.encode().unwrap();
        let decoded = C41ProviderBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.context, provider.context);
        assert_eq!(decoded.typed, provider.typed);
        assert_eq!(decoded.correlations.subs.len(), 2);
        assert!(C41VerifierBundle::decode(&encoded).is_err());

        let verifier = C41VerifierBundle {
            context: context(),
            delta: Fp2::new(Fp::new(9), Fp::new(10)),
            correlations: VerifierPcgPool {
                sub_keys: vec![Fp2::ONE, Fp2::ZERO],
                full_keys: vec![Fp2::ONE],
            },
            typed: C41TypedSetupVerifierState { keys: vec![Fp2::ONE; 1024], rows: 1 },
            verifier_model: vec![1, 2, 3],
        };
        let verifier_encoded = verifier.encode().unwrap();
        let decoded = C41VerifierBundle::decode(&verifier_encoded).unwrap();
        assert_eq!(decoded.context, verifier.context);
        assert_eq!(decoded.typed, verifier.typed);
        assert_eq!(decoded.verifier_model, verifier.verifier_model);
        assert!(C41ProviderBundle::decode(&verifier_encoded).is_err());

        let lot = C41MaterializedVerifierLot {
            context: context(),
            lot: C41SetupVerifierLot { a_keys: vec![Fp2::ONE; 16], b_keys: vec![Fp2::ZERO; 16] },
        };
        let mut lot_context = lot.context;
        lot_context.cells = 16;
        let lot = C41MaterializedVerifierLot { context: lot_context, ..lot };
        let lot_encoded = lot.encode().unwrap();
        let decoded = C41MaterializedVerifierLot::decode(&lot_encoded).unwrap();
        assert_eq!(decoded.context, lot.context);
        assert_eq!(decoded.lot, lot.lot);
        let mut tampered = lot_encoded;
        tampered[250] ^= 1;
        assert!(C41MaterializedVerifierLot::decode(&tampered).is_err());

        let mut tampered = verifier_encoded;
        tampered[40] ^= 1;
        assert!(C41VerifierBundle::decode(&tampered).is_err());
    }

    #[test]
    fn public_statement_and_model_setup_are_canonical() {
        let statement = C41ResponseStatement {
            prefill_tokens: 3,
            tokens: vec![1, 2, 3, 4, 5],
            chunk_rows: vec![2],
        };
        let bytes = statement.encode().unwrap();
        assert_eq!(C41ResponseStatement::decode(&bytes).unwrap(), statement);
        let mut changed = statement.clone();
        changed.tokens[0] += 1;
        assert_ne!(statement.digest().unwrap(), changed.digest().unwrap());

        let setup = C41ModelSetupArtifact {
            model_binding_digest: [1; 32],
            quantization_digest: [2; 32],
            pcs_parameter_digest: [3; 32],
            verifier_model_digest: [4; 32],
            weights_root: [5; 32],
            embed_root: [6; 32],
        };
        let bytes = setup.encode().unwrap();
        assert_eq!(C41ModelSetupArtifact::decode(&bytes).unwrap(), setup);
    }
}
