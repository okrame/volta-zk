//! C6 Δ-residual certificate, durable client head, and one-time attempt slots.
//!
//! This module is deliberately independent of the historical response proof
//! structs.  C4/T1 remains byte-for-byte available while C6 gets a canonical
//! full-duplex deployment boundary:
//!
//! * all client-received setup bytes are counted;
//! * a certificate binds one accepted predecessor and one compact cache head;
//! * the final designated-verifier check is one amplified affine Δ-residual
//!   event over two independent MAC coordinates;
//! * client acceptance is a durable compare-and-swap;
//! * provider attempts atomically reserve both one-time ranges in an
//!   append-only, burn-before-use slot journal.
//!
//! Cryptographic proof generation lives behind the C6 wrapper module.  The
//! codec here never accepts a placeholder proof in a production certificate:
//! proof bytes and every commitment/digest must be nonempty and bound by the
//! canonical statement digest.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use volta_field::{Fp, Fp2, P};

pub type C6Digest = [u8; 32];

pub const C6_CERTIFICATE_VERSION: u16 = 2;
pub const C6_CLIENT_STATE_VERSION: u16 = 3;
pub const C6_SLOT_JOURNAL_VERSION: u16 = 3;
pub const C6_LIGERO_QUERIES: u16 = 121;
pub const C6_MAX_CONTEXT: u32 = 1_024;
pub const C6_ACCEPTANCE_CREDITS: u16 = 17;
pub const C6_ABORT_RETRY_CREDITS: u16 = 4;
pub const C6_MAC_COORDINATES: usize = 2;
pub const C6_BASELINE_RAW_CORRELATIONS: u64 = 5_235_692;
pub const C6_TERMINAL_ONE_RAW_CAPACITY: u64 = 110_918_718;
pub const C6_FASE_D_SETUP_BYTES: u64 = 38_371_465;
pub const C6_PAIRED_PCG_SETUP_BYTES: u64 = C6_MAC_COORDINATES as u64 * C6_FASE_D_SETUP_BYTES;
pub const C6_SETUP_CAP_BYTES: u64 = 150_000_000;
pub const C6_RETAINED_Q121_BASELINE_BYTES: u64 = 29_176_632;
pub const C6_NEW_PAYLOAD_BUDGET_BYTES: u64 = 5_823_368;
pub const C6_PI_FINAL_CAP_BYTES: u64 = 4_500_000;
pub const C6_ROOFLINE_PI_FINAL_MAX_BYTES: u64 = 4_409_824;
/// Compatibility name for the cap historically described as the “final
/// proof”.  The normative cap includes its C6 framing and public claims.
pub const C6_FINAL_PROOF_CAP_BYTES: u64 = C6_PI_FINAL_CAP_BYTES;
pub const C6_RESPONSE_CAP_BYTES: u64 = 35_000_000;

const CERT_MAGIC: &[u8] = b"VOLTA-C6-CERT-v2\0";
const SETUP_MAGIC: &[u8] = b"VOLTA-C6-SETUP-v2";
const STATE_MAGIC: &[u8] = b"VOLTA-C6-STATE-v3";
const SLOT_MAGIC: &[u8] = b"VOLTA-C6-SLOT-v3\0";
const MAX_CLIENT_PARAMETER_BYTES: usize = (C6_SETUP_CAP_BYTES - C6_PAIRED_PCG_SETUP_BYTES) as usize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6Error(String);

impl C6Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6Error {}

type C6Result<T> = Result<T, C6Error>;

fn io_error(context: &str, path: &Path, error: std::io::Error) -> C6Error {
    C6Error::new(format!("{context} {}: {error}", path.display()))
}

fn is_nonzero(value: &C6Digest) -> bool {
    *value != [0; 32]
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> C6Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn hex_digest(value: C6Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn with_capacity(capacity: usize) -> Self {
        Self { bytes: Vec::with_capacity(capacity) }
    }

    fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
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

    fn digest(&mut self, value: &C6Digest) {
        self.raw(value);
    }

    fn fp2(&mut self, value: Fp2) {
        self.u64(value.c0.value());
        self.u64(value.c1.value());
    }

    fn blob(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.raw(value);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> C6Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| C6Error::new("C6 decoder offset overflow"))?;
        if end > self.bytes.len() {
            return Err(C6Error::new("truncated C6 encoding"));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn magic(&mut self, expected: &[u8]) -> C6Result<()> {
        if self.take(expected.len())? != expected {
            return Err(C6Error::new("wrong C6 magic/version domain"));
        }
        Ok(())
    }

    fn u8(&mut self) -> C6Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> C6Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }

    fn u32(&mut self) -> C6Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }

    fn u64(&mut self) -> C6Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }

    fn digest(&mut self) -> C6Result<C6Digest> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }

    fn fp2(&mut self) -> C6Result<Fp2> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(C6Error::new("noncanonical Goldilocks element in C6 encoding"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn blob(&mut self, max_len: usize) -> C6Result<Vec<u8>> {
        let len = usize::try_from(self.u64()?)
            .map_err(|_| C6Error::new("C6 blob length exceeds usize"))?;
        if len > max_len {
            return Err(C6Error::new("C6 blob exceeds its canonical cap"));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> C6Result<()> {
        if self.offset != self.bytes.len() {
            return Err(C6Error::new("trailing bytes in canonical C6 encoding"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheHead {
    pub epoch: u64,
    pub cache_len: u32,
    pub cache_root: C6Digest,
    /// Digest of the transition statement that produced this root.  Genesis
    /// uses zero; later heads must use a nonzero statement digest.
    pub producer_transition_digest: C6Digest,
}

impl C6CacheHead {
    fn encode_into(self, out: &mut Encoder) {
        out.u64(self.epoch);
        out.u32(self.cache_len);
        out.digest(&self.cache_root);
        out.digest(&self.producer_transition_digest);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            epoch: input.u64()?,
            cache_len: input.u32()?,
            cache_root: input.digest()?,
            producer_transition_digest: input.digest()?,
        })
    }

    pub fn validate(self) -> C6Result<()> {
        if self.cache_len > C6_MAX_CONTEXT || !is_nonzero(&self.cache_root) {
            return Err(C6Error::new("invalid C6 cache head geometry/root"));
        }
        if self.epoch == 0 {
            if self.producer_transition_digest != [0; 32] {
                return Err(C6Error::new("C6 genesis head has a producer digest"));
            }
        } else if !is_nonzero(&self.producer_transition_digest) {
            return Err(C6Error::new("non-genesis C6 head lacks a producer digest"));
        }
        Ok(())
    }

    pub fn digest(self) -> C6Digest {
        let mut encoded = Encoder::with_capacity(76);
        self.encode_into(&mut encoded);
        hash_parts(b"volta-zk/c6/cache-head/v1", &[&encoded.finish()])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CorrelationRange {
    pub stage: u32,
    pub start: u64,
    pub count: u64,
}

impl C6CorrelationRange {
    fn encode_into(self, out: &mut Encoder) {
        out.u32(self.stage);
        out.u64(self.start);
        out.u64(self.count);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self { stage: input.u32()?, start: input.u64()?, count: input.u64()? })
    }

    fn end(self) -> C6Result<u64> {
        self.start
            .checked_add(self.count)
            .ok_or_else(|| C6Error::new("C6 correlation range overflows"))
    }

    pub fn validate(self) -> C6Result<()> {
        if self.stage != 1 || self.count == 0 || self.end()? > C6_TERMINAL_ONE_RAW_CAPACITY {
            return Err(C6Error::new("invalid C6 production correlation range"));
        }
        Ok(())
    }

    pub fn overlaps(self, other: Self) -> C6Result<bool> {
        Ok(self.stage == other.stage && self.start < other.end()? && other.start < self.end()?)
    }
}

/// One indivisible reservation from each independent C6 MAC tape.
///
/// Coordinate zero names the ordinary T1 tape and coordinate one names the
/// residual-only tape.  Their offsets may differ, but an attempt consumes
/// the same raw count from both and no public API represents a half-pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PairedCorrelationRanges {
    pub coordinates: [C6CorrelationRange; C6_MAC_COORDINATES],
}

impl C6PairedCorrelationRanges {
    fn encode_into(self, out: &mut Encoder) {
        for range in self.coordinates {
            range.encode_into(out);
        }
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            coordinates: [
                C6CorrelationRange::decode_from(input)?,
                C6CorrelationRange::decode_from(input)?,
            ],
        })
    }

    pub fn validate(self) -> C6Result<()> {
        for range in self.coordinates {
            range.validate()?;
        }
        if self.coordinates[0].count != self.coordinates[1].count {
            return Err(C6Error::new("C6 paired correlation ranges consume different raw counts"));
        }
        Ok(())
    }

    pub fn raw_count(self) -> C6Result<u64> {
        self.validate()?;
        Ok(self.coordinates[0].count)
    }

    pub fn overlaps(self, other: Self) -> C6Result<bool> {
        self.validate()?;
        other.validate()?;
        for coordinate in 0..C6_MAC_COORDINATES {
            if self.coordinates[coordinate].overlaps(other.coordinates[coordinate])? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6Workload {
    pub prompt_tokens: u32,
    pub decode_tokens: u32,
    pub old_context: u32,
    pub new_context: u32,
}

impl C6Workload {
    fn encode_into(self, out: &mut Encoder) {
        out.u32(self.prompt_tokens);
        out.u32(self.decode_tokens);
        out.u32(self.old_context);
        out.u32(self.new_context);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            prompt_tokens: input.u32()?,
            decode_tokens: input.u32()?,
            old_context: input.u32()?,
            new_context: input.u32()?,
        })
    }

    pub fn validate(self) -> C6Result<()> {
        let appended = self
            .prompt_tokens
            .checked_add(self.decode_tokens)
            .ok_or_else(|| C6Error::new("C6 workload token count overflow"))?;
        if appended == 0
            || self.old_context.checked_add(appended) != Some(self.new_context)
            || self.new_context > C6_MAX_CONTEXT
        {
            return Err(C6Error::new("invalid C6 workload/cache-length transition"));
        }
        Ok(())
    }

    pub fn digest(self) -> C6Digest {
        let mut encoded = Encoder::with_capacity(16);
        self.encode_into(&mut encoded);
        hash_parts(b"volta-zk/c6/workload/v1", &[&encoded.finish()])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ClientAttempt {
    pub slot: u32,
    pub nonce: C6Digest,
    pub setup_manifest_digest: C6Digest,
    pub old_head_digest: C6Digest,
    pub predecessor_certificate_digest: C6Digest,
    pub correlation_ranges: C6PairedCorrelationRanges,
    pub workload: C6Workload,
}

impl C6ClientAttempt {
    fn encode_into(self, out: &mut Encoder) {
        out.u32(self.slot);
        out.digest(&self.nonce);
        out.digest(&self.setup_manifest_digest);
        out.digest(&self.old_head_digest);
        out.digest(&self.predecessor_certificate_digest);
        self.correlation_ranges.encode_into(out);
        self.workload.encode_into(out);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            slot: input.u32()?,
            nonce: input.digest()?,
            setup_manifest_digest: input.digest()?,
            old_head_digest: input.digest()?,
            predecessor_certificate_digest: input.digest()?,
            correlation_ranges: C6PairedCorrelationRanges::decode_from(input)?,
            workload: C6Workload::decode_from(input)?,
        })
    }

    fn validate_for(self, state: C6ClientState) -> C6Result<()> {
        if !is_nonzero(&self.nonce)
            || self.setup_manifest_digest != state.setup_manifest_digest
            || !is_nonzero(&self.old_head_digest)
            || self.old_head_digest != state.head.digest()
            || self.predecessor_certificate_digest != state.accepted_certificate_digest
            || self.workload.old_context != state.head.cache_len
        {
            return Err(C6Error::new("C6 pending attempt does not bind the current durable head"));
        }
        self.correlation_ranges.validate()?;
        self.workload.validate()
    }

    fn matches_certificate(self, certificate: &C6FinalCertificate) -> C6Result<()> {
        if certificate.slot != self.slot
            || certificate.nonce != self.nonce
            || certificate.setup_manifest_digest != self.setup_manifest_digest
            || certificate.old_head.digest() != self.old_head_digest
            || certificate.predecessor_certificate_digest != self.predecessor_certificate_digest
            || certificate.correlation_ranges != self.correlation_ranges
            || certificate.workload != self.workload
        {
            return Err(C6Error::new("C6 certificate does not match the client-reserved attempt"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6WrapperCommitments {
    pub prequery_statement_digest: C6Digest,
    pub correction_roots: [C6Digest; C6_MAC_COORDINATES],
    pub weights_u_root: C6Digest,
    pub embed_u_root: C6Digest,
    pub cache_witness_root: C6Digest,
}

impl C6WrapperCommitments {
    fn encode_into(self, out: &mut Encoder) {
        out.digest(&self.prequery_statement_digest);
        for root in self.correction_roots {
            out.digest(&root);
        }
        out.digest(&self.weights_u_root);
        out.digest(&self.embed_u_root);
        out.digest(&self.cache_witness_root);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            prequery_statement_digest: input.digest()?,
            correction_roots: [input.digest()?, input.digest()?],
            weights_u_root: input.digest()?,
            embed_u_root: input.digest()?,
            cache_witness_root: input.digest()?,
        })
    }

    fn validate(self) -> C6Result<()> {
        let values = [
            self.prequery_statement_digest,
            self.correction_roots[0],
            self.correction_roots[1],
            self.weights_u_root,
            self.embed_u_root,
            self.cache_witness_root,
        ];
        if values.iter().any(|value| !is_nonzero(value)) {
            return Err(C6Error::new("zero C6 wrapper commitment"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6DeltaResidual {
    /// Wrapper-certified dot product of hidden direct corrections.
    pub correction_rlc: Fp2,
    /// Matching retained prover-tag/public-message aggregate.
    pub public_tag_rlc: Fp2,
}

impl C6DeltaResidual {
    fn encode_into(self, out: &mut Encoder) {
        out.fp2(self.correction_rlc);
        out.fp2(self.public_tag_rlc);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self { correction_rlc: input.fp2()?, public_tag_rlc: input.fp2()? })
    }

    /// Final client-only designated-verifier equation.
    pub fn verify(self, base_key_rlc: Fp2, delta: Fp2) -> bool {
        base_key_rlc + delta * self.correction_rlc == self.public_tag_rlc
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6PairedDeltaResidual {
    pub coordinates: [C6DeltaResidual; C6_MAC_COORDINATES],
}

impl C6PairedDeltaResidual {
    fn encode_into(self, out: &mut Encoder) {
        for residual in self.coordinates {
            residual.encode_into(out);
        }
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            coordinates: [
                C6DeltaResidual::decode_from(input)?,
                C6DeltaResidual::decode_from(input)?,
            ],
        })
    }

    /// Both independent designated-verifier coordinates must accept.
    pub fn verify(
        self,
        base_key_rlcs: [Fp2; C6_MAC_COORDINATES],
        deltas: [Fp2; C6_MAC_COORDINATES],
    ) -> bool {
        (0..C6_MAC_COORDINATES).all(|coordinate| {
            self.coordinates[coordinate].verify(base_key_rlcs[coordinate], deltas[coordinate])
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6FinalCertificate {
    pub version: u16,
    pub ligero_queries: u16,
    pub protocol_digest: C6Digest,
    pub model_digest: C6Digest,
    pub params_digest: C6Digest,
    pub setup_manifest_digest: C6Digest,
    pub connection_id: C6Digest,
    pub nonce: C6Digest,
    pub slot: u32,
    pub correlation_ranges: C6PairedCorrelationRanges,
    pub predecessor_certificate_digest: C6Digest,
    pub old_head: C6CacheHead,
    pub new_head: C6CacheHead,
    pub workload: C6Workload,
    pub public_output_digest: C6Digest,
    pub wrapper: C6WrapperCommitments,
    pub residual: C6PairedDeltaResidual,
    pub retained_transcript_digest: C6Digest,
    pub wrapper_proof_digest: C6Digest,
    pub transition_statement_digest: C6Digest,
    pub retained_transcript: Vec<u8>,
    pub wrapper_proof: Vec<u8>,
}

impl C6FinalCertificate {
    fn encode_statement(&self) -> Vec<u8> {
        let mut out = Encoder::with_capacity(768);
        out.raw(b"VOLTA-C6-STATEMENT-v2");
        out.u16(self.version);
        out.u16(self.ligero_queries);
        out.digest(&self.protocol_digest);
        out.digest(&self.model_digest);
        out.digest(&self.params_digest);
        out.digest(&self.setup_manifest_digest);
        out.digest(&self.connection_id);
        out.digest(&self.nonce);
        out.u32(self.slot);
        self.correlation_ranges.encode_into(&mut out);
        out.digest(&self.predecessor_certificate_digest);
        self.old_head.encode_into(&mut out);
        out.u64(self.new_head.epoch);
        out.u32(self.new_head.cache_len);
        out.digest(&self.new_head.cache_root);
        self.workload.encode_into(&mut out);
        out.digest(&self.public_output_digest);
        self.wrapper.encode_into(&mut out);
        self.residual.encode_into(&mut out);
        out.digest(&self.retained_transcript_digest);
        out.digest(&self.wrapper_proof_digest);
        out.finish()
    }

    pub fn compute_transition_statement_digest(&self) -> C6Digest {
        hash_parts(b"volta-zk/c6/transition-statement/v2", &[&self.encode_statement()])
    }

    fn encode_unchecked(&self) -> Vec<u8> {
        let capacity = 768usize
            .saturating_add(self.retained_transcript.len())
            .saturating_add(self.wrapper_proof.len());
        let mut out = Encoder::with_capacity(capacity);
        out.raw(CERT_MAGIC);
        out.u16(self.version);
        out.u16(self.ligero_queries);
        out.digest(&self.protocol_digest);
        out.digest(&self.model_digest);
        out.digest(&self.params_digest);
        out.digest(&self.setup_manifest_digest);
        out.digest(&self.connection_id);
        out.digest(&self.nonce);
        out.u32(self.slot);
        self.correlation_ranges.encode_into(&mut out);
        out.digest(&self.predecessor_certificate_digest);
        self.old_head.encode_into(&mut out);
        self.new_head.encode_into(&mut out);
        self.workload.encode_into(&mut out);
        out.digest(&self.public_output_digest);
        self.wrapper.encode_into(&mut out);
        self.residual.encode_into(&mut out);
        out.digest(&self.retained_transcript_digest);
        out.digest(&self.wrapper_proof_digest);
        out.digest(&self.transition_statement_digest);
        out.blob(&self.retained_transcript);
        out.blob(&self.wrapper_proof);
        out.finish()
    }

    pub fn encode(&self) -> C6Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    pub fn decode(bytes: &[u8]) -> C6Result<Self> {
        if bytes.len() as u64 > C6_RESPONSE_CAP_BYTES {
            return Err(C6Error::new("C6 certificate exceeds response cap"));
        }
        let mut input = Decoder::new(bytes);
        input.magic(CERT_MAGIC)?;
        let certificate = Self {
            version: input.u16()?,
            ligero_queries: input.u16()?,
            protocol_digest: input.digest()?,
            model_digest: input.digest()?,
            params_digest: input.digest()?,
            setup_manifest_digest: input.digest()?,
            connection_id: input.digest()?,
            nonce: input.digest()?,
            slot: input.u32()?,
            correlation_ranges: C6PairedCorrelationRanges::decode_from(&mut input)?,
            predecessor_certificate_digest: input.digest()?,
            old_head: C6CacheHead::decode_from(&mut input)?,
            new_head: C6CacheHead::decode_from(&mut input)?,
            workload: C6Workload::decode_from(&mut input)?,
            public_output_digest: input.digest()?,
            wrapper: C6WrapperCommitments::decode_from(&mut input)?,
            residual: C6PairedDeltaResidual::decode_from(&mut input)?,
            retained_transcript_digest: input.digest()?,
            wrapper_proof_digest: input.digest()?,
            transition_statement_digest: input.digest()?,
            retained_transcript: input.blob(C6_RETAINED_Q121_BASELINE_BYTES as usize)?,
            wrapper_proof: input.blob(C6_FINAL_PROOF_CAP_BYTES as usize)?,
        };
        input.finish()?;
        certificate.validate()?;
        if certificate.encode_unchecked() != bytes {
            return Err(C6Error::new("noncanonical C6 certificate encoding"));
        }
        Ok(certificate)
    }

    pub fn digest(&self) -> C6Result<C6Digest> {
        Ok(hash_parts(b"volta-zk/c6/final-certificate/v2", &[&self.encode()?]))
    }

    pub fn encoded_len(&self) -> C6Result<u64> {
        Ok(self.encode()?.len() as u64)
    }

    pub fn new_payload_bytes(&self) -> C6Result<u64> {
        self.encoded_len()?
            .checked_sub(self.retained_transcript.len() as u64)
            .ok_or_else(|| C6Error::new("C6 payload accounting underflow"))
    }

    pub fn validate(&self) -> C6Result<()> {
        if self.version != C6_CERTIFICATE_VERSION || self.ligero_queries != C6_LIGERO_QUERIES {
            return Err(C6Error::new("wrong C6 certificate version/Q"));
        }
        let required = [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.setup_manifest_digest,
            self.connection_id,
            self.nonce,
            self.public_output_digest,
            self.retained_transcript_digest,
            self.wrapper_proof_digest,
            self.transition_statement_digest,
        ];
        if required.iter().any(|value| !is_nonzero(value)) {
            return Err(C6Error::new("zero required C6 certificate digest"));
        }
        self.old_head.validate()?;
        self.new_head.validate()?;
        if (self.old_head.epoch == 0 && self.predecessor_certificate_digest != [0; 32])
            || (self.old_head.epoch != 0 && !is_nonzero(&self.predecessor_certificate_digest))
        {
            return Err(C6Error::new(
                "C6 predecessor certificate digest does not match genesis status",
            ));
        }
        self.correlation_ranges.validate()?;
        self.workload.validate()?;
        self.wrapper.validate()?;
        if self.new_head.epoch
            != self
                .old_head
                .epoch
                .checked_add(1)
                .ok_or_else(|| C6Error::new("C6 cache epoch overflow"))?
            || self.workload.old_context != self.old_head.cache_len
            || self.workload.new_context != self.new_head.cache_len
        {
            return Err(C6Error::new("C6 certificate does not advance its exact predecessor"));
        }
        if self.retained_transcript.is_empty()
            || self.retained_transcript.len() as u64 > C6_RETAINED_Q121_BASELINE_BYTES
            || self.wrapper_proof.is_empty()
            || self.wrapper_proof.len() as u64 > C6_FINAL_PROOF_CAP_BYTES
        {
            return Err(C6Error::new("C6 retained/proof payload violates its cap"));
        }
        let retained_digest =
            hash_parts(b"volta-zk/c6/retained-transcript/v1", &[&self.retained_transcript]);
        let proof_digest = hash_parts(b"volta-zk/c6/wrapper-proof/v1", &[&self.wrapper_proof]);
        if retained_digest != self.retained_transcript_digest
            || proof_digest != self.wrapper_proof_digest
        {
            return Err(C6Error::new("C6 payload digest mismatch"));
        }
        let statement_digest = self.compute_transition_statement_digest();
        if statement_digest != self.transition_statement_digest
            || self.new_head.producer_transition_digest != statement_digest
        {
            return Err(C6Error::new("C6 transition/head statement digest mismatch"));
        }
        let encoded_len = self.encode_unchecked().len() as u64;
        let new_payload = encoded_len
            .checked_sub(self.retained_transcript.len() as u64)
            .ok_or_else(|| C6Error::new("C6 payload accounting underflow"))?;
        if encoded_len > C6_RESPONSE_CAP_BYTES
            || new_payload > C6_NEW_PAYLOAD_BUDGET_BYTES
            || new_payload > C6_ROOFLINE_PI_FINAL_MAX_BYTES
            || new_payload > C6_PI_FINAL_CAP_BYTES
        {
            return Err(C6Error::new("C6 complete/new-payload wire cap exceeded"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6MacTapeManifest {
    pub tape_id: C6Digest,
    pub raw_capacity: u64,
    pub baseline_raw_correlations: u64,
    pub first_exchange_bytes: u64,
}

impl C6MacTapeManifest {
    fn encode_into(self, out: &mut Encoder) {
        out.digest(&self.tape_id);
        out.u64(self.raw_capacity);
        out.u64(self.baseline_raw_correlations);
        out.u64(self.first_exchange_bytes);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            tape_id: input.digest()?,
            raw_capacity: input.u64()?,
            baseline_raw_correlations: input.u64()?,
            first_exchange_bytes: input.u64()?,
        })
    }

    fn validate(self) -> C6Result<()> {
        if !is_nonzero(&self.tape_id)
            || self.raw_capacity != C6_TERMINAL_ONE_RAW_CAPACITY
            || self.baseline_raw_correlations != C6_BASELINE_RAW_CORRELATIONS
            || self.first_exchange_bytes != C6_FASE_D_SETUP_BYTES
        {
            return Err(C6Error::new("C6 MAC-tape manifest differs from the frozen profile"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SetupManifest {
    pub version: u16,
    pub ligero_queries: u16,
    pub protocol_digest: C6Digest,
    pub model_digest: C6Digest,
    pub params_digest: C6Digest,
    pub connection_id: C6Digest,
    pub max_context: u32,
    pub acceptance_credits: u16,
    pub abort_retry_credits: u16,
    /// Coordinate zero is the ordinary T1 tape; coordinate one is the
    /// independent residual-only tape.
    pub mac_tapes: [C6MacTapeManifest; C6_MAC_COORDINATES],
    /// Transparent verifier tables actually received by the client.
    pub client_parameters: Vec<u8>,
    /// Separate from the full `params_digest`, which may also bind
    /// provider-only model-global tables.
    pub client_parameters_digest: C6Digest,
}

impl C6SetupManifest {
    fn encode_unchecked(&self) -> Vec<u8> {
        let mut out = Encoder::with_capacity(320 + self.client_parameters.len());
        out.raw(SETUP_MAGIC);
        out.u16(self.version);
        out.u16(self.ligero_queries);
        out.digest(&self.protocol_digest);
        out.digest(&self.model_digest);
        out.digest(&self.params_digest);
        out.digest(&self.connection_id);
        out.u32(self.max_context);
        out.u16(self.acceptance_credits);
        out.u16(self.abort_retry_credits);
        for tape in self.mac_tapes {
            tape.encode_into(&mut out);
        }
        out.digest(&self.client_parameters_digest);
        out.blob(&self.client_parameters);
        out.finish()
    }

    pub fn encode(&self) -> C6Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    pub fn decode(bytes: &[u8]) -> C6Result<Self> {
        let mut input = Decoder::new(bytes);
        input.magic(SETUP_MAGIC)?;
        let manifest = Self {
            version: input.u16()?,
            ligero_queries: input.u16()?,
            protocol_digest: input.digest()?,
            model_digest: input.digest()?,
            params_digest: input.digest()?,
            connection_id: input.digest()?,
            max_context: input.u32()?,
            acceptance_credits: input.u16()?,
            abort_retry_credits: input.u16()?,
            mac_tapes: [
                C6MacTapeManifest::decode_from(&mut input)?,
                C6MacTapeManifest::decode_from(&mut input)?,
            ],
            client_parameters_digest: input.digest()?,
            client_parameters: input.blob(MAX_CLIENT_PARAMETER_BYTES)?,
        };
        input.finish()?;
        manifest.validate()?;
        if manifest.encode_unchecked() != bytes {
            return Err(C6Error::new("noncanonical C6 setup encoding"));
        }
        Ok(manifest)
    }

    pub fn digest(&self) -> C6Result<C6Digest> {
        Ok(hash_parts(b"volta-zk/c6/setup-manifest/v2", &[&self.encode()?]))
    }

    pub fn paired_pcg_setup_bytes(&self) -> C6Result<u64> {
        self.mac_tapes.iter().try_fold(0u64, |total, tape| {
            total
                .checked_add(tape.first_exchange_bytes)
                .ok_or_else(|| C6Error::new("C6 paired PCG setup byte count overflow"))
        })
    }

    pub fn first_exchange_bytes(&self) -> C6Result<u64> {
        self.validate()?;
        self.first_exchange_bytes_unchecked()
    }

    pub fn validate(&self) -> C6Result<()> {
        if self.version != C6_CERTIFICATE_VERSION
            || self.ligero_queries != C6_LIGERO_QUERIES
            || self.max_context != C6_MAX_CONTEXT
            || self.acceptance_credits != C6_ACCEPTANCE_CREDITS
            || self.abort_retry_credits != C6_ABORT_RETRY_CREDITS
        {
            return Err(C6Error::new("C6 setup profile differs from the frozen profile"));
        }
        if [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.connection_id,
            self.client_parameters_digest,
        ]
        .iter()
        .any(|value| !is_nonzero(value))
        {
            return Err(C6Error::new("zero C6 setup identity digest"));
        }
        for tape in self.mac_tapes {
            tape.validate()?;
        }
        if self.mac_tapes[0].tape_id == self.mac_tapes[1].tape_id {
            return Err(C6Error::new("C6 setup reuses one MAC tape identity"));
        }
        let client_parameters_digest =
            hash_parts(b"volta-zk/c6/client-parameters/v2", &[&self.client_parameters]);
        if client_parameters_digest != self.client_parameters_digest {
            return Err(C6Error::new("C6 client-parameter digest mismatch"));
        }
        let slots = u64::from(self.acceptance_credits) + u64::from(self.abort_retry_credits);
        for tape in self.mac_tapes {
            if slots
                .checked_mul(tape.baseline_raw_correlations)
                .is_none_or(|needed| needed > tape.raw_capacity)
            {
                return Err(C6Error::new("C6 setup lacks 17+4 baseline ranges in both tapes"));
            }
        }
        if self.paired_pcg_setup_bytes()? != C6_PAIRED_PCG_SETUP_BYTES {
            return Err(C6Error::new("C6 paired PCG setup byte count mismatch"));
        }
        if self.first_exchange_bytes_unchecked()? > C6_SETUP_CAP_BYTES {
            return Err(C6Error::new("C6 first exchange exceeds 150 MB"));
        }
        Ok(())
    }

    fn first_exchange_bytes_unchecked(&self) -> C6Result<u64> {
        self.paired_pcg_setup_bytes()?
            .checked_add(self.encode_unchecked().len() as u64)
            .ok_or_else(|| C6Error::new("C6 setup byte count overflow"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6ClientState {
    pub protocol_digest: C6Digest,
    pub model_digest: C6Digest,
    pub params_digest: C6Digest,
    pub setup_manifest_digest: C6Digest,
    pub connection_id: C6Digest,
    pub head: C6CacheHead,
    /// Separate from `head.producer_transition_digest` to avoid a
    /// self-referential final-certificate hash.
    pub accepted_certificate_digest: C6Digest,
    /// The next client-issued slot.  It advances when an attempt is durably
    /// reserved, including attempts that later abort, so provider-controlled
    /// replay cannot move the slot high-water mark backwards.
    pub next_slot: u32,
    /// Client-owned raw high-water offsets for the two ordered MAC tapes.
    /// Ranges are allocated contiguously and both offsets advance durably
    /// before an attempt may be exposed to the provider.
    pub raw_high_water: [u64; C6_MAC_COORDINATES],
    /// At most one response may be in flight for the single-writer V1
    /// client.  This binds acceptance to a client-issued nonce/paired-range/
    /// workload rather than trusting a provider-created certificate request.
    pub pending_attempt: Option<C6ClientAttempt>,
}

impl C6ClientState {
    pub fn genesis_from_setup(setup: &C6SetupManifest, cache_root: C6Digest) -> C6Result<Self> {
        setup.validate()?;
        if !is_nonzero(&cache_root) {
            return Err(C6Error::new("zero C6 genesis cache root"));
        }
        let state = Self {
            protocol_digest: setup.protocol_digest,
            model_digest: setup.model_digest,
            params_digest: setup.params_digest,
            setup_manifest_digest: setup.digest()?,
            connection_id: setup.connection_id,
            head: C6CacheHead {
                epoch: 0,
                cache_len: 0,
                cache_root,
                producer_transition_digest: [0; 32],
            },
            accepted_certificate_digest: [0; 32],
            next_slot: 0,
            raw_high_water: [0; C6_MAC_COORDINATES],
            pending_attempt: None,
        };
        state.validate()?;
        Ok(state)
    }

    fn encode_unchecked(self) -> Vec<u8> {
        let mut out = Encoder::with_capacity(320);
        out.raw(STATE_MAGIC);
        out.u16(C6_CLIENT_STATE_VERSION);
        out.digest(&self.protocol_digest);
        out.digest(&self.model_digest);
        out.digest(&self.params_digest);
        out.digest(&self.setup_manifest_digest);
        out.digest(&self.connection_id);
        self.head.encode_into(&mut out);
        out.digest(&self.accepted_certificate_digest);
        out.u32(self.next_slot);
        for high_water in self.raw_high_water {
            out.u64(high_water);
        }
        match self.pending_attempt {
            Some(attempt) => {
                out.u8(1);
                attempt.encode_into(&mut out);
            }
            None => out.u8(0),
        }
        out.finish()
    }

    pub fn encode(self) -> C6Result<Vec<u8>> {
        self.validate()?;
        Ok(self.encode_unchecked())
    }

    pub fn decode(bytes: &[u8]) -> C6Result<Self> {
        let mut input = Decoder::new(bytes);
        input.magic(STATE_MAGIC)?;
        if input.u16()? != C6_CLIENT_STATE_VERSION {
            return Err(C6Error::new("wrong C6 client-state version"));
        }
        let state = Self {
            protocol_digest: input.digest()?,
            model_digest: input.digest()?,
            params_digest: input.digest()?,
            setup_manifest_digest: input.digest()?,
            connection_id: input.digest()?,
            head: C6CacheHead::decode_from(&mut input)?,
            accepted_certificate_digest: input.digest()?,
            next_slot: input.u32()?,
            raw_high_water: [input.u64()?, input.u64()?],
            pending_attempt: match input.u8()? {
                0 => None,
                1 => Some(C6ClientAttempt::decode_from(&mut input)?),
                _ => return Err(C6Error::new("noncanonical C6 pending-attempt flag")),
            },
        };
        input.finish()?;
        state.validate()?;
        if state.encode_unchecked() != bytes {
            return Err(C6Error::new("noncanonical C6 client-state encoding"));
        }
        Ok(state)
    }

    pub fn validate(self) -> C6Result<()> {
        self.head.validate()?;
        if [
            self.protocol_digest,
            self.model_digest,
            self.params_digest,
            self.setup_manifest_digest,
            self.connection_id,
        ]
        .iter()
        .any(|value| !is_nonzero(value))
        {
            return Err(C6Error::new("zero C6 client-state identity"));
        }
        if self.head.epoch == 0 {
            if self.accepted_certificate_digest != [0; 32] {
                return Err(C6Error::new("C6 genesis state has an accepted certificate"));
            }
        } else if !is_nonzero(&self.accepted_certificate_digest) {
            return Err(C6Error::new("advanced C6 state lacks certificate digest"));
        }
        if self.head.epoch > u64::from(self.next_slot)
            || self.raw_high_water.iter().any(|offset| *offset > C6_TERMINAL_ONE_RAW_CAPACITY)
        {
            return Err(C6Error::new("invalid C6 client high-water state"));
        }
        if let Some(attempt) = self.pending_attempt {
            if attempt.slot.checked_add(1) != Some(self.next_slot) {
                return Err(C6Error::new("C6 pending attempt is not the slot high-water mark"));
            }
            attempt.validate_for(self)?;
            for coordinate in 0..C6_MAC_COORDINATES {
                if attempt.correlation_ranges.coordinates[coordinate].end()?
                    != self.raw_high_water[coordinate]
                {
                    return Err(C6Error::new(
                        "C6 pending range does not end at the durable raw high-water mark",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn digest(self) -> C6Result<C6Digest> {
        Ok(hash_parts(b"volta-zk/c6/client-state/v2", &[&self.encode()?]))
    }

    pub fn accepts(self, certificate: &C6FinalCertificate) -> C6Result<Self> {
        self.validate()?;
        certificate.validate()?;
        let attempt = self
            .pending_attempt
            .ok_or_else(|| C6Error::new("C6 certificate has no client-reserved attempt"))?;
        attempt.matches_certificate(certificate)?;
        if certificate.protocol_digest != self.protocol_digest
            || certificate.model_digest != self.model_digest
            || certificate.params_digest != self.params_digest
            || certificate.setup_manifest_digest != self.setup_manifest_digest
            || certificate.connection_id != self.connection_id
            || certificate.old_head != self.head
            || certificate.predecessor_certificate_digest != self.accepted_certificate_digest
        {
            return Err(C6Error::new("C6 certificate is not a child of the durable head"));
        }
        let next = Self {
            protocol_digest: self.protocol_digest,
            model_digest: self.model_digest,
            params_digest: self.params_digest,
            setup_manifest_digest: self.setup_manifest_digest,
            connection_id: self.connection_id,
            head: certificate.new_head,
            accepted_certificate_digest: certificate.digest()?,
            next_slot: self.next_slot,
            raw_high_water: self.raw_high_water,
            pending_attempt: None,
        };
        next.validate()?;
        Ok(next)
    }

    pub fn reserve_attempt(
        self,
        nonce_entropy: C6Digest,
        raw_correlation_count: u64,
        workload: C6Workload,
    ) -> C6Result<(Self, C6ClientAttempt)> {
        self.validate()?;
        if self.pending_attempt.is_some() {
            return Err(C6Error::new("C6 single-writer client already has a pending attempt"));
        }
        if raw_correlation_count == 0 {
            return Err(C6Error::new("C6 attempt cannot reserve zero raw correlations"));
        }
        workload.validate()?;
        if workload.old_context != self.head.cache_len {
            return Err(C6Error::new(
                "C6 requested workload does not start at the durable cache head",
            ));
        }
        let next_slot = self
            .next_slot
            .checked_add(1)
            .ok_or_else(|| C6Error::new("C6 client slot high-water overflow"))?;
        let nonce = hash_parts(
            b"volta-zk/c6/client-nonce/v2",
            &[
                &self.connection_id,
                &self.next_slot.to_le_bytes(),
                &self.head.digest(),
                &nonce_entropy,
            ],
        );
        let coordinates = [
            C6CorrelationRange {
                stage: 1,
                start: self.raw_high_water[0],
                count: raw_correlation_count,
            },
            C6CorrelationRange {
                stage: 1,
                start: self.raw_high_water[1],
                count: raw_correlation_count,
            },
        ];
        let mut raw_high_water = self.raw_high_water;
        for coordinate in 0..C6_MAC_COORDINATES {
            raw_high_water[coordinate] = coordinates[coordinate].end()?;
            if raw_high_water[coordinate] > C6_TERMINAL_ONE_RAW_CAPACITY {
                return Err(C6Error::new("C6 client correlation capacity exhausted"));
            }
        }
        let correlation_ranges = C6PairedCorrelationRanges { coordinates };
        correlation_ranges.validate()?;
        let attempt = C6ClientAttempt {
            slot: self.next_slot,
            nonce,
            setup_manifest_digest: self.setup_manifest_digest,
            old_head_digest: self.head.digest(),
            predecessor_certificate_digest: self.accepted_certificate_digest,
            correlation_ranges,
            workload,
        };
        let next = Self { next_slot, raw_high_water, pending_attempt: Some(attempt), ..self };
        next.validate()?;
        Ok((next, attempt))
    }

    pub fn aborts_pending(self) -> C6Result<Self> {
        self.validate()?;
        if self.pending_attempt.is_none() {
            return Err(C6Error::new("C6 client has no pending attempt to abort"));
        }
        let next = Self { pending_attempt: None, ..self };
        next.validate()?;
        Ok(next)
    }

    pub fn is_idempotent_retransmission(self, certificate: &C6FinalCertificate) -> C6Result<bool> {
        self.validate()?;
        certificate.validate()?;
        Ok(certificate.connection_id == self.connection_id
            && certificate.protocol_digest == self.protocol_digest
            && certificate.model_digest == self.model_digest
            && certificate.params_digest == self.params_digest
            && certificate.setup_manifest_digest == self.setup_manifest_digest
            && certificate.new_head == self.head
            && certificate.digest()? == self.accepted_certificate_digest)
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn sync_directory(path: &Path) -> C6Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("cannot sync C6 directory", path, error))
}

fn next_path(path: &Path) -> C6Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| C6Error::new("C6 state path has no filename"))?;
    let mut next = name.to_os_string();
    next.push(".c6-next");
    Ok(path.with_file_name(next))
}

fn valid_client_state_transition(current: C6ClientState, next: C6ClientState) -> C6Result<()> {
    current.validate()?;
    next.validate()?;
    if current.protocol_digest != next.protocol_digest
        || current.model_digest != next.model_digest
        || current.params_digest != next.params_digest
        || current.setup_manifest_digest != next.setup_manifest_digest
        || current.connection_id != next.connection_id
    {
        return Err(C6Error::new("C6 atomic state transition changes connection identity"));
    }

    let reserved_ranges_advance_exactly = next.pending_attempt.is_some_and(|attempt| {
        (0..C6_MAC_COORDINATES).all(|coordinate| {
            let range = attempt.correlation_ranges.coordinates[coordinate];
            range.start == current.raw_high_water[coordinate]
                && range.end().ok() == Some(next.raw_high_water[coordinate])
        })
    });
    let reserves_attempt = current.pending_attempt.is_none()
        && next.pending_attempt.is_some()
        && next.head == current.head
        && next.accepted_certificate_digest == current.accepted_certificate_digest
        && current.next_slot.checked_add(1) == Some(next.next_slot)
        && reserved_ranges_advance_exactly;
    let aborts_attempt = current.pending_attempt.is_some()
        && next.pending_attempt.is_none()
        && next.head == current.head
        && next.accepted_certificate_digest == current.accepted_certificate_digest
        && next.next_slot == current.next_slot
        && next.raw_high_water == current.raw_high_water;
    let accepted_workload_end = current.pending_attempt.map(|attempt| attempt.workload.new_context);
    let accepts_certificate = current.pending_attempt.is_some()
        && next.pending_attempt.is_none()
        && next.next_slot == current.next_slot
        && current.head.epoch.checked_add(1).is_some_and(|epoch| next.head.epoch == epoch)
        && accepted_workload_end == Some(next.head.cache_len)
        && is_nonzero(&next.accepted_certificate_digest)
        && next.accepted_certificate_digest != current.accepted_certificate_digest
        && next.raw_high_water == current.raw_high_water;
    if !reserves_attempt && !aborts_attempt && !accepts_certificate {
        return Err(C6Error::new("invalid C6 atomic client-state transition"));
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_mode(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_private_mode(_options: &mut OpenOptions) {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtomicFault {
    None,
    AfterTempCreate,
    AfterTempWrite,
    AfterTempSync,
    AfterRename,
}

fn recover_atomic_state(path: &Path) -> C6Result<()> {
    let temp = next_path(path)?;
    if !temp.exists() {
        return Ok(());
    }
    if path.exists() {
        let current_bytes = fs::read(path)
            .map_err(|error| io_error("cannot read current C6 state", path, error))?;
        let current = C6ClientState::decode(&current_bytes)?;
        let temp_bytes = fs::read(&temp)
            .map_err(|error| io_error("cannot read C6 recovery temp", &temp, error))?;
        if let Ok(next) = C6ClientState::decode(&temp_bytes) {
            valid_client_state_transition(current, next)?;
        }
        // Rename did not occur.  Recovery deliberately selects the complete
        // old state.  A torn temp image is necessarily pre-rename and may be
        // discarded because the old image is still complete.
        fs::remove_file(&temp)
            .map_err(|error| io_error("cannot remove recovered C6 temp", &temp, error))?;
        sync_directory(parent_directory(path))?;
    } else {
        let temp_bytes = fs::read(&temp)
            .map_err(|error| io_error("cannot read C6 recovery temp", &temp, error))?;
        C6ClientState::decode(&temp_bytes)?;
        fs::rename(&temp, path)
            .map_err(|error| io_error("cannot install recovered C6 state", path, error))?;
        sync_directory(parent_directory(path))?;
    }
    Ok(())
}

fn atomic_replace_state(path: &Path, state: C6ClientState, fault: AtomicFault) -> C6Result<()> {
    state.validate()?;
    recover_atomic_state(path)?;
    let temp = next_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_mode(&mut options);
    let mut file = options
        .open(&temp)
        .map_err(|error| io_error("cannot create C6 temp state", &temp, error))?;
    if fault == AtomicFault::AfterTempCreate {
        return Err(C6Error::new("injected C6 crash after temp create"));
    }
    file.write_all(&state.encode()?)
        .map_err(|error| io_error("cannot write C6 temp state", &temp, error))?;
    if fault == AtomicFault::AfterTempWrite {
        return Err(C6Error::new("injected C6 crash after temp write"));
    }
    file.sync_all().map_err(|error| io_error("cannot sync C6 temp state", &temp, error))?;
    if fault == AtomicFault::AfterTempSync {
        return Err(C6Error::new("injected C6 crash after temp sync"));
    }
    fs::rename(&temp, path)
        .map_err(|error| io_error("cannot atomically replace C6 state", path, error))?;
    if fault == AtomicFault::AfterRename {
        return Err(C6Error::new("injected C6 crash after rename"));
    }
    sync_directory(parent_directory(path))
}

#[derive(Clone, Debug)]
pub struct C6ClientStore {
    path: PathBuf,
}

impl C6ClientStore {
    pub fn initialize(path: impl AsRef<Path>, state: C6ClientState) -> C6Result<Self> {
        state.validate()?;
        let path = path.as_ref().to_path_buf();
        let parent = parent_directory(&path);
        fs::create_dir_all(parent)
            .map_err(|error| io_error("cannot create C6 client-state directory", parent, error))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_mode(&mut options);
        let mut file = options
            .open(&path)
            .map_err(|error| io_error("cannot initialize C6 client state", &path, error))?;
        file.write_all(&state.encode()?)
            .map_err(|error| io_error("cannot write initial C6 client state", &path, error))?;
        file.sync_all()
            .map_err(|error| io_error("cannot sync initial C6 client state", &path, error))?;
        sync_directory(parent)?;
        Ok(Self { path })
    }

    pub fn open(path: impl AsRef<Path>) -> C6Result<Self> {
        let path = path.as_ref().to_path_buf();
        recover_atomic_state(&path)?;
        let store = Self { path };
        store.load()?;
        Ok(store)
    }

    pub fn load(&self) -> C6Result<C6ClientState> {
        let bytes = fs::read(&self.path)
            .map_err(|error| io_error("cannot read C6 client state", &self.path, error))?;
        C6ClientState::decode(&bytes)
    }

    pub fn accept(
        &self,
        expected: C6ClientState,
        certificate: &C6FinalCertificate,
    ) -> C6Result<C6ClientState> {
        self.accept_with_fault(expected, certificate, AtomicFault::None)
    }

    fn accept_with_fault(
        &self,
        expected: C6ClientState,
        certificate: &C6FinalCertificate,
        fault: AtomicFault,
    ) -> C6Result<C6ClientState> {
        let current = self.load()?;
        if current != expected {
            return Err(C6Error::new("C6 client compare-and-swap predecessor mismatch"));
        }
        let next = current.accepts(certificate)?;
        valid_client_state_transition(current, next)?;
        atomic_replace_state(&self.path, next, fault)?;
        Ok(next)
    }

    pub fn reserve_attempt(
        &self,
        expected: C6ClientState,
        nonce_entropy: C6Digest,
        raw_correlation_count: u64,
        workload: C6Workload,
    ) -> C6Result<(C6ClientState, C6ClientAttempt)> {
        self.reserve_attempt_with_fault(
            expected,
            nonce_entropy,
            raw_correlation_count,
            workload,
            AtomicFault::None,
        )
    }

    fn reserve_attempt_with_fault(
        &self,
        expected: C6ClientState,
        nonce_entropy: C6Digest,
        raw_correlation_count: u64,
        workload: C6Workload,
        fault: AtomicFault,
    ) -> C6Result<(C6ClientState, C6ClientAttempt)> {
        let current = self.load()?;
        if current != expected {
            return Err(C6Error::new("C6 client compare-and-swap predecessor mismatch"));
        }
        let (next, attempt) =
            current.reserve_attempt(nonce_entropy, raw_correlation_count, workload)?;
        valid_client_state_transition(current, next)?;
        atomic_replace_state(&self.path, next, fault)?;
        Ok((next, attempt))
    }

    pub fn abort_attempt(&self, expected: C6ClientState) -> C6Result<C6ClientState> {
        let current = self.load()?;
        if current != expected {
            return Err(C6Error::new("C6 client compare-and-swap predecessor mismatch"));
        }
        let next = current.aborts_pending()?;
        valid_client_state_transition(current, next)?;
        atomic_replace_state(&self.path, next, AtomicFault::None)?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6SlotReservation {
    pub connection_id: C6Digest,
    pub setup_manifest_digest: C6Digest,
    pub slot: u32,
    pub nonce: C6Digest,
    pub old_head_digest: C6Digest,
    pub predecessor_certificate_digest: C6Digest,
    pub correlation_ranges: C6PairedCorrelationRanges,
    pub workload: C6Workload,
}

impl C6SlotReservation {
    pub fn from_client_attempt(
        connection_id: C6Digest,
        attempt: C6ClientAttempt,
    ) -> C6Result<Self> {
        let reservation = Self {
            connection_id,
            setup_manifest_digest: attempt.setup_manifest_digest,
            slot: attempt.slot,
            nonce: attempt.nonce,
            old_head_digest: attempt.old_head_digest,
            predecessor_certificate_digest: attempt.predecessor_certificate_digest,
            correlation_ranges: attempt.correlation_ranges,
            workload: attempt.workload,
        };
        reservation.validate()?;
        Ok(reservation)
    }

    fn encode_into(self, out: &mut Encoder) {
        out.digest(&self.connection_id);
        out.digest(&self.setup_manifest_digest);
        out.u32(self.slot);
        out.digest(&self.nonce);
        out.digest(&self.old_head_digest);
        out.digest(&self.predecessor_certificate_digest);
        self.correlation_ranges.encode_into(out);
        self.workload.encode_into(out);
    }

    fn decode_from(input: &mut Decoder<'_>) -> C6Result<Self> {
        Ok(Self {
            connection_id: input.digest()?,
            setup_manifest_digest: input.digest()?,
            slot: input.u32()?,
            nonce: input.digest()?,
            old_head_digest: input.digest()?,
            predecessor_certificate_digest: input.digest()?,
            correlation_ranges: C6PairedCorrelationRanges::decode_from(input)?,
            workload: C6Workload::decode_from(input)?,
        })
    }

    pub fn validate(self) -> C6Result<()> {
        if !is_nonzero(&self.connection_id)
            || !is_nonzero(&self.setup_manifest_digest)
            || !is_nonzero(&self.nonce)
            || !is_nonzero(&self.old_head_digest)
        {
            return Err(C6Error::new("zero identity in C6 slot reservation"));
        }
        self.correlation_ranges.validate()?;
        self.workload.validate()
    }

    pub fn digest(self) -> C6Result<C6Digest> {
        self.validate()?;
        let mut encoded = Encoder::with_capacity(256);
        self.encode_into(&mut encoded);
        Ok(hash_parts(b"volta-zk/c6/slot-reservation/v2", &[&encoded.finish()]))
    }

    fn matches_certificate(self, certificate: &C6FinalCertificate) -> C6Result<()> {
        certificate.validate()?;
        if certificate.connection_id != self.connection_id
            || certificate.setup_manifest_digest != self.setup_manifest_digest
            || certificate.slot != self.slot
            || certificate.nonce != self.nonce
            || certificate.old_head.digest() != self.old_head_digest
            || certificate.predecessor_certificate_digest != self.predecessor_certificate_digest
            || certificate.correlation_ranges != self.correlation_ranges
            || certificate.workload != self.workload
        {
            return Err(C6Error::new("C6 certificate does not match its durable slot reservation"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6SlotStatus {
    Reserved,
    InFlight,
    Produced,
    Accepted,
    Burned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct C6SlotRecord {
    reservation: C6SlotReservation,
    status: C6SlotStatus,
    produced_certificate_digest: Option<C6Digest>,
    produced_certificate_len: Option<u64>,
    transition_count: u64,
    last_checksum: C6Digest,
}

const SLOT_TRANSITION_IN_FLIGHT: u8 = 1;
const SLOT_TRANSITION_PRODUCED: u8 = 2;
const SLOT_TRANSITION_ACCEPTED: u8 = 3;
const SLOT_TRANSITION_BURNED: u8 = 4;

fn slot_header(reservation: C6SlotReservation) -> C6Result<(Vec<u8>, C6Digest)> {
    reservation.validate()?;
    let mut encoded = Encoder::with_capacity(192);
    encoded.raw(SLOT_MAGIC);
    encoded.u16(C6_SLOT_JOURNAL_VERSION);
    reservation.encode_into(&mut encoded);
    let body = encoded.finish();
    let checksum = hash_parts(b"volta-zk/c6/slot-header/v2", &[&body]);
    let mut header = body;
    header.extend_from_slice(&checksum);
    Ok((header, checksum))
}

fn slot_transition_bytes(
    reservation_digest: C6Digest,
    previous_checksum: C6Digest,
    sequence: u64,
    marker: u8,
    certificate_digest: C6Digest,
    certificate_len: u64,
) -> (Vec<u8>, C6Digest) {
    let mut body = Encoder::with_capacity(49);
    body.u8(marker);
    body.u64(sequence);
    body.digest(&certificate_digest);
    body.u64(certificate_len);
    let body = body.finish();
    let checksum = hash_parts(
        b"volta-zk/c6/slot-transition/v2",
        &[&reservation_digest, &previous_checksum, &body],
    );
    let mut record = body;
    record.extend_from_slice(&checksum);
    (record, checksum)
}

fn parse_slot_journal(bytes: &[u8]) -> C6Result<C6SlotRecord> {
    let mut input = Decoder::new(bytes);
    input.magic(SLOT_MAGIC)?;
    if input.u16()? != C6_SLOT_JOURNAL_VERSION {
        return Err(C6Error::new("wrong C6 slot-journal version"));
    }
    let reservation = C6SlotReservation::decode_from(&mut input)?;
    reservation.validate()?;
    let header_body_end = input.offset;
    let header_checksum = input.digest()?;
    let expected_header_checksum =
        hash_parts(b"volta-zk/c6/slot-header/v2", &[&bytes[..header_body_end]]);
    if header_checksum != expected_header_checksum {
        return Err(C6Error::new("C6 slot header checksum mismatch"));
    }

    let reservation_digest = reservation.digest()?;
    let mut record = C6SlotRecord {
        reservation,
        status: C6SlotStatus::Reserved,
        produced_certificate_digest: None,
        produced_certificate_len: None,
        transition_count: 0,
        last_checksum: header_checksum,
    };
    while input.offset != bytes.len() {
        let marker = input.u8()?;
        let sequence = input.u64()?;
        let certificate_digest = input.digest()?;
        let certificate_len = input.u64()?;
        let checksum = input.digest()?;
        if sequence != record.transition_count + 1 {
            return Err(C6Error::new("non-sequential C6 slot transition"));
        }
        let (_, expected_checksum) = slot_transition_bytes(
            reservation_digest,
            record.last_checksum,
            sequence,
            marker,
            certificate_digest,
            certificate_len,
        );
        if checksum != expected_checksum {
            return Err(C6Error::new("C6 slot transition checksum mismatch"));
        }

        record.status = match (record.status, marker) {
            (C6SlotStatus::Reserved, SLOT_TRANSITION_IN_FLIGHT)
                if certificate_digest == [0; 32] && certificate_len == 0 =>
            {
                C6SlotStatus::InFlight
            }
            (C6SlotStatus::InFlight, SLOT_TRANSITION_PRODUCED)
                if is_nonzero(&certificate_digest) && certificate_len > 0 =>
            {
                record.produced_certificate_digest = Some(certificate_digest);
                record.produced_certificate_len = Some(certificate_len);
                C6SlotStatus::Produced
            }
            (C6SlotStatus::Produced, SLOT_TRANSITION_ACCEPTED)
                if Some(certificate_digest) == record.produced_certificate_digest
                    && certificate_len == 0 =>
            {
                C6SlotStatus::Accepted
            }
            (C6SlotStatus::Reserved | C6SlotStatus::InFlight, SLOT_TRANSITION_BURNED)
                if certificate_digest == [0; 32] && certificate_len == 0 =>
            {
                C6SlotStatus::Burned
            }
            _ => return Err(C6Error::new("illegal C6 slot transition")),
        };
        record.transition_count = sequence;
        record.last_checksum = checksum;
    }
    Ok(record)
}

fn slot_id(reservation: C6SlotReservation) -> C6Digest {
    hash_parts(
        b"volta-zk/c6/slot-journal-name/v2",
        &[&reservation.connection_id, &reservation.slot.to_le_bytes()],
    )
}

fn slot_path(root: &Path, connection_id: C6Digest, slot: u32) -> PathBuf {
    let id =
        hash_parts(b"volta-zk/c6/slot-journal-name/v2", &[&connection_id, &slot.to_le_bytes()]);
    root.join(format!("{}.slot", hex_digest(id)))
}

fn certificate_path(journal_path: &Path) -> PathBuf {
    journal_path.with_extension("certificate")
}

fn read_slot_record(path: &Path) -> C6Result<C6SlotRecord> {
    let bytes =
        fs::read(path).map_err(|error| io_error("cannot read C6 slot journal", path, error))?;
    parse_slot_journal(&bytes)
}

fn slot_records(root: &Path) -> C6Result<Vec<(PathBuf, C6SlotRecord)>> {
    let mut records = Vec::new();
    let entries = fs::read_dir(root)
        .map_err(|error| io_error("cannot scan C6 slot directory", root, error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("cannot read C6 slot-directory entry", root, error))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("slot") {
            continue;
        }
        records.push((path.clone(), read_slot_record(&path)?));
    }
    Ok(records)
}

#[derive(Clone, Debug)]
pub struct C6SlotStore {
    root: PathBuf,
}

impl C6SlotStore {
    pub fn open(root: impl AsRef<Path>) -> C6Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)
            .map_err(|error| io_error("cannot create C6 slot directory", &root, error))?;
        // Fail closed on every malformed historical journal before allowing a
        // fresh reservation.  No journal is ever repaired or overwritten.
        slot_records(&root)?;
        Ok(Self { root })
    }

    pub fn reserve(&self, reservation: C6SlotReservation) -> C6Result<C6SlotHandle> {
        reservation.validate()?;
        for (_, prior) in slot_records(&self.root)? {
            if prior.reservation.connection_id == reservation.connection_id
                && prior.reservation.nonce == reservation.nonce
            {
                return Err(C6Error::new("reused C6 slot nonce"));
            }
            if prior.reservation.correlation_ranges.overlaps(reservation.correlation_ranges)? {
                return Err(C6Error::new(
                    "a C6 paired correlation range overlaps an existing or burned slot",
                ));
            }
            let same_predecessor = prior.reservation.connection_id == reservation.connection_id
                && prior.reservation.old_head_digest == reservation.old_head_digest
                && prior.reservation.predecessor_certificate_digest
                    == reservation.predecessor_certificate_digest;
            if same_predecessor && prior.status != C6SlotStatus::Burned {
                return Err(C6Error::new(
                    "C6 predecessor already has a live or produced child attempt",
                ));
            }
        }

        let path = slot_path(&self.root, reservation.connection_id, reservation.slot);
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| C6Error::new("invalid C6 slot path"))?;
        if stem != hex_digest(slot_id(reservation)) {
            return Err(C6Error::new("C6 slot path/domain mismatch"));
        }
        let (header, _) = slot_header(reservation)?;
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(true);
        set_private_mode(&mut options);
        let mut journal = options
            .open(&path)
            .map_err(|error| io_error("cannot reserve C6 slot", &path, error))?;
        journal
            .write_all(&header)
            .map_err(|error| io_error("cannot write C6 slot header", &path, error))?;
        journal.sync_all().map_err(|error| io_error("cannot sync C6 slot header", &path, error))?;
        sync_directory(&self.root)?;
        let record = parse_slot_journal(&header)?;
        Ok(C6SlotHandle { journal_path: path, journal, record })
    }

    pub fn open_slot(&self, connection_id: C6Digest, slot: u32) -> C6Result<C6SlotHandle> {
        let path = slot_path(&self.root, connection_id, slot);
        let mut options = OpenOptions::new();
        options.read(true).append(true);
        let journal =
            options.open(&path).map_err(|error| io_error("cannot open C6 slot", &path, error))?;
        let record = read_slot_record(&path)?;
        if record.reservation.connection_id != connection_id || record.reservation.slot != slot {
            return Err(C6Error::new("C6 slot filename/header mismatch"));
        }
        let mut handle = C6SlotHandle { journal_path: path, journal, record };
        handle.recover_orphan()?;
        Ok(handle)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotProduceFault {
    None,
    AfterCertificateSync,
}

#[derive(Debug)]
pub struct C6SlotHandle {
    journal_path: PathBuf,
    journal: File,
    record: C6SlotRecord,
}

impl C6SlotHandle {
    pub fn reservation(&self) -> C6SlotReservation {
        self.record.reservation
    }

    pub fn status(&self) -> C6SlotStatus {
        self.record.status
    }

    pub fn produced_certificate_digest(&self) -> Option<C6Digest> {
        self.record.produced_certificate_digest
    }

    fn append_transition(
        &mut self,
        marker: u8,
        certificate_digest: C6Digest,
        certificate_len: u64,
    ) -> C6Result<()> {
        let sequence = self
            .record
            .transition_count
            .checked_add(1)
            .ok_or_else(|| C6Error::new("C6 slot transition counter overflow"))?;
        let (bytes, _) = slot_transition_bytes(
            self.record.reservation.digest()?,
            self.record.last_checksum,
            sequence,
            marker,
            certificate_digest,
            certificate_len,
        );
        self.journal.write_all(&bytes).map_err(|error| {
            io_error("cannot append C6 slot transition", &self.journal_path, error)
        })?;
        self.journal.sync_all().map_err(|error| {
            io_error("cannot sync C6 slot transition", &self.journal_path, error)
        })?;
        self.record = read_slot_record(&self.journal_path)?;
        Ok(())
    }

    pub fn start(&mut self) -> C6Result<()> {
        if self.record.status != C6SlotStatus::Reserved {
            return Err(C6Error::new("C6 slot can start only once from reserved"));
        }
        // The durable marker precedes every possible correlation read.
        self.append_transition(SLOT_TRANSITION_IN_FLIGHT, [0; 32], 0)
    }

    pub fn abort(&mut self) -> C6Result<()> {
        if !matches!(self.record.status, C6SlotStatus::Reserved | C6SlotStatus::InFlight) {
            return Err(C6Error::new("only an unproduced C6 slot may be burned on abort"));
        }
        self.append_transition(SLOT_TRANSITION_BURNED, [0; 32], 0)
    }

    pub fn produce(&mut self, certificate: &C6FinalCertificate) -> C6Result<C6Digest> {
        self.produce_with_fault(certificate, SlotProduceFault::None)
    }

    fn produce_with_fault(
        &mut self,
        certificate: &C6FinalCertificate,
        fault: SlotProduceFault,
    ) -> C6Result<C6Digest> {
        self.record.reservation.matches_certificate(certificate)?;
        let bytes = certificate.encode()?;
        let digest = certificate.digest()?;

        if matches!(self.record.status, C6SlotStatus::Produced | C6SlotStatus::Accepted) {
            let stored = self.retransmit()?;
            if stored != bytes || self.record.produced_certificate_digest != Some(digest) {
                return Err(C6Error::new("alternate C6 certificate forbidden for a produced slot"));
            }
            return Ok(digest);
        }
        if self.record.status != C6SlotStatus::InFlight {
            return Err(C6Error::new("C6 certificate requires a durable in-flight slot"));
        }

        let path = certificate_path(&self.journal_path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_private_mode(&mut options);
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(&bytes)
                    .map_err(|error| io_error("cannot write C6 certificate", &path, error))?;
                file.sync_all()
                    .map_err(|error| io_error("cannot sync C6 certificate", &path, error))?;
                sync_directory(parent_directory(&path))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stored = fs::read(&path).map_err(|read_error| {
                    io_error("cannot read existing C6 certificate", &path, read_error)
                })?;
                if stored != bytes {
                    self.abort()?;
                    return Err(C6Error::new(
                        "alternate bytes found in an in-flight C6 certificate slot",
                    ));
                }
            }
            Err(error) => return Err(io_error("cannot create C6 certificate", &path, error)),
        }
        if fault == SlotProduceFault::AfterCertificateSync {
            return Err(C6Error::new("injected C6 crash after certificate sync"));
        }
        self.append_transition(SLOT_TRANSITION_PRODUCED, digest, bytes.len() as u64)?;
        Ok(digest)
    }

    pub fn retransmit(&self) -> C6Result<Vec<u8>> {
        if !matches!(self.record.status, C6SlotStatus::Produced | C6SlotStatus::Accepted) {
            return Err(C6Error::new("C6 slot has no retransmittable certificate"));
        }
        let path = certificate_path(&self.journal_path);
        let bytes = fs::read(&path)
            .map_err(|error| io_error("cannot read stored C6 certificate", &path, error))?;
        if Some(bytes.len() as u64) != self.record.produced_certificate_len {
            return Err(C6Error::new("stored C6 certificate length mismatch"));
        }
        let certificate = C6FinalCertificate::decode(&bytes)?;
        self.record.reservation.matches_certificate(&certificate)?;
        if Some(certificate.digest()?) != self.record.produced_certificate_digest {
            return Err(C6Error::new("stored C6 certificate digest mismatch"));
        }
        Ok(bytes)
    }

    pub fn acknowledge(&mut self, certificate_digest: C6Digest) -> C6Result<()> {
        if self.record.status == C6SlotStatus::Accepted
            && self.record.produced_certificate_digest == Some(certificate_digest)
        {
            return Ok(());
        }
        if self.record.status != C6SlotStatus::Produced
            || self.record.produced_certificate_digest != Some(certificate_digest)
        {
            return Err(C6Error::new("C6 ACK does not name the produced certificate"));
        }
        self.append_transition(SLOT_TRANSITION_ACCEPTED, certificate_digest, 0)
    }

    fn recover_orphan(&mut self) -> C6Result<()> {
        let path = certificate_path(&self.journal_path);
        match self.record.status {
            C6SlotStatus::Reserved => {
                if path.exists() {
                    self.abort()?;
                    return Err(C6Error::new(
                        "C6 reserved slot contains an impossible certificate orphan",
                    ));
                }
            }
            C6SlotStatus::InFlight => {
                if !path.exists() {
                    // Reopening an in-flight attempt means its live prover
                    // state was lost.  Correlations may already have been
                    // consumed, so recovery is a durable burn, never resume.
                    self.abort()?;
                    return Ok(());
                }
                let bytes = fs::read(&path)
                    .map_err(|error| io_error("cannot read orphan C6 certificate", &path, error))?;
                let certificate = match C6FinalCertificate::decode(&bytes) {
                    Ok(certificate) => certificate,
                    Err(error) => {
                        self.abort()?;
                        return Err(C6Error::new(format!(
                            "invalid orphan C6 certificate; slot burned: {error}"
                        )));
                    }
                };
                if let Err(error) = self.record.reservation.matches_certificate(&certificate) {
                    self.abort()?;
                    return Err(C6Error::new(format!(
                        "mismatched orphan C6 certificate; slot burned: {error}"
                    )));
                }
                self.append_transition(
                    SLOT_TRANSITION_PRODUCED,
                    certificate.digest()?,
                    bytes.len() as u64,
                )?;
            }
            C6SlotStatus::Produced | C6SlotStatus::Accepted => {
                self.retransmit()?;
            }
            C6SlotStatus::Burned => {
                if path.exists() {
                    return Err(C6Error::new(
                        "burned C6 slot unexpectedly retains certificate bytes",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

    fn digest(byte: u8) -> C6Digest {
        [byte; 32]
    }

    fn test_directory(label: &str) -> PathBuf {
        let id = TEST_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("volta-c6-{label}-{}-{id}", std::process::id()))
    }

    fn genesis(connection_id: C6Digest) -> C6ClientState {
        C6ClientState::genesis_from_setup(&setup_manifest(connection_id), digest(4)).unwrap()
    }

    fn range(start: u64) -> C6CorrelationRange {
        C6CorrelationRange { stage: 1, start, count: 100 }
    }

    fn paired_ranges(start: u64) -> C6PairedCorrelationRanges {
        C6PairedCorrelationRanges { coordinates: [range(start), range(start)] }
    }

    fn workload(state: C6ClientState) -> C6Workload {
        C6Workload {
            prompt_tokens: 1,
            decode_tokens: 0,
            old_context: state.head.cache_len,
            new_context: state.head.cache_len + 1,
        }
    }

    fn certificate(
        state: C6ClientState,
        slot: u32,
        nonce: C6Digest,
        correlation_ranges: C6PairedCorrelationRanges,
        retained_len: usize,
        proof_len: usize,
    ) -> C6FinalCertificate {
        let retained_transcript = vec![0xa5; retained_len];
        let wrapper_proof = vec![0x5a; proof_len];
        let workload = workload(state);
        let mut certificate = C6FinalCertificate {
            version: C6_CERTIFICATE_VERSION,
            ligero_queries: C6_LIGERO_QUERIES,
            protocol_digest: state.protocol_digest,
            model_digest: state.model_digest,
            params_digest: state.params_digest,
            setup_manifest_digest: state.setup_manifest_digest,
            connection_id: state.connection_id,
            nonce,
            slot,
            correlation_ranges,
            predecessor_certificate_digest: state.accepted_certificate_digest,
            old_head: state.head,
            new_head: C6CacheHead {
                epoch: state.head.epoch + 1,
                cache_len: workload.new_context,
                cache_root: hash_parts(
                    b"volta-zk/c6/test-cache-root",
                    &[&state.head.cache_root, &slot.to_le_bytes()],
                ),
                producer_transition_digest: [0; 32],
            },
            workload,
            public_output_digest: digest(8),
            wrapper: C6WrapperCommitments {
                prequery_statement_digest: digest(9),
                correction_roots: [digest(10), digest(14)],
                weights_u_root: digest(11),
                embed_u_root: digest(12),
                cache_witness_root: digest(13),
            },
            residual: C6PairedDeltaResidual {
                coordinates: [
                    C6DeltaResidual {
                        correction_rlc: Fp2::new(Fp::new(7), Fp::new(11)),
                        public_tag_rlc: Fp2::new(Fp::new(13), Fp::new(17)),
                    },
                    C6DeltaResidual {
                        correction_rlc: Fp2::new(Fp::new(19), Fp::new(23)),
                        public_tag_rlc: Fp2::new(Fp::new(29), Fp::new(31)),
                    },
                ],
            },
            retained_transcript_digest: hash_parts(
                b"volta-zk/c6/retained-transcript/v1",
                &[&retained_transcript],
            ),
            wrapper_proof_digest: hash_parts(b"volta-zk/c6/wrapper-proof/v1", &[&wrapper_proof]),
            transition_statement_digest: [0; 32],
            retained_transcript,
            wrapper_proof,
        };
        let statement = certificate.compute_transition_statement_digest();
        certificate.transition_statement_digest = statement;
        certificate.new_head.producer_transition_digest = statement;
        certificate
    }

    fn reservation(
        state: C6ClientState,
        slot: u32,
        nonce: C6Digest,
        correlation_ranges: C6PairedCorrelationRanges,
    ) -> C6SlotReservation {
        C6SlotReservation {
            connection_id: state.connection_id,
            setup_manifest_digest: state.setup_manifest_digest,
            slot,
            nonce,
            old_head_digest: state.head.digest(),
            predecessor_certificate_digest: state.accepted_certificate_digest,
            correlation_ranges,
            workload: workload(state),
        }
    }

    fn setup_manifest(connection_id: C6Digest) -> C6SetupManifest {
        let client_parameters = vec![0x42; 128];
        C6SetupManifest {
            version: C6_CERTIFICATE_VERSION,
            ligero_queries: C6_LIGERO_QUERIES,
            protocol_digest: digest(1),
            model_digest: digest(2),
            params_digest: digest(3),
            connection_id,
            max_context: C6_MAX_CONTEXT,
            acceptance_credits: C6_ACCEPTANCE_CREDITS,
            abort_retry_credits: C6_ABORT_RETRY_CREDITS,
            mac_tapes: [
                C6MacTapeManifest {
                    tape_id: hash_parts(b"volta-zk/c6/test-tape/ordinary", &[&connection_id]),
                    raw_capacity: C6_TERMINAL_ONE_RAW_CAPACITY,
                    baseline_raw_correlations: C6_BASELINE_RAW_CORRELATIONS,
                    first_exchange_bytes: C6_FASE_D_SETUP_BYTES,
                },
                C6MacTapeManifest {
                    tape_id: hash_parts(b"volta-zk/c6/test-tape/residual", &[&connection_id]),
                    raw_capacity: C6_TERMINAL_ONE_RAW_CAPACITY,
                    baseline_raw_correlations: C6_BASELINE_RAW_CORRELATIONS,
                    first_exchange_bytes: C6_FASE_D_SETUP_BYTES,
                },
            ],
            client_parameters_digest: hash_parts(
                b"volta-zk/c6/client-parameters/v2",
                &[&client_parameters],
            ),
            client_parameters,
        }
    }

    #[test]
    fn setup_manifest_is_canonical_and_counts_every_client_byte() {
        let manifest = setup_manifest(digest(19));
        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), 437);
        assert_eq!(
            hex_digest(manifest.digest().unwrap()),
            "c3388a149106ea3f9442199a3e711f2c137d5fa66b13f82f525c2fd833b29d75"
        );
        assert_eq!(C6SetupManifest::decode(&bytes).unwrap(), manifest);
        assert_eq!(manifest.paired_pcg_setup_bytes().unwrap(), C6_PAIRED_PCG_SETUP_BYTES);
        assert_eq!(C6_PAIRED_PCG_SETUP_BYTES, 76_742_930);
        assert_eq!(
            manifest.first_exchange_bytes().unwrap(),
            C6_PAIRED_PCG_SETUP_BYTES + bytes.len() as u64
        );
        assert_eq!(manifest.first_exchange_bytes().unwrap(), 76_743_367);
        assert!(manifest.first_exchange_bytes().unwrap() <= C6_SETUP_CAP_BYTES);
        assert_ne!(manifest.mac_tapes[0].tape_id, manifest.mac_tapes[1].tape_id);
        for tape in manifest.mac_tapes {
            assert_eq!(
                tape.raw_capacity
                    - u64::from(C6_ACCEPTANCE_CREDITS + C6_ABORT_RETRY_CREDITS)
                        * tape.baseline_raw_correlations,
                969_186
            );
        }

        let mut trailing = bytes;
        trailing.push(0);
        assert!(C6SetupManifest::decode(&trailing).is_err());

        let mut mismatched_parameters = manifest.encode().unwrap();
        *mismatched_parameters.last_mut().unwrap() ^= 1;
        assert!(C6SetupManifest::decode(&mismatched_parameters).is_err());

        let mut reused_tape = manifest;
        reused_tape.mac_tapes[1].tape_id = reused_tape.mac_tapes[0].tape_id;
        assert!(reused_tape.validate().is_err());
    }

    #[test]
    fn paired_ranges_are_indivisible_and_overlap_checks_cover_both_tapes() {
        let mut unequal = paired_ranges(0);
        unequal.coordinates[1].count -= 1;
        assert!(unequal.validate().is_err());

        let root = test_directory("paired-range-overlap");
        let store = C6SlotStore::open(&root).unwrap();
        let state = genesis(digest(18));
        let first_ranges = C6PairedCorrelationRanges { coordinates: [range(0), range(1_000)] };
        let mut first = store.reserve(reservation(state, 0, digest(17), first_ranges)).unwrap();
        assert_eq!(first.reservation().correlation_ranges, first_ranges);
        first.abort().unwrap();

        // Coordinate zero starts exactly after the old range, but coordinate
        // one overlaps a burned range.  The pair must still be rejected.
        let overlaps_only_second =
            C6PairedCorrelationRanges { coordinates: [range(100), range(1_050)] };
        assert!(store.reserve(reservation(state, 1, digest(16), overlaps_only_second)).is_err());

        let disjoint = C6PairedCorrelationRanges { coordinates: [range(100), range(1_100)] };
        let mut retry = store.reserve(reservation(state, 1, digest(15), disjoint)).unwrap();
        retry.abort().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_codec_rejects_malleability_and_noncanonical_field_elements() {
        let state = genesis(digest(20));
        let certificate = certificate(state, 0, digest(21), paired_ranges(0), 37, 41);
        let bytes = certificate.encode().unwrap();
        assert_eq!(bytes.len(), 935);
        assert_eq!(
            hex_digest(certificate.digest().unwrap()),
            "454a4482ab3329fc5991d127a812f94c1f664348c2872e358c6322f8465ca8c1"
        );
        assert_eq!(state.encode().unwrap().len(), 308);
        assert_eq!(
            hex_digest(state.digest().unwrap()),
            "87f19b92d8e7a1370cd2b15c81ac4bccaf426933b0dd6512f234e903798b6d6b"
        );
        assert_eq!(C6FinalCertificate::decode(&bytes).unwrap(), certificate);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(C6FinalCertificate::decode(&trailing).is_err());

        let mut old_magic = bytes.clone();
        let version_offset = b"VOLTA-C6-CERT-v".len();
        old_magic[version_offset] = b'1';
        assert!(C6FinalCertificate::decode(&old_magic).is_err());

        let mut noncanonical = bytes;
        let mut input = Decoder::new(&noncanonical);
        input.magic(CERT_MAGIC).unwrap();
        input.u16().unwrap();
        input.u16().unwrap();
        for _ in 0..6 {
            input.digest().unwrap();
        }
        input.u32().unwrap();
        C6PairedCorrelationRanges::decode_from(&mut input).unwrap();
        input.digest().unwrap();
        C6CacheHead::decode_from(&mut input).unwrap();
        C6CacheHead::decode_from(&mut input).unwrap();
        C6Workload::decode_from(&mut input).unwrap();
        input.digest().unwrap();
        C6WrapperCommitments::decode_from(&mut input).unwrap();
        let residual_offset = input.offset;
        noncanonical[residual_offset..residual_offset + 8].copy_from_slice(&P.to_le_bytes());
        assert!(C6FinalCertificate::decode(&noncanonical).is_err());
    }

    #[test]
    fn setup_digest_is_bound_across_client_attempt_slot_and_certificate() {
        let initial = genesis(digest(66));
        let (pending, attempt) =
            initial.reserve_attempt(digest(67), 100, workload(initial)).unwrap();
        let mut forged =
            certificate(pending, attempt.slot, attempt.nonce, attempt.correlation_ranges, 32, 32);
        forged.setup_manifest_digest = digest(68);
        let statement = forged.compute_transition_statement_digest();
        forged.transition_statement_digest = statement;
        forged.new_head.producer_transition_digest = statement;
        assert!(forged.validate().is_ok());
        assert!(pending.accepts(&forged).is_err());
        assert!(reservation(pending, attempt.slot, attempt.nonce, attempt.correlation_ranges,)
            .matches_certificate(&forged)
            .is_err());
    }

    #[test]
    fn certificate_wire_is_flat_in_cache_length_and_history() {
        let first_state = genesis(digest(22));
        let first = certificate(first_state, 0, digest(23), paired_ranges(0), 256, 512);

        let late_state = C6ClientState {
            protocol_digest: first_state.protocol_digest,
            model_digest: first_state.model_digest,
            params_digest: first_state.params_digest,
            setup_manifest_digest: first_state.setup_manifest_digest,
            connection_id: first_state.connection_id,
            head: C6CacheHead {
                epoch: 16,
                cache_len: 900,
                cache_root: digest(24),
                producer_transition_digest: digest(25),
            },
            accepted_certificate_digest: digest(26),
            next_slot: 16,
            raw_high_water: [1_600; C6_MAC_COORDINATES],
            pending_attempt: None,
        };
        let late = certificate(late_state, 16, digest(27), paired_ranges(1_600), 256, 512);
        assert_eq!(first.encoded_len().unwrap(), late.encoded_len().unwrap());
        assert_eq!(first.new_payload_bytes().unwrap(), late.new_payload_bytes().unwrap());
        assert!(late.encoded_len().unwrap() <= C6_RESPONSE_CAP_BYTES);
    }

    #[test]
    fn pi_final_cap_includes_certificate_framing_and_public_claims() {
        let state = genesis(digest(28));
        let mut certificate = certificate(state, 0, digest(29), paired_ranges(0), 1, 1);
        let framing = certificate.new_payload_bytes().unwrap() - 1;
        let maximum_proof_len = usize::try_from(C6_ROOFLINE_PI_FINAL_MAX_BYTES - framing).unwrap();
        certificate.wrapper_proof = vec![0x5a; maximum_proof_len];
        certificate.wrapper_proof_digest =
            hash_parts(b"volta-zk/c6/wrapper-proof/v1", &[&certificate.wrapper_proof]);
        let statement = certificate.compute_transition_statement_digest();
        certificate.transition_statement_digest = statement;
        certificate.new_head.producer_transition_digest = statement;
        assert_eq!(certificate.new_payload_bytes().unwrap(), C6_ROOFLINE_PI_FINAL_MAX_BYTES);
        assert_eq!(C6_RETAINED_Q121_BASELINE_BYTES + C6_ROOFLINE_PI_FINAL_MAX_BYTES, 33_586_456);

        certificate.wrapper_proof.push(0x5a);
        certificate.wrapper_proof_digest =
            hash_parts(b"volta-zk/c6/wrapper-proof/v1", &[&certificate.wrapper_proof]);
        let statement = certificate.compute_transition_statement_digest();
        certificate.transition_statement_digest = statement;
        certificate.new_head.producer_transition_digest = statement;
        assert!(certificate.validate().is_err());
    }

    #[test]
    fn paired_delta_residual_requires_both_matching_affine_identities() {
        let bases = [Fp2::new(Fp::new(3), Fp::new(5)), Fp2::new(Fp::new(19), Fp::new(23))];
        let deltas = [Fp2::new(Fp::new(7), Fp::new(11)), Fp2::new(Fp::new(29), Fp::new(31))];
        let corrections = [Fp2::new(Fp::new(13), Fp::new(17)), Fp2::new(Fp::new(37), Fp::new(41))];
        let honest = C6PairedDeltaResidual {
            coordinates: [
                C6DeltaResidual {
                    correction_rlc: corrections[0],
                    public_tag_rlc: bases[0] + deltas[0] * corrections[0],
                },
                C6DeltaResidual {
                    correction_rlc: corrections[1],
                    public_tag_rlc: bases[1] + deltas[1] * corrections[1],
                },
            ],
        };
        assert!(honest.verify(bases, deltas));
        let mut forged = honest;
        forged.coordinates[1].public_tag_rlc += Fp2::from_base(Fp::new(1));
        assert!(!forged.verify(bases, deltas));
    }

    #[test]
    fn client_store_is_cas_and_recovers_both_atomic_crash_points() {
        let root = test_directory("client-store");
        fs::create_dir_all(&root).unwrap();
        let initial = genesis(digest(30));
        let path = root.join("head.state");
        let store = C6ClientStore::initialize(&path, initial).unwrap();
        let (pending, attempt) =
            store.reserve_attempt(initial, digest(31), 100, workload(initial)).unwrap();
        let first_certificate =
            certificate(pending, attempt.slot, attempt.nonce, attempt.correlation_ranges, 32, 32);
        let next = store.accept(pending, &first_certificate).unwrap();
        assert_eq!(store.load().unwrap(), next);
        assert!(store.accept(initial, &first_certificate).is_err());
        assert!(next.is_idempotent_retransmission(&first_certificate).unwrap());

        let temp_root = root.join("after-temp");
        fs::create_dir_all(&temp_root).unwrap();
        let temp_initial = genesis(digest(32));
        let temp_path = temp_root.join("head.state");
        let temp_store = C6ClientStore::initialize(&temp_path, temp_initial).unwrap();
        let (temp_pending, temp_attempt) = temp_store
            .reserve_attempt(temp_initial, digest(33), 100, workload(temp_initial))
            .unwrap();
        let temp_certificate = certificate(
            temp_pending,
            temp_attempt.slot,
            temp_attempt.nonce,
            temp_attempt.correlation_ranges,
            32,
            32,
        );
        assert!(temp_store
            .accept_with_fault(temp_pending, &temp_certificate, AtomicFault::AfterTempSync,)
            .is_err());
        let recovered = C6ClientStore::open(&temp_path).unwrap();
        assert_eq!(recovered.load().unwrap(), temp_pending);

        let rename_root = root.join("after-rename");
        fs::create_dir_all(&rename_root).unwrap();
        let rename_initial = genesis(digest(34));
        let rename_path = rename_root.join("head.state");
        let rename_store = C6ClientStore::initialize(&rename_path, rename_initial).unwrap();
        let (rename_pending, rename_attempt) = rename_store
            .reserve_attempt(rename_initial, digest(35), 100, workload(rename_initial))
            .unwrap();
        let rename_certificate = certificate(
            rename_pending,
            rename_attempt.slot,
            rename_attempt.nonce,
            rename_attempt.correlation_ranges,
            32,
            32,
        );
        let rename_expected = rename_pending.accepts(&rename_certificate).unwrap();
        assert!(rename_store
            .accept_with_fault(rename_pending, &rename_certificate, AtomicFault::AfterRename,)
            .is_err());
        let recovered = C6ClientStore::open(&rename_path).unwrap();
        assert_eq!(recovered.load().unwrap(), rename_expected);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn client_abort_preserves_head_and_burns_the_slot_high_water() {
        let root = test_directory("client-abort");
        let initial = genesis(digest(36));
        let path = root.join("head.state");
        let store = C6ClientStore::initialize(&path, initial).unwrap();
        let (pending, first_attempt) =
            store.reserve_attempt(initial, digest(37), 100, workload(initial)).unwrap();
        let after_abort = store.abort_attempt(pending).unwrap();
        assert_eq!(after_abort.head, initial.head);
        assert_eq!(after_abort.accepted_certificate_digest, initial.accepted_certificate_digest);
        assert_eq!(after_abort.next_slot, 1);
        assert_eq!(after_abort.raw_high_water, [100; C6_MAC_COORDINATES]);
        assert!(after_abort.pending_attempt.is_none());

        let (retry, retry_attempt) =
            store.reserve_attempt(after_abort, digest(37), 100, workload(after_abort)).unwrap();
        assert_eq!(retry_attempt.slot, 1);
        assert_ne!(retry_attempt.nonce, first_attempt.nonce);
        assert_eq!(retry_attempt.correlation_ranges.coordinates, [range(100), range(100)]);
        assert_eq!(retry.head, initial.head);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_state_recovers_torn_temp_create_and_write() {
        for (ordinal, fault) in
            [AtomicFault::AfterTempCreate, AtomicFault::AfterTempWrite].into_iter().enumerate()
        {
            let root = test_directory("client-torn");
            let initial = genesis(digest(70 + ordinal as u8));
            let path = root.join("head.state");
            let store = C6ClientStore::initialize(&path, initial).unwrap();
            let (pending, attempt) = store
                .reserve_attempt(initial, digest(72 + ordinal as u8), 100, workload(initial))
                .unwrap();
            let certificate = certificate(
                pending,
                attempt.slot,
                attempt.nonce,
                attempt.correlation_ranges,
                32,
                32,
            );
            assert!(store.accept_with_fault(pending, &certificate, fault).is_err());
            let recovered = C6ClientStore::open(&path).unwrap();
            assert_eq!(recovered.load().unwrap(), pending);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn slots_burn_ranges_forbid_forks_and_retransmit_identical_bytes() {
        let root = test_directory("slot-lifecycle");
        let store = C6SlotStore::open(&root).unwrap();
        let state = genesis(digest(40));

        let mut aborted =
            store.reserve(reservation(state, 0, digest(41), paired_ranges(0))).unwrap();
        aborted.start().unwrap();
        assert!(store.reserve(reservation(state, 1, digest(42), paired_ranges(100))).is_err());
        aborted.abort().unwrap();
        assert_eq!(aborted.status(), C6SlotStatus::Burned);
        assert!(store.reserve(reservation(state, 1, digest(42), paired_ranges(50))).is_err());

        let mut produced =
            store.reserve(reservation(state, 1, digest(42), paired_ranges(100))).unwrap();
        produced.start().unwrap();
        let certificate = certificate(state, 1, digest(42), paired_ranges(100), 64, 96);
        let expected_bytes = certificate.encode().unwrap();
        let certificate_digest = produced.produce(&certificate).unwrap();
        assert_eq!(produced.retransmit().unwrap(), expected_bytes);
        assert_eq!(produced.produce(&certificate).unwrap(), certificate_digest);

        let mut alternate = certificate.clone();
        alternate.public_output_digest = digest(43);
        let statement = alternate.compute_transition_statement_digest();
        alternate.transition_statement_digest = statement;
        alternate.new_head.producer_transition_digest = statement;
        assert!(produced.produce(&alternate).is_err());
        assert!(produced.abort().is_err());
        produced.acknowledge(certificate_digest).unwrap();
        produced.acknowledge(certificate_digest).unwrap();
        assert_eq!(produced.status(), C6SlotStatus::Accepted);
        assert_eq!(produced.retransmit().unwrap(), expected_bytes);

        assert!(store.reserve(reservation(state, 2, digest(42), paired_ranges(200))).is_err());
        assert!(store.reserve(reservation(state, 2, digest(44), paired_ranges(200))).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn orphan_certificate_recovers_but_empty_inflight_attempt_burns() {
        let root = test_directory("slot-crash");
        let store = C6SlotStore::open(&root).unwrap();
        let initial = genesis(digest(50));
        let (first_pending, first_attempt) =
            initial.reserve_attempt(digest(51), 100, workload(initial)).unwrap();
        let first = certificate(
            first_pending,
            first_attempt.slot,
            first_attempt.nonce,
            first_attempt.correlation_ranges,
            48,
            80,
        );
        let next = first_pending.accepts(&first).unwrap();

        let (orphan_pending, orphan_attempt) =
            next.reserve_attempt(digest(52), 100, workload(next)).unwrap();
        let mut orphan = store
            .reserve(reservation(
                orphan_pending,
                orphan_attempt.slot,
                orphan_attempt.nonce,
                orphan_attempt.correlation_ranges,
            ))
            .unwrap();
        orphan.start().unwrap();
        let orphan_certificate = certificate(
            orphan_pending,
            orphan_attempt.slot,
            orphan_attempt.nonce,
            orphan_attempt.correlation_ranges,
            48,
            80,
        );
        let expected = orphan_certificate.encode().unwrap();
        assert!(orphan
            .produce_with_fault(&orphan_certificate, SlotProduceFault::AfterCertificateSync)
            .is_err());
        drop(orphan);

        let recovered = store.open_slot(orphan_pending.connection_id, orphan_attempt.slot).unwrap();
        assert_eq!(recovered.status(), C6SlotStatus::Produced);
        assert_eq!(recovered.retransmit().unwrap(), expected);
        drop(recovered);

        let later = orphan_pending.accepts(&orphan_certificate).unwrap();
        let mut empty =
            store.reserve(reservation(later, 2, digest(53), paired_ranges(200))).unwrap();
        empty.start().unwrap();
        drop(empty);
        let burned = store.open_slot(later.connection_id, 2).unwrap();
        assert_eq!(burned.status(), C6SlotStatus::Burned);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_v3_codecs_reject_v2_state_and_slot_bytes() {
        let state = genesis(digest(80));
        let mut old_state = state.encode().unwrap();
        old_state[b"VOLTA-C6-STATE-v".len()] = b'2';
        assert!(C6ClientState::decode(&old_state).is_err());

        let reservation = reservation(state, 0, digest(81), paired_ranges(0));
        let (mut old_slot, _) = slot_header(reservation).unwrap();
        old_slot[b"VOLTA-C6-SLOT-v".len()] = b'2';
        assert!(parse_slot_journal(&old_slot).is_err());
    }

    #[test]
    fn client_owned_range_allocator_is_monotone_and_capacity_atomic() {
        let root = test_directory("client-raw-high-water");
        let initial = genesis(digest(82));
        let path = root.join("head.state");
        let store = C6ClientStore::initialize(&path, initial).unwrap();
        let (pending, attempt) = store
            .reserve_attempt(initial, digest(83), C6_TERMINAL_ONE_RAW_CAPACITY, workload(initial))
            .unwrap();
        assert_eq!(
            attempt.correlation_ranges.coordinates,
            [C6CorrelationRange { stage: 1, start: 0, count: C6_TERMINAL_ONE_RAW_CAPACITY };
                C6_MAC_COORDINATES]
        );
        assert_eq!(pending.raw_high_water, [C6_TERMINAL_ONE_RAW_CAPACITY; C6_MAC_COORDINATES]);
        let burned = store.abort_attempt(pending).unwrap();
        let before_failed_reservation = store.load().unwrap();
        assert_eq!(before_failed_reservation, burned);
        assert!(store.reserve_attempt(burned, digest(84), 1, workload(burned)).is_err());
        assert_eq!(store.load().unwrap(), before_failed_reservation);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn client_range_high_water_recovers_every_atomic_reservation_boundary() {
        for (ordinal, fault) in [
            AtomicFault::AfterTempCreate,
            AtomicFault::AfterTempWrite,
            AtomicFault::AfterTempSync,
            AtomicFault::AfterRename,
        ]
        .into_iter()
        .enumerate()
        {
            let root = test_directory("client-range-crash");
            let initial = genesis(digest(116 + ordinal as u8));
            let path = root.join("head.state");
            let store = C6ClientStore::initialize(&path, initial).unwrap();
            let entropy = digest(120 + ordinal as u8);
            let (expected_pending, _) = initial
                .reserve_attempt(entropy, C6_BASELINE_RAW_CORRELATIONS, workload(initial))
                .unwrap();
            assert!(store
                .reserve_attempt_with_fault(
                    initial,
                    entropy,
                    C6_BASELINE_RAW_CORRELATIONS,
                    workload(initial),
                    fault,
                )
                .is_err());
            let recovered = C6ClientStore::open(&path).unwrap().load().unwrap();
            if fault == AtomicFault::AfterRename {
                assert_eq!(recovered, expected_pending);
                assert_eq!(
                    recovered.raw_high_water,
                    [C6_BASELINE_RAW_CORRELATIONS; C6_MAC_COORDINATES]
                );
            } else {
                assert_eq!(recovered, initial);
                assert_eq!(recovered.raw_high_water, [0; C6_MAC_COORDINATES]);
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn slot_reservation_binds_workload_before_proof_work() {
        let root = test_directory("slot-workload-binding");
        let store = C6SlotStore::open(&root).unwrap();
        let initial = genesis(digest(85));
        let (pending, attempt) =
            initial.reserve_attempt(digest(86), 100, workload(initial)).unwrap();
        let reservation =
            C6SlotReservation::from_client_attempt(initial.connection_id, attempt).unwrap();
        let mut slot = store.reserve(reservation).unwrap();
        slot.start().unwrap();

        let mut changed =
            certificate(pending, attempt.slot, attempt.nonce, attempt.correlation_ranges, 32, 32);
        changed.workload.prompt_tokens = 0;
        changed.workload.decode_tokens = 1;
        let statement = changed.compute_transition_statement_digest();
        changed.transition_statement_digest = statement;
        changed.new_head.producer_transition_digest = statement;
        assert!(changed.validate().is_ok());
        assert!(slot.produce(&changed).is_err());
        assert!(pending.accepts(&changed).is_err());
        slot.abort().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_session_burns_four_attempts_then_accepts_seventeen_flat_certificates() {
        let root = test_directory("session-17-plus-4");
        let client_path = root.join("client").join("head.state");
        let slot_root = root.join("provider-slots");
        let initial = genesis(digest(87));
        let client = C6ClientStore::initialize(&client_path, initial).unwrap();
        let provider = C6SlotStore::open(&slot_root).unwrap();
        let mut state = initial;

        for ordinal in 0..C6_ABORT_RETRY_CREDITS {
            let (pending, attempt) = client
                .reserve_attempt(
                    state,
                    digest(88 + ordinal as u8),
                    C6_BASELINE_RAW_CORRELATIONS,
                    workload(state),
                )
                .unwrap();
            let expected_start =
                u64::from(ordinal).checked_mul(C6_BASELINE_RAW_CORRELATIONS).unwrap();
            for range in attempt.correlation_ranges.coordinates {
                assert_eq!(range.start, expected_start);
                assert_eq!(range.count, C6_BASELINE_RAW_CORRELATIONS);
            }
            let reservation =
                C6SlotReservation::from_client_attempt(state.connection_id, attempt).unwrap();
            let mut slot = provider.reserve(reservation).unwrap();
            slot.start().unwrap();
            slot.abort().unwrap();
            state = client.abort_attempt(pending).unwrap();
            assert_eq!(state.head, initial.head);
            assert_eq!(state.head.epoch, 0);
        }

        let mut flat_certificate_len = None;
        for ordinal in 0..C6_ACCEPTANCE_CREDITS {
            let (pending, attempt) = client
                .reserve_attempt(
                    state,
                    digest(96 + ordinal as u8),
                    C6_BASELINE_RAW_CORRELATIONS,
                    workload(state),
                )
                .unwrap();
            let reservation =
                C6SlotReservation::from_client_attempt(state.connection_id, attempt).unwrap();
            let mut slot = provider.reserve(reservation).unwrap();
            slot.start().unwrap();
            let certificate = certificate(
                pending,
                attempt.slot,
                attempt.nonce,
                attempt.correlation_ranges,
                64,
                96,
            );
            let encoded_len = certificate.encoded_len().unwrap();
            assert_eq!(*flat_certificate_len.get_or_insert(encoded_len), encoded_len);
            let certificate_digest = slot.produce(&certificate).unwrap();

            if ordinal == 8 {
                drop(slot);
                let reopened = provider.open_slot(state.connection_id, attempt.slot).unwrap();
                assert_eq!(reopened.status(), C6SlotStatus::Produced);
                assert_eq!(reopened.retransmit().unwrap(), certificate.encode().unwrap());
                slot = reopened;
            }

            state = client.accept(pending, &certificate).unwrap();
            assert!(state.is_idempotent_retransmission(&certificate).unwrap());
            slot.acknowledge(certificate_digest).unwrap();
            assert_eq!(slot.status(), C6SlotStatus::Accepted);
            assert_eq!(state.head.epoch, u64::from(ordinal) + 1);
            assert_eq!(state.head.cache_len, u32::from(ordinal) + 1);
            assert_eq!(state.next_slot, u32::from(C6_ABORT_RETRY_CREDITS) + u32::from(ordinal) + 1);
        }

        let consumed = u64::from(C6_ACCEPTANCE_CREDITS + C6_ABORT_RETRY_CREDITS)
            .checked_mul(C6_BASELINE_RAW_CORRELATIONS)
            .unwrap();
        assert_eq!(consumed, 109_949_532);
        assert_eq!(state.raw_high_water, [consumed; C6_MAC_COORDINATES]);
        assert_eq!(C6_TERMINAL_ONE_RAW_CAPACITY - consumed, 969_186);
        assert_eq!(state.head.epoch, u64::from(C6_ACCEPTANCE_CREDITS));
        assert_eq!(state.next_slot, u32::from(C6_ACCEPTANCE_CREDITS + C6_ABORT_RETRY_CREDITS));
        assert!(state.pending_attempt.is_none());
        assert_eq!(client.load().unwrap(), state);

        for slot_ordinal in 0..u32::from(C6_ACCEPTANCE_CREDITS + C6_ABORT_RETRY_CREDITS) {
            let slot = provider.open_slot(state.connection_id, slot_ordinal).unwrap();
            let expected = if slot_ordinal < u32::from(C6_ABORT_RETRY_CREDITS) {
                C6SlotStatus::Burned
            } else {
                C6SlotStatus::Accepted
            };
            assert_eq!(slot.status(), expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_append_only_journal_fails_closed() {
        let root = test_directory("slot-corrupt");
        let store = C6SlotStore::open(&root).unwrap();
        let state = genesis(digest(60));
        let slot = store.reserve(reservation(state, 0, digest(61), paired_ranges(0))).unwrap();
        let path = slot.journal_path.clone();
        drop(slot);
        OpenOptions::new().append(true).open(&path).unwrap().write_all(&[0xff]).unwrap();
        assert!(C6SlotStore::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
