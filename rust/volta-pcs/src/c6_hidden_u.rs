//! C6 reference seam for hiding the Ligero `u_c` / `u_g` vectors.
//!
//! This module deliberately does not implement a succinct proof.  It fixes
//! the exact statement that the future C6 wrapper backend must prove and
//! provides a witness-bearing reference auditor:
//!
//! - all `u` vectors are placed in two fixed, power-of-two padded layouts;
//! - roots and every public `ip_g` claim are sealed before post-commit
//!   challenges;
//! - every retained Ligero column check is translated byte-for-byte into
//!   `NTT(u_v)[j] = rhs[v]`;
//! - every old MAC bridge is translated into
//!   `ip_g = <u_g, q_col_g>`;
//! - weights and embedding relations share one independently expanded
//!   batching stream and one aggregate residual.
//!
//! The last point is load-bearing.  Using one independent RLC per family
//! would create two statistical collision events.  C6 has budgeted one
//! response-wide linear-functional event, so the canonical order is
//! family, queried column, vector, then `ip` claim.
//!
//! `C6HiddenUReferenceAudit` requires the hidden witness and therefore is not
//! a verifier or a proof.  Production acceptance must remain disabled until
//! a binding packed wrapper opening proves this exact relation.

use crate::batch::BlockClaim;
use crate::ligero::{LigeroParams, MultiOpenProof};
use crate::ntt::NttPlan;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fmt;
use volta_field::{Fp2, FpStream, P};
use volta_proto::mle::eq_vec;

pub type C6HiddenUDigest = [u8; 32];

const LAYOUT_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-layout/v1";
const FUNCTIONAL_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-functional-schedule/v1";
const WITNESS_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-reference-witness/v1";
const PREQUERY_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-prequery/v1";
const POSTCOMMIT_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-postcommit/v1";
const RESPONSE_DOMAIN: &[u8] = b"volta-zk/c6/hidden-u-reference-response/v1";
const BATCH_STREAM_DOMAINS: [u64; 2] = [0xC6_48_55_52_4C_43_01, 0xC6_48_55_52_4C_43_02];
const PREQUERY_MAGIC: &[u8; 4] = b"C6HU";
const PREQUERY_VERSION: u16 = 1;

/// C6 is a Q=121 descendant of the accepted rate-1/4 C3/T1 geometry.
/// Historical Q=120 constants remain untouched.
pub const C6_WEIGHTS_Q121: LigeroParams =
    LigeroParams { rows: 24_576, col_bits: 13, pad: 512, code_bits: 15, n_queries: 121 };
pub const C6_EMBED_Q121: LigeroParams =
    LigeroParams { rows: 2_080, col_bits: 15, pad: 512, code_bits: 17, n_queries: 121 };
pub const C6_HIDDEN_U_REPETITIONS: u64 = 2;
pub const C6_HIDDEN_U_BATCH_SEED_BYTES: u64 = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUError(String);

impl C6HiddenUError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6HiddenUError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for C6HiddenUError {}

type C6HiddenUResult<T> = Result<T, C6HiddenUError>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6HiddenUFamily {
    Weights = 1,
    Embed = 2,
}

impl C6HiddenUFamily {
    fn decode(value: u8) -> C6HiddenUResult<Self> {
        match value {
            1 => Ok(Self::Weights),
            2 => Ok(Self::Embed),
            _ => Err(C6HiddenUError::new("unknown C6 hidden-u family")),
        }
    }
}

/// Static layout of one family of hidden Ligero vectors.
///
/// Vector zero is `u_c`; vectors `1..=claim_count` are `u_g`.  Each live
/// vector contains exactly `msg_len` values followed by virtual zero padding
/// to `vector_stride`.  All inactive vector slots are virtual zero.
#[derive(Clone, Copy, Debug)]
pub struct C6HiddenULayout {
    pub family: C6HiddenUFamily,
    pub params: LigeroParams,
    pub claim_count: usize,
    pub vector_capacity: usize,
    pub vector_stride: usize,
}

impl PartialEq for C6HiddenULayout {
    fn eq(&self, other: &Self) -> bool {
        self.family == other.family
            && same_params(&self.params, &other.params)
            && self.claim_count == other.claim_count
            && self.vector_capacity == other.vector_capacity
            && self.vector_stride == other.vector_stride
    }
}

impl Eq for C6HiddenULayout {}

impl C6HiddenULayout {
    pub fn production_weights() -> Self {
        Self {
            family: C6HiddenUFamily::Weights,
            params: C6_WEIGHTS_Q121,
            claim_count: 96,
            vector_capacity: 128,
            vector_stride: 16_384,
        }
    }

    pub fn production_embed() -> Self {
        Self {
            family: C6HiddenUFamily::Embed,
            params: C6_EMBED_Q121,
            claim_count: 6,
            vector_capacity: 8,
            vector_stride: 65_536,
        }
    }

    pub fn validate(&self) -> C6HiddenUResult<()> {
        if self.params.rows == 0 {
            return Err(C6HiddenUError::new("C6 hidden-u layout has zero Ligero rows"));
        }
        if self.params.col_bits >= usize::BITS || self.params.code_bits >= usize::BITS {
            return Err(C6HiddenUError::new("C6 hidden-u Ligero exponent exceeds usize"));
        }
        let cols = 1usize
            .checked_shl(self.params.col_bits)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u column geometry overflow"))?;
        let msg_len = cols
            .checked_add(self.params.pad)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u message length overflow"))?;
        let code_len = 1usize
            .checked_shl(self.params.code_bits)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u code geometry overflow"))?;
        if msg_len > code_len {
            return Err(C6HiddenUError::new("C6 hidden-u Ligero rate exceeds one"));
        }
        if self.params.n_queries == 0 || self.params.n_queries > self.params.pad {
            return Err(C6HiddenUError::new(
                "C6 hidden-u query count must be nonzero and fit the Ligero pad",
            ));
        }
        if self.claim_count == 0 {
            return Err(C6HiddenUError::new("C6 hidden-u family has no claims"));
        }
        let live_vectors = self
            .claim_count
            .checked_add(1)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u live-vector count overflow"))?;
        if !self.vector_capacity.is_power_of_two() || live_vectors > self.vector_capacity {
            return Err(C6HiddenUError::new(
                "C6 hidden-u live vectors exceed a nonzero power-of-two capacity",
            ));
        }
        if !self.vector_stride.is_power_of_two()
            || self.vector_stride < msg_len
            || self.vector_stride > code_len
        {
            return Err(C6HiddenUError::new(
                "C6 hidden-u vector stride must be power-of-two between message and code length",
            ));
        }
        let padded_entries = self
            .vector_capacity
            .checked_mul(self.vector_stride)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u padded layout overflow"))?;
        if !padded_entries.is_power_of_two() {
            return Err(C6HiddenUError::new(
                "C6 hidden-u padded family is not one multilinear power-of-two oracle",
            ));
        }
        for (value, label) in [
            (self.params.rows, "rows"),
            (self.params.pad, "pad"),
            (self.params.n_queries, "queries"),
            (self.claim_count, "claims"),
            (self.vector_capacity, "vector capacity"),
            (self.vector_stride, "vector stride"),
        ] {
            u32::try_from(value).map_err(|_| {
                C6HiddenUError::new(format!("C6 hidden-u {label} does not fit canonical u32"))
            })?;
        }
        Ok(())
    }

    pub fn live_vectors(&self) -> usize {
        self.claim_count + 1
    }

    pub fn cols(&self) -> usize {
        1usize << self.params.col_bits
    }

    pub fn msg_len(&self) -> usize {
        self.cols() + self.params.pad
    }

    pub fn code_len(&self) -> usize {
        1usize << self.params.code_bits
    }

    pub fn padded_entries(&self) -> usize {
        self.vector_capacity * self.vector_stride
    }

    pub fn omitted_u_bytes(&self) -> u64 {
        16 * self.msg_len() as u64 * self.live_vectors() as u64
    }

    pub fn relation_count(&self) -> usize {
        self.params.n_queries * self.live_vectors() + self.claim_count
    }

    pub fn digest(&self) -> C6HiddenUDigest {
        self.validate().expect("invalid C6 hidden-u layout");
        let mut h = blake3::Hasher::new();
        h.update(&(LAYOUT_DOMAIN.len() as u64).to_le_bytes());
        h.update(LAYOUT_DOMAIN);
        h.update(&[self.family as u8]);
        for value in [
            self.params.rows,
            self.params.col_bits as usize,
            self.params.pad,
            self.params.code_bits as usize,
            self.params.n_queries,
            self.claim_count,
            self.vector_capacity,
            self.vector_stride,
        ] {
            h.update(&(value as u64).to_le_bytes());
        }
        *h.finalize().as_bytes()
    }
}

fn same_params(a: &LigeroParams, b: &LigeroParams) -> bool {
    a.rows == b.rows
        && a.col_bits == b.col_bits
        && a.pad == b.pad
        && a.code_bits == b.code_bits
        && a.n_queries == b.n_queries
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6HiddenUReferenceBudget {
    pub family_count: u64,
    pub padded_witness_entries: u64,
    pub omitted_u_bytes: u64,
    pub prequery_bytes: u64,
    pub client_batch_seed_bytes: u64,
    pub linear_relation_count: u64,
    pub complete_repetitions: u64,
}

pub fn hidden_u_prequery_encoded_len(layouts: &[C6HiddenULayout]) -> C6HiddenUResult<u64> {
    validate_layout_order(layouts)?;
    // magic/version/count/context + terminal digest
    let mut bytes = 40u64 + 32;
    for layout in layouts {
        // family/reserved + layout/function/root digests + ip count + ips
        bytes = bytes
            .checked_add(104)
            .and_then(|total| {
                total.checked_add(16u64.checked_mul(u64::try_from(layout.claim_count).ok()?)?)
            })
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u prequery byte count overflow"))?;
    }
    Ok(bytes)
}

pub fn production_hidden_u_reference_budget() -> C6HiddenUReferenceBudget {
    let layouts = [C6HiddenULayout::production_weights(), C6HiddenULayout::production_embed()];
    C6HiddenUReferenceBudget {
        family_count: layouts.len() as u64,
        padded_witness_entries: layouts.iter().map(|layout| layout.padded_entries() as u64).sum(),
        omitted_u_bytes: layouts.iter().map(C6HiddenULayout::omitted_u_bytes).sum(),
        prequery_bytes: hidden_u_prequery_encoded_len(&layouts)
            .expect("valid production C6 hidden-u layouts"),
        client_batch_seed_bytes: C6_HIDDEN_U_BATCH_SEED_BYTES,
        linear_relation_count: layouts.iter().map(|layout| layout.relation_count() as u64).sum(),
        complete_repetitions: C6_HIDDEN_U_REPETITIONS,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6HiddenUFamilyPrequery {
    family: C6HiddenUFamily,
    layout_digest: C6HiddenUDigest,
    functional_digest: C6HiddenUDigest,
    wrapper_root: C6HiddenUDigest,
    public_ips: Vec<Fp2>,
}

/// Canonical pre-query frame.  `public_ips` is intentionally present here,
/// before the old ZeroBatch `chi` and all Ligero/wrapper query challenges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUPrequery {
    context_digest: C6HiddenUDigest,
    families: Vec<C6HiddenUFamilyPrequery>,
    digest: C6HiddenUDigest,
}

impl C6HiddenUPrequery {
    fn new(
        layouts: &[C6HiddenULayout],
        roots: &[C6HiddenUDigest],
        context_digest: C6HiddenUDigest,
        functional_digests: &[C6HiddenUDigest],
        public_ips: Vec<Vec<Fp2>>,
    ) -> C6HiddenUResult<Self> {
        validate_layout_order(layouts)?;
        if context_digest == [0; 32] {
            return Err(C6HiddenUError::new("zero C6 hidden-u context digest"));
        }
        if roots.len() != layouts.len()
            || functional_digests.len() != layouts.len()
            || public_ips.len() != layouts.len()
        {
            return Err(C6HiddenUError::new("C6 hidden-u prequery family count mismatch"));
        }
        let mut families = Vec::with_capacity(layouts.len());
        for (((layout, root), functional_digest), ips) in
            layouts.iter().zip(roots).zip(functional_digests).zip(public_ips)
        {
            if *root == [0; 32] {
                return Err(C6HiddenUError::new("zero C6 hidden-u wrapper root"));
            }
            if *functional_digest == [0; 32] {
                return Err(C6HiddenUError::new("zero C6 hidden-u functional digest"));
            }
            if ips.len() != layout.claim_count {
                return Err(C6HiddenUError::new("C6 hidden-u public-ip census mismatch"));
            }
            families.push(C6HiddenUFamilyPrequery {
                family: layout.family,
                layout_digest: layout.digest(),
                functional_digest: *functional_digest,
                wrapper_root: *root,
                public_ips: ips,
            });
        }
        let mut frame = Self { context_digest, families, digest: [0; 32] };
        frame.digest = digest_prequery_prefix(&frame.encode_prefix()?);
        Ok(frame)
    }

    pub fn from_claims(
        layouts: &[C6HiddenULayout],
        roots: &[C6HiddenUDigest],
        context_digest: C6HiddenUDigest,
        functional_digests: &[C6HiddenUDigest],
        public_ips: Vec<Vec<Fp2>>,
    ) -> C6HiddenUResult<Self> {
        Self::new(layouts, roots, context_digest, functional_digests, public_ips)
    }

    pub fn digest(&self) -> C6HiddenUDigest {
        self.digest
    }

    pub fn context_digest(&self) -> C6HiddenUDigest {
        self.context_digest
    }

    pub fn wrapper_root(&self, family_index: usize) -> Option<C6HiddenUDigest> {
        self.families.get(family_index).map(|family| family.wrapper_root)
    }

    pub fn functional_digest(&self, family_index: usize) -> Option<C6HiddenUDigest> {
        self.families.get(family_index).map(|family| family.functional_digest)
    }

    pub fn public_ips(&self, family_index: usize) -> Option<&[Fp2]> {
        self.families.get(family_index).map(|family| family.public_ips.as_slice())
    }

    fn encode_prefix(&self) -> C6HiddenUResult<Vec<u8>> {
        let family_count = u16::try_from(self.families.len())
            .map_err(|_| C6HiddenUError::new("C6 hidden-u family count exceeds u16"))?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PREQUERY_MAGIC);
        bytes.extend_from_slice(&PREQUERY_VERSION.to_le_bytes());
        bytes.extend_from_slice(&family_count.to_le_bytes());
        bytes.extend_from_slice(&self.context_digest);
        for family in &self.families {
            bytes.push(family.family as u8);
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&family.layout_digest);
            bytes.extend_from_slice(&family.functional_digest);
            bytes.extend_from_slice(&family.wrapper_root);
            let ip_count = u32::try_from(family.public_ips.len())
                .map_err(|_| C6HiddenUError::new("C6 hidden-u ip count exceeds u32"))?;
            bytes.extend_from_slice(&ip_count.to_le_bytes());
            for value in &family.public_ips {
                encode_fp2(&mut bytes, *value);
            }
        }
        Ok(bytes)
    }

    pub fn encode(&self) -> C6HiddenUResult<Vec<u8>> {
        let prefix = self.encode_prefix()?;
        if digest_prequery_prefix(&prefix) != self.digest {
            return Err(C6HiddenUError::new("C6 hidden-u prequery digest mismatch"));
        }
        let mut bytes = prefix;
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(
        layouts: &[C6HiddenULayout],
        expected_functional_digests: &[C6HiddenUDigest],
        bytes: &[u8],
    ) -> C6HiddenUResult<Self> {
        validate_layout_order(layouts)?;
        if expected_functional_digests.len() != layouts.len() {
            return Err(C6HiddenUError::new(
                "C6 hidden-u expected functional-digest count mismatch",
            ));
        }
        let mut cursor = DecodeCursor::new(bytes);
        if cursor.take(4)? != PREQUERY_MAGIC {
            return Err(C6HiddenUError::new("bad C6 hidden-u prequery magic"));
        }
        if cursor.u16()? != PREQUERY_VERSION {
            return Err(C6HiddenUError::new("unknown C6 hidden-u prequery version"));
        }
        if cursor.u16()? as usize != layouts.len() {
            return Err(C6HiddenUError::new("C6 hidden-u decoded family count mismatch"));
        }
        let context_digest = cursor.digest()?;
        if context_digest == [0; 32] {
            return Err(C6HiddenUError::new("zero decoded C6 hidden-u context digest"));
        }
        let mut families = Vec::with_capacity(layouts.len());
        for (layout, expected_functional_digest) in layouts.iter().zip(expected_functional_digests)
        {
            let family = C6HiddenUFamily::decode(cursor.u8()?)?;
            if cursor.take(3)? != [0; 3] {
                return Err(C6HiddenUError::new("nonzero C6 hidden-u reserved bytes"));
            }
            if family != layout.family {
                return Err(C6HiddenUError::new("C6 hidden-u family order mismatch"));
            }
            let layout_digest = cursor.digest()?;
            if layout_digest != layout.digest() {
                return Err(C6HiddenUError::new("C6 hidden-u layout digest mismatch"));
            }
            let functional_digest = cursor.digest()?;
            if functional_digest != *expected_functional_digest {
                return Err(C6HiddenUError::new("C6 hidden-u functional digest mismatch"));
            }
            let wrapper_root = cursor.digest()?;
            if wrapper_root == [0; 32] {
                return Err(C6HiddenUError::new("zero decoded C6 hidden-u wrapper root"));
            }
            if cursor.u32()? as usize != layout.claim_count {
                return Err(C6HiddenUError::new("C6 hidden-u decoded ip census mismatch"));
            }
            let mut public_ips = Vec::with_capacity(layout.claim_count);
            for _ in 0..layout.claim_count {
                public_ips.push(cursor.fp2()?);
            }
            families.push(C6HiddenUFamilyPrequery {
                family,
                layout_digest,
                functional_digest,
                wrapper_root,
                public_ips,
            });
        }
        let digest_offset = cursor.position();
        let digest = cursor.digest()?;
        if !cursor.is_eof() {
            return Err(C6HiddenUError::new("trailing C6 hidden-u prequery bytes"));
        }
        if digest_prequery_prefix(&bytes[..digest_offset]) != digest {
            return Err(C6HiddenUError::new("decoded C6 hidden-u prequery digest mismatch"));
        }
        Ok(Self { context_digest, families, digest })
    }
}

fn digest_prequery_prefix(prefix: &[u8]) -> C6HiddenUDigest {
    hash_parts(PREQUERY_DOMAIN, &[prefix])
}

fn encode_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

struct DecodeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DecodeCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn is_eof(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, count: usize) -> C6HiddenUResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| C6HiddenUError::new("C6 hidden-u decoder overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6HiddenUError::new("truncated C6 hidden-u prequery"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> C6HiddenUResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> C6HiddenUResult<u16> {
        let mut raw = [0; 2];
        raw.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(raw))
    }

    fn u32(&mut self) -> C6HiddenUResult<u32> {
        let mut raw = [0; 4];
        raw.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn u64(&mut self) -> C6HiddenUResult<u64> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(raw))
    }

    fn digest(&mut self) -> C6HiddenUResult<C6HiddenUDigest> {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2(&mut self) -> C6HiddenUResult<Fp2> {
        let c0 = self.u64()?;
        let c1 = self.u64()?;
        if c0 >= P || c1 >= P {
            return Err(C6HiddenUError::new("noncanonical C6 hidden-u field element"));
        }
        Ok(Fp2::new(volta_field::Fp::new(c0), volta_field::Fp::new(c1)))
    }
}

fn validate_layout_order(layouts: &[C6HiddenULayout]) -> C6HiddenUResult<()> {
    if layouts.is_empty() {
        return Err(C6HiddenUError::new("empty C6 hidden-u family bundle"));
    }
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for layout in layouts {
        layout.validate()?;
        if previous.is_some_and(|family| family >= layout.family) {
            return Err(C6HiddenUError::new(
                "C6 hidden-u families must be unique and canonically ordered",
            ));
        }
        if !seen.insert(layout.family) {
            return Err(C6HiddenUError::new("duplicate C6 hidden-u family"));
        }
        previous = Some(layout.family);
    }
    Ok(())
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> C6HiddenUDigest {
    let mut h = blake3::Hasher::new();
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain);
    for part in parts {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    *h.finalize().as_bytes()
}

/// Digest of the exact pre-query `q_col` schedule derived from retained block
/// claims.  The client recomputes this value; an opaque caller-supplied
/// context digest is not sufficient to bind the MAC-bridge functional.
pub fn hidden_u_functional_digest(
    layout: C6HiddenULayout,
    q_cols: &[Vec<Fp2>],
) -> C6HiddenUResult<C6HiddenUDigest> {
    layout.validate()?;
    if q_cols.len() != layout.claim_count || q_cols.iter().any(|q_col| q_col.len() != layout.cols())
    {
        return Err(C6HiddenUError::new("C6 hidden-u functional-digest q_col census mismatch"));
    }
    let mut h = blake3::Hasher::new();
    h.update(&(FUNCTIONAL_DOMAIN.len() as u64).to_le_bytes());
    h.update(FUNCTIONAL_DOMAIN);
    h.update(&layout.digest());
    h.update(&(q_cols.len() as u64).to_le_bytes());
    for q_col in q_cols {
        h.update(&(q_col.len() as u64).to_le_bytes());
        for value in q_col {
            h.update(&value.c0.value().to_le_bytes());
            h.update(&value.c1.value().to_le_bytes());
        }
    }
    Ok(*h.finalize().as_bytes())
}

/// Hidden witness for one family.  Only live message coordinates are stored;
/// the canonical digest streams the fixed zero tails and inactive vectors.
pub struct C6HiddenUFamilyWitness {
    layout: C6HiddenULayout,
    vectors: Vec<Vec<Fp2>>,
    q_cols: Vec<Vec<Fp2>>,
}

impl C6HiddenUFamilyWitness {
    pub fn new(
        layout: C6HiddenULayout,
        u_c: Vec<Fp2>,
        u_gs: Vec<Vec<Fp2>>,
        q_cols: Vec<Vec<Fp2>>,
    ) -> C6HiddenUResult<Self> {
        layout.validate()?;
        if u_gs.len() != layout.claim_count || q_cols.len() != layout.claim_count {
            return Err(C6HiddenUError::new("C6 hidden-u witness claim census mismatch"));
        }
        let mut vectors = Vec::with_capacity(layout.live_vectors());
        vectors.push(u_c);
        vectors.extend(u_gs);
        if vectors.iter().any(|vector| vector.len() != layout.msg_len()) {
            return Err(C6HiddenUError::new("C6 hidden-u witness message length mismatch"));
        }
        if q_cols.iter().any(|row| row.len() != layout.cols()) {
            return Err(C6HiddenUError::new("C6 hidden-u q_col length mismatch"));
        }
        Ok(Self { layout, vectors, q_cols })
    }

    pub fn from_multi_open(
        layout: C6HiddenULayout,
        proof: &MultiOpenProof,
        q_cols: Vec<Vec<Fp2>>,
    ) -> C6HiddenUResult<Self> {
        Self::new(layout, proof.u_c.clone(), proof.u_gs.clone(), q_cols)
    }

    pub fn layout(&self) -> C6HiddenULayout {
        self.layout
    }

    fn public_ips(&self) -> Vec<Fp2> {
        self.q_cols
            .iter()
            .enumerate()
            .map(|(claim, q_col)| {
                self.vectors[1 + claim][..self.layout.cols()]
                    .iter()
                    .zip(q_col)
                    .fold(Fp2::ZERO, |acc, (u, q)| acc + *u * *q)
            })
            .collect()
    }

    pub fn reference_witness_digest(&self) -> C6HiddenUDigest {
        let mut h = blake3::Hasher::new();
        h.update(&(WITNESS_DOMAIN.len() as u64).to_le_bytes());
        h.update(WITNESS_DOMAIN);
        h.update(&self.layout.digest());
        for vector in &self.vectors {
            for value in vector {
                h.update(&value.c0.value().to_le_bytes());
                h.update(&value.c1.value().to_le_bytes());
            }
            hash_zero_fp2s(&mut h, self.layout.vector_stride - self.layout.msg_len());
        }
        hash_zero_fp2s(
            &mut h,
            (self.layout.vector_capacity - self.layout.live_vectors()) * self.layout.vector_stride,
        );
        *h.finalize().as_bytes()
    }

    pub fn functional_digest(&self) -> C6HiddenUDigest {
        hidden_u_functional_digest(self.layout, &self.q_cols)
            .expect("validated C6 hidden-u q_col schedule")
    }
}

fn hash_zero_fp2s(hasher: &mut blake3::Hasher, count: usize) {
    const ZERO_BYTES: [u8; 4096] = [0; 4096];
    const FP2S_PER_CHUNK: usize = ZERO_BYTES.len() / 16;
    let mut remaining_fp2s = count;
    while remaining_fp2s >= FP2S_PER_CHUNK {
        hasher.update(&ZERO_BYTES);
        remaining_fp2s -= FP2S_PER_CHUNK;
    }
    if remaining_fp2s != 0 {
        hasher.update(&ZERO_BYTES[..remaining_fp2s * 16]);
    }
}

/// Pre-query typestate for the complete family bundle.
pub struct C6HiddenUBundleWitness {
    families: Vec<C6HiddenUFamilyWitness>,
}

impl C6HiddenUBundleWitness {
    pub fn new(families: Vec<C6HiddenUFamilyWitness>) -> C6HiddenUResult<Self> {
        let layouts: Vec<_> = families.iter().map(C6HiddenUFamilyWitness::layout).collect();
        validate_layout_order(&layouts)?;
        Ok(Self { families })
    }

    pub fn production(
        weights: C6HiddenUFamilyWitness,
        embed: C6HiddenUFamilyWitness,
    ) -> C6HiddenUResult<Self> {
        if weights.layout != C6HiddenULayout::production_weights()
            || embed.layout != C6HiddenULayout::production_embed()
        {
            return Err(C6HiddenUError::new("C6 hidden-u production layout mismatch"));
        }
        Self::new(vec![weights, embed])
    }

    /// Seal wrapper roots and all `ip_g` values before post-commit
    /// challenges become available.
    pub fn seal(
        self,
        wrapper_roots: Vec<C6HiddenUDigest>,
        context_digest: C6HiddenUDigest,
    ) -> C6HiddenUResult<C6SealedHiddenUBundle> {
        let layouts: Vec<_> = self.families.iter().map(C6HiddenUFamilyWitness::layout).collect();
        let public_ips =
            self.families.iter().map(C6HiddenUFamilyWitness::public_ips).collect::<Vec<_>>();
        let functional_digests =
            self.families.iter().map(C6HiddenUFamilyWitness::functional_digest).collect::<Vec<_>>();
        let prequery = C6HiddenUPrequery::new(
            &layouts,
            &wrapper_roots,
            context_digest,
            &functional_digests,
            public_ips,
        )?;
        let witness_digests =
            self.families.iter().map(C6HiddenUFamilyWitness::reference_witness_digest).collect();
        Ok(C6SealedHiddenUBundle {
            families: self.families,
            wrapper_roots,
            context_digest,
            witness_digests,
            prequery,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUQueryClaim {
    pub index: u32,
    /// Old verifier RHS in canonical vector order: `u_c`, then every `u_g`.
    pub rhs: Vec<Fp2>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUFamilyPostCommit {
    pub family: C6HiddenUFamily,
    pub queries: Vec<C6HiddenUQueryClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUPostCommit {
    pub prequery_digest: C6HiddenUDigest,
    /// Fresh verifier seed expanded after the complete pre-query frame.
    pub batching_seed: [u8; 32],
    pub families: Vec<C6HiddenUFamilyPostCommit>,
}

impl C6HiddenUPostCommit {
    fn validate(&self, layouts: &[C6HiddenULayout]) -> C6HiddenUResult<()> {
        if self.families.len() != layouts.len() {
            return Err(C6HiddenUError::new("C6 hidden-u postcommit family count mismatch"));
        }
        for (family, layout) in self.families.iter().zip(layouts) {
            if family.family != layout.family {
                return Err(C6HiddenUError::new("C6 hidden-u postcommit family order mismatch"));
            }
            if family.queries.len() != layout.params.n_queries {
                return Err(C6HiddenUError::new("C6 hidden-u query census mismatch"));
            }
            for query in &family.queries {
                if query.index as usize >= layout.code_len() {
                    return Err(C6HiddenUError::new("C6 hidden-u query index out of range"));
                }
                if query.rhs.len() != layout.live_vectors() {
                    return Err(C6HiddenUError::new("C6 hidden-u query RHS census mismatch"));
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self, layouts: &[C6HiddenULayout]) -> C6HiddenUResult<C6HiddenUDigest> {
        self.validate(layouts)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.prequery_digest);
        bytes.extend_from_slice(&self.batching_seed);
        for family in &self.families {
            bytes.push(family.family as u8);
            bytes.extend_from_slice(&(family.queries.len() as u64).to_le_bytes());
            for query in &family.queries {
                bytes.extend_from_slice(&query.index.to_le_bytes());
                bytes.extend_from_slice(&(query.rhs.len() as u64).to_le_bytes());
                for rhs in &query.rhs {
                    encode_fp2(&mut bytes, *rhs);
                }
            }
        }
        Ok(hash_parts(POSTCOMMIT_DOMAIN, &[&bytes]))
    }
}

/// Witness-bearing reference result.  This is an implementation oracle for
/// the future backend, never a production verifier result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUReferenceAudit {
    pub ntt_relation_count: u64,
    pub ip_relation_count: u64,
    pub nonzero_relation_count: u64,
    /// Two independent complete repetitions are required.  One `Fp2`
    /// repetition is not literally 128 bits and does not meet the frozen
    /// wrapper-event floor.
    pub aggregate_residuals: [Fp2; 2],
    pub postcommit_digest: C6HiddenUDigest,
    pub response_digest: C6HiddenUDigest,
}

impl C6HiddenUReferenceAudit {
    pub fn exact_relations_hold(&self) -> bool {
        self.nonzero_relation_count == 0
    }

    pub fn batched_relation_holds(&self) -> bool {
        self.aggregate_residuals == [Fp2::ZERO; 2]
    }
}

pub struct C6SealedHiddenUBundle {
    families: Vec<C6HiddenUFamilyWitness>,
    wrapper_roots: Vec<C6HiddenUDigest>,
    context_digest: C6HiddenUDigest,
    witness_digests: Vec<C6HiddenUDigest>,
    prequery: C6HiddenUPrequery,
}

impl C6SealedHiddenUBundle {
    pub fn prequery(&self) -> &C6HiddenUPrequery {
        &self.prequery
    }

    pub fn witness_digests(&self) -> &[C6HiddenUDigest] {
        &self.witness_digests
    }

    /// Audit the exact hidden-u relation against an explicitly claimed
    /// pre-query frame and post-commit challenge set.
    pub fn audit_reference(
        &self,
        claimed_prequery: &C6HiddenUPrequery,
        postcommit: &C6HiddenUPostCommit,
    ) -> C6HiddenUResult<C6HiddenUReferenceAudit> {
        let layouts: Vec<_> = self.families.iter().map(C6HiddenUFamilyWitness::layout).collect();
        if claimed_prequery.context_digest != self.context_digest
            || claimed_prequery.families.len() != self.families.len()
        {
            return Err(C6HiddenUError::new("C6 hidden-u claimed prequery context mismatch"));
        }
        for (index, (claimed, layout)) in claimed_prequery.families.iter().zip(&layouts).enumerate()
        {
            if claimed.family != layout.family
                || claimed.layout_digest != layout.digest()
                || claimed.functional_digest != self.families[index].functional_digest()
                || claimed.wrapper_root != self.wrapper_roots[index]
            {
                return Err(C6HiddenUError::new("C6 hidden-u claimed prequery binding mismatch"));
            }
            if claimed.public_ips.len() != layout.claim_count {
                return Err(C6HiddenUError::new("C6 hidden-u claimed ip census mismatch"));
            }
        }
        if claimed_prequery.encode().is_err() {
            return Err(C6HiddenUError::new("noncanonical C6 hidden-u claimed prequery"));
        }
        if postcommit.prequery_digest != claimed_prequery.digest {
            return Err(C6HiddenUError::new("C6 hidden-u postcommit/prequery digest mismatch"));
        }
        postcommit.validate(&layouts)?;
        let postcommit_digest = postcommit.digest(&layouts)?;

        let encoded: Vec<Vec<Vec<Fp2>>> = self
            .families
            .par_iter()
            .map(|family| {
                let plan = NttPlan::new(family.layout.code_len());
                family.vectors.par_iter().map(|vector| encode_fp2_ntt(&plan, vector)).collect()
            })
            .collect();

        let mut alpha_streams = BATCH_STREAM_DOMAINS
            .map(|domain| FpStream::domain_separated(postcommit.batching_seed, domain));
        let mut aggregate = [Fp2::ZERO; 2];
        let mut nonzero = 0u64;
        let mut ntt_count = 0u64;
        let mut ip_count = 0u64;

        // One response-wide coefficient stream.  Do not reset at a family
        // boundary: that would define multiple collision events.
        for (family_index, family_post) in postcommit.families.iter().enumerate() {
            let family = &self.families[family_index];
            for query in &family_post.queries {
                let j = query.index as usize;
                for (vector_index, rhs) in query.rhs.iter().enumerate() {
                    let residual = encoded[family_index][vector_index][j] - *rhs;
                    if residual != Fp2::ZERO {
                        nonzero += 1;
                    }
                    for (repetition, stream) in alpha_streams.iter_mut().enumerate() {
                        aggregate[repetition] += stream.next_fp2() * residual;
                    }
                    ntt_count += 1;
                }
            }
            for claim in 0..family.layout.claim_count {
                let actual_ip = family.vectors[1 + claim][..family.layout.cols()]
                    .iter()
                    .zip(&family.q_cols[claim])
                    .fold(Fp2::ZERO, |acc, (u, q)| acc + *u * *q);
                let residual =
                    actual_ip - claimed_prequery.families[family_index].public_ips[claim];
                if residual != Fp2::ZERO {
                    nonzero += 1;
                }
                for (repetition, stream) in alpha_streams.iter_mut().enumerate() {
                    aggregate[repetition] += stream.next_fp2() * residual;
                }
                ip_count += 1;
            }
        }

        let mut response_bytes = Vec::new();
        response_bytes.extend_from_slice(&claimed_prequery.digest);
        response_bytes.extend_from_slice(&postcommit_digest);
        for residual in aggregate {
            encode_fp2(&mut response_bytes, residual);
        }
        response_bytes.extend_from_slice(&ntt_count.to_le_bytes());
        response_bytes.extend_from_slice(&ip_count.to_le_bytes());
        let response_digest = hash_parts(RESPONSE_DOMAIN, &[&response_bytes]);

        Ok(C6HiddenUReferenceAudit {
            ntt_relation_count: ntt_count,
            ip_relation_count: ip_count,
            nonzero_relation_count: nonzero,
            aggregate_residuals: aggregate,
            postcommit_digest,
            response_digest,
        })
    }
}

fn encode_fp2_ntt(plan: &NttPlan, vector: &[Fp2]) -> Vec<Fp2> {
    let c0 = vector.iter().map(|value| value.c0).collect::<Vec<_>>();
    let c1 = vector.iter().map(|value| value.c1).collect::<Vec<_>>();
    plan.encode(&c0).into_iter().zip(plan.encode(&c1)).map(|(a, b)| Fp2::new(a, b)).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6HiddenUDerivedFamily {
    pub q_cols: Vec<Vec<Fp2>>,
    pub postcommit: C6HiddenUFamilyPostCommit,
}

/// Translate the retained old Ligero columns into the exact hidden-u public
/// RHS values.  Merkle paths and MAC keys are deliberately not checked here;
/// the unchanged retained verifier remains responsible for those checks.
pub fn derive_hidden_u_family_claims(
    layout: C6HiddenULayout,
    claims: &[BlockClaim],
    proof: &MultiOpenProof,
    proximity_challenge: Fp2,
    expected_query_indices: &[usize],
) -> C6HiddenUResult<C6HiddenUDerivedFamily> {
    layout.validate()?;
    if claims.len() != layout.claim_count
        || proof.columns.len() != layout.params.n_queries
        || expected_query_indices.len() != layout.params.n_queries
    {
        return Err(C6HiddenUError::new("C6 hidden-u retained Ligero census mismatch"));
    }
    let geometries = claims
        .iter()
        .map(|claim| claim_geometry(&layout, claim))
        .collect::<C6HiddenUResult<Vec<_>>>()?;

    let mut c_powers = Vec::with_capacity(layout.params.rows);
    let mut power = Fp2::ONE;
    for _ in 0..layout.params.rows {
        power = power * proximity_challenge;
        c_powers.push(power);
    }

    let mut queries = Vec::with_capacity(layout.params.n_queries);
    for ((column, expected_index), query_ordinal) in
        proof.columns.iter().zip(expected_query_indices).zip(0usize..)
    {
        if column.j as usize != *expected_index {
            return Err(C6HiddenUError::new(format!(
                "C6 hidden-u retained query index mismatch at ordinal {query_ordinal}"
            )));
        }
        if *expected_index >= layout.code_len()
            || column.col.len() != layout.params.rows
            || column.mask_col.len() != layout.live_vectors()
        {
            return Err(C6HiddenUError::new("C6 hidden-u retained column geometry mismatch"));
        }
        let mut rhs = Vec::with_capacity(layout.live_vectors());
        let proximity_rhs = c_powers
            .iter()
            .zip(&column.col)
            .fold(Fp2::ZERO, |acc, (coefficient, value)| acc + coefficient.mul_base(*value))
            + column.mask_col[0];
        rhs.push(proximity_rhs);
        for (claim, geometry) in geometries.iter().enumerate() {
            let local_rhs =
                geometry.q_row.iter().enumerate().fold(Fp2::ZERO, |acc, (offset, coefficient)| {
                    acc + coefficient.mul_base(column.col[geometry.row0 + offset])
                }) + column.mask_col[1 + claim];
            rhs.push(local_rhs);
        }
        queries.push(C6HiddenUQueryClaim { index: column.j, rhs });
    }

    Ok(C6HiddenUDerivedFamily {
        q_cols: geometries.into_iter().map(|geometry| geometry.q_col).collect(),
        postcommit: C6HiddenUFamilyPostCommit { family: layout.family, queries },
    })
}

struct ClaimGeometry {
    row0: usize,
    q_row: Vec<Fp2>,
    q_col: Vec<Fp2>,
}

fn claim_geometry(layout: &C6HiddenULayout, claim: &BlockClaim) -> C6HiddenUResult<ClaimGeometry> {
    let col_bits = layout.params.col_bits as usize;
    let block_vars = claim.point.len();
    if block_vars < col_bits || block_vars > layout.params.n_vars() {
        return Err(C6HiddenUError::new("C6 hidden-u claim variable count mismatch"));
    }
    let block_len = 1usize
        .checked_shl(block_vars as u32)
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u claim block overflow"))?;
    if claim.offset % block_len != 0 {
        return Err(C6HiddenUError::new("C6 hidden-u claim block is not aligned"));
    }
    let row_count = 1usize
        .checked_shl((block_vars - col_bits) as u32)
        .ok_or_else(|| C6HiddenUError::new("C6 hidden-u claim row count overflow"))?;
    let row0 = claim.offset >> col_bits;
    if row0.checked_add(row_count).is_none_or(|end| end > layout.params.rows) {
        return Err(C6HiddenUError::new("C6 hidden-u claim rows exceed Ligero matrix"));
    }
    Ok(ClaimGeometry {
        row0,
        q_row: eq_vec(&claim.point[col_bits..]),
        q_col: eq_vec(&claim.point[..col_bits]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ligero::{commit, open_multi_zk, verify_multi_open};
    use volta_field::{Fp, FpStream};
    use volta_mac::{
        CorrIndex, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
    };
    use volta_proto::mle::eval_mle;

    fn test_layout() -> C6HiddenULayout {
        C6HiddenULayout {
            family: C6HiddenUFamily::Weights,
            params: LigeroParams { rows: 8, col_bits: 3, pad: 4, code_bits: 4, n_queries: 4 },
            claim_count: 2,
            vector_capacity: 4,
            vector_stride: 16,
        }
    }

    fn fp2(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 17 + 3))
    }

    fn query_indices(seed: [u8; 32], layout: C6HiddenULayout) -> (Fp2, Vec<usize>) {
        let mut tx = Transcript::new(seed);
        let c = tx.challenge_fp2();
        let _chi = tx.challenge_fp2();
        let indices = (0..layout.params.n_queries)
            .map(|_| tx.challenge_fp2().c0.value() as usize % layout.code_len())
            .collect();
        (c, indices)
    }

    #[test]
    fn production_layouts_pin_q121_and_removed_bytes() {
        let weights = C6HiddenULayout::production_weights();
        let embed = C6HiddenULayout::production_embed();
        weights.validate().unwrap();
        embed.validate().unwrap();
        assert_eq!(weights.params.n_queries, 121);
        assert_eq!(embed.params.n_queries, 121);
        assert_eq!(weights.live_vectors(), 97);
        assert_eq!(embed.live_vectors(), 7);
        assert_eq!(weights.padded_entries(), 1 << 21);
        assert_eq!(embed.padded_entries(), 1 << 19);
        assert_eq!(weights.relation_count(), 11_833);
        assert_eq!(embed.relation_count(), 853);
        assert_eq!(weights.omitted_u_bytes(), 13_508_608);
        assert_eq!(embed.omitted_u_bytes(), 3_727_360);
        assert_eq!(weights.omitted_u_bytes() + embed.omitted_u_bytes(), 17_235_968);
        let budget = production_hidden_u_reference_budget();
        assert_eq!(budget.family_count, 2);
        assert_eq!(budget.padded_witness_entries, (1 << 21) + (1 << 19));
        assert_eq!(budget.omitted_u_bytes, 17_235_968);
        assert_eq!(budget.prequery_bytes, 1_912);
        assert_eq!(budget.client_batch_seed_bytes, 32);
        assert_eq!(budget.linear_relation_count, 12_686);
        assert_eq!(budget.complete_repetitions, 2);
    }

    #[test]
    fn prequery_codec_is_canonical_and_strict() {
        let layout = test_layout();
        let roots = [[0x31; 32]];
        let q_cols = vec![
            (0..layout.cols() as u64).map(|value| fp2(value + 21)).collect(),
            (0..layout.cols() as u64).map(|value| fp2(value + 41)).collect(),
        ];
        let functional_digest = hidden_u_functional_digest(layout, &q_cols).unwrap();
        let prequery = C6HiddenUPrequery::from_claims(
            &[layout],
            &roots,
            [0x42; 32],
            &[functional_digest],
            vec![vec![fp2(7), fp2(9)]],
        )
        .unwrap();
        let encoded = prequery.encode().unwrap();
        assert_eq!(encoded.len(), 208);
        assert_eq!(
            C6HiddenUPrequery::decode(&[layout], &[functional_digest], &encoded).unwrap(),
            prequery
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6HiddenUPrequery::decode(&[layout], &[functional_digest], &trailing).is_err());

        let mut bad_version = encoded.clone();
        bad_version[4] = 2;
        assert!(C6HiddenUPrequery::decode(&[layout], &[functional_digest], &bad_version).is_err());

        let mut bad_reserved = encoded.clone();
        bad_reserved[41] = 1;
        assert!(C6HiddenUPrequery::decode(&[layout], &[functional_digest], &bad_reserved).is_err());

        let mut bad_field = encoded.clone();
        // Header 40 + family descriptor 104; first ip starts at byte 144.
        bad_field[144..152].copy_from_slice(&P.to_le_bytes());
        assert!(C6HiddenUPrequery::decode(&[layout], &[functional_digest], &bad_field).is_err());

        let mut bad_digest = encoded.clone();
        *bad_digest.last_mut().unwrap() ^= 1;
        assert!(C6HiddenUPrequery::decode(&[layout], &[functional_digest], &bad_digest).is_err());
        assert!(C6HiddenUPrequery::decode(&[layout], &[[0x99; 32]], &encoded).is_err());

        assert_eq!(
            hex(&prequery.digest()),
            "7e6ae8da6a0eec1d4c4daca7e745a2639d4730aac7c51851e2c267a961f3e7fc"
        );
    }

    #[test]
    fn layout_and_witness_shape_fail_closed() {
        let mut layout = test_layout();
        layout.vector_stride = 8;
        assert!(layout.validate().is_err());

        let layout = test_layout();
        let u = vec![Fp2::ZERO; layout.msg_len()];
        let q = vec![Fp2::ZERO; layout.cols()];
        assert!(C6HiddenUFamilyWitness::new(
            layout,
            u.clone(),
            vec![u.clone()],
            vec![q.clone(), q.clone()]
        )
        .is_err());
        assert!(C6HiddenUFamilyWitness::new(
            layout,
            u.clone(),
            vec![u.clone(), vec![Fp2::ZERO; layout.msg_len() - 1]],
            vec![q.clone(), q]
        )
        .is_err());
    }

    #[test]
    fn one_global_rlc_covers_ntt_and_ip_relations() {
        let layout = test_layout();
        let u_c = (0..layout.msg_len() as u64).map(|value| fp2(value + 1)).collect();
        let u_gs = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.msg_len() as u64)
                    .map(|value| fp2(100 * claim as u64 + value + 11))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let q_cols = (0..layout.claim_count)
            .map(|claim| {
                (0..layout.cols() as u64)
                    .map(|value| fp2(200 * claim as u64 + value + 5))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let witness = C6HiddenUFamilyWitness::new(layout, u_c, u_gs, q_cols.clone()).unwrap();
        let bundle = C6HiddenUBundleWitness::new(vec![witness])
            .unwrap()
            .seal(vec![[0x61; 32]], [0x62; 32])
            .unwrap();

        let plan = NttPlan::new(layout.code_len());
        let encoded = bundle.families[0]
            .vectors
            .iter()
            .map(|vector| encode_fp2_ntt(&plan, vector))
            .collect::<Vec<_>>();
        let indices = [0usize, 3, 7, 15];
        let queries = indices
            .iter()
            .map(|index| C6HiddenUQueryClaim {
                index: *index as u32,
                rhs: encoded.iter().map(|vector| vector[*index]).collect(),
            })
            .collect();
        let postcommit = C6HiddenUPostCommit {
            prequery_digest: bundle.prequery().digest(),
            batching_seed: [0x63; 32],
            families: vec![C6HiddenUFamilyPostCommit { family: C6HiddenUFamily::Weights, queries }],
        };
        let audit = bundle.audit_reference(bundle.prequery(), &postcommit).unwrap();
        assert!(audit.exact_relations_hold());
        assert!(audit.batched_relation_holds());
        assert_eq!(audit.ntt_relation_count, 12);
        assert_eq!(audit.ip_relation_count, 2);

        let mut bad_postcommit = postcommit.clone();
        bad_postcommit.families[0].queries[2].rhs[1] += Fp2::ONE;
        let bad = bundle.audit_reference(bundle.prequery(), &bad_postcommit).unwrap();
        assert!(!bad.exact_relations_hold());
        assert!(!bad.batched_relation_holds());
        assert_ne!(bad.aggregate_residuals[0], Fp2::ZERO);
        assert_ne!(bad.aggregate_residuals[1], Fp2::ZERO);

        let mut missing_query = postcommit.clone();
        missing_query.families[0].queries.pop();
        assert!(bundle.audit_reference(bundle.prequery(), &missing_query).is_err());

        let mut wrong_prequery_digest = postcommit.clone();
        wrong_prequery_digest.prequery_digest[0] ^= 1;
        assert!(bundle.audit_reference(bundle.prequery(), &wrong_prequery_digest).is_err());

        let mut bad_ips = bundle.prequery().public_ips(0).unwrap().to_vec();
        bad_ips[0] += Fp2::ONE;
        let bad_prequery = C6HiddenUPrequery::from_claims(
            &[layout],
            &[[0x61; 32]],
            [0x62; 32],
            &[hidden_u_functional_digest(layout, &q_cols).unwrap()],
            vec![bad_ips],
        )
        .unwrap();
        let mut bad_ip_postcommit = postcommit;
        bad_ip_postcommit.prequery_digest = bad_prequery.digest();
        let bad = bundle.audit_reference(&bad_prequery, &bad_ip_postcommit).unwrap();
        assert!(!bad.exact_relations_hold());
        assert!(!bad.batched_relation_holds());

        let mut changed_q_cols = q_cols;
        changed_q_cols[0][0] += Fp2::ONE;
        let wrong_functional_prequery = C6HiddenUPrequery::from_claims(
            &[layout],
            &[[0x61; 32]],
            [0x62; 32],
            &[hidden_u_functional_digest(layout, &changed_q_cols).unwrap()],
            vec![bundle.prequery().public_ips(0).unwrap().to_vec()],
        )
        .unwrap();
        let mut wrong_functional_postcommit = bad_ip_postcommit;
        wrong_functional_postcommit.prequery_digest = wrong_functional_prequery.digest();
        assert!(bundle
            .audit_reference(&wrong_functional_prequery, &wrong_functional_postcommit)
            .is_err());
    }

    fn domain(tensor: u8, row: u32) -> u64 {
        CorrIndex { session: 7, layer: 0, head: 0, tensor, row }.domain()
    }

    #[test]
    fn hidden_relation_matches_the_unchanged_ligero_verifier() {
        let layout = test_layout();
        let params = layout.params;
        let weights = (0..params.rows() * params.cols())
            .map(|index| ((index * 29 + 7) % 251) as i16 - 125)
            .collect::<Vec<_>>();
        let embedded = weights
            .iter()
            .map(|value| Fp2::from_base(Fp::from_i64(*value as i64)))
            .collect::<Vec<_>>();
        let (commitment, matrix) = commit(&weights, &params, [0x71; 32]);
        let pcg_seed = [0x72; 32];
        let tx_seed = [0x73; 32];
        let delta = fp2(77);
        let mut prover_stream = CorrelationStream::new(pcg_seed);
        let mut prover_tx = Transcript::new(tx_seed);

        let mut claims_p = Vec::new();
        let mut corrections = Vec::new();
        for claim_index in 0..layout.claim_count {
            let mut point_stream = FpStream::domain_separated([0x74; 32], claim_index as u64);
            let point = (0..5).map(|_| point_stream.next_fp2()).collect::<Vec<_>>();
            let claim = BlockClaim { offset: claim_index << 5, point };
            let value = eval_mle(&embedded, &claim.global_point(params.n_vars()));
            let correlation = prover_stream.draw_fulls(domain(0xE0, claim_index as u32), 1)[0];
            corrections.push(value - correlation.x);
            prover_tx.append("w_claim_correction", 16);
            claims_p.push((claim, ProverAuthed { x: value, m: correlation.m }));
        }
        let (proof, _) = open_multi_zk(
            &weights,
            &matrix,
            &claims_p,
            &mut prover_stream,
            domain(0xE1, 0),
            domain(0xE1, 1),
            [0x75; 32],
            &mut prover_tx,
        );

        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let claims_v = claims_p
            .iter()
            .enumerate()
            .map(|(index, (claim, _))| {
                let base_key = verifier.expand_full_keys(domain(0xE0, index as u32), 1)[0];
                (claim.clone(), VerifierKey { k: base_key + delta * corrections[index] })
            })
            .collect::<Vec<_>>();
        assert!(verify_multi_open(
            &commitment.root,
            &params,
            &claims_v,
            &proof,
            &mut verifier,
            domain(0xE1, 0),
            domain(0xE1, 1),
            &mut verifier_tx,
        ));

        let (proximity_challenge, indices) = query_indices(tx_seed, layout);
        let bare_claims = claims_p.iter().map(|(claim, _)| claim.clone()).collect::<Vec<_>>();
        let derived = derive_hidden_u_family_claims(
            layout,
            &bare_claims,
            &proof,
            proximity_challenge,
            &indices,
        )
        .unwrap();
        let mut wrong_indices = indices.clone();
        wrong_indices[0] = (wrong_indices[0] + 1) % layout.code_len();
        assert!(derive_hidden_u_family_claims(
            layout,
            &bare_claims,
            &proof,
            proximity_challenge,
            &wrong_indices,
        )
        .is_err());
        let witness =
            C6HiddenUFamilyWitness::from_multi_open(layout, &proof, derived.q_cols).unwrap();
        let sealed = C6HiddenUBundleWitness::new(vec![witness])
            .unwrap()
            .seal(vec![[0x76; 32]], [0x77; 32])
            .unwrap();
        let postcommit = C6HiddenUPostCommit {
            prequery_digest: sealed.prequery().digest(),
            batching_seed: [0x78; 32],
            families: vec![derived.postcommit],
        };
        let audit = sealed.audit_reference(sealed.prequery(), &postcommit).unwrap();
        assert!(audit.exact_relations_hold());
        assert!(audit.batched_relation_holds());
        assert_eq!(audit.ntt_relation_count as usize, layout.params.n_queries * 3);
        assert_eq!(audit.ip_relation_count as usize, layout.claim_count);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
