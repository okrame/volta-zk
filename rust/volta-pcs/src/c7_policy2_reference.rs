//! C7 policy-2 carrier-independent CPU reference.
//!
//! This module fixes the addressed BLAKE3-XOF byte stream, public salted
//! BLAKE3 leaves, one canonical leaf-opening frame, non-refundable query
//! accounting, and the in-memory accepted-state CAS used by the tiny seam
//! test. It is not a PCS, a durable allocator, or a malicious-DV theorem.

use volta_field::{Fp, P};

pub const C7_POLICY2_LOGICAL_LEAF_SYMBOLS: usize = 141;
pub const C7_POLICY2_SALT_BYTES: usize = 32;
pub const C7_POLICY2_DIGEST_BYTES: usize = 32;
pub const C7_POLICY2_OPENING_FIXED_BYTES: usize = 1_296;
pub const C7_ROOT_MASK_DRAWS: u8 = 6;

const ROOT_MASK_SUITE: &[u8; 14] = b"C7-RM-B3XOF-v1";
const OPENING_MAGIC: &[u8; 8] = b"C7P2OP1\0";
const OPENING_VERSION: u16 = 1;
const LEAF_DOMAIN: &str = "volta-zk/c7/policy2/public-leaf/v1";
const PADDING_LEAF_DOMAIN: &str = "volta-zk/c7/policy2/padding-leaf/v1";
const NODE_DOMAIN: &str = "volta-zk/c7/policy2/tree-node/v1";
const OPENING_DOMAIN: &str = "volta-zk/c7/policy2/opening-frame/v1";

type Digest = [u8; C7_POLICY2_DIGEST_BYTES];
type Result<T> = std::result::Result<T, String>;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C7Policy2Plane {
    PackedWeights = 1,
    ResponseBoundary = 2,
    KvPredecessor = 3,
    KvSuccessor = 4,
}

impl C7Policy2Plane {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PackedWeights),
            2 => Ok(Self::ResponseBoundary),
            3 => Ok(Self::KvPredecessor),
            4 => Ok(Self::KvSuccessor),
            _ => Err("C7 policy-2 leaf plane is unknown".to_owned()),
        }
    }
}

/// Frozen logical input to `C7-RM-B3XOF-v1`. The private seed is never part
/// of this descriptor or any response frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7RootMaskDescriptor {
    pub model_id: Digest,
    pub epoch_id: u64,
    pub layout_digest: Digest,
}

impl C7RootMaskDescriptor {
    pub const ENCODED_BYTES: usize = 90;

    pub fn encode(self) -> Result<[u8; Self::ENCODED_BYTES]> {
        if self.model_id == [0; 32] || self.layout_digest == [0; 32] {
            return Err("C7 root-mask descriptor contains a zero digest".to_owned());
        }
        let mut bytes = [0u8; Self::ENCODED_BYTES];
        bytes[..14].copy_from_slice(ROOT_MASK_SUITE);
        bytes[14..46].copy_from_slice(&self.model_id);
        bytes[46..54].copy_from_slice(&self.epoch_id.to_le_bytes());
        bytes[54..86].copy_from_slice(&self.layout_digest);
        bytes[86..90].copy_from_slice(&[3, 1, 2, 4]); // Fp3, rate 1/2, k0=4.
        Ok(bytes)
    }
}

/// Seekable reference for the selected BLAKE3-XOF candidate. Security remains
/// conditional on the separately required multi-root advantage theorem.
pub struct C7RootMaskXof {
    reader: blake3::OutputReader,
}

impl C7RootMaskXof {
    pub fn new(seed: [u8; 32], descriptor: C7RootMaskDescriptor) -> Result<Self> {
        let mut hasher = blake3::Hasher::new_keyed(&seed);
        hasher.update(&descriptor.encode()?);
        Ok(Self { reader: hasher.finalize_xof() })
    }

    pub fn draw_word(&mut self, coefficient_index: u64, draw_index: u8) -> Result<u64> {
        if draw_index >= C7_ROOT_MASK_DRAWS {
            return Err("C7 root-mask draw index exceeds six-draw profile".to_owned());
        }
        let word_index = coefficient_index
            .checked_mul(u64::from(C7_ROOT_MASK_DRAWS))
            .and_then(|value| value.checked_add(u64::from(draw_index)))
            .ok_or_else(|| "C7 root-mask word index overflows".to_owned())?;
        let offset = word_index
            .checked_mul(8)
            .ok_or_else(|| "C7 root-mask byte offset overflows".to_owned())?;
        if offset > u64::MAX - 8 {
            return Err("C7 root-mask word crosses the XOF position limit".to_owned());
        }
        let mut bytes = [0u8; 8];
        self.reader.set_position(offset);
        self.reader.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    /// First canonical Goldilocks word among the six fixed addresses.
    pub fn coefficient(&mut self, coefficient_index: u64) -> Result<(Fp, u8)> {
        for draw in 0..C7_ROOT_MASK_DRAWS {
            let word = self.draw_word(coefficient_index, draw)?;
            if word < P {
                return Ok((Fp::new(word), draw + 1));
            }
        }
        Err("C7 root-mask coefficient exhausted all six draws".to_owned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Policy2LeafMetadata {
    pub root_context: Digest,
    pub plane: C7Policy2Plane,
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub total_symbols: u64,
    pub payload_len: u16,
}

impl C7Policy2LeafMetadata {
    pub fn validate(self) -> Result<()> {
        if self.root_context == [0; 32] || self.total_symbols == 0 || self.leaf_count == 0 {
            return Err("C7 policy-2 leaf geometry contains zero".to_owned());
        }
        let width = C7_POLICY2_LOGICAL_LEAF_SYMBOLS as u64;
        let expected_leaf_count = self
            .total_symbols
            .checked_add(width - 1)
            .ok_or_else(|| "C7 policy-2 leaf count overflows".to_owned())?
            / width;
        if self.leaf_count != expected_leaf_count || self.leaf_index >= self.leaf_count {
            return Err("C7 policy-2 leaf count or index differs".to_owned());
        }
        let start = self
            .leaf_index
            .checked_mul(width)
            .ok_or_else(|| "C7 policy-2 leaf offset overflows".to_owned())?;
        let expected_len = (self.total_symbols - start).min(width) as u16;
        if self.payload_len != expected_len {
            return Err("C7 policy-2 leaf payload length differs".to_owned());
        }
        Ok(())
    }
}

pub fn c7_policy2_leaf_digest(
    metadata: C7Policy2LeafMetadata,
    salt: [u8; C7_POLICY2_SALT_BYTES],
    payload: &[Fp; C7_POLICY2_LOGICAL_LEAF_SYMBOLS],
) -> Result<Digest> {
    metadata.validate()?;
    if payload[usize::from(metadata.payload_len)..].iter().any(|value| *value != Fp::ZERO) {
        return Err("C7 policy-2 padding is nonzero".to_owned());
    }
    let mut hasher = blake3::Hasher::new_derive_key(LEAF_DOMAIN);
    hasher.update(&metadata.root_context);
    hasher.update(&[metadata.plane as u8]);
    hasher.update(&metadata.leaf_index.to_le_bytes());
    hasher.update(&metadata.leaf_count.to_le_bytes());
    hasher.update(&metadata.total_symbols.to_le_bytes());
    hasher.update(&metadata.payload_len.to_le_bytes());
    hasher.update(&salt);
    for value in payload {
        hasher.update(&value.value().to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn padding_leaf_digest(root_context: Digest, leaf_count: u64, index: u64) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(PADDING_LEAF_DOMAIN);
    hasher.update(&root_context);
    hasher.update(&leaf_count.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn node_digest(level: u16, left: Digest, right: Digest) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(NODE_DOMAIN);
    hasher.update(&level.to_le_bytes());
    hasher.update(&left);
    hasher.update(&right);
    *hasher.finalize().as_bytes()
}

/// Full-memory tree used only by the tiny reference. Production setup still
/// owes a streaming ordered-root implementation and measured resource row.
pub struct C7Policy2ReferenceTree {
    root_context: Digest,
    real_leaf_count: u64,
    levels: Vec<Vec<Digest>>,
}

impl C7Policy2ReferenceTree {
    pub fn from_leaf_digests(root_context: Digest, leaves: Vec<Digest>) -> Result<Self> {
        if root_context == [0; 32] || leaves.is_empty() {
            return Err("C7 policy-2 tree input is empty or has zero context".to_owned());
        }
        let real_leaf_count = leaves.len() as u64;
        let padded_count = leaves
            .len()
            .checked_next_power_of_two()
            .ok_or_else(|| "C7 policy-2 padded leaf count overflows".to_owned())?;
        let mut bottom = leaves;
        for index in bottom.len()..padded_count {
            bottom.push(padding_leaf_digest(root_context, real_leaf_count, index as u64));
        }
        let mut levels = vec![bottom];
        let mut level = 0u16;
        while levels.last().expect("tree has bottom level").len() > 1 {
            let next = levels
                .last()
                .expect("tree has prior level")
                .chunks_exact(2)
                .map(|pair| node_digest(level, pair[0], pair[1]))
                .collect();
            levels.push(next);
            level = level
                .checked_add(1)
                .ok_or_else(|| "C7 policy-2 tree depth overflows".to_owned())?;
        }
        Ok(Self { root_context, real_leaf_count, levels })
    }

    pub fn root(&self) -> Digest {
        self.levels.last().expect("tree has root")[0]
    }

    pub fn depth(&self) -> u16 {
        (self.levels.len() - 1) as u16
    }

    pub fn open_path(&self, leaf_index: u64) -> Result<Vec<Digest>> {
        if leaf_index >= self.real_leaf_count {
            return Err("C7 policy-2 opening index is outside real leaves".to_owned());
        }
        let mut index = usize::try_from(leaf_index)
            .map_err(|_| "C7 policy-2 opening index exceeds usize".to_owned())?;
        let mut path = Vec::with_capacity(self.depth() as usize);
        for level in &self.levels[..self.levels.len() - 1] {
            path.push(level[index ^ 1]);
            index >>= 1;
        }
        Ok(path)
    }

    pub fn root_context(&self) -> Digest {
        self.root_context
    }
}

fn expected_tree_depth(leaf_count: u64) -> Result<u16> {
    let count = usize::try_from(leaf_count)
        .map_err(|_| "C7 policy-2 leaf count exceeds usize".to_owned())?;
    let padded = count
        .checked_next_power_of_two()
        .ok_or_else(|| "C7 policy-2 tree depth overflows".to_owned())?;
    Ok(padded.trailing_zeros() as u16)
}

fn verify_path(root: Digest, mut index: u64, leaf: Digest, path: &[Digest]) -> bool {
    let mut current = leaf;
    for (level, sibling) in path.iter().enumerate() {
        current = if index & 1 == 0 {
            node_digest(level as u16, current, *sibling)
        } else {
            node_digest(level as u16, *sibling, current)
        };
        index >>= 1;
    }
    current == root
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C7Policy2LeafOpening {
    pub metadata: C7Policy2LeafMetadata,
    pub root: Digest,
    pub salt: [u8; C7_POLICY2_SALT_BYTES],
    pub payload: [Fp; C7_POLICY2_LOGICAL_LEAF_SYMBOLS],
    pub path: Vec<Digest>,
}

impl C7Policy2LeafOpening {
    pub fn verify(&self) -> Result<()> {
        self.metadata.validate()?;
        if self.root == [0; 32]
            || self.path.len() != usize::from(expected_tree_depth(self.metadata.leaf_count)?)
        {
            return Err("C7 policy-2 opening root or depth differs".to_owned());
        }
        let leaf = c7_policy2_leaf_digest(self.metadata, self.salt, &self.payload)?;
        if !verify_path(self.root, self.metadata.leaf_index, leaf, &self.path) {
            return Err("C7 policy-2 Merkle path does not reach the root".to_owned());
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize> {
        self.verify()?;
        C7_POLICY2_OPENING_FIXED_BYTES
            .checked_add(self.path.len() * C7_POLICY2_DIGEST_BYTES)
            .ok_or_else(|| "C7 policy-2 opening length overflows".to_owned())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let encoded_len = self.encoded_len()?;
        let mut bytes = Vec::with_capacity(encoded_len);
        bytes.extend_from_slice(OPENING_MAGIC);
        bytes.extend_from_slice(&OPENING_VERSION.to_le_bytes());
        bytes.push(self.metadata.plane as u8);
        bytes.push(0);
        bytes.extend_from_slice(&self.metadata.root_context);
        bytes.extend_from_slice(&self.root);
        bytes.extend_from_slice(&self.metadata.leaf_index.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.leaf_count.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.total_symbols.to_le_bytes());
        bytes.extend_from_slice(&self.metadata.payload_len.to_le_bytes());
        bytes.extend_from_slice(&(self.path.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.salt);
        for value in self.payload {
            bytes.extend_from_slice(&value.value().to_le_bytes());
        }
        for sibling in &self.path {
            bytes.extend_from_slice(sibling);
        }
        let digest = domain_digest(OPENING_DOMAIN, &bytes);
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < C7_POLICY2_OPENING_FIXED_BYTES
            || bytes.get(..8) != Some(OPENING_MAGIC)
            || u16_at(bytes, 8)? != OPENING_VERSION
            || bytes[11] != 0
        {
            return Err("C7 policy-2 opening header differs".to_owned());
        }
        let path_len = usize::from(u16_at(bytes, 102)?);
        let expected_len = C7_POLICY2_OPENING_FIXED_BYTES
            .checked_add(path_len * C7_POLICY2_DIGEST_BYTES)
            .ok_or_else(|| "C7 policy-2 opening length overflows".to_owned())?;
        if bytes.len() != expected_len
            || bytes[bytes.len() - 32..]
                != domain_digest(OPENING_DOMAIN, &bytes[..bytes.len() - 32])
        {
            return Err("C7 policy-2 opening length or digest differs".to_owned());
        }
        let metadata = C7Policy2LeafMetadata {
            root_context: digest_at(bytes, 12)?,
            plane: C7Policy2Plane::decode(bytes[10])?,
            leaf_index: u64_at(bytes, 76)?,
            leaf_count: u64_at(bytes, 84)?,
            total_symbols: u64_at(bytes, 92)?,
            payload_len: u16_at(bytes, 100)?,
        };
        let root = digest_at(bytes, 44)?;
        let salt = digest_at(bytes, 104)?;
        let mut payload = [Fp::ZERO; C7_POLICY2_LOGICAL_LEAF_SYMBOLS];
        let mut offset = 136;
        for value in &mut payload {
            let limb = u64_at(bytes, offset)?;
            if limb >= P {
                return Err("C7 policy-2 opening contains a noncanonical Fp".to_owned());
            }
            *value = Fp::new(limb);
            offset += 8;
        }
        let path_end = offset + path_len * 32;
        let path = bytes[offset..path_end]
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().expect("exact digest chunk"))
            .collect();
        let opening = Self { metadata, root, salt, payload, path };
        opening.verify()?;
        if opening.encode()? != bytes {
            return Err("C7 policy-2 opening is not canonical".to_owned());
        }
        Ok(opening)
    }

    pub fn query_census(&self) -> Result<C7Policy2QueryCensus> {
        self.verify()?;
        Ok(C7Policy2QueryCensus {
            logical_samples: 1,
            visible_fp: C7_POLICY2_LOGICAL_LEAF_SYMBOLS as u64,
            unique_leaves: 1,
            sibling_nodes: self.path.len() as u64,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C7Policy2QueryCensus {
    pub logical_samples: u64,
    pub visible_fp: u64,
    pub unique_leaves: u64,
    pub sibling_nodes: u64,
}

impl C7Policy2QueryCensus {
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        Some(Self {
            logical_samples: self.logical_samples.checked_add(rhs.logical_samples)?,
            visible_fp: self.visible_fp.checked_add(rhs.visible_fp)?,
            unique_leaves: self.unique_leaves.checked_add(rhs.unique_leaves)?,
            sibling_nodes: self.sibling_nodes.checked_add(rhs.sibling_nodes)?,
        })
    }

    pub fn componentwise_le(self, rhs: Self) -> bool {
        self.logical_samples <= rhs.logical_samples
            && self.visible_fp <= rhs.visible_fp
            && self.unique_leaves <= rhs.unique_leaves
            && self.sibling_nodes <= rhs.sibling_nodes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C7Policy2AttemptStatus {
    Reserved,
    InFlight,
    Accepted,
    Burned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7Policy2BudgetProfile {
    pub q_attempt: C7Policy2QueryCensus,
    pub q_root: C7Policy2QueryCensus,
    pub max_attempts: u64,
}

/// In-memory reference for fixed, non-refundable reservations. Durability,
/// allocator authentication, concurrency, and crash recovery remain gates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C7Policy2RootBudget {
    profile: C7Policy2BudgetProfile,
    spent: C7Policy2QueryCensus,
    attempts_reserved: u64,
    active: Option<(u64, C7Policy2AttemptStatus)>,
    last_response: Option<C7Policy2QueryCensus>,
}

impl C7Policy2RootBudget {
    pub fn new(profile: C7Policy2BudgetProfile) -> Result<Self> {
        if profile.max_attempts == 0
            || profile.q_attempt.logical_samples == 0
            || profile.q_attempt.visible_fp == 0
            || profile.q_attempt.unique_leaves == 0
            || !profile.q_attempt.componentwise_le(profile.q_root)
        {
            return Err("C7 policy-2 budget profile is empty or inconsistent".to_owned());
        }
        Ok(Self {
            profile,
            spent: C7Policy2QueryCensus::default(),
            attempts_reserved: 0,
            active: None,
            last_response: None,
        })
    }

    /// Charges the full fixed attempt before any leaf can be disclosed.
    pub fn reserve(&mut self) -> Result<u64> {
        if self.active.is_some() || self.attempts_reserved >= self.profile.max_attempts {
            return Err("C7 policy-2 attempt cannot be reserved".to_owned());
        }
        let next_spent = self
            .spent
            .checked_add(self.profile.q_attempt)
            .ok_or_else(|| "C7 policy-2 budget counter overflows".to_owned())?;
        if !next_spent.componentwise_le(self.profile.q_root) {
            return Err("C7 policy-2 root budget is exhausted".to_owned());
        }
        let attempt = self.attempts_reserved;
        self.attempts_reserved += 1;
        self.spent = next_spent;
        self.active = Some((attempt, C7Policy2AttemptStatus::Reserved));
        Ok(attempt)
    }

    pub fn start(&mut self, attempt: u64) -> Result<()> {
        if self.active != Some((attempt, C7Policy2AttemptStatus::Reserved)) {
            return Err("C7 policy-2 attempt is not reserved".to_owned());
        }
        self.active = Some((attempt, C7Policy2AttemptStatus::InFlight));
        Ok(())
    }

    pub fn finish(
        &mut self,
        attempt: u64,
        accepted: bool,
        q_response: C7Policy2QueryCensus,
    ) -> Result<C7Policy2AttemptStatus> {
        let Some((active, status)) = self.active else {
            return Err("C7 policy-2 attempt is absent".to_owned());
        };
        if active != attempt
            || !q_response.componentwise_le(self.profile.q_attempt)
            || !matches!(
                (status, accepted),
                (C7Policy2AttemptStatus::InFlight, true)
                    | (C7Policy2AttemptStatus::Reserved | C7Policy2AttemptStatus::InFlight, false)
            )
        {
            return Err("C7 policy-2 attempt transition is illegal".to_owned());
        }
        let terminal = if accepted {
            C7Policy2AttemptStatus::Accepted
        } else {
            C7Policy2AttemptStatus::Burned
        };
        self.active = None;
        self.last_response = Some(q_response);
        Ok(terminal)
    }

    pub fn spent(&self) -> C7Policy2QueryCensus {
        self.spent
    }

    pub fn last_response(&self) -> Option<C7Policy2QueryCensus> {
        self.last_response
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7ReferenceAcceptedState {
    pub epoch: u64,
    pub kv_len: u64,
    pub kv_root: Digest,
    pub certificate_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C7ReferenceVerifiedTransition {
    pub old_epoch: u64,
    pub old_kv_len: u64,
    pub old_kv_root: Digest,
    pub new_epoch: u64,
    pub new_kv_len: u64,
    pub new_kv_root: Digest,
    pub certificate_digest: Digest,
}

impl C7ReferenceAcceptedState {
    /// CAS after external relation/PCS/MAC verification. This function proves
    /// no prefix relation; it only prevents replay and competing promotion.
    pub fn promote_verified(&mut self, transition: C7ReferenceVerifiedTransition) -> Result<()> {
        if transition.old_epoch != self.epoch
            || transition.old_kv_len != self.kv_len
            || transition.old_kv_root != self.kv_root
            || transition.new_epoch != self.epoch.checked_add(1).ok_or("C7 epoch overflows")?
            || transition.new_kv_len < self.kv_len
            || transition.new_kv_root == [0; 32]
            || transition.certificate_digest == [0; 32]
        {
            return Err("C7 verified transition does not extend the accepted head".to_owned());
        }
        *self = Self {
            epoch: transition.new_epoch,
            kv_len: transition.new_kv_len,
            kv_root: transition.new_kv_root,
            certificate_digest: transition.certificate_digest,
        };
        Ok(())
    }
}

fn domain_digest(domain: &str, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| "C7 policy-2 frame is truncated".to_owned())
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    bytes
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| "C7 policy-2 frame is truncated".to_owned())
}

fn digest_at(bytes: &[u8], offset: usize) -> Result<Digest> {
    bytes
        .get(offset..offset + 32)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| "C7 policy-2 frame is truncated".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp3;
    use volta_mac::{
        c7_fp3_transfer_prover, c7_fp3_transfer_verifier, C7Fp3ProverAuthed, C7Fp3VerifierKey,
    };

    fn fp3(a: u64, b: u64, c: u64) -> Fp3 {
        Fp3::new(Fp::new(a), Fp::new(b), Fp::new(c))
    }

    fn masked_leaf(
        xof: &mut C7RootMaskXof,
        start: u64,
        payload_len: usize,
    ) -> [Fp; C7_POLICY2_LOGICAL_LEAF_SYMBOLS] {
        let mut payload = [Fp::ZERO; C7_POLICY2_LOGICAL_LEAF_SYMBOLS];
        for (local, value) in payload[..payload_len].iter_mut().enumerate() {
            let source = Fp::new(start + local as u64 + 1);
            let (mask, _) = xof.coefficient(start + local as u64).unwrap();
            *value = source + mask;
        }
        payload
    }

    #[test]
    fn tiny_policy2_codec_budget_terminal_and_state_seam() {
        let descriptor =
            C7RootMaskDescriptor { model_id: [0x11; 32], epoch_id: 7, layout_digest: [0x22; 32] };
        assert_eq!(descriptor.encode().unwrap().len(), 90);
        let mut xof = C7RootMaskXof::new([0x33; 32], descriptor).unwrap();
        assert_eq!(xof.draw_word(0, 0).unwrap(), 16_865_677_179_585_383_035);
        assert_eq!(xof.draw_word(1, 0).unwrap(), 14_444_659_047_400_826_690);
        assert!(xof.draw_word(0, C7_ROOT_MASK_DRAWS).is_err());
        assert!(xof.draw_word(u64::MAX, 0).is_err());
        assert!(C7RootMaskXof::new([0; 32], descriptor).is_ok());

        let root_context = [0x44; 32];
        let total_symbols = 200u64;
        let first_payload = masked_leaf(&mut xof, 0, 141);
        let second_payload = masked_leaf(&mut xof, 141, 59);
        let first_metadata = C7Policy2LeafMetadata {
            root_context,
            plane: C7Policy2Plane::PackedWeights,
            leaf_index: 0,
            leaf_count: 2,
            total_symbols,
            payload_len: 141,
        };
        let second_metadata =
            C7Policy2LeafMetadata { leaf_index: 1, payload_len: 59, ..first_metadata };
        let first_salt = [0x55; 32];
        let second_salt = [0x66; 32];
        assert!(c7_policy2_leaf_digest(first_metadata, [0; 32], &first_payload).is_ok());
        let first_digest =
            c7_policy2_leaf_digest(first_metadata, first_salt, &first_payload).unwrap();
        let second_digest =
            c7_policy2_leaf_digest(second_metadata, second_salt, &second_payload).unwrap();
        let tree = C7Policy2ReferenceTree::from_leaf_digests(
            root_context,
            vec![first_digest, second_digest],
        )
        .unwrap();
        assert_eq!(tree.root_context(), root_context);
        assert_eq!(tree.depth(), 1);
        let opening = C7Policy2LeafOpening {
            metadata: first_metadata,
            root: tree.root(),
            salt: first_salt,
            payload: first_payload,
            path: tree.open_path(0).unwrap(),
        };
        let encoded = opening.encode().unwrap();
        assert_eq!(encoded.len(), C7_POLICY2_OPENING_FIXED_BYTES + 32);
        assert_eq!(C7Policy2LeafOpening::decode(&encoded).unwrap(), opening);
        assert_eq!(
            opening.query_census().unwrap(),
            C7Policy2QueryCensus {
                logical_samples: 1,
                visible_fp: 141,
                unique_leaves: 1,
                sibling_nodes: 1,
            }
        );
        let mut wrong_payload = opening.clone();
        wrong_payload.payload[0] += Fp::ONE;
        assert!(wrong_payload.verify().is_err());
        let mut noncanonical = encoded.clone();
        noncanonical[136..144].copy_from_slice(&P.to_le_bytes());
        let last = noncanonical.len() - 32;
        let digest = domain_digest(OPENING_DOMAIN, &noncanonical[..last]);
        noncanonical[last..].copy_from_slice(&digest);
        assert!(C7Policy2LeafOpening::decode(&noncanonical).is_err());
        let mut mutated = encoded;
        mutated[136] ^= 1;
        assert!(C7Policy2LeafOpening::decode(&mutated).is_err());
        let mut bad_padding = second_payload;
        bad_padding[59] = Fp::ONE;
        assert!(c7_policy2_leaf_digest(second_metadata, second_salt, &bad_padding).is_err());

        let per_attempt = C7Policy2QueryCensus {
            logical_samples: 1,
            visible_fp: 141,
            unique_leaves: 1,
            sibling_nodes: 1,
        };
        let q_root = per_attempt.checked_add(per_attempt).unwrap();
        let mut budget = C7Policy2RootBudget::new(C7Policy2BudgetProfile {
            q_attempt: per_attempt,
            q_root,
            max_attempts: 2,
        })
        .unwrap();
        let aborted = budget.reserve().unwrap();
        budget.start(aborted).unwrap();
        assert_eq!(
            budget.finish(aborted, false, C7Policy2QueryCensus::default()).unwrap(),
            C7Policy2AttemptStatus::Burned
        );
        assert_eq!(budget.spent(), per_attempt);
        assert_eq!(budget.last_response(), Some(C7Policy2QueryCensus::default()));
        let accepted = budget.reserve().unwrap();
        budget.start(accepted).unwrap();
        let oversized = C7Policy2QueryCensus { visible_fp: 142, ..per_attempt };
        assert!(budget.finish(accepted, true, oversized).is_err());
        assert_eq!(
            budget.finish(accepted, true, per_attempt).unwrap(),
            C7Policy2AttemptStatus::Accepted
        );
        assert_eq!(budget.spent(), q_root);
        assert!(budget.reserve().is_err());

        let delta = fp3(3, 5, 7);
        let correlation = C7Fp3ProverAuthed::new(fp3(11, 13, 17), fp3(19, 23, 29));
        let key = C7Fp3VerifierKey::new(correlation.m + delta * correlation.x);
        let target = fp3(31, 37, 41);
        let (correction, authenticated) = c7_fp3_transfer_prover(correlation, target);
        let corrected_key = c7_fp3_transfer_verifier(key, delta, correction);
        assert_eq!(corrected_key.k, authenticated.m + delta * authenticated.x);

        let mut state = C7ReferenceAcceptedState {
            epoch: 0,
            kv_len: 100,
            kv_root: [0x77; 32],
            certificate_digest: [0; 32],
        };
        let transition = C7ReferenceVerifiedTransition {
            old_epoch: 0,
            old_kv_len: 100,
            old_kv_root: [0x77; 32],
            new_epoch: 1,
            new_kv_len: 150,
            new_kv_root: [0x88; 32],
            certificate_digest: [0x99; 32],
        };
        state.promote_verified(transition).unwrap();
        assert_eq!(state.epoch, 1);
        assert!(state.promote_verified(transition).is_err()); // replay
        let fork = C7ReferenceVerifiedTransition {
            new_kv_root: [0xaa; 32],
            certificate_digest: [0xbb; 32],
            ..transition
        };
        assert!(state.promote_verified(fork).is_err());
    }
}
