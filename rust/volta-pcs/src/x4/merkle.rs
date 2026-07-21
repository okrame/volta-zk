//! N4-separated two-dimensional cohort Merkle commitment.
//!
//! A coordinate has an inner tree over canonical block slots.  The outer
//! tree commits the ordered inner roots.  Multiproofs disclose only queried
//! coordinates and touched slots; every internal hash includes its exact
//! role, cohort, oracle, fold round, depth and index.

use std::collections::{BTreeMap, BTreeSet};

use volta_field::Fp2;

use super::frame::{
    hash_pcs_leaf, hash_pcs_node, AuxNode, CohortMultiproofFrame, Digest, FrameError, OracleKind,
    PcsLeafFrame, PcsLeafPayload, PcsNodeFrame, TreeRole,
};

pub const ABSENT_DESCRIPTOR_DIGEST: Digest = [0; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleError {
    Frame(FrameError),
    InvalidGeometry(&'static str),
    InvalidOpening(&'static str),
    Overflow,
}

impl From<FrameError> for MerkleError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CohortIdentity {
    pub cohort_id: u32,
    pub oracle_kind: OracleKind,
    pub fold_round: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortVerifierConfig {
    pub identity: CohortIdentity,
    /// Descriptor digest at each real slot; `None` is a canonical absent
    /// padding slot.  The length is the exact power-of-two inner tree size.
    pub slot_descriptors: Vec<Option<Digest>>,
    pub outer_len: usize,
    /// Symbols carried by a present leaf at this oracle/fold round.
    pub expected_symbol_count: usize,
}

impl CohortVerifierConfig {
    pub fn validate(&self) -> Result<(), MerkleError> {
        if self.slot_descriptors.is_empty() || !self.slot_descriptors.len().is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("inner slot count"));
        }
        if self.outer_len == 0 || !self.outer_len.is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("outer length"));
        }
        if self.expected_symbol_count == 0 || self.expected_symbol_count > usize::from(u16::MAX) {
            return Err(MerkleError::InvalidGeometry("leaf symbol count"));
        }
        let mut seen = BTreeSet::new();
        for digest in self.slot_descriptors.iter().flatten() {
            if *digest == ABSENT_DESCRIPTOR_DIGEST || !seen.insert(*digest) {
                return Err(MerkleError::InvalidGeometry("slot descriptor"));
            }
        }
        Ok(())
    }

    pub fn inner_depth(&self) -> u8 {
        self.slot_descriptors.len().ilog2() as u8
    }

    pub fn outer_depth(&self) -> u8 {
        self.outer_len.ilog2() as u8
    }
}

/// One outer coordinate, with exactly one entry per configured inner slot.
/// Real descriptor slots must be `Some`; canonical padding slots must be
/// `None`.
pub type CoordinateSymbols = Vec<Option<Vec<Fp2>>>;

#[derive(Clone, Debug)]
pub struct CohortTree {
    config: CohortVerifierConfig,
    /// Slot-major, coordinate-major symbols. A present slot has exactly
    /// `outer_len * expected_symbol_count` entries.
    slot_symbols: Vec<Option<Vec<Fp2>>>,
    inner_levels: Vec<Vec<Vec<Digest>>>,
    outer_leaf_frames: Vec<PcsLeafFrame>,
    outer_levels: Vec<Vec<Digest>>,
}

impl CohortTree {
    pub fn build(
        config: CohortVerifierConfig,
        coordinates: Vec<CoordinateSymbols>,
    ) -> Result<Self, MerkleError> {
        config.validate()?;
        if coordinates.len() != config.outer_len {
            return Err(MerkleError::InvalidGeometry("coordinate count"));
        }

        let flat_capacity = config
            .outer_len
            .checked_mul(config.expected_symbol_count)
            .ok_or(MerkleError::Overflow)?;
        let mut slot_symbols: Vec<Option<Vec<Fp2>>> = config
            .slot_descriptors
            .iter()
            .map(|descriptor| descriptor.map(|_| Vec::with_capacity(flat_capacity)))
            .collect();
        for coordinate in coordinates {
            if coordinate.len() != config.slot_descriptors.len() {
                return Err(MerkleError::InvalidGeometry("coordinate slot count"));
            }
            for (slot, symbols) in coordinate.into_iter().enumerate() {
                match (&mut slot_symbols[slot], symbols) {
                    (Some(output), Some(symbols))
                        if symbols.len() == config.expected_symbol_count =>
                    {
                        output.extend(symbols);
                    }
                    (None, None) => {}
                    (Some(_), Some(_)) => {
                        return Err(MerkleError::InvalidGeometry("coordinate symbol count"));
                    }
                    _ => return Err(MerkleError::InvalidGeometry("coordinate presence")),
                }
            }
        }
        Self::build_flat(config, slot_symbols)
    }

    pub fn build_flat(
        config: CohortVerifierConfig,
        slot_symbols: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, MerkleError> {
        config.validate()?;
        if slot_symbols.len() != config.slot_descriptors.len() {
            return Err(MerkleError::InvalidGeometry("flat slot count"));
        }
        let expected_flat_len = config
            .outer_len
            .checked_mul(config.expected_symbol_count)
            .ok_or(MerkleError::Overflow)?;
        for (descriptor, symbols) in config.slot_descriptors.iter().zip(&slot_symbols) {
            match (descriptor, symbols) {
                (Some(_), Some(symbols)) if symbols.len() == expected_flat_len => {}
                (None, None) => {}
                (Some(_), Some(_)) => {
                    return Err(MerkleError::InvalidGeometry("flat symbol count"));
                }
                _ => return Err(MerkleError::InvalidGeometry("flat slot presence")),
            }
        }

        let mut inner_levels = Vec::with_capacity(config.outer_len);
        let mut outer_leaf_frames = Vec::with_capacity(config.outer_len);
        let mut outer_leaf_hashes = Vec::with_capacity(config.outer_len);

        for outer_index_usize in 0..config.outer_len {
            let outer_index =
                u64::try_from(outer_index_usize).map_err(|_| MerkleError::Overflow)?;
            let mut leaf_hashes = Vec::with_capacity(config.slot_descriptors.len());
            for (slot, (descriptor, symbols)) in
                config.slot_descriptors.iter().zip(&slot_symbols).enumerate()
            {
                let slot = u16::try_from(slot).map_err(|_| MerkleError::Overflow)?;
                let (descriptor_digest, present, symbols) = match (descriptor, symbols) {
                    (Some(descriptor_digest), Some(symbols)) => {
                        let start = outer_index_usize
                            .checked_mul(config.expected_symbol_count)
                            .ok_or(MerkleError::Overflow)?;
                        let end = start
                            .checked_add(config.expected_symbol_count)
                            .ok_or(MerkleError::Overflow)?;
                        (*descriptor_digest, true, symbols[start..end].to_vec())
                    }
                    (None, None) => (ABSENT_DESCRIPTOR_DIGEST, false, Vec::new()),
                    _ => unreachable!("flat geometry was validated"),
                };
                let leaf = PcsLeafFrame {
                    cohort_id: config.identity.cohort_id,
                    tree_role: TreeRole::Inner,
                    oracle_kind: config.identity.oracle_kind,
                    fold_round: config.identity.fold_round,
                    outer_index,
                    payload: PcsLeafPayload::Inner { descriptor_digest, slot, present, symbols },
                };
                leaf_hashes.push(hash_pcs_leaf(&leaf)?);
            }
            let levels = build_levels(&config, TreeRole::Inner, outer_index, leaf_hashes)?;
            let inner_root = *levels.last().unwrap().first().unwrap();
            let outer_leaf = PcsLeafFrame {
                cohort_id: config.identity.cohort_id,
                tree_role: TreeRole::Outer,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                payload: PcsLeafPayload::Outer { inner_root_digest: inner_root },
            };
            outer_leaf_hashes.push(hash_pcs_leaf(&outer_leaf)?);
            inner_levels.push(levels);
            outer_leaf_frames.push(outer_leaf);
        }
        let outer_levels = build_levels(&config, TreeRole::Outer, u64::MAX, outer_leaf_hashes)?;
        Ok(Self { config, slot_symbols, inner_levels, outer_leaf_frames, outer_levels })
    }

    pub fn config(&self) -> &CohortVerifierConfig {
        &self.config
    }

    pub fn root(&self) -> Digest {
        self.outer_levels.last().unwrap()[0]
    }

    fn inner_leaf(&self, outer_index: usize, slot: usize) -> Result<PcsLeafFrame, MerkleError> {
        let descriptor = self
            .config
            .slot_descriptors
            .get(slot)
            .ok_or(MerkleError::InvalidOpening("inner leaf slot"))?;
        let symbols =
            self.slot_symbols.get(slot).ok_or(MerkleError::InvalidOpening("inner leaf slot"))?;
        let (descriptor_digest, present, symbols) = match (descriptor, symbols) {
            (Some(descriptor_digest), Some(symbols)) => {
                let start = outer_index
                    .checked_mul(self.config.expected_symbol_count)
                    .ok_or(MerkleError::Overflow)?;
                let end = start
                    .checked_add(self.config.expected_symbol_count)
                    .ok_or(MerkleError::Overflow)?;
                (*descriptor_digest, true, symbols[start..end].to_vec())
            }
            (None, None) => (ABSENT_DESCRIPTOR_DIGEST, false, Vec::new()),
            _ => return Err(MerkleError::InvalidGeometry("stored slot presence")),
        };
        Ok(PcsLeafFrame {
            cohort_id: self.config.identity.cohort_id,
            tree_role: TreeRole::Inner,
            oracle_kind: self.config.identity.oracle_kind,
            fold_round: self.config.identity.fold_round,
            outer_index: u64::try_from(outer_index).map_err(|_| MerkleError::Overflow)?,
            payload: PcsLeafPayload::Inner {
                descriptor_digest,
                slot: u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
                present,
                symbols,
            },
        })
    }

    pub fn open(
        &self,
        outer_indices: &[u64],
        touched_slots: &[u16],
    ) -> Result<CohortMultiproofFrame, MerkleError> {
        require_strictly_increasing(outer_indices, "query indices")?;
        require_strictly_increasing(touched_slots, "touched slots")?;
        if outer_indices.is_empty() || touched_slots.is_empty() {
            return Err(MerkleError::InvalidOpening("empty query"));
        }
        for index in outer_indices {
            let index = usize::try_from(*index).map_err(|_| MerkleError::Overflow)?;
            if index >= self.config.outer_len {
                return Err(MerkleError::InvalidOpening("outer index"));
            }
        }
        for slot in touched_slots {
            let slot = usize::from(*slot);
            if slot >= self.config.slot_descriptors.len()
                || self.config.slot_descriptors[slot].is_none()
            {
                return Err(MerkleError::InvalidOpening("touched slot"));
            }
        }

        let mut opened_leaves = Vec::with_capacity(
            outer_indices
                .len()
                .checked_mul(touched_slots.len() + 1)
                .ok_or(MerkleError::Overflow)?,
        );
        let mut aux_nodes = Vec::new();
        for index in outer_indices {
            let coordinate = usize::try_from(*index).map_err(|_| MerkleError::Overflow)?;
            opened_leaves.push(self.outer_leaf_frames[coordinate].clone());
            for slot in touched_slots {
                opened_leaves.push(self.inner_leaf(coordinate, usize::from(*slot))?);
            }
            collect_aux_nodes(
                &self.config,
                TreeRole::Inner,
                *index,
                &self.inner_levels[coordinate],
                &touched_slots.iter().map(|slot| usize::from(*slot)).collect::<Vec<_>>(),
                &mut aux_nodes,
            )?;
        }
        collect_aux_nodes(
            &self.config,
            TreeRole::Outer,
            u64::MAX,
            &self.outer_levels,
            &outer_indices
                .iter()
                .map(|index| usize::try_from(*index).map_err(|_| MerkleError::Overflow))
                .collect::<Result<Vec<_>, _>>()?,
            &mut aux_nodes,
        )?;
        aux_nodes.sort_by_key(|node| {
            (node.tree_role as u8, node.outer_index, node.level, node.node_index, node.digest)
        });
        let proof = CohortMultiproofFrame {
            cohort_id: self.config.identity.cohort_id,
            oracle_kind: self.config.identity.oracle_kind,
            fold_round: self.config.identity.fold_round,
            outer_indices: outer_indices.to_vec(),
            touched_slots: touched_slots.to_vec(),
            opened_leaves,
            aux_nodes,
        };
        proof.validate()?;
        Ok(proof)
    }
}

pub fn verify_cohort_opening(
    root: Digest,
    config: &CohortVerifierConfig,
    expected_outer_indices: &[u64],
    expected_touched_slots: &[u16],
    proof: &CohortMultiproofFrame,
) -> Result<(), MerkleError> {
    config.validate()?;
    proof.validate()?;
    if proof.cohort_id != config.identity.cohort_id
        || proof.oracle_kind != config.identity.oracle_kind
        || proof.fold_round != config.identity.fold_round
        || proof.outer_indices != expected_outer_indices
        || proof.touched_slots != expected_touched_slots
    {
        return Err(MerkleError::InvalidOpening("proof schedule"));
    }
    require_strictly_increasing(expected_outer_indices, "query indices")?;
    require_strictly_increasing(expected_touched_slots, "touched slots")?;

    let mut aux = BTreeMap::new();
    for node in &proof.aux_nodes {
        let key = (node.tree_role, node.outer_index, node.level, node.node_index);
        if aux.insert(key, node.digest).is_some() {
            return Err(MerkleError::InvalidOpening("duplicate aux node"));
        }
    }
    let mut consumed_aux = BTreeSet::new();
    let mut leaves = proof.opened_leaves.iter();
    let mut outer_hashes = BTreeMap::new();
    for outer_index in expected_outer_indices {
        let outer_index_usize = usize::try_from(*outer_index).map_err(|_| MerkleError::Overflow)?;
        if outer_index_usize >= config.outer_len {
            return Err(MerkleError::InvalidOpening("outer index"));
        }
        let outer_leaf = leaves.next().ok_or(MerkleError::InvalidOpening("outer leaf"))?;
        let expected_inner_root = match &outer_leaf.payload {
            PcsLeafPayload::Outer { inner_root_digest }
                if outer_leaf.tree_role == TreeRole::Outer
                    && outer_leaf.outer_index == *outer_index =>
            {
                *inner_root_digest
            }
            _ => return Err(MerkleError::InvalidOpening("outer leaf")),
        };

        let mut inner_hashes = BTreeMap::new();
        for slot in expected_touched_slots {
            let slot_index = usize::from(*slot);
            let Some(expected_descriptor) =
                config.slot_descriptors.get(slot_index).copied().flatten()
            else {
                return Err(MerkleError::InvalidOpening("touched slot"));
            };
            let leaf = leaves.next().ok_or(MerkleError::InvalidOpening("inner leaf"))?;
            match &leaf.payload {
                PcsLeafPayload::Inner { descriptor_digest, slot: leaf_slot, present, symbols }
                    if leaf.tree_role == TreeRole::Inner
                        && leaf.outer_index == *outer_index
                        && *leaf_slot == *slot
                        && *descriptor_digest == expected_descriptor
                        && *present
                        && symbols.len() == config.expected_symbol_count => {}
                _ => return Err(MerkleError::InvalidOpening("inner leaf")),
            }
            inner_hashes.insert(u64::from(*slot), hash_pcs_leaf(leaf)?);
        }
        let inner_root = reconstruct_root(
            config,
            TreeRole::Inner,
            *outer_index,
            config.inner_depth(),
            inner_hashes,
            &aux,
            &mut consumed_aux,
        )?;
        if inner_root != expected_inner_root {
            return Err(MerkleError::InvalidOpening("inner root"));
        }
        outer_hashes.insert(*outer_index, hash_pcs_leaf(outer_leaf)?);
    }
    if leaves.next().is_some() {
        return Err(MerkleError::InvalidOpening("extra opened leaf"));
    }

    let computed_root = reconstruct_root(
        config,
        TreeRole::Outer,
        u64::MAX,
        config.outer_depth(),
        outer_hashes,
        &aux,
        &mut consumed_aux,
    )?;
    if consumed_aux.len() != aux.len() {
        return Err(MerkleError::InvalidOpening("unused aux node"));
    }
    if computed_root != root {
        return Err(MerkleError::InvalidOpening("outer root"));
    }
    Ok(())
}

fn build_levels(
    config: &CohortVerifierConfig,
    role: TreeRole,
    outer_index: u64,
    leaves: Vec<Digest>,
) -> Result<Vec<Vec<Digest>>, MerkleError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("Merkle leaf count"));
    }
    let mut levels = vec![leaves];
    let mut level = 1u8;
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity(previous.len() / 2);
        for (node_index, pair) in previous.chunks_exact(2).enumerate() {
            let frame = PcsNodeFrame {
                cohort_id: config.identity.cohort_id,
                tree_role: role,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                level,
                node_index: u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                left_digest: pair[0],
                right_digest: pair[1],
            };
            next.push(hash_pcs_node(&frame)?);
        }
        levels.push(next);
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }
    Ok(levels)
}

fn collect_aux_nodes(
    _config: &CohortVerifierConfig,
    role: TreeRole,
    outer_index: u64,
    levels: &[Vec<Digest>],
    opened_indices: &[usize],
    output: &mut Vec<AuxNode>,
) -> Result<(), MerkleError> {
    if opened_indices.is_empty() {
        return Err(MerkleError::InvalidOpening("empty multiproof branch"));
    }
    let mut current: BTreeSet<usize> = opened_indices.iter().copied().collect();
    if current.len() != opened_indices.len()
        || current.iter().any(|index| *index >= levels[0].len())
    {
        return Err(MerkleError::InvalidOpening("multiproof branch indices"));
    }
    for (level, digests) in levels[..levels.len() - 1].iter().enumerate() {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                output.push(AuxNode {
                    tree_role: role,
                    outer_index,
                    level: u8::try_from(level).map_err(|_| MerkleError::Overflow)?,
                    node_index: u64::try_from(sibling).map_err(|_| MerkleError::Overflow)?,
                    digest: digests[sibling],
                });
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(())
}

fn reconstruct_root(
    config: &CohortVerifierConfig,
    role: TreeRole,
    outer_index: u64,
    depth: u8,
    mut current: BTreeMap<u64, Digest>,
    aux: &BTreeMap<(TreeRole, u64, u8, u64), Digest>,
    consumed_aux: &mut BTreeSet<(TreeRole, u64, u8, u64)>,
) -> Result<Digest, MerkleError> {
    if current.is_empty() {
        return Err(MerkleError::InvalidOpening("empty reconstruction"));
    }
    let leaf_count = 1u64.checked_shl(u32::from(depth)).ok_or(MerkleError::Overflow)?;
    if current.keys().any(|index| *index >= leaf_count) {
        return Err(MerkleError::InvalidOpening("reconstruction index"));
    }
    for level in 0..depth {
        let mut next = BTreeMap::new();
        let indices: Vec<u64> = current.keys().copied().collect();
        let mut handled = BTreeSet::new();
        for index in indices {
            if handled.contains(&index) {
                continue;
            }
            let digest = current[&index];
            let sibling_index = index ^ 1;
            let sibling = if let Some(sibling) = current.get(&sibling_index) {
                handled.insert(sibling_index);
                *sibling
            } else {
                let key = (role, outer_index, level, sibling_index);
                let sibling =
                    *aux.get(&key).ok_or(MerkleError::InvalidOpening("missing aux node"))?;
                if !consumed_aux.insert(key) {
                    return Err(MerkleError::InvalidOpening("reused aux node"));
                }
                sibling
            };
            handled.insert(index);
            let (left_digest, right_digest) =
                if index & 1 == 0 { (digest, sibling) } else { (sibling, digest) };
            let node_index = index / 2;
            let frame = PcsNodeFrame {
                cohort_id: config.identity.cohort_id,
                tree_role: role,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                level: level + 1,
                node_index,
                left_digest,
                right_digest,
            };
            let parent = hash_pcs_node(&frame)?;
            if next.insert(node_index, parent).is_some() {
                return Err(MerkleError::InvalidOpening("duplicate reconstructed parent"));
            }
        }
        current = next;
    }
    if current.len() != 1 || !current.contains_key(&0) {
        return Err(MerkleError::InvalidOpening("reconstruction root"));
    }
    Ok(current[&0])
}

fn require_strictly_increasing<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), MerkleError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(MerkleError::InvalidOpening(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::frame::{decode, Frame};
    use volta_field::Fp;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value + 1))
    }

    fn config() -> CohortVerifierConfig {
        CohortVerifierConfig {
            identity: CohortIdentity {
                cohort_id: 41,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), Some([2; 32]), Some([3; 32]), None],
            outer_len: 8,
            expected_symbol_count: 2,
        }
    }

    fn coordinates(config: &CohortVerifierConfig) -> Vec<CoordinateSymbols> {
        (0..config.outer_len)
            .map(|outer| {
                config
                    .slot_descriptors
                    .iter()
                    .enumerate()
                    .map(|(slot, descriptor)| {
                        descriptor.map(|_| {
                            vec![
                                symbol(1000 + (outer * 10 + slot) as u64),
                                symbol(2000 + (outer * 10 + slot) as u64),
                            ]
                        })
                    })
                    .collect()
            })
            .collect()
    }

    fn fixture() -> (CohortVerifierConfig, CohortTree, CohortMultiproofFrame) {
        let config = config();
        let tree = CohortTree::build(config.clone(), coordinates(&config)).unwrap();
        let proof = tree.open(&[1, 6], &[0, 2]).unwrap();
        (config, tree, proof)
    }

    fn rejects(config: &CohortVerifierConfig, root: Digest, proof: &CohortMultiproofFrame) {
        assert!(verify_cohort_opening(root, config, &[1, 6], &[0, 2], proof).is_err());
    }

    #[test]
    fn cohort_roundtrip_opens_only_touched_slots() {
        let (config, tree, proof) = fixture();
        verify_cohort_opening(tree.root(), &config, &[1, 6], &[0, 2], &proof).unwrap();
        assert_eq!(proof.opened_leaves.len(), 2 * (1 + 2));
        assert!(proof.opened_leaves.iter().all(|leaf| match &leaf.payload {
            PcsLeafPayload::Outer { .. } => true,
            PcsLeafPayload::Inner { slot, .. } => matches!(slot, 0 | 2),
        }));

        let bytes = Frame::CohortMultiproof(proof.clone()).encode().unwrap();
        assert_eq!(decode(&bytes).unwrap(), Frame::CohortMultiproof(proof));
    }

    #[test]
    fn every_leaf_identity_and_symbol_tamper_rejects() {
        let (config, tree, proof) = fixture();

        let mut bad = proof.clone();
        match &mut bad.opened_leaves[1].payload {
            PcsLeafPayload::Inner { symbols, .. } => symbols[0] += Fp2::ONE,
            _ => unreachable!(),
        }
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        match &mut bad.opened_leaves[1].payload {
            PcsLeafPayload::Inner { descriptor_digest, .. } => descriptor_digest[0] ^= 1,
            _ => unreachable!(),
        }
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        match &mut bad.opened_leaves[1].payload {
            PcsLeafPayload::Inner { slot, .. } => *slot = 1,
            _ => unreachable!(),
        }
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.opened_leaves[1].cohort_id ^= 1;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.opened_leaves[1].oracle_kind = OracleKind::Auxiliary;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.opened_leaves[1].fold_round = 1;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        match &mut bad.opened_leaves[0].payload {
            PcsLeafPayload::Outer { inner_root_digest } => inner_root_digest[0] ^= 1,
            _ => unreachable!(),
        }
        rejects(&config, tree.root(), &bad);
    }

    #[test]
    fn every_aux_role_depth_index_and_digest_tamper_rejects() {
        let (config, tree, proof) = fixture();
        assert!(!proof.aux_nodes.is_empty());

        let mut bad = proof.clone();
        bad.aux_nodes[0].digest[0] ^= 1;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.aux_nodes[0].node_index ^= 1;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.aux_nodes[0].level = bad.aux_nodes[0].level.saturating_add(1);
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.aux_nodes[0].tree_role = TreeRole::Outer;
        bad.aux_nodes[0].outer_index = u64::MAX;
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        if let Some(node) = bad.aux_nodes.iter_mut().find(|node| node.tree_role == TreeRole::Inner)
        {
            node.outer_index = 6;
        }
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.aux_nodes.pop();
        rejects(&config, tree.root(), &bad);

        let mut bad = proof.clone();
        bad.aux_nodes.push(bad.aux_nodes.last().unwrap().clone());
        rejects(&config, tree.root(), &bad);
    }

    #[test]
    fn proof_context_depth_schedule_and_root_are_not_malleable() {
        let (config, tree, proof) = fixture();

        let mut wrong_root = tree.root();
        wrong_root[0] ^= 1;
        rejects(&config, wrong_root, &proof);
        assert!(verify_cohort_opening(tree.root(), &config, &[1, 5], &[0, 2], &proof).is_err());
        assert!(verify_cohort_opening(tree.root(), &config, &[1, 6], &[0, 1], &proof).is_err());

        let mut wrong_config = config.clone();
        wrong_config.outer_len = 16;
        rejects(&wrong_config, tree.root(), &proof);

        let mut wrong_config = config.clone();
        wrong_config.expected_symbol_count = 1;
        rejects(&wrong_config, tree.root(), &proof);

        let mut wrong_config = config.clone();
        wrong_config.identity.cohort_id ^= 1;
        rejects(&wrong_config, tree.root(), &proof);

        assert_eq!(tree.open(&[1, 1], &[0, 2]), Err(MerkleError::InvalidOpening("query indices")));
        assert_eq!(tree.open(&[1, 6], &[0, 0]), Err(MerkleError::InvalidOpening("touched slots")));
        assert_eq!(tree.open(&[1, 6], &[0, 3]), Err(MerkleError::InvalidOpening("touched slot")));
    }

    #[test]
    fn absent_slot_descriptor_order_and_hash_type_change_the_root() {
        let config = config();
        let coordinates = coordinates(&config);
        let tree = CohortTree::build(config.clone(), coordinates.clone()).unwrap();

        let mut swapped_config = config.clone();
        swapped_config.slot_descriptors.swap(0, 1);
        let mut swapped_coordinates = coordinates.clone();
        for coordinate in &mut swapped_coordinates {
            coordinate.swap(0, 1);
        }
        let swapped = CohortTree::build(swapped_config, swapped_coordinates).unwrap();
        assert_ne!(tree.root(), swapped.root());

        let mut filled_config = config.clone();
        filled_config.slot_descriptors[3] = Some([4; 32]);
        let mut filled_coordinates = coordinates;
        for (outer, coordinate) in filled_coordinates.iter_mut().enumerate() {
            coordinate[3] = Some(vec![symbol(3000 + outer as u64), symbol(4000 + outer as u64)]);
        }
        let filled = CohortTree::build(filled_config, filled_coordinates).unwrap();
        assert_ne!(tree.root(), filled.root());

        let leaf_hash = hash_pcs_leaf(&tree.outer_leaf_frames[0]).unwrap();
        let node_hash = hash_pcs_node(&PcsNodeFrame {
            cohort_id: config.identity.cohort_id,
            tree_role: TreeRole::Outer,
            oracle_kind: config.identity.oracle_kind,
            fold_round: config.identity.fold_round,
            outer_index: u64::MAX,
            level: 1,
            node_index: 0,
            left_digest: [0; 32],
            right_digest: [0; 32],
        })
        .unwrap();
        assert_ne!(leaf_hash, node_hash);
    }

    #[test]
    fn invalid_tree_and_symbol_geometries_fail_closed() {
        let mut bad = config();
        bad.slot_descriptors.pop();
        assert_eq!(bad.validate(), Err(MerkleError::InvalidGeometry("inner slot count")));

        let config = config();
        let mut coords = coordinates(&config);
        coords[0][0].as_mut().unwrap().pop();
        assert!(matches!(
            CohortTree::build(config.clone(), coords),
            Err(MerkleError::InvalidGeometry("coordinate symbol count"))
        ));

        let mut coords = coordinates(&config);
        coords[0][3] = Some(vec![symbol(1), symbol(2)]);
        assert!(matches!(
            CohortTree::build(config, coords),
            Err(MerkleError::InvalidGeometry("coordinate presence"))
        ));
    }
}
