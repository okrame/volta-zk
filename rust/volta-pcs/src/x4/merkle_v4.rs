//! Schema-4 model-global cohort Merkle commitments and packed openings.
//!
//! The tree is the same two-dimensional construction as schema 3, but every
//! leaf and internal node is hashed from a complete schema-4 preimage under a
//! v4 N4-separated domain.  Packed proofs omit only coordinates and node
//! positions that the verifier derives from the sealed 111-draw schedule.

use std::collections::{BTreeMap, BTreeSet};

use volta_field::Fp2;

use super::accounting::{merkle_aux_node_count, projected_query_indices};
use super::frame::{Digest, TreeRole};
use super::frame_v4::{
    hash_pcs_leaf_v4, hash_pcs_node_v4, FoldRoundOpeningV4, InitialOpeningGroupV4, OracleKindV4,
    PcsLeafFrameV4, PcsLeafPayloadV4, PcsNodeFrameV4,
};
use super::merkle::MerkleError;

pub const ABSENT_DESCRIPTOR_DIGEST_V4: Digest = [0; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CohortIdentityV4 {
    pub cohort_id: u32,
    pub oracle_kind: OracleKindV4,
    pub fold_round: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortVerifierConfigV4 {
    pub identity: CohortIdentityV4,
    /// Canonical descriptor-slot vector across all logical namespaces in this
    /// model-global same-domain cohort. `None` is a committed absent slot.
    pub slot_descriptors: Vec<Option<Digest>>,
    pub outer_len: usize,
    pub expected_symbol_count: usize,
}

impl CohortVerifierConfigV4 {
    pub fn validate(&self) -> Result<(), MerkleError> {
        if self.slot_descriptors.is_empty() || !self.slot_descriptors.len().is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("v4 inner slot count"));
        }
        if self.outer_len < 8 || !self.outer_len.is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("v4 outer length"));
        }
        if self.expected_symbol_count != 1 {
            return Err(MerkleError::InvalidGeometry("v4 packed leaf symbol count"));
        }
        match self.identity.oracle_kind {
            OracleKindV4::GlobalFoldAggregate => {
                if self.identity.fold_round == 0 || self.slot_descriptors.len() != 1 {
                    return Err(MerkleError::InvalidGeometry("v4 global fold identity"));
                }
            }
            OracleKindV4::WeightExtension | OracleKindV4::Auxiliary => {
                if self.identity.fold_round != 0 {
                    return Err(MerkleError::InvalidGeometry("v4 initial identity"));
                }
            }
        }
        let mut seen = BTreeSet::new();
        for descriptor in self.slot_descriptors.iter().flatten() {
            if *descriptor == ABSENT_DESCRIPTOR_DIGEST_V4 || !seen.insert(*descriptor) {
                return Err(MerkleError::InvalidGeometry("v4 slot descriptor"));
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

#[derive(Clone, Debug)]
pub struct CohortTreeV4 {
    config: CohortVerifierConfigV4,
    /// Slot-major, coordinate-major retained symbols.
    slot_symbols: Vec<Option<Vec<Fp2>>>,
    inner_levels: Vec<Vec<Vec<Digest>>>,
    outer_levels: Vec<Vec<Digest>>,
}

impl CohortTreeV4 {
    pub fn build_flat(
        config: CohortVerifierConfigV4,
        slot_symbols: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, MerkleError> {
        config.validate()?;
        if slot_symbols.len() != config.slot_descriptors.len() {
            return Err(MerkleError::InvalidGeometry("v4 flat slot count"));
        }
        let expected_len = config
            .outer_len
            .checked_mul(config.expected_symbol_count)
            .ok_or(MerkleError::Overflow)?;
        for (descriptor, symbols) in config.slot_descriptors.iter().zip(&slot_symbols) {
            match (descriptor, symbols) {
                (Some(_), Some(symbols)) if symbols.len() == expected_len => {}
                (None, None) => {}
                (Some(_), Some(_)) => {
                    return Err(MerkleError::InvalidGeometry("v4 flat symbol count"));
                }
                _ => return Err(MerkleError::InvalidGeometry("v4 flat slot presence")),
            }
        }

        let mut inner_levels = Vec::with_capacity(config.outer_len);
        let mut outer_leaf_hashes = Vec::with_capacity(config.outer_len);
        for coordinate in 0..config.outer_len {
            let outer_index = u64::try_from(coordinate).map_err(|_| MerkleError::Overflow)?;
            let mut leaves = Vec::with_capacity(config.slot_descriptors.len());
            for slot in 0..config.slot_descriptors.len() {
                leaves.push(hash_pcs_leaf_v4(&inner_leaf_from_flat(
                    &config,
                    &slot_symbols,
                    coordinate,
                    slot,
                )?)?);
            }
            let levels = build_levels_v4(&config, TreeRole::Inner, outer_index, leaves)?;
            let inner_root = levels.last().unwrap()[0];
            outer_leaf_hashes.push(hash_pcs_leaf_v4(&PcsLeafFrameV4 {
                cohort_id: config.identity.cohort_id,
                tree_role: TreeRole::Outer,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                payload: PcsLeafPayloadV4::Outer { inner_root_digest: inner_root },
            })?);
            inner_levels.push(levels);
        }
        let outer_levels = build_levels_v4(&config, TreeRole::Outer, u64::MAX, outer_leaf_hashes)?;
        Ok(Self { config, slot_symbols, inner_levels, outer_levels })
    }

    pub fn config(&self) -> &CohortVerifierConfigV4 {
        &self.config
    }

    pub fn root(&self) -> Digest {
        self.outer_levels.last().unwrap()[0]
    }

    pub fn open_initial(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<InitialOpeningGroupV4, MerkleError> {
        if matches!(self.config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate) {
            return Err(MerkleError::InvalidOpening("v4 initial oracle kind"));
        }
        validate_touched_slots(&self.config, touched_slots)?;
        let indices = projected_query_indices(query_draws, self.config.outer_depth())
            .map_err(|_| MerkleError::InvalidOpening("v4 projected query indices"))?;
        let mut opened_symbols = Vec::with_capacity(
            indices.len().checked_mul(touched_slots.len()).ok_or(MerkleError::Overflow)?,
        );
        let mut inner_sibling_digests = Vec::new();
        for index in &indices {
            let coordinate = usize::try_from(*index).map_err(|_| MerkleError::Overflow)?;
            for slot in touched_slots {
                let symbols = self.slot_symbols[usize::from(*slot)]
                    .as_ref()
                    .ok_or(MerkleError::InvalidOpening("v4 touched slot"))?;
                opened_symbols.push(symbols[coordinate]);
            }
            append_frontier_digests(
                &self.inner_levels[coordinate],
                &touched_slots.iter().map(|slot| u64::from(*slot)).collect::<Vec<_>>(),
                &mut inner_sibling_digests,
            )?;
        }
        let mut outer_sibling_digests = Vec::new();
        append_frontier_digests(&self.outer_levels, &indices, &mut outer_sibling_digests)?;
        let opening = InitialOpeningGroupV4 {
            cohort_id: self.config.identity.cohort_id,
            domain_log2: self.config.outer_depth(),
            slot_count: u16::try_from(self.config.slot_descriptors.len())
                .map_err(|_| MerkleError::Overflow)?,
            touched_slots: touched_slots.to_vec(),
            opened_symbols,
            inner_sibling_digests,
            outer_sibling_digests,
        };
        opening.validate().map_err(MerkleError::Frame)?;
        Ok(opening)
    }

    pub fn open_fold_round(&self, query_draws: &[u64]) -> Result<FoldRoundOpeningV4, MerkleError> {
        if self.config.identity.oracle_kind != OracleKindV4::GlobalFoldAggregate
            || self.config.slot_descriptors.len() != 1
        {
            return Err(MerkleError::InvalidOpening("v4 fold oracle kind"));
        }
        let indices = projected_query_indices(query_draws, self.config.outer_depth())
            .map_err(|_| MerkleError::InvalidOpening("v4 projected fold indices"))?;
        let symbols =
            self.slot_symbols[0].as_ref().ok_or(MerkleError::InvalidGeometry("v4 fold slot"))?;
        let opened_symbols = indices
            .iter()
            .map(|index| {
                usize::try_from(*index)
                    .map_err(|_| MerkleError::Overflow)
                    .map(|index| symbols[index])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut outer_sibling_digests = Vec::new();
        append_frontier_digests(&self.outer_levels, &indices, &mut outer_sibling_digests)?;
        let opening = FoldRoundOpeningV4 {
            fold_round: self.config.identity.fold_round,
            domain_log2: self.config.outer_depth(),
            opened_symbols,
            outer_sibling_digests,
        };
        opening.validate().map_err(MerkleError::Frame)?;
        Ok(opening)
    }
}

pub fn verify_initial_packed_opening_v4(
    root: Digest,
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    expected_touched_slots: &[u16],
    opening: &InitialOpeningGroupV4,
) -> Result<(), MerkleError> {
    config.validate()?;
    validate_touched_slots(config, expected_touched_slots)?;
    opening.validate().map_err(MerkleError::Frame)?;
    if matches!(config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate)
        || opening.cohort_id != config.identity.cohort_id
        || opening.domain_log2 != config.outer_depth()
        || usize::from(opening.slot_count) != config.slot_descriptors.len()
        || opening.touched_slots != expected_touched_slots
    {
        return Err(MerkleError::InvalidOpening("v4 packed initial schedule"));
    }
    let indices = projected_query_indices(query_draws, config.outer_depth())
        .map_err(|_| MerkleError::InvalidOpening("v4 projected query indices"))?;
    let expected_symbols =
        indices.len().checked_mul(expected_touched_slots.len()).ok_or(MerkleError::Overflow)?;
    let inner_per_coordinate = merkle_aux_node_count(
        config.inner_depth(),
        &expected_touched_slots.iter().map(|slot| u64::from(*slot)).collect::<Vec<_>>(),
    )
    .map_err(|_| MerkleError::InvalidOpening("v4 inner frontier"))?;
    let expected_inner = u64::try_from(indices.len())
        .map_err(|_| MerkleError::Overflow)?
        .checked_mul(inner_per_coordinate)
        .ok_or(MerkleError::Overflow)?;
    let expected_outer = merkle_aux_node_count(config.outer_depth(), &indices)
        .map_err(|_| MerkleError::InvalidOpening("v4 outer frontier"))?;
    if opening.opened_symbols.len() != expected_symbols
        || opening.inner_sibling_digests.len()
            != usize::try_from(expected_inner).map_err(|_| MerkleError::Overflow)?
        || opening.outer_sibling_digests.len()
            != usize::try_from(expected_outer).map_err(|_| MerkleError::Overflow)?
    {
        return Err(MerkleError::InvalidOpening("v4 packed initial counts"));
    }

    let mut symbol_cursor = 0usize;
    let mut inner_cursor = 0usize;
    let mut outer_hashes = BTreeMap::new();
    for outer_index in &indices {
        let mut inner_hashes = BTreeMap::new();
        for slot in expected_touched_slots {
            let descriptor = config.slot_descriptors[usize::from(*slot)]
                .ok_or(MerkleError::InvalidOpening("v4 touched descriptor"))?;
            let symbol = opening.opened_symbols[symbol_cursor];
            symbol_cursor += 1;
            let leaf = PcsLeafFrameV4 {
                cohort_id: config.identity.cohort_id,
                tree_role: TreeRole::Inner,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index: *outer_index,
                payload: PcsLeafPayloadV4::Inner {
                    descriptor_digest: descriptor,
                    slot: *slot,
                    present: true,
                    symbols: vec![symbol],
                },
            };
            inner_hashes.insert(u64::from(*slot), hash_pcs_leaf_v4(&leaf)?);
        }
        let inner_root = reconstruct_root_from_ordered_v4(
            config,
            TreeRole::Inner,
            *outer_index,
            config.inner_depth(),
            inner_hashes,
            &opening.inner_sibling_digests,
            &mut inner_cursor,
        )?;
        let outer_leaf = PcsLeafFrameV4 {
            cohort_id: config.identity.cohort_id,
            tree_role: TreeRole::Outer,
            oracle_kind: config.identity.oracle_kind,
            fold_round: config.identity.fold_round,
            outer_index: *outer_index,
            payload: PcsLeafPayloadV4::Outer { inner_root_digest: inner_root },
        };
        outer_hashes.insert(*outer_index, hash_pcs_leaf_v4(&outer_leaf)?);
    }
    if symbol_cursor != opening.opened_symbols.len()
        || inner_cursor != opening.inner_sibling_digests.len()
    {
        return Err(MerkleError::InvalidOpening("v4 packed initial trailing data"));
    }
    let mut outer_cursor = 0usize;
    let computed = reconstruct_root_from_ordered_v4(
        config,
        TreeRole::Outer,
        u64::MAX,
        config.outer_depth(),
        outer_hashes,
        &opening.outer_sibling_digests,
        &mut outer_cursor,
    )?;
    if outer_cursor != opening.outer_sibling_digests.len() || computed != root {
        return Err(MerkleError::InvalidOpening("v4 packed initial root"));
    }
    Ok(())
}

pub fn verify_fold_round_packed_opening_v4(
    root: Digest,
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    opening: &FoldRoundOpeningV4,
) -> Result<(), MerkleError> {
    config.validate()?;
    opening.validate().map_err(MerkleError::Frame)?;
    if config.identity.oracle_kind != OracleKindV4::GlobalFoldAggregate
        || config.slot_descriptors.len() != 1
        || opening.fold_round != config.identity.fold_round
        || opening.domain_log2 != config.outer_depth()
    {
        return Err(MerkleError::InvalidOpening("v4 packed fold schedule"));
    }
    let indices = projected_query_indices(query_draws, config.outer_depth())
        .map_err(|_| MerkleError::InvalidOpening("v4 projected fold indices"))?;
    let expected_outer = merkle_aux_node_count(config.outer_depth(), &indices)
        .map_err(|_| MerkleError::InvalidOpening("v4 fold frontier"))?;
    if opening.opened_symbols.len() != indices.len()
        || opening.outer_sibling_digests.len()
            != usize::try_from(expected_outer).map_err(|_| MerkleError::Overflow)?
    {
        return Err(MerkleError::InvalidOpening("v4 packed fold counts"));
    }
    let descriptor =
        config.slot_descriptors[0].ok_or(MerkleError::InvalidGeometry("v4 fold descriptor"))?;
    let mut outer_hashes = BTreeMap::new();
    for (outer_index, symbol) in indices.iter().zip(&opening.opened_symbols) {
        let inner_leaf = PcsLeafFrameV4 {
            cohort_id: config.identity.cohort_id,
            tree_role: TreeRole::Inner,
            oracle_kind: config.identity.oracle_kind,
            fold_round: config.identity.fold_round,
            outer_index: *outer_index,
            payload: PcsLeafPayloadV4::Inner {
                descriptor_digest: descriptor,
                slot: 0,
                present: true,
                symbols: vec![*symbol],
            },
        };
        let outer_leaf = PcsLeafFrameV4 {
            cohort_id: config.identity.cohort_id,
            tree_role: TreeRole::Outer,
            oracle_kind: config.identity.oracle_kind,
            fold_round: config.identity.fold_round,
            outer_index: *outer_index,
            payload: PcsLeafPayloadV4::Outer { inner_root_digest: hash_pcs_leaf_v4(&inner_leaf)? },
        };
        outer_hashes.insert(*outer_index, hash_pcs_leaf_v4(&outer_leaf)?);
    }
    let mut cursor = 0usize;
    let computed = reconstruct_root_from_ordered_v4(
        config,
        TreeRole::Outer,
        u64::MAX,
        config.outer_depth(),
        outer_hashes,
        &opening.outer_sibling_digests,
        &mut cursor,
    )?;
    if cursor != opening.outer_sibling_digests.len() || computed != root {
        return Err(MerkleError::InvalidOpening("v4 packed fold root"));
    }
    Ok(())
}

fn inner_leaf_from_flat(
    config: &CohortVerifierConfigV4,
    slot_symbols: &[Option<Vec<Fp2>>],
    outer_index: usize,
    slot: usize,
) -> Result<PcsLeafFrameV4, MerkleError> {
    let (descriptor_digest, present, symbols) =
        match (&config.slot_descriptors[slot], &slot_symbols[slot]) {
            (Some(descriptor), Some(symbols)) => (*descriptor, true, vec![symbols[outer_index]]),
            (None, None) => (ABSENT_DESCRIPTOR_DIGEST_V4, false, Vec::new()),
            _ => return Err(MerkleError::InvalidGeometry("v4 stored slot presence")),
        };
    Ok(PcsLeafFrameV4 {
        cohort_id: config.identity.cohort_id,
        tree_role: TreeRole::Inner,
        oracle_kind: config.identity.oracle_kind,
        fold_round: config.identity.fold_round,
        outer_index: u64::try_from(outer_index).map_err(|_| MerkleError::Overflow)?,
        payload: PcsLeafPayloadV4::Inner {
            descriptor_digest,
            slot: u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
            present,
            symbols,
        },
    })
}

fn build_levels_v4(
    config: &CohortVerifierConfigV4,
    role: TreeRole,
    outer_index: u64,
    leaves: Vec<Digest>,
) -> Result<Vec<Vec<Digest>>, MerkleError> {
    if leaves.is_empty() || !leaves.len().is_power_of_two() {
        return Err(MerkleError::InvalidGeometry("v4 Merkle leaf count"));
    }
    let mut levels = vec![leaves];
    let mut level = 1u8;
    while levels.last().unwrap().len() > 1 {
        let previous = levels.last().unwrap();
        let mut next = Vec::with_capacity(previous.len() / 2);
        for (node_index, pair) in previous.chunks_exact(2).enumerate() {
            next.push(hash_pcs_node_v4(&PcsNodeFrameV4 {
                cohort_id: config.identity.cohort_id,
                tree_role: role,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                level,
                node_index: u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                left_digest: pair[0],
                right_digest: pair[1],
            })?);
        }
        levels.push(next);
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }
    Ok(levels)
}

fn append_frontier_digests(
    levels: &[Vec<Digest>],
    opened_indices: &[u64],
    output: &mut Vec<Digest>,
) -> Result<(), MerkleError> {
    if opened_indices.is_empty()
        || !opened_indices.windows(2).all(|pair| pair[0] < pair[1])
        || levels.is_empty()
        || opened_indices.iter().any(|index| *index >= levels[0].len() as u64)
    {
        return Err(MerkleError::InvalidOpening("v4 frontier indices"));
    }
    let mut current = opened_indices.iter().copied().collect::<BTreeSet<_>>();
    for digests in &levels[..levels.len() - 1] {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                output.push(digests[usize::try_from(sibling).map_err(|_| MerkleError::Overflow)?]);
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(())
}

fn reconstruct_root_from_ordered_v4(
    config: &CohortVerifierConfigV4,
    role: TreeRole,
    outer_index: u64,
    depth: u8,
    mut current: BTreeMap<u64, Digest>,
    siblings: &[Digest],
    cursor: &mut usize,
) -> Result<Digest, MerkleError> {
    if current.is_empty() {
        return Err(MerkleError::InvalidOpening("v4 empty reconstruction"));
    }
    let leaf_count = 1u64.checked_shl(u32::from(depth)).ok_or(MerkleError::Overflow)?;
    if current.keys().any(|index| *index >= leaf_count) {
        return Err(MerkleError::InvalidOpening("v4 reconstruction index"));
    }
    for level in 0..depth {
        let indices = current.keys().copied().collect::<Vec<_>>();
        let mut handled = BTreeSet::new();
        let mut next = BTreeMap::new();
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
                let sibling = *siblings
                    .get(*cursor)
                    .ok_or(MerkleError::InvalidOpening("v4 missing sibling digest"))?;
                *cursor = (*cursor).checked_add(1).ok_or(MerkleError::Overflow)?;
                sibling
            };
            handled.insert(index);
            let (left_digest, right_digest) =
                if index & 1 == 0 { (digest, sibling) } else { (sibling, digest) };
            let node_index = index / 2;
            let parent = hash_pcs_node_v4(&PcsNodeFrameV4 {
                cohort_id: config.identity.cohort_id,
                tree_role: role,
                oracle_kind: config.identity.oracle_kind,
                fold_round: config.identity.fold_round,
                outer_index,
                level: level + 1,
                node_index,
                left_digest,
                right_digest,
            })?;
            if next.insert(node_index, parent).is_some() {
                return Err(MerkleError::InvalidOpening("v4 duplicate reconstructed parent"));
            }
        }
        current = next;
    }
    if current.len() != 1 || !current.contains_key(&0) {
        return Err(MerkleError::InvalidOpening("v4 reconstructed root"));
    }
    Ok(current[&0])
}

fn validate_touched_slots(
    config: &CohortVerifierConfigV4,
    touched_slots: &[u16],
) -> Result<(), MerkleError> {
    if touched_slots.is_empty() || !touched_slots.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(MerkleError::InvalidOpening("v4 touched slot order"));
    }
    for slot in touched_slots {
        if config.slot_descriptors.get(usize::from(*slot)).copied().flatten().is_none() {
            return Err(MerkleError::InvalidOpening("v4 touched slot"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 11 + 1))
    }

    fn initial_config() -> CohortVerifierConfigV4 {
        CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xA500_1234,
                oracle_kind: OracleKindV4::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), Some([2; 32]), Some([3; 32]), None],
            outer_len: 32,
            expected_symbol_count: 1,
        }
    }

    fn initial_tree() -> CohortTreeV4 {
        let config = initial_config();
        let symbols = config
            .slot_descriptors
            .iter()
            .enumerate()
            .map(|(slot, descriptor)| {
                descriptor.map(|_| {
                    (0..config.outer_len)
                        .map(|index| symbol(1000 * slot as u64 + index as u64 + 1))
                        .collect()
                })
            })
            .collect();
        CohortTreeV4::build_flat(config, symbols).unwrap()
    }

    #[test]
    fn model_global_initial_packed_opening_reconstructs_complete_v4_preimages() {
        let tree = initial_tree();
        let draws = (0..111).map(|index| (13 * index % 64) as u64).collect::<Vec<_>>();
        let opening = tree.open_initial(&draws, &[0, 2]).unwrap();
        verify_initial_packed_opening_v4(tree.root(), tree.config(), &draws, &[0, 2], &opening)
            .unwrap();
        assert_eq!(opening.inner_sibling_digests.len() as u64, opening.opened_symbols.len() as u64);
    }

    #[test]
    fn packed_leaf_sibling_slot_and_domain_tampers_reject() {
        let tree = initial_tree();
        let draws = (0..111).map(|index| (index % 4) as u64).collect::<Vec<_>>();
        let opening = tree.open_initial(&draws, &[0, 2]).unwrap();
        let rejects = |opening: &InitialOpeningGroupV4, config: &CohortVerifierConfigV4| {
            assert!(verify_initial_packed_opening_v4(
                tree.root(),
                config,
                &draws,
                &[0, 2],
                opening,
            )
            .is_err());
        };

        let mut bad = opening.clone();
        bad.opened_symbols[0] += Fp2::ONE;
        rejects(&bad, tree.config());
        let mut bad = opening.clone();
        bad.inner_sibling_digests[0][0] ^= 1;
        rejects(&bad, tree.config());
        let mut bad = opening.clone();
        bad.outer_sibling_digests[0][0] ^= 1;
        rejects(&bad, tree.config());
        let mut bad = opening.clone();
        bad.touched_slots = vec![0, 1];
        rejects(&bad, tree.config());
        let mut wrong = tree.config().clone();
        wrong.identity.oracle_kind = OracleKindV4::Auxiliary;
        rejects(&opening, &wrong);
        let mut wrong = tree.config().clone();
        wrong.slot_descriptors.swap(0, 1);
        rejects(&opening, &wrong);
        let mut wrong = tree.config().clone();
        wrong.outer_len *= 2;
        rejects(&opening, &wrong);
    }

    #[test]
    fn global_fold_single_slot_packed_opening_roundtrips() {
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xA500_F001,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: 3,
            },
            slot_descriptors: vec![Some([9; 32])],
            outer_len: 32,
            expected_symbol_count: 1,
        };
        let tree = CohortTreeV4::build_flat(
            config,
            vec![Some((0..32).map(|index| symbol(500 + index)).collect())],
        )
        .unwrap();
        let draws = (0..111).map(|index| (17 * index % 64) as u64).collect::<Vec<_>>();
        let opening = tree.open_fold_round(&draws).unwrap();
        verify_fold_round_packed_opening_v4(tree.root(), tree.config(), &draws, &opening).unwrap();

        let mut bad = opening.clone();
        bad.opened_symbols[0] += Fp2::ONE;
        assert!(
            verify_fold_round_packed_opening_v4(tree.root(), tree.config(), &draws, &bad).is_err()
        );
        let mut bad = opening;
        if let Some(digest) = bad.outer_sibling_digests.first_mut() {
            digest[0] ^= 1;
        } else {
            bad.opened_symbols.pop();
        }
        assert!(
            verify_fold_round_packed_opening_v4(tree.root(), tree.config(), &draws, &bad).is_err()
        );
    }

    #[test]
    fn absent_slot_and_leaf_node_domains_change_model_global_root() {
        let tree = initial_tree();
        let mut config = initial_config();
        config.slot_descriptors[3] = Some([4; 32]);
        let mut symbols = (0..3)
            .map(|slot| {
                Some((0..32).map(|index| symbol(1000 * slot + index + 1)).collect::<Vec<_>>())
            })
            .collect::<Vec<_>>();
        symbols.push(Some((0..32).map(|index| symbol(9000 + index)).collect()));
        let filled = CohortTreeV4::build_flat(config, symbols).unwrap();
        assert_ne!(tree.root(), filled.root());

        let leaf = PcsLeafFrameV4 {
            cohort_id: 1,
            tree_role: TreeRole::Outer,
            oracle_kind: OracleKindV4::WeightExtension,
            fold_round: 0,
            outer_index: 0,
            payload: PcsLeafPayloadV4::Outer { inner_root_digest: [0; 32] },
        };
        let node = PcsNodeFrameV4 {
            cohort_id: 1,
            tree_role: TreeRole::Outer,
            oracle_kind: OracleKindV4::WeightExtension,
            fold_round: 0,
            outer_index: u64::MAX,
            level: 1,
            node_index: 0,
            left_digest: [0; 32],
            right_digest: [0; 32],
        };
        assert_ne!(hash_pcs_leaf_v4(&leaf).unwrap(), hash_pcs_node_v4(&node).unwrap());
    }
}
