//! Closed byte accounting for canonical X4 cohort multiproofs.
//!
//! The production prover may materialize or recompute Merkle artifacts, but
//! neither policy changes these wire sizes.  Keeping the formula next to the
//! normative codec lets preflights account for production-sized trees without
//! allocating their codewords.

use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiproofAccountingError {
    InvalidGeometry(&'static str),
    Overflow,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CohortMultiproofByteCount {
    pub query_count: u64,
    pub touched_slot_count: u64,
    pub inner_aux_nodes_per_query: u64,
    pub inner_aux_nodes: u64,
    pub outer_aux_nodes: u64,
    pub total_aux_nodes: u64,
    /// Complete canonical cohort frame with every auxiliary-node entry
    /// assigned zero bytes.  This is a strict lower bound, not a decodable
    /// frame.
    pub bytes_without_aux_nodes: u64,
    /// Complete canonical serialized frame length.
    pub serialized_bytes: u64,
}

/// Project a response-wide exact-bit draw schedule into one power-of-two
/// folding domain and return the canonical sorted/deduplicated `+/-` set.
/// The input remains the ordered multiset; this function is only the wire
/// compression used by the multiproof.
pub fn projected_query_indices(
    query_draws: &[u64],
    domain_log2: u8,
) -> Result<Vec<u64>, MultiproofAccountingError> {
    if !(1..=63).contains(&domain_log2) || query_draws.is_empty() {
        return Err(MultiproofAccountingError::InvalidGeometry("query domain"));
    }
    let half =
        1u64.checked_shl(u32::from(domain_log2 - 1)).ok_or(MultiproofAccountingError::Overflow)?;
    let mask = half - 1;
    let mut indices = BTreeSet::new();
    for draw in query_draws {
        let base = *draw & mask;
        indices.insert(base);
        indices.insert(base + half);
    }
    Ok(indices.into_iter().collect())
}

/// Number of sibling digests in the canonical binary Merkle multiproof for
/// an exact sorted leaf set.
pub fn merkle_aux_node_count(
    depth: u8,
    opened_indices: &[u64],
) -> Result<u64, MultiproofAccountingError> {
    if opened_indices.is_empty() || !opened_indices.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(MultiproofAccountingError::InvalidGeometry("Merkle opening indices"));
    }
    let leaf_count =
        1u64.checked_shl(u32::from(depth)).ok_or(MultiproofAccountingError::Overflow)?;
    if opened_indices.iter().any(|index| *index >= leaf_count) {
        return Err(MultiproofAccountingError::InvalidGeometry("Merkle opening range"));
    }

    let mut current = opened_indices.iter().copied().collect::<BTreeSet<_>>();
    let mut count = 0u64;
    for _ in 0..depth {
        let mut next = BTreeSet::new();
        for index in &current {
            if !current.contains(&(*index ^ 1)) {
                count = count.checked_add(1).ok_or(MultiproofAccountingError::Overflow)?;
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(count)
}

/// Exact v3 `CohortMultiproofFrame` byte count for a power-of-two cohort.
///
/// Each queried coordinate carries one 63-byte outer leaf and one present
/// inner leaf per touched slot.  A present inner leaf is `68 + 16*S` bytes
/// for `S` field symbols.  Every canonical auxiliary-node entry is 50 bytes.
pub fn cohort_multiproof_byte_count(
    domain_log2: u8,
    total_slots: usize,
    touched_slots: &[u16],
    expected_symbol_count: usize,
    outer_indices: &[u64],
) -> Result<CohortMultiproofByteCount, MultiproofAccountingError> {
    if total_slots == 0
        || !total_slots.is_power_of_two()
        || touched_slots.is_empty()
        || !touched_slots.windows(2).all(|pair| pair[0] < pair[1])
        || touched_slots.iter().any(|slot| usize::from(*slot) >= total_slots)
        || expected_symbol_count == 0
        || expected_symbol_count > usize::from(u16::MAX)
    {
        return Err(MultiproofAccountingError::InvalidGeometry("cohort geometry"));
    }
    let query_count =
        u64::try_from(outer_indices.len()).map_err(|_| MultiproofAccountingError::Overflow)?;
    let touched_slot_count =
        u64::try_from(touched_slots.len()).map_err(|_| MultiproofAccountingError::Overflow)?;
    let inner_depth =
        u8::try_from(total_slots.ilog2()).map_err(|_| MultiproofAccountingError::Overflow)?;
    let inner_indices = touched_slots.iter().map(|slot| u64::from(*slot)).collect::<Vec<_>>();
    let inner_aux_nodes_per_query = merkle_aux_node_count(inner_depth, &inner_indices)?;
    let inner_aux_nodes = inner_aux_nodes_per_query
        .checked_mul(query_count)
        .ok_or(MultiproofAccountingError::Overflow)?;
    let outer_aux_nodes = merkle_aux_node_count(domain_log2, outer_indices)?;
    let total_aux_nodes =
        inner_aux_nodes.checked_add(outer_aux_nodes).ok_or(MultiproofAccountingError::Overflow)?;

    let symbol_bytes = 16u64
        .checked_mul(
            u64::try_from(expected_symbol_count)
                .map_err(|_| MultiproofAccountingError::Overflow)?,
        )
        .ok_or(MultiproofAccountingError::Overflow)?;
    let inner_leaf_bytes =
        68u64.checked_add(symbol_bytes).ok_or(MultiproofAccountingError::Overflow)?;
    let leaves_per_query_bytes = 71u64
        .checked_add(
            touched_slot_count
                .checked_mul(inner_leaf_bytes)
                .ok_or(MultiproofAccountingError::Overflow)?,
        )
        .ok_or(MultiproofAccountingError::Overflow)?;
    let bytes_without_aux_nodes = 34u64
        .checked_add(
            2u64.checked_mul(touched_slot_count).ok_or(MultiproofAccountingError::Overflow)?,
        )
        .and_then(|bytes| {
            query_count
                .checked_mul(leaves_per_query_bytes)
                .and_then(|leaves| bytes.checked_add(leaves))
        })
        .ok_or(MultiproofAccountingError::Overflow)?;
    let serialized_bytes = bytes_without_aux_nodes
        .checked_add(50u64.checked_mul(total_aux_nodes).ok_or(MultiproofAccountingError::Overflow)?)
        .ok_or(MultiproofAccountingError::Overflow)?;

    Ok(CohortMultiproofByteCount {
        query_count,
        touched_slot_count,
        inner_aux_nodes_per_query,
        inner_aux_nodes,
        outer_aux_nodes,
        total_aux_nodes,
        bytes_without_aux_nodes,
        serialized_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::frame::{Frame, OracleKind};
    use crate::x4::merkle::{CohortIdentity, CohortTree, CohortVerifierConfig};
    use volta_field::{Fp, Fp2};

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value + 1))
    }

    #[test]
    fn closed_formula_matches_normative_codec() {
        let config = CohortVerifierConfig {
            identity: CohortIdentity {
                cohort_id: 77,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), Some([2; 32]), Some([3; 32]), None],
            outer_len: 8,
            expected_symbol_count: 2,
        };
        let slot_symbols = (0..4)
            .map(|slot| {
                config.slot_descriptors[slot].map(|_| {
                    (0..config.outer_len * config.expected_symbol_count)
                        .map(|index| symbol((100 * slot + index) as u64 + 1))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let tree = CohortTree::build_flat(config, slot_symbols).unwrap();
        let outer_indices = [1, 6];
        let touched_slots = [0, 2];
        let proof = tree.open(&outer_indices, &touched_slots).unwrap();
        let encoded = Frame::CohortMultiproof(proof).encode().unwrap();
        let count = cohort_multiproof_byte_count(3, 4, &touched_slots, 2, &outer_indices).unwrap();
        assert_eq!(count.serialized_bytes, encoded.len() as u64);
        assert_eq!(
            count.serialized_bytes - count.bytes_without_aux_nodes,
            50 * count.total_aux_nodes
        );
    }

    #[test]
    fn query_projection_retains_multiset_only_outside_wire_set() {
        let draws = [0, 0, 1, 7, 15];
        assert_eq!(projected_query_indices(&draws, 4).unwrap(), vec![0, 1, 7, 8, 9, 15]);
    }
}
