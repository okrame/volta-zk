//! Schema-4 model-global cohort Merkle commitments and packed openings.
//!
//! The tree is the same two-dimensional construction as schema 3, but every
//! leaf and internal node is hashed from a complete schema-4 preimage under a
//! v4 N4-separated domain.  Packed proofs omit only coordinates and node
//! positions that the verifier derives from the sealed 111-draw schedule.

use std::collections::{BTreeMap, BTreeSet};

use rayon::prelude::*;
use volta_field::Fp2;

use super::accounting::{merkle_aux_node_count, projected_query_indices};
use super::frame::{Digest, TreeRole};
use super::frame_v4::{
    encode_pcs_inner_leaf_fields_v4, encode_pcs_node_fields_v4, encode_pcs_outer_leaf_fields_v4,
    hash_pcs_inner_leaf_fields_v4, hash_pcs_leaf_frames_many_v4, hash_pcs_leaf_v4,
    hash_pcs_node_fields_v4, hash_pcs_node_frames_many_v4, hash_pcs_node_v4,
    hash_pcs_outer_leaf_fields_v4, FoldRoundOpeningV4, InitialOpeningGroupV4, OracleKindV4,
    PcsLeafFrameV4, PcsLeafPayloadV4, PcsNodeFrameV4,
};
use super::merkle::MerkleError;

pub const ABSENT_DESCRIPTOR_DIGEST_V4: Digest = [0; 32];
const CPU_N4_COORDINATE_TILE_V4: usize = 1_024;
const CPU_N4_OUTER_NODE_TILE_V4: usize = 4_096;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OuterCachePolicyV4 {
    /// Number of internal levels immediately above the outer leaves that are
    /// omitted and reconstructed from the persisted oracle during opening.
    pub bottom_levels_omitted: u8,
}

impl OuterCachePolicyV4 {
    pub const FULL: Self = Self { bottom_levels_omitted: 0 };
    pub const RAM_DEGRADED_ONE_LEVEL: Self = Self { bottom_levels_omitted: 1 };

    fn validate(self, outer_depth: u8) -> Result<(), MerkleError> {
        if self.bottom_levels_omitted >= outer_depth {
            return Err(MerkleError::InvalidGeometry("v4 outer cache cutoff"));
        }
        Ok(())
    }

    pub fn retained_digest_count(self, outer_len: usize) -> Result<u64, MerkleError> {
        if outer_len < 8 || !outer_len.is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("v4 outer cache length"));
        }
        self.validate(outer_len.ilog2() as u8)?;
        let first_retained = u32::from(self.bottom_levels_omitted) + 1;
        let retained = outer_len
            .checked_shr(first_retained)
            .ok_or(MerkleError::Overflow)?
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(MerkleError::Overflow)?;
        u64::try_from(retained).map_err(|_| MerkleError::Overflow)
    }

    pub fn retained_bytes(self, outer_len: usize) -> Result<u64, MerkleError> {
        self.retained_digest_count(outer_len)?.checked_mul(32).ok_or(MerkleError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpeningRebuildMetricsV4 {
    pub queried_coordinates: u64,
    pub inner_trees_rebuilt: u64,
    pub outer_frontier_leaves_rebuilt: u64,
    pub outer_internal_nodes_rebuilt: u64,
    pub oracle_symbols_read: u64,
    pub cached_outer_digests_read: u64,
}

pub trait OracleSymbolSourceV4: std::fmt::Debug + Sync {
    fn read_symbol(&self, slot: u16, coordinate: u64) -> Result<Fp2, MerkleError>;
}

pub trait OuterNodeSourceV4: std::fmt::Debug + Sync {
    fn cache_policy(&self) -> OuterCachePolicyV4;
    fn root(&self) -> Digest;
    fn read_cached_digest(&self, level: u8, index: u64) -> Result<Digest, MerkleError>;
}

#[derive(Clone, Debug)]
pub struct DenseOuterNodeCacheV4 {
    outer_len: usize,
    policy: OuterCachePolicyV4,
    /// Actual outer levels 1..=depth. Omitted bottom levels are `None` and
    /// level zero (outer leaves) is never retained.
    levels: Vec<Option<Vec<Digest>>>,
    root: Digest,
}

impl DenseOuterNodeCacheV4 {
    pub fn from_levels(
        outer_len: usize,
        policy: OuterCachePolicyV4,
        levels: Vec<Option<Vec<Digest>>>,
        root: Digest,
    ) -> Result<Self, MerkleError> {
        if outer_len < 8 || !outer_len.is_power_of_two() {
            return Err(MerkleError::InvalidGeometry("v4 outer cache length"));
        }
        let depth = outer_len.ilog2() as u8;
        policy.validate(depth)?;
        if levels.len() != usize::from(depth) {
            return Err(MerkleError::InvalidGeometry("v4 outer cache levels"));
        }
        for level in 1..=depth {
            let entry = &levels[usize::from(level - 1)];
            if level <= policy.bottom_levels_omitted {
                if entry.is_some() {
                    return Err(MerkleError::InvalidGeometry("v4 omitted outer cache level"));
                }
            } else {
                let expected = outer_len >> level;
                if entry.as_ref().map(Vec::len) != Some(expected) {
                    return Err(MerkleError::InvalidGeometry("v4 retained outer cache level"));
                }
            }
        }
        if levels.last().and_then(Option::as_ref).and_then(|level| level.first()).copied()
            != Some(root)
        {
            return Err(MerkleError::InvalidGeometry("v4 outer cache root"));
        }
        Ok(Self { outer_len, policy, levels, root })
    }

    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn retained_bytes(&self) -> Result<u64, MerkleError> {
        self.policy.retained_bytes(self.outer_len)
    }
}

impl OuterNodeSourceV4 for DenseOuterNodeCacheV4 {
    fn cache_policy(&self) -> OuterCachePolicyV4 {
        self.policy
    }

    fn root(&self) -> Digest {
        self.root
    }

    fn read_cached_digest(&self, level: u8, index: u64) -> Result<Digest, MerkleError> {
        if level == 0 || level > self.outer_len.ilog2() as u8 {
            return Err(MerkleError::InvalidOpening("v4 cached outer level"));
        }
        let digests = self.levels[usize::from(level - 1)]
            .as_ref()
            .ok_or(MerkleError::InvalidOpening("v4 omitted outer level read"))?;
        digests
            .get(usize::try_from(index).map_err(|_| MerkleError::Overflow)?)
            .copied()
            .ok_or(MerkleError::InvalidOpening("v4 cached outer index"))
    }
}

#[derive(Clone, Debug)]
pub struct CohortTreeV4 {
    config: CohortVerifierConfigV4,
    /// Slot-major, coordinate-major retained symbols.
    slot_symbols: Vec<Option<Vec<Fp2>>>,
    outer_cache: DenseOuterNodeCacheV4,
}

impl CohortTreeV4 {
    pub fn build_flat(
        config: CohortVerifierConfigV4,
        slot_symbols: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, MerkleError> {
        Self::build_flat_with_cache_policy(config, slot_symbols, OuterCachePolicyV4::FULL)
    }

    pub fn build_flat_with_cache_policy(
        config: CohortVerifierConfigV4,
        slot_symbols: Vec<Option<Vec<Fp2>>>,
        outer_cache_policy: OuterCachePolicyV4,
    ) -> Result<Self, MerkleError> {
        config.validate()?;
        outer_cache_policy.validate(config.outer_depth())?;
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

        // Rayon owns disjoint coordinate tiles. Each tile serializes a
        // contiguous level-order slab and hashes it many-at-once; allocation
        // occurs per tile/level, never per node.
        let mut outer_leaf_hashes = vec![[0u8; 32]; config.outer_len];
        outer_leaf_hashes.par_chunks_mut(CPU_N4_COORDINATE_TILE_V4).enumerate().try_for_each(
            |(tile_index, output)| -> Result<(), MerkleError> {
                let start = tile_index
                    .checked_mul(CPU_N4_COORDINATE_TILE_V4)
                    .ok_or(MerkleError::Overflow)?;
                let tile = outer_leaf_hashes_from_flat_tile_v4(
                    &config,
                    &slot_symbols,
                    start,
                    output.len(),
                )?;
                output.copy_from_slice(&tile);
                Ok(())
            },
        )?;
        let outer_cache = build_outer_cache_v4(&config, outer_leaf_hashes, outer_cache_policy)?;
        Ok(Self { config, slot_symbols, outer_cache })
    }

    /// Assemble a compact in-memory opening source from a root/cache produced
    /// by the byte-identical accelerated commit path.  This performs every
    /// structural check but deliberately does not re-hash the full tree on
    /// the CPU; CPU/GPU root equality is the X4b gate for that boundary.
    pub(crate) fn from_accelerated_commit_parts(
        config: CohortVerifierConfigV4,
        slot_symbols: Vec<Option<Vec<Fp2>>>,
        outer_cache: DenseOuterNodeCacheV4,
    ) -> Result<Self, MerkleError> {
        config.validate()?;
        if slot_symbols.len() != config.slot_descriptors.len()
            || outer_cache.outer_len != config.outer_len
        {
            return Err(MerkleError::InvalidGeometry("v4 accelerated commit parts"));
        }
        for (descriptor, symbols) in config.slot_descriptors.iter().zip(&slot_symbols) {
            match (descriptor, symbols) {
                (Some(_), Some(symbols)) if symbols.len() == config.outer_len => {}
                (None, None) => {}
                _ => {
                    return Err(MerkleError::InvalidGeometry(
                        "v4 accelerated commit symbol geometry",
                    ));
                }
            }
        }
        Ok(Self { config, slot_symbols, outer_cache })
    }

    pub fn config(&self) -> &CohortVerifierConfigV4 {
        &self.config
    }

    pub fn root(&self) -> Digest {
        self.outer_cache.root()
    }

    pub fn outer_cache_policy(&self) -> OuterCachePolicyV4 {
        self.outer_cache.cache_policy()
    }

    pub fn outer_cache_bytes(&self) -> Result<u64, MerkleError> {
        self.outer_cache.retained_bytes()
    }

    pub fn outer_cache(&self) -> &DenseOuterNodeCacheV4 {
        &self.outer_cache
    }

    pub fn open_initial(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<InitialOpeningGroupV4, MerkleError> {
        self.open_initial_with_metrics(query_draws, touched_slots).map(|(opening, _)| opening)
    }

    pub fn open_initial_with_metrics(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(InitialOpeningGroupV4, OpeningRebuildMetricsV4), MerkleError> {
        open_initial_from_sources_v4(
            &self.config,
            query_draws,
            touched_slots,
            self,
            &self.outer_cache,
        )
    }

    pub fn open_fold_round(&self, query_draws: &[u64]) -> Result<FoldRoundOpeningV4, MerkleError> {
        self.open_fold_round_with_metrics(query_draws).map(|(opening, _)| opening)
    }

    pub fn open_fold_round_with_metrics(
        &self,
        query_draws: &[u64],
    ) -> Result<(FoldRoundOpeningV4, OpeningRebuildMetricsV4), MerkleError> {
        open_fold_from_sources_v4(&self.config, query_draws, self, &self.outer_cache)
    }
}

impl OracleSymbolSourceV4 for CohortTreeV4 {
    fn read_symbol(&self, slot: u16, coordinate: u64) -> Result<Fp2, MerkleError> {
        self.slot_symbols
            .get(usize::from(slot))
            .and_then(Option::as_ref)
            .and_then(|symbols| symbols.get(usize::try_from(coordinate).ok()?))
            .copied()
            .ok_or(MerkleError::InvalidOpening("v4 in-memory oracle read"))
    }
}

pub fn open_initial_from_sources_v4<
    S: OracleSymbolSourceV4 + ?Sized,
    C: OuterNodeSourceV4 + ?Sized,
>(
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    touched_slots: &[u16],
    symbols: &S,
    outer_cache: &C,
) -> Result<(InitialOpeningGroupV4, OpeningRebuildMetricsV4), MerkleError> {
    if matches!(config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate) {
        return Err(MerkleError::InvalidOpening("v4 initial oracle kind"));
    }
    validate_touched_slots(config, touched_slots)?;
    let indices = projected_query_indices(query_draws, config.outer_depth())
        .map_err(|_| MerkleError::InvalidOpening("v4 projected query indices"))?;
    let mut opened_symbols = Vec::with_capacity(
        indices.len().checked_mul(touched_slots.len()).ok_or(MerkleError::Overflow)?,
    );
    let mut inner_sibling_digests = Vec::new();
    let mut metrics = OpeningRebuildMetricsV4::default();
    let mut scratch = Vec::with_capacity(config.slot_descriptors.len());
    for index in &indices {
        append_inner_opening_v4(
            config,
            symbols,
            *index,
            touched_slots,
            &mut opened_symbols,
            &mut inner_sibling_digests,
            &mut scratch,
            &mut metrics,
        )?;
    }
    let mut outer_sibling_digests = Vec::new();
    append_outer_frontier_from_sources_v4(
        config,
        symbols,
        outer_cache,
        &indices,
        &mut outer_sibling_digests,
        &mut metrics,
    )?;
    let opening = InitialOpeningGroupV4 {
        cohort_id: config.identity.cohort_id,
        domain_log2: config.outer_depth(),
        slot_count: u16::try_from(config.slot_descriptors.len())
            .map_err(|_| MerkleError::Overflow)?,
        touched_slots: touched_slots.to_vec(),
        opened_symbols,
        inner_sibling_digests,
        outer_sibling_digests,
    };
    opening.validate().map_err(MerkleError::Frame)?;
    Ok((opening, metrics))
}

pub fn open_fold_from_sources_v4<
    S: OracleSymbolSourceV4 + ?Sized,
    C: OuterNodeSourceV4 + ?Sized,
>(
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    symbols: &S,
    outer_cache: &C,
) -> Result<(FoldRoundOpeningV4, OpeningRebuildMetricsV4), MerkleError> {
    if config.identity.oracle_kind != OracleKindV4::GlobalFoldAggregate
        || config.slot_descriptors.len() != 1
    {
        return Err(MerkleError::InvalidOpening("v4 fold oracle kind"));
    }
    let indices = projected_query_indices(query_draws, config.outer_depth())
        .map_err(|_| MerkleError::InvalidOpening("v4 projected fold indices"))?;
    let mut metrics = OpeningRebuildMetricsV4::default();
    let opened_symbols = indices
        .iter()
        .map(|index| {
            metrics.queried_coordinates =
                metrics.queried_coordinates.checked_add(1).ok_or(MerkleError::Overflow)?;
            metrics.oracle_symbols_read =
                metrics.oracle_symbols_read.checked_add(1).ok_or(MerkleError::Overflow)?;
            symbols.read_symbol(0, *index)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut outer_sibling_digests = Vec::new();
    append_outer_frontier_from_sources_v4(
        config,
        symbols,
        outer_cache,
        &indices,
        &mut outer_sibling_digests,
        &mut metrics,
    )?;
    let opening = FoldRoundOpeningV4 {
        fold_round: config.identity.fold_round,
        domain_log2: config.outer_depth(),
        opened_symbols,
        outer_sibling_digests,
    };
    opening.validate().map_err(MerkleError::Frame)?;
    Ok((opening, metrics))
}

fn append_outer_frontier_from_sources_v4<
    S: OracleSymbolSourceV4 + ?Sized,
    C: OuterNodeSourceV4 + ?Sized,
>(
    config: &CohortVerifierConfigV4,
    symbols: &S,
    outer_cache: &C,
    opened_indices: &[u64],
    output: &mut Vec<Digest>,
    metrics: &mut OpeningRebuildMetricsV4,
) -> Result<(), MerkleError> {
    if opened_indices.is_empty()
        || !opened_indices.windows(2).all(|pair| pair[0] < pair[1])
        || opened_indices.iter().any(|index| *index >= config.outer_len as u64)
    {
        return Err(MerkleError::InvalidOpening("v4 frontier indices"));
    }
    let mut memo = BTreeMap::new();
    let mut current = opened_indices.iter().copied().collect::<BTreeSet<_>>();
    for level in 0..config.outer_depth() {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                output.push(outer_digest_from_sources_v4(
                    config,
                    symbols,
                    outer_cache,
                    level,
                    sibling,
                    &mut memo,
                    metrics,
                )?);
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(())
}

fn outer_digest_from_sources_v4<S: OracleSymbolSourceV4 + ?Sized, C: OuterNodeSourceV4 + ?Sized>(
    config: &CohortVerifierConfigV4,
    symbols: &S,
    outer_cache: &C,
    level: u8,
    index: u64,
    memo: &mut BTreeMap<(u8, u64), Digest>,
    metrics: &mut OpeningRebuildMetricsV4,
) -> Result<Digest, MerkleError> {
    if let Some(digest) = memo.get(&(level, index)) {
        return Ok(*digest);
    }
    let digest = if level == 0 {
        metrics.outer_frontier_leaves_rebuilt =
            metrics.outer_frontier_leaves_rebuilt.checked_add(1).ok_or(MerkleError::Overflow)?;
        let mut scratch = Vec::with_capacity(config.slot_descriptors.len());
        let inner_root = inner_root_from_source_v4(config, symbols, index, &mut scratch, metrics)?;
        hash_pcs_outer_leaf_fields_v4(
            config.identity.cohort_id,
            config.identity.oracle_kind,
            config.identity.fold_round,
            index,
            inner_root,
        )?
    } else if level > outer_cache.cache_policy().bottom_levels_omitted {
        metrics.cached_outer_digests_read =
            metrics.cached_outer_digests_read.checked_add(1).ok_or(MerkleError::Overflow)?;
        outer_cache.read_cached_digest(level, index)?
    } else {
        let left_index = index.checked_mul(2).ok_or(MerkleError::Overflow)?;
        let left = outer_digest_from_sources_v4(
            config,
            symbols,
            outer_cache,
            level - 1,
            left_index,
            memo,
            metrics,
        )?;
        let right = outer_digest_from_sources_v4(
            config,
            symbols,
            outer_cache,
            level - 1,
            left_index + 1,
            memo,
            metrics,
        )?;
        metrics.outer_internal_nodes_rebuilt =
            metrics.outer_internal_nodes_rebuilt.checked_add(1).ok_or(MerkleError::Overflow)?;
        hash_pcs_node_fields_v4(
            config.identity.cohort_id,
            TreeRole::Outer,
            config.identity.oracle_kind,
            config.identity.fold_round,
            u64::MAX,
            level,
            index,
            left,
            right,
        )?
    };
    memo.insert((level, index), digest);
    Ok(digest)
}

pub fn verify_initial_packed_opening_v4(
    root: Digest,
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    expected_touched_slots: &[u16],
    opening: &InitialOpeningGroupV4,
) -> Result<(), MerkleError> {
    if reconstruct_initial_packed_opening_root_v4(
        config,
        query_draws,
        expected_touched_slots,
        opening,
    )? != root
    {
        return Err(MerkleError::InvalidOpening("v4 packed initial root"));
    }
    Ok(())
}

pub fn reconstruct_initial_packed_opening_root_v4(
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    expected_touched_slots: &[u16],
    opening: &InitialOpeningGroupV4,
) -> Result<Digest, MerkleError> {
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
    if outer_cursor != opening.outer_sibling_digests.len() {
        return Err(MerkleError::InvalidOpening("v4 packed initial trailing outer data"));
    }
    Ok(computed)
}

pub fn verify_fold_round_packed_opening_v4(
    root: Digest,
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    opening: &FoldRoundOpeningV4,
) -> Result<(), MerkleError> {
    if reconstruct_fold_round_packed_opening_root_v4(config, query_draws, opening)? != root {
        return Err(MerkleError::InvalidOpening("v4 packed fold root"));
    }
    Ok(())
}

pub fn reconstruct_fold_round_packed_opening_root_v4(
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    opening: &FoldRoundOpeningV4,
) -> Result<Digest, MerkleError> {
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
    if cursor != opening.outer_sibling_digests.len() {
        return Err(MerkleError::InvalidOpening("v4 packed fold trailing outer data"));
    }
    Ok(computed)
}

fn outer_leaf_hashes_from_flat_tile_v4(
    config: &CohortVerifierConfigV4,
    slot_symbols: &[Option<Vec<Fp2>>],
    start: usize,
    count: usize,
) -> Result<Vec<Digest>, MerkleError> {
    let end = start.checked_add(count).ok_or(MerkleError::Overflow)?;
    if count == 0 || end > config.outer_len {
        return Err(MerkleError::InvalidGeometry("v4 CPU N4 tile range"));
    }
    let slot_count = config.slot_descriptors.len();
    let mut current = vec![[0u8; 32]; count.checked_mul(slot_count).ok_or(MerkleError::Overflow)?];
    for slot in 0..slot_count {
        let slot_u16 = u16::try_from(slot).map_err(|_| MerkleError::Overflow)?;
        match (&config.slot_descriptors[slot], &slot_symbols[slot]) {
            (Some(descriptor), Some(symbols)) => {
                let frames = (start..end)
                    .map(|coordinate| {
                        encode_pcs_inner_leaf_fields_v4(
                            config.identity.cohort_id,
                            config.identity.oracle_kind,
                            config.identity.fold_round,
                            u64::try_from(coordinate).map_err(|_| MerkleError::Overflow)?,
                            *descriptor,
                            slot_u16,
                            Some(symbols[coordinate]),
                        )
                        .map_err(MerkleError::Frame)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                for (coordinate, digest) in
                    hash_pcs_leaf_frames_many_v4(&frames).into_iter().enumerate()
                {
                    current[coordinate * slot_count + slot] = digest;
                }
            }
            (None, None) => {
                let frames = (start..end)
                    .map(|coordinate| {
                        let wide = encode_pcs_inner_leaf_fields_v4(
                            config.identity.cohort_id,
                            config.identity.oracle_kind,
                            config.identity.fold_round,
                            u64::try_from(coordinate).map_err(|_| MerkleError::Overflow)?,
                            ABSENT_DESCRIPTOR_DIGEST_V4,
                            slot_u16,
                            None,
                        )?;
                        let mut compact = [0u8; 68];
                        compact.copy_from_slice(&wide[..68]);
                        Ok(compact)
                    })
                    .collect::<Result<Vec<_>, MerkleError>>()?;
                for (coordinate, digest) in
                    hash_pcs_leaf_frames_many_v4(&frames).into_iter().enumerate()
                {
                    current[coordinate * slot_count + slot] = digest;
                }
            }
            _ => return Err(MerkleError::InvalidGeometry("v4 stored slot presence")),
        }
    }

    let mut width = slot_count;
    let mut level = 1u8;
    while width > 1 {
        let parent_width = width / 2;
        let frames = (0..count)
            .flat_map(|coordinate| {
                (0..parent_width).map(move |node_index| (coordinate, node_index))
            })
            .map(|(coordinate, node_index)| {
                encode_pcs_node_fields_v4(
                    config.identity.cohort_id,
                    TreeRole::Inner,
                    config.identity.oracle_kind,
                    config.identity.fold_round,
                    u64::try_from(start + coordinate).map_err(|_| MerkleError::Overflow)?,
                    level,
                    u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                    current[coordinate * width + 2 * node_index],
                    current[coordinate * width + 2 * node_index + 1],
                )
                .map_err(MerkleError::Frame)
            })
            .collect::<Result<Vec<_>, _>>()?;
        current = hash_pcs_node_frames_many_v4(&frames);
        width /= 2;
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }

    let outer_frames = current
        .iter()
        .enumerate()
        .map(|(coordinate, inner_root)| {
            encode_pcs_outer_leaf_fields_v4(
                config.identity.cohort_id,
                config.identity.oracle_kind,
                config.identity.fold_round,
                u64::try_from(start + coordinate).map_err(|_| MerkleError::Overflow)?,
                *inner_root,
            )
            .map_err(MerkleError::Frame)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(hash_pcs_leaf_frames_many_v4(&outer_frames))
}

fn inner_root_from_source_v4<S: OracleSymbolSourceV4 + ?Sized>(
    config: &CohortVerifierConfigV4,
    symbols: &S,
    coordinate: u64,
    scratch: &mut Vec<Digest>,
    metrics: &mut OpeningRebuildMetricsV4,
) -> Result<Digest, MerkleError> {
    scratch.clear();
    scratch.resize(config.slot_descriptors.len(), [0; 32]);
    for (slot, output) in scratch.iter_mut().enumerate() {
        let (descriptor, symbol) = match config.slot_descriptors[slot] {
            Some(descriptor) => {
                metrics.oracle_symbols_read =
                    metrics.oracle_symbols_read.checked_add(1).ok_or(MerkleError::Overflow)?;
                (
                    descriptor,
                    Some(symbols.read_symbol(
                        u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
                        coordinate,
                    )?),
                )
            }
            None => (ABSENT_DESCRIPTOR_DIGEST_V4, None),
        };
        *output = hash_pcs_inner_leaf_fields_v4(
            config.identity.cohort_id,
            config.identity.oracle_kind,
            config.identity.fold_round,
            coordinate,
            descriptor,
            u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
            symbol,
        )?;
    }
    metrics.inner_trees_rebuilt =
        metrics.inner_trees_rebuilt.checked_add(1).ok_or(MerkleError::Overflow)?;
    let mut width = scratch.len();
    let mut level = 1u8;
    while width > 1 {
        for node_index in 0..width / 2 {
            scratch[node_index] = hash_pcs_node_fields_v4(
                config.identity.cohort_id,
                TreeRole::Inner,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate,
                level,
                u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                scratch[2 * node_index],
                scratch[2 * node_index + 1],
            )?;
        }
        width /= 2;
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }
    Ok(scratch[0])
}

fn append_inner_opening_v4<S: OracleSymbolSourceV4 + ?Sized>(
    config: &CohortVerifierConfigV4,
    symbols: &S,
    coordinate: u64,
    touched_slots: &[u16],
    opened_symbols: &mut Vec<Fp2>,
    sibling_digests: &mut Vec<Digest>,
    scratch: &mut Vec<Digest>,
    metrics: &mut OpeningRebuildMetricsV4,
) -> Result<(), MerkleError> {
    scratch.clear();
    scratch.resize(config.slot_descriptors.len(), [0; 32]);
    let mut touched_cursor = 0usize;
    for (slot, output) in scratch.iter_mut().enumerate() {
        let (descriptor, symbol) = match config.slot_descriptors[slot] {
            Some(descriptor) => {
                metrics.oracle_symbols_read =
                    metrics.oracle_symbols_read.checked_add(1).ok_or(MerkleError::Overflow)?;
                (
                    descriptor,
                    Some(symbols.read_symbol(
                        u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
                        coordinate,
                    )?),
                )
            }
            None => (ABSENT_DESCRIPTOR_DIGEST_V4, None),
        };
        if touched_slots.get(touched_cursor).copied() == Some(slot as u16) {
            opened_symbols.push(symbol.ok_or(MerkleError::InvalidOpening("v4 touched slot"))?);
            touched_cursor += 1;
        }
        *output = hash_pcs_inner_leaf_fields_v4(
            config.identity.cohort_id,
            config.identity.oracle_kind,
            config.identity.fold_round,
            coordinate,
            descriptor,
            u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
            symbol,
        )?;
    }
    if touched_cursor != touched_slots.len() {
        return Err(MerkleError::InvalidOpening("v4 touched slot"));
    }

    metrics.queried_coordinates =
        metrics.queried_coordinates.checked_add(1).ok_or(MerkleError::Overflow)?;
    metrics.inner_trees_rebuilt =
        metrics.inner_trees_rebuilt.checked_add(1).ok_or(MerkleError::Overflow)?;

    let mut current = touched_slots.iter().map(|slot| u64::from(*slot)).collect::<BTreeSet<_>>();
    let mut width = scratch.len();
    let mut level = 1u8;
    while width > 1 {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                sibling_digests
                    .push(scratch[usize::try_from(sibling).map_err(|_| MerkleError::Overflow)?]);
            }
            next.insert(*index / 2);
        }
        for node_index in 0..width / 2 {
            scratch[node_index] = hash_pcs_node_fields_v4(
                config.identity.cohort_id,
                TreeRole::Inner,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate,
                level,
                u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                scratch[2 * node_index],
                scratch[2 * node_index + 1],
            )?;
        }
        current = next;
        width /= 2;
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }
    Ok(())
}

fn build_outer_cache_v4(
    config: &CohortVerifierConfigV4,
    outer_leaves: Vec<Digest>,
    policy: OuterCachePolicyV4,
) -> Result<DenseOuterNodeCacheV4, MerkleError> {
    if outer_leaves.len() != config.outer_len {
        return Err(MerkleError::InvalidGeometry("v4 outer leaf count"));
    }
    let depth = config.outer_depth();
    policy.validate(depth)?;
    let mut retained = (0..depth).map(|_| None).collect::<Vec<_>>();
    let mut previous = outer_leaves;
    let mut previous_level = 0u8;
    for level in 1..=depth {
        let parent_count = previous.len() / 2;
        let mut next = vec![[0u8; 32]; parent_count];
        next.par_chunks_mut(CPU_N4_OUTER_NODE_TILE_V4).enumerate().try_for_each(
            |(tile_index, output)| -> Result<(), MerkleError> {
                let start = tile_index
                    .checked_mul(CPU_N4_OUTER_NODE_TILE_V4)
                    .ok_or(MerkleError::Overflow)?;
                let frames = (start..start + output.len())
                    .map(|node_index| {
                        encode_pcs_node_fields_v4(
                            config.identity.cohort_id,
                            TreeRole::Outer,
                            config.identity.oracle_kind,
                            config.identity.fold_round,
                            u64::MAX,
                            level,
                            u64::try_from(node_index).map_err(|_| MerkleError::Overflow)?,
                            previous[2 * node_index],
                            previous[2 * node_index + 1],
                        )
                        .map_err(MerkleError::Frame)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                output.copy_from_slice(&hash_pcs_node_frames_many_v4(&frames));
                Ok(())
            },
        )?;
        if previous_level > policy.bottom_levels_omitted {
            retained[usize::from(previous_level - 1)] = Some(previous);
        }
        previous = next;
        previous_level = level;
    }
    let root = *previous.first().ok_or(MerkleError::InvalidGeometry("v4 empty outer root"))?;
    retained[usize::from(depth - 1)] = Some(previous);
    DenseOuterNodeCacheV4::from_levels(config.outer_len, policy, retained, root)
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

    #[test]
    fn x4b_one_level_ram_degradation_preserves_root_and_proof_bytes() {
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
            .collect::<Vec<_>>();
        let full = CohortTreeV4::build_flat(config.clone(), symbols.clone()).unwrap();
        let degraded = CohortTreeV4::build_flat_with_cache_policy(
            config,
            symbols,
            OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL,
        )
        .unwrap();
        assert_eq!(full.root(), degraded.root());
        assert_eq!(full.outer_cache_bytes().unwrap(), 31 * 32);
        assert_eq!(degraded.outer_cache_bytes().unwrap(), 15 * 32);

        let draws = vec![3; 111];
        let (full_opening, full_metrics) = full.open_initial_with_metrics(&draws, &[0, 2]).unwrap();
        let (degraded_opening, degraded_metrics) =
            degraded.open_initial_with_metrics(&draws, &[0, 2]).unwrap();
        assert_eq!(full_opening, degraded_opening);
        assert_eq!(full_metrics.outer_internal_nodes_rebuilt, 0);
        assert!(degraded_metrics.outer_internal_nodes_rebuilt > 0);
        assert!(
            degraded_metrics.outer_frontier_leaves_rebuilt
                >= full_metrics.outer_frontier_leaves_rebuilt
        );
        verify_initial_packed_opening_v4(
            degraded.root(),
            degraded.config(),
            &draws,
            &[0, 2],
            &degraded_opening,
        )
        .unwrap();
    }
}
