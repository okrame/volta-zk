//! X4b raw persisted-oracle source and derived outer-cache opening path.
//!
//! The oracle file is local prover state, not a proof frame: present slots
//! are stored slot-major as canonical `(c0,c1)` little-endian `Fp2` symbols.
//! Absent structural slots occupy no file bytes.  The separately supplied
//! binding is checked against the frozen profile, model and committed root
//! before a source can answer an opening.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use volta_field::{Fp, Fp2, P};

use super::accounting::projected_query_indices;
use super::folding_v4::{
    CombinedInitialV4, FoldingErrorV4, ModelGlobalCohortCommitmentV4, ModelGlobalOpeningSourceV4,
    SourceRecomputeTrafficV4,
};
use super::frame::{Digest, TreeRole};
use super::frame_v4::{
    hash_pcs_inner_leaf_fields_v4, hash_pcs_node_fields_v4, hash_pcs_outer_leaf_fields_v4,
};
use super::frame_v4::{profile_digest_v4, FoldRoundOpeningV4, InitialOpeningGroupV4, OracleKindV4};
use super::merkle::MerkleError;
use super::merkle_v4::{
    open_fold_from_sources_v4, open_initial_from_sources_v4, CohortVerifierConfigV4,
    OpeningRebuildMetricsV4, OracleSymbolSourceV4, OuterCachePolicyV4, OuterNodeSourceV4,
};
use super::ntt::evaluate_multilinear_coefficients;

pub const PERSISTED_SYMBOL_BYTES_V4: u64 = 16;
pub const PERSISTED_DIGEST_BYTES_V4: u64 = 32;
const PERSISTED_IO_CHUNK_SYMBOLS_V4: usize = 64 * 1024;

fn advise_dontneed_range_v4(file: &File, offset: u64, bytes: u64) -> Result<(), io::Error> {
    if offset > i64::MAX as u64 || bytes > i64::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "v4 persisted fadvise range overflow",
        ));
    }
    unsafe extern "C" {
        fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    }
    const POSIX_FADV_DONTNEED: i32 = 4;
    // SAFETY: the persisted oracle owns this live descriptor for the call;
    // offset and length were checked against the platform `off_t` range.
    let status = unsafe {
        posix_fadvise(file.as_raw_fd(), offset as i64, bytes as i64, POSIX_FADV_DONTNEED)
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

pub(crate) fn write_canonical_fp2_slice_v4<W: Write>(
    writer: &mut W,
    symbols: &[Fp2],
) -> Result<(), io::Error> {
    let mut encoded = vec![0u8; PERSISTED_IO_CHUNK_SYMBOLS_V4 * 16];
    for chunk in symbols.chunks(PERSISTED_IO_CHUNK_SYMBOLS_V4) {
        let bytes = chunk.len() * 16;
        for (destination, symbol) in encoded[..bytes].chunks_exact_mut(16).zip(chunk) {
            destination[..8].copy_from_slice(&symbol.c0.value().to_le_bytes());
            destination[8..].copy_from_slice(&symbol.c1.value().to_le_bytes());
        }
        writer.write_all(&encoded[..bytes])?;
    }
    Ok(())
}

fn read_canonical_fp2_count_v4<R: Read>(
    reader: &mut R,
    count: usize,
) -> Result<Vec<Fp2>, PersistedOracleErrorV4> {
    let mut output = Vec::with_capacity(count);
    let mut encoded = vec![0u8; PERSISTED_IO_CHUNK_SYMBOLS_V4 * 16];
    let mut remaining = count;
    while remaining != 0 {
        let symbols = remaining.min(PERSISTED_IO_CHUNK_SYMBOLS_V4);
        let bytes = symbols * 16;
        reader.read_exact(&mut encoded[..bytes])?;
        for chunk in encoded[..bytes].chunks_exact(16) {
            let c0 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
            if c0 >= P || c1 >= P {
                return Err(PersistedOracleErrorV4::Invalid(
                    "v4 non-canonical persisted coefficient",
                ));
            }
            output.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
        }
        remaining -= symbols;
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4bOpeningSourcePolicyV4 {
    PersistedOracle,
    AuditRecompute,
}

impl X4bOpeningSourcePolicyV4 {
    pub fn require_record_eligible(self) -> Result<(), PersistedOracleErrorV4> {
        match self {
            Self::PersistedOracle => Ok(()),
            Self::AuditRecompute => Err(PersistedOracleErrorV4::Invalid(
                "AuditRecompute is refused by X4b record-producing modes",
            )),
        }
    }
}

#[derive(Debug)]
pub enum PersistedOracleErrorV4 {
    Io(io::Error),
    Merkle(MerkleError),
    Invalid(&'static str),
}

impl From<io::Error> for PersistedOracleErrorV4 {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<MerkleError> for PersistedOracleErrorV4 {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistedOracleBindingV4 {
    pub profile_digest: Digest,
    pub model_config_digest: Digest,
    pub model_root: Digest,
    pub cohort_root: Digest,
}

impl PersistedOracleBindingV4 {
    pub fn new(model_config_digest: Digest, model_root: Digest, cohort_root: Digest) -> Self {
        Self { profile_digest: profile_digest_v4(), model_config_digest, model_root, cohort_root }
    }
}

#[derive(Debug)]
pub struct PersistedOracleV4 {
    file: File,
    path: PathBuf,
    config: CohortVerifierConfigV4,
    present_rank_by_slot: Vec<Option<u64>>,
    logical_bytes: u64,
    binding: PersistedOracleBindingV4,
}

impl PersistedOracleV4 {
    pub fn load(
        path: impl AsRef<Path>,
        config: CohortVerifierConfigV4,
        binding: PersistedOracleBindingV4,
        expected_binding: PersistedOracleBindingV4,
    ) -> Result<Self, PersistedOracleErrorV4> {
        config.validate()?;
        if binding != expected_binding
            || binding.profile_digest != profile_digest_v4()
            || matches!(config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate)
                && config.slot_descriptors.len() != 1
        {
            return Err(PersistedOracleErrorV4::Invalid("v4 persisted binding"));
        }
        let (present_rank_by_slot, present_slots) = present_slot_ranks(&config)?;
        let logical_bytes = present_slots
            .checked_mul(u64::try_from(config.outer_len).map_err(|_| MerkleError::Overflow)?)
            .and_then(|symbols| symbols.checked_mul(PERSISTED_SYMBOL_BYTES_V4))
            .ok_or(MerkleError::Overflow)?;
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).open(&path)?;
        if file.metadata()?.len() != logical_bytes {
            return Err(PersistedOracleErrorV4::Invalid("v4 persisted oracle length"));
        }
        Ok(Self { file, path, config, present_rank_by_slot, logical_bytes, binding })
    }

    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn binding(&self) -> PersistedOracleBindingV4 {
        self.binding
    }

    fn symbol_offset(&self, slot: u16, coordinate: u64) -> Result<u64, MerkleError> {
        if coordinate >= self.config.outer_len as u64 {
            return Err(MerkleError::InvalidOpening("v4 persisted coordinate"));
        }
        let rank = self
            .present_rank_by_slot
            .get(usize::from(slot))
            .copied()
            .flatten()
            .ok_or(MerkleError::InvalidOpening("v4 persisted slot"))?;
        rank.checked_mul(self.config.outer_len as u64)
            .and_then(|base| base.checked_add(coordinate))
            .and_then(|symbol| symbol.checked_mul(PERSISTED_SYMBOL_BYTES_V4))
            .ok_or(MerkleError::Overflow)
    }

    fn accumulate_slot(
        &self,
        slot: u16,
        weight: Fp2,
        output: &mut [Fp2],
    ) -> Result<u64, MerkleError> {
        if output.len() != self.config.outer_len {
            return Err(MerkleError::InvalidGeometry("v4 persisted accumulation length"));
        }
        let start = self.symbol_offset(slot, 0)?;
        const CHUNK_SYMBOLS: usize = 32 * 1024;
        let mut encoded = vec![0u8; CHUNK_SYMBOLS * PERSISTED_SYMBOL_BYTES_V4 as usize];
        let mut symbol_start = 0usize;
        while symbol_start < output.len() {
            let count = (output.len() - symbol_start).min(CHUNK_SYMBOLS);
            let bytes = count
                .checked_mul(PERSISTED_SYMBOL_BYTES_V4 as usize)
                .ok_or(MerkleError::Overflow)?;
            let offset = start
                .checked_add(
                    u64::try_from(symbol_start)
                        .map_err(|_| MerkleError::Overflow)?
                        .checked_mul(PERSISTED_SYMBOL_BYTES_V4)
                        .ok_or(MerkleError::Overflow)?,
                )
                .ok_or(MerkleError::Overflow)?;
            let mut read = 0usize;
            while read < bytes {
                let got = self
                    .file
                    .read_at(&mut encoded[read..bytes], offset + read as u64)
                    .map_err(|_| MerkleError::InvalidOpening("v4 persisted oracle I/O"))?;
                if got == 0 {
                    return Err(MerkleError::InvalidOpening("v4 persisted oracle EOF"));
                }
                read += got;
            }
            for (relative, chunk) in encoded[..bytes].chunks_exact(16).enumerate() {
                let c0 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
                let c1 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
                if c0 >= P || c1 >= P {
                    return Err(MerkleError::InvalidOpening("v4 non-canonical persisted symbol"));
                }
                output[symbol_start + relative] += weight * Fp2::new(Fp::new(c0), Fp::new(c1));
            }
            symbol_start += count;
        }
        let bytes = u64::try_from(output.len())
            .map_err(|_| MerkleError::Overflow)?
            .checked_mul(PERSISTED_SYMBOL_BYTES_V4)
            .ok_or(MerkleError::Overflow)?;
        // This is the only response path that scans a complete persisted
        // slot. Evict the completed range explicitly; tiny random query
        // reads remain visible in the opening traffic counters.
        advise_dontneed_range_v4(&self.file, start, bytes)
            .map_err(|_| MerkleError::InvalidOpening("v4 persisted oracle fadvise"))?;
        Ok(bytes)
    }
}

impl OracleSymbolSourceV4 for PersistedOracleV4 {
    fn read_symbol(&self, slot: u16, coordinate: u64) -> Result<Fp2, MerkleError> {
        let offset = self.symbol_offset(slot, coordinate)?;
        let mut encoded = [0u8; PERSISTED_SYMBOL_BYTES_V4 as usize];
        let mut read = 0usize;
        while read < encoded.len() {
            let count = self
                .file
                .read_at(&mut encoded[read..], offset + read as u64)
                .map_err(|_| MerkleError::InvalidOpening("v4 persisted oracle I/O"))?;
            if count == 0 {
                return Err(MerkleError::InvalidOpening("v4 persisted oracle EOF"));
            }
            read += count;
        }
        let c0 = u64::from_le_bytes(encoded[..8].try_into().unwrap());
        let c1 = u64::from_le_bytes(encoded[8..].try_into().unwrap());
        if c0 >= P || c1 >= P {
            return Err(MerkleError::InvalidOpening("v4 non-canonical persisted symbol"));
        }
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }
}

pub fn write_persisted_oracle_v4(
    path: impl AsRef<Path>,
    config: &CohortVerifierConfigV4,
    slot_symbols: &[Option<Vec<Fp2>>],
) -> Result<u64, PersistedOracleErrorV4> {
    config.validate()?;
    if slot_symbols.len() != config.slot_descriptors.len() {
        return Err(PersistedOracleErrorV4::Invalid("v4 persisted slot count"));
    }
    let file = OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut symbols_written = 0u64;
    for (descriptor, symbols) in config.slot_descriptors.iter().zip(slot_symbols) {
        match (descriptor, symbols) {
            (Some(_), Some(symbols)) if symbols.len() == config.outer_len => {
                write_canonical_fp2_slice_v4(&mut writer, symbols)?;
                symbols_written = symbols_written
                    .checked_add(u64::try_from(symbols.len()).map_err(|_| MerkleError::Overflow)?)
                    .ok_or(MerkleError::Overflow)?;
            }
            (None, None) => {}
            _ => return Err(PersistedOracleErrorV4::Invalid("v4 persisted slot geometry")),
        }
    }
    writer.flush()?;
    symbols_written.checked_mul(PERSISTED_SYMBOL_BYTES_V4).ok_or(MerkleError::Overflow.into())
}

/// Load the canonical coefficient artifact written by the X4b production
/// committer. The file is prover state, not a transcript frame; its exact
/// length and every field limb are nevertheless fail-closed before use.
pub fn read_persisted_coefficients_v4(
    path: impl AsRef<Path>,
    config: &CohortVerifierConfigV4,
) -> Result<Vec<Option<Vec<Fp2>>>, PersistedOracleErrorV4> {
    config.validate()?;
    let coefficient_len = config.outer_len / 8;
    if coefficient_len == 0 || !coefficient_len.is_power_of_two() {
        return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficient length"));
    }
    let present = config.slot_descriptors.iter().flatten().count();
    let expected_bytes = u64::try_from(present)
        .map_err(|_| MerkleError::Overflow)?
        .checked_mul(u64::try_from(coefficient_len).map_err(|_| MerkleError::Overflow)?)
        .and_then(|symbols| symbols.checked_mul(PERSISTED_SYMBOL_BYTES_V4))
        .ok_or(MerkleError::Overflow)?;
    let file = OpenOptions::new().read(true).open(path)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficient file length"));
    }
    let mut reader = BufReader::with_capacity(8 * 1024 * 1024, file);
    let mut output = Vec::with_capacity(config.slot_descriptors.len());
    for descriptor in &config.slot_descriptors {
        if descriptor.is_none() {
            output.push(None);
            continue;
        }
        let coefficients = read_canonical_fp2_count_v4(&mut reader, coefficient_len)?;
        output.push(Some(coefficients));
    }
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficient trailing bytes"));
    }
    Ok(output)
}

pub fn write_persisted_coefficients_v4(
    path: impl AsRef<Path>,
    config: &CohortVerifierConfigV4,
    coefficients: &[Option<Vec<Fp2>>],
) -> Result<u64, PersistedOracleErrorV4> {
    config.validate()?;
    if coefficients.len() != config.slot_descriptors.len() {
        return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficient slot count"));
    }
    let coefficient_len = config.outer_len / 8;
    let file = OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut written = 0u64;
    for (descriptor, values) in config.slot_descriptors.iter().zip(coefficients) {
        match (descriptor, values) {
            (Some(_), Some(values)) if values.len() == coefficient_len => {
                write_canonical_fp2_slice_v4(&mut writer, values)?;
                written = written
                    .checked_add(
                        u64::try_from(values.len())
                            .map_err(|_| MerkleError::Overflow)?
                            .checked_mul(PERSISTED_SYMBOL_BYTES_V4)
                            .ok_or(MerkleError::Overflow)?,
                    )
                    .ok_or(MerkleError::Overflow)?;
            }
            (None, None) => {}
            _ => {
                return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficient geometry"));
            }
        }
    }
    writer.flush()?;
    Ok(written)
}

fn present_slot_ranks(
    config: &CohortVerifierConfigV4,
) -> Result<(Vec<Option<u64>>, u64), MerkleError> {
    let mut next = 0u64;
    let mut ranks = Vec::with_capacity(config.slot_descriptors.len());
    for descriptor in &config.slot_descriptors {
        if descriptor.is_some() {
            ranks.push(Some(next));
            next = next.checked_add(1).ok_or(MerkleError::Overflow)?;
        } else {
            ranks.push(None);
        }
    }
    Ok((ranks, next))
}

#[derive(Clone, Debug)]
pub struct SparseOuterNodeCacheV4 {
    outer_len: usize,
    policy: OuterCachePolicyV4,
    root: Digest,
    digests: BTreeMap<(u8, u64), Digest>,
}

impl SparseOuterNodeCacheV4 {
    pub fn new(
        outer_len: usize,
        policy: OuterCachePolicyV4,
        root: Digest,
        digests: BTreeMap<(u8, u64), Digest>,
    ) -> Result<Self, MerkleError> {
        policy.retained_digest_count(outer_len)?;
        let depth = outer_len.ilog2() as u8;
        if digests.keys().any(|(level, index)| {
            *level <= policy.bottom_levels_omitted
                || *level >= depth
                || *index >= (outer_len as u64 >> *level)
        }) {
            return Err(MerkleError::InvalidGeometry("v4 sparse outer cache key"));
        }
        Ok(Self { outer_len, policy, root, digests })
    }

    pub fn deterministic_fixture(
        config: &CohortVerifierConfigV4,
        query_draws: &[u64],
        policy: OuterCachePolicyV4,
        root: Digest,
    ) -> Result<Self, MerkleError> {
        let keys = outer_cache_keys_for_queries_v4(config, query_draws, policy)?;
        let digests = keys
            .into_iter()
            .map(|key @ (level, index)| {
                let digest = if level == 1 {
                    zero_outer_level_one_v4(config, index).expect("validated zero fixture geometry")
                } else {
                    let mut input = [0u8; 16];
                    input[0] = level;
                    input[1..9].copy_from_slice(&index.to_le_bytes());
                    input[9..13].copy_from_slice(&config.identity.cohort_id.to_le_bytes());
                    input[13] = config.identity.oracle_kind as u8;
                    input[14] = config.identity.fold_round;
                    input[15] = config.outer_depth();
                    *blake3::hash(&input).as_bytes()
                };
                (key, digest)
            })
            .collect();
        Self::new(config.outer_len, policy, root, digests)
    }

    pub fn required_digest_count(&self) -> usize {
        self.digests.len()
    }
}

fn zero_outer_level_one_v4(
    config: &CohortVerifierConfigV4,
    node_index: u64,
) -> Result<Digest, MerkleError> {
    let left_index = node_index.checked_mul(2).ok_or(MerkleError::Overflow)?;
    let left = zero_outer_leaf_v4(config, left_index)?;
    let right = zero_outer_leaf_v4(config, left_index + 1)?;
    Ok(hash_pcs_node_fields_v4(
        config.identity.cohort_id,
        TreeRole::Outer,
        config.identity.oracle_kind,
        config.identity.fold_round,
        u64::MAX,
        1,
        node_index,
        left,
        right,
    )?)
}

fn zero_outer_leaf_v4(
    config: &CohortVerifierConfigV4,
    coordinate: u64,
) -> Result<Digest, MerkleError> {
    let mut scratch = Vec::with_capacity(config.slot_descriptors.len());
    for (slot, descriptor) in config.slot_descriptors.iter().enumerate() {
        scratch.push(hash_pcs_inner_leaf_fields_v4(
            config.identity.cohort_id,
            config.identity.oracle_kind,
            config.identity.fold_round,
            coordinate,
            descriptor.unwrap_or([0; 32]),
            u16::try_from(slot).map_err(|_| MerkleError::Overflow)?,
            descriptor.map(|_| Fp2::ZERO),
        )?);
    }
    let mut width = scratch.len();
    let mut level = 1u8;
    while width > 1 {
        for index in 0..width / 2 {
            scratch[index] = hash_pcs_node_fields_v4(
                config.identity.cohort_id,
                TreeRole::Inner,
                config.identity.oracle_kind,
                config.identity.fold_round,
                coordinate,
                level,
                u64::try_from(index).map_err(|_| MerkleError::Overflow)?,
                scratch[2 * index],
                scratch[2 * index + 1],
            )?;
        }
        width /= 2;
        level = level.checked_add(1).ok_or(MerkleError::Overflow)?;
    }
    Ok(hash_pcs_outer_leaf_fields_v4(
        config.identity.cohort_id,
        config.identity.oracle_kind,
        config.identity.fold_round,
        coordinate,
        scratch[0],
    )?)
}

impl OuterNodeSourceV4 for SparseOuterNodeCacheV4 {
    fn cache_policy(&self) -> OuterCachePolicyV4 {
        self.policy
    }

    fn root(&self) -> Digest {
        self.root
    }

    fn read_cached_digest(&self, level: u8, index: u64) -> Result<Digest, MerkleError> {
        if level == 0 || index >= (self.outer_len as u64 >> level) {
            return Err(MerkleError::InvalidOpening("v4 sparse cached outer index"));
        }
        self.digests
            .get(&(level, index))
            .copied()
            .ok_or(MerkleError::InvalidOpening("v4 sparse cached outer digest"))
    }
}

pub fn outer_cache_keys_for_queries_v4(
    config: &CohortVerifierConfigV4,
    query_draws: &[u64],
    policy: OuterCachePolicyV4,
) -> Result<BTreeSet<(u8, u64)>, MerkleError> {
    config.validate()?;
    policy.retained_digest_count(config.outer_len)?;
    let indices = projected_query_indices(query_draws, config.outer_depth())
        .map_err(|_| MerkleError::InvalidOpening("v4 projected persisted indices"))?;
    let mut keys = BTreeSet::new();
    let mut current = indices.into_iter().collect::<BTreeSet<_>>();
    for level in 0..config.outer_depth() {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                collect_cache_requirements(level, sibling, policy, &mut keys)?;
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(keys)
}

fn collect_cache_requirements(
    level: u8,
    index: u64,
    policy: OuterCachePolicyV4,
    keys: &mut BTreeSet<(u8, u64)>,
) -> Result<(), MerkleError> {
    if level == 0 {
        return Ok(());
    }
    if level > policy.bottom_levels_omitted {
        keys.insert((level, index));
        return Ok(());
    }
    let left = index.checked_mul(2).ok_or(MerkleError::Overflow)?;
    collect_cache_requirements(level - 1, left, policy, keys)?;
    collect_cache_requirements(level - 1, left + 1, policy, keys)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PersistedOpeningTrafficV4 {
    pub oracle_file_bytes_read: u64,
    pub outer_cache_bytes_read: u64,
    pub inner_trees_rebuilt: u64,
    pub outer_frontier_leaves_rebuilt: u64,
    pub outer_internal_nodes_rebuilt: u64,
}

impl PersistedOpeningTrafficV4 {
    pub fn from_metrics(metrics: OpeningRebuildMetricsV4) -> Result<Self, MerkleError> {
        Ok(Self {
            oracle_file_bytes_read: metrics
                .oracle_symbols_read
                .checked_mul(PERSISTED_SYMBOL_BYTES_V4)
                .ok_or(MerkleError::Overflow)?,
            outer_cache_bytes_read: metrics
                .cached_outer_digests_read
                .checked_mul(PERSISTED_DIGEST_BYTES_V4)
                .ok_or(MerkleError::Overflow)?,
            inner_trees_rebuilt: metrics.inner_trees_rebuilt,
            outer_frontier_leaves_rebuilt: metrics.outer_frontier_leaves_rebuilt,
            outer_internal_nodes_rebuilt: metrics.outer_internal_nodes_rebuilt,
        })
    }
}

#[derive(Debug)]
pub struct PersistedCohortOpeningV4<C: OuterNodeSourceV4> {
    config: CohortVerifierConfigV4,
    oracle: PersistedOracleV4,
    outer_cache: C,
}

impl<C: OuterNodeSourceV4> PersistedCohortOpeningV4<C> {
    pub fn load(
        path: impl AsRef<Path>,
        config: CohortVerifierConfigV4,
        outer_cache: C,
        binding: PersistedOracleBindingV4,
        expected_binding: PersistedOracleBindingV4,
    ) -> Result<Self, PersistedOracleErrorV4> {
        if binding.cohort_root != outer_cache.root() {
            return Err(PersistedOracleErrorV4::Invalid("v4 persisted cache root"));
        }
        let oracle = PersistedOracleV4::load(path, config.clone(), binding, expected_binding)?;
        Ok(Self { config, oracle, outer_cache })
    }

    pub fn root(&self) -> Digest {
        self.outer_cache.root()
    }

    pub fn logical_oracle_bytes(&self) -> u64 {
        self.oracle.logical_bytes()
    }

    pub fn open_initial(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(InitialOpeningGroupV4, PersistedOpeningTrafficV4), PersistedOracleErrorV4> {
        let (opening, metrics) = open_initial_from_sources_v4(
            &self.config,
            query_draws,
            touched_slots,
            &self.oracle,
            &self.outer_cache,
        )?;
        Ok((opening, PersistedOpeningTrafficV4::from_metrics(metrics)?))
    }

    pub fn open_fold_round(
        &self,
        query_draws: &[u64],
    ) -> Result<(FoldRoundOpeningV4, PersistedOpeningTrafficV4), PersistedOracleErrorV4> {
        let (opening, metrics) =
            open_fold_from_sources_v4(&self.config, query_draws, &self.oracle, &self.outer_cache)?;
        Ok((opening, PersistedOpeningTrafficV4::from_metrics(metrics)?))
    }
}

#[derive(Debug)]
pub struct PersistedModelGlobalCohortV4<C: OuterNodeSourceV4> {
    commitment: ModelGlobalCohortCommitmentV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    opening: PersistedCohortOpeningV4<C>,
}

impl<C: OuterNodeSourceV4> PersistedModelGlobalCohortV4<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        path: impl AsRef<Path>,
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
        outer_cache: C,
        binding: PersistedOracleBindingV4,
        expected_binding: PersistedOracleBindingV4,
    ) -> Result<Self, PersistedOracleErrorV4> {
        if coefficients.len() != config.slot_descriptors.len() {
            return Err(PersistedOracleErrorV4::Invalid("v4 persisted coefficients"));
        }
        let coefficient_len = config.outer_len / 8;
        for (descriptor, slot_coefficients) in config.slot_descriptors.iter().zip(&coefficients) {
            match (descriptor, slot_coefficients) {
                (Some(_), Some(values)) if values.len() == coefficient_len => {}
                (None, None) => {}
                _ => {
                    return Err(PersistedOracleErrorV4::Invalid(
                        "v4 persisted coefficient geometry",
                    ));
                }
            }
        }
        let opening = PersistedCohortOpeningV4::load(
            path,
            config.clone(),
            outer_cache,
            binding,
            expected_binding,
        )?;
        let commitment = ModelGlobalCohortCommitmentV4 { root: binding.cohort_root, config };
        Ok(Self { commitment, coefficients, opening })
    }
}

impl<C: OuterNodeSourceV4> ModelGlobalOpeningSourceV4 for PersistedModelGlobalCohortV4<C> {
    fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        &self.commitment
    }

    fn combine_source(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<(CombinedInitialV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        if touched_slots.is_empty()
            || touched_slots.len() != weights.len()
            || !touched_slots.windows(2).all(|pair| pair[0] < pair[1])
            || target_point.len() != (self.commitment.config.outer_len / 8).ilog2() as usize
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 persisted group geometry"));
        }
        let coefficient_len = self.commitment.config.outer_len / 8;
        let mut coefficients = vec![Fp2::ZERO; coefficient_len];
        let mut codeword = vec![Fp2::ZERO; self.commitment.config.outer_len];
        let mut persisted_bytes = 0u64;
        for (slot, weight) in touched_slots.iter().zip(weights) {
            let source = self
                .coefficients
                .get(usize::from(*slot))
                .and_then(Option::as_ref)
                .ok_or(FoldingErrorV4::InvalidGeometry("v4 persisted touched slot"))?;
            for (output, value) in coefficients.iter_mut().zip(source) {
                *output += *weight * *value;
            }
            persisted_bytes = persisted_bytes
                .checked_add(self.opening.oracle.accumulate_slot(*slot, *weight, &mut codeword)?)
                .ok_or(FoldingErrorV4::Overflow)?;
        }
        let claimed_value = evaluate_multilinear_coefficients(&coefficients, target_point)
            .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 persisted target evaluation"))?;
        Ok((
            CombinedInitialV4 { coefficients, codeword, claimed_value },
            SourceRecomputeTrafficV4 {
                persisted_oracle_bytes_read: persisted_bytes,
                persisted_page_cache_dontneed_bytes: persisted_bytes,
                persisted_page_cache_advice_calls: u64::try_from(touched_slots.len())
                    .map_err(|_| FoldingErrorV4::Overflow)?,
                ..SourceRecomputeTrafficV4::default()
            },
        ))
    }

    fn open_initial_source(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(InitialOpeningGroupV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        let (opening, traffic) =
            self.opening.open_initial(query_draws, touched_slots).map_err(|error| match error {
                PersistedOracleErrorV4::Merkle(error) => FoldingErrorV4::Merkle(error),
                PersistedOracleErrorV4::Io(_) | PersistedOracleErrorV4::Invalid(_) => {
                    FoldingErrorV4::InvalidProof("v4 persisted opening")
                }
            })?;
        Ok((
            opening,
            SourceRecomputeTrafficV4 {
                persisted_oracle_bytes_read: traffic.oracle_file_bytes_read,
                outer_cache_bytes_read: traffic.outer_cache_bytes_read,
                inner_trees_rebuilt: traffic.inner_trees_rebuilt,
                outer_frontier_leaves_rebuilt: traffic.outer_frontier_leaves_rebuilt,
                outer_internal_nodes_rebuilt: traffic.outer_internal_nodes_rebuilt,
                ..SourceRecomputeTrafficV4::default()
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::merkle_v4::{
        verify_initial_packed_opening_v4, CohortIdentityV4, CohortTreeV4, DenseOuterNodeCacheV4,
    };

    fn config() -> CohortVerifierConfigV4 {
        CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xA500_7711,
                oracle_kind: OracleKindV4::Auxiliary,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), None, Some([3; 32]), None],
            outer_len: 32,
            expected_symbol_count: 1,
        }
    }

    fn symbols() -> Vec<Option<Vec<Fp2>>> {
        vec![
            Some((0..32).map(|i| Fp2::new(Fp::new(i + 1), Fp::new(2 * i + 9))).collect()),
            None,
            Some((0..32).map(|i| Fp2::new(Fp::new(i + 101), Fp::new(3 * i + 7))).collect()),
            None,
        ]
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "volta-x4b-{label}-{}-{}.oracle",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }

    #[test]
    fn persisted_oracle_opening_matches_in_memory_reference_byte_for_byte() {
        let config = config();
        let symbols = symbols();
        let tree = CohortTreeV4::build_flat(config.clone(), symbols.clone()).unwrap();
        let path = temp_path("dense");
        let bytes = write_persisted_oracle_v4(&path, &config, &symbols).unwrap();
        assert_eq!(bytes, 2 * 32 * 16);
        let binding = PersistedOracleBindingV4::new([0x22; 32], [0x44; 32], tree.root());
        let persisted = PersistedCohortOpeningV4::<DenseOuterNodeCacheV4>::load(
            &path,
            config,
            tree.outer_cache().clone(),
            binding,
            binding,
        )
        .unwrap();
        let draws = vec![7; 111];
        let reference = tree.open_initial(&draws, &[0, 2]).unwrap();
        let (opening, traffic) = persisted.open_initial(&draws, &[0, 2]).unwrap();
        assert_eq!(opening, reference);
        assert!(traffic.oracle_file_bytes_read > 0);
        verify_initial_packed_opening_v4(
            persisted.root(),
            tree.config(),
            &draws,
            &[0, 2],
            &opening,
        )
        .unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn x4b_record_policy_refuses_audit_recompute() {
        X4bOpeningSourcePolicyV4::PersistedOracle.require_record_eligible().unwrap();
        assert!(X4bOpeningSourcePolicyV4::AuditRecompute.require_record_eligible().is_err());
    }

    #[test]
    fn persisted_coefficients_roundtrip_with_absent_slots_and_exact_length() {
        let config = config();
        let coefficients = vec![
            Some((0..4).map(|i| Fp2::new(Fp::new(i + 7), Fp::new(i + 19))).collect()),
            None,
            Some((0..4).map(|i| Fp2::new(Fp::new(i + 71), Fp::new(i + 91))).collect()),
            None,
        ];
        let path = temp_path("coefficients");
        assert_eq!(write_persisted_coefficients_v4(&path, &config, &coefficients).unwrap(), 128);
        assert_eq!(read_persisted_coefficients_v4(&path, &config).unwrap(), coefficients);
        std::fs::remove_file(path).unwrap();
    }
}
