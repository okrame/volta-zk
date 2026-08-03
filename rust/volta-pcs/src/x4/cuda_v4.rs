//! X4b CUDA commit schedule for the frozen schema-4 cohort construction.
//!
//! One present slot is encoded at a time with the exact `E` NTT, immediately
//! persisted, and dropped before the next slot.  A second streaming pass reads
//! power-of-two coordinate tiles, emits typed N4 outer leaves, and reduces
//! outer levels through bounded staging files.  No whole-model oracle is ever
//! resident on the device and no proof/frame byte is defined in this module.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use volta_accel::{AccelError, Backend, BackendKind};
use volta_field::{Fp, Fp2, P};

use super::folding_v4::ModelGlobalCohortCommitmentV4;
use super::frame::Digest;
use super::lifecycle_v4::{
    NoopX4LifecycleObserverV4, X4AcceleratorControlSnapshotV4, X4LegacySealedOwnershipV4,
    X4LifecycleContextV4, X4LifecycleEventV4, X4LifecycleNestingV4, X4LifecycleObserverV4,
    X4LifecyclePhaseV4, X4LifecycleTrackV4, X4TemporaryFileStateV4,
};
use super::merkle::MerkleError;
use super::merkle_v4::{CohortVerifierConfigV4, DenseOuterNodeCacheV4, OuterCachePolicyV4};
use super::persisted_v4::write_canonical_fp2_slice_v4;

pub const X4B_DEVICE_BYTE_CEILING_V4: u64 = 48 * 1024 * 1024 * 1024;
pub const X4B_N4_TILE_BYTE_CEILING_V4: u64 = 512 * 1024 * 1024;
const SYMBOL_BYTES: u64 = 16;
const DIGEST_BYTES: u64 = 32;
const KEY_BYTES: u64 = 4 * DIGEST_BYTES;
static STAGING_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub struct X4bCudaCohortPathsV4 {
    pub coefficients: PathBuf,
    pub oracle: PathBuf,
    pub root: PathBuf,
    pub staging_directory: PathBuf,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X4bCudaCommitMetricsV4 {
    pub present_slots: u64,
    pub structural_slots: u64,
    pub coefficient_bytes_read: u64,
    pub coefficient_bytes_persisted: u64,
    pub oracle_bytes_persisted: u64,
    pub root_bytes_persisted: u64,
    pub persisted_oracle_bytes_read_for_n4: u64,
    pub staging_bytes_read: u64,
    pub staging_bytes_written: u64,
    pub peak_live_staging_bytes: u64,
    pub retained_outer_cache_bytes: u64,
    pub expected_h2d_bytes: u64,
    pub expected_d2h_bytes: u64,
    pub expected_device_zeroed_bytes: u64,
    pub maximum_n4_tile_bytes: u64,
    pub page_cache_dontneed_bytes: u64,
    pub page_cache_advice_calls: u64,
    pub fsync_count: u64,
    pub ntt_calls: u64,
    pub inner_tile_calls: u64,
    pub outer_tile_calls: u64,
    pub files_created: u64,
    pub files_deleted: u64,
    pub directories_created: u64,
    pub directories_deleted: u64,
}

impl X4bCudaCommitMetricsV4 {
    pub fn persistent_artifact_bytes(&self) -> Result<u64, X4bCudaCommitErrorV4> {
        self.coefficient_bytes_persisted
            .checked_add(self.oracle_bytes_persisted)
            .and_then(|value| value.checked_add(self.root_bytes_persisted))
            .ok_or(X4bCudaCommitErrorV4::Overflow)
    }

    pub fn include(&mut self, other: &Self) -> Result<(), X4bCudaCommitErrorV4> {
        macro_rules! add {
            ($field:ident) => {
                self.$field =
                    self.$field.checked_add(other.$field).ok_or(X4bCudaCommitErrorV4::Overflow)?;
            };
        }
        add!(present_slots);
        add!(structural_slots);
        add!(coefficient_bytes_read);
        add!(coefficient_bytes_persisted);
        add!(oracle_bytes_persisted);
        add!(root_bytes_persisted);
        add!(persisted_oracle_bytes_read_for_n4);
        add!(staging_bytes_read);
        add!(staging_bytes_written);
        add!(retained_outer_cache_bytes);
        add!(expected_h2d_bytes);
        add!(expected_d2h_bytes);
        add!(expected_device_zeroed_bytes);
        add!(ntt_calls);
        add!(inner_tile_calls);
        add!(outer_tile_calls);
        add!(files_created);
        add!(files_deleted);
        add!(directories_created);
        add!(directories_deleted);
        add!(page_cache_dontneed_bytes);
        add!(page_cache_advice_calls);
        add!(fsync_count);
        self.peak_live_staging_bytes =
            self.peak_live_staging_bytes.max(other.peak_live_staging_bytes);
        self.maximum_n4_tile_bytes = self.maximum_n4_tile_bytes.max(other.maximum_n4_tile_bytes);
        Ok(())
    }
}

#[derive(Debug)]
pub struct X4bCudaCohortArtifactsV4 {
    pub commitment: ModelGlobalCohortCommitmentV4,
    pub outer_cache: DenseOuterNodeCacheV4,
    pub paths: X4bCudaCohortPathsV4,
    pub metrics: X4bCudaCommitMetricsV4,
}

#[derive(Debug)]
pub enum X4bCudaCommitErrorV4 {
    Accel(AccelError),
    Io(io::Error),
    Merkle(MerkleError),
    Invalid(&'static str),
    Overflow,
}

impl std::fmt::Display for X4bCudaCommitErrorV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accel(error) => write!(formatter, "X4b CUDA error: {error}"),
            Self::Io(error) => write!(formatter, "X4b artifact I/O error: {error}"),
            Self::Merkle(error) => write!(formatter, "X4b Merkle error: {error:?}"),
            Self::Invalid(message) => write!(formatter, "invalid X4b CUDA commit: {message}"),
            Self::Overflow => write!(formatter, "X4b CUDA commit byte geometry overflow"),
        }
    }
}

impl std::error::Error for X4bCudaCommitErrorV4 {}

impl From<AccelError> for X4bCudaCommitErrorV4 {
    fn from(value: AccelError) -> Self {
        Self::Accel(value)
    }
}

impl From<io::Error> for X4bCudaCommitErrorV4 {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<MerkleError> for X4bCudaCommitErrorV4 {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

#[derive(Debug, Default)]
struct CreatedFiles {
    paths: Vec<PathBuf>,
    keep: bool,
}

impl CreatedFiles {
    fn create(&mut self, path: &Path) -> Result<File, io::Error> {
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        self.paths.push(path.to_path_buf());
        Ok(file)
    }

    fn retain(mut self) {
        self.keep = true;
    }
}

impl Drop for CreatedFiles {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Debug, Default)]
struct StagingFiles {
    paths: BTreeSet<PathBuf>,
}

impl StagingFiles {
    fn create(&mut self, path: &Path) -> Result<File, io::Error> {
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        self.paths.insert(path.to_path_buf());
        Ok(file)
    }

    fn remove(&mut self, path: &Path) -> Result<(), io::Error> {
        fs::remove_file(path)?;
        self.paths.remove(path);
        Ok(())
    }
}

impl Drop for StagingFiles {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

/// Largest power-of-two coordinate tile whose complete logical device
/// buffers fit the frozen 512-MiB N4 ceiling.
pub fn x4b_inner_tile_coordinates_v4(
    structural_slots: usize,
    present_slots: usize,
    outer_len: usize,
) -> Result<usize, X4bCudaCommitErrorV4> {
    if structural_slots == 0
        || !structural_slots.is_power_of_two()
        || structural_slots > 64
        || present_slots == 0
        || present_slots > structural_slots
        || outer_len < 8
        || !outer_len.is_power_of_two()
    {
        return Err(X4bCudaCommitErrorV4::Invalid("N4 inner tile geometry"));
    }
    let metadata = u64::try_from(structural_slots)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(2 + DIGEST_BYTES)
        .and_then(|value| value.checked_add(KEY_BYTES))
        .and_then(|value| value.checked_add(if structural_slots == 1 { DIGEST_BYTES } else { 0 }))
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let first_hash = u64::try_from(structural_slots)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let second_hash = if structural_slots == 1 { 0 } else { first_hash / 2 };
    let per_coordinate = u64::try_from(present_slots)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(SYMBOL_BYTES)
        .and_then(|value| value.checked_add(first_hash))
        .and_then(|value| value.checked_add(second_hash))
        .and_then(|value| value.checked_add(DIGEST_BYTES))
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let available = X4B_N4_TILE_BYTE_CEILING_V4
        .checked_sub(metadata)
        .ok_or(X4bCudaCommitErrorV4::Invalid("N4 metadata exceeds tile ceiling"))?;
    let maximum = usize::try_from(available / per_coordinate)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .min(outer_len);
    if maximum == 0 {
        return Err(X4bCudaCommitErrorV4::Invalid("N4 tile has no coordinate capacity"));
    }
    Ok(1usize << maximum.ilog2())
}

pub fn x4b_outer_tile_parents_v4(parent_count: usize) -> Result<usize, X4bCudaCommitErrorV4> {
    if parent_count == 0 || !parent_count.is_power_of_two() {
        return Err(X4bCudaCommitErrorV4::Invalid("N4 outer tile geometry"));
    }
    let available =
        X4B_N4_TILE_BYTE_CEILING_V4.checked_sub(KEY_BYTES).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let maximum = usize::try_from(available / (3 * DIGEST_BYTES))
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .min(parent_count);
    Ok(1usize << maximum.ilog2())
}

/// Full byte-for-byte cross-check between a GPU-produced persisted oracle and
/// the CPU reference codewords retained by the folding relation. This is an
/// explicit host-read counter, never a free correctness assertion.
pub fn verify_persisted_oracle_matches_v4(
    path: impl AsRef<Path>,
    config: &CohortVerifierConfigV4,
    slot_symbols: &[Option<&[Fp2]>],
) -> Result<u64, X4bCudaCommitErrorV4> {
    config.validate()?;
    if slot_symbols.len() != config.slot_descriptors.len() {
        return Err(X4bCudaCommitErrorV4::Invalid("oracle comparison slot count"));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let present = config.slot_descriptors.iter().flatten().count();
    let expected_bytes = u64::try_from(present)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(config.outer_len as u64)
        .and_then(|value| value.checked_mul(SYMBOL_BYTES))
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(X4bCudaCommitErrorV4::Invalid("oracle comparison file length"));
    }
    const CHUNK_SYMBOLS: usize = 32 * 1024;
    let mut encoded = vec![0u8; CHUNK_SYMBOLS * SYMBOL_BYTES as usize];
    let mut offset = 0u64;
    for (descriptor, symbols) in config.slot_descriptors.iter().zip(slot_symbols) {
        match (descriptor, symbols) {
            (Some(_), Some(symbols)) if symbols.len() == config.outer_len => {
                for chunk in symbols.chunks(CHUNK_SYMBOLS) {
                    let byte_count = chunk
                        .len()
                        .checked_mul(SYMBOL_BYTES as usize)
                        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                    read_exact_at(&file, offset, &mut encoded[..byte_count])?;
                    for (actual, expected) in encoded[..byte_count].chunks_exact(16).zip(chunk) {
                        if actual[..8] != expected.c0.value().to_le_bytes()
                            || actual[8..] != expected.c1.value().to_le_bytes()
                        {
                            return Err(X4bCudaCommitErrorV4::Invalid(
                                "GPU/CPU persisted codeword mismatch",
                            ));
                        }
                    }
                    offset = offset
                        .checked_add(
                            u64::try_from(byte_count)
                                .map_err(|_| X4bCudaCommitErrorV4::Overflow)?,
                        )
                        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                }
            }
            (None, None) => {}
            _ => {
                return Err(X4bCudaCommitErrorV4::Invalid("oracle comparison symbol geometry"));
            }
        }
    }
    if offset != expected_bytes {
        return Err(X4bCudaCommitErrorV4::Invalid("oracle comparison byte count"));
    }
    Ok(expected_bytes)
}

fn observe_seal_v4(
    backend: &Backend,
    observer: &mut dyn X4LifecycleObserverV4,
    phase: X4LifecyclePhaseV4,
    span_start: bool,
    context: X4LifecycleContextV4,
    sealed_ownership: X4LegacySealedOwnershipV4,
    temporary_files: X4TemporaryFileStateV4,
) {
    let event = if span_start {
        X4LifecycleEventV4::span_start(
            X4LifecycleTrackV4::LegacySeal,
            phase,
            X4LifecycleNestingV4::TopLevel,
            context,
            sealed_ownership,
            temporary_files,
        )
    } else {
        X4LifecycleEventV4::span_end(
            X4LifecycleTrackV4::LegacySeal,
            phase,
            X4LifecycleNestingV4::TopLevel,
            context,
            sealed_ownership,
            temporary_files,
        )
    };
    observer
        .observe(&event.with_accelerator_control(X4AcceleratorControlSnapshotV4::capture(backend)));
}

fn record_file_created_v4(
    state: &mut X4TemporaryFileStateV4,
    metrics: &mut X4bCudaCommitMetricsV4,
) -> Result<(), X4bCudaCommitErrorV4> {
    state.record_file_created().ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.files_created =
        metrics.files_created.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    Ok(())
}

fn record_file_bytes_v4(
    state: &mut X4TemporaryFileStateV4,
    bytes: u64,
) -> Result<(), X4bCudaCommitErrorV4> {
    state.record_file_bytes_written(bytes).ok_or(X4bCudaCommitErrorV4::Overflow)
}

fn record_file_deleted_v4(
    state: &mut X4TemporaryFileStateV4,
    metrics: &mut X4bCudaCommitMetricsV4,
    bytes: u64,
) -> Result<(), X4bCudaCommitErrorV4> {
    state.record_file_deleted(bytes).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.files_deleted =
        metrics.files_deleted.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    Ok(())
}

fn record_directory_created_v4(
    state: &mut X4TemporaryFileStateV4,
    metrics: &mut X4bCudaCommitMetricsV4,
) -> Result<(), X4bCudaCommitErrorV4> {
    state.record_directory_created().ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.directories_created =
        metrics.directories_created.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn commit_cohort_cuda_v4(
    backend: &mut Backend,
    config: CohortVerifierConfigV4,
    coefficients: &[Option<Vec<Fp2>>],
    paths: X4bCudaCohortPathsV4,
    cache_policy: OuterCachePolicyV4,
) -> Result<X4bCudaCohortArtifactsV4, X4bCudaCommitErrorV4> {
    let mut observer = NoopX4LifecycleObserverV4;
    let mut temporary_files = X4TemporaryFileStateV4::default();
    commit_cohort_cuda_v4_instrumented(
        backend,
        config,
        coefficients,
        paths,
        cache_policy,
        &mut observer,
        X4LegacySealedOwnershipV4::default(),
        &mut temporary_files,
    )
}

/// Instrumented legacy X4b cohort commit. The observer sees coarse host-wall
/// boundaries only; no CUDA-event timing is introduced here.
#[allow(clippy::too_many_arguments)]
pub fn commit_cohort_cuda_v4_instrumented(
    backend: &mut Backend,
    config: CohortVerifierConfigV4,
    coefficients: &[Option<Vec<Fp2>>],
    paths: X4bCudaCohortPathsV4,
    cache_policy: OuterCachePolicyV4,
    observer: &mut dyn X4LifecycleObserverV4,
    sealed_ownership: X4LegacySealedOwnershipV4,
    temporary_files: &mut X4TemporaryFileStateV4,
) -> Result<X4bCudaCohortArtifactsV4, X4bCudaCommitErrorV4> {
    if backend.kind() == BackendKind::Cpu {
        return Err(X4bCudaCommitErrorV4::Invalid("CPU backend supplied to CUDA commit"));
    }
    if !sealed_ownership.is_consistent_legacy() || !temporary_files.is_consistent() {
        return Err(X4bCudaCommitErrorV4::Invalid("lifecycle ownership"));
    }
    config.validate()?;
    cache_policy.retained_bytes(config.outer_len)?;
    if coefficients.len() != config.slot_descriptors.len() {
        return Err(X4bCudaCommitErrorV4::Invalid("coefficient slot count"));
    }
    if paths.coefficients == paths.oracle
        || paths.coefficients == paths.root
        || paths.oracle == paths.root
    {
        return Err(X4bCudaCommitErrorV4::Invalid("artifact paths must be distinct"));
    }
    let present_slots = config.slot_descriptors.iter().flatten().count();
    let coefficient_len = config.outer_len / 8;
    let mut metrics = X4bCudaCommitMetricsV4 {
        present_slots: u64::try_from(present_slots).map_err(|_| X4bCudaCommitErrorV4::Overflow)?,
        structural_slots: u64::try_from(config.slot_descriptors.len())
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?,
        ..X4bCudaCommitMetricsV4::default()
    };
    let staging_directory_existed = paths.staging_directory.exists();
    fs::create_dir_all(&paths.staging_directory)?;
    if !staging_directory_existed {
        record_directory_created_v4(temporary_files, &mut metrics)?;
    }
    let base_context = X4LifecycleContextV4 {
        cohort_id: Some(config.identity.cohort_id),
        fold_round: Some(config.identity.fold_round),
        ..X4LifecycleContextV4::default()
    };

    let mut artifacts = CreatedFiles::default();
    let coefficient_file = artifacts.create(&paths.coefficients)?;
    record_file_created_v4(temporary_files, &mut metrics)?;
    let oracle_file = artifacts.create(&paths.oracle)?;
    record_file_created_v4(temporary_files, &mut metrics)?;
    let mut coefficient_writer = BufWriter::with_capacity(8 * 1024 * 1024, coefficient_file);
    let mut oracle_writer = BufWriter::with_capacity(8 * 1024 * 1024, oracle_file);
    for (slot_index, (descriptor, slot_coefficients)) in
        config.slot_descriptors.iter().zip(coefficients).enumerate()
    {
        match (descriptor, slot_coefficients) {
            (Some(_), Some(slot_coefficients)) if slot_coefficients.len() == coefficient_len => {
                let coefficient_bytes = u64::try_from(slot_coefficients.len())
                    .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
                    .checked_mul(SYMBOL_BYTES)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                let slot_index =
                    u16::try_from(slot_index).map_err(|_| X4bCudaCommitErrorV4::Overflow)?;
                let coefficient_write_context = X4LifecycleContextV4 {
                    slot_index: Some(slot_index),
                    segment_index: u32::from(slot_index) * 2,
                    ..base_context
                };
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::CoefficientOracleWrite,
                    true,
                    coefficient_write_context,
                    sealed_ownership,
                    *temporary_files,
                );
                write_symbols(&mut coefficient_writer, slot_coefficients)?;
                record_file_bytes_v4(temporary_files, coefficient_bytes)?;
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::CoefficientOracleWrite,
                    false,
                    coefficient_write_context,
                    sealed_ownership,
                    *temporary_files,
                );
                let ntt_context = X4LifecycleContextV4 {
                    slot_index: Some(slot_index),
                    segment_index: u32::from(slot_index),
                    ..base_context
                };
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::ENtt,
                    true,
                    ntt_context,
                    sealed_ownership,
                    *temporary_files,
                );
                let codeword = backend.x4b_ntt_fp2(slot_coefficients, config.outer_len)?;
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::ENtt,
                    false,
                    ntt_context,
                    sealed_ownership,
                    *temporary_files,
                );
                let oracle_bytes = u64::try_from(codeword.len())
                    .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
                    .checked_mul(SYMBOL_BYTES)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                let oracle_write_context = X4LifecycleContextV4 {
                    slot_index: Some(slot_index),
                    segment_index: u32::from(slot_index) * 2 + 1,
                    ..base_context
                };
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::CoefficientOracleWrite,
                    true,
                    oracle_write_context,
                    sealed_ownership,
                    *temporary_files,
                );
                write_symbols(&mut oracle_writer, &codeword)?;
                record_file_bytes_v4(temporary_files, oracle_bytes)?;
                observe_seal_v4(
                    backend,
                    observer,
                    X4LifecyclePhaseV4::CoefficientOracleWrite,
                    false,
                    oracle_write_context,
                    sealed_ownership,
                    *temporary_files,
                );
                metrics.coefficient_bytes_read = metrics
                    .coefficient_bytes_read
                    .checked_add(coefficient_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.coefficient_bytes_persisted = metrics
                    .coefficient_bytes_persisted
                    .checked_add(coefficient_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.oracle_bytes_persisted = metrics
                    .oracle_bytes_persisted
                    .checked_add(oracle_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.expected_h2d_bytes = metrics
                    .expected_h2d_bytes
                    .checked_add(coefficient_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.expected_d2h_bytes = metrics
                    .expected_d2h_bytes
                    .checked_add(oracle_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.expected_device_zeroed_bytes = metrics
                    .expected_device_zeroed_bytes
                    .checked_add(oracle_bytes - coefficient_bytes)
                    .ok_or(X4bCudaCommitErrorV4::Overflow)?;
                metrics.ntt_calls += 1;
            }
            (None, None) => {}
            _ => return Err(X4bCudaCommitErrorV4::Invalid("coefficient slot geometry")),
        }
    }
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        true,
        X4LifecycleContextV4 { segment_index: 0, ..base_context },
        sealed_ownership,
        *temporary_files,
    );
    coefficient_writer.flush()?;
    coefficient_writer.get_ref().sync_data()?;
    oracle_writer.flush()?;
    oracle_writer.get_ref().sync_data()?;
    metrics.fsync_count =
        metrics.fsync_count.checked_add(2).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    advise_dontneed(coefficient_writer.get_ref(), metrics.coefficient_bytes_persisted)?;
    advise_dontneed(oracle_writer.get_ref(), metrics.oracle_bytes_persisted)?;
    metrics.page_cache_dontneed_bytes = metrics
        .coefficient_bytes_persisted
        .checked_add(metrics.oracle_bytes_persisted)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.page_cache_advice_calls = 2;
    drop(coefficient_writer);
    drop(oracle_writer);
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        false,
        X4LifecycleContextV4 { segment_index: 0, ..base_context },
        sealed_ownership,
        *temporary_files,
    );

    let mut staging = StagingFiles::default();
    let nonce = STAGING_NONCE.fetch_add(1, Ordering::Relaxed);
    let prefix = format!(
        "x4b-{}-{}-{}-{}-{}",
        std::process::id(),
        nonce,
        config.identity.cohort_id,
        config.identity.oracle_kind as u8,
        config.identity.fold_round,
    );
    let leaves_path = paths.staging_directory.join(format!("{prefix}-outer-0.bin"));
    let leaves_file = staging.create(&leaves_path)?;
    record_file_created_v4(temporary_files, &mut metrics)?;
    let mut leaves_writer = BufWriter::with_capacity(8 * 1024 * 1024, leaves_file);
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::OracleRereadN4Inner,
        true,
        base_context,
        sealed_ownership,
        *temporary_files,
    );
    let oracle_reader = OpenOptions::new().read(true).open(&paths.oracle)?;

    let mut ranks = Vec::with_capacity(config.slot_descriptors.len());
    let mut descriptors = Vec::with_capacity(config.slot_descriptors.len());
    let mut next_rank = 0u16;
    for descriptor in &config.slot_descriptors {
        if let Some(descriptor) = descriptor {
            ranks.push(next_rank);
            descriptors.push(*descriptor);
            next_rank = next_rank.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
        } else {
            ranks.push(u16::MAX);
            descriptors.push([0u8; 32]);
        }
    }
    if usize::from(next_rank) != present_slots {
        return Err(X4bCudaCommitErrorV4::Invalid("present-slot rank count"));
    }
    let coordinate_tile = x4b_inner_tile_coordinates_v4(
        config.slot_descriptors.len(),
        present_slots,
        config.outer_len,
    )?;
    let inner_tile_bytes =
        n4_inner_logical_tile_bytes(config.slot_descriptors.len(), present_slots, coordinate_tile)?;
    metrics.maximum_n4_tile_bytes = metrics.maximum_n4_tile_bytes.max(inner_tile_bytes);
    for coordinate_start in (0..config.outer_len).step_by(coordinate_tile) {
        let symbols = read_oracle_tile(
            &oracle_reader,
            config.outer_len,
            present_slots,
            coordinate_start,
            coordinate_tile,
        )?;
        let outer_leaves = backend.x4b_n4_inner_tile(
            &symbols,
            coordinate_tile,
            &ranks,
            &descriptors,
            u64::try_from(coordinate_start).map_err(|_| X4bCudaCommitErrorV4::Overflow)?,
            config.identity.cohort_id,
            config.identity.oracle_kind as u8,
            config.identity.fold_round,
        )?;
        write_digests(&mut leaves_writer, &outer_leaves)?;
        let symbol_bytes = u64::try_from(symbols.len())
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(SYMBOL_BYTES)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        let metadata_bytes = u64::try_from(ranks.len() * 2 + descriptors.len() * 32)
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?;
        let output_bytes = u64::try_from(outer_leaves.len())
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(DIGEST_BYTES)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        record_file_bytes_v4(temporary_files, output_bytes)?;
        metrics.persisted_oracle_bytes_read_for_n4 = metrics
            .persisted_oracle_bytes_read_for_n4
            .checked_add(symbol_bytes)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.expected_h2d_bytes = metrics
            .expected_h2d_bytes
            .checked_add(symbol_bytes)
            .and_then(|value| value.checked_add(metadata_bytes))
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.expected_d2h_bytes = metrics
            .expected_d2h_bytes
            .checked_add(output_bytes)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.staging_bytes_written = metrics
            .staging_bytes_written
            .checked_add(output_bytes)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.inner_tile_calls += 1;
    }
    // The canonical oracle remains durable, so discard the sequential N4
    // read footprint explicitly instead of relying on deletion (as the
    // response-local staging files can).  The earlier advice covers the
    // write pass; this second, separately counted advice covers the read.
    advise_dontneed(&oracle_reader, metrics.persisted_oracle_bytes_read_for_n4)?;
    metrics.page_cache_dontneed_bytes = metrics
        .page_cache_dontneed_bytes
        .checked_add(metrics.persisted_oracle_bytes_read_for_n4)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.page_cache_advice_calls += 1;
    drop(oracle_reader);
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::OracleRereadN4Inner,
        false,
        base_context,
        sealed_ownership,
        *temporary_files,
    );
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        true,
        X4LifecycleContextV4 { segment_index: 1, ..base_context },
        sealed_ownership,
        *temporary_files,
    );
    leaves_writer.flush()?;
    leaves_writer.get_ref().sync_data()?;
    metrics.fsync_count =
        metrics.fsync_count.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let leaves_bytes = u64::try_from(config.outer_len)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    advise_dontneed(leaves_writer.get_ref(), leaves_bytes)?;
    metrics.page_cache_dontneed_bytes = metrics
        .page_cache_dontneed_bytes
        .checked_add(leaves_bytes)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.page_cache_advice_calls += 1;
    drop(leaves_writer);
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        false,
        X4LifecycleContextV4 { segment_index: 1, ..base_context },
        sealed_ownership,
        *temporary_files,
    );

    let outer_depth = config.outer_len.ilog2() as u8;
    let mut retained_levels = vec![None; usize::from(outer_depth)];
    let mut current_path = leaves_path;
    let mut current_count = config.outer_len;
    let mut level = 1u8;
    let mut root = [0u8; 32];
    metrics.peak_live_staging_bytes = (config.outer_len as u64)
        .checked_mul(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    while current_count > 1 {
        let level_context = X4LifecycleContextV4 {
            outer_level: Some(level),
            segment_index: u32::from(level),
            ..base_context
        };
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::N4OuterLevels,
            true,
            level_context,
            sealed_ownership,
            *temporary_files,
        );
        let parent_count = current_count / 2;
        let parent_tile = x4b_outer_tile_parents_v4(parent_count)?;
        let outer_tile_bytes = u64::try_from(parent_tile)
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(3 * DIGEST_BYTES)
            .and_then(|value| value.checked_add(KEY_BYTES))
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.maximum_n4_tile_bytes = metrics.maximum_n4_tile_bytes.max(outer_tile_bytes);
        let next_path = paths.staging_directory.join(format!("{prefix}-outer-{level}.bin"));
        let next_file = staging.create(&next_path)?;
        record_file_created_v4(temporary_files, &mut metrics)?;
        let mut next_writer = BufWriter::with_capacity(8 * 1024 * 1024, next_file);
        let current_reader = OpenOptions::new().read(true).open(&current_path)?;
        let mut retained =
            (level > cache_policy.bottom_levels_omitted).then(|| Vec::with_capacity(parent_count));
        for node_start in (0..parent_count).step_by(parent_tile) {
            let children = read_digest_range(&current_reader, 2 * node_start, 2 * parent_tile)?;
            let parents = backend.x4b_n4_outer_nodes(
                &children,
                u64::try_from(node_start).map_err(|_| X4bCudaCommitErrorV4::Overflow)?,
                config.identity.cohort_id,
                config.identity.oracle_kind as u8,
                config.identity.fold_round,
                level,
            )?;
            write_digests(&mut next_writer, &parents)?;
            if let Some(retained) = &mut retained {
                retained.extend_from_slice(&parents);
            }
            root = *parents.last().ok_or(X4bCudaCommitErrorV4::Invalid("empty outer tile"))?;
            let input_bytes = u64::try_from(children.len())
                .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
                .checked_mul(DIGEST_BYTES)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            let output_bytes = u64::try_from(parents.len())
                .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
                .checked_mul(DIGEST_BYTES)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            record_file_bytes_v4(temporary_files, output_bytes)?;
            metrics.staging_bytes_read = metrics
                .staging_bytes_read
                .checked_add(input_bytes)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            metrics.staging_bytes_written = metrics
                .staging_bytes_written
                .checked_add(output_bytes)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            metrics.expected_h2d_bytes = metrics
                .expected_h2d_bytes
                .checked_add(input_bytes)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            metrics.expected_d2h_bytes = metrics
                .expected_d2h_bytes
                .checked_add(output_bytes)
                .ok_or(X4bCudaCommitErrorV4::Overflow)?;
            metrics.outer_tile_calls += 1;
        }
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::N4OuterLevels,
            false,
            level_context,
            sealed_ownership,
            *temporary_files,
        );
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::FlushSyncData,
            true,
            X4LifecycleContextV4 { segment_index: u32::from(level) + 1, ..level_context },
            sealed_ownership,
            *temporary_files,
        );
        next_writer.flush()?;
        next_writer.get_ref().sync_data()?;
        metrics.fsync_count =
            metrics.fsync_count.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
        let next_bytes = u64::try_from(parent_count)
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(DIGEST_BYTES)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        advise_dontneed(next_writer.get_ref(), next_bytes)?;
        metrics.page_cache_dontneed_bytes = metrics
            .page_cache_dontneed_bytes
            .checked_add(next_bytes)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.page_cache_advice_calls += 1;
        drop(next_writer);
        drop(current_reader);
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::FlushSyncData,
            false,
            X4LifecycleContextV4 { segment_index: u32::from(level) + 1, ..level_context },
            sealed_ownership,
            *temporary_files,
        );
        let current_bytes = u64::try_from(current_count)
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(DIGEST_BYTES)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        metrics.peak_live_staging_bytes =
            metrics.peak_live_staging_bytes.max(current_bytes + next_bytes);
        retained_levels[usize::from(level - 1)] = retained;
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::FileCleanup,
            true,
            level_context,
            sealed_ownership,
            *temporary_files,
        );
        staging.remove(&current_path)?;
        record_file_deleted_v4(temporary_files, &mut metrics, current_bytes)?;
        observe_seal_v4(
            backend,
            observer,
            X4LifecyclePhaseV4::FileCleanup,
            false,
            level_context,
            sealed_ownership,
            *temporary_files,
        );
        current_path = next_path;
        current_count = parent_count;
        level += 1;
    }
    let final_staging_bytes = u64::try_from(current_count)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let final_cleanup_context = X4LifecycleContextV4 {
        outer_level: Some(level.saturating_sub(1)),
        segment_index: u32::from(level),
        ..base_context
    };
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FileCleanup,
        true,
        final_cleanup_context,
        sealed_ownership,
        *temporary_files,
    );
    staging.remove(&current_path)?;
    record_file_deleted_v4(temporary_files, &mut metrics, final_staging_bytes)?;
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FileCleanup,
        false,
        final_cleanup_context,
        sealed_ownership,
        *temporary_files,
    );

    let outer_cache =
        DenseOuterNodeCacheV4::from_levels(config.outer_len, cache_policy, retained_levels, root)?;
    metrics.retained_outer_cache_bytes = outer_cache.retained_bytes()?;
    let root_context = X4LifecycleContextV4 {
        outer_level: Some(outer_depth),
        segment_index: u32::from(outer_depth) + 1,
        ..base_context
    };
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::N4OuterLevels,
        true,
        root_context,
        sealed_ownership,
        *temporary_files,
    );
    let root_file = artifacts.create(&paths.root)?;
    record_file_created_v4(temporary_files, &mut metrics)?;
    let mut root_writer = BufWriter::new(root_file);
    root_writer.write_all(&root)?;
    record_file_bytes_v4(temporary_files, DIGEST_BYTES)?;
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::N4OuterLevels,
        false,
        root_context,
        sealed_ownership,
        *temporary_files,
    );
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        true,
        root_context,
        sealed_ownership,
        *temporary_files,
    );
    root_writer.flush()?;
    root_writer.get_ref().sync_data()?;
    metrics.fsync_count =
        metrics.fsync_count.checked_add(1).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    advise_dontneed(root_writer.get_ref(), DIGEST_BYTES)?;
    metrics.page_cache_dontneed_bytes = metrics
        .page_cache_dontneed_bytes
        .checked_add(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    metrics.page_cache_advice_calls += 1;
    metrics.root_bytes_persisted = DIGEST_BYTES;
    drop(root_writer);
    observe_seal_v4(
        backend,
        observer,
        X4LifecyclePhaseV4::FlushSyncData,
        false,
        root_context,
        sealed_ownership,
        *temporary_files,
    );

    let expected_coefficient_bytes = u64::try_from(present_slots)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(coefficient_len as u64)
        .and_then(|value| value.checked_mul(SYMBOL_BYTES))
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let expected_oracle_bytes = u64::try_from(present_slots)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(config.outer_len as u64)
        .and_then(|value| value.checked_mul(SYMBOL_BYTES))
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    if metrics.coefficient_bytes_persisted != expected_coefficient_bytes
        || metrics.oracle_bytes_persisted != expected_oracle_bytes
        || fs::metadata(&paths.coefficients)?.len() != expected_coefficient_bytes
        || fs::metadata(&paths.oracle)?.len() != expected_oracle_bytes
        || fs::metadata(&paths.root)?.len() != DIGEST_BYTES
        || metrics.persisted_oracle_bytes_read_for_n4 != expected_oracle_bytes
        || metrics.maximum_n4_tile_bytes > X4B_N4_TILE_BYTE_CEILING_V4
        || metrics.files_created.checked_sub(metrics.files_deleted) != Some(3)
        || !temporary_files.is_consistent()
    {
        return Err(X4bCudaCommitErrorV4::Invalid("artifact/accounting reconciliation"));
    }
    let commitment = ModelGlobalCohortCommitmentV4 { root, config };
    artifacts.retain();
    Ok(X4bCudaCohortArtifactsV4 { commitment, outer_cache, paths, metrics })
}

fn n4_inner_logical_tile_bytes(
    structural_slots: usize,
    present_slots: usize,
    coordinates: usize,
) -> Result<u64, X4bCudaCommitErrorV4> {
    let structural = u64::try_from(structural_slots).map_err(|_| X4bCudaCommitErrorV4::Overflow)?;
    let present = u64::try_from(present_slots).map_err(|_| X4bCudaCommitErrorV4::Overflow)?;
    let coordinates = u64::try_from(coordinates).map_err(|_| X4bCudaCommitErrorV4::Overflow)?;
    let second_hash_bytes = if structural_slots == 1 {
        DIGEST_BYTES
    } else {
        structural
            .checked_mul(coordinates)
            .and_then(|value| value.checked_mul(DIGEST_BYTES / 2))
            .ok_or(X4bCudaCommitErrorV4::Overflow)?
    };
    present
        .checked_mul(coordinates)
        .and_then(|value| value.checked_mul(SYMBOL_BYTES))
        .and_then(|value| value.checked_add(structural.checked_mul(2 + DIGEST_BYTES)?))
        .and_then(|value| {
            value.checked_add(structural.checked_mul(coordinates)?.checked_mul(DIGEST_BYTES)?)
        })
        .and_then(|value| value.checked_add(second_hash_bytes))
        .and_then(|value| value.checked_add(coordinates.checked_mul(DIGEST_BYTES)?))
        .and_then(|value| value.checked_add(KEY_BYTES))
        .ok_or(X4bCudaCommitErrorV4::Overflow)
}

fn write_symbols(writer: &mut BufWriter<File>, symbols: &[Fp2]) -> Result<(), io::Error> {
    write_canonical_fp2_slice_v4(writer, symbols)
}

fn advise_dontneed(file: &File, bytes: u64) -> Result<(), io::Error> {
    if bytes > i64::MAX as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "X4b fadvise length overflow"));
    }
    unsafe extern "C" {
        fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32;
    }
    const POSIX_FADV_DONTNEED: i32 = 4;
    // SAFETY: `file` owns a live descriptor for the duration of the call and
    // the checked byte length fits the platform `off_t` used here.
    let status = unsafe { posix_fadvise(file.as_raw_fd(), 0, bytes as i64, POSIX_FADV_DONTNEED) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

fn write_digests(writer: &mut BufWriter<File>, digests: &[Digest]) -> Result<(), io::Error> {
    for digest in digests {
        writer.write_all(digest)?;
    }
    Ok(())
}

fn read_exact_at(file: &File, mut offset: u64, mut output: &mut [u8]) -> Result<(), io::Error> {
    while !output.is_empty() {
        let read = file.read_at(output, offset)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "X4b staging EOF"));
        }
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| io::ErrorKind::InvalidData)?)
            .ok_or(io::ErrorKind::InvalidData)?;
        output = &mut output[read..];
    }
    Ok(())
}

fn read_oracle_tile(
    file: &File,
    outer_len: usize,
    present_slots: usize,
    coordinate_start: usize,
    coordinates: usize,
) -> Result<Vec<Fp2>, X4bCudaCommitErrorV4> {
    let bytes_per_slot =
        coordinates.checked_mul(SYMBOL_BYTES as usize).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let mut encoded = vec![0u8; bytes_per_slot];
    let mut output = Vec::with_capacity(
        present_slots.checked_mul(coordinates).ok_or(X4bCudaCommitErrorV4::Overflow)?,
    );
    for rank in 0..present_slots {
        let symbol_offset = rank
            .checked_mul(outer_len)
            .and_then(|value| value.checked_add(coordinate_start))
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        let byte_offset = u64::try_from(symbol_offset)
            .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
            .checked_mul(SYMBOL_BYTES)
            .ok_or(X4bCudaCommitErrorV4::Overflow)?;
        read_exact_at(file, byte_offset, &mut encoded)?;
        for chunk in encoded.chunks_exact(16) {
            let c0 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
            if c0 >= P || c1 >= P {
                return Err(X4bCudaCommitErrorV4::Invalid("non-canonical persisted symbol"));
            }
            output.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
        }
    }
    Ok(output)
}

fn read_digest_range(
    file: &File,
    start: usize,
    count: usize,
) -> Result<Vec<Digest>, X4bCudaCommitErrorV4> {
    let byte_count = count.checked_mul(32).ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let byte_start = u64::try_from(start)
        .map_err(|_| X4bCudaCommitErrorV4::Overflow)?
        .checked_mul(DIGEST_BYTES)
        .ok_or(X4bCudaCommitErrorV4::Overflow)?;
    let mut bytes = vec![0u8; byte_count];
    read_exact_at(file, byte_start, &mut bytes)?;
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("32-byte digest chunk"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "cuda")]
    use crate::x4::{
        encode_rate_eighth, CohortIdentityV4, CohortTreeV4, OracleKindV4, OuterCachePolicyV4,
        MANIFEST_LEAF_HASH_CONTEXT_V4, MANIFEST_NODE_HASH_CONTEXT_V4, PCS_LEAF_HASH_CONTEXT_V4,
        PCS_NODE_HASH_CONTEXT_V4,
    };

    #[test]
    fn tile_planner_is_power_of_two_and_enforces_the_frozen_ceiling() {
        for (structural, present) in [(1, 1), (2, 1), (16, 13), (64, 49)] {
            let coordinates = x4b_inner_tile_coordinates_v4(structural, present, 1 << 30).unwrap();
            assert!(coordinates.is_power_of_two());
            assert!(
                n4_inner_logical_tile_bytes(structural, present, coordinates).unwrap()
                    <= X4B_N4_TILE_BYTE_CEILING_V4
            );
            if coordinates < 1 << 30 {
                assert!(
                    n4_inner_logical_tile_bytes(structural, present, 2 * coordinates).unwrap()
                        > X4B_N4_TILE_BYTE_CEILING_V4
                );
            }
        }
        let parents = x4b_outer_tile_parents_v4(1 << 29).unwrap();
        assert!(parents.is_power_of_two());
        assert!((parents as u64) * 96 + KEY_BYTES <= X4B_N4_TILE_BYTE_CEILING_V4);
        assert!((parents as u64) * 2 * 96 + KEY_BYTES > X4B_N4_TILE_BYTE_CEILING_V4);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_ntt_and_n4_roots_match_cpu_for_all_structural_shapes() {
        let mut gpu = match Backend::cuda_hybrid() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var_os("VOLTA_REQUIRE_CUDA").is_some() => {
                panic!("VOLTA_REQUIRE_CUDA set but the CUDA backend failed to initialize: {error}")
            }
            Err(_) => return,
        };
        let payload = (0..104u8).map(|value| value.wrapping_mul(37)).collect::<Vec<_>>();
        let observed = gpu.x4b_context_probe(&payload).unwrap();
        for (index, context) in [
            PCS_LEAF_HASH_CONTEXT_V4,
            PCS_NODE_HASH_CONTEXT_V4,
            MANIFEST_LEAF_HASH_CONTEXT_V4,
            MANIFEST_NODE_HASH_CONTEXT_V4,
        ]
        .into_iter()
        .enumerate()
        {
            let mut hasher = blake3::Hasher::new_derive_key(context);
            hasher.update(&payload);
            assert_eq!(observed[index], *hasher.finalize().as_bytes(), "context {context}");
        }
        let base = std::env::temp_dir().join(format!(
            "volta-x4b-cuda-test-{}-{}",
            std::process::id(),
            STAGING_NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&base).unwrap();
        for (case, structural, present, kind, round) in [
            (0u32, 1usize, 1usize, OracleKindV4::WeightExtension, 0u8),
            (1, 2, 1, OracleKindV4::Auxiliary, 0),
            (2, 16, 13, OracleKindV4::WeightExtension, 0),
            (3, 64, 49, OracleKindV4::Auxiliary, 0),
            (4, 1, 1, OracleKindV4::GlobalFoldAggregate, 3),
        ] {
            let config = CohortVerifierConfigV4 {
                identity: CohortIdentityV4 {
                    cohort_id: 0xB400_0000 + case,
                    oracle_kind: kind,
                    fold_round: round,
                },
                slot_descriptors: (0..structural)
                    .map(|slot| (slot < present).then(|| [slot as u8 + 1; 32]))
                    .collect(),
                outer_len: 32,
                expected_symbol_count: 1,
            };
            let coefficients = (0..structural)
                .map(|slot| {
                    (slot < present).then(|| {
                        (0..4)
                            .map(|index| {
                                Fp2::new(
                                    Fp::new((slot * 257 + index * 17 + 3) as u64),
                                    Fp::new((slot * 19 + index * index + 5) as u64),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            let codewords = coefficients
                .iter()
                .map(|values| values.as_ref().map(|values| encode_rate_eighth(values).unwrap()))
                .collect::<Vec<_>>();
            let cpu = CohortTreeV4::build_flat(config.clone(), codewords).unwrap();
            let case_dir = base.join(format!("case-{case}"));
            fs::create_dir_all(&case_dir).unwrap();
            let gpu_artifacts = commit_cohort_cuda_v4(
                &mut gpu,
                config,
                &coefficients,
                X4bCudaCohortPathsV4 {
                    coefficients: case_dir.join("coefficients.bin"),
                    oracle: case_dir.join("oracle.bin"),
                    root: case_dir.join("root.bin"),
                    staging_directory: case_dir.join("staging"),
                },
                OuterCachePolicyV4::FULL,
            )
            .unwrap();
            assert_eq!(gpu_artifacts.commitment.root, cpu.root(), "case {case}");
            assert_eq!(gpu_artifacts.outer_cache.root(), cpu.root());
        }
        fs::remove_dir_all(base).unwrap();
    }
}
