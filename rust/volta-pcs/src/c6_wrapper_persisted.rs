//! Create-new persisted opening owners for the C6 wrapper PCS.
//!
//! The first checkpoint is deliberately scaled and consumes the resident
//! reference owner. Production geometry has a separate CUDA constructor and
//! cannot enter through this module's reference adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use volta_accel::{Backend, BackendKind};
use volta_field::{Fp, Fp2, P};

use crate::c6_wrapper_pcs::{
    c6_wrapper_commit_config, compile_c6_wrapper_slot_coefficients, production_c6_wrapper_specs,
    validate_claim, C6CacheStateDescriptors, C6CommittedWrapperCohort, C6WrapperCommitment,
    C6WrapperDigest, C6WrapperOpeningClaim, C6WrapperPcsError, C6WrapperSlotWitness,
    CombinedCohort, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
    C6_WRAPPER_REPETITIONS,
};
use crate::x4::cuda_v4::{commit_cohort_cuda_v4, X4bCudaCohortPathsV4, X4bCudaCommitMetricsV4};
use crate::x4::frame_v4::{FoldRoundOpeningV4, InitialOpeningGroupV4, OracleKindV4};
use crate::x4::merkle_v4::{
    CohortTreeV4, CohortVerifierConfigV4, DenseOuterNodeCacheV4, OuterCachePolicyV4,
};
use crate::x4::ntt::evaluate_multilinear_coefficients;
use crate::x4::persisted_v4::{
    read_persisted_coefficients_v4, write_canonical_fp2_slice_v4, PersistedCohortOpeningV4,
    PersistedOpeningTrafficV4, PersistedOracleBindingV4,
};

const MANIFEST_MAGIC: [u8; 8] = *b"C6WSP1\0\0";
const MANIFEST_VERSION: u16 = 2;
const MANIFEST_DOMAIN: &str = "volta-zk/c6/wrapper-persisted-manifest/v2";
const FOLD_MANIFEST_MAGIC: [u8; 8] = *b"C6WFP1\0\0";
const FOLD_MANIFEST_VERSION: u16 = 1;
const FOLD_MANIFEST_DOMAIN: &str = "volta-zk/c6/wrapper-persisted-fold-manifest/v1";
#[allow(dead_code)]
const LINK_FOLD_MANIFEST_MAGIC: [u8; 8] = *b"C6LFP1\0\0";
#[allow(dead_code)]
const LINK_FOLD_MANIFEST_VERSION: u16 = 1;
#[allow(dead_code)]
const LINK_FOLD_MANIFEST_DOMAIN: &str = "volta-zk/c6/link-persisted-fold-manifest/v1";
const LINK_FOLD_SOURCE_DOMAIN: &str = "volta-zk/c6/link-persisted-fold-source/v1";
#[allow(dead_code)]
const LINK_FOLD_CHUNK_SYMBOLS: usize = 16 * 1024;
pub const C6_PRODUCTION_WRAPPER_CACHE_OMITTED_LEVELS: u8 = 8;

type Result<T> = std::result::Result<T, C6WrapperPcsError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6PersistedWrapperMetrics {
    pub coefficient_bytes_written: u64,
    pub oracle_bytes_written: u64,
    pub semantic_cache_bytes_written: u64,
    pub files_created: u64,
    pub fsync_count: u64,
    pub resident_codeword_copies_after_seal: u64,
}

impl C6PersistedWrapperMetrics {
    pub fn include(&mut self, next: Self) -> Result<()> {
        macro_rules! add {
            ($field:ident) => {
                self.$field = self.$field.checked_add(next.$field).ok_or_else(|| {
                    C6WrapperPcsError::external_message("C6 persisted-wrapper metric overflow")
                })?;
            };
        }
        add!(coefficient_bytes_written);
        add!(oracle_bytes_written);
        add!(semantic_cache_bytes_written);
        add!(files_created);
        add!(fsync_count);
        add!(resident_codeword_copies_after_seal);
        Ok(())
    }
}

#[derive(Debug)]
pub struct C6PersistedWrapperCohort {
    commitment: C6WrapperCommitment,
    session_digest: C6WrapperDigest,
    oracle_ordinal: u64,
    directory: PathBuf,
    semantic_cache_path: Option<PathBuf>,
    opening: PersistedCohortOpeningV4<DenseOuterNodeCacheV4>,
    metrics: C6PersistedWrapperMetrics,
}

#[derive(Debug)]
pub struct C6PersistedCacheSemanticReader {
    file: File,
    payload_len: usize,
    statement_digest: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    root: C6WrapperDigest,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct C6PersistedCoefficientSlotReader {
    file: File,
    slot_count: u16,
    coefficient_len: usize,
    statement_digest: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    root: C6WrapperDigest,
}

#[allow(dead_code)]
impl C6PersistedCoefficientSlotReader {
    pub(crate) fn coefficient_len(&self) -> usize {
        self.coefficient_len
    }

    pub(crate) fn binding(&self) -> (C6WrapperDigest, C6WrapperDigest, C6WrapperDigest) {
        (self.statement_digest, self.session_digest, self.root)
    }

    pub(crate) fn read_slot_range(
        &self,
        slot: u16,
        start: usize,
        count: usize,
    ) -> Result<(Vec<Fp2>, u64)> {
        if slot >= self.slot_count
            || count == 0
            || start.checked_add(count).is_none_or(|end| end > self.coefficient_len)
        {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted coefficient read range mismatch",
            ));
        }
        let symbol_start = usize::from(slot)
            .checked_mul(self.coefficient_len)
            .and_then(|base| base.checked_add(start))
            .ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 persisted coefficient offset overflow")
            })?;
        read_canonical_fp2_range(&self.file, symbol_start, count)
    }

    pub(crate) fn open_link_fold_owner(
        &self,
        spill_root: impl AsRef<Path>,
        repetition: u8,
        cohort_id: u32,
        slot: u16,
        target_digest: C6WrapperDigest,
    ) -> Result<(C6PersistedLinkFoldOwner, C6PersistedLinkFoldMetrics)> {
        if slot >= self.slot_count || target_digest == [0; 32] {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted link fold source binding mismatch",
            ));
        }
        let symbol_start =
            usize::from(slot).checked_mul(self.coefficient_len).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 persisted link source offset overflow")
            })?;
        let directory = spill_root
            .as_ref()
            .join(format!("link-repetition-{repetition}-cohort-{cohort_id}-slot-{slot}"));
        fs::create_dir(&directory)
            .map_err(|error| C6WrapperPcsError::external("create C6 link fold directory", error))?;
        File::open(spill_root.as_ref())
            .and_then(|root| root.sync_all())
            .map_err(|error| C6WrapperPcsError::external("fsync C6 link fold root", error))?;
        let binding = C6PersistedLinkFoldBinding {
            statement_digest: self.statement_digest,
            session_digest: self.session_digest,
            root: self.root,
            repetition,
            cohort_id,
            slot,
            round: 0,
            target_digest,
        };
        let state_digest = link_fold_source_digest(&binding, self.coefficient_len)?;
        let owner = C6PersistedLinkFoldOwner {
            binding,
            coefficient_len: self.coefficient_len,
            state_digest,
            directory,
            storage: C6PersistedLinkFoldStorage::Cohort {
                file: self.file.try_clone().map_err(|error| {
                    C6WrapperPcsError::external("clone C6 link coefficient source", error)
                })?,
                symbol_start,
            },
        };
        Ok((
            owner,
            C6PersistedLinkFoldMetrics {
                directories_created: 1,
                fsync_count: 1,
                ..Default::default()
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct C6PersistedLinkFoldBinding {
    pub(crate) statement_digest: C6WrapperDigest,
    pub(crate) session_digest: C6WrapperDigest,
    pub(crate) root: C6WrapperDigest,
    pub(crate) repetition: u8,
    pub(crate) cohort_id: u32,
    pub(crate) slot: u16,
    pub(crate) round: u16,
    pub(crate) target_digest: C6WrapperDigest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct C6PersistedLinkFoldMetrics {
    pub(crate) coefficient_bytes_read: u64,
    pub(crate) coefficient_bytes_written: u64,
    pub(crate) manifest_bytes_written: u64,
    pub(crate) files_created: u64,
    pub(crate) files_deleted_after_successor_durable: u64,
    pub(crate) directories_created: u64,
    pub(crate) fsync_count: u64,
    pub(crate) current_live_spill_bytes: u64,
    pub(crate) peak_live_spill_bytes: u64,
}

impl C6PersistedLinkFoldMetrics {
    #[allow(dead_code)]
    fn add_live(&mut self, bytes: u64) -> Result<()> {
        self.current_live_spill_bytes =
            self.current_live_spill_bytes.checked_add(bytes).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 persisted link live spill overflow")
            })?;
        self.peak_live_spill_bytes = self.peak_live_spill_bytes.max(self.current_live_spill_bytes);
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_live(&mut self, bytes: u64) -> Result<()> {
        self.current_live_spill_bytes =
            self.current_live_spill_bytes.checked_sub(bytes).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 persisted link live spill underflow")
            })?;
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum C6PersistedLinkFoldStorage {
    Cohort { file: File, symbol_start: usize },
    Owned { file: File, coefficient_path: PathBuf, manifest_path: PathBuf, live_bytes: u64 },
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct C6PersistedLinkFoldOwner {
    binding: C6PersistedLinkFoldBinding,
    coefficient_len: usize,
    state_digest: C6WrapperDigest,
    directory: PathBuf,
    storage: C6PersistedLinkFoldStorage,
}

#[allow(dead_code)]
impl C6PersistedLinkFoldOwner {
    pub(crate) fn binding(&self) -> C6PersistedLinkFoldBinding {
        self.binding
    }

    pub(crate) fn coefficient_len(&self) -> usize {
        self.coefficient_len
    }

    pub(crate) fn read_range(&self, start: usize, count: usize) -> Result<(Vec<Fp2>, u64)> {
        if count == 0 || start.checked_add(count).is_none_or(|end| end > self.coefficient_len) {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted link coefficient read range mismatch",
            ));
        }
        match &self.storage {
            C6PersistedLinkFoldStorage::Cohort { file, symbol_start } => {
                let absolute = symbol_start.checked_add(start).ok_or_else(|| {
                    C6WrapperPcsError::external_message("C6 persisted link read offset overflow")
                })?;
                read_canonical_fp2_range(file, absolute, count)
            }
            C6PersistedLinkFoldStorage::Owned { file, .. } => {
                read_canonical_fp2_range(file, start, count)
            }
        }
    }

    pub(crate) fn bind_create_new(
        self,
        challenge: Fp2,
        next_round: u16,
        metrics: &mut C6PersistedLinkFoldMetrics,
    ) -> Result<Self> {
        if self.coefficient_len < 2
            || self.coefficient_len % 2 != 0
            || next_round != self.binding.round.checked_add(1).unwrap_or_default()
        {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted link successor round mismatch",
            ));
        }
        let next_len = self.coefficient_len / 2;
        let coefficient_path = self.directory.join(format!("round-{next_round:02}.fp2"));
        let manifest_path = self.directory.join(format!("round-{next_round:02}.c6lfp1"));
        let file =
            OpenOptions::new().create_new(true).write(true).open(&coefficient_path).map_err(
                |error| C6WrapperPcsError::external("create C6 link folded coefficients", error),
            )?;
        let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
        let mut read_symbols = 0usize;
        while read_symbols < self.coefficient_len {
            let count = (self.coefficient_len - read_symbols).min(LINK_FOLD_CHUNK_SYMBOLS);
            let count = count - count % 2;
            let (source, bytes_read) = self.read_range(read_symbols, count)?;
            metrics.coefficient_bytes_read =
                metrics.coefficient_bytes_read.checked_add(bytes_read).ok_or_else(|| {
                    C6WrapperPcsError::external_message("C6 link coefficient read overflow")
                })?;
            let folded = source
                .chunks_exact(2)
                .map(|pair| pair[0] + challenge * pair[1])
                .collect::<Vec<_>>();
            write_canonical_fp2_slice_v4(&mut writer, &folded).map_err(|error| {
                C6WrapperPcsError::external("write C6 link folded coefficients", error)
            })?;
            read_symbols += count;
        }
        writer.flush().map_err(|error| {
            C6WrapperPcsError::external("flush C6 link folded coefficients", error)
        })?;
        writer.get_ref().sync_all().map_err(|error| {
            C6WrapperPcsError::external("fsync C6 link folded coefficients", error)
        })?;
        metrics.fsync_count = metrics
            .fsync_count
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link fsync metric overflow"))?;
        let coefficient_bytes =
            u64::try_from(next_len).ok().and_then(|symbols| symbols.checked_mul(16)).ok_or_else(
                || C6WrapperPcsError::external_message("C6 link coefficient byte overflow"),
            )?;
        metrics.coefficient_bytes_written =
            metrics.coefficient_bytes_written.checked_add(coefficient_bytes).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 link coefficient write overflow")
            })?;
        metrics.files_created = metrics
            .files_created
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link file metric overflow"))?;

        let mut next_binding = self.binding;
        next_binding.round = next_round;
        let manifest = encode_link_fold_manifest(
            &next_binding,
            next_len,
            self.state_digest,
            challenge,
            coefficient_bytes,
        )?;
        write_bytes_create_new(&manifest_path, &manifest)?;
        metrics.manifest_bytes_written = metrics
            .manifest_bytes_written
            .checked_add(u64::try_from(manifest.len()).unwrap())
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link manifest overflow"))?;
        metrics.files_created = metrics
            .files_created
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link file metric overflow"))?;
        metrics.fsync_count = metrics
            .fsync_count
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link fsync metric overflow"))?;
        File::open(&self.directory).and_then(|directory| directory.sync_all()).map_err(
            |error| C6WrapperPcsError::external("fsync durable C6 link successor", error),
        )?;
        metrics.fsync_count = metrics
            .fsync_count
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link fsync metric overflow"))?;
        let live_bytes = coefficient_bytes
            .checked_add(manifest.len() as u64)
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 link live byte overflow"))?;
        metrics.add_live(live_bytes)?;

        if let C6PersistedLinkFoldStorage::Owned {
            coefficient_path: predecessor_coefficients,
            manifest_path: predecessor_manifest,
            live_bytes: predecessor_live_bytes,
            ..
        } = &self.storage
        {
            fs::remove_file(predecessor_coefficients).map_err(|error| {
                C6WrapperPcsError::external("release C6 link predecessor coefficients", error)
            })?;
            fs::remove_file(predecessor_manifest).map_err(|error| {
                C6WrapperPcsError::external("release C6 link predecessor manifest", error)
            })?;
            File::open(&self.directory).and_then(|directory| directory.sync_all()).map_err(
                |error| C6WrapperPcsError::external("fsync C6 link predecessor release", error),
            )?;
            metrics.files_deleted_after_successor_durable =
                metrics.files_deleted_after_successor_durable.checked_add(2).ok_or_else(|| {
                    C6WrapperPcsError::external_message("C6 link deleted-file overflow")
                })?;
            metrics.fsync_count = metrics.fsync_count.checked_add(1).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 link fsync metric overflow")
            })?;
            metrics.remove_live(*predecessor_live_bytes)?;
        }
        let state_digest = manifest[manifest.len() - 32..].try_into().unwrap();
        let file = OpenOptions::new().read(true).open(&coefficient_path).map_err(|error| {
            C6WrapperPcsError::external("open durable C6 link successor", error)
        })?;
        if file
            .metadata()
            .map_err(|error| C6WrapperPcsError::external("stat C6 link successor", error))?
            .len()
            != coefficient_bytes
        {
            return Err(C6WrapperPcsError::external_message("C6 link successor length mismatch"));
        }
        Ok(Self {
            binding: next_binding,
            coefficient_len: next_len,
            state_digest,
            directory: self.directory,
            storage: C6PersistedLinkFoldStorage::Owned {
                file,
                coefficient_path,
                manifest_path,
                live_bytes,
            },
        })
    }

    pub(crate) fn release(self, metrics: &mut C6PersistedLinkFoldMetrics) -> Result<()> {
        if let C6PersistedLinkFoldStorage::Owned {
            coefficient_path,
            manifest_path,
            live_bytes,
            ..
        } = self.storage
        {
            fs::remove_file(coefficient_path).map_err(|error| {
                C6WrapperPcsError::external("release terminal C6 link coefficients", error)
            })?;
            fs::remove_file(manifest_path).map_err(|error| {
                C6WrapperPcsError::external("release terminal C6 link manifest", error)
            })?;
            File::open(&self.directory).and_then(|directory| directory.sync_all()).map_err(
                |error| C6WrapperPcsError::external("fsync terminal C6 link release", error),
            )?;
            metrics.files_deleted_after_successor_durable =
                metrics.files_deleted_after_successor_durable.checked_add(2).ok_or_else(|| {
                    C6WrapperPcsError::external_message("C6 link deleted-file overflow")
                })?;
            metrics.fsync_count = metrics.fsync_count.checked_add(1).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 link fsync metric overflow")
            })?;
            metrics.remove_live(live_bytes)?;
        }
        Ok(())
    }
}

impl C6PersistedCacheSemanticReader {
    pub fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub fn binding(&self) -> (C6WrapperDigest, C6WrapperDigest, C6WrapperDigest) {
        (self.statement_digest, self.session_digest, self.root)
    }

    pub fn read_slot_range(&self, slot: u8, start: usize, count: usize) -> Result<(Vec<Fp2>, u64)> {
        if slot >= 2
            || count == 0
            || start.checked_add(count).is_none_or(|end| end > self.payload_len)
        {
            return Err(C6WrapperPcsError::external_message(
                "C6 semantic cache read range mismatch",
            ));
        }
        let symbol_start = usize::from(slot)
            .checked_mul(self.payload_len)
            .and_then(|base| base.checked_add(start))
            .ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 semantic cache offset overflow")
            })?;
        let byte_offset =
            u64::try_from(symbol_start).ok().and_then(|value| value.checked_mul(16)).ok_or_else(
                || C6WrapperPcsError::external_message("C6 semantic cache offset overflow"),
            )?;
        let byte_count = count.checked_mul(16).ok_or_else(|| {
            C6WrapperPcsError::external_message("C6 semantic cache read overflow")
        })?;
        let mut encoded = vec![0u8; byte_count];
        let mut read = 0usize;
        while read < encoded.len() {
            let got = self
                .file
                .read_at(&mut encoded[read..], byte_offset + read as u64)
                .map_err(|error| C6WrapperPcsError::external("read C6 semantic cache", error))?;
            if got == 0 {
                return Err(C6WrapperPcsError::external_message("truncated C6 semantic cache"));
            }
            read += got;
        }
        let mut values = Vec::with_capacity(count);
        for chunk in encoded.chunks_exact(16) {
            let c0 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
            if c0 >= P || c1 >= P {
                return Err(C6WrapperPcsError::external_message(
                    "noncanonical C6 semantic cache field element",
                ));
            }
            values.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
        }
        Ok((
            values,
            u64::try_from(byte_count).map_err(|_| {
                C6WrapperPcsError::external_message("C6 semantic cache byte count overflow")
            })?,
        ))
    }
}

impl C6PersistedWrapperCohort {
    pub fn commitment(&self) -> &C6WrapperCommitment {
        &self.commitment
    }

    pub fn session_digest(&self) -> C6WrapperDigest {
        self.session_digest
    }

    pub fn oracle_ordinal(&self) -> u64 {
        self.oracle_ordinal
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn semantic_cache_path(&self) -> Option<&Path> {
        self.semantic_cache_path.as_deref()
    }

    pub fn open_semantic_cache(&self) -> Result<C6PersistedCacheSemanticReader> {
        let path = self.semantic_cache_path.as_ref().ok_or_else(|| {
            C6WrapperPcsError::external_message("C6 cohort has no semantic cache owner")
        })?;
        if !matches!(
            self.commitment.spec.cohort_id,
            C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID
        ) {
            return Err(C6WrapperPcsError::external_message(
                "non-cache C6 cohort has semantic cache owner",
            ));
        }
        let payload_len =
            1usize.checked_shl(u32::from(self.commitment.spec.payload_log2)).ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 semantic cache length overflow")
            })?;
        let expected_bytes = u64::try_from(payload_len)
            .ok()
            .and_then(|symbols| symbols.checked_mul(2))
            .and_then(|symbols| symbols.checked_mul(16))
            .ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 semantic cache bytes overflow")
            })?;
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|error| C6WrapperPcsError::external("open C6 semantic cache", error))?;
        if file
            .metadata()
            .map_err(|error| C6WrapperPcsError::external("stat C6 semantic cache", error))?
            .len()
            != expected_bytes
        {
            return Err(C6WrapperPcsError::external_message(
                "C6 semantic cache file length mismatch",
            ));
        }
        Ok(C6PersistedCacheSemanticReader {
            file,
            payload_len,
            statement_digest: self.commitment.statement_digest,
            session_digest: self.session_digest,
            root: self.commitment.root,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn open_coefficient_slots(&self) -> Result<C6PersistedCoefficientSlotReader> {
        let coefficient_len = self.commitment.config.outer_len / 8;
        let expected_bytes = u64::from(self.commitment.spec.slot_count)
            .checked_mul(u64::try_from(coefficient_len).map_err(|_| {
                C6WrapperPcsError::external_message("C6 coefficient length exceeds u64")
            })?)
            .and_then(|symbols| symbols.checked_mul(16))
            .ok_or_else(|| {
                C6WrapperPcsError::external_message("C6 persisted coefficient bytes overflow")
            })?;
        let file = OpenOptions::new()
            .read(true)
            .open(self.directory.join("coefficients.fp2"))
            .map_err(|error| C6WrapperPcsError::external("open C6 coefficients", error))?;
        if file
            .metadata()
            .map_err(|error| C6WrapperPcsError::external("stat C6 coefficients", error))?
            .len()
            != expected_bytes
        {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted coefficient file length mismatch",
            ));
        }
        Ok(C6PersistedCoefficientSlotReader {
            file,
            slot_count: self.commitment.spec.slot_count,
            coefficient_len,
            statement_digest: self.commitment.statement_digest,
            session_digest: self.session_digest,
            root: self.commitment.root,
        })
    }

    pub fn metrics(&self) -> C6PersistedWrapperMetrics {
        self.metrics
    }

    pub fn open_initial(
        &self,
        query_draws: &[u64],
    ) -> Result<(InitialOpeningGroupV4, PersistedOpeningTrafficV4)> {
        let touched = (0..self.commitment.spec.slot_count).collect::<Vec<_>>();
        self.opening
            .open_initial(query_draws, &touched)
            .map_err(|error| C6WrapperPcsError::external("C6 persisted initial opening", error))
    }

    pub(crate) fn combine(&self, claim: &C6WrapperOpeningClaim) -> Result<CombinedCohort> {
        let (coefficients, _) = self.combine_coefficients(claim)?;
        let slots = (0..self.commitment.spec.slot_count).collect::<Vec<_>>();
        let (codeword, _bytes_read) = self
            .opening
            .combine_slots(&slots, &claim.slot_weights)
            .map_err(|error| C6WrapperPcsError::external("combine C6 persisted oracle", error))?;
        Ok(CombinedCohort {
            outer_len: self.commitment.config.outer_len,
            coefficients,
            codeword,
            claimed_value: claim.value,
        })
    }

    pub(crate) fn combine_coefficients(
        &self,
        claim: &C6WrapperOpeningClaim,
    ) -> Result<(Vec<Fp2>, u64)> {
        validate_claim(&self.commitment, claim)?;
        let slots = (0..self.commitment.spec.slot_count).collect::<Vec<_>>();
        let coefficient_path = self.directory.join("coefficients.fp2");
        let coefficient_bytes = File::open(&coefficient_path)
            .and_then(|file| file.metadata())
            .map_err(|error| C6WrapperPcsError::external("stat C6 persisted coefficients", error))?
            .len();
        let coefficient_slots =
            read_persisted_coefficients_v4(&coefficient_path, &self.commitment.config).map_err(
                |error| C6WrapperPcsError::external("read C6 persisted coefficients", error),
            )?;
        let coefficient_len = self.commitment.config.outer_len / 8;
        let mut coefficients = vec![Fp2::ZERO; coefficient_len];
        for ((slot, weight), source) in
            slots.iter().zip(&claim.slot_weights).zip(coefficient_slots.iter())
        {
            let source = source.as_ref().ok_or_else(|| {
                C6WrapperPcsError::external_message("missing C6 persisted coefficient slot")
            })?;
            if usize::from(*slot) >= coefficient_slots.len() || source.len() != coefficient_len {
                return Err(C6WrapperPcsError::external_message(
                    "C6 persisted coefficient geometry changed",
                ));
            }
            for (output, value) in coefficients.iter_mut().zip(source) {
                *output += *weight * *value;
            }
        }
        let actual = evaluate_multilinear_coefficients(&coefficients, &claim.point)
            .map_err(|error| C6WrapperPcsError::external("evaluate C6 persisted claim", error))?;
        if actual != claim.value {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted claim does not match coefficients",
            ));
        }
        Ok((coefficients, coefficient_bytes))
    }
}

#[allow(dead_code)]
fn read_canonical_fp2_range(
    file: &File,
    symbol_start: usize,
    count: usize,
) -> Result<(Vec<Fp2>, u64)> {
    let byte_offset = u64::try_from(symbol_start)
        .ok()
        .and_then(|value| value.checked_mul(16))
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 persisted field offset overflow"))?;
    let byte_count = count
        .checked_mul(16)
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 persisted field read overflow"))?;
    let mut encoded = vec![0u8; byte_count];
    let mut read = 0usize;
    while read < encoded.len() {
        let got = file
            .read_at(&mut encoded[read..], byte_offset + read as u64)
            .map_err(|error| C6WrapperPcsError::external("read C6 persisted fields", error))?;
        if got == 0 {
            return Err(C6WrapperPcsError::external_message("truncated C6 persisted field file"));
        }
        read += got;
    }
    let mut values = Vec::with_capacity(count);
    for chunk in encoded.chunks_exact(16) {
        let c0 = u64::from_le_bytes(chunk[..8].try_into().unwrap());
        let c1 = u64::from_le_bytes(chunk[8..].try_into().unwrap());
        if c0 >= P || c1 >= P {
            return Err(C6WrapperPcsError::external_message(
                "noncanonical C6 persisted field element",
            ));
        }
        values.push(Fp2::new(Fp::new(c0), Fp::new(c1)));
    }
    Ok((
        values,
        u64::try_from(byte_count).map_err(|_| {
            C6WrapperPcsError::external_message("C6 persisted field byte count exceeds u64")
        })?,
    ))
}

#[derive(Debug)]
pub(crate) struct C6PersistedFoldOpening {
    opening: PersistedCohortOpeningV4<DenseOuterNodeCacheV4>,
}

impl C6PersistedFoldOpening {
    pub(crate) fn root(&self) -> C6WrapperDigest {
        self.opening.root()
    }

    pub(crate) fn open(
        &self,
        query_draws: &[u64],
    ) -> Result<(FoldRoundOpeningV4, PersistedOpeningTrafficV4)> {
        self.opening
            .open_fold_round(query_draws)
            .map_err(|error| C6WrapperPcsError::external("C6 persisted fold opening", error))
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_scaled_c6_wrapper_fold_reference(
    tree: CohortTreeV4,
    codeword: &[Fp2],
    root: impl AsRef<Path>,
    statement_digest: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    repetition: u8,
    fold_round: u8,
) -> Result<C6PersistedFoldOpening> {
    let parts = tree.into_lifecycle_parts();
    if parts.config.outer_depth() > 16
        || parts.slot_symbols.as_slice() != [Some(codeword.to_vec())]
        || parts.config.identity.fold_round != fold_round
    {
        return Err(C6WrapperPcsError::external_message("C6 scaled persisted fold owner mismatch"));
    }
    let directory = root.as_ref().join(format!("repetition-{repetition}-fold-{fold_round:02}"));
    fs::create_dir(&directory)
        .map_err(|error| C6WrapperPcsError::external("create C6 persisted fold", error))?;
    let oracle_path = directory.join("oracle.fp2");
    write_slot_file_create_new(&oracle_path, &[codeword.to_vec()])?;
    let binding =
        PersistedOracleBindingV4::new(statement_digest, session_digest, parts.outer_cache.root());
    let opening = PersistedCohortOpeningV4::load(
        &oracle_path,
        parts.config,
        parts.outer_cache,
        binding,
        binding,
    )
    .map_err(|error| C6WrapperPcsError::external("load C6 persisted fold", error))?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| C6WrapperPcsError::external("fsync C6 persisted fold directory", error))?;
    Ok(C6PersistedFoldOpening { opening })
}

/// Consume a scaled resident cohort and seal its canonical coefficient and
/// oracle files. Existing directories/files fail closed; production geometry
/// is rejected by `into_scaled_persisted_parts` before this function writes.
pub fn persist_scaled_c6_wrapper_cohort_reference(
    cohort: C6CommittedWrapperCohort,
    root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    oracle_ordinal: u64,
) -> Result<C6PersistedWrapperCohort> {
    if session_digest == [0; 32] {
        return Err(C6WrapperPcsError::external_message(
            "zero C6 persisted wrapper session digest",
        ));
    }
    let parts = cohort.into_scaled_persisted_parts()?;
    let directory = root.as_ref().join(format!(
        "cohort-{:08x}-ordinal-{oracle_ordinal:04}",
        parts.commitment.spec.cohort_id
    ));
    fs::create_dir(&directory)
        .map_err(|error| C6WrapperPcsError::external("create C6 persisted cohort", error))?;

    let coefficient_path = directory.join("coefficients.fp2");
    let oracle_path = directory.join("oracle.fp2");
    let manifest_path = directory.join("manifest.c6wsp1");
    let coefficient_bytes = write_slot_file_create_new(&coefficient_path, &parts.coefficients)?;
    let oracle_bytes = write_slot_file_create_new(&oracle_path, &parts.codewords)?;

    let manifest = encode_manifest(
        &parts.commitment,
        session_digest,
        oracle_ordinal,
        coefficient_bytes,
        oracle_bytes,
        0,
    )?;
    write_bytes_create_new(&manifest_path, &manifest)?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| C6WrapperPcsError::external("fsync C6 persisted directory", error))?;

    let binding = PersistedOracleBindingV4::new(
        parts.commitment.statement_digest,
        session_digest,
        parts.commitment.root,
    );
    let opening = PersistedCohortOpeningV4::load(
        &oracle_path,
        parts.commitment.config.clone(),
        parts.outer_cache,
        binding,
        binding,
    )
    .map_err(|error| C6WrapperPcsError::external("load C6 persisted opening", error))?;
    if opening.root() != parts.commitment.root {
        return Err(C6WrapperPcsError::external_message("C6 persisted opening root changed"));
    }
    Ok(C6PersistedWrapperCohort {
        commitment: parts.commitment,
        session_digest,
        oracle_ordinal,
        directory,
        semantic_cache_path: None,
        opening,
        metrics: C6PersistedWrapperMetrics {
            coefficient_bytes_written: coefficient_bytes,
            oracle_bytes_written: oracle_bytes,
            semantic_cache_bytes_written: 0,
            files_created: 3,
            fsync_count: 4,
            resident_codeword_copies_after_seal: 0,
        },
    })
}

/// Commit one exact production cohort with CUDA, persist its coefficients and
/// oracle, and retain only the compact upper Merkle cache required by later
/// verifier-derived openings. CPU backends reject before allocation or I/O.
#[allow(clippy::too_many_arguments)]
pub fn commit_production_c6_wrapper_cohort_cuda(
    backend: &mut Backend,
    statement_digest: C6WrapperDigest,
    spec: crate::c6_wrapper_pcs::C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
    cache_descriptors: Option<&C6CacheStateDescriptors>,
    root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    oracle_ordinal: u64,
) -> Result<(C6PersistedWrapperCohort, X4bCudaCommitMetricsV4)> {
    if backend.kind() == BackendKind::Cpu {
        return Err(C6WrapperPcsError::external_message(
            "C6 production wrapper refuses CPU backend",
        ));
    }
    if statement_digest == [0; 32]
        || session_digest == [0; 32]
        || !production_c6_wrapper_specs().contains(&spec)
        || (matches!(spec.cohort_id, C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID)
            != cache_descriptors.is_some())
    {
        return Err(C6WrapperPcsError::external_message(
            "C6 production wrapper statement/profile binding mismatch",
        ));
    }
    let config = c6_wrapper_commit_config(statement_digest, spec, cache_descriptors)?;
    let directory =
        root.as_ref().join(format!("cohort-{:08x}-ordinal-{oracle_ordinal:04}", spec.cohort_id));
    fs::create_dir(&directory)
        .map_err(|error| C6WrapperPcsError::external("create C6 CUDA cohort", error))?;
    let semantic_cache_path = cache_descriptors.map(|_| directory.join("semantic-cache.fp2"));
    let semantic_cache_bytes = semantic_cache_path
        .as_ref()
        .map(|path| write_cache_semantic_create_new(path, spec, &slots))
        .transpose()?
        .unwrap_or(0);
    let coefficients = compile_c6_wrapper_slot_coefficients(spec, slots)?;
    let paths = X4bCudaCohortPathsV4 {
        coefficients: directory.join("coefficients.fp2"),
        oracle: directory.join("oracle.fp2"),
        root: directory.join("root.digest"),
        staging_directory: directory.join("staging"),
    };
    let artifacts = commit_cohort_cuda_v4(
        backend,
        config.clone(),
        &coefficients,
        paths.clone(),
        OuterCachePolicyV4 { bottom_levels_omitted: C6_PRODUCTION_WRAPPER_CACHE_OMITTED_LEVELS },
    )
    .map_err(|error| C6WrapperPcsError::external("commit C6 CUDA cohort", error))?;
    if artifacts.commitment.config != config {
        return Err(C6WrapperPcsError::external_message(
            "C6 CUDA cohort returned different verifier config",
        ));
    }
    let commitment = if let Some(descriptors) = cache_descriptors {
        C6WrapperCommitment::from_cache_root(
            statement_digest,
            spec,
            artifacts.commitment.root,
            descriptors,
        )?
    } else {
        C6WrapperCommitment::from_root(statement_digest, spec, artifacts.commitment.root)?
    };
    let manifest = encode_manifest(
        &commitment,
        session_digest,
        oracle_ordinal,
        artifacts.metrics.coefficient_bytes_persisted,
        artifacts.metrics.oracle_bytes_persisted,
        semantic_cache_bytes,
    )?;
    write_bytes_create_new(&directory.join("manifest.c6wsp1"), &manifest)?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| C6WrapperPcsError::external("fsync C6 CUDA cohort directory", error))?;
    let binding = PersistedOracleBindingV4::new(statement_digest, session_digest, commitment.root);
    let opening = PersistedCohortOpeningV4::load(
        &paths.oracle,
        config,
        artifacts.outer_cache,
        binding,
        binding,
    )
    .map_err(|error| C6WrapperPcsError::external("load C6 CUDA opening", error))?;
    let mut metrics = artifacts.metrics;
    include_c6_owner_metadata(&mut metrics, semantic_cache_path.is_some())?;
    let owner = C6PersistedWrapperCohort {
        commitment,
        session_digest,
        oracle_ordinal,
        directory,
        semantic_cache_path,
        opening,
        metrics: C6PersistedWrapperMetrics {
            coefficient_bytes_written: metrics.coefficient_bytes_persisted,
            oracle_bytes_written: metrics.oracle_bytes_persisted,
            semantic_cache_bytes_written: semantic_cache_bytes,
            files_created: metrics.files_created,
            fsync_count: metrics.fsync_count,
            resident_codeword_copies_after_seal: 0,
        },
    };
    Ok((owner, metrics))
}

/// Commit one production global-fold aggregate directly from its folded
/// coefficients. CUDA creates the rate-eight oracle and Merkle root; no
/// resident codeword or `CohortTreeV4` is constructed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_production_c6_wrapper_fold_cuda(
    backend: &mut Backend,
    config: CohortVerifierConfigV4,
    coefficients: Vec<Fp2>,
    root: impl AsRef<Path>,
    statement_digest: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    repetition: u8,
    fold_round: u8,
) -> Result<(C6PersistedFoldOpening, X4bCudaCommitMetricsV4, Vec<Fp2>)> {
    if backend.kind() == BackendKind::Cpu {
        return Err(C6WrapperPcsError::external_message("C6 production fold refuses CPU backend"));
    }
    config
        .validate()
        .map_err(|error| C6WrapperPcsError::external("validate C6 CUDA fold", error))?;
    if statement_digest == [0; 32]
        || session_digest == [0; 32]
        || usize::from(repetition) >= C6_WRAPPER_REPETITIONS
        || fold_round == 0
        || config.identity.oracle_kind != OracleKindV4::GlobalFoldAggregate
        || config.identity.fold_round != fold_round
        || config.slot_descriptors.len() != 1
        || config.slot_descriptors[0].is_none()
        || coefficients.len() != config.outer_len / 8
    {
        return Err(C6WrapperPcsError::external_message(
            "C6 production fold statement/profile binding mismatch",
        ));
    }
    let directory = root.as_ref().join(format!("repetition-{repetition}-fold-{fold_round:02}"));
    fs::create_dir(&directory)
        .map_err(|error| C6WrapperPcsError::external("create C6 CUDA fold", error))?;
    let paths = X4bCudaCohortPathsV4 {
        coefficients: directory.join("coefficients.fp2"),
        oracle: directory.join("oracle.fp2"),
        root: directory.join("root.digest"),
        staging_directory: directory.join("staging"),
    };
    let cache_policy = OuterCachePolicyV4 {
        bottom_levels_omitted: C6_PRODUCTION_WRAPPER_CACHE_OMITTED_LEVELS
            .min(config.outer_depth() - 1),
    };
    let coefficient_slots = vec![Some(coefficients)];
    let artifacts = commit_cohort_cuda_v4(
        backend,
        config.clone(),
        &coefficient_slots,
        paths.clone(),
        cache_policy,
    )
    .map_err(|error| C6WrapperPcsError::external("commit C6 CUDA fold", error))?;
    if artifacts.commitment.config != config {
        return Err(C6WrapperPcsError::external_message(
            "C6 CUDA fold returned different verifier config",
        ));
    }
    let manifest = encode_fold_manifest(
        &config,
        statement_digest,
        session_digest,
        repetition,
        artifacts.commitment.root,
        artifacts.metrics.coefficient_bytes_persisted,
        artifacts.metrics.oracle_bytes_persisted,
    )?;
    write_bytes_create_new(&directory.join("manifest.c6wfp1"), &manifest)?;
    File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| C6WrapperPcsError::external("fsync C6 CUDA fold directory", error))?;
    let binding =
        PersistedOracleBindingV4::new(statement_digest, session_digest, artifacts.commitment.root);
    let opening = PersistedCohortOpeningV4::load(
        &paths.oracle,
        config,
        artifacts.outer_cache,
        binding,
        binding,
    )
    .map_err(|error| C6WrapperPcsError::external("load C6 CUDA fold opening", error))?;
    let mut metrics = artifacts.metrics;
    include_c6_owner_metadata(&mut metrics, false)?;
    let coefficients =
        coefficient_slots.into_iter().next().flatten().ok_or_else(|| {
            C6WrapperPcsError::external_message("C6 fold coefficients disappeared")
        })?;
    Ok((C6PersistedFoldOpening { opening }, metrics, coefficients))
}

fn include_c6_owner_metadata(
    metrics: &mut X4bCudaCommitMetricsV4,
    has_semantic_cache: bool,
) -> Result<()> {
    metrics.files_created = metrics
        .files_created
        .checked_add(1 + u64::from(has_semantic_cache))
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 CUDA file overflow"))?;
    metrics.directories_created = metrics
        .directories_created
        .checked_add(1)
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 CUDA directory overflow"))?;
    metrics.fsync_count = metrics
        .fsync_count
        .checked_add(2 + u64::from(has_semantic_cache))
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 CUDA fsync overflow"))?;
    Ok(())
}

fn link_fold_source_digest(
    binding: &C6PersistedLinkFoldBinding,
    coefficient_len: usize,
) -> Result<C6WrapperDigest> {
    let coefficient_len = u64::try_from(coefficient_len).map_err(|_| {
        C6WrapperPcsError::external_message("C6 link source coefficient length exceeds u64")
    })?;
    let mut hasher = blake3::Hasher::new_derive_key(LINK_FOLD_SOURCE_DOMAIN);
    hasher.update(&binding.statement_digest);
    hasher.update(&binding.session_digest);
    hasher.update(&binding.root);
    hasher.update(&[binding.repetition]);
    hasher.update(&binding.cohort_id.to_le_bytes());
    hasher.update(&binding.slot.to_le_bytes());
    hasher.update(&binding.round.to_le_bytes());
    hasher.update(&coefficient_len.to_le_bytes());
    hasher.update(&binding.target_digest);
    Ok(*hasher.finalize().as_bytes())
}

#[allow(dead_code)]
fn encode_link_fold_manifest(
    binding: &C6PersistedLinkFoldBinding,
    coefficient_len: usize,
    predecessor_digest: C6WrapperDigest,
    challenge: Fp2,
    coefficient_bytes: u64,
) -> Result<Vec<u8>> {
    if binding.statement_digest == [0; 32]
        || binding.session_digest == [0; 32]
        || binding.root == [0; 32]
        || binding.target_digest == [0; 32]
        || binding.round == 0
        || predecessor_digest == [0; 32]
        || coefficient_bytes
            != u64::try_from(coefficient_len)
                .ok()
                .and_then(|symbols| symbols.checked_mul(16))
                .unwrap_or_default()
    {
        return Err(C6WrapperPcsError::external_message("C6 link fold manifest binding mismatch"));
    }
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&LINK_FOLD_MANIFEST_MAGIC);
    bytes.extend_from_slice(&LINK_FOLD_MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&binding.statement_digest);
    bytes.extend_from_slice(&binding.session_digest);
    bytes.extend_from_slice(&binding.root);
    bytes.push(binding.repetition);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&binding.cohort_id.to_le_bytes());
    bytes.extend_from_slice(&binding.slot.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&binding.round.to_le_bytes());
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&(coefficient_len as u64).to_le_bytes());
    bytes.extend_from_slice(&binding.target_digest);
    bytes.extend_from_slice(&predecessor_digest);
    bytes.extend_from_slice(&challenge.c0.value().to_le_bytes());
    bytes.extend_from_slice(&challenge.c1.value().to_le_bytes());
    bytes.extend_from_slice(&coefficient_bytes.to_le_bytes());
    let mut hasher = blake3::Hasher::new_derive_key(LINK_FOLD_MANIFEST_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    if bytes.len() != 256 {
        return Err(C6WrapperPcsError::external_message("C6 link fold manifest length changed"));
    }
    Ok(bytes)
}

fn write_slot_file_create_new(path: &Path, slots: &[Vec<Fp2>]) -> Result<u64> {
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| C6WrapperPcsError::external("create C6 persisted slot file", error))?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut symbols = 0u64;
    for slot in slots {
        write_canonical_fp2_slice_v4(&mut writer, slot)
            .map_err(|error| C6WrapperPcsError::external("write C6 persisted slot", error))?;
        symbols = symbols
            .checked_add(
                u64::try_from(slot.len()).map_err(|error| {
                    C6WrapperPcsError::external("count C6 persisted slot", error)
                })?,
            )
            .ok_or_else(|| C6WrapperPcsError::external_message("C6 persisted symbol overflow"))?;
    }
    writer
        .flush()
        .map_err(|error| C6WrapperPcsError::external("flush C6 persisted slot", error))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| C6WrapperPcsError::external("fsync C6 persisted slot", error))?;
    symbols
        .checked_mul(16)
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 persisted byte overflow"))
}

fn write_cache_semantic_create_new(
    path: &Path,
    spec: crate::c6_wrapper_pcs::C6WrapperCohortSpec,
    slots: &[C6WrapperSlotWitness],
) -> Result<u64> {
    if !matches!(spec.cohort_id, C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID)
        || slots.len() != usize::from(spec.slot_count)
    {
        return Err(C6WrapperPcsError::external_message(
            "C6 semantic cache owner geometry mismatch",
        ));
    }
    let payload_len = 1usize
        .checked_shl(u32::from(spec.payload_log2))
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 semantic cache length overflow"))?;
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| C6WrapperPcsError::external("create C6 semantic cache", error))?;
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    for slot in slots.iter().take(2) {
        let C6WrapperSlotWitness::Witness { witness, zk_mask } = slot else {
            return Err(C6WrapperPcsError::external_message(
                "C6 semantic cache slot kind mismatch",
            ));
        };
        if witness.len() != payload_len || zk_mask.len() != payload_len {
            return Err(C6WrapperPcsError::external_message(
                "C6 semantic cache slot length mismatch",
            ));
        }
        write_canonical_fp2_slice_v4(&mut writer, witness)
            .map_err(|error| C6WrapperPcsError::external("write C6 semantic cache", error))?;
    }
    writer
        .flush()
        .map_err(|error| C6WrapperPcsError::external("flush C6 semantic cache", error))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| C6WrapperPcsError::external("fsync C6 semantic cache", error))?;
    u64::try_from(payload_len)
        .ok()
        .and_then(|symbols| symbols.checked_mul(2))
        .and_then(|symbols| symbols.checked_mul(16))
        .ok_or_else(|| C6WrapperPcsError::external_message("C6 semantic cache bytes overflow"))
}

fn write_bytes_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| C6WrapperPcsError::external("create C6 persisted manifest", error))?;
    file.write_all(bytes)
        .map_err(|error| C6WrapperPcsError::external("write C6 persisted manifest", error))?;
    file.sync_all()
        .map_err(|error| C6WrapperPcsError::external("fsync C6 persisted manifest", error))
}

fn encode_manifest(
    commitment: &C6WrapperCommitment,
    session_digest: C6WrapperDigest,
    oracle_ordinal: u64,
    coefficient_bytes: u64,
    oracle_bytes: u64,
    semantic_cache_bytes: u64,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(180);
    bytes.extend_from_slice(&MANIFEST_MAGIC);
    bytes.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&session_digest);
    bytes.extend_from_slice(&commitment.statement_digest);
    bytes.extend_from_slice(&commitment.root);
    bytes.extend_from_slice(&commitment.spec.cohort_id.to_le_bytes());
    bytes.push(commitment.spec.oracle_kind as u8);
    bytes.push(commitment.spec.payload_log2);
    bytes.extend_from_slice(&commitment.spec.slot_count.to_le_bytes());
    bytes.extend_from_slice(&oracle_ordinal.to_le_bytes());
    bytes.extend_from_slice(&coefficient_bytes.to_le_bytes());
    bytes.extend_from_slice(&oracle_bytes.to_le_bytes());
    bytes.extend_from_slice(&semantic_cache_bytes.to_le_bytes());
    let mut hasher = blake3::Hasher::new_derive_key(MANIFEST_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    if bytes.len() != 180 {
        return Err(C6WrapperPcsError::external_message("C6 persisted manifest length changed"));
    }
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn encode_fold_manifest(
    config: &CohortVerifierConfigV4,
    statement_digest: C6WrapperDigest,
    session_digest: C6WrapperDigest,
    repetition: u8,
    root: C6WrapperDigest,
    coefficient_bytes: u64,
    oracle_bytes: u64,
) -> Result<Vec<u8>> {
    let descriptor = config
        .slot_descriptors
        .first()
        .copied()
        .flatten()
        .ok_or_else(|| C6WrapperPcsError::external_message("missing C6 fold descriptor"))?;
    let mut bytes = Vec::with_capacity(204);
    bytes.extend_from_slice(&FOLD_MANIFEST_MAGIC);
    bytes.extend_from_slice(&FOLD_MANIFEST_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&session_digest);
    bytes.extend_from_slice(&statement_digest);
    bytes.extend_from_slice(&root);
    bytes.extend_from_slice(&descriptor);
    bytes.extend_from_slice(&config.identity.cohort_id.to_le_bytes());
    bytes.push(config.identity.oracle_kind as u8);
    bytes.push(config.identity.fold_round);
    bytes.push(repetition);
    bytes.push(0);
    bytes.extend_from_slice(
        &u64::try_from(config.outer_len)
            .map_err(|_| C6WrapperPcsError::external_message("C6 fold outer length overflow"))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(&coefficient_bytes.to_le_bytes());
    bytes.extend_from_slice(&oracle_bytes.to_le_bytes());
    let mut hasher = blake3::Hasher::new_derive_key(FOLD_MANIFEST_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    if bytes.len() != 204 {
        return Err(C6WrapperPcsError::external_message(
            "C6 persisted fold manifest length changed",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_fold_owner_is_create_new_bound_and_releases_only_durable_predecessors() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-link-fold-owner-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let spill = root.join("spill");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&spill).unwrap();
        let path = root.join("coefficients.fp2");
        let coefficients = (1..=8).map(|value| Fp2::from_base(Fp::new(value))).collect::<Vec<_>>();
        assert_eq!(write_slot_file_create_new(&path, &[coefficients.clone()]).unwrap(), 128);
        let reader = C6PersistedCoefficientSlotReader {
            file: OpenOptions::new().read(true).open(&path).unwrap(),
            slot_count: 1,
            coefficient_len: 8,
            statement_digest: [0x81; 32],
            session_digest: [0x82; 32],
            root: [0x83; 32],
        };
        let (mut owner, mut metrics) =
            reader.open_link_fold_owner(&spill, 1, 17, 0, [0x84; 32]).unwrap();
        assert_eq!(
            owner.binding(),
            C6PersistedLinkFoldBinding {
                statement_digest: [0x81; 32],
                session_digest: [0x82; 32],
                root: [0x83; 32],
                repetition: 1,
                cohort_id: 17,
                slot: 0,
                round: 0,
                target_digest: [0x84; 32],
            }
        );
        let challenges =
            [Fp2::from_base(Fp::new(3)), Fp2::from_base(Fp::new(5)), Fp2::from_base(Fp::new(7))];
        let mut expected = coefficients;
        for (round, challenge) in challenges.into_iter().enumerate() {
            let next = expected
                .chunks_exact(2)
                .map(|pair| pair[0] + challenge * pair[1])
                .collect::<Vec<_>>();
            owner = owner.bind_create_new(challenge, (round + 1) as u16, &mut metrics).unwrap();
            assert_eq!(owner.coefficient_len(), next.len());
            assert_eq!(owner.read_range(0, next.len()).unwrap().0, next);
            expected = next;
        }
        let term_directory = spill.join("link-repetition-1-cohort-17-slot-0");
        assert!(!term_directory.join("round-01.fp2").exists());
        assert!(!term_directory.join("round-02.fp2").exists());
        assert!(term_directory.join("round-03.fp2").exists());
        assert!(reader.open_link_fold_owner(&spill, 1, 17, 0, [0x84; 32]).is_err());
        owner.release(&mut metrics).unwrap();
        assert_eq!(metrics.coefficient_bytes_read, 224);
        assert_eq!(metrics.coefficient_bytes_written, 112);
        assert_eq!(metrics.manifest_bytes_written, 768);
        assert_eq!(metrics.files_created, 6);
        assert_eq!(metrics.files_deleted_after_successor_durable, 6);
        assert_eq!(metrics.directories_created, 1);
        assert_eq!(metrics.fsync_count, 13);
        assert_eq!(metrics.current_live_spill_bytes, 0);
        assert_eq!(metrics.peak_live_spill_bytes, 608);
        assert_eq!(fs::read_dir(&term_directory).unwrap().count(), 0);
        drop(reader);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn coefficient_slot_reader_is_random_access_bound_and_truncation_closed() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-coefficient-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("coefficients.fp2");
        let slots = (0..3)
            .map(|slot| {
                (0..8)
                    .map(|index| Fp2::from_base(Fp::new((100 * slot + index + 1) as u64)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(write_slot_file_create_new(&path, &slots).unwrap(), 384);
        let reader = C6PersistedCoefficientSlotReader {
            file: OpenOptions::new().read(true).open(&path).unwrap(),
            slot_count: 3,
            coefficient_len: 8,
            statement_digest: [0xA1; 32],
            session_digest: [0xA2; 32],
            root: [0xA3; 32],
        };
        assert_eq!(reader.coefficient_len(), 8);
        assert_eq!(reader.binding(), ([0xA1; 32], [0xA2; 32], [0xA3; 32]));
        assert_eq!(
            reader.read_slot_range(1, 2, 3).unwrap().0,
            (103..=105).map(|value| Fp2::from_base(Fp::new(value))).collect::<Vec<_>>()
        );
        assert!(reader.read_slot_range(3, 0, 1).is_err());
        assert!(reader.read_slot_range(0, 7, 2).is_err());
        OpenOptions::new().write(true).open(&path).unwrap().set_len(16).unwrap();
        assert!(reader.read_slot_range(2, 0, 1).is_err());
        drop(reader);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn semantic_cache_owner_is_canonical_random_access_and_truncation_closed() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-semantic-cache-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("semantic-cache.fp2");
        let spec = crate::c6_wrapper_pcs::C6WrapperCohortSpec {
            cohort_id: C6_PREDECESSOR_CACHE_COHORT_ID,
            oracle_kind: crate::c6_wrapper_pcs::C6WrapperOracleKind::Witness,
            payload_log2: 2,
            slot_count: 8,
        };
        let slots = (0..8)
            .map(|slot| C6WrapperSlotWitness::Witness {
                witness: (0..4)
                    .map(|index| Fp2::from_base(Fp::new((100 * slot + index + 1) as u64)))
                    .collect(),
                zk_mask: vec![Fp2::ZERO; 4],
            })
            .collect::<Vec<_>>();
        assert_eq!(write_cache_semantic_create_new(&path, spec, &slots).unwrap(), 128);
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        let reader = C6PersistedCacheSemanticReader {
            file,
            payload_len: 4,
            statement_digest: [0x91; 32],
            session_digest: [0x92; 32],
            root: [0x93; 32],
        };
        assert_eq!(reader.binding(), ([0x91; 32], [0x92; 32], [0x93; 32]));
        assert_eq!(
            reader.read_slot_range(0, 1, 2).unwrap().0,
            vec![Fp2::from_base(Fp::new(2)), Fp2::from_base(Fp::new(3))]
        );
        assert_eq!(
            reader.read_slot_range(1, 0, 4).unwrap().0,
            (101..=104).map(|value| Fp2::from_base(Fp::new(value))).collect::<Vec<_>>()
        );
        assert!(reader.read_slot_range(2, 0, 1).is_err());
        OpenOptions::new().write(true).open(&path).unwrap().set_len(16).unwrap();
        assert!(reader.read_slot_range(1, 0, 1).is_err());
        drop(reader);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_constructor_refuses_cpu_before_allocation_or_io() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-cuda-reject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut backend = Backend::cpu();
        let error = commit_production_c6_wrapper_cohort_cuda(
            &mut backend,
            [0x81; 32],
            production_c6_wrapper_specs()[2],
            Vec::new(),
            None,
            &root,
            [0x82; 32],
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refuses CPU"));
        assert!(!root.exists());
    }

    #[test]
    fn production_fold_constructor_refuses_cpu_before_allocation_or_io() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-fold-cuda-reject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let config = CohortVerifierConfigV4 {
            identity: crate::x4::merkle_v4::CohortIdentityV4 {
                cohort_id: 0xC6F0_0000,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: 1,
            },
            slot_descriptors: vec![Some([0x83; 32])],
            outer_len: 16,
            expected_symbol_count: 1,
        };
        let error = commit_production_c6_wrapper_fold_cuda(
            &mut Backend::cpu(),
            config,
            vec![Fp2::ZERO; 2],
            &root,
            [0x81; 32],
            [0x82; 32],
            0,
            1,
        )
        .unwrap_err();
        assert!(error.to_string().contains("refuses CPU"));
        assert!(!root.exists());
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn scaled_cuda_fold_owner_matches_resident_root_and_opening() {
        use volta_field::Fp;

        let mut backend = match Backend::cuda_hybrid() {
            Ok(backend) => backend,
            Err(error) if std::env::var_os("VOLTA_REQUIRE_CUDA").is_some() => {
                panic!("VOLTA_REQUIRE_CUDA set but C6 fold CUDA failed to initialize: {error}")
            }
            Err(_) => return,
        };
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-fold-cuda-diff-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let config = CohortVerifierConfigV4 {
            identity: crate::x4::merkle_v4::CohortIdentityV4 {
                cohort_id: 0xC6F0_0000,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: 1,
            },
            slot_descriptors: vec![Some([0x83; 32])],
            outer_len: 32,
            expected_symbol_count: 1,
        };
        let coefficients = (0..4)
            .map(|index| Fp2::new(Fp::new(19 * index + 3), Fp::new(31 * index * index + 5)))
            .collect::<Vec<_>>();
        let codeword = crate::x4::ntt::encode_rate_eighth(&coefficients).unwrap();
        let reference = CohortTreeV4::build_flat(config.clone(), vec![Some(codeword)]).unwrap();
        let (opening, metrics, returned) = commit_production_c6_wrapper_fold_cuda(
            &mut backend,
            config,
            coefficients.clone(),
            &root,
            [0x81; 32],
            [0x82; 32],
            0,
            1,
        )
        .unwrap();
        assert_eq!(opening.root(), reference.root());
        assert_eq!(returned, coefficients);
        let draws = [1, 3, 5, 7];
        assert_eq!(opening.open(&draws).unwrap().0, reference.open_fold_round(&draws).unwrap());
        assert_eq!(metrics.files_created, 4);
        assert_eq!(metrics.directories_created, 2);
        assert!(metrics.fsync_count >= 2);
        assert_eq!(
            fs::metadata(root.join("repetition-0-fold-01/manifest.c6wfp1")).unwrap().len(),
            204
        );
        fs::remove_dir_all(root).unwrap();
    }
}
