//! Create-new persisted opening owners for the C6 wrapper PCS.
//!
//! The first checkpoint is deliberately scaled and consumes the resident
//! reference owner. Production geometry has a separate CUDA constructor and
//! cannot enter through this module's reference adapter.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use volta_accel::{Backend, BackendKind};
use volta_field::Fp2;

use crate::c6_wrapper_pcs::{
    c6_wrapper_commit_config, compile_c6_wrapper_slot_coefficients, production_c6_wrapper_specs,
    validate_claim, C6CacheStateDescriptors, C6CommittedWrapperCohort, C6WrapperCommitment,
    C6WrapperDigest, C6WrapperOpeningClaim, C6WrapperPcsError, C6WrapperSlotWitness,
    CombinedCohort, C6_PREDECESSOR_CACHE_COHORT_ID, C6_SUCCESSOR_CACHE_COHORT_ID,
};
use crate::x4::cuda_v4::{commit_cohort_cuda_v4, X4bCudaCohortPathsV4, X4bCudaCommitMetricsV4};
use crate::x4::frame_v4::{FoldRoundOpeningV4, InitialOpeningGroupV4};
use crate::x4::merkle_v4::{CohortTreeV4, DenseOuterNodeCacheV4, OuterCachePolicyV4};
use crate::x4::ntt::evaluate_multilinear_coefficients;
use crate::x4::persisted_v4::{
    read_persisted_coefficients_v4, write_canonical_fp2_slice_v4, PersistedCohortOpeningV4,
    PersistedOpeningTrafficV4, PersistedOracleBindingV4,
};

const MANIFEST_MAGIC: [u8; 8] = *b"C6WSP1\0\0";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_DOMAIN: &str = "volta-zk/c6/wrapper-persisted-manifest/v1";
pub const C6_PRODUCTION_WRAPPER_CACHE_OMITTED_LEVELS: u8 = 8;

type Result<T> = std::result::Result<T, C6WrapperPcsError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6PersistedWrapperMetrics {
    pub coefficient_bytes_written: u64,
    pub oracle_bytes_written: u64,
    pub files_created: u64,
    pub fsync_count: u64,
    pub resident_codeword_copies_after_seal: u64,
}

#[derive(Debug)]
pub struct C6PersistedWrapperCohort {
    commitment: C6WrapperCommitment,
    session_digest: C6WrapperDigest,
    oracle_ordinal: u64,
    directory: PathBuf,
    opening: PersistedCohortOpeningV4<DenseOuterNodeCacheV4>,
    metrics: C6PersistedWrapperMetrics,
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
        validate_claim(&self.commitment, claim)?;
        let slots = (0..self.commitment.spec.slot_count).collect::<Vec<_>>();
        let coefficient_slots = read_persisted_coefficients_v4(
            self.directory.join("coefficients.fp2"),
            &self.commitment.config,
        )
        .map_err(|error| C6WrapperPcsError::external("read C6 persisted coefficients", error))?;
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
        let (codeword, _bytes_read) = self
            .opening
            .combine_slots(&slots, &claim.slot_weights)
            .map_err(|error| C6WrapperPcsError::external("combine C6 persisted oracle", error))?;
        let actual = evaluate_multilinear_coefficients(&coefficients, &claim.point)
            .map_err(|error| C6WrapperPcsError::external("evaluate C6 persisted claim", error))?;
        if actual != claim.value {
            return Err(C6WrapperPcsError::external_message(
                "C6 persisted claim does not match coefficients",
            ));
        }
        Ok(CombinedCohort {
            outer_len: self.commitment.config.outer_len,
            coefficients,
            codeword,
            claimed_value: claim.value,
        })
    }
}

#[derive(Debug)]
pub(crate) struct C6PersistedFoldOpening {
    opening: PersistedCohortOpeningV4<DenseOuterNodeCacheV4>,
}

impl C6PersistedFoldOpening {
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
        opening,
        metrics: C6PersistedWrapperMetrics {
            coefficient_bytes_written: coefficient_bytes,
            oracle_bytes_written: oracle_bytes,
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
    let metrics = artifacts.metrics;
    let owner = C6PersistedWrapperCohort {
        commitment,
        session_digest,
        oracle_ordinal,
        directory,
        opening,
        metrics: C6PersistedWrapperMetrics {
            coefficient_bytes_written: metrics.coefficient_bytes_persisted,
            oracle_bytes_written: metrics.oracle_bytes_persisted,
            files_created: metrics
                .files_created
                .checked_add(1)
                .ok_or_else(|| C6WrapperPcsError::external_message("C6 CUDA file overflow"))?,
            fsync_count: metrics
                .fsync_count
                .checked_add(2)
                .ok_or_else(|| C6WrapperPcsError::external_message("C6 CUDA fsync overflow"))?,
            resident_codeword_copies_after_seal: 0,
        },
    };
    Ok((owner, metrics))
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
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(172);
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
    let mut hasher = blake3::Hasher::new_derive_key(MANIFEST_DOMAIN);
    hasher.update(&bytes);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    if bytes.len() != 172 {
        return Err(C6WrapperPcsError::external_message("C6 persisted manifest length changed"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
