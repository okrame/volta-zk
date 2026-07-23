//! Model-global, different-size zkDeepFold-UD chain for schema 4.
//!
//! Initial cohorts are fixed and canonically ordered before the fold and
//! activation challenges.  [`GlobalChainDraftV4::seal`] computes every fold
//! commitment; only the resulting [`SealedGlobalChainV4`] can consume the
//! exact 111-query tape and emit the single packed opening.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use volta_accel::Backend;
use volta_field::{Fp, Fp2};
use volta_mac::Transcript;

use super::accounting::projected_query_indices;
use super::cuda_v4::{
    commit_cohort_cuda_v4_instrumented, verify_persisted_oracle_matches_v4,
    X4bCudaCohortArtifactsV4, X4bCudaCohortPathsV4, X4bCudaCommitMetricsV4,
};
use super::frame::{Digest, FrameError};
use super::frame_v4::{
    opening_schedule_digest_v4, profile_digest_v4, FoldCommitmentFrameV4, InitialOpeningScheduleV4,
    OracleKindV4, PackedBatchOpeningFrameV4, PackedOpeningScheduleV4, PRODUCTION_QUERY_COUNT_V4,
};
use super::lifecycle_v4::{
    NoopX4LifecycleObserverV4, X4AcceleratorControlSnapshotV4, X4LegacySealedOwnershipV4,
    X4LifecycleContextV4, X4LifecycleEventV4, X4LifecycleNestingV4, X4LifecycleObserverV4,
    X4LifecyclePhaseV4, X4LifecycleTrackV4, X4TemporaryFileStateV4,
};
use super::merkle::MerkleError;
use super::merkle_v4::{
    verify_fold_round_packed_opening_v4, verify_initial_packed_opening_v4, CohortIdentityV4,
    CohortTreeLifecyclePartsV4, CohortTreeV4, CohortVerifierConfigV4,
    DenseOuterNodeCacheLifecyclePartsV4, OuterCachePolicyV4,
};
use super::ntt::{
    encode_rate_eighth, evaluate_multilinear_coefficients, fold_codeword, fold_coefficients,
    root_of_unity,
};

pub const MAX_RESPONSE_CLAIMS_V4: usize = 3_320;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldingErrorV4 {
    Frame(FrameError),
    Merkle(MerkleError),
    InvalidGeometry(&'static str),
    InvalidProof(&'static str),
    EarlyQueryRejected,
    Artifact(String),
    Overflow,
}

impl From<FrameError> for FoldingErrorV4 {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<MerkleError> for FoldingErrorV4 {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelGlobalCohortCommitmentV4 {
    pub root: Digest,
    pub config: CohortVerifierConfigV4,
}

#[derive(Clone, Debug)]
pub struct CommittedModelGlobalCohortV4 {
    commitment: ModelGlobalCohortCommitmentV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    codewords: Vec<Option<Vec<Fp2>>>,
    tree: CohortTreeV4,
}

impl CommittedModelGlobalCohortV4 {
    pub fn commit(
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, FoldingErrorV4> {
        config.validate()?;
        if matches!(config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate)
            || coefficients.len() != config.slot_descriptors.len()
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 initial cohort"));
        }
        let coefficient_len = config.outer_len / 8;
        if coefficient_len == 0 || !coefficient_len.is_power_of_two() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 rate-eighth cohort"));
        }
        let mut codewords = Vec::with_capacity(coefficients.len());
        for (descriptor, coefficients) in config.slot_descriptors.iter().zip(&coefficients) {
            match (descriptor, coefficients) {
                (Some(_), Some(coefficients)) if coefficients.len() == coefficient_len => {
                    codewords
                        .push(Some(encode_rate_eighth(coefficients).map_err(|_| {
                            FoldingErrorV4::InvalidGeometry("v4 initial encoding")
                        })?));
                }
                (None, None) => codewords.push(None),
                (Some(_), Some(_)) => {
                    return Err(FoldingErrorV4::InvalidGeometry("v4 coefficient length"));
                }
                _ => return Err(FoldingErrorV4::InvalidGeometry("v4 coefficient presence")),
            }
        }
        let tree = CohortTreeV4::build_flat(config.clone(), codewords.clone())?;
        let commitment = ModelGlobalCohortCommitmentV4 { root: tree.root(), config };
        Ok(Self { commitment, coefficients, codewords, tree })
    }

    pub fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        &self.commitment
    }

    pub(crate) fn combine(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<CombinedInitialV4, FoldingErrorV4> {
        validate_group_geometry(&self.commitment, touched_slots, weights, target_point)?;
        let coefficient_len = self.commitment.config.outer_len / 8;
        let mut coefficients = vec![Fp2::ZERO; coefficient_len];
        let mut codeword = vec![Fp2::ZERO; self.commitment.config.outer_len];
        for (slot, weight) in touched_slots.iter().zip(weights) {
            let index = usize::from(*slot);
            let source_coefficients = self.coefficients[index]
                .as_ref()
                .ok_or(FoldingErrorV4::InvalidGeometry("v4 touched coefficient slot"))?;
            let source_codeword = self.codewords[index]
                .as_ref()
                .ok_or(FoldingErrorV4::InvalidGeometry("v4 touched codeword slot"))?;
            for (output, value) in coefficients.iter_mut().zip(source_coefficients) {
                *output += *weight * *value;
            }
            for (output, value) in codeword.iter_mut().zip(source_codeword) {
                *output += *weight * *value;
            }
        }
        let claimed_value = evaluate_multilinear_coefficients(&coefficients, target_point)
            .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 target evaluation"))?;
        Ok(CombinedInitialV4 { coefficients, codeword, claimed_value })
    }
}

#[derive(Clone, Debug)]
pub struct CombinedInitialV4 {
    pub(crate) coefficients: Vec<Fp2>,
    pub(crate) codeword: Vec<Fp2>,
    pub(crate) claimed_value: Fp2,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceRecomputeTrafficV4 {
    pub source_bytes_read: u64,
    pub oracle_bytes_recomputed: u64,
    pub merkle_bytes_recomputed: u64,
    pub persisted_oracle_bytes_read: u64,
    pub persisted_page_cache_dontneed_bytes: u64,
    pub persisted_page_cache_advice_calls: u64,
    pub outer_cache_bytes_read: u64,
    pub inner_trees_rebuilt: u64,
    pub outer_frontier_leaves_rebuilt: u64,
    pub outer_internal_nodes_rebuilt: u64,
}

/// Source abstraction used by the global chain.  A retained cohort answers
/// directly; the G6 recompute implementation rebuilds and root-checks one
/// cohort per call, then discards it.
pub trait ModelGlobalOpeningSourceV4: std::fmt::Debug {
    fn commitment(&self) -> &ModelGlobalCohortCommitmentV4;

    fn combine_source(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<(CombinedInitialV4, SourceRecomputeTrafficV4), FoldingErrorV4>;

    fn open_initial_source(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(super::frame_v4::InitialOpeningGroupV4, SourceRecomputeTrafficV4), FoldingErrorV4>;
}

impl ModelGlobalOpeningSourceV4 for CommittedModelGlobalCohortV4 {
    fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        self.commitment()
    }

    fn combine_source(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<(CombinedInitialV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        Ok((
            self.combine(touched_slots, weights, target_point)?,
            SourceRecomputeTrafficV4::default(),
        ))
    }

    fn open_initial_source(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(super::frame_v4::InitialOpeningGroupV4, SourceRecomputeTrafficV4), FoldingErrorV4>
    {
        let (opening, metrics) = self.tree.open_initial_with_metrics(query_draws, touched_slots)?;
        Ok((
            opening,
            SourceRecomputeTrafficV4 {
                outer_cache_bytes_read: metrics
                    .cached_outer_digests_read
                    .checked_mul(32)
                    .ok_or(FoldingErrorV4::Overflow)?,
                inner_trees_rebuilt: metrics.inner_trees_rebuilt,
                outer_frontier_leaves_rebuilt: metrics.outer_frontier_leaves_rebuilt,
                outer_internal_nodes_rebuilt: metrics.outer_internal_nodes_rebuilt,
                ..SourceRecomputeTrafficV4::default()
            },
        ))
    }
}

#[derive(Clone, Debug)]
pub struct GlobalProverGroupV4<'a> {
    pub cohort: &'a dyn ModelGlobalOpeningSourceV4,
    pub touched_slots: Vec<u16>,
    /// Verifier-derived same-domain reduction weights in canonical slot order.
    pub weights: Vec<Fp2>,
    /// Suffix of the response-global point appropriate to this domain.
    pub target_point: Vec<Fp2>,
    /// Fresh activation challenge for this committed cohort.
    pub activation_challenge: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalVerifierGroupV4 {
    pub commitment: ModelGlobalCohortCommitmentV4,
    pub touched_slots: Vec<u16>,
    pub weights: Vec<Fp2>,
    pub target_point: Vec<Fp2>,
    pub activation_challenge: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalFoldChallengesV4 {
    /// One challenge per coefficient variable of the largest active domain.
    pub folds: Vec<Fp2>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GlobalOpenMetricsV4 {
    pub source_coefficients_read: u64,
    pub initial_encoded_symbols_read: u64,
    /// Per-cohort same-domain aggregates retained while the global chain is
    /// sealed.  These are prover artifacts, not serialized proof symbols.
    pub combined_coefficient_symbols: u64,
    pub combined_codeword_symbols: u64,
    pub folded_symbols_written: u64,
    pub aggregate_merkle_symbols_written: u64,
    pub aggregate_merkle_digests_written: u64,
    /// Exact live payload owned by the response-local fold trees when the
    /// chain becomes sealed. These bytes are consumed by `issue_queries` and
    /// explicitly dropped in its teardown timer.
    pub sealed_fold_codeword_bytes: u64,
    pub sealed_fold_outer_cache_bytes: u64,
    pub sealed_fold_tree_count: u64,
    pub sealed_fold_outer_level_vectors: u64,
    pub serialized_fold_bytes: u64,
    pub serialized_packed_opening_bytes: u64,
    /// Coarse wall decomposition of the one-shot sealed-to-opening
    /// transition. The categories are deliberately implementation-facing and
    /// do not enter the transcript or proof grammar.
    pub issue_queries_query_gather_wall_ns: u64,
    pub issue_queries_hashing_path_assembly_wall_ns: u64,
    pub issue_queries_encode_serialize_wall_ns: u64,
    pub issue_queries_teardown_wall_ns: u64,
    pub issue_queries_total_wall_ns: u64,
    pub recomputed_source_bytes_read: u64,
    pub recomputed_oracle_bytes: u64,
    pub recomputed_merkle_bytes: u64,
    pub persisted_oracle_bytes_read: u64,
    pub persisted_page_cache_dontneed_bytes: u64,
    pub persisted_page_cache_advice_calls: u64,
    pub outer_cache_bytes_read: u64,
    pub inner_trees_rebuilt: u64,
    pub outer_frontier_leaves_rebuilt: u64,
    pub outer_internal_nodes_rebuilt: u64,
    pub x4b_fold_coefficient_bytes_persisted: u64,
    pub x4b_fold_oracle_bytes_persisted: u64,
    pub x4b_fold_root_bytes_persisted: u64,
    pub x4b_fold_reference_bytes_read: u64,
    pub x4b_fold_staging_bytes_read: u64,
    pub x4b_fold_staging_bytes_written: u64,
    pub x4b_fold_retained_outer_cache_bytes: u64,
    pub x4b_fold_expected_h2d_bytes: u64,
    pub x4b_fold_expected_d2h_bytes: u64,
    pub x4b_fold_expected_device_zeroed_bytes: u64,
    pub x4b_fold_maximum_n4_tile_bytes: u64,
    pub x4b_fold_page_cache_dontneed_bytes: u64,
    pub x4b_fold_page_cache_advice_calls: u64,
    pub x4b_fold_files_created: u64,
    pub x4b_fold_files_deleted: u64,
    pub x4b_fold_directories_created: u64,
    pub x4b_fold_directories_deleted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalFoldingProofV4 {
    pub fold_frames: Vec<FoldCommitmentFrameV4>,
    pub packed_opening: PackedBatchOpeningFrameV4,
}

impl GlobalFoldingProofV4 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FoldingErrorV4> {
        let mut bytes = Vec::new();
        for frame in &self.fold_frames {
            bytes.extend(super::frame_v4::FrameV4::FoldCommitment(frame.clone()).encode()?);
        }
        bytes.extend(
            super::frame_v4::FrameV4::PackedBatchOpening(self.packed_opening.clone()).encode()?,
        );
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct GlobalChainDraftV4<'a> {
    model_root: Digest,
    epoch: u64,
    global_cohort_id: u32,
    global_descriptor_digest: Digest,
    common_point: Vec<Fp2>,
    groups: Vec<GlobalProverGroupV4<'a>>,
    fixed_challenges: Option<GlobalFoldChallengesV4>,
}

trait FoldChallengeSourceV4 {
    fn next_challenge(
        &mut self,
        round_index: usize,
        line_zero: Fp2,
        line_one: Fp2,
    ) -> Result<Fp2, FoldingErrorV4>;

    fn frame_sealed(&mut self, frame: &FoldCommitmentFrameV4) -> Result<(), FoldingErrorV4>;
}

struct FixedFoldChallengeSourceV4 {
    challenges: GlobalFoldChallengesV4,
    cursor: usize,
}

impl FoldChallengeSourceV4 for FixedFoldChallengeSourceV4 {
    fn next_challenge(
        &mut self,
        round_index: usize,
        _line_zero: Fp2,
        _line_one: Fp2,
    ) -> Result<Fp2, FoldingErrorV4> {
        if self.cursor != round_index {
            return Err(FoldingErrorV4::InvalidGeometry("v4 fixed challenge order"));
        }
        let challenge = *self
            .challenges
            .folds
            .get(self.cursor)
            .ok_or(FoldingErrorV4::InvalidGeometry("v4 fixed challenge count"))?;
        self.cursor += 1;
        Ok(challenge)
    }

    fn frame_sealed(&mut self, _frame: &FoldCommitmentFrameV4) -> Result<(), FoldingErrorV4> {
        Ok(())
    }
}

struct InteractiveFoldChallengeSourceV4<'a> {
    tx: &'a mut Transcript,
}

impl FoldChallengeSourceV4 for InteractiveFoldChallengeSourceV4<'_> {
    fn next_challenge(
        &mut self,
        _round_index: usize,
        _line_zero: Fp2,
        _line_one: Fp2,
    ) -> Result<Fp2, FoldingErrorV4> {
        self.tx.append("x4_v4_global_fold_line", 32);
        Ok(self.tx.challenge_fp2())
    }

    fn frame_sealed(&mut self, frame: &FoldCommitmentFrameV4) -> Result<(), FoldingErrorV4> {
        let frame_bytes = super::frame_v4::FrameV4::FoldCommitment(frame.clone()).encode()?.len();
        let remainder = frame_bytes
            .checked_sub(32)
            .ok_or(FoldingErrorV4::InvalidGeometry("v4 fold frame line width"))?;
        self.tx.append(
            "x4_v4_global_fold_post_challenge",
            u64::try_from(remainder).map_err(|_| FoldingErrorV4::Overflow)?,
        );
        Ok(())
    }
}

trait FoldRoundCommitterV4 {
    fn commit_round(
        &mut self,
        config: CohortVerifierConfigV4,
        coefficients: &[Fp2],
        codeword: &[Fp2],
    ) -> Result<CohortTreeV4, FoldingErrorV4>;

    fn charge_metrics(&self, _metrics: &mut GlobalOpenMetricsV4) -> Result<(), FoldingErrorV4> {
        Ok(())
    }

    fn seal_finished(&mut self) {}

    fn temporary_file_state(&self) -> X4TemporaryFileStateV4 {
        X4TemporaryFileStateV4::default()
    }

    fn accelerator_control_snapshot(&self) -> Option<X4AcceleratorControlSnapshotV4> {
        None
    }
}

fn observe_lifecycle_span_v4(
    observer: &mut dyn X4LifecycleObserverV4,
    track: X4LifecycleTrackV4,
    phase: X4LifecyclePhaseV4,
    nesting: X4LifecycleNestingV4,
    span_start: bool,
    context: X4LifecycleContextV4,
    ownership: X4LegacySealedOwnershipV4,
    files: X4TemporaryFileStateV4,
) {
    let event = if span_start {
        X4LifecycleEventV4::span_start(track, phase, nesting, context, ownership, files)
    } else {
        X4LifecycleEventV4::span_end(track, phase, nesting, context, ownership, files)
    };
    observer.observe(&event);
}

struct CpuFoldRoundCommitterV4;

impl FoldRoundCommitterV4 for CpuFoldRoundCommitterV4 {
    fn commit_round(
        &mut self,
        config: CohortVerifierConfigV4,
        _coefficients: &[Fp2],
        codeword: &[Fp2],
    ) -> Result<CohortTreeV4, FoldingErrorV4> {
        CohortTreeV4::build_flat(config, vec![Some(codeword.to_vec())]).map_err(Into::into)
    }
}

struct X4bCudaFoldRoundCommitterV4<'a> {
    backend: &'a mut Backend,
    observer: &'a mut dyn X4LifecycleObserverV4,
    artifact_directory: PathBuf,
    cache_policy: OuterCachePolicyV4,
    metrics: X4bCudaCommitMetricsV4,
    reference_bytes_read: u64,
    sealed_ownership: X4LegacySealedOwnershipV4,
    temporary_files: X4TemporaryFileStateV4,
}

impl X4bCudaFoldRoundCommitterV4<'_> {
    fn observe_seal_phase(
        &mut self,
        phase: X4LifecyclePhaseV4,
        span_start: bool,
        context: X4LifecycleContextV4,
    ) {
        let ownership = self
            .sealed_ownership
            .with_accelerator_control(X4AcceleratorControlSnapshotV4::capture(self.backend));
        observe_lifecycle_span_v4(
            self.observer,
            X4LifecycleTrackV4::LegacySeal,
            phase,
            X4LifecycleNestingV4::TopLevel,
            span_start,
            context,
            ownership,
            self.temporary_files,
        );
    }
}

impl FoldRoundCommitterV4 for X4bCudaFoldRoundCommitterV4<'_> {
    fn commit_round(
        &mut self,
        config: CohortVerifierConfigV4,
        coefficients: &[Fp2],
        codeword: &[Fp2],
    ) -> Result<CohortTreeV4, FoldingErrorV4> {
        let round = config.identity.fold_round;
        let context = X4LifecycleContextV4 {
            cohort_id: Some(config.identity.cohort_id),
            fold_round: Some(round),
            ..X4LifecycleContextV4::default()
        };
        let paths = X4bCudaCohortPathsV4 {
            coefficients: self.artifact_directory.join(format!("fold-{round}-coefficients.bin")),
            oracle: self.artifact_directory.join(format!("fold-{round}-oracle.bin")),
            root: self.artifact_directory.join(format!("fold-{round}-root.bin")),
            staging_directory: self.artifact_directory.join("n4-staging"),
        };
        self.observe_seal_phase(X4LifecyclePhaseV4::CoefficientCloneAllocation, true, context);
        let cloned_coefficients = vec![Some(coefficients.to_vec())];
        self.observe_seal_phase(X4LifecyclePhaseV4::CoefficientCloneAllocation, false, context);
        let artifacts = commit_cohort_cuda_v4_instrumented(
            self.backend,
            config.clone(),
            &cloned_coefficients,
            paths,
            self.cache_policy,
            self.observer,
            self.sealed_ownership,
            &mut self.temporary_files,
        )
        .map_err(|error| FoldingErrorV4::Artifact(error.to_string()))?;
        let X4bCudaCohortArtifactsV4 { commitment, outer_cache, paths, mut metrics } = artifacts;
        if commitment.config != config {
            return Err(FoldingErrorV4::Artifact(
                "X4b fold commit returned a different verifier configuration".to_owned(),
            ));
        }
        self.observe_seal_phase(X4LifecyclePhaseV4::FullOracleComparison, true, context);
        let compared =
            verify_persisted_oracle_matches_v4(&paths.oracle, &config, &[Some(codeword)])
                .map_err(|error| FoldingErrorV4::Artifact(error.to_string()))?;
        self.observe_seal_phase(X4LifecyclePhaseV4::FullOracleComparison, false, context);
        self.observe_seal_phase(X4LifecyclePhaseV4::CpuCodewordCacheCloneBack, true, context);
        let tree = CohortTreeV4::from_accelerated_commit_parts(
            config,
            vec![Some(codeword.to_vec())],
            outer_cache,
        )?;
        let round_codeword_bytes = tree.codeword_bytes()?;
        let round_cache_bytes = tree.outer_cache_bytes()?;
        self.sealed_ownership = X4LegacySealedOwnershipV4::from_fold_payload(
            self.sealed_ownership
                .fold_codeword_bytes
                .checked_add(round_codeword_bytes)
                .ok_or(FoldingErrorV4::Overflow)?,
            self.sealed_ownership
                .fold_outer_cache_bytes
                .checked_add(round_cache_bytes)
                .ok_or(FoldingErrorV4::Overflow)?,
        )
        .ok_or(FoldingErrorV4::Overflow)?;
        self.observe_seal_phase(X4LifecyclePhaseV4::CpuCodewordCacheCloneBack, false, context);
        self.observe_seal_phase(X4LifecyclePhaseV4::FileCleanup, true, context);
        for path in [&paths.coefficients, &paths.oracle, &paths.root] {
            let bytes = std::fs::metadata(path)
                .map_err(|error| FoldingErrorV4::Artifact(error.to_string()))?
                .len();
            std::fs::remove_file(path).map_err(|error| {
                FoldingErrorV4::Artifact(format!(
                    "cannot remove response-local X4b fold artifact {}: {error}",
                    path.display()
                ))
            })?;
            self.temporary_files.record_file_deleted(bytes).ok_or(FoldingErrorV4::Overflow)?;
            metrics.files_deleted =
                metrics.files_deleted.checked_add(1).ok_or(FoldingErrorV4::Overflow)?;
        }
        self.observe_seal_phase(X4LifecyclePhaseV4::FileCleanup, false, context);
        self.metrics
            .include(&metrics)
            .map_err(|error| FoldingErrorV4::Artifact(error.to_string()))?;
        self.reference_bytes_read =
            self.reference_bytes_read.checked_add(compared).ok_or(FoldingErrorV4::Overflow)?;
        Ok(tree)
    }

    fn charge_metrics(&self, metrics: &mut GlobalOpenMetricsV4) -> Result<(), FoldingErrorV4> {
        metrics.x4b_fold_coefficient_bytes_persisted = self.metrics.coefficient_bytes_persisted;
        metrics.x4b_fold_oracle_bytes_persisted = self.metrics.oracle_bytes_persisted;
        metrics.x4b_fold_root_bytes_persisted = self.metrics.root_bytes_persisted;
        metrics.x4b_fold_reference_bytes_read = self.reference_bytes_read;
        metrics.x4b_fold_staging_bytes_read = self.metrics.staging_bytes_read;
        metrics.x4b_fold_staging_bytes_written = self.metrics.staging_bytes_written;
        metrics.x4b_fold_retained_outer_cache_bytes = self.metrics.retained_outer_cache_bytes;
        metrics.x4b_fold_expected_h2d_bytes = self.metrics.expected_h2d_bytes;
        metrics.x4b_fold_expected_d2h_bytes = self.metrics.expected_d2h_bytes;
        metrics.x4b_fold_expected_device_zeroed_bytes = self.metrics.expected_device_zeroed_bytes;
        metrics.x4b_fold_maximum_n4_tile_bytes = self.metrics.maximum_n4_tile_bytes;
        metrics.x4b_fold_page_cache_dontneed_bytes = self.metrics.page_cache_dontneed_bytes;
        metrics.x4b_fold_page_cache_advice_calls = self.metrics.page_cache_advice_calls;
        metrics.x4b_fold_files_created = self.metrics.files_created;
        metrics.x4b_fold_files_deleted = self.metrics.files_deleted;
        metrics.x4b_fold_directories_created = self.metrics.directories_created;
        metrics.x4b_fold_directories_deleted = self.metrics.directories_deleted;
        Ok(())
    }

    fn seal_finished(&mut self) {
        self.observe_seal_phase(
            X4LifecyclePhaseV4::DirectoryCleanup,
            true,
            X4LifecycleContextV4::default(),
        );
        // The response-local fold files have already been unlinked, but the
        // shared staging directory is intentionally retained until the
        // runner's post-open/post-verify cleanup.  This measured no-op records
        // the exact zero seal-window directory-deletion control.
        self.observe_seal_phase(
            X4LifecyclePhaseV4::DirectoryCleanup,
            false,
            X4LifecycleContextV4::default(),
        );
    }

    fn temporary_file_state(&self) -> X4TemporaryFileStateV4 {
        self.temporary_files
    }

    fn accelerator_control_snapshot(&self) -> Option<X4AcceleratorControlSnapshotV4> {
        Some(X4AcceleratorControlSnapshotV4::capture(self.backend))
    }
}

impl<'a> GlobalChainDraftV4<'a> {
    pub fn new(
        model_root: Digest,
        epoch: u64,
        global_cohort_id: u32,
        global_descriptor_digest: Digest,
        common_point: Vec<Fp2>,
        groups: Vec<GlobalProverGroupV4<'a>>,
        challenges: GlobalFoldChallengesV4,
    ) -> Result<Self, FoldingErrorV4> {
        if common_point.len() != challenges.folds.len() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 fixed fold challenges"));
        }
        let mut draft = Self::new_common(
            model_root,
            epoch,
            global_cohort_id,
            global_descriptor_digest,
            common_point,
            groups,
        )?;
        draft.fixed_challenges = Some(challenges);
        Ok(draft)
    }

    /// Production constructor: fold challenges are unavailable until each
    /// line message has been fixed in [`Self::seal_interactive`].
    pub fn new_interactive(
        model_root: Digest,
        epoch: u64,
        global_cohort_id: u32,
        global_descriptor_digest: Digest,
        common_point: Vec<Fp2>,
        groups: Vec<GlobalProverGroupV4<'a>>,
    ) -> Result<Self, FoldingErrorV4> {
        Self::new_common(
            model_root,
            epoch,
            global_cohort_id,
            global_descriptor_digest,
            common_point,
            groups,
        )
    }

    fn new_common(
        model_root: Digest,
        epoch: u64,
        global_cohort_id: u32,
        global_descriptor_digest: Digest,
        common_point: Vec<Fp2>,
        groups: Vec<GlobalProverGroupV4<'a>>,
    ) -> Result<Self, FoldingErrorV4> {
        if global_descriptor_digest == [0; 32]
            || groups.is_empty()
            || common_point.is_empty()
            || common_point.len() > 30
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 global chain"));
        }
        validate_prover_groups(&groups, &common_point)?;
        if global_descriptor_digest != global_descriptor_from_prover_groups(&groups) {
            return Err(FoldingErrorV4::InvalidGeometry("v4 global descriptor binding"));
        }
        Ok(Self {
            model_root,
            epoch,
            global_cohort_id,
            global_descriptor_digest,
            common_point,
            groups,
            fixed_challenges: None,
        })
    }

    /// Audit-visible rejection hook.  It returns no draws and cannot mutate
    /// the draft; the only successful query method belongs to the sealed type.
    pub fn reject_query_before_seal(&self) -> Result<(), FoldingErrorV4> {
        Err(FoldingErrorV4::EarlyQueryRejected)
    }

    pub(crate) fn into_x4c_parts(self) -> super::x4c_v4::X4cDraftPartsV4<'a> {
        super::x4c_v4::X4cDraftPartsV4 {
            model_root: self.model_root,
            epoch: self.epoch,
            global_cohort_id: self.global_cohort_id,
            global_descriptor_digest: self.global_descriptor_digest,
            common_point: self.common_point,
            groups: self.groups,
            fixed_challenges: self.fixed_challenges,
        }
    }

    pub fn seal(self) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        let challenges = self
            .fixed_challenges
            .clone()
            .ok_or(FoldingErrorV4::InvalidGeometry("v4 interactive seal required"))?;
        let mut source = FixedFoldChallengeSourceV4 { challenges, cursor: 0 };
        self.seal_with_source(&mut source, &mut CpuFoldRoundCommitterV4)
    }

    /// Fix each line message, receive its fresh verifier challenge, and only
    /// then build and fix the resulting fold root.  The complete chain is
    /// sealed before this method returns.
    pub fn seal_interactive(
        self,
        tx: &mut Transcript,
    ) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        if self.fixed_challenges.is_some() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 fixed seal is not interactive"));
        }
        let mut source = InteractiveFoldChallengeSourceV4 { tx };
        self.seal_with_source(&mut source, &mut CpuFoldRoundCommitterV4)
    }

    /// X4b production seal: transcript/challenge order is identical to
    /// [`Self::seal_interactive`], while every response-local fold cohort is
    /// committed by the exact CUDA E-NTT/N4 path and retained in the compact
    /// CPU opening representation. Query draws remain unavailable until all
    /// roots have been fixed and this method returns.
    pub fn seal_interactive_x4b_cuda(
        self,
        tx: &mut Transcript,
        backend: &mut Backend,
        artifact_directory: impl AsRef<Path>,
        cache_policy: OuterCachePolicyV4,
    ) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        let mut observer = NoopX4LifecycleObserverV4;
        self.seal_interactive_x4b_cuda_instrumented(
            tx,
            backend,
            artifact_directory,
            cache_policy,
            &mut observer,
        )
    }

    /// Legacy X4b seal with coarse host-wall lifecycle events. The transcript,
    /// roots and retained sealed representation are byte-identical to
    /// [`Self::seal_interactive_x4b_cuda`].
    pub fn seal_interactive_x4b_cuda_instrumented(
        self,
        tx: &mut Transcript,
        backend: &mut Backend,
        artifact_directory: impl AsRef<Path>,
        cache_policy: OuterCachePolicyV4,
        observer: &mut dyn X4LifecycleObserverV4,
    ) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        if self.fixed_challenges.is_some() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 fixed seal is not interactive"));
        }
        let mut source = InteractiveFoldChallengeSourceV4 { tx };
        let artifact_directory = artifact_directory.as_ref().to_path_buf();
        let directory_existed = artifact_directory.exists();
        let mut committer = X4bCudaFoldRoundCommitterV4 {
            backend,
            observer,
            artifact_directory,
            cache_policy,
            metrics: X4bCudaCommitMetricsV4::default(),
            reference_bytes_read: 0,
            sealed_ownership: X4LegacySealedOwnershipV4::default(),
            temporary_files: X4TemporaryFileStateV4::default(),
        };
        std::fs::create_dir_all(&committer.artifact_directory)
            .map_err(|error| FoldingErrorV4::Artifact(error.to_string()))?;
        if !directory_existed {
            committer.temporary_files.record_directory_created().ok_or(FoldingErrorV4::Overflow)?;
            committer.metrics.directories_created = 1;
        }
        self.seal_with_source(&mut source, &mut committer)
    }

    fn seal_with_source(
        self,
        source: &mut impl FoldChallengeSourceV4,
        committer: &mut impl FoldRoundCommitterV4,
    ) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        let max_domain_log2 = self.groups[0].cohort.commitment().config.outer_depth();
        if usize::from(max_domain_log2 - 3) != self.common_point.len() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 maximum domain/common point"));
        }
        let max_outer_len = self.groups[0].cohort.commitment().config.outer_len;
        let max_coefficient_len = max_outer_len / 8;
        let verifier_groups = self
            .groups
            .iter()
            .map(|group| GlobalVerifierGroupV4 {
                commitment: group.cohort.commitment().clone(),
                touched_slots: group.touched_slots.clone(),
                weights: group.weights.clone(),
                target_point: group.target_point.clone(),
                activation_challenge: group.activation_challenge,
            })
            .collect::<Vec<_>>();
        let mut metrics = GlobalOpenMetricsV4::default();

        let mut current_coefficients = vec![Fp2::ZERO; max_coefficient_len];
        let mut current_codeword = vec![Fp2::ZERO; max_outer_len];
        let mut current_claim = Fp2::ZERO;
        let mut activated = combine_and_activate_groups_streaming_v4(
            max_outer_len,
            &self.groups,
            &mut current_coefficients,
            &mut current_codeword,
            &mut current_claim,
            &mut metrics,
        )?;
        if activated == 0 {
            return Err(FoldingErrorV4::InvalidGeometry("v4 initial activation"));
        }

        let mut fold_frames = Vec::with_capacity(self.common_point.len());
        let mut round_trees = Vec::with_capacity(self.common_point.len());
        let mut fold_challenges = Vec::with_capacity(self.common_point.len());
        let mut input_len = max_outer_len;
        for round_index in 0..self.common_point.len() {
            let (line_zero, line_one) =
                claim_line_v4(&current_coefficients, &self.common_point[round_index + 1..])?;
            if interpolate_v4(line_zero, line_one, self.common_point[round_index]) != current_claim
            {
                return Err(FoldingErrorV4::InvalidGeometry("v4 claim-line input"));
            }
            let fold_challenge = source.next_challenge(round_index, line_zero, line_one)?;
            fold_challenges.push(fold_challenge);
            current_claim = interpolate_v4(line_zero, line_one, fold_challenge);
            current_coefficients = fold_coefficients(&current_coefficients, fold_challenge)
                .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 coefficient fold"))?;
            current_codeword = fold_codeword(&current_codeword, fold_challenge)
                .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 codeword fold"))?;
            let output_len = input_len / 2;
            activated += combine_and_activate_groups_streaming_v4(
                output_len,
                &self.groups,
                &mut current_coefficients,
                &mut current_codeword,
                &mut current_claim,
                &mut metrics,
            )?;
            metrics.folded_symbols_written = metrics
                .folded_symbols_written
                .checked_add(u64::try_from(output_len).map_err(|_| FoldingErrorV4::Overflow)?)
                .ok_or(FoldingErrorV4::Overflow)?;
            // A one-slot fold cohort retains one inner leaf digest per outer
            // coordinate plus a complete outer tree (2*n-1 digests).
            let output_len_u64 = u64::try_from(output_len).map_err(|_| FoldingErrorV4::Overflow)?;
            let round_digests = output_len_u64
                .checked_mul(3)
                .and_then(|value| value.checked_sub(1))
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.aggregate_merkle_digests_written = metrics
                .aggregate_merkle_digests_written
                .checked_add(round_digests)
                .ok_or(FoldingErrorV4::Overflow)?;

            let fold_round = u8::try_from(round_index + 1).map_err(|_| FoldingErrorV4::Overflow)?;
            let config = CohortVerifierConfigV4 {
                identity: CohortIdentityV4 {
                    cohort_id: self.global_cohort_id,
                    oracle_kind: OracleKindV4::GlobalFoldAggregate,
                    fold_round,
                },
                slot_descriptors: vec![Some(self.global_descriptor_digest)],
                outer_len: output_len,
                expected_symbol_count: 1,
            };
            let tree = committer.commit_round(config, &current_coefficients, &current_codeword)?;
            metrics.sealed_fold_codeword_bytes = metrics
                .sealed_fold_codeword_bytes
                .checked_add(
                    u64::try_from(output_len)
                        .map_err(|_| FoldingErrorV4::Overflow)?
                        .checked_mul(16)
                        .ok_or(FoldingErrorV4::Overflow)?,
                )
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.sealed_fold_outer_cache_bytes = metrics
                .sealed_fold_outer_cache_bytes
                .checked_add(tree.outer_cache_bytes()?)
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.sealed_fold_tree_count =
                metrics.sealed_fold_tree_count.checked_add(1).ok_or(FoldingErrorV4::Overflow)?;
            metrics.sealed_fold_outer_level_vectors = metrics
                .sealed_fold_outer_level_vectors
                .checked_add(u64::from(
                    tree.config().outer_depth() - tree.outer_cache_policy().bottom_levels_omitted,
                ))
                .ok_or(FoldingErrorV4::Overflow)?;
            let mut messages = vec![line_zero, line_one];
            if round_index + 1 == self.common_point.len() {
                if current_coefficients.as_slice() != [current_claim] {
                    return Err(FoldingErrorV4::InvalidGeometry("v4 final folded scalar"));
                }
                messages.push(current_claim);
            }
            let frame = FoldCommitmentFrameV4 {
                cohort_id: self.global_cohort_id,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round,
                input_log2: input_len.ilog2() as u8,
                output_log2: output_len.ilog2() as u8,
                root_digest: tree.root(),
                ordered_message_symbols: messages,
            };
            source.frame_sealed(&frame)?;
            fold_frames.push(frame);
            round_trees.push(tree);
            input_len = output_len;
        }
        if input_len != 8 || activated != self.groups.len() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 final activation schedule"));
        }
        metrics.aggregate_merkle_symbols_written = metrics.folded_symbols_written;
        committer.charge_metrics(&mut metrics)?;
        committer.seal_finished();
        metrics.serialized_fold_bytes = fold_frames.iter().try_fold(0u64, |sum, frame| {
            sum.checked_add(
                u64::try_from(
                    super::frame_v4::FrameV4::FoldCommitment(frame.clone()).encode()?.len(),
                )
                .map_err(|_| FoldingErrorV4::Overflow)?,
            )
            .ok_or(FoldingErrorV4::Overflow)
        })?;
        let mut lifecycle_ownership = X4LegacySealedOwnershipV4::from_fold_payload(
            metrics.sealed_fold_codeword_bytes,
            metrics.sealed_fold_outer_cache_bytes,
        )
        .ok_or(FoldingErrorV4::Overflow)?;
        if let Some(accelerator_control) = committer.accelerator_control_snapshot() {
            lifecycle_ownership = lifecycle_ownership.with_accelerator_control(accelerator_control);
        }
        let lifecycle_temporary_files = committer.temporary_file_state();
        Ok(SealedGlobalChainV4 {
            model_root: self.model_root,
            epoch: self.epoch,
            common_point: self.common_point,
            groups: self.groups,
            verifier_groups,
            challenges: GlobalFoldChallengesV4 { folds: fold_challenges },
            fold_frames,
            round_trees,
            metrics,
            lifecycle_ownership,
            lifecycle_temporary_files,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SealedGlobalChainV4<'a> {
    model_root: Digest,
    epoch: u64,
    common_point: Vec<Fp2>,
    groups: Vec<GlobalProverGroupV4<'a>>,
    verifier_groups: Vec<GlobalVerifierGroupV4>,
    challenges: GlobalFoldChallengesV4,
    fold_frames: Vec<FoldCommitmentFrameV4>,
    round_trees: Vec<CohortTreeV4>,
    metrics: GlobalOpenMetricsV4,
    lifecycle_ownership: X4LegacySealedOwnershipV4,
    lifecycle_temporary_files: X4TemporaryFileStateV4,
}

impl SealedGlobalChainV4<'_> {
    pub fn common_point(&self) -> &[Fp2] {
        &self.common_point
    }

    pub fn challenges(&self) -> &GlobalFoldChallengesV4 {
        &self.challenges
    }

    pub fn verifier_groups(&self) -> &[GlobalVerifierGroupV4] {
        &self.verifier_groups
    }

    pub fn fold_frames(&self) -> &[FoldCommitmentFrameV4] {
        &self.fold_frames
    }

    /// Exact logical ownership carried into lifecycle events.  This getter is
    /// intentionally read-only so a runner can bracket the runner-owned
    /// `Backend::finish_measurement` boundary without changing sealed state.
    pub const fn lifecycle_ownership(&self) -> X4LegacySealedOwnershipV4 {
        self.lifecycle_ownership
    }

    /// Exact response-local file/directory ledger at the end of seal.  The
    /// runner uses this alongside [`Self::lifecycle_ownership`] when it emits
    /// the backend-finish synchronization boundary.
    pub const fn lifecycle_temporary_files(&self) -> X4TemporaryFileStateV4 {
        self.lifecycle_temporary_files
    }

    /// Replace the copied accelerator boundary after the runner has measured
    /// and completed `Backend::finish_measurement`.  Opening instrumentation
    /// then carries that exact post-finish state at every boundary.
    pub fn set_lifecycle_accelerator_control(
        &mut self,
        accelerator_control: X4AcceleratorControlSnapshotV4,
    ) -> Result<(), FoldingErrorV4> {
        if !accelerator_control.available
            || !accelerator_control.is_consistent()
            || accelerator_control.measurement_active
            || !accelerator_control.synchronized
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 post-finish accelerator control"));
        }
        self.lifecycle_ownership =
            self.lifecycle_ownership.with_accelerator_control(accelerator_control);
        Ok(())
    }

    /// Consume the sealed state so one epoch cannot emit a second opening.
    pub fn issue_queries(
        self,
        query_draws: Vec<u64>,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4),
        FoldingErrorV4,
    > {
        let mut observer = NoopX4LifecycleObserverV4;
        self.issue_queries_instrumented(query_draws, &mut observer)
    }

    /// Consume the legacy sealed state while emitting coarse host-wall and
    /// exact logical-ownership boundaries. Nested hashing/path spans are
    /// hierarchical children of their initial/fold opening spans.
    pub fn issue_queries_instrumented(
        self,
        query_draws: Vec<u64>,
        observer: &mut dyn X4LifecycleObserverV4,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4),
        FoldingErrorV4,
    > {
        let total_started = Instant::now();
        let SealedGlobalChainV4 {
            model_root,
            epoch,
            common_point,
            groups,
            verifier_groups,
            challenges,
            fold_frames,
            round_trees,
            mut metrics,
            mut lifecycle_ownership,
            lifecycle_temporary_files,
        } = self;
        if !lifecycle_ownership.is_consistent_legacy() || !lifecycle_temporary_files.is_consistent()
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 lifecycle ownership"));
        }

        // "Query gather" is the verifier-owned schedule preparation: validate
        // the exact draw tape and gather the canonical per-cohort metadata
        // against which the opening will be assembled.
        let query_gather_started = Instant::now();
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DrawValidationSchedule,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        validate_query_draws(&query_draws, groups[0].cohort.commitment().config.outer_len)?;
        let schedule = packed_schedule_from_verifier(
            model_root,
            epoch,
            &verifier_groups,
            &fold_frames,
            query_draws,
        )?;
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DrawValidationSchedule,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        metrics.issue_queries_query_gather_wall_ns = elapsed_ns(query_gather_started)?;

        // All queried symbol/cache reads, inner-tree hashing and ordered
        // sibling-path assembly live in this coarse category.
        let hashing_path_started = Instant::now();
        let mut initial_groups = Vec::with_capacity(groups.len());
        for (group_index, group) in groups.iter().enumerate() {
            let context = X4LifecycleContextV4 {
                cohort_id: Some(group.cohort.commitment().config.identity.cohort_id),
                initial_group_index: Some(
                    u32::try_from(group_index).map_err(|_| FoldingErrorV4::Overflow)?,
                ),
                segment_index: u32::try_from(group_index).map_err(|_| FoldingErrorV4::Overflow)?,
                ..X4LifecycleContextV4::default()
            };
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InitialGroupOpening,
                X4LifecycleNestingV4::TopLevel,
                true,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InnerHashingPathAssembly,
                X4LifecycleNestingV4::Nested,
                true,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            let (opening, recompute) =
                group.cohort.open_initial_source(&schedule.query_draws, &group.touched_slots)?;
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InnerHashingPathAssembly,
                X4LifecycleNestingV4::Nested,
                false,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            accumulate_recompute_traffic(&mut metrics, recompute)?;
            initial_groups.push(opening);
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InitialGroupOpening,
                X4LifecycleNestingV4::TopLevel,
                false,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
        }
        let mut fold_rounds = Vec::with_capacity(round_trees.len());
        for (round_index, tree) in round_trees.iter().enumerate() {
            let context = X4LifecycleContextV4 {
                cohort_id: Some(tree.config().identity.cohort_id),
                fold_round: Some(tree.config().identity.fold_round),
                segment_index: u32::try_from(round_index).map_err(|_| FoldingErrorV4::Overflow)?,
                ..X4LifecycleContextV4::default()
            };
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::FoldRoundOpening,
                X4LifecycleNestingV4::TopLevel,
                true,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InnerHashingPathAssembly,
                X4LifecycleNestingV4::Nested,
                true,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            fold_rounds.push(tree.open_fold_round(&schedule.query_draws)?);
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::InnerHashingPathAssembly,
                X4LifecycleNestingV4::Nested,
                false,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
            observe_lifecycle_span_v4(
                observer,
                X4LifecycleTrackV4::LegacyOpening,
                X4LifecyclePhaseV4::FoldRoundOpening,
                X4LifecycleNestingV4::TopLevel,
                false,
                context,
                lifecycle_ownership,
                lifecycle_temporary_files,
            );
        }
        metrics.issue_queries_hashing_path_assembly_wall_ns = elapsed_ns(hashing_path_started)?;

        let encode_serialize_started = Instant::now();
        let mut packed_opening = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: [0; 32],
            initial_groups,
            fold_rounds,
        };
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::ScheduleDigestStructuralValidation,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        packed_opening.opening_schedule_digest = opening_schedule_digest_v4(&schedule)?;
        packed_opening.validate_against_schedule(&schedule)?;
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::ScheduleDigestStructuralValidation,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::CanonicalEncodeSerialization,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        metrics.serialized_packed_opening_bytes = u64::try_from(
            super::frame_v4::FrameV4::PackedBatchOpening(packed_opening.clone()).encode()?.len(),
        )
        .map_err(|_| FoldingErrorV4::Overflow)?;
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::CanonicalEncodeSerialization,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        metrics.issue_queries_encode_serialize_wall_ns = elapsed_ns(encode_serialize_started)?;

        // The historical API consumes the sealed state, so Rust otherwise
        // destroys its multi-gigabyte round trees implicitly before returning
        // to the caller. Make that lifecycle boundary explicit and measured.
        let teardown_started = Instant::now();
        let mut codeword_payloads = Vec::with_capacity(round_trees.len());
        let mut outer_cache_levels = Vec::with_capacity(round_trees.len());
        let mut remaining_tree_metadata = Vec::with_capacity(round_trees.len());
        for tree in round_trees {
            let CohortTreeLifecyclePartsV4 { config, slot_symbols, outer_cache } =
                tree.into_lifecycle_parts();
            let DenseOuterNodeCacheLifecyclePartsV4 { outer_len, policy, levels, root } =
                outer_cache.into_lifecycle_parts();
            codeword_payloads.push(slot_symbols);
            outer_cache_levels.push(levels);
            remaining_tree_metadata.push((config, outer_len, policy, root));
        }
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyCodewords,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        drop(codeword_payloads);
        let accelerator_control = lifecycle_ownership.accelerator_control;
        lifecycle_ownership = X4LegacySealedOwnershipV4::from_fold_payload(
            0,
            lifecycle_ownership.fold_outer_cache_bytes,
        )
        .ok_or(FoldingErrorV4::Overflow)?
        .with_accelerator_control(accelerator_control);
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyCodewords,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyOuterCacheLevels,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        drop(outer_cache_levels);
        lifecycle_ownership = X4LegacySealedOwnershipV4::from_fold_payload(0, 0)
            .ok_or(FoldingErrorV4::Overflow)?
            .with_accelerator_control(accelerator_control);
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyOuterCacheLevels,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyRemainingSealedState,
            X4LifecycleNestingV4::TopLevel,
            true,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        drop(remaining_tree_metadata);
        drop(groups);
        drop(common_point);
        drop(challenges);
        drop(schedule);
        observe_lifecycle_span_v4(
            observer,
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DestroyRemainingSealedState,
            X4LifecycleNestingV4::TopLevel,
            false,
            X4LifecycleContextV4::default(),
            lifecycle_ownership,
            lifecycle_temporary_files,
        );
        metrics.issue_queries_teardown_wall_ns = elapsed_ns(teardown_started)?;
        metrics.issue_queries_total_wall_ns = elapsed_ns(total_started)?;
        Ok((GlobalFoldingProofV4 { fold_frames, packed_opening }, verifier_groups, metrics))
    }

    /// Production query transition.  Exact-bit draws are unavailable until
    /// the complete fold chain has been sealed and charged above.
    pub fn issue_queries_interactive(
        self,
        tx: &mut Transcript,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4, Vec<u64>),
        FoldingErrorV4,
    > {
        let mut observer = NoopX4LifecycleObserverV4;
        self.issue_queries_interactive_instrumented(tx, &mut observer)
    }

    pub fn issue_queries_interactive_instrumented(
        self,
        tx: &mut Transcript,
        observer: &mut dyn X4LifecycleObserverV4,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4, Vec<u64>),
        FoldingErrorV4,
    > {
        let draw_width = self.groups[0].cohort.commitment().config.outer_depth();
        let draws = (0..PRODUCTION_QUERY_COUNT_V4)
            .map(|_| tx.challenge_bits(draw_width))
            .collect::<Vec<_>>();
        let (proof, groups, metrics) = self.issue_queries_instrumented(draws.clone(), observer)?;
        tx.append(
            "x4_v4_packed_opening",
            u64::try_from(
                super::frame_v4::FrameV4::PackedBatchOpening(proof.packed_opening.clone())
                    .encode()?
                    .len(),
            )
            .map_err(|_| FoldingErrorV4::Overflow)?,
        );
        Ok((proof, groups, metrics, draws))
    }
}

/// Verifier-side replay of the production interaction.  Line messages are
/// fixed before fold challenges; every fold root is fixed before exact-bit
/// queries; the packed answer is charged only after those draws.
pub fn verify_global_folding_interactive_v4(
    model_root: Digest,
    epoch: u64,
    common_point: &[Fp2],
    groups: &[GlobalVerifierGroupV4],
    proof: &GlobalFoldingProofV4,
    tx: &mut Transcript,
) -> Result<Fp2, FoldingErrorV4> {
    if proof.fold_frames.is_empty() {
        return Err(FoldingErrorV4::InvalidProof("v4 empty interactive fold chain"));
    }
    let mut folds = Vec::with_capacity(proof.fold_frames.len());
    for frame in &proof.fold_frames {
        frame.validate()?;
        tx.append("x4_v4_global_fold_line", 32);
        folds.push(tx.challenge_fp2());
        let frame_bytes = super::frame_v4::FrameV4::FoldCommitment(frame.clone()).encode()?.len();
        tx.append(
            "x4_v4_global_fold_post_challenge",
            u64::try_from(
                frame_bytes
                    .checked_sub(32)
                    .ok_or(FoldingErrorV4::InvalidProof("v4 fold frame line width"))?,
            )
            .map_err(|_| FoldingErrorV4::Overflow)?,
        );
    }
    let draw_width = proof.fold_frames[0].input_log2;
    let draws =
        (0..PRODUCTION_QUERY_COUNT_V4).map(|_| tx.challenge_bits(draw_width)).collect::<Vec<_>>();
    let accepted = verify_global_folding_v4(
        model_root,
        epoch,
        common_point,
        groups,
        &GlobalFoldChallengesV4 { folds },
        &draws,
        proof,
    )?;
    tx.append(
        "x4_v4_packed_opening",
        u64::try_from(
            super::frame_v4::FrameV4::PackedBatchOpening(proof.packed_opening.clone())
                .encode()?
                .len(),
        )
        .map_err(|_| FoldingErrorV4::Overflow)?,
    );
    Ok(accepted)
}

pub fn verify_global_folding_v4(
    model_root: Digest,
    epoch: u64,
    common_point: &[Fp2],
    groups: &[GlobalVerifierGroupV4],
    challenges: &GlobalFoldChallengesV4,
    query_draws: &[u64],
    proof: &GlobalFoldingProofV4,
) -> Result<Fp2, FoldingErrorV4> {
    validate_verifier_groups(groups, common_point)?;
    if challenges.folds.len() != common_point.len()
        || proof.fold_frames.len() != common_point.len()
        || proof.packed_opening.initial_groups.len() != groups.len()
        || proof.packed_opening.fold_rounds.len() != proof.fold_frames.len()
    {
        return Err(FoldingErrorV4::InvalidProof("v4 fold/query frame count"));
    }
    validate_query_draws(query_draws, groups[0].commitment.config.outer_len)?;
    let schedule = packed_schedule_from_verifier(
        model_root,
        epoch,
        groups,
        &proof.fold_frames,
        query_draws.to_vec(),
    )?;
    proof.packed_opening.validate_against_schedule(&schedule)?;
    for ((group, opening), expected_schedule) in
        groups.iter().zip(&proof.packed_opening.initial_groups).zip(&schedule.initial_groups)
    {
        if group.commitment.root != expected_schedule.root_digest {
            return Err(FoldingErrorV4::InvalidProof("v4 initial root schedule"));
        }
        verify_initial_packed_opening_v4(
            group.commitment.root,
            &group.commitment.config,
            query_draws,
            &group.touched_slots,
            opening,
        )?;
    }
    for ((frame, opening), round_index) in
        proof.fold_frames.iter().zip(&proof.packed_opening.fold_rounds).zip(0usize..)
    {
        frame.validate()?;
        let output_len =
            1usize.checked_shl(u32::from(frame.output_log2)).ok_or(FoldingErrorV4::Overflow)?;
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: frame.cohort_id,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: frame.fold_round,
            },
            slot_descriptors: vec![Some(global_descriptor_from_groups(groups))],
            outer_len: output_len,
            expected_symbol_count: 1,
        };
        if frame.oracle_kind != OracleKindV4::GlobalFoldAggregate
            || usize::from(frame.fold_round) != round_index + 1
            || usize::from(frame.input_log2)
                != groups[0].commitment.config.outer_depth() as usize - round_index
            || usize::from(frame.output_log2) + 1 != usize::from(frame.input_log2)
            || frame.ordered_message_symbols.len()
                != if round_index + 1 == common_point.len() { 3 } else { 2 }
        {
            return Err(FoldingErrorV4::InvalidProof("v4 fold frame schedule"));
        }
        verify_fold_round_packed_opening_v4(frame.root_digest, &config, query_draws, opening)?;
    }

    verify_query_chain(groups, challenges, query_draws, proof)?;
    let final_scalar = proof
        .fold_frames
        .last()
        .and_then(|frame| frame.ordered_message_symbols.get(2))
        .copied()
        .ok_or(FoldingErrorV4::InvalidProof("v4 final scalar"))?;
    if proof
        .packed_opening
        .fold_rounds
        .last()
        .ok_or(FoldingErrorV4::InvalidProof("v4 final opening"))?
        .opened_symbols
        .iter()
        .any(|symbol| *symbol != final_scalar)
    {
        return Err(FoldingErrorV4::InvalidProof("v4 final constant codeword"));
    }
    opened_global_value_from_lines_v4(common_point, challenges, &proof.fold_frames)
}

/// Recover the response-global value claimed at the sumcheck point.  Each
/// difference between a post-challenge line value and the next pre-fold line
/// is exactly the claim activated at that smaller domain.  The fold/query
/// proof, rather than a prover-supplied group value, binds this sum.
pub fn opened_global_value_from_lines_v4(
    common_point: &[Fp2],
    challenges: &GlobalFoldChallengesV4,
    frames: &[FoldCommitmentFrameV4],
) -> Result<Fp2, FoldingErrorV4> {
    if frames.is_empty()
        || frames.len() != common_point.len()
        || frames.len() != challenges.folds.len()
    {
        return Err(FoldingErrorV4::InvalidProof("v4 global opened-value schedule"));
    }
    let mut opened = interpolate_v4(
        frames[0].ordered_message_symbols[0],
        frames[0].ordered_message_symbols[1],
        common_point[0],
    );
    for (round_index, frame) in frames.iter().enumerate() {
        let folded = interpolate_v4(
            frame.ordered_message_symbols[0],
            frame.ordered_message_symbols[1],
            challenges.folds[round_index],
        );
        let after_activation = if round_index + 1 < frames.len() {
            interpolate_v4(
                frames[round_index + 1].ordered_message_symbols[0],
                frames[round_index + 1].ordered_message_symbols[1],
                common_point[round_index + 1],
            )
        } else {
            *frame
                .ordered_message_symbols
                .get(2)
                .ok_or(FoldingErrorV4::InvalidProof("v4 final opened-value scalar"))?
        };
        opened += after_activation - folded;
    }
    Ok(opened)
}

pub(crate) fn packed_schedule_from_verifier(
    model_root: Digest,
    epoch: u64,
    groups: &[GlobalVerifierGroupV4],
    fold_frames: &[FoldCommitmentFrameV4],
    query_draws: Vec<u64>,
) -> Result<PackedOpeningScheduleV4, FoldingErrorV4> {
    let initial_groups = groups
        .iter()
        .map(|group| -> Result<InitialOpeningScheduleV4, FoldingErrorV4> {
            Ok(InitialOpeningScheduleV4 {
                cohort_id: group.commitment.config.identity.cohort_id,
                domain_log2: group.commitment.config.outer_depth(),
                slot_count: u16::try_from(group.commitment.config.slot_descriptors.len())
                    .map_err(|_| FoldingErrorV4::Overflow)?,
                touched_slots: group.touched_slots.clone(),
                root_digest: group.commitment.root,
            })
        })
        .collect::<Result<Vec<_>, FoldingErrorV4>>()?;
    Ok(PackedOpeningScheduleV4 {
        profile_digest: profile_digest_v4(),
        model_root,
        epoch,
        initial_groups,
        fold_frames: fold_frames.to_vec(),
        draw_width: groups[0].commitment.config.outer_depth(),
        query_draws,
    })
}

fn validate_prover_groups(
    groups: &[GlobalProverGroupV4<'_>],
    common_point: &[Fp2],
) -> Result<(), FoldingErrorV4> {
    let verifier = groups
        .iter()
        .map(|group| GlobalVerifierGroupV4 {
            commitment: group.cohort.commitment().clone(),
            touched_slots: group.touched_slots.clone(),
            weights: group.weights.clone(),
            target_point: group.target_point.clone(),
            activation_challenge: group.activation_challenge,
        })
        .collect::<Vec<_>>();
    validate_verifier_groups(&verifier, common_point)
}

fn validate_verifier_groups(
    groups: &[GlobalVerifierGroupV4],
    common_point: &[Fp2],
) -> Result<(), FoldingErrorV4> {
    if groups.is_empty() || groups.len() > MAX_RESPONSE_CLAIMS_V4 {
        return Err(FoldingErrorV4::InvalidGeometry("v4 global groups"));
    }
    let mut touched_total = 0usize;
    let mut seen = BTreeSet::new();
    for (index, group) in groups.iter().enumerate() {
        group.commitment.config.validate()?;
        validate_group_geometry(
            &group.commitment,
            &group.touched_slots,
            &group.weights,
            &group.target_point,
        )?;
        touched_total =
            touched_total.checked_add(group.touched_slots.len()).ok_or(FoldingErrorV4::Overflow)?;
        if !seen.insert(group.commitment.config.identity.cohort_id) {
            return Err(FoldingErrorV4::InvalidGeometry("v4 duplicate cohort"));
        }
        let domain = group.commitment.config.outer_depth();
        if index > 0 {
            let previous = &groups[index - 1].commitment.config;
            let previous_domain = previous.outer_depth();
            if previous_domain < domain
                || (previous_domain == domain
                    && previous.identity.cohort_id >= group.commitment.config.identity.cohort_id)
            {
                return Err(FoldingErrorV4::InvalidGeometry("v4 canonical cohort order"));
            }
        }
        if usize::from(domain - 3) > common_point.len()
            || group.target_point != common_point[common_point.len() - group.target_point.len()..]
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 point suffix"));
        }
    }
    if touched_total > MAX_RESPONSE_CLAIMS_V4 {
        return Err(FoldingErrorV4::InvalidGeometry("v4 response claim union"));
    }
    Ok(())
}

fn validate_group_geometry(
    commitment: &ModelGlobalCohortCommitmentV4,
    touched_slots: &[u16],
    weights: &[Fp2],
    target_point: &[Fp2],
) -> Result<(), FoldingErrorV4> {
    commitment.config.validate()?;
    if matches!(commitment.config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate)
        || touched_slots.is_empty()
        || touched_slots.len() != weights.len()
        || !touched_slots.windows(2).all(|pair| pair[0] < pair[1])
        || target_point.len() != (commitment.config.outer_len / 8).ilog2() as usize
    {
        return Err(FoldingErrorV4::InvalidGeometry("v4 group geometry"));
    }
    for slot in touched_slots {
        if commitment.config.slot_descriptors.get(usize::from(*slot)).copied().flatten().is_none() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 touched slot"));
        }
    }
    Ok(())
}

pub(crate) fn validate_query_draws(
    draws: &[u64],
    max_outer_len: usize,
) -> Result<(), FoldingErrorV4> {
    if draws.len() != PRODUCTION_QUERY_COUNT_V4
        || draws.iter().any(|draw| *draw >= max_outer_len as u64)
    {
        return Err(FoldingErrorV4::InvalidGeometry("v4 exact query tape"));
    }
    Ok(())
}

fn elapsed_ns(started: Instant) -> Result<u64, FoldingErrorV4> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|_| FoldingErrorV4::Overflow)
}

pub(crate) fn accumulate_recompute_traffic(
    metrics: &mut GlobalOpenMetricsV4,
    traffic: SourceRecomputeTrafficV4,
) -> Result<(), FoldingErrorV4> {
    metrics.recomputed_source_bytes_read = metrics
        .recomputed_source_bytes_read
        .checked_add(traffic.source_bytes_read)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.recomputed_oracle_bytes = metrics
        .recomputed_oracle_bytes
        .checked_add(traffic.oracle_bytes_recomputed)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.recomputed_merkle_bytes = metrics
        .recomputed_merkle_bytes
        .checked_add(traffic.merkle_bytes_recomputed)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.persisted_oracle_bytes_read = metrics
        .persisted_oracle_bytes_read
        .checked_add(traffic.persisted_oracle_bytes_read)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.persisted_page_cache_dontneed_bytes = metrics
        .persisted_page_cache_dontneed_bytes
        .checked_add(traffic.persisted_page_cache_dontneed_bytes)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.persisted_page_cache_advice_calls = metrics
        .persisted_page_cache_advice_calls
        .checked_add(traffic.persisted_page_cache_advice_calls)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.outer_cache_bytes_read = metrics
        .outer_cache_bytes_read
        .checked_add(traffic.outer_cache_bytes_read)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.inner_trees_rebuilt = metrics
        .inner_trees_rebuilt
        .checked_add(traffic.inner_trees_rebuilt)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.outer_frontier_leaves_rebuilt = metrics
        .outer_frontier_leaves_rebuilt
        .checked_add(traffic.outer_frontier_leaves_rebuilt)
        .ok_or(FoldingErrorV4::Overflow)?;
    metrics.outer_internal_nodes_rebuilt = metrics
        .outer_internal_nodes_rebuilt
        .checked_add(traffic.outer_internal_nodes_rebuilt)
        .ok_or(FoldingErrorV4::Overflow)?;
    Ok(())
}

fn combine_and_activate_groups_streaming_v4(
    output_len: usize,
    groups: &[GlobalProverGroupV4<'_>],
    current_coefficients: &mut [Fp2],
    current_codeword: &mut [Fp2],
    current_claim: &mut Fp2,
    metrics: &mut GlobalOpenMetricsV4,
) -> Result<usize, FoldingErrorV4> {
    let mut activated = 0usize;
    for group in groups {
        if group.cohort.commitment().config.outer_len != output_len {
            continue;
        }
        let (initial, recompute) = group.cohort.combine_source(
            &group.touched_slots,
            &group.weights,
            &group.target_point,
        )?;
        accumulate_recompute_traffic(metrics, recompute)?;
        let touched =
            u64::try_from(group.touched_slots.len()).map_err(|_| FoldingErrorV4::Overflow)?;
        let coefficient_symbols =
            u64::try_from(initial.coefficients.len()).map_err(|_| FoldingErrorV4::Overflow)?;
        let codeword_symbols =
            u64::try_from(initial.codeword.len()).map_err(|_| FoldingErrorV4::Overflow)?;
        metrics.source_coefficients_read = metrics
            .source_coefficients_read
            .checked_add(touched.checked_mul(coefficient_symbols).ok_or(FoldingErrorV4::Overflow)?)
            .ok_or(FoldingErrorV4::Overflow)?;
        metrics.initial_encoded_symbols_read = metrics
            .initial_encoded_symbols_read
            .checked_add(touched.checked_mul(codeword_symbols).ok_or(FoldingErrorV4::Overflow)?)
            .ok_or(FoldingErrorV4::Overflow)?;
        metrics.combined_coefficient_symbols = metrics
            .combined_coefficient_symbols
            .checked_add(coefficient_symbols)
            .ok_or(FoldingErrorV4::Overflow)?;
        metrics.combined_codeword_symbols = metrics
            .combined_codeword_symbols
            .checked_add(codeword_symbols)
            .ok_or(FoldingErrorV4::Overflow)?;
        if current_coefficients.len() != initial.coefficients.len()
            || current_codeword.len() != initial.codeword.len()
        {
            return Err(FoldingErrorV4::InvalidGeometry("v4 activation domain"));
        }
        for (output, value) in current_coefficients.iter_mut().zip(&initial.coefficients) {
            *output += group.activation_challenge * *value;
        }
        for (output, value) in current_codeword.iter_mut().zip(&initial.codeword) {
            *output += group.activation_challenge * *value;
        }
        *current_claim += group.activation_challenge * initial.claimed_value;
        activated = activated.checked_add(1).ok_or(FoldingErrorV4::Overflow)?;
    }
    Ok(activated)
}

fn verify_query_chain(
    groups: &[GlobalVerifierGroupV4],
    challenges: &GlobalFoldChallengesV4,
    draws: &[u64],
    proof: &GlobalFoldingProofV4,
) -> Result<(), FoldingErrorV4> {
    let max_len = groups[0].commitment.config.outer_len;
    let mut index_sets = BTreeMap::<u8, Vec<u64>>::new();
    for group in groups {
        index_sets.entry(group.commitment.config.outer_depth()).or_insert(
            projected_query_indices(draws, group.commitment.config.outer_depth())
                .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 projected initial indices"))?,
        );
    }
    for frame in &proof.fold_frames {
        index_sets.entry(frame.output_log2).or_insert(
            projected_query_indices(draws, frame.output_log2)
                .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 projected fold indices"))?,
        );
    }

    for draw in draws {
        let mut current_len = max_len;
        for round_index in 0..challenges.folds.len() {
            let base = (*draw % current_len as u64) % (current_len as u64 / 2);
            let positive = if round_index == 0 {
                activated_initial_value_at(
                    groups,
                    &proof.packed_opening,
                    &index_sets,
                    current_len,
                    base,
                )?
            } else {
                fold_opened_symbol_at(&proof.packed_opening, &index_sets, round_index - 1, base)?
            };
            let negative_index = base + current_len as u64 / 2;
            let negative = if round_index == 0 {
                activated_initial_value_at(
                    groups,
                    &proof.packed_opening,
                    &index_sets,
                    current_len,
                    negative_index,
                )?
            } else {
                fold_opened_symbol_at(
                    &proof.packed_opening,
                    &index_sets,
                    round_index - 1,
                    negative_index,
                )?
            };
            let mut expected =
                fold_pair_v4(positive, negative, base, current_len, challenges.folds[round_index])?;
            let output_len = current_len / 2;
            expected += activated_initial_value_at(
                groups,
                &proof.packed_opening,
                &index_sets,
                output_len,
                base,
            )?;
            let actual =
                fold_opened_symbol_at(&proof.packed_opening, &index_sets, round_index, base)?;
            if actual != expected {
                return Err(FoldingErrorV4::InvalidProof("v4 queried fold relation"));
            }
            current_len = output_len;
        }
    }
    Ok(())
}

fn activated_initial_value_at(
    groups: &[GlobalVerifierGroupV4],
    opening: &PackedBatchOpeningFrameV4,
    index_sets: &BTreeMap<u8, Vec<u64>>,
    domain_len: usize,
    outer_index: u64,
) -> Result<Fp2, FoldingErrorV4> {
    let domain_log2 = domain_len.ilog2() as u8;
    let indices =
        index_sets.get(&domain_log2).ok_or(FoldingErrorV4::InvalidProof("v4 initial index set"))?;
    let Some(coordinate_position) = indices.iter().position(|index| *index == outer_index) else {
        return Err(FoldingErrorV4::InvalidProof("v4 missing initial coordinate"));
    };
    let mut value = Fp2::ZERO;
    for (group_index, group) in groups.iter().enumerate() {
        if group.commitment.config.outer_len != domain_len {
            continue;
        }
        let packed = &opening.initial_groups[group_index];
        let width = group.touched_slots.len();
        let start = coordinate_position.checked_mul(width).ok_or(FoldingErrorV4::Overflow)?;
        let aggregate = packed.opened_symbols[start..start + width]
            .iter()
            .zip(&group.weights)
            .fold(Fp2::ZERO, |sum, (symbol, weight)| sum + *weight * *symbol);
        value += group.activation_challenge * aggregate;
    }
    Ok(value)
}

fn fold_opened_symbol_at(
    opening: &PackedBatchOpeningFrameV4,
    index_sets: &BTreeMap<u8, Vec<u64>>,
    round_index: usize,
    outer_index: u64,
) -> Result<Fp2, FoldingErrorV4> {
    let round = opening
        .fold_rounds
        .get(round_index)
        .ok_or(FoldingErrorV4::InvalidProof("v4 fold opening round"))?;
    let indices = index_sets
        .get(&round.domain_log2)
        .ok_or(FoldingErrorV4::InvalidProof("v4 fold index set"))?;
    let position = indices
        .iter()
        .position(|index| *index == outer_index)
        .ok_or(FoldingErrorV4::InvalidProof("v4 missing fold coordinate"))?;
    Ok(round.opened_symbols[position])
}

fn global_descriptor_from_groups(groups: &[GlobalVerifierGroupV4]) -> Digest {
    global_fold_descriptor_digest_v4(
        &groups
            .iter()
            .map(|group| (group.commitment.config.identity.cohort_id, group.commitment.root))
            .collect::<Vec<_>>(),
    )
}

fn global_descriptor_from_prover_groups(groups: &[GlobalProverGroupV4<'_>]) -> Digest {
    global_fold_descriptor_digest_v4(
        &groups
            .iter()
            .map(|group| {
                (
                    group.cohort.commitment().config.identity.cohort_id,
                    group.cohort.commitment().root,
                )
            })
            .collect::<Vec<_>>(),
    )
}

/// Hash the already-canonical ordered `(cohort_id, root)` list that defines
/// the response-global aggregate slot.  Ordering is validated by the chain
/// constructors; the digest never accepts prover metadata from the opening.
pub fn global_fold_descriptor_digest_v4(ordered_commitments: &[(u32, Digest)]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key("volta-zk/x4/global-fold-descriptor/v4");
    for (cohort_id, root) in ordered_commitments {
        hasher.update(&cohort_id.to_le_bytes());
        hasher.update(root);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn claim_line_v4(
    coefficients: &[Fp2],
    remaining_point: &[Fp2],
) -> Result<(Fp2, Fp2), FoldingErrorV4> {
    if coefficients.len() < 2 || coefficients.len() / 2 != 1usize << remaining_point.len() {
        return Err(FoldingErrorV4::InvalidGeometry("v4 claim line"));
    }
    let mut even = Vec::with_capacity(coefficients.len() / 2);
    let mut odd = Vec::with_capacity(coefficients.len() / 2);
    for pair in coefficients.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }
    let at_zero = evaluate_multilinear_coefficients(&even, remaining_point)
        .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 claim line zero"))?;
    let odd_value = evaluate_multilinear_coefficients(&odd, remaining_point)
        .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 claim line one"))?;
    Ok((at_zero, at_zero + odd_value))
}

pub(crate) fn interpolate_v4(at_zero: Fp2, at_one: Fp2, point: Fp2) -> Fp2 {
    at_zero + point * (at_one - at_zero)
}

fn fold_pair_v4(
    positive: Fp2,
    negative: Fp2,
    base_index: u64,
    input_len: usize,
    challenge: Fp2,
) -> Result<Fp2, FoldingErrorV4> {
    let omega = root_of_unity(input_len.ilog2())
        .map_err(|_| FoldingErrorV4::InvalidGeometry("v4 fold root"))?;
    let x = super::ntt::fp2_pow(omega, u128::from(base_index));
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    let even = (positive + negative) * inverse_two;
    let odd = (positive - negative) * inverse_two * x.inv();
    Ok(even + challenge * odd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::X4LifecycleTransitionV4;

    #[derive(Default)]
    struct RecordingObserver {
        events: Vec<X4LifecycleEventV4>,
    }

    impl X4LifecycleObserverV4 for RecordingObserver {
        fn observe(&mut self, event: &X4LifecycleEventV4) {
            self.events.push(*event);
        }
    }

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 13 + 5))
    }

    fn committed(
        cohort_id: u32,
        oracle_kind: OracleKindV4,
        outer_len: usize,
        slot_count: usize,
        absent_slot: Option<usize>,
    ) -> CommittedModelGlobalCohortV4 {
        let coefficient_len = outer_len / 8;
        let slot_descriptors = (0..slot_count)
            .map(|slot| {
                if absent_slot == Some(slot) {
                    None
                } else {
                    let mut digest = [0u8; 32];
                    digest[..4].copy_from_slice(&cohort_id.to_le_bytes());
                    digest[4..8].copy_from_slice(&(slot as u32 + 1).to_le_bytes());
                    Some(digest)
                }
            })
            .collect::<Vec<_>>();
        let coefficients = slot_descriptors
            .iter()
            .enumerate()
            .map(|(slot, descriptor)| {
                descriptor.map(|_| {
                    (0..coefficient_len)
                        .map(|index| {
                            symbol(
                                10_000 * u64::from(cohort_id)
                                    + 100 * slot as u64
                                    + index as u64
                                    + 1,
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        CommittedModelGlobalCohortV4::commit(
            CohortVerifierConfigV4 {
                identity: CohortIdentityV4 { cohort_id, oracle_kind, fold_round: 0 },
                slot_descriptors,
                outer_len,
                expected_symbol_count: 1,
            },
            coefficients,
        )
        .unwrap()
    }

    fn common_point() -> Vec<Fp2> {
        [3, 5, 7, 11].into_iter().map(symbol).collect()
    }

    fn challenges() -> GlobalFoldChallengesV4 {
        GlobalFoldChallengesV4 { folds: [13, 17, 19, 23].into_iter().map(symbol).collect() }
    }

    fn query_draws() -> Vec<u64> {
        (0..PRODUCTION_QUERY_COUNT_V4).map(|index| (index % 8) as u64).collect()
    }

    fn groups<'a>(
        large: &'a CommittedModelGlobalCohortV4,
        small: &'a CommittedModelGlobalCohortV4,
    ) -> Vec<GlobalProverGroupV4<'a>> {
        let point = common_point();
        vec![
            GlobalProverGroupV4 {
                cohort: large,
                touched_slots: vec![0, 2],
                weights: vec![Fp2::ONE, symbol(29)],
                target_point: point.clone(),
                activation_challenge: symbol(31),
            },
            GlobalProverGroupV4 {
                cohort: small,
                touched_slots: vec![0, 1],
                weights: vec![Fp2::ONE, symbol(37)],
                target_point: point[2..].to_vec(),
                activation_challenge: symbol(41),
            },
        ]
    }

    fn prove(
        large: &CommittedModelGlobalCohortV4,
        small: &CommittedModelGlobalCohortV4,
    ) -> (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4) {
        let groups = groups(large, small);
        let descriptor = global_descriptor_from_prover_groups(&groups);
        let draft = GlobalChainDraftV4::new(
            [9; 32],
            77,
            0xA500_F001,
            descriptor,
            common_point(),
            groups,
            challenges(),
        )
        .unwrap();
        assert_eq!(draft.reject_query_before_seal(), Err(FoldingErrorV4::EarlyQueryRejected));
        let sealed = draft.seal().unwrap();
        assert_eq!(sealed.common_point(), common_point());
        assert_eq!(sealed.challenges(), &challenges());
        sealed.issue_queries(query_draws()).unwrap()
    }

    fn verify(
        groups: &[GlobalVerifierGroupV4],
        proof: &GlobalFoldingProofV4,
    ) -> Result<Fp2, FoldingErrorV4> {
        verify_global_folding_v4(
            [9; 32],
            77,
            &common_point(),
            groups,
            &challenges(),
            &query_draws(),
            proof,
        )
    }

    #[test]
    fn sealed_model_global_different_size_chain_accepts_once() {
        let large = committed(10, OracleKindV4::WeightExtension, 128, 4, Some(1));
        let small = committed(20, OracleKindV4::Auxiliary, 32, 2, None);
        let (proof, verifier_groups, metrics) = prove(&large, &small);
        let opened = verify(&verifier_groups, &proof).unwrap();
        assert_eq!(
            opened,
            opened_global_value_from_lines_v4(&common_point(), &challenges(), &proof.fold_frames)
                .unwrap()
        );
        assert_eq!(proof.fold_frames.len(), 4);
        assert_eq!(proof.packed_opening.initial_groups.len(), 2);
        assert_eq!(proof.packed_opening.fold_rounds.len(), 4);
        assert_eq!(proof.fold_frames.last().unwrap().output_log2, 3);
        assert_eq!(proof.fold_frames.last().unwrap().ordered_message_symbols.len(), 3);
        assert_eq!(metrics.source_coefficients_read, 40);
        assert_eq!(metrics.initial_encoded_symbols_read, 320);
        assert_eq!(metrics.folded_symbols_written, 120);
        assert_eq!(metrics.aggregate_merkle_symbols_written, 120);
        assert_eq!(metrics.sealed_fold_codeword_bytes, 120 * 16);
        assert_eq!(
            metrics.sealed_fold_outer_cache_bytes,
            ((64 - 1) + (32 - 1) + (16 - 1) + (8 - 1)) * 32
        );
        assert_eq!(metrics.sealed_fold_tree_count, 4);
        assert_eq!(metrics.sealed_fold_outer_level_vectors, 6 + 5 + 4 + 3);
        assert!(metrics.serialized_fold_bytes > 0);
        assert!(metrics.serialized_packed_opening_bytes > 0);
        assert!(metrics.issue_queries_total_wall_ns >= metrics.issue_queries_teardown_wall_ns);
        assert_eq!(proof.packed_opening.initial_groups[0].touched_slots, [0, 2]);
        assert_eq!(proof.packed_opening.initial_groups[1].touched_slots, [0, 1]);
    }

    #[test]
    fn instrumented_opening_orders_nested_spans_and_zeros_legacy_ownership() {
        let large = committed(10, OracleKindV4::WeightExtension, 128, 4, Some(1));
        let small = committed(20, OracleKindV4::Auxiliary, 32, 2, None);
        let prover_groups = groups(&large, &small);
        let descriptor = global_descriptor_from_prover_groups(&prover_groups);
        let sealed = GlobalChainDraftV4::new(
            [9; 32],
            77,
            0xA500_F001,
            descriptor,
            common_point(),
            prover_groups,
            challenges(),
        )
        .unwrap()
        .seal()
        .unwrap();
        let mut observer = RecordingObserver::default();
        let (proof, verifier_groups, _) =
            sealed.issue_queries_instrumented(query_draws(), &mut observer).unwrap();
        assert!(verify(&verifier_groups, &proof).is_ok());
        let (plain_proof, plain_verifier_groups, _) = prove(&large, &small);
        assert_eq!(proof, plain_proof);
        assert_eq!(verifier_groups, plain_verifier_groups);
        assert!(!observer.events.is_empty());

        let mut stack = Vec::new();
        for event in &observer.events {
            assert_eq!(event.track, X4LifecycleTrackV4::LegacyOpening);
            assert!(event.sealed_ownership.is_consistent_legacy());
            assert_eq!(event.sealed_ownership.pinned_host_bytes, 0);
            assert_eq!(event.sealed_ownership.device_bytes, 0);
            assert_eq!(event.sealed_ownership.file_backed_bytes, 0);
            assert_eq!(event.sealed_ownership.owned_files, 0);
            assert_eq!(event.sealed_ownership.owned_mappings, 0);
            assert_eq!(event.temporary_files, X4TemporaryFileStateV4::default());
            match event.transition {
                X4LifecycleTransitionV4::SpanStart => {
                    stack.push((event.phase, event.nesting));
                }
                X4LifecycleTransitionV4::SpanEnd => {
                    assert_eq!(stack.pop(), Some((event.phase, event.nesting)));
                }
                X4LifecycleTransitionV4::Boundary => {
                    panic!("opening instrumentation emitted an unexpected instant boundary");
                }
            }
        }
        assert!(stack.is_empty());

        let starts = observer
            .events
            .iter()
            .filter(|event| {
                event.transition == X4LifecycleTransitionV4::SpanStart
                    && event.nesting == X4LifecycleNestingV4::TopLevel
            })
            .map(|event| event.phase)
            .collect::<Vec<_>>();
        assert_eq!(starts.first(), Some(&X4LifecyclePhaseV4::DrawValidationSchedule));
        assert_eq!(
            &starts[starts.len() - 5..],
            &[
                X4LifecyclePhaseV4::ScheduleDigestStructuralValidation,
                X4LifecyclePhaseV4::CanonicalEncodeSerialization,
                X4LifecyclePhaseV4::DestroyCodewords,
                X4LifecyclePhaseV4::DestroyOuterCacheLevels,
                X4LifecyclePhaseV4::DestroyRemainingSealedState,
            ]
        );
        assert_eq!(
            observer
                .events
                .iter()
                .filter(|event| {
                    event.phase == X4LifecyclePhaseV4::InnerHashingPathAssembly
                        && event.transition == X4LifecycleTransitionV4::SpanStart
                })
                .count(),
            6
        );

        let destroy_codewords_end = observer
            .events
            .iter()
            .find(|event| {
                event.phase == X4LifecyclePhaseV4::DestroyCodewords
                    && event.transition == X4LifecycleTransitionV4::SpanEnd
            })
            .unwrap();
        assert_eq!(destroy_codewords_end.sealed_ownership.fold_codeword_bytes, 0);
        assert!(destroy_codewords_end.sealed_ownership.fold_outer_cache_bytes > 0);
        let destroy_cache_end = observer
            .events
            .iter()
            .find(|event| {
                event.phase == X4LifecyclePhaseV4::DestroyOuterCacheLevels
                    && event.transition == X4LifecycleTransitionV4::SpanEnd
            })
            .unwrap();
        assert_eq!(destroy_cache_end.sealed_ownership.accounted_ordinary_host_bytes, 0);
    }

    #[test]
    fn descriptor_order_activation_and_query_schedule_tampers_reject() {
        let large = committed(10, OracleKindV4::WeightExtension, 128, 4, Some(1));
        let small = committed(20, OracleKindV4::Auxiliary, 32, 2, None);
        let prover_groups = groups(&large, &small);
        let mut wrong_descriptor = global_descriptor_from_prover_groups(&prover_groups);
        wrong_descriptor[0] ^= 1;
        assert!(GlobalChainDraftV4::new(
            [9; 32],
            77,
            0xA500_F001,
            wrong_descriptor,
            common_point(),
            prover_groups,
            challenges(),
        )
        .is_err());

        let (proof, verifier_groups, _) = prove(&large, &small);
        let mut swapped = verifier_groups.clone();
        swapped.swap(0, 1);
        assert!(verify(&swapped, &proof).is_err());
        let mut bad = verifier_groups.clone();
        bad[1].activation_challenge += Fp2::ONE;
        assert!(verify(&bad, &proof).is_err());
        let mut bad = verifier_groups.clone();
        bad[0].touched_slots = vec![0, 3];
        assert!(verify(&bad, &proof).is_err());

        let mut bad_draws = query_draws();
        bad_draws.pop();
        assert!(verify_global_folding_v4(
            [9; 32],
            77,
            &common_point(),
            &verifier_groups,
            &challenges(),
            &bad_draws,
            &proof,
        )
        .is_err());
        let mut reordered = query_draws();
        reordered.swap(0, 1);
        assert!(verify_global_folding_v4(
            [9; 32],
            77,
            &common_point(),
            &verifier_groups,
            &challenges(),
            &reordered,
            &proof,
        )
        .is_err());
    }

    #[test]
    fn packed_symbols_siblings_fold_messages_and_roots_tamper_reject() {
        let large = committed(10, OracleKindV4::WeightExtension, 128, 4, Some(1));
        let small = committed(20, OracleKindV4::Auxiliary, 32, 2, None);
        let (proof, verifier_groups, _) = prove(&large, &small);

        let mut bad = proof.clone();
        bad.packed_opening.initial_groups[0].opened_symbols[0] += Fp2::ONE;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.packed_opening.initial_groups[0].inner_sibling_digests[0][0] ^= 1;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.packed_opening.initial_groups[0].outer_sibling_digests[0][0] ^= 1;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.packed_opening.fold_rounds[0].opened_symbols[0] += Fp2::ONE;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.packed_opening.fold_rounds[0].outer_sibling_digests[0][0] ^= 1;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.fold_frames[0].ordered_message_symbols[0] += Fp2::ONE;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof.clone();
        bad.fold_frames[0].root_digest[0] ^= 1;
        assert!(verify(&verifier_groups, &bad).is_err());
        let mut bad = proof;
        bad.packed_opening.opening_schedule_digest[0] ^= 1;
        assert!(verify(&verifier_groups, &bad).is_err());
    }
}
