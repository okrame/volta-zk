//! Explicit X4 artifact policy and G6 accounting.
//!
//! The recompute policy persists only canonical coefficients plus the root and
//! rebuilds the rate-1/8 oracle and N4 Merkle authentication for an opening.
//! Cohorts are committed sequentially, so the logical working set is the
//! largest cohort rather than the sum of all model cohorts.  Measured RSS and
//! device memory remain record fields; these counters do not substitute for
//! OS/GPU measurements.

use volta_field::Fp2;

use super::folding::{
    FoldingError, UdChallenges, UdCohortCommitment, UdCommittedCohort, UdFoldingProof,
    UdOpenMetrics, UdWeightedOpeningSource,
};
use super::merkle::CohortVerifierConfig;

const SYMBOL_BYTES: u64 = 16;
const DIGEST_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdArtifactPolicy {
    /// Retain the in-memory oracle and authentication tree.  This is useful
    /// for small synthetic fixtures and is not a claim of a disk format.
    PersistOracleAndMerkle,
    /// Retain canonical coefficients and the root; rebuild oracle/tree per
    /// opening, one cohort at a time.
    RecomputeOracleAndMerkle,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdCohortArtifactPlan {
    pub present_slots: u64,
    pub structural_slots: u64,
    pub coefficient_symbols: u64,
    pub logical_first_oracle_symbols: u64,
    pub inner_merkle_digests: u64,
    pub outer_merkle_digests: u64,
    pub coefficient_bytes: u64,
    pub logical_first_oracle_bytes: u64,
    pub merkle_digest_bytes: u64,
    pub root_bytes: u64,
    pub retained_logical_payload_bytes: u64,
    pub recomputed_bytes_per_open: u64,
    pub logical_commit_working_set_bytes: u64,
}

impl UdCohortArtifactPlan {
    pub fn new(
        config: &CohortVerifierConfig,
        policy: UdArtifactPolicy,
    ) -> Result<Self, FoldingError> {
        config.validate()?;
        if config.identity.fold_round != 0 || config.expected_symbol_count != 1 {
            return Err(FoldingError::InvalidGeometry("artifact plan round-zero cohort"));
        }
        let present_slots = u64::try_from(config.slot_descriptors.iter().flatten().count())
            .map_err(|_| FoldingError::Overflow)?;
        let structural_slots =
            u64::try_from(config.slot_descriptors.len()).map_err(|_| FoldingError::Overflow)?;
        let outer_len = u64::try_from(config.outer_len).map_err(|_| FoldingError::Overflow)?;
        let coefficient_symbols =
            present_slots.checked_mul(outer_len / 8).ok_or(FoldingError::Overflow)?;
        let logical_first_oracle_symbols =
            present_slots.checked_mul(outer_len).ok_or(FoldingError::Overflow)?;
        let inner_tree_digests_per_coordinate = structural_slots
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FoldingError::Overflow)?;
        let inner_merkle_digests = outer_len
            .checked_mul(inner_tree_digests_per_coordinate)
            .ok_or(FoldingError::Overflow)?;
        let outer_merkle_digests = outer_len
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FoldingError::Overflow)?;
        let coefficient_bytes =
            coefficient_symbols.checked_mul(SYMBOL_BYTES).ok_or(FoldingError::Overflow)?;
        let logical_first_oracle_bytes =
            logical_first_oracle_symbols.checked_mul(SYMBOL_BYTES).ok_or(FoldingError::Overflow)?;
        let merkle_digest_bytes = inner_merkle_digests
            .checked_add(outer_merkle_digests)
            .and_then(|value| value.checked_mul(DIGEST_BYTES))
            .ok_or(FoldingError::Overflow)?;
        let root_bytes = DIGEST_BYTES;
        let retained_logical_payload_bytes = match policy {
            UdArtifactPolicy::PersistOracleAndMerkle => coefficient_bytes
                .checked_add(
                    logical_first_oracle_bytes.checked_mul(2).ok_or(FoldingError::Overflow)?,
                )
                .and_then(|value| value.checked_add(merkle_digest_bytes))
                .and_then(|value| value.checked_add(root_bytes))
                .ok_or(FoldingError::Overflow)?,
            UdArtifactPolicy::RecomputeOracleAndMerkle => {
                coefficient_bytes.checked_add(root_bytes).ok_or(FoldingError::Overflow)?
            }
        };
        let recomputed_bytes_per_open = match policy {
            UdArtifactPolicy::PersistOracleAndMerkle => 0,
            UdArtifactPolicy::RecomputeOracleAndMerkle => logical_first_oracle_bytes
                .checked_add(merkle_digest_bytes)
                .ok_or(FoldingError::Overflow)?,
        };
        // The current CPU reference creates one encoded copy for folding and
        // one inside the cohort tree.  This exact logical payload is reported
        // alongside measured RSS, which also includes allocator overhead.
        let logical_commit_working_set_bytes = coefficient_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(logical_first_oracle_bytes.checked_mul(2)?))
            .and_then(|value| value.checked_add(merkle_digest_bytes))
            .ok_or(FoldingError::Overflow)?;
        Ok(Self {
            present_slots,
            structural_slots,
            coefficient_symbols,
            logical_first_oracle_symbols,
            inner_merkle_digests,
            outer_merkle_digests,
            coefficient_bytes,
            logical_first_oracle_bytes,
            merkle_digest_bytes,
            root_bytes,
            retained_logical_payload_bytes,
            recomputed_bytes_per_open,
            logical_commit_working_set_bytes,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdArtifactTraffic {
    pub source_bytes_read: u64,
    pub oracle_bytes_read: u64,
    pub merkle_bytes_read: u64,
    pub recomputed_oracle_bytes: u64,
    pub recomputed_merkle_bytes: u64,
    pub folded_oracle_bytes_written: u64,
    pub serialized_bytes_written: u64,
}

pub struct UdRecomputableCohort {
    commitment: UdCohortCommitment,
    coefficients: Vec<Option<Vec<Fp2>>>,
    retained: Option<UdCommittedCohort>,
    policy: UdArtifactPolicy,
    plan: UdCohortArtifactPlan,
}

impl UdRecomputableCohort {
    pub fn commit(
        config: CohortVerifierConfig,
        coefficients: Vec<Option<Vec<Fp2>>>,
        policy: UdArtifactPolicy,
    ) -> Result<Self, FoldingError> {
        let plan = UdCohortArtifactPlan::new(&config, policy)?;
        let committed = UdCommittedCohort::commit(config, coefficients.clone())?;
        let commitment = committed.commitment().clone();
        let retained = match policy {
            UdArtifactPolicy::PersistOracleAndMerkle => Some(committed),
            UdArtifactPolicy::RecomputeOracleAndMerkle => None,
        };
        Ok(Self { commitment, coefficients, retained, policy, plan })
    }

    pub fn commitment(&self) -> &UdCohortCommitment {
        &self.commitment
    }

    pub fn policy(&self) -> UdArtifactPolicy {
        self.policy
    }

    pub fn artifact_plan(&self) -> &UdCohortArtifactPlan {
        &self.plan
    }

    pub fn open_weighted(
        &self,
        touched_slots: &[u16],
        common_point: &[Fp2],
        weights: &[Fp2],
        challenges: &UdChallenges,
        expected_query_count: usize,
    ) -> Result<(UdFoldingProof, UdOpenMetrics, UdArtifactTraffic), FoldingError> {
        let rebuilt;
        let cohort = if let Some(retained) = &self.retained {
            retained
        } else {
            rebuilt = UdCommittedCohort::commit(
                self.commitment.config.clone(),
                self.coefficients.clone(),
            )?;
            if rebuilt.commitment().root != self.commitment.root {
                return Err(FoldingError::InvalidProof("recomputed cohort root"));
            }
            &rebuilt
        };
        let (proof, metrics) = cohort.open_weighted(
            touched_slots,
            common_point,
            weights,
            challenges,
            expected_query_count,
        )?;
        let serialized_bytes_written = metrics
            .serialized_fold_bytes
            .checked_add(metrics.serialized_query_bytes)
            .ok_or(FoldingError::Overflow)?;
        let folded_oracle_bytes_written = metrics
            .folded_symbols_written
            .checked_mul(SYMBOL_BYTES)
            .ok_or(FoldingError::Overflow)?;
        let (recomputed_oracle_bytes, recomputed_merkle_bytes) = match self.policy {
            UdArtifactPolicy::PersistOracleAndMerkle => (0, 0),
            UdArtifactPolicy::RecomputeOracleAndMerkle => {
                (self.plan.logical_first_oracle_bytes, self.plan.merkle_digest_bytes)
            }
        };
        let traffic = UdArtifactTraffic {
            source_bytes_read: metrics
                .source_coefficients_read
                .checked_mul(SYMBOL_BYTES)
                .and_then(|value| {
                    value.checked_add(if recomputed_oracle_bytes == 0 {
                        0
                    } else {
                        self.plan.coefficient_bytes
                    })
                })
                .ok_or(FoldingError::Overflow)?,
            oracle_bytes_read: metrics
                .initial_encoded_symbols_read
                .checked_mul(SYMBOL_BYTES)
                .ok_or(FoldingError::Overflow)?,
            merkle_bytes_read: metrics.serialized_query_bytes,
            recomputed_oracle_bytes,
            recomputed_merkle_bytes,
            folded_oracle_bytes_written,
            serialized_bytes_written,
        };
        Ok((proof, metrics, traffic))
    }
}

impl UdWeightedOpeningSource for UdRecomputableCohort {
    fn commitment(&self) -> &UdCohortCommitment {
        self.commitment()
    }

    fn open_weighted_source(
        &self,
        touched_slots: &[u16],
        common_point: &[Fp2],
        weights: &[Fp2],
        challenges: &UdChallenges,
        expected_query_count: usize,
    ) -> Result<(UdFoldingProof, UdOpenMetrics), FoldingError> {
        let (proof, metrics, _) = self.open_weighted(
            touched_slots,
            common_point,
            weights,
            challenges,
            expected_query_count,
        )?;
        Ok((proof, metrics))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdStreamingCommitMetrics {
    pub cohort_count: u64,
    pub coefficient_bytes: u64,
    pub logical_first_oracle_bytes: u64,
    pub merkle_digest_bytes: u64,
    pub retained_logical_payload_bytes: u64,
    pub maximum_cohort_working_set_bytes: u64,
}

impl UdStreamingCommitMetrics {
    pub fn include(&mut self, plan: &UdCohortArtifactPlan) -> Result<(), FoldingError> {
        self.cohort_count = self.cohort_count.checked_add(1).ok_or(FoldingError::Overflow)?;
        self.coefficient_bytes = self
            .coefficient_bytes
            .checked_add(plan.coefficient_bytes)
            .ok_or(FoldingError::Overflow)?;
        self.logical_first_oracle_bytes = self
            .logical_first_oracle_bytes
            .checked_add(plan.logical_first_oracle_bytes)
            .ok_or(FoldingError::Overflow)?;
        self.merkle_digest_bytes = self
            .merkle_digest_bytes
            .checked_add(plan.merkle_digest_bytes)
            .ok_or(FoldingError::Overflow)?;
        self.retained_logical_payload_bytes = self
            .retained_logical_payload_bytes
            .checked_add(plan.retained_logical_payload_bytes)
            .ok_or(FoldingError::Overflow)?;
        self.maximum_cohort_working_set_bytes =
            self.maximum_cohort_working_set_bytes.max(plan.logical_commit_working_set_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::folding::verify_ud_folding_weighted;
    use crate::x4::frame::OracleKind;
    use crate::x4::merkle::CohortIdentity;
    use crate::x4::ntt::multilinear_coefficients;
    use volta_field::Fp;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(5 * value + 1))
    }

    fn config() -> CohortVerifierConfig {
        CohortVerifierConfig {
            identity: CohortIdentity {
                cohort_id: 91,
                oracle_kind: OracleKind::Auxiliary,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), None, Some([3; 32]), None],
            outer_len: 128,
            expected_symbol_count: 1,
        }
    }

    fn coefficients() -> Vec<Option<Vec<Fp2>>> {
        let first = (0..16).map(|index| symbol(index + 1)).collect::<Vec<_>>();
        let second = (0..16).map(|index| symbol(100 + index)).collect::<Vec<_>>();
        vec![
            Some(multilinear_coefficients(&first).unwrap()),
            None,
            Some(multilinear_coefficients(&second).unwrap()),
            None,
        ]
    }

    #[test]
    fn persist_and_recompute_paths_have_identical_roots_and_proofs() {
        let persisted = UdRecomputableCohort::commit(
            config(),
            coefficients(),
            UdArtifactPolicy::PersistOracleAndMerkle,
        )
        .unwrap();
        let recomputed = UdRecomputableCohort::commit(
            config(),
            coefficients(),
            UdArtifactPolicy::RecomputeOracleAndMerkle,
        )
        .unwrap();
        assert_eq!(persisted.commitment().root, recomputed.commitment().root);
        let point = vec![symbol(3), symbol(5), symbol(7), symbol(11)];
        let weights = vec![symbol(13), symbol(17)];
        let touched = vec![0, 2];
        let challenges = UdChallenges {
            combine: Fp2::ZERO,
            folds: vec![symbol(19), symbol(23), symbol(29), symbol(31)],
            query_draws: vec![0, 1, 7, 31, 64, 65, 95, 127],
        };
        let (persisted_proof, _, persisted_traffic) =
            persisted.open_weighted(&touched, &point, &weights, &challenges, 8).unwrap();
        let (recomputed_proof, _, recomputed_traffic) =
            recomputed.open_weighted(&touched, &point, &weights, &challenges, 8).unwrap();
        assert_eq!(persisted_proof, recomputed_proof);
        assert_eq!(persisted_traffic.recomputed_oracle_bytes, 0);
        assert_eq!(recomputed_traffic.recomputed_oracle_bytes, 4096);
        verify_ud_folding_weighted(
            recomputed.commitment(),
            &touched,
            &point,
            &weights,
            &challenges,
            8,
            &recomputed_proof,
        )
        .unwrap();
    }

    #[test]
    fn g6_plan_counts_two_dimensional_tree_and_streaming_peak_exactly() {
        let persist =
            UdCohortArtifactPlan::new(&config(), UdArtifactPolicy::PersistOracleAndMerkle).unwrap();
        let recompute =
            UdCohortArtifactPlan::new(&config(), UdArtifactPolicy::RecomputeOracleAndMerkle)
                .unwrap();
        assert_eq!(persist.present_slots, 2);
        assert_eq!(persist.structural_slots, 4);
        assert_eq!(persist.coefficient_symbols, 32);
        assert_eq!(persist.logical_first_oracle_symbols, 256);
        assert_eq!(persist.inner_merkle_digests, 128 * 7);
        assert_eq!(persist.outer_merkle_digests, 255);
        assert_eq!(recompute.retained_logical_payload_bytes, recompute.coefficient_bytes + 32);
        assert_eq!(
            recompute.recomputed_bytes_per_open,
            recompute.logical_first_oracle_bytes + recompute.merkle_digest_bytes
        );

        let mut streaming = UdStreamingCommitMetrics::default();
        streaming.include(&persist).unwrap();
        streaming.include(&recompute).unwrap();
        assert_eq!(streaming.cohort_count, 2);
        assert_eq!(
            streaming.maximum_cohort_working_set_bytes,
            persist.logical_commit_working_set_bytes
        );
        assert_ne!(
            streaming.maximum_cohort_working_set_bytes,
            persist.logical_commit_working_set_bytes + recompute.logical_commit_working_set_bytes
        );
    }
}
