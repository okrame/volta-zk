//! Schema-4 streaming/recompute policy and exact G6 logical counters.
//!
//! The recompute source retains canonical coefficients plus the pinned root.
//! The global prover rebuilds and root-checks one model-global cohort for its
//! aggregate contribution, discards it, and rebuilds it once more after the
//! sealed exact-bit query tape to emit the initial packed frontier.  These two
//! materializations are both counted; measured RSS remains a record field.

use volta_field::Fp2;

use super::folding_v4::{
    CombinedInitialV4, CommittedModelGlobalCohortV4, FoldingErrorV4, ModelGlobalCohortCommitmentV4,
    ModelGlobalOpeningSourceV4, SourceRecomputeTrafficV4,
};
use super::frame_v4::InitialOpeningGroupV4;
use super::merkle_v4::CohortVerifierConfigV4;

const SYMBOL_BYTES_V4: u64 = 16;
const DIGEST_BYTES_V4: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V4ArtifactPolicy {
    PersistOracleAndMerkle,
    RecomputeOracleAndMerkle,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V4CohortArtifactPlan {
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
    pub recomputed_bytes_per_materialization: u64,
    pub recomputed_bytes_per_response: u64,
    pub logical_commit_working_set_bytes: u64,
}

impl V4CohortArtifactPlan {
    pub fn new(
        config: &CohortVerifierConfigV4,
        policy: V4ArtifactPolicy,
    ) -> Result<Self, FoldingErrorV4> {
        config.validate()?;
        if config.identity.fold_round != 0 || config.expected_symbol_count != 1 {
            return Err(FoldingErrorV4::InvalidGeometry("v4 artifact round-zero cohort"));
        }
        let present_slots = u64::try_from(config.slot_descriptors.iter().flatten().count())
            .map_err(|_| FoldingErrorV4::Overflow)?;
        let structural_slots =
            u64::try_from(config.slot_descriptors.len()).map_err(|_| FoldingErrorV4::Overflow)?;
        let outer_len = u64::try_from(config.outer_len).map_err(|_| FoldingErrorV4::Overflow)?;
        let coefficient_symbols =
            present_slots.checked_mul(outer_len / 8).ok_or(FoldingErrorV4::Overflow)?;
        let logical_first_oracle_symbols =
            present_slots.checked_mul(outer_len).ok_or(FoldingErrorV4::Overflow)?;
        let inner_per_coordinate = structural_slots
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FoldingErrorV4::Overflow)?;
        let inner_merkle_digests =
            outer_len.checked_mul(inner_per_coordinate).ok_or(FoldingErrorV4::Overflow)?;
        let outer_merkle_digests = outer_len
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .ok_or(FoldingErrorV4::Overflow)?;
        let coefficient_bytes =
            coefficient_symbols.checked_mul(SYMBOL_BYTES_V4).ok_or(FoldingErrorV4::Overflow)?;
        let logical_first_oracle_bytes = logical_first_oracle_symbols
            .checked_mul(SYMBOL_BYTES_V4)
            .ok_or(FoldingErrorV4::Overflow)?;
        let merkle_digest_bytes = inner_merkle_digests
            .checked_add(outer_merkle_digests)
            .and_then(|value| value.checked_mul(DIGEST_BYTES_V4))
            .ok_or(FoldingErrorV4::Overflow)?;
        let root_bytes = DIGEST_BYTES_V4;
        let retained_logical_payload_bytes = match policy {
            V4ArtifactPolicy::PersistOracleAndMerkle => coefficient_bytes
                .checked_add(
                    logical_first_oracle_bytes.checked_mul(2).ok_or(FoldingErrorV4::Overflow)?,
                )
                .and_then(|value| value.checked_add(merkle_digest_bytes))
                .and_then(|value| value.checked_add(root_bytes))
                .ok_or(FoldingErrorV4::Overflow)?,
            V4ArtifactPolicy::RecomputeOracleAndMerkle => {
                coefficient_bytes.checked_add(root_bytes).ok_or(FoldingErrorV4::Overflow)?
            }
        };
        let recomputed_bytes_per_materialization = match policy {
            V4ArtifactPolicy::PersistOracleAndMerkle => 0,
            V4ArtifactPolicy::RecomputeOracleAndMerkle => logical_first_oracle_bytes
                .checked_add(merkle_digest_bytes)
                .ok_or(FoldingErrorV4::Overflow)?,
        };
        let recomputed_bytes_per_response =
            recomputed_bytes_per_materialization.checked_mul(2).ok_or(FoldingErrorV4::Overflow)?;
        let logical_commit_working_set_bytes = coefficient_bytes
            .checked_mul(2)
            .and_then(|value| value.checked_add(logical_first_oracle_bytes.checked_mul(2)?))
            .and_then(|value| value.checked_add(merkle_digest_bytes))
            .ok_or(FoldingErrorV4::Overflow)?;
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
            recomputed_bytes_per_materialization,
            recomputed_bytes_per_response,
            logical_commit_working_set_bytes,
        })
    }
}

#[derive(Debug)]
pub struct RecomputableModelGlobalCohortV4 {
    commitment: ModelGlobalCohortCommitmentV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    retained: Option<CommittedModelGlobalCohortV4>,
    policy: V4ArtifactPolicy,
    plan: V4CohortArtifactPlan,
}

impl RecomputableModelGlobalCohortV4 {
    pub fn commit(
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
        policy: V4ArtifactPolicy,
    ) -> Result<Self, FoldingErrorV4> {
        let plan = V4CohortArtifactPlan::new(&config, policy)?;
        let committed = CommittedModelGlobalCohortV4::commit(config, coefficients.clone())?;
        let commitment = committed.commitment().clone();
        let retained = match policy {
            V4ArtifactPolicy::PersistOracleAndMerkle => Some(committed),
            V4ArtifactPolicy::RecomputeOracleAndMerkle => None,
        };
        Ok(Self { commitment, coefficients, retained, policy, plan })
    }

    pub fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        &self.commitment
    }

    pub fn policy(&self) -> V4ArtifactPolicy {
        self.policy
    }

    pub fn artifact_plan(&self) -> &V4CohortArtifactPlan {
        &self.plan
    }

    fn traffic(&self) -> SourceRecomputeTrafficV4 {
        match self.policy {
            V4ArtifactPolicy::PersistOracleAndMerkle => SourceRecomputeTrafficV4::default(),
            V4ArtifactPolicy::RecomputeOracleAndMerkle => SourceRecomputeTrafficV4 {
                source_bytes_read: self.plan.coefficient_bytes,
                oracle_bytes_recomputed: self.plan.logical_first_oracle_bytes,
                merkle_bytes_recomputed: self.plan.merkle_digest_bytes,
            },
        }
    }

    fn rebuild(&self) -> Result<CommittedModelGlobalCohortV4, FoldingErrorV4> {
        let rebuilt = CommittedModelGlobalCohortV4::commit(
            self.commitment.config.clone(),
            self.coefficients.clone(),
        )?;
        if rebuilt.commitment().root != self.commitment.root {
            return Err(FoldingErrorV4::InvalidProof("v4 recomputed cohort root"));
        }
        Ok(rebuilt)
    }
}

impl ModelGlobalOpeningSourceV4 for RecomputableModelGlobalCohortV4 {
    fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        self.commitment()
    }

    fn combine_source(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<(CombinedInitialV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        if let Some(retained) = &self.retained {
            return Ok((
                retained.combine(touched_slots, weights, target_point)?,
                SourceRecomputeTrafficV4::default(),
            ));
        }
        let rebuilt = self.rebuild()?;
        Ok((rebuilt.combine(touched_slots, weights, target_point)?, self.traffic()))
    }

    fn open_initial_source(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(InitialOpeningGroupV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        if let Some(retained) = &self.retained {
            return retained.open_initial_source(query_draws, touched_slots);
        }
        let rebuilt = self.rebuild()?;
        let (opening, _) = rebuilt.open_initial_source(query_draws, touched_slots)?;
        Ok((opening, self.traffic()))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct V4StreamingCommitMetrics {
    pub cohort_count: u64,
    pub coefficient_bytes: u64,
    pub logical_first_oracle_bytes: u64,
    pub merkle_digest_bytes: u64,
    pub retained_logical_payload_bytes: u64,
    pub response_recomputed_bytes: u64,
    pub maximum_cohort_working_set_bytes: u64,
}

impl V4StreamingCommitMetrics {
    pub fn include(&mut self, plan: &V4CohortArtifactPlan) -> Result<(), FoldingErrorV4> {
        self.cohort_count = self.cohort_count.checked_add(1).ok_or(FoldingErrorV4::Overflow)?;
        self.coefficient_bytes = self
            .coefficient_bytes
            .checked_add(plan.coefficient_bytes)
            .ok_or(FoldingErrorV4::Overflow)?;
        self.logical_first_oracle_bytes = self
            .logical_first_oracle_bytes
            .checked_add(plan.logical_first_oracle_bytes)
            .ok_or(FoldingErrorV4::Overflow)?;
        self.merkle_digest_bytes = self
            .merkle_digest_bytes
            .checked_add(plan.merkle_digest_bytes)
            .ok_or(FoldingErrorV4::Overflow)?;
        self.retained_logical_payload_bytes = self
            .retained_logical_payload_bytes
            .checked_add(plan.retained_logical_payload_bytes)
            .ok_or(FoldingErrorV4::Overflow)?;
        self.response_recomputed_bytes = self
            .response_recomputed_bytes
            .checked_add(plan.recomputed_bytes_per_response)
            .ok_or(FoldingErrorV4::Overflow)?;
        self.maximum_cohort_working_set_bytes =
            self.maximum_cohort_working_set_bytes.max(plan.logical_commit_working_set_bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::folding_v4::{
        global_fold_descriptor_digest_v4, verify_global_folding_interactive_v4, GlobalChainDraftV4,
        GlobalProverGroupV4,
    };
    use crate::x4::frame_v4::OracleKindV4;
    use crate::x4::merkle_v4::CohortIdentityV4;
    use crate::x4::ntt::multilinear_coefficients;
    use volta_field::Fp;
    use volta_mac::Transcript;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(5 * value + 1))
    }

    fn config() -> CohortVerifierConfigV4 {
        CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xA500_0123,
                oracle_kind: OracleKindV4::Auxiliary,
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

    fn prove(
        source: &dyn ModelGlobalOpeningSourceV4,
    ) -> (
        super::super::folding_v4::GlobalFoldingProofV4,
        super::super::folding_v4::GlobalOpenMetricsV4,
    ) {
        let point = vec![symbol(3), symbol(5), symbol(7), symbol(11)];
        let groups = vec![GlobalProverGroupV4 {
            cohort: source,
            touched_slots: vec![0, 2],
            weights: vec![symbol(13), symbol(17)],
            target_point: point.clone(),
            activation_challenge: symbol(19),
        }];
        let descriptor = global_fold_descriptor_digest_v4(&[(
            source.commitment().config.identity.cohort_id,
            source.commitment().root,
        )]);
        let mut prover_tx = Transcript::new([0xB7; 32]);
        let sealed = GlobalChainDraftV4::new_interactive(
            [0xA5; 32],
            9,
            0xA500_F001,
            descriptor,
            point.clone(),
            groups,
        )
        .unwrap()
        .seal_interactive(&mut prover_tx)
        .unwrap();
        let (proof, verifier_groups, metrics, _) =
            sealed.issue_queries_interactive(&mut prover_tx).unwrap();
        let mut verifier_tx = Transcript::new([0xB7; 32]);
        verify_global_folding_interactive_v4(
            [0xA5; 32],
            9,
            &point,
            &verifier_groups,
            &proof,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
        (proof, metrics)
    }

    #[test]
    fn persisted_and_twice_recomputed_sources_emit_identical_global_proofs() {
        let persisted = RecomputableModelGlobalCohortV4::commit(
            config(),
            coefficients(),
            V4ArtifactPolicy::PersistOracleAndMerkle,
        )
        .unwrap();
        let recomputed = RecomputableModelGlobalCohortV4::commit(
            config(),
            coefficients(),
            V4ArtifactPolicy::RecomputeOracleAndMerkle,
        )
        .unwrap();
        assert_eq!(persisted.commitment().root, recomputed.commitment().root);
        let (persisted_proof, persisted_metrics) = prove(&persisted);
        let (recomputed_proof, recomputed_metrics) = prove(&recomputed);
        assert_eq!(persisted_proof, recomputed_proof);
        assert_eq!(persisted_metrics.recomputed_oracle_bytes, 0);
        assert_eq!(persisted_metrics.recomputed_merkle_bytes, 0);
        assert_eq!(
            recomputed_metrics.recomputed_source_bytes_read,
            2 * recomputed.artifact_plan().coefficient_bytes
        );
        assert_eq!(
            recomputed_metrics.recomputed_oracle_bytes,
            2 * recomputed.artifact_plan().logical_first_oracle_bytes
        );
        assert_eq!(
            recomputed_metrics.recomputed_merkle_bytes,
            2 * recomputed.artifact_plan().merkle_digest_bytes
        );
    }

    #[test]
    fn v4_g6_plan_counts_model_global_tree_and_streaming_peak_exactly() {
        let persisted =
            V4CohortArtifactPlan::new(&config(), V4ArtifactPolicy::PersistOracleAndMerkle).unwrap();
        let recomputed =
            V4CohortArtifactPlan::new(&config(), V4ArtifactPolicy::RecomputeOracleAndMerkle)
                .unwrap();
        assert_eq!(persisted.present_slots, 2);
        assert_eq!(persisted.structural_slots, 4);
        assert_eq!(persisted.coefficient_symbols, 32);
        assert_eq!(persisted.logical_first_oracle_symbols, 256);
        assert_eq!(persisted.inner_merkle_digests, 128 * 7);
        assert_eq!(persisted.outer_merkle_digests, 255);
        assert_eq!(recomputed.retained_logical_payload_bytes, recomputed.coefficient_bytes + 32);
        assert_eq!(
            recomputed.recomputed_bytes_per_response,
            2 * (recomputed.logical_first_oracle_bytes + recomputed.merkle_digest_bytes)
        );
        let mut streaming = V4StreamingCommitMetrics::default();
        streaming.include(&persisted).unwrap();
        streaming.include(&recomputed).unwrap();
        assert_eq!(streaming.cohort_count, 2);
        assert_eq!(
            streaming.maximum_cohort_working_set_bytes,
            persisted.logical_commit_working_set_bytes
        );
        assert_ne!(
            streaming.maximum_cohort_working_set_bytes,
            persisted.logical_commit_working_set_bytes
                + recomputed.logical_commit_working_set_bytes
        );
    }
}
