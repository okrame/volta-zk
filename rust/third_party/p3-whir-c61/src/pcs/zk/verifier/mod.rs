//! HVZK-WHIR verifier.
//!
//! ```text
//!     masked sumcheck batches -> code-switching rounds -> masked base case
//! ```
//!
//! The carried claim is tracked symbolically throughout.

mod masks;

use alloc::vec;
use alloc::vec::Vec;

use masks::VerifierMasks;
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_field::{ExtensionField, TwoAdicField, dot_product};
use p3_matrix::Dimensions;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::SumcheckError;
use p3_sumcheck::zk::{AffineClaim, ZkVerifier};
use thiserror::Error;
use tracing::instrument;

use super::base_case::{
    BaseCaseClaimlessClosure, BaseCaseZkConfig, BaseCaseZkError, BaseCaseZkVerifier,
};
use super::code_switch::{
    CodeSwitchError, ZkMaskClaim, accumulate_randomness_query_covector, switch_mask_covector,
};
use super::config::ZkWhirConfig;
use super::constraint::SourceClaim;
use super::proof::ZkWhirProof;
use super::{NoZkWhirInitialOracleLink, ZkWhirInitialOracleLink};
use crate::pcs::proof::QueryOpenings;
use crate::pcs::utils::get_challenge_stir_queries;

/// Failure modes of the HVZK-WHIR verifier.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ZkVerifierError {
    /// A masked sumcheck batch failed to replay.
    #[error(transparent)]
    Sumcheck(#[from] SumcheckError),

    /// The base case rejected.
    #[error(transparent)]
    BaseCase(#[from] BaseCaseZkError),

    /// A batched-claim dimension mismatch.
    #[error(transparent)]
    CodeSwitch(#[from] CodeSwitchError),

    /// An opening point has the wrong arity for the committed polynomial.
    #[error("claim {claim}: point arity mismatch: expected {expected}, got {actual}")]
    ClaimArityMismatch { claim: usize, expected: usize, actual: usize },

    /// The proof carries the wrong number of code-switching rounds.
    #[error("round count mismatch: expected {expected}, got {actual}")]
    RoundCountMismatch { expected: usize, actual: usize },

    /// The proof carries the wrong number of sumcheck batches.
    #[error("sumcheck batch count mismatch: expected {expected}, got {actual}")]
    SumcheckBatchCountMismatch { expected: usize, actual: usize },

    /// A round carries the wrong number of out-of-domain answers.
    #[error("round {round}: OOD answer count mismatch: expected {expected}, got {actual}")]
    OodAnswerCountMismatch { round: usize, expected: usize, actual: usize },

    /// A round carries the wrong number of query openings.
    #[error("round {round}: query count mismatch: expected {expected}, got {actual}")]
    QueryCountMismatch { round: usize, expected: usize, actual: usize },

    /// C6.1 admits one bounded ordered batch of authenticated opening
    /// targets per chain.
    #[error("claimless point count mismatch: expected 1..=128, got {actual}")]
    ClaimlessPointCountMismatch { actual: usize },

    /// A Merkle multi-opening failed to verify.
    #[error("merkle verification failed in round {round}")]
    MerkleVerificationFailed { round: usize },

    /// A round failed its proof-of-work check.
    #[error("invalid proof-of-work witness in round {round}")]
    InvalidPowWitness { round: usize },

    /// The opt-in initial-oracle link was absent or appeared on the wrong
    /// proof shape.
    #[error("initial-oracle link opening is missing")]
    InitialOracleLinkMissing,

    /// The link must expose one mask value per initial STIR query.
    #[error("initial-oracle link query count mismatch: expected {expected}, got {actual}")]
    InitialOracleLinkQueryCountMismatch { expected: usize, actual: usize },
}

/// The commitment a code-switch round opens against.
enum ActiveOracle<'a, C> {
    /// Base-field initial oracle.
    Base(&'a C),
    /// Extension-field folded oracle.
    Ext(&'a C),
}

/// Public result of a complete claimless verifier replay.  The caller lifts
/// `target` onto its designated MAC key and closes `base_case` with C6AWH1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimlessWhirVerifierClosure<EF> {
    /// Powers of the post-commitment batching challenge.  The designated
    /// verifier uses these public coefficients to aggregate the individual
    /// target keys before applying the affine closure.
    pub claim_weights: Vec<EF>,
    pub target: AffineClaim<EF>,
    pub base_case: BaseCaseClaimlessClosure<EF>,
}

/// HVZK-WHIR verifier.
#[derive(Debug)]
pub struct HidingWhirVerifier<'a, EF, F, MT, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    MT: Mmcs<F>,
{
    /// Derived HVZK configuration.
    pub config: &'a ZkWhirConfig<EF, F, Challenger>,
    /// Base-field Merkle commitment scheme.
    pub mmcs: &'a MT,
    /// Extension-field commitment scheme for folded oracles and masks.
    pub extension_mmcs: ExtensionMmcs<F, EF, MT>,
}

impl<'a, EF, F, MT, Challenger> HidingWhirVerifier<'a, EF, F, MT, Challenger>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    MT: Mmcs<F>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + CanSampleUniformBits<F>
        + CanObserve<MT::Commitment>,
{
    /// Bundles the verifier dependencies.
    pub fn new(config: &'a ZkWhirConfig<EF, F, Challenger>, mmcs: &'a MT) -> Self {
        Self { config, mmcs, extension_mmcs: ExtensionMmcs::new(mmcs.clone()) }
    }

    /// Verify one opening point without receiving or absorbing its target.
    #[instrument(skip_all)]
    #[allow(clippy::too_many_lines)]
    pub fn verify_claimless(
        &self,
        proof: &ZkWhirProof<F, EF, MT>,
        commitment: &MT::Commitment,
        points: &[Point<EF>],
        challenger: &mut Challenger,
    ) -> Result<ClaimlessWhirVerifierClosure<EF>, ZkVerifierError> {
        self.verify_claimless_inner(
            proof,
            commitment,
            points,
            &NoZkWhirInitialOracleLink,
            challenger,
        )
    }

    /// Verifies a claimless proof with an opt-in first-oracle decomposition.
    /// The historical method above keeps using the no-link mode.
    #[instrument(skip_all)]
    pub fn verify_claimless_with_initial_link<L>(
        &self,
        proof: &ZkWhirProof<F, EF, MT>,
        commitment: &MT::Commitment,
        points: &[Point<EF>],
        initial_link: &L,
        challenger: &mut Challenger,
    ) -> Result<ClaimlessWhirVerifierClosure<EF>, ZkVerifierError>
    where
        L: ZkWhirInitialOracleLink<F, EF, MT>,
    {
        self.verify_claimless_inner(proof, commitment, points, initial_link, challenger)
    }

    #[allow(clippy::too_many_lines)]
    fn verify_claimless_inner<L>(
        &self,
        proof: &ZkWhirProof<F, EF, MT>,
        commitment: &MT::Commitment,
        points: &[Point<EF>],
        initial_link: &L,
        challenger: &mut Challenger,
    ) -> Result<ClaimlessWhirVerifierClosure<EF>, ZkVerifierError>
    where
        L: ZkWhirInitialOracleLink<F, EF, MT>,
    {
        let config = self.config;
        let n_rounds = config.n_rounds();

        // Structural checks before any transcript work.
        if proof.rounds.len() != n_rounds {
            return Err(ZkVerifierError::RoundCountMismatch {
                expected: n_rounds,
                actual: proof.rounds.len(),
            });
        }
        // One sumcheck transcript and one interleaved mask commitment per
        // batch; check each count on its own so the error names the culprit.
        if proof.sumchecks.len() != n_rounds + 1 {
            return Err(ZkVerifierError::SumcheckBatchCountMismatch {
                expected: n_rounds + 1,
                actual: proof.sumchecks.len(),
            });
        }
        if proof.sumcheck_mask_commitments.len() != n_rounds + 1 {
            return Err(ZkVerifierError::SumcheckBatchCountMismatch {
                expected: n_rounds + 1,
                actual: proof.sumcheck_mask_commitments.len(),
            });
        }

        if points.is_empty() || points.len() > 128 {
            return Err(ZkVerifierError::ClaimlessPointCountMismatch { actual: points.len() });
        }

        // Reject malformed statements before any folding arithmetic runs.
        //
        //     point arity != committed arity  ->  error, never a panic
        for (claim, point) in points.iter().enumerate() {
            if point.num_variables() != self.config.num_variables {
                return Err(ZkVerifierError::ClaimArityMismatch {
                    claim,
                    expected: self.config.num_variables,
                    actual: point.num_variables(),
                });
            }
        }

        // Reduce the ordered point batch with one fresh post-commitment
        // alpha, while never materializing any opening value on the verifier
        // role.  The same coefficients aggregate the designated target keys.
        let alpha: EF = challenger.sample_algebra_element();
        let claim_weights: Vec<EF> = alpha.powers().collect_n(points.len());
        let mut source = SourceClaim::new();
        for (point, coefficient) in points.iter().cloned().zip(claim_weights.iter().copied()) {
            source.push_eq(point, coefficient);
        }
        let mut target = AffineClaim::identity();
        let mut masks = VerifierMasks::new();

        // Initial masked sumcheck batch.
        let mut randomness = self.replay_sumcheck_batch(
            proof,
            0,
            config.round_folding_factor(0),
            config.starting_folding_pow_bits,
            &mut target,
            &mut source,
            &mut masks,
            challenger,
        )?;

        let mut active = ActiveOracle::Base(commitment);
        let mut num_variables = config.num_variables - config.round_folding_factor(0);

        // Code-switching rounds.
        for round in 0..n_rounds {
            let round_params = &config.round_parameters[round];
            let round_proof = &proof.rounds[round];
            let folding = config.round_folding_factor(round);
            let folding_next = config.round_folding_factor(round + 1);

            // New oracle and code-switch mask commitments.
            let new_commitment = &round_proof.commitment;
            challenger.observe(new_commitment.clone());
            let mask_commitment = &round_proof.mask_commitment;
            challenger.observe(mask_commitment.clone());

            // Private out-of-domain answers.
            if round_proof.ood_answers.len() != round_params.ood_samples {
                return Err(ZkVerifierError::OodAnswerCountMismatch {
                    round,
                    expected: round_params.ood_samples,
                    actual: round_proof.ood_answers.len(),
                });
            }
            let mut rho_points = Vec::with_capacity(round_params.ood_samples);
            for &answer in &round_proof.ood_answers {
                let rho: EF = challenger.sample_algebra_element();
                challenger.observe_algebra_element(answer);
                rho_points.push(rho);
            }

            // PoW, transcript checkpoint, STIR queries on the previous oracle.
            if round_params.pow_bits > 0
                && !challenger.check_witness(round_params.pow_bits, round_proof.pow_witness)
            {
                return Err(ZkVerifierError::InvalidPowWitness { round });
            }
            challenger.sample();
            let stir_indexes = get_challenge_stir_queries::<Challenger, F>(
                round_params.domain_size,
                folding,
                round_params.num_queries,
                challenger,
            );
            // Authenticate the leaves in one multiproof and fold them at the
            // batch randomness.
            let dims = vec![Dimensions {
                height: round_params.domain_size >> folding,
                width: 1 << folding,
            }];
            let folded_values = self.verify_and_fold_leaves(
                &active,
                &dims,
                &stir_indexes,
                &round_proof.openings,
                round,
                &randomness,
            )?;
            let linked_mask_values = (round == 0)
                .then(|| {
                    initial_link.folded_mask_values(
                        &round_proof.openings,
                        &stir_indexes,
                        &randomness,
                    )
                })
                .flatten();
            if round == 0 && initial_link.required() && linked_mask_values.is_none() {
                return Err(ZkVerifierError::InitialOracleLinkMissing);
            }
            if let Some(values) = &linked_mask_values {
                if values.len() != stir_indexes.len() {
                    return Err(ZkVerifierError::InitialOracleLinkQueryCountMismatch {
                        expected: stir_indexes.len(),
                        actual: values.len(),
                    });
                }
            }
            let query_points: Vec<EF> = stir_indexes
                .iter()
                .map(|&index| EF::from(round_params.folded_domain_gen.exp_u64(index as u64)))
                .collect();

            // Batch the carried claim with the fresh constraints.
            let combination: EF = challenger.sample_algebra_element();
            let link_queries = linked_mask_values.as_ref().map_or(0, Vec::len);
            let coeffs: Vec<EF> = combination
                .shifted_powers(combination)
                .collect_n(rho_points.len() + query_points.len() + link_queries);
            let (ood_coeffs, rest) = coeffs.split_at(rho_points.len());
            let (query_coeffs, link_coeffs) = rest.split_at(query_points.len());

            let mask_claim = ZkMaskClaim {
                base_claim_coeff: EF::ONE,
                ood_coeffs: ood_coeffs.to_vec(),
                in_domain_coeffs: query_coeffs.to_vec(),
            };
            let mut public_offset =
                mask_claim.batched_claim(EF::ZERO, &round_proof.ood_answers, &folded_values)?;
            if let Some(values) = &linked_mask_values {
                public_offset +=
                    dot_product::<EF, _, _>(link_coeffs.iter().copied(), values.iter().copied());
            }
            target = target.add_public(public_offset);

            // Source side: fresh power constraints over the new message.
            for (&rho, &coeff) in rho_points.iter().zip(ood_coeffs) {
                source.push_pow(rho, num_variables, coeff);
            }
            for (&x, &coeff) in query_points.iter().zip(query_coeffs) {
                source.push_pow(x, num_variables, coeff);
            }

            // Mask side: the fresh code-switch mask enters the relation as
            // its own width-one group.
            let mut mask_covector = switch_mask_covector(
                1 << num_variables,
                config.oracle_randomness[round],
                round_params.ood_samples,
                &rho_points,
                ood_coeffs,
                &query_points,
                query_coeffs,
            );
            if !link_coeffs.is_empty() {
                accumulate_randomness_query_covector(
                    &mut mask_covector,
                    1 << num_variables,
                    config.oracle_randomness[round],
                    &query_points,
                    link_coeffs,
                );
            }
            masks.push_switch_mask(
                mask_covector,
                config.switch_masks[round],
                mask_commitment.clone(),
            );

            // Next masked sumcheck batch over the new oracle.
            randomness = self.replay_sumcheck_batch(
                proof,
                round + 1,
                folding_next,
                round_params.folding_pow_bits,
                &mut target,
                &mut source,
                &mut masks,
                challenger,
            )?;

            active = ActiveOracle::Ext(new_commitment);
            num_variables -= folding_next;
        }

        // Masked base case on the virtual folded oracle.
        let final_config = config.final_round_config();
        let source_code = super::committer::FoldedRsCode::<F>::new(
            1 << final_config.num_variables,
            config.oracle_randomness[n_rounds],
            final_config.domain_size >> final_config.folding_factor,
        );
        let base_config = BaseCaseZkConfig {
            code: source_code,
            mask_groups: masks.groups,
            num_queries: config.final_queries,
            mask_queries: config.mask_queries,
            pow_bits: config.final_pow_bits,
        };
        let base_verifier =
            BaseCaseZkVerifier { config: &base_config, extension_mmcs: &self.extension_mmcs };

        let source_covector = source.materialize(final_config.num_variables);
        let dims = vec![Dimensions {
            height: final_config.domain_size >> final_config.folding_factor,
            width: 1 << final_config.folding_factor,
        }];
        let base_case = base_verifier.verify_claimless(
            &proof.base_case,
            source_covector.as_slice(),
            &masks.claims.covectors,
            &masks.commitments,
            |positions, openings| {
                self.verify_and_fold_leaves(
                    &active,
                    &dims,
                    positions,
                    openings,
                    n_rounds,
                    &randomness,
                )
                .map_err(|_| BaseCaseZkError::SourceOpeningsRejected)
            },
            challenger,
        )?;

        Ok(ClaimlessWhirVerifierClosure { claim_weights, target, base_case })
    }

    /// Replays one masked sumcheck batch and updates the carried relation.
    ///
    /// Returns the batch's folding randomness.
    #[allow(clippy::too_many_arguments)]
    fn replay_sumcheck_batch(
        &self,
        proof: &ZkWhirProof<F, EF, MT>,
        batch: usize,
        folding: usize,
        pow_bits: usize,
        target: &mut AffineClaim<EF>,
        source: &mut SourceClaim<EF>,
        masks: &mut VerifierMasks<F, EF, MT>,
        challenger: &mut Challenger,
    ) -> Result<Point<EF>, ZkVerifierError> {
        let ell_zk = self.config.zk.ell_zk;
        let commitment = &proof.sumcheck_mask_commitments[batch];
        let handoff = ZkVerifier::<F, EF>::verify_affine_claim::<ExtensionMmcs<F, EF, MT>, _>(
            &proof.sumchecks[batch],
            commitment,
            ell_zk,
            folding,
            pow_bits,
            *target,
            challenger,
        )?;

        // Source constraints fold, then absorb the combining challenge.
        source.fold(&handoff.randomness);
        for constraint in &mut source.constraints {
            constraint.coeff *= handoff.eps;
        }
        // Mask side: carried covectors absorb eps * 2^{-k}, the batch's fresh
        // sumcheck masks enter at scale one.
        masks.record_sumcheck_batch(
            handoff.eps,
            folding,
            ell_zk,
            &handoff.randomness,
            self.config.sumcheck_mask,
            commitment.clone(),
        );

        *target = handoff.claimed_residual;
        Ok(handoff.randomness)
    }

    /// Authenticates every leaf of the active oracle in one multiproof and
    /// folds each at the batch randomness.
    ///
    /// Base-field leaves fold through the mixed-field evaluator, so no lift
    /// to the extension is materialized.
    ///
    /// The variant must match the oracle: a base oracle carries base rows,
    /// an extension oracle carries extension rows. A disagreement is rejected.
    fn verify_and_fold_leaves(
        &self,
        active: &ActiveOracle<'_, MT::Commitment>,
        dims: &[Dimensions],
        indices: &[usize],
        openings: &QueryOpenings<F, EF, MT::MultiProof>,
        round: usize,
        randomness: &Point<EF>,
    ) -> Result<Vec<EF>, ZkVerifierError> {
        let width = dims.first().map_or(0, |d| d.width);
        let reject = || ZkVerifierError::MerkleVerificationFailed { round };

        // One opened row per sampled index, each of the committed leaf width.
        let check_shape = |rows: &[usize]| {
            if rows.len() != indices.len() {
                return Err(ZkVerifierError::QueryCountMismatch {
                    round,
                    expected: indices.len(),
                    actual: rows.len(),
                });
            }
            if rows.iter().any(|&len| len != width) {
                return Err(reject());
            }
            Ok(())
        };

        match (active, openings) {
            (ActiveOracle::Base(commitment), QueryOpenings::Base(opening)) => {
                check_shape(&opening.rows.iter().map(Vec::len).collect::<Vec<_>>())?;
                opening.verify(self.mmcs, commitment, dims, indices).map_err(|_| reject())?;
                // Mixed-field fold: base leaves at an extension point.
                Ok(opening
                    .rows
                    .iter()
                    .map(|row| Poly::new(row.clone()).eval_base(randomness))
                    .collect())
            }
            (ActiveOracle::Ext(commitment), QueryOpenings::Extension(opening)) => {
                check_shape(&opening.rows.iter().map(Vec::len).collect::<Vec<_>>())?;
                opening
                    .verify(&self.extension_mmcs, commitment, dims, indices)
                    .map_err(|_| reject())?;
                Ok(opening
                    .rows
                    .iter()
                    .map(|row| Poly::new(row.clone()).eval_ext::<F>(randomness))
                    .collect())
            }
            _ => Err(reject()),
        }
    }
}
