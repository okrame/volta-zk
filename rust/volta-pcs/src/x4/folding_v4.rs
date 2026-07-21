//! Model-global, different-size zkDeepFold-UD chain for schema 4.
//!
//! Initial cohorts are fixed and canonically ordered before the fold and
//! activation challenges.  [`GlobalChainDraftV4::seal`] computes every fold
//! commitment; only the resulting [`SealedGlobalChainV4`] can consume the
//! exact 111-query tape and emit the single packed opening.

use std::collections::{BTreeMap, BTreeSet};

use volta_field::{Fp, Fp2};
use volta_mac::Transcript;

use super::accounting::projected_query_indices;
use super::frame::{Digest, FrameError};
use super::frame_v4::{
    opening_schedule_digest_v4, profile_digest_v4, FoldCommitmentFrameV4, InitialOpeningScheduleV4,
    OracleKindV4, PackedBatchOpeningFrameV4, PackedOpeningScheduleV4, PRODUCTION_QUERY_COUNT_V4,
};
use super::merkle::MerkleError;
use super::merkle_v4::{
    verify_fold_round_packed_opening_v4, verify_initial_packed_opening_v4, CohortIdentityV4,
    CohortTreeV4, CohortVerifierConfigV4,
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
        Ok((
            self.tree.open_initial(query_draws, touched_slots)?,
            SourceRecomputeTrafficV4::default(),
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
    pub serialized_fold_bytes: u64,
    pub serialized_packed_opening_bytes: u64,
    pub recomputed_source_bytes_read: u64,
    pub recomputed_oracle_bytes: u64,
    pub recomputed_merkle_bytes: u64,
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

    pub fn seal(self) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        let challenges = self
            .fixed_challenges
            .clone()
            .ok_or(FoldingErrorV4::InvalidGeometry("v4 interactive seal required"))?;
        let mut source = FixedFoldChallengeSourceV4 { challenges, cursor: 0 };
        self.seal_with_source(&mut source)
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
        self.seal_with_source(&mut source)
    }

    fn seal_with_source(
        self,
        source: &mut impl FoldChallengeSourceV4,
    ) -> Result<SealedGlobalChainV4<'a>, FoldingErrorV4> {
        let max_domain_log2 = self.groups[0].cohort.commitment().config.outer_depth();
        if usize::from(max_domain_log2 - 3) != self.common_point.len() {
            return Err(FoldingErrorV4::InvalidGeometry("v4 maximum domain/common point"));
        }
        let max_outer_len = self.groups[0].cohort.commitment().config.outer_len;
        let max_coefficient_len = max_outer_len / 8;
        let mut combined = Vec::with_capacity(self.groups.len());
        let mut verifier_groups = Vec::with_capacity(self.groups.len());
        let mut metrics = GlobalOpenMetricsV4::default();
        for group in &self.groups {
            let (value, recompute) = group.cohort.combine_source(
                &group.touched_slots,
                &group.weights,
                &group.target_point,
            )?;
            accumulate_recompute_traffic(&mut metrics, recompute)?;
            let touched =
                u64::try_from(group.touched_slots.len()).map_err(|_| FoldingErrorV4::Overflow)?;
            metrics.source_coefficients_read = metrics
                .source_coefficients_read
                .checked_add(
                    touched
                        .checked_mul(
                            u64::try_from(value.coefficients.len())
                                .map_err(|_| FoldingErrorV4::Overflow)?,
                        )
                        .ok_or(FoldingErrorV4::Overflow)?,
                )
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.initial_encoded_symbols_read = metrics
                .initial_encoded_symbols_read
                .checked_add(
                    touched
                        .checked_mul(
                            u64::try_from(value.codeword.len())
                                .map_err(|_| FoldingErrorV4::Overflow)?,
                        )
                        .ok_or(FoldingErrorV4::Overflow)?,
                )
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.combined_coefficient_symbols = metrics
                .combined_coefficient_symbols
                .checked_add(
                    u64::try_from(value.coefficients.len())
                        .map_err(|_| FoldingErrorV4::Overflow)?,
                )
                .ok_or(FoldingErrorV4::Overflow)?;
            metrics.combined_codeword_symbols = metrics
                .combined_codeword_symbols
                .checked_add(
                    u64::try_from(value.codeword.len()).map_err(|_| FoldingErrorV4::Overflow)?,
                )
                .ok_or(FoldingErrorV4::Overflow)?;
            verifier_groups.push(GlobalVerifierGroupV4 {
                commitment: group.cohort.commitment().clone(),
                touched_slots: group.touched_slots.clone(),
                weights: group.weights.clone(),
                target_point: group.target_point.clone(),
                activation_challenge: group.activation_challenge,
            });
            combined.push(value);
        }

        let mut current_coefficients = vec![Fp2::ZERO; max_coefficient_len];
        let mut current_codeword = vec![Fp2::ZERO; max_outer_len];
        let mut current_claim = Fp2::ZERO;
        activate_groups(
            max_outer_len,
            &self.groups,
            &combined,
            &mut current_coefficients,
            &mut current_codeword,
            &mut current_claim,
        )?;
        let mut activated = self
            .groups
            .iter()
            .filter(|group| group.cohort.commitment().config.outer_len == max_outer_len)
            .count();
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
            activate_groups(
                output_len,
                &self.groups,
                &combined,
                &mut current_coefficients,
                &mut current_codeword,
                &mut current_claim,
            )?;
            activated += self
                .groups
                .iter()
                .filter(|group| group.cohort.commitment().config.outer_len == output_len)
                .count();
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
            let tree = CohortTreeV4::build_flat(config, vec![Some(current_codeword.clone())])?;
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
        metrics.serialized_fold_bytes = fold_frames.iter().try_fold(0u64, |sum, frame| {
            sum.checked_add(
                u64::try_from(
                    super::frame_v4::FrameV4::FoldCommitment(frame.clone()).encode()?.len(),
                )
                .map_err(|_| FoldingErrorV4::Overflow)?,
            )
            .ok_or(FoldingErrorV4::Overflow)
        })?;
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

    /// Consume the sealed state so one epoch cannot emit a second opening.
    pub fn issue_queries(
        mut self,
        query_draws: Vec<u64>,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, GlobalOpenMetricsV4),
        FoldingErrorV4,
    > {
        validate_query_draws(&query_draws, self.groups[0].cohort.commitment().config.outer_len)?;
        let mut initial_groups = Vec::with_capacity(self.groups.len());
        for group in &self.groups {
            let (opening, recompute) =
                group.cohort.open_initial_source(&query_draws, &group.touched_slots)?;
            accumulate_recompute_traffic(&mut self.metrics, recompute)?;
            initial_groups.push(opening);
        }
        let mut fold_rounds = Vec::with_capacity(self.round_trees.len());
        for tree in &self.round_trees {
            fold_rounds.push(tree.open_fold_round(&query_draws)?);
        }
        let schedule = packed_schedule_from_verifier(
            self.model_root,
            self.epoch,
            &self.verifier_groups,
            &self.fold_frames,
            query_draws,
        )?;
        let mut packed_opening = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: [0; 32],
            initial_groups,
            fold_rounds,
        };
        packed_opening.opening_schedule_digest = opening_schedule_digest_v4(&schedule)?;
        packed_opening.validate_against_schedule(&schedule)?;
        self.metrics.serialized_packed_opening_bytes = u64::try_from(
            super::frame_v4::FrameV4::PackedBatchOpening(packed_opening.clone()).encode()?.len(),
        )
        .map_err(|_| FoldingErrorV4::Overflow)?;
        Ok((
            GlobalFoldingProofV4 { fold_frames: self.fold_frames, packed_opening },
            self.verifier_groups,
            self.metrics,
        ))
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
        let draw_width = self.groups[0].cohort.commitment().config.outer_depth();
        let draws = (0..PRODUCTION_QUERY_COUNT_V4)
            .map(|_| tx.challenge_bits(draw_width))
            .collect::<Vec<_>>();
        let (proof, groups, metrics) = self.issue_queries(draws.clone())?;
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

fn packed_schedule_from_verifier(
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

fn validate_query_draws(draws: &[u64], max_outer_len: usize) -> Result<(), FoldingErrorV4> {
    if draws.len() != PRODUCTION_QUERY_COUNT_V4
        || draws.iter().any(|draw| *draw >= max_outer_len as u64)
    {
        return Err(FoldingErrorV4::InvalidGeometry("v4 exact query tape"));
    }
    Ok(())
}

fn accumulate_recompute_traffic(
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
    Ok(())
}

fn activate_groups(
    output_len: usize,
    groups: &[GlobalProverGroupV4<'_>],
    combined: &[CombinedInitialV4],
    current_coefficients: &mut [Fp2],
    current_codeword: &mut [Fp2],
    current_claim: &mut Fp2,
) -> Result<(), FoldingErrorV4> {
    for (group, initial) in groups.iter().zip(combined) {
        if group.cohort.commitment().config.outer_len != output_len {
            continue;
        }
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
    }
    Ok(())
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

fn claim_line_v4(
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

fn interpolate_v4(at_zero: Fp2, at_one: Fp2, point: Fp2) -> Fp2 {
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
        assert!(metrics.serialized_fold_bytes > 0);
        assert!(metrics.serialized_packed_opening_bytes > 0);
        assert_eq!(proof.packed_opening.initial_groups[0].touched_slots, [0, 2]);
        assert_eq!(proof.packed_opening.initial_groups[1].touched_slots, [0, 1]);
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
