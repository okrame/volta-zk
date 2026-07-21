//! Strict unique-decoding BaseFold core for the amended X4 profile.
//!
//! This is an interactive verifier API: challenges are explicit inputs and
//! are never derived with Fiat--Shamir.  Same-size touched block slots are
//! combined only after their order and roots are fixed.  Round zero keeps the
//! full cohort; later rounds use the singleton aggregate layout registered in
//! implementation clarification I1.

use std::collections::BTreeSet;

use volta_field::{Fp, Fp2};

use super::frame::{
    CohortMultiproofFrame, Digest, FoldCommitmentFrame, Frame, FrameError, PcsLeafPayload,
};
use super::merkle::{
    verify_cohort_opening, CohortIdentity, CohortTree, CohortVerifierConfig, MerkleError,
};
use super::ntt::{
    encode_rate_eighth, evaluate_multilinear_coefficients, fold_codeword, fold_coefficients,
    root_of_unity,
};

pub const PRODUCTION_QUERY_COUNT: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldingError {
    Frame(FrameError),
    Merkle(MerkleError),
    InvalidGeometry(&'static str),
    InvalidProof(&'static str),
    Overflow,
}

impl From<FrameError> for FoldingError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<MerkleError> for FoldingError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdChallenges {
    /// Same-size cohort combination challenge.  Powers follow touched-slot
    /// order, beginning with one.
    pub combine: Fp2,
    /// One field challenge per coefficient variable.
    pub folds: Vec<Fp2>,
    /// Ordered samples from the full round-zero domain.  Production requires
    /// exactly 128; duplicate samples remain in this vector.
    pub query_draws: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdFoldingProof {
    pub fold_frames: Vec<FoldCommitmentFrame>,
    /// Round zero followed by every committed output round, including the
    /// final rate-1/8 constant oracle of length eight.
    pub query_frames: Vec<CohortMultiproofFrame>,
}

impl UdFoldingProof {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FoldingError> {
        let mut bytes = Vec::new();
        for frame in &self.fold_frames {
            bytes.extend(Frame::FoldCommitment(frame.clone()).encode()?);
        }
        for frame in &self.query_frames {
            bytes.extend(Frame::CohortMultiproof(frame.clone()).encode()?);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UdOpenMetrics {
    pub source_coefficients_read: u64,
    pub initial_encoded_symbols_read: u64,
    pub folded_symbols_written: u64,
    pub aggregate_merkle_symbols_written: u64,
    pub serialized_fold_bytes: u64,
    pub serialized_query_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct UdCohortCommitment {
    pub root: Digest,
    pub config: CohortVerifierConfig,
}

#[derive(Clone, Debug)]
pub struct UdCommittedCohort {
    commitment: UdCohortCommitment,
    coefficients: Vec<Option<Vec<Fp2>>>,
    codewords: Vec<Option<Vec<Fp2>>>,
    tree: CohortTree,
}

impl UdCommittedCohort {
    /// Commit already-canonical multilinear monomial coefficients.  Source
    /// Boolean evaluation tables must first pass through
    /// `multilinear_coefficients`.
    pub fn commit(
        config: CohortVerifierConfig,
        coefficients: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, FoldingError> {
        config.validate()?;
        if config.identity.fold_round != 0
            || config.expected_symbol_count != 1
            || coefficients.len() != config.slot_descriptors.len()
            || config.outer_len < 16
        {
            return Err(FoldingError::InvalidGeometry("round-zero cohort"));
        }
        let coefficient_len = config.outer_len / 8;
        if coefficient_len == 0 || !coefficient_len.is_power_of_two() {
            return Err(FoldingError::InvalidGeometry("rate-eighth cohort"));
        }
        let mut codewords = Vec::with_capacity(coefficients.len());
        for (descriptor, coefficients) in config.slot_descriptors.iter().zip(&coefficients) {
            match (descriptor, coefficients) {
                (Some(_), Some(coefficients)) if coefficients.len() == coefficient_len => {
                    codewords.push(Some(encode_rate_eighth(coefficients)?));
                }
                (None, None) => codewords.push(None),
                (Some(_), Some(_)) => {
                    return Err(FoldingError::InvalidGeometry("cohort coefficient length"));
                }
                _ => return Err(FoldingError::InvalidGeometry("cohort coefficient presence")),
            }
        }
        let tree = CohortTree::build_flat(config.clone(), codewords.clone())?;
        let commitment = UdCohortCommitment { root: tree.root(), config };
        Ok(Self { commitment, coefficients, codewords, tree })
    }

    pub fn commitment(&self) -> &UdCohortCommitment {
        &self.commitment
    }

    pub fn open(
        &self,
        touched_slots: &[u16],
        common_point: &[Fp2],
        claimed_values: &[Fp2],
        challenges: &UdChallenges,
        expected_query_count: usize,
    ) -> Result<(UdFoldingProof, UdOpenMetrics), FoldingError> {
        validate_opening_inputs(
            &self.commitment,
            touched_slots,
            common_point,
            claimed_values,
            challenges,
            expected_query_count,
        )?;
        let coefficient_len = self.commitment.config.outer_len / 8;
        let mut combined_coefficients = vec![Fp2::ZERO; coefficient_len];
        let mut combined_codeword = vec![Fp2::ZERO; self.commitment.config.outer_len];
        let mut combined_claim = Fp2::ZERO;
        let mut power = Fp2::ONE;
        for (slot, claimed) in touched_slots.iter().zip(claimed_values) {
            let index = usize::from(*slot);
            let coefficients = self.coefficients[index]
                .as_ref()
                .ok_or(FoldingError::InvalidGeometry("touched coefficient slot"))?;
            let codeword = self.codewords[index]
                .as_ref()
                .ok_or(FoldingError::InvalidGeometry("touched codeword slot"))?;
            if evaluate_multilinear_coefficients(coefficients, common_point)? != *claimed {
                return Err(FoldingError::InvalidGeometry("false claimed evaluation"));
            }
            for (output, value) in combined_coefficients.iter_mut().zip(coefficients) {
                *output += power * *value;
            }
            for (output, value) in combined_codeword.iter_mut().zip(codeword) {
                *output += power * *value;
            }
            combined_claim += power * *claimed;
            power = power * challenges.combine;
        }

        let anchor = self.commitment.config.slot_descriptors[0]
            .ok_or(FoldingError::InvalidGeometry("aggregate slot-zero anchor"))?;
        let mut fold_frames = Vec::with_capacity(common_point.len());
        let mut aggregate_trees = Vec::with_capacity(common_point.len());
        let mut current_coefficients = combined_coefficients;
        let mut current_codeword = combined_codeword;
        let mut current_claim = combined_claim;
        let mut folded_symbols_written = 0u64;

        for (round_index, challenge) in challenges.folds.iter().enumerate() {
            let (line_zero, line_one) =
                claim_line(&current_coefficients, &common_point[round_index + 1..])?;
            if interpolate(line_zero, line_one, common_point[round_index]) != current_claim {
                return Err(FoldingError::InvalidGeometry("claim-line input"));
            }
            current_claim = interpolate(line_zero, line_one, *challenge);
            current_coefficients = fold_coefficients(&current_coefficients, *challenge)?;
            current_codeword = fold_codeword(&current_codeword, *challenge)?;
            folded_symbols_written = folded_symbols_written
                .checked_add(
                    u64::try_from(current_codeword.len()).map_err(|_| FoldingError::Overflow)?,
                )
                .ok_or(FoldingError::Overflow)?;

            let fold_round = u8::try_from(round_index + 1).map_err(|_| FoldingError::Overflow)?;
            let aggregate_config = CohortVerifierConfig {
                identity: CohortIdentity {
                    cohort_id: self.commitment.config.identity.cohort_id,
                    oracle_kind: self.commitment.config.identity.oracle_kind,
                    fold_round,
                },
                slot_descriptors: vec![Some(anchor)],
                outer_len: current_codeword.len(),
                expected_symbol_count: 1,
            };
            let tree =
                CohortTree::build_flat(aggregate_config, vec![Some(current_codeword.clone())])?;
            let mut messages = vec![line_zero, line_one];
            if round_index + 1 == challenges.folds.len() {
                if current_coefficients.len() != 1 || current_coefficients[0] != current_claim {
                    return Err(FoldingError::InvalidGeometry("final folded scalar"));
                }
                messages.push(current_claim);
            }
            fold_frames.push(FoldCommitmentFrame {
                cohort_id: self.commitment.config.identity.cohort_id,
                oracle_kind: self.commitment.config.identity.oracle_kind,
                fold_round,
                input_log2: u8::try_from(current_codeword.len().ilog2() + 1)
                    .map_err(|_| FoldingError::Overflow)?,
                output_log2: u8::try_from(current_codeword.len().ilog2())
                    .map_err(|_| FoldingError::Overflow)?,
                root_digest: tree.root(),
                ordered_message_symbols: messages,
            });
            aggregate_trees.push(tree);
        }

        let mut query_frames = Vec::with_capacity(aggregate_trees.len() + 1);
        let initial_indices =
            query_indices(&challenges.query_draws, self.commitment.config.outer_len)?;
        query_frames.push(self.tree.open(&initial_indices, touched_slots)?);
        for tree in &aggregate_trees {
            let indices = query_indices(&challenges.query_draws, tree.config().outer_len)?;
            query_frames.push(tree.open(&indices, &[0])?);
        }
        let proof = UdFoldingProof { fold_frames, query_frames };
        let serialized_fold_bytes = proof
            .fold_frames
            .iter()
            .map(|frame| Frame::FoldCommitment(frame.clone()).encode().map(|bytes| bytes.len()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .try_fold(0u64, |sum, bytes| {
                sum.checked_add(bytes as u64).ok_or(FoldingError::Overflow)
            })?;
        let serialized_query_bytes = proof
            .query_frames
            .iter()
            .map(|frame| Frame::CohortMultiproof(frame.clone()).encode().map(|bytes| bytes.len()))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .try_fold(0u64, |sum, bytes| {
                sum.checked_add(bytes as u64).ok_or(FoldingError::Overflow)
            })?;
        let touched = u64::try_from(touched_slots.len()).map_err(|_| FoldingError::Overflow)?;
        let metrics = UdOpenMetrics {
            source_coefficients_read: touched
                .checked_mul(u64::try_from(coefficient_len).map_err(|_| FoldingError::Overflow)?)
                .ok_or(FoldingError::Overflow)?,
            initial_encoded_symbols_read: touched
                .checked_mul(
                    u64::try_from(self.commitment.config.outer_len)
                        .map_err(|_| FoldingError::Overflow)?,
                )
                .ok_or(FoldingError::Overflow)?,
            folded_symbols_written,
            aggregate_merkle_symbols_written: folded_symbols_written,
            serialized_fold_bytes,
            serialized_query_bytes,
        };
        Ok((proof, metrics))
    }

    pub fn open_production(
        &self,
        touched_slots: &[u16],
        common_point: &[Fp2],
        claimed_values: &[Fp2],
        challenges: &UdChallenges,
    ) -> Result<(UdFoldingProof, UdOpenMetrics), FoldingError> {
        self.open(touched_slots, common_point, claimed_values, challenges, PRODUCTION_QUERY_COUNT)
    }
}

pub fn verify_ud_folding(
    commitment: &UdCohortCommitment,
    touched_slots: &[u16],
    common_point: &[Fp2],
    claimed_values: &[Fp2],
    challenges: &UdChallenges,
    expected_query_count: usize,
    proof: &UdFoldingProof,
) -> Result<(), FoldingError> {
    validate_opening_inputs(
        commitment,
        touched_slots,
        common_point,
        claimed_values,
        challenges,
        expected_query_count,
    )?;
    let rounds = common_point.len();
    if proof.fold_frames.len() != rounds || proof.query_frames.len() != rounds + 1 {
        return Err(FoldingError::InvalidProof("fold/query frame count"));
    }
    let anchor = commitment.config.slot_descriptors[0]
        .ok_or(FoldingError::InvalidGeometry("aggregate slot-zero anchor"))?;

    let initial_indices = query_indices(&challenges.query_draws, commitment.config.outer_len)?;
    verify_cohort_opening(
        commitment.root,
        &commitment.config,
        &initial_indices,
        touched_slots,
        &proof.query_frames[0],
    )?;

    let mut output_configs = Vec::with_capacity(rounds);
    let mut input_len = commitment.config.outer_len;
    for (round_index, (frame, query_frame)) in
        proof.fold_frames.iter().zip(&proof.query_frames[1..]).enumerate()
    {
        frame.validate()?;
        let output_len = input_len / 2;
        let fold_round = u8::try_from(round_index + 1).map_err(|_| FoldingError::Overflow)?;
        let expected_messages = if round_index + 1 == rounds { 3 } else { 2 };
        if frame.cohort_id != commitment.config.identity.cohort_id
            || frame.oracle_kind != commitment.config.identity.oracle_kind
            || frame.fold_round != fold_round
            || usize::from(frame.input_log2) != input_len.ilog2() as usize
            || usize::from(frame.output_log2) != output_len.ilog2() as usize
            || frame.ordered_message_symbols.len() != expected_messages
        {
            return Err(FoldingError::InvalidProof("fold frame schedule"));
        }
        let config = CohortVerifierConfig {
            identity: CohortIdentity {
                cohort_id: commitment.config.identity.cohort_id,
                oracle_kind: commitment.config.identity.oracle_kind,
                fold_round,
            },
            slot_descriptors: vec![Some(anchor)],
            outer_len: output_len,
            expected_symbol_count: 1,
        };
        let indices = query_indices(&challenges.query_draws, output_len)?;
        verify_cohort_opening(frame.root_digest, &config, &indices, &[0], query_frame)?;
        output_configs.push(config);
        input_len = output_len;
    }
    if input_len != 8 {
        return Err(FoldingError::InvalidProof("final rate-eighth oracle"));
    }

    let mut combined_claim = Fp2::ZERO;
    let mut power = Fp2::ONE;
    for claimed in claimed_values {
        combined_claim += power * *claimed;
        power = power * challenges.combine;
    }
    for (round_index, frame) in proof.fold_frames.iter().enumerate() {
        let line_zero = frame.ordered_message_symbols[0];
        let line_one = frame.ordered_message_symbols[1];
        if interpolate(line_zero, line_one, common_point[round_index]) != combined_claim {
            return Err(FoldingError::InvalidProof("claim-line relation"));
        }
        combined_claim = interpolate(line_zero, line_one, challenges.folds[round_index]);
    }
    let final_scalar = proof.fold_frames.last().unwrap().ordered_message_symbols[2];
    if final_scalar != combined_claim {
        return Err(FoldingError::InvalidProof("final claim scalar"));
    }

    for draw in &challenges.query_draws {
        let mut current_len = commitment.config.outer_len;
        for round_index in 0..rounds {
            let base = (*draw % current_len as u64) % (current_len as u64 / 2);
            let positive = if round_index == 0 {
                aggregate_opened_symbol(
                    &proof.query_frames[0],
                    base,
                    touched_slots,
                    challenges.combine,
                )?
            } else {
                opened_symbol(&proof.query_frames[round_index], base, 0)?
            };
            let negative_index = base + current_len as u64 / 2;
            let negative = if round_index == 0 {
                aggregate_opened_symbol(
                    &proof.query_frames[0],
                    negative_index,
                    touched_slots,
                    challenges.combine,
                )?
            } else {
                opened_symbol(&proof.query_frames[round_index], negative_index, 0)?
            };
            let expected =
                fold_pair(positive, negative, base, current_len, challenges.folds[round_index])?;
            let actual = opened_symbol(&proof.query_frames[round_index + 1], base, 0)?;
            if actual != expected {
                return Err(FoldingError::InvalidProof("queried fold relation"));
            }
            current_len /= 2;
        }
    }
    for leaf in &proof.query_frames.last().unwrap().opened_leaves {
        if let PcsLeafPayload::Inner { present: true, symbols, .. } = &leaf.payload {
            if symbols.as_slice() != [final_scalar] {
                return Err(FoldingError::InvalidProof("final constant codeword"));
            }
        }
    }
    Ok(())
}

pub fn verify_ud_folding_production(
    commitment: &UdCohortCommitment,
    touched_slots: &[u16],
    common_point: &[Fp2],
    claimed_values: &[Fp2],
    challenges: &UdChallenges,
    proof: &UdFoldingProof,
) -> Result<(), FoldingError> {
    verify_ud_folding(
        commitment,
        touched_slots,
        common_point,
        claimed_values,
        challenges,
        PRODUCTION_QUERY_COUNT,
        proof,
    )
}

fn validate_opening_inputs(
    commitment: &UdCohortCommitment,
    touched_slots: &[u16],
    common_point: &[Fp2],
    claimed_values: &[Fp2],
    challenges: &UdChallenges,
    expected_query_count: usize,
) -> Result<(), FoldingError> {
    commitment.config.validate()?;
    if commitment.config.identity.fold_round != 0
        || commitment.config.expected_symbol_count != 1
        || touched_slots.is_empty()
        || touched_slots.len() != claimed_values.len()
        || challenges.query_draws.len() != expected_query_count
    {
        return Err(FoldingError::InvalidGeometry("opening schedule"));
    }
    if !touched_slots.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(FoldingError::InvalidGeometry("touched slot order"));
    }
    for slot in touched_slots {
        if commitment.config.slot_descriptors.get(usize::from(*slot)).copied().flatten().is_none() {
            return Err(FoldingError::InvalidGeometry("touched slot"));
        }
    }
    let coefficient_len = commitment.config.outer_len / 8;
    if coefficient_len != 1usize.checked_shl(common_point.len() as u32).unwrap_or(0)
        || common_point.is_empty()
        || challenges.folds.len() != common_point.len()
        || challenges.query_draws.iter().any(|draw| *draw >= commitment.config.outer_len as u64)
    {
        return Err(FoldingError::InvalidGeometry("fold challenge geometry"));
    }
    Ok(())
}

fn claim_line(coefficients: &[Fp2], remaining_point: &[Fp2]) -> Result<(Fp2, Fp2), FoldingError> {
    if coefficients.len() < 2 || coefficients.len() / 2 != 1usize << remaining_point.len() {
        return Err(FoldingError::InvalidGeometry("claim line"));
    }
    let mut even = Vec::with_capacity(coefficients.len() / 2);
    let mut odd = Vec::with_capacity(coefficients.len() / 2);
    for pair in coefficients.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }
    let at_zero = evaluate_multilinear_coefficients(&even, remaining_point)?;
    let odd_value = evaluate_multilinear_coefficients(&odd, remaining_point)?;
    Ok((at_zero, at_zero + odd_value))
}

fn interpolate(at_zero: Fp2, at_one: Fp2, point: Fp2) -> Fp2 {
    at_zero + point * (at_one - at_zero)
}

fn query_indices(draws: &[u64], domain_len: usize) -> Result<Vec<u64>, FoldingError> {
    if domain_len < 2 || !domain_len.is_power_of_two() {
        return Err(FoldingError::InvalidGeometry("query domain"));
    }
    let domain_len = u64::try_from(domain_len).map_err(|_| FoldingError::Overflow)?;
    let half = domain_len / 2;
    let mut indices = BTreeSet::new();
    for draw in draws {
        let base = (*draw % domain_len) % half;
        indices.insert(base);
        indices.insert(base + half);
    }
    Ok(indices.into_iter().collect())
}

fn opened_symbol(
    proof: &CohortMultiproofFrame,
    outer_index: u64,
    slot: u16,
) -> Result<Fp2, FoldingError> {
    for leaf in &proof.opened_leaves {
        if leaf.outer_index != outer_index {
            continue;
        }
        if let PcsLeafPayload::Inner { slot: leaf_slot, present: true, symbols, .. } = &leaf.payload
        {
            if *leaf_slot == slot {
                return match symbols.as_slice() {
                    [symbol] => Ok(*symbol),
                    _ => Err(FoldingError::InvalidProof("opened symbol count")),
                };
            }
        }
    }
    Err(FoldingError::InvalidProof("missing opened symbol"))
}

fn aggregate_opened_symbol(
    proof: &CohortMultiproofFrame,
    outer_index: u64,
    touched_slots: &[u16],
    challenge: Fp2,
) -> Result<Fp2, FoldingError> {
    let mut aggregate = Fp2::ZERO;
    let mut power = Fp2::ONE;
    for slot in touched_slots {
        aggregate += power * opened_symbol(proof, outer_index, *slot)?;
        power = power * challenge;
    }
    Ok(aggregate)
}

fn fold_pair(
    positive: Fp2,
    negative: Fp2,
    base_index: u64,
    input_len: usize,
    challenge: Fp2,
) -> Result<Fp2, FoldingError> {
    let omega = root_of_unity(input_len.ilog2())?;
    let x = super::ntt::fp2_pow(omega, u128::from(base_index));
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    let even = (positive + negative) * inverse_two;
    let odd = (positive - negative) * inverse_two * x.inv();
    Ok(even + challenge * odd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::frame::OracleKind;
    use crate::x4::ntt::{evaluate_multilinear_table, multilinear_coefficients};

    const QUERIES: usize = 8;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 7 + 3))
    }

    fn fixture() -> (UdCommittedCohort, Vec<u16>, Vec<Fp2>, Vec<Fp2>, UdChallenges, UdFoldingProof)
    {
        let descriptors = vec![Some([1; 32]), Some([2; 32]), Some([3; 32]), Some([4; 32])];
        let evaluations: Vec<Vec<Fp2>> = (0..4)
            .map(|slot| (0..16).map(|index| symbol(100 * slot + index + 1)).collect::<Vec<_>>())
            .collect();
        let coefficients = evaluations
            .iter()
            .map(|values| Some(multilinear_coefficients(values).unwrap()))
            .collect();
        let config = CohortVerifierConfig {
            identity: CohortIdentity {
                cohort_id: 73,
                oracle_kind: OracleKind::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: descriptors,
            outer_len: 128,
            expected_symbol_count: 1,
        };
        let committed = UdCommittedCohort::commit(config, coefficients).unwrap();
        let touched = vec![0, 2, 3];
        let point = vec![symbol(17), symbol(19), symbol(23), symbol(29)];
        let claimed: Vec<_> = touched
            .iter()
            .map(|slot| {
                evaluate_multilinear_table(&evaluations[usize::from(*slot)], &point).unwrap()
            })
            .collect();
        let challenges = UdChallenges {
            combine: symbol(31),
            folds: vec![symbol(37), symbol(41), symbol(43), symbol(47)],
            query_draws: vec![0, 1, 7, 31, 64, 65, 95, 127],
        };
        let (proof, _) = committed.open(&touched, &point, &claimed, &challenges, QUERIES).unwrap();
        (committed, touched, point, claimed, challenges, proof)
    }

    fn rejects(
        committed: &UdCommittedCohort,
        touched: &[u16],
        point: &[Fp2],
        claimed: &[Fp2],
        challenges: &UdChallenges,
        proof: &UdFoldingProof,
    ) {
        assert!(verify_ud_folding(
            committed.commitment(),
            touched,
            point,
            claimed,
            challenges,
            QUERIES,
            proof,
        )
        .is_err());
    }

    #[test]
    fn honest_ud_cohort_fold_accepts_and_is_canonical() {
        let (committed, touched, point, claimed, challenges, proof) = fixture();
        verify_ud_folding(
            committed.commitment(),
            &touched,
            &point,
            &claimed,
            &challenges,
            QUERIES,
            &proof,
        )
        .unwrap();
        assert_eq!(proof.fold_frames.len(), point.len());
        assert_eq!(proof.query_frames.len(), point.len() + 1);
        assert_eq!(proof.fold_frames.last().unwrap().output_log2, 3);
        assert_eq!(proof.fold_frames.last().unwrap().ordered_message_symbols.len(), 3);
        assert!(!proof.canonical_bytes().unwrap().is_empty());

        for leaf in &proof.query_frames[0].opened_leaves {
            if let PcsLeafPayload::Inner { slot, .. } = &leaf.payload {
                assert!(touched.contains(slot));
                assert_ne!(*slot, 1, "unopened slot must not appear in the proof");
            }
        }
        for round in &proof.query_frames[1..] {
            assert_eq!(round.touched_slots, [0]);
        }
    }

    #[test]
    fn claim_line_final_scalar_and_fold_root_tampers_reject() {
        let (committed, touched, point, claimed, challenges, proof) = fixture();

        let mut bad = proof.clone();
        bad.fold_frames[0].ordered_message_symbols[0] += Fp2::ONE;
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.fold_frames.last_mut().unwrap().ordered_message_symbols[2] += Fp2::ONE;
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.fold_frames[1].root_digest[0] ^= 1;
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.fold_frames.swap(0, 1);
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.fold_frames.pop();
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);
    }

    #[test]
    fn query_symbol_path_index_and_final_constant_tampers_reject() {
        let (committed, touched, point, claimed, challenges, proof) = fixture();

        let mut bad = proof.clone();
        let leaf = bad.query_frames[0]
            .opened_leaves
            .iter_mut()
            .find(|leaf| matches!(leaf.payload, PcsLeafPayload::Inner { .. }))
            .unwrap();
        match &mut leaf.payload {
            PcsLeafPayload::Inner { symbols, .. } => symbols[0] += Fp2::ONE,
            _ => unreachable!(),
        }
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.query_frames[1].aux_nodes[0].digest[0] ^= 1;
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.query_frames[2].outer_indices[0] ^= 1;
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        let leaf = bad
            .query_frames
            .last_mut()
            .unwrap()
            .opened_leaves
            .iter_mut()
            .find(|leaf| matches!(leaf.payload, PcsLeafPayload::Inner { .. }));
        match &mut leaf.unwrap().payload {
            PcsLeafPayload::Inner { symbols, .. } => symbols[0] += Fp2::ONE,
            _ => unreachable!(),
        }
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);

        let mut bad = proof.clone();
        bad.query_frames.pop();
        rejects(&committed, &touched, &point, &claimed, &challenges, &bad);
    }

    #[test]
    fn transcript_challenge_claim_point_and_touch_order_are_bound() {
        let (committed, touched, point, claimed, challenges, proof) = fixture();

        let mut bad_challenges = challenges.clone();
        bad_challenges.combine += Fp2::ONE;
        rejects(&committed, &touched, &point, &claimed, &bad_challenges, &proof);

        let mut bad_challenges = challenges.clone();
        bad_challenges.folds[2] += Fp2::ONE;
        rejects(&committed, &touched, &point, &claimed, &bad_challenges, &proof);

        let mut bad_challenges = challenges.clone();
        bad_challenges.query_draws[1] = 2;
        rejects(&committed, &touched, &point, &claimed, &bad_challenges, &proof);

        let mut bad_claimed = claimed.clone();
        bad_claimed[0] += Fp2::ONE;
        rejects(&committed, &touched, &point, &bad_claimed, &challenges, &proof);

        let mut bad_point = point.clone();
        bad_point[0] += Fp2::ONE;
        rejects(&committed, &touched, &bad_point, &claimed, &challenges, &proof);

        let mut bad_touched = touched.clone();
        bad_touched.swap(0, 1);
        rejects(&committed, &bad_touched, &point, &claimed, &challenges, &proof);
    }

    #[test]
    fn prover_rejects_false_claims_and_non_exact_query_tapes() {
        let (committed, touched, point, claimed, challenges, _) = fixture();
        let mut false_claims = claimed.clone();
        false_claims[1] += Fp2::ONE;
        assert!(matches!(
            committed.open(&touched, &point, &false_claims, &challenges, QUERIES),
            Err(FoldingError::InvalidGeometry("false claimed evaluation"))
        ));

        let mut short = challenges.clone();
        short.query_draws.pop();
        assert!(committed.open(&touched, &point, &claimed, &short, QUERIES).is_err());

        let mut out_of_range = challenges;
        out_of_range.query_draws[0] = committed.commitment.config.outer_len as u64;
        assert!(committed.open(&touched, &point, &claimed, &out_of_range, QUERIES).is_err());
    }

    #[test]
    fn duplicate_samples_are_retained_but_merkle_indices_are_deduplicated() {
        let (committed, touched, point, claimed, mut challenges, _) = fixture();
        challenges.query_draws = vec![7; QUERIES];
        let (proof, _) = committed.open(&touched, &point, &claimed, &challenges, QUERIES).unwrap();
        assert_eq!(proof.query_frames[0].outer_indices.len(), 2);
        verify_ud_folding(
            committed.commitment(),
            &touched,
            &point,
            &claimed,
            &challenges,
            QUERIES,
            &proof,
        )
        .unwrap();
    }
}
