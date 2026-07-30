//! Response-local packed PCS for the C6 wrapper.
//!
//! This module intentionally does not call the historical X4 global-chain
//! engine.  It reuses only its byte-differential native-field primitives:
//! multilinear coefficient conversion, rate-1/8 NTT/folding, N4 cohort
//! Merkle openings, and standalone schema-4 frame codecs.  Every descriptor
//! and opening schedule is re-domain-separated for C6.
//!
//! The implementation here is the in-memory reference backend.  Production
//! timing credit requires the separately gated fused CUDA implementation; the
//! reference backend exists to freeze algebra, transcript order, rejection
//! behavior, and exact wire bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use volta_field::{Fp, Fp2};
use volta_mac::Transcript;

use crate::x4::accounting::projected_query_indices;
use crate::x4::frame::Digest;
use crate::x4::frame_v4::{
    decode_v4, FoldCommitmentFrameV4, FoldRoundOpeningV4, FrameV4, InitialOpeningGroupV4,
    OracleKindV4, PackedBatchOpeningFrameV4, HEADER_LEN_V4,
};
use crate::x4::merkle_v4::{
    verify_fold_round_packed_opening_v4, verify_initial_packed_opening_v4, CohortIdentityV4,
    CohortTreeV4, CohortVerifierConfigV4,
};
use crate::x4::ntt::{
    encode_rate_eighth, evaluate_multilinear_coefficients, fold_codeword, fold_coefficients,
    fp2_pow, multilinear_coefficients, root_of_unity,
};

pub const C6_WRAPPER_QUERY_COUNT: usize = 86;
pub const C6_WRAPPER_REPETITIONS: usize = 2;
pub const C6_WRAPPER_TERMINAL_LOG2: u8 = 3;
pub const C6_WRAPPER_ACTIVE_SLOTS: usize = 64;
pub const C6_WRAPPER_ONE_CHAIN_BYTES: u64 = 1_804_912;
pub const C6_WRAPPER_TWO_CHAIN_BYTES: u64 = 3_609_824;

const C6_WRAPPER_PROFILE_NAME: &[u8] = b"c6-transparent-rate8-s86-p64-two-repetition-v1";
const C6_SLOT_DESCRIPTOR_CONTEXT: &str = "volta-zk/c6/wrapper-slot-descriptor/v1";
const C6_FOLD_DESCRIPTOR_CONTEXT: &str = "volta-zk/c6/wrapper-fold-descriptor/v1";
const C6_OPENING_SCHEDULE_CONTEXT: &str = "volta-zk/c6/wrapper-opening-schedule/v1";
const C6_TERMINAL_CLAIMS_LABEL: &str = "c6_wrapper_terminal_claims";
const C6_FOLD_LINE_LABEL: &str = "c6_wrapper_fold_line";
const C6_FOLD_POST_CHALLENGE_LABEL: &str = "c6_wrapper_fold_post_challenge";
const C6_PACKED_OPENING_LABEL: &str = "c6_wrapper_packed_opening";
const C6_GLOBAL_FOLD_COHORT_BASE: u32 = 0xC6F0_0000;

pub type C6WrapperDigest = [u8; 32];
type Result<T> = std::result::Result<T, C6WrapperPcsError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperPcsError(String);

impl C6WrapperPcsError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn frame(context: &'static str, error: impl fmt::Debug) -> Self {
        Self(format!("{context}: {error:?}"))
    }
}

impl fmt::Display for C6WrapperPcsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6WrapperPcsError {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6WrapperOracleKind {
    Witness = 1,
    Auxiliary = 2,
}

impl C6WrapperOracleKind {
    fn v4(self) -> OracleKindV4 {
        match self {
            Self::Witness => OracleKindV4::WeightExtension,
            Self::Auxiliary => OracleKindV4::Auxiliary,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6WrapperCohortSpec {
    pub cohort_id: u32,
    pub oracle_kind: C6WrapperOracleKind,
    /// `mu` for a witness cohort and `ell` for an auxiliary cohort.
    pub payload_log2: u8,
    pub slot_count: u16,
}

impl C6WrapperCohortSpec {
    pub fn validate(self) -> Result<()> {
        if self.cohort_id == 0
            || self.slot_count == 0
            || !self.slot_count.is_power_of_two()
            || self.coefficient_log2()? == 0
            || self.encoded_domain_log2()? > 32
        {
            return Err(C6WrapperPcsError::new("invalid C6 wrapper cohort geometry"));
        }
        Ok(())
    }

    pub fn coefficient_log2(self) -> Result<u8> {
        match self.oracle_kind {
            C6WrapperOracleKind::Witness => self
                .payload_log2
                .checked_add(1)
                .ok_or_else(|| C6WrapperPcsError::new("C6 witness coefficient log overflows")),
            C6WrapperOracleKind::Auxiliary => Ok(self.payload_log2),
        }
    }

    pub fn encoded_domain_log2(self) -> Result<u8> {
        self.coefficient_log2()?
            .checked_add(3)
            .ok_or_else(|| C6WrapperPcsError::new("C6 encoded-domain log overflows"))
    }

    fn payload_len(self) -> Result<usize> {
        checked_pow2(self.payload_log2, "C6 payload length")
    }

    fn coefficient_len(self) -> Result<usize> {
        checked_pow2(self.coefficient_log2()?, "C6 coefficient length")
    }

    fn encoded_len(self) -> Result<usize> {
        checked_pow2(self.encoded_domain_log2()?, "C6 encoded length")
    }
}

/// Frozen production capacity profile, in canonical descending-domain order.
pub fn production_c6_wrapper_specs() -> [C6WrapperCohortSpec; 5] {
    [
        C6WrapperCohortSpec {
            cohort_id: 0xC601_0001,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 24,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: 0xC601_0002,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 23,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: 0xC601_0003,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 21,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: 0xC601_0004,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 19,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: 0xC601_0005,
            oracle_kind: C6WrapperOracleKind::Auxiliary,
            payload_log2: 16,
            slot_count: 32,
        },
    ]
}

pub fn c6_wrapper_profile_digest() -> C6WrapperDigest {
    *blake3::hash(C6_WRAPPER_PROFILE_NAME).as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum C6WrapperSlotWitness {
    /// The second table is the independent ZK twin.  Appending a zero to an
    /// opening point selects `witness`, while one selects `zk_mask`.
    Witness {
        witness: Vec<Fp2>,
        zk_mask: Vec<Fp2>,
    },
    Auxiliary {
        evaluations: Vec<Fp2>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperCommitment {
    pub profile_digest: C6WrapperDigest,
    pub statement_digest: C6WrapperDigest,
    pub spec: C6WrapperCohortSpec,
    pub root: Digest,
    pub config: CohortVerifierConfigV4,
}

impl C6WrapperCommitment {
    pub fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        if self.profile_digest != c6_wrapper_profile_digest()
            || self.statement_digest == [0; 32]
            || self.config.identity
                != (CohortIdentityV4 {
                    cohort_id: self.spec.cohort_id,
                    oracle_kind: self.spec.oracle_kind.v4(),
                    fold_round: 0,
                })
            || self.config.outer_len != self.spec.encoded_len()?
            || self.config.expected_symbol_count != 1
            || self.config.slot_descriptors.len() != usize::from(self.spec.slot_count)
        {
            return Err(C6WrapperPcsError::new("C6 wrapper commitment geometry mismatch"));
        }
        self.config
            .validate()
            .map_err(|error| C6WrapperPcsError::frame("C6 wrapper commitment config", error))?;
        for (slot, descriptor) in self.config.slot_descriptors.iter().enumerate() {
            let expected = slot_descriptor_digest(
                self.statement_digest,
                self.spec,
                u16::try_from(slot)
                    .map_err(|_| C6WrapperPcsError::new("C6 descriptor slot overflows"))?,
            );
            if *descriptor != Some(expected) {
                return Err(C6WrapperPcsError::new("C6 wrapper slot descriptor mismatch"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct C6CommittedWrapperCohort {
    commitment: C6WrapperCommitment,
    coefficients: Vec<Vec<Fp2>>,
    codewords: Vec<Vec<Fp2>>,
    tree: CohortTreeV4,
}

impl C6CommittedWrapperCohort {
    pub fn commitment(&self) -> &C6WrapperCommitment {
        &self.commitment
    }

    fn combine(&self, claim: &C6WrapperOpeningClaim) -> Result<CombinedCohort> {
        validate_claim(&self.commitment, claim)?;
        let coefficient_len = self.commitment.spec.coefficient_len()?;
        let encoded_len = self.commitment.spec.encoded_len()?;
        let mut coefficients = vec![Fp2::ZERO; coefficient_len];
        let mut codeword = vec![Fp2::ZERO; encoded_len];
        for ((source_coefficients, source_codeword), weight) in
            self.coefficients.iter().zip(&self.codewords).zip(&claim.slot_weights)
        {
            for (output, value) in coefficients.iter_mut().zip(source_coefficients) {
                *output += *weight * *value;
            }
            for (output, value) in codeword.iter_mut().zip(source_codeword) {
                *output += *weight * *value;
            }
        }
        let actual = evaluate_multilinear_coefficients(&coefficients, &claim.point)
            .map_err(|error| C6WrapperPcsError::frame("C6 wrapper claim evaluation", error))?;
        if actual != claim.value {
            return Err(C6WrapperPcsError::new(
                "C6 wrapper prover claim does not match committed coefficients",
            ));
        }
        Ok(CombinedCohort {
            outer_len: encoded_len,
            coefficients,
            codeword,
            claimed_value: claim.value,
        })
    }
}

/// Build one response-local cohort with every capacity slot present.
pub fn commit_c6_wrapper_cohort(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
) -> Result<C6CommittedWrapperCohort> {
    spec.validate()?;
    if statement_digest == [0; 32] || slots.len() != usize::from(spec.slot_count) {
        return Err(C6WrapperPcsError::new("C6 wrapper slot census mismatch"));
    }
    let payload_len = spec.payload_len()?;
    let mut coefficients = Vec::with_capacity(slots.len());
    let mut codewords = Vec::with_capacity(slots.len());
    for slot in slots {
        let evaluations = match (spec.oracle_kind, slot) {
            (C6WrapperOracleKind::Witness, C6WrapperSlotWitness::Witness { witness, zk_mask })
                if witness.len() == payload_len && zk_mask.len() == payload_len =>
            {
                let mut extended = Vec::with_capacity(
                    payload_len
                        .checked_mul(2)
                        .ok_or_else(|| C6WrapperPcsError::new("C6 ZK twin length overflows"))?,
                );
                extended.extend(witness);
                extended.extend(zk_mask);
                extended
            }
            (C6WrapperOracleKind::Auxiliary, C6WrapperSlotWitness::Auxiliary { evaluations })
                if evaluations.len() == payload_len =>
            {
                evaluations
            }
            _ => {
                return Err(C6WrapperPcsError::new(
                    "C6 wrapper slot kind or evaluation length mismatch",
                ))
            }
        };
        let slot_coefficients = multilinear_coefficients(&evaluations)
            .map_err(|error| C6WrapperPcsError::frame("C6 multilinear conversion", error))?;
        let slot_codeword = encode_rate_eighth(&slot_coefficients)
            .map_err(|error| C6WrapperPcsError::frame("C6 rate-eighth encoding", error))?;
        coefficients.push(slot_coefficients);
        codewords.push(slot_codeword);
    }
    let slot_descriptors = (0..spec.slot_count)
        .map(|slot| Some(slot_descriptor_digest(statement_digest, spec, slot)))
        .collect::<Vec<_>>();
    let config = CohortVerifierConfigV4 {
        identity: CohortIdentityV4 {
            cohort_id: spec.cohort_id,
            oracle_kind: spec.oracle_kind.v4(),
            fold_round: 0,
        },
        slot_descriptors,
        outer_len: spec.encoded_len()?,
        expected_symbol_count: 1,
    };
    let tree = CohortTreeV4::build_flat(
        config.clone(),
        codewords.iter().cloned().map(Some).collect::<Vec<_>>(),
    )
    .map_err(|error| C6WrapperPcsError::frame("C6 initial cohort commitment", error))?;
    let commitment = C6WrapperCommitment {
        profile_digest: c6_wrapper_profile_digest(),
        statement_digest,
        spec,
        root: tree.root(),
        config,
    };
    commitment.validate()?;
    Ok(C6CommittedWrapperCohort { commitment, coefficients, codewords, tree })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperOpeningClaim {
    pub repetition: u8,
    pub cohort_id: u32,
    /// LSB-first point on the committed coefficient MLE.  Witness points
    /// include the final zero selecting the non-mask half.
    pub point: Vec<Fp2>,
    /// Same-point reduction weights for every capacity slot, in slot order.
    pub slot_weights: Vec<Fp2>,
    pub value: Fp2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperChainProof {
    pub repetition: u8,
    pub fold_frames: Vec<FoldCommitmentFrameV4>,
    pub packed_opening: PackedBatchOpeningFrameV4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperPcsProof {
    pub chains: Vec<C6WrapperChainProof>,
}

impl C6WrapperPcsProof {
    /// Exact PCS payload.  There is deliberately no extra outer framing:
    /// chain and round counts are fixed by the C6 profile, and every embedded
    /// schema-4 frame is self-delimiting and canonical.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.chains.len() != C6_WRAPPER_REPETITIONS {
            return Err(C6WrapperPcsError::new("C6 wrapper chain count mismatch"));
        }
        let mut bytes = Vec::new();
        for (repetition, chain) in self.chains.iter().enumerate() {
            if usize::from(chain.repetition) != repetition || chain.fold_frames.is_empty() {
                return Err(C6WrapperPcsError::new("C6 wrapper chain order mismatch"));
            }
            for frame in &chain.fold_frames {
                bytes.extend(
                    FrameV4::FoldCommitment(frame.clone())
                        .encode()
                        .map_err(|error| C6WrapperPcsError::frame("C6 fold frame encode", error))?,
                );
            }
            bytes.extend(
                FrameV4::PackedBatchOpening(chain.packed_opening.clone())
                    .encode()
                    .map_err(|error| C6WrapperPcsError::frame("C6 packed frame encode", error))?,
            );
        }
        Ok(bytes)
    }

    pub fn encoded_len(&self) -> Result<u64> {
        u64::try_from(self.canonical_bytes()?.len())
            .map_err(|_| C6WrapperPcsError::new("C6 wrapper proof length exceeds u64"))
    }

    pub fn decode(commitments: &[C6WrapperCommitment], bytes: &[u8]) -> Result<Self> {
        validate_commitments(commitments)?;
        let round_count = usize::from(
            commitments[0]
                .config
                .outer_depth()
                .checked_sub(C6_WRAPPER_TERMINAL_LOG2)
                .ok_or_else(|| C6WrapperPcsError::new("C6 wrapper terminal geometry"))?,
        );
        let mut cursor = 0usize;
        let mut chains = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            let mut fold_frames = Vec::with_capacity(round_count);
            for _ in 0..round_count {
                let frame = take_v4_frame(bytes, &mut cursor)?;
                match frame {
                    FrameV4::FoldCommitment(frame) => fold_frames.push(frame),
                    _ => {
                        return Err(C6WrapperPcsError::new(
                            "C6 wrapper expected fold commitment frame",
                        ))
                    }
                }
            }
            let packed_opening = match take_v4_frame(bytes, &mut cursor)? {
                FrameV4::PackedBatchOpening(frame) => frame,
                _ => {
                    return Err(C6WrapperPcsError::new("C6 wrapper expected packed opening frame"))
                }
            };
            chains.push(C6WrapperChainProof {
                repetition: repetition as u8,
                fold_frames,
                packed_opening,
            });
        }
        if cursor != bytes.len() {
            return Err(C6WrapperPcsError::new("trailing C6 wrapper proof bytes"));
        }
        let proof = Self { chains };
        if proof.canonical_bytes()?.as_slice() != bytes {
            return Err(C6WrapperPcsError::new("noncanonical C6 wrapper proof bytes"));
        }
        Ok(proof)
    }
}

#[derive(Clone, Debug)]
struct CombinedCohort {
    outer_len: usize,
    coefficients: Vec<Fp2>,
    codeword: Vec<Fp2>,
    claimed_value: Fp2,
}

#[derive(Debug)]
struct SealedChain {
    repetition: u8,
    common_point: Vec<Fp2>,
    activation_challenges: Vec<Fp2>,
    fold_challenges: Vec<Fp2>,
    fold_frames: Vec<FoldCommitmentFrameV4>,
    fold_trees: Vec<CohortTreeV4>,
}

/// Honest in-memory prover.  Commitments and all terminal claims must already
/// be fixed before this method derives their batching and folding challenges.
pub fn prove_c6_wrapper_pcs(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6CommittedWrapperCohort],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
    validate_statement_and_claims(statement_digest, &commitments, claims_by_repetition)?;
    if cohorts.len() != commitments.len() {
        return Err(C6WrapperPcsError::new("C6 wrapper prover cohort census mismatch"));
    }

    append_terminal_claims(transcript, claims_by_repetition)?;
    let activations = derive_activation_challenges(transcript, commitments.len());
    let mut sealed = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        sealed.push(seal_chain(
            statement_digest,
            repetition,
            cohorts,
            &claims_by_repetition[repetition],
            activations[repetition].clone(),
            transcript,
        )?);
    }

    // Both complete root chains are fixed before either repetition receives
    // a proximity-query tape.
    let draw_width = commitments[0].config.outer_depth();
    let query_tapes = (0..C6_WRAPPER_REPETITIONS)
        .map(|_| {
            (0..C6_WRAPPER_QUERY_COUNT)
                .map(|_| transcript.challenge_bits(draw_width))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut chains = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for (sealed_chain, draws) in sealed.into_iter().zip(&query_tapes) {
        let chain = issue_chain_openings(
            statement_digest,
            cohorts,
            &claims_by_repetition[usize::from(sealed_chain.repetition)],
            sealed_chain,
            draws,
        )?;
        let packed_len = FrameV4::PackedBatchOpening(chain.packed_opening.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 packed opening encode", error))?
            .len();
        transcript.append(
            C6_PACKED_OPENING_LABEL,
            u64::try_from(packed_len)
                .map_err(|_| C6WrapperPcsError::new("C6 packed opening length exceeds u64"))?,
        );
        chains.push(chain);
    }
    Ok(C6WrapperPcsProof { chains })
}

/// Replay the designated-verifier interaction and verify both packed chains.
pub fn verify_c6_wrapper_pcs(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    proof: &C6WrapperPcsProof,
    transcript: &mut Transcript,
) -> Result<()> {
    validate_statement_and_claims(statement_digest, commitments, claims_by_repetition)?;
    if proof.chains.len() != C6_WRAPPER_REPETITIONS {
        return Err(C6WrapperPcsError::new("C6 wrapper proof repetition mismatch"));
    }

    append_terminal_claims(transcript, claims_by_repetition)?;
    let activations = derive_activation_challenges(transcript, commitments.len());
    let mut fold_challenges = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let chain = &proof.chains[repetition];
        if usize::from(chain.repetition) != repetition {
            return Err(C6WrapperPcsError::new("C6 wrapper proof chain order mismatch"));
        }
        fold_challenges.push(replay_fold_messages(
            repetition,
            commitments,
            &claims_by_repetition[repetition],
            &activations[repetition],
            chain,
            transcript,
        )?);
    }

    let draw_width = commitments[0].config.outer_depth();
    let query_tapes = (0..C6_WRAPPER_REPETITIONS)
        .map(|_| {
            (0..C6_WRAPPER_QUERY_COUNT)
                .map(|_| transcript.challenge_bits(draw_width))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    for repetition in 0..C6_WRAPPER_REPETITIONS {
        verify_chain_openings(
            statement_digest,
            repetition,
            commitments,
            &claims_by_repetition[repetition],
            &activations[repetition],
            &fold_challenges[repetition],
            &query_tapes[repetition],
            &proof.chains[repetition],
        )?;
        let packed_len =
            FrameV4::PackedBatchOpening(proof.chains[repetition].packed_opening.clone())
                .encode()
                .map_err(|error| C6WrapperPcsError::frame("C6 packed opening encode", error))?
                .len();
        transcript.append(
            C6_PACKED_OPENING_LABEL,
            u64::try_from(packed_len)
                .map_err(|_| C6WrapperPcsError::new("C6 packed opening length exceeds u64"))?,
        );
    }
    Ok(())
}

fn seal_chain(
    statement_digest: C6WrapperDigest,
    repetition: usize,
    cohorts: &[C6CommittedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: Vec<Fp2>,
    transcript: &mut Transcript,
) -> Result<SealedChain> {
    let common_point = claims[0].point.clone();
    let combined = cohorts
        .iter()
        .zip(claims)
        .map(|(cohort, claim)| cohort.combine(claim))
        .collect::<Result<Vec<_>>>()?;
    let max_outer_len = cohorts[0].commitment.spec.encoded_len()?;
    let max_coefficient_len = max_outer_len / 8;
    let mut current_coefficients = vec![Fp2::ZERO; max_coefficient_len];
    let mut current_codeword = vec![Fp2::ZERO; max_outer_len];
    let mut current_claim = Fp2::ZERO;
    let mut activated = activate_at_domain(
        max_outer_len,
        &combined,
        &activation_challenges,
        &mut current_coefficients,
        &mut current_codeword,
        &mut current_claim,
    )?;
    if activated == 0 {
        return Err(C6WrapperPcsError::new("C6 wrapper maximum cohort did not activate"));
    }

    let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
    let fold_descriptor = fold_descriptor_digest(statement_digest, repetition as u8, &commitments);
    let global_cohort_id = C6_GLOBAL_FOLD_COHORT_BASE
        .checked_add(repetition as u32)
        .ok_or_else(|| C6WrapperPcsError::new("C6 fold cohort id overflows"))?;
    let mut fold_frames = Vec::with_capacity(common_point.len());
    let mut fold_trees = Vec::with_capacity(common_point.len());
    let mut fold_challenges = Vec::with_capacity(common_point.len());
    let mut input_len = max_outer_len;

    for round_index in 0..common_point.len() {
        let (line_zero, line_one) =
            claim_line(&current_coefficients, &common_point[round_index + 1..])?;
        if interpolate(line_zero, line_one, common_point[round_index]) != current_claim {
            return Err(C6WrapperPcsError::new("C6 wrapper claim-line input mismatch"));
        }
        transcript.append(C6_FOLD_LINE_LABEL, 32);
        let fold_challenge = transcript.challenge_fp2();
        fold_challenges.push(fold_challenge);
        current_claim = interpolate(line_zero, line_one, fold_challenge);
        current_coefficients = fold_coefficients(&current_coefficients, fold_challenge)
            .map_err(|error| C6WrapperPcsError::frame("C6 coefficient fold", error))?;
        current_codeword = fold_codeword(&current_codeword, fold_challenge)
            .map_err(|error| C6WrapperPcsError::frame("C6 codeword fold", error))?;
        let output_len = input_len / 2;
        activated += activate_at_domain(
            output_len,
            &combined,
            &activation_challenges,
            &mut current_coefficients,
            &mut current_codeword,
            &mut current_claim,
        )?;

        let fold_round = u8::try_from(round_index + 1)
            .map_err(|_| C6WrapperPcsError::new("C6 fold round overflows"))?;
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: global_cohort_id,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round,
            },
            slot_descriptors: vec![Some(fold_descriptor)],
            outer_len: output_len,
            expected_symbol_count: 1,
        };
        let tree = CohortTreeV4::build_flat(config, vec![Some(current_codeword.clone())])
            .map_err(|error| C6WrapperPcsError::frame("C6 fold-tree commitment", error))?;
        let mut messages = vec![line_zero, line_one];
        if round_index + 1 == common_point.len() {
            if current_coefficients.as_slice() != [current_claim] {
                return Err(C6WrapperPcsError::new("C6 final folded scalar mismatch"));
            }
            messages.push(current_claim);
        }
        let frame = FoldCommitmentFrameV4 {
            cohort_id: global_cohort_id,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round,
            input_log2: input_len.ilog2() as u8,
            output_log2: output_len.ilog2() as u8,
            root_digest: tree.root(),
            ordered_message_symbols: messages,
        };
        let frame_len = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 fold frame encode", error))?
            .len();
        transcript.append(
            C6_FOLD_POST_CHALLENGE_LABEL,
            u64::try_from(
                frame_len
                    .checked_sub(32)
                    .ok_or_else(|| C6WrapperPcsError::new("C6 fold frame shorter than line"))?,
            )
            .map_err(|_| C6WrapperPcsError::new("C6 fold frame length exceeds u64"))?,
        );
        fold_frames.push(frame);
        fold_trees.push(tree);
        input_len = output_len;
    }
    if input_len != 1usize << C6_WRAPPER_TERMINAL_LOG2 || activated != cohorts.len() {
        return Err(C6WrapperPcsError::new("C6 wrapper activation schedule incomplete"));
    }
    Ok(SealedChain {
        repetition: repetition as u8,
        common_point,
        activation_challenges,
        fold_challenges,
        fold_frames,
        fold_trees,
    })
}

fn issue_chain_openings(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6CommittedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    sealed: SealedChain,
    query_draws: &[u64],
) -> Result<C6WrapperChainProof> {
    validate_query_draws(query_draws, cohorts[0].commitment.config.outer_depth())?;
    if sealed.common_point != claims[0].point
        || sealed.activation_challenges.len() != cohorts.len()
        || sealed.fold_challenges.len() != sealed.fold_frames.len()
        || sealed.fold_trees.len() != sealed.fold_frames.len()
    {
        return Err(C6WrapperPcsError::new("C6 sealed-chain geometry mismatch"));
    }
    let mut initial_groups = Vec::with_capacity(cohorts.len());
    for cohort in cohorts {
        let touched = all_slots(cohort.commitment.spec.slot_count);
        initial_groups.push(
            cohort
                .tree
                .open_initial(query_draws, &touched)
                .map_err(|error| C6WrapperPcsError::frame("C6 initial packed opening", error))?,
        );
    }
    let fold_rounds = sealed
        .fold_trees
        .iter()
        .map(|tree| {
            tree.open_fold_round(query_draws)
                .map_err(|error| C6WrapperPcsError::frame("C6 fold packed opening", error))
        })
        .collect::<Result<Vec<_>>>()?;
    let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
    let opening_schedule_digest = opening_schedule_digest(
        statement_digest,
        sealed.repetition,
        &commitments,
        claims,
        &sealed.fold_frames,
        query_draws,
    )?;
    let packed_opening =
        PackedBatchOpeningFrameV4 { opening_schedule_digest, initial_groups, fold_rounds };
    packed_opening
        .validate()
        .map_err(|error| C6WrapperPcsError::frame("C6 packed opening shape", error))?;
    Ok(C6WrapperChainProof {
        repetition: sealed.repetition,
        fold_frames: sealed.fold_frames,
        packed_opening,
    })
}

fn replay_fold_messages(
    repetition: usize,
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    chain: &C6WrapperChainProof,
    transcript: &mut Transcript,
) -> Result<Vec<Fp2>> {
    let common_point = &claims[0].point;
    if chain.fold_frames.len() != common_point.len() {
        return Err(C6WrapperPcsError::new("C6 fold-frame count mismatch"));
    }
    let max_outer_len = commitments[0].spec.encoded_len()?;
    let mut current_claim = Fp2::ZERO;
    activate_claims_at_domain(
        max_outer_len,
        commitments,
        claims,
        activation_challenges,
        &mut current_claim,
    )?;
    let fold_descriptor =
        fold_descriptor_digest(commitments[0].statement_digest, repetition as u8, commitments);
    let global_cohort_id = C6_GLOBAL_FOLD_COHORT_BASE
        .checked_add(repetition as u32)
        .ok_or_else(|| C6WrapperPcsError::new("C6 fold cohort id overflows"))?;
    let mut input_len = max_outer_len;
    let mut fold_challenges = Vec::with_capacity(common_point.len());
    for (round_index, frame) in chain.fold_frames.iter().enumerate() {
        frame.validate().map_err(|error| C6WrapperPcsError::frame("C6 fold frame", error))?;
        let output_len = input_len / 2;
        let expected_messages = if round_index + 1 == common_point.len() { 3 } else { 2 };
        if frame.cohort_id != global_cohort_id
            || frame.oracle_kind != OracleKindV4::GlobalFoldAggregate
            || usize::from(frame.fold_round) != round_index + 1
            || frame.input_log2 != input_len.ilog2() as u8
            || frame.output_log2 != output_len.ilog2() as u8
            || frame.ordered_message_symbols.len() != expected_messages
        {
            return Err(C6WrapperPcsError::new("C6 fold frame schedule mismatch"));
        }
        let line_zero = frame.ordered_message_symbols[0];
        let line_one = frame.ordered_message_symbols[1];
        if interpolate(line_zero, line_one, common_point[round_index]) != current_claim {
            return Err(C6WrapperPcsError::new("C6 fold line does not open current claim"));
        }
        transcript.append(C6_FOLD_LINE_LABEL, 32);
        let challenge = transcript.challenge_fp2();
        fold_challenges.push(challenge);
        current_claim = interpolate(line_zero, line_one, challenge);
        activate_claims_at_domain(
            output_len,
            commitments,
            claims,
            activation_challenges,
            &mut current_claim,
        )?;
        if round_index + 1 == common_point.len()
            && frame.ordered_message_symbols[2] != current_claim
        {
            return Err(C6WrapperPcsError::new("C6 terminal fold scalar mismatch"));
        }
        let frame_len = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 fold frame encode", error))?
            .len();
        transcript.append(
            C6_FOLD_POST_CHALLENGE_LABEL,
            u64::try_from(
                frame_len
                    .checked_sub(32)
                    .ok_or_else(|| C6WrapperPcsError::new("C6 fold frame shorter than line"))?,
            )
            .map_err(|_| C6WrapperPcsError::new("C6 fold frame length exceeds u64"))?,
        );
        input_len = output_len;
    }
    if input_len != 1usize << C6_WRAPPER_TERMINAL_LOG2 || fold_descriptor == [0; 32] {
        return Err(C6WrapperPcsError::new("C6 terminal fold geometry mismatch"));
    }
    Ok(fold_challenges)
}

#[allow(clippy::too_many_arguments)]
fn verify_chain_openings(
    statement_digest: C6WrapperDigest,
    repetition: usize,
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    fold_challenges: &[Fp2],
    query_draws: &[u64],
    chain: &C6WrapperChainProof,
) -> Result<()> {
    validate_query_draws(query_draws, commitments[0].config.outer_depth())?;
    chain
        .packed_opening
        .validate()
        .map_err(|error| C6WrapperPcsError::frame("C6 packed opening", error))?;
    if chain.packed_opening.initial_groups.len() != commitments.len()
        || chain.packed_opening.fold_rounds.len() != chain.fold_frames.len()
        || fold_challenges.len() != chain.fold_frames.len()
    {
        return Err(C6WrapperPcsError::new("C6 packed opening census mismatch"));
    }
    let expected_schedule = opening_schedule_digest(
        statement_digest,
        repetition as u8,
        commitments,
        claims,
        &chain.fold_frames,
        query_draws,
    )?;
    if chain.packed_opening.opening_schedule_digest != expected_schedule {
        return Err(C6WrapperPcsError::new("C6 packed opening schedule digest mismatch"));
    }
    for ((commitment, opening), claim) in
        commitments.iter().zip(&chain.packed_opening.initial_groups).zip(claims)
    {
        let touched = all_slots(commitment.spec.slot_count);
        if opening.cohort_id != commitment.spec.cohort_id
            || opening.domain_log2 != commitment.config.outer_depth()
            || opening.slot_count != commitment.spec.slot_count
            || opening.touched_slots != touched
            || claim.cohort_id != commitment.spec.cohort_id
        {
            return Err(C6WrapperPcsError::new("C6 initial opening schedule mismatch"));
        }
        verify_initial_packed_opening_v4(
            commitment.root,
            &commitment.config,
            query_draws,
            &touched,
            opening,
        )
        .map_err(|error| C6WrapperPcsError::frame("C6 initial Merkle opening", error))?;
    }
    let fold_descriptor = fold_descriptor_digest(statement_digest, repetition as u8, commitments);
    for (round_index, (frame, opening)) in
        chain.fold_frames.iter().zip(&chain.packed_opening.fold_rounds).enumerate()
    {
        let output_len = checked_pow2(frame.output_log2, "C6 fold output length")?;
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: frame.cohort_id,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: frame.fold_round,
            },
            slot_descriptors: vec![Some(fold_descriptor)],
            outer_len: output_len,
            expected_symbol_count: 1,
        };
        if usize::from(frame.fold_round) != round_index + 1
            || opening.fold_round != frame.fold_round
            || opening.domain_log2 != frame.output_log2
        {
            return Err(C6WrapperPcsError::new("C6 fold opening schedule mismatch"));
        }
        verify_fold_round_packed_opening_v4(frame.root_digest, &config, query_draws, opening)
            .map_err(|error| C6WrapperPcsError::frame("C6 fold Merkle opening", error))?;
    }
    verify_query_chain(
        commitments,
        claims,
        activation_challenges,
        fold_challenges,
        query_draws,
        chain,
    )?;
    let final_scalar = chain
        .fold_frames
        .last()
        .and_then(|frame| frame.ordered_message_symbols.get(2))
        .copied()
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 final scalar"))?;
    if chain
        .packed_opening
        .fold_rounds
        .last()
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 final fold opening"))?
        .opened_symbols
        .iter()
        .any(|symbol| *symbol != final_scalar)
    {
        return Err(C6WrapperPcsError::new("C6 final codeword is not constant"));
    }
    Ok(())
}

fn verify_query_chain(
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    fold_challenges: &[Fp2],
    query_draws: &[u64],
    chain: &C6WrapperChainProof,
) -> Result<()> {
    let mut index_sets = BTreeMap::<u8, Vec<u64>>::new();
    for commitment in commitments {
        index_sets.entry(commitment.config.outer_depth()).or_insert(
            projected_query_indices(query_draws, commitment.config.outer_depth())
                .map_err(|error| C6WrapperPcsError::frame("C6 initial query projection", error))?,
        );
    }
    for frame in &chain.fold_frames {
        index_sets.entry(frame.output_log2).or_insert(
            projected_query_indices(query_draws, frame.output_log2)
                .map_err(|error| C6WrapperPcsError::frame("C6 fold query projection", error))?,
        );
    }

    let max_len = commitments[0].spec.encoded_len()?;
    for draw in query_draws {
        let mut current_len = max_len;
        for (round_index, challenge) in fold_challenges.iter().enumerate() {
            let half = current_len / 2;
            let base = *draw & (half as u64 - 1);
            let positive = if round_index == 0 {
                activated_initial_value_at(
                    commitments,
                    claims,
                    activation_challenges,
                    &chain.packed_opening,
                    &index_sets,
                    current_len,
                    base,
                )?
            } else {
                fold_opened_symbol_at(&chain.packed_opening, &index_sets, round_index - 1, base)?
            };
            let negative_index = base + half as u64;
            let negative = if round_index == 0 {
                activated_initial_value_at(
                    commitments,
                    claims,
                    activation_challenges,
                    &chain.packed_opening,
                    &index_sets,
                    current_len,
                    negative_index,
                )?
            } else {
                fold_opened_symbol_at(
                    &chain.packed_opening,
                    &index_sets,
                    round_index - 1,
                    negative_index,
                )?
            };
            let mut expected = fold_pair(positive, negative, base, current_len, *challenge)?;
            let output_len = half;
            expected += activated_initial_value_at(
                commitments,
                claims,
                activation_challenges,
                &chain.packed_opening,
                &index_sets,
                output_len,
                base,
            )?;
            let actual =
                fold_opened_symbol_at(&chain.packed_opening, &index_sets, round_index, base)?;
            if actual != expected {
                return Err(C6WrapperPcsError::new("C6 queried fold relation mismatch"));
            }
            current_len = output_len;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn activated_initial_value_at(
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    opening: &PackedBatchOpeningFrameV4,
    index_sets: &BTreeMap<u8, Vec<u64>>,
    domain_len: usize,
    outer_index: u64,
) -> Result<Fp2> {
    let domain_log2 = domain_len.ilog2() as u8;
    let indices = index_sets
        .get(&domain_log2)
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 initial query index set"))?;
    let Some(coordinate_position) = indices.iter().position(|index| *index == outer_index) else {
        return Err(C6WrapperPcsError::new("missing C6 initial query coordinate"));
    };
    let mut value = Fp2::ZERO;
    for (group_index, ((commitment, claim), activation)) in
        commitments.iter().zip(claims).zip(activation_challenges).enumerate()
    {
        if commitment.config.outer_len != domain_len {
            continue;
        }
        let packed = &opening.initial_groups[group_index];
        let width = usize::from(commitment.spec.slot_count);
        let start = coordinate_position
            .checked_mul(width)
            .ok_or_else(|| C6WrapperPcsError::new("C6 initial opening offset overflows"))?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| C6WrapperPcsError::new("C6 initial opening range overflows"))?;
        let symbols = packed
            .opened_symbols
            .get(start..end)
            .ok_or_else(|| C6WrapperPcsError::new("C6 initial opening symbol range"))?;
        let aggregate = symbols
            .iter()
            .zip(&claim.slot_weights)
            .fold(Fp2::ZERO, |sum, (symbol, weight)| sum + *weight * *symbol);
        value += *activation * aggregate;
    }
    Ok(value)
}

fn fold_opened_symbol_at(
    opening: &PackedBatchOpeningFrameV4,
    index_sets: &BTreeMap<u8, Vec<u64>>,
    round_index: usize,
    outer_index: u64,
) -> Result<Fp2> {
    let round = opening
        .fold_rounds
        .get(round_index)
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 fold opening round"))?;
    let indices = index_sets
        .get(&round.domain_log2)
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 fold query index set"))?;
    let position = indices
        .iter()
        .position(|index| *index == outer_index)
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 fold query coordinate"))?;
    round
        .opened_symbols
        .get(position)
        .copied()
        .ok_or_else(|| C6WrapperPcsError::new("missing C6 fold opening symbol"))
}

fn activate_at_domain(
    domain_len: usize,
    combined: &[CombinedCohort],
    activation_challenges: &[Fp2],
    current_coefficients: &mut [Fp2],
    current_codeword: &mut [Fp2],
    current_claim: &mut Fp2,
) -> Result<usize> {
    let mut activated = 0usize;
    for (group, activation) in combined.iter().zip(activation_challenges) {
        if group.outer_len != domain_len {
            continue;
        }
        if group.coefficients.len() != current_coefficients.len()
            || group.codeword.len() != current_codeword.len()
        {
            return Err(C6WrapperPcsError::new("C6 activation domain mismatch"));
        }
        for (output, value) in current_coefficients.iter_mut().zip(&group.coefficients) {
            *output += *activation * *value;
        }
        for (output, value) in current_codeword.iter_mut().zip(&group.codeword) {
            *output += *activation * *value;
        }
        *current_claim += *activation * group.claimed_value;
        activated += 1;
    }
    Ok(activated)
}

fn activate_claims_at_domain(
    domain_len: usize,
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    current_claim: &mut Fp2,
) -> Result<()> {
    for ((commitment, claim), activation) in
        commitments.iter().zip(claims).zip(activation_challenges)
    {
        if commitment.spec.encoded_len()? == domain_len {
            *current_claim += *activation * claim.value;
        }
    }
    Ok(())
}

fn append_terminal_claims(
    transcript: &mut Transcript,
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
) -> Result<()> {
    let count = claims_by_repetition.iter().try_fold(0usize, |sum, claims| {
        sum.checked_add(claims.len())
            .ok_or_else(|| C6WrapperPcsError::new("C6 terminal claim count overflows"))
    })?;
    let bytes = count
        .checked_mul(16)
        .ok_or_else(|| C6WrapperPcsError::new("C6 terminal claim bytes overflow"))?;
    transcript.append(
        C6_TERMINAL_CLAIMS_LABEL,
        u64::try_from(bytes)
            .map_err(|_| C6WrapperPcsError::new("C6 terminal claim bytes exceed u64"))?,
    );
    Ok(())
}

fn derive_activation_challenges(transcript: &mut Transcript, cohort_count: usize) -> Vec<Vec<Fp2>> {
    (0..C6_WRAPPER_REPETITIONS)
        .map(|_| (0..cohort_count).map(|_| transcript.challenge_fp2()).collect())
        .collect()
}

fn validate_statement_and_claims(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
) -> Result<()> {
    validate_commitments(commitments)?;
    if statement_digest == [0; 32]
        || commitments.iter().any(|commitment| commitment.statement_digest != statement_digest)
        || claims_by_repetition.len() != C6_WRAPPER_REPETITIONS
    {
        return Err(C6WrapperPcsError::new("C6 wrapper statement or repetition mismatch"));
    }
    for (repetition, claims) in claims_by_repetition.iter().enumerate() {
        if claims.len() != commitments.len() {
            return Err(C6WrapperPcsError::new("C6 wrapper claim census mismatch"));
        }
        let common_point = &claims[0].point;
        for (commitment, claim) in commitments.iter().zip(claims) {
            validate_claim(commitment, claim)?;
            if usize::from(claim.repetition) != repetition
                || claim.point.len() > common_point.len()
                || claim.point != common_point[common_point.len() - claim.point.len()..]
            {
                return Err(C6WrapperPcsError::new(
                    "C6 wrapper points are not one common-point suffix schedule",
                ));
            }
        }
    }
    Ok(())
}

fn validate_commitments(commitments: &[C6WrapperCommitment]) -> Result<()> {
    if commitments.is_empty() || commitments.len() > C6_WRAPPER_ACTIVE_SLOTS {
        return Err(C6WrapperPcsError::new("C6 wrapper commitment census mismatch"));
    }
    let mut seen = BTreeSet::new();
    let mut active_slots = 0usize;
    for (index, commitment) in commitments.iter().enumerate() {
        commitment.validate()?;
        active_slots = active_slots
            .checked_add(usize::from(commitment.spec.slot_count))
            .ok_or_else(|| C6WrapperPcsError::new("C6 active slot census overflows"))?;
        if !seen.insert(commitment.spec.cohort_id) {
            return Err(C6WrapperPcsError::new("duplicate C6 wrapper cohort id"));
        }
        if index > 0 {
            let previous = commitments[index - 1].spec;
            let previous_domain = previous.encoded_domain_log2()?;
            let domain = commitment.spec.encoded_domain_log2()?;
            if previous_domain < domain
                || (previous_domain == domain && previous.cohort_id >= commitment.spec.cohort_id)
            {
                return Err(C6WrapperPcsError::new(
                    "C6 wrapper commitments are not canonically ordered",
                ));
            }
        }
    }
    if active_slots > C6_WRAPPER_ACTIVE_SLOTS {
        return Err(C6WrapperPcsError::new("C6 wrapper active-slot cap exceeded"));
    }
    let max_domain = commitments[0].spec.encoded_domain_log2()?;
    if max_domain <= C6_WRAPPER_TERMINAL_LOG2 || max_domain - C6_WRAPPER_TERMINAL_LOG2 > 30 {
        return Err(C6WrapperPcsError::new("C6 wrapper fold depth is outside codec"));
    }
    Ok(())
}

fn validate_claim(commitment: &C6WrapperCommitment, claim: &C6WrapperOpeningClaim) -> Result<()> {
    if claim.cohort_id != commitment.spec.cohort_id
        || claim.point.len() != usize::from(commitment.spec.coefficient_log2()?)
        || claim.slot_weights.len() != usize::from(commitment.spec.slot_count)
    {
        return Err(C6WrapperPcsError::new("C6 wrapper opening claim geometry mismatch"));
    }
    Ok(())
}

fn validate_query_draws(query_draws: &[u64], draw_width: u8) -> Result<()> {
    let bound = 1u64
        .checked_shl(u32::from(draw_width))
        .ok_or_else(|| C6WrapperPcsError::new("C6 query width overflows"))?;
    if query_draws.len() != C6_WRAPPER_QUERY_COUNT || query_draws.iter().any(|draw| *draw >= bound)
    {
        return Err(C6WrapperPcsError::new("C6 exact query tape mismatch"));
    }
    Ok(())
}

fn claim_line(coefficients: &[Fp2], remaining_point: &[Fp2]) -> Result<(Fp2, Fp2)> {
    if coefficients.len() < 2
        || coefficients.len() / 2
            != 1usize
                .checked_shl(remaining_point.len() as u32)
                .ok_or_else(|| C6WrapperPcsError::new("C6 claim-line point overflows"))?
    {
        return Err(C6WrapperPcsError::new("C6 claim-line geometry mismatch"));
    }
    let mut even = Vec::with_capacity(coefficients.len() / 2);
    let mut odd = Vec::with_capacity(coefficients.len() / 2);
    for pair in coefficients.chunks_exact(2) {
        even.push(pair[0]);
        odd.push(pair[1]);
    }
    let at_zero = evaluate_multilinear_coefficients(&even, remaining_point)
        .map_err(|error| C6WrapperPcsError::frame("C6 claim-line zero", error))?;
    let odd_value = evaluate_multilinear_coefficients(&odd, remaining_point)
        .map_err(|error| C6WrapperPcsError::frame("C6 claim-line one", error))?;
    Ok((at_zero, at_zero + odd_value))
}

fn interpolate(at_zero: Fp2, at_one: Fp2, point: Fp2) -> Fp2 {
    at_zero + point * (at_one - at_zero)
}

fn fold_pair(
    positive: Fp2,
    negative: Fp2,
    base_index: u64,
    input_len: usize,
    challenge: Fp2,
) -> Result<Fp2> {
    let omega = root_of_unity(input_len.ilog2())
        .map_err(|error| C6WrapperPcsError::frame("C6 fold root", error))?;
    let x = fp2_pow(omega, u128::from(base_index));
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    let even = (positive + negative) * inverse_two;
    let odd = (positive - negative) * inverse_two * x.inv();
    Ok(even + challenge * odd)
}

fn slot_descriptor_digest(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    slot: u16,
) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(C6_SLOT_DESCRIPTOR_CONTEXT);
    hasher.update(&c6_wrapper_profile_digest());
    hasher.update(&statement_digest);
    hasher.update(&spec.cohort_id.to_le_bytes());
    hasher.update(&[spec.oracle_kind as u8, spec.payload_log2]);
    hasher.update(&spec.slot_count.to_le_bytes());
    hasher.update(&slot.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn fold_descriptor_digest(
    statement_digest: C6WrapperDigest,
    repetition: u8,
    commitments: &[C6WrapperCommitment],
) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(C6_FOLD_DESCRIPTOR_CONTEXT);
    hasher.update(&c6_wrapper_profile_digest());
    hasher.update(&statement_digest);
    hasher.update(&[repetition]);
    hasher.update(&(commitments.len() as u16).to_le_bytes());
    for commitment in commitments {
        hasher.update(&commitment.spec.cohort_id.to_le_bytes());
        hasher.update(&commitment.root);
    }
    *hasher.finalize().as_bytes()
}

fn opening_schedule_digest(
    statement_digest: C6WrapperDigest,
    repetition: u8,
    commitments: &[C6WrapperCommitment],
    claims: &[C6WrapperOpeningClaim],
    fold_frames: &[FoldCommitmentFrameV4],
    query_draws: &[u64],
) -> Result<Digest> {
    let mut hasher = blake3::Hasher::new_derive_key(C6_OPENING_SCHEDULE_CONTEXT);
    hasher.update(&c6_wrapper_profile_digest());
    hasher.update(&statement_digest);
    hasher.update(&[repetition]);
    hasher.update(
        &u16::try_from(commitments.len())
            .map_err(|_| C6WrapperPcsError::new("C6 schedule cohort count overflows"))?
            .to_le_bytes(),
    );
    for (commitment, claim) in commitments.iter().zip(claims) {
        hasher.update(&commitment.spec.cohort_id.to_le_bytes());
        hasher.update(&[commitment.spec.oracle_kind as u8, commitment.spec.payload_log2]);
        hasher.update(&commitment.spec.slot_count.to_le_bytes());
        hasher.update(&commitment.root);
        hasher.update(
            &u16::try_from(claim.point.len())
                .map_err(|_| C6WrapperPcsError::new("C6 schedule point length overflows"))?
                .to_le_bytes(),
        );
        for value in &claim.point {
            hash_fp2(&mut hasher, *value);
        }
        hasher.update(
            &u16::try_from(claim.slot_weights.len())
                .map_err(|_| C6WrapperPcsError::new("C6 schedule weight count overflows"))?
                .to_le_bytes(),
        );
        for weight in &claim.slot_weights {
            hash_fp2(&mut hasher, *weight);
        }
        hash_fp2(&mut hasher, claim.value);
    }
    hasher.update(
        &u8::try_from(fold_frames.len())
            .map_err(|_| C6WrapperPcsError::new("C6 schedule fold count overflows"))?
            .to_le_bytes(),
    );
    for frame in fold_frames {
        let encoded = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 schedule fold frame", error))?;
        hasher.update(
            &u32::try_from(encoded.len())
                .map_err(|_| C6WrapperPcsError::new("C6 schedule frame length overflows"))?
                .to_le_bytes(),
        );
        hasher.update(&encoded);
    }
    let draw_width = commitments[0].config.outer_depth();
    hasher.update(&[draw_width]);
    hasher.update(
        &u16::try_from(query_draws.len())
            .map_err(|_| C6WrapperPcsError::new("C6 schedule draw count overflows"))?
            .to_le_bytes(),
    );
    for draw in query_draws {
        hasher.update(&draw.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

fn all_slots(slot_count: u16) -> Vec<u16> {
    (0..slot_count).collect()
}

fn checked_pow2(log2: u8, context: &'static str) -> Result<usize> {
    1usize
        .checked_shl(u32::from(log2))
        .ok_or_else(|| C6WrapperPcsError::new(format!("{context} overflows")))
}

fn take_v4_frame(bytes: &[u8], cursor: &mut usize) -> Result<FrameV4> {
    let header_end = cursor
        .checked_add(HEADER_LEN_V4)
        .ok_or_else(|| C6WrapperPcsError::new("C6 frame header offset overflows"))?;
    let header = bytes
        .get(*cursor..header_end)
        .ok_or_else(|| C6WrapperPcsError::new("truncated C6 wrapper frame header"))?;
    let body_len = usize::try_from(u32::from_le_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| C6WrapperPcsError::new("truncated C6 wrapper frame length"))?,
    ))
    .map_err(|_| C6WrapperPcsError::new("C6 wrapper frame length exceeds usize"))?;
    let end = header_end
        .checked_add(body_len)
        .ok_or_else(|| C6WrapperPcsError::new("C6 wrapper frame end overflows"))?;
    let encoded = bytes
        .get(*cursor..end)
        .ok_or_else(|| C6WrapperPcsError::new("truncated C6 wrapper frame body"))?;
    let frame = decode_v4(encoded)
        .map_err(|error| C6WrapperPcsError::frame("C6 embedded frame decode", error))?;
    *cursor = end;
    Ok(frame)
}

/// Materialized worst-case production codec fixture.  Payload symbols and
/// digests are zero because this function measures grammar only; it is never
/// a cryptographic proof and is not accepted by the verifier.
pub fn production_c6_wrapper_codec_reference() -> Result<C6WrapperPcsProof> {
    let specs = production_c6_wrapper_specs();
    let mut initial_groups = Vec::with_capacity(specs.len());
    for spec in specs {
        let domain_log2 = spec.encoded_domain_log2()?;
        let (opened, siblings) = paired_wire_maximum(domain_log2, usize::from(spec.slot_count))?;
        initial_groups.push(InitialOpeningGroupV4 {
            cohort_id: spec.cohort_id,
            domain_log2,
            slot_count: spec.slot_count,
            touched_slots: all_slots(spec.slot_count),
            opened_symbols: vec![Fp2::ZERO; opened],
            inner_sibling_digests: Vec::new(),
            outer_sibling_digests: vec![[0; 32]; siblings],
        });
    }
    let mut fold_rounds = Vec::with_capacity(25);
    for (index, domain_log2) in (C6_WRAPPER_TERMINAL_LOG2..28u8).rev().enumerate() {
        let (opened, siblings) = paired_wire_maximum(domain_log2, 1)?;
        fold_rounds.push(FoldRoundOpeningV4 {
            fold_round: u8::try_from(index + 1)
                .map_err(|_| C6WrapperPcsError::new("C6 codec fold round overflows"))?,
            domain_log2,
            opened_symbols: vec![Fp2::ZERO; opened],
            outer_sibling_digests: vec![[0; 32]; siblings],
        });
    }
    let packed =
        PackedBatchOpeningFrameV4 { opening_schedule_digest: [0; 32], initial_groups, fold_rounds };
    packed
        .validate()
        .map_err(|error| C6WrapperPcsError::frame("C6 production codec fixture", error))?;
    let mut chains = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let mut fold_frames = Vec::with_capacity(25);
        for round_index in 0..25usize {
            let input_log2 = 28u8 - round_index as u8;
            let output_log2 = input_log2 - 1;
            let mut messages = vec![Fp2::ZERO, Fp2::ZERO];
            if round_index == 24 {
                messages.push(Fp2::ZERO);
            }
            fold_frames.push(FoldCommitmentFrameV4 {
                cohort_id: C6_GLOBAL_FOLD_COHORT_BASE + repetition as u32,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: (round_index + 1) as u8,
                input_log2,
                output_log2,
                root_digest: [0; 32],
                ordered_message_symbols: messages,
            });
        }
        chains.push(C6WrapperChainProof {
            repetition: repetition as u8,
            fold_frames,
            packed_opening: packed.clone(),
        });
    }
    Ok(C6WrapperPcsProof { chains })
}

fn paired_wire_maximum(domain_log2: u8, touched_slots: usize) -> Result<(usize, usize)> {
    if domain_log2 <= 1 || touched_slots == 0 {
        return Err(C6WrapperPcsError::new("invalid C6 codec wire geometry"));
    }
    let half_depth = domain_log2 - 1;
    let half_capacity = checked_pow2(half_depth, "C6 codec half-domain")?;
    let maximum_distinct = C6_WRAPPER_QUERY_COUNT.min(half_capacity);
    let mut memo = BTreeMap::new();
    let mut best: Option<(usize, usize, usize)> = None;
    for distinct in 1..=maximum_distinct {
        let opened = distinct
            .checked_mul(2)
            .and_then(|value| value.checked_mul(touched_slots))
            .ok_or_else(|| C6WrapperPcsError::new("C6 codec opened symbols overflow"))?;
        let siblings = max_merkle_frontier(half_depth, distinct, &mut memo)?
            .checked_mul(2)
            .ok_or_else(|| C6WrapperPcsError::new("C6 codec sibling count overflows"))?;
        let payload = opened
            .checked_mul(16)
            .and_then(|value| value.checked_add(siblings.checked_mul(32)?))
            .ok_or_else(|| C6WrapperPcsError::new("C6 codec payload bytes overflow"))?;
        if best.map(|(_, _, best_payload)| payload > best_payload).unwrap_or(true) {
            best = Some((opened, siblings, payload));
        }
    }
    best.map(|(opened, siblings, _)| (opened, siblings))
        .ok_or_else(|| C6WrapperPcsError::new("empty C6 codec wire maximum"))
}

fn max_merkle_frontier(
    depth: u8,
    opened: usize,
    memo: &mut BTreeMap<(u8, usize), usize>,
) -> Result<usize> {
    if let Some(value) = memo.get(&(depth, opened)) {
        return Ok(*value);
    }
    let capacity = checked_pow2(depth, "C6 codec Merkle capacity")?;
    if opened == 0 || opened > capacity {
        return Err(C6WrapperPcsError::new("invalid C6 codec Merkle frontier"));
    }
    let value = if depth == 0 {
        0
    } else {
        let half = capacity / 2;
        let mut best = if opened <= half {
            Some(
                max_merkle_frontier(depth - 1, opened, memo)?
                    .checked_add(1)
                    .ok_or_else(|| C6WrapperPcsError::new("C6 frontier count overflows"))?,
            )
        } else {
            None
        };
        let first_left = 1usize.max(opened.saturating_sub(half));
        let last_left = half.min(opened.saturating_sub(1));
        for left in first_left..=last_left {
            let right = opened - left;
            let candidate = max_merkle_frontier(depth - 1, left, memo)?
                .checked_add(max_merkle_frontier(depth - 1, right, memo)?)
                .ok_or_else(|| C6WrapperPcsError::new("C6 frontier count overflows"))?;
            best = Some(best.map(|current| current.max(candidate)).unwrap_or(candidate));
        }
        best.ok_or_else(|| C6WrapperPcsError::new("empty C6 codec Merkle recurrence"))?
    };
    memo.insert((depth, opened), value);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::ntt::evaluate_multilinear_table;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(17 * value + 3))
    }

    fn statement() -> C6WrapperDigest {
        [0x6c; 32]
    }

    fn scaled_specs() -> [C6WrapperCohortSpec; 3] {
        [
            C6WrapperCohortSpec {
                cohort_id: 11,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 3,
                slot_count: 2,
            },
            C6WrapperCohortSpec {
                cohort_id: 12,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 2,
                slot_count: 2,
            },
            C6WrapperCohortSpec {
                cohort_id: 13,
                oracle_kind: C6WrapperOracleKind::Auxiliary,
                payload_log2: 2,
                slot_count: 4,
            },
        ]
    }

    fn slots(spec: C6WrapperCohortSpec) -> Vec<C6WrapperSlotWitness> {
        let len = spec.payload_len().unwrap();
        (0..spec.slot_count)
            .map(|slot| {
                let base = 1_000 * u64::from(spec.cohort_id) + 100 * u64::from(slot);
                match spec.oracle_kind {
                    C6WrapperOracleKind::Witness => C6WrapperSlotWitness::Witness {
                        witness: (0..len).map(|index| symbol(base + index as u64 + 1)).collect(),
                        zk_mask: (0..len).map(|index| symbol(base + index as u64 + 501)).collect(),
                    },
                    C6WrapperOracleKind::Auxiliary => C6WrapperSlotWitness::Auxiliary {
                        evaluations: (0..len)
                            .map(|index| symbol(base + index as u64 + 1))
                            .collect(),
                    },
                }
            })
            .collect()
    }

    fn honest_claim(
        cohort: &C6CommittedWrapperCohort,
        repetition: usize,
        common_point: &[Fp2],
    ) -> C6WrapperOpeningClaim {
        let point_len = cohort.commitment.spec.coefficient_log2().unwrap() as usize;
        let point = common_point[common_point.len() - point_len..].to_vec();
        let slot_weights = (0..cohort.commitment.spec.slot_count)
            .map(|slot| symbol(70_000 + 1_000 * repetition as u64 + u64::from(slot) + 1))
            .collect::<Vec<_>>();
        let mut coefficients = vec![Fp2::ZERO; cohort.commitment.spec.coefficient_len().unwrap()];
        for (source, weight) in cohort.coefficients.iter().zip(&slot_weights) {
            for (output, value) in coefficients.iter_mut().zip(source) {
                *output += *weight * *value;
            }
        }
        let value = evaluate_multilinear_coefficients(&coefficients, &point).unwrap();
        C6WrapperOpeningClaim {
            repetition: repetition as u8,
            cohort_id: cohort.commitment.spec.cohort_id,
            point,
            slot_weights,
            value,
        }
    }

    fn fixture(
    ) -> (Vec<C6CommittedWrapperCohort>, Vec<C6WrapperCommitment>, Vec<Vec<C6WrapperOpeningClaim>>)
    {
        let cohorts = scaled_specs()
            .into_iter()
            .map(|spec| commit_c6_wrapper_cohort(statement(), spec, slots(spec)).unwrap())
            .collect::<Vec<_>>();
        let claims = (0..C6_WRAPPER_REPETITIONS)
            .map(|repetition| {
                let common_point = (0..4)
                    .map(|index| symbol(90_000 + 100 * repetition as u64 + index))
                    .collect::<Vec<_>>();
                cohorts
                    .iter()
                    .map(|cohort| honest_claim(cohort, repetition, &common_point))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect();
        (cohorts, commitments, claims)
    }

    fn assert_rejects(
        commitments: &[C6WrapperCommitment],
        claims: &[Vec<C6WrapperOpeningClaim>],
        proof: &C6WrapperPcsProof,
        seed: [u8; 32],
    ) {
        let mut verifier_tx = Transcript::new(seed);
        assert!(verify_c6_wrapper_pcs(statement(), commitments, claims, proof, &mut verifier_tx)
            .is_err());
    }

    #[test]
    fn witness_zero_suffix_selects_the_non_mask_half() {
        let spec = C6WrapperCohortSpec {
            cohort_id: 9,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 2,
            slot_count: 1,
        };
        let witness = vec![symbol(1), symbol(2), symbol(3), symbol(4)];
        let zk_mask = vec![symbol(101), symbol(102), symbol(103), symbol(104)];
        let cohort = commit_c6_wrapper_cohort(
            statement(),
            spec,
            vec![C6WrapperSlotWitness::Witness {
                witness: witness.clone(),
                zk_mask: zk_mask.clone(),
            }],
        )
        .unwrap();
        let base_point = vec![symbol(31), symbol(32)];
        let mut witness_point = base_point.clone();
        witness_point.push(Fp2::ZERO);
        let mut mask_point = base_point.clone();
        mask_point.push(Fp2::ONE);
        assert_eq!(
            evaluate_multilinear_coefficients(&cohort.coefficients[0], &witness_point).unwrap(),
            evaluate_multilinear_table(&witness, &base_point).unwrap()
        );
        assert_eq!(
            evaluate_multilinear_coefficients(&cohort.coefficients[0], &mask_point).unwrap(),
            evaluate_multilinear_table(&zk_mask, &base_point).unwrap()
        );
    }

    #[test]
    fn two_response_local_chains_open_all_slots_and_roundtrip() {
        let (cohorts, commitments, claims) = fixture();
        let seed = [0x37; 32];
        let mut prover_tx = Transcript::new(seed);
        let proof = prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut prover_tx).unwrap();
        assert_eq!(proof.chains.len(), C6_WRAPPER_REPETITIONS);
        for chain in &proof.chains {
            assert_eq!(chain.fold_frames.len(), 4);
            assert_eq!(chain.packed_opening.initial_groups.len(), cohorts.len());
            for (group, commitment) in chain.packed_opening.initial_groups.iter().zip(&commitments)
            {
                assert_eq!(group.touched_slots, all_slots(commitment.spec.slot_count));
            }
            // 86 draws into only 64 first-round +/- bases necessarily
            // collide; the canonical wire retains only the projected set.
            assert!(
                chain.packed_opening.initial_groups[0].opened_symbols.len()
                    < 2 * C6_WRAPPER_QUERY_COUNT * usize::from(commitments[0].spec.slot_count)
            );
        }
        let encoded = proof.canonical_bytes().unwrap();
        let decoded = C6WrapperPcsProof::decode(&commitments, &encoded).unwrap();
        assert_eq!(decoded, proof);

        let mut verifier_tx = Transcript::new(seed);
        verify_c6_wrapper_pcs(statement(), &commitments, &claims, &decoded, &mut verifier_tx)
            .unwrap();
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());
        assert_eq!(
            prover_tx.bytes_for(C6_TERMINAL_CLAIMS_LABEL),
            (C6_WRAPPER_REPETITIONS * commitments.len() * 16) as u64
        );
    }

    #[test]
    fn packed_chain_rejects_root_symbol_sibling_line_claim_point_and_tape_tampers() {
        let (cohorts, commitments, claims) = fixture();
        let seed = [0x51; 32];
        let mut prover_tx = Transcript::new(seed);
        let proof = prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut prover_tx).unwrap();

        let mut bad = proof.clone();
        bad.chains[0].fold_frames[0].ordered_message_symbols[0] += Fp2::ONE;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        bad.chains[1].fold_frames.last_mut().unwrap().ordered_message_symbols[2] += Fp2::ONE;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        bad.chains[0].fold_frames[1].root_digest[0] ^= 1;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        bad.chains[0].packed_opening.initial_groups[0].opened_symbols[0] += Fp2::ONE;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        let group = bad.chains[0]
            .packed_opening
            .initial_groups
            .iter_mut()
            .find(|group| !group.outer_sibling_digests.is_empty())
            .unwrap();
        group.outer_sibling_digests[0][0] ^= 1;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        bad.chains[1].packed_opening.fold_rounds[0].opened_symbols[0] += Fp2::ONE;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad = proof.clone();
        bad.chains[0].packed_opening.opening_schedule_digest[0] ^= 1;
        assert_rejects(&commitments, &claims, &bad, seed);

        let mut bad_claims = claims.clone();
        bad_claims[0][0].value += Fp2::ONE;
        assert_rejects(&commitments, &bad_claims, &proof, seed);

        let mut bad_claims = claims.clone();
        bad_claims[0][1].point[0] += Fp2::ONE;
        assert_rejects(&commitments, &bad_claims, &proof, seed);

        let mut bad_claims = claims.clone();
        bad_claims[1][2].slot_weights[0] += Fp2::ONE;
        assert_rejects(&commitments, &bad_claims, &proof, seed);

        let mut bad_commitments = commitments.clone();
        bad_commitments[0].root[0] ^= 1;
        assert_rejects(&bad_commitments, &claims, &proof, seed);

        assert_rejects(&commitments, &claims, &proof, [0x52; 32]);

        let encoded = proof.canonical_bytes().unwrap();
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(C6WrapperPcsProof::decode(&commitments, &trailing).is_err());
        let mut bad_magic = encoded;
        bad_magic[0] ^= 1;
        assert!(C6WrapperPcsProof::decode(&commitments, &bad_magic).is_err());
    }

    #[test]
    fn false_prover_claim_and_non_suffix_schedule_fail_before_a_proof() {
        let (cohorts, _, mut claims) = fixture();
        claims[0][0].value += Fp2::ONE;
        let mut transcript = Transcript::new([0x71; 32]);
        assert!(prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut transcript).is_err());

        let (_, _, mut claims) = fixture();
        claims[0][1].point[0] += Fp2::ONE;
        let mut transcript = Transcript::new([0x72; 32]);
        assert!(prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut transcript).is_err());
    }

    #[test]
    fn production_profile_and_codec_match_the_preregistered_roofline() {
        let specs = production_c6_wrapper_specs();
        assert_eq!(
            specs.iter().map(|spec| usize::from(spec.slot_count)).sum::<usize>(),
            C6_WRAPPER_ACTIVE_SLOTS
        );
        assert_eq!(
            specs.iter().map(|spec| spec.encoded_domain_log2().unwrap()).collect::<Vec<_>>(),
            vec![28, 27, 25, 23, 19]
        );
        for spec in specs {
            spec.validate().unwrap();
        }

        let proof = production_c6_wrapper_codec_reference().unwrap();
        assert_eq!(proof.encoded_len().unwrap(), C6_WRAPPER_TWO_CHAIN_BYTES);
        for chain in &proof.chains {
            let fold_bytes = chain
                .fold_frames
                .iter()
                .map(|frame| FrameV4::FoldCommitment(frame.clone()).encode().unwrap().len() as u64)
                .sum::<u64>();
            assert_eq!(fold_bytes, 2_266);
            let components = chain.packed_opening.byte_components().unwrap();
            assert_eq!(components.opened_symbols, 14_528);
            assert_eq!(components.initial_inner_siblings, 0);
            assert_eq!(components.initial_outer_siblings + components.fold_outer_siblings, 49_052);
            assert_eq!(components.metadata_bytes, 534);
            assert_eq!(components.serialized_bytes, 1_802_646);
            assert_eq!(fold_bytes + components.serialized_bytes, C6_WRAPPER_ONE_CHAIN_BYTES);
        }
    }
}
