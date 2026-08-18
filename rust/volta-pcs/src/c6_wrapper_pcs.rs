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
use std::path::Path;

use volta_accel::{Backend, BackendKind};
use volta_field::{Fp, Fp2};
use volta_mac::Transcript;
use volta_proto::{C6ResidualRelationManifest, C6ResidualRelationRootBound};

use crate::c6_hidden_u::C6HiddenUFamily;
use crate::c6_hidden_u_sumcheck::C6HiddenUOpeningClaim;
use crate::c6_persistent_cache::{C6PersistentCacheStaticProfile, C6_PERSISTENT_CACHE_SLOTS};
use crate::c6_wrapper_persisted::{
    commit_production_c6_wrapper_fold_cuda, persist_scaled_c6_wrapper_fold_reference,
    C6PersistedFoldOpening, C6PersistedWrapperCohort,
};
use crate::x4::accounting::projected_query_indices;
use crate::x4::cuda_v4::X4bCudaCommitMetricsV4;
use crate::x4::frame::Digest;
use crate::x4::frame_v4::{
    decode_v4, FoldCommitmentFrameV4, FoldRoundOpeningV4, FrameV4, InitialOpeningGroupV4,
    OracleKindV4, PackedBatchOpeningFrameV4, HEADER_LEN_V4,
};
use crate::x4::merkle_v4::{
    verify_fold_round_packed_opening_v4, verify_initial_packed_opening_v4, CohortIdentityV4,
    CohortTreeV4, CohortVerifierConfigV4, DenseOuterNodeCacheV4,
};
use crate::x4::ntt::{
    encode_rate_eighth, evaluate_multilinear_coefficients, fold_codeword, fold_coefficients,
    fp2_pow, multilinear_coefficients, root_of_unity,
};
use crate::x4::persisted_v4::PersistedOpeningTrafficV4;

pub const C6_WRAPPER_QUERY_COUNT: usize = 86;
pub const C6_WRAPPER_REPETITIONS: usize = 2;
pub const C6_WRAPPER_TERMINAL_LOG2: u8 = 3;
pub const C6_WRAPPER_ACTIVE_SLOTS: usize = 72;
pub const C61_NATIVE_WRAPPER_ACTIVE_SLOTS: usize = 56;
pub const C6_WRAPPER_RANDOM_POINT_LEN: usize = 24;
pub const C6_WRAPPER_COMMON_POINT_LEN: usize = 25;
pub const C6_DELTA_RESIDUAL_ACTIVATION_ROUND: usize = 1;
pub const C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND: usize = 3;
pub const C6_HIDDEN_U_EMBED_ACTIVATION_ROUND: usize = 5;
pub const C6_WRAPPER_AUXILIARY_ACTIVATION_ROUND: usize = 9;
pub const C6_WRAPPER_ONE_CHAIN_BYTES: u64 = 1_939_733;
pub const C6_WRAPPER_TWO_CHAIN_BYTES: u64 = 3_879_466;
pub const C61_NATIVE_WRAPPER_ONE_CHAIN_BYTES: u64 = 1_714_123;
pub const C61_NATIVE_WRAPPER_TWO_CHAIN_BYTES: u64 = 3_428_246;
pub const C6_CACHE_ROUND_PARTICIPANT_ID: u32 = 0xC6A0_0001;
pub const C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID: u32 = 0xC6A0_0002;
pub const C6_HIDDEN_U_ROUND_PARTICIPANT_ID: u32 = 0xC6A0_0003;
pub const C6_PREDECESSOR_CACHE_COHORT_ID: u32 = 0xC601_0001;
pub const C6_SUCCESSOR_CACHE_COHORT_ID: u32 = 0xC601_0002;
pub const C6_CACHE_STATE_MERKLE_COHORT_ID: u32 = 0xC6C0_0001;
pub const C6_DELTA_RESIDUAL_COHORT_ID: u32 = 0xC601_0003;
pub const C6_HIDDEN_U_WEIGHTS_COHORT_ID: u32 = 0xC601_0004;
pub const C6_HIDDEN_U_EMBED_COHORT_ID: u32 = 0xC601_0005;
pub const C6_WRAPPER_AUXILIARY_COHORT_ID: u32 = 0xC601_0006;

const C6_WRAPPER_PROFILE_NAME: &[u8] = b"c6-transparent-rate8-s86-p72-persistent-cache-v2";
const C6_SLOT_DESCRIPTOR_CONTEXT: &str = "volta-zk/c6/wrapper-slot-descriptor/v2";
const C6_FOLD_DESCRIPTOR_CONTEXT: &str = "volta-zk/c6/wrapper-fold-descriptor/v2";
const C6_OPENING_SCHEDULE_CONTEXT: &str = "volta-zk/c6/wrapper-opening-schedule/v2";
const C6_FIXED_ROOTS_CONTEXT: &str = "volta-zk/c6/wrapper-fixed-roots/v2";
const C6_INITIAL_ROOTS_LABEL: &str = "c6_wrapper_initial_roots";
const C6_GLOBAL_ROUND_MESSAGES_LABEL: &str = "c6_wrapper_global_sumcheck_round";
#[cfg(test)]
const C6_SLOT_TERMINAL_VALUES_LABEL: &str = "c6_wrapper_slot_terminal_values";
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

    pub(crate) fn external(context: &'static str, error: impl fmt::Debug) -> Self {
        Self(format!("{context}: {error:?}"))
    }

    pub(crate) fn external_message(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6WrapperPcsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6WrapperPcsError {}

/// Model-global cache-state descriptors installed during session setup.
/// Both cache roles use this exact set and the same Merkle identity; the
/// response statement binds only their ordered predecessor/successor roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheStateDescriptors {
    slots: [Digest; C6_PERSISTENT_CACHE_SLOTS],
}

impl C6CacheStateDescriptors {
    pub fn from_persistent_profile(profile: &C6PersistentCacheStaticProfile) -> Result<Self> {
        if profile.wrapper_profile_digest != c6_wrapper_profile_digest() {
            return Err(C6WrapperPcsError::new(
                "C6 cache descriptors use a different wrapper profile",
            ));
        }
        let slots = profile
            .slot_descriptors()
            .map_err(|error| C6WrapperPcsError::new(error.to_string()))?;
        Self::from_slots(slots)
    }

    pub(crate) fn from_slots(slots: [Digest; C6_PERSISTENT_CACHE_SLOTS]) -> Result<Self> {
        let unique = slots.iter().copied().collect::<BTreeSet<_>>();
        if slots.contains(&[0; 32]) || unique.len() != slots.len() {
            return Err(C6WrapperPcsError::new("invalid C6 cache-state descriptor set"));
        }
        Ok(Self { slots })
    }

    pub fn slots(&self) -> &[Digest; C6_PERSISTENT_CACHE_SLOTS] {
        &self.slots
    }
}

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

/// Frozen persistent-cache production profile, in canonical role order and
/// then descending-domain order.  The two equal-geometry cache roots remain
/// distinct cohorts so the outer statement can bind predecessor and
/// successor roles without changing either reusable static descriptor.
pub fn production_c6_wrapper_specs() -> [C6WrapperCohortSpec; 6] {
    [
        C6WrapperCohortSpec {
            cohort_id: C6_PREDECESSOR_CACHE_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 24,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: C6_SUCCESSOR_CACHE_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 24,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: C6_DELTA_RESIDUAL_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 23,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: C6_HIDDEN_U_WEIGHTS_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 21,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: C6_HIDDEN_U_EMBED_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 19,
            slot_count: 8,
        },
        C6WrapperCohortSpec {
            cohort_id: C6_WRAPPER_AUXILIARY_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Auxiliary,
            payload_log2: 16,
            slot_count: 32,
        },
    ]
}

/// Closed C6.1 native profile. Hidden-u cohorts are absent, not represented
/// by empty slots or canonical roots.
pub fn production_c61_native_wrapper_specs() -> [C6WrapperCohortSpec; 4] {
    let legacy = production_c6_wrapper_specs();
    [legacy[0], legacy[1], legacy[2], legacy[5]]
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
    cache_descriptors: Option<C6CacheStateDescriptors>,
}

impl C6WrapperCommitment {
    /// Reconstruct the canonical verifier configuration from the public C6
    /// profile and one received cohort root.
    pub fn from_root(
        statement_digest: C6WrapperDigest,
        spec: C6WrapperCohortSpec,
        root: Digest,
    ) -> Result<Self> {
        if is_cache_state_role(spec.cohort_id) {
            return Err(C6WrapperPcsError::new(
                "C6 cache root requires installed static descriptors",
            ));
        }
        Self::from_root_inner(statement_digest, spec, root, None)
    }

    pub fn from_cache_root(
        statement_digest: C6WrapperDigest,
        spec: C6WrapperCohortSpec,
        root: Digest,
        cache_descriptors: &C6CacheStateDescriptors,
    ) -> Result<Self> {
        if !is_cache_state_role(spec.cohort_id) {
            return Err(C6WrapperPcsError::new(
                "non-cache C6 root received cache-state descriptors",
            ));
        }
        Self::from_root_inner(statement_digest, spec, root, Some(cache_descriptors.clone()))
    }

    fn from_root_inner(
        statement_digest: C6WrapperDigest,
        spec: C6WrapperCohortSpec,
        root: Digest,
        cache_descriptors: Option<C6CacheStateDescriptors>,
    ) -> Result<Self> {
        spec.validate()?;
        if statement_digest == [0; 32] || root == [0; 32] {
            return Err(C6WrapperPcsError::new("zero C6 wrapper statement/root"));
        }
        let commitment = Self {
            profile_digest: c6_wrapper_profile_digest(),
            statement_digest,
            spec,
            root,
            config: wrapper_verifier_config(statement_digest, spec, cache_descriptors.as_ref())?,
            cache_descriptors,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        if self.profile_digest != c6_wrapper_profile_digest()
            || self.statement_digest == [0; 32]
            || self.root == [0; 32]
            || self.config
                != wrapper_verifier_config(
                    self.statement_digest,
                    self.spec,
                    self.cache_descriptors.as_ref(),
                )?
        {
            return Err(C6WrapperPcsError::new("C6 wrapper commitment geometry mismatch"));
        }
        self.config
            .validate()
            .map_err(|error| C6WrapperPcsError::frame("C6 wrapper commitment config", error))?;
        Ok(())
    }
}

/// Canonically ordered C6 roots after they have been fixed in the
/// designated-verifier transcript.  Fields are private so a production
/// round coordinator cannot be started from an unvalidated root list.
#[derive(Clone, Debug)]
pub struct C6FixedWrapperCommitments {
    statement_digest: C6WrapperDigest,
    binding_digest: C6WrapperDigest,
    commitments: Vec<C6WrapperCommitment>,
    profile: C6FixedWrapperProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C6FixedWrapperProfile {
    Test,
    HistoricalC6,
    C61Native,
}

impl C6FixedWrapperCommitments {
    pub fn statement_digest(&self) -> C6WrapperDigest {
        self.statement_digest
    }

    pub fn binding_digest(&self) -> C6WrapperDigest {
        self.binding_digest
    }

    pub fn commitments(&self) -> &[C6WrapperCommitment] {
        &self.commitments
    }

    pub(crate) fn is_production_profile(&self) -> bool {
        self.profile != C6FixedWrapperProfile::Test
    }

    pub(crate) fn is_c61_native_profile(&self) -> bool {
        self.profile == C6FixedWrapperProfile::C61Native
    }
}

/// Join the private PCS fixed-root token to the exact production C6RLM1
/// manifest.  This is the only admitted production constructor for the
/// residual v3 root-bound typestate.
pub fn bind_production_c6_residual_relation_roots(
    fixed: &C6FixedWrapperCommitments,
    manifest: C6ResidualRelationManifest,
) -> Result<C6ResidualRelationRootBound> {
    if !fixed.is_production_profile() || !manifest.is_production_geometry() {
        return Err(C6WrapperPcsError::new(
            "C6 residual relation root join requires production roots and C6RLM1 geometry",
        ));
    }
    C6ResidualRelationRootBound::bind_fixed_roots(
        manifest,
        fixed.statement_digest,
        fixed.binding_digest,
    )
    .map_err(|error| C6WrapperPcsError::new(error.to_string()))
}

/// Fix the exact six production roots before any response-global sumcheck
/// challenge is released.
pub fn fix_production_c6_wrapper_commitments(
    statement_digest: C6WrapperDigest,
    cache_descriptors: &C6CacheStateDescriptors,
    commitments: &[C6WrapperCommitment],
    transcript: &mut Transcript,
) -> Result<C6FixedWrapperCommitments> {
    fix_c6_wrapper_commitments_inner(
        statement_digest,
        Some(cache_descriptors),
        commitments,
        C6FixedWrapperProfile::HistoricalC6,
        &production_c6_wrapper_specs(),
        transcript,
    )
}

/// Fix exactly the four C6.1 native roots. A historical six-root list cannot
/// be adapted into this typestate.
pub fn fix_production_c61_native_wrapper_commitments(
    statement_digest: C6WrapperDigest,
    cache_descriptors: &C6CacheStateDescriptors,
    commitments: &[C6WrapperCommitment],
    transcript: &mut Transcript,
) -> Result<C6FixedWrapperCommitments> {
    fix_c6_wrapper_commitments_inner(
        statement_digest,
        Some(cache_descriptors),
        commitments,
        C6FixedWrapperProfile::C61Native,
        &production_c61_native_wrapper_specs(),
        transcript,
    )
}

#[cfg(test)]
pub(crate) fn fix_test_c6_wrapper_commitments(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    transcript: &mut Transcript,
) -> Result<C6FixedWrapperCommitments> {
    fix_c6_wrapper_commitments_inner(
        statement_digest,
        None,
        commitments,
        C6FixedWrapperProfile::Test,
        &[],
        transcript,
    )
}

fn fix_c6_wrapper_commitments_inner(
    statement_digest: C6WrapperDigest,
    required_cache_descriptors: Option<&C6CacheStateDescriptors>,
    commitments: &[C6WrapperCommitment],
    profile: C6FixedWrapperProfile,
    expected: &[C6WrapperCohortSpec],
    transcript: &mut Transcript,
) -> Result<C6FixedWrapperCommitments> {
    validate_commitments(commitments)?;
    if statement_digest == [0; 32]
        || commitments.iter().any(|commitment| commitment.statement_digest != statement_digest)
    {
        return Err(C6WrapperPcsError::new("C6 fixed-root statement mismatch"));
    }
    if profile != C6FixedWrapperProfile::Test {
        let required_cache_descriptors = required_cache_descriptors.ok_or_else(|| {
            C6WrapperPcsError::new("C6 production roots require installed cache descriptors")
        })?;
        if commitments.len() != expected.len()
            || !commitments.iter().map(|commitment| commitment.spec).eq(expected.iter().copied())
            || commitments
                .iter()
                .filter(|commitment| is_cache_state_role(commitment.spec.cohort_id))
                .any(|commitment| {
                    commitment.cache_descriptors.as_ref() != Some(required_cache_descriptors)
                })
        {
            return Err(C6WrapperPcsError::new(
                "C6 fixed roots do not use the frozen production profile",
            ));
        }
    }
    if transcript.is_fiat_shamir() {
        let roots = commitments.iter().flat_map(|commitment| commitment.root).collect::<Vec<_>>();
        transcript.append_message(C6_INITIAL_ROOTS_LABEL, &roots);
    } else {
        let root_bytes = commitments
            .len()
            .checked_mul(32)
            .ok_or_else(|| C6WrapperPcsError::new("C6 initial-root bytes overflow"))?;
        transcript.append(
            C6_INITIAL_ROOTS_LABEL,
            u64::try_from(root_bytes)
                .map_err(|_| C6WrapperPcsError::new("C6 initial-root bytes exceed u64"))?,
        );
    }
    Ok(C6FixedWrapperCommitments {
        statement_digest,
        binding_digest: fixed_roots_digest(statement_digest, commitments),
        commitments: commitments.to_vec(),
        profile,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6WrapperRoundMessageReceipt {
    pub participant_id: u32,
    pub message_bytes: u64,
}

#[derive(Clone, Debug)]
struct PendingC6WrapperRound {
    participant_ids: Vec<u32>,
    challenge: Fp2,
}

/// One production repetition of the response-global 24-round challenge
/// schedule.  It releases no challenge until the exact active participant
/// set has fixed its messages, and it refuses the next round until all those
/// participants acknowledge binding the released challenge.
#[derive(Clone, Debug)]
pub struct C6WrapperRoundCoordinator {
    repetition: u8,
    fixed_roots_digest: C6WrapperDigest,
    random_point_len: usize,
    delta_activation_round: usize,
    hidden_activation_round: usize,
    global_round: usize,
    random_point: Vec<Fp2>,
    pending: Option<PendingC6WrapperRound>,
}

impl C6WrapperRoundCoordinator {
    pub fn new(fixed: &C6FixedWrapperCommitments, repetition: u8) -> Result<Self> {
        if fixed.profile != C6FixedWrapperProfile::HistoricalC6
            || usize::from(repetition) >= C6_WRAPPER_REPETITIONS
            || fixed.commitments.len() != production_c6_wrapper_specs().len()
        {
            return Err(C6WrapperPcsError::new(
                "C6 production round coordinator root/repetition mismatch",
            ));
        }
        Ok(Self {
            repetition,
            fixed_roots_digest: fixed.binding_digest,
            random_point_len: C6_WRAPPER_RANDOM_POINT_LEN,
            delta_activation_round: C6_DELTA_RESIDUAL_ACTIVATION_ROUND,
            hidden_activation_round: C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND,
            global_round: 0,
            random_point: Vec::with_capacity(C6_WRAPPER_RANDOM_POINT_LEN),
            pending: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_test(
        fixed: &C6FixedWrapperCommitments,
        repetition: u8,
        random_point_len: usize,
        delta_activation_round: usize,
        hidden_activation_round: usize,
    ) -> Result<Self> {
        if usize::from(repetition) >= C6_WRAPPER_REPETITIONS
            || random_point_len == 0
            || delta_activation_round >= random_point_len
            || hidden_activation_round >= random_point_len
            || delta_activation_round >= hidden_activation_round
        {
            return Err(C6WrapperPcsError::new("invalid scaled C6 coordinator schedule"));
        }
        Ok(Self {
            repetition,
            fixed_roots_digest: fixed.binding_digest,
            random_point_len,
            delta_activation_round,
            hidden_activation_round,
            global_round: 0,
            random_point: Vec::with_capacity(random_point_len),
            pending: None,
        })
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn expected_participant_ids(&self) -> Result<Vec<u32>> {
        if self.pending.is_some() || self.global_round >= self.random_point_len {
            return Err(C6WrapperPcsError::new(
                "C6 coordinator is not awaiting global-round messages",
            ));
        }
        Ok(c6_active_participant_ids(
            self.global_round,
            self.random_point_len,
            self.delta_activation_round,
            self.hidden_activation_round,
        ))
    }

    /// Fix one complete active-message set and only then draw the shared
    /// designated-verifier challenge.
    pub fn fix_messages_and_release_challenge(
        &mut self,
        receipts: &[C6WrapperRoundMessageReceipt],
        transcript: &mut Transcript,
    ) -> Result<Fp2> {
        let expected = self.expected_participant_ids()?;
        if receipts.len() != expected.len()
            || receipts.iter().map(|receipt| receipt.participant_id).ne(expected.iter().copied())
            || receipts.iter().any(|receipt| receipt.message_bytes == 0)
        {
            return Err(C6WrapperPcsError::new(
                "C6 global round has a missing, duplicate, reordered or empty participant",
            ));
        }
        let bytes = receipts.iter().try_fold(0u64, |sum, receipt| {
            sum.checked_add(receipt.message_bytes)
                .ok_or_else(|| C6WrapperPcsError::new("C6 global-round bytes overflow"))
        })?;
        transcript.append(C6_GLOBAL_ROUND_MESSAGES_LABEL, bytes);
        let challenge = transcript.challenge_fp2();
        self.pending = Some(PendingC6WrapperRound { participant_ids: expected, challenge });
        Ok(challenge)
    }

    /// Confirm that the same exact active set bound the released challenge.
    /// The concrete participant states perform their own algebraic bind
    /// before this acknowledgement.
    pub fn confirm_participants_bound(&mut self, participant_ids: &[u32]) -> Result<()> {
        let pending = self.pending.take().ok_or_else(|| {
            C6WrapperPcsError::new("C6 coordinator has no released challenge to bind")
        })?;
        if participant_ids != pending.participant_ids.as_slice() {
            self.pending = Some(pending);
            return Err(C6WrapperPcsError::new(
                "C6 global-round bind acknowledgements do not match the active set",
            ));
        }
        self.random_point.push(pending.challenge);
        self.global_round += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<C6WrapperRoundPoint> {
        if self.pending.is_some()
            || self.global_round != self.random_point_len
            || self.random_point.len() != self.random_point_len
        {
            return Err(C6WrapperPcsError::new("incomplete C6 global-round coordinator"));
        }
        let mut common_point = self.random_point.clone();
        common_point.push(Fp2::ZERO);
        Ok(C6WrapperRoundPoint {
            repetition: self.repetition,
            fixed_roots_digest: self.fixed_roots_digest,
            random_point: self.random_point,
            common_point,
        })
    }
}

/// C6.1-native response-global schedule. Its type has no hidden-u activation
/// field or constructor from the historical six-root profile.
#[derive(Clone, Debug)]
pub struct C61NativeWrapperRoundCoordinator {
    repetition: u8,
    fixed_roots_digest: C6WrapperDigest,
    global_round: usize,
    random_point: Vec<Fp2>,
    pending: Option<PendingC6WrapperRound>,
}

impl C61NativeWrapperRoundCoordinator {
    pub fn new(fixed: &C6FixedWrapperCommitments, repetition: u8) -> Result<Self> {
        if !fixed.is_c61_native_profile()
            || usize::from(repetition) >= C6_WRAPPER_REPETITIONS
            || fixed.commitments.len() != production_c61_native_wrapper_specs().len()
        {
            return Err(C6WrapperPcsError::new(
                "C6.1 native round coordinator root/repetition mismatch",
            ));
        }
        Ok(Self {
            repetition,
            fixed_roots_digest: fixed.binding_digest,
            global_round: 0,
            random_point: Vec::with_capacity(C6_WRAPPER_RANDOM_POINT_LEN),
            pending: None,
        })
    }

    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn round_index(&self) -> usize {
        self.global_round
    }

    pub fn expected_participant_ids(&self) -> Result<Vec<u32>> {
        if self.pending.is_some() || self.global_round >= C6_WRAPPER_RANDOM_POINT_LEN {
            return Err(C6WrapperPcsError::new(
                "C6.1 native coordinator is not awaiting global-round messages",
            ));
        }
        let mut active = vec![C6_CACHE_ROUND_PARTICIPANT_ID];
        if self.global_round >= C6_DELTA_RESIDUAL_ACTIVATION_ROUND {
            active.push(C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID);
        }
        Ok(active)
    }

    pub fn fix_messages_and_release_challenge(
        &mut self,
        receipts: &[C6WrapperRoundMessageReceipt],
        transcript: &mut Transcript,
    ) -> Result<Fp2> {
        let expected = self.expected_participant_ids()?;
        if receipts.len() != expected.len()
            || receipts.iter().map(|receipt| receipt.participant_id).ne(expected.iter().copied())
            || receipts.iter().any(|receipt| receipt.message_bytes == 0)
        {
            return Err(C6WrapperPcsError::new(
                "C6.1 native round has a missing, duplicate, reordered or empty participant",
            ));
        }
        let bytes = receipts.iter().try_fold(0u64, |sum, receipt| {
            sum.checked_add(receipt.message_bytes)
                .ok_or_else(|| C6WrapperPcsError::new("C6.1 native round bytes overflow"))
        })?;
        transcript.append(C6_GLOBAL_ROUND_MESSAGES_LABEL, bytes);
        let challenge = transcript.challenge_fp2();
        self.pending = Some(PendingC6WrapperRound { participant_ids: expected, challenge });
        Ok(challenge)
    }

    pub fn confirm_participants_bound(&mut self, participant_ids: &[u32]) -> Result<()> {
        let pending = self.pending.take().ok_or_else(|| {
            C6WrapperPcsError::new("C6.1 native coordinator has no released challenge to bind")
        })?;
        if participant_ids != pending.participant_ids.as_slice() {
            self.pending = Some(pending);
            return Err(C6WrapperPcsError::new(
                "C6.1 native bind acknowledgements do not match the active set",
            ));
        }
        self.random_point.push(pending.challenge);
        self.global_round += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<C6WrapperRoundPoint> {
        if self.pending.is_some()
            || self.global_round != C6_WRAPPER_RANDOM_POINT_LEN
            || self.random_point.len() != C6_WRAPPER_RANDOM_POINT_LEN
        {
            return Err(C6WrapperPcsError::new("incomplete C6.1 native round coordinator"));
        }
        let mut common_point = self.random_point.clone();
        common_point.push(Fp2::ZERO);
        Ok(C6WrapperRoundPoint {
            repetition: self.repetition,
            fixed_roots_digest: self.fixed_roots_digest,
            random_point: self.random_point,
            common_point,
        })
    }
}

fn c6_active_participant_ids(
    global_round: usize,
    random_point_len: usize,
    delta_activation_round: usize,
    hidden_activation_round: usize,
) -> Vec<u32> {
    let mut active = Vec::with_capacity(3);
    if global_round < random_point_len {
        active.push(C6_CACHE_ROUND_PARTICIPANT_ID);
    }
    if (delta_activation_round..random_point_len).contains(&global_round) {
        active.push(C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID);
    }
    if (hidden_activation_round..random_point_len).contains(&global_round) {
        active.push(C6_HIDDEN_U_ROUND_PARTICIPANT_ID);
    }
    active
}

/// Verifier-owned common point produced only by a completed coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperRoundPoint {
    repetition: u8,
    fixed_roots_digest: C6WrapperDigest,
    random_point: Vec<Fp2>,
    common_point: Vec<Fp2>,
}

impl C6WrapperRoundPoint {
    pub fn repetition(&self) -> u8 {
        self.repetition
    }

    pub fn random_point(&self) -> &[Fp2] {
        &self.random_point
    }

    pub fn common_point(&self) -> &[Fp2] {
        &self.common_point
    }

    pub fn cohort_point(&self, spec: C6WrapperCohortSpec) -> Result<Vec<Fp2>> {
        spec.validate()?;
        let point_len = usize::from(spec.coefficient_log2()?);
        if point_len > self.common_point.len() {
            return Err(C6WrapperPcsError::new("C6 cohort point exceeds the common point"));
        }
        Ok(self.common_point[self.common_point.len() - point_len..].to_vec())
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

    /// Consume only the scaled resident reference owner into the persisted
    /// differential. Production geometry must enter through the separately
    /// gated CUDA constructor and is rejected here before any file is made.
    pub(crate) fn into_scaled_persisted_parts(self) -> Result<C6ScaledPersistedCohortParts> {
        if self.commitment.spec.encoded_domain_log2()? > 16 {
            return Err(C6WrapperPcsError::new(
                "C6 scaled persisted adapter rejects production geometry",
            ));
        }
        let tree = self.tree.into_lifecycle_parts();
        if tree.config != self.commitment.config
            || tree.slot_symbols.len() != self.codewords.len()
            || tree
                .slot_symbols
                .iter()
                .zip(&self.codewords)
                .any(|(tree_slot, codeword)| tree_slot.as_ref() != Some(codeword))
        {
            return Err(C6WrapperPcsError::new(
                "C6 resident tree differs from its persisted source owner",
            ));
        }
        Ok(C6ScaledPersistedCohortParts {
            commitment: self.commitment,
            coefficients: self.coefficients,
            codewords: self.codewords,
            outer_cache: tree.outer_cache,
        })
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

pub(crate) struct C6ScaledPersistedCohortParts {
    pub(crate) commitment: C6WrapperCommitment,
    pub(crate) coefficients: Vec<Vec<Fp2>>,
    pub(crate) codewords: Vec<Vec<Fp2>>,
    pub(crate) outer_cache: DenseOuterNodeCacheV4,
}

/// Build one response-local cohort with every capacity slot present.
pub fn commit_c6_wrapper_cohort(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
) -> Result<C6CommittedWrapperCohort> {
    if is_cache_state_role(spec.cohort_id) {
        return Err(C6WrapperPcsError::new(
            "C6 cache cohort requires installed static descriptors",
        ));
    }
    commit_c6_wrapper_cohort_inner(statement_digest, spec, slots, None)
}

pub fn commit_c6_cache_state_cohort(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
    cache_descriptors: &C6CacheStateDescriptors,
) -> Result<C6CommittedWrapperCohort> {
    if !is_cache_state_role(spec.cohort_id) {
        return Err(C6WrapperPcsError::new("non-cache C6 cohort received cache-state descriptors"));
    }
    commit_c6_wrapper_cohort_inner(statement_digest, spec, slots, Some(cache_descriptors))
}

fn commit_c6_wrapper_cohort_inner(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
    cache_descriptors: Option<&C6CacheStateDescriptors>,
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
    let config = wrapper_verifier_config(statement_digest, spec, cache_descriptors)?;
    let tree = CohortTreeV4::build_flat(
        config.clone(),
        codewords.iter().cloned().map(Some).collect::<Vec<_>>(),
    )
    .map_err(|error| C6WrapperPcsError::frame("C6 initial cohort commitment", error))?;
    let commitment = if let Some(descriptors) = cache_descriptors {
        C6WrapperCommitment::from_cache_root(statement_digest, spec, tree.root(), descriptors)?
    } else {
        C6WrapperCommitment::from_root(statement_digest, spec, tree.root())?
    };
    if commitment.config != config {
        return Err(C6WrapperPcsError::new("C6 wrapper verifier config reconstruction mismatch"));
    }
    Ok(C6CommittedWrapperCohort { commitment, coefficients, codewords, tree })
}

pub(crate) fn compile_c6_wrapper_slot_coefficients(
    spec: C6WrapperCohortSpec,
    slots: Vec<C6WrapperSlotWitness>,
) -> Result<Vec<Option<Vec<Fp2>>>> {
    spec.validate()?;
    if slots.len() != usize::from(spec.slot_count) {
        return Err(C6WrapperPcsError::new("C6 wrapper coefficient slot census mismatch"));
    }
    let payload_len = spec.payload_len()?;
    slots
        .into_iter()
        .map(|slot| {
            let evaluations = match (spec.oracle_kind, slot) {
                (
                    C6WrapperOracleKind::Witness,
                    C6WrapperSlotWitness::Witness { witness, zk_mask },
                ) if witness.len() == payload_len && zk_mask.len() == payload_len => {
                    let mut extended =
                        Vec::with_capacity(payload_len.checked_mul(2).ok_or_else(|| {
                            C6WrapperPcsError::new("C6 ZK twin length overflows")
                        })?);
                    extended.extend(witness);
                    extended.extend(zk_mask);
                    extended
                }
                (
                    C6WrapperOracleKind::Auxiliary,
                    C6WrapperSlotWitness::Auxiliary { evaluations },
                ) if evaluations.len() == payload_len => evaluations,
                _ => {
                    return Err(C6WrapperPcsError::new(
                        "C6 wrapper slot kind or evaluation length mismatch",
                    ))
                }
            };
            multilinear_coefficients(&evaluations)
                .map(Some)
                .map_err(|error| C6WrapperPcsError::frame("C6 multilinear conversion", error))
        })
        .collect()
}

pub(crate) fn c6_wrapper_commit_config(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    cache_descriptors: Option<&C6CacheStateDescriptors>,
) -> Result<CohortVerifierConfigV4> {
    wrapper_verifier_config(statement_digest, spec, cache_descriptors)
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

/// One typed terminal value before the verifier-owned same-point slot
/// reduction is assembled.  This is an in-memory seam, not a wire field:
/// the cohort/slot registry and reduction weights are reconstructed by the
/// final wrapper orchestrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6WrapperSlotOpeningClaim {
    pub repetition: u8,
    pub cohort_id: u32,
    pub slot: u16,
    pub point: Vec<Fp2>,
    pub value: Fp2,
}

/// Map the four hidden-`u` terminal claims into two registered wrapper slots.
/// No `u_vector` or prior key vector is copied or serialized.
pub fn bind_hidden_u_opening_claims_to_wrapper_slots(
    hidden_claims: &[C6HiddenUOpeningClaim],
    weights_spec: C6WrapperCohortSpec,
    weights_slot: u16,
    embed_spec: C6WrapperCohortSpec,
    embed_slot: u16,
) -> Result<Vec<C6WrapperSlotOpeningClaim>> {
    weights_spec.validate()?;
    embed_spec.validate()?;
    if weights_spec.oracle_kind != C6WrapperOracleKind::Witness
        || embed_spec.oracle_kind != C6WrapperOracleKind::Witness
        || weights_slot >= weights_spec.slot_count
        || embed_slot >= embed_spec.slot_count
        || hidden_claims.len() != 2 * C6_WRAPPER_REPETITIONS
    {
        return Err(C6WrapperPcsError::new("C6 hidden-u wrapper slot registry mismatch"));
    }
    let mut output = Vec::with_capacity(hidden_claims.len());
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let weights = &hidden_claims[2 * repetition];
        let embed = &hidden_claims[2 * repetition + 1];
        if usize::from(weights.repetition) != repetition
            || usize::from(embed.repetition) != repetition
            || weights.family != C6HiddenUFamily::Weights
            || embed.family != C6HiddenUFamily::Embed
            || weights.point.len() != usize::from(weights_spec.payload_log2)
            || embed.point.len() != usize::from(embed_spec.payload_log2)
            || embed.point.len() > weights.point.len()
            || embed.point != weights.point[weights.point.len() - embed.point.len()..]
        {
            return Err(C6WrapperPcsError::new(
                "C6 hidden-u claims do not match the registered suffix geometry",
            ));
        }
        let weights_point = weights.wrapper_point();
        let embed_point = embed.wrapper_point();
        if weights_point.len() != usize::from(weights_spec.coefficient_log2()?)
            || embed_point.len() != usize::from(embed_spec.coefficient_log2()?)
            || embed_point != weights_point[weights_point.len() - embed_point.len()..]
        {
            return Err(C6WrapperPcsError::new(
                "C6 hidden-u strict-rate points are not suffix aligned",
            ));
        }
        output.push(C6WrapperSlotOpeningClaim {
            repetition: repetition as u8,
            cohort_id: weights_spec.cohort_id,
            slot: weights_slot,
            point: weights_point,
            value: weights.value,
        });
        output.push(C6WrapperSlotOpeningClaim {
            repetition: repetition as u8,
            cohort_id: embed_spec.cohort_id,
            slot: embed_slot,
            point: embed_point,
            value: embed.value,
        });
    }
    Ok(output)
}

/// Sealed output of the verifier-owned all-slot reduction.  The slot weights
/// are private implementation details and cannot be supplied by a provider
/// through this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6AssembledWrapperClaims {
    statement_digest: C6WrapperDigest,
    fixed_roots_digest: C6WrapperDigest,
    slot_terminal_count: usize,
    claims_by_repetition: Vec<Vec<C6WrapperOpeningClaim>>,
    authenticated_link: bool,
}

impl C6AssembledWrapperClaims {
    pub fn slot_terminal_count(&self) -> usize {
        self.slot_terminal_count
    }

    pub fn claims_by_repetition(&self) -> &[Vec<C6WrapperOpeningClaim>] {
        &self.claims_by_repetition
    }
}

/// Historical clear-terminal assembler retained only as a diagnostic
/// reference.  Its output is deliberately not authorized to enter either
/// public assembled PCS entry point.
#[cfg(test)]
pub(crate) fn assemble_production_c6_wrapper_claims(
    fixed: &C6FixedWrapperCommitments,
    round_points: &[C6WrapperRoundPoint],
    slot_claims: &[C6WrapperSlotOpeningClaim],
    transcript: &mut Transcript,
) -> Result<C6AssembledWrapperClaims> {
    assemble_c6_wrapper_claims_inner(fixed, round_points, slot_claims, true, transcript)
}

#[cfg(test)]
fn assemble_c6_wrapper_claims_inner(
    fixed: &C6FixedWrapperCommitments,
    round_points: &[C6WrapperRoundPoint],
    slot_claims: &[C6WrapperSlotOpeningClaim],
    require_production: bool,
    transcript: &mut Transcript,
) -> Result<C6AssembledWrapperClaims> {
    validate_commitments(&fixed.commitments)?;
    if require_production && !fixed.is_production_profile() {
        return Err(C6WrapperPcsError::new(
            "C6 production slot assembly requires production-fixed roots",
        ));
    }
    if round_points.len() != C6_WRAPPER_REPETITIONS {
        return Err(C6WrapperPcsError::new("C6 wrapper round-point repetition mismatch"));
    }
    let max_point_len = usize::from(fixed.commitments[0].spec.coefficient_log2()?);
    for (repetition, point) in round_points.iter().enumerate() {
        if usize::from(point.repetition) != repetition
            || point.fixed_roots_digest != fixed.binding_digest
            || point.common_point.len() != max_point_len
            || point.common_point.last() != Some(&Fp2::ZERO)
        {
            return Err(C6WrapperPcsError::new(
                "C6 wrapper round point does not bind the fixed roots/profile",
            ));
        }
        if require_production
            && (point.random_point.len() != C6_WRAPPER_RANDOM_POINT_LEN
                || &point.common_point[..C6_WRAPPER_RANDOM_POINT_LEN]
                    != point.random_point.as_slice())
        {
            return Err(C6WrapperPcsError::new(
                "C6 production wrapper point is not 24 random coordinates plus zero",
            ));
        }
    }

    let slots_per_repetition = fixed.commitments.iter().try_fold(0usize, |sum, commitment| {
        sum.checked_add(usize::from(commitment.spec.slot_count))
            .ok_or_else(|| C6WrapperPcsError::new("C6 wrapper slot count overflows"))
    })?;
    let expected_terminal_count = slots_per_repetition
        .checked_mul(C6_WRAPPER_REPETITIONS)
        .ok_or_else(|| C6WrapperPcsError::new("C6 wrapper terminal count overflows"))?;
    if slot_claims.len() != expected_terminal_count
        || (require_production && slots_per_repetition != C6_WRAPPER_ACTIVE_SLOTS)
    {
        return Err(C6WrapperPcsError::new("C6 wrapper terminal-slot census mismatch"));
    }

    let mut registry = BTreeMap::new();
    for claim in slot_claims {
        let repetition = usize::from(claim.repetition);
        if repetition >= C6_WRAPPER_REPETITIONS {
            return Err(C6WrapperPcsError::new("C6 terminal claim repetition out of range"));
        }
        let commitment = fixed
            .commitments
            .iter()
            .find(|commitment| commitment.spec.cohort_id == claim.cohort_id)
            .ok_or_else(|| C6WrapperPcsError::new("unknown C6 terminal-claim cohort"))?;
        if claim.slot >= commitment.spec.slot_count
            || claim.point != round_points[repetition].cohort_point(commitment.spec)?
        {
            return Err(C6WrapperPcsError::new(
                "C6 terminal claim has a wrong slot or verifier-owned point",
            ));
        }
        if registry.insert((claim.repetition, claim.cohort_id, claim.slot), claim.value).is_some() {
            return Err(C6WrapperPcsError::new("duplicate C6 terminal slot claim"));
        }
    }

    for repetition in 0..C6_WRAPPER_REPETITIONS {
        for commitment in &fixed.commitments {
            for slot in 0..commitment.spec.slot_count {
                if !registry.contains_key(&(repetition as u8, commitment.spec.cohort_id, slot)) {
                    return Err(C6WrapperPcsError::new("missing C6 terminal slot claim"));
                }
            }
        }
    }

    let terminal_bytes = expected_terminal_count
        .checked_mul(16)
        .ok_or_else(|| C6WrapperPcsError::new("C6 terminal-slot bytes overflow"))?;
    transcript.append(
        C6_SLOT_TERMINAL_VALUES_LABEL,
        u64::try_from(terminal_bytes)
            .map_err(|_| C6WrapperPcsError::new("C6 terminal-slot bytes exceed u64"))?,
    );

    let mut claims_by_repetition = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let mut repetition_claims = Vec::with_capacity(fixed.commitments.len());
        for commitment in &fixed.commitments {
            let mut slot_weights = Vec::with_capacity(usize::from(commitment.spec.slot_count));
            let mut value = Fp2::ZERO;
            for slot in 0..commitment.spec.slot_count {
                let weight = transcript.challenge_fp2();
                let terminal = registry[&(repetition as u8, commitment.spec.cohort_id, slot)];
                slot_weights.push(weight);
                value += weight * terminal;
            }
            repetition_claims.push(C6WrapperOpeningClaim {
                repetition: repetition as u8,
                cohort_id: commitment.spec.cohort_id,
                point: round_points[repetition].cohort_point(commitment.spec)?,
                slot_weights,
                value,
            });
        }
        claims_by_repetition.push(repetition_claims);
    }
    validate_statement_and_claims(
        fixed.statement_digest,
        &fixed.commitments,
        &claims_by_repetition,
    )?;
    Ok(C6AssembledWrapperClaims {
        statement_digest: fixed.statement_digest,
        fixed_roots_digest: fixed.binding_digest,
        slot_terminal_count: expected_terminal_count,
        claims_by_repetition,
        authenticated_link: false,
    })
}

/// Seal the five per-repetition wrapper claims only after the packed
/// authenticated-output link has fixed them.  This is crate-private so the
/// provider cannot manufacture the typestate accepted by the public PCS
/// entry points.
pub(crate) fn seal_authenticated_link_c6_wrapper_claims(
    fixed: &C6FixedWrapperCommitments,
    claims_by_repetition: Vec<Vec<C6WrapperOpeningClaim>>,
) -> Result<C6AssembledWrapperClaims> {
    validate_commitments(&fixed.commitments)?;
    validate_statement_and_claims(
        fixed.statement_digest,
        &fixed.commitments,
        &claims_by_repetition,
    )?;
    let slots_per_repetition = fixed.commitments.iter().try_fold(0usize, |sum, commitment| {
        sum.checked_add(usize::from(commitment.spec.slot_count))
            .ok_or_else(|| C6WrapperPcsError::new("C6 linked slot count overflows"))
    })?;
    let slot_terminal_count = slots_per_repetition
        .checked_mul(C6_WRAPPER_REPETITIONS)
        .ok_or_else(|| C6WrapperPcsError::new("C6 linked terminal count overflows"))?;
    for claims in &claims_by_repetition {
        let common_point = claims
            .first()
            .ok_or_else(|| C6WrapperPcsError::new("empty C6 linked claim repetition"))?
            .point
            .as_slice();
        if common_point.last() == Some(&Fp2::ZERO) {
            return Err(C6WrapperPcsError::new(
                "C6 authenticated link fresh ZK coordinate is zero",
            ));
        }
    }
    Ok(C6AssembledWrapperClaims {
        statement_digest: fixed.statement_digest,
        fixed_roots_digest: fixed.binding_digest,
        slot_terminal_count,
        claims_by_repetition,
        authenticated_link: true,
    })
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
pub(crate) struct CombinedCohort {
    pub(crate) outer_len: usize,
    pub(crate) coefficients: Vec<Fp2>,
    pub(crate) codeword: Vec<Fp2>,
    pub(crate) claimed_value: Fp2,
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

#[derive(Debug)]
struct PersistedSealedChain {
    repetition: u8,
    common_point: Vec<Fp2>,
    activation_challenges: Vec<Fp2>,
    fold_challenges: Vec<Fp2>,
    fold_frames: Vec<FoldCommitmentFrameV4>,
    fold_openings: Vec<C6PersistedFoldOpening>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct C6ProductionWrapperPcsMetrics {
    pub coefficient_bytes_read: u64,
    pub fold_commit: X4bCudaCommitMetricsV4,
    pub opening: PersistedOpeningTrafficV4,
    pub resident_codeword_copies_after_seal: u64,
}

/// Diagnostic/raw-weight in-memory prover.  Production callers use
/// [`prove_c6_wrapper_pcs_assembled`], which cannot accept provider-selected
/// slot weights.
pub fn prove_c6_wrapper_pcs(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6CommittedWrapperCohort],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    prove_c6_wrapper_pcs_inner(statement_digest, cohorts, claims_by_repetition, true, transcript)
}

/// Scaled byte-identity differential for the resource-aware owner. Every
/// initial and folded query is served from a create-new persisted oracle.
/// Production-sized owners are rejected by their constructors and must use
/// the separately gated CUDA path.
pub fn prove_c6_wrapper_pcs_persisted_reference(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    spill_root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    validate_statement_and_claims(statement_digest, &commitments, claims_by_repetition)?;
    prove_c6_wrapper_pcs_persisted_reference_inner(
        statement_digest,
        cohorts,
        claims_by_repetition,
        spill_root.as_ref(),
        session_digest,
        true,
        transcript,
    )
}

/// Scaled persisted companion of the authenticated-link assembled entry
/// point. Aggregate claims were already absorbed by C6LNK2 and therefore are
/// not appended to the transcript a second time.
#[allow(dead_code)]
pub(crate) fn prove_c6_wrapper_pcs_persisted_reference_assembled(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    assembled: &C6AssembledWrapperClaims,
    spill_root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    if !assembled.authenticated_link {
        return Err(C6WrapperPcsError::new(
            "C6 persisted assembled PCS requires authenticated-output-link sealing",
        ));
    }
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    validate_assembled_claims(statement_digest, &commitments, assembled)?;
    prove_c6_wrapper_pcs_persisted_reference_inner(
        statement_digest,
        cohorts,
        &assembled.claims_by_repetition,
        spill_root.as_ref(),
        session_digest,
        false,
        transcript,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_c6_wrapper_pcs_persisted_reference_inner(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    spill_root: &Path,
    session_digest: C6WrapperDigest,
    append_aggregate_claims: bool,
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    if session_digest == [0; 32]
        || cohorts.iter().any(|cohort| cohort.session_digest() != session_digest)
        || !cohorts.windows(2).all(|pair| pair[0].oracle_ordinal() < pair[1].oracle_ordinal())
    {
        return Err(C6WrapperPcsError::new("C6 persisted wrapper response binding mismatch"));
    }
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    validate_statement_and_claims(statement_digest, &commitments, claims_by_repetition)?;
    if append_aggregate_claims {
        append_terminal_claims(transcript, claims_by_repetition)?;
    }
    let activations = derive_activation_challenges(transcript, commitments.len());
    let mut sealed = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        sealed.push(seal_persisted_reference_chain(
            statement_digest,
            repetition,
            cohorts,
            &claims_by_repetition[repetition],
            activations[repetition].clone(),
            spill_root,
            session_digest,
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
    let mut chains = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for (sealed, draws) in sealed.into_iter().zip(&query_tapes) {
        let chain = issue_persisted_reference_openings(
            statement_digest,
            cohorts,
            &claims_by_repetition[usize::from(sealed.repetition)],
            sealed,
            draws,
        )?;
        let packed_len = FrameV4::PackedBatchOpening(chain.packed_opening.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 persisted packed opening", error))?
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

/// Production assembled PCS over the create-new persisted owners. Every fold
/// oracle/root is produced by CUDA directly from the folded coefficients;
/// both complete chains are fixed before either proximity-query tape is drawn.
#[allow(clippy::too_many_arguments)]
pub fn prove_c6_wrapper_pcs_persisted_cuda_assembled(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    assembled: &C6AssembledWrapperClaims,
    backend: &mut Backend,
    spill_root: impl AsRef<Path>,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<(C6WrapperPcsProof, C6ProductionWrapperPcsMetrics)> {
    if backend.kind() == BackendKind::Cpu {
        return Err(C6WrapperPcsError::new("C6 production persisted PCS refuses CPU backend"));
    }
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    let legacy_specs = production_c6_wrapper_specs();
    let native_specs = production_c61_native_wrapper_specs();
    let production_specs: &[C6WrapperCohortSpec] =
        if commitments.iter().map(|commitment| commitment.spec).eq(legacy_specs) {
            &legacy_specs
        } else if commitments.iter().map(|commitment| commitment.spec).eq(native_specs) {
            &native_specs
        } else {
            return Err(C6WrapperPcsError::new(
                "C6 production persisted PCS rejects an unregistered profile",
            ));
        };
    if session_digest == [0; 32]
        || cohorts.len() != production_specs.len()
        || cohorts.iter().enumerate().any(|(index, cohort)| {
            cohort.session_digest() != session_digest
                || cohort.oracle_ordinal() != index as u64
                || cohort.commitment().spec != production_specs[index]
        })
    {
        return Err(C6WrapperPcsError::new(
            "C6 production persisted PCS response/profile binding mismatch",
        ));
    }
    if !assembled.authenticated_link {
        return Err(C6WrapperPcsError::new(
            "C6 production persisted PCS requires authenticated-output-link sealing",
        ));
    }
    validate_assembled_claims(statement_digest, &commitments, assembled)?;
    let activations = derive_activation_challenges(transcript, commitments.len());
    let mut sealed = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    let mut metrics = C6ProductionWrapperPcsMetrics::default();
    for repetition in 0..C6_WRAPPER_REPETITIONS {
        let (chain, coefficient_bytes_read, fold_commit) = seal_persisted_cuda_chain(
            statement_digest,
            repetition,
            cohorts,
            &assembled.claims_by_repetition[repetition],
            activations[repetition].clone(),
            backend,
            spill_root.as_ref(),
            session_digest,
            transcript,
        )?;
        metrics.coefficient_bytes_read = metrics
            .coefficient_bytes_read
            .checked_add(coefficient_bytes_read)
            .ok_or_else(|| C6WrapperPcsError::new("C6 coefficient-read metric overflows"))?;
        metrics
            .fold_commit
            .include(&fold_commit)
            .map_err(|error| C6WrapperPcsError::frame("C6 fold metric", error))?;
        sealed.push(chain);
    }
    let draw_width = commitments[0].config.outer_depth();
    let query_tapes = (0..C6_WRAPPER_REPETITIONS)
        .map(|_| {
            (0..C6_WRAPPER_QUERY_COUNT)
                .map(|_| transcript.challenge_bits(draw_width))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut chains = Vec::with_capacity(C6_WRAPPER_REPETITIONS);
    for (sealed, draws) in sealed.into_iter().zip(&query_tapes) {
        let repetition = usize::from(sealed.repetition);
        let (chain, opening) = issue_persisted_openings(
            statement_digest,
            cohorts,
            &assembled.claims_by_repetition[repetition],
            sealed,
            draws,
        )?;
        include_opening_traffic(&mut metrics.opening, opening)?;
        let packed_len = FrameV4::PackedBatchOpening(chain.packed_opening.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 production packed opening", error))?
            .len();
        transcript.append(
            C6_PACKED_OPENING_LABEL,
            u64::try_from(packed_len)
                .map_err(|_| C6WrapperPcsError::new("C6 packed opening length exceeds u64"))?,
        );
        chains.push(chain);
    }
    Ok((C6WrapperPcsProof { chains }, metrics))
}

/// PCS entry point after authenticated-output-link sealing.  The ten masked
/// new-point aggregate values were already fixed by that link and are not
/// serialized a second time; clear old-point terminal scalars are forbidden.
pub fn prove_c6_wrapper_pcs_assembled(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6CommittedWrapperCohort],
    assembled: &C6AssembledWrapperClaims,
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    if !assembled.authenticated_link {
        return Err(C6WrapperPcsError::new(
            "C6 assembled PCS requires authenticated-output-link sealing",
        ));
    }
    let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
    validate_assembled_claims(statement_digest, &commitments, assembled)?;
    prove_c6_wrapper_pcs_inner(
        statement_digest,
        cohorts,
        &assembled.claims_by_repetition,
        false,
        transcript,
    )
}

fn prove_c6_wrapper_pcs_inner(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6CommittedWrapperCohort],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    append_aggregate_claims: bool,
    transcript: &mut Transcript,
) -> Result<C6WrapperPcsProof> {
    let commitments = cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
    validate_statement_and_claims(statement_digest, &commitments, claims_by_repetition)?;
    if cohorts.len() != commitments.len() {
        return Err(C6WrapperPcsError::new("C6 wrapper prover cohort census mismatch"));
    }

    if append_aggregate_claims {
        append_terminal_claims(transcript, claims_by_repetition)?;
    }
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

/// Diagnostic/raw-weight verifier companion to [`prove_c6_wrapper_pcs`].
pub fn verify_c6_wrapper_pcs(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    proof: &C6WrapperPcsProof,
    transcript: &mut Transcript,
) -> Result<()> {
    verify_c6_wrapper_pcs_inner(
        statement_digest,
        commitments,
        claims_by_repetition,
        proof,
        true,
        transcript,
    )
}

pub fn verify_c6_wrapper_pcs_assembled(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    assembled: &C6AssembledWrapperClaims,
    proof: &C6WrapperPcsProof,
    transcript: &mut Transcript,
) -> Result<()> {
    if !assembled.authenticated_link {
        return Err(C6WrapperPcsError::new(
            "C6 assembled PCS requires authenticated-output-link sealing",
        ));
    }
    validate_assembled_claims(statement_digest, commitments, assembled)?;
    verify_c6_wrapper_pcs_inner(
        statement_digest,
        commitments,
        &assembled.claims_by_repetition,
        proof,
        false,
        transcript,
    )
}

fn verify_c6_wrapper_pcs_inner(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    claims_by_repetition: &[Vec<C6WrapperOpeningClaim>],
    proof: &C6WrapperPcsProof,
    append_aggregate_claims: bool,
    transcript: &mut Transcript,
) -> Result<()> {
    validate_statement_and_claims(statement_digest, commitments, claims_by_repetition)?;
    if proof.chains.len() != C6_WRAPPER_REPETITIONS {
        return Err(C6WrapperPcsError::new("C6 wrapper proof repetition mismatch"));
    }

    if append_aggregate_claims {
        append_terminal_claims(transcript, claims_by_repetition)?;
    }
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

#[allow(clippy::too_many_arguments)]
fn seal_persisted_reference_chain(
    statement_digest: C6WrapperDigest,
    repetition: usize,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: Vec<Fp2>,
    spill_root: &Path,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<PersistedSealedChain> {
    let common_point = claims[0].point.clone();
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    let max_outer_len = commitments[0].spec.encoded_len()?;
    let max_coefficient_len = max_outer_len / 8;
    let mut current_coefficients = vec![Fp2::ZERO; max_coefficient_len];
    let mut current_codeword = vec![Fp2::ZERO; max_outer_len];
    let mut current_claim = Fp2::ZERO;
    let mut activated = activate_persisted_at_domain(
        max_outer_len,
        cohorts,
        claims,
        &activation_challenges,
        &mut current_coefficients,
        &mut current_codeword,
        &mut current_claim,
    )?;
    if activated == 0 {
        return Err(C6WrapperPcsError::new("C6 persisted maximum cohort did not activate"));
    }
    let fold_descriptor = fold_descriptor_digest(statement_digest, repetition as u8, &commitments);
    let global_cohort_id = C6_GLOBAL_FOLD_COHORT_BASE
        .checked_add(repetition as u32)
        .ok_or_else(|| C6WrapperPcsError::new("C6 persisted fold cohort id overflows"))?;
    let mut fold_frames = Vec::with_capacity(common_point.len());
    let mut fold_openings = Vec::with_capacity(common_point.len());
    let mut fold_challenges = Vec::with_capacity(common_point.len());
    let mut input_len = max_outer_len;
    for round_index in 0..common_point.len() {
        let (line_zero, line_one) =
            claim_line(&current_coefficients, &common_point[round_index + 1..])?;
        if interpolate(line_zero, line_one, common_point[round_index]) != current_claim {
            return Err(C6WrapperPcsError::new("C6 persisted claim-line input mismatch"));
        }
        transcript.append(C6_FOLD_LINE_LABEL, 32);
        let fold_challenge = transcript.challenge_fp2();
        fold_challenges.push(fold_challenge);
        current_claim = interpolate(line_zero, line_one, fold_challenge);
        current_coefficients = fold_coefficients(&current_coefficients, fold_challenge)
            .map_err(|error| C6WrapperPcsError::frame("C6 persisted coefficient fold", error))?;
        current_codeword = fold_codeword(&current_codeword, fold_challenge)
            .map_err(|error| C6WrapperPcsError::frame("C6 persisted codeword fold", error))?;
        let output_len = input_len / 2;
        activated += activate_persisted_at_domain(
            output_len,
            cohorts,
            claims,
            &activation_challenges,
            &mut current_coefficients,
            &mut current_codeword,
            &mut current_claim,
        )?;
        let fold_round = u8::try_from(round_index + 1)
            .map_err(|_| C6WrapperPcsError::new("C6 persisted fold round overflows"))?;
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
            .map_err(|error| C6WrapperPcsError::frame("C6 persisted fold commitment", error))?;
        let root = tree.root();
        let opening = persist_scaled_c6_wrapper_fold_reference(
            tree,
            &current_codeword,
            spill_root,
            statement_digest,
            session_digest,
            repetition as u8,
            fold_round,
        )?;
        let mut messages = vec![line_zero, line_one];
        if round_index + 1 == common_point.len() {
            if current_coefficients.as_slice() != [current_claim] {
                return Err(C6WrapperPcsError::new("C6 persisted final folded scalar mismatch"));
            }
            messages.push(current_claim);
        }
        let frame = FoldCommitmentFrameV4 {
            cohort_id: global_cohort_id,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round,
            input_log2: input_len.ilog2() as u8,
            output_log2: output_len.ilog2() as u8,
            root_digest: root,
            ordered_message_symbols: messages,
        };
        let frame_len = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 persisted fold frame", error))?
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
        fold_openings.push(opening);
        input_len = output_len;
    }
    if input_len != 1usize << C6_WRAPPER_TERMINAL_LOG2 || activated != cohorts.len() {
        return Err(C6WrapperPcsError::new("C6 persisted activation schedule incomplete"));
    }
    Ok(PersistedSealedChain {
        repetition: repetition as u8,
        common_point,
        activation_challenges,
        fold_challenges,
        fold_frames,
        fold_openings,
    })
}

#[allow(clippy::too_many_arguments)]
fn seal_persisted_cuda_chain(
    statement_digest: C6WrapperDigest,
    repetition: usize,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: Vec<Fp2>,
    backend: &mut Backend,
    spill_root: &Path,
    session_digest: C6WrapperDigest,
    transcript: &mut Transcript,
) -> Result<(PersistedSealedChain, u64, X4bCudaCommitMetricsV4)> {
    let common_point = claims[0].point.clone();
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
    let max_outer_len = commitments[0].spec.encoded_len()?;
    let mut current_coefficients = vec![Fp2::ZERO; max_outer_len / 8];
    let mut current_claim = Fp2::ZERO;
    let (mut activated, mut coefficient_bytes_read) = activate_persisted_coefficients_at_domain(
        max_outer_len,
        cohorts,
        claims,
        &activation_challenges,
        &mut current_coefficients,
        &mut current_claim,
    )?;
    if activated == 0 {
        return Err(C6WrapperPcsError::new("C6 CUDA persisted maximum cohort did not activate"));
    }
    let fold_descriptor = fold_descriptor_digest(statement_digest, repetition as u8, &commitments);
    let global_cohort_id = C6_GLOBAL_FOLD_COHORT_BASE
        .checked_add(repetition as u32)
        .ok_or_else(|| C6WrapperPcsError::new("C6 CUDA fold cohort id overflows"))?;
    let mut fold_frames = Vec::with_capacity(common_point.len());
    let mut fold_openings = Vec::with_capacity(common_point.len());
    let mut fold_challenges = Vec::with_capacity(common_point.len());
    let mut fold_commit = X4bCudaCommitMetricsV4::default();
    let mut input_len = max_outer_len;
    for round_index in 0..common_point.len() {
        let (line_zero, line_one) =
            claim_line(&current_coefficients, &common_point[round_index + 1..])?;
        if interpolate(line_zero, line_one, common_point[round_index]) != current_claim {
            return Err(C6WrapperPcsError::new("C6 CUDA persisted claim-line input mismatch"));
        }
        transcript.append(C6_FOLD_LINE_LABEL, 32);
        let fold_challenge = transcript.challenge_fp2();
        fold_challenges.push(fold_challenge);
        current_claim = interpolate(line_zero, line_one, fold_challenge);
        current_coefficients = fold_coefficients(&current_coefficients, fold_challenge)
            .map_err(|error| C6WrapperPcsError::frame("C6 CUDA coefficient fold", error))?;
        let output_len = input_len / 2;
        let (activated_now, bytes_read_now) = activate_persisted_coefficients_at_domain(
            output_len,
            cohorts,
            claims,
            &activation_challenges,
            &mut current_coefficients,
            &mut current_claim,
        )?;
        activated = activated
            .checked_add(activated_now)
            .ok_or_else(|| C6WrapperPcsError::new("C6 CUDA activation count overflows"))?;
        coefficient_bytes_read = coefficient_bytes_read
            .checked_add(bytes_read_now)
            .ok_or_else(|| C6WrapperPcsError::new("C6 CUDA coefficient reads overflow"))?;
        let fold_round = u8::try_from(round_index + 1)
            .map_err(|_| C6WrapperPcsError::new("C6 CUDA fold round overflows"))?;
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
        let (opening, round_metrics, returned_coefficients) =
            commit_production_c6_wrapper_fold_cuda(
                backend,
                config,
                current_coefficients,
                spill_root,
                statement_digest,
                session_digest,
                repetition as u8,
                fold_round,
            )?;
        current_coefficients = returned_coefficients;
        fold_commit
            .include(&round_metrics)
            .map_err(|error| C6WrapperPcsError::frame("C6 CUDA fold metric", error))?;
        let mut messages = vec![line_zero, line_one];
        if round_index + 1 == common_point.len() {
            if current_coefficients.as_slice() != [current_claim] {
                return Err(C6WrapperPcsError::new(
                    "C6 CUDA persisted final folded scalar mismatch",
                ));
            }
            messages.push(current_claim);
        }
        let frame = FoldCommitmentFrameV4 {
            cohort_id: global_cohort_id,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round,
            input_log2: input_len.ilog2() as u8,
            output_log2: output_len.ilog2() as u8,
            root_digest: opening.root(),
            ordered_message_symbols: messages,
        };
        let frame_len = FrameV4::FoldCommitment(frame.clone())
            .encode()
            .map_err(|error| C6WrapperPcsError::frame("C6 CUDA fold frame", error))?
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
        fold_openings.push(opening);
        input_len = output_len;
    }
    if input_len != 1usize << C6_WRAPPER_TERMINAL_LOG2 || activated != cohorts.len() {
        return Err(C6WrapperPcsError::new("C6 CUDA persisted activation schedule incomplete"));
    }
    Ok((
        PersistedSealedChain {
            repetition: repetition as u8,
            common_point,
            activation_challenges,
            fold_challenges,
            fold_frames,
            fold_openings,
        },
        coefficient_bytes_read,
        fold_commit,
    ))
}

#[allow(clippy::too_many_arguments)]
fn activate_persisted_coefficients_at_domain(
    domain_len: usize,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    current_coefficients: &mut [Fp2],
    current_claim: &mut Fp2,
) -> Result<(usize, u64)> {
    let mut activated = 0usize;
    let mut bytes_read = 0u64;
    for ((cohort, claim), activation) in cohorts.iter().zip(claims).zip(activation_challenges) {
        if cohort.commitment().spec.encoded_len()? != domain_len {
            continue;
        }
        let (combined, cohort_bytes_read) = cohort.combine_coefficients(claim)?;
        if combined.len() != current_coefficients.len() {
            return Err(C6WrapperPcsError::new("C6 CUDA persisted activation domain mismatch"));
        }
        for (output, value) in current_coefficients.iter_mut().zip(combined) {
            *output += *activation * value;
        }
        *current_claim += *activation * claim.value;
        activated = activated
            .checked_add(1)
            .ok_or_else(|| C6WrapperPcsError::new("C6 CUDA activation count overflows"))?;
        bytes_read = bytes_read
            .checked_add(cohort_bytes_read)
            .ok_or_else(|| C6WrapperPcsError::new("C6 CUDA coefficient reads overflow"))?;
    }
    Ok((activated, bytes_read))
}

#[allow(clippy::too_many_arguments)]
fn activate_persisted_at_domain(
    domain_len: usize,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    activation_challenges: &[Fp2],
    current_coefficients: &mut [Fp2],
    current_codeword: &mut [Fp2],
    current_claim: &mut Fp2,
) -> Result<usize> {
    let mut activated = 0usize;
    for ((cohort, claim), activation) in cohorts.iter().zip(claims).zip(activation_challenges) {
        if cohort.commitment().spec.encoded_len()? != domain_len {
            continue;
        }
        let combined = cohort.combine(claim)?;
        if combined.coefficients.len() != current_coefficients.len()
            || combined.codeword.len() != current_codeword.len()
        {
            return Err(C6WrapperPcsError::new("C6 persisted activation domain mismatch"));
        }
        for (output, value) in current_coefficients.iter_mut().zip(&combined.coefficients) {
            *output += *activation * *value;
        }
        for (output, value) in current_codeword.iter_mut().zip(&combined.codeword) {
            *output += *activation * *value;
        }
        *current_claim += *activation * combined.claimed_value;
        activated += 1;
    }
    Ok(activated)
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
        let mut opening = cohort
            .tree
            .open_initial(query_draws, &touched)
            .map_err(|error| C6WrapperPcsError::frame("C6 initial packed opening", error))?;
        // The N4 root uses one response-independent cache-state identity.
        // The packed envelope uses distinct outer role IDs so predecessor and
        // successor remain canonically ordered and statement-bound.
        opening.cohort_id = cohort.commitment.spec.cohort_id;
        initial_groups.push(opening);
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

fn issue_persisted_reference_openings(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    sealed: PersistedSealedChain,
    query_draws: &[u64],
) -> Result<C6WrapperChainProof> {
    issue_persisted_openings(statement_digest, cohorts, claims, sealed, query_draws)
        .map(|(chain, _)| chain)
}

fn issue_persisted_openings(
    statement_digest: C6WrapperDigest,
    cohorts: &[C6PersistedWrapperCohort],
    claims: &[C6WrapperOpeningClaim],
    sealed: PersistedSealedChain,
    query_draws: &[u64],
) -> Result<(C6WrapperChainProof, PersistedOpeningTrafficV4)> {
    validate_query_draws(query_draws, cohorts[0].commitment().config.outer_depth())?;
    if sealed.common_point != claims[0].point
        || sealed.activation_challenges.len() != cohorts.len()
        || sealed.fold_challenges.len() != sealed.fold_frames.len()
        || sealed.fold_openings.len() != sealed.fold_frames.len()
    {
        return Err(C6WrapperPcsError::new("C6 persisted sealed-chain geometry mismatch"));
    }
    let mut traffic = PersistedOpeningTrafficV4::default();
    let mut initial_groups = Vec::with_capacity(cohorts.len());
    for cohort in cohorts {
        let (mut opening, opening_traffic) = cohort.open_initial(query_draws)?;
        include_opening_traffic(&mut traffic, opening_traffic)?;
        opening.cohort_id = cohort.commitment().spec.cohort_id;
        initial_groups.push(opening);
    }
    let mut fold_rounds = Vec::with_capacity(sealed.fold_openings.len());
    for opening in &sealed.fold_openings {
        let (round, opening_traffic) = opening.open(query_draws)?;
        include_opening_traffic(&mut traffic, opening_traffic)?;
        fold_rounds.push(round);
    }
    let commitments = cohorts.iter().map(|cohort| cohort.commitment().clone()).collect::<Vec<_>>();
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
        .map_err(|error| C6WrapperPcsError::frame("C6 persisted packed opening shape", error))?;
    Ok((
        C6WrapperChainProof {
            repetition: sealed.repetition,
            fold_frames: sealed.fold_frames,
            packed_opening,
        },
        traffic,
    ))
}

fn include_opening_traffic(
    total: &mut PersistedOpeningTrafficV4,
    next: PersistedOpeningTrafficV4,
) -> Result<()> {
    macro_rules! add {
        ($field:ident) => {
            total.$field = total
                .$field
                .checked_add(next.$field)
                .ok_or_else(|| C6WrapperPcsError::new("C6 opening traffic metric overflows"))?;
        };
    }
    add!(oracle_file_bytes_read);
    add!(outer_cache_bytes_read);
    add!(inner_trees_rebuilt);
    add!(outer_frontier_leaves_rebuilt);
    add!(outer_internal_nodes_rebuilt);
    Ok(())
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
        let mut merkle_opening = opening.clone();
        merkle_opening.cohort_id = commitment.config.identity.cohort_id;
        verify_initial_packed_opening_v4(
            commitment.root,
            &commitment.config,
            query_draws,
            &touched,
            &merkle_opening,
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

fn validate_assembled_claims(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
    assembled: &C6AssembledWrapperClaims,
) -> Result<()> {
    validate_commitments(commitments)?;
    let slots_per_repetition = commitments.iter().try_fold(0usize, |sum, commitment| {
        sum.checked_add(usize::from(commitment.spec.slot_count))
            .ok_or_else(|| C6WrapperPcsError::new("C6 assembled slot count overflows"))
    })?;
    let expected_terminal_count = slots_per_repetition
        .checked_mul(C6_WRAPPER_REPETITIONS)
        .ok_or_else(|| C6WrapperPcsError::new("C6 assembled terminal count overflows"))?;
    if assembled.statement_digest != statement_digest
        || assembled.fixed_roots_digest != fixed_roots_digest(statement_digest, commitments)
        || assembled.slot_terminal_count != expected_terminal_count
    {
        return Err(C6WrapperPcsError::new("C6 assembled claims do not bind the PCS commitments"));
    }
    validate_statement_and_claims(statement_digest, commitments, &assembled.claims_by_repetition)
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

pub(crate) fn validate_claim(
    commitment: &C6WrapperCommitment,
    claim: &C6WrapperOpeningClaim,
) -> Result<()> {
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

fn is_cache_state_role(cohort_id: u32) -> bool {
    matches!(cohort_id, C6_PREDECESSOR_CACHE_COHORT_ID | C6_SUCCESSOR_CACHE_COHORT_ID)
}

fn merkle_cohort_id(cohort_id: u32) -> u32 {
    if is_cache_state_role(cohort_id) {
        C6_CACHE_STATE_MERKLE_COHORT_ID
    } else {
        cohort_id
    }
}

fn wrapper_verifier_config(
    statement_digest: C6WrapperDigest,
    spec: C6WrapperCohortSpec,
    cache_descriptors: Option<&C6CacheStateDescriptors>,
) -> Result<CohortVerifierConfigV4> {
    spec.validate()?;
    if statement_digest == [0; 32] {
        return Err(C6WrapperPcsError::new("zero C6 wrapper statement"));
    }
    let slot_descriptors = if is_cache_state_role(spec.cohort_id) {
        let descriptors = cache_descriptors.ok_or_else(|| {
            C6WrapperPcsError::new("C6 cache config is missing static descriptors")
        })?;
        if usize::from(spec.slot_count) != C6_PERSISTENT_CACHE_SLOTS {
            return Err(C6WrapperPcsError::new("C6 cache config has a wrong slot census"));
        }
        descriptors.slots().iter().copied().map(Some).collect()
    } else {
        if cache_descriptors.is_some() {
            return Err(C6WrapperPcsError::new("non-cache C6 config received cache descriptors"));
        }
        (0..spec.slot_count)
            .map(|slot| Some(slot_descriptor_digest(statement_digest, spec, slot)))
            .collect()
    };
    Ok(CohortVerifierConfigV4 {
        identity: CohortIdentityV4 {
            cohort_id: merkle_cohort_id(spec.cohort_id),
            oracle_kind: spec.oracle_kind.v4(),
            fold_round: 0,
        },
        slot_descriptors,
        outer_len: spec.encoded_len()?,
        expected_symbol_count: 1,
    })
}

fn fixed_roots_digest(
    statement_digest: C6WrapperDigest,
    commitments: &[C6WrapperCommitment],
) -> C6WrapperDigest {
    let mut hasher = blake3::Hasher::new_derive_key(C6_FIXED_ROOTS_CONTEXT);
    hasher.update(&c6_wrapper_profile_digest());
    hasher.update(&statement_digest);
    hasher.update(&(commitments.len() as u64).to_le_bytes());
    for commitment in commitments {
        hasher.update(&commitment.spec.cohort_id.to_le_bytes());
        hasher.update(&[commitment.spec.oracle_kind as u8, commitment.spec.payload_log2]);
        hasher.update(&commitment.spec.slot_count.to_le_bytes());
        hasher.update(&commitment.root);
    }
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
    production_wrapper_codec_reference(&specs)
}

/// Materialized worst-case C6.1 native codec fixture with the hidden-u
/// groups absent from the packed opening.
pub fn production_c61_native_wrapper_codec_reference() -> Result<C6WrapperPcsProof> {
    let specs = production_c61_native_wrapper_specs();
    production_wrapper_codec_reference(&specs)
}

fn production_wrapper_codec_reference(specs: &[C6WrapperCohortSpec]) -> Result<C6WrapperPcsProof> {
    let mut initial_groups = Vec::with_capacity(specs.len());
    for &spec in specs {
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
    use std::array;

    use crate::c6_wrapper_persisted::persist_scaled_c6_wrapper_cohort_reference;
    use crate::x4::ntt::evaluate_multilinear_table;

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(17 * value + 3))
    }

    fn statement() -> C6WrapperDigest {
        [0x6c; 32]
    }

    fn cache_descriptors() -> C6CacheStateDescriptors {
        C6CacheStateDescriptors::from_persistent_profile(&C6PersistentCacheStaticProfile {
            protocol_digest: [0x11; 32],
            model_digest: [0x22; 32],
            params_digest: [0x33; 32],
            wrapper_profile_digest: c6_wrapper_profile_digest(),
        })
        .unwrap()
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

    fn production_commitments() -> Vec<C6WrapperCommitment> {
        let cache_descriptors = cache_descriptors();
        production_c6_wrapper_specs()
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                let root = [(index + 1) as u8; 32];
                if is_cache_state_role(spec.cohort_id) {
                    C6WrapperCommitment::from_cache_root(
                        statement(),
                        spec,
                        root,
                        &cache_descriptors,
                    )
                    .unwrap()
                } else {
                    C6WrapperCommitment::from_root(statement(), spec, root).unwrap()
                }
            })
            .collect()
    }

    fn run_production_coordinators(
        fixed: &C6FixedWrapperCommitments,
        transcript: &mut Transcript,
    ) -> Vec<C6WrapperRoundPoint> {
        (0..C6_WRAPPER_REPETITIONS as u8)
            .map(|repetition| {
                let mut coordinator = C6WrapperRoundCoordinator::new(fixed, repetition).unwrap();
                while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
                    let ids = coordinator.expected_participant_ids().unwrap();
                    let receipts = ids
                        .iter()
                        .map(|participant_id| C6WrapperRoundMessageReceipt {
                            participant_id: *participant_id,
                            message_bytes: 48,
                        })
                        .collect::<Vec<_>>();
                    coordinator.fix_messages_and_release_challenge(&receipts, transcript).unwrap();
                    coordinator.confirm_participants_bound(&ids).unwrap();
                }
                coordinator.finish().unwrap()
            })
            .collect()
    }

    fn production_slot_claims(
        commitments: &[C6WrapperCommitment],
        points: &[C6WrapperRoundPoint],
    ) -> Vec<C6WrapperSlotOpeningClaim> {
        let mut claims = Vec::with_capacity(2 * C6_WRAPPER_ACTIVE_SLOTS);
        for (repetition, round_point) in points.iter().enumerate() {
            for commitment in commitments {
                let point = round_point.cohort_point(commitment.spec).unwrap();
                for slot in 0..commitment.spec.slot_count {
                    claims.push(C6WrapperSlotOpeningClaim {
                        repetition: repetition as u8,
                        cohort_id: commitment.spec.cohort_id,
                        slot,
                        point: point.clone(),
                        value: symbol(
                            100_000
                                + 10_000 * repetition as u64
                                + 100 * u64::from(commitment.spec.payload_log2)
                                + u64::from(slot),
                        ),
                    });
                }
            }
        }
        claims
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

    #[test]
    fn scaled_persisted_owner_matches_resident_root_and_opening_byte_for_byte() {
        let (mut cohorts, _, claims) = fixture();
        let cohort = cohorts.remove(0);
        let claim = claims[0][0].clone();
        let mut expected_coefficients = vec![Fp2::ZERO; cohort.coefficients[0].len()];
        for (source, weight) in cohort.coefficients.iter().zip(&claim.slot_weights) {
            for (output, value) in expected_coefficients.iter_mut().zip(source) {
                *output += *weight * *value;
            }
        }
        let commitment = cohort.commitment.clone();
        let draw_bound = 1u64 << (commitment.config.outer_depth() - 1);
        let draws = (0..C6_WRAPPER_QUERY_COUNT)
            .map(|index| (3 * index as u64 + 1) % draw_bound)
            .collect::<Vec<_>>();
        let touched = all_slots(commitment.spec.slot_count);
        let reference = cohort.tree.open_initial(&draws, &touched).unwrap();
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-persisted-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let persisted =
            persist_scaled_c6_wrapper_cohort_reference(cohort, &root, [0x51; 32], 7).unwrap();
        let (opening, traffic) = persisted.open_initial(&draws).unwrap();
        assert_eq!(persisted.commitment(), &commitment);
        assert_eq!(opening, reference);
        assert_eq!(persisted.session_digest(), [0x51; 32]);
        assert_eq!(persisted.oracle_ordinal(), 7);
        assert_eq!(persisted.metrics().resident_codeword_copies_after_seal, 0);
        assert_eq!(persisted.metrics().files_created, 3);
        assert_eq!(persisted.metrics().fsync_count, 4);
        assert!(traffic.oracle_file_bytes_read > 0);
        let (combined_coefficients, coefficient_bytes_read) =
            persisted.combine_coefficients(&claim).unwrap();
        assert_eq!(combined_coefficients, expected_coefficients);
        assert_eq!(
            coefficient_bytes_read,
            std::fs::metadata(persisted.directory().join("coefficients.fp2")).unwrap().len()
        );
        verify_initial_packed_opening_v4(
            commitment.root,
            &commitment.config,
            &draws,
            &touched,
            &opening,
        )
        .unwrap();
        let duplicate =
            commit_c6_wrapper_cohort(statement(), scaled_specs()[0], slots(scaled_specs()[0]))
                .unwrap();
        assert!(
            persist_scaled_c6_wrapper_cohort_reference(duplicate, &root, [0x51; 32], 7,).is_err()
        );
        std::fs::OpenOptions::new()
            .write(true)
            .open(persisted.directory().join("oracle.fp2"))
            .unwrap()
            .set_len(0)
            .unwrap();
        assert!(persisted.open_initial(&draws).is_err());
        drop(persisted);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_persisted_pcs_refuses_cpu_before_profile_or_io() {
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-pcs-cuda-reject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let assembled = C6AssembledWrapperClaims {
            statement_digest: [0; 32],
            fixed_roots_digest: [0; 32],
            slot_terminal_count: 0,
            claims_by_repetition: Vec::new(),
            authenticated_link: false,
        };
        let error = prove_c6_wrapper_pcs_persisted_cuda_assembled(
            [0; 32],
            &[],
            &assembled,
            &mut Backend::cpu(),
            &root,
            [0; 32],
            &mut Transcript::new([0x84; 32]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("refuses CPU"));
        assert!(!root.exists());
    }

    #[test]
    fn scaled_persisted_two_chain_proof_matches_resident_bytes_and_transcript() {
        let (cohorts, commitments, claims) = fixture();
        let seed = [0x72; 32];
        let mut resident_tx = Transcript::new(seed);
        let resident =
            prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut resident_tx).unwrap();
        let root = std::env::temp_dir().join(format!(
            "volta-c6-wrapper-persisted-chain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let session = [0x73; 32];
        let persisted = cohorts
            .into_iter()
            .enumerate()
            .map(|(ordinal, cohort)| {
                persist_scaled_c6_wrapper_cohort_reference(cohort, &root, session, ordinal as u64)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut persisted_tx = Transcript::new(seed);
        let proof = prove_c6_wrapper_pcs_persisted_reference(
            statement(),
            &persisted,
            &claims,
            &root,
            session,
            &mut persisted_tx,
        )
        .unwrap();
        assert_eq!(proof, resident);
        assert_eq!(proof.canonical_bytes().unwrap(), resident.canonical_bytes().unwrap());
        assert_eq!(persisted_tx.ledger(), resident_tx.ledger());
        assert_eq!(persisted_tx.total_bytes(), resident_tx.total_bytes());
        let mut verifier_tx = Transcript::new(seed);
        verify_c6_wrapper_pcs(statement(), &commitments, &claims, &proof, &mut verifier_tx)
            .unwrap();
        assert_eq!(verifier_tx.ledger(), persisted_tx.ledger());
        drop(persisted);
        std::fs::remove_dir_all(root).unwrap();
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
    fn production_coordinator_and_all_slot_assembly_are_verifier_owned() {
        let commitments = production_commitments();
        let seed = [0x2a; 32];
        let mut prover_tx = Transcript::new(seed);
        let fixed = fix_production_c6_wrapper_commitments(
            statement(),
            &cache_descriptors(),
            &commitments,
            &mut prover_tx,
        )
        .unwrap();
        assert_eq!(prover_tx.bytes_for(C6_INITIAL_ROOTS_LABEL), 6 * 32);
        let wrong_descriptors =
            C6CacheStateDescriptors::from_slots(array::from_fn(|slot| [(slot + 0x61) as u8; 32]))
                .unwrap();
        assert!(fix_production_c6_wrapper_commitments(
            statement(),
            &wrong_descriptors,
            &commitments,
            &mut Transcript::new([0x29; 32]),
        )
        .is_err());

        let mut first = C6WrapperRoundCoordinator::new(&fixed, 0).unwrap();
        assert!(first.confirm_participants_bound(&[]).is_err());
        assert_eq!(first.expected_participant_ids().unwrap(), vec![C6_CACHE_ROUND_PARTICIPANT_ID]);
        let first_receipt = [C6WrapperRoundMessageReceipt {
            participant_id: C6_CACHE_ROUND_PARTICIPANT_ID,
            message_bytes: 48,
        }];
        let first_challenge =
            first.fix_messages_and_release_challenge(&first_receipt, &mut prover_tx).unwrap();
        assert_ne!(first_challenge, Fp2::ZERO);
        assert!(first.fix_messages_and_release_challenge(&first_receipt, &mut prover_tx).is_err());
        assert!(first
            .confirm_participants_bound(&[C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID])
            .is_err());
        first.confirm_participants_bound(&[C6_CACHE_ROUND_PARTICIPANT_ID]).unwrap();
        assert_eq!(
            first.expected_participant_ids().unwrap(),
            vec![C6_CACHE_ROUND_PARTICIPANT_ID, C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID]
        );

        // Complete this first repetition manually, then use the common
        // helper for an independent verifier replay below.
        while first.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
            let ids = first.expected_participant_ids().unwrap();
            if first.round_index() == C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND {
                assert_eq!(
                    ids,
                    vec![
                        C6_CACHE_ROUND_PARTICIPANT_ID,
                        C6_DELTA_RESIDUAL_ROUND_PARTICIPANT_ID,
                        C6_HIDDEN_U_ROUND_PARTICIPANT_ID,
                    ]
                );
            }
            let receipts = ids
                .iter()
                .map(|participant_id| C6WrapperRoundMessageReceipt {
                    participant_id: *participant_id,
                    message_bytes: 48,
                })
                .collect::<Vec<_>>();
            first.fix_messages_and_release_challenge(&receipts, &mut prover_tx).unwrap();
            first.confirm_participants_bound(&ids).unwrap();
        }
        let point_zero = first.finish().unwrap();
        let mut second = C6WrapperRoundCoordinator::new(&fixed, 1).unwrap();
        while second.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
            let ids = second.expected_participant_ids().unwrap();
            let receipts = ids
                .iter()
                .map(|participant_id| C6WrapperRoundMessageReceipt {
                    participant_id: *participant_id,
                    message_bytes: 48,
                })
                .collect::<Vec<_>>();
            second.fix_messages_and_release_challenge(&receipts, &mut prover_tx).unwrap();
            second.confirm_participants_bound(&ids).unwrap();
        }
        let points = vec![point_zero, second.finish().unwrap()];
        for point in &points {
            assert_eq!(point.random_point().len(), C6_WRAPPER_RANDOM_POINT_LEN);
            assert_eq!(point.common_point().len(), C6_WRAPPER_COMMON_POINT_LEN);
            assert_eq!(point.common_point().last(), Some(&Fp2::ZERO));
            for commitment in &commitments {
                let cohort_point = point.cohort_point(commitment.spec).unwrap();
                assert_eq!(
                    cohort_point,
                    point.common_point()[point.common_point().len() - cohort_point.len()..]
                );
            }
        }

        let slot_claims = production_slot_claims(&commitments, &points);
        let assembled =
            assemble_production_c6_wrapper_claims(&fixed, &points, &slot_claims, &mut prover_tx)
                .unwrap();
        assert_eq!(assembled.slot_terminal_count(), 2 * C6_WRAPPER_ACTIVE_SLOTS);
        assert_eq!(
            prover_tx.bytes_for(C6_SLOT_TERMINAL_VALUES_LABEL),
            (2 * C6_WRAPPER_ACTIVE_SLOTS * 16) as u64
        );
        assert_eq!(prover_tx.bytes_for(C6_TERMINAL_CLAIMS_LABEL), 0);

        let mut cursor = 0usize;
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            for (commitment, aggregate) in
                commitments.iter().zip(&assembled.claims_by_repetition()[repetition])
            {
                let terminals =
                    &slot_claims[cursor..cursor + usize::from(commitment.spec.slot_count)];
                let expected = aggregate
                    .slot_weights
                    .iter()
                    .zip(terminals)
                    .fold(Fp2::ZERO, |sum, (weight, terminal)| sum + *weight * terminal.value);
                assert_eq!(aggregate.value, expected);
                cursor += usize::from(commitment.spec.slot_count);
            }
        }

        let mut verifier_tx = Transcript::new(seed);
        let verifier_fixed = fix_production_c6_wrapper_commitments(
            statement(),
            &cache_descriptors(),
            &commitments,
            &mut verifier_tx,
        )
        .unwrap();
        let verifier_points = run_production_coordinators(&verifier_fixed, &mut verifier_tx);
        let verifier_slot_claims = production_slot_claims(&commitments, &verifier_points);
        let verifier_assembled = assemble_production_c6_wrapper_claims(
            &verifier_fixed,
            &verifier_points,
            &verifier_slot_claims,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(points, verifier_points);
        assert_eq!(assembled, verifier_assembled);
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());

        let mut missing = slot_claims.clone();
        missing.pop();
        assert!(assemble_production_c6_wrapper_claims(
            &fixed,
            &points,
            &missing,
            &mut Transcript::new([0x7a; 32]),
        )
        .is_err());
        let mut duplicate = slot_claims.clone();
        let first_claim = duplicate[0].clone();
        *duplicate.last_mut().unwrap() = first_claim;
        assert!(assemble_production_c6_wrapper_claims(
            &fixed,
            &points,
            &duplicate,
            &mut Transcript::new([0x7b; 32]),
        )
        .is_err());
        let mut wrong_point = slot_claims;
        wrong_point[0].point[0] += Fp2::ONE;
        assert!(assemble_production_c6_wrapper_claims(
            &fixed,
            &points,
            &wrong_point,
            &mut Transcript::new([0x7c; 32]),
        )
        .is_err());
    }

    #[test]
    fn hidden_u_claims_bind_to_registered_slots_without_vector_payloads() {
        let specs = production_c6_wrapper_specs();
        let mut hidden_claims = Vec::new();
        let mut common_points = Vec::new();
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            let random_point = (0..C6_WRAPPER_RANDOM_POINT_LEN)
                .map(|index| symbol(800_000 + 100 * repetition as u64 + index as u64))
                .collect::<Vec<_>>();
            hidden_claims.push(C6HiddenUOpeningClaim {
                repetition: repetition as u8,
                family: C6HiddenUFamily::Weights,
                point: random_point[C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND..].to_vec(),
                value: symbol(810_000 + repetition as u64),
            });
            hidden_claims.push(C6HiddenUOpeningClaim {
                repetition: repetition as u8,
                family: C6HiddenUFamily::Embed,
                point: random_point[C6_HIDDEN_U_EMBED_ACTIVATION_ROUND..].to_vec(),
                value: symbol(820_000 + repetition as u64),
            });
            let mut common = random_point;
            common.push(Fp2::ZERO);
            common_points.push(common);
        }
        let slots =
            bind_hidden_u_opening_claims_to_wrapper_slots(&hidden_claims, specs[3], 2, specs[4], 5)
                .unwrap();
        assert_eq!(slots.len(), 4);
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            let weights = &slots[2 * repetition];
            let embed = &slots[2 * repetition + 1];
            assert_eq!(weights.cohort_id, C6_HIDDEN_U_WEIGHTS_COHORT_ID);
            assert_eq!(embed.cohort_id, C6_HIDDEN_U_EMBED_COHORT_ID);
            assert_eq!((weights.slot, embed.slot), (2, 5));
            assert_eq!(
                weights.point,
                common_points[repetition][common_points[repetition].len() - weights.point.len()..]
            );
            assert_eq!(
                embed.point,
                common_points[repetition][common_points[repetition].len() - embed.point.len()..]
            );
            assert_eq!(weights.value, hidden_claims[2 * repetition].value);
            assert_eq!(embed.value, hidden_claims[2 * repetition + 1].value);
        }

        let mut bad = hidden_claims.clone();
        bad[1].point[0] += Fp2::ONE;
        assert!(
            bind_hidden_u_opening_claims_to_wrapper_slots(&bad, specs[3], 2, specs[4], 5).is_err()
        );
        assert!(bind_hidden_u_opening_claims_to_wrapper_slots(
            &hidden_claims,
            specs[3],
            specs[3].slot_count,
            specs[4],
            5,
        )
        .is_err());
    }

    #[test]
    fn clear_slot_assembly_is_diagnostic_only_and_cannot_cross_public_seam() {
        let (cohorts, commitments, _) = fixture();
        let seed = [0x2b; 32];
        let mut prover_tx = Transcript::new(seed);
        let fixed = fix_c6_wrapper_commitments_inner(
            statement(),
            None,
            &commitments,
            C6FixedWrapperProfile::Test,
            &[],
            &mut prover_tx,
        )
        .unwrap();
        let points = (0..C6_WRAPPER_REPETITIONS)
            .map(|repetition| {
                let random_point = (0..3)
                    .map(|index| symbol(300_000 + 100 * repetition as u64 + index))
                    .collect::<Vec<_>>();
                let mut common_point = random_point.clone();
                common_point.push(Fp2::ZERO);
                C6WrapperRoundPoint {
                    repetition: repetition as u8,
                    fixed_roots_digest: fixed.binding_digest,
                    random_point,
                    common_point,
                }
            })
            .collect::<Vec<_>>();
        let mut slot_claims = Vec::new();
        for (repetition, round_point) in points.iter().enumerate() {
            for cohort in &cohorts {
                let point = round_point.cohort_point(cohort.commitment.spec).unwrap();
                for (slot, coefficients) in cohort.coefficients.iter().enumerate() {
                    slot_claims.push(C6WrapperSlotOpeningClaim {
                        repetition: repetition as u8,
                        cohort_id: cohort.commitment.spec.cohort_id,
                        slot: slot as u16,
                        point: point.clone(),
                        value: evaluate_multilinear_coefficients(coefficients, &point).unwrap(),
                    });
                }
            }
        }
        let assembled =
            assemble_c6_wrapper_claims_inner(&fixed, &points, &slot_claims, false, &mut prover_tx)
                .unwrap();
        assert!(prove_c6_wrapper_pcs_assembled(statement(), &cohorts, &assembled, &mut prover_tx)
            .is_err());
        let proof = prove_c6_wrapper_pcs_inner(
            statement(),
            &cohorts,
            assembled.claims_by_repetition(),
            false,
            &mut prover_tx,
        )
        .unwrap();
        assert_eq!(prover_tx.bytes_for(C6_TERMINAL_CLAIMS_LABEL), 0);
        assert_eq!(
            prover_tx.bytes_for(C6_SLOT_TERMINAL_VALUES_LABEL),
            (slot_claims.len() * 16) as u64
        );

        let mut verifier_tx = Transcript::new(seed);
        let verifier_fixed = fix_c6_wrapper_commitments_inner(
            statement(),
            None,
            &commitments,
            C6FixedWrapperProfile::Test,
            &[],
            &mut verifier_tx,
        )
        .unwrap();
        let verifier_points = points
            .iter()
            .map(|point| C6WrapperRoundPoint {
                repetition: point.repetition,
                fixed_roots_digest: verifier_fixed.binding_digest,
                random_point: point.random_point.clone(),
                common_point: point.common_point.clone(),
            })
            .collect::<Vec<_>>();
        let verifier_assembled = assemble_c6_wrapper_claims_inner(
            &verifier_fixed,
            &verifier_points,
            &slot_claims,
            false,
            &mut verifier_tx,
        )
        .unwrap();
        assert!(verify_c6_wrapper_pcs_assembled(
            statement(),
            &commitments,
            &verifier_assembled,
            &proof,
            &mut verifier_tx,
        )
        .is_err());
        verify_c6_wrapper_pcs_inner(
            statement(),
            &commitments,
            verifier_assembled.claims_by_repetition(),
            &proof,
            false,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(assembled, verifier_assembled);
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());
    }

    #[test]
    fn mapped_hidden_u_slot_claims_enter_the_two_packed_chains() {
        let specs = [
            C6WrapperCohortSpec {
                cohort_id: 0xC6EE_0001,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 8,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_WEIGHTS_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 5,
                slot_count: 1,
            },
            C6WrapperCohortSpec {
                cohort_id: C6_HIDDEN_U_EMBED_COHORT_ID,
                oracle_kind: C6WrapperOracleKind::Witness,
                payload_log2: 3,
                slot_count: 1,
            },
        ];
        let tables = specs
            .iter()
            .enumerate()
            .map(|(cohort, spec)| {
                (0..spec.payload_len().unwrap())
                    .map(|index| symbol(900_000 + 10_000 * cohort as u64 + index as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let cohorts = specs
            .iter()
            .enumerate()
            .map(|(cohort, spec)| {
                let mask = (0..spec.payload_len().unwrap())
                    .map(|index| symbol(950_000 + 10_000 * cohort as u64 + index as u64))
                    .collect::<Vec<_>>();
                commit_c6_wrapper_cohort(
                    statement(),
                    *spec,
                    vec![C6WrapperSlotWitness::Witness {
                        witness: tables[cohort].clone(),
                        zk_mask: mask,
                    }],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut hidden_claims = Vec::new();
        let mut random_points = Vec::new();
        for repetition in 0..C6_WRAPPER_REPETITIONS {
            let random_point = (0..8)
                .map(|index| symbol(970_000 + 100 * repetition as u64 + index))
                .collect::<Vec<_>>();
            let weights_point = random_point[3..].to_vec();
            let embed_point = random_point[5..].to_vec();
            hidden_claims.push(C6HiddenUOpeningClaim {
                repetition: repetition as u8,
                family: C6HiddenUFamily::Weights,
                value: evaluate_multilinear_table(&tables[1], &weights_point).unwrap(),
                point: weights_point,
            });
            hidden_claims.push(C6HiddenUOpeningClaim {
                repetition: repetition as u8,
                family: C6HiddenUFamily::Embed,
                value: evaluate_multilinear_table(&tables[2], &embed_point).unwrap(),
                point: embed_point,
            });
            random_points.push(random_point);
        }
        let hidden_slots =
            bind_hidden_u_opening_claims_to_wrapper_slots(&hidden_claims, specs[1], 0, specs[2], 0)
                .unwrap();
        let claims = (0..C6_WRAPPER_REPETITIONS)
            .map(|repetition| {
                let mut cache_point = random_points[repetition].clone();
                cache_point.push(Fp2::ZERO);
                vec![
                    C6WrapperOpeningClaim {
                        repetition: repetition as u8,
                        cohort_id: specs[0].cohort_id,
                        point: cache_point,
                        slot_weights: vec![Fp2::ONE],
                        value: evaluate_multilinear_table(&tables[0], &random_points[repetition])
                            .unwrap(),
                    },
                    C6WrapperOpeningClaim {
                        repetition: repetition as u8,
                        cohort_id: hidden_slots[2 * repetition].cohort_id,
                        point: hidden_slots[2 * repetition].point.clone(),
                        slot_weights: vec![Fp2::ONE],
                        value: hidden_slots[2 * repetition].value,
                    },
                    C6WrapperOpeningClaim {
                        repetition: repetition as u8,
                        cohort_id: hidden_slots[2 * repetition + 1].cohort_id,
                        point: hidden_slots[2 * repetition + 1].point.clone(),
                        slot_weights: vec![Fp2::ONE],
                        value: hidden_slots[2 * repetition + 1].value,
                    },
                ]
            })
            .collect::<Vec<_>>();
        let commitments =
            cohorts.iter().map(|cohort| cohort.commitment.clone()).collect::<Vec<_>>();
        let seed = [0x63; 32];
        let mut prover_tx = Transcript::new(seed);
        let proof = prove_c6_wrapper_pcs(statement(), &cohorts, &claims, &mut prover_tx).unwrap();
        let mut verifier_tx = Transcript::new(seed);
        verify_c6_wrapper_pcs(statement(), &commitments, &claims, &proof, &mut verifier_tx)
            .unwrap();
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());
        assert_eq!(hidden_slots.iter().map(|claim| claim.value).collect::<Vec<_>>(), {
            hidden_claims.iter().map(|claim| claim.value).collect::<Vec<_>>()
        });
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
    fn cache_state_root_is_role_and_response_independent_but_profile_bound() {
        let predecessor_spec = C6WrapperCohortSpec {
            cohort_id: C6_PREDECESSOR_CACHE_COHORT_ID,
            oracle_kind: C6WrapperOracleKind::Witness,
            payload_log2: 3,
            slot_count: 8,
        };
        let successor_spec =
            C6WrapperCohortSpec { cohort_id: C6_SUCCESSOR_CACHE_COHORT_ID, ..predecessor_spec };
        let state_slots = (0..predecessor_spec.slot_count)
            .map(|slot| C6WrapperSlotWitness::Witness {
                witness: (0..8)
                    .map(|index| symbol(1_100_000 + 100 * u64::from(slot) + index))
                    .collect(),
                zk_mask: (0..8)
                    .map(|index| symbol(1_200_000 + 100 * u64::from(slot) + index))
                    .collect(),
            })
            .collect::<Vec<_>>();
        let descriptors = cache_descriptors();
        let predecessor = commit_c6_cache_state_cohort(
            [0x41; 32],
            predecessor_spec,
            state_slots.clone(),
            &descriptors,
        )
        .unwrap();
        let successor = commit_c6_cache_state_cohort(
            [0x42; 32],
            successor_spec,
            state_slots.clone(),
            &descriptors,
        )
        .unwrap();
        assert_eq!(predecessor.commitment.root, successor.commitment.root);
        assert_eq!(
            predecessor.commitment.config.identity.cohort_id,
            C6_CACHE_STATE_MERKLE_COHORT_ID
        );
        assert_eq!(predecessor.commitment.config, successor.commitment.config);
        assert_ne!(predecessor.commitment.spec.cohort_id, successor.commitment.spec.cohort_id);

        let reused = C6WrapperCommitment::from_cache_root(
            [0x43; 32],
            predecessor_spec,
            successor.commitment.root,
            &descriptors,
        )
        .unwrap();
        assert_eq!(reused.root, successor.commitment.root);
        assert_eq!(reused.config, successor.commitment.config);

        let other_descriptors =
            C6CacheStateDescriptors::from_slots(array::from_fn(|slot| [(slot + 0x41) as u8; 32]))
                .unwrap();
        let other = commit_c6_cache_state_cohort(
            [0x42; 32],
            successor_spec,
            state_slots,
            &other_descriptors,
        )
        .unwrap();
        assert_ne!(successor.commitment.root, other.commitment.root);
        assert!(commit_c6_wrapper_cohort(
            [0x42; 32],
            successor_spec,
            vec![
                C6WrapperSlotWitness::Witness {
                    witness: vec![Fp2::ZERO; 8],
                    zk_mask: vec![Fp2::ZERO; 8],
                };
                8
            ],
        )
        .is_err());
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
            // 86 draws into the scaled first-round +/- bases necessarily
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
            vec![28, 28, 27, 25, 23, 19]
        );
        let maximum_point = usize::from(specs[0].coefficient_log2().unwrap());
        assert_eq!(maximum_point, C6_WRAPPER_COMMON_POINT_LEN);
        assert_eq!(
            maximum_point - usize::from(specs[2].coefficient_log2().unwrap()),
            C6_DELTA_RESIDUAL_ACTIVATION_ROUND
        );
        assert_eq!(
            maximum_point - usize::from(specs[3].coefficient_log2().unwrap()),
            C6_HIDDEN_U_WEIGHTS_ACTIVATION_ROUND
        );
        assert_eq!(
            maximum_point - usize::from(specs[4].coefficient_log2().unwrap()),
            C6_HIDDEN_U_EMBED_ACTIVATION_ROUND
        );
        assert_eq!(
            maximum_point - usize::from(specs[5].coefficient_log2().unwrap()),
            C6_WRAPPER_AUXILIARY_ACTIVATION_ROUND
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
            assert_eq!(components.opened_symbols, 15_904);
            assert_eq!(components.initial_inner_siblings, 0);
            assert_eq!(components.initial_outer_siblings + components.fold_outer_siblings, 52_576);
            assert_eq!(components.metadata_bytes, 571);
            assert_eq!(components.serialized_bytes, 1_937_467);
            assert_eq!(fold_bytes + components.serialized_bytes, C6_WRAPPER_ONE_CHAIN_BYTES);
        }
    }

    #[test]
    fn c61_native_profile_has_four_roots_56_slots_and_no_hidden_participant() {
        let specs = production_c61_native_wrapper_specs();
        assert_eq!(
            specs.iter().map(|spec| usize::from(spec.slot_count)).sum::<usize>(),
            C61_NATIVE_WRAPPER_ACTIVE_SLOTS
        );
        assert_eq!(
            specs.iter().map(|spec| spec.encoded_domain_log2().unwrap()).collect::<Vec<_>>(),
            vec![28, 28, 27, 19]
        );
        assert!(specs.iter().all(|spec| !matches!(
            spec.cohort_id,
            C6_HIDDEN_U_WEIGHTS_COHORT_ID | C6_HIDDEN_U_EMBED_COHORT_ID
        )));

        let cache_descriptors = cache_descriptors();
        let commitments = specs
            .into_iter()
            .enumerate()
            .map(|(index, spec)| {
                let root = [0x80 + index as u8; 32];
                if is_cache_state_role(spec.cohort_id) {
                    C6WrapperCommitment::from_cache_root(
                        statement(),
                        spec,
                        root,
                        &cache_descriptors,
                    )
                    .unwrap()
                } else {
                    C6WrapperCommitment::from_root(statement(), spec, root).unwrap()
                }
            })
            .collect::<Vec<_>>();
        let mut transcript = Transcript::new([0x91; 32]);
        let fixed = fix_production_c61_native_wrapper_commitments(
            statement(),
            &cache_descriptors,
            &commitments,
            &mut transcript,
        )
        .unwrap();
        assert!(fixed.is_c61_native_profile());
        assert!(C6WrapperRoundCoordinator::new(&fixed, 0).is_err());

        let mut fiat_shamir = Transcript::new_fiat_shamir([0x93; 32]).unwrap();
        fix_production_c61_native_wrapper_commitments(
            statement(),
            &cache_descriptors,
            &commitments,
            &mut fiat_shamir,
        )
        .unwrap();
        assert_eq!(fiat_shamir.bytes_for(C6_INITIAL_ROOTS_LABEL), 4 * 32);
        assert!(fiat_shamir.canonical_binding_digest().is_ok());

        let mut coordinator = C61NativeWrapperRoundCoordinator::new(&fixed, 0).unwrap();
        while coordinator.round_index() < C6_WRAPPER_RANDOM_POINT_LEN {
            let ids = coordinator.expected_participant_ids().unwrap();
            assert!(!ids.contains(&C6_HIDDEN_U_ROUND_PARTICIPANT_ID));
            let receipts = ids
                .iter()
                .map(|participant_id| C6WrapperRoundMessageReceipt {
                    participant_id: *participant_id,
                    message_bytes: 48,
                })
                .collect::<Vec<_>>();
            coordinator.fix_messages_and_release_challenge(&receipts, &mut transcript).unwrap();
            coordinator.confirm_participants_bound(&ids).unwrap();
        }
        assert_eq!(coordinator.finish().unwrap().common_point().len(), 25);

        let mut wrong_transcript = Transcript::new([0x92; 32]);
        assert!(fix_production_c6_wrapper_commitments(
            statement(),
            &cache_descriptors,
            &commitments,
            &mut wrong_transcript,
        )
        .is_err());
        assert!(fix_production_c61_native_wrapper_commitments(
            statement(),
            &cache_descriptors,
            &production_commitments(),
            &mut wrong_transcript,
        )
        .is_err());

        let proof = production_c61_native_wrapper_codec_reference().unwrap();
        assert_eq!(proof.encoded_len().unwrap(), C61_NATIVE_WRAPPER_TWO_CHAIN_BYTES);
        assert!(proof.chains.iter().all(|chain| chain.packed_opening.initial_groups.len() == 4));
    }
}
