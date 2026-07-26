//! Blind M9 seam for the schema-4 model-global folding PCS.
//!
//! Corrections create only pending values.  The sole Pending-to-Bound
//! transition closes a delayed-variable blind sumcheck against the final
//! scalar of the commitment's own sealed global fold/query chain.  No target
//! evaluation or prover assertion is an accepted substitute.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use volta_field::Fp2;
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_prover,
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::mle::{eq_points, eq_vec, fold_low, lagrange3};

use super::deferred_v4::{
    authenticated_output_link_schedule_digest_x4d_v1, x4d_settlement_context_digest_v1,
    X4dSettlementContextV1, X4D_MASKED_GROUP_CAP_V1, X4D_QUERY_COUNT_V1,
};
use super::folding_v4::{
    global_fold_descriptor_digest_v4, opened_global_value_from_lines_v4,
    verify_global_folding_interactive_v4, verify_global_folding_v4, FoldingErrorV4,
    GlobalChainDraftV4, GlobalFoldChallengesV4, GlobalFoldingProofV4, GlobalOpenMetricsV4,
    GlobalProverGroupV4, GlobalVerifierGroupV4, ModelGlobalOpeningSourceV4, MAX_RESPONSE_CLAIMS_V4,
};
use super::frame::{
    AuthenticatedOutputLinkFrame, Digest, FrameError, M9TransferFrame, ReducedClaimFrame,
    ResponseZeroBatchFrame,
};
use super::frame_v4::{authenticated_output_link_schedule_digest_v4, FrameV4, OracleKindV4};
use super::x4c_v4::{
    SealedGlobalChainX4cV4, X4cArenaRuntimeV4, X4cErrorV4, X4cResponseMetricsV4, X4cSealConfigV4,
    X4dLinkEqualityContributionV4, X4dResidentLinkCountersV4, X4dResidentLinkOutputV4,
    X4dResidentLinkTermV4,
};

pub const GLOBAL_FOLD_COHORT_ID_V4: u32 = 0xA500_F001;

/// Wall-only phase boundaries for the physical X4c seal/open path.
///
/// These values are record instrumentation only. They are not transcript
/// frames, protocol inputs, CUDA-event measurements or soundness evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4cAuthenticatedOutputPhaseWallsV4 {
    /// Validation, relation-coefficient construction, evaluation-table
    /// materialization and delayed sumcheck before the encoded oracle is read.
    pub claim_coefficient_preparation_wall_ns: u64,
    /// Public coefficient/challenge preparation and schedule validation.
    pub link_coefficient_challenge_wall_ns: u64,
    /// Combined link-equality generation and accumulation.
    pub combined_link_equality_wall_ns: u64,
    /// Source-table clone/copy while materializing delayed terms.
    pub link_source_clone_wall_ns: u64,
    /// Delayed-link product round-message evaluation.
    pub delayed_link_round_evaluation_wall_ns: u64,
    /// Delayed-link source/equality folds.
    pub delayed_link_fold_wall_ns: u64,
    /// Mask/transcript work plus terminal/group construction and the
    /// explicitly reconciled preparation residual.
    pub link_terminal_group_orchestration_wall_ns: u64,
    /// Initial coefficient/codeword reads and linear combination across all
    /// activated source groups.
    pub oracle_read_combine_wall_ns: u64,
    /// The remainder of the physical seal: resident folds, N4 construction
    /// and parity gathers.
    pub fold_merkle_wall_ns: u64,
    /// The one canonical post-seal opening/query gather.
    pub query_gather_wall_ns: u64,
    /// Historical aggregate fields retained for X4c record compatibility.
    pub seal_wall_ns: u64,
    pub open_wall_ns: u64,
}

/// Verifier-owned exact-bit query tape.
///
/// The draws are intentionally private and can be consumed only after an
/// X4c sealed state proves the expected `(model_root, epoch)` binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cSelectedQueryTapeV4 {
    draws: Vec<u64>,
}

const X4D_QUERY_SEED_COMMITMENT_CONTEXT_V1: &str =
    "volta-zk/x4d/settlement-query-seed-commitment/v1";
const X4D_QUERY_DRAW_CONTEXT_V1: &str = "volta-zk/x4d/settlement-query-draws/v1";

/// Verifier-owned X4d query seed. The commitment is durably burned before
/// challenges; the exact draws are derived only after every fold root exists.
#[derive(Debug)]
pub struct X4dSettlementQuerySeedV1 {
    seed: Digest,
    commitment: Digest,
}

impl X4dSettlementQuerySeedV1 {
    pub fn new(seed: Digest) -> Result<Self, AuthenticatedOutputErrorV4> {
        if seed == [0; 32] {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry("zero X4d query seed"));
        }
        let mut hasher = blake3::Hasher::new_derive_key(X4D_QUERY_SEED_COMMITMENT_CONTEXT_V1);
        hasher.update(&seed);
        Ok(Self { seed, commitment: *hasher.finalize().as_bytes() })
    }

    pub fn commitment(&self) -> Digest {
        self.commitment
    }

    fn release_after_roots<A>(
        self,
        sealed: &SealedGlobalChainX4cV4<'_, A>,
        context: &X4dSettlementContextV1,
        expected_model_root: Digest,
        expected_epoch: u64,
    ) -> Result<Vec<u64>, AuthenticatedOutputErrorV4> {
        if sealed.model_root() != expected_model_root
            || sealed.epoch() != expected_epoch
            || context.range.settlement_epoch != expected_epoch
        {
            return Err(AuthenticatedOutputErrorV4::EpochMismatch);
        }
        let draw_width = sealed
            .verifier_groups()
            .first()
            .ok_or(AuthenticatedOutputErrorV4::InvalidSchedule("empty X4d verifier groups"))?
            .commitment
            .config
            .outer_depth();
        if draw_width == 0 || draw_width > 63 {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry("X4d query width"));
        }
        let context_digest = x4d_settlement_context_digest_v1(context)
            .map_err(|_| AuthenticatedOutputErrorV4::InvalidSchedule("X4d context digest"))?;
        let mut hasher = blake3::Hasher::new_derive_key(X4D_QUERY_DRAW_CONTEXT_V1);
        hasher.update(&self.seed);
        hasher.update(&context_digest);
        hasher.update(&expected_model_root);
        hasher.update(&expected_epoch.to_le_bytes());
        for frame in sealed.fold_frames() {
            hasher.update(&frame.root_digest);
        }
        let mut reader = hasher.finalize_xof();
        let mask = (1u64 << draw_width) - 1;
        let mut draws = Vec::with_capacity(X4D_QUERY_COUNT_V1);
        for _ in 0..X4D_QUERY_COUNT_V1 {
            let mut bytes = [0u8; 8];
            reader.fill(&mut bytes);
            draws.push(u64::from_le_bytes(bytes) & mask);
        }
        Ok(draws)
    }
}

enum X4AcceleratedQuerySourceV4 {
    X4c(X4cSelectedQueryTapeV4),
    X4d(X4dSettlementQuerySeedV1),
}

impl X4cSelectedQueryTapeV4 {
    pub fn new(draws: Vec<u64>) -> Result<Self, AuthenticatedOutputErrorV4> {
        if draws.is_empty() {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "empty X4c selected query tape",
            ));
        }
        Ok(Self { draws })
    }

    pub fn draw_count(&self) -> usize {
        self.draws.len()
    }

    fn release_after_roots<A>(
        self,
        sealed: &SealedGlobalChainX4cV4<'_, A>,
        expected_model_root: Digest,
        expected_epoch: u64,
    ) -> Result<Vec<u64>, AuthenticatedOutputErrorV4> {
        if sealed.model_root() != expected_model_root || sealed.epoch() != expected_epoch {
            return Err(AuthenticatedOutputErrorV4::EpochMismatch);
        }
        Ok(self.draws)
    }
}

fn phase_wall_ns_v4(started: Instant) -> Result<u64, AuthenticatedOutputErrorV4> {
    u64::try_from(started.elapsed().as_nanos())
        .map(|value| value.max(1))
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticatedOutputErrorV4 {
    Frame(FrameError),
    Folding(FoldingErrorV4),
    X4c(X4cErrorV4),
    InvalidGeometry(&'static str),
    InvalidSchedule(&'static str),
    FalseInitialClaim,
    SumcheckTerminalMismatch,
    GlobalTerminalMismatch,
    TerminalMacMismatch,
    LinkRejected,
    ZeroBatchRejected,
    EpochAlreadyOpened,
    EpochMismatch,
    Overflow,
}

impl From<FrameError> for AuthenticatedOutputErrorV4 {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<FoldingErrorV4> for AuthenticatedOutputErrorV4 {
    fn from(value: FoldingErrorV4) -> Self {
        Self::Folding(value)
    }
}

impl From<X4cErrorV4> for AuthenticatedOutputErrorV4 {
    fn from(value: X4cErrorV4) -> Self {
        Self::X4c(value)
    }
}

#[derive(Debug)]
pub struct PendingAuxEvalProverV4 {
    descriptor_digest: Digest,
    auth: ProverAuthed,
}

#[derive(Debug)]
pub struct PendingAuxEvalVerifierV4 {
    descriptor_digest: Digest,
    key: VerifierKey,
}

/// Opaque prover value with a verified v4 PCS origin.
#[derive(Debug)]
pub struct BoundAuxEvalProverV4 {
    descriptor_digest: Digest,
    auth: ProverAuthed,
}

/// Opaque verifier value with a verified v4 PCS origin.
#[derive(Debug)]
pub struct BoundAuxEvalVerifierV4 {
    descriptor_digest: Digest,
    key: VerifierKey,
}

impl BoundAuxEvalProverV4 {
    pub fn descriptor_digest(&self) -> Digest {
        self.descriptor_digest
    }

    pub fn authenticated(&self) -> ProverAuthed {
        self.auth
    }
}

impl BoundAuxEvalVerifierV4 {
    pub fn descriptor_digest(&self) -> Digest {
        self.descriptor_digest
    }

    pub fn key(&self) -> VerifierKey {
        self.key
    }
}

pub fn authenticate_pending_aux_prover_v4(
    descriptor_digest: Digest,
    secret: Fp2,
    stream: &mut CorrelationStream,
    correlation_domain: u64,
    tx: &mut Transcript,
) -> Result<(PendingAuxEvalProverV4, M9TransferFrame), AuthenticatedOutputErrorV4> {
    let correlation = stream.draw_fulls(correlation_domain, 1)[0];
    let frame =
        M9TransferFrame { descriptor_digest, mask_correction_symbol: secret - correlation.x };
    tx.append(
        "x4_v4_m9_transfer_frame",
        u64::try_from(FrameV4::M9Transfer(frame.clone()).encode()?.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
    );
    Ok((
        PendingAuxEvalProverV4 {
            descriptor_digest,
            auth: ProverAuthed { x: secret, m: correlation.m },
        },
        frame,
    ))
}

pub fn authenticate_pending_aux_verifier_v4(
    frame: &M9TransferFrame,
    ctx: &mut VerifierCtx,
    correlation_domain: u64,
    tx: &mut Transcript,
) -> Result<PendingAuxEvalVerifierV4, AuthenticatedOutputErrorV4> {
    frame.validate()?;
    let key =
        ctx.expand_full_keys(correlation_domain, 1)[0] + ctx.delta * frame.mask_correction_symbol;
    tx.append(
        "x4_v4_m9_transfer_frame",
        u64::try_from(FrameV4::M9Transfer(frame.clone()).encode()?.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
    );
    Ok(PendingAuxEvalVerifierV4 {
        descriptor_digest: frame.descriptor_digest,
        key: VerifierKey { k: key },
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkCohortKeyV4 {
    pub domain_log2: u8,
    pub cohort_id: u32,
    pub oracle_kind: OracleKindV4,
    pub root: Digest,
}

impl LinkCohortKeyV4 {
    pub fn from_cohort(cohort: &dyn ModelGlobalOpeningSourceV4) -> Self {
        let commitment = cohort.commitment();
        Self {
            domain_log2: commitment.config.outer_depth(),
            cohort_id: commitment.config.identity.cohort_id,
            oracle_kind: commitment.config.identity.oracle_kind,
            root: commitment.root,
        }
    }
}

impl PartialOrd for LinkCohortKeyV4 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LinkCohortKeyV4 {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .domain_log2
            .cmp(&self.domain_log2)
            .then_with(|| self.cohort_id.cmp(&other.cohort_id))
            .then_with(|| self.oracle_kind.cmp(&other.oracle_kind))
            .then_with(|| self.root.cmp(&other.root))
    }
}

pub struct LinkPolynomialProverV4<'a> {
    pub cohort: &'a dyn ModelGlobalOpeningSourceV4,
    pub slot: u16,
    /// Boolean-hypercube evaluations; never serialized.
    pub evaluations: &'a [Fp2],
    pub target_point: &'a [Fp2],
}

pub struct LinkPolynomialVerifierV4<'a> {
    pub commitment: &'a super::folding_v4::ModelGlobalCohortCommitmentV4,
    pub slot: u16,
    pub target_point: &'a [Fp2],
}

pub struct AuthenticatedOutputBlockProverV4<'a> {
    pub descriptor_digest: Digest,
    pub public_h: Fp2,
    pub pending_aux: PendingAuxEvalProverV4,
    pub weight_extension: LinkPolynomialProverV4<'a>,
    pub auxiliary: LinkPolynomialProverV4<'a>,
}

pub struct AuthenticatedOutputBlockVerifierV4<'a> {
    pub descriptor_digest: Digest,
    pub public_h: Fp2,
    pub pending_aux: PendingAuxEvalVerifierV4,
    pub weight_extension: LinkPolynomialVerifierV4<'a>,
    pub auxiliary: LinkPolynomialVerifierV4<'a>,
}

#[derive(Clone, Copy)]
pub struct AuthenticatedOutputLinkPrefixV4<'a> {
    pub epoch: u64,
    pub claim_frames: &'a [ReducedClaimFrame],
    pub descriptor_digests: &'a [Digest],
    pub ordered_h_symbols: &'a [Fp2],
    pub m9_frames: &'a [M9TransferFrame],
    pub round_correlation_domain_ids: &'a [u64],
}

#[derive(Default)]
pub struct X4OpeningRegistryV4 {
    opened: BTreeSet<(Digest, u64)>,
}

pub struct X4OpeningPermitV4 {
    model_root: Digest,
    epoch: u64,
    persistent_freshness_record_digest: Option<Digest>,
}

impl X4OpeningRegistryV4 {
    pub fn authorize(
        &mut self,
        model_root: Digest,
        epoch: u64,
    ) -> Result<X4OpeningPermitV4, AuthenticatedOutputErrorV4> {
        if !self.opened.insert((model_root, epoch)) {
            return Err(AuthenticatedOutputErrorV4::EpochAlreadyOpened);
        }
        Ok(X4OpeningPermitV4 { model_root, epoch, persistent_freshness_record_digest: None })
    }

    /// Authorize an opening only after the caller has durably burned the X4
    /// `(model_root, epoch)`, challenge seed, and real-PCG authorization.
    /// The nonzero digest is the persisted burn receipt; production E2E
    /// drivers must use this entry point rather than [`Self::authorize`].
    pub fn authorize_after_persistent_freshness(
        &mut self,
        model_root: Digest,
        epoch: u64,
        freshness_record_digest: Digest,
    ) -> Result<X4OpeningPermitV4, AuthenticatedOutputErrorV4> {
        if freshness_record_digest == [0; 32] {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "persistent X4 freshness receipt",
            ));
        }
        if !self.opened.insert((model_root, epoch)) {
            return Err(AuthenticatedOutputErrorV4::EpochAlreadyOpened);
        }
        Ok(X4OpeningPermitV4 {
            model_root,
            epoch,
            persistent_freshness_record_digest: Some(freshness_record_digest),
        })
    }

    pub fn has_opened(&self, model_root: Digest, epoch: u64) -> bool {
        self.opened.contains(&(model_root, epoch))
    }
}

impl X4OpeningPermitV4 {
    pub fn model_root(&self) -> Digest {
        self.model_root
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn persistent_freshness_record_digest(&self) -> Option<Digest> {
        self.persistent_freshness_record_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedOutputLinkProofV4 {
    pub frame: AuthenticatedOutputLinkFrame,
    pub global_folding: GlobalFoldingProofV4,
}

impl AuthenticatedOutputLinkProofV4 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedOutputErrorV4> {
        let mut bytes = FrameV4::AuthenticatedOutputLink(self.frame.clone()).encode()?;
        bytes.extend(self.global_folding.canonical_bytes()?);
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticatedOutputLinkMetricsV4 {
    pub touched_blocks: u64,
    pub relation_count: u64,
    pub round_count: u64,
    pub m9_full_correlations: u64,
    pub link_round_full_correlations: u64,
    pub seam_full_correlations_with_response_zero: u64,
    pub m9_frame_bytes: u64,
    pub link_frame_bytes: u64,
    pub response_zero_batch_frame_bytes: u64,
    pub seam_frame_bytes: u64,
    pub fold_bytes: u64,
    pub packed_opening_bytes: u64,
    /// Protocol relation terms before any implementation-only linear fusion.
    pub sumcheck_relation_terms: u64,
    /// Physical delayed-sumcheck terms materialized by the prover driver.
    pub sumcheck_materialized_terms: u64,
    /// Response-local terms eliminated by settlement-only early fusion.
    pub sumcheck_fused_terms: u64,
    /// Source-table symbols cloned into materialized terms. This is an actual
    /// driver pass counter, not the logical protocol relation count.
    pub sumcheck_source_symbols_read: u64,
    /// Equality-table symbols retained by the materialized terms.
    pub sumcheck_equality_symbols_materialized: u64,
    pub resident_link_host_bytes: u64,
    pub resident_link_device_bytes: u64,
    pub resident_link_h2d_bytes: u64,
    pub resident_link_source_clone_bytes: u64,
    pub resident_link_d2h_bytes: u64,
    pub resident_link_d2d_bytes: u64,
    pub resident_link_protocol_scalar_d2h_bytes: u64,
    pub resident_link_kernel_calls: u64,
    pub resident_link_allocation_requests: u64,
    pub resident_link_buffer_reuse_hits: u64,
    pub resident_link_peak_live_host_scratch_bytes: u64,
    pub resident_link_peak_live_scratch_bytes: u64,
    pub source_coefficients_read: u64,
    pub encoded_symbols_read: u64,
    pub combined_coefficient_symbols: u64,
    pub combined_codeword_symbols: u64,
    pub folded_symbols_written: u64,
    pub aggregate_merkle_symbols_written: u64,
    pub aggregate_merkle_digests_written: u64,
    pub recomputed_source_bytes_read: u64,
    pub recomputed_oracle_bytes: u64,
    pub recomputed_merkle_bytes: u64,
}

pub fn x4_v4_seam_full_correlations(
    touched_blocks: usize,
    rounds: usize,
) -> Result<u64, AuthenticatedOutputErrorV4> {
    if touched_blocks == 0 || touched_blocks > 1660 || rounds == 0 || rounds > 30 {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 seam correlations"));
    }
    u64::try_from(
        touched_blocks
            .checked_add(2usize.checked_mul(rounds).ok_or(AuthenticatedOutputErrorV4::Overflow)?)
            .and_then(|value| value.checked_add(1))
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?,
    )
    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)
}

pub fn x4_v4_seam_frame_bytes(
    touched_blocks: usize,
    rounds: usize,
) -> Result<u64, AuthenticatedOutputErrorV4> {
    if touched_blocks == 0 || touched_blocks > 1660 || rounds == 0 || rounds > 30 {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 seam frame bytes"));
    }
    let m9 = 64usize.checked_mul(touched_blocks).ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let round_bytes = 32usize.checked_mul(rounds).ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    u64::try_from(
        m9.checked_add(119)
            .and_then(|value| value.checked_add(round_bytes))
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?,
    )
    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)
}

#[derive(Clone)]
struct DelayedSumcheckTermV4 {
    coefficient: Fp2,
    evaluations: Vec<Fp2>,
    equality: Vec<Fp2>,
    leading_virtual_rounds: usize,
    virtual_factor: Fp2,
}

impl DelayedSumcheckTermV4 {
    fn new(
        coefficient: Fp2,
        evaluations: &[Fp2],
        target_point: &[Fp2],
        global_rounds: usize,
    ) -> Result<Self, AuthenticatedOutputErrorV4> {
        if target_point.is_empty()
            || target_point.len() > global_rounds
            || evaluations.len() != 1usize.checked_shl(target_point.len() as u32).unwrap_or(0)
        {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link polynomial table"));
        }
        Ok(Self {
            coefficient,
            evaluations: evaluations.to_vec(),
            equality: eq_vec(target_point),
            leading_virtual_rounds: global_rounds - target_point.len(),
            virtual_factor: Fp2::ONE,
        })
    }

    fn active_sum(&self) -> Fp2 {
        self.evaluations.iter().zip(&self.equality).fold(Fp2::ZERO, |sum, (value, eq)| {
            sum + self.coefficient * *value * *eq * self.virtual_factor
        })
    }

    fn initial_sum(&self) -> Fp2 {
        self.active_sum()
    }

    fn round_values(&self) -> Result<(Fp2, Fp2), AuthenticatedOutputErrorV4> {
        if self.evaluations.len() != self.equality.len() || self.evaluations.is_empty() {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link sumcheck state"));
        }
        if self.leading_virtual_rounds > 0 {
            let at_zero = self.active_sum();
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        if self.evaluations.len() == 1 {
            let at_zero =
                self.coefficient * self.evaluations[0] * self.equality[0] * self.virtual_factor;
            return Ok((at_zero, Fp2::ZERO - at_zero));
        }
        let mut at_zero = Fp2::ZERO;
        let mut at_two = Fp2::ZERO;
        for (values, equality) in
            self.evaluations.chunks_exact(2).zip(self.equality.chunks_exact(2))
        {
            let value_two = values[0] + (values[1] - values[0]) + (values[1] - values[0]);
            let equality_two =
                equality[0] + (equality[1] - equality[0]) + (equality[1] - equality[0]);
            at_zero += self.coefficient * values[0] * equality[0] * self.virtual_factor;
            at_two += self.coefficient * value_two * equality_two * self.virtual_factor;
        }
        Ok((at_zero, at_two))
    }

    fn bind(&mut self, challenge: Fp2) {
        if self.leading_virtual_rounds > 0 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
            self.leading_virtual_rounds -= 1;
        } else if self.evaluations.len() == 1 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
        } else {
            fold_low(&mut self.evaluations, challenge);
            fold_low(&mut self.equality, challenge);
        }
    }

    fn terminal(&self) -> Result<Fp2, AuthenticatedOutputErrorV4> {
        if self.leading_virtual_rounds != 0
            || self.evaluations.len() != 1
            || self.equality.len() != 1
        {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link terminal state"));
        }
        Ok(self.coefficient * self.evaluations[0] * self.equality[0] * self.virtual_factor)
    }

    fn from_fused_equality(
        evaluations: &[Fp2],
        equality: Vec<Fp2>,
        dimension: usize,
        global_rounds: usize,
    ) -> Result<Self, AuthenticatedOutputErrorV4> {
        if dimension == 0
            || dimension > global_rounds
            || evaluations.len() != equality.len()
            || evaluations.len() != 1usize.checked_shl(dimension as u32).unwrap_or(0)
        {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "X4d fused link polynomial table",
            ));
        }
        Ok(Self {
            coefficient: Fp2::ONE,
            evaluations: evaluations.to_vec(),
            equality,
            leading_virtual_rounds: global_rounds - dimension,
            virtual_factor: Fp2::ONE,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FusedSettlementTermKeyV4 {
    cohort: LinkCohortKeyV4,
    slot: u16,
}

struct FusedSettlementTermAccumulatorV4<'a> {
    evaluations: &'a [Fp2],
    contributions: Vec<X4dLinkEqualityContributionV4>,
    dimension: usize,
}

fn accumulate_fused_settlement_term_v4<'a>(
    terms: &mut BTreeMap<FusedSettlementTermKeyV4, FusedSettlementTermAccumulatorV4<'a>>,
    polynomial: &LinkPolynomialProverV4<'a>,
    coefficient: Fp2,
) -> Result<(), AuthenticatedOutputErrorV4> {
    let key = FusedSettlementTermKeyV4 {
        cohort: LinkCohortKeyV4::from_cohort(polynomial.cohort),
        slot: polynomial.slot,
    };
    let contribution =
        X4dLinkEqualityContributionV4 { coefficient, point: polynomial.target_point.to_vec() };
    match terms.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(FusedSettlementTermAccumulatorV4 {
                evaluations: polynomial.evaluations,
                contributions: vec![contribution],
                dimension: polynomial.target_point.len(),
            });
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let accumulator = entry.get_mut();
            if accumulator.dimension != polynomial.target_point.len()
                || accumulator.evaluations.len() != polynomial.evaluations.len()
                || !std::ptr::eq(accumulator.evaluations.as_ptr(), polynomial.evaluations.as_ptr())
            {
                return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                    "X4d fused link source alias",
                ));
            }
            accumulator.contributions.push(contribution);
        }
    }
    Ok(())
}

struct MaterializedDelayedTermsV4 {
    terms: Vec<DelayedSumcheckTermV4>,
    source_symbols_read: u64,
    equality_symbols_materialized: u64,
    source_clone_wall_ns: u64,
    equality_generation_wall_ns: u64,
}

fn materialize_fused_settlement_terms_v4(
    terms: BTreeMap<FusedSettlementTermKeyV4, FusedSettlementTermAccumulatorV4<'_>>,
    global_rounds: usize,
) -> Result<MaterializedDelayedTermsV4, AuthenticatedOutputErrorV4> {
    let mut source_symbols_read = 0u64;
    let mut equality_symbols_materialized = 0u64;
    let mut materialized = Vec::with_capacity(terms.len());
    let mut source_clone_wall_ns = 0u64;
    let mut equality_generation_wall_ns = 0u64;
    for (_, term) in terms {
        source_symbols_read = source_symbols_read
            .checked_add(
                u64::try_from(term.evaluations.len())
                    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
            )
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        equality_symbols_materialized = equality_symbols_materialized
            .checked_add(
                u64::try_from(term.evaluations.len())
                    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
            )
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let equality_started = Instant::now();
        let mut equality = vec![Fp2::ZERO; term.evaluations.len()];
        for contribution in term.contributions {
            let values = eq_vec(&contribution.point);
            for (combined, value) in equality.iter_mut().zip(values) {
                *combined += contribution.coefficient * value;
            }
        }
        equality_generation_wall_ns = equality_generation_wall_ns
            .checked_add(phase_wall_ns_v4(equality_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let clone_started = Instant::now();
        materialized.push(DelayedSumcheckTermV4::from_fused_equality(
            term.evaluations,
            equality,
            term.dimension,
            global_rounds,
        )?);
        source_clone_wall_ns = source_clone_wall_ns
            .checked_add(phase_wall_ns_v4(clone_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    }
    Ok(MaterializedDelayedTermsV4 {
        terms: materialized,
        source_symbols_read,
        equality_symbols_materialized,
        source_clone_wall_ns,
        equality_generation_wall_ns,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DelayedSumcheckPhaseWallsV4 {
    round_evaluation_wall_ns: u64,
    fold_wall_ns: u64,
    masks_transcript_terminal_wall_ns: u64,
}

struct SumcheckProverOutputV4 {
    corrections: Vec<Fp2>,
    point: Vec<Fp2>,
    final_claim: ProverAuthed,
    terminal_value: Fp2,
    phase_walls: DelayedSumcheckPhaseWallsV4,
}

fn prove_delayed_sumcheck_v4(
    mut terms: Vec<DelayedSumcheckTermV4>,
    round_count: usize,
    initial_claim: ProverAuthed,
    stream: &mut CorrelationStream,
    domains: &[u64],
    tx: &mut Transcript,
) -> Result<SumcheckProverOutputV4, AuthenticatedOutputErrorV4> {
    if round_count == 0 || round_count > 30 || domains.len() != 2 * round_count {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link round schedule"));
    }
    if terms.iter().fold(Fp2::ZERO, |sum, term| sum + term.initial_sum()) != initial_claim.x {
        return Err(AuthenticatedOutputErrorV4::FalseInitialClaim);
    }
    let mut claim = initial_claim;
    let mut corrections = Vec::with_capacity(2 * round_count);
    let mut point = Vec::with_capacity(round_count);
    let sumcheck_started = Instant::now();
    let mut phase_walls = DelayedSumcheckPhaseWallsV4::default();
    for round in 0..round_count {
        let round_started = Instant::now();
        let mut at_zero = Fp2::ZERO;
        let mut at_two = Fp2::ZERO;
        for term in &terms {
            let (term_zero, term_two) = term.round_values()?;
            at_zero += term_zero;
            at_two += term_two;
        }
        phase_walls.round_evaluation_wall_ns = phase_walls
            .round_evaluation_wall_ns
            .checked_add(phase_wall_ns_v4(round_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let orchestration_started = Instant::now();
        let mask_zero = stream.draw_fulls(domains[2 * round], 1)[0];
        let mask_two = stream.draw_fulls(domains[2 * round + 1], 1)[0];
        corrections.push(at_zero - mask_zero.x);
        corrections.push(at_two - mask_two.x);
        tx.append("x4_v4_auth_output_link_round_corrections", 32);
        let auth_zero = ProverAuthed { x: at_zero, m: mask_zero.m };
        let auth_two = ProverAuthed { x: at_two, m: mask_two.m };
        let auth_one = claim.sub(auth_zero);
        let challenge = tx.challenge_fp2();
        let weights = lagrange3(challenge);
        claim = auth_zero
            .scale(weights[0])
            .add(auth_one.scale(weights[1]))
            .add(auth_two.scale(weights[2]));
        phase_walls.masks_transcript_terminal_wall_ns = phase_walls
            .masks_transcript_terminal_wall_ns
            .checked_add(phase_wall_ns_v4(orchestration_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let fold_started = Instant::now();
        for term in &mut terms {
            term.bind(challenge);
        }
        phase_walls.fold_wall_ns = phase_walls
            .fold_wall_ns
            .checked_add(phase_wall_ns_v4(fold_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        point.push(challenge);
    }
    let terminal_started = Instant::now();
    let terminal_value = terms.iter().try_fold(Fp2::ZERO, |sum, term| {
        Ok::<_, AuthenticatedOutputErrorV4>(sum + term.terminal()?)
    })?;
    if terminal_value != claim.x {
        return Err(AuthenticatedOutputErrorV4::SumcheckTerminalMismatch);
    }
    phase_walls.masks_transcript_terminal_wall_ns = phase_walls
        .masks_transcript_terminal_wall_ns
        .checked_add(phase_wall_ns_v4(terminal_started)?)
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let children = phase_walls
        .round_evaluation_wall_ns
        .checked_add(phase_walls.fold_wall_ns)
        .and_then(|value| value.checked_add(phase_walls.masks_transcript_terminal_wall_ns))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let total = phase_wall_ns_v4(sumcheck_started)?;
    phase_walls.masks_transcript_terminal_wall_ns = phase_walls
        .masks_transcript_terminal_wall_ns
        .checked_add(total.saturating_sub(children))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    Ok(SumcheckProverOutputV4 {
        corrections,
        point,
        final_claim: claim,
        terminal_value,
        phase_walls,
    })
}

/// CPU implementation of the resident delayed-link operation contract.
///
/// This deliberately enters the same `Some(resident)` orchestration branch
/// as CUDA while retaining the existing CPU sumcheck as its byte oracle.
/// It is used by permanent local tests; all device traffic remains zero.
pub(crate) fn prove_x4d_delayed_link_cpu_resident_v4(
    terms: &[X4dResidentLinkTermV4<'_>],
    round_count: usize,
    initial_claim: ProverAuthed,
    stream: &mut CorrelationStream,
    domains: &[u64],
    tx: &mut Transcript,
) -> Result<X4dResidentLinkOutputV4, AuthenticatedOutputErrorV4> {
    if terms.is_empty()
        || round_count == 0
        || round_count > 30
        || domains.len() != 2 * round_count
        || terms.iter().any(|term| {
            term.dimension == 0
                || term.dimension > round_count
                || term.evaluations.len() != 1usize << term.dimension
                || term.contributions.is_empty()
                || term
                    .contributions
                    .iter()
                    .any(|contribution| contribution.point.len() != term.dimension)
        })
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
            "X4d CPU resident delayed-link geometry",
        ));
    }
    let mut counters =
        X4dResidentLinkCountersV4 { unique_terms: terms.len() as u64, ..Default::default() };
    let mut materialized = Vec::with_capacity(terms.len());
    let mut equality_generation_wall_ns = 0u64;
    let mut source_copy_wall_ns = 0u64;
    for term in terms {
        let equality_started = Instant::now();
        let mut equality = vec![Fp2::ZERO; term.evaluations.len()];
        for contribution in &term.contributions {
            for (combined, value) in equality.iter_mut().zip(eq_vec(&contribution.point)) {
                *combined += contribution.coefficient * value;
            }
        }
        equality_generation_wall_ns = equality_generation_wall_ns
            .checked_add(phase_wall_ns_v4(equality_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let copy_started = Instant::now();
        materialized.push(DelayedSumcheckTermV4::from_fused_equality(
            term.evaluations,
            equality,
            term.dimension,
            round_count,
        )?);
        source_copy_wall_ns = source_copy_wall_ns
            .checked_add(phase_wall_ns_v4(copy_started)?)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        let symbols = u64::try_from(term.evaluations.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
        counters.source_symbols = counters
            .source_symbols
            .checked_add(symbols)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        counters.equality_symbols = counters
            .equality_symbols
            .checked_add(symbols)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        counters.allocation_requests = counters
            .allocation_requests
            .checked_add(2)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    }
    counters.host_bytes = counters
        .source_symbols
        .checked_add(counters.equality_symbols)
        .and_then(|symbols| symbols.checked_mul(16))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    counters.source_clone_bytes =
        counters.source_symbols.checked_mul(16).ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    counters.peak_live_host_scratch_bytes = counters.host_bytes;
    let sumcheck =
        prove_delayed_sumcheck_v4(materialized, round_count, initial_claim, stream, domains, tx)?;
    Ok(X4dResidentLinkOutputV4 {
        corrections: sumcheck.corrections,
        point: sumcheck.point,
        final_claim: sumcheck.final_claim,
        terminal_value: sumcheck.terminal_value,
        equality_generation_wall_ns,
        source_copy_wall_ns,
        round_evaluation_wall_ns: sumcheck.phase_walls.round_evaluation_wall_ns,
        fold_wall_ns: sumcheck.phase_walls.fold_wall_ns,
        masks_transcript_terminal_wall_ns: sumcheck.phase_walls.masks_transcript_terminal_wall_ns,
        counters,
    })
}

fn verify_delayed_sumcheck_v4(
    round_count: usize,
    initial_key: VerifierKey,
    corrections: &[Fp2],
    ctx: &mut VerifierCtx,
    domains: &[u64],
    tx: &mut Transcript,
) -> Result<(Vec<Fp2>, VerifierKey), AuthenticatedOutputErrorV4> {
    if round_count == 0
        || round_count > 30
        || corrections.len() != 2 * round_count
        || domains.len() != 2 * round_count
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link verifier rounds"));
    }
    let mut claim = initial_key;
    let mut point = Vec::with_capacity(round_count);
    for round in 0..round_count {
        let key_zero =
            ctx.expand_full_keys(domains[2 * round], 1)[0] + ctx.delta * corrections[2 * round];
        let key_two = ctx.expand_full_keys(domains[2 * round + 1], 1)[0]
            + ctx.delta * corrections[2 * round + 1];
        tx.append("x4_v4_auth_output_link_round_corrections", 32);
        let auth_zero = VerifierKey { k: key_zero };
        let auth_two = VerifierKey { k: key_two };
        let auth_one = claim.sub(auth_zero);
        let challenge = tx.challenge_fp2();
        let weights = lagrange3(challenge);
        claim = auth_zero
            .scale(weights[0])
            .add(auth_one.scale(weights[1]))
            .add(auth_two.scale(weights[2]));
        point.push(challenge);
    }
    Ok((point, claim))
}

fn validate_domains_v4(
    domains: &[u64],
    round_count: usize,
) -> Result<(), AuthenticatedOutputErrorV4> {
    if domains.len() != 2 * round_count || !domains.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link correlation domains"));
    }
    Ok(())
}

fn validate_canonical_points_v4(weight: &[Fp2], auxiliary: &[Fp2]) -> bool {
    if weight.len() < 2 || auxiliary.is_empty() || auxiliary.len() > weight.len() {
        return false;
    }
    if *weight.last().unwrap() != Fp2::ZERO || *auxiliary.last().unwrap() != Fp2::ZERO {
        return false;
    }
    let z = &weight[..weight.len() - 1];
    let suffix_len = auxiliary.len() - 1;
    auxiliary[..suffix_len] == z[z.len() - suffix_len..]
}

fn validate_prover_polynomial_v4(
    descriptor: Digest,
    expected_kind: OracleKindV4,
    polynomial: &LinkPolynomialProverV4<'_>,
) -> Result<(), AuthenticatedOutputErrorV4> {
    let commitment = polynomial.cohort.commitment();
    if commitment.config.identity.oracle_kind != expected_kind
        || commitment.config.identity.fold_round != 0
        || commitment.config.slot_descriptors.get(usize::from(polynomial.slot)).copied().flatten()
            != Some(descriptor)
        || commitment.config.outer_len / 8 != polynomial.evaluations.len()
        || polynomial.evaluations.len()
            != 1usize.checked_shl(polynomial.target_point.len() as u32).unwrap_or(0)
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link prover polynomial"));
    }
    Ok(())
}

fn validate_verifier_polynomial_v4(
    descriptor: Digest,
    expected_kind: OracleKindV4,
    polynomial: &LinkPolynomialVerifierV4<'_>,
) -> Result<(), AuthenticatedOutputErrorV4> {
    let commitment = polynomial.commitment;
    if commitment.config.identity.oracle_kind != expected_kind
        || commitment.config.identity.fold_round != 0
        || commitment.config.slot_descriptors.get(usize::from(polynomial.slot)).copied().flatten()
            != Some(descriptor)
        || commitment.config.outer_len / 8
            != 1usize.checked_shl(polynomial.target_point.len() as u32).unwrap_or(0)
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link verifier polynomial"));
    }
    Ok(())
}

fn validate_prefix_common_v4(
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    relation_descriptors: &[Digest],
    public_h: &[Fp2],
    round_count: usize,
    settlement_context: Option<&X4dSettlementContextV1>,
) -> Result<Digest, AuthenticatedOutputErrorV4> {
    if relation_descriptors.is_empty()
        || relation_descriptors.len() > X4D_MASKED_GROUP_CAP_V1
        || prefix.ordered_h_symbols != public_h
        || prefix.m9_frames.len() != relation_descriptors.len()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 authenticated-output prefix"));
    }
    for (descriptor, frame) in relation_descriptors.iter().zip(prefix.m9_frames) {
        if descriptor != &frame.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 M9 descriptor order"));
        }
    }
    if prefix.claim_frames.len() > MAX_RESPONSE_CLAIMS_V4 {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link reduced claims"));
    }
    validate_domains_v4(prefix.round_correlation_domain_ids, round_count)?;
    let round_count =
        u8::try_from(round_count).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
    match settlement_context {
        None => {
            if prefix.descriptor_digests != relation_descriptors
                || relation_descriptors.iter().copied().collect::<BTreeSet<_>>().len()
                    != relation_descriptors.len()
                || prefix
                    .claim_frames
                    .iter()
                    .any(|claim| !relation_descriptors.contains(&claim.descriptor_digest))
            {
                return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                    "v4 response descriptor inventory",
                ));
            }
            Ok(authenticated_output_link_schedule_digest_v4(
                prefix.epoch,
                prefix.claim_frames,
                prefix.descriptor_digests,
                prefix.ordered_h_symbols,
                prefix.m9_frames,
                round_count,
                prefix.round_correlation_domain_ids,
            )?)
        }
        Some(context) => {
            let inventory = prefix.descriptor_digests.iter().copied().collect::<BTreeSet<_>>();
            if prefix.epoch != context.range.settlement_epoch
                || prefix.claim_frames.len()
                    != usize::try_from(context.range.claim_count)
                        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?
                || prefix.descriptor_digests.is_empty()
                || inventory.len() != prefix.descriptor_digests.len()
                || relation_descriptors.iter().any(|descriptor| !inventory.contains(descriptor))
                || prefix
                    .claim_frames
                    .iter()
                    .any(|claim| !inventory.contains(&claim.descriptor_digest))
            {
                return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                    "X4d settlement descriptor inventory",
                ));
            }
            authenticated_output_link_schedule_digest_x4d_v1(
                context,
                prefix.claim_frames,
                prefix.descriptor_digests,
                prefix.ordered_h_symbols,
                prefix.m9_frames,
                round_count,
                prefix.round_correlation_domain_ids,
            )
            .map_err(|_| {
                AuthenticatedOutputErrorV4::InvalidSchedule("X4d settlement link schedule")
            })
        }
    }
}

fn terminal_weight_v4(base: Fp2, target: &[Fp2], common: &[Fp2]) -> Fp2 {
    let leading = common.len() - target.len();
    let virtual_factor = common[..leading]
        .iter()
        .fold(Fp2::ONE, |product, challenge| product * (Fp2::ONE - *challenge));
    base * virtual_factor * eq_points(target, &common[leading..])
}

struct ProverGroupV4<'a> {
    cohort: &'a dyn ModelGlobalOpeningSourceV4,
    dimension: usize,
    weights: BTreeMap<u16, Fp2>,
}

fn insert_prover_group_v4<'a>(
    groups: &mut BTreeMap<LinkCohortKeyV4, ProverGroupV4<'a>>,
    polynomial: &'a LinkPolynomialProverV4<'a>,
    weight: Fp2,
    accumulate_duplicate_slot: bool,
) -> Result<(), AuthenticatedOutputErrorV4> {
    let key = LinkCohortKeyV4::from_cohort(polynomial.cohort);
    let entry = groups.entry(key).or_insert_with(|| ProverGroupV4 {
        cohort: polynomial.cohort,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.cohort.commitment().root != polynomial.cohort.commitment().root
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link prover cohort grouping"));
    }
    match entry.weights.entry(polynomial.slot) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(weight);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) if accumulate_duplicate_slot => {
            *slot.get_mut() += weight;
        }
        std::collections::btree_map::Entry::Occupied(_) => {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 link prover cohort grouping",
            ))
        }
    }
    Ok(())
}

struct VerifierGroupV4<'a> {
    commitment: &'a super::folding_v4::ModelGlobalCohortCommitmentV4,
    dimension: usize,
    weights: BTreeMap<u16, Fp2>,
}

fn verifier_key_v4(polynomial: &LinkPolynomialVerifierV4<'_>) -> LinkCohortKeyV4 {
    LinkCohortKeyV4 {
        domain_log2: polynomial.commitment.config.outer_depth(),
        cohort_id: polynomial.commitment.config.identity.cohort_id,
        oracle_kind: polynomial.commitment.config.identity.oracle_kind,
        root: polynomial.commitment.root,
    }
}

fn insert_verifier_group_v4<'a>(
    groups: &mut BTreeMap<LinkCohortKeyV4, VerifierGroupV4<'a>>,
    polynomial: &'a LinkPolynomialVerifierV4<'a>,
    weight: Fp2,
    accumulate_duplicate_slot: bool,
) -> Result<(), AuthenticatedOutputErrorV4> {
    let key = verifier_key_v4(polynomial);
    let entry = groups.entry(key).or_insert_with(|| VerifierGroupV4 {
        commitment: polynomial.commitment,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.commitment.root != polynomial.commitment.root
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
            "v4 link verifier cohort grouping",
        ));
    }
    match entry.weights.entry(polynomial.slot) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert(weight);
        }
        std::collections::btree_map::Entry::Occupied(mut slot) if accumulate_duplicate_slot => {
            *slot.get_mut() += weight;
        }
        std::collections::btree_map::Entry::Occupied(_) => {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 link verifier cohort grouping",
            ))
        }
    }
    Ok(())
}

fn prover_keys_v4(blocks: &[AuthenticatedOutputBlockProverV4<'_>]) -> BTreeSet<LinkCohortKeyV4> {
    blocks
        .iter()
        .flat_map(|block| {
            [
                LinkCohortKeyV4::from_cohort(block.weight_extension.cohort),
                LinkCohortKeyV4::from_cohort(block.auxiliary.cohort),
            ]
        })
        .collect()
}

fn verifier_keys_v4(
    blocks: &[AuthenticatedOutputBlockVerifierV4<'_>],
) -> BTreeSet<LinkCohortKeyV4> {
    blocks
        .iter()
        .flat_map(|block| {
            [verifier_key_v4(&block.weight_extension), verifier_key_v4(&block.auxiliary)]
        })
        .collect()
}

fn activation_challenges_v4(
    keys: &BTreeSet<LinkCohortKeyV4>,
    tx: &mut Transcript,
) -> BTreeMap<LinkCohortKeyV4, Fp2> {
    keys.iter().cloned().map(|key| (key, tx.challenge_fp2())).collect()
}

fn accumulate_global_metrics_v4(
    metrics: &mut AuthenticatedOutputLinkMetricsV4,
    opened: &GlobalOpenMetricsV4,
) {
    metrics.fold_bytes = opened.serialized_fold_bytes;
    metrics.packed_opening_bytes = opened.serialized_packed_opening_bytes;
    metrics.source_coefficients_read = opened.source_coefficients_read;
    metrics.encoded_symbols_read = opened.initial_encoded_symbols_read;
    metrics.combined_coefficient_symbols = opened.combined_coefficient_symbols;
    metrics.combined_codeword_symbols = opened.combined_codeword_symbols;
    metrics.folded_symbols_written = opened.folded_symbols_written;
    metrics.aggregate_merkle_symbols_written = opened.aggregate_merkle_symbols_written;
    metrics.aggregate_merkle_digests_written = opened.aggregate_merkle_digests_written;
    metrics.recomputed_source_bytes_read = opened.recomputed_source_bytes_read;
    metrics.recomputed_oracle_bytes = opened.recomputed_oracle_bytes;
    metrics.recomputed_merkle_bytes = opened.recomputed_merkle_bytes;
}

#[allow(clippy::too_many_arguments)]
pub fn prove_authenticated_output_link_v4(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockProverV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> Result<
    (AuthenticatedOutputLinkProofV4, Vec<BoundAuxEvalProverV4>, AuthenticatedOutputLinkMetricsV4),
    AuthenticatedOutputErrorV4,
> {
    if permit.model_root != model_root || permit.epoch != prefix.epoch {
        return Err(AuthenticatedOutputErrorV4::EpochMismatch);
    }
    let descriptors = blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let public_h = blocks.iter().map(|block| block.public_h).collect::<Vec<_>>();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 pending prover descriptor",
            ));
        }
        validate_prover_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::WeightExtension,
            &block.weight_extension,
        )?;
        validate_prover_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points_v4(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "v4 canonical auxiliary point",
            ));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    if round_count == 0 || round_count > 30 {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link maximum dimension"));
    }
    let schedule_digest =
        validate_prefix_common_v4(prefix, &descriptors, &public_h, round_count, None)?;
    let accumulate_duplicate_slots = false;
    let keys = prover_keys_v4(&blocks);

    // All roots, h values and M9 corrections are fixed before this vector of
    // verifier challenges.  Cohort activations and relation atoms share the
    // same coefficients, so the final MAC claim and global chain are one
    // linear functional rather than two independently shiftable promises.
    let beta = tx.challenge_fp2();
    let activation = activation_challenges_v4(&keys, tx);
    let mut power = beta;
    let mut initial_claim = ProverAuthed::ZERO;
    let mut response_local_terms = Vec::with_capacity(2 * blocks.len());
    let mut fused_settlement_terms = BTreeMap::new();
    let mut bases = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let weight_key = LinkCohortKeyV4::from_cohort(block.weight_extension.cohort);
        let auxiliary_key = LinkCohortKeyV4::from_cohort(block.auxiliary.cohort);
        let weight_base = power;
        let auxiliary_base = weight_base * beta;
        let masked_coefficient = activation[&weight_key] * weight_base;
        let auxiliary_coefficient = activation[&auxiliary_key] * auxiliary_base;
        let output_coefficient = auxiliary_coefficient - masked_coefficient;
        initial_claim = initial_claim
            .add(ProverAuthed::from_public(block.public_h).scale(masked_coefficient))
            .add(block.pending_aux.auth.scale(output_coefficient));
        if accumulate_duplicate_slots {
            accumulate_fused_settlement_term_v4(
                &mut fused_settlement_terms,
                &block.weight_extension,
                masked_coefficient,
            )?;
            accumulate_fused_settlement_term_v4(
                &mut fused_settlement_terms,
                &block.auxiliary,
                auxiliary_coefficient,
            )?;
        } else {
            response_local_terms.push(DelayedSumcheckTermV4::new(
                masked_coefficient,
                block.weight_extension.evaluations,
                block.weight_extension.target_point,
                round_count,
            )?);
            response_local_terms.push(DelayedSumcheckTermV4::new(
                auxiliary_coefficient,
                block.auxiliary.evaluations,
                block.auxiliary.target_point,
                round_count,
            )?);
        }
        bases.push((weight_base, auxiliary_base));
        power = auxiliary_base * beta;
    }
    let relation_terms =
        u64::try_from(2 * blocks.len()).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
    let materialized = if accumulate_duplicate_slots {
        materialize_fused_settlement_terms_v4(fused_settlement_terms, round_count)?
    } else {
        let response_source_symbols = response_local_terms.iter().try_fold(0u64, |sum, term| {
            sum.checked_add(
                u64::try_from(term.evaluations.len())
                    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
            )
            .ok_or(AuthenticatedOutputErrorV4::Overflow)
        })?;
        let response_equality_symbols =
            response_local_terms.iter().try_fold(0u64, |sum, term| {
                sum.checked_add(
                    u64::try_from(term.equality.len())
                        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
                )
                .ok_or(AuthenticatedOutputErrorV4::Overflow)
            })?;
        MaterializedDelayedTermsV4 {
            terms: response_local_terms,
            source_symbols_read: response_source_symbols,
            equality_symbols_materialized: response_equality_symbols,
            source_clone_wall_ns: 0,
            equality_generation_wall_ns: 0,
        }
    };
    let materialized_terms = u64::try_from(materialized.terms.len())
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
    let fused_terms = relation_terms
        .checked_sub(materialized_terms)
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let sumcheck = prove_delayed_sumcheck_v4(
        materialized.terms,
        round_count,
        initial_claim,
        stream,
        prefix.round_correlation_domain_ids,
        tx,
    )?;

    let mut grouped = BTreeMap::new();
    for (block, (weight_base, auxiliary_base)) in blocks.iter().zip(&bases) {
        insert_prover_group_v4(
            &mut grouped,
            &block.weight_extension,
            terminal_weight_v4(*weight_base, block.weight_extension.target_point, &sumcheck.point),
            false,
        )?;
        insert_prover_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &sumcheck.point),
            false,
        )?;
    }
    if grouped.len() != keys.len() {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 global cohort set"));
    }
    let groups = grouped
        .iter()
        .map(|(key, group)| GlobalProverGroupV4 {
            cohort: group.cohort,
            touched_slots: group.weights.keys().copied().collect(),
            weights: group.weights.values().copied().collect(),
            target_point: sumcheck.point[round_count - group.dimension..].to_vec(),
            activation_challenge: activation[key],
        })
        .collect::<Vec<_>>();
    let descriptor = global_fold_descriptor_digest_v4(
        &groups
            .iter()
            .map(|group| {
                (
                    group.cohort.commitment().config.identity.cohort_id,
                    group.cohort.commitment().root,
                )
            })
            .collect::<Vec<_>>(),
    );
    let sealed = GlobalChainDraftV4::new_interactive(
        model_root,
        prefix.epoch,
        GLOBAL_FOLD_COHORT_ID_V4,
        descriptor,
        sumcheck.point.clone(),
        groups,
    )?
    .seal_interactive(tx)?;
    let fold_challenges = sealed.challenges().clone();
    let (global_folding, _verifier_groups, open_metrics, _draws) =
        sealed.issue_queries_interactive(tx)?;
    let opened_global = opened_global_value_from_lines_v4(
        &sumcheck.point,
        &fold_challenges,
        &global_folding.fold_frames,
    )?;
    if opened_global != sumcheck.terminal_value {
        return Err(AuthenticatedOutputErrorV4::GlobalTerminalMismatch);
    }
    let terminal_residual = sumcheck.final_claim.sub(ProverAuthed::from_public(opened_global));
    if terminal_residual.x != Fp2::ZERO {
        return Err(AuthenticatedOutputErrorV4::TerminalMacMismatch);
    }
    let terminal_tag = zero_open_prover(&terminal_residual, tx);
    let frame = AuthenticatedOutputLinkFrame {
        relation_count: u16::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        round_count: u8::try_from(round_count).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_schedule_digest: schedule_digest,
        ordered_round_correction_symbols: sumcheck.corrections,
        terminal_opened_tag_symbol: terminal_tag,
    };
    frame.validate()?;
    let mut metrics = AuthenticatedOutputLinkMetricsV4 {
        touched_blocks: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        relation_count: u64::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        round_count: u64::try_from(round_count)
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        m9_full_correlations: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_round_full_correlations: u64::try_from(2 * round_count)
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        seam_full_correlations_with_response_zero: x4_v4_seam_full_correlations(
            blocks.len(),
            round_count,
        )?,
        m9_frame_bytes: u64::try_from(
            64usize.checked_mul(blocks.len()).ok_or(AuthenticatedOutputErrorV4::Overflow)?,
        )
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_frame_bytes: u64::try_from(
            FrameV4::AuthenticatedOutputLink(frame.clone()).encode()?.len(),
        )
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        response_zero_batch_frame_bytes: 50,
        sumcheck_relation_terms: relation_terms,
        sumcheck_materialized_terms: materialized_terms,
        sumcheck_fused_terms: fused_terms,
        sumcheck_source_symbols_read: materialized.source_symbols_read,
        sumcheck_equality_symbols_materialized: materialized.equality_symbols_materialized,
        ..Default::default()
    };
    metrics.seam_frame_bytes = metrics
        .m9_frame_bytes
        .checked_add(metrics.link_frame_bytes)
        .and_then(|bytes| bytes.checked_add(metrics.response_zero_batch_frame_bytes))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    accumulate_global_metrics_v4(&mut metrics, &open_metrics);
    let bound = blocks
        .into_iter()
        .map(|block| BoundAuxEvalProverV4 {
            descriptor_digest: block.descriptor_digest,
            auth: block.pending_aux.auth,
        })
        .collect();
    Ok((AuthenticatedOutputLinkProofV4 { frame, global_folding }, bound, metrics))
}

pub type X4AcceleratedAuthenticatedOutputProverResultV4 = (
    AuthenticatedOutputLinkProofV4,
    Vec<BoundAuxEvalProverV4>,
    AuthenticatedOutputLinkMetricsV4,
    X4cResponseMetricsV4,
    X4cAuthenticatedOutputPhaseWallsV4,
    Vec<u64>,
);

/// Shared accelerated execution for X4c responses and X4d settlements.
///
/// `settlement_context = None` preserves the immutable X4c statement.
/// `Some(context)` lifts seal-before-query to the exact X4d frozen range and
/// permits repeated response-local relations to accumulate onto the same
/// static weight and settlement-fresh auxiliary slots.
#[allow(clippy::too_many_arguments)]
fn prove_authenticated_output_link_accelerated_v4<R: X4cArenaRuntimeV4>(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockProverV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    settlement_context: Option<&X4dSettlementContextV1>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    query_source: X4AcceleratedQuerySourceV4,
    runtime: &mut R,
    seal_config: X4cSealConfigV4,
) -> Result<X4AcceleratedAuthenticatedOutputProverResultV4, AuthenticatedOutputErrorV4> {
    let claim_coefficient_preparation_started = Instant::now();
    if permit.model_root != model_root
        || permit.epoch != prefix.epoch
        || permit.persistent_freshness_record_digest.is_none()
    {
        return Err(AuthenticatedOutputErrorV4::EpochMismatch);
    }
    let descriptors = blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let public_h = blocks.iter().map(|block| block.public_h).collect::<Vec<_>>();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 pending prover descriptor",
            ));
        }
        validate_prover_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::WeightExtension,
            &block.weight_extension,
        )?;
        validate_prover_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points_v4(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "v4 canonical auxiliary point",
            ));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    if round_count == 0 || round_count > 30 {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 link maximum dimension"));
    }
    let schedule_digest = validate_prefix_common_v4(
        prefix,
        &descriptors,
        &public_h,
        round_count,
        settlement_context,
    )?;
    let accumulate_duplicate_slots = settlement_context.is_some();
    let keys = prover_keys_v4(&blocks);
    let beta = tx.challenge_fp2();
    let activation = activation_challenges_v4(&keys, tx);
    let mut power = beta;
    let mut initial_claim = ProverAuthed::ZERO;
    let mut coefficients = Vec::with_capacity(blocks.len());
    let mut bases = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let weight_key = LinkCohortKeyV4::from_cohort(block.weight_extension.cohort);
        let auxiliary_key = LinkCohortKeyV4::from_cohort(block.auxiliary.cohort);
        let weight_base = power;
        let auxiliary_base = weight_base * beta;
        let masked_coefficient = activation[&weight_key] * weight_base;
        let auxiliary_coefficient = activation[&auxiliary_key] * auxiliary_base;
        let output_coefficient = auxiliary_coefficient - masked_coefficient;
        initial_claim = initial_claim
            .add(ProverAuthed::from_public(block.public_h).scale(masked_coefficient))
            .add(block.pending_aux.auth.scale(output_coefficient));
        coefficients.push((masked_coefficient, auxiliary_coefficient));
        bases.push((weight_base, auxiliary_base));
        power = auxiliary_base * beta;
    }
    let link_coefficient_challenge_wall_ns =
        phase_wall_ns_v4(claim_coefficient_preparation_started)?;
    let combined_link_equality_started = Instant::now();
    let mut response_local_terms = Vec::with_capacity(2 * blocks.len());
    let mut fused_settlement_terms = BTreeMap::new();
    for (block, &(masked_coefficient, auxiliary_coefficient)) in blocks.iter().zip(&coefficients) {
        if accumulate_duplicate_slots {
            accumulate_fused_settlement_term_v4(
                &mut fused_settlement_terms,
                &block.weight_extension,
                masked_coefficient,
            )?;
            accumulate_fused_settlement_term_v4(
                &mut fused_settlement_terms,
                &block.auxiliary,
                auxiliary_coefficient,
            )?;
        } else {
            response_local_terms.push(DelayedSumcheckTermV4::new(
                masked_coefficient,
                block.weight_extension.evaluations,
                block.weight_extension.target_point,
                round_count,
            )?);
            response_local_terms.push(DelayedSumcheckTermV4::new(
                auxiliary_coefficient,
                block.auxiliary.evaluations,
                block.auxiliary.target_point,
                round_count,
            )?);
        }
    }
    let mut combined_link_equality_wall_ns = phase_wall_ns_v4(combined_link_equality_started)?;
    let relation_terms =
        u64::try_from(2 * blocks.len()).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
    let mut resident_link_counters = super::x4c_v4::X4dResidentLinkCountersV4::default();
    let (materialized_terms, fused_terms, source_symbols_read, equality_symbols_materialized);
    let (sumcheck, link_source_clone_wall_ns);
    if accumulate_duplicate_slots {
        let resident_inputs = fused_settlement_terms
            .values()
            .map(|term| X4dResidentLinkTermV4 {
                evaluations: term.evaluations,
                dimension: term.dimension,
                contributions: term.contributions.clone(),
            })
            .collect::<Vec<_>>();
        materialized_terms = u64::try_from(resident_inputs.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
        fused_terms = relation_terms
            .checked_sub(materialized_terms)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        source_symbols_read = resident_inputs.iter().try_fold(0u64, |sum, term| {
            sum.checked_add(
                u64::try_from(term.evaluations.len())
                    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
            )
            .ok_or(AuthenticatedOutputErrorV4::Overflow)
        })?;
        equality_symbols_materialized = source_symbols_read;
        if let Some(resident) = runtime.prove_x4d_delayed_link_resident(
            &resident_inputs,
            round_count,
            initial_claim,
            stream,
            prefix.round_correlation_domain_ids,
            tx,
        )? {
            combined_link_equality_wall_ns = combined_link_equality_wall_ns
                .checked_add(resident.equality_generation_wall_ns)
                .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
            link_source_clone_wall_ns = resident.source_copy_wall_ns;
            resident_link_counters = resident.counters;
            sumcheck = SumcheckProverOutputV4 {
                corrections: resident.corrections,
                point: resident.point,
                final_claim: resident.final_claim,
                terminal_value: resident.terminal_value,
                phase_walls: DelayedSumcheckPhaseWallsV4 {
                    round_evaluation_wall_ns: resident.round_evaluation_wall_ns,
                    fold_wall_ns: resident.fold_wall_ns,
                    masks_transcript_terminal_wall_ns: resident.masks_transcript_terminal_wall_ns,
                },
            };
        } else {
            let materialized =
                materialize_fused_settlement_terms_v4(fused_settlement_terms, round_count)?;
            combined_link_equality_wall_ns = combined_link_equality_wall_ns
                .checked_add(materialized.equality_generation_wall_ns)
                .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
            link_source_clone_wall_ns = materialized.source_clone_wall_ns;
            sumcheck = prove_delayed_sumcheck_v4(
                materialized.terms,
                round_count,
                initial_claim,
                stream,
                prefix.round_correlation_domain_ids,
                tx,
            )?;
        }
    } else {
        let response_source_symbols = response_local_terms.iter().try_fold(0u64, |sum, term| {
            sum.checked_add(
                u64::try_from(term.evaluations.len())
                    .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
            )
            .ok_or(AuthenticatedOutputErrorV4::Overflow)
        })?;
        let response_equality_symbols =
            response_local_terms.iter().try_fold(0u64, |sum, term| {
                sum.checked_add(
                    u64::try_from(term.equality.len())
                        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
                )
                .ok_or(AuthenticatedOutputErrorV4::Overflow)
            })?;
        let materialized = MaterializedDelayedTermsV4 {
            terms: response_local_terms,
            source_symbols_read: response_source_symbols,
            equality_symbols_materialized: response_equality_symbols,
            source_clone_wall_ns: 0,
            equality_generation_wall_ns: 0,
        };
        materialized_terms = u64::try_from(materialized.terms.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?;
        fused_terms = relation_terms
            .checked_sub(materialized_terms)
            .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
        source_symbols_read = materialized.source_symbols_read;
        equality_symbols_materialized = materialized.equality_symbols_materialized;
        link_source_clone_wall_ns = materialized.source_clone_wall_ns;
        sumcheck = prove_delayed_sumcheck_v4(
            materialized.terms,
            round_count,
            initial_claim,
            stream,
            prefix.round_correlation_domain_ids,
            tx,
        )?;
    }
    let terminal_group_started = Instant::now();
    let mut grouped = BTreeMap::new();
    for (block, (weight_base, auxiliary_base)) in blocks.iter().zip(&bases) {
        insert_prover_group_v4(
            &mut grouped,
            &block.weight_extension,
            terminal_weight_v4(*weight_base, block.weight_extension.target_point, &sumcheck.point),
            accumulate_duplicate_slots,
        )?;
        insert_prover_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &sumcheck.point),
            accumulate_duplicate_slots,
        )?;
    }
    if grouped.len() != keys.len() {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 global cohort set"));
    }
    let groups = grouped
        .iter()
        .map(|(key, group)| GlobalProverGroupV4 {
            cohort: group.cohort,
            touched_slots: group.weights.keys().copied().collect(),
            weights: group.weights.values().copied().collect(),
            target_point: sumcheck.point[round_count - group.dimension..].to_vec(),
            activation_challenge: activation[key],
        })
        .collect::<Vec<_>>();
    let descriptor = global_fold_descriptor_digest_v4(
        &groups
            .iter()
            .map(|group| {
                (
                    group.cohort.commitment().config.identity.cohort_id,
                    group.cohort.commitment().root,
                )
            })
            .collect::<Vec<_>>(),
    );
    let draft = GlobalChainDraftV4::new_interactive(
        model_root,
        prefix.epoch,
        GLOBAL_FOLD_COHORT_ID_V4,
        descriptor,
        sumcheck.point.clone(),
        groups,
    )?;
    let claim_coefficient_preparation_wall_ns =
        phase_wall_ns_v4(claim_coefficient_preparation_started)?;
    let terminal_group_wall_ns = phase_wall_ns_v4(terminal_group_started)?;
    let accounted_preparation_children = link_coefficient_challenge_wall_ns
        .checked_add(combined_link_equality_wall_ns)
        .and_then(|value| value.checked_add(link_source_clone_wall_ns))
        .and_then(|value| value.checked_add(sumcheck.phase_walls.round_evaluation_wall_ns))
        .and_then(|value| value.checked_add(sumcheck.phase_walls.fold_wall_ns))
        .and_then(|value| value.checked_add(sumcheck.phase_walls.masks_transcript_terminal_wall_ns))
        .and_then(|value| value.checked_add(terminal_group_wall_ns))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let link_terminal_group_orchestration_wall_ns = sumcheck
        .phase_walls
        .masks_transcript_terminal_wall_ns
        .checked_add(terminal_group_wall_ns)
        .and_then(|value| {
            value.checked_add(
                claim_coefficient_preparation_wall_ns
                    .saturating_sub(accounted_preparation_children),
            )
        })
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let seal_started = Instant::now();
    let sealed = draft.seal_interactive_x4c(tx, runtime, seal_config)?;
    let seal_wall_ns = phase_wall_ns_v4(seal_started)?;
    let fold_challenges = sealed.challenges().clone();
    let (selected_draws, fresh_x4d_queries) = match (query_source, settlement_context) {
        (X4AcceleratedQuerySourceV4::X4c(selected_tape), None) => {
            (selected_tape.release_after_roots(&sealed, model_root, prefix.epoch)?, false)
        }
        (X4AcceleratedQuerySourceV4::X4d(query_seed), Some(context)) => {
            (query_seed.release_after_roots(&sealed, context, model_root, prefix.epoch)?, true)
        }
        _ => {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule("X4 accelerated query source"))
        }
    };
    let open_started = Instant::now();
    let (global_folding, _verifier_groups, x4c_metrics, returned_draws) = if fresh_x4d_queries {
        sealed.issue_queries_x4d(selected_draws.clone(), tx, runtime)?
    } else {
        sealed.issue_queries_x4c(selected_draws.clone(), tx, runtime)?
    };
    let open_wall_ns = phase_wall_ns_v4(open_started)?;
    if returned_draws != selected_draws {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("X4c selected draw tape"));
    }
    let opened_global = opened_global_value_from_lines_v4(
        &sumcheck.point,
        &fold_challenges,
        &global_folding.fold_frames,
    )?;
    if opened_global != sumcheck.terminal_value {
        return Err(AuthenticatedOutputErrorV4::GlobalTerminalMismatch);
    }
    let terminal_residual = sumcheck.final_claim.sub(ProverAuthed::from_public(opened_global));
    if terminal_residual.x != Fp2::ZERO {
        return Err(AuthenticatedOutputErrorV4::TerminalMacMismatch);
    }
    let terminal_tag = zero_open_prover(&terminal_residual, tx);
    let frame = AuthenticatedOutputLinkFrame {
        relation_count: u16::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        round_count: u8::try_from(round_count).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_schedule_digest: schedule_digest,
        ordered_round_correction_symbols: sumcheck.corrections,
        terminal_opened_tag_symbol: terminal_tag,
    };
    frame.validate()?;
    let mut metrics = AuthenticatedOutputLinkMetricsV4 {
        touched_blocks: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        relation_count: u64::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        round_count: u64::try_from(round_count)
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        m9_full_correlations: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_round_full_correlations: u64::try_from(2 * round_count)
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        seam_full_correlations_with_response_zero: x4_v4_seam_full_correlations(
            blocks.len(),
            round_count,
        )?,
        m9_frame_bytes: u64::try_from(
            64usize.checked_mul(blocks.len()).ok_or(AuthenticatedOutputErrorV4::Overflow)?,
        )
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        link_frame_bytes: u64::try_from(
            FrameV4::AuthenticatedOutputLink(frame.clone()).encode()?.len(),
        )
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        response_zero_batch_frame_bytes: 50,
        sumcheck_relation_terms: relation_terms,
        sumcheck_materialized_terms: materialized_terms,
        sumcheck_fused_terms: fused_terms,
        sumcheck_source_symbols_read: source_symbols_read,
        sumcheck_equality_symbols_materialized: equality_symbols_materialized,
        resident_link_host_bytes: resident_link_counters.host_bytes,
        resident_link_device_bytes: resident_link_counters.device_bytes,
        resident_link_h2d_bytes: resident_link_counters.h2d_bytes,
        resident_link_source_clone_bytes: resident_link_counters.source_clone_bytes,
        resident_link_d2h_bytes: resident_link_counters.d2h_bytes,
        resident_link_d2d_bytes: resident_link_counters.d2d_bytes,
        resident_link_protocol_scalar_d2h_bytes: resident_link_counters.protocol_scalar_d2h_bytes,
        resident_link_kernel_calls: resident_link_counters.kernel_calls,
        resident_link_allocation_requests: resident_link_counters.allocation_requests,
        resident_link_buffer_reuse_hits: resident_link_counters.buffer_reuse_hits,
        resident_link_peak_live_host_scratch_bytes: resident_link_counters
            .peak_live_host_scratch_bytes,
        resident_link_peak_live_scratch_bytes: resident_link_counters.peak_live_scratch_bytes,
        ..Default::default()
    };
    metrics.seam_frame_bytes = metrics
        .m9_frame_bytes
        .checked_add(metrics.link_frame_bytes)
        .and_then(|bytes| bytes.checked_add(metrics.response_zero_batch_frame_bytes))
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    accumulate_global_metrics_v4(&mut metrics, &x4c_metrics.global_open);
    let oracle_read_combine_wall_ns = x4c_metrics.global_open.oracle_read_combine_wall_ns;
    let fold_merkle_wall_ns = seal_wall_ns
        .checked_sub(oracle_read_combine_wall_ns)
        .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
    let bound = blocks
        .into_iter()
        .map(|block| BoundAuxEvalProverV4 {
            descriptor_digest: block.descriptor_digest,
            auth: block.pending_aux.auth,
        })
        .collect();
    Ok((
        AuthenticatedOutputLinkProofV4 { frame, global_folding },
        bound,
        metrics,
        x4c_metrics,
        X4cAuthenticatedOutputPhaseWallsV4 {
            claim_coefficient_preparation_wall_ns,
            link_coefficient_challenge_wall_ns,
            combined_link_equality_wall_ns,
            link_source_clone_wall_ns,
            delayed_link_round_evaluation_wall_ns: sumcheck.phase_walls.round_evaluation_wall_ns,
            delayed_link_fold_wall_ns: sumcheck.phase_walls.fold_wall_ns,
            link_terminal_group_orchestration_wall_ns,
            oracle_read_combine_wall_ns,
            fold_merkle_wall_ns,
            query_gather_wall_ns: open_wall_ns,
            seal_wall_ns,
            open_wall_ns,
        },
        selected_draws,
    ))
}

/// X4c execution of the unchanged schema-4 authenticated-output link.
#[allow(clippy::too_many_arguments)]
pub fn prove_authenticated_output_link_x4c_v4<R: X4cArenaRuntimeV4>(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockProverV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    selected_tape: X4cSelectedQueryTapeV4,
    runtime: &mut R,
    seal_config: X4cSealConfigV4,
) -> Result<X4AcceleratedAuthenticatedOutputProverResultV4, AuthenticatedOutputErrorV4> {
    prove_authenticated_output_link_accelerated_v4(
        permit,
        model_root,
        blocks,
        prefix,
        None,
        stream,
        tx,
        X4AcceleratedQuerySourceV4::X4c(selected_tape),
        runtime,
        seal_config,
    )
}

/// X4d settlement execution over one exact digest-sealed claim union.
#[allow(clippy::too_many_arguments)]
pub fn prove_authenticated_output_link_x4d_v4<R: X4cArenaRuntimeV4>(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockProverV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    settlement_context: &X4dSettlementContextV1,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    query_seed: X4dSettlementQuerySeedV1,
    runtime: &mut R,
    seal_config: X4cSealConfigV4,
) -> Result<X4AcceleratedAuthenticatedOutputProverResultV4, AuthenticatedOutputErrorV4> {
    prove_authenticated_output_link_accelerated_v4(
        permit,
        model_root,
        blocks,
        prefix,
        Some(settlement_context),
        stream,
        tx,
        X4AcceleratedQuerySourceV4::X4d(query_seed),
        runtime,
        seal_config,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_output_link_v4(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockVerifierV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    proof: &AuthenticatedOutputLinkProofV4,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifierV4>, AuthenticatedOutputErrorV4> {
    if permit.model_root != model_root || permit.epoch != prefix.epoch {
        return Err(AuthenticatedOutputErrorV4::EpochMismatch);
    }
    proof.frame.validate()?;
    let descriptors = blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let public_h = blocks.iter().map(|block| block.public_h).collect::<Vec<_>>();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 pending verifier descriptor",
            ));
        }
        validate_verifier_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::WeightExtension,
            &block.weight_extension,
        )?;
        validate_verifier_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points_v4(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "v4 canonical auxiliary point",
            ));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    let expected_digest =
        validate_prefix_common_v4(prefix, &descriptors, &public_h, round_count, None)?;
    if usize::from(proof.frame.relation_count) != 2 * blocks.len()
        || usize::from(proof.frame.round_count) != round_count
        || proof.frame.link_schedule_digest != expected_digest
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link frame statement"));
    }
    let keys = verifier_keys_v4(&blocks);
    let beta = tx.challenge_fp2();
    let activation = activation_challenges_v4(&keys, tx);
    let mut power = beta;
    let mut initial_key = VerifierKey::ZERO;
    let mut bases = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let weight_key = verifier_key_v4(&block.weight_extension);
        let auxiliary_key = verifier_key_v4(&block.auxiliary);
        let weight_base = power;
        let auxiliary_base = weight_base * beta;
        let masked_coefficient = activation[&weight_key] * weight_base;
        let auxiliary_coefficient = activation[&auxiliary_key] * auxiliary_base;
        let output_coefficient = auxiliary_coefficient - masked_coefficient;
        initial_key = initial_key
            .add(VerifierKey::from_public(block.public_h, ctx.delta).scale(masked_coefficient))
            .add(block.pending_aux.key.scale(output_coefficient));
        bases.push((weight_base, auxiliary_base));
        power = auxiliary_base * beta;
    }
    let (point, final_key) = verify_delayed_sumcheck_v4(
        round_count,
        initial_key,
        &proof.frame.ordered_round_correction_symbols,
        ctx,
        prefix.round_correlation_domain_ids,
        tx,
    )?;

    let mut grouped = BTreeMap::new();
    for (block, (weight_base, auxiliary_base)) in blocks.iter().zip(&bases) {
        insert_verifier_group_v4(
            &mut grouped,
            &block.weight_extension,
            terminal_weight_v4(*weight_base, block.weight_extension.target_point, &point),
            false,
        )?;
        insert_verifier_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &point),
            false,
        )?;
    }
    if grouped.len() != keys.len()
        || proof.global_folding.packed_opening.initial_groups.len() != grouped.len()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 global cohort proof set"));
    }
    let groups = grouped
        .iter()
        .map(|(key, group)| GlobalVerifierGroupV4 {
            commitment: group.commitment.clone(),
            touched_slots: group.weights.keys().copied().collect(),
            weights: group.weights.values().copied().collect(),
            target_point: point[round_count - group.dimension..].to_vec(),
            activation_challenge: activation[key],
        })
        .collect::<Vec<_>>();
    let opened_global = verify_global_folding_interactive_v4(
        model_root,
        prefix.epoch,
        &point,
        &groups,
        &proof.global_folding,
        tx,
    )?;
    let terminal_key = final_key.sub(VerifierKey::from_public(opened_global, ctx.delta));
    if !zero_open_verify(terminal_key, proof.frame.terminal_opened_tag_symbol) {
        return Err(AuthenticatedOutputErrorV4::LinkRejected);
    }
    tx.append("zero_open_tag", 16);
    Ok(blocks
        .into_iter()
        .map(|block| BoundAuxEvalVerifierV4 {
            descriptor_digest: block.descriptor_digest,
            key: block.pending_aux.key,
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn verify_authenticated_output_link_accelerated_v4(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockVerifierV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    settlement_context: Option<&X4dSettlementContextV1>,
    proof: &AuthenticatedOutputLinkProofV4,
    selected_draws: &[u64],
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifierV4>, AuthenticatedOutputErrorV4> {
    if permit.model_root != model_root
        || permit.epoch != prefix.epoch
        || permit.persistent_freshness_record_digest.is_none()
    {
        return Err(AuthenticatedOutputErrorV4::EpochMismatch);
    }
    proof.frame.validate()?;
    let descriptors = blocks.iter().map(|block| block.descriptor_digest).collect::<Vec<_>>();
    let public_h = blocks.iter().map(|block| block.public_h).collect::<Vec<_>>();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
                "v4 pending verifier descriptor",
            ));
        }
        validate_verifier_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::WeightExtension,
            &block.weight_extension,
        )?;
        validate_verifier_polynomial_v4(
            block.descriptor_digest,
            OracleKindV4::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points_v4(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputErrorV4::InvalidGeometry(
                "v4 canonical auxiliary point",
            ));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    let expected_digest = validate_prefix_common_v4(
        prefix,
        &descriptors,
        &public_h,
        round_count,
        settlement_context,
    )?;
    if usize::from(proof.frame.relation_count) != 2 * blocks.len()
        || usize::from(proof.frame.round_count) != round_count
        || proof.frame.link_schedule_digest != expected_digest
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link frame statement"));
    }
    let keys = verifier_keys_v4(&blocks);
    let beta = tx.challenge_fp2();
    let activation = activation_challenges_v4(&keys, tx);
    let mut power = beta;
    let mut initial_key = VerifierKey::ZERO;
    let mut bases = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let weight_key = verifier_key_v4(&block.weight_extension);
        let auxiliary_key = verifier_key_v4(&block.auxiliary);
        let weight_base = power;
        let auxiliary_base = weight_base * beta;
        let masked_coefficient = activation[&weight_key] * weight_base;
        let auxiliary_coefficient = activation[&auxiliary_key] * auxiliary_base;
        let output_coefficient = auxiliary_coefficient - masked_coefficient;
        initial_key = initial_key
            .add(VerifierKey::from_public(block.public_h, ctx.delta).scale(masked_coefficient))
            .add(block.pending_aux.key.scale(output_coefficient));
        bases.push((weight_base, auxiliary_base));
        power = auxiliary_base * beta;
    }
    let (point, final_key) = verify_delayed_sumcheck_v4(
        round_count,
        initial_key,
        &proof.frame.ordered_round_correction_symbols,
        ctx,
        prefix.round_correlation_domain_ids,
        tx,
    )?;
    let accumulate_duplicate_slots = settlement_context.is_some();
    let mut grouped = BTreeMap::new();
    for (block, (weight_base, auxiliary_base)) in blocks.iter().zip(&bases) {
        insert_verifier_group_v4(
            &mut grouped,
            &block.weight_extension,
            terminal_weight_v4(*weight_base, block.weight_extension.target_point, &point),
            accumulate_duplicate_slots,
        )?;
        insert_verifier_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &point),
            accumulate_duplicate_slots,
        )?;
    }
    if grouped.len() != keys.len()
        || proof.global_folding.packed_opening.initial_groups.len() != grouped.len()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 global cohort proof set"));
    }
    let groups = grouped
        .iter()
        .map(|(key, group)| GlobalVerifierGroupV4 {
            commitment: group.commitment.clone(),
            touched_slots: group.weights.keys().copied().collect(),
            weights: group.weights.values().copied().collect(),
            target_point: point[round_count - group.dimension..].to_vec(),
            activation_challenge: activation[key],
        })
        .collect::<Vec<_>>();
    if proof.global_folding.fold_frames.is_empty() {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 empty X4c fold chain"));
    }
    let mut folds = Vec::with_capacity(proof.global_folding.fold_frames.len());
    for frame in &proof.global_folding.fold_frames {
        frame.validate()?;
        tx.append("x4_v4_global_fold_line", 32);
        folds.push(tx.challenge_fp2());
        let frame_bytes = FrameV4::FoldCommitment(frame.clone()).encode()?.len();
        tx.append(
            "x4_v4_global_fold_post_challenge",
            u64::try_from(
                frame_bytes.checked_sub(32).ok_or(AuthenticatedOutputErrorV4::InvalidSchedule(
                    "v4 fold frame line width",
                ))?,
            )
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        );
    }
    let opened_global = verify_global_folding_v4(
        model_root,
        prefix.epoch,
        &point,
        &groups,
        &GlobalFoldChallengesV4 { folds },
        selected_draws,
        &proof.global_folding,
    )?;
    tx.append(
        "x4_v4_packed_opening",
        u64::try_from(
            FrameV4::PackedBatchOpening(proof.global_folding.packed_opening.clone())
                .encode()?
                .len(),
        )
        .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
    );
    let terminal_key = final_key.sub(VerifierKey::from_public(opened_global, ctx.delta));
    if !zero_open_verify(terminal_key, proof.frame.terminal_opened_tag_symbol) {
        return Err(AuthenticatedOutputErrorV4::LinkRejected);
    }
    tx.append("zero_open_tag", 16);
    Ok(blocks
        .into_iter()
        .map(|block| BoundAuxEvalVerifierV4 {
            descriptor_digest: block.descriptor_digest,
            key: block.pending_aux.key,
        })
        .collect())
}

/// Verifier replay for the immutable X4c response statement.
#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_output_link_x4c_v4(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockVerifierV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    proof: &AuthenticatedOutputLinkProofV4,
    selected_draws: &[u64],
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifierV4>, AuthenticatedOutputErrorV4> {
    verify_authenticated_output_link_accelerated_v4(
        permit,
        model_root,
        blocks,
        prefix,
        None,
        proof,
        selected_draws,
        ctx,
        tx,
    )
}

/// Verifier replay for one digest-sealed X4d settlement union.
#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_output_link_x4d_v4(
    permit: X4OpeningPermitV4,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockVerifierV4<'_>>,
    prefix: AuthenticatedOutputLinkPrefixV4<'_>,
    settlement_context: &X4dSettlementContextV1,
    proof: &AuthenticatedOutputLinkProofV4,
    selected_draws: &[u64],
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifierV4>, AuthenticatedOutputErrorV4> {
    verify_authenticated_output_link_accelerated_v4(
        permit,
        model_root,
        blocks,
        prefix,
        Some(settlement_context),
        proof,
        selected_draws,
        ctx,
        tx,
    )
}

pub fn prove_bound_response_zero_batch_v4(
    authenticated_weight_evals: &[ProverAuthed],
    bound_aux: &[BoundAuxEvalProverV4],
    public_h: &[Fp2],
    stream: &mut CorrelationStream,
    mask_domain: u64,
    tx: &mut Transcript,
) -> Result<ResponseZeroBatchFrame, AuthenticatedOutputErrorV4> {
    if authenticated_weight_evals.len() != bound_aux.len()
        || bound_aux.len() != public_h.len()
        || bound_aux.len() > 1660
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 bound response ZeroBatch"));
    }
    let residuals = authenticated_weight_evals
        .iter()
        .zip(bound_aux)
        .zip(public_h)
        .map(|((weight, auxiliary), h)| {
            weight.add(auxiliary.auth).sub(ProverAuthed::from_public(*h))
        })
        .collect::<Vec<_>>();
    if residuals.iter().any(|residual| residual.x != Fp2::ZERO) {
        return Err(AuthenticatedOutputErrorV4::ZeroBatchRejected);
    }
    let correlation = stream.draw_fulls(mask_domain, 1)[0];
    let (mask, correction) = fresh_zero_mask(correlation, tx);
    let challenge = tx.challenge_fp2();
    let opened_tag = zero_batch_prover(&residuals, &mask, challenge, tx);
    let frame = ResponseZeroBatchFrame {
        claim_count: u16::try_from(residuals.len())
            .map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        mask_correction_symbol: correction,
        opened_tag_symbol: opened_tag,
    };
    frame.validate()?;
    Ok(frame)
}

pub fn verify_bound_response_zero_batch_v4(
    authenticated_weight_keys: &[VerifierKey],
    bound_aux: &[BoundAuxEvalVerifierV4],
    public_h: &[Fp2],
    frame: &ResponseZeroBatchFrame,
    ctx: &mut VerifierCtx,
    mask_domain: u64,
    tx: &mut Transcript,
) -> Result<(), AuthenticatedOutputErrorV4> {
    frame.validate()?;
    if authenticated_weight_keys.len() != bound_aux.len()
        || bound_aux.len() != public_h.len()
        || usize::from(frame.claim_count) != bound_aux.len()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidGeometry("v4 bound response ZeroBatch"));
    }
    let residual_keys = authenticated_weight_keys
        .iter()
        .zip(bound_aux)
        .zip(public_h)
        .map(|((weight, auxiliary), h)| {
            weight.add(auxiliary.key).sub(VerifierKey::from_public(*h, ctx.delta))
        })
        .collect::<Vec<_>>();
    let full_key = ctx.expand_full_keys(mask_domain, 1)[0];
    tx.append("mask_correction", 16);
    let mask_key = zero_mask_key(ctx, full_key, frame.mask_correction_symbol);
    let challenge = tx.challenge_fp2();
    tx.append("zero_batch_tag", 16);
    if zero_batch_verify(&residual_keys, mask_key, challenge, frame.opened_tag_symbol) {
        Ok(())
    } else {
        Err(AuthenticatedOutputErrorV4::ZeroBatchRejected)
    }
}

/// Permanent beta-collision diagnostic.  `true` is classified as LinkBad;
/// it is never converted into deterministic equality.
pub fn beta_collision_is_link_bad_v4(
    masked_residual: Fp2,
    output_residual: Fp2,
    beta: Fp2,
) -> bool {
    masked_residual != Fp2::ZERO
        && output_residual != Fp2::ZERO
        && masked_residual + beta * output_residual == Fp2::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::folding_v4::CommittedModelGlobalCohortV4;
    use crate::x4::merkle_v4::{CohortIdentityV4, CohortVerifierConfigV4};
    use crate::x4::ntt::{evaluate_multilinear_table, multilinear_coefficients};
    use crate::x4::x4c_v4::{X4cArenaLayoutV4, X4cCpuReferenceRuntimeV4, X4C_DESIGN_SHA256_V4};
    use volta_field::Fp;

    const M9_DOMAIN: u64 = 0x61_000;
    const LINK_DOMAINS: [u64; 8] =
        [0x62_000, 0x62_001, 0x62_002, 0x62_003, 0x62_004, 0x62_005, 0x62_006, 0x62_007];
    const ZERO_DOMAIN: u64 = 0x63_000;
    const PCG_SEED: [u8; 32] = [0xC3; 32];
    const TX_SEED: [u8; 32] = [0xD4; 32];
    const MODEL_CONFIG_DIGEST: Digest = [0xE5; 32];
    const WEIGHTS_DIGEST: Digest = [0xE6; 32];

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 7 + 5))
    }

    fn committed(
        descriptor: Digest,
        cohort_id: u32,
        kind: OracleKindV4,
        evaluations: &[Fp2],
    ) -> CommittedModelGlobalCohortV4 {
        CommittedModelGlobalCohortV4::commit(
            CohortVerifierConfigV4 {
                identity: CohortIdentityV4 { cohort_id, oracle_kind: kind, fold_round: 0 },
                slot_descriptors: vec![Some(descriptor)],
                outer_len: 8 * evaluations.len(),
                expected_symbol_count: 1,
            },
            vec![Some(multilinear_coefficients(evaluations).unwrap())],
        )
        .unwrap()
    }

    #[test]
    fn delayed_term_round_invariant_matches_leading_zero_embedding() {
        let evaluations = (0..4).map(|index| symbol(90 + index)).collect::<Vec<_>>();
        let target = vec![symbol(13), Fp2::ZERO];
        let mut term = DelayedSumcheckTermV4::new(symbol(17), &evaluations, &target, 4).unwrap();
        let mut claim = term.initial_sum();
        for challenge in [symbol(19), symbol(23), symbol(29), symbol(31)] {
            let (at_zero, at_two) = term.round_values().unwrap();
            let at_one = claim - at_zero;
            let weights = lagrange3(challenge);
            claim = at_zero * weights[0] + at_one * weights[1] + at_two * weights[2];
            term.bind(challenge);
            assert_eq!(claim, term.active_sum());
        }
        assert_eq!(claim, term.terminal().unwrap());
    }

    #[test]
    fn fused_settlement_terms_are_round_exact_and_require_one_source_alias() {
        let descriptor = [0x18; 32];
        let evaluations = (0..16).map(|index| symbol(700 + index)).collect::<Vec<_>>();
        let duplicate_allocation = evaluations.clone();
        let cohort =
            committed(descriptor, 0xA510_0001, OracleKindV4::WeightExtension, &evaluations);
        let points = [
            vec![symbol(3), symbol(5), symbol(7), Fp2::ZERO],
            vec![symbol(11), symbol(13), symbol(17), Fp2::ZERO],
            vec![symbol(19), symbol(23), symbol(29), Fp2::ZERO],
        ];
        let coefficients = [symbol(31), symbol(37), symbol(41)];
        let mut response_local = points
            .iter()
            .zip(coefficients)
            .map(|(point, coefficient)| {
                DelayedSumcheckTermV4::new(coefficient, &evaluations, point, 4).unwrap()
            })
            .collect::<Vec<_>>();
        let mut accumulators = BTreeMap::new();
        for (point, coefficient) in points.iter().zip(coefficients) {
            accumulate_fused_settlement_term_v4(
                &mut accumulators,
                &LinkPolynomialProverV4 {
                    cohort: &cohort,
                    slot: 0,
                    evaluations: &evaluations,
                    target_point: point,
                },
                coefficient,
            )
            .unwrap();
        }
        let alias_rejected = accumulate_fused_settlement_term_v4(
            &mut accumulators,
            &LinkPolynomialProverV4 {
                cohort: &cohort,
                slot: 0,
                evaluations: &duplicate_allocation,
                target_point: &points[0],
            },
            symbol(43),
        );
        assert!(matches!(
            alias_rejected,
            Err(AuthenticatedOutputErrorV4::InvalidSchedule("X4d fused link source alias"))
        ));
        let materialized = materialize_fused_settlement_terms_v4(accumulators, 4).unwrap();
        assert_eq!(materialized.terms.len(), 1);
        assert_eq!(materialized.source_symbols_read, 16);
        assert_eq!(materialized.equality_symbols_materialized, 16);
        let mut fused = materialized.terms;
        let response_initial =
            response_local.iter().fold(Fp2::ZERO, |sum, term| sum + term.initial_sum());
        let fused_initial = fused.iter().fold(Fp2::ZERO, |sum, term| sum + term.initial_sum());
        assert_eq!(response_initial, fused_initial);
        for challenge in [symbol(47), symbol(53), symbol(59), symbol(61)] {
            let response_round = response_local.iter().try_fold(
                (Fp2::ZERO, Fp2::ZERO),
                |(at_zero, at_two), term| {
                    let (term_zero, term_two) = term.round_values()?;
                    Ok::<_, AuthenticatedOutputErrorV4>((at_zero + term_zero, at_two + term_two))
                },
            );
            let fused_round =
                fused.iter().try_fold((Fp2::ZERO, Fp2::ZERO), |(at_zero, at_two), term| {
                    let (term_zero, term_two) = term.round_values()?;
                    Ok::<_, AuthenticatedOutputErrorV4>((at_zero + term_zero, at_two + term_two))
                });
            assert_eq!(response_round.unwrap(), fused_round.unwrap());
            for term in &mut response_local {
                term.bind(challenge);
            }
            for term in &mut fused {
                term.bind(challenge);
            }
        }
        let response_terminal = response_local
            .iter()
            .try_fold(Fp2::ZERO, |sum, term| {
                Ok::<_, AuthenticatedOutputErrorV4>(sum + term.terminal()?)
            })
            .unwrap();
        let fused_terminal = fused
            .iter()
            .try_fold(Fp2::ZERO, |sum, term| {
                Ok::<_, AuthenticatedOutputErrorV4>(sum + term.terminal()?)
            })
            .unwrap();
        assert_eq!(response_terminal, fused_terminal);
    }

    struct Generated {
        descriptor: Digest,
        descriptors: Vec<Digest>,
        public_h: Vec<Fp2>,
        m9_frames: Vec<M9TransferFrame>,
        weight_evaluations: Vec<Fp2>,
        auxiliary_evaluations: Vec<Fp2>,
        weight_point: Vec<Fp2>,
        auxiliary_point: Vec<Fp2>,
        weight: CommittedModelGlobalCohortV4,
        auxiliary: CommittedModelGlobalCohortV4,
        model_root: Digest,
        manifest_frames: Vec<crate::x4::frame_v4::ManifestFrameV4>,
        proof: AuthenticatedOutputLinkProofV4,
        bound_prover: Vec<BoundAuxEvalProverV4>,
        metrics: AuthenticatedOutputLinkMetricsV4,
        prover_stream: CorrelationStream,
        prover_tx: Transcript,
        weight_value: Fp2,
        auxiliary_value: Fp2,
        delta: Fp2,
    }

    fn generate() -> Generated {
        let descriptor = [0x27; 32];
        let weight_evaluations = (0..16).map(|index| symbol(10 + index)).collect::<Vec<_>>();
        let auxiliary_evaluations = (0..4).map(|index| symbol(80 + 3 * index)).collect::<Vec<_>>();
        let weight_point = vec![symbol(7), symbol(11), symbol(13), Fp2::ZERO];
        let auxiliary_point = vec![symbol(13), Fp2::ZERO];
        let weight_value = evaluate_multilinear_table(&weight_evaluations, &weight_point).unwrap();
        let auxiliary_value =
            evaluate_multilinear_table(&auxiliary_evaluations, &auxiliary_point).unwrap();
        let public_h = vec![weight_value + auxiliary_value];
        let descriptors = vec![descriptor];
        let weight =
            committed(descriptor, 0xA500_0001, OracleKindV4::WeightExtension, &weight_evaluations);
        let auxiliary =
            committed(descriptor, 0xA500_0100, OracleKindV4::Auxiliary, &auxiliary_evaluations);
        let manifest = crate::x4::manifest_v4::ManifestTreeV4::build(
            crate::x4::frame_v4::manifest_id_digest_v4(MODEL_CONFIG_DIGEST, WEIGHTS_DIGEST, 9),
            vec![crate::x4::frame::ManifestLeafFrame {
                descriptor_digest: descriptor,
                ordered_roots: vec![weight.commitment().root, auxiliary.commitment().root],
            }],
        )
        .unwrap();
        let model_root = manifest.root();
        let manifest_frames = manifest.open(&descriptors).unwrap();
        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let (pending, m9) = authenticate_pending_aux_prover_v4(
            descriptor,
            auxiliary_value,
            &mut prover_stream,
            M9_DOMAIN,
            &mut prover_tx,
        )
        .unwrap();
        let m9_frames = vec![m9];
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch: 9,
            claim_frames: &[],
            descriptor_digests: &descriptors,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        let blocks = vec![AuthenticatedOutputBlockProverV4 {
            descriptor_digest: descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialProverV4 {
                cohort: &weight,
                slot: 0,
                evaluations: &weight_evaluations,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialProverV4 {
                cohort: &auxiliary,
                slot: 0,
                evaluations: &auxiliary_evaluations,
                target_point: &auxiliary_point,
            },
        }];
        let permit = X4OpeningRegistryV4::default().authorize(model_root, 9).unwrap();
        let (proof, bound_prover, metrics) = prove_authenticated_output_link_v4(
            permit,
            model_root,
            blocks,
            prefix,
            &mut prover_stream,
            &mut prover_tx,
        )
        .unwrap();
        Generated {
            descriptor,
            descriptors,
            public_h,
            m9_frames,
            weight_evaluations,
            auxiliary_evaluations,
            weight_point,
            auxiliary_point,
            weight,
            auxiliary,
            model_root,
            manifest_frames,
            proof,
            bound_prover,
            metrics,
            prover_stream,
            prover_tx,
            weight_value,
            auxiliary_value,
            delta: symbol(101),
        }
    }

    fn verify_with(
        generated: &Generated,
        proof: &AuthenticatedOutputLinkProofV4,
        descriptors: &[Digest],
        public_h: &[Fp2],
        m9_frames: &[M9TransferFrame],
        domains: &[u64],
    ) -> Result<(Vec<BoundAuxEvalVerifierV4>, VerifierCtx, Transcript), AuthenticatedOutputErrorV4>
    {
        let mut ctx = VerifierCtx::new(PCG_SEED, generated.delta);
        let mut tx = Transcript::new(TX_SEED);
        let pending =
            authenticate_pending_aux_verifier_v4(&m9_frames[0], &mut ctx, M9_DOMAIN, &mut tx)?;
        let blocks = vec![AuthenticatedOutputBlockVerifierV4 {
            descriptor_digest: generated.descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialVerifierV4 {
                commitment: generated.weight.commitment(),
                slot: 0,
                target_point: &generated.weight_point,
            },
            auxiliary: LinkPolynomialVerifierV4 {
                commitment: generated.auxiliary.commitment(),
                slot: 0,
                target_point: &generated.auxiliary_point,
            },
        }];
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch: 9,
            claim_frames: &[],
            descriptor_digests: descriptors,
            ordered_h_symbols: public_h,
            m9_frames,
            round_correlation_domain_ids: domains,
        };
        let permit = X4OpeningRegistryV4::default().authorize(generated.model_root, 9).unwrap();
        let bound = verify_authenticated_output_link_v4(
            permit,
            generated.model_root,
            blocks,
            prefix,
            proof,
            &mut ctx,
            &mut tx,
        )?;
        Ok((bound, ctx, tx))
    }

    #[test]
    fn honest_v4_link_delays_short_cohort_and_only_returns_bound_values() {
        let mut generated = generate();
        let (bound_verifier, mut ctx, mut verifier_tx) = verify_with(
            &generated,
            &generated.proof,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .unwrap();
        assert_eq!(generated.bound_prover[0].authenticated().x, generated.auxiliary_value);
        assert_eq!(generated.metrics.m9_full_correlations, 1);
        assert_eq!(generated.metrics.link_round_full_correlations, 8);
        assert_eq!(generated.metrics.seam_full_correlations_with_response_zero, 10);
        assert_eq!(generated.metrics.link_frame_bytes, 69 + 32 * 4);
        assert_eq!(generated.metrics.seam_frame_bytes, 64 + (69 + 32 * 4) + 50);
        assert_eq!(generated.proof.global_folding.fold_frames.len(), 4);
        assert_eq!(generated.proof.global_folding.packed_opening.initial_groups.len(), 2);
        assert_eq!(generated.proof.global_folding.packed_opening.fold_rounds.len(), 4);
        assert_eq!(generated.proof.global_folding.packed_opening.initial_groups[0].domain_log2, 7);
        assert_eq!(generated.proof.global_folding.packed_opening.initial_groups[1].domain_log2, 5);
        assert_eq!(generated.proof.frame.relation_count, 2);
        assert_eq!(generated.proof.frame.round_count, 4);
        let weight_tag = symbol(700);
        let weight_auth = ProverAuthed { x: generated.weight_value, m: weight_tag };
        let weight_key = VerifierKey { k: weight_tag + generated.delta * generated.weight_value };
        let zero_frame = prove_bound_response_zero_batch_v4(
            &[weight_auth],
            &generated.bound_prover,
            &generated.public_h,
            &mut generated.prover_stream,
            ZERO_DOMAIN,
            &mut generated.prover_tx,
        )
        .unwrap();
        verify_bound_response_zero_batch_v4(
            &[weight_key],
            &bound_verifier,
            &generated.public_h,
            &zero_frame,
            &mut ctx,
            ZERO_DOMAIN,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(generated.prover_stream.counters.full_corrs, 10);
        assert_eq!(ctx.counters.full_corrs, 10);
        assert_eq!(FrameV4::ResponseZeroBatch(zero_frame.clone()).encode().unwrap().len(), 50);
        assert_ne!(generated.proof.frame.terminal_opened_tag_symbol, generated.auxiliary_value);
        assert_eq!(generated.weight_evaluations.len(), 16);
        assert_eq!(generated.auxiliary_evaluations.len(), 4);

        let response = crate::x4::frame_v4::ResponseEnvelopeFrameV4 {
            profile_digest: crate::x4::frame_v4::profile_digest_v4(),
            model_root: generated.model_root,
            epoch: 9,
            descriptor_digests: generated.descriptors.clone(),
            manifest_frames: generated.manifest_frames.clone(),
            claim_frames: vec![],
            ordered_h_symbols: generated.public_h.clone(),
            m9_frames: generated.m9_frames.clone(),
            authenticated_output_link_frame: generated.proof.frame.clone(),
            fold_frames: generated.proof.global_folding.fold_frames.clone(),
            packed_opening_frame: generated.proof.global_folding.packed_opening.clone(),
            zero_batch_frame: zero_frame,
        };
        crate::x4::manifest_v4::verify_response_manifest_v4(
            &response,
            MODEL_CONFIG_DIGEST,
            WEIGHTS_DIGEST,
            &generated.descriptors,
        )
        .unwrap();
        let encoded = FrameV4::ResponseEnvelope(response.clone()).encode().unwrap();
        assert_eq!(
            crate::x4::frame_v4::decode_v4(&encoded).unwrap(),
            FrameV4::ResponseEnvelope(response)
        );
    }

    #[test]
    fn x4c_arena_link_is_byte_identical_and_requires_persistent_freshness() {
        let descriptor = [0x37; 32];
        let weight_evaluations = (0..16).map(|index| symbol(110 + index)).collect::<Vec<_>>();
        let auxiliary_evaluations = (0..4).map(|index| symbol(180 + 3 * index)).collect::<Vec<_>>();
        let weight_point = vec![symbol(17), symbol(21), symbol(23), Fp2::ZERO];
        let auxiliary_point = vec![symbol(23), Fp2::ZERO];
        let weight_value = evaluate_multilinear_table(&weight_evaluations, &weight_point).unwrap();
        let auxiliary_value =
            evaluate_multilinear_table(&auxiliary_evaluations, &auxiliary_point).unwrap();
        let public_h = vec![weight_value + auxiliary_value];
        let descriptors = vec![descriptor];
        let weight =
            committed(descriptor, 0xA500_0001, OracleKindV4::WeightExtension, &weight_evaluations);
        let auxiliary =
            committed(descriptor, 0xA500_0100, OracleKindV4::Auxiliary, &auxiliary_evaluations);
        let manifest = crate::x4::manifest_v4::ManifestTreeV4::build(
            crate::x4::frame_v4::manifest_id_digest_v4(MODEL_CONFIG_DIGEST, WEIGHTS_DIGEST, 19),
            vec![crate::x4::frame::ManifestLeafFrame {
                descriptor_digest: descriptor,
                ordered_roots: vec![weight.commitment().root, auxiliary.commitment().root],
            }],
        )
        .unwrap();
        let model_root = manifest.root();
        let selected_draws = (0..crate::x4::frame_v4::PRODUCTION_QUERY_COUNT_V4)
            .map(|index| (index as u64 * 13) & 127)
            .collect::<Vec<_>>();

        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let (pending, m9) = authenticate_pending_aux_prover_v4(
            descriptor,
            auxiliary_value,
            &mut prover_stream,
            M9_DOMAIN,
            &mut prover_tx,
        )
        .unwrap();
        let m9_frames = vec![m9];
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch: 19,
            claim_frames: &[],
            descriptor_digests: &descriptors,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        let prover_blocks = vec![AuthenticatedOutputBlockProverV4 {
            descriptor_digest: descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialProverV4 {
                cohort: &weight,
                slot: 0,
                evaluations: &weight_evaluations,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialProverV4 {
                cohort: &auxiliary,
                slot: 0,
                evaluations: &auxiliary_evaluations,
                target_point: &auxiliary_point,
            },
        }];
        let legacy_permit = X4OpeningRegistryV4::default().authorize(model_root, 19).unwrap();
        let mut rejected_runtime = X4cCpuReferenceRuntimeV4;
        let rejected = prove_authenticated_output_link_x4c_v4(
            legacy_permit,
            model_root,
            prover_blocks,
            prefix,
            &mut prover_stream,
            &mut prover_tx,
            X4cSelectedQueryTapeV4::new(selected_draws.clone()).unwrap(),
            &mut rejected_runtime,
            X4cSealConfigV4 {
                design_sha256: X4C_DESIGN_SHA256_V4,
                clean_source_sha256: [0x81; 32],
                response_ordinal: 1,
                arena_layout: X4cArenaLayoutV4::new(7, 3, 4096).unwrap(),
            },
        );
        assert!(matches!(rejected, Err(AuthenticatedOutputErrorV4::EpochMismatch)));

        // Rebuild the one-shot prover state after the deliberate preflight
        // rejection; the rejected call consumed no transcript/correlation.
        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let (pending, m9) = authenticate_pending_aux_prover_v4(
            descriptor,
            auxiliary_value,
            &mut prover_stream,
            M9_DOMAIN,
            &mut prover_tx,
        )
        .unwrap();
        let m9_frames = vec![m9];
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch: 19,
            claim_frames: &[],
            descriptor_digests: &descriptors,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        let blocks = vec![AuthenticatedOutputBlockProverV4 {
            descriptor_digest: descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialProverV4 {
                cohort: &weight,
                slot: 0,
                evaluations: &weight_evaluations,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialProverV4 {
                cohort: &auxiliary,
                slot: 0,
                evaluations: &auxiliary_evaluations,
                target_point: &auxiliary_point,
            },
        }];
        let permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, 19, [0x91; 32])
            .unwrap();
        let mut runtime = X4cCpuReferenceRuntimeV4;
        let (proof, bound_prover, metrics, x4c_metrics, phase_walls, released_draws) =
            prove_authenticated_output_link_x4c_v4(
                permit,
                model_root,
                blocks,
                prefix,
                &mut prover_stream,
                &mut prover_tx,
                X4cSelectedQueryTapeV4::new(selected_draws.clone()).unwrap(),
                &mut runtime,
                X4cSealConfigV4 {
                    design_sha256: X4C_DESIGN_SHA256_V4,
                    clean_source_sha256: [0x81; 32],
                    response_ordinal: 2,
                    arena_layout: X4cArenaLayoutV4::new(7, 3, 4096).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(metrics.fold_bytes, x4c_metrics.global_open.serialized_fold_bytes);
        assert_eq!(
            metrics.packed_opening_bytes,
            x4c_metrics.global_open.serialized_packed_opening_bytes
        );
        assert_eq!(x4c_metrics.execution.query_gather_calls, 1);
        assert_eq!(x4c_metrics.io, Default::default());
        assert_eq!(x4c_metrics.sampling_soundness_credit_bits, 0);
        assert!(phase_walls.seal_wall_ns > 0);
        assert!(phase_walls.open_wall_ns > 0);
        assert_eq!(released_draws, selected_draws);

        let delta = symbol(201);
        let mut ctx = VerifierCtx::new(PCG_SEED, delta);
        let mut verifier_tx = Transcript::new(TX_SEED);
        let pending = authenticate_pending_aux_verifier_v4(
            &m9_frames[0],
            &mut ctx,
            M9_DOMAIN,
            &mut verifier_tx,
        )
        .unwrap();
        let verifier_blocks = vec![AuthenticatedOutputBlockVerifierV4 {
            descriptor_digest: descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialVerifierV4 {
                commitment: weight.commitment(),
                slot: 0,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialVerifierV4 {
                commitment: auxiliary.commitment(),
                slot: 0,
                target_point: &auxiliary_point,
            },
        }];
        let verifier_permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, 19, [0x91; 32])
            .unwrap();
        let bound_verifier = verify_authenticated_output_link_x4c_v4(
            verifier_permit,
            model_root,
            verifier_blocks,
            prefix,
            &proof,
            &selected_draws,
            &mut ctx,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(bound_prover.len(), 1);
        assert_eq!(bound_verifier.len(), 1);
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SyntheticSettlementCounters {
        relation_terms: u64,
        materialized_terms: u64,
        fused_terms: u64,
        source_symbols_read: u64,
        equality_symbols_materialized: u64,
        initial_encoded_symbols_read: u64,
        combined_codeword_symbols: u64,
        query_gather_calls: u64,
    }

    fn synthetic_fused_settlement_counters(responses: usize) -> SyntheticSettlementCounters {
        let descriptor = [0x67; 32];
        let weight_evaluations = (0..16).map(|index| symbol(900 + index)).collect::<Vec<_>>();
        let auxiliary_evaluations = (0..4).map(|index| symbol(980 + 3 * index)).collect::<Vec<_>>();
        let weight_points = (0..responses)
            .map(|index| {
                vec![
                    symbol(1_100 + 5 * index as u64),
                    symbol(1_101 + 7 * index as u64),
                    symbol(1_102 + 11 * index as u64),
                    Fp2::ZERO,
                ]
            })
            .collect::<Vec<_>>();
        let auxiliary_points =
            weight_points.iter().map(|point| vec![point[2], Fp2::ZERO]).collect::<Vec<_>>();
        let weight_values = weight_points
            .iter()
            .map(|point| evaluate_multilinear_table(&weight_evaluations, point).unwrap())
            .collect::<Vec<_>>();
        let auxiliary_values = auxiliary_points
            .iter()
            .map(|point| evaluate_multilinear_table(&auxiliary_evaluations, point).unwrap())
            .collect::<Vec<_>>();
        let public_h = weight_values
            .iter()
            .zip(&auxiliary_values)
            .map(|(weight, auxiliary)| *weight + *auxiliary)
            .collect::<Vec<_>>();
        let weight =
            committed(descriptor, 0xA520_0001, OracleKindV4::WeightExtension, &weight_evaluations);
        let auxiliary =
            committed(descriptor, 0xA520_0100, OracleKindV4::Auxiliary, &auxiliary_evaluations);
        let epoch = 70 + responses as u64;
        let claims = (0..responses)
            .map(|index| ReducedClaimFrame {
                descriptor_digest: descriptor,
                parent_claim_digest: [0x68 + index as u8; 32],
                phase: crate::x4::frame::Phase::Decode,
                phase_ordinal: u16::try_from(index).unwrap(),
                point: vec![symbol(1_200 + index as u64); 14],
                affine_scale: Fp2::ONE,
                auth_domain: 0x6A_000 + index as u64,
            })
            .collect::<Vec<_>>();
        let context = X4dSettlementContextV1 {
            range: crate::x4::deferred_v4::X4dSettlementRangeV1 {
                connection_id: [0x69; 32],
                settlement_epoch: epoch,
                first_claim_index: 0,
                claim_count: u32::try_from(responses).unwrap(),
                starting_accumulator_digest: [0x6A; 32],
                sealed_accumulator_digest: [0x6B; 32],
                ordered_response_nonces: (0..responses)
                    .map(|index| {
                        let mut nonce = [0x6C; 32];
                        nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
                        nonce
                    })
                    .collect(),
            },
        };
        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let mut pending = Vec::with_capacity(responses);
        let mut m9_frames = Vec::with_capacity(responses);
        for (index, value) in auxiliary_values.iter().enumerate() {
            let (pending_aux, frame) = authenticate_pending_aux_prover_v4(
                descriptor,
                *value,
                &mut prover_stream,
                M9_DOMAIN + index as u64,
                &mut prover_tx,
            )
            .unwrap();
            pending.push(pending_aux);
            m9_frames.push(frame);
        }
        let blocks = pending
            .into_iter()
            .enumerate()
            .map(|(index, pending_aux)| AuthenticatedOutputBlockProverV4 {
                descriptor_digest: descriptor,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialProverV4 {
                    cohort: &weight,
                    slot: 0,
                    evaluations: &weight_evaluations,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialProverV4 {
                    cohort: &auxiliary,
                    slot: 0,
                    evaluations: &auxiliary_evaluations,
                    target_point: &auxiliary_points[index],
                },
            })
            .collect::<Vec<_>>();
        let descriptor_inventory = [descriptor];
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch,
            claim_frames: &claims,
            descriptor_digests: &descriptor_inventory,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        let model_root = [0x6D; 32];
        let permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, epoch, [0x6E; 32])
            .unwrap();
        let mut runtime = X4cCpuReferenceRuntimeV4;
        let (_, _, metrics, x4c_metrics, _, _) = prove_authenticated_output_link_x4d_v4(
            permit,
            model_root,
            blocks,
            prefix,
            &context,
            &mut prover_stream,
            &mut prover_tx,
            X4dSettlementQuerySeedV1::new([0x6F; 32]).unwrap(),
            &mut runtime,
            X4cSealConfigV4 {
                design_sha256: X4C_DESIGN_SHA256_V4,
                clean_source_sha256: [0x70; 32],
                response_ordinal: responses as u64,
                arena_layout: X4cArenaLayoutV4::new(7, 3, 4096).unwrap(),
            },
        )
        .unwrap();
        SyntheticSettlementCounters {
            relation_terms: metrics.sumcheck_relation_terms,
            materialized_terms: metrics.sumcheck_materialized_terms,
            fused_terms: metrics.sumcheck_fused_terms,
            source_symbols_read: metrics.sumcheck_source_symbols_read,
            equality_symbols_materialized: metrics.sumcheck_equality_symbols_materialized,
            initial_encoded_symbols_read: x4c_metrics.global_open.initial_encoded_symbols_read,
            combined_codeword_symbols: x4c_metrics.global_open.combined_codeword_symbols,
            query_gather_calls: x4c_metrics.execution.query_gather_calls,
        }
    }

    #[test]
    fn fused_settlement_counters_are_flat_at_k1_and_k16() {
        let k1 = synthetic_fused_settlement_counters(1);
        let k16 = synthetic_fused_settlement_counters(16);
        assert_eq!(k1.relation_terms, 2);
        assert_eq!(k16.relation_terms, 32);
        assert_eq!(k1.materialized_terms, 2);
        assert_eq!(k16.materialized_terms, 2);
        assert_eq!(k1.fused_terms, 0);
        assert_eq!(k16.fused_terms, 30);
        assert_eq!(k1.source_symbols_read, 20);
        assert_eq!(k1.equality_symbols_materialized, 20);
        assert_eq!(k1.source_symbols_read, k16.source_symbols_read);
        assert_eq!(k1.equality_symbols_materialized, k16.equality_symbols_materialized);
        assert_eq!(k1.initial_encoded_symbols_read, k16.initial_encoded_symbols_read);
        assert_eq!(k1.combined_codeword_symbols, k16.combined_codeword_symbols);
        assert_eq!(k1.query_gather_calls, 1);
        assert_eq!(k16.query_gather_calls, 1);
    }

    #[test]
    fn x4d_two_response_settlement_reuses_one_chain_and_binds_exact_union() {
        let descriptor = [0x47; 32];
        let weight_evaluations = (0..16).map(|index| symbol(210 + index)).collect::<Vec<_>>();
        let auxiliary_evaluations = (0..4).map(|index| symbol(280 + 3 * index)).collect::<Vec<_>>();
        let weight_points = [
            vec![symbol(17), symbol(21), symbol(23), Fp2::ZERO],
            vec![symbol(31), symbol(37), symbol(41), Fp2::ZERO],
        ];
        let auxiliary_points = [vec![symbol(23), Fp2::ZERO], vec![symbol(41), Fp2::ZERO]];
        let weight_values = weight_points
            .iter()
            .map(|point| evaluate_multilinear_table(&weight_evaluations, point).unwrap())
            .collect::<Vec<_>>();
        let auxiliary_values = auxiliary_points
            .iter()
            .map(|point| evaluate_multilinear_table(&auxiliary_evaluations, point).unwrap())
            .collect::<Vec<_>>();
        let public_h = weight_values
            .iter()
            .zip(&auxiliary_values)
            .map(|(weight, auxiliary)| *weight + *auxiliary)
            .collect::<Vec<_>>();
        let descriptor_inventory = vec![descriptor];
        let weight =
            committed(descriptor, 0xA500_0001, OracleKindV4::WeightExtension, &weight_evaluations);
        let auxiliary =
            committed(descriptor, 0xA500_0100, OracleKindV4::Auxiliary, &auxiliary_evaluations);
        let manifest = crate::x4::manifest_v4::ManifestTreeV4::build(
            crate::x4::frame_v4::manifest_id_digest_v4(MODEL_CONFIG_DIGEST, WEIGHTS_DIGEST, 29),
            vec![crate::x4::frame::ManifestLeafFrame {
                descriptor_digest: descriptor,
                ordered_roots: vec![weight.commitment().root, auxiliary.commitment().root],
            }],
        )
        .unwrap();
        let model_root = manifest.root();
        let claims = (0..2u16)
            .map(|ordinal| ReducedClaimFrame {
                descriptor_digest: descriptor,
                parent_claim_digest: [0x51 + ordinal as u8; 32],
                phase: crate::x4::frame::Phase::Decode,
                phase_ordinal: ordinal,
                point: vec![symbol(500 + u64::from(ordinal)); 14],
                affine_scale: Fp2::ONE,
                auth_domain: 0x64_000 + u64::from(ordinal),
            })
            .collect::<Vec<_>>();
        let context = X4dSettlementContextV1 {
            range: crate::x4::deferred_v4::X4dSettlementRangeV1 {
                connection_id: [0x52; 32],
                settlement_epoch: 29,
                first_claim_index: 0,
                claim_count: 2,
                starting_accumulator_digest: [0x53; 32],
                sealed_accumulator_digest: [0x54; 32],
                ordered_response_nonces: vec![[0x55; 32], [0x56; 32]],
            },
        };
        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let mut pending_prover = Vec::new();
        let mut m9_frames = Vec::new();
        for (index, value) in auxiliary_values.iter().enumerate() {
            let (pending, frame) = authenticate_pending_aux_prover_v4(
                descriptor,
                *value,
                &mut prover_stream,
                M9_DOMAIN + index as u64,
                &mut prover_tx,
            )
            .unwrap();
            pending_prover.push(pending);
            m9_frames.push(frame);
        }
        let prover_blocks = pending_prover
            .into_iter()
            .enumerate()
            .map(|(index, pending_aux)| AuthenticatedOutputBlockProverV4 {
                descriptor_digest: descriptor,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialProverV4 {
                    cohort: &weight,
                    slot: 0,
                    evaluations: &weight_evaluations,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialProverV4 {
                    cohort: &auxiliary,
                    slot: 0,
                    evaluations: &auxiliary_evaluations,
                    target_point: &auxiliary_points[index],
                },
            })
            .collect::<Vec<_>>();
        let prefix = AuthenticatedOutputLinkPrefixV4 {
            epoch: 29,
            claim_frames: &claims,
            descriptor_digests: &descriptor_inventory,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        authenticated_output_link_schedule_digest_x4d_v1(
            &context,
            &claims,
            &descriptor_inventory,
            &public_h,
            &m9_frames,
            4,
            &LINK_DOMAINS,
        )
        .unwrap();
        let prover_permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, 29, [0x57; 32])
            .unwrap();
        let mut runtime = X4cCpuReferenceRuntimeV4;
        let (proof, bound_prover, metrics, x4c_metrics, _, released_draws) =
            prove_authenticated_output_link_x4d_v4(
                prover_permit,
                model_root,
                prover_blocks,
                prefix,
                &context,
                &mut prover_stream,
                &mut prover_tx,
                X4dSettlementQuerySeedV1::new([0x59; 32]).unwrap(),
                &mut runtime,
                X4cSealConfigV4 {
                    design_sha256: X4C_DESIGN_SHA256_V4,
                    clean_source_sha256: [0x58; 32],
                    response_ordinal: 1,
                    arena_layout: X4cArenaLayoutV4::new(7, 3, 4096).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(proof.frame.relation_count, 4);
        assert_eq!(metrics.sumcheck_relation_terms, 4);
        assert_eq!(metrics.sumcheck_materialized_terms, 2);
        assert_eq!(metrics.sumcheck_fused_terms, 2);
        assert_eq!(metrics.sumcheck_source_symbols_read, 20);
        assert_eq!(metrics.sumcheck_equality_symbols_materialized, 20);
        assert_eq!(proof.global_folding.packed_opening.initial_groups.len(), 2);
        assert_eq!(x4c_metrics.execution.query_gather_calls, 1);
        assert_eq!(released_draws.len(), crate::x4::frame_v4::PRODUCTION_QUERY_COUNT_V4);
        assert!(released_draws.iter().all(|draw| *draw < 128));

        let delta = symbol(301);
        let mut verifier = VerifierCtx::new(PCG_SEED, delta);
        let mut verifier_tx = Transcript::new(TX_SEED);
        let pending_verifier = m9_frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                authenticate_pending_aux_verifier_v4(
                    frame,
                    &mut verifier,
                    M9_DOMAIN + index as u64,
                    &mut verifier_tx,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let verifier_blocks = pending_verifier
            .into_iter()
            .enumerate()
            .map(|(index, pending_aux)| AuthenticatedOutputBlockVerifierV4 {
                descriptor_digest: descriptor,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialVerifierV4 {
                    commitment: weight.commitment(),
                    slot: 0,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialVerifierV4 {
                    commitment: auxiliary.commitment(),
                    slot: 0,
                    target_point: &auxiliary_points[index],
                },
            })
            .collect::<Vec<_>>();
        let verifier_permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, 29, [0x57; 32])
            .unwrap();
        let bound_verifier = verify_authenticated_output_link_x4d_v4(
            verifier_permit,
            model_root,
            verifier_blocks,
            prefix,
            &context,
            &proof,
            &released_draws,
            &mut verifier,
            &mut verifier_tx,
        )
        .unwrap();
        let prover_weight = weight_values
            .iter()
            .enumerate()
            .map(|(index, value)| ProverAuthed { x: *value, m: symbol(400 + index as u64) })
            .collect::<Vec<_>>();
        let verifier_weight = prover_weight
            .iter()
            .map(|value| VerifierKey { k: value.m + delta * value.x })
            .collect::<Vec<_>>();
        let zero = prove_bound_response_zero_batch_v4(
            &prover_weight,
            &bound_prover,
            &public_h,
            &mut prover_stream,
            ZERO_DOMAIN,
            &mut prover_tx,
        )
        .unwrap();
        verify_bound_response_zero_batch_v4(
            &verifier_weight,
            &bound_verifier,
            &public_h,
            &zero,
            &mut verifier,
            ZERO_DOMAIN,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());

        let mut wrong_context = context.clone();
        wrong_context.range.ordered_response_nonces.reverse();
        let mut rejected_verifier = VerifierCtx::new(PCG_SEED, delta);
        let mut rejected_tx = Transcript::new(TX_SEED);
        let rejected_pending = m9_frames
            .iter()
            .enumerate()
            .map(|(index, frame)| {
                authenticate_pending_aux_verifier_v4(
                    frame,
                    &mut rejected_verifier,
                    M9_DOMAIN + index as u64,
                    &mut rejected_tx,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let rejected_blocks = rejected_pending
            .into_iter()
            .enumerate()
            .map(|(index, pending_aux)| AuthenticatedOutputBlockVerifierV4 {
                descriptor_digest: descriptor,
                public_h: public_h[index],
                pending_aux,
                weight_extension: LinkPolynomialVerifierV4 {
                    commitment: weight.commitment(),
                    slot: 0,
                    target_point: &weight_points[index],
                },
                auxiliary: LinkPolynomialVerifierV4 {
                    commitment: auxiliary.commitment(),
                    slot: 0,
                    target_point: &auxiliary_points[index],
                },
            })
            .collect::<Vec<_>>();
        let rejected_permit = X4OpeningRegistryV4::default()
            .authorize_after_persistent_freshness(model_root, 29, [0x57; 32])
            .unwrap();
        assert!(verify_authenticated_output_link_x4d_v4(
            rejected_permit,
            model_root,
            rejected_blocks,
            prefix,
            &wrong_context,
            &proof,
            &released_draws,
            &mut rejected_verifier,
            &mut rejected_tx,
        )
        .is_err());
    }

    #[test]
    fn v4_schedule_link_global_chain_and_packed_tampers_reject() {
        let generated = generate();
        let mut bad_h = generated.public_h.clone();
        bad_h[0] += Fp2::ONE;
        assert!(verify_with(
            &generated,
            &generated.proof,
            &generated.descriptors,
            &bad_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
        let mut bad = generated.proof.clone();
        bad.frame.ordered_round_correction_symbols[0] += Fp2::ONE;
        assert!(verify_with(
            &generated,
            &bad,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
        let mut bad = generated.proof.clone();
        bad.frame.terminal_opened_tag_symbol += Fp2::ONE;
        assert!(verify_with(
            &generated,
            &bad,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
        let mut bad = generated.proof.clone();
        bad.global_folding.fold_frames[0].root_digest[0] ^= 1;
        assert!(verify_with(
            &generated,
            &bad,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
        let mut bad = generated.proof.clone();
        bad.global_folding.packed_opening.initial_groups[1].opened_symbols[0] += Fp2::ONE;
        assert!(verify_with(
            &generated,
            &bad,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
        let mut bad = generated.proof.clone();
        bad.global_folding.packed_opening.opening_schedule_digest[0] ^= 1;
        assert!(verify_with(
            &generated,
            &bad,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());
    }

    #[test]
    fn v4_delta_shift_class_and_beta_collision_remain_negative_artifacts() {
        let generated = generate();
        for delta in 1..=32 {
            let mut shifted_m9 = generated.m9_frames.clone();
            shifted_m9[0].mask_correction_symbol += Fp2::from_base(Fp::new(delta));
            let mut shifted_proof = generated.proof.clone();
            shifted_proof.frame.link_schedule_digest =
                authenticated_output_link_schedule_digest_v4(
                    9,
                    &[],
                    &generated.descriptors,
                    &generated.public_h,
                    &shifted_m9,
                    4,
                    &LINK_DOMAINS,
                )
                .unwrap();
            assert!(verify_with(
                &generated,
                &shifted_proof,
                &generated.descriptors,
                &generated.public_h,
                &shifted_m9,
                &LINK_DOMAINS,
            )
            .is_err());
        }

        let committed_w = Fp2::from_base(Fp::new(3));
        let committed_g = Fp2::from_base(Fp::new(5));
        let public_h = Fp2::from_base(Fp::new(7));
        let authenticated_s = Fp2::from_base(Fp::new(6));
        let masked_residual = committed_w + committed_g - public_h;
        let output_residual = committed_g - authenticated_s;
        assert!(beta_collision_is_link_bad_v4(masked_residual, output_residual, Fp2::ONE));
        assert_eq!(x4_v4_seam_full_correlations(1660, 30).unwrap(), 1721);
        assert_eq!(x4_v4_seam_frame_bytes(1660, 30).unwrap(), 107_319);

        let mut registry = X4OpeningRegistryV4::default();
        let root = [0xE5; 32];
        let permit = registry.authorize(root, 17).unwrap();
        assert_eq!(permit.model_root(), root);
        assert_eq!(permit.epoch(), 17);
        assert!(registry.has_opened(root, 17));
        assert!(matches!(
            registry.authorize(root, 17),
            Err(AuthenticatedOutputErrorV4::EpochAlreadyOpened)
        ));

        let persistent_root = [0xE6; 32];
        assert!(matches!(
            registry.authorize_after_persistent_freshness(persistent_root, 18, [0; 32]),
            Err(AuthenticatedOutputErrorV4::InvalidGeometry(_))
        ));
        let receipt = [0xA7; 32];
        let permit =
            registry.authorize_after_persistent_freshness(persistent_root, 18, receipt).unwrap();
        assert_eq!(permit.persistent_freshness_record_digest(), Some(receipt));
    }
}
