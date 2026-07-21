//! Blind M9 seam for the schema-4 model-global folding PCS.
//!
//! Corrections create only pending values.  The sole Pending-to-Bound
//! transition closes a delayed-variable blind sumcheck against the final
//! scalar of the commitment's own sealed global fold/query chain.  No target
//! evaluation or prover assertion is an accepted substitute.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use volta_field::Fp2;
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_prover,
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::mle::{eq_points, eq_vec, fold_low, lagrange3};

use super::folding_v4::{
    global_fold_descriptor_digest_v4, opened_global_value_from_lines_v4,
    verify_global_folding_interactive_v4, FoldingErrorV4, GlobalChainDraftV4, GlobalFoldingProofV4,
    GlobalOpenMetricsV4, GlobalProverGroupV4, GlobalVerifierGroupV4, ModelGlobalOpeningSourceV4,
};
use super::frame::{
    AuthenticatedOutputLinkFrame, Digest, FrameError, M9TransferFrame, ReducedClaimFrame,
    ResponseZeroBatchFrame,
};
use super::frame_v4::{authenticated_output_link_schedule_digest_v4, FrameV4, OracleKindV4};

pub const GLOBAL_FOLD_COHORT_ID_V4: u32 = 0xA500_F001;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticatedOutputErrorV4 {
    Frame(FrameError),
    Folding(FoldingErrorV4),
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
        Ok(X4OpeningPermitV4 { model_root, epoch })
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
    pub sumcheck_source_symbols_read: u64,
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
}

struct SumcheckProverOutputV4 {
    corrections: Vec<Fp2>,
    point: Vec<Fp2>,
    final_claim: ProverAuthed,
    terminal_value: Fp2,
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
    for round in 0..round_count {
        let mut at_zero = Fp2::ZERO;
        let mut at_two = Fp2::ZERO;
        for term in &terms {
            let (term_zero, term_two) = term.round_values()?;
            at_zero += term_zero;
            at_two += term_two;
        }
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
        for term in &mut terms {
            term.bind(challenge);
        }
        point.push(challenge);
    }
    let terminal_value = terms.iter().try_fold(Fp2::ZERO, |sum, term| {
        Ok::<_, AuthenticatedOutputErrorV4>(sum + term.terminal()?)
    })?;
    if terminal_value != claim.x {
        return Err(AuthenticatedOutputErrorV4::SumcheckTerminalMismatch);
    }
    Ok(SumcheckProverOutputV4 { corrections, point, final_claim: claim, terminal_value })
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
    descriptors: &[Digest],
    public_h: &[Fp2],
    round_count: usize,
) -> Result<Digest, AuthenticatedOutputErrorV4> {
    if descriptors.is_empty()
        || descriptors.len() > 1660
        || prefix.descriptor_digests != descriptors
        || prefix.ordered_h_symbols != public_h
        || prefix.m9_frames.len() != descriptors.len()
        || descriptors.iter().copied().collect::<BTreeSet<_>>().len() != descriptors.len()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 authenticated-output prefix"));
    }
    for (descriptor, frame) in descriptors.iter().zip(prefix.m9_frames) {
        if descriptor != &frame.descriptor_digest {
            return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 M9 descriptor order"));
        }
    }
    if prefix.claim_frames.len() > 3320
        || prefix.claim_frames.iter().any(|claim| !descriptors.contains(&claim.descriptor_digest))
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link reduced claims"));
    }
    validate_domains_v4(prefix.round_correlation_domain_ids, round_count)?;
    Ok(authenticated_output_link_schedule_digest_v4(
        prefix.epoch,
        prefix.claim_frames,
        prefix.descriptor_digests,
        prefix.ordered_h_symbols,
        prefix.m9_frames,
        u8::try_from(round_count).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?,
        prefix.round_correlation_domain_ids,
    )?)
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
) -> Result<(), AuthenticatedOutputErrorV4> {
    let key = LinkCohortKeyV4::from_cohort(polynomial.cohort);
    let entry = groups.entry(key).or_insert_with(|| ProverGroupV4 {
        cohort: polynomial.cohort,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.cohort.commitment().root != polynomial.cohort.commitment().root
        || entry.weights.insert(polynomial.slot, weight).is_some()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule("v4 link prover cohort grouping"));
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
) -> Result<(), AuthenticatedOutputErrorV4> {
    let key = verifier_key_v4(polynomial);
    let entry = groups.entry(key).or_insert_with(|| VerifierGroupV4 {
        commitment: polynomial.commitment,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.commitment.root != polynomial.commitment.root
        || entry.weights.insert(polynomial.slot, weight).is_some()
    {
        return Err(AuthenticatedOutputErrorV4::InvalidSchedule(
            "v4 link verifier cohort grouping",
        ));
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
    let schedule_digest = validate_prefix_common_v4(prefix, &descriptors, &public_h, round_count)?;
    let keys = prover_keys_v4(&blocks);

    // All roots, h values and M9 corrections are fixed before this vector of
    // verifier challenges.  Cohort activations and relation atoms share the
    // same coefficients, so the final MAC claim and global chain are one
    // linear functional rather than two independently shiftable promises.
    let beta = tx.challenge_fp2();
    let activation = activation_challenges_v4(&keys, tx);
    let mut power = beta;
    let mut initial_claim = ProverAuthed::ZERO;
    let mut terms = Vec::with_capacity(2 * blocks.len());
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
        terms.push(DelayedSumcheckTermV4::new(
            masked_coefficient,
            block.weight_extension.evaluations,
            block.weight_extension.target_point,
            round_count,
        )?);
        terms.push(DelayedSumcheckTermV4::new(
            auxiliary_coefficient,
            block.auxiliary.evaluations,
            block.auxiliary.target_point,
            round_count,
        )?);
        bases.push((weight_base, auxiliary_base));
        power = auxiliary_base * beta;
    }
    let sumcheck = prove_delayed_sumcheck_v4(
        terms,
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
        )?;
        insert_prover_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &sumcheck.point),
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
        sumcheck_source_symbols_read: blocks.iter().try_fold(0u64, |sum, block| {
            let count = block
                .weight_extension
                .evaluations
                .len()
                .checked_add(block.auxiliary.evaluations.len())
                .ok_or(AuthenticatedOutputErrorV4::Overflow)?;
            sum.checked_add(u64::try_from(count).map_err(|_| AuthenticatedOutputErrorV4::Overflow)?)
                .ok_or(AuthenticatedOutputErrorV4::Overflow)
        })?,
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
    let expected_digest = validate_prefix_common_v4(prefix, &descriptors, &public_h, round_count)?;
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
        )?;
        insert_verifier_group_v4(
            &mut grouped,
            &block.auxiliary,
            terminal_weight_v4(*auxiliary_base, block.auxiliary.target_point, &point),
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
    }
}
