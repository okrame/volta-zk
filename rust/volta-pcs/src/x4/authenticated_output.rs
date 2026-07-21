//! Blind authenticated-output link for the X4 v3 M9 seam.
//!
//! An M9 correction creates only a [`PendingAuxEvalProver`] or
//! [`PendingAuxEvalVerifier`].  The opaque bound types have no public
//! constructor; they are returned only after the dual-relation blind
//! sumcheck is closed by the commitment's own weighted UD fold/query
//! verification.  Individual target evaluations are never proof fields.

use std::collections::{BTreeMap, BTreeSet};

use volta_field::Fp2;
use volta_mac::{
    fresh_zero_mask, zero_batch_prover, zero_batch_verify, zero_mask_key, zero_open_prover,
    zero_open_verify, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};
use volta_proto::mle::{eq_points, eq_vec, fold_low, lagrange3};

use super::folding::{
    verify_ud_folding_weighted, FoldingError, UdChallenges, UdCohortCommitment, UdFoldingProof,
    UdOpenMetrics, UdWeightedOpeningSource, PRODUCTION_QUERY_COUNT,
};
use super::frame::{
    authenticated_output_link_schedule_digest, AuthenticatedOutputLinkFrame, Digest, Frame,
    FrameError, M9TransferFrame, OracleKind, ReducedClaimFrame, ResponseZeroBatchFrame,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthenticatedOutputError {
    Frame(FrameError),
    Folding(FoldingError),
    InvalidGeometry(&'static str),
    InvalidSchedule(&'static str),
    FalseInitialClaim,
    TerminalMismatch,
    LinkRejected,
    ZeroBatchRejected,
    EpochAlreadyOpened,
    EpochMismatch,
    Overflow,
}

impl From<FrameError> for AuthenticatedOutputError {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<FoldingError> for AuthenticatedOutputError {
    fn from(value: FoldingError) -> Self {
        Self::Folding(value)
    }
}

/// Prover half of an auxiliary evaluation that is authenticated but not yet
/// bound to the committed auxiliary polynomial.
#[derive(Debug)]
pub struct PendingAuxEvalProver {
    descriptor_digest: Digest,
    auth: ProverAuthed,
}

/// Verifier half of an auxiliary evaluation that is authenticated but not yet
/// bound to the committed auxiliary polynomial.
#[derive(Debug)]
pub struct PendingAuxEvalVerifier {
    descriptor_digest: Digest,
    key: VerifierKey,
}

/// Prover half accepted by the v3 authenticated-output opening.  Its fields
/// are intentionally private: only this module's successful link path can
/// construct it.
#[derive(Debug)]
pub struct BoundAuxEvalProver {
    descriptor_digest: Digest,
    auth: ProverAuthed,
}

/// Verifier half accepted by the v3 authenticated-output opening.
#[derive(Debug)]
pub struct BoundAuxEvalVerifier {
    descriptor_digest: Digest,
    key: VerifierKey,
}

impl BoundAuxEvalProver {
    pub fn descriptor_digest(&self) -> Digest {
        self.descriptor_digest
    }

    pub fn authenticated(&self) -> ProverAuthed {
        self.auth
    }
}

impl BoundAuxEvalVerifier {
    pub fn descriptor_digest(&self) -> Digest {
        self.descriptor_digest
    }

    pub fn key(&self) -> VerifierKey {
        self.key
    }
}

/// Consume one fresh full correlation and emit the ordinary 64-byte M9 frame.
/// The result is pending; there is deliberately no correction-to-bound API.
pub fn authenticate_pending_aux_prover(
    descriptor_digest: Digest,
    secret: Fp2,
    stream: &mut CorrelationStream,
    correlation_domain: u64,
    tx: &mut Transcript,
) -> Result<(PendingAuxEvalProver, M9TransferFrame), AuthenticatedOutputError> {
    let correlation = stream.draw_fulls(correlation_domain, 1)[0];
    let frame =
        M9TransferFrame { descriptor_digest, mask_correction_symbol: secret - correlation.x };
    let bytes = Frame::M9Transfer(frame.clone()).encode()?.len();
    tx.append(
        "x4_m9_transfer_frame",
        u64::try_from(bytes).map_err(|_| AuthenticatedOutputError::Overflow)?,
    );
    Ok((
        PendingAuxEvalProver {
            descriptor_digest,
            auth: ProverAuthed { x: secret, m: correlation.m },
        },
        frame,
    ))
}

/// Mirror one M9 correction into the verifier key.  This still returns only a
/// pending value.
pub fn authenticate_pending_aux_verifier(
    frame: &M9TransferFrame,
    ctx: &mut VerifierCtx,
    correlation_domain: u64,
    tx: &mut Transcript,
) -> Result<PendingAuxEvalVerifier, AuthenticatedOutputError> {
    frame.validate()?;
    let key =
        ctx.expand_full_keys(correlation_domain, 1)[0] + ctx.delta * frame.mask_correction_symbol;
    let bytes = Frame::M9Transfer(frame.clone()).encode()?.len();
    tx.append(
        "x4_m9_transfer_frame",
        u64::try_from(bytes).map_err(|_| AuthenticatedOutputError::Overflow)?,
    );
    Ok(PendingAuxEvalVerifier {
        descriptor_digest: frame.descriptor_digest,
        key: VerifierKey { k: key },
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkCohortKey {
    pub cohort_id: u32,
    pub oracle_kind: OracleKind,
    pub root: Digest,
}

impl LinkCohortKey {
    pub fn from_commitment(commitment: &UdCohortCommitment) -> Self {
        Self {
            cohort_id: commitment.config.identity.cohort_id,
            oracle_kind: commitment.config.identity.oracle_kind,
            root: commitment.root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkCohortChallenges {
    pub key: LinkCohortKey,
    /// `combine` is canonically zero in this exact-weight path and is never a
    /// prover-selected slot-combination challenge.
    pub challenges: UdChallenges,
}

pub struct LinkPolynomialProver<'a> {
    pub cohort: &'a dyn UdWeightedOpeningSource,
    pub slot: u16,
    /// Boolean-hypercube evaluations used by the sumcheck.  They are prover
    /// state and are absent from [`AuthenticatedOutputLinkProof`].
    pub evaluations: &'a [Fp2],
    pub target_point: &'a [Fp2],
}

pub struct LinkPolynomialVerifier<'a> {
    pub commitment: &'a UdCohortCommitment,
    pub slot: u16,
    pub target_point: &'a [Fp2],
}

pub struct AuthenticatedOutputBlockProver<'a> {
    pub descriptor_digest: Digest,
    pub public_h: Fp2,
    pub pending_aux: PendingAuxEvalProver,
    pub weight_extension: LinkPolynomialProver<'a>,
    pub auxiliary: LinkPolynomialProver<'a>,
}

pub struct AuthenticatedOutputBlockVerifier<'a> {
    pub descriptor_digest: Digest,
    pub public_h: Fp2,
    pub pending_aux: PendingAuxEvalVerifier,
    pub weight_extension: LinkPolynomialVerifier<'a>,
    pub auxiliary: LinkPolynomialVerifier<'a>,
}

#[derive(Clone, Copy)]
pub struct AuthenticatedOutputLinkPrefix<'a> {
    pub epoch: u64,
    pub claim_frames: &'a [ReducedClaimFrame],
    pub descriptor_digests: &'a [Digest],
    pub ordered_h_symbols: &'a [Fp2],
    pub m9_frames: &'a [M9TransferFrame],
    /// Exact ordered `(round at 0, round at 2, ...)` full-correlation domain
    /// ids.  They are reconstructed statement data, not proof metadata.
    pub round_correlation_domain_ids: &'a [u64],
}

#[derive(Default)]
pub struct X4OpeningRegistry {
    opened: BTreeSet<(Digest, u64)>,
}

/// One-shot authority for exactly one response opening of a static model
/// commitment epoch.  Fields are private and the token is not clonable.
pub struct X4OpeningPermit {
    model_root: Digest,
    epoch: u64,
}

impl X4OpeningRegistry {
    pub fn authorize(
        &mut self,
        model_root: Digest,
        epoch: u64,
    ) -> Result<X4OpeningPermit, AuthenticatedOutputError> {
        if !self.opened.insert((model_root, epoch)) {
            return Err(AuthenticatedOutputError::EpochAlreadyOpened);
        }
        Ok(X4OpeningPermit { model_root, epoch })
    }

    pub fn has_opened(&self, model_root: Digest, epoch: u64) -> bool {
        self.opened.contains(&(model_root, epoch))
    }
}

impl X4OpeningPermit {
    pub fn model_root(&self) -> Digest {
        self.model_root
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkCohortOpeningProof {
    pub key: LinkCohortKey,
    pub touched_slots: Vec<u16>,
    pub folding: UdFoldingProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedOutputLinkProof {
    pub frame: AuthenticatedOutputLinkFrame,
    pub cohort_openings: Vec<LinkCohortOpeningProof>,
}

impl AuthenticatedOutputLinkProof {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthenticatedOutputError> {
        let mut bytes = Frame::AuthenticatedOutputLink(self.frame.clone()).encode()?;
        for opening in &self.cohort_openings {
            bytes.extend(opening.folding.canonical_bytes()?);
        }
        Ok(bytes)
    }

    pub fn fold_frames(&self) -> impl Iterator<Item = &super::frame::FoldCommitmentFrame> {
        self.cohort_openings.iter().flat_map(|opening| opening.folding.fold_frames.iter())
    }

    pub fn query_frames(&self) -> impl Iterator<Item = &super::frame::CohortMultiproofFrame> {
        self.cohort_openings.iter().flat_map(|opening| opening.folding.query_frames.iter())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthenticatedOutputLinkMetrics {
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
    pub query_bytes: u64,
    pub sumcheck_source_symbols_read: u64,
    pub source_coefficients_read: u64,
    pub encoded_symbols_read: u64,
    pub folded_symbols_written: u64,
}

pub fn x4_v3_seam_full_correlations(
    touched_blocks: usize,
    rounds: usize,
) -> Result<u64, AuthenticatedOutputError> {
    if touched_blocks == 0 || touched_blocks > 1660 || rounds == 0 || rounds > 30 {
        return Err(AuthenticatedOutputError::InvalidGeometry("v3 seam correlations"));
    }
    u64::try_from(
        touched_blocks
            .checked_add(2usize.checked_mul(rounds).ok_or(AuthenticatedOutputError::Overflow)?)
            .and_then(|value| value.checked_add(1))
            .ok_or(AuthenticatedOutputError::Overflow)?,
    )
    .map_err(|_| AuthenticatedOutputError::Overflow)
}

pub fn x4_v3_seam_frame_bytes(
    touched_blocks: usize,
    rounds: usize,
) -> Result<u64, AuthenticatedOutputError> {
    if touched_blocks == 0 || touched_blocks > 1660 || rounds == 0 || rounds > 30 {
        return Err(AuthenticatedOutputError::InvalidGeometry("v3 seam frame bytes"));
    }
    let m9 = 64usize.checked_mul(touched_blocks).ok_or(AuthenticatedOutputError::Overflow)?;
    let round_bytes = 32usize.checked_mul(rounds).ok_or(AuthenticatedOutputError::Overflow)?;
    u64::try_from(
        m9.checked_add(119)
            .and_then(|value| value.checked_add(round_bytes))
            .ok_or(AuthenticatedOutputError::Overflow)?,
    )
    .map_err(|_| AuthenticatedOutputError::Overflow)
}

#[derive(Clone)]
struct SumcheckTerm {
    coefficient: Fp2,
    evaluations: Vec<Fp2>,
    equality: Vec<Fp2>,
    virtual_factor: Fp2,
}

impl SumcheckTerm {
    fn new(
        coefficient: Fp2,
        evaluations: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<Self, AuthenticatedOutputError> {
        if target_point.is_empty()
            || evaluations.len() != 1usize.checked_shl(target_point.len() as u32).unwrap_or(0)
        {
            return Err(AuthenticatedOutputError::InvalidGeometry("link polynomial table"));
        }
        Ok(Self {
            coefficient,
            evaluations: evaluations.to_vec(),
            equality: eq_vec(target_point),
            virtual_factor: Fp2::ONE,
        })
    }

    fn initial_sum(&self) -> Fp2 {
        self.evaluations
            .iter()
            .zip(&self.equality)
            .fold(Fp2::ZERO, |sum, (value, equality)| sum + self.coefficient * *value * *equality)
    }

    fn round_values(&self) -> Result<(Fp2, Fp2), AuthenticatedOutputError> {
        if self.evaluations.len() != self.equality.len() || self.evaluations.is_empty() {
            return Err(AuthenticatedOutputError::InvalidGeometry("link sumcheck state"));
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
        if self.evaluations.len() == 1 {
            self.virtual_factor = self.virtual_factor * (Fp2::ONE - challenge);
        } else {
            fold_low(&mut self.evaluations, challenge);
            fold_low(&mut self.equality, challenge);
        }
    }

    fn terminal(&self) -> Result<Fp2, AuthenticatedOutputError> {
        if self.evaluations.len() != 1 || self.equality.len() != 1 {
            return Err(AuthenticatedOutputError::InvalidGeometry("link terminal state"));
        }
        Ok(self.coefficient * self.evaluations[0] * self.equality[0] * self.virtual_factor)
    }
}

struct SumcheckProverOutput {
    corrections: Vec<Fp2>,
    point: Vec<Fp2>,
    final_claim: ProverAuthed,
    terminal_value: Fp2,
}

fn prove_blind_multi_term_sumcheck(
    mut terms: Vec<SumcheckTerm>,
    round_count: usize,
    initial_claim: ProverAuthed,
    stream: &mut CorrelationStream,
    domains: &[u64],
    tx: &mut Transcript,
) -> Result<SumcheckProverOutput, AuthenticatedOutputError> {
    if round_count == 0 || round_count > 30 || domains.len() != 2 * round_count {
        return Err(AuthenticatedOutputError::InvalidGeometry("link round schedule"));
    }
    let initial_sum = terms.iter().fold(Fp2::ZERO, |sum, term| sum + term.initial_sum());
    if initial_sum != initial_claim.x {
        return Err(AuthenticatedOutputError::FalseInitialClaim);
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
        tx.append("x4_auth_output_link_round_corrections", 32);

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
        Ok::<_, AuthenticatedOutputError>(sum + term.terminal()?)
    })?;
    if terminal_value != claim.x {
        return Err(AuthenticatedOutputError::TerminalMismatch);
    }
    Ok(SumcheckProverOutput { corrections, point, final_claim: claim, terminal_value })
}

fn verify_blind_multi_term_sumcheck(
    round_count: usize,
    initial_key: VerifierKey,
    corrections: &[Fp2],
    ctx: &mut VerifierCtx,
    domains: &[u64],
    tx: &mut Transcript,
) -> Result<(Vec<Fp2>, VerifierKey), AuthenticatedOutputError> {
    if round_count == 0
        || round_count > 30
        || corrections.len() != 2 * round_count
        || domains.len() != 2 * round_count
    {
        return Err(AuthenticatedOutputError::InvalidGeometry("link verifier rounds"));
    }
    let mut claim = initial_key;
    let mut point = Vec::with_capacity(round_count);
    for round in 0..round_count {
        let key_zero =
            ctx.expand_full_keys(domains[2 * round], 1)[0] + ctx.delta * corrections[2 * round];
        let key_two = ctx.expand_full_keys(domains[2 * round + 1], 1)[0]
            + ctx.delta * corrections[2 * round + 1];
        tx.append("x4_auth_output_link_round_corrections", 32);
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

fn validate_domains(domains: &[u64], round_count: usize) -> Result<(), AuthenticatedOutputError> {
    if domains.len() != 2 * round_count || !domains.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(AuthenticatedOutputError::InvalidSchedule("link correlation domains"));
    }
    Ok(())
}

fn validate_canonical_points(weight: &[Fp2], auxiliary: &[Fp2]) -> bool {
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

fn validate_prover_polynomial(
    descriptor: Digest,
    expected_kind: OracleKind,
    polynomial: &LinkPolynomialProver<'_>,
) -> Result<(), AuthenticatedOutputError> {
    let commitment = polynomial.cohort.commitment();
    if commitment.config.identity.oracle_kind != expected_kind
        || commitment.config.identity.fold_round != 0
        || commitment.config.slot_descriptors.get(usize::from(polynomial.slot)).copied().flatten()
            != Some(descriptor)
        || commitment.config.outer_len / 8 != polynomial.evaluations.len()
        || polynomial.evaluations.len()
            != 1usize.checked_shl(polynomial.target_point.len() as u32).unwrap_or(0)
    {
        return Err(AuthenticatedOutputError::InvalidGeometry("link prover polynomial"));
    }
    Ok(())
}

fn validate_verifier_polynomial(
    descriptor: Digest,
    expected_kind: OracleKind,
    polynomial: &LinkPolynomialVerifier<'_>,
) -> Result<(), AuthenticatedOutputError> {
    let commitment = polynomial.commitment;
    if commitment.config.identity.oracle_kind != expected_kind
        || commitment.config.identity.fold_round != 0
        || commitment.config.slot_descriptors.get(usize::from(polynomial.slot)).copied().flatten()
            != Some(descriptor)
        || commitment.config.outer_len / 8
            != 1usize.checked_shl(polynomial.target_point.len() as u32).unwrap_or(0)
    {
        return Err(AuthenticatedOutputError::InvalidGeometry("link verifier polynomial"));
    }
    Ok(())
}

fn validate_prefix_common(
    prefix: AuthenticatedOutputLinkPrefix<'_>,
    descriptors: &[Digest],
    public_h: &[Fp2],
    round_count: usize,
) -> Result<Digest, AuthenticatedOutputError> {
    if descriptors.is_empty()
        || descriptors.len() > 1660
        || prefix.descriptor_digests != descriptors
        || prefix.ordered_h_symbols != public_h
        || prefix.m9_frames.len() != descriptors.len()
        || descriptors.iter().copied().collect::<BTreeSet<_>>().len() != descriptors.len()
    {
        return Err(AuthenticatedOutputError::InvalidSchedule("authenticated-output prefix"));
    }
    for (descriptor, frame) in descriptors.iter().zip(prefix.m9_frames) {
        if descriptor != &frame.descriptor_digest {
            return Err(AuthenticatedOutputError::InvalidSchedule("M9 descriptor order"));
        }
    }
    if prefix.claim_frames.len() > 3320
        || prefix.claim_frames.iter().any(|claim| !descriptors.contains(&claim.descriptor_digest))
    {
        return Err(AuthenticatedOutputError::InvalidSchedule("link reduced claims"));
    }
    validate_domains(prefix.round_correlation_domain_ids, round_count)?;
    Ok(authenticated_output_link_schedule_digest(
        prefix.epoch,
        prefix.claim_frames,
        prefix.descriptor_digests,
        prefix.ordered_h_symbols,
        prefix.m9_frames,
        u8::try_from(round_count).map_err(|_| AuthenticatedOutputError::Overflow)?,
        prefix.round_correlation_domain_ids,
    )?)
}

fn challenge_map(
    challenges: &[LinkCohortChallenges],
    expected_query_count: usize,
) -> Result<BTreeMap<LinkCohortKey, &UdChallenges>, AuthenticatedOutputError> {
    let mut map = BTreeMap::new();
    let mut previous = None;
    for entry in challenges {
        if previous.is_some_and(|key| key >= entry.key)
            || entry.challenges.combine != Fp2::ZERO
            || entry.challenges.query_draws.len() != expected_query_count
        {
            return Err(AuthenticatedOutputError::InvalidSchedule("link cohort challenges"));
        }
        previous = Some(entry.key);
        map.insert(entry.key, &entry.challenges);
    }
    Ok(map)
}

fn terminal_weight(coefficient: Fp2, target: &[Fp2], common: &[Fp2]) -> Fp2 {
    let active = target.len();
    let equality = eq_points(target, &common[..active]);
    let virtual_factor = common[active..]
        .iter()
        .fold(Fp2::ONE, |product, challenge| product * (Fp2::ONE - *challenge));
    coefficient * equality * virtual_factor
}

struct ProverGroup<'a> {
    cohort: &'a dyn UdWeightedOpeningSource,
    dimension: usize,
    weights: BTreeMap<u16, Fp2>,
}

fn insert_prover_group<'a>(
    groups: &mut BTreeMap<LinkCohortKey, ProverGroup<'a>>,
    polynomial: &'a LinkPolynomialProver<'a>,
    weight: Fp2,
) -> Result<(), AuthenticatedOutputError> {
    let key = LinkCohortKey::from_commitment(polynomial.cohort.commitment());
    let entry = groups.entry(key).or_insert_with(|| ProverGroup {
        cohort: polynomial.cohort,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.cohort.commitment().root != polynomial.cohort.commitment().root
        || entry.weights.insert(polynomial.slot, weight).is_some()
    {
        return Err(AuthenticatedOutputError::InvalidSchedule("link prover cohort grouping"));
    }
    Ok(())
}

struct VerifierGroup<'a> {
    commitment: &'a UdCohortCommitment,
    dimension: usize,
    weights: BTreeMap<u16, Fp2>,
}

fn insert_verifier_group<'a>(
    groups: &mut BTreeMap<LinkCohortKey, VerifierGroup<'a>>,
    polynomial: &'a LinkPolynomialVerifier<'a>,
    weight: Fp2,
) -> Result<(), AuthenticatedOutputError> {
    let key = LinkCohortKey::from_commitment(polynomial.commitment);
    let entry = groups.entry(key).or_insert_with(|| VerifierGroup {
        commitment: polynomial.commitment,
        dimension: polynomial.target_point.len(),
        weights: BTreeMap::new(),
    });
    if entry.dimension != polynomial.target_point.len()
        || entry.commitment.root != polynomial.commitment.root
        || entry.weights.insert(polynomial.slot, weight).is_some()
    {
        return Err(AuthenticatedOutputError::InvalidSchedule("link verifier cohort grouping"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_authenticated_output_link(
    blocks: Vec<AuthenticatedOutputBlockProver<'_>>,
    prefix: AuthenticatedOutputLinkPrefix<'_>,
    cohort_challenges: &[LinkCohortChallenges],
    expected_query_count: usize,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> Result<
    (AuthenticatedOutputLinkProof, Vec<BoundAuxEvalProver>, AuthenticatedOutputLinkMetrics),
    AuthenticatedOutputError,
> {
    let descriptors: Vec<_> = blocks.iter().map(|block| block.descriptor_digest).collect();
    let public_h: Vec<_> = blocks.iter().map(|block| block.public_h).collect();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputError::InvalidSchedule("pending prover descriptor"));
        }
        validate_prover_polynomial(
            block.descriptor_digest,
            OracleKind::WeightExtension,
            &block.weight_extension,
        )?;
        validate_prover_polynomial(
            block.descriptor_digest,
            OracleKind::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputError::InvalidGeometry("canonical auxiliary point"));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    if round_count == 0 || round_count > 30 {
        return Err(AuthenticatedOutputError::InvalidGeometry("link maximum dimension"));
    }
    let schedule_digest = validate_prefix_common(prefix, &descriptors, &public_h, round_count)?;
    let challenge_by_cohort = challenge_map(cohort_challenges, expected_query_count)?;

    // Every M9 frame has already been fixed and charged before this challenge.
    let beta = tx.challenge_fp2();
    let mut power = beta;
    let mut initial_claim = ProverAuthed::ZERO;
    let mut terms = Vec::with_capacity(2 * blocks.len());
    let mut polynomial_coefficients = Vec::with_capacity(2 * blocks.len());
    for block in &blocks {
        let masked_coefficient = power;
        let output_coefficient = power * beta;
        initial_claim = initial_claim
            .add(ProverAuthed::from_public(block.public_h).scale(masked_coefficient))
            .add(block.pending_aux.auth.scale(output_coefficient));
        let auxiliary_coefficient = masked_coefficient + output_coefficient;
        terms.push(SumcheckTerm::new(
            masked_coefficient,
            block.weight_extension.evaluations,
            block.weight_extension.target_point,
        )?);
        terms.push(SumcheckTerm::new(
            auxiliary_coefficient,
            block.auxiliary.evaluations,
            block.auxiliary.target_point,
        )?);
        polynomial_coefficients.push((masked_coefficient, auxiliary_coefficient));
        power = output_coefficient * beta;
    }
    let sumcheck = prove_blind_multi_term_sumcheck(
        terms,
        round_count,
        initial_claim,
        stream,
        prefix.round_correlation_domain_ids,
        tx,
    )?;

    let mut groups = BTreeMap::new();
    for (block, (weight_coefficient, auxiliary_coefficient)) in
        blocks.iter().zip(&polynomial_coefficients)
    {
        insert_prover_group(
            &mut groups,
            &block.weight_extension,
            terminal_weight(
                *weight_coefficient,
                block.weight_extension.target_point,
                &sumcheck.point,
            ),
        )?;
        insert_prover_group(
            &mut groups,
            &block.auxiliary,
            terminal_weight(*auxiliary_coefficient, block.auxiliary.target_point, &sumcheck.point),
        )?;
    }
    if groups.len() != challenge_by_cohort.len() {
        return Err(AuthenticatedOutputError::InvalidSchedule("link cohort challenge set"));
    }

    let mut cohort_openings = Vec::with_capacity(groups.len());
    let mut terminal_from_commitments = Fp2::ZERO;
    let mut metrics = AuthenticatedOutputLinkMetrics {
        touched_blocks: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        relation_count: u64::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        round_count: u64::try_from(round_count).map_err(|_| AuthenticatedOutputError::Overflow)?,
        m9_full_correlations: u64::try_from(blocks.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        link_round_full_correlations: u64::try_from(2 * round_count)
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        seam_full_correlations_with_response_zero: u64::try_from(
            blocks.len() + 2 * round_count + 1,
        )
        .map_err(|_| AuthenticatedOutputError::Overflow)?,
        m9_frame_bytes: u64::try_from(
            64usize.checked_mul(blocks.len()).ok_or(AuthenticatedOutputError::Overflow)?,
        )
        .map_err(|_| AuthenticatedOutputError::Overflow)?,
        response_zero_batch_frame_bytes: 50,
        sumcheck_source_symbols_read: blocks.iter().try_fold(0u64, |sum, block| {
            let symbols = block
                .weight_extension
                .evaluations
                .len()
                .checked_add(block.auxiliary.evaluations.len())
                .ok_or(AuthenticatedOutputError::Overflow)?;
            sum.checked_add(u64::try_from(symbols).map_err(|_| AuthenticatedOutputError::Overflow)?)
                .ok_or(AuthenticatedOutputError::Overflow)
        })?,
        ..Default::default()
    };
    for (key, group) in groups {
        let challenges = challenge_by_cohort
            .get(&key)
            .ok_or(AuthenticatedOutputError::InvalidSchedule("missing link cohort challenges"))?;
        let touched_slots: Vec<_> = group.weights.keys().copied().collect();
        let weights: Vec<_> = group.weights.values().copied().collect();
        let common_point = &sumcheck.point[..group.dimension];
        let (folding, open_metrics) = group.cohort.open_weighted_source(
            &touched_slots,
            common_point,
            &weights,
            challenges,
            expected_query_count,
        )?;
        let opened = verify_ud_folding_weighted(
            group.cohort.commitment(),
            &touched_slots,
            common_point,
            &weights,
            challenges,
            expected_query_count,
            &folding,
        )?;
        terminal_from_commitments += opened;
        accumulate_open_metrics(&mut metrics, &open_metrics)?;
        cohort_openings.push(LinkCohortOpeningProof { key, touched_slots, folding });
    }
    if terminal_from_commitments != sumcheck.terminal_value {
        return Err(AuthenticatedOutputError::TerminalMismatch);
    }
    let terminal_residual =
        sumcheck.final_claim.sub(ProverAuthed::from_public(terminal_from_commitments));
    if terminal_residual.x != Fp2::ZERO {
        return Err(AuthenticatedOutputError::TerminalMismatch);
    }
    let terminal_tag = zero_open_prover(&terminal_residual, tx);
    let frame = AuthenticatedOutputLinkFrame {
        relation_count: u16::try_from(2 * blocks.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        round_count: u8::try_from(round_count).map_err(|_| AuthenticatedOutputError::Overflow)?,
        link_schedule_digest: schedule_digest,
        ordered_round_correction_symbols: sumcheck.corrections,
        terminal_opened_tag_symbol: terminal_tag,
    };
    frame.validate()?;
    metrics.link_frame_bytes =
        u64::try_from(Frame::AuthenticatedOutputLink(frame.clone()).encode()?.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?;
    metrics.seam_frame_bytes = metrics
        .m9_frame_bytes
        .checked_add(metrics.link_frame_bytes)
        .and_then(|bytes| bytes.checked_add(metrics.response_zero_batch_frame_bytes))
        .ok_or(AuthenticatedOutputError::Overflow)?;
    let bound = blocks
        .into_iter()
        .map(|block| BoundAuxEvalProver {
            descriptor_digest: block.descriptor_digest,
            auth: block.pending_aux.auth,
        })
        .collect();
    Ok((AuthenticatedOutputLinkProof { frame, cohort_openings }, bound, metrics))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_authenticated_output_link(
    blocks: Vec<AuthenticatedOutputBlockVerifier<'_>>,
    prefix: AuthenticatedOutputLinkPrefix<'_>,
    cohort_challenges: &[LinkCohortChallenges],
    expected_query_count: usize,
    proof: &AuthenticatedOutputLinkProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifier>, AuthenticatedOutputError> {
    proof.frame.validate()?;
    let descriptors: Vec<_> = blocks.iter().map(|block| block.descriptor_digest).collect();
    let public_h: Vec<_> = blocks.iter().map(|block| block.public_h).collect();
    let mut round_count = 0usize;
    for block in &blocks {
        if block.pending_aux.descriptor_digest != block.descriptor_digest {
            return Err(AuthenticatedOutputError::InvalidSchedule("pending verifier descriptor"));
        }
        validate_verifier_polynomial(
            block.descriptor_digest,
            OracleKind::WeightExtension,
            &block.weight_extension,
        )?;
        validate_verifier_polynomial(
            block.descriptor_digest,
            OracleKind::Auxiliary,
            &block.auxiliary,
        )?;
        if !validate_canonical_points(
            block.weight_extension.target_point,
            block.auxiliary.target_point,
        ) {
            return Err(AuthenticatedOutputError::InvalidGeometry("canonical auxiliary point"));
        }
        round_count = round_count
            .max(block.weight_extension.target_point.len())
            .max(block.auxiliary.target_point.len());
    }
    let expected_digest = validate_prefix_common(prefix, &descriptors, &public_h, round_count)?;
    if usize::from(proof.frame.relation_count) != 2 * blocks.len()
        || usize::from(proof.frame.round_count) != round_count
        || proof.frame.link_schedule_digest != expected_digest
    {
        return Err(AuthenticatedOutputError::InvalidSchedule("link frame statement"));
    }
    let challenge_by_cohort = challenge_map(cohort_challenges, expected_query_count)?;

    let beta = tx.challenge_fp2();
    let mut power = beta;
    let mut initial_key = VerifierKey::ZERO;
    let mut polynomial_coefficients = Vec::with_capacity(2 * blocks.len());
    for block in &blocks {
        let masked_coefficient = power;
        let output_coefficient = power * beta;
        initial_key = initial_key
            .add(VerifierKey::from_public(block.public_h, ctx.delta).scale(masked_coefficient))
            .add(block.pending_aux.key.scale(output_coefficient));
        polynomial_coefficients.push((masked_coefficient, masked_coefficient + output_coefficient));
        power = output_coefficient * beta;
    }
    let (point, final_key) = verify_blind_multi_term_sumcheck(
        round_count,
        initial_key,
        &proof.frame.ordered_round_correction_symbols,
        ctx,
        prefix.round_correlation_domain_ids,
        tx,
    )?;

    let mut groups = BTreeMap::new();
    for (block, (weight_coefficient, auxiliary_coefficient)) in
        blocks.iter().zip(&polynomial_coefficients)
    {
        insert_verifier_group(
            &mut groups,
            &block.weight_extension,
            terminal_weight(*weight_coefficient, block.weight_extension.target_point, &point),
        )?;
        insert_verifier_group(
            &mut groups,
            &block.auxiliary,
            terminal_weight(*auxiliary_coefficient, block.auxiliary.target_point, &point),
        )?;
    }
    if groups.len() != challenge_by_cohort.len() || groups.len() != proof.cohort_openings.len() {
        return Err(AuthenticatedOutputError::InvalidSchedule("link cohort proof set"));
    }
    let mut terminal_from_commitments = Fp2::ZERO;
    for (((key, group), opening), challenge_entry) in
        groups.into_iter().zip(&proof.cohort_openings).zip(cohort_challenges)
    {
        if opening.key != key || challenge_entry.key != key {
            return Err(AuthenticatedOutputError::InvalidSchedule("link cohort proof order"));
        }
        let touched_slots: Vec<_> = group.weights.keys().copied().collect();
        let weights: Vec<_> = group.weights.values().copied().collect();
        if opening.touched_slots != touched_slots {
            return Err(AuthenticatedOutputError::InvalidSchedule("link touched-slot schedule"));
        }
        terminal_from_commitments += verify_ud_folding_weighted(
            group.commitment,
            &touched_slots,
            &point[..group.dimension],
            &weights,
            &challenge_entry.challenges,
            expected_query_count,
            &opening.folding,
        )?;
    }
    let terminal_key =
        final_key.sub(VerifierKey::from_public(terminal_from_commitments, ctx.delta));
    if !zero_open_verify(terminal_key, proof.frame.terminal_opened_tag_symbol) {
        return Err(AuthenticatedOutputError::LinkRejected);
    }
    tx.append("zero_open_tag", 16);
    Ok(blocks
        .into_iter()
        .map(|block| BoundAuxEvalVerifier {
            descriptor_digest: block.descriptor_digest,
            key: block.pending_aux.key,
        })
        .collect())
}

fn accumulate_open_metrics(
    total: &mut AuthenticatedOutputLinkMetrics,
    opened: &UdOpenMetrics,
) -> Result<(), AuthenticatedOutputError> {
    total.fold_bytes = total
        .fold_bytes
        .checked_add(opened.serialized_fold_bytes)
        .ok_or(AuthenticatedOutputError::Overflow)?;
    total.query_bytes = total
        .query_bytes
        .checked_add(opened.serialized_query_bytes)
        .ok_or(AuthenticatedOutputError::Overflow)?;
    total.source_coefficients_read = total
        .source_coefficients_read
        .checked_add(opened.source_coefficients_read)
        .ok_or(AuthenticatedOutputError::Overflow)?;
    total.encoded_symbols_read = total
        .encoded_symbols_read
        .checked_add(opened.initial_encoded_symbols_read)
        .ok_or(AuthenticatedOutputError::Overflow)?;
    total.folded_symbols_written = total
        .folded_symbols_written
        .checked_add(opened.folded_symbols_written)
        .ok_or(AuthenticatedOutputError::Overflow)?;
    Ok(())
}

pub fn prove_authenticated_output_link_production(
    permit: X4OpeningPermit,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockProver<'_>>,
    prefix: AuthenticatedOutputLinkPrefix<'_>,
    cohort_challenges: &[LinkCohortChallenges],
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> Result<
    (AuthenticatedOutputLinkProof, Vec<BoundAuxEvalProver>, AuthenticatedOutputLinkMetrics),
    AuthenticatedOutputError,
> {
    if permit.model_root != model_root || permit.epoch != prefix.epoch {
        return Err(AuthenticatedOutputError::EpochMismatch);
    }
    prove_authenticated_output_link(
        blocks,
        prefix,
        cohort_challenges,
        PRODUCTION_QUERY_COUNT,
        stream,
        tx,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_authenticated_output_link_production(
    permit: X4OpeningPermit,
    model_root: Digest,
    blocks: Vec<AuthenticatedOutputBlockVerifier<'_>>,
    prefix: AuthenticatedOutputLinkPrefix<'_>,
    cohort_challenges: &[LinkCohortChallenges],
    proof: &AuthenticatedOutputLinkProof,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Result<Vec<BoundAuxEvalVerifier>, AuthenticatedOutputError> {
    if permit.model_root != model_root || permit.epoch != prefix.epoch {
        return Err(AuthenticatedOutputError::EpochMismatch);
    }
    verify_authenticated_output_link(
        blocks,
        prefix,
        cohort_challenges,
        PRODUCTION_QUERY_COUNT,
        proof,
        ctx,
        tx,
    )
}

/// Response ZeroBatch accepts only values that passed the link typestate.
pub fn prove_bound_response_zero_batch(
    authenticated_weight_evals: &[ProverAuthed],
    bound_aux: &[BoundAuxEvalProver],
    public_h: &[Fp2],
    stream: &mut CorrelationStream,
    mask_domain: u64,
    tx: &mut Transcript,
) -> Result<ResponseZeroBatchFrame, AuthenticatedOutputError> {
    if authenticated_weight_evals.len() != bound_aux.len()
        || bound_aux.len() != public_h.len()
        || bound_aux.len() > 1660
    {
        return Err(AuthenticatedOutputError::InvalidGeometry("bound response ZeroBatch"));
    }
    let residuals: Vec<_> = authenticated_weight_evals
        .iter()
        .zip(bound_aux)
        .zip(public_h)
        .map(|((weight, auxiliary), h)| {
            weight.add(auxiliary.auth).sub(ProverAuthed::from_public(*h))
        })
        .collect();
    if residuals.iter().any(|residual| residual.x != Fp2::ZERO) {
        return Err(AuthenticatedOutputError::ZeroBatchRejected);
    }
    let correlation = stream.draw_fulls(mask_domain, 1)[0];
    let (mask, correction) = fresh_zero_mask(correlation, tx);
    let challenge = tx.challenge_fp2();
    let opened_tag = zero_batch_prover(&residuals, &mask, challenge, tx);
    let frame = ResponseZeroBatchFrame {
        claim_count: u16::try_from(residuals.len())
            .map_err(|_| AuthenticatedOutputError::Overflow)?,
        mask_correction_symbol: correction,
        opened_tag_symbol: opened_tag,
    };
    frame.validate()?;
    Ok(frame)
}

pub fn verify_bound_response_zero_batch(
    authenticated_weight_keys: &[VerifierKey],
    bound_aux: &[BoundAuxEvalVerifier],
    public_h: &[Fp2],
    frame: &ResponseZeroBatchFrame,
    ctx: &mut VerifierCtx,
    mask_domain: u64,
    tx: &mut Transcript,
) -> Result<(), AuthenticatedOutputError> {
    frame.validate()?;
    if authenticated_weight_keys.len() != bound_aux.len()
        || bound_aux.len() != public_h.len()
        || usize::from(frame.claim_count) != bound_aux.len()
    {
        return Err(AuthenticatedOutputError::InvalidGeometry("bound response ZeroBatch"));
    }
    let residual_keys: Vec<_> = authenticated_weight_keys
        .iter()
        .zip(bound_aux)
        .zip(public_h)
        .map(|((weight, auxiliary), h)| {
            weight.add(auxiliary.key).sub(VerifierKey::from_public(*h, ctx.delta))
        })
        .collect();
    let full_key = ctx.expand_full_keys(mask_domain, 1)[0];
    tx.append("mask_correction", 16);
    let mask_key = zero_mask_key(ctx, full_key, frame.mask_correction_symbol);
    let challenge = tx.challenge_fp2();
    tx.append("zero_batch_tag", 16);
    if zero_batch_verify(&residual_keys, mask_key, challenge, frame.opened_tag_symbol) {
        Ok(())
    } else {
        Err(AuthenticatedOutputError::ZeroBatchRejected)
    }
}

/// Pure diagnostic used by the permanent beta-collision negative test.  A
/// true result is classified as `LinkBad`; it is never promoted to a
/// deterministic authenticated equality.
pub fn beta_collision_is_link_bad(masked_residual: Fp2, output_residual: Fp2, beta: Fp2) -> bool {
    masked_residual != Fp2::ZERO
        && output_residual != Fp2::ZERO
        && masked_residual + beta * output_residual == Fp2::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::folding::UdCommittedCohort;
    use crate::x4::frame::PcsLeafPayload;
    use crate::x4::merkle::{CohortIdentity, CohortVerifierConfig};
    use crate::x4::ntt::{evaluate_multilinear_table, multilinear_coefficients};
    use volta_field::Fp;

    const QUERIES: usize = 8;
    const M9_DOMAIN: u64 = 0x51_000;
    const LINK_DOMAINS: [u64; 4] = [0x52_000, 0x52_001, 0x52_002, 0x52_003];
    const ZERO_DOMAIN: u64 = 0x53_000;
    const PCG_SEED: [u8; 32] = [0xA3; 32];
    const TX_SEED: [u8; 32] = [0xB4; 32];

    fn symbol(value: u64) -> Fp2 {
        Fp2::new(Fp::new(value), Fp::new(value * 7 + 5))
    }

    fn committed(
        descriptor: Digest,
        cohort_id: u32,
        kind: OracleKind,
        evaluations: &[Fp2],
    ) -> UdCommittedCohort {
        let config = CohortVerifierConfig {
            identity: CohortIdentity { cohort_id, oracle_kind: kind, fold_round: 0 },
            slot_descriptors: vec![Some(descriptor)],
            outer_len: 8 * evaluations.len(),
            expected_symbol_count: 1,
        };
        UdCommittedCohort::commit(
            config,
            vec![Some(multilinear_coefficients(evaluations).unwrap())],
        )
        .unwrap()
    }

    fn cohort_challenges(
        weight: &UdCommittedCohort,
        auxiliary: &UdCommittedCohort,
    ) -> Vec<LinkCohortChallenges> {
        let mut challenges = vec![weight, auxiliary]
            .into_iter()
            .map(|cohort| LinkCohortChallenges {
                key: LinkCohortKey::from_commitment(cohort.commitment()),
                challenges: UdChallenges {
                    combine: Fp2::ZERO,
                    folds: vec![symbol(31), symbol(37)],
                    query_draws: vec![0, 1, 3, 7, 8, 15, 23, 31],
                },
            })
            .collect::<Vec<_>>();
        challenges.sort_by_key(|entry| entry.key);
        challenges
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
        weight: UdCommittedCohort,
        auxiliary: UdCommittedCohort,
        challenges: Vec<LinkCohortChallenges>,
        proof: AuthenticatedOutputLinkProof,
        bound_prover: Vec<BoundAuxEvalProver>,
        metrics: AuthenticatedOutputLinkMetrics,
        prover_stream: CorrelationStream,
        prover_tx: Transcript,
        weight_value: Fp2,
        auxiliary_value: Fp2,
        delta: Fp2,
    }

    fn generate() -> Generated {
        let descriptor = [0x17; 32];
        let weight_evaluations = (0..4).map(|index| symbol(10 + index)).collect::<Vec<_>>();
        let auxiliary_evaluations = (0..4).map(|index| symbol(80 + 3 * index)).collect::<Vec<_>>();
        let weight_point = vec![symbol(7), Fp2::ZERO];
        let auxiliary_point = vec![symbol(7), Fp2::ZERO];
        let weight_value = evaluate_multilinear_table(&weight_evaluations, &weight_point).unwrap();
        let auxiliary_value =
            evaluate_multilinear_table(&auxiliary_evaluations, &auxiliary_point).unwrap();
        let public_h = vec![weight_value + auxiliary_value];
        let descriptors = vec![descriptor];
        let weight = committed(descriptor, 41, OracleKind::WeightExtension, &weight_evaluations);
        let auxiliary = committed(descriptor, 42, OracleKind::Auxiliary, &auxiliary_evaluations);
        let challenges = cohort_challenges(&weight, &auxiliary);

        let mut prover_stream = CorrelationStream::new(PCG_SEED);
        let mut prover_tx = Transcript::new(TX_SEED);
        let (pending, m9) = authenticate_pending_aux_prover(
            descriptor,
            auxiliary_value,
            &mut prover_stream,
            M9_DOMAIN,
            &mut prover_tx,
        )
        .unwrap();
        let m9_frames = vec![m9];
        let prefix = AuthenticatedOutputLinkPrefix {
            epoch: 9,
            claim_frames: &[],
            descriptor_digests: &descriptors,
            ordered_h_symbols: &public_h,
            m9_frames: &m9_frames,
            round_correlation_domain_ids: &LINK_DOMAINS,
        };
        let blocks = vec![AuthenticatedOutputBlockProver {
            descriptor_digest: descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialProver {
                cohort: &weight,
                slot: 0,
                evaluations: &weight_evaluations,
                target_point: &weight_point,
            },
            auxiliary: LinkPolynomialProver {
                cohort: &auxiliary,
                slot: 0,
                evaluations: &auxiliary_evaluations,
                target_point: &auxiliary_point,
            },
        }];
        let (proof, bound_prover, metrics) = prove_authenticated_output_link(
            blocks,
            prefix,
            &challenges,
            QUERIES,
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
            challenges,
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
        proof: &AuthenticatedOutputLinkProof,
        descriptors: &[Digest],
        public_h: &[Fp2],
        m9_frames: &[M9TransferFrame],
        domains: &[u64],
    ) -> Result<(Vec<BoundAuxEvalVerifier>, VerifierCtx, Transcript), AuthenticatedOutputError>
    {
        let mut ctx = VerifierCtx::new(PCG_SEED, generated.delta);
        let mut tx = Transcript::new(TX_SEED);
        let pending =
            authenticate_pending_aux_verifier(&m9_frames[0], &mut ctx, M9_DOMAIN, &mut tx)?;
        let blocks = vec![AuthenticatedOutputBlockVerifier {
            descriptor_digest: generated.descriptor,
            public_h: public_h[0],
            pending_aux: pending,
            weight_extension: LinkPolynomialVerifier {
                commitment: generated.weight.commitment(),
                slot: 0,
                target_point: &generated.weight_point,
            },
            auxiliary: LinkPolynomialVerifier {
                commitment: generated.auxiliary.commitment(),
                slot: 0,
                target_point: &generated.auxiliary_point,
            },
        }];
        let prefix = AuthenticatedOutputLinkPrefix {
            epoch: 9,
            claim_frames: &[],
            descriptor_digests: descriptors,
            ordered_h_symbols: public_h,
            m9_frames,
            round_correlation_domain_ids: domains,
        };
        let bound = verify_authenticated_output_link(
            blocks,
            prefix,
            &generated.challenges,
            QUERIES,
            proof,
            &mut ctx,
            &mut tx,
        )?;
        Ok((bound, ctx, tx))
    }

    #[test]
    fn honest_link_is_blind_commitment_bound_and_only_then_zero_batches() {
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
        assert_eq!(generated.metrics.link_round_full_correlations, 4);
        assert_eq!(generated.metrics.seam_full_correlations_with_response_zero, 6);
        assert_eq!(generated.metrics.link_frame_bytes, 69 + 32 * 2);
        assert_eq!(generated.metrics.seam_frame_bytes, 64 + (69 + 32 * 2) + 50);
        assert_eq!(generated.proof.frame.relation_count, 2);
        assert_eq!(generated.proof.frame.round_count, 2);

        let weight_tag = symbol(700);
        let weight_auth = ProverAuthed { x: generated.weight_value, m: weight_tag };
        let weight_key = VerifierKey { k: weight_tag + generated.delta * generated.weight_value };
        let zero_frame = prove_bound_response_zero_batch(
            &[weight_auth],
            &generated.bound_prover,
            &generated.public_h,
            &mut generated.prover_stream,
            ZERO_DOMAIN,
            &mut generated.prover_tx,
        )
        .unwrap();
        verify_bound_response_zero_batch(
            &[weight_key],
            &bound_verifier,
            &generated.public_h,
            &zero_frame,
            &mut ctx,
            ZERO_DOMAIN,
            &mut verifier_tx,
        )
        .unwrap();
        assert_eq!(generated.prover_stream.counters.full_corrs, 6);
        assert_eq!(ctx.counters.full_corrs, 6);
        assert_eq!(Frame::ResponseZeroBatch(zero_frame).encode().unwrap().len(), 50);

        // The proof contains only round corrections, one terminal tag and
        // simulator-covered fold/query messages, never an individual target.
        assert_eq!(generated.proof.frame.ordered_round_correction_symbols.len(), 4);
        assert_ne!(generated.proof.frame.terminal_opened_tag_symbol, generated.auxiliary_value);
        assert_eq!(generated.weight_evaluations.len(), 4);
        assert_eq!(generated.auxiliary_evaluations.len(), 4);
    }

    #[test]
    fn schedule_correction_terminal_fold_and_query_tampers_reject() {
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

        let mut bad_descriptor = generated.descriptors.clone();
        bad_descriptor[0][0] ^= 1;
        assert!(verify_with(
            &generated,
            &generated.proof,
            &bad_descriptor,
            &generated.public_h,
            &generated.m9_frames,
            &LINK_DOMAINS,
        )
        .is_err());

        let mut bad_m9 = generated.m9_frames.clone();
        bad_m9[0].mask_correction_symbol += Fp2::ONE;
        assert!(verify_with(
            &generated,
            &generated.proof,
            &generated.descriptors,
            &generated.public_h,
            &bad_m9,
            &LINK_DOMAINS,
        )
        .is_err());

        let bad_domains = [LINK_DOMAINS[0], LINK_DOMAINS[2], LINK_DOMAINS[1], LINK_DOMAINS[3]];
        assert!(verify_with(
            &generated,
            &generated.proof,
            &generated.descriptors,
            &generated.public_h,
            &generated.m9_frames,
            &bad_domains,
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
        bad.cohort_openings[0].folding.fold_frames[0].root_digest[0] ^= 1;
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
        let auxiliary_opening = bad
            .cohort_openings
            .iter_mut()
            .find(|opening| opening.key.oracle_kind == OracleKind::Auxiliary)
            .unwrap();
        auxiliary_opening.key.root[0] ^= 1;
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
        let leaf = bad.cohort_openings[0].folding.query_frames[0]
            .opened_leaves
            .iter_mut()
            .find(|leaf| matches!(leaf.payload, PcsLeafPayload::Inner { .. }))
            .unwrap();
        match &mut leaf.payload {
            PcsLeafPayload::Inner { symbols, .. } => symbols[0] += Fp2::ONE,
            _ => unreachable!(),
        }
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
    fn recomputed_schedule_delta_shift_family_rejects_at_the_link() {
        let generated = generate();
        for delta in 1..=32 {
            let mut shifted_m9 = generated.m9_frames.clone();
            shifted_m9[0].mask_correction_symbol += Fp2::from_base(Fp::new(delta));
            let mut shifted_proof = generated.proof.clone();
            shifted_proof.frame.link_schedule_digest = authenticated_output_link_schedule_digest(
                9,
                &[],
                &generated.descriptors,
                &generated.public_h,
                &shifted_m9,
                2,
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
    }

    #[test]
    fn beta_collision_is_permanent_linkbad_negative_artifact() {
        let committed_w = Fp2::from_base(Fp::new(3));
        let committed_g = Fp2::from_base(Fp::new(5));
        let public_h = Fp2::from_base(Fp::new(7));
        let authenticated_s = Fp2::from_base(Fp::new(6));
        let beta = Fp2::ONE;
        let masked_residual = committed_w + committed_g - public_h;
        let output_residual = committed_g - authenticated_s;
        assert_ne!(masked_residual, Fp2::ZERO);
        assert_ne!(output_residual, Fp2::ZERO);
        assert_ne!(authenticated_s, committed_g);
        assert!(beta_collision_is_link_bad(masked_residual, output_residual, beta));
        assert_eq!(x4_v3_seam_full_correlations(1660, 30).unwrap(), 1721);
        assert_eq!(x4_v3_seam_frame_bytes(1660, 30).unwrap(), 107_319);

        let mut registry = X4OpeningRegistry::default();
        let root = [0xA5; 32];
        let permit = registry.authorize(root, 17).unwrap();
        assert_eq!(permit.model_root(), root);
        assert_eq!(permit.epoch(), 17);
        assert!(registry.has_opened(root, 17));
        assert!(matches!(
            registry.authorize(root, 17),
            Err(AuthenticatedOutputError::EpochAlreadyOpened)
        ));
        assert!(registry.authorize(root, 18).is_ok());
    }

    #[test]
    fn zero_batch_tamper_rejects_after_bound_transition() {
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
        let weight_tag = symbol(900);
        let weight_auth = ProverAuthed { x: generated.weight_value, m: weight_tag };
        let weight_key = VerifierKey { k: weight_tag + generated.delta * generated.weight_value };
        let mut frame = prove_bound_response_zero_batch(
            &[weight_auth],
            &generated.bound_prover,
            &generated.public_h,
            &mut generated.prover_stream,
            ZERO_DOMAIN,
            &mut generated.prover_tx,
        )
        .unwrap();
        frame.opened_tag_symbol += Fp2::ONE;
        assert!(verify_bound_response_zero_batch(
            &[weight_key],
            &bound_verifier,
            &generated.public_h,
            &frame,
            &mut ctx,
            ZERO_DOMAIN,
            &mut verifier_tx,
        )
        .is_err());
    }
}
