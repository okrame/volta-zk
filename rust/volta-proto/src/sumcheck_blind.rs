//! Blind product sumcheck (M3 schema, compressed variant): the round
//! polynomial evaluations are never revealed — each is transferred as an
//! authenticated value via a correction against a **fresh full-field mask**
//! (one per coefficient per round, never reused: `CorrelationStream`'s
//! one-time ledger enforces what M3's `uniformVec_zipWith_sub` requires).
//! Challenges are public (interactive-mock, from the shared transcript).
//!
//! With the compressed `[g(0), g(2)]` encoding, `g(1) = claim − g(0)` holds
//! by construction on both the value and the key side, so the per-round zero
//! claims of the Lean statement fold into the final claim, which the caller
//! closes with Π_Prod / ZeroBatch against authenticated tensor openings.

use crate::mle::{fold_low, lagrange3};
use crate::schedule::{RoundFamily, ScheduleError, SchedulePlan, ScheduleSite, SiteId};
use std::fmt;
use volta_accel::{AccelError, Backend, DeviceBuffer, DeviceSlice, Fp2Repr, Operation};
use volta_field::Fp2;
use volta_mac::{
    CorrReservationError, CorrelationStream, FullCorrRange, ProverAuthed, Transcript, VerifierCtx,
    VerifierKey,
};

#[derive(Debug, PartialEq, Eq)]
pub struct BlindSumcheckProof {
    /// Per round: corrections (16 B each) transferring g(0), g(2) onto masks.
    pub round_corrs: Vec<[Fp2; 2]>,
}

/// One member of a sealed, public round-synchronous sumcheck cohort.
///
/// `site_id` is part of the public schedule, not a completion-order tag.  A
/// cohort is sorted by this identifier before it consumes correlations or
/// verifier challenges, so host scheduling cannot perturb the proof.
pub struct BlindSumcheckBatchJob {
    pub site_id: SiteId,
    pub a: Vec<Fp2>,
    pub b: Vec<Fp2>,
    pub claim0: ProverAuthed,
    pub mask_dom_base: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlindSumcheckBatchOutput {
    pub site_id: SiteId,
    pub proof: BlindSumcheckProof,
    pub point: Vec<Fp2>,
    pub claim: ProverAuthed,
    /// Final device-independent scalar openings of the two folded factors.
    /// Keeping them in the scheduled output lets higher-level protocols
    /// finalize their existing product checks without cloning the full
    /// witness vectors before the round cohort starts.
    pub a_final: Fp2,
    pub b_final: Fp2,
}

/// Device-owned member of a sealed product-sumcheck cohort. Ownership of
/// both resident vectors transfers to [`blind_prove_resident_batch`], which
/// releases them on success and on every recoverable CUDA error path.
#[derive(Debug)]
pub struct BlindSumcheckResidentBatchJob {
    pub site_id: SiteId,
    pub a: DeviceBuffer<Fp2Repr>,
    pub b: DeviceBuffer<Fp2Repr>,
    pub claim0: ProverAuthed,
    pub mask_dom_base: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlindSumcheckResidentBatchOutput {
    pub site_id: SiteId,
    pub proof: BlindSumcheckProof,
    pub point: Vec<Fp2>,
    pub claim: ProverAuthed,
    pub a_final: Fp2,
    pub b_final: Fp2,
}

#[derive(Debug)]
pub enum ResidentBlindBatchError {
    Schedule(ScheduleError),
    Correlation(CorrReservationError),
    Accel(AccelError),
    /// Pure ownership preflight failed. No handle was consumed, so the caller
    /// can recover the complete cohort and retry with its creating backend.
    WrongBackend {
        error: AccelError,
        jobs: Vec<BlindSumcheckResidentBatchJob>,
    },
}

impl ResidentBlindBatchError {
    pub fn into_jobs(self) -> Option<Vec<BlindSumcheckResidentBatchJob>> {
        match self {
            Self::WrongBackend { jobs, .. } => Some(jobs),
            Self::Schedule(_) | Self::Correlation(_) | Self::Accel(_) => None,
        }
    }
}

impl fmt::Display for ResidentBlindBatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schedule(error) => write!(f, "resident blind-batch schedule: {error}"),
            Self::Correlation(error) => {
                write!(f, "resident blind-batch correlation reservation: {error}")
            }
            Self::Accel(error) => write!(f, "resident blind-batch accelerator: {error}"),
            Self::WrongBackend { error, .. } => {
                write!(f, "resident blind-batch ownership: {error}")
            }
        }
    }
}

impl std::error::Error for ResidentBlindBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Schedule(error) => Some(error),
            Self::Correlation(error) => Some(error),
            Self::Accel(error) => Some(error),
            Self::WrongBackend { error, .. } => Some(error),
        }
    }
}

impl From<ScheduleError> for ResidentBlindBatchError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl From<AccelError> for ResidentBlindBatchError {
    fn from(error: AccelError) -> Self {
        Self::Accel(error)
    }
}

impl From<CorrReservationError> for ResidentBlindBatchError {
    fn from(error: CorrReservationError) -> Self {
        Self::Correlation(error)
    }
}

/// Verifier input for one member of the same public cohort.
pub struct BlindSumcheckBatchVerifyJob<'a> {
    pub site_id: SiteId,
    pub n_vars: usize,
    pub claim0: VerifierKey,
    pub proof: &'a BlindSumcheckProof,
    pub mask_dom_base: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BlindSumcheckBatchVerifyOutput {
    pub site_id: SiteId,
    pub point: Vec<Fp2>,
    pub claim: VerifierKey,
}

struct BatchProverState {
    site_id: SiteId,
    n_vars: usize,
    a: Vec<Fp2>,
    b: Vec<Fp2>,
    mask_dom_base: u64,
    round_corrs: Vec<[Fp2; 2]>,
    point: Vec<Fp2>,
    claim: ProverAuthed,
}

/// CPU reference for the P7b round-synchronous schedule.
///
/// Every active member first publishes its round message in canonical
/// `site_id` order.  Only after the complete epoch is sealed do the members
/// receive distinct fresh challenges, again in canonical order.  This keeps
/// every original message and proof field, but intentionally assigns the
/// global interactive challenge tape differently from sequential proving.
/// The verifier below mirrors that schedule exactly.
pub fn blind_prove_batch(
    plan: &SchedulePlan,
    mut jobs: Vec<BlindSumcheckBatchJob>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
) -> Result<Vec<BlindSumcheckBatchOutput>, ScheduleError> {
    jobs.sort_by_key(|job| job.site_id);
    if let Some(job) = jobs
        .iter()
        .find(|job| job.a.len() != job.b.len() || job.a.len() < 2 || !job.a.len().is_power_of_two())
    {
        return Err(ScheduleError::InvalidJobShape(job.site_id));
    }
    plan.validate_family(
        RoundFamily::BlindProduct,
        jobs.iter().map(|job| ScheduleSite {
            id: job.site_id,
            rounds: job.a.len().trailing_zeros() as usize,
            mask_dom_base: job.mask_dom_base,
            mask_dom_span: job.a.len().trailing_zeros() as u64,
        }),
    )?;
    if jobs.is_empty() {
        return Ok(Vec::new());
    }
    // Reserve the complete, noncontiguous cohort atomically before the first
    // correction or challenge. This catches a prior ledger collision without
    // partially consuming either the correlation stream or transcript.
    let ranges: Vec<FullCorrRange> = jobs
        .iter()
        .map(|job| FullCorrRange {
            base_domain: job.mask_dom_base,
            rows: job.a.len().trailing_zeros() as usize,
            count_per_domain: 2,
        })
        .collect();
    let mut round_masks = stream.reserve_full_corr_ranges(&ranges);

    let mut states: Vec<BatchProverState> = jobs
        .into_iter()
        .map(|job| {
            let n_vars = job.a.len().trailing_zeros() as usize;
            BatchProverState {
                site_id: job.site_id,
                n_vars,
                a: job.a,
                b: job.b,
                mask_dom_base: job.mask_dom_base,
                round_corrs: Vec::with_capacity(n_vars),
                point: Vec::with_capacity(n_vars),
                claim: job.claim0,
            }
        })
        .collect();
    let max_rounds = states.iter().map(|state| state.n_vars).max().unwrap_or(0);

    for round in 0..max_rounds {
        // Phase A: seal every prover message in this public epoch.  No
        // challenge is consumed anywhere in this loop.
        let mut messages = Vec::with_capacity(states.len());
        for (index, state) in states.iter_mut().enumerate() {
            if round >= state.n_vars {
                continue;
            }
            let half = state.a.len() / 2;
            let mut g0 = Fp2::ZERO;
            let mut g2 = Fp2::ZERO;
            for i in 0..half {
                let (a0, a1) = (state.a[2 * i], state.a[2 * i + 1]);
                let (b0, b1) = (state.b[2 * i], state.b[2 * i + 1]);
                g0 += a0 * b0;
                let (da, db) = (a1 - a0, b1 - b0);
                g2 += (a0 + da + da) * (b0 + db + db);
            }
            let domain = state.mask_dom_base + round as u64;
            debug_assert_eq!(domain, ranges[index].domain(round));
            let masks = round_masks.draw(index, round);
            state.round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
            tx.append("blind_round_corrections", 32);
            messages.push((
                index,
                ProverAuthed { x: g0, m: masks[0].m },
                ProverAuthed { x: g2, m: masks[1].m },
            ));
        }

        // Phase B: the epoch is complete.  Draw and apply one independent
        // challenge per active SiteId; folds remain device-local in the CUDA
        // implementation of the same schedule.
        for (index, g0, g2) in messages {
            let state = &mut states[index];
            let g1 = state.claim.sub(g0);
            let r = tx.challenge_fp2();
            let w = lagrange3(r);
            state.claim = g0.scale(w[0]).add(g1.scale(w[1])).add(g2.scale(w[2]));
            fold_low(&mut state.a, r);
            fold_low(&mut state.b, r);
            state.point.push(r);
        }
    }

    round_masks.finish();
    Ok(states
        .into_iter()
        .map(|state| BlindSumcheckBatchOutput {
            site_id: state.site_id,
            proof: BlindSumcheckProof { round_corrs: state.round_corrs },
            point: state.point,
            claim: state.claim,
            a_final: state.a[0],
            b_final: state.b[0],
        })
        .collect())
}

struct BatchVerifierState<'a> {
    site_id: SiteId,
    n_vars: usize,
    proof: &'a BlindSumcheckProof,
    mask_dom_base: u64,
    point: Vec<Fp2>,
    claim: VerifierKey,
}

/// Verifier mirror of [`blind_prove_batch`].
pub fn blind_verify_batch(
    plan: &SchedulePlan,
    mut jobs: Vec<BlindSumcheckBatchVerifyJob<'_>>,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
) -> Option<Vec<BlindSumcheckBatchVerifyOutput>> {
    jobs.sort_by_key(|job| job.site_id);
    if plan
        .validate_family(
            RoundFamily::BlindProduct,
            jobs.iter().map(|job| ScheduleSite {
                id: job.site_id,
                rounds: job.n_vars,
                mask_dom_base: job.mask_dom_base,
                mask_dom_span: job.n_vars as u64,
            }),
        )
        .is_err()
        || jobs.iter().any(|job| job.proof.round_corrs.len() != job.n_vars)
    {
        return None;
    }
    if jobs.is_empty() {
        return Some(Vec::new());
    }
    let ranges: Vec<FullCorrRange> = jobs
        .iter()
        .map(|job| FullCorrRange {
            base_domain: job.mask_dom_base,
            rows: job.n_vars,
            count_per_domain: 2,
        })
        .collect();
    let delta = ctx.delta;
    let mut round_keys = ctx.try_reserve_full_key_ranges(&ranges).ok()?;
    let mut states: Vec<BatchVerifierState<'_>> = jobs
        .into_iter()
        .map(|job| BatchVerifierState {
            site_id: job.site_id,
            n_vars: job.n_vars,
            proof: job.proof,
            mask_dom_base: job.mask_dom_base,
            point: Vec::with_capacity(job.n_vars),
            claim: job.claim0,
        })
        .collect();
    let max_rounds = states.iter().map(|state| state.n_vars).max().unwrap_or(0);

    for round in 0..max_rounds {
        // Mirror the complete-message phase before consuming any challenge.
        let mut messages = Vec::with_capacity(states.len());
        for (index, state) in states.iter().enumerate() {
            if round >= state.n_vars {
                continue;
            }
            let domain = state.mask_dom_base.checked_add(round as u64)?;
            debug_assert_eq!(domain, ranges[index].domain(round));
            let masks = round_keys.expand(index, round);
            let corrs = state.proof.round_corrs[round];
            messages.push((
                index,
                VerifierKey { k: masks[0] + delta * corrs[0] },
                VerifierKey { k: masks[1] + delta * corrs[1] },
            ));
        }
        for (index, g0, g2) in messages {
            let state = &mut states[index];
            let g1 = state.claim.sub(g0);
            let r = tx.challenge_fp2();
            let w = lagrange3(r);
            state.claim = g0.scale(w[0]).add(g1.scale(w[1])).add(g2.scale(w[2]));
            state.point.push(r);
        }
    }

    round_keys.finish();
    Some(
        states
            .into_iter()
            .map(|state| BlindSumcheckBatchVerifyOutput {
                site_id: state.site_id,
                point: state.point,
                claim: state.claim,
            })
            .collect(),
    )
}

fn record_cleanup_error(first: &mut Option<AccelError>, result: Result<(), AccelError>) {
    if first.is_none() {
        *first = result.err();
    }
}

fn cleanup_fp2_buffers(
    backend: &mut Backend,
    buffers: impl IntoIterator<Item = DeviceBuffer<Fp2Repr>>,
) -> Result<(), AccelError> {
    let mut first = None;
    for buffer in buffers {
        record_cleanup_error(&mut first, backend.free_device(buffer));
    }
    first.map_or(Ok(()), Err)
}

fn free_fp2_pair(
    backend: &mut Backend,
    a: DeviceBuffer<Fp2Repr>,
    b: DeviceBuffer<Fp2Repr>,
) -> Result<(), AccelError> {
    cleanup_fp2_buffers(backend, [a, b])
}

fn prefer_cleanup_accel_error(
    primary: AccelError,
    first_cleanup: Option<AccelError>,
) -> AccelError {
    first_cleanup.unwrap_or(primary)
}

fn prefer_cleanup_batch_error(
    primary: ResidentBlindBatchError,
    first_cleanup: Option<AccelError>,
) -> ResidentBlindBatchError {
    first_cleanup.map_or(primary, ResidentBlindBatchError::Accel)
}

fn resident_accel_failure(
    primary: AccelError,
    mut first_cleanup: Option<AccelError>,
    backend: &mut Backend,
    buffers: impl IntoIterator<Item = DeviceBuffer<Fp2Repr>>,
) -> AccelError {
    record_cleanup_error(&mut first_cleanup, cleanup_fp2_buffers(backend, buffers));
    prefer_cleanup_accel_error(primary, first_cleanup)
}

struct ResidentBatchState {
    site_id: SiteId,
    n_vars: usize,
    a: Option<DeviceBuffer<Fp2Repr>>,
    b: Option<DeviceBuffer<Fp2Repr>>,
    scratch_a: Option<DeviceBuffer<Fp2Repr>>,
    scratch_b: Option<DeviceBuffer<Fp2Repr>>,
    /// `true` when the active prefix is in `a`/`b`, false when it is in the
    /// preallocated scratch pair. Each round toggles the owner without any
    /// cudaMalloc/cudaFree inside the sealed epoch.
    primary_active: bool,
    active_len: usize,
    mask_dom_base: u64,
    round_corrs: Vec<[Fp2; 2]>,
    point: Vec<Fp2>,
    claim: ProverAuthed,
}

impl ResidentBatchState {
    fn active_a(&self) -> &DeviceBuffer<Fp2Repr> {
        if self.primary_active {
            self.a.as_ref().expect("live primary resident A vector")
        } else {
            self.scratch_a.as_ref().expect("live scratch resident A vector")
        }
    }

    fn active_b(&self) -> &DeviceBuffer<Fp2Repr> {
        if self.primary_active {
            self.b.as_ref().expect("live primary resident B vector")
        } else {
            self.scratch_b.as_ref().expect("live scratch resident B vector")
        }
    }

    fn next_a(&self) -> &DeviceBuffer<Fp2Repr> {
        if self.primary_active {
            self.scratch_a.as_ref().expect("live scratch resident A vector")
        } else {
            self.a.as_ref().expect("live primary resident A vector")
        }
    }

    fn next_b(&self) -> &DeviceBuffer<Fp2Repr> {
        if self.primary_active {
            self.scratch_b.as_ref().expect("live scratch resident B vector")
        } else {
            self.b.as_ref().expect("live primary resident B vector")
        }
    }
}

fn cleanup_resident_jobs(
    backend: &mut Backend,
    jobs: Vec<BlindSumcheckResidentBatchJob>,
) -> Result<(), AccelError> {
    let mut first = None;
    for job in jobs {
        record_cleanup_error(&mut first, free_fp2_pair(backend, job.a, job.b));
    }
    first.map_or(Ok(()), Err)
}

fn cleanup_resident_batch(
    backend: &mut Backend,
    states: &mut [ResidentBatchState],
    mailbox: Option<DeviceBuffer<Fp2Repr>>,
) -> Result<(), AccelError> {
    let mut first = None;
    if let Some(mailbox) = mailbox {
        record_cleanup_error(&mut first, backend.free_device(mailbox));
    }
    for state in states {
        match (state.a.take(), state.b.take()) {
            (Some(a), Some(b)) => {
                record_cleanup_error(&mut first, free_fp2_pair(backend, a, b));
            }
            (Some(a), None) => record_cleanup_error(&mut first, backend.free_device(a)),
            (None, Some(b)) => record_cleanup_error(&mut first, backend.free_device(b)),
            (None, None) => {}
        }
        match (state.scratch_a.take(), state.scratch_b.take()) {
            (Some(a), Some(b)) => {
                record_cleanup_error(&mut first, free_fp2_pair(backend, a, b));
            }
            (Some(a), None) => record_cleanup_error(&mut first, backend.free_device(a)),
            (None, Some(b)) => record_cleanup_error(&mut first, backend.free_device(b)),
            (None, None) => {}
        }
    }
    first.map_or(Ok(()), Err)
}

fn resident_jobs_failure(
    primary: ResidentBlindBatchError,
    backend: &mut Backend,
    jobs: Vec<BlindSumcheckResidentBatchJob>,
) -> ResidentBlindBatchError {
    let cleanup = cleanup_resident_jobs(backend, jobs).err();
    prefer_cleanup_batch_error(primary, cleanup)
}

fn resident_batch_failure(
    primary: ResidentBlindBatchError,
    mut first_cleanup: Option<AccelError>,
    backend: &mut Backend,
    states: &mut [ResidentBatchState],
    mailbox: Option<DeviceBuffer<Fp2Repr>>,
) -> ResidentBlindBatchError {
    record_cleanup_error(&mut first_cleanup, cleanup_resident_batch(backend, states, mailbox));
    prefer_cleanup_batch_error(primary, first_cleanup)
}

fn preflight_resident_batch(
    plan: &SchedulePlan,
    jobs: &[BlindSumcheckResidentBatchJob],
) -> Result<(), ResidentBlindBatchError> {
    for job in jobs {
        if job.a.len() != job.b.len() || job.a.len() < 2 || !job.a.len().is_power_of_two() {
            return Err(ScheduleError::InvalidJobShape(job.site_id).into());
        }
    }
    plan.validate_family(
        RoundFamily::BlindProduct,
        jobs.iter().map(|job| ScheduleSite {
            id: job.site_id,
            rounds: job.a.len().trailing_zeros() as usize,
            mask_dom_base: job.mask_dom_base,
            mask_dom_span: job.a.len().trailing_zeros() as u64,
        }),
    )?;
    jobs.len()
        .checked_mul(RoundFamily::BlindProduct.message_width())
        .filter(|&elements| elements > 0 || jobs.is_empty())
        .ok_or(AccelError::InvalidInput("resident blind mailbox length overflow"))?;
    Ok(())
}

/// Round-synchronous resident prover for one sealed product-sumcheck cohort.
///
/// The complete plan, private shapes, domains, and buffer ownership are
/// checked before allocating a mailbox or consuming the correlation and
/// challenge streams. Each epoch then has three explicit phases:
///
/// 1. enqueue every active SiteId into the persistent device mailbox;
/// 2. download that sealed prefix once and append every correction;
/// 3. assign challenges in canonical SiteId order and fold all vectors D2D.
///
/// Final A/B scalars from every member cross the boundary in one segmented
/// download. Input buffers and all temporary resident storage are consumed on
/// every return path except [`ResidentBlindBatchError::WrongBackend`], which
/// returns the untouched jobs so the caller can retry with their owner.
pub fn blind_prove_resident_batch(
    plan: &SchedulePlan,
    mut jobs: Vec<BlindSumcheckResidentBatchJob>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<Vec<BlindSumcheckResidentBatchOutput>, ResidentBlindBatchError> {
    jobs.sort_by_key(|job| job.site_id);
    if backend.kind() != volta_accel::BackendKind::CudaResident
        || jobs.iter().any(|job| !job.a.is_owned_by(backend) || !job.b.is_owned_by(backend))
    {
        return Err(ResidentBlindBatchError::WrongBackend {
            error: AccelError::InvalidInput(
                "resident blind batch buffer belongs to a different CUDA context",
            ),
            jobs,
        });
    }
    if let Err(error) = preflight_resident_batch(plan, &jobs) {
        return Err(resident_jobs_failure(error, backend, jobs));
    }
    if jobs.is_empty() {
        return Ok(Vec::new());
    }
    let ranges: Vec<FullCorrRange> = jobs
        .iter()
        .map(|job| FullCorrRange {
            base_domain: job.mask_dom_base,
            rows: job.a.len().trailing_zeros() as usize,
            count_per_domain: 2,
        })
        .collect();
    // This transaction is established before scratch/mailbox allocation and
    // before the first CUDA launch. A collision in any later head therefore
    // cannot strand GPU work or a partial transcript.
    let mut round_masks = match stream.try_reserve_full_corr_ranges(&ranges) {
        Ok(reservation) => reservation,
        Err(error) => {
            return Err(resident_jobs_failure(error.into(), backend, jobs));
        }
    };

    let mailbox_elements = jobs
        .len()
        .checked_mul(RoundFamily::BlindProduct.message_width())
        .expect("mailbox length checked by preflight");
    let mut states: Vec<ResidentBatchState> = jobs
        .into_iter()
        .map(|job| {
            let n_vars = job.a.len().trailing_zeros() as usize;
            ResidentBatchState {
                site_id: job.site_id,
                n_vars,
                active_len: job.a.len(),
                a: Some(job.a),
                b: Some(job.b),
                scratch_a: None,
                scratch_b: None,
                primary_active: true,
                mask_dom_base: job.mask_dom_base,
                round_corrs: Vec::with_capacity(n_vars),
                point: Vec::with_capacity(n_vars),
                claim: job.claim0,
            }
        })
        .collect();
    let max_rounds = states.iter().map(|state| state.n_vars).max().unwrap_or(0);
    let timing_records = match max_rounds.checked_mul(2) {
        Some(bound) => bound,
        None => {
            return Err(resident_batch_failure(
                AccelError::InvalidInput("resident blind timing bound overflow").into(),
                None,
                backend,
                &mut states,
                None,
            ));
        }
    };
    if let Err(error) = backend.ensure_timing_capacity(timing_records) {
        return Err(resident_batch_failure(error.into(), None, backend, &mut states, None));
    }
    let max_pairs =
        states.iter().map(|state| state.active_len / 2).max().expect("non-empty resident cohort");
    if let Err(error) = backend.reserve_fp2_product_round_workspace(max_pairs) {
        return Err(resident_batch_failure(error.into(), None, backend, &mut states, None));
    }
    // One ping-pong pair per job, allocated before any coarse epoch starts.
    // The largest destination is N/2; later rounds reuse its active prefix.
    for index in 0..states.len() {
        let scratch_len = states[index].active_len / 2;
        let scratch_a = match backend.alloc_device::<Fp2Repr>(scratch_len) {
            Ok(buffer) => buffer,
            Err(error) => {
                return Err(resident_batch_failure(error.into(), None, backend, &mut states, None));
            }
        };
        // Transfer ownership immediately so a later scratch-B allocation
        // failure cannot strand this otherwise-local handle.
        states[index].scratch_a = Some(scratch_a);
        let scratch_b = match backend.alloc_device::<Fp2Repr>(scratch_len) {
            Ok(buffer) => buffer,
            Err(error) => {
                return Err(resident_batch_failure(error.into(), None, backend, &mut states, None));
            }
        };
        states[index].scratch_b = Some(scratch_b);
    }
    let mut mailbox = match backend.alloc_device::<Fp2Repr>(mailbox_elements) {
        Ok(mailbox) => Some(mailbox),
        Err(error) => {
            return Err(resident_batch_failure(error.into(), None, backend, &mut states, None));
        }
    };
    for round in 0..max_rounds {
        let active: Vec<usize> = states
            .iter()
            .enumerate()
            .filter_map(|(index, state)| (round < state.n_vars).then_some(index))
            .collect();

        // All product-message kernels in this public epoch share one timing
        // interval. Thunder therefore sees one event-resolution barrier, not
        // one remote cudaEventElapsedTime query per active head.
        let (product_phase, product_cleanup_error) =
            match backend.coarse_timing_scope(Operation::Gemm) {
                Ok(mut scope) => {
                    let mut first = None;
                    for (slot, &index) in active.iter().enumerate() {
                        let state = &states[index];
                        let len = state.active_len;
                        let result = scope.backend_mut().fp2_product_round_into_device(
                            DeviceSlice::new(state.active_a(), 0, len)
                                .expect("active resident A prefix"),
                            DeviceSlice::new(state.active_b(), 0, len)
                                .expect("active resident B prefix"),
                            mailbox.as_ref().expect("live resident mailbox"),
                            slot * RoundFamily::BlindProduct.message_width(),
                        );
                        if let Err(error) = result {
                            first = Some(error);
                            break;
                        }
                    }
                    match first {
                        Some(error) => {
                            let cleanup = scope.abort().err();
                            (Err(error), cleanup)
                        }
                        None => (scope.finish(), None),
                    }
                }
                Err(error) => (Err(error), None),
            };
        if let Err(error) = product_phase {
            return Err(resident_batch_failure(
                error.into(),
                product_cleanup_error,
                backend,
                &mut states,
                mailbox.take(),
            ));
        }

        let message_elements = active.len() * RoundFamily::BlindProduct.message_width();
        let raw_messages = match backend.download_device(
            mailbox.as_ref().expect("live resident mailbox"),
            0,
            message_elements,
        ) {
            Ok(messages) => messages,
            Err(error) => {
                return Err(resident_batch_failure(
                    error.into(),
                    None,
                    backend,
                    &mut states,
                    mailbox.take(),
                ));
            }
        };

        // Seal every correction before assigning the first challenge in this
        // epoch. `active` inherits canonical SiteId order from `states`.
        let mut messages = Vec::with_capacity(active.len());
        for (slot, &index) in active.iter().enumerate() {
            let g0 = Fp2::from(raw_messages[2 * slot]);
            let g2 = Fp2::from(raw_messages[2 * slot + 1]);
            let state = &mut states[index];
            debug_assert_eq!(state.mask_dom_base + round as u64, ranges[index].domain(round));
            let masks = round_masks.draw(index, round);
            state.round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
            tx.append("blind_round_corrections", 32);
            messages.push((
                index,
                ProverAuthed { x: g0, m: masks[0].m },
                ProverAuthed { x: g2, m: masks[1].m },
            ));
        }

        let mut folds = Vec::with_capacity(messages.len());
        for (index, g0, g2) in messages {
            let r = tx.challenge_fp2();
            let weights = lagrange3(r);
            let g1 = states[index].claim.sub(g0);
            states[index].claim =
                g0.scale(weights[0]).add(g1.scale(weights[1])).add(g2.scale(weights[2]));
            states[index].point.push(r);
            folds.push((index, r));
        }

        // Challenges are fixed in canonical order before this device-only
        // phase begins. Both A and B folds then reuse preallocated ping-pong
        // storage under one LogUp timing interval.
        let (fold_phase, fold_cleanup_error) = match backend.coarse_timing_scope(Operation::Logup) {
            Ok(mut scope) => {
                let mut first = None;
                for &(index, r) in &folds {
                    let state = &states[index];
                    let len = state.active_len;
                    let a_result = scope.backend_mut().fp2_fold_rows_into_device(
                        DeviceSlice::new(state.active_a(), 0, len)
                            .expect("active resident A prefix"),
                        1,
                        len,
                        r,
                        state.next_a(),
                        0,
                    );
                    if let Err(error) = a_result {
                        first = Some(error);
                        break;
                    }
                    let b_result = scope.backend_mut().fp2_fold_rows_into_device(
                        DeviceSlice::new(state.active_b(), 0, len)
                            .expect("active resident B prefix"),
                        1,
                        len,
                        r,
                        state.next_b(),
                        0,
                    );
                    if let Err(error) = b_result {
                        first = Some(error);
                        break;
                    }
                }
                match first {
                    Some(error) => {
                        let cleanup = scope.abort().err();
                        (Err(error), cleanup)
                    }
                    None => (scope.finish(), None),
                }
            }
            Err(error) => (Err(error), None),
        };
        if let Err(error) = fold_phase {
            return Err(resident_batch_failure(
                error.into(),
                fold_cleanup_error,
                backend,
                &mut states,
                mailbox.take(),
            ));
        }
        for (index, _) in folds {
            states[index].primary_active = !states[index].primary_active;
            states[index].active_len /= 2;
        }
    }
    round_masks.finish();

    let final_values = {
        let mut segments = Vec::with_capacity(2 * states.len());
        for state in &states {
            segments
                .push(DeviceSlice::new(state.active_a(), 0, 1).expect("resident final A slice"));
            segments
                .push(DeviceSlice::new(state.active_b(), 0, 1).expect("resident final B slice"));
        }
        backend.download_device_segments(&segments)
    };
    let final_values = match final_values {
        Ok(values) => values,
        Err(error) => {
            return Err(resident_batch_failure(
                error.into(),
                None,
                backend,
                &mut states,
                mailbox.take(),
            ));
        }
    };
    cleanup_resident_batch(backend, &mut states, mailbox.take())?;

    Ok(states
        .into_iter()
        .enumerate()
        .map(|(index, state)| BlindSumcheckResidentBatchOutput {
            site_id: state.site_id,
            proof: BlindSumcheckProof { round_corrs: state.round_corrs },
            point: state.point,
            claim: state.claim,
            a_final: Fp2::from(final_values[2 * index]),
            b_final: Fp2::from(final_values[2 * index + 1]),
        })
        .collect())
}

/// Resident counterpart of [`blind_prove`]. Rust retains transcript and MAC
/// orchestration; each round returns only `[g(0), g(2)]`, then folds both
/// witness vectors D2D. The input buffers are consumed on every path.
pub fn blind_prove_resident(
    mut a: DeviceBuffer<Fp2Repr>,
    mut b: DeviceBuffer<Fp2Repr>,
    claim0: ProverAuthed,
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
    backend: &mut Backend,
) -> Result<(BlindSumcheckProof, Vec<Fp2>, ProverAuthed, Fp2, Fp2), AccelError> {
    if a.len() != b.len() || a.len() < 2 || !a.len().is_power_of_two() {
        return Err(resident_accel_failure(
            AccelError::InvalidInput("resident blind sumcheck requires equal power-of-two vectors"),
            None,
            backend,
            [a, b],
        ));
    }
    let n_vars = a.len().trailing_zeros() as usize;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    for round in 0..n_vars {
        let len = a.len();
        let round_values = match backend.fp2_product_round_device(
            DeviceSlice::new(&a, 0, len).expect("whole resident A vector"),
            DeviceSlice::new(&b, 0, len).expect("whole resident B vector"),
        ) {
            Ok(values) => values,
            Err(error) => {
                return Err(resident_accel_failure(error, None, backend, [a, b]));
            }
        };
        let [g0, g2] = round_values;
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        round_corrs.push([g0 - masks[0].x, g2 - masks[1].x]);
        tx.append("blind_round_corrections", 32);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g1_a = claim.sub(g0_a);
        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));

        let next_a = match backend.fp2_fold_rows_device(&a, 0, 1, len, r) {
            Ok(value) => value,
            Err(error) => {
                return Err(resident_accel_failure(error, None, backend, [a, b]));
            }
        };
        let next_b = match backend.fp2_fold_rows_device(&b, 0, 1, len, r) {
            Ok(value) => value,
            Err(error) => {
                return Err(resident_accel_failure(error, None, backend, [next_a, a, b]));
            }
        };
        if let Err(first_cleanup) = free_fp2_pair(backend, a, b) {
            return Err(resident_accel_failure(
                first_cleanup.clone(),
                Some(first_cleanup),
                backend,
                [next_a, next_b],
            ));
        }
        a = next_a;
        b = next_b;
        point.push(r);
    }
    let finals = match backend.download_device_segments(&[
        DeviceSlice::new(&a, 0, 1).expect("resident sumcheck final A scalar"),
        DeviceSlice::new(&b, 0, 1).expect("resident sumcheck final B scalar"),
    ]) {
        Ok(value) => value,
        Err(error) => {
            return Err(resident_accel_failure(error, None, backend, [a, b]));
        }
    };
    let a_final = Fp2::from(finals[0]);
    let b_final = Fp2::from(finals[1]);
    free_fp2_pair(backend, a, b)?;
    Ok((BlindSumcheckProof { round_corrs }, point, claim, a_final, b_final))
}

/// Prover. `claim0` is the (authenticated) initial claim Ỹ(r_i, r_j).
/// Returns the proof, the bound point, and the authenticated final claim.
/// Mask domains are `mask_dom_base + round`.
pub fn blind_prove(
    mut a: Vec<Fp2>,
    mut b: Vec<Fp2>,
    claim0: ProverAuthed,
    stream: &mut CorrelationStream,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> (BlindSumcheckProof, Vec<Fp2>, ProverAuthed) {
    assert_eq!(a.len(), b.len());
    let n_vars = a.len().trailing_zeros() as usize;
    let mut round_corrs = Vec::with_capacity(n_vars);
    let mut point = Vec::with_capacity(n_vars);
    let mut claim = claim0;
    for round in 0..n_vars {
        let half = a.len() / 2;
        let mut g0 = Fp2::ZERO;
        let mut g2 = Fp2::ZERO;
        for i in 0..half {
            let (a0, a1) = (a[2 * i], a[2 * i + 1]);
            let (b0, b1) = (b[2 * i], b[2 * i + 1]);
            g0 += a0 * b0;
            let (da, db) = (a1 - a0, b1 - b0);
            g2 += (a0 + da + da) * (b0 + db + db);
        }
        // Fresh full-field masks for the two coefficients of this round.
        let masks = stream.draw_fulls(mask_dom_base + round as u64, 2);
        let corrs = [g0 - masks[0].x, g2 - masks[1].x];
        tx.append("blind_round_corrections", 32);
        round_corrs.push(corrs);
        let g0_a = ProverAuthed { x: g0, m: masks[0].m };
        let g2_a = ProverAuthed { x: g2, m: masks[1].m };
        let g1_a = claim.sub(g0_a); // g(1) = claim − g(0), authenticated

        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        claim = g0_a.scale(w[0]).add(g1_a.scale(w[1])).add(g2_a.scale(w[2]));
        fold_low(&mut a, r);
        fold_low(&mut b, r);
        point.push(r);
    }
    (BlindSumcheckProof { round_corrs }, point, claim)
}

/// Verifier: mirrors the recursion on the key side. Returns the bound point
/// and the key of the final claim.
pub fn blind_verify(
    n_vars: usize,
    k_claim0: VerifierKey,
    proof: &BlindSumcheckProof,
    ctx: &mut VerifierCtx,
    mask_dom_base: u64,
    tx: &mut Transcript,
) -> Option<(Vec<Fp2>, VerifierKey)> {
    if proof.round_corrs.len() != n_vars {
        return None;
    }
    let mut point = Vec::with_capacity(n_vars);
    let mut k_claim = k_claim0;
    for (round, corrs) in proof.round_corrs.iter().enumerate() {
        let k_masks = ctx.expand_full_keys(mask_dom_base + round as u64, 2);
        let k_g0 = VerifierKey { k: k_masks[0] + ctx.delta * corrs[0] };
        let k_g2 = VerifierKey { k: k_masks[1] + ctx.delta * corrs[1] };
        let k_g1 = k_claim.sub(k_g0);
        let r = tx.challenge_fp2();
        let w = lagrange3(r);
        k_claim = k_g0.scale(w[0]).add(k_g1.scale(w[1])).add(k_g2.scale(w[2]));
        point.push(r);
    }
    Some((point, k_claim))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumcheck_clear::prove_clear;
    use rand::{Rng, SeedableRng};
    use volta_field::{Fp, FpStream};

    fn rand_fp2(rng: &mut impl Rng) -> Fp2 {
        Fp2::new(
            Fp::new(rng.gen_range(0..volta_field::P)),
            Fp::new(rng.gen_range(0..volta_field::P)),
        )
    }

    #[test]
    fn resident_failure_helpers_preserve_first_cleanup_error() {
        let primary = AccelError::InvalidInput("primary failure");
        let first_cleanup = AccelError::Cuda("first cleanup failure".into());
        let second_cleanup = AccelError::Cuda("second cleanup failure".into());

        let mut observed = None;
        record_cleanup_error(&mut observed, Err(first_cleanup.clone()));
        record_cleanup_error(&mut observed, Err(second_cleanup));
        record_cleanup_error(&mut observed, Ok(()));
        assert_eq!(observed, Some(first_cleanup.clone()));

        assert_eq!(prefer_cleanup_accel_error(primary.clone(), observed.clone()), first_cleanup);
        assert_eq!(prefer_cleanup_accel_error(primary.clone(), None), primary);

        match prefer_cleanup_batch_error(ResidentBlindBatchError::Accel(primary.clone()), observed)
        {
            ResidentBlindBatchError::Accel(error) => assert_eq!(error, first_cleanup),
            other => panic!("cleanup failure must become the batch error, got {other}"),
        }
        match prefer_cleanup_batch_error(ResidentBlindBatchError::Accel(primary.clone()), None) {
            ResidentBlindBatchError::Accel(error) => assert_eq!(error, primary),
            other => panic!("primary batch error must survive clean release, got {other}"),
        }
    }

    #[test]
    fn blind_matches_clear_differential() {
        // Same witness, same challenges: the blind transcript's authenticated
        // round values must equal the clear round polys pointwise.
        let mut rng = rand::rngs::StdRng::seed_from_u64(81);
        let a: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
        let b: Vec<Fp2> = (0..32).map(|_| rand_fp2(&mut rng)).collect();
        let claim_val = a.iter().zip(&b).fold(Fp2::ZERO, |s, (&x, &y)| s + x * y);

        // Clear reference with the transcript's challenge stream: Transcript
        // challenges come from domain u64::MAX of the tx seed.
        let tx_seed = [4u8; 32];
        let (clear, _) =
            prove_clear(a.clone(), b.clone(), &mut FpStream::domain_separated(tx_seed, u64::MAX));

        let mut ps = CorrelationStream::new([5u8; 32]);
        let mut tx = Transcript::new(tx_seed);
        let claim0 = ProverAuthed { x: claim_val, m: rand_fp2(&mut rng) };
        let (blind, _, final_claim) =
            blind_prove(a.clone(), b.clone(), claim0, &mut ps, 1000, &mut tx);

        // Reconstruct blind g values from corrections + the same mask stream.
        let mut check = CorrelationStream::new([5u8; 32]);
        for (round, corrs) in blind.round_corrs.iter().enumerate() {
            let masks = check.draw_fulls(1000 + round as u64, 2);
            assert_eq!(masks[0].x + corrs[0], clear.rounds[round][0], "g(0) round {round}");
            assert_eq!(masks[1].x + corrs[1], clear.rounds[round][1], "g(2) round {round}");
        }
        assert_eq!(final_claim.x, clear.a_final * clear.b_final);
        // Mask freshness: 2 fresh full correlations per round, all counted.
        assert_eq!(ps.counters.full_corrs, 2 * blind.round_corrs.len() as u64);
    }

    #[test]
    fn round_synchronous_batch_is_canonical_and_verifier_mirrored() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xB47C_2026);
        let pcg_seed = [0x35; 32];
        let tx_seed = [0x91; 32];
        let delta = rand_fp2(&mut rng);

        let mut witnesses = Vec::new();
        for &(lane, len, domain) in
            &[(30u64, 8usize, 0x30_000u64), (10, 16, 0x10_000), (20, 8, 0x20_000)]
        {
            let site_id = SiteId::new(9, RoundFamily::BlindProduct, lane as u32);
            let a: Vec<Fp2> = (0..len).map(|_| rand_fp2(&mut rng)).collect();
            let b: Vec<Fp2> = (0..len).map(|_| rand_fp2(&mut rng)).collect();
            let total = a.iter().zip(&b).fold(Fp2::ZERO, |sum, (&x, &y)| sum + x * y);
            witnesses.push((site_id, domain, a, b, total));
        }

        // Deliberately submit out of order: both parties must canonicalize by
        // SiteId before consuming either correlations or challenges.
        let jobs = witnesses
            .iter()
            .map(|(site_id, domain, a, b, total)| BlindSumcheckBatchJob {
                site_id: *site_id,
                a: a.clone(),
                b: b.clone(),
                claim0: ProverAuthed::from_public(*total),
                mask_dom_base: *domain,
            })
            .collect();
        let mut prover_stream = CorrelationStream::new(pcg_seed);
        let mut prover_tx = Transcript::new(tx_seed);
        let plan = SchedulePlan::new(
            witnesses
                .iter()
                .map(|(site_id, domain, a, _, _)| ScheduleSite {
                    id: *site_id,
                    rounds: a.len().trailing_zeros() as usize,
                    mask_dom_base: *domain,
                    mask_dom_span: a.len().trailing_zeros() as u64,
                })
                .collect(),
        )
        .unwrap();
        let outputs = blind_prove_batch(&plan, jobs, &mut prover_stream, &mut prover_tx).unwrap();
        assert_eq!(outputs.iter().map(|out| out.site_id.lane()).collect::<Vec<_>>(), [10, 20, 30]);
        assert_eq!(
            outputs.iter().map(|out| out.proof.round_corrs.len()).collect::<Vec<_>>(),
            [4, 3, 3]
        );
        assert_eq!(prover_tx.bytes_for("blind_round_corrections"), 32 * 10);

        let verify_jobs = outputs
            .iter()
            .map(|out| {
                let (_, domain, a, _, total) = witnesses
                    .iter()
                    .find(|(site_id, _, _, _, _)| *site_id == out.site_id)
                    .expect("known public SiteId");
                BlindSumcheckBatchVerifyJob {
                    site_id: out.site_id,
                    n_vars: a.len().trailing_zeros() as usize,
                    claim0: VerifierKey::from_public(*total, delta),
                    proof: &out.proof,
                    mask_dom_base: *domain,
                }
            })
            .rev()
            .collect();
        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let verified = blind_verify_batch(&plan, verify_jobs, &mut verifier, &mut verifier_tx)
            .expect("scheduled verifier accepts");
        assert_eq!(verified.iter().map(|out| out.site_id.lane()).collect::<Vec<_>>(), [10, 20, 30]);
        for (prover, verifier) in outputs.iter().zip(&verified) {
            assert_eq!(verifier.point, prover.point);
            assert_eq!(verifier.claim.k, prover.claim.m + delta * prover.claim.x);
        }
        assert_eq!(verifier.counters, prover_stream.counters);

        // The new schedule does not pretend to preserve the historical
        // sequential challenge assignment: site 20 receives challenge #2 in
        // the first epoch, not the challenge after all four site-10 rounds.
        let mut sequential_stream = CorrelationStream::new(pcg_seed);
        let mut sequential_tx = Transcript::new(tx_seed);
        let mut sequential_point = Vec::new();
        for lane in [10, 20, 30] {
            let site = witnesses.iter().find(|(site, _, _, _, _)| site.lane() == lane).unwrap();
            let (_, point, _) = blind_prove(
                site.2.clone(),
                site.3.clone(),
                ProverAuthed::from_public(site.4),
                &mut sequential_stream,
                site.1,
                &mut sequential_tx,
            );
            if lane == 20 {
                sequential_point = point;
            }
        }
        assert_ne!(outputs[1].point, sequential_point);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_batch_matches_scheduled_cpu_with_one_barrier_per_epoch() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident batch differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xB47C_A100);
        let pcg_seed = [0xA7; 32];
        let tx_seed = [0xD3; 32];
        let delta = rand_fp2(&mut rng);

        // Twelve public lanes at depth seven mirror the natural T=100 W·V
        // attention cohort. Submission order is deliberately reversed; CPU
        // and GPU must still emit canonical SiteId order while host-output
        // barriers scale with depth, never `12 * depth`.
        let mut witnesses = Vec::new();
        for &(lane, depth, domain) in &[
            (70u32, 7usize, 0x70_000u64),
            (10, 7, 0x10_000),
            (120, 7, 0xC0_000),
            (40, 7, 0x40_000),
            (90, 7, 0x90_000),
            (20, 7, 0x20_000),
            (110, 7, 0xB0_000),
            (60, 7, 0x60_000),
            (30, 7, 0x30_000),
            (100, 7, 0xA0_000),
            (50, 7, 0x50_000),
            (80, 7, 0x80_000),
        ] {
            let site_id = SiteId::new(17, RoundFamily::BlindProduct, lane);
            let len = 1usize << depth;
            let a: Vec<Fp2> = (0..len).map(|_| rand_fp2(&mut rng)).collect();
            let b: Vec<Fp2> = (0..len).map(|_| rand_fp2(&mut rng)).collect();
            let total = a.iter().zip(&b).fold(Fp2::ZERO, |sum, (&x, &y)| sum + x * y);
            witnesses.push((site_id, depth, domain, a, b, total));
        }
        let plan = SchedulePlan::new(
            witnesses
                .iter()
                .map(|(site_id, depth, domain, _, _, _)| ScheduleSite {
                    id: *site_id,
                    rounds: *depth,
                    mask_dom_base: *domain,
                    mask_dom_span: *depth as u64,
                })
                .collect(),
        )
        .unwrap();

        // Exact membership is a pure preflight with respect to transcript and
        // correlations, while owned device inputs are still reclaimed.
        let preflight_site = SiteId::new(18, RoundFamily::BlindProduct, 1);
        let preflight_plan = SchedulePlan::new(vec![ScheduleSite {
            id: preflight_site,
            rounds: 3,
            mask_dom_base: 0x41_001,
            mask_dom_span: 3,
        }])
        .unwrap();
        let preflight_values = vec![Fp2Repr::default(); 8];
        let preflight_a = gpu.upload_new_device(&preflight_values).unwrap();
        let preflight_b = gpu.upload_new_device(&preflight_values).unwrap();
        let mut preflight_stream = CorrelationStream::new([0x11; 32]);
        let mut preflight_tx = Transcript::new([0x22; 32]);
        let preflight_error = blind_prove_resident_batch(
            &preflight_plan,
            vec![BlindSumcheckResidentBatchJob {
                site_id: preflight_site,
                a: preflight_a,
                b: preflight_b,
                claim0: ProverAuthed::from_public(Fp2::ZERO),
                mask_dom_base: 0x41_000,
            }],
            &mut preflight_stream,
            &mut preflight_tx,
            &mut gpu,
        )
        .unwrap_err();
        assert!(matches!(
            preflight_error,
            ResidentBlindBatchError::Schedule(ScheduleError::MembershipMismatch {
                family: RoundFamily::BlindProduct,
            })
        ));
        assert_eq!(preflight_stream.counters, Default::default());
        assert!(preflight_tx.ledger().is_empty());
        assert_eq!(gpu.device_memory_breakdown().unwrap().resident_bytes, 0);

        // A collision in the *second* noncontiguous range is detected before
        // the first range is reserved, before any CUDA work/transcript byte,
        // and all transferred input owners are reclaimed.
        let collision_sites = [
            (SiteId::new(19, RoundFamily::BlindProduct, 1), 0x43_000u64),
            (SiteId::new(19, RoundFamily::BlindProduct, 2), 0x44_000u64),
        ];
        let collision_plan = SchedulePlan::new(
            collision_sites
                .iter()
                .map(|&(id, base)| ScheduleSite {
                    id,
                    rounds: 3,
                    mask_dom_base: base,
                    mask_dom_span: 3,
                })
                .collect(),
        )
        .unwrap();
        let mut collision_stream = CorrelationStream::new([0x51; 32]);
        collision_stream.draw_fulls(0x44_001, 2);
        let collision_before = collision_stream.counters;
        let mut collision_tx = Transcript::new([0x52; 32]);
        let collision_jobs = collision_sites
            .iter()
            .map(|&(site_id, mask_dom_base)| BlindSumcheckResidentBatchJob {
                site_id,
                a: gpu.upload_new_device(&preflight_values).unwrap(),
                b: gpu.upload_new_device(&preflight_values).unwrap(),
                claim0: ProverAuthed::from_public(Fp2::ZERO),
                mask_dom_base,
            })
            .collect();
        let collision_error = blind_prove_resident_batch(
            &collision_plan,
            collision_jobs,
            &mut collision_stream,
            &mut collision_tx,
            &mut gpu,
        )
        .unwrap_err();
        assert!(matches!(collision_error, ResidentBlindBatchError::Correlation(_)));
        assert_eq!(collision_stream.counters, collision_before);
        assert!(collision_tx.ledger().is_empty());
        assert_eq!(gpu.device_memory_breakdown().unwrap().resident_bytes, 0);

        let mut foreign = Backend::cuda_resident().unwrap();
        let ownership_plan = SchedulePlan::new(vec![ScheduleSite {
            id: preflight_site,
            rounds: 3,
            mask_dom_base: 0x42_000,
            mask_dom_span: 3,
        }])
        .unwrap();
        let owned_a = gpu.upload_new_device(&preflight_values).unwrap();
        let owned_b = gpu.upload_new_device(&preflight_values).unwrap();
        let mut ownership_stream = CorrelationStream::new([0x33; 32]);
        let mut ownership_tx = Transcript::new([0x44; 32]);
        let ownership_error = blind_prove_resident_batch(
            &ownership_plan,
            vec![BlindSumcheckResidentBatchJob {
                site_id: preflight_site,
                a: owned_a,
                b: owned_b,
                claim0: ProverAuthed::from_public(Fp2::ZERO),
                mask_dom_base: 0x42_000,
            }],
            &mut ownership_stream,
            &mut ownership_tx,
            &mut foreign,
        )
        .unwrap_err();
        let recovered = ownership_error.into_jobs().expect("foreign jobs are recoverable");
        assert_eq!(ownership_stream.counters, Default::default());
        assert!(ownership_tx.ledger().is_empty());
        assert_eq!(foreign.device_memory_breakdown().unwrap().resident_bytes, 0);
        for job in recovered {
            free_fp2_pair(&mut gpu, job.a, job.b).unwrap();
        }
        assert_eq!(gpu.device_memory_breakdown().unwrap().resident_bytes, 0);

        let cpu_jobs = witnesses
            .iter()
            .map(|(site_id, _, domain, a, b, total)| BlindSumcheckBatchJob {
                site_id: *site_id,
                a: a.clone(),
                b: b.clone(),
                claim0: ProverAuthed::from_public(*total),
                mask_dom_base: *domain,
            })
            .collect();
        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let cpu_outputs = blind_prove_batch(&plan, cpu_jobs, &mut cpu_stream, &mut cpu_tx).unwrap();

        let mut resident_jobs = Vec::new();
        for index in (0..witnesses.len()).rev() {
            let (site_id, _, domain, a, b, total) = &witnesses[index];
            let raw_a: Vec<Fp2Repr> = a.iter().copied().map(Into::into).collect();
            let raw_b: Vec<Fp2Repr> = b.iter().copied().map(Into::into).collect();
            resident_jobs.push(BlindSumcheckResidentBatchJob {
                site_id: *site_id,
                a: gpu.upload_new_device(&raw_a).unwrap(),
                b: gpu.upload_new_device(&raw_b).unwrap(),
                claim0: ProverAuthed::from_public(*total),
                mask_dom_base: *domain,
            });
        }
        let mut resident_stream = CorrelationStream::new(pcg_seed);
        let mut resident_tx = Transcript::new(tx_seed);
        gpu.begin_measurement().unwrap();
        let resident_outputs = blind_prove_resident_batch(
            &plan,
            resident_jobs,
            &mut resident_stream,
            &mut resident_tx,
            &mut gpu,
        )
        .unwrap();
        let stats = gpu.finish_measurement().unwrap();

        assert_eq!(
            resident_outputs.iter().map(|out| out.site_id.lane()).collect::<Vec<_>>(),
            (1..=12).map(|lane| lane * 10).collect::<Vec<_>>()
        );
        for (cpu, resident) in cpu_outputs.iter().zip(&resident_outputs) {
            assert_eq!(resident.site_id, cpu.site_id);
            assert_eq!(resident.proof, cpu.proof);
            assert_eq!(resident.point, cpu.point);
            assert_eq!(resident.claim, cpu.claim);
            let witness = witnesses
                .iter()
                .find(|(site_id, _, _, _, _, _)| *site_id == resident.site_id)
                .unwrap();
            assert_eq!(resident.a_final, crate::mle::eval_mle(&witness.3, &resident.point));
            assert_eq!(resident.b_final, crate::mle::eval_mle(&witness.4, &resident.point));
        }
        assert_eq!(resident_stream.counters, cpu_stream.counters);
        assert_eq!(resident_tx.ledger(), cpu_tx.ledger());
        let rounds: usize = witnesses.iter().map(|witness| witness.1).sum();
        assert_eq!(resident_tx.bytes_for("blind_round_corrections"), 32 * rounds as u64);

        let verify_jobs = resident_outputs
            .iter()
            .rev()
            .map(|output| {
                let witness = witnesses
                    .iter()
                    .find(|(site_id, _, _, _, _, _)| *site_id == output.site_id)
                    .unwrap();
                BlindSumcheckBatchVerifyJob {
                    site_id: output.site_id,
                    n_vars: witness.1,
                    claim0: VerifierKey::from_public(witness.5, delta),
                    proof: &output.proof,
                    mask_dom_base: witness.2,
                }
            })
            .collect();
        let mut verifier = VerifierCtx::new(pcg_seed, delta);
        let mut verifier_tx = Transcript::new(tx_seed);
        let verified = blind_verify_batch(&plan, verify_jobs, &mut verifier, &mut verifier_tx)
            .expect("resident scheduled proof verifies");
        for (resident, verified) in resident_outputs.iter().zip(verified) {
            assert_eq!(verified.site_id, resident.site_id);
            assert_eq!(verified.point, resident.point);
            assert_eq!(verified.claim.k, resident.claim.m + delta * resident.claim.x);
        }
        assert_eq!(verifier.counters, resident_stream.counters);

        let expected_d2h_elements = 2 * rounds + 2 * witnesses.len();
        assert_eq!(stats.h2d_bytes, 0);
        assert_eq!(
            stats.d2h_bytes,
            (expected_d2h_elements * std::mem::size_of::<Fp2Repr>()) as u64
        );
        assert_eq!(stats.sync_host_output, plan.round_epoch_upper_bound() as u64 + 1);
        let legacy_per_head_sync = rounds + witnesses.len();
        assert_eq!(legacy_per_head_sync, 96);
        assert_eq!(stats.sync_host_output, 8);
        assert_eq!(legacy_per_head_sync as u64 - stats.sync_host_output, 88);
        assert_eq!(stats.coarse_timing_scopes, 2 * plan.round_epoch_upper_bound() as u64);
        assert_eq!(gpu.device_memory_breakdown().unwrap().resident_bytes, 0);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_blind_sumcheck_matches_cpu_and_reuses_context() {
        let mut gpu = match Backend::cuda_resident() {
            Ok(gpu) => gpu,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident sumcheck differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x51A7);
        let a: Vec<Fp2> = (0..128).map(|_| rand_fp2(&mut rng)).collect();
        let b: Vec<Fp2> = (0..128).map(|_| rand_fp2(&mut rng)).collect();
        let total = a.iter().zip(&b).fold(Fp2::ZERO, |sum, (&x, &y)| sum + x * y);
        let claim0 = ProverAuthed { x: total, m: rand_fp2(&mut rng) };
        let pcg_seed = [0xA3; 32];
        let tx_seed = [0x6C; 32];
        let mut cpu_stream = CorrelationStream::new(pcg_seed);
        let mut cpu_tx = Transcript::new(tx_seed);
        let (cpu_proof, cpu_point, cpu_claim) =
            blind_prove(a.clone(), b.clone(), claim0, &mut cpu_stream, 0xD000, &mut cpu_tx);
        let mut live_after_first = None;
        for _ in 0..2 {
            let da = gpu
                .upload_new_device(&a.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let db = gpu
                .upload_new_device(&b.iter().copied().map(Into::into).collect::<Vec<_>>())
                .unwrap();
            let mut stream = CorrelationStream::new(pcg_seed);
            let mut tx = Transcript::new(tx_seed);
            let (proof, point, claim, a_final, b_final) =
                blind_prove_resident(da, db, claim0, &mut stream, 0xD000, &mut tx, &mut gpu)
                    .unwrap();
            assert_eq!(proof, cpu_proof);
            assert_eq!(point, cpu_point);
            assert_eq!(claim, cpu_claim);
            assert_eq!(a_final, crate::mle::eval_mle(&a, &point));
            assert_eq!(b_final, crate::mle::eval_mle(&b, &point));
            assert_eq!(stream.counters, cpu_stream.counters);
            assert_eq!(tx.ledger(), cpu_tx.ledger());
            let live = gpu.stats().unwrap().live_device_bytes;
            if let Some(first) = live_after_first {
                assert_eq!(live, first, "resident sumcheck leaked across context reuse");
            } else {
                // Workspace is persistent by design; resident inputs/folds
                // have already been freed by the sumcheck.
                assert!(live > 0);
                live_after_first = Some(live);
            }
        }
    }
}
