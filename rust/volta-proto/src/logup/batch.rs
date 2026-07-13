//! Round-synchronous lookup-side LogUp cohorts.
//!
//! This module deliberately sits below GPT-2 call sites. It owns protocol
//! state across global root/round/split epochs so every ready device job can
//! share one protocol-visible D2H mailbox, while the unchanged singleton API
//! remains the compatibility path.

use super::*;
use crate::schedule::{
    CorrelationScope, CorrelationSegment, RoundFamily, ScheduleError, SchedulePlan, ScheduleSite,
    SiteCorrPlan, SiteId, StagedEpoch, StagedEpochSite,
};
use std::fmt;
use volta_mac::{
    CorrReservationError, FullCorrBatchReservation, FullCorrRange, FullKeyBatchReservation,
};

/// Fixed deferred-timing ring in the current CUDA backend.
pub const LOGUP_BATCH_TIMING_RING_CAPACITY: usize = volta_accel::DEFERRED_TIMING_CAPACITY;
/// Conservative maximum number of deferred records produced while preparing
/// one resident site for its next public mailbox.
pub const LOGUP_BATCH_PREPARATION_RECORDS_PER_SITE: usize = 9;

/// One explicit deferred-timing preflight and the consecutive slice of the
/// sealed active-site list it protects. The final chunk also reserves the two
/// records that close the phase: the coarse mailbox interval and its D2H.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogupTimingPreparationChunk {
    pub site_offset: usize,
    pub site_count: usize,
    pub record_bound: usize,
}

/// Deterministically split a preparation phase so no resident timing record
/// can trigger an automatic mid-phase flush. For 72 sites this is two public
/// preflights (56 + 16), not two protocol cohorts: membership, transcript
/// order, mailbox layout, proof bytes and the sole epoch D2H are unchanged.
pub fn logup_batch_timing_preparation_chunks(
    site_count: usize,
) -> Option<Vec<LogupTimingPreparationChunk>> {
    let per_site = LOGUP_BATCH_PREPARATION_RECORDS_PER_SITE;
    let closing_records = 2usize;
    let max_without_mailbox =
        LOGUP_BATCH_TIMING_RING_CAPACITY.checked_sub(closing_records)? / per_site;
    if max_without_mailbox == 0 || site_count == 0 {
        return None;
    }
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while offset < site_count {
        let count = (site_count - offset).min(max_without_mailbox);
        let last = offset.checked_add(count)? == site_count;
        let record_bound =
            count.checked_mul(per_site)?.checked_add(if last { closing_records } else { 0 })?;
        chunks.push(LogupTimingPreparationChunk {
            site_offset: offset,
            site_count: count,
            record_bound,
        });
        offset = offset.checked_add(count)?;
    }
    Some(chunks)
}

/// Public geometry and exact correlation allocation for one lookup instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogupBatchSite {
    pub id: SiteId,
    pub depth: usize,
    pub column_count: usize,
    pub aux_claim_count: usize,
    pub mask_dom_base: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogupBatchPlan {
    schedule: SchedulePlan,
    sites: Vec<LogupBatchSite>,
    full_corr_ranges: Vec<FullCorrRange>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum LogupBatchError {
    Schedule(ScheduleError),
    CohortTooSmall,
    InvalidGeometry(SiteId),
    InvalidProof(SiteId),
    CorrelationRoleMismatch(SiteId),
    Correlation(CorrReservationError),
    Accel(AccelError),
}

impl fmt::Display for LogupBatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schedule(error) => write!(f, "LogUp batch schedule: {error}"),
            Self::CohortTooSmall => write!(f, "LogUp batch requires at least two sites"),
            Self::InvalidGeometry(site) => {
                write!(f, "LogUp batch site {:#x} has invalid geometry", site.packed())
            }
            Self::InvalidProof(site) => {
                write!(f, "LogUp batch proof for site {:#x} has invalid shape", site.packed())
            }
            Self::CorrelationRoleMismatch(site) => write!(
                f,
                "LogUp batch site {:#x} consumed a correlation outside its sealed role",
                site.packed()
            ),
            Self::Correlation(error) => write!(f, "LogUp correlation reservation: {error}"),
            Self::Accel(error) => write!(f, "resident LogUp batch accelerator: {error}"),
        }
    }
}

impl std::error::Error for LogupBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Schedule(error) => Some(error),
            Self::Correlation(error) => Some(error),
            Self::Accel(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ScheduleError> for LogupBatchError {
    fn from(error: ScheduleError) -> Self {
        Self::Schedule(error)
    }
}

impl From<AccelError> for LogupBatchError {
    fn from(error: AccelError) -> Self {
        Self::Accel(error)
    }
}

impl From<CorrReservationError> for LogupBatchError {
    fn from(error: CorrReservationError) -> Self {
        Self::Correlation(error)
    }
}

fn correlations_per_domain(
    site: LogupBatchSite,
    scope: CorrelationScope,
) -> Result<usize, LogupBatchError> {
    match scope {
        CorrelationScope::LogupRoot | CorrelationScope::LogupGeneralRound => Ok(2),
        CorrelationScope::LogupAuxRound | CorrelationScope::LogupProduct => Ok(3),
        CorrelationScope::LogupSplit => Ok(4),
        CorrelationScope::LogupAuxColumn => {
            site.column_count.checked_mul(2).ok_or(LogupBatchError::InvalidGeometry(site.id))
        }
        CorrelationScope::Round => Err(LogupBatchError::CorrelationRoleMismatch(site.id)),
    }
}

fn logup_domain_span(depth: usize) -> Option<u64> {
    let depth = u64::try_from(depth).ok()?;
    depth
        .checked_mul(depth.checked_sub(1)?)
        .and_then(|rounds| rounds.checked_div(2))
        .and_then(|rounds| rounds.checked_add(depth.checked_mul(2)?))
        .and_then(|span| span.checked_add(2))
}

fn logup_message_epochs(depth: usize) -> Option<usize> {
    depth
        .checked_mul(depth.checked_sub(1)?)
        .and_then(|rounds| rounds.checked_div(2))
        .and_then(|rounds| rounds.checked_add(depth))
        .and_then(|epochs| epochs.checked_add(1))
}

fn correlation_segments(depth: usize) -> Result<Vec<CorrelationSegment>, LogupBatchError> {
    let mut segments = Vec::new();
    let mut offset = 0u64;
    let mut push = |scope: CorrelationScope, span: u64| -> Result<(), LogupBatchError> {
        if span == 0 {
            return Ok(());
        }
        segments.push(CorrelationSegment { offset, span, scope });
        offset = offset.checked_add(span).ok_or(ScheduleError::RoundD2hOverflow)?;
        Ok(())
    };
    push(CorrelationScope::LogupRoot, 1)?;
    for layer in 0..depth {
        if layer + 1 == depth {
            push(CorrelationScope::LogupAuxRound, layer as u64)?;
            push(CorrelationScope::LogupSplit, 1)?;
            push(CorrelationScope::LogupProduct, 1)?;
            push(CorrelationScope::LogupAuxColumn, 1)?;
        } else {
            push(CorrelationScope::LogupGeneralRound, layer as u64)?;
            push(CorrelationScope::LogupSplit, 1)?;
            push(CorrelationScope::LogupProduct, 1)?;
        }
    }
    Ok(segments)
}

impl LogupBatchPlan {
    pub fn new(mut sites: Vec<LogupBatchSite>) -> Result<Self, LogupBatchError> {
        if sites.len() < 2 {
            return Err(LogupBatchError::CohortTooSmall);
        }
        sites.sort_by_key(|site| site.id);
        // A large public cohort is kept intact and protected by explicit
        // preparation chunks; it is never split merely to fit the timing
        // ring. Validate the deterministic chunk geometry up front.
        logup_batch_timing_preparation_chunks(sites.len())
            .ok_or(ScheduleError::MailboxSizeOverflow)?;

        let mut schedule_sites = Vec::with_capacity(sites.len());
        let mut correlations = Vec::with_capacity(sites.len());
        let mut full_corr_ranges = Vec::new();
        for site in &sites {
            if site.id.family() != Some(RoundFamily::LogupAux)
                || site.depth == 0
                || site.column_count == 0
                || site
                    .column_count
                    .checked_sub(1)
                    .and_then(|max_column| u32::try_from(max_column).ok())
                    .is_none()
            {
                return Err(LogupBatchError::InvalidGeometry(site.id));
            }
            let span =
                logup_domain_span(site.depth).ok_or(LogupBatchError::InvalidGeometry(site.id))?;
            let rounds = logup_message_epochs(site.depth)
                .ok_or(LogupBatchError::InvalidGeometry(site.id))?;
            schedule_sites.push(ScheduleSite {
                id: site.id,
                rounds,
                mask_dom_base: site.mask_dom_base,
                mask_dom_span: span,
            });
            let segments = correlation_segments(site.depth)?;
            for segment in &segments {
                let base_domain = site
                    .mask_dom_base
                    .checked_add(segment.offset)
                    .ok_or(LogupBatchError::InvalidGeometry(site.id))?;
                let rows = usize::try_from(segment.span)
                    .map_err(|_| LogupBatchError::InvalidGeometry(site.id))?;
                full_corr_ranges.push(FullCorrRange {
                    base_domain,
                    rows,
                    count_per_domain: correlations_per_domain(*site, segment.scope)?,
                });
            }
            correlations.push(SiteCorrPlan { site: site.id, segments });
        }
        let max_depth = sites.iter().map(|site| site.depth).max().unwrap_or(0);
        let mut epochs = Vec::new();
        epochs.push(StagedEpoch {
            sites: sites
                .iter()
                .map(|site| StagedEpochSite {
                    id: site.id,
                    family: RoundFamily::LogupRoot,
                    message_width: 2,
                })
                .collect(),
        });
        for layer in 0..max_depth {
            let active: Vec<_> = sites.iter().filter(|site| layer < site.depth).copied().collect();
            for _ in 0..layer {
                let epoch_sites: Vec<_> = active
                    .iter()
                    .map(|site| {
                        let leaf = layer + 1 == site.depth;
                        StagedEpochSite {
                            id: site.id,
                            family: if leaf {
                                RoundFamily::LogupAux
                            } else {
                                RoundFamily::LogupGeneral
                            },
                            message_width: if leaf { 3 } else { 4 },
                        }
                    })
                    .collect();
                epochs.push(StagedEpoch { sites: epoch_sites });
            }
            let split_sites: Vec<_> = active
                .iter()
                .map(|site| {
                    let leaf = layer + 1 == site.depth;
                    let message_width = if leaf {
                        site.column_count
                            .checked_mul(2)
                            // Lookup-side leaf numerators are the public
                            // constant one.  Only q0/q1 and the auxiliary
                            // columns need a resident mailbox slot; p0/p1
                            // are reconstructed canonically on the host.
                            .and_then(|width| width.checked_add(2))
                            .ok_or(ScheduleError::MailboxSizeOverflow)?
                    } else {
                        4
                    };
                    Ok(StagedEpochSite {
                        id: site.id,
                        family: RoundFamily::LogupSplit,
                        message_width,
                    })
                })
                .collect::<Result<_, ScheduleError>>()?;
            epochs.push(StagedEpoch { sites: split_sites });
        }
        let schedule = SchedulePlan::new_staged(schedule_sites, correlations, epochs)?;
        Ok(Self { schedule, sites, full_corr_ranges })
    }

    pub fn sites(&self) -> &[LogupBatchSite] {
        &self.sites
    }

    pub fn schedule(&self) -> &SchedulePlan {
        &self.schedule
    }

    pub fn timing_preparation_chunks(
        &self,
        active_site_count: usize,
    ) -> Option<Vec<LogupTimingPreparationChunk>> {
        if active_site_count > self.sites.len() {
            return None;
        }
        logup_batch_timing_preparation_chunks(active_site_count)
    }

    /// Exact, canonical full-field correlation reservation. One range maps to
    /// one sealed role segment; row order within the range is round order.
    pub fn full_corr_ranges(&self) -> &[FullCorrRange] {
        &self.full_corr_ranges
    }

    fn site(&self, id: SiteId) -> Option<LogupBatchSite> {
        self.sites.binary_search_by_key(&id, |site| site.id).ok().map(|i| self.sites[i])
    }

    fn validate_membership<I>(&self, actual: I) -> Result<(), LogupBatchError>
    where
        I: IntoIterator<Item = (SiteId, usize, usize, usize)>,
    {
        let mut actual: Vec<_> = actual.into_iter().collect();
        actual.sort_by_key(|entry| entry.0);
        let expected: Vec<_> = self
            .sites
            .iter()
            .map(|site| (site.id, site.depth, site.column_count, site.aux_claim_count))
            .collect();
        if actual != expected {
            return Err(ScheduleError::MembershipMismatch { family: RoundFamily::LogupAux }.into());
        }
        Ok(())
    }
}

pub struct CpuLogupBatchJob {
    pub site: SiteId,
    pub columns: Vec<Vec<Fp>>,
    pub shifts: Vec<Option<u32>>,
    pub alpha: Fp2,
    pub aux_claims: Vec<LeafAuxClaim>,
}

pub struct ResidentLogupBatchJob<'a> {
    pub site: SiteId,
    pub columns: DeviceSlice<'a, u64>,
    pub column_count: usize,
    pub entries: usize,
    pub shifts: Vec<Option<u32>>,
    pub alpha: Fp2,
    pub aux_claims: Vec<LeafAuxClaim>,
}

pub struct VerifyLogupBatchJob<'a> {
    pub site: SiteId,
    pub n_bits: usize,
    pub shifts: &'a [Option<u32>],
    pub alpha: Fp2,
    pub proof: &'a BlindInstance,
    pub aux_claims: &'a [(usize, Vec<Fp2>, VerifierKey)],
}

pub struct LogupBatchOutputP {
    pub site: SiteId,
    pub output: InstanceOutP,
}

pub struct LogupBatchOutputV {
    pub site: SiteId,
    pub output: InstanceOutV,
}

#[derive(Clone)]
struct CorrelationCursor {
    site: SiteId,
    segments: Vec<CorrelationSegment>,
    range_base: usize,
    segment: usize,
    within: usize,
}

#[derive(Clone, Copy)]
struct CorrelationDraw {
    range: usize,
    row: usize,
}

impl CorrelationCursor {
    fn new(plan: &LogupBatchPlan, site: SiteId) -> Result<Self, LogupBatchError> {
        let corr_index = plan
            .schedule
            .correlations()
            .binary_search_by_key(&site, |corr| corr.site)
            .map_err(|_| LogupBatchError::InvalidGeometry(site))?;
        let corr = &plan.schedule.correlations()[corr_index];
        let range_base = plan.schedule.correlations()[..corr_index]
            .iter()
            .try_fold(0usize, |base, prior| base.checked_add(prior.segments.len()))
            .ok_or(LogupBatchError::InvalidGeometry(site))?;
        Ok(Self { site, segments: corr.segments.clone(), range_base, segment: 0, within: 0 })
    }

    fn take(&mut self, scope: CorrelationScope) -> Result<CorrelationDraw, LogupBatchError> {
        let segment = self
            .segments
            .get(self.segment)
            .ok_or(LogupBatchError::CorrelationRoleMismatch(self.site))?;
        let span = usize::try_from(segment.span)
            .map_err(|_| LogupBatchError::CorrelationRoleMismatch(self.site))?;
        if segment.scope != scope || self.within >= span {
            return Err(LogupBatchError::CorrelationRoleMismatch(self.site));
        }
        let draw = CorrelationDraw {
            range: self
                .range_base
                .checked_add(self.segment)
                .ok_or(LogupBatchError::CorrelationRoleMismatch(self.site))?,
            row: self.within,
        };
        self.within = self
            .within
            .checked_add(1)
            .ok_or(LogupBatchError::CorrelationRoleMismatch(self.site))?;
        if self.within == span {
            self.segment += 1;
            self.within = 0;
        }
        Ok(draw)
    }

    fn complete(&self) -> bool {
        self.segment == self.segments.len() && self.within == 0
    }
}

struct PendingRound2 {
    h0: ProverAuthed,
    h2: ProverAuthed,
    point: Fp2,
}

struct PendingRound3 {
    values: [ProverAuthed; 3],
    point: Fp2,
}

struct PendingSplitP {
    p0: ProverAuthed,
    p1: ProverAuthed,
    q0: ProverAuthed,
    q1: ProverAuthed,
    columns: Option<Vec<[ProverAuthed; 2]>>,
}

struct BatchBlindState {
    site: SiteId,
    corr: CorrelationCursor,
    cp: ProverAuthed,
    cq: ProverAuthed,
    claim: ProverAuthed,
    lambda: Fp2,
    cpref: Fp2,
    root_corrs: [Fp2; 2],
    rounds_cur: Vec<[Fp2; 2]>,
    layers: Vec<BlindLayerProof>,
    roots: (ProverAuthed, ProverAuthed),
    rounds3_cur: Vec<[Fp2; 3]>,
    col_corrs: Vec<[Fp2; 2]>,
    aux_col_claims: Vec<ProverAuthed>,
    pending_round2: Option<PendingRound2>,
    pending_round3: Option<PendingRound3>,
    pending_split: Option<PendingSplitP>,
}

impl BatchBlindState {
    fn new(plan: &LogupBatchPlan, site: SiteId) -> Result<Self, LogupBatchError> {
        let public_zero = ProverAuthed::from_public(Fp2::ZERO);
        Ok(Self {
            site,
            corr: CorrelationCursor::new(plan, site)?,
            cp: public_zero,
            cq: public_zero,
            claim: public_zero,
            lambda: Fp2::ZERO,
            cpref: Fp2::ONE,
            root_corrs: [Fp2::ZERO; 2],
            rounds_cur: Vec::new(),
            layers: Vec::new(),
            roots: (public_zero, public_zero),
            rounds3_cur: Vec::new(),
            col_corrs: Vec::new(),
            aux_col_claims: Vec::new(),
            pending_round2: None,
            pending_round3: None,
            pending_split: None,
        })
    }

    fn seal_root(
        &mut self,
        p: Fp2,
        q: Fp2,
        correlations: &mut FullCorrBatchReservation<'_>,
        tx: &mut Transcript,
    ) -> Result<(), LogupBatchError> {
        let draw = self.corr.take(CorrelationScope::LogupRoot)?;
        let masks = correlations.draw(draw.range, draw.row);
        self.root_corrs = [p - masks[0].x, q - masks[1].x];
        tx.append("logup_root_corrections", 32);
        self.roots = (ProverAuthed { x: p, m: masks[0].m }, ProverAuthed { x: q, m: masks[1].m });
        self.cp = self.roots.0;
        self.cq = self.roots.1;
        Ok(())
    }

    fn begin_layer(
        &mut self,
        aux_claims: Option<&[LeafAuxClaim]>,
        tx: &mut Transcript,
        ctr: &mut Counters,
    ) -> Vec<Fp2> {
        self.lambda = tx.challenge_fp2();
        ctr.bulk(4, 0);
        self.claim = self.cp.scale(self.lambda).add(self.cq);
        self.cpref = Fp2::ONE;
        let Some(aux_claims) = aux_claims else { return Vec::new() };
        let mus: Vec<_> = aux_claims.iter().map(|_| tx.challenge_fp2()).collect();
        for (claim, &mu) in aux_claims.iter().zip(&mus) {
            self.claim = self.claim.add(claim.value.scale(mu));
        }
        ctr.bulk(2 * aux_claims.len() as u64, 0);
        mus
    }

    fn seal_round2(
        &mut self,
        h: [Fp2; 2],
        point: Fp2,
        correlations: &mut FullCorrBatchReservation<'_>,
        tx: &mut Transcript,
    ) -> Result<(), LogupBatchError> {
        if self.pending_round2.is_some() || self.pending_round3.is_some() {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let draw = self.corr.take(CorrelationScope::LogupGeneralRound)?;
        let masks = correlations.draw(draw.range, draw.row);
        self.rounds_cur.push([h[0] - masks[0].x, h[1] - masks[1].x]);
        tx.append("logup_round_corrections", 32);
        self.pending_round2 = Some(PendingRound2 {
            h0: ProverAuthed { x: h[0], m: masks[0].m },
            h2: ProverAuthed { x: h[1], m: masks[1].m },
            point,
        });
        Ok(())
    }

    fn finish_round2(
        &mut self,
        tx: &mut Transcript,
        ctr: &mut Counters,
    ) -> Result<Fp2, LogupBatchError> {
        let pending =
            self.pending_round2.take().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        if pending.point == Fp2::ZERO {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let r = tx.challenge_fp2();
        let ell0 = Fp2::ONE - pending.point;
        let h1 = self.claim.sub(pending.h0.scale(ell0)).scale(pending.point.inv());
        let w = lagrange3(r);
        let ell_r = ell0 + (pending.point + pending.point - Fp2::ONE) * r;
        self.claim =
            pending.h0.scale(w[0]).add(h1.scale(w[1])).add(pending.h2.scale(w[2])).scale(ell_r);
        let pr = pending.point * r;
        self.cpref = self.cpref * (pr + pr - pending.point - r + Fp2::ONE);
        ctr.bulk(16, 0);
        Ok(r)
    }

    fn seal_round3(
        &mut self,
        g: [Fp2; 3],
        point: Fp2,
        correlations: &mut FullCorrBatchReservation<'_>,
        tx: &mut Transcript,
    ) -> Result<(), LogupBatchError> {
        if self.pending_round2.is_some() || self.pending_round3.is_some() {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let draw = self.corr.take(CorrelationScope::LogupAuxRound)?;
        let masks = correlations.draw(draw.range, draw.row);
        self.rounds3_cur.push([g[0] - masks[0].x, g[1] - masks[1].x, g[2] - masks[2].x]);
        tx.append("logup_aux_round_corrections", 48);
        self.pending_round3 = Some(PendingRound3 {
            values: [
                ProverAuthed { x: g[0], m: masks[0].m },
                ProverAuthed { x: g[1], m: masks[1].m },
                ProverAuthed { x: g[2], m: masks[2].m },
            ],
            point,
        });
        Ok(())
    }

    fn finish_round3(
        &mut self,
        tx: &mut Transcript,
        ctr: &mut Counters,
    ) -> Result<Fp2, LogupBatchError> {
        let pending =
            self.pending_round3.take().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let r = tx.challenge_fp2();
        let g1 = self.claim.sub(pending.values[0]);
        let w = lagrange4(r);
        self.claim = pending.values[0]
            .scale(w[0])
            .add(g1.scale(w[1]))
            .add(pending.values[1].scale(w[2]))
            .add(pending.values[2].scale(w[3]));
        let pr = pending.point * r;
        self.cpref = self.cpref * (pr + pr - pending.point - r + Fp2::ONE);
        ctr.bulk(12, 0);
        Ok(r)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_split(
        &mut self,
        splits: [Fp2; 4],
        columns: Option<&[[Fp2; 2]]>,
        finals: &[AuxFinal],
        correlations: &mut FullCorrBatchReservation<'_>,
        tx: &mut Transcript,
        ctr: &mut Counters,
        prod: &mut ProdTriples,
        zero: &mut Vec<ProverAuthed>,
    ) -> Result<(), LogupBatchError> {
        if self.pending_split.is_some() {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let draw = self.corr.take(CorrelationScope::LogupSplit)?;
        let masks = correlations.draw(draw.range, draw.row);
        let split_corrs = [
            splits[0] - masks[0].x,
            splits[1] - masks[1].x,
            splits[2] - masks[2].x,
            splits[3] - masks[3].x,
        ];
        tx.append("logup_split_corrections", 64);
        let p0 = ProverAuthed { x: splits[0], m: masks[0].m };
        let p1 = ProverAuthed { x: splits[1], m: masks[1].m };
        let q0 = ProverAuthed { x: splits[2], m: masks[2].m };
        let q1 = ProverAuthed { x: splits[3], m: masks[3].m };
        let zx = [splits[0] * splits[3], splits[1] * splits[2], splits[2] * splits[3]];
        let draw = self.corr.take(CorrelationScope::LogupProduct)?;
        let zmasks = correlations.draw(draw.range, draw.row);
        let z_corrs = [zx[0] - zmasks[0].x, zx[1] - zmasks[1].x, zx[2] - zmasks[2].x];
        tx.append("logup_prod_corrections", 48);
        let z = [
            ProverAuthed { x: zx[0], m: zmasks[0].m },
            ProverAuthed { x: zx[1], m: zmasks[1].m },
            ProverAuthed { x: zx[2], m: zmasks[2].m },
        ];
        prod.push((p0, q1, z[0]));
        prod.push((p1, q0, z[1]));
        prod.push((q0, q1, z[2]));
        let mut row = z[0]
            .add(z[1])
            .scale(self.lambda * self.cpref)
            .add(z[2].scale(self.cpref))
            .sub(self.claim);

        let columns = if let Some(columns) = columns {
            let draw = self.corr.take(CorrelationScope::LogupAuxColumn)?;
            let cmasks = correlations.draw(draw.range, draw.row);
            tx.append("logup_col_corrections", 32 * columns.len() as u64);
            let mut authenticated = Vec::with_capacity(columns.len());
            for (index, column) in columns.iter().enumerate() {
                self.col_corrs
                    .push([column[0] - cmasks[2 * index].x, column[1] - cmasks[2 * index + 1].x]);
                authenticated.push([
                    ProverAuthed { x: column[0], m: cmasks[2 * index].m },
                    ProverAuthed { x: column[1], m: cmasks[2 * index + 1].m },
                ]);
            }
            for final_claim in finals {
                let column = authenticated
                    .get(final_claim.col)
                    .ok_or(LogupBatchError::InvalidGeometry(self.site))?;
                row = row.add(
                    column[0]
                        .scale(final_claim.w0)
                        .add(column[1].scale(final_claim.w1))
                        .scale(final_claim.eq_r),
                );
            }
            Some(authenticated)
        } else {
            None
        };
        debug_assert_eq!(row.x, Fp2::ZERO, "scheduled LogUp layer-end relation violated");
        zero.push(row);
        ctr.bulk(
            3 + 8
                + 4
                + if let Some(columns) = &columns {
                    6 * finals.len() as u64 + 2 * columns.len() as u64
                } else {
                    0
                },
            0,
        );
        self.layers.push(BlindLayerProof {
            round_corrs: std::mem::take(&mut self.rounds_cur),
            split_corrs,
            z_corrs,
        });
        self.pending_split = Some(PendingSplitP { p0, p1, q0, q1, columns });
        Ok(())
    }

    fn finish_split(&mut self, tx: &mut Transcript) -> Result<Fp2, LogupBatchError> {
        let pending =
            self.pending_split.take().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let t = tx.challenge_fp2();
        self.cp = pending.p0.add(pending.p1.sub(pending.p0).scale(t));
        self.cq = pending.q0.add(pending.q1.sub(pending.q0).scale(t));
        if let Some(columns) = pending.columns {
            self.aux_col_claims = columns
                .iter()
                .map(|column| column[0].add(column[1].sub(column[0]).scale(t)))
                .collect();
        }
        Ok(t)
    }

    fn finish(self, depth: usize) -> Result<BlindFinish, LogupBatchError> {
        if !self.corr.complete()
            || self.pending_round2.is_some()
            || self.pending_round3.is_some()
            || self.pending_split.is_some()
            || self.layers.len() != depth
        {
            return Err(LogupBatchError::CorrelationRoleMismatch(self.site));
        }
        Ok(BlindFinish {
            proof: BlindFracProof {
                root_corrs: self.root_corrs,
                layers: self.layers,
                aux: Some(BlindAuxPart { rounds3: self.rounds3_cur, col_corrs: self.col_corrs }),
            },
            cp: self.cp,
            cq: self.cq,
            roots: self.roots,
            col_claims: self.aux_col_claims,
        })
    }
}

struct BlindFinish {
    proof: BlindFracProof,
    cp: ProverAuthed,
    cq: ProverAuthed,
    roots: (ProverAuthed, ProverAuthed),
    col_claims: Vec<ProverAuthed>,
}

fn validate_common_geometry(
    site: LogupBatchSite,
    entries: usize,
    shifts: &[Option<u32>],
    aux_claims: &[LeafAuxClaim],
) -> Result<(), LogupBatchError> {
    if entries < 2
        || !entries.is_power_of_two()
        || entries.trailing_zeros() as usize != site.depth
        || shifts.len() != site.column_count
        || !shifts.iter().any(Option::is_some)
        || shifts.iter().flatten().any(|&shift| shift >= 63)
        || aux_claims
            .iter()
            .any(|claim| claim.col >= site.column_count || claim.point.len() != site.depth)
    {
        return Err(LogupBatchError::InvalidGeometry(site.id));
    }
    Ok(())
}

fn preflight_cpu(plan: &LogupBatchPlan, jobs: &[CpuLogupBatchJob]) -> Result<(), LogupBatchError> {
    let shapes: Vec<_> = jobs
        .iter()
        .map(|job| {
            let depth =
                job.columns.first().map_or(0, |column| column.len().trailing_zeros() as usize);
            (job.site, depth, job.columns.len(), job.aux_claims.len())
        })
        .collect();
    plan.validate_membership(shapes)?;
    for job in jobs {
        let site = plan.site(job.site).ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        let entries = job.columns.first().map_or(0, Vec::len);
        validate_common_geometry(site, entries, &job.shifts, &job.aux_claims)?;
        if job.columns.len() != site.column_count
            || job.columns.iter().any(|column| column.len() != entries)
        {
            return Err(LogupBatchError::InvalidGeometry(job.site));
        }
    }
    Ok(())
}

struct CpuGeneralLayer {
    vectors: [Vec<Fp2>; 4],
    suffix: Vec<Vec<Fp2>>,
    lambda: Fp2,
    cpref: Fp2,
    rprime: Vec<Fp2>,
}

struct CpuAuxLayer {
    q0: Vec<Fp2>,
    q1: Vec<Fp2>,
    columns: Vec<LeafAuxCol>,
    eq_rows: Vec<Vec<Fp2>>,
    suffix: Vec<Vec<Fp2>>,
    weights: Vec<(Fp2, Fp2)>,
    lambda: Fp2,
    cpref: Fp2,
    rprime: Vec<Fp2>,
}

enum CpuLayer {
    General(CpuGeneralLayer),
    Aux(CpuAuxLayer),
}

struct CpuJobState {
    site: SiteId,
    depth: usize,
    column_count: usize,
    shifts: Vec<Option<u32>>,
    alpha: Fp2,
    leaf_q: LeafQ,
    tree: Tree,
    aux_columns: Option<Vec<LeafAuxCol>>,
    aux_claims: Vec<LeafAuxClaim>,
    point: Vec<Fp2>,
    layer: Option<CpuLayer>,
    blind: Option<BatchBlindState>,
}

impl CpuJobState {
    fn new(
        plan: &LogupBatchPlan,
        job: CpuLogupBatchJob,
        ctr: &mut Counters,
    ) -> Result<Self, LogupBatchError> {
        let site = plan.site(job.site).ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        let entries = job.columns[0].len();
        let packed: Vec<Fp> = (0..entries)
            .map(|row| {
                job.columns.iter().zip(&job.shifts).fold(Fp::ZERO, |sum, (column, shift)| {
                    shift.map_or(sum, |shift| sum + column[row] * Fp::new(1u64 << shift))
                })
            })
            .collect();
        ctr.bulk(0, (entries * job.shifts.iter().flatten().count()) as u64);
        let leaf_q = lift_q_fp(&packed, job.alpha);
        let tree = build_tree_cpu(&LeafP::Ones, &leaf_q, ctr);
        let aux_columns = Some(job.columns.iter().map(|column| aux_col(column)).collect());
        Ok(Self {
            site: job.site,
            depth: site.depth,
            column_count: site.column_count,
            shifts: job.shifts,
            alpha: job.alpha,
            leaf_q,
            tree,
            aux_columns,
            aux_claims: job.aux_claims,
            point: Vec::new(),
            layer: None,
            blind: Some(BatchBlindState::new(plan, job.site)?),
        })
    }

    fn root(&self) -> (Fp2, Fp2) {
        (self.tree.p[0][0], self.tree.q[0][0])
    }

    fn begin_layer(
        &mut self,
        layer_index: usize,
        tx: &mut Transcript,
        ctr: &mut Counters,
    ) -> Result<(), LogupBatchError> {
        if self.layer.is_some() || layer_index >= self.depth || self.point.len() != layer_index {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let leaf = layer_index + 1 == self.depth;
        let blind = self.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let mus = blind.begin_layer(if leaf { Some(&self.aux_claims) } else { None }, tx, ctr);
        let lambda = blind.lambda;
        if leaf {
            let weights: Vec<_> = self
                .aux_claims
                .iter()
                .zip(&mus)
                .map(|(claim, &mu)| (mu * (Fp2::ONE - claim.point[0]), mu * claim.point[0]))
                .collect();
            ctr.bulk(2 * weights.len() as u64, 0);
            let eq_rows: Vec<Vec<Fp2>> =
                self.aux_claims.iter().map(|claim| crate::mle::eq_vec(&claim.point[1..])).collect();
            ctr.bulk(eq_rows.iter().map(|row| row.len() as u64).sum(), 0);
            let q0 = (0..self.leaf_q.a.len() / 2).map(|index| self.leaf_q.get(2 * index)).collect();
            let q1 =
                (0..self.leaf_q.a.len() / 2).map(|index| self.leaf_q.get(2 * index + 1)).collect();
            let suffix = suffix_eq_tables(&self.point, ctr);
            self.layer = Some(CpuLayer::Aux(CpuAuxLayer {
                q0,
                q1,
                columns: self
                    .aux_columns
                    .take()
                    .ok_or(LogupBatchError::InvalidGeometry(self.site))?,
                eq_rows,
                suffix,
                weights,
                lambda,
                cpref: Fp2::ONE,
                rprime: Vec::with_capacity(layer_index),
            }));
        } else {
            let evens = |values: &[Fp2]| values.iter().step_by(2).copied().collect();
            let odds = |values: &[Fp2]| values.iter().skip(1).step_by(2).copied().collect();
            let p = &self.tree.p[layer_index + 1];
            let q = &self.tree.q[layer_index + 1];
            self.layer = Some(CpuLayer::General(CpuGeneralLayer {
                vectors: [evens(p), odds(p), evens(q), odds(q)],
                suffix: suffix_eq_tables(&self.point, ctr),
                lambda,
                cpref: Fp2::ONE,
                rprime: Vec::with_capacity(layer_index),
            }));
        }
        Ok(())
    }

    fn round_message(
        &mut self,
        round: usize,
        ctr: &mut Counters,
    ) -> Result<RoundMessage, LogupBatchError> {
        let point = *self.point.get(round).ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        match self.layer.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            CpuLayer::General(state) => {
                let half = state.vectors[0].len() / 2;
                let suffix =
                    state.suffix.get(round).ok_or(LogupBatchError::InvalidGeometry(self.site))?;
                ctr.bulk(10 * half as u64 + 4, 0);
                let mut acc = RoundAcc::default();
                for index in 0..half {
                    let (p00, p02) =
                        at02(state.vectors[0][2 * index], state.vectors[0][2 * index + 1]);
                    let (p10, p12) =
                        at02(state.vectors[1][2 * index], state.vectors[1][2 * index + 1]);
                    let (q00, q02) =
                        at02(state.vectors[2][2 * index], state.vectors[2][2 * index + 1]);
                    let (q10, q12) =
                        at02(state.vectors[3][2 * index], state.vectors[3][2 * index + 1]);
                    acc = acc.add(RoundAcc {
                        pq0: suffix[index] * (p00 * q10 + p10 * q00),
                        pq2: suffix[index] * (p02 * q12 + p12 * q02),
                        qq0: suffix[index] * (q00 * q10),
                        qq2: suffix[index] * (q02 * q12),
                    });
                }
                Ok(RoundMessage::General([
                    state.cpref * (state.lambda * acc.pq0 + acc.qq0),
                    state.cpref * (state.lambda * acc.pq2 + acc.qq2),
                ]))
            }
            CpuLayer::Aux(state) => {
                let half = state.q0.len() / 2;
                let suffix =
                    state.suffix.get(round).ok_or(LogupBatchError::InvalidGeometry(self.site))?;
                if round == 0 {
                    ctr.bulk(0, 24 * half as u64);
                } else {
                    ctr.bulk(9 * half as u64, 0);
                }
                ctr.bulk(9 * half as u64 * self.aux_claims.len() as u64, 0);
                ctr.bulk(9, 0);
                let mut layer_acc = [Fp2::ZERO; 6];
                for index in 0..half {
                    let (c0, c2, c3) = at023(state.q0[2 * index], state.q0[2 * index + 1]);
                    let (d0, d2, d3) = at023(state.q1[2 * index], state.q1[2 * index + 1]);
                    for (slot, (c, d)) in [(c0, d0), (c2, d2), (c3, d3)].into_iter().enumerate() {
                        layer_acc[slot] += suffix[index] * (c + d);
                        layer_acc[slot + 3] += suffix[index] * (c * d);
                    }
                }
                let mut aux_acc = [Fp2::ZERO; 3];
                for (claim_index, claim) in self.aux_claims.iter().enumerate() {
                    let column = state
                        .columns
                        .get(claim.col)
                        .ok_or(LogupBatchError::InvalidGeometry(self.site))?;
                    let eq = &state.eq_rows[claim_index];
                    let (w0, w1) = state.weights[claim_index];
                    for index in 0..half {
                        let v0 = at023(column.half0[2 * index], column.half0[2 * index + 1]);
                        let v1 = at023(column.half1[2 * index], column.half1[2 * index + 1]);
                        let e = at023(eq[2 * index], eq[2 * index + 1]);
                        aux_acc[0] += e.0 * (w0 * v0.0 + w1 * v1.0);
                        aux_acc[1] += e.1 * (w0 * v0.1 + w1 * v1.1);
                        aux_acc[2] += e.2 * (w0 * v0.2 + w1 * v1.2);
                    }
                }
                let l0 = Fp2::ONE - point;
                let l2 = point + point + point - Fp2::ONE;
                let l3 = point + point + point + point + point - Fp2::ONE - Fp2::ONE;
                let finish = |slot: usize, ell: Fp2| {
                    ell * (state.cpref * (state.lambda * layer_acc[slot] + layer_acc[slot + 3]))
                        + aux_acc[slot]
                };
                Ok(RoundMessage::Aux([finish(0, l0), finish(1, l2), finish(2, l3)]))
            }
        }
    }

    fn fold_round(
        &mut self,
        round: usize,
        challenge: Fp2,
        ctr: &mut Counters,
    ) -> Result<(), LogupBatchError> {
        let point = self.point[round];
        match self.layer.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            CpuLayer::General(state) => {
                let half = state.vectors[0].len() / 2;
                ctr.bulk(4 * half as u64 + 2, 0);
                for vector in &mut state.vectors {
                    fold_vec(vector, challenge, half);
                }
                let pr = point * challenge;
                state.cpref = state.cpref * (pr + pr - point - challenge + Fp2::ONE);
                state.rprime.push(challenge);
            }
            CpuLayer::Aux(state) => {
                let half = state.q0.len() / 2;
                if round == 0 {
                    ctr.bulk(2, 4 * half as u64);
                } else {
                    ctr.bulk(2 * half as u64 + 2, 0);
                }
                ctr.bulk(2 * half as u64 * self.column_count as u64, 0);
                ctr.bulk(half as u64 * self.aux_claims.len() as u64, 0);
                fold_vec(&mut state.q0, challenge, half);
                fold_vec(&mut state.q1, challenge, half);
                for column in &mut state.columns {
                    fold_vec(&mut column.half0, challenge, half);
                    fold_vec(&mut column.half1, challenge, half);
                }
                for eq in &mut state.eq_rows {
                    fold_vec(eq, challenge, half);
                }
                let pr = point * challenge;
                state.cpref = state.cpref * (pr + pr - point - challenge + Fp2::ONE);
                state.rprime.push(challenge);
            }
        }
        Ok(())
    }

    fn split_message(&self, ctr: &mut Counters) -> Result<SplitMessage, LogupBatchError> {
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            CpuLayer::General(state) => Ok(SplitMessage {
                splits: [
                    state.vectors[0][0],
                    state.vectors[1][0],
                    state.vectors[2][0],
                    state.vectors[3][0],
                ],
                columns: None,
                finals: Vec::new(),
            }),
            CpuLayer::Aux(state) => {
                let columns: Vec<_> =
                    state.columns.iter().map(|column| [column.half0[0], column.half1[0]]).collect();
                let finals: Vec<_> = self
                    .aux_claims
                    .iter()
                    .zip(&state.weights)
                    .map(|(claim, &(w0, w1))| AuxFinal {
                        col: claim.col,
                        w0,
                        w1,
                        eq_r: crate::mle::eq_points(&claim.point[1..], &state.rprime),
                    })
                    .collect();
                ctr.bulk(2 * self.point.len() as u64 * finals.len() as u64, 0);
                Ok(SplitMessage {
                    splits: [Fp2::ONE, Fp2::ONE, state.q0[0], state.q1[0]],
                    columns: Some(columns),
                    finals,
                })
            }
        }
    }

    fn finish_layer(&mut self, challenge: Fp2) -> Result<(), LogupBatchError> {
        let layer = self.layer.take().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let rprime = match layer {
            CpuLayer::General(state) => state.rprime,
            CpuLayer::Aux(state) => state.rprime,
        };
        self.point = std::iter::once(challenge).chain(rprime).collect();
        Ok(())
    }

    fn finish(
        mut self,
        ctr: &mut Counters,
        zero: &mut Vec<ProverAuthed>,
    ) -> Result<LogupBatchOutputP, LogupBatchError> {
        let blind = self
            .blind
            .take()
            .ok_or(LogupBatchError::InvalidGeometry(self.site))?
            .finish(self.depth)?;
        zero.push(blind.cp.sub(ProverAuthed::from_public(Fp2::ONE)));
        let mut closure = blind.cq.sub(ProverAuthed::from_public(self.alpha));
        for (claim, shift) in blind.col_claims.iter().zip(&self.shifts) {
            if let Some(shift) = shift {
                closure = closure.add(claim.scale(Fp2::from_base(Fp::new(1u64 << shift))));
            }
        }
        debug_assert_eq!(closure.x, Fp2::ZERO, "scheduled packed leaf closure violated");
        zero.push(closure);
        ctr.bulk(2 * self.column_count as u64, 0);
        let point = self.point;
        Ok(LogupBatchOutputP {
            site: self.site,
            output: InstanceOutP {
                proof: BlindInstance { lookup: blind.proof },
                alpha: self.alpha,
                col_claims: blind
                    .col_claims
                    .into_iter()
                    .map(|value| OpenClaim { point: point.clone(), value })
                    .collect(),
                roots: blind.roots,
                point,
            },
        })
    }
}

enum RoundMessage {
    General([Fp2; 2]),
    Aux([Fp2; 3]),
}

struct SplitMessage {
    splits: [Fp2; 4],
    columns: Option<Vec<[Fp2; 2]>>,
    finals: Vec<AuxFinal>,
}

/// CPU reference for the scheduled transcript. It intentionally follows the
/// same global epochs as the resident runner, rather than invoking singleton
/// provers, so transcript/challenge order is differential-testable.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_prove_batch_cpu(
    plan: &LogupBatchPlan,
    mut jobs: Vec<CpuLogupBatchJob>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
) -> Result<Vec<LogupBatchOutputP>, LogupBatchError> {
    preflight_cpu(plan, &jobs)?;
    let mut correlations = stream.try_reserve_full_corr_ranges(plan.full_corr_ranges())?;
    jobs.sort_by_key(|job| job.site);
    let mut states: Vec<CpuJobState> =
        jobs.into_iter().map(|job| CpuJobState::new(plan, job, ctr)).collect::<Result<_, _>>()?;

    // Root epoch: seal every correction before drawing any layer challenge.
    for state in &mut states {
        let (p, q) = state.root();
        state.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(state.site))?.seal_root(
            p,
            q,
            &mut correlations,
            tx,
        )?;
    }

    let max_depth = states.iter().map(|state| state.depth).max().unwrap_or(0);
    for layer in 0..max_depth {
        let active: Vec<usize> = states
            .iter()
            .enumerate()
            .filter_map(|(i, state)| (layer < state.depth).then_some(i))
            .collect();
        for &index in &active {
            states[index].begin_layer(layer, tx, ctr)?;
        }
        for round in 0..layer {
            let mut messages = Vec::with_capacity(active.len());
            for &index in &active {
                messages.push((index, states[index].round_message(round, ctr)?));
            }
            for (index, message) in &messages {
                let state = &mut states[*index];
                let blind =
                    state.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(state.site))?;
                match message {
                    RoundMessage::General(values) => {
                        blind.seal_round2(*values, state.point[round], &mut correlations, tx)?
                    }
                    RoundMessage::Aux(values) => {
                        blind.seal_round3(*values, state.point[round], &mut correlations, tx)?
                    }
                }
            }
            let mut challenges = Vec::with_capacity(active.len());
            for &(index, ref message) in &messages {
                let site = states[index].site;
                let blind =
                    states[index].blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(site))?;
                let challenge = match message {
                    RoundMessage::General(_) => blind.finish_round2(tx, ctr)?,
                    RoundMessage::Aux(_) => blind.finish_round3(tx, ctr)?,
                };
                challenges.push((index, challenge));
            }
            for (index, challenge) in challenges {
                states[index].fold_round(round, challenge, ctr)?;
            }
        }

        let mut split_messages = Vec::with_capacity(active.len());
        for &index in &active {
            split_messages.push((index, states[index].split_message(ctr)?));
        }
        for (index, message) in &split_messages {
            let state = &mut states[*index];
            state.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(state.site))?.seal_split(
                message.splits,
                message.columns.as_deref(),
                &message.finals,
                &mut correlations,
                tx,
                ctr,
                prod,
                zero,
            )?;
        }
        let mut challenges = Vec::with_capacity(active.len());
        for &index in &active {
            let site = states[index].site;
            let challenge = states[index]
                .blind
                .as_mut()
                .ok_or(LogupBatchError::InvalidGeometry(site))?
                .finish_split(tx)?;
            challenges.push((index, challenge));
        }
        for (index, challenge) in challenges {
            states[index].finish_layer(challenge)?;
        }
    }

    let outputs =
        states.into_iter().map(|state| state.finish(ctr, zero)).collect::<Result<_, _>>()?;
    correlations.finish();
    Ok(outputs)
}

fn preflight_verify(
    plan: &LogupBatchPlan,
    jobs: &[VerifyLogupBatchJob<'_>],
) -> Result<(), LogupBatchError> {
    plan.validate_membership(
        jobs.iter().map(|job| (job.site, job.n_bits, job.shifts.len(), job.aux_claims.len())),
    )?;
    for job in jobs {
        let site = plan.site(job.site).ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        if job.n_bits != site.depth
            || job.shifts.len() != site.column_count
            || !job.shifts.iter().any(Option::is_some)
            || job.shifts.iter().flatten().any(|&shift| shift >= 63)
            || job
                .aux_claims
                .iter()
                .any(|(column, point, _)| *column >= site.column_count || point.len() != site.depth)
        {
            return Err(LogupBatchError::InvalidGeometry(job.site));
        }
        let proof = &job.proof.lookup;
        let aux = proof.aux.as_ref().ok_or(LogupBatchError::InvalidProof(job.site))?;
        if proof.layers.len() != site.depth
            || aux.rounds3.len() != site.depth - 1
            || aux.col_corrs.len() != site.column_count
        {
            return Err(LogupBatchError::InvalidProof(job.site));
        }
        for (layer, proof_layer) in proof.layers.iter().enumerate() {
            let expected = if layer + 1 == site.depth { 0 } else { layer };
            if proof_layer.round_corrs.len() != expected {
                return Err(LogupBatchError::InvalidProof(job.site));
            }
        }
    }
    Ok(())
}

struct PendingVerifyRound2 {
    h0: VerifierKey,
    h2: VerifierKey,
    point: Fp2,
}

struct PendingVerifyRound3 {
    values: [VerifierKey; 3],
    point: Fp2,
}

struct PendingVerifySplit {
    splits: [VerifierKey; 4],
    columns: Option<Vec<[VerifierKey; 2]>>,
}

struct BatchVerifyState<'a> {
    site: SiteId,
    depth: usize,
    shifts: &'a [Option<u32>],
    alpha: Fp2,
    delta: Fp2,
    proof: &'a BlindFracProof,
    aux_claims: &'a [(usize, Vec<Fp2>, VerifierKey)],
    corr: CorrelationCursor,
    roots: (VerifierKey, VerifierKey),
    cp: VerifierKey,
    cq: VerifierKey,
    claim: VerifierKey,
    lambda: Fp2,
    cpref: Fp2,
    point: Vec<Fp2>,
    rprime: Vec<Fp2>,
    weights: Vec<(Fp2, Fp2)>,
    col_keys: Vec<VerifierKey>,
    pending_round2: Option<PendingVerifyRound2>,
    pending_round3: Option<PendingVerifyRound3>,
    pending_split: Option<PendingVerifySplit>,
}

impl<'a> BatchVerifyState<'a> {
    fn new(
        plan: &LogupBatchPlan,
        job: VerifyLogupBatchJob<'a>,
        delta: Fp2,
    ) -> Result<Self, LogupBatchError> {
        let public_zero = VerifierKey::from_public(Fp2::ZERO, delta);
        Ok(Self {
            site: job.site,
            depth: job.n_bits,
            shifts: job.shifts,
            alpha: job.alpha,
            delta,
            proof: &job.proof.lookup,
            aux_claims: job.aux_claims,
            corr: CorrelationCursor::new(plan, job.site)?,
            roots: (public_zero, public_zero),
            cp: public_zero,
            cq: public_zero,
            claim: public_zero,
            lambda: Fp2::ZERO,
            cpref: Fp2::ONE,
            point: Vec::new(),
            rprime: Vec::new(),
            weights: Vec::new(),
            col_keys: Vec::new(),
            pending_round2: None,
            pending_round3: None,
            pending_split: None,
        })
    }

    fn seal_root(
        &mut self,
        correlations: &mut FullKeyBatchReservation<'_>,
        tx: &mut Transcript,
    ) -> Result<(), LogupBatchError> {
        let draw = self.corr.take(CorrelationScope::LogupRoot)?;
        let keys = correlations.expand(draw.range, draw.row);
        self.roots = (
            VerifierKey { k: keys[0] + self.delta * self.proof.root_corrs[0] },
            VerifierKey { k: keys[1] + self.delta * self.proof.root_corrs[1] },
        );
        self.cp = self.roots.0;
        self.cq = self.roots.1;
        tx.append("logup_root_corrections", 32);
        Ok(())
    }

    fn begin_layer(&mut self, layer: usize, tx: &mut Transcript) {
        self.lambda = tx.challenge_fp2();
        self.claim = self.cp.scale(self.lambda).add(self.cq);
        self.cpref = Fp2::ONE;
        self.rprime = Vec::with_capacity(layer);
        self.weights.clear();
        if layer + 1 == self.depth {
            for (column, point, key) in self.aux_claims {
                let _ = column;
                let mu = tx.challenge_fp2();
                self.claim = self.claim.add(key.scale(mu));
                self.weights.push((mu * (Fp2::ONE - point[0]), mu * point[0]));
            }
        }
    }

    fn seal_round(
        &mut self,
        layer: usize,
        round: usize,
        correlations: &mut FullKeyBatchReservation<'_>,
        tx: &mut Transcript,
    ) -> Result<bool, LogupBatchError> {
        let leaf = layer + 1 == self.depth;
        let point = *self.point.get(round).ok_or(LogupBatchError::InvalidProof(self.site))?;
        if leaf {
            let corrs = self
                .proof
                .aux
                .as_ref()
                .and_then(|aux| aux.rounds3.get(round))
                .ok_or(LogupBatchError::InvalidProof(self.site))?;
            let draw = self.corr.take(CorrelationScope::LogupAuxRound)?;
            let keys = correlations.expand(draw.range, draw.row);
            self.pending_round3 = Some(PendingVerifyRound3 {
                values: [
                    VerifierKey { k: keys[0] + self.delta * corrs[0] },
                    VerifierKey { k: keys[1] + self.delta * corrs[1] },
                    VerifierKey { k: keys[2] + self.delta * corrs[2] },
                ],
                point,
            });
            tx.append("logup_aux_round_corrections", 48);
        } else {
            let corrs = self.proof.layers[layer]
                .round_corrs
                .get(round)
                .ok_or(LogupBatchError::InvalidProof(self.site))?;
            let draw = self.corr.take(CorrelationScope::LogupGeneralRound)?;
            let keys = correlations.expand(draw.range, draw.row);
            self.pending_round2 = Some(PendingVerifyRound2 {
                h0: VerifierKey { k: keys[0] + self.delta * corrs[0] },
                h2: VerifierKey { k: keys[1] + self.delta * corrs[1] },
                point,
            });
            tx.append("logup_round_corrections", 32);
        }
        Ok(leaf)
    }

    fn finish_round(&mut self, leaf: bool, tx: &mut Transcript) -> Result<(), LogupBatchError> {
        let r = tx.challenge_fp2();
        if leaf {
            let pending =
                self.pending_round3.take().ok_or(LogupBatchError::InvalidProof(self.site))?;
            let g1 = self.claim.sub(pending.values[0]);
            let w = lagrange4(r);
            self.claim = pending.values[0]
                .scale(w[0])
                .add(g1.scale(w[1]))
                .add(pending.values[1].scale(w[2]))
                .add(pending.values[2].scale(w[3]));
            let pr = pending.point * r;
            self.cpref = self.cpref * (pr + pr - pending.point - r + Fp2::ONE);
        } else {
            let pending =
                self.pending_round2.take().ok_or(LogupBatchError::InvalidProof(self.site))?;
            if pending.point == Fp2::ZERO {
                return Err(LogupBatchError::InvalidProof(self.site));
            }
            let ell0 = Fp2::ONE - pending.point;
            let h1 = self.claim.sub(pending.h0.scale(ell0)).scale(pending.point.inv());
            let w = lagrange3(r);
            let ell_r = ell0 + (pending.point + pending.point - Fp2::ONE) * r;
            self.claim =
                pending.h0.scale(w[0]).add(h1.scale(w[1])).add(pending.h2.scale(w[2])).scale(ell_r);
            let pr = pending.point * r;
            self.cpref = self.cpref * (pr + pr - pending.point - r + Fp2::ONE);
        }
        self.rprime.push(r);
        Ok(())
    }

    fn seal_split(
        &mut self,
        layer: usize,
        correlations: &mut FullKeyBatchReservation<'_>,
        tx: &mut Transcript,
        kprod: &mut ProdKeyTriples,
        kzero: &mut Vec<VerifierKey>,
    ) -> Result<(), LogupBatchError> {
        let leaf = layer + 1 == self.depth;
        let proof_layer = &self.proof.layers[layer];
        let draw = self.corr.take(CorrelationScope::LogupSplit)?;
        let split_masks = correlations.expand(draw.range, draw.row);
        let splits = [
            VerifierKey { k: split_masks[0] + self.delta * proof_layer.split_corrs[0] },
            VerifierKey { k: split_masks[1] + self.delta * proof_layer.split_corrs[1] },
            VerifierKey { k: split_masks[2] + self.delta * proof_layer.split_corrs[2] },
            VerifierKey { k: split_masks[3] + self.delta * proof_layer.split_corrs[3] },
        ];
        tx.append("logup_split_corrections", 64);
        let draw = self.corr.take(CorrelationScope::LogupProduct)?;
        let product_masks = correlations.expand(draw.range, draw.row);
        let products = [
            VerifierKey { k: product_masks[0] + self.delta * proof_layer.z_corrs[0] },
            VerifierKey { k: product_masks[1] + self.delta * proof_layer.z_corrs[1] },
            VerifierKey { k: product_masks[2] + self.delta * proof_layer.z_corrs[2] },
        ];
        tx.append("logup_prod_corrections", 48);
        kprod.push((splits[0], splits[3], products[0]));
        kprod.push((splits[1], splits[2], products[1]));
        kprod.push((splits[2], splits[3], products[2]));
        let mut row = products[0]
            .add(products[1])
            .scale(self.lambda * self.cpref)
            .add(products[2].scale(self.cpref))
            .sub(self.claim);
        let columns = if leaf {
            let aux = self.proof.aux.as_ref().ok_or(LogupBatchError::InvalidProof(self.site))?;
            let draw = self.corr.take(CorrelationScope::LogupAuxColumn)?;
            let column_masks = correlations.expand(draw.range, draw.row);
            tx.append("logup_col_corrections", 32 * aux.col_corrs.len() as u64);
            let columns: Vec<[VerifierKey; 2]> = aux
                .col_corrs
                .iter()
                .enumerate()
                .map(|(index, corrs)| {
                    [
                        VerifierKey { k: column_masks[2 * index] + self.delta * corrs[0] },
                        VerifierKey { k: column_masks[2 * index + 1] + self.delta * corrs[1] },
                    ]
                })
                .collect();
            for (((column, point, _), &(w0, w1)), _) in
                self.aux_claims.iter().zip(&self.weights).zip(0..)
            {
                let column_keys =
                    columns.get(*column).ok_or(LogupBatchError::InvalidProof(self.site))?;
                let eq_r = crate::mle::eq_points(&point[1..], &self.rprime);
                row = row.add(column_keys[0].scale(w0).add(column_keys[1].scale(w1)).scale(eq_r));
            }
            Some(columns)
        } else {
            None
        };
        kzero.push(row);
        self.pending_split = Some(PendingVerifySplit { splits, columns });
        Ok(())
    }

    fn finish_split(&mut self, tx: &mut Transcript) -> Result<(), LogupBatchError> {
        let pending = self.pending_split.take().ok_or(LogupBatchError::InvalidProof(self.site))?;
        let t = tx.challenge_fp2();
        self.cp = pending.splits[0].add(pending.splits[1].sub(pending.splits[0]).scale(t));
        self.cq = pending.splits[2].add(pending.splits[3].sub(pending.splits[2]).scale(t));
        if let Some(columns) = pending.columns {
            self.col_keys = columns
                .iter()
                .map(|column| column[0].add(column[1].sub(column[0]).scale(t)))
                .collect();
        }
        self.point = std::iter::once(t).chain(std::mem::take(&mut self.rprime)).collect();
        Ok(())
    }

    fn finish(
        self,
        delta: Fp2,
        kzero: &mut Vec<VerifierKey>,
    ) -> Result<LogupBatchOutputV, LogupBatchError> {
        if !self.corr.complete() || self.point.len() != self.depth {
            return Err(LogupBatchError::CorrelationRoleMismatch(self.site));
        }
        kzero.push(self.cp.sub(VerifierKey::from_public(Fp2::ONE, delta)));
        let mut closure = self.cq.sub(VerifierKey::from_public(self.alpha, delta));
        for (key, shift) in self.col_keys.iter().zip(self.shifts) {
            if let Some(shift) = shift {
                closure = closure.add(key.scale(Fp2::from_base(Fp::new(1u64 << shift))));
            }
        }
        kzero.push(closure);
        let point = self.point;
        Ok(LogupBatchOutputV {
            site: self.site,
            output: InstanceOutV {
                col_keys: self
                    .col_keys
                    .into_iter()
                    .map(|key| OpenKey { point: point.clone(), key })
                    .collect(),
                kroots: self.roots,
                point,
            },
        })
    }
}

/// Verifier mirror of the scheduled lookup cohort. Proof bytes and the
/// singleton proof structs are unchanged; only transcript ordering differs.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_verify_batch(
    plan: &LogupBatchPlan,
    mut jobs: Vec<VerifyLogupBatchJob<'_>>,
    ctx: &mut VerifierCtx,
    tx: &mut Transcript,
    kprod: &mut ProdKeyTriples,
    kzero: &mut Vec<VerifierKey>,
) -> Result<Vec<LogupBatchOutputV>, LogupBatchError> {
    preflight_verify(plan, &jobs)?;
    let delta = ctx.delta;
    let mut correlations = ctx.try_reserve_full_key_ranges(plan.full_corr_ranges())?;
    jobs.sort_by_key(|job| job.site);
    let max_depth = jobs.iter().map(|job| job.n_bits).max().unwrap_or(0);
    let mut states: Vec<_> = jobs
        .into_iter()
        .map(|job| BatchVerifyState::new(plan, job, delta))
        .collect::<Result<_, _>>()?;
    for state in &mut states {
        state.seal_root(&mut correlations, tx)?;
    }
    for layer in 0..max_depth {
        let active: Vec<_> = states
            .iter()
            .enumerate()
            .filter_map(|(i, state)| (layer < state.depth).then_some(i))
            .collect();
        for &index in &active {
            states[index].begin_layer(layer, tx);
        }
        for round in 0..layer {
            let mut leaf = Vec::with_capacity(active.len());
            for &index in &active {
                leaf.push((index, states[index].seal_round(layer, round, &mut correlations, tx)?));
            }
            for (index, is_leaf) in leaf {
                states[index].finish_round(is_leaf, tx)?;
            }
        }
        for &index in &active {
            states[index].seal_split(layer, &mut correlations, tx, kprod, kzero)?;
        }
        for &index in &active {
            states[index].finish_split(tx)?;
        }
    }
    let outputs =
        states.into_iter().map(|state| state.finish(delta, kzero)).collect::<Result<_, _>>()?;
    correlations.finish();
    Ok(outputs)
}

fn preflight_resident(
    plan: &LogupBatchPlan,
    jobs: &[ResidentLogupBatchJob<'_>],
    backend: &Backend,
) -> Result<(), LogupBatchError> {
    if backend.kind() != BackendKind::CudaResident {
        return Err(AccelError::InvalidInput(
            "scheduled resident LogUp requires a cuda-resident backend",
        )
        .into());
    }
    plan.validate_membership(jobs.iter().map(|job| {
        (job.site, job.entries.trailing_zeros() as usize, job.column_count, job.aux_claims.len())
    }))?;
    for job in jobs {
        let site = plan.site(job.site).ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        validate_common_geometry(site, job.entries, &job.shifts, &job.aux_claims)?;
        let total = job
            .column_count
            .checked_mul(job.entries)
            .ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        if job.column_count != site.column_count || job.columns.len() != total {
            return Err(LogupBatchError::InvalidGeometry(job.site));
        }
        if !job.columns.buffer().is_owned_by(backend) {
            return Err(AccelError::InvalidInput(
                "scheduled resident LogUp source belongs to a foreign CUDA context",
            )
            .into());
        }
    }
    Ok(())
}

fn free_fp2_buffers(
    backend: &mut Backend,
    buffers: &mut Vec<DeviceBuffer<Fp2Repr>>,
) -> Result<(), AccelError> {
    cleanup_all(std::mem::take(buffers), |buffer| backend.free_device(buffer))
}

fn free_fp2_option(
    backend: &mut Backend,
    buffer: &mut Option<DeviceBuffer<Fp2Repr>>,
) -> Result<(), AccelError> {
    buffer.take().map_or(Ok(()), |buffer| backend.free_device(buffer))
}

fn free_u32_option(
    backend: &mut Backend,
    buffer: &mut Option<DeviceBuffer<u32>>,
) -> Result<(), AccelError> {
    buffer.take().map_or(Ok(()), |buffer| backend.free_device(buffer))
}

fn remember_cleanup(result: Result<(), AccelError>, first: &mut Option<AccelError>) {
    if let Err(error) = result {
        first.get_or_insert(error);
    }
}

/// Run every release even after one fails and retain the first cleanup error.
/// A failed device release makes the CUDA context unsafe to reuse, so callers
/// must never short-circuit the remaining ownership sweep.
fn cleanup_all<I, T, F>(items: I, mut cleanup: F) -> Result<(), AccelError>
where
    I: IntoIterator<Item = T>,
    F: FnMut(T) -> Result<(), AccelError>,
{
    let mut first = None;
    for item in items {
        remember_cleanup(cleanup(item), &mut first);
    }
    first.map_or(Ok(()), Err)
}

fn prefer_accel_cleanup(primary: AccelError, cleanup: Result<(), AccelError>) -> AccelError {
    cleanup.err().unwrap_or(primary)
}

fn prefer_cleanup(primary: LogupBatchError, cleanup: Result<(), AccelError>) -> LogupBatchError {
    cleanup.err().map_or(primary, LogupBatchError::Accel)
}

struct ResidentGeneralLayer {
    vectors: Vec<DeviceBuffer<Fp2Repr>>,
    next_vectors: Vec<DeviceBuffer<Fp2Repr>>,
    point_device: Option<DeviceBuffer<Fp2Repr>>,
    suffix: Option<DeviceBuffer<Fp2Repr>>,
    current_len: usize,
    point_len: usize,
    lambda: Fp2,
    cpref: Fp2,
    rprime: Vec<Fp2>,
}

impl ResidentGeneralLayer {
    fn cleanup(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        remember_cleanup(free_fp2_buffers(backend, &mut self.next_vectors), &mut first);
        remember_cleanup(free_fp2_buffers(backend, &mut self.vectors), &mut first);
        remember_cleanup(free_fp2_option(backend, &mut self.suffix), &mut first);
        remember_cleanup(free_fp2_option(backend, &mut self.point_device), &mut first);
        first.map_or(Ok(()), Err)
    }

    fn allocate_next(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        if !self.next_vectors.is_empty() || self.current_len < 2 {
            return Err(AccelError::InvalidInput("invalid scheduled general fold state"));
        }
        let half = self.current_len / 2;
        for _ in 0..4 {
            match backend.alloc_device(half) {
                Ok(buffer) => self.next_vectors.push(buffer),
                Err(error) => {
                    let cleanup = free_fp2_buffers(backend, &mut self.next_vectors);
                    return Err(prefer_accel_cleanup(error, cleanup));
                }
            }
        }
        Ok(())
    }

    fn enqueue_round(
        &self,
        round: usize,
        mailbox: &DeviceBuffer<Fp2Repr>,
        offset: usize,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        let half = self.current_len / 2;
        let suffix_offset = (1usize << (self.point_len - 1 - round)) - 1;
        backend.logup_general_round_into_device(
            &self.vectors[0],
            0,
            &self.vectors[1],
            0,
            &self.vectors[2],
            0,
            &self.vectors[3],
            0,
            self.suffix
                .as_ref()
                .ok_or(AccelError::InvalidInput("scheduled general round missing suffix table"))?,
            suffix_offset,
            half,
            mailbox,
            offset,
        )
    }

    fn enqueue_fold(&self, challenge: Fp2, backend: &mut Backend) -> Result<(), AccelError> {
        if self.next_vectors.len() != 4 {
            return Err(AccelError::InvalidInput("scheduled general fold output missing"));
        }
        for index in 0..4 {
            backend.fp2_fold_rows_into_device(
                DeviceSlice::new(&self.vectors[index], 0, self.current_len)?,
                1,
                self.current_len,
                challenge,
                &self.next_vectors[index],
                0,
            )?;
        }
        Ok(())
    }

    fn commit_fold(
        &mut self,
        point: Fp2,
        challenge: Fp2,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        let old = std::mem::replace(&mut self.vectors, std::mem::take(&mut self.next_vectors));
        let mut old = old;
        let cleanup = free_fp2_buffers(backend, &mut old);
        self.current_len /= 2;
        let pr = point * challenge;
        self.cpref = self.cpref * (pr + pr - point - challenge + Fp2::ONE);
        self.rprime.push(challenge);
        cleanup
    }
}

struct ResidentAuxLayer {
    // Only q0/q1 are private fold state.  The lookup-side p polynomial is
    // identically one at the leaves, hence every folded p0/p1 split is the
    // public scalar one and must not consume GPU kernels or analytic work.
    vectors: Vec<DeviceBuffer<Fp2Repr>>, // q0, q1
    next_vectors: Vec<DeviceBuffer<Fp2Repr>>,
    columns: Option<DeviceBuffer<Fp2Repr>>,
    next_columns: Option<DeviceBuffer<Fp2Repr>>,
    eq_rows: Option<DeviceBuffer<Fp2Repr>>,
    next_eq_rows: Option<DeviceBuffer<Fp2Repr>>,
    claim_points: Option<DeviceBuffer<Fp2Repr>>,
    claim_columns: Option<DeviceBuffer<u32>>,
    weights_device: Option<DeviceBuffer<Fp2Repr>>,
    point_device: Option<DeviceBuffer<Fp2Repr>>,
    suffix: Option<DeviceBuffer<Fp2Repr>>,
    weights: Vec<(Fp2, Fp2)>,
    column_count: usize,
    claim_count: usize,
    point_len: usize,
    current_len: usize,
    lambda: Fp2,
    cpref: Fp2,
    rprime: Vec<Fp2>,
}

impl ResidentAuxLayer {
    fn cleanup(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        remember_cleanup(free_fp2_buffers(backend, &mut self.next_vectors), &mut first);
        remember_cleanup(free_fp2_buffers(backend, &mut self.vectors), &mut first);
        for buffer in [
            &mut self.next_columns,
            &mut self.columns,
            &mut self.next_eq_rows,
            &mut self.eq_rows,
            &mut self.claim_points,
            &mut self.weights_device,
            &mut self.point_device,
            &mut self.suffix,
        ] {
            remember_cleanup(free_fp2_option(backend, buffer), &mut first);
        }
        remember_cleanup(free_u32_option(backend, &mut self.claim_columns), &mut first);
        first.map_or(Ok(()), Err)
    }

    fn allocate_next(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        if !self.next_vectors.is_empty()
            || self.next_columns.is_some()
            || self.next_eq_rows.is_some()
            || self.current_len < 2
        {
            return Err(AccelError::InvalidInput("invalid scheduled aux fold state"));
        }
        let half = self.current_len / 2;
        let result = (|| {
            for _ in 0..2 {
                self.next_vectors.push(backend.alloc_device(half)?);
            }
            self.next_columns = Some(backend.alloc_device(2 * self.column_count * half)?);
            if self.claim_count > 0 {
                self.next_eq_rows = Some(backend.alloc_device(self.claim_count * half)?);
            }
            Ok(())
        })();
        if let Err(error) = result {
            let mut first = None;
            remember_cleanup(free_fp2_buffers(backend, &mut self.next_vectors), &mut first);
            remember_cleanup(free_fp2_option(backend, &mut self.next_columns), &mut first);
            remember_cleanup(free_fp2_option(backend, &mut self.next_eq_rows), &mut first);
            return Err(prefer_accel_cleanup(error, first.map_or(Ok(()), Err)));
        }
        Ok(())
    }

    fn enqueue_round(
        &self,
        round: usize,
        point: Fp2,
        mailbox: &DeviceBuffer<Fp2Repr>,
        offset: usize,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        let suffix_offset = (1usize << (self.point_len - 1 - round)) - 1;
        backend.logup_aux_round_into_device(
            &self.vectors[0],
            &self.vectors[1],
            self.suffix
                .as_ref()
                .ok_or(AccelError::InvalidInput("scheduled aux round missing suffix"))?,
            suffix_offset,
            self.columns
                .as_ref()
                .ok_or(AccelError::InvalidInput("scheduled aux columns already consumed"))?,
            self.eq_rows.as_ref(),
            self.claim_columns.as_ref(),
            self.weights_device.as_ref(),
            self.column_count,
            self.claim_count,
            self.current_len,
            self.lambda,
            self.cpref,
            point,
            mailbox,
            offset,
        )
    }

    fn enqueue_fold(&self, challenge: Fp2, backend: &mut Backend) -> Result<(), AccelError> {
        if self.next_vectors.len() != 2 {
            return Err(AccelError::InvalidInput("scheduled aux fold outputs missing"));
        }
        for index in 0..2 {
            backend.fp2_fold_rows_into_device(
                DeviceSlice::new(&self.vectors[index], 0, self.current_len)?,
                1,
                self.current_len,
                challenge,
                &self.next_vectors[index],
                0,
            )?;
        }
        backend.fp2_fold_rows_into_device(
            DeviceSlice::new(
                self.columns
                    .as_ref()
                    .ok_or(AccelError::InvalidInput("scheduled aux columns missing"))?,
                0,
                2 * self.column_count * self.current_len,
            )?,
            2 * self.column_count,
            self.current_len,
            challenge,
            self.next_columns
                .as_ref()
                .ok_or(AccelError::InvalidInput("scheduled aux folded columns missing"))?,
            0,
        )?;
        if self.claim_count > 0 {
            backend.fp2_fold_rows_into_device(
                DeviceSlice::new(
                    self.eq_rows
                        .as_ref()
                        .ok_or(AccelError::InvalidInput("scheduled aux eq rows missing"))?,
                    0,
                    self.claim_count * self.current_len,
                )?,
                self.claim_count,
                self.current_len,
                challenge,
                self.next_eq_rows
                    .as_ref()
                    .ok_or(AccelError::InvalidInput("scheduled aux folded eq rows missing"))?,
                0,
            )?;
        }
        Ok(())
    }

    fn commit_fold(
        &mut self,
        point: Fp2,
        challenge: Fp2,
        backend: &mut Backend,
    ) -> Result<(), AccelError> {
        let mut first = None;
        let mut old_vectors =
            std::mem::replace(&mut self.vectors, std::mem::take(&mut self.next_vectors));
        remember_cleanup(free_fp2_buffers(backend, &mut old_vectors), &mut first);
        let mut old_columns = self.columns.replace(
            self.next_columns
                .take()
                .ok_or(AccelError::InvalidInput("scheduled aux folded columns absent"))?,
        );
        remember_cleanup(free_fp2_option(backend, &mut old_columns), &mut first);
        if self.claim_count > 0 {
            let mut old_eq = self.eq_rows.replace(
                self.next_eq_rows
                    .take()
                    .ok_or(AccelError::InvalidInput("scheduled aux folded eq rows absent"))?,
            );
            remember_cleanup(free_fp2_option(backend, &mut old_eq), &mut first);
        }
        self.current_len /= 2;
        let pr = point * challenge;
        self.cpref = self.cpref * (pr + pr - point - challenge + Fp2::ONE);
        self.rprime.push(challenge);
        first.map_or(Ok(()), Err)
    }
}

enum ResidentLayer {
    General(ResidentGeneralLayer),
    Aux(ResidentAuxLayer),
}

impl ResidentLayer {
    fn cleanup(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        match self {
            Self::General(layer) => layer.cleanup(backend),
            Self::Aux(layer) => layer.cleanup(backend),
        }
    }
}

struct ResidentJobState {
    site: SiteId,
    depth: usize,
    column_count: usize,
    shifts: Vec<Option<u32>>,
    alpha: Fp2,
    aux_claims: Vec<LeafAuxClaim>,
    dleaf: Option<DeviceBuffer<u64>>,
    tree_p: Option<DeviceBuffer<Fp2Repr>>,
    tree_q: Option<DeviceBuffer<Fp2Repr>>,
    aux_columns: Option<DeviceBuffer<Fp2Repr>>,
    point: Vec<Fp2>,
    layer: Option<ResidentLayer>,
    blind: Option<BatchBlindState>,
}

impl ResidentJobState {
    fn new(
        plan: &LogupBatchPlan,
        job: ResidentLogupBatchJob<'_>,
        ctr: &mut Counters,
        backend: &mut Backend,
    ) -> Result<Self, LogupBatchError> {
        let site = plan.site(job.site).ok_or(LogupBatchError::InvalidGeometry(job.site))?;
        let mut state = Self {
            site: job.site,
            depth: site.depth,
            column_count: site.column_count,
            shifts: job.shifts,
            alpha: job.alpha,
            aux_claims: job.aux_claims,
            dleaf: None,
            tree_p: None,
            tree_q: None,
            aux_columns: None,
            point: Vec::new(),
            layer: None,
            blind: Some(BatchBlindState::new(plan, job.site)?),
        };
        let result = (|| {
            state.dleaf = Some(backend.pack_lookup_leaf_device(
                job.columns,
                job.column_count,
                job.entries,
                &state.shifts,
                state.alpha.c0,
            )?);
            state.aux_columns = Some(backend.deinterleave_base_columns_device(
                job.columns,
                job.column_count,
                job.entries,
            )?);
            let (tree_p, tree_q) = backend.logup_tree_device(
                state
                    .dleaf
                    .as_ref()
                    .ok_or(AccelError::InvalidInput("scheduled resident lookup leaf missing"))?,
                0,
                state.alpha.c1,
                None,
                job.entries,
            )?;
            state.tree_p = Some(tree_p);
            state.tree_q = Some(tree_q);
            Ok::<(), AccelError>(())
        })();
        if let Err(error) = result {
            let cleanup = state.cleanup(backend);
            return Err(prefer_cleanup(error.into(), cleanup));
        }
        ctr.bulk(0, (job.entries * state.shifts.iter().flatten().count()) as u64);
        let mut len = job.entries / 2;
        ctr.bulk(0, 2 * len as u64);
        while len > 1 {
            len /= 2;
            ctr.bulk(3 * len as u64, 0);
        }
        Ok(state)
    }

    fn cleanup(&mut self, backend: &mut Backend) -> Result<(), AccelError> {
        let mut first = None;
        if let Some(layer) = &mut self.layer {
            remember_cleanup(layer.cleanup(backend), &mut first);
        }
        self.layer = None;
        remember_cleanup(free_fp2_option(backend, &mut self.aux_columns), &mut first);
        remember_cleanup(free_fp2_option(backend, &mut self.tree_q), &mut first);
        remember_cleanup(free_fp2_option(backend, &mut self.tree_p), &mut first);
        if let Some(leaf) = self.dleaf.take() {
            remember_cleanup(backend.free_device(leaf), &mut first);
        }
        first.map_or(Ok(()), Err)
    }

    fn begin_layer(
        &mut self,
        layer_index: usize,
        tx: &mut Transcript,
        ctr: &mut Counters,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        if self.layer.is_some() || self.point.len() != layer_index {
            return Err(LogupBatchError::InvalidGeometry(self.site));
        }
        let leaf = layer_index + 1 == self.depth;
        let blind = self.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let mus = blind.begin_layer(if leaf { Some(&self.aux_claims) } else { None }, tx, ctr);
        let lambda = blind.lambda;
        if leaf {
            self.begin_aux_layer(layer_index, mus, lambda, ctr, backend)
        } else {
            self.begin_general_layer(layer_index, lambda, ctr, backend)
        }
    }

    fn begin_general_layer(
        &mut self,
        layer_index: usize,
        lambda: Fp2,
        ctr: &mut Counters,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let child_len = 1usize << (layer_index + 1);
        let child_offset = child_len - 1;
        let vector_len = child_len / 2;
        let mut state = ResidentGeneralLayer {
            vectors: Vec::new(),
            next_vectors: Vec::new(),
            point_device: None,
            suffix: None,
            current_len: vector_len,
            point_len: layer_index,
            lambda,
            cpref: Fp2::ONE,
            rprime: Vec::with_capacity(layer_index),
        };
        let result =
            (|| {
                let (p0, p1) = backend.fp2_deinterleave_device(
                    self.tree_p
                        .as_ref()
                        .ok_or(AccelError::InvalidInput("scheduled resident p-tree missing"))?,
                    child_offset,
                    vector_len,
                )?;
                state.vectors.extend([p0, p1]);
                let (q0, q1) = backend.fp2_deinterleave_device(
                    self.tree_q
                        .as_ref()
                        .ok_or(AccelError::InvalidInput("scheduled resident q-tree missing"))?,
                    child_offset,
                    vector_len,
                )?;
                state.vectors.extend([q0, q1]);
                if !self.point.is_empty() {
                    state.point_device = Some(backend.upload_new_device(
                        &self.point.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
                    )?);
                    state.suffix =
                        Some(backend.logup_suffix_eq_device(
                            state.point_device.as_ref().ok_or(AccelError::InvalidInput(
                                "scheduled resident points missing",
                            ))?,
                            0,
                            self.point.len(),
                        )?);
                }
                Ok::<(), AccelError>(())
            })();
        if let Err(error) = result {
            let cleanup = state.cleanup(backend);
            return Err(prefer_cleanup(error.into(), cleanup));
        }
        if self.point.len() > 1 {
            ctr.bulk((1usize << (self.point.len() - 1)) as u64 - 1, 0);
        }
        self.layer = Some(ResidentLayer::General(state));
        Ok(())
    }

    fn begin_aux_layer(
        &mut self,
        layer_index: usize,
        mus: Vec<Fp2>,
        lambda: Fp2,
        ctr: &mut Counters,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let vector_len = 1usize << layer_index;
        let claim_columns = self
            .aux_claims
            .iter()
            .map(|claim| {
                u32::try_from(claim.col).map_err(|_| LogupBatchError::InvalidGeometry(self.site))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let weights: Vec<_> = self
            .aux_claims
            .iter()
            .zip(&mus)
            .map(|(claim, &mu)| (mu * (Fp2::ONE - claim.point[0]), mu * claim.point[0]))
            .collect();
        ctr.bulk(2 * weights.len() as u64, 0);
        let mut state = ResidentAuxLayer {
            vectors: Vec::new(),
            next_vectors: Vec::new(),
            columns: self.aux_columns.take(),
            next_columns: None,
            eq_rows: None,
            next_eq_rows: None,
            claim_points: None,
            claim_columns: None,
            weights_device: None,
            point_device: None,
            suffix: None,
            weights,
            column_count: self.column_count,
            claim_count: self.aux_claims.len(),
            point_len: layer_index,
            current_len: vector_len,
            lambda,
            cpref: Fp2::ONE,
            rprime: Vec::with_capacity(layer_index),
        };
        let result = (|| {
            if state.claim_count > 0 && layer_index > 0 {
                state.claim_points = Some(
                    backend.upload_new_device(
                        &self
                            .aux_claims
                            .iter()
                            .flat_map(|claim| claim.point[1..].iter().copied().map(Fp2Repr::from))
                            .collect::<Vec<_>>(),
                    )?,
                );
            }
            if state.claim_count > 0 {
                state.eq_rows = Some(backend.logup_eq_rows_device(
                    state.claim_points.as_ref(),
                    state.claim_count,
                    layer_index,
                )?);
                state.claim_columns = Some(backend.upload_new_device(&claim_columns)?);
                state.weights_device = Some(
                    backend.upload_new_device(
                        &state
                            .weights
                            .iter()
                            .flat_map(|&(w0, w1)| [Fp2Repr::from(w0), Fp2Repr::from(w1)])
                            .collect::<Vec<_>>(),
                    )?,
                );
            }
            let (leaf_p, leaf_q) = backend.logup_materialize_leaves_device(
                self.dleaf
                    .as_ref()
                    .ok_or(AccelError::InvalidInput("scheduled aux lookup leaf missing"))?,
                0,
                self.alpha.c1,
                None,
                2 * vector_len,
            )?;
            // P is the public all-ones leaf.  Its two folded halves remain
            // one under every challenge, so materializing/folding p0 and p1
            // would be pure resident overhead.  The backend currently
            // returns the leaf allocation as a pair; release P immediately
            // and keep only the private q halves.
            let q_pair = backend.fp2_deinterleave_device(&leaf_q, 0, vector_len);
            let mut leaf_cleanup = None;
            remember_cleanup(backend.free_device(leaf_p), &mut leaf_cleanup);
            remember_cleanup(backend.free_device(leaf_q), &mut leaf_cleanup);
            let leaf_cleanup = leaf_cleanup.map_or(Ok(()), Err);
            match q_pair {
                Ok((q0, q1)) => {
                    state.vectors.extend([q0, q1]);
                    leaf_cleanup?;
                }
                Err(error) => return Err(prefer_accel_cleanup(error, leaf_cleanup)),
            }
            if layer_index > 0 {
                state.point_device = Some(backend.upload_new_device(
                    &self.point.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>(),
                )?);
                state.suffix = Some(
                    backend.logup_suffix_eq_device(
                        state
                            .point_device
                            .as_ref()
                            .ok_or(AccelError::InvalidInput("scheduled aux points missing"))?,
                        0,
                        layer_index,
                    )?,
                );
            }
            Ok::<(), AccelError>(())
        })();
        if let Err(error) = result {
            let cleanup = state.cleanup(backend);
            return Err(prefer_cleanup(error.into(), cleanup));
        }
        ctr.bulk((state.claim_count * vector_len) as u64, 0);
        if layer_index > 1 {
            ctr.bulk((1usize << (layer_index - 1)) as u64 - 1, 0);
        }
        self.layer = Some(ResidentLayer::Aux(state));
        Ok(())
    }

    fn allocate_fold(&mut self, backend: &mut Backend) -> Result<(), LogupBatchError> {
        match self.layer.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => layer.allocate_next(backend)?,
            ResidentLayer::Aux(layer) => layer.allocate_next(backend)?,
        }
        Ok(())
    }

    fn count_round(&self, round: usize, ctr: &mut Counters) -> Result<(), LogupBatchError> {
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => {
                let half = layer.current_len / 2;
                ctr.bulk(10 * half as u64 + 4, 0);
            }
            ResidentLayer::Aux(layer) => {
                let half = layer.current_len / 2;
                if round == 0 {
                    ctr.bulk(0, 24 * half as u64);
                } else {
                    ctr.bulk(9 * half as u64, 0);
                }
                ctr.bulk(9 * half as u64 * self.aux_claims.len() as u64, 0);
                ctr.bulk(9, 0);
            }
        }
        Ok(())
    }

    fn enqueue_round(
        &self,
        round: usize,
        mailbox: &DeviceBuffer<Fp2Repr>,
        offset: usize,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let point = self.point[round];
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => {
                layer.enqueue_round(round, mailbox, offset, backend)?
            }
            ResidentLayer::Aux(layer) => {
                layer.enqueue_round(round, point, mailbox, offset, backend)?
            }
        }
        Ok(())
    }

    fn round_message(&self, raw: &[Fp2Repr]) -> Result<RoundMessage, LogupBatchError> {
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => {
                if raw.len() != 4 {
                    return Err(LogupBatchError::InvalidGeometry(self.site));
                }
                let values: Vec<Fp2> = raw.iter().copied().map(Into::into).collect();
                Ok(RoundMessage::General([
                    layer.cpref * (layer.lambda * values[0] + values[2]),
                    layer.cpref * (layer.lambda * values[1] + values[3]),
                ]))
            }
            ResidentLayer::Aux(_) => {
                if raw.len() != 3 {
                    return Err(LogupBatchError::InvalidGeometry(self.site));
                }
                Ok(RoundMessage::Aux([raw[0].into(), raw[1].into(), raw[2].into()]))
            }
        }
    }

    fn enqueue_fold(&self, challenge: Fp2, backend: &mut Backend) -> Result<(), LogupBatchError> {
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => layer.enqueue_fold(challenge, backend)?,
            ResidentLayer::Aux(layer) => layer.enqueue_fold(challenge, backend)?,
        }
        Ok(())
    }

    fn commit_fold(
        &mut self,
        round: usize,
        challenge: Fp2,
        ctr: &mut Counters,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let point = self.point[round];
        match self.layer.as_mut().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(layer) => {
                let half = layer.current_len / 2;
                ctr.bulk(4 * half as u64 + 2, 0);
                layer.commit_fold(point, challenge, backend)?;
            }
            ResidentLayer::Aux(layer) => {
                let half = layer.current_len / 2;
                if round == 0 {
                    ctr.bulk(2, 4 * half as u64);
                } else {
                    ctr.bulk(2 * half as u64 + 2, 0);
                }
                ctr.bulk(2 * half as u64 * self.column_count as u64, 0);
                ctr.bulk(half as u64 * self.aux_claims.len() as u64, 0);
                layer.commit_fold(point, challenge, backend)?;
            }
        }
        Ok(())
    }

    fn copy_split_to_mailbox(
        &self,
        mailbox: &DeviceBuffer<Fp2Repr>,
        offset: usize,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let layer = self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let mut copy = |buffer: &DeviceBuffer<Fp2Repr>, len: usize, at: usize| {
            backend.copy_mailbox_rows(
                DeviceSlice::new(buffer, 0, len)?,
                len,
                mailbox,
                at,
                len,
                1,
                len,
            )
        };
        match layer {
            ResidentLayer::General(layer) => {
                for (index, buffer) in layer.vectors.iter().enumerate() {
                    copy(buffer, 1, offset + index)?;
                }
            }
            ResidentLayer::Aux(layer) => {
                for (index, buffer) in layer.vectors.iter().enumerate() {
                    copy(buffer, 1, offset + index)?;
                }
                copy(
                    layer.columns.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))?,
                    2 * self.column_count,
                    offset + 2,
                )?;
            }
        }
        Ok(())
    }

    fn split_message(
        &self,
        raw: &[Fp2Repr],
        ctr: &mut Counters,
    ) -> Result<SplitMessage, LogupBatchError> {
        match self.layer.as_ref().ok_or(LogupBatchError::InvalidGeometry(self.site))? {
            ResidentLayer::General(_) => {
                if raw.len() != 4 {
                    return Err(LogupBatchError::InvalidGeometry(self.site));
                }
                Ok(SplitMessage {
                    splits: [raw[0].into(), raw[1].into(), raw[2].into(), raw[3].into()],
                    columns: None,
                    finals: Vec::new(),
                })
            }
            ResidentLayer::Aux(layer) => {
                if raw.len() != 2 + 2 * self.column_count {
                    return Err(LogupBatchError::InvalidGeometry(self.site));
                }
                let columns: Vec<[Fp2; 2]> = raw[2..]
                    .chunks_exact(2)
                    .map(|values| [values[0].into(), values[1].into()])
                    .collect();
                let finals = self
                    .aux_claims
                    .iter()
                    .zip(&layer.weights)
                    .map(|(claim, &(w0, w1))| AuxFinal {
                        col: claim.col,
                        w0,
                        w1,
                        eq_r: crate::mle::eq_points(&claim.point[1..], &layer.rprime),
                    })
                    .collect::<Vec<_>>();
                ctr.bulk(2 * self.point.len() as u64 * finals.len() as u64, 0);
                Ok(SplitMessage {
                    splits: [Fp2::ONE, Fp2::ONE, raw[0].into(), raw[1].into()],
                    columns: Some(columns),
                    finals,
                })
            }
        }
    }

    fn finish_layer(
        &mut self,
        challenge: Fp2,
        backend: &mut Backend,
    ) -> Result<(), LogupBatchError> {
        let mut layer = self.layer.take().ok_or(LogupBatchError::InvalidGeometry(self.site))?;
        let rprime = match &layer {
            ResidentLayer::General(layer) => layer.rprime.clone(),
            ResidentLayer::Aux(layer) => layer.rprime.clone(),
        };
        layer.cleanup(backend)?;
        self.point = std::iter::once(challenge).chain(rprime).collect();
        Ok(())
    }

    fn finish(
        mut self,
        ctr: &mut Counters,
        zero: &mut Vec<ProverAuthed>,
        backend: &mut Backend,
    ) -> Result<LogupBatchOutputP, LogupBatchError> {
        let cleanup = self.cleanup(backend);
        let blind = self
            .blind
            .take()
            .ok_or(LogupBatchError::InvalidGeometry(self.site))
            .and_then(|blind| blind.finish(self.depth));
        let blind = match blind {
            Ok(blind) => {
                cleanup.map_err(LogupBatchError::Accel)?;
                blind
            }
            Err(primary) => return Err(prefer_cleanup(primary, cleanup)),
        };
        zero.push(blind.cp.sub(ProverAuthed::from_public(Fp2::ONE)));
        let mut closure = blind.cq.sub(ProverAuthed::from_public(self.alpha));
        for (claim, shift) in blind.col_claims.iter().zip(&self.shifts) {
            if let Some(shift) = shift {
                closure = closure.add(claim.scale(Fp2::from_base(Fp::new(1u64 << shift))));
            }
        }
        debug_assert_eq!(closure.x, Fp2::ZERO, "scheduled resident leaf closure violated");
        zero.push(closure);
        ctr.bulk(2 * self.column_count as u64, 0);
        let point = self.point;
        Ok(LogupBatchOutputP {
            site: self.site,
            output: InstanceOutP {
                proof: BlindInstance { lookup: blind.proof },
                alpha: self.alpha,
                col_claims: blind
                    .col_claims
                    .into_iter()
                    .map(|value| OpenClaim { point: point.clone(), value })
                    .collect(),
                roots: blind.roots,
                point,
            },
        })
    }
}

fn cleanup_resident_states(
    states: &mut [ResidentJobState],
    backend: &mut Backend,
) -> Result<(), AccelError> {
    cleanup_all(states, |state| state.cleanup(backend))
}

fn resident_failure(
    primary: LogupBatchError,
    states: &mut [ResidentJobState],
    backend: &mut Backend,
) -> LogupBatchError {
    prefer_cleanup(primary, cleanup_resident_states(states, backend))
}

fn resident_state_index(
    states: &[ResidentJobState],
    site: SiteId,
) -> Result<usize, LogupBatchError> {
    states
        .binary_search_by_key(&site, |state| state.site)
        .map_err(|_| LogupBatchError::InvalidGeometry(site))
}

fn download_and_free_mailbox(
    backend: &mut Backend,
    mailbox: DeviceBuffer<Fp2Repr>,
) -> Result<Vec<Fp2Repr>, LogupBatchError> {
    let result = backend.download_device(&mailbox, 0, mailbox.len());
    let cleanup = backend.free_device(mailbox);
    match (result, cleanup) {
        (_, Err(error)) => Err(error.into()),
        (Err(error), Ok(())) => Err(error.into()),
        (Ok(values), Ok(())) => Ok(values),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_resident_batch(
    plan: &LogupBatchPlan,
    states: &mut Vec<ResidentJobState>,
    correlations: &mut FullCorrBatchReservation<'_>,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> Result<Vec<LogupBatchOutputP>, LogupBatchError> {
    let epochs = plan.schedule().epochs();
    let root_epoch = epochs.first().ok_or(LogupBatchError::CohortTooSmall)?;
    if root_epoch.sites.len() != states.len()
        || root_epoch
            .sites
            .iter()
            .any(|site| site.family != RoundFamily::LogupRoot || site.message_width != 2)
    {
        return Err(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch));
    }

    // Root mailbox: tree construction has already been enqueued for every
    // site. Copies share one coarse PcsRows scope and one D2H barrier.
    let root_mailbox = backend.alloc_device(root_epoch.mailbox_elements)?;
    let root_copy = (|| {
        let mut scope = backend.coarse_timing_scope(Operation::Mailbox)?;
        for stage in &root_epoch.sites {
            let index = resident_state_index(states, stage.id)
                .map_err(|_| AccelError::InvalidInput("scheduled root site missing"))?;
            let state = &states[index];
            for (slot, tree) in
                [state.tree_p.as_ref(), state.tree_q.as_ref()].into_iter().enumerate()
            {
                let tree = tree.ok_or(AccelError::InvalidInput("scheduled root tree missing"))?;
                scope.backend_mut().copy_mailbox_rows(
                    DeviceSlice::new(tree, 0, 1)?,
                    1,
                    &root_mailbox,
                    stage.mailbox_offset + slot,
                    1,
                    1,
                    1,
                )?;
            }
        }
        scope.finish()
    })();
    if let Err(error) = root_copy {
        let cleanup = backend.free_device(root_mailbox);
        return Err(prefer_cleanup(error.into(), cleanup));
    }
    let root_values = download_and_free_mailbox(backend, root_mailbox)?;
    for stage in &root_epoch.sites {
        let index = resident_state_index(states, stage.id)?;
        let values = &root_values[stage.mailbox_offset..stage.mailbox_offset + 2];
        let site = states[index].site;
        states[index].blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(site))?.seal_root(
            values[0].into(),
            values[1].into(),
            correlations,
            tx,
        )?;
    }

    let max_depth = states.iter().map(|state| state.depth).max().unwrap_or(0);
    let mut epoch_index = 1usize;
    for layer_index in 0..max_depth {
        let active: Vec<_> = states
            .iter()
            .enumerate()
            .filter_map(|(index, state)| (layer_index < state.depth).then_some(index))
            .collect();
        let timing_chunks = plan
            .timing_preparation_chunks(active.len())
            .ok_or(ScheduleError::MailboxSizeOverflow)?;
        for chunk in timing_chunks {
            // The returned `flushed` bit and backend stats classify any
            // necessary network synchronization as a timing-only boundary.
            // No public mailbox is downloaded and the cohort stays intact.
            let _timing_preflight = backend.ensure_timing_capacity(chunk.record_bound)?;
            let end = chunk
                .site_offset
                .checked_add(chunk.site_count)
                .ok_or(LogupBatchError::InvalidGeometry(states[0].site))?;
            for &index in active
                .get(chunk.site_offset..end)
                .ok_or(LogupBatchError::InvalidGeometry(states[0].site))?
            {
                states[index].begin_layer(layer_index, tx, ctr, backend)?;
            }
        }

        for round in 0..layer_index {
            let epoch = epochs
                .get(epoch_index)
                .ok_or(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch))?;
            if epoch.sites.len() != active.len() {
                return Err(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch));
            }
            let mailbox = backend.alloc_device(epoch.mailbox_elements)?;
            let launch = (|| {
                let mut scope = backend.coarse_timing_scope(Operation::Logup)?;
                for stage in &epoch.sites {
                    let index = resident_state_index(states, stage.id)
                        .map_err(|_| AccelError::InvalidInput("scheduled round site missing"))?;
                    states[index]
                        .enqueue_round(round, &mailbox, stage.mailbox_offset, scope.backend_mut())
                        .map_err(|error| match error {
                            LogupBatchError::Accel(error) => error,
                            _ => AccelError::InvalidInput("invalid scheduled round state"),
                        })?;
                }
                scope.finish()
            })();
            if let Err(error) = launch {
                let cleanup = backend.free_device(mailbox);
                return Err(prefer_cleanup(error.into(), cleanup));
            }
            let raw = download_and_free_mailbox(backend, mailbox)?;
            let mut messages = Vec::with_capacity(epoch.sites.len());
            for stage in &epoch.sites {
                let index = resident_state_index(states, stage.id)?;
                states[index].count_round(round, ctr)?;
                let end = stage
                    .mailbox_offset
                    .checked_add(stage.message_width)
                    .ok_or(ScheduleError::MailboxSizeOverflow)?;
                messages
                    .push((index, states[index].round_message(&raw[stage.mailbox_offset..end])?));
            }
            for (index, message) in &messages {
                let state = &mut states[*index];
                let blind =
                    state.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(state.site))?;
                match message {
                    RoundMessage::General(values) => {
                        blind.seal_round2(*values, state.point[round], correlations, tx)?
                    }
                    RoundMessage::Aux(values) => {
                        blind.seal_round3(*values, state.point[round], correlations, tx)?
                    }
                }
            }
            let mut challenges = Vec::with_capacity(messages.len());
            for (index, message) in &messages {
                let site = states[*index].site;
                let blind =
                    states[*index].blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(site))?;
                let challenge = match message {
                    RoundMessage::General(_) => blind.finish_round2(tx, ctr)?,
                    RoundMessage::Aux(_) => blind.finish_round3(tx, ctr)?,
                };
                challenges.push((*index, challenge));
            }

            // Allocate every output before entering the fold scope. No
            // allocator/free operation is permitted while coarse timing is active.
            for (index, _) in &challenges {
                states[*index].allocate_fold(backend)?;
            }
            let fold_launch = (|| {
                let mut scope = backend.coarse_timing_scope(Operation::Logup)?;
                for &(index, challenge) in &challenges {
                    states[index].enqueue_fold(challenge, scope.backend_mut()).map_err(
                        |error| match error {
                            LogupBatchError::Accel(error) => error,
                            _ => AccelError::InvalidInput("invalid scheduled fold state"),
                        },
                    )?;
                }
                scope.finish()
            })();
            if let Err(error) = fold_launch {
                return Err(error.into());
            }
            for (index, challenge) in challenges {
                states[index].commit_fold(round, challenge, ctr, backend)?;
            }
            epoch_index += 1;
        }

        let epoch = epochs
            .get(epoch_index)
            .ok_or(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch))?;
        if epoch.sites.len() != active.len()
            || epoch.sites.iter().any(|stage| stage.family != RoundFamily::LogupSplit)
        {
            return Err(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch));
        }
        let mailbox = backend.alloc_device(epoch.mailbox_elements)?;
        let split_copy = (|| {
            let mut scope = backend.coarse_timing_scope(Operation::Mailbox)?;
            for stage in &epoch.sites {
                let index = resident_state_index(states, stage.id)
                    .map_err(|_| AccelError::InvalidInput("scheduled split site missing"))?;
                states[index]
                    .copy_split_to_mailbox(&mailbox, stage.mailbox_offset, scope.backend_mut())
                    .map_err(|error| match error {
                        LogupBatchError::Accel(error) => error,
                        _ => AccelError::InvalidInput("invalid scheduled split state"),
                    })?;
            }
            scope.finish()
        })();
        if let Err(error) = split_copy {
            let cleanup = backend.free_device(mailbox);
            return Err(prefer_cleanup(error.into(), cleanup));
        }
        let raw = download_and_free_mailbox(backend, mailbox)?;
        let mut messages = Vec::with_capacity(epoch.sites.len());
        for stage in &epoch.sites {
            let index = resident_state_index(states, stage.id)?;
            let end = stage
                .mailbox_offset
                .checked_add(stage.message_width)
                .ok_or(ScheduleError::MailboxSizeOverflow)?;
            messages
                .push((index, states[index].split_message(&raw[stage.mailbox_offset..end], ctr)?));
        }
        for (index, message) in &messages {
            let state = &mut states[*index];
            state.blind.as_mut().ok_or(LogupBatchError::InvalidGeometry(state.site))?.seal_split(
                message.splits,
                message.columns.as_deref(),
                &message.finals,
                correlations,
                tx,
                ctr,
                prod,
                zero,
            )?;
        }
        let mut split_challenges = Vec::with_capacity(messages.len());
        for (index, _) in &messages {
            let site = states[*index].site;
            let challenge = states[*index]
                .blind
                .as_mut()
                .ok_or(LogupBatchError::InvalidGeometry(site))?
                .finish_split(tx)?;
            split_challenges.push((*index, challenge));
        }
        for (index, challenge) in split_challenges {
            states[index].finish_layer(challenge, backend)?;
        }
        epoch_index += 1;
    }
    if epoch_index != epochs.len() {
        return Err(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch));
    }

    let mut outputs = Vec::with_capacity(states.len());
    while !states.is_empty() {
        let state = states.remove(0);
        outputs.push(state.finish(ctr, zero, backend)?);
    }
    Ok(outputs)
}

/// Whole-tree resident lookup cohort. Every protocol-visible root, round and
/// split crosses D2H once per public epoch; folds and round kernels execute in
/// non-allocating coarse scopes, and all source views remain caller-owned.
#[allow(clippy::too_many_arguments)]
pub fn blind_instance_prove_resident_batch(
    plan: &LogupBatchPlan,
    mut jobs: Vec<ResidentLogupBatchJob<'_>>,
    stream: &mut CorrelationStream,
    tx: &mut Transcript,
    ctr: &mut Counters,
    prod: &mut ProdTriples,
    zero: &mut Vec<ProverAuthed>,
    backend: &mut Backend,
) -> Result<Vec<LogupBatchOutputP>, LogupBatchError> {
    // All exact membership, shape, domain-range and timing-ring checks happen
    // before the backend, transcript, correlation stream or output batches
    // are mutated.
    preflight_resident(plan, &jobs, backend)?;
    let mut correlations = stream.try_reserve_full_corr_ranges(plan.full_corr_ranges())?;
    // Product-round reductions use two private CUDA scratch slots. Size them
    // before any coarse epoch begins so the first auxiliary round cannot
    // lazily grow workspace inside the sealed scope.
    if let Some(max_pairs) =
        jobs.iter().filter_map(|job| (job.entries >= 4).then_some(job.entries / 4)).max()
    {
        backend.reserve_logup_round_workspace(max_pairs)?;
    }
    jobs.sort_by_key(|job| job.site);
    let mut states = Vec::with_capacity(jobs.len());
    let timing_chunks =
        plan.timing_preparation_chunks(jobs.len()).ok_or(ScheduleError::MailboxSizeOverflow)?;
    let mut jobs = jobs.into_iter();
    for chunk in timing_chunks {
        // Explicit, classified pre-message boundary. The final chunk includes
        // the root-mailbox and D2H timing records reserved by the helper.
        if let Err(error) = backend.ensure_timing_capacity(chunk.record_bound) {
            return Err(resident_failure(error.into(), &mut states, backend));
        }
        for _ in 0..chunk.site_count {
            let job = jobs
                .next()
                .ok_or(LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch));
            let job = match job {
                Ok(job) => job,
                Err(error) => return Err(resident_failure(error, &mut states, backend)),
            };
            match ResidentJobState::new(plan, job, ctr, backend) {
                Ok(state) => states.push(state),
                Err(error) => {
                    return Err(resident_failure(error, &mut states, backend));
                }
            }
        }
    }
    if jobs.next().is_some() {
        return Err(resident_failure(
            LogupBatchError::Schedule(ScheduleError::EpochMembershipMismatch),
            &mut states,
            backend,
        ));
    }
    let result =
        run_resident_batch(plan, &mut states, &mut correlations, tx, ctr, prod, zero, backend);
    let outputs = match result {
        Ok(outputs) => outputs,
        Err(error) => return Err(resident_failure(error, &mut states, backend)),
    };
    correlations.finish();
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn cleanup_is_exhaustive_and_cleanup_error_precedes_primary() {
        let first = AccelError::InvalidInput("first cleanup failure");
        let second = AccelError::InvalidInput("second cleanup failure");
        let mut visited = Vec::new();
        let cleanup = cleanup_all(0..4, |index| {
            visited.push(index);
            match index {
                1 => Err(first.clone()),
                2 => Err(second.clone()),
                _ => Ok(()),
            }
        });
        assert_eq!(visited, vec![0, 1, 2, 3]);
        assert_eq!(cleanup, Err(first.clone()));

        let site = SiteId::new(14, RoundFamily::LogupAux, 0);
        assert_eq!(
            prefer_cleanup(LogupBatchError::InvalidProof(site), Ok(())),
            LogupBatchError::InvalidProof(site),
            "a clean ownership sweep must preserve the primary error"
        );
        assert_eq!(
            prefer_cleanup(LogupBatchError::InvalidProof(site), Err(first.clone())),
            LogupBatchError::Accel(first.clone()),
            "a release failure makes the resident context unsafe and must prevail"
        );
        assert_eq!(
            prefer_accel_cleanup(second, Err(first.clone())),
            first,
            "nested accelerator constructors use the same cleanup precedence"
        );
        let nested_primary = AccelError::InvalidInput("nested primary failure");
        assert_eq!(
            prefer_accel_cleanup(nested_primary.clone(), Ok(())),
            nested_primary,
            "a clean nested constructor cleanup must preserve its primary error"
        );
    }

    #[test]
    fn later_timing_chunk_failure_releases_every_prior_chunk_owner() {
        let chunks = logup_batch_timing_preparation_chunks(57).unwrap();
        assert_eq!(chunks.len(), 2);
        let mut owners = Vec::new();
        let mut released = Vec::new();
        let cleanup_failure = AccelError::InvalidInput("owner release failed");
        let preflight_failure =
            LogupBatchError::Accel(AccelError::InvalidInput("timing preflight failed"));
        let mut failure = None;

        for (chunk_index, chunk) in chunks.into_iter().enumerate() {
            if chunk_index == 1 {
                let cleanup = cleanup_all(std::mem::take(&mut owners), |owner| {
                    released.push(owner);
                    if owner == 7 {
                        Err(cleanup_failure.clone())
                    } else {
                        Ok(())
                    }
                });
                failure = Some(prefer_cleanup(preflight_failure, cleanup));
                break;
            }
            owners.extend(chunk.site_offset..chunk.site_offset + chunk.site_count);
        }

        assert!(owners.is_empty());
        assert_eq!(released, (0..56).collect::<Vec<_>>());
        assert_eq!(failure, Some(LogupBatchError::Accel(cleanup_failure)));
    }

    fn auth_pair(
        stream: &mut CorrelationStream,
        ctx: &mut VerifierCtx,
        domain: u64,
        value: Fp2,
    ) -> (ProverAuthed, VerifierKey) {
        let corr = stream.draw_fulls(domain, 1)[0];
        let key = ctx.expand_full_keys(domain, 1)[0];
        (
            ProverAuthed { x: value, m: corr.m },
            VerifierKey { k: key + ctx.delta * (value - corr.x) },
        )
    }

    fn raw_d2h_elements(depth: usize, columns: usize) -> usize {
        let upper_rounds = (depth - 1) * (depth - 2) / 2;
        2 + 4 * upper_rounds + 4 * (depth - 1) + 3 * (depth - 1) + 2 + 2 * columns
    }

    fn proof_elements(depth: usize, columns: usize) -> usize {
        let upper_round_values: usize = (0..depth - 1).map(|layer| 2 * layer + 7).sum();
        2 + upper_round_values + 7 + 3 * (depth - 1) + 2 * columns
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn public_column_index_range_must_fit_cuda_u32() {
        let max_representable_count = u32::MAX as usize + 1;
        let site = |slot, column_count, mask_dom_base| LogupBatchSite {
            id: SiteId::new(14, RoundFamily::LogupAux, slot),
            depth: 1,
            column_count,
            aux_claim_count: 0,
            mask_dom_base,
        };
        assert!(LogupBatchPlan::new(vec![
            site(0, max_representable_count, 0x40_000),
            site(1, max_representable_count, 0x40_100),
        ])
        .is_ok());

        let invalid = site(2, max_representable_count + 1, 0x40_200);
        assert_eq!(
            LogupBatchPlan::new(vec![invalid, site(3, 1, 0x40_300)]),
            Err(LogupBatchError::InvalidGeometry(invalid.id))
        );
    }

    #[test]
    fn one_column_aux_sites_use_four_element_raw_split_mailboxes() {
        let sites: Vec<_> = (0..2)
            .map(|lane| LogupBatchSite {
                id: SiteId::new(3, RoundFamily::LogupAux, lane),
                depth: 2,
                column_count: 1,
                aux_claim_count: 1,
                mask_dom_base: 0x3000 + u64::from(lane) * 0x100,
            })
            .collect();
        let plan = LogupBatchPlan::new(sites).unwrap();
        let leaf_splits: Vec<_> = plan
            .schedule()
            .epochs()
            .iter()
            .flat_map(|epoch| &epoch.sites)
            .filter(|site| site.family == RoundFamily::LogupSplit && site.message_width != 4)
            .collect();
        assert!(leaf_splits.is_empty());
    }

    #[test]
    fn scheduled_cpu_heterogeneous_depths_verify_and_layout_is_exact() {
        let sites = [
            LogupBatchSite {
                id: SiteId::new(4, RoundFamily::LogupAux, 9),
                depth: 2,
                column_count: 2,
                aux_claim_count: 1,
                mask_dom_base: 0x4000,
            },
            LogupBatchSite {
                id: SiteId::new(4, RoundFamily::LogupAux, 3),
                depth: 3,
                column_count: 2,
                aux_claim_count: 1,
                mask_dom_base: 0x5000,
            },
        ];
        let plan = LogupBatchPlan::new(sites.to_vec()).unwrap();
        assert_eq!(
            plan.schedule().round_d2h_bytes(),
            16 * sites
                .iter()
                .map(|site| raw_d2h_elements(site.depth, site.column_count) as u64)
                .sum::<u64>()
        );
        assert_eq!(plan.schedule().epochs()[0].mailbox_elements, 4);
        assert_eq!(
            plan.schedule().epochs()[0].sites.iter().map(|site| site.family).collect::<Vec<_>>(),
            vec![RoundFamily::LogupRoot, RoundFamily::LogupRoot]
        );
        assert!(plan
            .schedule()
            .epochs()
            .iter()
            .any(|epoch| epoch.sites.iter().any(|site| {
                site.family == RoundFamily::LogupSplit && site.message_width == 6
            })));

        let delta = Fp2::new(Fp::new(17), Fp::new(29));
        let mut prover_stream = CorrelationStream::new([31; 32]);
        let mut verifier_ctx = VerifierCtx::new([31; 32], delta);
        let mut jobs = Vec::new();
        let mut verifier_aux = Vec::new();
        for (job_index, site) in sites.iter().enumerate() {
            let entries = 1usize << site.depth;
            let c0: Vec<Fp> =
                (0..entries).map(|row| Fp::new((row * 13 + job_index * 7 + 1) as u64)).collect();
            let c1: Vec<Fp> =
                (0..entries).map(|row| Fp::new((row * row + job_index * 11 + 2) as u64)).collect();
            let point: Vec<Fp2> = (0..site.depth)
                .map(|i| Fp2::new(Fp::new((i + 3) as u64), Fp::new((2 * i + 5) as u64)))
                .collect();
            let lifted: Vec<Fp2> = c1.iter().copied().map(Fp2::from_base).collect();
            let value = crate::mle::eval_mle(&lifted, &point);
            let (auth, key) =
                auth_pair(&mut prover_stream, &mut verifier_ctx, 0x100 + job_index as u64, value);
            verifier_aux.push(vec![(1usize, point.clone(), key)]);
            jobs.push(CpuLogupBatchJob {
                site: site.id,
                columns: vec![c0, c1],
                shifts: vec![Some(0), Some(8)],
                alpha: Fp2::new(Fp::new(101 + job_index as u64), Fp::new(211 + job_index as u64)),
                aux_claims: vec![LeafAuxClaim { col: 1, point, value: auth }],
            });
        }
        // Exercise canonicalization: completion/input order is deliberately
        // the opposite of SiteId order.
        jobs.reverse();
        verifier_aux.reverse();
        let mut prover_tx = Transcript::new([41; 32]);
        let mut ctr = Counters::default();
        let mut prod = Vec::new();
        let mut zero = Vec::new();
        let outputs = blind_instance_prove_batch_cpu(
            &plan,
            jobs,
            &mut prover_stream,
            &mut prover_tx,
            &mut ctr,
            &mut prod,
            &mut zero,
        )
        .unwrap();
        assert_eq!(outputs.iter().map(|output| output.site).collect::<Vec<_>>(), {
            let mut ids = sites.iter().map(|site| site.id).collect::<Vec<_>>();
            ids.sort();
            ids
        });
        let expected_proof_bytes: u64 = sites
            .iter()
            .map(|site| 16 * proof_elements(site.depth, site.column_count) as u64)
            .sum();
        assert_eq!(
            outputs.iter().map(|output| output.output.proof.bytes()).sum::<u64>(),
            expected_proof_bytes
        );

        // Metadata was built in original site order then reversed with jobs;
        // pair it by SiteId before constructing the verifier cohort.
        let mut aux_by_id: BTreeMap<SiteId, Vec<(usize, Vec<Fp2>, VerifierKey)>> =
            sites.iter().rev().map(|site| site.id).zip(verifier_aux).collect();
        let verify_shifts = [Some(0), Some(8)];
        let verify_jobs: Vec<_> = outputs
            .iter()
            .map(|output| {
                let site = plan.site(output.site).unwrap();
                VerifyLogupBatchJob {
                    site: output.site,
                    n_bits: site.depth,
                    shifts: &verify_shifts,
                    alpha: output.output.alpha,
                    proof: &output.output.proof,
                    aux_claims: aux_by_id.get(&output.site).unwrap(),
                }
            })
            .collect();
        let mut verifier_tx = Transcript::new([41; 32]);
        let mut kprod = Vec::new();
        let mut kzero = Vec::new();
        let verified = blind_instance_verify_batch(
            &plan,
            verify_jobs,
            &mut verifier_ctx,
            &mut verifier_tx,
            &mut kprod,
            &mut kzero,
        )
        .unwrap();
        assert_eq!(prover_tx.ledger(), verifier_tx.ledger());
        assert_eq!(prod.len(), kprod.len());
        assert_eq!(zero.len(), kzero.len());
        for (output, checked) in outputs.iter().zip(&verified) {
            assert_eq!(output.site, checked.site);
            assert_eq!(output.output.point, checked.output.point);
            for (claim, key) in output.output.col_claims.iter().zip(&checked.output.col_keys) {
                assert_eq!(key.key.k, claim.value.m + delta * claim.value.x);
            }
        }
        for (claim, key) in zero.iter().zip(&kzero) {
            assert_eq!(claim.x, Fp2::ZERO);
            assert_eq!(key.k, claim.m + delta * claim.x);
        }

        let collision_jobs: Vec<_> = outputs
            .iter()
            .map(|output| {
                let site = plan.site(output.site).unwrap();
                VerifyLogupBatchJob {
                    site: output.site,
                    n_bits: site.depth,
                    shifts: &verify_shifts,
                    alpha: output.output.alpha,
                    proof: &output.output.proof,
                    aux_claims: aux_by_id.get(&output.site).unwrap(),
                }
            })
            .collect();
        let mut collision_ctx = VerifierCtx::new([31; 32], delta);
        let _ = collision_ctx.expand_full_keys(sites[0].mask_dom_base, 2);
        let collision_counters = collision_ctx.counters;
        let mut collision_tx = Transcript::new([41; 32]);
        let mut collision_kprod = Vec::new();
        let mut collision_kzero = Vec::new();
        let collision = blind_instance_verify_batch(
            &plan,
            collision_jobs,
            &mut collision_ctx,
            &mut collision_tx,
            &mut collision_kprod,
            &mut collision_kzero,
        );
        assert!(matches!(collision, Err(LogupBatchError::Correlation(_))));
        assert_eq!(collision_ctx.counters, collision_counters);
        assert_eq!(collision_tx.total_bytes(), 0);
        assert!(collision_kprod.is_empty() && collision_kzero.is_empty());
        aux_by_id.clear();
    }

    #[test]
    fn scheduled_preflight_does_not_mutate_protocol_state() {
        let site = LogupBatchSite {
            id: SiteId::new(9, RoundFamily::LogupAux, 0),
            depth: 2,
            column_count: 1,
            aux_claim_count: 0,
            mask_dom_base: 0x9000,
        };
        let other = LogupBatchSite {
            id: SiteId::new(9, RoundFamily::LogupAux, 1),
            mask_dom_base: 0xa000,
            ..site
        };
        let plan = LogupBatchPlan::new(vec![site, other]).unwrap();
        let mut stream = CorrelationStream::new([51; 32]);
        let before = stream.counters;
        let mut tx = Transcript::new([52; 32]);
        let mut ctr = Counters::default();
        let mut prod = Vec::new();
        let mut zero = Vec::new();
        let result = blind_instance_prove_batch_cpu(
            &plan,
            vec![CpuLogupBatchJob {
                site: site.id,
                columns: vec![vec![Fp::ZERO; 4]],
                shifts: vec![Some(0)],
                alpha: Fp2::ONE,
                aux_claims: Vec::new(),
            }],
            &mut stream,
            &mut tx,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        assert!(matches!(
            result,
            Err(LogupBatchError::Schedule(ScheduleError::MembershipMismatch { .. }))
        ));
        assert_eq!(stream.counters, before);
        assert_eq!(tx.total_bytes(), 0);
        assert_eq!(ctr, Counters::default());
        assert!(prod.is_empty() && zero.is_empty());
    }

    #[test]
    fn scheduled_full_correlation_reservation_is_atomic() {
        let site0 = LogupBatchSite {
            id: SiteId::new(10, RoundFamily::LogupAux, 0),
            depth: 2,
            column_count: 1,
            aux_claim_count: 0,
            mask_dom_base: 0x15_000,
        };
        let site1 = LogupBatchSite {
            id: SiteId::new(10, RoundFamily::LogupAux, 1),
            mask_dom_base: 0x16_000,
            ..site0
        };
        let sites = [site0, site1];
        let plan = LogupBatchPlan::new(sites.to_vec()).unwrap();
        let mut stream = CorrelationStream::new([53; 32]);
        // Poison the first root domain. The later ranges remain untouched and
        // every protocol/output accumulator must stay unchanged.
        let _ = stream.draw_fulls(sites[0].mask_dom_base, 2);
        let counters_before = stream.counters;
        let mut tx = Transcript::new([54; 32]);
        let mut ctr = Counters::default();
        let mut prod = Vec::new();
        let mut zero = Vec::new();
        let jobs = sites
            .iter()
            .map(|site| CpuLogupBatchJob {
                site: site.id,
                columns: vec![vec![Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4)]],
                shifts: vec![Some(0)],
                alpha: Fp2::new(Fp::new(101), Fp::new(103)),
                aux_claims: Vec::new(),
            })
            .collect();
        let result = blind_instance_prove_batch_cpu(
            &plan,
            jobs,
            &mut stream,
            &mut tx,
            &mut ctr,
            &mut prod,
            &mut zero,
        );
        assert!(matches!(result, Err(LogupBatchError::Correlation(_))));
        assert_eq!(stream.counters, counters_before);
        assert_eq!(tx.total_bytes(), 0);
        assert_eq!(ctr, Counters::default());
        assert!(prod.is_empty() && zero.is_empty());
    }

    #[test]
    fn seventy_two_sites_keep_one_cohort_with_two_timing_preflights() {
        assert_eq!(
            logup_batch_timing_preparation_chunks(56).unwrap(),
            vec![LogupTimingPreparationChunk {
                site_offset: 0,
                site_count: 56,
                // 56 * 9 preparation records + mailbox + D2H.
                record_bound: 506,
            }]
        );
        assert_eq!(
            logup_batch_timing_preparation_chunks(57).unwrap(),
            vec![
                LogupTimingPreparationChunk { site_offset: 0, site_count: 56, record_bound: 504 },
                LogupTimingPreparationChunk { site_offset: 56, site_count: 1, record_bound: 11 },
            ]
        );
        let sites: Vec<_> = (0..72)
            .map(|slot| LogupBatchSite {
                id: SiteId::new(13, RoundFamily::LogupAux, slot),
                depth: 1,
                column_count: 1,
                aux_claim_count: 0,
                mask_dom_base: 0x20_000 + 0x10 * slot as u64,
            })
            .collect();
        let plan = LogupBatchPlan::new(sites).unwrap();
        assert_eq!(plan.sites().len(), 72);
        assert_eq!(
            plan.timing_preparation_chunks(72).unwrap(),
            vec![
                LogupTimingPreparationChunk { site_offset: 0, site_count: 56, record_bound: 504 },
                LogupTimingPreparationChunk { site_offset: 56, site_count: 16, record_bound: 146 },
            ]
        );
        // Root + split remain one mailbox epoch each for all 72 sites.
        assert_eq!(plan.schedule().epochs().len(), 2);
        assert!(plan.schedule().epochs().iter().all(|epoch| epoch.sites.len() == 72));
    }

    #[test]
    #[should_panic(expected = "reserved top bits")]
    fn legacy_domain_cursor_fails_closed_at_reserved_boundary() {
        let mut domains = Doms::new(crate::schedule::CORRELATION_DOMAIN_LIMIT - 1);
        let _ = domains.take(2);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_scheduled_batch_matches_cpu_and_has_one_d2h_per_epoch() {
        struct Case {
            site: LogupBatchSite,
            columns: Vec<Vec<Fp>>,
            shifts: Vec<Option<u32>>,
            alpha: Fp2,
            point: Vec<Fp2>,
            value: Fp2,
        }

        let mut resident = match Backend::cuda_resident() {
            Ok(backend) => backend,
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping resident scheduled LogUp differential: {error}");
                return;
            }
            Err(error) => panic!("CUDA required: {error}"),
        };
        let cases: Vec<_> = [2usize, 3]
            .into_iter()
            .enumerate()
            .map(|(case_index, depth)| {
                let entries = 1usize << depth;
                let c0: Vec<Fp> = (0..entries)
                    .map(|row| Fp::new((row * 19 + case_index * 5 + 3) as u64))
                    .collect();
                let c1: Vec<Fp> = (0..entries)
                    .map(|row| Fp::new((row * row * 7 + case_index * 13 + 4) as u64))
                    .collect();
                let point: Vec<Fp2> = (0..depth)
                    .map(|i| {
                        Fp2::new(
                            Fp::new((i * 23 + case_index + 2) as u64),
                            Fp::new((i * 29 + case_index + 7) as u64),
                        )
                    })
                    .collect();
                let lifted: Vec<Fp2> = c1.iter().copied().map(Fp2::from_base).collect();
                let value = crate::mle::eval_mle(&lifted, &point);
                Case {
                    site: LogupBatchSite {
                        id: SiteId::new(11, RoundFamily::LogupAux, (5 - case_index) as u32),
                        depth,
                        column_count: 2,
                        aux_claim_count: 1,
                        mask_dom_base: 0xb000 + 0x1000 * case_index as u64,
                    },
                    columns: vec![c0, c1],
                    shifts: vec![Some(0), Some(9)],
                    alpha: Fp2::new(
                        Fp::new(301 + case_index as u64),
                        Fp::new(401 + case_index as u64),
                    ),
                    point,
                    value,
                }
            })
            .collect();
        let plan = LogupBatchPlan::new(cases.iter().map(|case| case.site).collect()).unwrap();
        let make_cpu_jobs = |stream: &mut CorrelationStream| {
            cases
                .iter()
                .enumerate()
                .map(|(index, case)| {
                    let corr = stream.draw_fulls(0x200 + index as u64, 1)[0];
                    CpuLogupBatchJob {
                        site: case.site.id,
                        columns: case.columns.clone(),
                        shifts: case.shifts.clone(),
                        alpha: case.alpha,
                        aux_claims: vec![LeafAuxClaim {
                            col: 1,
                            point: case.point.clone(),
                            value: ProverAuthed { x: case.value, m: corr.m },
                        }],
                    }
                })
                .collect::<Vec<_>>()
        };

        let mut cpu_stream = CorrelationStream::new([61; 32]);
        let mut cpu_tx = Transcript::new([62; 32]);
        let mut cpu_ctr = Counters::default();
        let mut cpu_prod = Vec::new();
        let mut cpu_zero = Vec::new();
        let cpu = blind_instance_prove_batch_cpu(
            &plan,
            make_cpu_jobs(&mut cpu_stream),
            &mut cpu_stream,
            &mut cpu_tx,
            &mut cpu_ctr,
            &mut cpu_prod,
            &mut cpu_zero,
        )
        .unwrap();

        let baseline_memory = resident.device_memory_breakdown().unwrap();
        let max_pairs = cases
            .iter()
            .filter_map(|case| {
                let entries = 1usize << case.site.depth;
                (entries >= 4).then_some(entries / 4)
            })
            .max()
            .unwrap();
        resident.reserve_logup_round_workspace(max_pairs).unwrap();
        let prewarmed_memory = resident.device_memory_breakdown().unwrap();
        assert!(prewarmed_memory.workspace_bytes > baseline_memory.workspace_bytes);
        let mut sources = Vec::new();
        for case in &cases {
            let raw: Vec<u64> = case
                .columns
                .iter()
                .flat_map(|column| column.iter().map(|value| value.value()))
                .collect();
            sources.push(resident.upload_new_device(&raw).unwrap());
        }
        let sources_memory = resident.device_memory_breakdown().unwrap();
        let mut gpu_stream = CorrelationStream::new([61; 32]);
        let mut resident_jobs = Vec::new();
        for (index, (case, source)) in cases.iter().zip(&sources).enumerate() {
            let corr = gpu_stream.draw_fulls(0x200 + index as u64, 1)[0];
            resident_jobs.push(ResidentLogupBatchJob {
                site: case.site.id,
                columns: DeviceSlice::new(source, 0, source.len()).unwrap(),
                column_count: case.site.column_count,
                entries: 1usize << case.site.depth,
                shifts: case.shifts.clone(),
                alpha: case.alpha,
                aux_claims: vec![LeafAuxClaim {
                    col: 1,
                    point: case.point.clone(),
                    value: ProverAuthed { x: case.value, m: corr.m },
                }],
            });
        }
        resident_jobs.reverse();
        resident.begin_measurement().unwrap();
        let mut gpu_tx = Transcript::new([62; 32]);
        let mut gpu_ctr = Counters::default();
        let mut gpu_prod = Vec::new();
        let mut gpu_zero = Vec::new();
        let gpu = blind_instance_prove_resident_batch(
            &plan,
            resident_jobs,
            &mut gpu_stream,
            &mut gpu_tx,
            &mut gpu_ctr,
            &mut gpu_prod,
            &mut gpu_zero,
            &mut resident,
        )
        .unwrap();
        assert_eq!(gpu.len(), cpu.len());
        for (expected, got) in cpu.iter().zip(&gpu) {
            assert_eq!(got.site, expected.site);
            assert_eq!(got.output.proof, expected.output.proof);
            assert_eq!(got.output.alpha, expected.output.alpha);
            assert_eq!(got.output.point, expected.output.point);
            assert_eq!(got.output.roots, expected.output.roots);
            assert_eq!(got.output.col_claims.len(), expected.output.col_claims.len());
            for (got, expected) in got.output.col_claims.iter().zip(&expected.output.col_claims) {
                assert_eq!(got.point, expected.point);
                assert_eq!(got.value, expected.value);
            }
        }
        assert_eq!(gpu_prod, cpu_prod);
        assert_eq!(gpu_zero, cpu_zero);
        assert_eq!(gpu_ctr, cpu_ctr);
        assert_eq!(gpu_stream.counters, cpu_stream.counters);
        assert_eq!(gpu_tx.ledger(), cpu_tx.ledger());
        assert_eq!(
            resident.device_memory_breakdown().unwrap().resident_bytes,
            sources_memory.resident_bytes
        );
        let stats = resident.finish_measurement().unwrap();
        assert_eq!(stats.sync_host_output, plan.schedule().epochs().len() as u64);
        assert_eq!(stats.d2h_bytes, plan.schedule().round_d2h_bytes());
        let round_epochs = plan
            .schedule()
            .epochs()
            .iter()
            .filter(|epoch| {
                epoch.sites.first().is_some_and(|site| {
                    matches!(site.family, RoundFamily::LogupGeneral | RoundFamily::LogupAux)
                })
            })
            .count();
        assert_eq!(
            stats.coarse_timing_scopes,
            (plan.schedule().epochs().len() + round_epochs) as u64
        );
        assert_eq!(stats.sync_timing_flush, 0, "hidden timing-only barrier inside cohort");
        assert!(stats.timing_pending_high_water < LOGUP_BATCH_TIMING_RING_CAPACITY as u64);
        assert!(stats.h2d_bytes <= 100 * 1024 * 1024);
        assert_eq!(stats.operation(Operation::Logup).cpu_residual_ns, 0);
        for source in sources {
            resident.free_device(source).unwrap();
        }
        // Context-private primitive scratch and the inactive resident arena
        // are intentionally cached; no active cohort/source buffer survives.
        let final_memory = resident.device_memory_breakdown().unwrap();
        assert_eq!(final_memory.resident_bytes, baseline_memory.resident_bytes);
        assert!(final_memory.workspace_bytes >= prewarmed_memory.workspace_bytes);
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn resident_preflight_rejects_foreign_context_without_mutation() {
        let (mut owner, mut other) = match (Backend::cuda_resident(), Backend::cuda_resident()) {
            (Ok(owner), Ok(other)) => (owner, other),
            (Err(error), _) | (_, Err(error))
                if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") =>
            {
                eprintln!("skipping foreign-context LogUp preflight: {error}");
                return;
            }
            (Err(error), _) | (_, Err(error)) => panic!("CUDA required: {error}"),
        };
        let site0 = LogupBatchSite {
            id: SiteId::new(12, RoundFamily::LogupAux, 0),
            depth: 2,
            column_count: 1,
            aux_claim_count: 0,
            mask_dom_base: 0xd000,
        };
        let site1 = LogupBatchSite {
            id: SiteId::new(12, RoundFamily::LogupAux, 1),
            mask_dom_base: 0xe000,
            ..site0
        };
        let plan = LogupBatchPlan::new(vec![site0, site1]).unwrap();
        let sources = [
            owner.upload_new_device(&[1u64, 2, 3, 4]).unwrap(),
            owner.upload_new_device(&[5u64, 6, 7, 8]).unwrap(),
        ];
        let jobs = [site0, site1]
            .into_iter()
            .zip(&sources)
            .map(|(site, source)| ResidentLogupBatchJob {
                site: site.id,
                columns: DeviceSlice::new(source, 0, 4).unwrap(),
                column_count: 1,
                entries: 4,
                shifts: vec![Some(0)],
                alpha: Fp2::new(Fp::new(3), Fp::new(7)),
                aux_claims: Vec::new(),
            })
            .collect();
        let before_backend = other.stats().unwrap();
        let mut stream = CorrelationStream::new([81; 32]);
        let before_corr = stream.counters;
        let mut tx = Transcript::new([82; 32]);
        let mut ctr = Counters::default();
        let mut prod = Vec::new();
        let mut zero = Vec::new();
        let result = blind_instance_prove_resident_batch(
            &plan,
            jobs,
            &mut stream,
            &mut tx,
            &mut ctr,
            &mut prod,
            &mut zero,
            &mut other,
        );
        assert!(matches!(result, Err(LogupBatchError::Accel(AccelError::InvalidInput(_)))));
        assert_eq!(other.stats().unwrap(), before_backend);
        assert_eq!(stream.counters, before_corr);
        assert_eq!(tx.total_bytes(), 0);
        assert_eq!(ctr, Counters::default());
        assert!(prod.is_empty() && zero.is_empty());
        for source in sources {
            owner.free_device(source).unwrap();
        }
    }
}
