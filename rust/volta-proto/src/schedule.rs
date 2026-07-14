//! Public, versioned schedule identifiers for P7b round-synchronous cohorts.
//!
//! The schedule is protocol metadata: both parties construct the same plan
//! from public model/phase geometry, seal it before the first cohort message,
//! and reject missing, extra, duplicate, or shape-mismatched jobs.  Runtime
//! completion order is never an input to challenge assignment.

use std::fmt;

pub const SCHEDULE_VERSION: u8 = 1;
/// Correlation domains reserve the top three bits for the MAC stream's
/// full-field, tag, and ledger-shadow namespaces. Public schedules must stay
/// entirely below this boundary.
pub const CORRELATION_DOMAIN_LIMIT: u64 = 1 << 61;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RoundFamily {
    BlindProduct = 1,
    HadamardTriple = 2,
    LogupGeneral = 3,
    LogupAux = 4,
    LogupRoot = 5,
    LogupSplit = 6,
}

impl RoundFamily {
    pub const fn message_width(self) -> usize {
        match self {
            RoundFamily::BlindProduct => 2,
            RoundFamily::HadamardTriple | RoundFamily::LogupAux => 3,
            RoundFamily::LogupGeneral | RoundFamily::LogupSplit => 4,
            RoundFamily::LogupRoot => 2,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::BlindProduct),
            2 => Some(Self::HadamardTriple),
            3 => Some(Self::LogupGeneral),
            4 => Some(Self::LogupAux),
            5 => Some(Self::LogupRoot),
            6 => Some(Self::LogupSplit),
            _ => None,
        }
    }
}

/// Canonical 64-bit identity: version | section | family | lane.
///
/// `section` names a public proof phase (prefill layer block, decode band,
/// table close, ...); `lane` is the public index within that section.  The
/// family is encoded into the identity so a product job cannot be silently
/// substituted for a degree-3 or LogUp job at the same lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SiteId(u64);

impl SiteId {
    pub fn new(section: u16, family: RoundFamily, lane: u32) -> Self {
        Self(
            (u64::from(SCHEDULE_VERSION) << 56)
                | (u64::from(section) << 40)
                | (u64::from(family as u8) << 32)
                | u64::from(lane),
        )
    }

    pub const fn packed(self) -> u64 {
        self.0
    }

    pub const fn version(self) -> u8 {
        (self.0 >> 56) as u8
    }

    pub const fn section(self) -> u16 {
        ((self.0 >> 40) & 0xffff) as u16
    }

    pub fn family(self) -> Option<RoundFamily> {
        RoundFamily::from_u8(((self.0 >> 32) & 0xff) as u8)
    }

    pub const fn lane(self) -> u32 {
        self.0 as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleSite {
    pub id: SiteId,
    /// Number of interactive round messages emitted by this job.  Zero-round
    /// boundary records use their dedicated family and remain explicit.
    pub rounds: usize,
    /// First one-time correlation domain used by this job's round messages.
    pub mask_dom_base: u64,
    /// Exact number of consecutive one-time domains owned by this site.
    ///
    /// Product/Hadamard round jobs use `rounds`. Protocols with root, split,
    /// product, or auxiliary masks (notably LogUp) must seal their full,
    /// nonlinear span here rather than deriving it from `rounds`.
    pub mask_dom_span: u64,
}

/// Protocol role of a consecutive sub-range inside a site's sealed
/// correlation allocation. This keeps nonlinear protocols auditable: a
/// LogUp product mask cannot silently be consumed as an aux-column mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrelationScope {
    Round,
    LogupRoot,
    LogupGeneralRound,
    LogupAuxRound,
    LogupSplit,
    LogupProduct,
    LogupAuxColumn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelationSegment {
    /// Offset from the owning [`ScheduleSite::mask_dom_base`].
    pub offset: u64,
    pub span: u64,
    pub scope: CorrelationScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteCorrPlan {
    pub site: SiteId,
    /// Ordered, gap-free partition of the site's exact correlation span.
    pub segments: Vec<CorrelationSegment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochSite {
    /// Logical job identity. Its encoded family names the whole job; `family`
    /// below names this particular protocol stage.
    pub id: SiteId,
    pub family: RoundFamily,
    pub mailbox_offset: usize,
    pub message_width: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochLayout {
    pub round: usize,
    pub sites: Vec<EpochSite>,
    pub mailbox_elements: usize,
}

/// Protocol-specific stage entry used when a logical job changes message
/// family or width over its lifetime (LogUp root/general/aux/split).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedEpochSite {
    pub id: SiteId,
    pub family: RoundFamily,
    pub message_width: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedEpoch {
    pub sites: Vec<StagedEpochSite>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulePlan {
    sites: Vec<ScheduleSite>,
    correlations: Vec<SiteCorrPlan>,
    epochs: Vec<EpochLayout>,
    round_d2h_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    WrongVersion(SiteId),
    UnknownFamily(SiteId),
    DuplicateSite(SiteId),
    EmptyRoundJob(SiteId),
    InvalidJobShape(SiteId),
    EmptyCorrelationRange(SiteId),
    CorrelationRangeOverflow(SiteId),
    ReservedCorrelationDomainBits(SiteId),
    CorrelationRangeOverlap { first: SiteId, second: SiteId },
    CorrelationScopeMembershipMismatch,
    InvalidCorrelationScope(SiteId),
    EpochMembershipMismatch,
    DuplicateEpochSite(SiteId),
    InvalidEpochMessageWidth(SiteId),
    InvalidEpochFamily { site: SiteId, family: RoundFamily },
    EmptyEpoch(usize),
    NonContiguousEpochSite(SiteId),
    EpochRoundCountMismatch(SiteId),
    EpochCorrelationScopeMismatch(SiteId),
    MailboxSizeOverflow,
    RoundD2hOverflow,
    MembershipMismatch { family: RoundFamily },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScheduleError::WrongVersion(id) => {
                write!(f, "schedule site {:#x} has unsupported version", id.packed())
            }
            ScheduleError::UnknownFamily(id) => {
                write!(f, "schedule site {:#x} has an unknown family", id.packed())
            }
            ScheduleError::DuplicateSite(id) => {
                write!(f, "schedule site {:#x} is duplicated", id.packed())
            }
            ScheduleError::EmptyRoundJob(id) => {
                write!(f, "round schedule site {:#x} has zero rounds", id.packed())
            }
            ScheduleError::InvalidJobShape(id) => {
                write!(f, "schedule site {:#x} has invalid private job geometry", id.packed())
            }
            ScheduleError::EmptyCorrelationRange(id) => {
                write!(f, "schedule site {:#x} owns no correlation domains", id.packed())
            }
            ScheduleError::CorrelationRangeOverflow(id) => {
                write!(f, "schedule site {:#x} correlation range overflows", id.packed())
            }
            ScheduleError::ReservedCorrelationDomainBits(id) => write!(
                f,
                "schedule site {:#x} correlation range enters reserved domain bits",
                id.packed()
            ),
            ScheduleError::CorrelationRangeOverlap { first, second } => write!(
                f,
                "schedule sites {:#x} and {:#x} own overlapping correlation ranges",
                first.packed(),
                second.packed()
            ),
            ScheduleError::CorrelationScopeMembershipMismatch => {
                write!(f, "correlation-scope membership does not match schedule sites")
            }
            ScheduleError::InvalidCorrelationScope(id) => write!(
                f,
                "schedule site {:#x} has a gapped, overlapping, or out-of-range correlation scope",
                id.packed()
            ),
            ScheduleError::EpochMembershipMismatch => {
                write!(f, "staged epoch references a site outside the sealed schedule")
            }
            ScheduleError::DuplicateEpochSite(id) => {
                write!(f, "staged epoch duplicates site {:#x}", id.packed())
            }
            ScheduleError::InvalidEpochMessageWidth(id) => {
                write!(f, "staged epoch has an invalid message width for site {:#x}", id.packed())
            }
            ScheduleError::InvalidEpochFamily { site, family } => write!(
                f,
                "staged epoch family {family:?} is invalid for logical site {:#x}",
                site.packed()
            ),
            ScheduleError::EmptyEpoch(round) => {
                write!(f, "staged schedule epoch {round} is empty")
            }
            ScheduleError::NonContiguousEpochSite(id) => write!(
                f,
                "staged schedule site {:#x} disappeared and later reappeared",
                id.packed()
            ),
            ScheduleError::EpochRoundCountMismatch(id) => write!(
                f,
                "staged epoch count does not match registered rounds for site {:#x}",
                id.packed()
            ),
            ScheduleError::EpochCorrelationScopeMismatch(id) => write!(
                f,
                "staged epoch sequence and correlation scopes differ for site {:#x}",
                id.packed()
            ),
            ScheduleError::MailboxSizeOverflow => write!(f, "schedule mailbox size overflows"),
            ScheduleError::RoundD2hOverflow => {
                write!(f, "schedule round-message D2H accounting overflows")
            }
            ScheduleError::MembershipMismatch { family } => {
                write!(f, "sealed schedule membership mismatch for {family:?}")
            }
        }
    }
}

impl std::error::Error for ScheduleError {}

impl SchedulePlan {
    /// Construct a round-only plan. Product/Hadamard callers must register
    /// `mask_dom_span == rounds`; nonlinear protocols use [`Self::new_scoped`].
    pub fn new(sites: Vec<ScheduleSite>) -> Result<Self, ScheduleError> {
        if let Some(site) = sites.iter().find(|site| site.mask_dom_span != site.rounds as u64) {
            return Err(ScheduleError::InvalidJobShape(site.id));
        }
        let correlations = sites
            .iter()
            .map(|site| SiteCorrPlan {
                site: site.id,
                segments: vec![CorrelationSegment {
                    offset: 0,
                    span: site.mask_dom_span,
                    scope: CorrelationScope::Round,
                }],
            })
            .collect();
        Self::new_scoped(sites, correlations)
    }

    /// Construct a plan with an exact role partition for every site's domain
    /// range. Segments must be ordered, non-empty, gap-free, and cover the
    /// registered span exactly.
    pub fn new_scoped(
        sites: Vec<ScheduleSite>,
        correlations: Vec<SiteCorrPlan>,
    ) -> Result<Self, ScheduleError> {
        let max_rounds = sites.iter().map(|site| site.rounds).max().unwrap_or(0);
        let mut epochs: Vec<StagedEpoch> = Vec::with_capacity(max_rounds);
        for round in 0..max_rounds {
            let epoch_sites: Vec<_> = sites
                .iter()
                .filter(|site| round < site.rounds)
                .map(|site| {
                    let family = site.id.family().ok_or(ScheduleError::UnknownFamily(site.id))?;
                    Ok(StagedEpochSite {
                        id: site.id,
                        family,
                        message_width: family.message_width(),
                    })
                })
                .collect::<Result<_, _>>()?;
            epochs.push(StagedEpoch { sites: epoch_sites });
        }
        Self::new_staged(sites, correlations, epochs)
    }

    /// Construct an exact stage-varying schedule. Dynamic widths are allowed
    /// above the family's canonical minimum (for example an aux LogUp split
    /// carries two q scalars plus two scalars per column).
    pub fn new_staged(
        mut sites: Vec<ScheduleSite>,
        mut correlations: Vec<SiteCorrPlan>,
        epochs: Vec<StagedEpoch>,
    ) -> Result<Self, ScheduleError> {
        sites.sort_by_key(|site| site.id);
        for site in &sites {
            if site.id.version() != SCHEDULE_VERSION {
                return Err(ScheduleError::WrongVersion(site.id));
            }
            if site.id.family().is_none() {
                return Err(ScheduleError::UnknownFamily(site.id));
            }
            if site.rounds == 0 {
                return Err(ScheduleError::EmptyRoundJob(site.id));
            }
        }
        if let Some(pair) = sites.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(ScheduleError::DuplicateSite(pair[0].id));
        }

        let mut ranges = Vec::with_capacity(sites.len());
        for site in &sites {
            if site.mask_dom_span == 0 {
                return Err(ScheduleError::EmptyCorrelationRange(site.id));
            }
            let end = site
                .mask_dom_base
                .checked_add(site.mask_dom_span)
                .ok_or(ScheduleError::CorrelationRangeOverflow(site.id))?;
            if site.mask_dom_base >= CORRELATION_DOMAIN_LIMIT || end > CORRELATION_DOMAIN_LIMIT {
                return Err(ScheduleError::ReservedCorrelationDomainBits(site.id));
            }
            ranges.push((site.mask_dom_base, end, site.id));
        }
        ranges.sort_by_key(|&(base, _, id)| (base, id));
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(ScheduleError::CorrelationRangeOverlap {
                    first: pair[0].2,
                    second: pair[1].2,
                });
            }
        }

        correlations.sort_by_key(|plan| plan.site);
        if correlations.len() != sites.len()
            || correlations.iter().zip(&sites).any(|(corr, site)| corr.site != site.id)
        {
            return Err(ScheduleError::CorrelationScopeMembershipMismatch);
        }
        for (corr, site) in correlations.iter().zip(&sites) {
            let mut next = 0u64;
            if corr.segments.is_empty() {
                return Err(ScheduleError::InvalidCorrelationScope(site.id));
            }
            for segment in &corr.segments {
                if segment.span == 0 || segment.offset != next {
                    return Err(ScheduleError::InvalidCorrelationScope(site.id));
                }
                next = next
                    .checked_add(segment.span)
                    .ok_or(ScheduleError::InvalidCorrelationScope(site.id))?;
                if next > site.mask_dom_span {
                    return Err(ScheduleError::InvalidCorrelationScope(site.id));
                }
            }
            if next != site.mask_dom_span {
                return Err(ScheduleError::InvalidCorrelationScope(site.id));
            }
        }

        let mut last_epoch = vec![None; sites.len()];
        for (round, epoch) in epochs.iter().enumerate() {
            if epoch.sites.is_empty() {
                return Err(ScheduleError::EmptyEpoch(round));
            }
            for staged_site in &epoch.sites {
                let index = sites
                    .binary_search_by_key(&staged_site.id, |site| site.id)
                    .map_err(|_| ScheduleError::EpochMembershipMismatch)?;
                last_epoch[index] = Some(round);
            }
        }
        let mut epoch_layouts = Vec::with_capacity(epochs.len());
        let mut observed_rounds = vec![0usize; sites.len()];
        let mut prior_epoch: Vec<Option<usize>> = vec![None; sites.len()];
        for (round, staged) in epochs.into_iter().enumerate() {
            let mut offset = 0usize;
            let mut staged_sites = staged.sites;
            staged_sites.sort_by_key(|site| site.id);
            if let Some(pair) = staged_sites.windows(2).find(|pair| pair[0].id == pair[1].id) {
                return Err(ScheduleError::DuplicateEpochSite(pair[0].id));
            }
            let mut active = Vec::with_capacity(staged_sites.len());
            for staged_site in staged_sites {
                let index = sites
                    .binary_search_by_key(&staged_site.id, |site| site.id)
                    .map_err(|_| ScheduleError::EpochMembershipMismatch)?;
                if prior_epoch[index].is_some_and(|prior| prior.checked_add(1) != Some(round))
                    || prior_epoch[index].is_none() && round != 0
                {
                    return Err(ScheduleError::NonContiguousEpochSite(staged_site.id));
                }
                prior_epoch[index] = Some(round);
                let logical_family = sites[index]
                    .id
                    .family()
                    .ok_or(ScheduleError::UnknownFamily(sites[index].id))?;
                let family_allowed = if logical_family == RoundFamily::LogupAux {
                    matches!(
                        staged_site.family,
                        RoundFamily::LogupRoot
                            | RoundFamily::LogupGeneral
                            | RoundFamily::LogupAux
                            | RoundFamily::LogupSplit
                    )
                } else {
                    staged_site.family == logical_family
                };
                if !family_allowed {
                    return Err(ScheduleError::InvalidEpochFamily {
                        site: staged_site.id,
                        family: staged_site.family,
                    });
                }
                let dynamic_final_split = logical_family == RoundFamily::LogupAux
                    && staged_site.family == RoundFamily::LogupSplit
                    && last_epoch[index] == Some(round);
                let width_valid = if dynamic_final_split {
                    // The four logical split values include public p0=p1=1
                    // for lookup-side leaves.  Resident mailboxes carry only
                    // private q0/q1 plus two scalars per auxiliary column,
                    // so one-column sites legitimately use raw width four.
                    staged_site.message_width >= RoundFamily::LogupSplit.message_width()
                        && staged_site.message_width % 2 == 0
                } else {
                    staged_site.message_width == staged_site.family.message_width()
                };
                if !width_valid {
                    return Err(ScheduleError::InvalidEpochMessageWidth(staged_site.id));
                }
                observed_rounds[index] = observed_rounds[index]
                    .checked_add(1)
                    .ok_or(ScheduleError::MailboxSizeOverflow)?;
                active.push(EpochSite {
                    id: staged_site.id,
                    family: staged_site.family,
                    mailbox_offset: offset,
                    message_width: staged_site.message_width,
                });
                offset = offset
                    .checked_add(staged_site.message_width)
                    .ok_or(ScheduleError::MailboxSizeOverflow)?;
            }
            epoch_layouts.push(EpochLayout { round, sites: active, mailbox_elements: offset });
        }
        for (site, observed) in sites.iter().zip(observed_rounds) {
            if site.rounds != observed {
                return Err(ScheduleError::EpochRoundCountMismatch(site.id));
            }
        }
        for (index, site) in sites.iter().enumerate() {
            let logical_family = site.id.family().ok_or(ScheduleError::UnknownFamily(site.id))?;
            let mut scopes = Vec::<CorrelationScope>::new();
            for epoch in &epoch_layouts {
                let Some(stage) = epoch.sites.iter().find(|stage| stage.id == site.id) else {
                    continue;
                };
                match (logical_family, stage.family) {
                    (RoundFamily::BlindProduct | RoundFamily::HadamardTriple, _) => {
                        scopes.push(CorrelationScope::Round);
                    }
                    (RoundFamily::LogupAux, RoundFamily::LogupRoot) => {
                        scopes.push(CorrelationScope::LogupRoot);
                    }
                    (RoundFamily::LogupAux, RoundFamily::LogupGeneral) => {
                        scopes.push(CorrelationScope::LogupGeneralRound);
                    }
                    (RoundFamily::LogupAux, RoundFamily::LogupAux) => {
                        scopes.push(CorrelationScope::LogupAuxRound);
                    }
                    (RoundFamily::LogupAux, RoundFamily::LogupSplit) => {
                        scopes.push(CorrelationScope::LogupSplit);
                        scopes.push(CorrelationScope::LogupProduct);
                        if Some(epoch.round) == last_epoch[index] {
                            scopes.push(CorrelationScope::LogupAuxColumn);
                        }
                    }
                    _ => scopes.push(CorrelationScope::Round),
                }
            }
            let mut expected = Vec::<CorrelationSegment>::new();
            let mut offset = 0u64;
            for scope in scopes {
                if let Some(last) = expected.last_mut().filter(|segment| segment.scope == scope) {
                    last.span = last
                        .span
                        .checked_add(1)
                        .ok_or(ScheduleError::InvalidCorrelationScope(site.id))?;
                } else {
                    expected.push(CorrelationSegment { offset, span: 1, scope });
                }
                offset =
                    offset.checked_add(1).ok_or(ScheduleError::InvalidCorrelationScope(site.id))?;
            }
            // Recompute offsets after coalescing adjacent equal roles.
            let mut offset = 0u64;
            for segment in &mut expected {
                segment.offset = offset;
                offset = offset
                    .checked_add(segment.span)
                    .ok_or(ScheduleError::InvalidCorrelationScope(site.id))?;
            }
            if correlations[index].segments != expected {
                return Err(ScheduleError::EpochCorrelationScopeMismatch(site.id));
            }
        }
        let round_d2h_bytes = epoch_layouts.iter().try_fold(0u64, |total, epoch| {
            let elements = u64::try_from(epoch.mailbox_elements)
                .map_err(|_| ScheduleError::RoundD2hOverflow)?;
            let bytes = elements.checked_mul(16).ok_or(ScheduleError::RoundD2hOverflow)?;
            total.checked_add(bytes).ok_or(ScheduleError::RoundD2hOverflow)
        })?;
        Ok(Self { sites, correlations, epochs: epoch_layouts, round_d2h_bytes })
    }

    pub fn sites(&self) -> &[ScheduleSite] {
        &self.sites
    }

    pub fn family_sites(&self, family: RoundFamily) -> impl Iterator<Item = ScheduleSite> + '_ {
        self.sites.iter().copied().filter(move |site| site.id.family() == Some(family))
    }

    pub fn correlations(&self) -> &[SiteCorrPlan] {
        &self.correlations
    }

    pub fn epochs(&self) -> &[EpochLayout] {
        &self.epochs
    }

    /// Exact sealed-membership check. `actual` may arrive in any order; the
    /// comparison is canonical and includes each job's public round count.
    pub fn validate_family(
        &self,
        family: RoundFamily,
        actual: impl IntoIterator<Item = ScheduleSite>,
    ) -> Result<(), ScheduleError> {
        let expected: Vec<_> = self.family_sites(family).collect();
        let mut actual: Vec<_> = actual.into_iter().collect();
        actual.sort_by_key(|site| site.id);
        if actual != expected {
            return Err(ScheduleError::MembershipMismatch { family });
        }
        Ok(())
    }

    pub fn round_epoch_upper_bound(&self) -> usize {
        self.epochs.len()
    }

    pub fn mailbox_elements_upper_bound(&self) -> usize {
        self.epochs.iter().map(|epoch| epoch.mailbox_elements).max().unwrap_or(0)
    }

    pub fn round_d2h_bytes(&self) -> u64 {
        // Raw GPU mailbox traffic, not serialized proof bytes. In particular,
        // a general LogUp round contributes four raw accumulators although
        // only two masked corrections enter `BlindFracProof`.
        self.round_d2h_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_canonical_and_checks_exact_membership() {
        let a = ScheduleSite {
            id: SiteId::new(7, RoundFamily::BlindProduct, 3),
            rounds: 12,
            mask_dom_base: 0x7000,
            mask_dom_span: 12,
        };
        let b = ScheduleSite {
            id: SiteId::new(7, RoundFamily::HadamardTriple, 1),
            rounds: 9,
            mask_dom_base: 0x7100,
            mask_dom_span: 9,
        };
        let c = ScheduleSite {
            id: SiteId::new(2, RoundFamily::BlindProduct, 8),
            rounds: 4,
            mask_dom_base: 0x7200,
            mask_dom_span: 4,
        };
        let plan = SchedulePlan::new(vec![a, b, c]).unwrap();
        assert_eq!(plan.round_epoch_upper_bound(), 12);
        assert_eq!(plan.mailbox_elements_upper_bound(), 7);
        assert_eq!(plan.round_d2h_bytes(), 944);
        assert_eq!(plan.epochs()[0].sites[0].mailbox_offset, 0);
        plan.validate_family(RoundFamily::BlindProduct, [a, c]).unwrap();
        assert_eq!(
            plan.validate_family(RoundFamily::BlindProduct, [a]),
            Err(ScheduleError::MembershipMismatch { family: RoundFamily::BlindProduct })
        );
        assert_eq!(SchedulePlan::new(vec![a, a]), Err(ScheduleError::DuplicateSite(a.id)));
    }

    #[test]
    fn plan_rejects_overlapping_and_reserved_correlation_ranges() {
        let a = ScheduleSite {
            id: SiteId::new(1, RoundFamily::BlindProduct, 0),
            rounds: 4,
            mask_dom_base: 100,
            mask_dom_span: 4,
        };
        let b = ScheduleSite {
            id: SiteId::new(1, RoundFamily::BlindProduct, 1),
            rounds: 2,
            mask_dom_base: 103,
            mask_dom_span: 2,
        };
        assert_eq!(
            SchedulePlan::new(vec![a, b]),
            Err(ScheduleError::CorrelationRangeOverlap { first: a.id, second: b.id })
        );
        let reserved = ScheduleSite {
            rounds: 2,
            mask_dom_base: CORRELATION_DOMAIN_LIMIT - 1,
            mask_dom_span: 2,
            ..a
        };
        assert_eq!(
            SchedulePlan::new(vec![reserved]),
            Err(ScheduleError::ReservedCorrelationDomainBits(reserved.id))
        );
    }

    fn one_logup_staged(width: usize) -> Result<SchedulePlan, ScheduleError> {
        let id = SiteId::new(3, RoundFamily::LogupAux, 0);
        SchedulePlan::new_staged(
            vec![ScheduleSite { id, rounds: 2, mask_dom_base: 0x3000, mask_dom_span: 4 }],
            vec![SiteCorrPlan {
                site: id,
                segments: vec![
                    CorrelationSegment { offset: 0, span: 1, scope: CorrelationScope::LogupRoot },
                    CorrelationSegment { offset: 1, span: 1, scope: CorrelationScope::LogupSplit },
                    CorrelationSegment {
                        offset: 2,
                        span: 1,
                        scope: CorrelationScope::LogupProduct,
                    },
                    CorrelationSegment {
                        offset: 3,
                        span: 1,
                        scope: CorrelationScope::LogupAuxColumn,
                    },
                ],
            }],
            vec![
                StagedEpoch {
                    sites: vec![StagedEpochSite {
                        id,
                        family: RoundFamily::LogupRoot,
                        message_width: 2,
                    }],
                },
                StagedEpoch {
                    sites: vec![StagedEpochSite {
                        id,
                        family: RoundFamily::LogupSplit,
                        message_width: width,
                    }],
                },
            ],
        )
    }

    #[test]
    fn staged_plan_rejects_wrong_family_and_inflated_fixed_width() {
        let id = SiteId::new(6, RoundFamily::BlindProduct, 0);
        let site = ScheduleSite { id, rounds: 1, mask_dom_base: 0x6000, mask_dom_span: 1 };
        let corr = SiteCorrPlan {
            site: id,
            segments: vec![CorrelationSegment {
                offset: 0,
                span: 1,
                scope: CorrelationScope::Round,
            }],
        };
        let epoch = |family, width| StagedEpoch {
            sites: vec![StagedEpochSite { id, family, message_width: width }],
        };
        assert_eq!(
            SchedulePlan::new_staged(
                vec![site],
                vec![corr.clone()],
                vec![epoch(RoundFamily::HadamardTriple, 3)]
            ),
            Err(ScheduleError::InvalidEpochFamily {
                site: id,
                family: RoundFamily::HadamardTriple
            })
        );
        assert_eq!(
            SchedulePlan::new_staged(
                vec![site],
                vec![corr],
                vec![epoch(RoundFamily::BlindProduct, 3)]
            ),
            Err(ScheduleError::InvalidEpochMessageWidth(id))
        );
    }

    #[test]
    fn staged_logup_final_split_accepts_one_column_raw_mailbox() {
        assert!(one_logup_staged(4).is_ok());
        assert_eq!(
            one_logup_staged(2),
            Err(ScheduleError::InvalidEpochMessageWidth(SiteId::new(3, RoundFamily::LogupAux, 0,)))
        );
        assert_eq!(
            one_logup_staged(5),
            Err(ScheduleError::InvalidEpochMessageWidth(SiteId::new(3, RoundFamily::LogupAux, 0,)))
        );
    }

    #[test]
    fn staged_plan_rejects_empty_and_refilled_epochs() {
        let id0 = SiteId::new(8, RoundFamily::BlindProduct, 0);
        let id1 = SiteId::new(8, RoundFamily::BlindProduct, 1);
        let sites = [
            ScheduleSite { id: id0, rounds: 2, mask_dom_base: 0x8000, mask_dom_span: 2 },
            ScheduleSite { id: id1, rounds: 3, mask_dom_base: 0x8100, mask_dom_span: 3 },
        ];
        let corr = |site: ScheduleSite| SiteCorrPlan {
            site: site.id,
            segments: vec![CorrelationSegment {
                offset: 0,
                span: site.mask_dom_span,
                scope: CorrelationScope::Round,
            }],
        };
        assert_eq!(
            SchedulePlan::new_staged(
                vec![sites[0]],
                vec![corr(sites[0])],
                vec![StagedEpoch { sites: Vec::new() }]
            ),
            Err(ScheduleError::EmptyEpoch(0))
        );
        let stage =
            |id| StagedEpochSite { id, family: RoundFamily::BlindProduct, message_width: 2 };
        assert_eq!(
            SchedulePlan::new_staged(
                sites.to_vec(),
                sites.iter().copied().map(corr).collect(),
                vec![
                    StagedEpoch { sites: vec![stage(id0), stage(id1)] },
                    StagedEpoch { sites: vec![stage(id1)] },
                    StagedEpoch { sites: vec![stage(id0), stage(id1)] },
                ]
            ),
            Err(ScheduleError::NonContiguousEpochSite(id0))
        );
    }

    #[test]
    fn staged_plan_checks_scope_binding_and_d2h_overflow() {
        let id = SiteId::new(3, RoundFamily::LogupAux, 0);
        let mut wrong = vec![
            CorrelationSegment { offset: 0, span: 1, scope: CorrelationScope::LogupRoot },
            CorrelationSegment { offset: 1, span: 1, scope: CorrelationScope::LogupProduct },
            CorrelationSegment { offset: 2, span: 1, scope: CorrelationScope::LogupSplit },
            CorrelationSegment { offset: 3, span: 1, scope: CorrelationScope::LogupAuxColumn },
        ];
        let base = one_logup_staged(6).unwrap();
        let epochs: Vec<_> = base
            .epochs()
            .iter()
            .map(|epoch| StagedEpoch {
                sites: epoch
                    .sites
                    .iter()
                    .map(|site| StagedEpochSite {
                        id: site.id,
                        family: site.family,
                        message_width: site.message_width,
                    })
                    .collect(),
            })
            .collect();
        assert_eq!(
            SchedulePlan::new_staged(
                vec![ScheduleSite { id, rounds: 2, mask_dom_base: 0x3000, mask_dom_span: 4 }],
                vec![SiteCorrPlan { site: id, segments: std::mem::take(&mut wrong) }],
                epochs,
            ),
            Err(ScheduleError::EpochCorrelationScopeMismatch(id))
        );
        if usize::BITS == 64 {
            assert_eq!(one_logup_staged(usize::MAX - 1), Err(ScheduleError::RoundD2hOverflow));
        }
    }
}
