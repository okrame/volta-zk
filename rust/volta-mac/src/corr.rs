//! Mock-PCG correlation streams (P0 decision 4): both parties expand the same
//! ChaCha seed deterministically; `Δ` exists only in `VerifierCtx`. Every
//! consumption is counted, indices are domain-separated and one-time-use
//! (M4/M6 discipline: a domain drawn twice is a protocol bug, so it panics).
//!
//! Stream layout for a base domain `dom` (top two bits of `dom` reserved):
//! * subfield correlations (M5): mask `r ∈ F_p` from `stream(dom).next_fp()`
//!   — byte-compatible with the P1 GEMM epilogue — and tag `m_r ∈ E` from
//!   `stream(dom | TAG_BIT).next_fp2()`;
//! * full-field correlations (masks for ZeroBatch / round coefficients):
//!   value `x ∈ E` from `stream(dom | FULL_BIT).next_fp2()`, tag from
//!   `stream(dom | FULL_BIT | TAG_BIT).next_fp2()`.

use std::collections::HashMap;
use volta_field::{Fp, Fp2, FpStream};
use volta_pcg::{FullVole, ProverPcgPool, SubVole, VerifierPcgPool};

pub const TAG_BIT: u64 = 1 << 63;
pub const FULL_BIT: u64 = 1 << 62;
/// Internal ledger discriminator separating full-field draws from subfield
/// draws at the same public domain. Callers must never set this bit.
pub const LEDGER_SHADOW_BIT: u64 = 1 << 61;
/// Bits unavailable to caller-owned correlation domains.
pub const RESERVED_DOMAIN_BITS: u64 = TAG_BIT | FULL_BIT | LEDGER_SHADOW_BIT;

/// Domain-separated correlation index. Packs to the P1 GEMM convention
/// `(tensor_tag << 32) | row` with `tensor_tag = session·2^24 | layer·2^16 |
/// head·2^8 | tensor`; the top two bits of `tensor_tag` must stay clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CorrIndex {
    pub session: u8,
    pub layer: u8,
    pub head: u8,
    pub tensor: u8,
    /// Row / position within the tensor stream.
    pub row: u32,
}

impl CorrIndex {
    #[inline]
    pub fn tensor_tag(&self) -> u32 {
        // Top three domain bits are reserved (TAG_BIT, FULL_BIT, ledger shadow).
        assert!(self.session < 0x20, "top three tag bits reserved");
        ((self.session as u32) << 24)
            | ((self.layer as u32) << 16)
            | ((self.head as u32) << 8)
            | self.tensor as u32
    }

    #[inline]
    pub fn domain(&self) -> u64 {
        ((self.tensor_tag() as u64) << 32) | self.row as u64
    }
}

/// Prover half of a subfield correlation: `(r, m_r)`, `k_r = m_r + Δ·r` on V's side.
#[derive(Clone, Copy, Debug)]
pub struct SubCorr {
    pub r: Fp,
    pub m: Fp2,
}

/// Prover half of a full-field correlation (fresh mask): `(x, m)`, `k = m + Δ·x`.
#[derive(Clone, Copy, Debug)]
pub struct FullCorr {
    pub x: Fp2,
    pub m: Fp2,
}

/// Audited reservation of row-major subfield masks.
///
/// `ChaCha8` is returned only by [`CorrelationStream::new`], the explicitly
/// mock-PCG, non-production backend. It lets the prover expand the same
/// Goldilocks masks on its device without uploading them. The seed is the
/// shared mock correlation seed: it is never `Delta`, a verifier challenge,
/// or a Fiat-Shamir/transcript challenge. A pooled/production-oriented stream
/// returns `Host`, because its masks are allocated VOLE material and must not
/// be replaced by deterministic device expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubMaskRowsReservation {
    ChaCha8 { seed: [u8; 32], base_domain: u64, rows: usize, cols: usize },
    Host { masks: Vec<Fp>, rows: usize, cols: usize },
}

impl SubMaskRowsReservation {
    pub fn rows(&self) -> usize {
        match self {
            Self::ChaCha8 { rows, .. } | Self::Host { rows, .. } => *rows,
        }
    }

    pub fn cols(&self) -> usize {
        match self {
            Self::ChaCha8 { cols, .. } | Self::Host { cols, .. } => *cols,
        }
    }

    pub fn len(&self) -> usize {
        self.rows().checked_mul(self.cols()).expect("validated sub-mask reservation overflow")
    }

    pub fn is_empty(&self) -> bool {
        self.rows() == 0 || self.cols() == 0
    }

    /// Materialize the reservation on the host. Existing host-only callsites
    /// use this compatibility path; GPU integration should match `ChaCha8`
    /// directly so the masks never become H2D payload.
    pub fn into_host_masks(self) -> Vec<Fp> {
        match self {
            Self::ChaCha8 { seed, base_domain, rows, cols } => {
                let mut masks = Vec::with_capacity(
                    rows.checked_mul(cols).expect("validated sub-mask reservation overflow"),
                );
                for row in 0..rows {
                    let domain = base_domain + row as u64;
                    let mut stream = FpStream::domain_separated(seed, domain);
                    masks.extend((0..cols).map(|_| stream.next_fp()));
                }
                masks
            }
            Self::Host { masks, rows, cols } => {
                assert_eq!(
                    masks.len(),
                    rows.checked_mul(cols).expect("validated sub-mask reservation overflow")
                );
                masks
            }
        }
    }
}

/// One rectangular range in an atomic full-correlation reservation batch.
/// Domains are `base_domain + row`, with `count_per_domain` correlations in
/// every row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullCorrRange {
    pub base_domain: u64,
    pub rows: usize,
    pub count_per_domain: usize,
}

impl FullCorrRange {
    pub fn domain(self, row: usize) -> u64 {
        assert!(row < self.rows, "full-correlation reservation row out of bounds");
        let row = u64::try_from(row).expect("full-correlation reservation row exceeds u64");
        self.base_domain
            .checked_add(row)
            .expect("full-correlation reservation domain overflows u64")
    }
}

/// Recoverable failure from atomic full-correlation preflight. Scheduled GPU
/// callers use the `try_reserve_*` APIs so they can reclaim owned device jobs
/// before returning an error; legacy assertion-based wrappers remain for
/// protocol code that treats reuse as an invariant violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrReservationError {
    message: String,
}

impl CorrReservationError {
    fn new(message: impl Into<String>) -> Self {
        CorrReservationError { message: message.into() }
    }
}

impl std::fmt::Display for CorrReservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CorrReservationError {}

/// Consumption counters — compared against the P0 analytic budget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CorrCounters {
    pub sub_corrs: u64,
    pub full_corrs: u64,
    /// Domains opened (one-time indices actually used).
    pub domains: u64,
}

/// Shared one-time-use ledger: domain → number of correlations drawn there.
/// Sequential draws only; re-opening a domain panics (M4: never reuse).
#[derive(Default)]
struct DomainLedger {
    consumed: HashMap<u64, u64>,
    reserved: HashMap<u64, u64>,
}

impl DomainLedger {
    fn open(&mut self, dom: u64, n: usize) {
        assert!(dom & (TAG_BIT | FULL_BIT) == 0, "reserved domain bits set");
        if let Some(&reserved) = self.reserved.get(&dom) {
            assert_eq!(
                reserved,
                u64::try_from(n).expect("correlation draw count exceeds u64"),
                "reserved correlation length mismatch at {dom:#x}"
            );
            self.reserved.remove(&dom);
        }
        assert!(
            !self.consumed.contains_key(&dom),
            "correlation domain {dom:#x} reused (one-time-use violation)"
        );
        self.consumed.insert(dom, u64::try_from(n).expect("correlation draw count exceeds u64"));
    }

    /// Atomically preflight and open every subfield row domain. A duplicate in
    /// the middle of the range must not partially consume the surrounding
    /// domains before the one-time-use violation is reported.
    fn open_sub_rows(&mut self, base_domain: u64, rows: usize, cols: usize) {
        let cols_u64 = u64::try_from(cols).expect("sub-mask column count exceeds u64");
        for row in 0..rows {
            let domain = base_domain + row as u64;
            assert!(
                !self.consumed.contains_key(&domain) && !self.reserved.contains_key(&domain),
                "correlation domain {domain:#x} reused (one-time-use violation)"
            );
        }
        for row in 0..rows {
            let domain = base_domain + row as u64;
            let previous = self.consumed.insert(domain, cols_u64);
            debug_assert!(previous.is_none());
        }
    }

    /// Atomically preflight all ranges before recording any reservation.
    fn try_reserve_full_ranges(
        &mut self,
        ranges: &[FullCorrRange],
    ) -> Result<(), CorrReservationError> {
        let mut pending = HashMap::new();
        for range in ranges {
            let count = u64::try_from(range.count_per_domain)
                .map_err(|_| CorrReservationError::new("full-correlation row count exceeds u64"))?;
            for row in 0..range.rows {
                let domain = range.domain(row);
                let key = domain | FULL_BIT_SHADOW;
                if self.consumed.contains_key(&key)
                    || self.reserved.contains_key(&key)
                    || pending.contains_key(&key)
                {
                    return Err(CorrReservationError::new(format!(
                        "correlation domain {domain:#x} reused (one-time-use violation)"
                    )));
                }
                pending.insert(key, count);
            }
        }
        self.reserved.extend(pending);
        Ok(())
    }

    fn cancel_full_reservation(&mut self, domain: u64, count: usize) {
        let key = domain | FULL_BIT_SHADOW;
        let expected = u64::try_from(count).expect("full-correlation row count exceeds u64");
        if self.reserved.get(&key) == Some(&expected) {
            self.reserved.remove(&key);
        }
    }
}

fn validate_sub_mask_rows(base_domain: u64, rows: usize, cols: usize) -> usize {
    validate_correlation_rows(base_domain, rows, cols, "sub-mask reservation")
}

fn try_validate_full_corr_range(
    range: FullCorrRange,
    index: usize,
) -> Result<usize, CorrReservationError> {
    if range.rows == 0 {
        return Err(CorrReservationError::new(format!(
            "full-correlation range {index} requires at least one row"
        )));
    }
    if range.count_per_domain == 0 {
        return Err(CorrReservationError::new(format!(
            "full-correlation range {index} requires at least one correlation per domain"
        )));
    }
    let row_span = u64::try_from(range.rows - 1).map_err(|_| {
        CorrReservationError::new(format!("full-correlation range {index} row count exceeds u64"))
    })?;
    let last_domain = range.base_domain.checked_add(row_span).ok_or_else(|| {
        CorrReservationError::new(format!(
            "full-correlation range {index} domain range overflows u64"
        ))
    })?;
    if range.base_domain & RESERVED_DOMAIN_BITS != 0 || last_domain & RESERVED_DOMAIN_BITS != 0 {
        return Err(CorrReservationError::new(format!(
            "full-correlation range {index} sets reserved domain bits"
        )));
    }
    let total = range.rows.checked_mul(range.count_per_domain).ok_or_else(|| {
        CorrReservationError::new(format!(
            "full-correlation range {index} geometry overflows usize"
        ))
    })?;
    let _ = u64::try_from(total).map_err(|_| {
        CorrReservationError::new(format!("full-correlation range {index} count exceeds u64"))
    })?;
    Ok(total)
}

fn validate_correlation_rows(
    base_domain: u64,
    rows: usize,
    cols: usize,
    description: &str,
) -> usize {
    assert!(rows > 0, "{description} requires at least one row");
    assert!(cols > 0, "{description} requires at least one column");
    let row_span = u64::try_from(rows - 1).expect("correlation row count exceeds u64");
    let last_domain = base_domain
        .checked_add(row_span)
        .unwrap_or_else(|| panic!("{description} domain range overflows u64"));
    assert!(
        base_domain & RESERVED_DOMAIN_BITS == 0 && last_domain & RESERVED_DOMAIN_BITS == 0,
        "reserved correlation domain bits set"
    );
    let total =
        rows.checked_mul(cols).unwrap_or_else(|| panic!("{description} geometry overflows usize"));
    let _ = u64::try_from(total).unwrap_or_else(|_| panic!("{description} count exceeds u64"));
    total
}

#[derive(Debug)]
struct FullReservationProgress {
    ranges: Vec<FullCorrRange>,
    drawn: Vec<Vec<bool>>,
}

impl FullReservationProgress {
    fn try_new(ranges: &[FullCorrRange]) -> Result<(Self, usize), CorrReservationError> {
        if ranges.is_empty() {
            return Err(CorrReservationError::new("full-correlation reservation batch is empty"));
        }
        let mut total = 0usize;
        for (index, &range) in ranges.iter().enumerate() {
            total = total.checked_add(try_validate_full_corr_range(range, index)?).ok_or_else(
                || CorrReservationError::new("full-correlation batch count overflows usize"),
            )?;
        }
        let drawn = ranges.iter().map(|range| vec![false; range.rows]).collect();
        Ok((FullReservationProgress { ranges: ranges.to_vec(), drawn }, total))
    }

    fn pending(&self, range: usize, row: usize) -> FullCorrRange {
        let spec = *self
            .ranges
            .get(range)
            .unwrap_or_else(|| panic!("full-correlation reservation range out of bounds"));
        assert!(row < spec.rows, "full-correlation reservation row out of bounds");
        assert!(!self.drawn[range][row], "full-correlation reservation row drawn twice");
        spec
    }

    fn mark_drawn(&mut self, range: usize, row: usize) {
        self.drawn[range][row] = true;
    }

    fn is_complete(&self) -> bool {
        self.drawn.iter().flatten().all(|drawn| *drawn)
    }

    fn cancel_remaining(&self, ledger: &mut DomainLedger) {
        for (range, drawn) in self.ranges.iter().zip(&self.drawn) {
            for (row, &was_drawn) in drawn.iter().enumerate() {
                if !was_drawn {
                    ledger.cancel_full_reservation(range.domain(row), range.count_per_domain);
                }
            }
        }
    }
}

/// Exclusive prover-side transaction for one atomically preflighted batch of
/// full-correlation ranges.
///
/// It borrows the stream, so unrelated draws cannot perturb pooled allocation
/// order. `draw(range, row)` advances counters and pooled offsets in exactly
/// the caller's draw order. [`Self::finish`] requires every row to have been
/// consumed. Dropping or explicitly aborting releases only still-undrawn
/// ledger reservations; already drawn correlations remain consumed, so no
/// pooled allocation is silently stranded.
#[must_use = "a full-correlation reservation must be consumed, finished, or aborted"]
pub struct FullCorrBatchReservation<'a> {
    stream: &'a mut CorrelationStream,
    progress: FullReservationProgress,
    active: bool,
}

/// Verifier mirror of [`FullCorrBatchReservation`], preserving the same
/// caller-selected draw order and pooled allocation digest.
#[must_use = "a full-key reservation must be consumed, finished, or aborted"]
pub struct FullKeyBatchReservation<'a> {
    context: &'a mut VerifierCtx,
    progress: FullReservationProgress,
    active: bool,
}

/// Prover-side correlation expander.
pub struct CorrelationStream {
    backend: ProverBackend,
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl CorrelationStream {
    pub fn new(seed: [u8; 32]) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Mock { seed },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn from_pcg_pool(pool: ProverPcgPool) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Pooled(PooledProver::new(pool)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            ProverBackend::Mock { .. } => None,
            ProverBackend::Pooled(p) => Some(p.allocation_digest_hex()),
        }
    }

    /// Atomically preflight one full-correlation domain range. Reservation
    /// does not consume counters or pooled offsets; the returned transaction
    /// exclusively borrows this stream and charges rows in draw order.
    pub fn reserve_full_corr_rows(
        &mut self,
        base_domain: u64,
        rows: usize,
        count_per_domain: usize,
    ) -> FullCorrBatchReservation<'_> {
        self.try_reserve_full_corr_rows(base_domain, rows, count_per_domain)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn try_reserve_full_corr_rows(
        &mut self,
        base_domain: u64,
        rows: usize,
        count_per_domain: usize,
    ) -> Result<FullCorrBatchReservation<'_>, CorrReservationError> {
        self.try_reserve_full_corr_ranges(&[FullCorrRange { base_domain, rows, count_per_domain }])
    }

    /// Atomically preflight all full-correlation ranges as one transaction.
    /// A collision anywhere leaves the ledger, counters, pool cursor and
    /// allocation digest unchanged.
    pub fn reserve_full_corr_ranges(
        &mut self,
        ranges: &[FullCorrRange],
    ) -> FullCorrBatchReservation<'_> {
        self.try_reserve_full_corr_ranges(ranges).unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn try_reserve_full_corr_ranges(
        &mut self,
        ranges: &[FullCorrRange],
    ) -> Result<FullCorrBatchReservation<'_>, CorrReservationError> {
        let (progress, total) = FullReservationProgress::try_new(ranges)?;
        if let ProverBackend::Pooled(pooled) = &self.backend {
            if total > pooled.remaining_full_capacity() {
                return Err(CorrReservationError::new(format!(
                    "pooled full correlation underflow: need {total}, remaining {}",
                    pooled.remaining_full_capacity()
                )));
            }
        }
        self.ledger.try_reserve_full_ranges(&progress.ranges)?;
        Ok(FullCorrBatchReservation { stream: self, progress, active: true })
    }

    /// Reserve `rows` consecutive one-time subfield domains, each containing
    /// `cols` masks, in row-major order.
    ///
    /// The complete range is validated and checked for reuse before any
    /// domain is opened. Counters advance by exactly `rows * cols` subfield
    /// correlations and `rows` domains. Mock-PCG returns a device-expandable
    /// ChaCha8 descriptor; pooled PCG returns the allocated host masks. Lazy
    /// tags remain available per row through [`Self::draw_sub_tags`].
    pub fn reserve_sub_mask_rows(
        &mut self,
        base_domain: u64,
        rows: usize,
        cols: usize,
    ) -> SubMaskRowsReservation {
        let total = validate_sub_mask_rows(base_domain, rows, cols);
        if let ProverBackend::Pooled(pooled) = &self.backend {
            pooled.assert_sub_capacity(total);
        }
        self.ledger.open_sub_rows(base_domain, rows, cols);
        self.counters.sub_corrs = self
            .counters
            .sub_corrs
            .checked_add(u64::try_from(total).expect("validated sub-mask count exceeds u64"))
            .expect("sub-correlation counter overflow");
        self.counters.domains = self
            .counters
            .domains
            .checked_add(u64::try_from(rows).expect("validated sub-mask rows exceed u64"))
            .expect("correlation domain counter overflow");
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                SubMaskRowsReservation::ChaCha8 { seed: *seed, base_domain, rows, cols }
            }
            ProverBackend::Pooled(pooled) => SubMaskRowsReservation::Host {
                masks: pooled.reserve_sub_mask_rows(base_domain, rows, cols),
                rows,
                cols,
            },
        }
    }

    /// Draw `n` subfield correlations at `dom`. One-shot per domain.
    pub fn draw_subs(&mut self, dom: u64, n: usize) -> Vec<SubCorr> {
        let masks = self.reserve_sub_mask_rows(dom, 1, n).into_host_masks();
        let tags = self.draw_sub_tags(dom, n);
        masks.into_iter().zip(tags).map(|(r, m)| SubCorr { r, m }).collect()
    }

    /// Draw the mask stream only (what the P1 GEMM epilogue consumes); the
    /// tags are expanded lazily by `draw_sub_tags` at opening time (ledger
    /// deviation 2026-07-03: that cost is charged to P3's prover budget).
    pub fn draw_sub_masks(&mut self, dom: u64, n: usize) -> Vec<Fp> {
        self.reserve_sub_mask_rows(dom, 1, n).into_host_masks()
    }

    /// Lazy tag expansion for a domain already opened via `draw_sub_masks`.
    pub fn draw_sub_tags(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let drawn = self.ledger.consumed.get(&dom).copied();
        assert_eq!(drawn, Some(n as u64), "tag expansion must match the mask draw at {dom:#x}");
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2()).collect()
            }
            ProverBackend::Pooled(p) => p.draw_sub_tags(dom, n),
        }
    }

    /// Draw `n` full-field correlations at `dom`. One-shot per domain.
    pub fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        assert!(dom & RESERVED_DOMAIN_BITS == 0, "reserved correlation domain bits set");
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            ProverBackend::Mock { seed } => {
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n).map(|_| FullCorr { x: xs.next_fp2(), m: ms.next_fp2() }).collect()
            }
            ProverBackend::Pooled(p) => p.draw_fulls(dom, n),
        }
    }
}

/// Full-domain shadow key in the ledger so `draw_subs(dom)` and
/// `draw_fulls(dom)` are tracked as distinct one-time indices (the underlying
/// ChaCha streams are already separated by `FULL_BIT`).
const FULL_BIT_SHADOW: u64 = LEDGER_SHADOW_BIT;

/// Verifier-side context: `Δ`, the shared seed, and its own mirror counters.
pub struct VerifierCtx {
    pub delta: Fp2,
    backend: VerifierBackend,
    ledger: DomainLedger,
    pub counters: CorrCounters,
}

impl VerifierCtx {
    pub fn new(seed: [u8; 32], delta: Fp2) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Mock { seed },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn from_pcg_pool(delta: Fp2, pool: VerifierPcgPool) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Pooled(PooledVerifier::new(pool)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
        }
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            VerifierBackend::Mock { .. } => None,
            VerifierBackend::Pooled(v) => Some(v.allocation_digest_hex()),
        }
    }

    pub fn reserve_full_key_rows(
        &mut self,
        base_domain: u64,
        rows: usize,
        count_per_domain: usize,
    ) -> FullKeyBatchReservation<'_> {
        self.try_reserve_full_key_rows(base_domain, rows, count_per_domain)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn try_reserve_full_key_rows(
        &mut self,
        base_domain: u64,
        rows: usize,
        count_per_domain: usize,
    ) -> Result<FullKeyBatchReservation<'_>, CorrReservationError> {
        self.try_reserve_full_key_ranges(&[FullCorrRange { base_domain, rows, count_per_domain }])
    }

    /// Verifier-side atomic mirror of
    /// [`CorrelationStream::reserve_full_corr_ranges`].
    pub fn reserve_full_key_ranges(
        &mut self,
        ranges: &[FullCorrRange],
    ) -> FullKeyBatchReservation<'_> {
        self.try_reserve_full_key_ranges(ranges).unwrap_or_else(|error| panic!("{error}"))
    }

    pub fn try_reserve_full_key_ranges(
        &mut self,
        ranges: &[FullCorrRange],
    ) -> Result<FullKeyBatchReservation<'_>, CorrReservationError> {
        let (progress, total) = FullReservationProgress::try_new(ranges)?;
        if let VerifierBackend::Pooled(pooled) = &self.backend {
            if total > pooled.remaining_full_capacity() {
                return Err(CorrReservationError::new(format!(
                    "pooled full-key underflow: need {total}, remaining {}",
                    pooled.remaining_full_capacity()
                )));
            }
        }
        self.ledger.try_reserve_full_ranges(&progress.ranges)?;
        Ok(FullKeyBatchReservation { context: self, progress, active: true })
    }

    /// Keys `k_r = m_r + Δ·r` for `n` subfield correlations at `dom`.
    pub fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        assert!(dom & RESERVED_DOMAIN_BITS == 0, "reserved correlation domain bits set");
        self.ledger.open(dom, n);
        self.counters.sub_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            VerifierBackend::Mock { seed } => {
                let mut rs = FpStream::domain_separated(*seed, dom);
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta.mul_base(rs.next_fp())).collect()
            }
            VerifierBackend::Pooled(v) => v.expand_sub_keys(dom, n),
        }
    }

    /// Keys `k = m + Δ·x` for `n` full-field correlations at `dom`.
    pub fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        assert!(dom & RESERVED_DOMAIN_BITS == 0, "reserved correlation domain bits set");
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        match &mut self.backend {
            VerifierBackend::Mock { seed } => {
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta * xs.next_fp2()).collect()
            }
            VerifierBackend::Pooled(v) => v.expand_full_keys(dom, n),
        }
    }
}

impl FullCorrBatchReservation<'_> {
    pub fn ranges(&self) -> &[FullCorrRange] {
        &self.progress.ranges
    }

    pub fn counters(&self) -> CorrCounters {
        self.stream.counters
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        self.stream.allocation_digest_hex()
    }

    pub fn draw(&mut self, range: usize, row: usize) -> Vec<FullCorr> {
        let spec = self.progress.pending(range, row);
        let values = self.stream.draw_fulls(spec.domain(row), spec.count_per_domain);
        self.progress.mark_drawn(range, row);
        values
    }

    pub fn finish(mut self) {
        assert!(self.progress.is_complete(), "full-correlation reservation finished incomplete");
        self.active = false;
    }

    pub fn abort(mut self) {
        self.progress.cancel_remaining(&mut self.stream.ledger);
        self.active = false;
    }
}

impl Drop for FullCorrBatchReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.progress.cancel_remaining(&mut self.stream.ledger);
            self.active = false;
        }
    }
}

impl FullKeyBatchReservation<'_> {
    pub fn ranges(&self) -> &[FullCorrRange] {
        &self.progress.ranges
    }

    pub fn counters(&self) -> CorrCounters {
        self.context.counters
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        self.context.allocation_digest_hex()
    }

    pub fn expand(&mut self, range: usize, row: usize) -> Vec<Fp2> {
        let spec = self.progress.pending(range, row);
        let values = self.context.expand_full_keys(spec.domain(row), spec.count_per_domain);
        self.progress.mark_drawn(range, row);
        values
    }

    pub fn finish(mut self) {
        assert!(self.progress.is_complete(), "full-key reservation finished incomplete");
        self.active = false;
    }

    pub fn abort(mut self) {
        self.progress.cancel_remaining(&mut self.context.ledger);
        self.active = false;
    }
}

impl Drop for FullKeyBatchReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.progress.cancel_remaining(&mut self.context.ledger);
            self.active = false;
        }
    }
}

enum ProverBackend {
    Mock { seed: [u8; 32] },
    Pooled(PooledProver),
}

enum VerifierBackend {
    Mock { seed: [u8; 32] },
    Pooled(PooledVerifier),
}

struct PooledProver {
    subs: Vec<SubVole>,
    fulls: Vec<FullVole>,
    next_sub: usize,
    next_full: usize,
    sub_domains: HashMap<u64, (usize, usize)>,
    hasher: blake3::Hasher,
}

impl PooledProver {
    fn new(pool: ProverPcgPool) -> PooledProver {
        PooledProver {
            subs: pool.subs,
            fulls: pool.fulls,
            next_sub: 0,
            next_full: 0,
            sub_domains: HashMap::new(),
            hasher: blake3::Hasher::new(),
        }
    }

    fn assert_sub_capacity(&self, n: usize) {
        assert!(
            n <= self.subs.len().saturating_sub(self.next_sub),
            "pooled sub correlation underflow"
        );
    }

    fn reserve_sub_mask_rows(&mut self, base_domain: u64, rows: usize, cols: usize) -> Vec<Fp> {
        let total = rows.checked_mul(cols).expect("validated pooled sub-mask geometry overflow");
        self.assert_sub_capacity(total);
        let mut masks = Vec::with_capacity(total);
        for row in 0..rows {
            let domain = base_domain + row as u64;
            let off = self.take_sub_domain(domain, cols);
            masks.extend(self.subs[off..off + cols].iter().map(|sub| sub.r));
        }
        masks
    }

    fn draw_sub_tags(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let Some((off, drawn)) = self.sub_domains.get(&dom).copied() else {
            panic!("pooled tag expansion before mask draw at {dom:#x}");
        };
        assert_eq!(drawn, n, "pooled tag expansion length mismatch at {dom:#x}");
        self.subs[off..off + n].iter().map(|s| s.m).collect()
    }

    fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        self.assert_full_capacity(n);
        let off = self.next_full;
        self.next_full += n;
        record_alloc(&mut self.hasher, b"full", dom, off, n);
        self.fulls[off..off + n].iter().map(|f| FullCorr { x: f.x, m: f.m }).collect()
    }

    fn take_sub_domain(&mut self, dom: u64, n: usize) -> usize {
        self.assert_sub_capacity(n);
        let off = self.next_sub;
        self.next_sub += n;
        let prev = self.sub_domains.insert(dom, (off, n));
        assert!(prev.is_none(), "pooled sub domain {dom:#x} allocated twice");
        record_alloc(&mut self.hasher, b"sub", dom, off, n);
        off
    }

    fn allocation_digest_hex(&self) -> String {
        self.hasher.clone().finalize().to_hex().to_string()
    }

    fn assert_full_capacity(&self, n: usize) {
        assert!(n <= self.remaining_full_capacity(), "pooled full correlation underflow");
    }

    fn remaining_full_capacity(&self) -> usize {
        self.fulls.len().saturating_sub(self.next_full)
    }
}

struct PooledVerifier {
    sub_keys: Vec<Fp2>,
    full_keys: Vec<Fp2>,
    next_sub: usize,
    next_full: usize,
    hasher: blake3::Hasher,
}

impl PooledVerifier {
    fn new(pool: VerifierPcgPool) -> PooledVerifier {
        PooledVerifier {
            sub_keys: pool.sub_keys,
            full_keys: pool.full_keys,
            next_sub: 0,
            next_full: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        assert!(self.next_sub + n <= self.sub_keys.len(), "pooled sub-key underflow");
        let off = self.next_sub;
        self.next_sub += n;
        record_alloc(&mut self.hasher, b"sub", dom, off, n);
        self.sub_keys[off..off + n].to_vec()
    }

    fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.assert_full_capacity(n);
        let off = self.next_full;
        self.next_full += n;
        record_alloc(&mut self.hasher, b"full", dom, off, n);
        self.full_keys[off..off + n].to_vec()
    }

    fn allocation_digest_hex(&self) -> String {
        self.hasher.clone().finalize().to_hex().to_string()
    }

    fn assert_full_capacity(&self, n: usize) {
        assert!(n <= self.remaining_full_capacity(), "pooled full-key underflow");
    }

    fn remaining_full_capacity(&self) -> usize {
        self.full_keys.len().saturating_sub(self.next_full)
    }
}

fn record_alloc(h: &mut blake3::Hasher, kind: &[u8], dom: u64, off: usize, n: usize) {
    h.update(kind);
    h.update(&dom.to_le_bytes());
    h.update(&(off as u64).to_le_bytes());
    h.update(&(n as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corr_index_matches_p1_packing() {
        let idx = CorrIndex { session: 0, layer: 0, head: 0, tensor: 3, row: 5 };
        assert_eq!(idx.domain(), (3u64 << 32) | 5); // P1 epilogue: (tensor_tag<<32)|row
    }

    #[test]
    fn prover_and_verifier_expansions_are_correlated() {
        let seed = [9u8; 32];
        let delta = Fp2::new(Fp::new(1234567), Fp::new(89));
        let mut p = CorrelationStream::new(seed);
        let mut v = VerifierCtx::new(seed, delta);
        let subs = p.draw_subs(77, 32);
        let keys = v.expand_sub_keys(77, 32);
        for (s, k) in subs.iter().zip(&keys) {
            assert_eq!(*k, s.m + delta.mul_base(s.r)); // k_r = m_r + Δ·r
        }
        let fulls = p.draw_fulls(77, 8);
        let fkeys = v.expand_full_keys(77, 8);
        for (f, k) in fulls.iter().zip(&fkeys) {
            assert_eq!(*k, f.m + delta * f.x);
        }
        assert_eq!(p.counters, v.counters);
        assert_eq!(p.counters.sub_corrs, 32);
        assert_eq!(p.counters.full_corrs, 8);
    }

    #[test]
    fn lazy_tags_match_eager_draw() {
        let seed = [3u8; 32];
        let mut p1 = CorrelationStream::new(seed);
        let mut p2 = CorrelationStream::new(seed);
        let eager = p1.draw_subs(5, 16);
        let masks = p2.draw_sub_masks(5, 16);
        let tags = p2.draw_sub_tags(5, 16);
        for ((e, r), m) in eager.iter().zip(&masks).zip(&tags) {
            assert_eq!(e.r, *r);
            assert_eq!(e.m, *m);
        }
    }

    #[test]
    fn mock_sub_mask_rows_match_host_draws_and_keep_lazy_tags() {
        let seed = [0xA5; 32];
        let (base_domain, rows, cols) = (0x1234_5000, 3usize, 11usize);
        let mut batched = CorrelationStream::new(seed);
        let reservation = batched.reserve_sub_mask_rows(base_domain, rows, cols);
        assert_eq!(
            batched.counters,
            CorrCounters { sub_corrs: (rows * cols) as u64, full_corrs: 0, domains: rows as u64 }
        );
        assert_eq!(reservation.rows(), rows);
        assert_eq!(reservation.cols(), cols);
        assert!(matches!(&reservation, SubMaskRowsReservation::ChaCha8 { .. }));
        let batched_masks = reservation.into_host_masks();

        let mut rowwise = CorrelationStream::new(seed);
        let mut expected_masks = Vec::new();
        for row in 0..rows {
            expected_masks.extend(rowwise.draw_sub_masks(base_domain + row as u64, cols));
        }
        assert_eq!(batched_masks, expected_masks);
        assert_eq!(batched.counters, rowwise.counters);

        for row in 0..rows {
            assert_eq!(
                batched.draw_sub_tags(base_domain + row as u64, cols),
                rowwise.draw_sub_tags(base_domain + row as u64, cols)
            );
        }
        assert_eq!(batched.counters, rowwise.counters);
    }

    #[test]
    fn pooled_sub_mask_rows_return_host_masks_and_preserve_digest() {
        let seed = [0x4D; 32];
        let delta = Fp2::new(Fp::new(0x12345), Fp::new(0x6789));
        let (base_domain, rows, cols) = (0x2200, 3usize, 5usize);
        let total = rows * cols;
        let params = volta_pcg::PhaseAParams::tiny_for_test(total);
        let pool = volta_pcg::expand_phase_a(seed, delta, total, 0, params);
        let mut prover = CorrelationStream::from_pcg_pool(pool.prover);
        let mut verifier = VerifierCtx::from_pcg_pool(delta, pool.verifier);

        let reservation = prover.reserve_sub_mask_rows(base_domain, rows, cols);
        let masks = match reservation {
            SubMaskRowsReservation::Host { masks, rows: got_rows, cols: got_cols } => {
                assert_eq!((got_rows, got_cols), (rows, cols));
                masks
            }
            SubMaskRowsReservation::ChaCha8 { .. } => {
                panic!("pooled correlations exposed a mock ChaCha8 seed")
            }
        };
        for row in 0..rows {
            let tags = prover.draw_sub_tags(base_domain + row as u64, cols);
            let keys = verifier.expand_sub_keys(base_domain + row as u64, cols);
            for i in 0..cols {
                let mask = masks[row * cols + i];
                assert_eq!(keys[i], tags[i] + delta.mul_base(mask));
            }
        }
        assert_eq!(prover.counters, verifier.counters);
        assert_eq!(prover.allocation_digest_hex(), verifier.allocation_digest_hex());
    }

    #[test]
    fn sub_mask_row_collision_is_atomic_and_boundaries_are_rejected() {
        let mut stream = CorrelationStream::new([0x37; 32]);
        let _ = stream.draw_sub_masks(0x101, 4);
        let before = stream.counters;
        let collision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = stream.reserve_sub_mask_rows(0x100, 3, 4);
        }));
        assert!(collision.is_err());
        assert_eq!(stream.counters, before);
        let _ = stream.draw_sub_masks(0x100, 4);
        let _ = stream.draw_sub_masks(0x102, 4);

        for (base, rows) in [
            (TAG_BIT, 1usize),
            (FULL_BIT, 1),
            (LEDGER_SHADOW_BIT, 1),
            (LEDGER_SHADOW_BIT - 1, 2),
            (u64::MAX, 2),
        ] {
            let invalid = std::panic::catch_unwind(|| {
                let mut candidate = CorrelationStream::new([0x38; 32]);
                let _ = candidate.reserve_sub_mask_rows(base, rows, 1);
            });
            assert!(invalid.is_err(), "invalid range base={base:#x} rows={rows} was accepted");
        }
    }

    #[test]
    fn verifier_sub_keys_reject_reserved_namespaces_before_ledger_mutation() {
        let seed = [0x39; 32];
        let delta = Fp2::new(Fp::new(17), Fp::new(29));
        for domain in [TAG_BIT, FULL_BIT, LEDGER_SHADOW_BIT] {
            let mut verifier = VerifierCtx::new(seed, delta);
            let invalid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = verifier.expand_sub_keys(domain, 1);
            }));
            assert!(invalid.is_err(), "reserved verifier domain {domain:#x} was accepted");
            assert_eq!(verifier.counters, CorrCounters::default());

            if domain == LEDGER_SHADOW_BIT {
                // Full-domain zero uses the same ledger shadow key. It must
                // remain available when the rejected subfield call fails
                // before touching the one-time-use ledger.
                assert_eq!(verifier.expand_full_keys(0, 1).len(), 1);
            }
        }

        let mut boundary = VerifierCtx::new(seed, delta);
        assert_eq!(boundary.expand_sub_keys(LEDGER_SHADOW_BIT - 1, 1).len(), 1);
    }

    #[test]
    fn full_range_batch_is_atomic_epoch_ordered_and_digest_identical() {
        let seed = [0x63; 32];
        let delta = Fp2::new(Fp::new(71), Fp::new(97));
        let ranges = [
            FullCorrRange { base_domain: 0x1000, rows: 3, count_per_domain: 2 },
            FullCorrRange { base_domain: 0x3000, rows: 2, count_per_domain: 3 },
        ];
        let total_fulls = 3 * 2 + 2 * 3;
        let params = volta_pcg::PhaseAParams::tiny_for_test(2 * total_fulls);
        let pool = volta_pcg::expand_phase_a(seed, delta, 0, total_fulls, params);
        let mut prover = CorrelationStream::from_pcg_pool(pool.prover);
        let mut verifier = VerifierCtx::from_pcg_pool(delta, pool.verifier);

        let mut prover_reservation = prover.reserve_full_corr_ranges(&ranges);
        let mut verifier_reservation = verifier.reserve_full_key_ranges(&ranges);
        assert_eq!(prover_reservation.counters(), CorrCounters::default());
        assert_eq!(verifier_reservation.counters(), CorrCounters::default());
        let initial_digest = prover_reservation.allocation_digest_hex();
        assert_eq!(initial_digest, verifier_reservation.allocation_digest_hex());

        let mut correlated = Vec::new();
        for row in 0..3 {
            for range in 0..ranges.len() {
                if row >= ranges[range].rows {
                    continue;
                }
                let fulls = prover_reservation.draw(range, row);
                let keys = verifier_reservation.expand(range, row);
                correlated.extend(fulls.into_iter().zip(keys));
            }
        }
        assert_eq!(
            prover_reservation.counters(),
            CorrCounters { sub_corrs: 0, full_corrs: total_fulls as u64, domains: 5 }
        );
        assert_eq!(prover_reservation.counters(), verifier_reservation.counters());
        assert_ne!(prover_reservation.allocation_digest_hex(), initial_digest);
        assert_eq!(
            prover_reservation.allocation_digest_hex(),
            verifier_reservation.allocation_digest_hex()
        );
        for (full, key) in correlated {
            assert_eq!(key, full.m + delta * full.x);
        }
        prover_reservation.finish();
        verifier_reservation.finish();
        assert_eq!(prover.allocation_digest_hex(), verifier.allocation_digest_hex());
    }

    #[test]
    fn full_range_middle_collision_is_atomic_and_drop_releases_undrawn_rows() {
        let mut stream = CorrelationStream::new([0x91; 32]);
        let _ = stream.draw_fulls(0x201, 1);
        let before = stream.counters;
        let ranges = [
            FullCorrRange { base_domain: 0x100, rows: 2, count_per_domain: 2 },
            FullCorrRange { base_domain: 0x200, rows: 3, count_per_domain: 1 },
        ];
        let collision = match stream.try_reserve_full_corr_ranges(&ranges) {
            Ok(_) => panic!("middle collision was accepted"),
            Err(error) => error,
        };
        assert!(collision.to_string().contains("reused"));
        assert_eq!(stream.counters, before);

        {
            let mut reservation = stream.reserve_full_corr_rows(0x100, 2, 2);
            let _ = reservation.draw(0, 0);
            assert_eq!(
                reservation.counters(),
                CorrCounters {
                    sub_corrs: before.sub_corrs,
                    full_corrs: before.full_corrs + 2,
                    domains: before.domains + 1,
                }
            );
            // Drop deliberately: row 1 is unreserved automatically.
        }
        let _ = stream.draw_fulls(0x101, 2);

        for range in [
            FullCorrRange { base_domain: TAG_BIT, rows: 1, count_per_domain: 1 },
            FullCorrRange { base_domain: FULL_BIT, rows: 1, count_per_domain: 1 },
            FullCorrRange { base_domain: LEDGER_SHADOW_BIT, rows: 1, count_per_domain: 1 },
            FullCorrRange { base_domain: LEDGER_SHADOW_BIT - 1, rows: 2, count_per_domain: 1 },
            FullCorrRange { base_domain: u64::MAX, rows: 2, count_per_domain: 1 },
        ] {
            let mut candidate = CorrelationStream::new([0x92; 32]);
            assert!(candidate.try_reserve_full_corr_ranges(&[range]).is_err());
            assert_eq!(candidate.counters, CorrCounters::default());
        }
    }

    #[test]
    fn full_range_capacity_error_is_recoverable_without_allocation() {
        let seed = [0xB7; 32];
        let delta = Fp2::new(Fp::new(19), Fp::new(23));
        let params = volta_pcg::PhaseAParams::tiny_for_test(2);
        let pool = volta_pcg::expand_phase_a(seed, delta, 0, 1, params);
        let mut prover = CorrelationStream::from_pcg_pool(pool.prover);
        let mut verifier = VerifierCtx::from_pcg_pool(delta, pool.verifier);
        let prover_digest = prover.allocation_digest_hex();
        let verifier_digest = verifier.allocation_digest_hex();
        let too_large = [FullCorrRange { base_domain: 0x700, rows: 2, count_per_domain: 1 }];
        assert!(prover.try_reserve_full_corr_ranges(&too_large).is_err());
        assert!(verifier.try_reserve_full_key_ranges(&too_large).is_err());
        assert_eq!(prover.counters, CorrCounters::default());
        assert_eq!(verifier.counters, CorrCounters::default());
        assert_eq!(prover.allocation_digest_hex(), prover_digest);
        assert_eq!(verifier.allocation_digest_hex(), verifier_digest);

        let full = prover.draw_fulls(0x700, 1)[0];
        let key = verifier.expand_full_keys(0x700, 1)[0];
        assert_eq!(key, full.m + delta * full.x);
        assert_eq!(prover.allocation_digest_hex(), verifier.allocation_digest_hex());
    }

    #[test]
    #[should_panic(expected = "one-time-use violation")]
    fn counter_no_reuse_panics() {
        let mut p = CorrelationStream::new([1u8; 32]);
        let _ = p.draw_subs(42, 4);
        let _ = p.draw_subs(42, 4);
    }

    #[test]
    fn pooled_backend_preserves_mac_relation_and_allocation_hash() {
        let seed = [0x44u8; 32];
        let delta = Fp2::new(Fp::new(7), Fp::new(11));
        let params = volta_pcg::PhaseAParams::tiny_for_test(12 + 2 * 3);
        let pool = volta_pcg::expand_phase_a(seed, delta, 12, 3, params);
        let mut p = CorrelationStream::from_pcg_pool(pool.prover);
        let mut v = VerifierCtx::from_pcg_pool(delta, pool.verifier);

        let masks = p.draw_sub_masks(0x10, 5);
        let tags = p.draw_sub_tags(0x10, 5);
        let keys = v.expand_sub_keys(0x10, 5);
        for ((r, m), k) in masks.iter().zip(&tags).zip(&keys) {
            assert_eq!(*k, *m + delta.mul_base(*r));
        }

        let subs = p.draw_subs(0x11, 7);
        let sub_keys = v.expand_sub_keys(0x11, 7);
        for (s, k) in subs.iter().zip(&sub_keys) {
            assert_eq!(*k, s.m + delta.mul_base(s.r));
        }

        let fulls = p.draw_fulls(0x12, 3);
        let full_keys = v.expand_full_keys(0x12, 3);
        for (f, k) in fulls.iter().zip(&full_keys) {
            assert_eq!(*k, f.m + delta * f.x);
        }
        assert_eq!(p.counters, v.counters);
        assert_eq!(p.allocation_digest_hex(), v.allocation_digest_hex());
    }
}
