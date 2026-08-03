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

use crate::authed::{ProverAuthed, ProverSubAuthed, VerifierKey};
use crate::c6_trace::C6TraceToken;
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

/// Connection/response scope layered above the historical packed tensor
/// domain.  It is part of the logical allocation digest for both mock and real
/// pools, and mock seeds are re-derived from it so the same tensor domain in a
/// later response cannot reproduce correlations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionCorrelationScope {
    pub connection_id: [u8; 32],
    pub response_nonce: [u8; 32],
}

impl ConnectionCorrelationScope {
    pub fn new(connection_id: [u8; 32], response_nonce: [u8; 32]) -> Self {
        assert!(connection_id != [0; 32], "connection identity must be nonzero");
        assert!(response_nonce != [0; 32], "response nonce must be nonzero");
        Self { connection_id, response_nonce }
    }

    fn derive_mock_seed(self, seed: [u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta/mac/mock-connection-scope/v1");
        hasher.update(&self.connection_id);
        hasher.update(&self.response_nonce);
        hasher.update(&seed);
        *hasher.finalize().as_bytes()
    }
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
    #[cfg(feature = "c6-trace")]
    trace: C6TraceToken,
}

/// Prover half of a full-field correlation (fresh mask): `(x, m)`, `k = m + Δ·x`.
#[derive(Clone, Copy, Debug)]
pub struct FullCorr {
    pub x: Fp2,
    pub m: Fp2,
    #[cfg(feature = "c6-trace")]
    trace: C6TraceToken,
}

impl SubCorr {
    #[inline]
    fn new(r: Fp, m: Fp2, _trace: C6TraceToken) -> Self {
        Self {
            r,
            m,
            #[cfg(feature = "c6-trace")]
            trace: _trace,
        }
    }

    /// Authenticate a corrected plaintext while preserving its canonical
    /// correlation-source provenance in a diagnostic trace build.
    #[inline]
    pub fn authenticate(self, x: Fp) -> ProverSubAuthed {
        ProverSubAuthed::from_traced_parts(x, self.m, self.c6_trace_token())
    }

    #[inline]
    pub fn c6_trace_token(self) -> C6TraceToken {
        #[cfg(feature = "c6-trace")]
        {
            self.trace
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            C6TraceToken::untracked()
        }
    }
}

impl FullCorr {
    #[inline]
    fn new(x: Fp2, m: Fp2, _trace: C6TraceToken) -> Self {
        Self {
            x,
            m,
            #[cfg(feature = "c6-trace")]
            trace: _trace,
        }
    }

    /// Authenticate a corrected plaintext while preserving its canonical
    /// correlation-source provenance in a diagnostic trace build.
    #[inline]
    pub fn authenticate(self, x: Fp2) -> ProverAuthed {
        ProverAuthed::from_traced_parts(x, self.m, self.c6_trace_token())
    }

    #[inline]
    pub fn c6_trace_token(self) -> C6TraceToken {
        #[cfg(feature = "c6-trace")]
        {
            self.trace
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            C6TraceToken::untracked()
        }
    }
}

/// Full-field correlation consumed uncorrected as the masking leaf of one
/// QuickSilver product closure.  Construction is intentionally restricted to
/// [`CorrelationStream::draw_product_mask`].
#[derive(Clone, Copy, Debug)]
pub struct ProductMaskCorr {
    correlation: FullCorr,
    product_triples: usize,
}

impl ProductMaskCorr {
    pub fn into_inner(self) -> FullCorr {
        self.correlation
    }

    pub fn plaintext(&self) -> Fp2 {
        self.correlation.x
    }

    pub fn tag(&self) -> Fp2 {
        self.correlation.m
    }

    pub fn product_triples(&self) -> usize {
        self.product_triples
    }

    pub fn c6_trace_token(&self) -> C6TraceToken {
        self.correlation.c6_trace_token()
    }
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

/// Public type discriminator for the optional correlation-schedule audit.
///
/// The audit records logical allocation metadata only.  It never contains a
/// mask, tag, verifier key, PCG seed or `Delta`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrScheduleKind {
    Subfield = 1,
    FullField = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorrScheduleRole {
    DirectCorrection = 1,
    ProductMask = 2,
}

/// One canonical logical draw in protocol execution order.
///
/// `global_offset` is maintained independently for subfield and full-field
/// streams, exactly like the existing allocation digest.  `count` leaves at
/// this draw have physical identities `(kind, domain, 0..count)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrScheduleDraw {
    pub ordinal: u64,
    pub kind: CorrScheduleKind,
    pub role: CorrScheduleRole,
    /// Nonzero only for `ProductMask`: the exact number of triples closed by
    /// the corresponding QuickSilver batch.
    pub product_triples: u64,
    pub domain: u64,
    pub global_offset: u64,
    pub count: u64,
}

/// Immutable snapshot of the optional logical schedule recorder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrScheduleAudit {
    pub draws: Vec<CorrScheduleDraw>,
    pub counters: CorrCounters,
    pub digest: [u8; 32],
}

impl CorrScheduleAudit {
    pub fn canonical_digest(draws: &[CorrScheduleDraw]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("volta/mac/correlation-schedule-audit/v1");
        for draw in draws {
            hasher.update(&draw.ordinal.to_le_bytes());
            hasher.update(&[draw.kind as u8, draw.role as u8]);
            hasher.update(&draw.product_triples.to_le_bytes());
            hasher.update(&draw.domain.to_le_bytes());
            hasher.update(&draw.global_offset.to_le_bytes());
            hasher.update(&draw.count.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Recompute ordinals, kind-local offsets, counters and digest.
    pub fn is_canonical(&self) -> bool {
        let mut next_sub = 0u64;
        let mut next_full = 0u64;
        for (index, draw) in self.draws.iter().enumerate() {
            if draw.ordinal != index as u64 || draw.count == 0 {
                return false;
            }
            match draw.role {
                CorrScheduleRole::DirectCorrection if draw.product_triples != 0 => return false,
                CorrScheduleRole::ProductMask
                    if draw.kind != CorrScheduleKind::FullField
                        || draw.count != 1
                        || draw.product_triples == 0 =>
                {
                    return false;
                }
                CorrScheduleRole::DirectCorrection | CorrScheduleRole::ProductMask => {}
            }
            let next = match draw.kind {
                CorrScheduleKind::Subfield => &mut next_sub,
                CorrScheduleKind::FullField => &mut next_full,
            };
            if draw.global_offset != *next {
                return false;
            }
            let Some(updated) = next.checked_add(draw.count) else {
                return false;
            };
            *next = updated;
        }
        self.counters
            == (CorrCounters {
                sub_corrs: next_sub,
                full_corrs: next_full,
                domains: self.draws.len() as u64,
            })
            && self.digest == Self::canonical_digest(&self.draws)
    }
}

/// One subfield draw in the prover-only C6 witness sidecar.
///
/// The sidecar is never part of the public schedule audit or a wire object:
/// it contains secret masks/tags and hidden corrections. `witness_offset`
/// indexes the flat arrays in [`C6SubfieldWitnessAudit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6SubfieldWitnessDraw {
    pub domain: u64,
    pub global_offset: u64,
    pub count: u64,
    pub witness_offset: u64,
}

/// Prover-only reference witness for every corrected subfield source.
///
/// Collection is explicit and disabled by default. The digests are reference
/// commitments for census/replay tests, not a replacement for the binding C6
/// wrapper PCS. This value must never be serialized to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6SubfieldWitnessAudit {
    draws: Vec<C6SubfieldWitnessDraw>,
    masks: Vec<Fp>,
    corrections: Vec<Fp>,
    tags: Vec<Fp2>,
    pub witness_digest: [u8; 32],
    pub correction_digest: [u8; 32],
    pub plaintext_digest: [u8; 32],
}

impl C6SubfieldWitnessAudit {
    pub fn draws(&self) -> &[C6SubfieldWitnessDraw] {
        &self.draws
    }

    pub fn masks(&self) -> &[Fp] {
        &self.masks
    }

    pub fn corrections(&self) -> &[Fp] {
        &self.corrections
    }

    pub fn tags(&self) -> &[Fp2] {
        &self.tags
    }

    pub fn len(&self) -> usize {
        self.masks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.masks.is_empty()
    }

    pub fn plaintext(&self, index: usize) -> Option<Fp> {
        self.masks
            .get(index)
            .zip(self.corrections.get(index))
            .map(|(&mask, &correction)| mask + correction)
    }

    pub fn validate_against(&self, schedule: &CorrScheduleAudit) -> Result<(), String> {
        if !schedule.is_canonical() {
            return Err("C6 subfield witness received a noncanonical schedule".to_owned());
        }
        if self.masks.len() != self.corrections.len() || self.masks.len() != self.tags.len() {
            return Err("C6 subfield witness flat arrays have different lengths".to_owned());
        }
        let schedule_draws =
            schedule.draws.iter().filter(|draw| draw.kind == CorrScheduleKind::Subfield);
        let mut expected_witness_offset = 0u64;
        for (witness_draw, schedule_draw) in self.draws.iter().zip(schedule_draws) {
            if witness_draw.domain != schedule_draw.domain
                || witness_draw.global_offset != schedule_draw.global_offset
                || witness_draw.count != schedule_draw.count
                || witness_draw.witness_offset != expected_witness_offset
            {
                return Err("C6 subfield witness draw order differs from the correlation schedule"
                    .to_owned());
            }
            expected_witness_offset = expected_witness_offset
                .checked_add(witness_draw.count)
                .ok_or_else(|| "C6 subfield witness offset overflows".to_owned())?;
        }
        let schedule_sub_draw_count =
            schedule.draws.iter().filter(|draw| draw.kind == CorrScheduleKind::Subfield).count();
        if self.draws.len() != schedule_sub_draw_count
            || expected_witness_offset != self.masks.len() as u64
            || expected_witness_offset != schedule.counters.sub_corrs
        {
            return Err("C6 subfield witness count differs from its schedule".to_owned());
        }
        let (witness_digest, correction_digest, plaintext_digest) =
            c6_subfield_witness_digests(&self.draws, &self.masks, &self.corrections, &self.tags)?;
        if witness_digest != self.witness_digest
            || correction_digest != self.correction_digest
            || plaintext_digest != self.plaintext_digest
        {
            return Err("C6 subfield witness reference digest mismatch".to_owned());
        }
        Ok(())
    }
}

fn c6_subfield_witness_digests(
    draws: &[C6SubfieldWitnessDraw],
    masks: &[Fp],
    corrections: &[Fp],
    tags: &[Fp2],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    if masks.len() != corrections.len() || masks.len() != tags.len() {
        return Err("C6 subfield witness digest arrays have different lengths".to_owned());
    }
    let mut witness = blake3::Hasher::new_derive_key("volta/mac/c6/subfield-witness-reference/v1");
    let mut correction =
        blake3::Hasher::new_derive_key("volta/mac/c6/subfield-correction-reference/v1");
    let mut plaintext =
        blake3::Hasher::new_derive_key("volta/mac/c6/subfield-plaintext-reference/v1");
    for draw in draws {
        for hasher in [&mut witness, &mut correction, &mut plaintext] {
            hasher.update(&draw.domain.to_le_bytes());
            hasher.update(&draw.global_offset.to_le_bytes());
            hasher.update(&draw.count.to_le_bytes());
            hasher.update(&draw.witness_offset.to_le_bytes());
        }
        let first = usize::try_from(draw.witness_offset)
            .map_err(|_| "C6 subfield witness offset exceeds usize".to_owned())?;
        let count = usize::try_from(draw.count)
            .map_err(|_| "C6 subfield witness count exceeds usize".to_owned())?;
        let end = first
            .checked_add(count)
            .ok_or_else(|| "C6 subfield witness range overflows".to_owned())?;
        if end > masks.len() {
            return Err("C6 subfield witness draw exceeds its flat arrays".to_owned());
        }
        for index in first..end {
            let mask = masks[index];
            let direct_correction = corrections[index];
            let tag = tags[index];
            let value = mask + direct_correction;
            witness.update(&mask.value().to_le_bytes());
            witness.update(&direct_correction.value().to_le_bytes());
            witness.update(&tag.c0.value().to_le_bytes());
            witness.update(&tag.c1.value().to_le_bytes());
            correction.update(&direct_correction.value().to_le_bytes());
            plaintext.update(&value.value().to_le_bytes());
        }
    }
    Ok((
        *witness.finalize().as_bytes(),
        *correction.finalize().as_bytes(),
        *plaintext.finalize().as_bytes(),
    ))
}

#[derive(Default)]
struct C6SubfieldWitnessRecorder {
    draws: Vec<C6SubfieldWitnessDraw>,
    draw_by_domain: HashMap<u64, usize>,
    masks: Vec<Fp>,
    corrections: Vec<Fp>,
    tags: Vec<Fp2>,
    corrections_recorded: Vec<bool>,
    tags_recorded: Vec<bool>,
}

impl C6SubfieldWitnessRecorder {
    fn record_masks(
        &mut self,
        base_domain: u64,
        rows: usize,
        cols: usize,
        masks: &[Fp],
    ) -> Result<(), String> {
        let expected = rows
            .checked_mul(cols)
            .ok_or_else(|| "C6 subfield witness mask geometry overflows".to_owned())?;
        if masks.len() != expected {
            return Err("C6 subfield witness mask reservation has wrong length".to_owned());
        }
        for row in 0..rows {
            let domain = base_domain
                .checked_add(row as u64)
                .ok_or_else(|| "C6 subfield witness domain overflows".to_owned())?;
            if self.draw_by_domain.contains_key(&domain) {
                return Err(format!("duplicate C6 subfield witness domain {domain:#x}"));
            }
            let first = row * cols;
            let end = first + cols;
            let witness_offset = self.masks.len() as u64;
            let global_offset = witness_offset;
            self.masks.extend_from_slice(&masks[first..end]);
            self.corrections.resize(self.masks.len(), Fp::ZERO);
            self.tags.resize(self.masks.len(), Fp2::ZERO);
            let draw_index = self.draws.len();
            self.draws.push(C6SubfieldWitnessDraw {
                domain,
                global_offset,
                count: cols as u64,
                witness_offset,
            });
            self.draw_by_domain.insert(domain, draw_index);
            self.corrections_recorded.push(false);
            self.tags_recorded.push(false);
        }
        Ok(())
    }

    fn draw_range(&self, domain: u64, count: usize) -> Result<(usize, usize, usize), String> {
        let draw_index = *self
            .draw_by_domain
            .get(&domain)
            .ok_or_else(|| format!("C6 subfield witness has no mask draw at {domain:#x}"))?;
        let draw = self.draws[draw_index];
        if draw.count != count as u64 {
            return Err(format!("C6 subfield witness length mismatch at {domain:#x}"));
        }
        let first = draw.witness_offset as usize;
        Ok((draw_index, first, first + count))
    }

    fn record_corrections(&mut self, domain: u64, values: &[u64]) -> Result<(), String> {
        if values.iter().any(|&value| value >= volta_field::P) {
            return Err(format!("noncanonical C6 subfield correction at {domain:#x}"));
        }
        let (draw_index, first, end) = self.draw_range(domain, values.len())?;
        if self.corrections_recorded[draw_index] {
            return Err(format!("duplicate C6 subfield corrections at {domain:#x}"));
        }
        for (slot, &value) in self.corrections[first..end].iter_mut().zip(values) {
            *slot = Fp::new(value);
        }
        self.corrections_recorded[draw_index] = true;
        Ok(())
    }

    fn record_tags(&mut self, domain: u64, values: &[Fp2]) -> Result<(), String> {
        let (draw_index, first, end) = self.draw_range(domain, values.len())?;
        if self.tags_recorded[draw_index] {
            if self.tags[first..end] != *values {
                return Err(format!("C6 subfield tags changed on replay at {domain:#x}"));
            }
            return Ok(());
        }
        self.tags[first..end].copy_from_slice(values);
        self.tags_recorded[draw_index] = true;
        Ok(())
    }

    fn missing_tag_draws(&self) -> Result<Vec<(u64, usize)>, String> {
        self.draws
            .iter()
            .zip(&self.tags_recorded)
            .filter_map(|(draw, &recorded)| (!recorded).then_some(draw))
            .map(|draw| {
                usize::try_from(draw.count).map(|count| (draw.domain, count)).map_err(|_| {
                    format!("C6 subfield witness tag count exceeds usize at {:#x}", draw.domain)
                })
            })
            .collect()
    }

    fn finish(self, schedule: &CorrScheduleAudit) -> Result<C6SubfieldWitnessAudit, String> {
        if let Some(index) = self.corrections_recorded.iter().position(|recorded| !recorded) {
            return Err(format!(
                "C6 subfield witness draw {} lacks its hidden corrections",
                self.draws[index].domain
            ));
        }
        if let Some(index) = self.tags_recorded.iter().position(|recorded| !recorded) {
            return Err(format!(
                "C6 subfield witness draw {} lacks its prover tags",
                self.draws[index].domain
            ));
        }
        let (witness_digest, correction_digest, plaintext_digest) =
            c6_subfield_witness_digests(&self.draws, &self.masks, &self.corrections, &self.tags)?;
        let audit = C6SubfieldWitnessAudit {
            draws: self.draws,
            masks: self.masks,
            corrections: self.corrections,
            tags: self.tags,
            witness_digest,
            correction_digest,
            plaintext_digest,
        };
        audit.validate_against(schedule)?;
        Ok(audit)
    }
}

/// One full-field draw in the prover-only C6 witness sidecar.
///
/// Direct corrected sources and uncorrected ProductClosure masks share the
/// same full-field correlation stream, so the role and exact product-triple
/// census are part of the witness order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6FullfieldWitnessDraw {
    pub domain: u64,
    pub global_offset: u64,
    pub count: u64,
    pub witness_offset: u64,
    pub role: CorrScheduleRole,
    pub product_triples: u64,
}

/// Prover-only reference witness for all full-field C6 source leaves.
///
/// Direct leaves contain their hidden correction. ProductMask leaves are
/// deliberately uncorrected and therefore have a canonical zero correction.
/// This value contains secret correlation material and must never be sent to
/// the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6FullfieldWitnessAudit {
    draws: Vec<C6FullfieldWitnessDraw>,
    masks: Vec<Fp2>,
    corrections: Vec<Fp2>,
    tags: Vec<Fp2>,
    pub witness_digest: [u8; 32],
    pub correction_digest: [u8; 32],
    pub plaintext_digest: [u8; 32],
}

impl C6FullfieldWitnessAudit {
    pub fn draws(&self) -> &[C6FullfieldWitnessDraw] {
        &self.draws
    }

    pub fn masks(&self) -> &[Fp2] {
        &self.masks
    }

    pub fn corrections(&self) -> &[Fp2] {
        &self.corrections
    }

    pub fn tags(&self) -> &[Fp2] {
        &self.tags
    }

    pub fn len(&self) -> usize {
        self.masks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.masks.is_empty()
    }

    pub fn plaintext(&self, index: usize) -> Option<Fp2> {
        self.masks
            .get(index)
            .zip(self.corrections.get(index))
            .map(|(&mask, &correction)| mask + correction)
    }

    pub fn validate_against(&self, schedule: &CorrScheduleAudit) -> Result<(), String> {
        if !schedule.is_canonical() {
            return Err("C6 full-field witness received a noncanonical schedule".to_owned());
        }
        if self.masks.len() != self.corrections.len() || self.masks.len() != self.tags.len() {
            return Err("C6 full-field witness flat arrays have different lengths".to_owned());
        }
        let schedule_draws =
            schedule.draws.iter().filter(|draw| draw.kind == CorrScheduleKind::FullField);
        let mut expected_witness_offset = 0u64;
        for (witness_draw, schedule_draw) in self.draws.iter().zip(schedule_draws) {
            if witness_draw.domain != schedule_draw.domain
                || witness_draw.global_offset != schedule_draw.global_offset
                || witness_draw.count != schedule_draw.count
                || witness_draw.witness_offset != expected_witness_offset
                || witness_draw.role != schedule_draw.role
                || witness_draw.product_triples != schedule_draw.product_triples
            {
                return Err(
                    "C6 full-field witness draw order differs from the correlation schedule"
                        .to_owned(),
                );
            }
            expected_witness_offset = expected_witness_offset
                .checked_add(witness_draw.count)
                .ok_or_else(|| "C6 full-field witness offset overflows".to_owned())?;
        }
        let schedule_full_draw_count =
            schedule.draws.iter().filter(|draw| draw.kind == CorrScheduleKind::FullField).count();
        if self.draws.len() != schedule_full_draw_count
            || expected_witness_offset != self.masks.len() as u64
            || expected_witness_offset != schedule.counters.full_corrs
        {
            return Err("C6 full-field witness count differs from its schedule".to_owned());
        }
        for draw in &self.draws {
            if draw.role == CorrScheduleRole::ProductMask {
                let first = usize::try_from(draw.witness_offset)
                    .map_err(|_| "C6 full-field mask offset exceeds usize".to_owned())?;
                let count = usize::try_from(draw.count)
                    .map_err(|_| "C6 full-field mask count exceeds usize".to_owned())?;
                let end = first
                    .checked_add(count)
                    .ok_or_else(|| "C6 full-field mask range overflows".to_owned())?;
                if self.corrections[first..end].iter().any(|&correction| correction != Fp2::ZERO) {
                    return Err("C6 ProductMask witness has a nonzero correction".to_owned());
                }
            }
        }
        let (witness_digest, correction_digest, plaintext_digest) =
            c6_fullfield_witness_digests(&self.draws, &self.masks, &self.corrections, &self.tags)?;
        if witness_digest != self.witness_digest
            || correction_digest != self.correction_digest
            || plaintext_digest != self.plaintext_digest
        {
            return Err("C6 full-field witness reference digest mismatch".to_owned());
        }
        Ok(())
    }
}

fn c6_fullfield_witness_digests(
    draws: &[C6FullfieldWitnessDraw],
    masks: &[Fp2],
    corrections: &[Fp2],
    tags: &[Fp2],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    if masks.len() != corrections.len() || masks.len() != tags.len() {
        return Err("C6 full-field witness digest arrays have different lengths".to_owned());
    }
    let mut witness = blake3::Hasher::new_derive_key("volta/mac/c6/full-witness-reference/v1");
    let mut correction =
        blake3::Hasher::new_derive_key("volta/mac/c6/full-correction-reference/v1");
    let mut plaintext = blake3::Hasher::new_derive_key("volta/mac/c6/full-plaintext-reference/v1");
    for draw in draws {
        for hasher in [&mut witness, &mut correction, &mut plaintext] {
            hasher.update(&draw.domain.to_le_bytes());
            hasher.update(&draw.global_offset.to_le_bytes());
            hasher.update(&draw.count.to_le_bytes());
            hasher.update(&draw.witness_offset.to_le_bytes());
            hasher.update(&[draw.role as u8]);
            hasher.update(&draw.product_triples.to_le_bytes());
        }
        let first = usize::try_from(draw.witness_offset)
            .map_err(|_| "C6 full-field witness offset exceeds usize".to_owned())?;
        let count = usize::try_from(draw.count)
            .map_err(|_| "C6 full-field witness count exceeds usize".to_owned())?;
        let end = first
            .checked_add(count)
            .ok_or_else(|| "C6 full-field witness range overflows".to_owned())?;
        if end > masks.len() {
            return Err("C6 full-field witness draw exceeds its flat arrays".to_owned());
        }
        for index in first..end {
            let mask = masks[index];
            let direct_correction = corrections[index];
            let tag = tags[index];
            let value = mask + direct_correction;
            for component in
                [mask.c0, mask.c1, direct_correction.c0, direct_correction.c1, tag.c0, tag.c1]
            {
                witness.update(&component.value().to_le_bytes());
            }
            correction.update(&direct_correction.c0.value().to_le_bytes());
            correction.update(&direct_correction.c1.value().to_le_bytes());
            plaintext.update(&value.c0.value().to_le_bytes());
            plaintext.update(&value.c1.value().to_le_bytes());
        }
    }
    Ok((
        *witness.finalize().as_bytes(),
        *correction.finalize().as_bytes(),
        *plaintext.finalize().as_bytes(),
    ))
}

#[derive(Default)]
struct C6FullfieldWitnessRecorder {
    draws: Vec<C6FullfieldWitnessDraw>,
    draw_by_domain: HashMap<u64, usize>,
    masks: Vec<Fp2>,
    corrections: Vec<Fp2>,
    tags: Vec<Fp2>,
    corrections_recorded: Vec<bool>,
}

impl C6FullfieldWitnessRecorder {
    fn record_draw(
        &mut self,
        domain: u64,
        role: CorrScheduleRole,
        product_triples: usize,
        correlations: &[FullCorr],
    ) -> Result<(), String> {
        if correlations.is_empty() {
            return Err("empty C6 full-field witness draw".to_owned());
        }
        if self.draw_by_domain.contains_key(&domain) {
            return Err(format!("duplicate C6 full-field witness domain {domain:#x}"));
        }
        if (role == CorrScheduleRole::ProductMask)
            != (correlations.len() == 1 && product_triples > 0)
        {
            return Err(format!("malformed C6 full-field witness role at {domain:#x}"));
        }
        let witness_offset = self.masks.len() as u64;
        let global_offset = witness_offset;
        self.masks.extend(correlations.iter().map(|correlation| correlation.x));
        self.tags.extend(correlations.iter().map(|correlation| correlation.m));
        self.corrections.resize(self.masks.len(), Fp2::ZERO);
        let draw_index = self.draws.len();
        self.draws.push(C6FullfieldWitnessDraw {
            domain,
            global_offset,
            count: correlations.len() as u64,
            witness_offset,
            role,
            product_triples: product_triples as u64,
        });
        self.draw_by_domain.insert(domain, draw_index);
        self.corrections_recorded.push(role == CorrScheduleRole::ProductMask);
        Ok(())
    }

    fn record_corrections(&mut self, domain: u64, values: &[Fp2]) -> Result<(), String> {
        let draw_index = *self
            .draw_by_domain
            .get(&domain)
            .ok_or_else(|| format!("C6 full-field witness has no mask draw at {domain:#x}"))?;
        let draw = self.draws[draw_index];
        if draw.role != CorrScheduleRole::DirectCorrection {
            return Err(format!("C6 ProductMask at {domain:#x} cannot receive a correction"));
        }
        if draw.count != values.len() as u64 {
            return Err(format!("C6 full-field witness length mismatch at {domain:#x}"));
        }
        if self.corrections_recorded[draw_index] {
            return Err(format!("duplicate C6 full-field corrections at {domain:#x}"));
        }
        let first = draw.witness_offset as usize;
        self.corrections[first..first + values.len()].copy_from_slice(values);
        self.corrections_recorded[draw_index] = true;
        Ok(())
    }

    fn record_plaintexts(&mut self, domain: u64, values: &[Fp2]) -> Result<(), String> {
        let draw_index = *self
            .draw_by_domain
            .get(&domain)
            .ok_or_else(|| format!("C6 full-field witness has no mask draw at {domain:#x}"))?;
        let draw = self.draws[draw_index];
        if draw.count != values.len() as u64 {
            return Err(format!("C6 full-field witness length mismatch at {domain:#x}"));
        }
        let first = draw.witness_offset as usize;
        let corrections = values
            .iter()
            .zip(&self.masks[first..first + values.len()])
            .map(|(&value, &mask)| value - mask)
            .collect::<Vec<_>>();
        self.record_corrections(domain, &corrections)
    }

    fn finish(self, schedule: &CorrScheduleAudit) -> Result<C6FullfieldWitnessAudit, String> {
        if let Some(index) = self.corrections_recorded.iter().position(|recorded| !recorded) {
            return Err(format!(
                "C6 full-field witness draw {} lacks its hidden corrections",
                self.draws[index].domain
            ));
        }
        let (witness_digest, correction_digest, plaintext_digest) =
            c6_fullfield_witness_digests(&self.draws, &self.masks, &self.corrections, &self.tags)?;
        let audit = C6FullfieldWitnessAudit {
            draws: self.draws,
            masks: self.masks,
            corrections: self.corrections,
            tags: self.tags,
            witness_digest,
            correction_digest,
            plaintext_digest,
        };
        audit.validate_against(schedule)?;
        Ok(audit)
    }
}

#[derive(Default)]
struct CorrScheduleRecorder {
    draws: Vec<CorrScheduleDraw>,
    next_sub: u64,
    next_full: u64,
}

impl CorrScheduleRecorder {
    fn record(
        &mut self,
        kind: CorrScheduleKind,
        role: CorrScheduleRole,
        product_triples: usize,
        domain: u64,
        count: usize,
    ) {
        let count = u64::try_from(count).expect("correlation audit count exceeds u64");
        let ordinal =
            u64::try_from(self.draws.len()).expect("correlation audit draw count exceeds u64");
        let global_offset = match kind {
            CorrScheduleKind::Subfield => self.next_sub,
            CorrScheduleKind::FullField => self.next_full,
        };
        let next = global_offset.checked_add(count).expect("correlation audit offset overflow");
        match kind {
            CorrScheduleKind::Subfield => self.next_sub = next,
            CorrScheduleKind::FullField => self.next_full = next,
        }
        self.draws.push(CorrScheduleDraw {
            ordinal,
            kind,
            role,
            product_triples: u64::try_from(product_triples)
                .expect("product triple count exceeds u64"),
            domain,
            global_offset,
            count,
        });
    }

    fn snapshot(&self) -> CorrScheduleAudit {
        CorrScheduleAudit {
            draws: self.draws.clone(),
            counters: CorrCounters {
                sub_corrs: self.next_sub,
                full_corrs: self.next_full,
                domains: u64::try_from(self.draws.len())
                    .expect("correlation audit draw count exceeds u64"),
            },
            digest: CorrScheduleAudit::canonical_digest(&self.draws),
        }
    }
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
    schedule_audit: Option<CorrScheduleRecorder>,
    c6_subfield_witness: Option<C6SubfieldWitnessRecorder>,
    c6_subfield_witness_closed: bool,
    c6_fullfield_witness: Option<C6FullfieldWitnessRecorder>,
    c6_fullfield_witness_closed: bool,
    #[cfg(feature = "c6-trace")]
    c6_trace_sources_enabled: bool,
    #[cfg(feature = "c6-trace")]
    c6_trace_next_source: u32,
    #[cfg(feature = "c6-trace")]
    c6_trace_sub_sources: HashMap<u64, Vec<C6TraceToken>>,
}

impl CorrelationStream {
    pub fn new(seed: [u8; 32]) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Mock { seed, allocation: LogicalAllocation::new(None) },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            c6_subfield_witness: None,
            c6_subfield_witness_closed: false,
            c6_fullfield_witness: None,
            c6_fullfield_witness_closed: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
        }
    }

    pub fn new_connection_mock(
        seed: [u8; 32],
        scope: ConnectionCorrelationScope,
    ) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Mock {
                seed: scope.derive_mock_seed(seed),
                allocation: LogicalAllocation::new(Some(scope)),
            },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            c6_subfield_witness: None,
            c6_subfield_witness_closed: false,
            c6_fullfield_witness: None,
            c6_fullfield_witness_closed: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
        }
    }

    pub fn from_pcg_pool(pool: ProverPcgPool) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Pooled(PooledProver::new(pool, None)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            c6_subfield_witness: None,
            c6_subfield_witness_closed: false,
            c6_fullfield_witness: None,
            c6_fullfield_witness_closed: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
        }
    }

    pub fn from_pcg_pool_connection(
        pool: ProverPcgPool,
        scope: ConnectionCorrelationScope,
    ) -> CorrelationStream {
        CorrelationStream {
            backend: ProverBackend::Pooled(PooledProver::new(pool, Some(scope))),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            c6_subfield_witness: None,
            c6_subfield_witness_closed: false,
            c6_fullfield_witness: None,
            c6_fullfield_witness_closed: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
        }
    }

    /// True only for correlations expanded from a real PCG pool.
    /// Production callers use this to fail closed instead of accepting the
    /// deterministic mock backend.
    pub fn uses_pooled_pcg(&self) -> bool {
        matches!(&self.backend, ProverBackend::Pooled(_))
    }

    /// Enable canonical source-token assignment for one diagnostic operation
    /// trace. The process-local trace must already be active, and the stream
    /// must not have consumed any correlation.
    pub fn enable_c6_operation_trace(&mut self) -> Result<(), &'static str> {
        #[cfg(feature = "c6-trace")]
        {
            if self.counters != CorrCounters::default() {
                return Err("C6 operation tracing must start before the first draw");
            }
            if self.c6_trace_sources_enabled {
                return Err("C6 operation tracing is already enabled");
            }
            self.c6_trace_sources_enabled = true;
            self.c6_trace_next_source = 0;
            self.c6_trace_sub_sources.clear();
            Ok(())
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Err("C6 operation tracing requires the diagnostic c6-trace feature")
        }
    }

    #[cfg(feature = "c6-trace")]
    fn allocate_c6_trace_sources(&mut self, count: usize) -> Vec<C6TraceToken> {
        if !self.c6_trace_sources_enabled {
            return vec![C6TraceToken::untracked(); count];
        }
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            let index = self.c6_trace_next_source;
            let token = C6TraceToken::source(index)
                .unwrap_or_else(|error| panic!("C6 source provenance HARD STOP: {error}"));
            self.c6_trace_next_source =
                index.checked_add(1).expect("C6 trace source counter overflow");
            tokens.push(token);
        }
        tokens
    }

    /// Reconstruct one authenticated subfield source after lazy tag
    /// expansion, using the token assigned at the original mask draw.
    #[inline]
    pub fn authenticate_subfield_at(
        &self,
        domain: u64,
        index: usize,
        x: Fp,
        m: Fp2,
    ) -> ProverSubAuthed {
        #[cfg(feature = "c6-trace")]
        {
            let trace = if self.c6_trace_sources_enabled {
                *self
                    .c6_trace_sub_sources
                    .get(&domain)
                    .unwrap_or_else(|| {
                        panic!("C6 subfield source domain {domain:#x} lacks provenance")
                    })
                    .get(index)
                    .unwrap_or_else(|| {
                        panic!("C6 subfield source index {index} is out of range at {domain:#x}")
                    })
            } else {
                C6TraceToken::untracked()
            };
            return ProverSubAuthed::from_traced_parts(x, m, trace);
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            let _ = (domain, index);
            ProverSubAuthed::new(x, m)
        }
    }

    /// Authenticate one public linear form over a previously allocated
    /// subfield source domain. In a trace build, provenance is derived only
    /// from the canonical source tokens and the supplied public weights.
    #[inline]
    pub fn authenticate_subfield_linear(
        &self,
        domain: u64,
        weights: &[Fp2],
        x: Fp2,
        m: Fp2,
    ) -> ProverAuthed {
        #[cfg(feature = "c6-trace")]
        {
            if self.c6_trace_sources_enabled {
                let sources = self.c6_trace_sub_sources.get(&domain).unwrap_or_else(|| {
                    panic!("C6 subfield linear domain {domain:#x} lacks provenance")
                });
                assert_eq!(
                    sources.len(),
                    weights.len(),
                    "C6 subfield linear weight count mismatch at {domain:#x}"
                );
                let trace = sources
                    .iter()
                    .zip(weights)
                    .fold(C6TraceToken::public_zero(), |acc, (&source, &weight)| {
                        acc.add(source.scale(weight))
                    });
                return ProverAuthed::from_traced_parts(x, m, trace);
            }
        }
        let _ = (domain, weights);
        ProverAuthed::new(x, m)
    }

    /// Sparse twin of [`Self::authenticate_subfield_linear`]. `source_count`
    /// binds the complete allocated domain while `terms` names exactly the
    /// source indices used by the public linear kernel.
    #[inline]
    pub fn authenticate_subfield_sparse_linear(
        &self,
        domain: u64,
        source_count: usize,
        terms: &[(usize, Fp2)],
        x: Fp2,
        m: Fp2,
    ) -> ProverAuthed {
        #[cfg(feature = "c6-trace")]
        {
            if self.c6_trace_sources_enabled {
                let sources = self.c6_trace_sub_sources.get(&domain).unwrap_or_else(|| {
                    panic!("C6 sparse subfield domain {domain:#x} lacks provenance")
                });
                assert_eq!(
                    sources.len(),
                    source_count,
                    "C6 sparse subfield source count mismatch at {domain:#x}"
                );
                let trace = terms.iter().fold(
                    C6TraceToken::public_zero(),
                    |acc, &(index, weight)| {
                        let source = *sources.get(index).unwrap_or_else(|| {
                            panic!(
                                "C6 sparse subfield source index {index} is out of range at {domain:#x}"
                            )
                        });
                        acc.add(source.scale(weight))
                    },
                );
                return ProverAuthed::from_traced_parts(x, m, trace);
            }
        }
        let _ = (domain, source_count, terms);
        ProverAuthed::new(x, m)
    }

    /// Enable the diagnostic logical-schedule recorder before the first draw.
    ///
    /// Existing production and benchmark constructors leave it disabled, so
    /// historical profiles pay neither per-domain storage nor digest work.
    pub fn enable_schedule_audit(&mut self) -> Result<(), &'static str> {
        if self.counters != CorrCounters::default() {
            return Err("correlation schedule audit must start before the first draw");
        }
        if self.schedule_audit.is_some() {
            return Err("correlation schedule audit already enabled");
        }
        self.schedule_audit = Some(CorrScheduleRecorder::default());
        Ok(())
    }

    pub fn schedule_audit(&self) -> Option<CorrScheduleAudit> {
        self.schedule_audit.as_ref().map(CorrScheduleRecorder::snapshot)
    }

    /// Enable the prover-only C6 `(r,d,m)` sidecar before the first draw.
    ///
    /// This also enables the public logical schedule audit used to bind its
    /// order. Existing protocol and benchmark paths never call this method,
    /// so they retain their historical allocations and data structures.
    pub fn enable_c6_subfield_witness_collection(&mut self) -> Result<(), &'static str> {
        if self.counters != CorrCounters::default() {
            return Err("C6 subfield witness collection must start before the first draw");
        }
        if self.c6_subfield_witness.is_some() || self.c6_subfield_witness_closed {
            return Err("C6 subfield witness collection already enabled or closed");
        }
        if self.schedule_audit.is_none() {
            self.schedule_audit = Some(CorrScheduleRecorder::default());
        }
        self.c6_subfield_witness = Some(C6SubfieldWitnessRecorder::default());
        Ok(())
    }

    /// Enable both prover-only C6 source sidecars before the first draw.
    ///
    /// This is the production-source migration seam.  It remains opt-in and
    /// also enables the public logical schedule audit.
    pub fn enable_c6_source_witness_collection(&mut self) -> Result<(), &'static str> {
        if self.counters != CorrCounters::default() {
            return Err("C6 source witness collection must start before the first draw");
        }
        if self.c6_subfield_witness.is_some()
            || self.c6_subfield_witness_closed
            || self.c6_fullfield_witness.is_some()
            || self.c6_fullfield_witness_closed
        {
            return Err("C6 source witness collection already enabled or closed");
        }
        if self.schedule_audit.is_none() {
            self.schedule_audit = Some(CorrScheduleRecorder::default());
        }
        self.c6_subfield_witness = Some(C6SubfieldWitnessRecorder::default());
        self.c6_fullfield_witness = Some(C6FullfieldWitnessRecorder::default());
        Ok(())
    }

    /// Attach canonical hidden corrections to a previously drawn subfield
    /// domain. It is a no-op unless C6 witness collection was enabled.
    pub fn record_c6_subfield_corrections(
        &mut self,
        domain: u64,
        corrections: &[u64],
    ) -> Result<(), String> {
        if self.c6_subfield_witness_closed {
            return Err("C6 subfield witness collection is already closed".to_owned());
        }
        if let Some(witness) = &mut self.c6_subfield_witness {
            witness.record_corrections(domain, corrections)?;
        }
        Ok(())
    }

    /// Attach hidden full-field corrections to a previously drawn direct
    /// source domain. It is a no-op unless complete C6 source collection was
    /// enabled. ProductMask domains reject corrections.
    pub fn record_c6_fullfield_corrections(
        &mut self,
        domain: u64,
        corrections: &[Fp2],
    ) -> Result<(), String> {
        if self.c6_fullfield_witness_closed {
            return Err("C6 full-field witness collection is already closed".to_owned());
        }
        if let Some(witness) = &mut self.c6_fullfield_witness {
            witness.record_corrections(domain, corrections)?;
        }
        Ok(())
    }

    /// Attach direct full-field plaintexts to a previously drawn domain.
    /// Corrections are derived only when the complete C6 source sidecar is
    /// active, so the ordinary prover path allocates no extra vector.
    pub fn record_c6_fullfield_plaintexts(
        &mut self,
        domain: u64,
        plaintexts: &[Fp2],
    ) -> Result<(), String> {
        if self.c6_fullfield_witness_closed {
            return Err("C6 full-field witness collection is already closed".to_owned());
        }
        if let Some(witness) = &mut self.c6_fullfield_witness {
            witness.record_plaintexts(domain, plaintexts)?;
        }
        Ok(())
    }

    /// Iterator twin of [`Self::record_c6_fullfield_plaintexts`]. The
    /// iterator is not consumed when C6 source collection is disabled.
    pub fn record_c6_fullfield_plaintexts_iter<I>(
        &mut self,
        domain: u64,
        plaintexts: I,
    ) -> Result<(), String>
    where
        I: IntoIterator<Item = Fp2>,
    {
        if self.c6_fullfield_witness_closed {
            return Err("C6 full-field witness collection is already closed".to_owned());
        }
        if let Some(witness) = &mut self.c6_fullfield_witness {
            let plaintexts = plaintexts.into_iter().collect::<Vec<_>>();
            witness.record_plaintexts(domain, &plaintexts)?;
        }
        Ok(())
    }

    /// Close and move out the secret sidecar after the last subfield source.
    ///
    /// Tags for sources that the historical proof never opens are expanded
    /// here from their already-consumed correlation ranges. This is opt-in
    /// witness materialization, not a new correlation draw. Later full-field
    /// closure draws remain legal; any later subfield draw fails closed
    /// because it would escape the committed witness.
    pub fn finish_c6_subfield_witness_collection(
        &mut self,
    ) -> Result<C6SubfieldWitnessAudit, String> {
        let missing_tags = self
            .c6_subfield_witness
            .as_ref()
            .ok_or_else(|| "C6 subfield witness collection is not active".to_owned())?
            .missing_tag_draws()?;
        for (domain, count) in missing_tags {
            let _ = self.draw_sub_tags(domain, count);
        }
        let schedule = self
            .schedule_audit()
            .ok_or_else(|| "C6 subfield witness lacks its schedule audit".to_owned())?;
        let witness = self
            .c6_subfield_witness
            .take()
            .ok_or_else(|| "C6 subfield witness collection is not active".to_owned())?;
        self.c6_subfield_witness_closed = true;
        witness.finish(&schedule)
    }

    /// Close and move out the full-field source sidecar after the final
    /// direct source and ProductClosure mask.
    pub fn finish_c6_fullfield_witness_collection(
        &mut self,
    ) -> Result<C6FullfieldWitnessAudit, String> {
        let schedule = self
            .schedule_audit()
            .ok_or_else(|| "C6 full-field witness lacks its schedule audit".to_owned())?;
        let witness = self
            .c6_fullfield_witness
            .take()
            .ok_or_else(|| "C6 full-field witness collection is not active".to_owned())?;
        self.c6_fullfield_witness_closed = true;
        witness.finish(&schedule)
    }
    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            ProverBackend::Mock { allocation, .. } => Some(allocation.digest_hex()),
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
        assert!(
            !self.c6_subfield_witness_closed,
            "subfield draw after the C6 witness sidecar was closed"
        );
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
        let reservation = match &mut self.backend {
            ProverBackend::Mock { seed, allocation } => {
                for row in 0..rows {
                    allocation.take_sub(base_domain + row as u64, cols);
                }
                SubMaskRowsReservation::ChaCha8 { seed: *seed, base_domain, rows, cols }
            }
            ProverBackend::Pooled(pooled) => SubMaskRowsReservation::Host {
                masks: pooled.reserve_sub_mask_rows(base_domain, rows, cols),
                rows,
                cols,
            },
        };
        if let Some(audit) = &mut self.schedule_audit {
            for row in 0..rows {
                audit.record(
                    CorrScheduleKind::Subfield,
                    CorrScheduleRole::DirectCorrection,
                    0,
                    base_domain + row as u64,
                    cols,
                );
            }
        }
        if let Some(witness) = &mut self.c6_subfield_witness {
            let masks = reservation.clone().into_host_masks();
            witness
                .record_masks(base_domain, rows, cols, &masks)
                .expect("C6 subfield witness mask schedule");
        }
        #[cfg(feature = "c6-trace")]
        if self.c6_trace_sources_enabled {
            for row in 0..rows {
                let domain = base_domain + row as u64;
                let tokens = self.allocate_c6_trace_sources(cols);
                let previous = self.c6_trace_sub_sources.insert(domain, tokens);
                assert!(previous.is_none(), "duplicate C6 subfield trace domain {domain:#x}");
            }
        }
        reservation
    }

    /// Draw `n` subfield correlations at `dom`. One-shot per domain.
    pub fn draw_subs(&mut self, dom: u64, n: usize) -> Vec<SubCorr> {
        let masks = self.reserve_sub_mask_rows(dom, 1, n).into_host_masks();
        let tags = self.draw_sub_tags(dom, n);
        #[cfg(feature = "c6-trace")]
        {
            return masks
                .into_iter()
                .zip(tags)
                .enumerate()
                .map(|(index, (r, m))| {
                    SubCorr::new(
                        r,
                        m,
                        self.authenticate_subfield_at(dom, index, r, m).c6_trace_token(),
                    )
                })
                .collect();
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            masks
                .into_iter()
                .zip(tags)
                .map(|(r, m)| SubCorr::new(r, m, C6TraceToken::untracked()))
                .collect()
        }
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
        let tags = match &mut self.backend {
            ProverBackend::Mock { seed, .. } => {
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2()).collect()
            }
            ProverBackend::Pooled(p) => p.draw_sub_tags(dom, n),
        };
        if let Some(witness) = &mut self.c6_subfield_witness {
            witness.record_tags(dom, &tags).expect("C6 subfield witness tag schedule");
        }
        tags
    }

    /// Re-read the mask coordinates of an already consumed subfield source
    /// without opening a domain, advancing a pool cursor, or changing any
    /// correlation counter.  C6 uses this only to stream linear functionals
    /// of the same authenticated cache source after its direct correction was
    /// emitted.  This is source access, not a second correlation draw.
    pub fn replay_consumed_sub_masks(&mut self, dom: u64, n: usize) -> Vec<Fp> {
        let drawn = self.ledger.consumed.get(&dom).copied();
        assert_eq!(drawn, Some(n as u64), "mask replay must match the consumed source at {dom:#x}");
        match &mut self.backend {
            ProverBackend::Mock { seed, .. } => {
                let mut masks = FpStream::domain_separated(*seed, dom);
                (0..n).map(|_| masks.next_fp()).collect()
            }
            ProverBackend::Pooled(pooled) => pooled.replay_sub_masks(dom, n),
        }
    }

    /// Draw `n` full-field correlations at `dom`. One-shot per domain.
    pub fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        self.draw_fulls_with_role(dom, n, CorrScheduleRole::DirectCorrection, 0)
    }

    /// Draw the unique uncorrected full-field mask of one ProductClosure.
    pub fn draw_product_mask(&mut self, dom: u64, product_triples: usize) -> ProductMaskCorr {
        assert!(product_triples > 0, "a ProductClosure cannot be empty");
        ProductMaskCorr {
            correlation: self
                .draw_fulls_with_role(dom, 1, CorrScheduleRole::ProductMask, product_triples)
                .into_iter()
                .next()
                .expect("one C6 product-mask correlation"),
            product_triples,
        }
    }

    fn draw_fulls_with_role(
        &mut self,
        dom: u64,
        n: usize,
        role: CorrScheduleRole,
        product_triples: usize,
    ) -> Vec<FullCorr> {
        assert!(
            !self.c6_fullfield_witness_closed,
            "full-field draw after the C6 witness sidecar was closed"
        );
        assert!(dom & RESERVED_DOMAIN_BITS == 0, "reserved correlation domain bits set");
        assert!(
            role != CorrScheduleRole::ProductMask || n == 1,
            "a ProductClosure consumes exactly one full-field mask"
        );
        assert_eq!(
            role == CorrScheduleRole::ProductMask,
            product_triples > 0,
            "only a nonempty ProductClosure carries a triple count"
        );
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        let correlations = match &mut self.backend {
            ProverBackend::Mock { seed, allocation } => {
                allocation.take_full(dom, n);
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n)
                    .map(|_| FullCorr::new(xs.next_fp2(), ms.next_fp2(), C6TraceToken::untracked()))
                    .collect()
            }
            ProverBackend::Pooled(p) => p.draw_fulls(dom, n),
        };
        #[cfg(feature = "c6-trace")]
        let correlations = {
            let tokens = self.allocate_c6_trace_sources(n);
            correlations
                .into_iter()
                .zip(tokens)
                .map(|(correlation, trace)| FullCorr::new(correlation.x, correlation.m, trace))
                .collect::<Vec<_>>()
        };
        if let Some(audit) = &mut self.schedule_audit {
            audit.record(CorrScheduleKind::FullField, role, product_triples, dom, n);
        }
        if let Some(witness) = &mut self.c6_fullfield_witness {
            witness
                .record_draw(dom, role, product_triples, &correlations)
                .expect("C6 full-field witness draw schedule");
        }
        correlations
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
    schedule_audit: Option<CorrScheduleRecorder>,
    #[cfg(feature = "c6-trace")]
    c6_trace_sources_enabled: bool,
    #[cfg(feature = "c6-trace")]
    c6_trace_next_source: u32,
    #[cfg(feature = "c6-trace")]
    c6_trace_sub_sources: HashMap<u64, Vec<C6TraceToken>>,
    #[cfg(feature = "c6-trace")]
    c6_trace_full_sources: HashMap<u64, Vec<C6TraceToken>>,
}

impl VerifierCtx {
    pub fn new(seed: [u8; 32], delta: Fp2) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Mock { seed, allocation: LogicalAllocation::new(None) },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
            #[cfg(feature = "c6-trace")]
            c6_trace_full_sources: HashMap::new(),
        }
    }

    pub fn new_connection_mock(
        seed: [u8; 32],
        delta: Fp2,
        scope: ConnectionCorrelationScope,
    ) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Mock {
                seed: scope.derive_mock_seed(seed),
                allocation: LogicalAllocation::new(Some(scope)),
            },
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
            #[cfg(feature = "c6-trace")]
            c6_trace_full_sources: HashMap::new(),
        }
    }

    pub fn from_pcg_pool(delta: Fp2, pool: VerifierPcgPool) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Pooled(PooledVerifier::new(pool, None)),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
            #[cfg(feature = "c6-trace")]
            c6_trace_full_sources: HashMap::new(),
        }
    }

    pub fn from_pcg_pool_connection(
        delta: Fp2,
        pool: VerifierPcgPool,
        scope: ConnectionCorrelationScope,
    ) -> VerifierCtx {
        VerifierCtx {
            delta,
            backend: VerifierBackend::Pooled(PooledVerifier::new(pool, Some(scope))),
            ledger: DomainLedger::default(),
            counters: CorrCounters::default(),
            schedule_audit: None,
            #[cfg(feature = "c6-trace")]
            c6_trace_sources_enabled: false,
            #[cfg(feature = "c6-trace")]
            c6_trace_next_source: 0,
            #[cfg(feature = "c6-trace")]
            c6_trace_sub_sources: HashMap::new(),
            #[cfg(feature = "c6-trace")]
            c6_trace_full_sources: HashMap::new(),
        }
    }

    /// True only for verifier keys expanded from a real PCG pool.
    pub fn uses_pooled_pcg(&self) -> bool {
        matches!(&self.backend, VerifierBackend::Pooled(_))
    }

    /// Enable canonical source-token assignment for one independently
    /// recorded verifier trace. The verifier must not have consumed a draw.
    pub fn enable_c6_operation_trace(&mut self) -> Result<(), &'static str> {
        #[cfg(feature = "c6-trace")]
        {
            if self.counters != CorrCounters::default() {
                return Err("C6 verifier operation tracing must start before the first draw");
            }
            if self.c6_trace_sources_enabled {
                return Err("C6 verifier operation tracing is already enabled");
            }
            self.c6_trace_sources_enabled = true;
            self.c6_trace_next_source = 0;
            self.c6_trace_sub_sources.clear();
            self.c6_trace_full_sources.clear();
            Ok(())
        }
        #[cfg(not(feature = "c6-trace"))]
        {
            Err("C6 verifier operation tracing requires the diagnostic c6-trace feature")
        }
    }

    #[cfg(feature = "c6-trace")]
    fn allocate_c6_trace_sources(&mut self, count: usize) -> Vec<C6TraceToken> {
        if !self.c6_trace_sources_enabled {
            return vec![C6TraceToken::untracked(); count];
        }
        let mut tokens = Vec::with_capacity(count);
        for _ in 0..count {
            let index = self.c6_trace_next_source;
            let token = C6TraceToken::source(index)
                .unwrap_or_else(|error| panic!("C6 verifier source provenance HARD STOP: {error}"));
            self.c6_trace_next_source =
                index.checked_add(1).expect("C6 verifier trace source counter overflow");
            tokens.push(token);
        }
        tokens
    }

    fn trace_subfield_keys(&self, dom: u64, keys: Vec<Fp2>) -> Vec<VerifierKey> {
        #[cfg(feature = "c6-trace")]
        {
            if self.c6_trace_sources_enabled {
                let tokens = self.c6_trace_sub_sources.get(&dom).unwrap_or_else(|| {
                    panic!("C6 verifier subfield source domain {dom:#x} lacks provenance")
                });
                assert_eq!(
                    tokens.len(),
                    keys.len(),
                    "C6 verifier subfield source count mismatch at {dom:#x}"
                );
                return keys
                    .into_iter()
                    .zip(tokens)
                    .map(|(key, &trace)| VerifierKey::from_traced_key(key, trace))
                    .collect();
            }
        }
        let _ = dom;
        keys.into_iter().map(VerifierKey::new).collect()
    }

    fn trace_fullfield_keys(&self, dom: u64, keys: Vec<Fp2>) -> Vec<VerifierKey> {
        #[cfg(feature = "c6-trace")]
        {
            if self.c6_trace_sources_enabled {
                let tokens = self.c6_trace_full_sources.get(&dom).unwrap_or_else(|| {
                    panic!("C6 verifier full-field source domain {dom:#x} lacks provenance")
                });
                assert_eq!(
                    tokens.len(),
                    keys.len(),
                    "C6 verifier full-field source count mismatch at {dom:#x}"
                );
                return keys
                    .into_iter()
                    .zip(tokens)
                    .map(|(key, &trace)| VerifierKey::from_traced_key(key, trace))
                    .collect();
            }
        }
        let _ = dom;
        keys.into_iter().map(VerifierKey::new).collect()
    }

    pub fn enable_schedule_audit(&mut self) -> Result<(), &'static str> {
        if self.counters != CorrCounters::default() {
            return Err("correlation schedule audit must start before the first draw");
        }
        if self.schedule_audit.is_some() {
            return Err("correlation schedule audit already enabled");
        }
        self.schedule_audit = Some(CorrScheduleRecorder::default());
        Ok(())
    }

    pub fn schedule_audit(&self) -> Option<CorrScheduleAudit> {
        self.schedule_audit.as_ref().map(CorrScheduleRecorder::snapshot)
    }

    pub fn allocation_digest_hex(&self) -> Option<String> {
        match &self.backend {
            VerifierBackend::Mock { allocation, .. } => Some(allocation.digest_hex()),
            VerifierBackend::Pooled(v) => Some(v.allocation_digest_hex()),
        }
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

    /// Reserve consecutive subfield base-key sources in canonical allocation
    /// order without materializing their keys.  C6 uses this in phase 1 so
    /// later source-ordinal folds do not perturb the pooled PCG cursor.
    pub fn reserve_sub_key_rows(&mut self, base_domain: u64, rows: usize, cols: usize) {
        let total = validate_sub_mask_rows(base_domain, rows, cols);
        if let VerifierBackend::Pooled(pooled) = &self.backend {
            pooled.assert_sub_capacity(total);
        }
        self.ledger.open_sub_rows(base_domain, rows, cols);
        self.counters.sub_corrs = self
            .counters
            .sub_corrs
            .checked_add(u64::try_from(total).expect("validated sub-key count exceeds u64"))
            .expect("sub-key counter overflow");
        self.counters.domains = self
            .counters
            .domains
            .checked_add(u64::try_from(rows).expect("validated sub-key rows exceed u64"))
            .expect("sub-key domain counter overflow");
        match &mut self.backend {
            VerifierBackend::Mock { allocation, .. } => {
                for row in 0..rows {
                    allocation.take_sub(base_domain + row as u64, cols);
                }
            }
            VerifierBackend::Pooled(pooled) => {
                pooled.reserve_sub_key_rows(base_domain, rows, cols);
            }
        }
        if let Some(audit) = &mut self.schedule_audit {
            for row in 0..rows {
                audit.record(
                    CorrScheduleKind::Subfield,
                    CorrScheduleRole::DirectCorrection,
                    0,
                    base_domain + row as u64,
                    cols,
                );
            }
        }
        #[cfg(feature = "c6-trace")]
        if self.c6_trace_sources_enabled {
            for row in 0..rows {
                let domain = base_domain + row as u64;
                let tokens = self.allocate_c6_trace_sources(cols);
                assert!(
                    self.c6_trace_sub_sources.insert(domain, tokens).is_none(),
                    "duplicate C6 verifier subfield provenance domain {domain:#x}"
                );
            }
        }
    }

    /// Re-read reserved/consumed subfield base keys without changing the PCG
    /// cursor, counters, schedule audit, or allocation digest.
    pub fn replay_consumed_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        let drawn = self.ledger.consumed.get(&dom).copied();
        assert_eq!(drawn, Some(n as u64), "key replay must match the consumed source at {dom:#x}");
        match &mut self.backend {
            VerifierBackend::Mock { seed, .. } => {
                let mut rs = FpStream::domain_separated(*seed, dom);
                let mut ms = FpStream::domain_separated(*seed, dom | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta.mul_base(rs.next_fp())).collect()
            }
            VerifierBackend::Pooled(pooled) => pooled.replay_sub_keys(dom, n),
        }
    }

    /// Keys `k_r = m_r + Δ·r` for `n` subfield correlations at `dom`.
    pub fn expand_sub_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.reserve_sub_key_rows(dom, 1, n);
        self.replay_consumed_sub_keys(dom, n)
    }

    /// Traced verifier-key form of [`Self::expand_sub_keys`].
    pub fn expand_sub_verifier_keys(&mut self, dom: u64, n: usize) -> Vec<VerifierKey> {
        let keys = self.expand_sub_keys(dom, n);
        self.trace_subfield_keys(dom, keys)
    }

    pub fn replay_consumed_sub_verifier_keys(&mut self, dom: u64, n: usize) -> Vec<VerifierKey> {
        let keys = self.replay_consumed_sub_keys(dom, n);
        self.trace_subfield_keys(dom, keys)
    }

    /// Keys `k = m + Δ·x` for `n` full-field correlations at `dom`.
    pub fn expand_full_keys(&mut self, dom: u64, n: usize) -> Vec<Fp2> {
        self.expand_full_keys_with_role(dom, n, CorrScheduleRole::DirectCorrection, 0)
    }

    /// Traced verifier-key form of [`Self::expand_full_keys`].
    pub fn expand_full_verifier_keys(&mut self, dom: u64, n: usize) -> Vec<VerifierKey> {
        let keys = self.expand_full_keys(dom, n);
        self.trace_fullfield_keys(dom, keys)
    }

    /// Apply canonical full-field corrections while preserving each direct
    /// source token. Corrections are source metadata, not DAG operations.
    pub fn correct_full_verifier_keys(
        &mut self,
        dom: u64,
        corrections: &[Fp2],
    ) -> Vec<VerifierKey> {
        let delta = self.delta;
        self.expand_full_verifier_keys(dom, corrections.len())
            .into_iter()
            .zip(corrections)
            .map(|(key, &correction)| key.with_same_c6_trace(key.k + delta * correction))
            .collect()
    }

    pub fn correct_full_verifier_key(&mut self, dom: u64, correction: Fp2) -> VerifierKey {
        self.correct_full_verifier_keys(dom, &[correction])
            .into_iter()
            .next()
            .expect("one corrected full-field verifier key")
    }

    /// Expand the verifier key matching one uncorrected ProductClosure mask.
    pub fn expand_product_mask_key(&mut self, dom: u64, product_triples: usize) -> Fp2 {
        assert!(product_triples > 0, "a ProductClosure cannot be empty");
        self.expand_full_keys_with_role(dom, 1, CorrScheduleRole::ProductMask, product_triples)
            .into_iter()
            .next()
            .expect("one C6 product-mask key")
    }

    /// Traced verifier-key form of [`Self::expand_product_mask_key`].
    pub fn expand_product_mask_verifier_key(
        &mut self,
        dom: u64,
        product_triples: usize,
    ) -> VerifierKey {
        let key = self.expand_product_mask_key(dom, product_triples);
        self.trace_fullfield_keys(dom, vec![key])
            .into_iter()
            .next()
            .expect("one traced C6 product-mask key")
    }

    fn expand_full_keys_with_role(
        &mut self,
        dom: u64,
        n: usize,
        role: CorrScheduleRole,
        product_triples: usize,
    ) -> Vec<Fp2> {
        assert!(dom & RESERVED_DOMAIN_BITS == 0, "reserved correlation domain bits set");
        assert!(
            role != CorrScheduleRole::ProductMask || n == 1,
            "a ProductClosure consumes exactly one full-field key"
        );
        assert_eq!(
            role == CorrScheduleRole::ProductMask,
            product_triples > 0,
            "only a nonempty ProductClosure carries a triple count"
        );
        self.ledger.open(dom | FULL_BIT_SHADOW, n);
        self.counters.full_corrs += n as u64;
        self.counters.domains += 1;
        let keys = match &mut self.backend {
            VerifierBackend::Mock { seed, allocation } => {
                allocation.take_full(dom, n);
                let mut xs = FpStream::domain_separated(*seed, dom | FULL_BIT);
                let mut ms = FpStream::domain_separated(*seed, dom | FULL_BIT | TAG_BIT);
                (0..n).map(|_| ms.next_fp2() + self.delta * xs.next_fp2()).collect()
            }
            VerifierBackend::Pooled(v) => v.expand_full_keys(dom, n),
        };
        if let Some(audit) = &mut self.schedule_audit {
            audit.record(CorrScheduleKind::FullField, role, product_triples, dom, n);
        }
        #[cfg(feature = "c6-trace")]
        if self.c6_trace_sources_enabled {
            let tokens = self.allocate_c6_trace_sources(n);
            assert!(
                self.c6_trace_full_sources.insert(dom, tokens).is_none(),
                "duplicate C6 verifier full-field provenance domain {dom:#x}"
            );
        }
        keys
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

    /// Attach C6 plaintexts to a row drawn from this atomic reservation.
    pub fn record_c6_fullfield_plaintexts(
        &mut self,
        range: usize,
        row: usize,
        plaintexts: &[Fp2],
    ) -> Result<(), String> {
        let spec = *self
            .progress
            .ranges
            .get(range)
            .ok_or_else(|| "C6 full-field reservation range is out of bounds".to_owned())?;
        if row >= spec.rows {
            return Err("C6 full-field reservation row is out of bounds".to_owned());
        }
        self.stream.record_c6_fullfield_plaintexts(spec.domain(row), plaintexts)
    }

    /// Iterator twin for variable-width C6 reservation rows.
    pub fn record_c6_fullfield_plaintexts_iter<I>(
        &mut self,
        range: usize,
        row: usize,
        plaintexts: I,
    ) -> Result<(), String>
    where
        I: IntoIterator<Item = Fp2>,
    {
        let spec = *self
            .progress
            .ranges
            .get(range)
            .ok_or_else(|| "C6 full-field reservation range is out of bounds".to_owned())?;
        if row >= spec.rows {
            return Err("C6 full-field reservation row is out of bounds".to_owned());
        }
        self.stream.record_c6_fullfield_plaintexts_iter(spec.domain(row), plaintexts)
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

    pub fn expand(&mut self, range: usize, row: usize) -> Vec<VerifierKey> {
        let spec = self.progress.pending(range, row);
        let values =
            self.context.expand_full_verifier_keys(spec.domain(row), spec.count_per_domain);
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
    Mock { seed: [u8; 32], allocation: LogicalAllocation },
    Pooled(PooledProver),
}

enum VerifierBackend {
    Mock { seed: [u8; 32], allocation: LogicalAllocation },
    Pooled(PooledVerifier),
}

struct LogicalAllocation {
    next_sub: usize,
    next_full: usize,
    hasher: blake3::Hasher,
}

impl LogicalAllocation {
    fn new(scope: Option<ConnectionCorrelationScope>) -> Self {
        let mut hasher = blake3::Hasher::new();
        if let Some(scope) = scope {
            hasher.update(b"connection-scope");
            hasher.update(&scope.connection_id);
            hasher.update(&scope.response_nonce);
        }
        Self { next_sub: 0, next_full: 0, hasher }
    }

    fn take_sub(&mut self, dom: u64, n: usize) {
        record_alloc(&mut self.hasher, b"sub", dom, self.next_sub, n);
        self.next_sub = self.next_sub.checked_add(n).expect("logical sub allocation overflow");
    }

    fn take_full(&mut self, dom: u64, n: usize) {
        record_alloc(&mut self.hasher, b"full", dom, self.next_full, n);
        self.next_full = self.next_full.checked_add(n).expect("logical full allocation overflow");
    }

    fn digest_hex(&self) -> String {
        self.hasher.clone().finalize().to_hex().to_string()
    }
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
    fn new(pool: ProverPcgPool, scope: Option<ConnectionCorrelationScope>) -> PooledProver {
        let hasher = LogicalAllocation::new(scope).hasher;
        PooledProver {
            subs: pool.subs,
            fulls: pool.fulls,
            next_sub: 0,
            next_full: 0,
            sub_domains: HashMap::new(),
            hasher,
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

    fn replay_sub_masks(&self, dom: u64, n: usize) -> Vec<Fp> {
        let Some((off, drawn)) = self.sub_domains.get(&dom).copied() else {
            panic!("pooled mask replay before source consumption at {dom:#x}");
        };
        assert_eq!(drawn, n, "pooled mask replay length mismatch at {dom:#x}");
        self.subs[off..off + n].iter().map(|sub| sub.r).collect()
    }

    fn draw_fulls(&mut self, dom: u64, n: usize) -> Vec<FullCorr> {
        self.assert_full_capacity(n);
        let off = self.next_full;
        self.next_full += n;
        record_alloc(&mut self.hasher, b"full", dom, off, n);
        self.fulls[off..off + n]
            .iter()
            .map(|f| FullCorr::new(f.x, f.m, C6TraceToken::untracked()))
            .collect()
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
    sub_domains: HashMap<u64, (usize, usize)>,
    hasher: blake3::Hasher,
}

impl PooledVerifier {
    fn new(pool: VerifierPcgPool, scope: Option<ConnectionCorrelationScope>) -> PooledVerifier {
        let hasher = LogicalAllocation::new(scope).hasher;
        PooledVerifier {
            sub_keys: pool.sub_keys,
            full_keys: pool.full_keys,
            next_sub: 0,
            next_full: 0,
            sub_domains: HashMap::new(),
            hasher,
        }
    }

    fn assert_sub_capacity(&self, n: usize) {
        assert!(n <= self.sub_keys.len().saturating_sub(self.next_sub), "pooled sub-key underflow");
    }

    fn reserve_sub_key_rows(&mut self, base_domain: u64, rows: usize, cols: usize) {
        let total = rows.checked_mul(cols).expect("validated pooled sub-key geometry overflow");
        self.assert_sub_capacity(total);
        for row in 0..rows {
            let domain = base_domain + row as u64;
            let off = self.next_sub;
            self.next_sub += cols;
            let previous = self.sub_domains.insert(domain, (off, cols));
            assert!(previous.is_none(), "pooled verifier sub domain {domain:#x} allocated twice");
            record_alloc(&mut self.hasher, b"sub", domain, off, cols);
        }
    }

    fn replay_sub_keys(&self, dom: u64, n: usize) -> Vec<Fp2> {
        let Some((off, drawn)) = self.sub_domains.get(&dom).copied() else {
            panic!("pooled key replay before source reservation at {dom:#x}");
        };
        assert_eq!(drawn, n, "pooled key replay length mismatch at {dom:#x}");
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

    #[cfg(not(feature = "c6-trace"))]
    #[test]
    fn ordinary_correlation_layouts_remain_pinned() {
        assert_eq!(std::mem::size_of::<SubCorr>(), 24);
        assert_eq!(std::mem::size_of::<FullCorr>(), 32);
    }

    #[cfg(feature = "c6-trace")]
    #[test]
    fn operation_trace_sources_follow_interleaved_draw_order() {
        let _trace_guard = crate::C6_OPERATION_TRACE_TEST_LOCK.lock().unwrap();
        crate::c6_trace::begin_c6_prover_trace().unwrap();
        let mut stream = CorrelationStream::new([0xA6; 32]);
        stream.enable_c6_operation_trace().unwrap();
        let subs = stream.draw_subs(0x10, 2);
        let full = stream.draw_fulls(0x20, 1)[0];
        let product = stream.draw_product_mask(0x30, 1);
        assert_eq!(subs[0].c6_trace_token().source_index(), Some(0));
        assert_eq!(subs[1].c6_trace_token().source_index(), Some(1));
        assert_eq!(full.c6_trace_token().source_index(), Some(2));
        assert_eq!(product.c6_trace_token().source_index(), Some(3));
        let value = full.authenticate(Fp2::ONE);
        crate::c6_trace::record_c6_product_closure(
            &[[value.c6_trace_token(), value.c6_trace_token(), value.c6_trace_token()]],
            product.c6_trace_token(),
        )
        .unwrap();
        let snapshot = crate::c6_trace::finish_c6_prover_trace().unwrap();
        assert_eq!(snapshot.source_count, 4);
        assert_eq!(snapshot.products.len(), 1);
    }

    #[test]
    fn corr_index_matches_p1_packing() {
        let idx = CorrIndex { session: 0, layer: 0, head: 0, tensor: 3, row: 5 };
        assert_eq!(idx.domain(), (3u64 << 32) | 5); // P1 epilogue: (tensor_tag<<32)|row
    }

    #[test]
    fn optional_schedule_audit_is_canonical_and_role_symmetric() {
        let seed = [0xA6; 32];
        let delta = Fp2::new(Fp::new(17), Fp::new(23));
        let mut prover = CorrelationStream::new(seed);
        let mut verifier = VerifierCtx::new(seed, delta);
        assert!(prover.schedule_audit().is_none());
        assert!(verifier.schedule_audit().is_none());
        prover.enable_schedule_audit().unwrap();
        verifier.enable_schedule_audit().unwrap();

        let _ = prover.draw_subs(10, 2);
        let _ = verifier.expand_sub_keys(10, 2);
        let _ = prover.reserve_sub_mask_rows(20, 2, 3);
        let _ = verifier.expand_sub_keys(20, 3);
        let _ = verifier.expand_sub_keys(21, 3);
        let _ = prover.draw_fulls(30, 2);
        let _ = verifier.expand_full_keys(30, 2);
        let _ = prover.draw_product_mask(40, 7);
        let _ = verifier.expand_product_mask_key(40, 7);

        let prover_audit = prover.schedule_audit().unwrap();
        let verifier_audit = verifier.schedule_audit().unwrap();
        assert_eq!(prover_audit, verifier_audit);
        assert!(prover_audit.is_canonical());
        assert_eq!(prover_audit.counters, CorrCounters { sub_corrs: 8, full_corrs: 3, domains: 5 });
        assert_eq!(
            prover_audit.draws,
            vec![
                CorrScheduleDraw {
                    ordinal: 0,
                    kind: CorrScheduleKind::Subfield,
                    role: CorrScheduleRole::DirectCorrection,
                    product_triples: 0,
                    domain: 10,
                    global_offset: 0,
                    count: 2,
                },
                CorrScheduleDraw {
                    ordinal: 1,
                    kind: CorrScheduleKind::Subfield,
                    role: CorrScheduleRole::DirectCorrection,
                    product_triples: 0,
                    domain: 20,
                    global_offset: 2,
                    count: 3,
                },
                CorrScheduleDraw {
                    ordinal: 2,
                    kind: CorrScheduleKind::Subfield,
                    role: CorrScheduleRole::DirectCorrection,
                    product_triples: 0,
                    domain: 21,
                    global_offset: 5,
                    count: 3,
                },
                CorrScheduleDraw {
                    ordinal: 3,
                    kind: CorrScheduleKind::FullField,
                    role: CorrScheduleRole::DirectCorrection,
                    product_triples: 0,
                    domain: 30,
                    global_offset: 0,
                    count: 2,
                },
                CorrScheduleDraw {
                    ordinal: 4,
                    kind: CorrScheduleKind::FullField,
                    role: CorrScheduleRole::ProductMask,
                    product_triples: 7,
                    domain: 40,
                    global_offset: 2,
                    count: 1,
                },
            ]
        );
        assert_eq!(prover_audit.digest, prover.schedule_audit().unwrap().digest);
        let mut noncanonical = prover_audit.clone();
        noncanonical.draws.swap(0, 1);
        assert!(!noncanonical.is_canonical());
        assert!(prover.enable_schedule_audit().is_err());
        assert!(verifier.enable_schedule_audit().is_err());
    }

    #[test]
    fn c6_subfield_witness_sidecar_is_exact_opt_in_and_fail_closed() {
        let mut prover = CorrelationStream::new([0xC6; 32]);
        prover.enable_c6_subfield_witness_collection().unwrap();

        let first = prover.draw_subs(10, 2);
        let first_corrections = [5, 6];
        prover.record_c6_subfield_corrections(10, &first_corrections).unwrap();
        let second_masks = prover.draw_sub_masks(20, 3);
        let second_corrections = [7, 8, 9];
        prover.record_c6_subfield_corrections(20, &second_corrections).unwrap();
        let second_tags = prover.draw_sub_tags(20, 3);
        assert_eq!(second_tags, prover.draw_sub_tags(20, 3));
        let _ = prover.draw_fulls(30, 2);

        let schedule = prover.schedule_audit().unwrap();
        let witness = prover.finish_c6_subfield_witness_collection().unwrap();
        witness.validate_against(&schedule).unwrap();
        assert_eq!(witness.len(), 5);
        assert_eq!(witness.draws().len(), 2);
        assert_eq!(
            witness.corrections().iter().map(|value| value.value()).collect::<Vec<_>>(),
            [5, 6, 7, 8, 9]
        );
        assert_eq!(witness.tags()[..2], [first[0].m, first[1].m]);
        assert_eq!(witness.tags()[2..], second_tags);
        for index in 0..2 {
            assert_eq!(
                witness.plaintext(index),
                Some(first[index].r + Fp::new(first_corrections[index]))
            );
        }
        for index in 0..3 {
            assert_eq!(
                witness.plaintext(2 + index),
                Some(second_masks[index] + Fp::new(second_corrections[index]))
            );
        }

        let mut changed = witness.clone();
        changed.corrections[0] += Fp::ONE;
        assert!(changed.validate_against(&schedule).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prover.draw_sub_masks(40, 1);
        }))
        .is_err());

        let mut lazy_tags = CorrelationStream::new([0xC7; 32]);
        lazy_tags.enable_c6_subfield_witness_collection().unwrap();
        let _ = lazy_tags.draw_sub_masks(50, 1);
        lazy_tags.record_c6_subfield_corrections(50, &[1]).unwrap();
        let lazy_witness = lazy_tags.finish_c6_subfield_witness_collection().unwrap();
        assert_ne!(lazy_witness.tags(), &[Fp2::ZERO]);

        let mut incomplete = CorrelationStream::new([0xC8; 32]);
        incomplete.enable_c6_subfield_witness_collection().unwrap();
        let _ = incomplete.draw_sub_masks(51, 1);
        let error = incomplete.finish_c6_subfield_witness_collection().unwrap_err();
        assert!(error.contains("lacks its hidden corrections"));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = incomplete.draw_sub_masks(52, 1);
        }))
        .is_err());
    }

    #[test]
    fn c6_fullfield_witness_sidecar_types_direct_and_product_sources() {
        let mut prover = CorrelationStream::new([0xD6; 32]);
        prover.enable_c6_source_witness_collection().unwrap();

        let sub = prover.draw_subs(10, 1);
        prover.record_c6_subfield_corrections(10, &[3]).unwrap();
        let direct = prover.draw_fulls(20, 2);
        let direct_corrections = [Fp2::from_base(Fp::new(5)), Fp2::from_base(Fp::new(7))];
        prover.record_c6_fullfield_corrections(20, &direct_corrections).unwrap();
        let product = prover.draw_product_mask(30, 11);
        assert!(prover.record_c6_fullfield_corrections(30, &[Fp2::ZERO]).is_err());

        let schedule = prover.schedule_audit().unwrap();
        let subfield = prover.finish_c6_subfield_witness_collection().unwrap();
        let fullfield = prover.finish_c6_fullfield_witness_collection().unwrap();
        subfield.validate_against(&schedule).unwrap();
        fullfield.validate_against(&schedule).unwrap();
        assert_eq!(subfield.tags(), &[sub[0].m]);
        assert_eq!(fullfield.len(), 3);
        assert_eq!(fullfield.draws().len(), 2);
        assert_eq!(fullfield.draws()[0].role, CorrScheduleRole::DirectCorrection);
        assert_eq!(fullfield.draws()[1].role, CorrScheduleRole::ProductMask);
        assert_eq!(fullfield.draws()[1].product_triples, 11);
        assert_eq!(fullfield.plaintext(0), Some(direct[0].x + direct_corrections[0]));
        assert_eq!(fullfield.plaintext(1), Some(direct[1].x + direct_corrections[1]));
        assert_eq!(fullfield.plaintext(2), Some(product.plaintext()));
        assert_eq!(fullfield.tags()[2], product.tag());
        assert_eq!(fullfield.corrections()[2], Fp2::ZERO);

        let mut changed = fullfield.clone();
        changed.corrections[0] += Fp2::ONE;
        assert!(changed.validate_against(&schedule).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = prover.draw_fulls(40, 1);
        }))
        .is_err());

        let mut incomplete = CorrelationStream::new([0xD7; 32]);
        incomplete.enable_c6_source_witness_collection().unwrap();
        let _ = incomplete.draw_fulls(50, 1);
        let error = incomplete.finish_c6_fullfield_witness_collection().unwrap_err();
        assert!(error.contains("lacks its hidden corrections"));
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
    fn connection_scoped_mock_and_real_logical_allocations_match() {
        let seed = [0xC1; 32];
        let delta = Fp2::new(Fp::new(0x1234), Fp::new(0x5678));
        let scope = ConnectionCorrelationScope::new([0xC2; 32], [0xC3; 32]);
        let params = volta_pcg::PhaseAParams::tiny_for_test(9 + 2 * 3);
        let pool = volta_pcg::expand_phase_a(seed, delta, 9, 3, params);
        let mut mock_p = CorrelationStream::new_connection_mock(seed, scope);
        let mut mock_v = VerifierCtx::new_connection_mock(seed, delta, scope);
        let mut real_p = CorrelationStream::from_pcg_pool_connection(pool.prover, scope);
        let mut real_v = VerifierCtx::from_pcg_pool_connection(delta, pool.verifier, scope);
        assert!(!mock_p.uses_pooled_pcg());
        assert!(!mock_v.uses_pooled_pcg());
        assert!(real_p.uses_pooled_pcg());
        assert!(real_v.uses_pooled_pcg());

        for (domain, count) in [(0x10, 5), (0x11, 4)] {
            let _ = mock_p.draw_subs(domain, count);
            let _ = mock_v.expand_sub_keys(domain, count);
            let _ = real_p.draw_subs(domain, count);
            let _ = real_v.expand_sub_keys(domain, count);
        }
        for (domain, count) in [(0x20, 2), (0x21, 1)] {
            let _ = mock_p.draw_fulls(domain, count);
            let _ = mock_v.expand_full_keys(domain, count);
            let _ = real_p.draw_fulls(domain, count);
            let _ = real_v.expand_full_keys(domain, count);
        }
        assert_eq!(mock_p.counters, real_p.counters);
        assert_eq!(mock_v.counters, real_v.counters);
        assert_eq!(mock_p.allocation_digest_hex(), mock_v.allocation_digest_hex());
        assert_eq!(real_p.allocation_digest_hex(), real_v.allocation_digest_hex());
        assert_eq!(mock_p.allocation_digest_hex(), real_p.allocation_digest_hex());
    }

    #[test]
    fn connection_response_nonce_changes_mock_correlations_and_digest() {
        let seed = [0xD1; 32];
        let scope_one = ConnectionCorrelationScope::new([0xD2; 32], [0xD3; 32]);
        let scope_two = ConnectionCorrelationScope::new([0xD2; 32], [0xD4; 32]);
        let mut first = CorrelationStream::new_connection_mock(seed, scope_one);
        let mut second = CorrelationStream::new_connection_mock(seed, scope_two);
        assert_ne!(first.draw_subs(0x55, 4)[0].r, second.draw_subs(0x55, 4)[0].r);
        assert_ne!(first.allocation_digest_hex(), second.allocation_digest_hex());
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
    fn consumed_mask_replay_is_byte_exact_and_counter_neutral() {
        let mut stream = CorrelationStream::new([0x35; 32]);
        stream.enable_schedule_audit().unwrap();
        let masks = stream.draw_sub_masks(0x3500, 17);
        let counters = stream.counters;
        let schedule = stream.schedule_audit().unwrap();
        let allocation = stream.allocation_digest_hex();
        assert_eq!(stream.replay_consumed_sub_masks(0x3500, 17), masks);
        assert_eq!(stream.replay_consumed_sub_masks(0x3500, 17), masks);
        assert_eq!(stream.counters, counters);
        assert_eq!(stream.schedule_audit().unwrap(), schedule);
        assert_eq!(stream.allocation_digest_hex(), allocation);

        let delta = Fp2::new(Fp::new(0x351), Fp::new(0x352));
        let mut verifier = VerifierCtx::new([0x35; 32], delta);
        verifier.enable_schedule_audit().unwrap();
        verifier.reserve_sub_key_rows(0x3500, 1, 17);
        let verifier_counters = verifier.counters;
        let verifier_schedule = verifier.schedule_audit().unwrap();
        let verifier_allocation = verifier.allocation_digest_hex();
        let keys = verifier.replay_consumed_sub_keys(0x3500, 17);
        assert_eq!(verifier.replay_consumed_sub_keys(0x3500, 17), keys);
        assert_eq!(verifier.counters, verifier_counters);
        assert_eq!(verifier.schedule_audit().unwrap(), verifier_schedule);
        assert_eq!(verifier.allocation_digest_hex(), verifier_allocation);
    }

    #[test]
    fn pooled_reserved_key_rows_preserve_eager_allocation_order() {
        let seed = [0x36; 32];
        let delta = Fp2::new(Fp::new(0x361), Fp::new(0x362));
        let (base_domain, rows, cols) = (0x3600, 2usize, 3usize);
        let later_domain = 0x3700;
        let later_count = 4usize;
        let total = rows * cols + later_count;
        let params = volta_pcg::PhaseAParams::tiny_for_test(total);
        let eager_pool = volta_pcg::expand_phase_a(seed, delta, total, 0, params.clone());
        let reserved_pool = volta_pcg::expand_phase_a(seed, delta, total, 0, params);
        let mut eager = VerifierCtx::from_pcg_pool(delta, eager_pool.verifier);
        let mut reserved = VerifierCtx::from_pcg_pool(delta, reserved_pool.verifier);
        eager.enable_schedule_audit().unwrap();
        reserved.enable_schedule_audit().unwrap();

        let eager_rows = (0..rows)
            .map(|row| eager.expand_sub_keys(base_domain + row as u64, cols))
            .collect::<Vec<_>>();
        let eager_later = eager.expand_sub_keys(later_domain, later_count);

        reserved.reserve_sub_key_rows(base_domain, rows, cols);
        let reserved_later = reserved.expand_sub_keys(later_domain, later_count);
        let before_replay = (
            reserved.counters,
            reserved.schedule_audit().unwrap(),
            reserved.allocation_digest_hex(),
        );
        let reserved_rows = (0..rows)
            .map(|row| reserved.replay_consumed_sub_keys(base_domain + row as u64, cols))
            .collect::<Vec<_>>();

        assert_eq!(reserved_rows, eager_rows);
        assert_eq!(reserved_later, eager_later);
        assert_eq!(reserved.counters, eager.counters);
        assert_eq!(reserved.schedule_audit().unwrap(), eager.schedule_audit().unwrap());
        assert_eq!(reserved.allocation_digest_hex(), eager.allocation_digest_hex());
        assert_eq!(
            (
                reserved.counters,
                reserved.schedule_audit().unwrap(),
                reserved.allocation_digest_hex(),
            ),
            before_replay,
        );
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
        let counters = prover.counters;
        let allocation = prover.allocation_digest_hex();
        for row in 0..rows {
            assert_eq!(
                prover.replay_consumed_sub_masks(base_domain + row as u64, cols),
                masks[row * cols..(row + 1) * cols],
            );
        }
        assert_eq!(prover.counters, counters);
        assert_eq!(prover.allocation_digest_hex(), allocation);
        for row in 0..rows {
            let tags = prover.draw_sub_tags(base_domain + row as u64, cols);
            let keys = verifier.expand_sub_keys(base_domain + row as u64, cols);
            let counters = verifier.counters;
            let allocation = verifier.allocation_digest_hex();
            assert_eq!(verifier.replay_consumed_sub_keys(base_domain + row as u64, cols), keys);
            assert_eq!(verifier.counters, counters);
            assert_eq!(verifier.allocation_digest_hex(), allocation);
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
            assert_eq!(key.k, full.m + delta * full.x);
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
