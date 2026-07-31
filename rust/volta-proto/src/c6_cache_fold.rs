//! Diagnostic C6 recorder for the final authenticated K/V cache functionals.
//!
//! This module is compiled only with `c6-trace`.  It observes the exact
//! bilinear functional that the attention proof hands to the chained GEMM:
//! one public weight vector over cache rows, one over a 64-column head
//! window, and one authenticated target.  It never reconstructs a verifier
//! key from plaintext, never serializes a cache vector, and earns no wire or
//! timing credit.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use volta_field::Fp2;
use volta_mac::{C6TraceToken, ProverAuthed, VerifierKey};

pub const C6_CACHE_FOLD_TRACE_VERSION: u32 = 1;
pub const C6_CACHE_FOLD_SCALAR_BATCH_VERSION: u32 = 1;
pub const C6_CACHE_FOLD_MAX_RECORDS: usize = 576;
pub const C6_CACHE_FOLD_MAX_FACTOR_VALUES: u64 =
    C6_CACHE_FOLD_MAX_RECORDS as u64 * (C6_CACHE_MAX_CONTEXT as u64 + C6_CACHE_HEAD_WIDTH as u64);

const C6_CACHE_HEADS: usize = 12;
const C6_CACHE_HEAD_WIDTH: usize = 64;
const C6_CACHE_MODEL_LAYERS: u16 = 12;
const C6_CACHE_DECODE_SECTION_BASE: u16 = 16;
const C6_CACHE_MAX_CONTEXT: usize = 1024;
const C6_CACHE_HEAD_MASK: u16 = (1u16 << C6_CACHE_HEADS) - 1;

const C6_CACHE_FOLD_RECORD_TOPOLOGY_DOMAIN: &str = "volta/proto/c6/cache-fold-record-topology/v1";
const C6_CACHE_FOLD_RECORD_INSTANCE_DOMAIN: &str = "volta/proto/c6/cache-fold-record-instance/v1";
const C6_CACHE_FOLD_TOPOLOGY_DOMAIN: &str = "volta/proto/c6/cache-fold-topology/v1";
const C6_CACHE_FOLD_INSTANCE_DOMAIN: &str = "volta/proto/c6/cache-fold-instance/v1";
const C6_CACHE_FOLD_SCALAR_BATCH_DOMAIN: &str = "volta/proto/c6/cache-fold-scalar-batch/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTraceError(String);

impl C6CacheFoldTraceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for C6CacheFoldTraceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for C6CacheFoldTraceError {}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6CacheFoldParty {
    Prover = 1,
    Verifier = 2,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum C6CacheFoldKind {
    ValueColumns = 1,
    KeyRows = 2,
}

/// Role-typed authenticated target handed from the model proof to the cache
/// relation.  The scalar-batch identity deliberately excludes its MAC
/// payload; prover and verifier bind the same coefficient schedule while
/// retaining their different authenticated representations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C6CacheFoldAuthenticatedTarget {
    Prover(ProverAuthed),
    Verifier(VerifierKey),
}

impl C6CacheFoldAuthenticatedTarget {
    pub fn party(self) -> C6CacheFoldParty {
        match self {
            Self::Prover(_) => C6CacheFoldParty::Prover,
            Self::Verifier(_) => C6CacheFoldParty::Verifier,
        }
    }

    pub fn trace_token(self) -> C6TraceToken {
        match self {
            Self::Prover(value) => value.c6_trace_token(),
            Self::Verifier(key) => key.c6_trace_token(),
        }
    }

    pub fn prover(self) -> Option<ProverAuthed> {
        match self {
            Self::Prover(value) => Some(value),
            Self::Verifier(_) => None,
        }
    }

    pub fn verifier(self) -> Option<VerifierKey> {
        match self {
            Self::Verifier(key) => Some(key),
            Self::Prover(_) => None,
        }
    }
}

/// Response-specific descriptor of one final cache functional.
///
/// `topology_digest` excludes challenge values. `coefficient_digest` binds
/// both exact public weight vectors in canonical row-then-column order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldRecord {
    pub ordinal: u32,
    pub kind: C6CacheFoldKind,
    pub schedule_section: u16,
    pub model_layer: u16,
    pub t0: u32,
    pub q: u32,
    pub total_rows: u32,
    pub head: u16,
    pub column_offset: u32,
    pub column_width: u32,
    pub segment_rows: Vec<u32>,
    pub row_weight_count: u32,
    pub column_weight_count: u32,
    pub coefficient_applications: u64,
    pub topology_digest: [u8; 32],
    pub coefficient_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTraceIdentity {
    pub version: u32,
    pub fold_count: u32,
    pub coefficient_applications: u64,
    pub topology_digest: [u8; 32],
    pub instance_digest: [u8; 32],
}

/// Factorized public coefficient table for one observed cache functional.
/// Its outer product is embedded only in the record's layer/head window; no
/// `2^24` cache coefficient table is allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldFactors {
    row_weights: Vec<Fp2>,
    column_weights: Vec<Fp2>,
}

/// Completed role-local capture. Targets remain opaque provenance handles;
/// they do not participate in prover/verifier digest equality because the
/// two operation traces use distinct namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTraceSnapshot {
    pub party: C6CacheFoldParty,
    pub identity: C6CacheFoldTraceIdentity,
    pub records: Vec<C6CacheFoldRecord>,
    pub targets: Vec<C6CacheFoldAuthenticatedTarget>,
    pub factors: Vec<C6CacheFoldFactors>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldPairedProverTargets {
    pub identity: C6CacheFoldTraceIdentity,
    terms: Vec<(C6CacheFoldKind, [ProverAuthed; 2])>,
}

impl C6CacheFoldPairedProverTargets {
    pub fn pair(tapes: [&C6CacheFoldTraceSnapshot; 2]) -> Result<Self, C6CacheFoldTraceError> {
        validate_paired_schedules(tapes, C6CacheFoldParty::Prover)?;
        let mut terms = Vec::with_capacity(tapes[0].targets.len());
        for ((record, &left), &right) in
            tapes[0].records.iter().zip(&tapes[0].targets).zip(&tapes[1].targets)
        {
            let left = left.prover().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6 paired prover target has verifier role")
            })?;
            let right = right.prover().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6 paired prover target has verifier role")
            })?;
            if left.x != right.x {
                return Err(C6CacheFoldTraceError::new(
                    "C6 paired prover targets disagree on plaintext",
                ));
            }
            terms.push((record.kind, [left, right]));
        }
        Ok(Self { identity: tapes[0].identity, terms })
    }

    pub fn terms(&self) -> impl Iterator<Item = (C6CacheFoldKind, [ProverAuthed; 2])> + '_ {
        self.terms.iter().copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldPairedVerifierTargets {
    pub identity: C6CacheFoldTraceIdentity,
    terms: Vec<(C6CacheFoldKind, [VerifierKey; 2])>,
}

impl C6CacheFoldPairedVerifierTargets {
    pub fn pair(tapes: [&C6CacheFoldTraceSnapshot; 2]) -> Result<Self, C6CacheFoldTraceError> {
        validate_paired_schedules(tapes, C6CacheFoldParty::Verifier)?;
        let mut terms = Vec::with_capacity(tapes[0].targets.len());
        for ((record, &left), &right) in
            tapes[0].records.iter().zip(&tapes[0].targets).zip(&tapes[1].targets)
        {
            let left = left.verifier().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6 paired verifier target has prover role")
            })?;
            let right = right.verifier().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6 paired verifier target has prover role")
            })?;
            terms.push((record.kind, [left, right]));
        }
        Ok(Self { identity: tapes[0].identity, terms })
    }

    pub fn terms(&self) -> impl Iterator<Item = (C6CacheFoldKind, [VerifierKey; 2])> + '_ {
        self.terms.iter().copied()
    }
}

fn validate_paired_schedules(
    tapes: [&C6CacheFoldTraceSnapshot; 2],
    expected_party: C6CacheFoldParty,
) -> Result<(), C6CacheFoldTraceError> {
    if tapes.iter().any(|snapshot| snapshot.party != expected_party)
        || tapes[0].identity != tapes[1].identity
        || tapes[0].records != tapes[1].records
        || tapes[0].factors != tapes[1].factors
        || tapes.iter().any(|snapshot| {
            snapshot.records.len() != snapshot.targets.len()
                || snapshot.targets.iter().any(|target| target.party() != expected_party)
        })
    {
        return Err(C6CacheFoldTraceError::new(
            "C6 paired target tapes have different roles or public schedules",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheFoldScalarBatchIdentity {
    pub version: u32,
    pub fold_count: u32,
    pub factor_values: u64,
    pub coefficient_applications: u64,
    pub scalar_root: Fp2,
    pub topology_digest: [u8; 32],
    pub instance_digest: [u8; 32],
    pub batch_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct C6CacheFoldScalarBatchTerm {
    record: C6CacheFoldRecord,
    target: C6CacheFoldAuthenticatedTarget,
    factors: C6CacheFoldFactors,
    scalar_weight: Fp2,
}

/// One repetition's scalar-power batch over the exact runtime fold order.
/// The plan retains only row/column factors and opaque authenticated target
/// provenance.  It deliberately has no dense cache-coefficient field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldScalarBatchPlan {
    pub party: C6CacheFoldParty,
    pub identity: C6CacheFoldScalarBatchIdentity,
    terms: Vec<C6CacheFoldScalarBatchTerm>,
}

impl C6CacheFoldScalarBatchPlan {
    /// Evaluate the factorized coefficient of one live GPT-2 cache cell.
    /// This is a local reference query, not a materialization API.
    pub fn coefficient(
        &self,
        kind: C6CacheFoldKind,
        model_layer: usize,
        position: usize,
        channel: usize,
    ) -> Result<Fp2, C6CacheFoldTraceError> {
        if model_layer >= usize::from(C6_CACHE_MODEL_LAYERS)
            || position >= C6_CACHE_MAX_CONTEXT
            || channel >= C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH
        {
            return Err(C6CacheFoldTraceError::new(
                "C6 factorized coefficient query is outside live cache geometry",
            ));
        }
        Ok(self
            .terms
            .iter()
            .filter(|term| {
                term.record.kind == kind && usize::from(term.record.model_layer) == model_layer
            })
            .fold(Fp2::ZERO, |sum, term| {
                let column_start = term.record.column_offset as usize;
                if position >= term.factors.row_weights.len()
                    || channel < column_start
                    || channel >= column_start + term.factors.column_weights.len()
                {
                    return sum;
                }
                sum + term.scalar_weight
                    * term.factors.row_weights[position]
                    * term.factors.column_weights[channel - column_start]
            }))
    }

    pub fn target_terms(
        &self,
        kind: C6CacheFoldKind,
    ) -> impl Iterator<Item = (C6CacheFoldAuthenticatedTarget, Fp2)> + '_ {
        self.terms
            .iter()
            .filter(move |term| term.record.kind == kind)
            .map(|term| (term.target, term.scalar_weight))
    }

    /// Canonical global target order used by the successor scalar powers.
    pub fn ordered_target_terms(
        &self,
    ) -> impl Iterator<Item = (u32, C6CacheFoldKind, C6CacheFoldAuthenticatedTarget, Fp2)> + '_
    {
        self.terms
            .iter()
            .map(|term| (term.record.ordinal, term.record.kind, term.target, term.scalar_weight))
    }

    pub fn prover_target_aggregate(
        &self,
        kind: C6CacheFoldKind,
    ) -> Result<ProverAuthed, C6CacheFoldTraceError> {
        if self.party != C6CacheFoldParty::Prover {
            return Err(C6CacheFoldTraceError::new(
                "C6 scalar batch does not contain prover targets",
            ));
        }
        self.target_terms(kind).try_fold(ProverAuthed::ZERO, |sum, (target, weight)| {
            let value = target
                .prover()
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch mixed target roles"))?;
            Ok(sum.add(value.scale(weight)))
        })
    }

    pub fn verifier_target_aggregate(
        &self,
        kind: C6CacheFoldKind,
    ) -> Result<VerifierKey, C6CacheFoldTraceError> {
        if self.party != C6CacheFoldParty::Verifier {
            return Err(C6CacheFoldTraceError::new(
                "C6 scalar batch does not contain verifier targets",
            ));
        }
        self.target_terms(kind).try_fold(VerifierKey::ZERO, |sum, (target, weight)| {
            let key = target
                .verifier()
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch mixed target roles"))?;
            Ok(sum.add(key.scale(weight)))
        })
    }
}

#[derive(Debug)]
struct C6CacheFoldTraceRuntime {
    capture_id: u64,
    party: C6CacheFoldParty,
    records: Vec<C6CacheFoldRecord>,
    targets: Vec<C6CacheFoldAuthenticatedTarget>,
    factors: Vec<C6CacheFoldFactors>,
    semantic_keys: BTreeSet<(u16, u32, u32, C6CacheFoldKind, u16)>,
}

thread_local! {
    static C6_CACHE_FOLD_TRACE_RUNTIME: RefCell<Option<C6CacheFoldTraceRuntime>> =
        const { RefCell::new(None) };
    static C6_CACHE_FOLD_NEXT_CAPTURE_ID: Cell<u64> = const { Cell::new(1) };
}

/// Same-thread guard. Dropping an unfinished capture clears it, so a failed
/// diagnostic cannot contaminate a later proof on the worker thread.
pub struct C6CacheFoldTraceGuard {
    capture_id: u64,
    party: C6CacheFoldParty,
    finished: bool,
    _not_send: PhantomData<Rc<()>>,
}

impl C6CacheFoldTraceGuard {
    pub fn finish(mut self) -> Result<C6CacheFoldTraceSnapshot, C6CacheFoldTraceError> {
        let runtime = take_runtime(self.capture_id, self.party)?;
        self.finished = true;
        finish_runtime(runtime)
    }
}

impl Drop for C6CacheFoldTraceGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        C6_CACHE_FOLD_TRACE_RUNTIME.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut() {
                if slot.as_ref().is_some_and(|runtime| runtime.capture_id == self.capture_id) {
                    *slot = None;
                }
            }
        });
    }
}

pub fn begin_c6_cache_fold_trace(
    party: C6CacheFoldParty,
) -> Result<C6CacheFoldTraceGuard, C6CacheFoldTraceError> {
    let capture_id = C6_CACHE_FOLD_NEXT_CAPTURE_ID.with(|counter| {
        let current = counter.get();
        let next = current
            .checked_add(1)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold capture id exhausted"))?;
        counter.set(next);
        Ok(current)
    })?;
    C6_CACHE_FOLD_TRACE_RUNTIME.with(|cell| {
        let mut slot = cell
            .try_borrow_mut()
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold trace is borrowed"))?;
        if slot.is_some() {
            return Err(C6CacheFoldTraceError::new(
                "a C6 cache-fold trace is already active on this thread",
            ));
        }
        *slot = Some(C6CacheFoldTraceRuntime {
            capture_id,
            party,
            records: Vec::new(),
            targets: Vec::new(),
            factors: Vec::new(),
            semantic_keys: BTreeSet::new(),
        });
        Ok(C6CacheFoldTraceGuard { capture_id, party, finished: false, _not_send: PhantomData })
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_c6_cache_fold_if_active(
    kind: C6CacheFoldKind,
    schedule_section: u16,
    t0: usize,
    q: usize,
    segment_rows: &[usize],
    head: usize,
    column_offset: usize,
    row_weights: &[Fp2],
    column_weights: &[Fp2],
    target: C6CacheFoldAuthenticatedTarget,
) -> Result<(), C6CacheFoldTraceError> {
    C6_CACHE_FOLD_TRACE_RUNTIME.with(|cell| {
        let mut slot = cell
            .try_borrow_mut()
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold trace is borrowed"))?;
        let Some(runtime) = slot.as_mut() else {
            return Ok(());
        };
        if target.party() != runtime.party {
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold target role does not match the active capture",
            ));
        }
        let total_rows = t0
            .checked_add(q)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold row geometry overflows"))?;
        if q == 0 || total_rows > C6_CACHE_MAX_CONTEXT {
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold band is empty or exceeds the fixed context",
            ));
        }
        let model_layer = model_layer(schedule_section)?;
        if head >= C6_CACHE_HEADS
            || column_offset != head * C6_CACHE_HEAD_WIDTH
            || column_weights.len() != C6_CACHE_HEAD_WIDTH
            || row_weights.len() != total_rows
        {
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold head window or coefficient geometry is noncanonical",
            ));
        }
        if segment_rows.is_empty() || segment_rows.contains(&0) {
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold segments must be nonempty and positive",
            ));
        }
        let covered_rows = segment_rows.iter().try_fold(0usize, |sum, &rows| {
            sum.checked_add(rows)
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold segment sum overflows"))
        })?;
        if covered_rows != total_rows {
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold segments do not cover the public band cache",
            ));
        }

        let t0 = u32::try_from(t0)
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold t0 exceeds u32"))?;
        let q = u32::try_from(q)
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold q exceeds u32"))?;
        let total_rows = u32::try_from(total_rows)
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold rows exceed u32"))?;
        let head = u16::try_from(head)
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold head exceeds u16"))?;
        let column_offset = u32::try_from(column_offset)
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold column offset exceeds u32"))?;
        let row_weight_count = u32::try_from(row_weights.len())
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold row weights exceed u32"))?;
        let column_weight_count = u32::try_from(column_weights.len())
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold column weights exceed u32"))?;
        let coefficient_applications =
            u64::from(row_weight_count).checked_mul(u64::from(column_weight_count)).ok_or_else(
                || C6CacheFoldTraceError::new("C6 cache-fold coefficient applications overflow"),
            )?;
        let segment_rows: Vec<u32> = segment_rows
            .iter()
            .map(|&rows| {
                u32::try_from(rows)
                    .map_err(|_| C6CacheFoldTraceError::new("C6 cache segment exceeds u32"))
            })
            .collect::<Result<_, _>>()?;
        let semantic_key = (schedule_section, t0, q, kind, head);
        if !runtime.semantic_keys.insert(semantic_key) {
            return Err(C6CacheFoldTraceError::new("duplicate C6 cache-fold semantic identity"));
        }
        let ordinal = u32::try_from(runtime.records.len())
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold count exceeds u32"))?;
        let topology_digest = record_topology_digest(
            ordinal,
            kind,
            schedule_section,
            model_layer,
            t0,
            q,
            total_rows,
            head,
            column_offset,
            &segment_rows,
            row_weight_count,
            column_weight_count,
            coefficient_applications,
        );
        let coefficient_digest =
            record_coefficient_digest(topology_digest, row_weights, column_weights);
        runtime.records.push(C6CacheFoldRecord {
            ordinal,
            kind,
            schedule_section,
            model_layer,
            t0,
            q,
            total_rows,
            head,
            column_offset,
            column_width: C6_CACHE_HEAD_WIDTH as u32,
            segment_rows,
            row_weight_count,
            column_weight_count,
            coefficient_applications,
            topology_digest,
            coefficient_digest,
        });
        runtime.targets.push(target);
        runtime.factors.push(C6CacheFoldFactors {
            row_weights: row_weights.to_vec(),
            column_weights: column_weights.to_vec(),
        });
        Ok(())
    })
}

fn model_layer(schedule_section: u16) -> Result<u16, C6CacheFoldTraceError> {
    if schedule_section < C6_CACHE_MODEL_LAYERS {
        return Ok(schedule_section);
    }
    let decode_end = C6_CACHE_DECODE_SECTION_BASE + C6_CACHE_MODEL_LAYERS;
    if (C6_CACHE_DECODE_SECTION_BASE..decode_end).contains(&schedule_section) {
        return Ok(schedule_section - C6_CACHE_DECODE_SECTION_BASE);
    }
    Err(C6CacheFoldTraceError::new(
        "C6 cache-fold schedule section is not a GPT-2 prefill/decode layer",
    ))
}

fn take_runtime(
    capture_id: u64,
    party: C6CacheFoldParty,
) -> Result<C6CacheFoldTraceRuntime, C6CacheFoldTraceError> {
    C6_CACHE_FOLD_TRACE_RUNTIME.with(|cell| {
        let mut slot = cell
            .try_borrow_mut()
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold trace is borrowed"))?;
        let runtime = slot
            .take()
            .ok_or_else(|| C6CacheFoldTraceError::new("no C6 cache-fold trace is active"))?;
        if runtime.capture_id != capture_id || runtime.party != party {
            *slot = Some(runtime);
            return Err(C6CacheFoldTraceError::new(
                "C6 cache-fold capture guard does not own the active trace",
            ));
        }
        Ok(runtime)
    })
}

fn finish_runtime(
    runtime: C6CacheFoldTraceRuntime,
) -> Result<C6CacheFoldTraceSnapshot, C6CacheFoldTraceError> {
    if runtime.records.is_empty()
        || runtime.records.len() != runtime.targets.len()
        || runtime.records.len() != runtime.factors.len()
        || runtime.records.len() > C6_CACHE_FOLD_MAX_RECORDS
    {
        return Err(C6CacheFoldTraceError::new(
            "C6 cache-fold trace is empty, oversized or has a sidecar-count mismatch",
        ));
    }
    let factor_values = runtime.factors.iter().try_fold(0u64, |sum, factors| {
        let count = factors
            .row_weights
            .len()
            .checked_add(factors.column_weights.len())
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold factor census overflows"))?;
        sum.checked_add(count)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold factor census overflows"))
    })?;
    if factor_values > C6_CACHE_FOLD_MAX_FACTOR_VALUES {
        return Err(C6CacheFoldTraceError::new(
            "C6 cache-fold factor census exceeds the fixed two-band cap",
        ));
    }
    let mut head_masks: BTreeMap<(u16, u32, u32, C6CacheFoldKind), u16> = BTreeMap::new();
    let mut kind_masks: BTreeMap<(u16, u32, u32), u8> = BTreeMap::new();
    for record in &runtime.records {
        let mask = head_masks
            .entry((record.schedule_section, record.t0, record.q, record.kind))
            .or_default();
        *mask |= 1u16 << record.head;
        let kinds = kind_masks.entry((record.schedule_section, record.t0, record.q)).or_default();
        *kinds |= record.kind as u8;
    }
    if head_masks.values().any(|&mask| mask != C6_CACHE_HEAD_MASK) {
        return Err(C6CacheFoldTraceError::new(
            "C6 cache-fold layer/band cohort does not contain exactly all 12 heads",
        ));
    }
    if kind_masks.values().any(|&mask| mask != 3) {
        return Err(C6CacheFoldTraceError::new(
            "C6 cache-fold layer/band cohort is missing its K or V family",
        ));
    }

    let fold_count = u32::try_from(runtime.records.len())
        .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold count exceeds u32"))?;
    let coefficient_applications = runtime.records.iter().try_fold(0u64, |sum, record| {
        sum.checked_add(record.coefficient_applications)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 cache-fold application census overflows"))
    })?;
    let mut topology_hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_TOPOLOGY_DOMAIN);
    topology_hasher.update(&C6_CACHE_FOLD_TRACE_VERSION.to_le_bytes());
    topology_hasher.update(&fold_count.to_le_bytes());
    topology_hasher.update(&coefficient_applications.to_le_bytes());
    for record in &runtime.records {
        topology_hasher.update(&record.topology_digest);
    }
    let topology_digest = *topology_hasher.finalize().as_bytes();
    let mut instance_hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_INSTANCE_DOMAIN);
    instance_hasher.update(&C6_CACHE_FOLD_TRACE_VERSION.to_le_bytes());
    instance_hasher.update(&topology_digest);
    for record in &runtime.records {
        instance_hasher.update(&record.coefficient_digest);
    }
    let instance_digest = *instance_hasher.finalize().as_bytes();
    Ok(C6CacheFoldTraceSnapshot {
        party: runtime.party,
        identity: C6CacheFoldTraceIdentity {
            version: C6_CACHE_FOLD_TRACE_VERSION,
            fold_count,
            coefficient_applications,
            topology_digest,
            instance_digest,
        },
        records: runtime.records,
        targets: runtime.targets,
        factors: runtime.factors,
    })
}

/// Compile one independently challenged cache repetition without expanding a
/// dense coefficient table.  Powers use the global canonical record ordinal,
/// so K/V records cannot be reordered or independently renumbered.
pub fn compile_c6_cache_fold_scalar_batch(
    snapshot: &C6CacheFoldTraceSnapshot,
    scalar_root: Fp2,
) -> Result<C6CacheFoldScalarBatchPlan, C6CacheFoldTraceError> {
    let count = snapshot.records.len();
    if snapshot.identity.version != C6_CACHE_FOLD_TRACE_VERSION
        || count == 0
        || count > C6_CACHE_FOLD_MAX_RECORDS
        || count != snapshot.targets.len()
        || count != snapshot.factors.len()
        || snapshot.identity.fold_count as usize != count
        || snapshot.targets.iter().any(|target| target.party() != snapshot.party)
    {
        return Err(C6CacheFoldTraceError::new(
            "C6 scalar batch input has a noncanonical sidecar census",
        ));
    }
    let mut factor_values = 0u64;
    let mut coefficient_applications = 0u64;
    let mut semantic_keys = BTreeSet::new();
    let mut head_masks: BTreeMap<(u16, u32, u32, C6CacheFoldKind), u16> = BTreeMap::new();
    let mut kind_masks: BTreeMap<(u16, u32, u32), u8> = BTreeMap::new();
    let mut topology_hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_TOPOLOGY_DOMAIN);
    topology_hasher.update(&C6_CACHE_FOLD_TRACE_VERSION.to_le_bytes());
    topology_hasher.update(&snapshot.identity.fold_count.to_le_bytes());
    topology_hasher.update(&snapshot.identity.coefficient_applications.to_le_bytes());
    let mut instance_hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_INSTANCE_DOMAIN);
    let mut power = scalar_root;
    let mut terms = Vec::with_capacity(count);
    let mut hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_SCALAR_BATCH_DOMAIN);
    hasher.update(&C6_CACHE_FOLD_SCALAR_BATCH_VERSION.to_le_bytes());
    hasher.update(&snapshot.identity.fold_count.to_le_bytes());
    hasher.update(&snapshot.identity.coefficient_applications.to_le_bytes());
    hasher.update(&snapshot.identity.topology_digest);
    hasher.update(&snapshot.identity.instance_digest);
    hash_fp2(&mut hasher, scalar_root);
    for (index, ((record, &target), factors)) in
        snapshot.records.iter().zip(&snapshot.targets).zip(&snapshot.factors).enumerate()
    {
        let expected_layer = model_layer(record.schedule_section)?;
        let expected_total_rows = record
            .t0
            .checked_add(record.q)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch row geometry overflows"))?;
        let covered_rows = record.segment_rows.iter().try_fold(0u32, |sum, &rows| {
            if rows == 0 {
                return Err(C6CacheFoldTraceError::new(
                    "C6 scalar batch has an empty cache segment",
                ));
            }
            sum.checked_add(rows)
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch segment sum overflows"))
        })?;
        let semantic_key = (record.schedule_section, record.t0, record.q, record.kind, record.head);
        if record.ordinal as usize != index
            || expected_layer != record.model_layer
            || record.q == 0
            || expected_total_rows != record.total_rows
            || record.total_rows as usize > C6_CACHE_MAX_CONTEXT
            || covered_rows != record.total_rows
            || usize::from(record.head) >= C6_CACHE_HEADS
            || record.column_offset as usize != usize::from(record.head) * C6_CACHE_HEAD_WIDTH
            || record.column_width as usize != C6_CACHE_HEAD_WIDTH
            || record.row_weight_count != record.total_rows
            || record.column_weight_count as usize != C6_CACHE_HEAD_WIDTH
            || record.row_weight_count as usize != factors.row_weights.len()
            || record.column_weight_count as usize != factors.column_weights.len()
            || record.coefficient_applications
                != u64::from(record.row_weight_count) * u64::from(record.column_weight_count)
            || !semantic_keys.insert(semantic_key)
            || record_topology_digest(
                record.ordinal,
                record.kind,
                record.schedule_section,
                record.model_layer,
                record.t0,
                record.q,
                record.total_rows,
                record.head,
                record.column_offset,
                &record.segment_rows,
                record.row_weight_count,
                record.column_weight_count,
                record.coefficient_applications,
            ) != record.topology_digest
            || record_coefficient_digest(
                record.topology_digest,
                &factors.row_weights,
                &factors.column_weights,
            ) != record.coefficient_digest
        {
            return Err(C6CacheFoldTraceError::new(
                "C6 scalar batch record or factor binding is noncanonical",
            ));
        }
        let head_bit = 1u16 << record.head;
        let mask = head_masks
            .entry((record.schedule_section, record.t0, record.q, record.kind))
            .or_default();
        if *mask & head_bit != 0 {
            return Err(C6CacheFoldTraceError::new("C6 scalar batch repeats a cache-fold head"));
        }
        *mask |= head_bit;
        *kind_masks.entry((record.schedule_section, record.t0, record.q)).or_default() |=
            record.kind as u8;
        let values = u64::from(record.row_weight_count)
            .checked_add(u64::from(record.column_weight_count))
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch factor census overflows"))?;
        factor_values = factor_values
            .checked_add(values)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 scalar batch factor census overflows"))?;
        coefficient_applications =
            coefficient_applications.checked_add(record.coefficient_applications).ok_or_else(
                || C6CacheFoldTraceError::new("C6 scalar batch coefficient census overflows"),
            )?;
        topology_hasher.update(&record.topology_digest);
        hasher.update(&record.topology_digest);
        hasher.update(&record.coefficient_digest);
        hash_fp2(&mut hasher, power);
        terms.push(C6CacheFoldScalarBatchTerm {
            record: record.clone(),
            target,
            factors: factors.clone(),
            scalar_weight: power,
        });
        power = power * scalar_root;
    }
    if head_masks.values().any(|&mask| mask != C6_CACHE_HEAD_MASK)
        || kind_masks.values().any(|&mask| mask != 3)
        || factor_values > C6_CACHE_FOLD_MAX_FACTOR_VALUES
        || coefficient_applications != snapshot.identity.coefficient_applications
    {
        return Err(C6CacheFoldTraceError::new(
            "C6 scalar batch family or aggregate census is noncanonical",
        ));
    }
    let topology_digest = *topology_hasher.finalize().as_bytes();
    instance_hasher.update(&C6_CACHE_FOLD_TRACE_VERSION.to_le_bytes());
    instance_hasher.update(&topology_digest);
    for record in &snapshot.records {
        instance_hasher.update(&record.coefficient_digest);
    }
    let instance_digest = *instance_hasher.finalize().as_bytes();
    if topology_digest != snapshot.identity.topology_digest
        || instance_digest != snapshot.identity.instance_digest
    {
        return Err(C6CacheFoldTraceError::new(
            "C6 scalar batch aggregate identity is noncanonical",
        ));
    }
    let batch_digest = *hasher.finalize().as_bytes();
    Ok(C6CacheFoldScalarBatchPlan {
        party: snapshot.party,
        identity: C6CacheFoldScalarBatchIdentity {
            version: C6_CACHE_FOLD_SCALAR_BATCH_VERSION,
            fold_count: snapshot.identity.fold_count,
            factor_values,
            coefficient_applications: snapshot.identity.coefficient_applications,
            scalar_root,
            topology_digest: snapshot.identity.topology_digest,
            instance_digest: snapshot.identity.instance_digest,
            batch_digest,
        },
        terms,
    })
}

#[allow(clippy::too_many_arguments)]
fn record_topology_digest(
    ordinal: u32,
    kind: C6CacheFoldKind,
    schedule_section: u16,
    model_layer: u16,
    t0: u32,
    q: u32,
    total_rows: u32,
    head: u16,
    column_offset: u32,
    segment_rows: &[u32],
    row_weight_count: u32,
    column_weight_count: u32,
    coefficient_applications: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_RECORD_TOPOLOGY_DOMAIN);
    hasher.update(&C6_CACHE_FOLD_TRACE_VERSION.to_le_bytes());
    hasher.update(&ordinal.to_le_bytes());
    hasher.update(&[kind as u8]);
    hasher.update(&schedule_section.to_le_bytes());
    hasher.update(&model_layer.to_le_bytes());
    hasher.update(&t0.to_le_bytes());
    hasher.update(&q.to_le_bytes());
    hasher.update(&total_rows.to_le_bytes());
    hasher.update(&head.to_le_bytes());
    hasher.update(&column_offset.to_le_bytes());
    hasher.update(&(C6_CACHE_HEAD_WIDTH as u32).to_le_bytes());
    hasher.update(&(segment_rows.len() as u32).to_le_bytes());
    for &rows in segment_rows {
        hasher.update(&rows.to_le_bytes());
    }
    hasher.update(&row_weight_count.to_le_bytes());
    hasher.update(&column_weight_count.to_le_bytes());
    hasher.update(&coefficient_applications.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn record_coefficient_digest(
    topology_digest: [u8; 32],
    row_weights: &[Fp2],
    column_weights: &[Fp2],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(C6_CACHE_FOLD_RECORD_INSTANCE_DOMAIN);
    hasher.update(&topology_digest);
    hash_fp2_slice(&mut hasher, row_weights);
    hash_fp2_slice(&mut hasher, column_weights);
    *hasher.finalize().as_bytes()
}

fn hash_fp2_slice(hasher: &mut blake3::Hasher, values: &[Fp2]) {
    hasher.update(&(values.len() as u64).to_le_bytes());
    for value in values {
        hasher.update(&value.c0.value().to_le_bytes());
        hasher.update(&value.c1.value().to_le_bytes());
    }
}

fn hash_fp2(hasher: &mut blake3::Hasher, value: Fp2) {
    hasher.update(&value.c0.value().to_le_bytes());
    hasher.update(&value.c1.value().to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;
    use volta_mac::{ProverAuthed, VerifierKey};

    fn weights(length: usize, seed: u64) -> Vec<Fp2> {
        (0..length)
            .map(|index| {
                Fp2::new(Fp::new(seed + index as u64 + 1), Fp::new(seed * 3 + index as u64 + 7))
            })
            .collect()
    }

    fn record_family(kind: C6CacheFoldKind, seed: u64) {
        let rows = weights(4, seed);
        let columns = weights(C6_CACHE_HEAD_WIDTH, seed + 100);
        for head in 0..C6_CACHE_HEADS {
            record_c6_cache_fold_if_active(
                kind,
                0,
                0,
                4,
                &[4],
                head,
                head * C6_CACHE_HEAD_WIDTH,
                &rows,
                &columns,
                C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::ZERO),
            )
            .unwrap();
        }
    }

    fn capture(value_first: bool) -> C6CacheFoldTraceSnapshot {
        let guard = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        if value_first {
            record_family(C6CacheFoldKind::ValueColumns, 1);
            record_family(C6CacheFoldKind::KeyRows, 2);
        } else {
            record_family(C6CacheFoldKind::KeyRows, 2);
            record_family(C6CacheFoldKind::ValueColumns, 1);
        }
        guard.finish().unwrap()
    }

    #[test]
    fn complete_capture_is_order_bound_and_exact() {
        let canonical = capture(true);
        let reordered = capture(false);
        assert_eq!(canonical.identity.fold_count, 24);
        assert_eq!(canonical.identity.coefficient_applications, 24 * 4 * 64);
        assert_ne!(canonical.identity.topology_digest, reordered.identity.topology_digest);
        assert_ne!(canonical.identity.instance_digest, reordered.identity.instance_digest);
    }

    #[test]
    fn paired_targets_are_role_typed_plaintext_consistent_and_schedule_bound() {
        let mut left = capture(true);
        let mut right = left.clone();
        for (ordinal, (left_target, right_target)) in
            left.targets.iter_mut().zip(&mut right.targets).enumerate()
        {
            let value = Fp2::from_base(Fp::new(ordinal as u64 + 1));
            *left_target = C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(
                value,
                Fp2::from_base(Fp::new(10_000 + ordinal as u64)),
            ));
            *right_target = C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(
                value,
                Fp2::from_base(Fp::new(20_000 + ordinal as u64)),
            ));
        }
        let paired = C6CacheFoldPairedProverTargets::pair([&left, &right]).unwrap();
        assert_eq!(paired.identity, left.identity);
        assert_eq!(paired.terms().count(), 24);
        assert!(paired.terms().all(|(_, targets)| targets[0].x == targets[1].x));

        let mut wrong_plaintext = right.clone();
        let value = wrong_plaintext.targets[0].prover().unwrap();
        wrong_plaintext.targets[0] =
            C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(value.x + Fp2::ONE, value.m));
        assert!(C6CacheFoldPairedProverTargets::pair([&left, &wrong_plaintext]).is_err());
        let reordered = capture(false);
        assert!(C6CacheFoldPairedProverTargets::pair([&left, &reordered]).is_err());

        let mut verifier_left = left.clone();
        let mut verifier_right = right.clone();
        verifier_left.party = C6CacheFoldParty::Verifier;
        verifier_right.party = C6CacheFoldParty::Verifier;
        for (ordinal, (left_target, right_target)) in
            verifier_left.targets.iter_mut().zip(&mut verifier_right.targets).enumerate()
        {
            *left_target = C6CacheFoldAuthenticatedTarget::Verifier(VerifierKey::new(
                Fp2::from_base(Fp::new(30_000 + ordinal as u64)),
            ));
            *right_target = C6CacheFoldAuthenticatedTarget::Verifier(VerifierKey::new(
                Fp2::from_base(Fp::new(40_000 + ordinal as u64)),
            ));
        }
        let verifier_pair =
            C6CacheFoldPairedVerifierTargets::pair([&verifier_left, &verifier_right]).unwrap();
        assert_eq!(verifier_pair.identity, paired.identity);
        assert_eq!(verifier_pair.terms().count(), 24);
        assert!(C6CacheFoldPairedVerifierTargets::pair([&left, &right]).is_err());
    }

    fn fp2_power(base: Fp2, exponent: usize) -> Fp2 {
        (0..exponent).fold(Fp2::ONE, |power, _| power * base)
    }

    #[test]
    fn scalar_batch_matches_independent_dense_oracle_without_dense_plan() {
        let mut snapshot = capture(true);
        for (ordinal, target) in snapshot.targets.iter_mut().enumerate() {
            *target = C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::from_public(
                Fp2::from_base(Fp::new(ordinal as u64 + 1)),
            ));
        }
        let scalar_root = Fp2::new(Fp::new(3), Fp::new(5));
        let plan = compile_c6_cache_fold_scalar_batch(&snapshot, scalar_root).unwrap();
        assert_eq!(plan.identity.version, C6_CACHE_FOLD_SCALAR_BATCH_VERSION);
        assert_eq!(plan.identity.fold_count, 24);
        assert_eq!(plan.identity.factor_values, 24 * (4 + 64));
        assert_eq!(plan.identity.coefficient_applications, 24 * 4 * 64);
        assert_eq!(plan.identity.scalar_root, scalar_root);

        let value_rows = weights(4, 1);
        let value_columns = weights(C6_CACHE_HEAD_WIDTH, 101);
        let key_rows = weights(4, 2);
        let key_columns = weights(C6_CACHE_HEAD_WIDTH, 102);
        let mut dense_value = vec![Fp2::ZERO; 4 * C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH];
        let mut dense_key = vec![Fp2::ZERO; dense_value.len()];
        for head in 0..C6_CACHE_HEADS {
            let value_power = fp2_power(scalar_root, head + 1);
            let key_power = fp2_power(scalar_root, C6_CACHE_HEADS + head + 1);
            for row in 0..4 {
                for column in 0..C6_CACHE_HEAD_WIDTH {
                    let dense_index = row * C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH
                        + head * C6_CACHE_HEAD_WIDTH
                        + column;
                    dense_value[dense_index] =
                        value_power * value_rows[row] * value_columns[column];
                    dense_key[dense_index] = key_power * key_rows[row] * key_columns[column];
                }
            }
        }
        for row in 0..4 {
            for channel in 0..C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH {
                let dense_index = row * C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH + channel;
                assert_eq!(
                    plan.coefficient(C6CacheFoldKind::ValueColumns, 0, row, channel).unwrap(),
                    dense_value[dense_index]
                );
                assert_eq!(
                    plan.coefficient(C6CacheFoldKind::KeyRows, 0, row, channel).unwrap(),
                    dense_key[dense_index]
                );
            }
        }
        assert_eq!(plan.coefficient(C6CacheFoldKind::ValueColumns, 0, 4, 0).unwrap(), Fp2::ZERO);
        assert_eq!(plan.coefficient(C6CacheFoldKind::ValueColumns, 1, 0, 0).unwrap(), Fp2::ZERO);
        assert!(plan.coefficient(C6CacheFoldKind::ValueColumns, 12, 0, 0).is_err());
        assert!(plan
            .coefficient(C6CacheFoldKind::ValueColumns, 0, C6_CACHE_MAX_CONTEXT, 0)
            .is_err());
        assert!(plan
            .coefficient(C6CacheFoldKind::ValueColumns, 0, 0, C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH,)
            .is_err());

        let value_terms: Vec<_> = plan.target_terms(C6CacheFoldKind::ValueColumns).collect();
        let key_terms: Vec<_> = plan.target_terms(C6CacheFoldKind::KeyRows).collect();
        assert_eq!(value_terms.len(), C6_CACHE_HEADS);
        assert_eq!(key_terms.len(), C6_CACHE_HEADS);
        for (head, (_, weight)) in value_terms.iter().enumerate() {
            assert_eq!(*weight, fp2_power(scalar_root, head + 1));
        }
        for (head, (_, weight)) in key_terms.iter().enumerate() {
            assert_eq!(*weight, fp2_power(scalar_root, C6_CACHE_HEADS + head + 1));
        }
        let expected_values = (0..C6_CACHE_HEADS).fold(ProverAuthed::ZERO, |sum, ordinal| {
            sum.add(
                ProverAuthed::from_public(Fp2::from_base(Fp::new(ordinal as u64 + 1)))
                    .scale(fp2_power(scalar_root, ordinal + 1)),
            )
        });
        assert_eq!(
            plan.prover_target_aggregate(C6CacheFoldKind::ValueColumns).unwrap(),
            expected_values
        );
        assert!(plan.verifier_target_aggregate(C6CacheFoldKind::ValueColumns).is_err());
        assert!(plan
            .ordered_target_terms()
            .enumerate()
            .all(|(ordinal, term)| term.0 as usize == ordinal));

        let mut verifier_snapshot = snapshot.clone();
        verifier_snapshot.party = C6CacheFoldParty::Verifier;
        let delta = Fp2::new(Fp::new(7), Fp::new(11));
        for (ordinal, target) in verifier_snapshot.targets.iter_mut().enumerate() {
            *target = C6CacheFoldAuthenticatedTarget::Verifier(VerifierKey::new(
                delta * Fp2::from_base(Fp::new(ordinal as u64 + 1)),
            ));
        }
        let verifier_plan =
            compile_c6_cache_fold_scalar_batch(&verifier_snapshot, scalar_root).unwrap();
        assert_eq!(plan.identity, verifier_plan.identity);
        assert_eq!(
            verifier_plan.verifier_target_aggregate(C6CacheFoldKind::ValueColumns).unwrap().k,
            delta * expected_values.x
        );
        assert!(verifier_plan.prover_target_aggregate(C6CacheFoldKind::ValueColumns).is_err());

        let reordered = compile_c6_cache_fold_scalar_batch(&capture(false), scalar_root).unwrap();
        assert_ne!(plan.identity.batch_digest, reordered.identity.batch_digest);
    }

    #[test]
    fn scalar_batch_rejects_mutated_factor_record_and_aggregate_identity() {
        let scalar_root = Fp2::new(Fp::new(7), Fp::new(11));

        let mut bad_factor = capture(true);
        bad_factor.factors[0].row_weights[0] += Fp2::ONE;
        assert!(compile_c6_cache_fold_scalar_batch(&bad_factor, scalar_root).is_err());

        let mut bad_record = capture(true);
        bad_record.records[0].ordinal = 1;
        assert!(compile_c6_cache_fold_scalar_batch(&bad_record, scalar_root).is_err());

        let mut bad_identity = capture(true);
        bad_identity.identity.instance_digest[0] ^= 1;
        assert!(compile_c6_cache_fold_scalar_batch(&bad_identity, scalar_root).is_err());
    }

    #[test]
    fn malformed_geometry_and_nested_capture_fail_closed() {
        let guard = begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).unwrap();
        assert!(begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).is_err());
        let role_error = record_c6_cache_fold_if_active(
            C6CacheFoldKind::KeyRows,
            16,
            4,
            2,
            &[4, 2],
            0,
            0,
            &weights(6, 1),
            &weights(64, 2),
            C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::ZERO),
        )
        .unwrap_err();
        assert!(role_error.to_string().contains("target role"));
        let error = record_c6_cache_fold_if_active(
            C6CacheFoldKind::KeyRows,
            16,
            4,
            2,
            &[4, 1],
            0,
            0,
            &weights(6, 1),
            &weights(64, 2),
            C6CacheFoldAuthenticatedTarget::Verifier(VerifierKey::ZERO),
        )
        .unwrap_err();
        assert!(error.to_string().contains("do not cover"));
        drop(guard);
        let next = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        drop(next);

        let incomplete = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        record_family(C6CacheFoldKind::ValueColumns, 1);
        assert!(incomplete.finish().is_err());
    }
}
