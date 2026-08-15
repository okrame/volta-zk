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
use volta_field::{Fp, Fp2, P};
use volta_mac::{
    C6TraceToken, CorrelationStream, ProverAuthed, Transcript, VerifierCtx, VerifierKey,
};

pub const C6_CACHE_FOLD_TRACE_VERSION: u32 = 1;
pub const C6_CACHE_FOLD_SCALAR_BATCH_VERSION: u32 = 1;
pub const C6_CACHE_FOLD_MAX_RECORDS: usize = 576;
pub const C6_CACHE_FOLD_MAX_FACTOR_VALUES: u64 =
    C6_CACHE_FOLD_MAX_RECORDS as u64 * (C6_CACHE_MAX_CONTEXT as u64 + C6_CACHE_HEAD_WIDTH as u64);
pub const C6_CACHE_FOLD_TARGET_MAGIC: [u8; 8] = *b"C6FT1\0\0\0";
pub const C6_CACHE_FOLD_TARGET_VERSION: u16 = 1;
pub const C6_CACHE_FOLD_TARGET_TAPES: usize = 2;
pub const C6_CACHE_FOLD_TARGET_HEADER_BYTES: u64 = 48;
pub const C6_CACHE_FOLD_TARGET_SLOT_BYTES: u64 = 32;
pub const C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES: u64 = C6_CACHE_FOLD_TARGET_HEADER_BYTES
    + C6_CACHE_FOLD_MAX_RECORDS as u64 * C6_CACHE_FOLD_TARGET_SLOT_BYTES;

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
const C6_CACHE_FOLD_TARGET_HEADER_LABEL: &str = "c6_cache_fold_target_header";
const C6_CACHE_FOLD_TARGET_SLOT_LABEL: &str = "c6_cache_fold_target_corrections";
const C6_CACHE_FOLD_TARGET_PADDING_LABEL: &str = "c6_cache_fold_target_zero_padding";

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

/// Verifier-side aggregate base keys for the same canonical target schedule.
/// These are the linear folds of the direct source correlations before the
/// response-local `x-r` correction.  They deliberately cannot be obtained
/// from a corrected `CacheSegK` vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldPairedVerifierBaseTargets {
    pub identity: C6CacheFoldTraceIdentity,
    terms: Vec<(C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES])>,
}

impl C6CacheFoldPairedVerifierBaseTargets {
    pub fn new(
        identity: C6CacheFoldTraceIdentity,
        terms: Vec<(C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES])>,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_target_identity(identity, terms.len())?;
        Ok(Self { identity, terms })
    }

    pub fn terms(
        &self,
    ) -> impl Iterator<Item = (C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES])> + '_
    {
        self.terms.iter().copied()
    }
}

/// Canonical target ordinals known from the public response schedule.  The
/// trace identity is bound by the certificate statement; K/V kinds are kept
/// explicitly so an inline producer cannot silently reorder the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTargetSchedule {
    pub identity: C6CacheFoldTraceIdentity,
    kinds: Vec<C6CacheFoldKind>,
}

impl C6CacheFoldTargetSchedule {
    pub fn new(
        identity: C6CacheFoldTraceIdentity,
        kinds: Vec<C6CacheFoldKind>,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_target_identity(identity, kinds.len())?;
        Ok(Self { identity, kinds })
    }

    pub fn from_prover_targets(
        targets: &C6CacheFoldPairedProverTargets,
    ) -> Result<Self, C6CacheFoldTraceError> {
        Self::new(targets.identity, targets.terms.iter().map(|(kind, _)| *kind).collect())
    }

    pub fn live_count(&self) -> usize {
        self.kinds.len()
    }

    pub fn kinds(&self) -> impl Iterator<Item = C6CacheFoldKind> + '_ {
        self.kinds.iter().copied()
    }

    pub fn public_schedule(&self) -> C6CacheFoldTargetPublicSchedule {
        C6CacheFoldTargetPublicSchedule { kinds: self.kinds.clone() }
    }
}

/// Statement/workload-derived part of the C6FT1 target schedule.  Unlike a
/// complete runtime trace identity, this is available before the first
/// attention challenge and is therefore the only schedule accepted by the
/// production online start seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTargetPublicSchedule {
    kinds: Vec<C6CacheFoldKind>,
}

impl C6CacheFoldTargetPublicSchedule {
    pub fn new(kinds: Vec<C6CacheFoldKind>) -> Result<Self, C6CacheFoldTraceError> {
        validate_target_count(kinds.len())?;
        Ok(Self { kinds })
    }

    pub fn live_count(&self) -> usize {
        self.kinds.len()
    }

    pub fn kinds(&self) -> impl Iterator<Item = C6CacheFoldKind> + '_ {
        self.kinds.iter().copied()
    }
}

/// Provider-side inline builder.  It accepts only the next public ordinal,
/// emits its two corrections immediately, and returns the same authenticated
/// target for the caller's ProductClosure.  No future target or root is
/// required to advance it.
pub struct C6CacheFoldTargetInlineProver {
    statement_digest: [u8; 32],
    schedule: C6CacheFoldTargetPublicSchedule,
    expected_identity: Option<C6CacheFoldTraceIdentity>,
    corrections: Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
}

impl C6CacheFoldTargetInlineProver {
    pub fn start(
        statement_digest: [u8; 32],
        schedule: C6CacheFoldTargetSchedule,
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_statement_digest(statement_digest)?;
        validate_target_identity(schedule.identity, schedule.kinds.len())?;
        let identity = schedule.identity;
        Self::start_inner(statement_digest, schedule.public_schedule(), Some(identity), transcript)
    }

    /// Start the online C6FT1 stream before challenge-dependent row/column
    /// factors exist.  The complete runtime identity must be supplied to the
    /// matching `finish_*_with_identity` transition before a successor root.
    pub fn start_public(
        statement_digest: [u8; 32],
        schedule: C6CacheFoldTargetPublicSchedule,
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_statement_digest(statement_digest)?;
        Self::start_inner(statement_digest, schedule, None, transcript)
    }

    fn start_inner(
        statement_digest: [u8; 32],
        schedule: C6CacheFoldTargetPublicSchedule,
        expected_identity: Option<C6CacheFoldTraceIdentity>,
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_target_count(schedule.kinds.len())?;
        append_target_header(statement_digest, schedule.kinds.len(), transcript)?;
        Ok(Self {
            statement_digest,
            corrections: Vec::with_capacity(schedule.kinds.len()),
            schedule,
            expected_identity,
        })
    }

    pub fn push_target_before_product(
        &mut self,
        kind: C6CacheFoldKind,
        target: [ProverAuthed; C6_CACHE_FOLD_TARGET_TAPES],
        base_mask: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<[ProverAuthed; C6_CACHE_FOLD_TARGET_TAPES], C6CacheFoldTraceError> {
        let ordinal = self.corrections.len();
        if self.schedule.kinds.get(ordinal).copied() != Some(kind) {
            return Err(C6CacheFoldTraceError::new("C6FT1 inline prover target order mismatch"));
        }
        if target[0].x != target[1].x {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 inline prover tapes disagree on plaintext",
            ));
        }
        let correction = [target[0].x - base_mask[0], target[1].x - base_mask[1]];
        self.corrections.push(correction);
        transcript.append_fp2s(C6_CACHE_FOLD_TARGET_SLOT_LABEL, &correction);
        Ok(target)
    }

    pub fn finish_before_successor_root(
        self,
        transcript: &mut Transcript,
    ) -> Result<
        (C6CacheFoldTargetCorrectionFrame, C6CacheFoldTargetFixedCorrections),
        C6CacheFoldTraceError,
    > {
        let identity = self.expected_identity.ok_or_else(|| {
            C6CacheFoldTraceError::new(
                "C6FT1 public-start prover requires runtime identity at finish",
            )
        })?;
        self.finish_before_successor_root_with_identity(identity, transcript)
    }

    pub fn finish_before_successor_root_with_identity(
        self,
        identity: C6CacheFoldTraceIdentity,
        transcript: &mut Transcript,
    ) -> Result<
        (C6CacheFoldTargetCorrectionFrame, C6CacheFoldTargetFixedCorrections),
        C6CacheFoldTraceError,
    > {
        if self.corrections.len() != self.schedule.kinds.len() {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 inline prover did not exhaust live targets",
            ));
        }
        charge_target_padding(self.corrections.len(), transcript);
        validate_online_runtime_identity(
            identity,
            self.expected_identity,
            self.schedule.kinds.len(),
        )?;
        let frame = C6CacheFoldTargetCorrectionFrame {
            statement_digest: self.statement_digest,
            identity,
            corrections: self.corrections.clone(),
        };
        let fixed = C6CacheFoldTargetFixedCorrections {
            identity,
            kinds: self.schedule.kinds,
            corrections: self.corrections,
        };
        Ok((frame, fixed))
    }
}

/// Client-side inline cursor over a decoded fixed frame.  A base target key
/// is corrected only when its canonical ordinal is reached; callers receive
/// it after the correction message and before sampling the ProductClosure
/// challenge.
pub struct C6CacheFoldTargetInlineVerifier<'a> {
    corrections: &'a [[Fp2; C6_CACHE_FOLD_TARGET_TAPES]],
    decoded_identity: Option<C6CacheFoldTraceIdentity>,
    schedule: C6CacheFoldTargetPublicSchedule,
    expected_identity: Option<C6CacheFoldTraceIdentity>,
    deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
    next: usize,
}

impl<'a> C6CacheFoldTargetInlineVerifier<'a> {
    pub fn start(
        frame: &'a C6CacheFoldTargetCorrectionFrame,
        schedule: C6CacheFoldTargetSchedule,
        deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        if schedule.identity != frame.identity || schedule.kinds.len() != frame.corrections.len() {
            return Err(C6CacheFoldTraceError::new("C6FT1 inline verifier schedule mismatch"));
        }
        if deltas[0] == deltas[1] {
            return Err(C6CacheFoldTraceError::new("C6FT1 MAC tapes are not independent"));
        }
        let identity = schedule.identity;
        Self::start_inner(
            frame.statement_digest,
            &frame.corrections,
            Some(frame.identity),
            schedule.public_schedule(),
            Some(identity),
            deltas,
            transcript,
        )
    }

    pub fn start_public(
        frame: &'a C6CacheFoldTargetCorrectionFrame,
        schedule: C6CacheFoldTargetPublicSchedule,
        deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        if schedule.kinds.len() != frame.corrections.len() {
            return Err(C6CacheFoldTraceError::new("C6FT1 inline verifier schedule mismatch"));
        }
        if deltas[0] == deltas[1] {
            return Err(C6CacheFoldTraceError::new("C6FT1 MAC tapes are not independent"));
        }
        Self::start_inner(
            frame.statement_digest,
            &frame.corrections,
            Some(frame.identity),
            schedule,
            None,
            deltas,
            transcript,
        )
    }

    pub fn start_decoded_public(
        frame: &'a C6CacheFoldTargetPublicCorrectionFrame,
        schedule: C6CacheFoldTargetPublicSchedule,
        deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        if schedule.kinds.len() != frame.corrections.len() {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 decoded-public verifier schedule mismatch",
            ));
        }
        if deltas[0] == deltas[1] {
            return Err(C6CacheFoldTraceError::new("C6FT1 MAC tapes are not independent"));
        }
        Self::start_inner(
            frame.statement_digest,
            &frame.corrections,
            None,
            schedule,
            None,
            deltas,
            transcript,
        )
    }

    fn start_inner(
        statement_digest: [u8; 32],
        corrections: &'a [[Fp2; C6_CACHE_FOLD_TARGET_TAPES]],
        decoded_identity: Option<C6CacheFoldTraceIdentity>,
        schedule: C6CacheFoldTargetPublicSchedule,
        expected_identity: Option<C6CacheFoldTraceIdentity>,
        deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_target_count(schedule.kinds.len())?;
        append_target_header(statement_digest, schedule.kinds.len(), transcript)?;
        Ok(Self { corrections, decoded_identity, schedule, expected_identity, deltas, next: 0 })
    }

    pub fn correct_next_before_product(
        &mut self,
        kind: C6CacheFoldKind,
        base: [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<[VerifierKey; C6_CACHE_FOLD_TARGET_TAPES], C6CacheFoldTraceError> {
        if self.schedule.kinds.get(self.next).copied() != Some(kind) {
            return Err(C6CacheFoldTraceError::new("C6FT1 inline verifier target order mismatch"));
        }
        let correction = self.corrections[self.next];
        self.next += 1;
        transcript.append_fp2s(C6_CACHE_FOLD_TARGET_SLOT_LABEL, &correction);
        Ok(std::array::from_fn(|tape| {
            base[tape].with_same_c6_trace(base[tape].k + self.deltas[tape] * correction[tape])
        }))
    }

    pub fn finish_before_successor_root(
        self,
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceError> {
        let identity = self.expected_identity.ok_or_else(|| {
            C6CacheFoldTraceError::new(
                "C6FT1 public-start verifier requires runtime identity at finish",
            )
        })?;
        self.finish_before_successor_root_with_identity(identity, transcript)
    }

    pub fn finish_before_successor_root_with_identity(
        self,
        identity: C6CacheFoldTraceIdentity,
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceError> {
        if self.next != self.schedule.kinds.len() {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 inline verifier did not exhaust live targets",
            ));
        }
        charge_target_padding(self.corrections.len(), transcript);
        validate_online_runtime_identity(
            identity,
            self.expected_identity,
            self.schedule.kinds.len(),
        )?;
        if self.decoded_identity.is_some_and(|decoded| identity != decoded) {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 verifier runtime identity differs from decoded frame binding",
            ));
        }
        Ok(C6CacheFoldTargetFixedCorrections {
            identity,
            kinds: self.schedule.kinds,
            corrections: self.corrections.to_vec(),
        })
    }
}

/// Fixed-capacity `C6FT1` correction frame.  Only the live prefix is retained
/// in memory; encoding writes the entire 576-slot frame and requires the tail
/// to be canonical zero.  The corrections reuse existing direct source
/// correlations and therefore consume no fresh full-field correlation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTargetCorrectionFrame {
    statement_digest: [u8; 32],
    identity: C6CacheFoldTraceIdentity,
    corrections: Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
}

/// Strict disk-decoded C6FT1 bytes before the verifier has replayed the
/// response trace that independently reconstructs the omitted runtime
/// identity. The wire frame intentionally carries no copy of that identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTargetPublicCorrectionFrame {
    statement_digest: [u8; 32],
    corrections: Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
}

impl C6CacheFoldTargetPublicCorrectionFrame {
    pub fn decode(
        expected_statement_digest: [u8; 32],
        bytes: &[u8],
    ) -> Result<Self, C6CacheFoldTraceError> {
        Ok(Self {
            statement_digest: expected_statement_digest,
            corrections: decode_target_corrections(expected_statement_digest, bytes)?,
        })
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn live_count(&self) -> usize {
        self.corrections.len()
    }
}

impl C6CacheFoldTargetCorrectionFrame {
    pub fn from_prover_targets(
        statement_digest: [u8; 32],
        targets: &C6CacheFoldPairedProverTargets,
        base_masks: &[[Fp2; C6_CACHE_FOLD_TARGET_TAPES]],
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_statement_digest(statement_digest)?;
        validate_target_identity(targets.identity, targets.terms.len())?;
        if base_masks.len() != targets.terms.len() {
            return Err(C6CacheFoldTraceError::new("C6FT1 prover target/mask census mismatch"));
        }
        let corrections = targets
            .terms
            .iter()
            .zip(base_masks)
            .map(|((_, target), mask)| [target[0].x - mask[0], target[1].x - mask[1]])
            .collect();
        Ok(Self { statement_digest, identity: targets.identity, corrections })
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    pub fn live_count(&self) -> usize {
        self.corrections.len()
    }

    pub fn identity(&self) -> C6CacheFoldTraceIdentity {
        self.identity
    }

    pub fn encode(&self) -> Result<Vec<u8>, C6CacheFoldTraceError> {
        validate_statement_digest(self.statement_digest)?;
        validate_target_identity(self.identity, self.corrections.len())?;
        let live_count = u16::try_from(self.corrections.len())
            .map_err(|_| C6CacheFoldTraceError::new("C6FT1 live count exceeds u16"))?;
        let capacity = u16::try_from(C6_CACHE_FOLD_MAX_RECORDS)
            .map_err(|_| C6CacheFoldTraceError::new("C6FT1 capacity exceeds u16"))?;
        let mut bytes = Vec::with_capacity(C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES as usize);
        bytes.extend_from_slice(&C6_CACHE_FOLD_TARGET_MAGIC);
        bytes.extend_from_slice(&C6_CACHE_FOLD_TARGET_VERSION.to_le_bytes());
        bytes.push(C6_CACHE_FOLD_TARGET_TAPES as u8);
        bytes.push(2); // canonical Fp2 limb count
        bytes.extend_from_slice(&live_count.to_le_bytes());
        bytes.extend_from_slice(&capacity.to_le_bytes());
        bytes.extend_from_slice(&self.statement_digest);
        for correction in &self.corrections {
            for value in correction {
                encode_target_fp2(&mut bytes, *value);
            }
        }
        bytes.resize(C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES as usize, 0);
        if bytes.len() as u64 != C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES {
            return Err(C6CacheFoldTraceError::new("C6FT1 encoded length changed"));
        }
        Ok(bytes)
    }

    pub fn decode(
        expected_statement_digest: [u8; 32],
        expected_identity: C6CacheFoldTraceIdentity,
        bytes: &[u8],
    ) -> Result<Self, C6CacheFoldTraceError> {
        let corrections = decode_target_corrections(expected_statement_digest, bytes)?;
        let live_count = corrections.len();
        validate_target_identity(expected_identity, live_count)?;
        Ok(Self {
            statement_digest: expected_statement_digest,
            identity: expected_identity,
            corrections,
        })
    }

    /// Start the provider-side target-ordered stream.  Each `next` call
    /// charges exactly one two-tape correction before its caller may derive
    /// the corresponding ProductClosure challenge.
    pub fn start_prover_stream<'a>(
        &'a self,
        targets: &'a C6CacheFoldPairedProverTargets,
        base_masks: &'a [[Fp2; C6_CACHE_FOLD_TARGET_TAPES]],
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetProverStream<'a>, C6CacheFoldTraceError> {
        let expected = Self::from_prover_targets(self.statement_digest, targets, base_masks)?;
        if expected != *self {
            return Err(C6CacheFoldTraceError::new(
                "C6FT1 frame is not the canonical prover target correction",
            ));
        }
        append_target_header(self.statement_digest, self.corrections.len(), transcript)?;
        Ok(C6CacheFoldTargetProverStream { frame: self, targets, next: 0 })
    }

    /// Start the verifier-side base-key stream.  The returned keys are the
    /// only corrected target keys admitted to the immediate ProductClosure.
    pub fn start_verifier_stream<'a>(
        &'a self,
        base_targets: &'a C6CacheFoldPairedVerifierBaseTargets,
        deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetVerifierStream<'a>, C6CacheFoldTraceError> {
        validate_target_identity(base_targets.identity, base_targets.terms.len())?;
        if base_targets.identity != self.identity
            || base_targets.terms.len() != self.corrections.len()
        {
            return Err(C6CacheFoldTraceError::new("C6FT1 verifier target census mismatch"));
        }
        if deltas[0] == deltas[1] {
            return Err(C6CacheFoldTraceError::new("C6FT1 MAC tapes are not independent"));
        }
        append_target_header(self.statement_digest, self.corrections.len(), transcript)?;
        Ok(C6CacheFoldTargetVerifierStream { frame: self, base_targets, deltas, next: 0 })
    }
}

/// Frame view available only after every live correction and the canonical
/// zero tail have been placed before the successor scalar root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTargetFixedCorrections {
    identity: C6CacheFoldTraceIdentity,
    kinds: Vec<C6CacheFoldKind>,
    corrections: Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
}

impl C6CacheFoldTargetFixedCorrections {
    pub fn identity(&self) -> C6CacheFoldTraceIdentity {
        self.identity
    }

    /// Deterministic `C6PS1` successor fold in K/V order, per MAC tape.
    pub fn fold_corrections(&self, scalar_root: Fp2) -> [[Fp2; C6_CACHE_FOLD_TARGET_TAPES]; 2] {
        let mut result = [[Fp2::ZERO; C6_CACHE_FOLD_TARGET_TAPES]; 2];
        let mut weight = scalar_root;
        for (kind, correction) in self.kinds.iter().zip(&self.corrections) {
            let kv = match kind {
                C6CacheFoldKind::KeyRows => 0,
                C6CacheFoldKind::ValueColumns => 1,
            };
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                result[kv][tape] += weight * correction[tape];
            }
            weight = weight * scalar_root;
        }
        result
    }
}

pub struct C6CacheFoldTargetProverStream<'a> {
    frame: &'a C6CacheFoldTargetCorrectionFrame,
    targets: &'a C6CacheFoldPairedProverTargets,
    next: usize,
}

impl<'a> C6CacheFoldTargetProverStream<'a> {
    pub fn next_target(
        &mut self,
        transcript: &mut Transcript,
    ) -> Result<(C6CacheFoldKind, [ProverAuthed; C6_CACHE_FOLD_TARGET_TAPES]), C6CacheFoldTraceError>
    {
        let term =
            self.targets.terms.get(self.next).copied().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6FT1 prover target stream exhausted")
            })?;
        transcript.append_fp2s(
            C6_CACHE_FOLD_TARGET_SLOT_LABEL,
            &self.frame.corrections[self.next],
        );
        self.next += 1;
        Ok(term)
    }

    pub fn finish_before_successor_root(
        self,
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceError> {
        finish_target_stream(
            self.frame,
            self.targets.identity,
            &self.targets.terms,
            self.next,
            transcript,
        )
    }
}

pub struct C6CacheFoldTargetVerifierStream<'a> {
    frame: &'a C6CacheFoldTargetCorrectionFrame,
    base_targets: &'a C6CacheFoldPairedVerifierBaseTargets,
    deltas: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
    next: usize,
}

impl<'a> C6CacheFoldTargetVerifierStream<'a> {
    pub fn next_target(
        &mut self,
        transcript: &mut Transcript,
    ) -> Result<(C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES]), C6CacheFoldTraceError>
    {
        let (kind, base) =
            self.base_targets.terms.get(self.next).copied().ok_or_else(|| {
                C6CacheFoldTraceError::new("C6FT1 verifier target stream exhausted")
            })?;
        let correction = self.frame.corrections[self.next];
        transcript.append_fp2s(C6_CACHE_FOLD_TARGET_SLOT_LABEL, &correction);
        self.next += 1;
        Ok((
            kind,
            std::array::from_fn(|tape| {
                base[tape].with_same_c6_trace(base[tape].k + self.deltas[tape] * correction[tape])
            }),
        ))
    }

    pub fn finish_before_successor_root(
        self,
        transcript: &mut Transcript,
    ) -> Result<C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceError> {
        finish_target_stream(
            self.frame,
            self.base_targets.identity,
            &self.base_targets.terms,
            self.next,
            transcript,
        )
    }
}

fn finish_target_stream<T: Copy>(
    frame: &C6CacheFoldTargetCorrectionFrame,
    identity: C6CacheFoldTraceIdentity,
    terms: &[(C6CacheFoldKind, [T; C6_CACHE_FOLD_TARGET_TAPES])],
    next: usize,
    transcript: &mut Transcript,
) -> Result<C6CacheFoldTargetFixedCorrections, C6CacheFoldTraceError> {
    if next != frame.corrections.len() || terms.len() != frame.corrections.len() {
        return Err(C6CacheFoldTraceError::new(
            "C6FT1 live targets were not exhausted before successor root",
        ));
    }
    charge_target_padding(frame.corrections.len(), transcript);
    Ok(C6CacheFoldTargetFixedCorrections {
        identity,
        kinds: terms.iter().map(|(kind, _)| *kind).collect(),
        corrections: frame.corrections.clone(),
    })
}

fn charge_target_padding(live_count: usize, transcript: &mut Transcript) {
    let padding_slots = C6_CACHE_FOLD_MAX_RECORDS - live_count;
    if padding_slots != 0 {
        transcript.append_zero_message(
            C6_CACHE_FOLD_TARGET_PADDING_LABEL,
            padding_slots as u64 * C6_CACHE_FOLD_TARGET_SLOT_BYTES,
        );
    }
}

fn append_target_header(
    statement_digest: [u8; 32],
    live_count: usize,
    transcript: &mut Transcript,
) -> Result<(), C6CacheFoldTraceError> {
    validate_statement_digest(statement_digest)?;
    validate_target_count(live_count)?;
    let live_count = u16::try_from(live_count)
        .map_err(|_| C6CacheFoldTraceError::new("C6FT1 live count exceeds u16"))?;
    let capacity = u16::try_from(C6_CACHE_FOLD_MAX_RECORDS)
        .map_err(|_| C6CacheFoldTraceError::new("C6FT1 capacity exceeds u16"))?;
    let mut header = Vec::with_capacity(C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize);
    header.extend_from_slice(&C6_CACHE_FOLD_TARGET_MAGIC);
    header.extend_from_slice(&C6_CACHE_FOLD_TARGET_VERSION.to_le_bytes());
    header.push(C6_CACHE_FOLD_TARGET_TAPES as u8);
    header.push(2);
    header.extend_from_slice(&live_count.to_le_bytes());
    header.extend_from_slice(&capacity.to_le_bytes());
    header.extend_from_slice(&statement_digest);
    debug_assert_eq!(header.len(), C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize);
    transcript.append_message(C6_CACHE_FOLD_TARGET_HEADER_LABEL, &header);
    Ok(())
}

fn validate_statement_digest(statement_digest: [u8; 32]) -> Result<(), C6CacheFoldTraceError> {
    if statement_digest == [0; 32] {
        return Err(C6CacheFoldTraceError::new("zero C6FT1 statement digest"));
    }
    Ok(())
}

fn validate_target_identity(
    identity: C6CacheFoldTraceIdentity,
    count: usize,
) -> Result<(), C6CacheFoldTraceError> {
    validate_target_count(count)?;
    if identity.version != C6_CACHE_FOLD_TRACE_VERSION
        || identity.fold_count as usize != count
        || identity.topology_digest == [0; 32]
        || identity.instance_digest == [0; 32]
    {
        return Err(C6CacheFoldTraceError::new("C6FT1 target identity mismatch"));
    }
    Ok(())
}

fn validate_online_runtime_identity(
    identity: C6CacheFoldTraceIdentity,
    expected_identity: Option<C6CacheFoldTraceIdentity>,
    count: usize,
) -> Result<(), C6CacheFoldTraceError> {
    validate_target_identity(identity, count)?;
    if expected_identity.is_some_and(|expected| expected != identity) {
        return Err(C6CacheFoldTraceError::new(
            "C6FT1 runtime identity differs from its post-hoc schedule",
        ));
    }
    Ok(())
}

fn validate_target_count(count: usize) -> Result<(), C6CacheFoldTraceError> {
    if count == 0 || count > C6_CACHE_FOLD_MAX_RECORDS {
        return Err(C6CacheFoldTraceError::new("C6FT1 live target count is outside capacity"));
    }
    Ok(())
}

fn encode_target_fp2(bytes: &mut Vec<u8>, value: Fp2) {
    bytes.extend_from_slice(&value.c0.value().to_le_bytes());
    bytes.extend_from_slice(&value.c1.value().to_le_bytes());
}

fn decode_target_corrections(
    expected_statement_digest: [u8; 32],
    bytes: &[u8],
) -> Result<Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>, C6CacheFoldTraceError> {
    validate_statement_digest(expected_statement_digest)?;
    if bytes.len() as u64 != C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES {
        return Err(C6CacheFoldTraceError::new("C6FT1 encoded length mismatch"));
    }
    let mut cursor = C6CacheFoldTargetDecodeCursor::new(bytes);
    if cursor.take(8)? != C6_CACHE_FOLD_TARGET_MAGIC
        || cursor.u16()? != C6_CACHE_FOLD_TARGET_VERSION
        || cursor.u8()? as usize != C6_CACHE_FOLD_TARGET_TAPES
        || cursor.u8()? != 2
    {
        return Err(C6CacheFoldTraceError::new("C6FT1 header census mismatch"));
    }
    let live_count = usize::from(cursor.u16()?);
    if usize::from(cursor.u16()?) != C6_CACHE_FOLD_MAX_RECORDS {
        return Err(C6CacheFoldTraceError::new("C6FT1 capacity mismatch"));
    }
    validate_target_count(live_count)?;
    if cursor.digest()? != expected_statement_digest {
        return Err(C6CacheFoldTraceError::new("C6FT1 statement digest mismatch"));
    }
    let mut corrections = Vec::with_capacity(live_count);
    for _ in 0..live_count {
        corrections.push([cursor.fp2()?, cursor.fp2()?]);
    }
    if cursor.remaining().iter().any(|&byte| byte != 0) {
        return Err(C6CacheFoldTraceError::new("C6FT1 nonzero inactive tail"));
    }
    Ok(corrections)
}

struct C6CacheFoldTargetDecodeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> C6CacheFoldTargetDecodeCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], C6CacheFoldTraceError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6FT1 cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| C6CacheFoldTraceError::new("truncated C6FT1 frame"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, C6CacheFoldTraceError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, C6CacheFoldTraceError> {
        let mut bytes = [0u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(bytes))
    }

    fn digest(&mut self) -> Result<[u8; 32], C6CacheFoldTraceError> {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.take(32)?);
        Ok(digest)
    }

    fn fp2(&mut self) -> Result<Fp2, C6CacheFoldTraceError> {
        let c0 = self.u64_canonical()?;
        let c1 = self.u64_canonical()?;
        Ok(Fp2::new(Fp::new(c0), Fp::new(c1)))
    }

    fn u64_canonical(&mut self) -> Result<u64, C6CacheFoldTraceError> {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        let value = u64::from_le_bytes(bytes);
        if value >= P {
            return Err(C6CacheFoldTraceError::new("noncanonical C6FT1 field limb"));
        }
        Ok(value)
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
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
    /// Expand one real model layer into the fixed `1024 x 1024` padded cache
    /// slice. This is the production streaming unit: callers may retain one
    /// layer, but there is no API that materializes the `2^24` coefficient
    /// field.
    pub fn write_padded_layer_coefficients(
        &self,
        kind: C6CacheFoldKind,
        model_layer: usize,
        output: &mut [Fp2],
    ) -> Result<u64, C6CacheFoldTraceError> {
        let expected_len = C6_CACHE_MAX_CONTEXT
            .checked_mul(1usize << 10)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 layer coefficient length overflows"))?;
        if model_layer >= usize::from(C6_CACHE_MODEL_LAYERS) || output.len() != expected_len {
            return Err(C6CacheFoldTraceError::new(
                "C6 layer coefficient output has wrong production geometry",
            ));
        }
        output.fill(Fp2::ZERO);
        let mut applications = 0u64;
        for term in self.terms.iter().filter(|term| {
            term.record.kind == kind && usize::from(term.record.model_layer) == model_layer
        }) {
            let column_start = term.record.column_offset as usize;
            for (position, &row_weight) in term.factors.row_weights.iter().enumerate() {
                let row_factor = term.scalar_weight * row_weight;
                let row_start = position
                    .checked_mul(1usize << 10)
                    .and_then(|base| base.checked_add(column_start))
                    .ok_or_else(|| {
                        C6CacheFoldTraceError::new("C6 layer coefficient offset overflows")
                    })?;
                for (column, &column_weight) in term.factors.column_weights.iter().enumerate() {
                    output[row_start + column] += row_factor * column_weight;
                }
            }
            applications =
                applications.checked_add(term.record.coefficient_applications).ok_or_else(
                    || C6CacheFoldTraceError::new("C6 layer coefficient applications overflow"),
                )?;
        }
        Ok(applications)
    }

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

const C6_CACHE_FOLD_SOURCE_COLUMNS: usize = C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheFoldDirectSourceSegment {
    pub base_domain: u64,
    pub rows: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct C6CacheFoldOnlineLayerMetrics {
    pub source_groups: u64,
    pub source_cells: u64,
    pub coefficient_applications: u64,
    pub corrected_targets: u64,
    pub linear_auxiliary_source_cells: u64,
}

#[derive(Clone, Copy, Debug)]
struct C6OnlinePreparedProverTarget {
    kind: C6CacheFoldKind,
    primary_tag: Fp2,
    secondary_tag: Fp2,
    base_masks: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
}

#[derive(Clone, Copy, Debug)]
struct C6OnlinePreparedVerifierTarget {
    kind: C6CacheFoldKind,
    base_keys: [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES],
}

/// Per-layer provider adapter used by the actual attention ordering: prepare
/// all 12 base masks/tags with one source pass, then release one correction
/// immediately before each retained ProductClosure.
pub struct C6CacheFoldOnlineLayerProver<'a, 'b> {
    model_layer: u16,
    key_segments: Vec<C6CacheFoldDirectSourceSegment>,
    value_segments: Vec<C6CacheFoldDirectSourceSegment>,
    secondary: &'a mut CorrelationStream,
    target_builder: &'b mut C6CacheFoldTargetInlineProver,
    prepared: Vec<C6OnlinePreparedProverTarget>,
    next_prepared: usize,
    completed_families: usize,
    paired_targets: Vec<(C6CacheFoldKind, [ProverAuthed; C6_CACHE_FOLD_TARGET_TAPES])>,
    metrics: C6CacheFoldOnlineLayerMetrics,
    poisoned: bool,
}

impl<'a, 'b> C6CacheFoldOnlineLayerProver<'a, 'b> {
    pub fn new(
        model_layer: u16,
        key_segments: Vec<C6CacheFoldDirectSourceSegment>,
        value_segments: Vec<C6CacheFoldDirectSourceSegment>,
        secondary: &'a mut CorrelationStream,
        target_builder: &'b mut C6CacheFoldTargetInlineProver,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_online_layer_segments(model_layer, &key_segments, &value_segments)?;
        Ok(Self {
            model_layer,
            key_segments,
            value_segments,
            secondary,
            target_builder,
            prepared: Vec::new(),
            next_prepared: 0,
            completed_families: 0,
            paired_targets: Vec::with_capacity(C6_CACHE_HEADS * 2),
            metrics: C6CacheFoldOnlineLayerMetrics::default(),
            poisoned: false,
        })
    }

    pub fn paired_targets(
        &self,
    ) -> &[(C6CacheFoldKind, [ProverAuthed; C6_CACHE_FOLD_TARGET_TAPES])] {
        &self.paired_targets
    }

    pub fn metrics(&self) -> C6CacheFoldOnlineLayerMetrics {
        self.metrics
    }

    fn prepare_family(
        &mut self,
        primary: &mut CorrelationStream,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> Result<(), C6CacheFoldTraceError> {
        self.validate_prepare(kind, model_layer, row_weights, column_weights)?;
        let segments = self.segments(kind).to_vec();
        let before_primary = correlation_stream_state(primary);
        let before_secondary = correlation_stream_state(self.secondary);
        let mut primary_tags = [Fp2::ZERO; C6_CACHE_HEADS];
        let mut secondary_tags = [Fp2::ZERO; C6_CACHE_HEADS];
        let mut primary_masks = [Fp2::ZERO; C6_CACHE_HEADS];
        let mut secondary_masks = [Fp2::ZERO; C6_CACHE_HEADS];
        let mut global_row = 0usize;
        for segment in &segments {
            for local_row in 0..segment.rows {
                let domain = checked_source_domain(segment.base_domain, local_row)?;
                let masks = [
                    primary.replay_consumed_sub_masks(domain, C6_CACHE_FOLD_SOURCE_COLUMNS),
                    self.secondary.replay_consumed_sub_masks(domain, C6_CACHE_FOLD_SOURCE_COLUMNS),
                ];
                let tags = [
                    primary.draw_sub_tags(domain, C6_CACHE_FOLD_SOURCE_COLUMNS),
                    self.secondary.draw_sub_tags(domain, C6_CACHE_FOLD_SOURCE_COLUMNS),
                ];
                for channel in 0..C6_CACHE_FOLD_SOURCE_COLUMNS {
                    let head = channel / C6_CACHE_HEAD_WIDTH;
                    let within = channel % C6_CACHE_HEAD_WIDTH;
                    let coefficient = row_weights[head][global_row] * column_weights[head][within];
                    primary_masks[head] += coefficient.mul_base(masks[0][channel]);
                    secondary_masks[head] += coefficient.mul_base(masks[1][channel]);
                    primary_tags[head] += coefficient * tags[0][channel];
                    secondary_tags[head] += coefficient * tags[1][channel];
                }
                global_row += 1;
            }
        }
        if correlation_stream_state(primary) != before_primary
            || correlation_stream_state(self.secondary) != before_secondary
        {
            return self.fail("C6 online provider source replay changed correlation state");
        }
        self.prepared = (0..C6_CACHE_HEADS)
            .map(|head| C6OnlinePreparedProverTarget {
                kind,
                primary_tag: primary_tags[head],
                secondary_tag: secondary_tags[head],
                base_masks: [primary_masks[head], secondary_masks[head]],
            })
            .collect();
        self.next_prepared = 0;
        self.metrics.source_groups += 1;
        let cells = u64::try_from(global_row * C6_CACHE_FOLD_SOURCE_COLUMNS)
            .map_err(|_| C6CacheFoldTraceError::new("C6 online provider source census overflow"))?;
        self.metrics.source_cells += cells;
        self.metrics.coefficient_applications += cells;
        Ok(())
    }

    fn push_target(
        &mut self,
        kind: C6CacheFoldKind,
        target: ProverAuthed,
        transcript: &mut Transcript,
    ) -> Result<ProverAuthed, C6CacheFoldTraceError> {
        if self.poisoned {
            return Err(C6CacheFoldTraceError::new("poisoned C6 online provider layer"));
        }
        let prepared = self.prepared.get(self.next_prepared).copied().ok_or_else(|| {
            C6CacheFoldTraceError::new("C6 online provider target arrived before family prepare")
        })?;
        if prepared.kind != kind || target.m != prepared.primary_tag {
            return self.fail("C6 online provider target/tag/order mismatch");
        }
        let paired = [target, ProverAuthed::new(target.x, prepared.secondary_tag)];
        let accepted = self.target_builder.push_target_before_product(
            kind,
            paired,
            prepared.base_masks,
            transcript,
        )?;
        self.paired_targets.push((kind, accepted));
        self.next_prepared += 1;
        self.metrics.corrected_targets += 1;
        if self.next_prepared == self.prepared.len() {
            self.prepared.clear();
            self.next_prepared = 0;
            self.completed_families += 1;
        }
        Ok(accepted[0])
    }

    fn validate_prepare(
        &mut self,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned || !self.prepared.is_empty() || model_layer != self.model_layer {
            return self.fail("C6 online provider family state/layer mismatch");
        }
        let expected = [C6CacheFoldKind::ValueColumns, C6CacheFoldKind::KeyRows]
            .get(self.completed_families)
            .copied();
        let rows = source_segment_rows(self.segments(kind))?;
        if expected != Some(kind)
            || row_weights.len() != C6_CACHE_HEADS
            || column_weights.len() != C6_CACHE_HEADS
            || row_weights.iter().any(|weights| weights.len() != rows)
            || column_weights.iter().any(|weights| weights.len() != C6_CACHE_HEAD_WIDTH)
        {
            return self.fail("C6 online provider family geometry/order mismatch");
        }
        Ok(())
    }

    fn segments(&self, kind: C6CacheFoldKind) -> &[C6CacheFoldDirectSourceSegment] {
        match kind {
            C6CacheFoldKind::KeyRows => &self.key_segments,
            C6CacheFoldKind::ValueColumns => &self.value_segments,
        }
    }

    fn finish(&mut self) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned
            || !self.prepared.is_empty()
            || self.completed_families != 2
            || self.paired_targets.len() != 2 * C6_CACHE_HEADS
        {
            return self.fail("incomplete C6 online provider layer");
        }
        Ok(())
    }

    fn fail<T>(&mut self, message: &'static str) -> Result<T, C6CacheFoldTraceError> {
        self.poisoned = true;
        Err(C6CacheFoldTraceError::new(message))
    }
}

/// Client mirror of [`C6CacheFoldOnlineLayerProver`].  Direct base keys are
/// replayed after their phase-1 reservation, folded once per family, and
/// corrected only at the next C6FT1 ordinal.
pub struct C6CacheFoldOnlineLayerVerifier<'a, 'b, 'frame> {
    model_layer: u16,
    key_segments: Vec<C6CacheFoldDirectSourceSegment>,
    value_segments: Vec<C6CacheFoldDirectSourceSegment>,
    secondary: &'a mut VerifierCtx,
    target_cursor: &'b mut C6CacheFoldTargetInlineVerifier<'frame>,
    prepared: Vec<C6OnlinePreparedVerifierTarget>,
    next_prepared: usize,
    completed_families: usize,
    auxiliary_openings: usize,
    paired_targets: Vec<(C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES])>,
    metrics: C6CacheFoldOnlineLayerMetrics,
    poisoned: bool,
}

impl<'a, 'b, 'frame> C6CacheFoldOnlineLayerVerifier<'a, 'b, 'frame> {
    pub fn new(
        model_layer: u16,
        key_segments: Vec<C6CacheFoldDirectSourceSegment>,
        value_segments: Vec<C6CacheFoldDirectSourceSegment>,
        secondary: &'a mut VerifierCtx,
        target_cursor: &'b mut C6CacheFoldTargetInlineVerifier<'frame>,
    ) -> Result<Self, C6CacheFoldTraceError> {
        validate_online_layer_segments(model_layer, &key_segments, &value_segments)?;
        Ok(Self {
            model_layer,
            key_segments,
            value_segments,
            secondary,
            target_cursor,
            prepared: Vec::new(),
            next_prepared: 0,
            completed_families: 0,
            auxiliary_openings: 0,
            paired_targets: Vec::with_capacity(C6_CACHE_HEADS * 2),
            metrics: C6CacheFoldOnlineLayerMetrics::default(),
            poisoned: false,
        })
    }

    pub fn paired_targets(
        &self,
    ) -> &[(C6CacheFoldKind, [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES])] {
        &self.paired_targets
    }

    pub fn metrics(&self) -> C6CacheFoldOnlineLayerMetrics {
        self.metrics
    }

    fn prepare_family(
        &mut self,
        primary: &mut VerifierCtx,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> Result<(), C6CacheFoldTraceError> {
        self.validate_prepare(kind, model_layer, row_weights, column_weights)?;
        if primary.delta == self.secondary.delta {
            return self.fail("C6 online verifier MAC tapes are not independent");
        }
        let segments = self.segments(kind).to_vec();
        let before_primary = verifier_context_state(primary);
        let before_secondary = verifier_context_state(self.secondary);
        let mut aggregates = [[VerifierKey::ZERO; C6_CACHE_FOLD_TARGET_TAPES]; C6_CACHE_HEADS];
        let mut global_row = 0usize;
        match kind {
            // Match `cache_fold_cols_k`: fold each 64-column head window
            // inside one row, then fold the global row vector.  Only the
            // bounded row key survives each inner fold.
            C6CacheFoldKind::ValueColumns => {
                for segment in &segments {
                    for local_row in 0..segment.rows {
                        let domain = checked_source_domain(segment.base_domain, local_row)?;
                        let keys = [
                            primary.replay_consumed_sub_verifier_keys(
                                domain,
                                C6_CACHE_FOLD_SOURCE_COLUMNS,
                            ),
                            self.secondary.replay_consumed_sub_verifier_keys(
                                domain,
                                C6_CACHE_FOLD_SOURCE_COLUMNS,
                            ),
                        ];
                        for head in 0..C6_CACHE_HEADS {
                            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                                let row_key = (0..C6_CACHE_HEAD_WIDTH).fold(
                                    VerifierKey::ZERO,
                                    |sum, within| {
                                        let channel = head * C6_CACHE_HEAD_WIDTH + within;
                                        sum.add(
                                            keys[tape][channel].scale(column_weights[head][within]),
                                        )
                                    },
                                );
                                aggregates[head][tape] = aggregates[head][tape]
                                    .add(row_key.scale(row_weights[head][global_row]));
                            }
                        }
                        global_row += 1;
                    }
                }
            }
            // Match `cache_fold_rows_k`: retain a 64-column accumulator per
            // segment/head, join segments column-wise, then fold columns.
            // The state is fixed 12*64*2 regardless of cache length.
            C6CacheFoldKind::KeyRows => {
                let mut columns: [[[VerifierKey; C6_CACHE_HEAD_WIDTH]; C6_CACHE_FOLD_TARGET_TAPES];
                    C6_CACHE_HEADS] = [[[VerifierKey::ZERO; C6_CACHE_HEAD_WIDTH];
                    C6_CACHE_FOLD_TARGET_TAPES];
                    C6_CACHE_HEADS];
                for segment in &segments {
                    let mut segment_columns: [[[VerifierKey; C6_CACHE_HEAD_WIDTH];
                        C6_CACHE_FOLD_TARGET_TAPES];
                        C6_CACHE_HEADS] = [[[VerifierKey::ZERO; C6_CACHE_HEAD_WIDTH];
                        C6_CACHE_FOLD_TARGET_TAPES];
                        C6_CACHE_HEADS];
                    for local_row in 0..segment.rows {
                        let domain = checked_source_domain(segment.base_domain, local_row)?;
                        let keys = [
                            primary.replay_consumed_sub_verifier_keys(
                                domain,
                                C6_CACHE_FOLD_SOURCE_COLUMNS,
                            ),
                            self.secondary.replay_consumed_sub_verifier_keys(
                                domain,
                                C6_CACHE_FOLD_SOURCE_COLUMNS,
                            ),
                        ];
                        for head in 0..C6_CACHE_HEADS {
                            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                                for within in 0..C6_CACHE_HEAD_WIDTH {
                                    let channel = head * C6_CACHE_HEAD_WIDTH + within;
                                    let term = VerifierKey::ZERO.add(
                                        keys[tape][channel].scale(row_weights[head][global_row]),
                                    );
                                    segment_columns[head][tape][within] =
                                        segment_columns[head][tape][within].add(term);
                                }
                            }
                        }
                        global_row += 1;
                    }
                    for head in 0..C6_CACHE_HEADS {
                        for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                            for within in 0..C6_CACHE_HEAD_WIDTH {
                                columns[head][tape][within] = columns[head][tape][within]
                                    .add(segment_columns[head][tape][within]);
                            }
                        }
                    }
                }
                for head in 0..C6_CACHE_HEADS {
                    for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                        aggregates[head][tape] =
                            (0..C6_CACHE_HEAD_WIDTH).fold(VerifierKey::ZERO, |sum, within| {
                                sum.add(
                                    columns[head][tape][within].scale(column_weights[head][within]),
                                )
                            });
                    }
                }
            }
        }
        if verifier_context_state(primary) != before_primary
            || verifier_context_state(self.secondary) != before_secondary
        {
            return self.fail("C6 online verifier source replay changed correlation state");
        }
        self.prepared = aggregates
            .into_iter()
            .map(|base_keys| C6OnlinePreparedVerifierTarget { kind, base_keys })
            .collect();
        self.next_prepared = 0;
        self.metrics.source_groups += 1;
        let cells = u64::try_from(global_row * C6_CACHE_FOLD_SOURCE_COLUMNS)
            .map_err(|_| C6CacheFoldTraceError::new("C6 online verifier source census overflow"))?;
        self.metrics.source_cells += cells;
        self.metrics.coefficient_applications += cells;
        Ok(())
    }

    fn correct_next(
        &mut self,
        kind: C6CacheFoldKind,
        transcript: &mut Transcript,
    ) -> Result<VerifierKey, C6CacheFoldTraceError> {
        if self.poisoned {
            return Err(C6CacheFoldTraceError::new("poisoned C6 online verifier layer"));
        }
        let prepared = self.prepared.get(self.next_prepared).copied().ok_or_else(|| {
            C6CacheFoldTraceError::new("C6 online verifier target arrived before family prepare")
        })?;
        if prepared.kind != kind {
            return self.fail("C6 online verifier target order mismatch");
        }
        let corrected =
            self.target_cursor.correct_next_before_product(kind, prepared.base_keys, transcript)?;
        self.paired_targets.push((kind, corrected));
        self.next_prepared += 1;
        self.metrics.corrected_targets += 1;
        if self.next_prepared == self.prepared.len() {
            self.prepared.clear();
            self.next_prepared = 0;
            self.completed_families += 1;
        }
        Ok(corrected[0])
    }

    fn open_current_base(
        &mut self,
        primary: &mut VerifierCtx,
        kind: C6CacheFoldKind,
        point: &[Fp2],
    ) -> Result<VerifierKey, C6CacheFoldTraceError> {
        let expected = [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns]
            .get(self.auxiliary_openings)
            .copied();
        if self.poisoned
            || self.completed_families != 2
            || !self.prepared.is_empty()
            || expected != Some(kind)
        {
            return self.fail("C6 online verifier auxiliary opening order mismatch");
        }
        let segment = *self
            .segments(kind)
            .last()
            .ok_or_else(|| C6CacheFoldTraceError::new("missing C6 current source segment"))?;
        let column_bits = crate::thaler::pad_bits(C6_CACHE_FOLD_SOURCE_COLUMNS);
        if point.len() != column_bits + crate::thaler::pad_bits(segment.rows) {
            return self.fail("C6 online verifier auxiliary opening point mismatch");
        }
        let column_weights = crate::mle::eq_vec(&point[..column_bits]);
        let row_weights = crate::mle::eq_vec(&point[column_bits..]);
        let before = verifier_context_state(primary);
        let mut result = VerifierKey::ZERO;
        for row in 0..segment.rows {
            let domain = checked_source_domain(segment.base_domain, row)?;
            let keys =
                primary.replay_consumed_sub_verifier_keys(domain, C6_CACHE_FOLD_SOURCE_COLUMNS);
            let row_key = keys
                .into_iter()
                .zip(&column_weights)
                .fold(VerifierKey::ZERO, |sum, (key, &weight)| sum.add(key.scale(weight)));
            result = result.add(row_key.scale(row_weights[row]));
        }
        if verifier_context_state(primary) != before {
            return self.fail("C6 online verifier auxiliary replay changed correlation state");
        }
        self.auxiliary_openings += 1;
        self.metrics.linear_auxiliary_source_cells +=
            u64::try_from(segment.rows * C6_CACHE_FOLD_SOURCE_COLUMNS).map_err(|_| {
                C6CacheFoldTraceError::new("C6 online verifier auxiliary census overflow")
            })?;
        Ok(result)
    }

    fn validate_prepare(
        &mut self,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned || !self.prepared.is_empty() || model_layer != self.model_layer {
            return self.fail("C6 online verifier family state/layer mismatch");
        }
        let expected = [C6CacheFoldKind::ValueColumns, C6CacheFoldKind::KeyRows]
            .get(self.completed_families)
            .copied();
        let rows = source_segment_rows(self.segments(kind))?;
        if expected != Some(kind)
            || row_weights.len() != C6_CACHE_HEADS
            || column_weights.len() != C6_CACHE_HEADS
            || row_weights.iter().any(|weights| weights.len() != rows)
            || column_weights.iter().any(|weights| weights.len() != C6_CACHE_HEAD_WIDTH)
        {
            return self.fail("C6 online verifier family geometry/order mismatch");
        }
        Ok(())
    }

    fn segments(&self, kind: C6CacheFoldKind) -> &[C6CacheFoldDirectSourceSegment] {
        match kind {
            C6CacheFoldKind::KeyRows => &self.key_segments,
            C6CacheFoldKind::ValueColumns => &self.value_segments,
        }
    }

    fn finish(&mut self) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned
            || !self.prepared.is_empty()
            || self.completed_families != 2
            || self.auxiliary_openings != 2
            || self.paired_targets.len() != 2 * C6_CACHE_HEADS
        {
            return self.fail("incomplete C6 online verifier layer");
        }
        Ok(())
    }

    fn fail<T>(&mut self, message: &'static str) -> Result<T, C6CacheFoldTraceError> {
        self.poisoned = true;
        Err(C6CacheFoldTraceError::new(message))
    }
}

impl crate::block_proof::C6AttentionProverCache for C6CacheFoldOnlineLayerProver<'_, '_> {
    fn prepare_target_family(
        &mut self,
        primary: &mut CorrelationStream,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> bool {
        self.prepare_family(primary, kind, model_layer, row_weights, column_weights).is_ok()
    }

    fn push_target_before_product(
        &mut self,
        kind: C6CacheFoldKind,
        target: ProverAuthed,
        transcript: &mut Transcript,
    ) -> Option<ProverAuthed> {
        self.push_target(kind, target, transcript).ok()
    }

    fn finish_layer(&mut self) -> bool {
        self.finish().is_ok()
    }
}

impl crate::block_proof::C6AttentionVerifierCache for C6CacheFoldOnlineLayerVerifier<'_, '_, '_> {
    fn segment_rows(&self, kind: C6CacheFoldKind) -> Vec<usize> {
        self.segments(kind).iter().map(|segment| segment.rows).collect()
    }

    fn prepare_target_family(
        &mut self,
        primary: &mut VerifierCtx,
        kind: C6CacheFoldKind,
        model_layer: u16,
        row_weights: &[Vec<Fp2>],
        column_weights: &[Vec<Fp2>],
    ) -> bool {
        self.prepare_family(primary, kind, model_layer, row_weights, column_weights).is_ok()
    }

    fn correct_next_before_product(
        &mut self,
        kind: C6CacheFoldKind,
        transcript: &mut Transcript,
    ) -> Option<VerifierKey> {
        self.correct_next(kind, transcript).ok()
    }

    fn open_current_linear_base(
        &mut self,
        primary: &mut VerifierCtx,
        kind: C6CacheFoldKind,
        point: &[Fp2],
    ) -> Option<crate::block_proof::C6LinearOnlyKey> {
        self.open_current_base(primary, kind, point)
            .ok()
            .map(crate::block_proof::C6LinearOnlyKey::from_replayed_base)
    }

    fn finish_layer(&mut self) -> bool {
        self.finish().is_ok()
    }
}

fn validate_online_layer_segments(
    model_layer: u16,
    key_segments: &[C6CacheFoldDirectSourceSegment],
    value_segments: &[C6CacheFoldDirectSourceSegment],
) -> Result<(), C6CacheFoldTraceError> {
    if model_layer >= C6_CACHE_MODEL_LAYERS
        || key_segments.is_empty()
        || key_segments.len() != value_segments.len()
        || key_segments.iter().zip(value_segments).any(|(key, value)| key.rows != value.rows)
    {
        return Err(C6CacheFoldTraceError::new("invalid C6 online layer source geometry"));
    }
    let key_rows = source_segment_rows(key_segments)?;
    let value_rows = source_segment_rows(value_segments)?;
    if key_rows != value_rows || key_rows > C6_CACHE_MAX_CONTEXT {
        return Err(C6CacheFoldTraceError::new("invalid C6 online layer source row census"));
    }
    for segments in [key_segments, value_segments] {
        for segment in segments {
            let _ = checked_source_domain(segment.base_domain, segment.rows - 1)?;
        }
    }
    Ok(())
}

fn source_segment_rows(
    segments: &[C6CacheFoldDirectSourceSegment],
) -> Result<usize, C6CacheFoldTraceError> {
    segments.iter().try_fold(0usize, |sum, segment| {
        if segment.rows == 0 {
            return Err(C6CacheFoldTraceError::new("empty C6 online direct-source segment"));
        }
        sum.checked_add(segment.rows)
            .ok_or_else(|| C6CacheFoldTraceError::new("C6 online source rows overflow"))
    })
}

fn checked_source_domain(base_domain: u64, local_row: usize) -> Result<u64, C6CacheFoldTraceError> {
    base_domain
        .checked_add(local_row as u64)
        .ok_or_else(|| C6CacheFoldTraceError::new("C6 online source domain range overflow"))
}

fn correlation_stream_state(stream: &CorrelationStream) -> volta_mac::CorrCounters {
    // Keep this hot-path guard O(1).  The replay primitives' permanent
    // pooled tests separately pin audit, cursor and allocation-digest
    // neutrality.
    stream.counters
}

fn verifier_context_state(context: &VerifierCtx) -> volta_mac::CorrCounters {
    context.counters
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct C6CacheFoldSourceOrdinalMetrics {
    pub groups: u64,
    pub source_cells: u64,
    pub coefficient_applications: u64,
    pub target_accumulators: u64,
}

#[derive(Clone, Debug)]
struct C6CacheFoldSourceTarget {
    kind: C6CacheFoldKind,
    model_layer: u16,
    column_offset: usize,
    row_weights: Vec<Fp2>,
    column_weights: Vec<Fp2>,
}

#[derive(Clone, Debug)]
struct C6CacheFoldSourceGroup {
    kind: C6CacheFoldKind,
    model_layer: u16,
    rows: usize,
    target_ordinals: Vec<usize>,
}

/// Factorized source-ordinal compiler for C6FT1 base masks/keys.  It retains
/// at most the registered 576 target accumulators and the already accepted
/// row/column factors; no cache-sized key, mask or dense coefficient vector
/// is part of this type.
#[derive(Clone, Debug)]
pub struct C6CacheFoldSourceOrdinalPlan {
    pub identity: C6CacheFoldTraceIdentity,
    targets: Vec<C6CacheFoldSourceTarget>,
    groups: Vec<C6CacheFoldSourceGroup>,
    metrics: C6CacheFoldSourceOrdinalMetrics,
}

impl C6CacheFoldSourceOrdinalPlan {
    pub fn compile(snapshot: &C6CacheFoldTraceSnapshot) -> Result<Self, C6CacheFoldTraceError> {
        // Reuse the complete geometry/digest/family validator.  The root is
        // irrelevant here; source coefficients remain unfused per target.
        let validated = compile_c6_cache_fold_scalar_batch(snapshot, Fp2::ONE)?;
        let targets = validated
            .terms
            .iter()
            .map(|term| C6CacheFoldSourceTarget {
                kind: term.record.kind,
                model_layer: term.record.model_layer,
                column_offset: term.record.column_offset as usize,
                row_weights: term.factors.row_weights.clone(),
                column_weights: term.factors.column_weights.clone(),
            })
            .collect::<Vec<_>>();
        let mut groups = Vec::new();
        let mut source_cells = 0u64;
        for model_layer in 0..C6_CACHE_MODEL_LAYERS {
            for kind in [C6CacheFoldKind::KeyRows, C6CacheFoldKind::ValueColumns] {
                let target_ordinals = targets
                    .iter()
                    .enumerate()
                    .filter_map(|(ordinal, target)| {
                        (target.model_layer == model_layer && target.kind == kind)
                            .then_some(ordinal)
                    })
                    .collect::<Vec<_>>();
                if target_ordinals.is_empty() {
                    continue;
                }
                let rows = target_ordinals
                    .iter()
                    .map(|&ordinal| targets[ordinal].row_weights.len())
                    .max()
                    .expect("nonempty C6 source group");
                let group_cells = rows
                    .checked_mul(C6_CACHE_FOLD_SOURCE_COLUMNS)
                    .ok_or_else(|| C6CacheFoldTraceError::new("C6 source group cells overflow"))?;
                source_cells = source_cells
                    .checked_add(group_cells as u64)
                    .ok_or_else(|| C6CacheFoldTraceError::new("C6 source cell census overflow"))?;
                groups.push(C6CacheFoldSourceGroup { kind, model_layer, rows, target_ordinals });
            }
        }
        if groups.is_empty() || targets.len() != snapshot.identity.fold_count as usize {
            return Err(C6CacheFoldTraceError::new(
                "C6 source-ordinal plan is empty or incomplete",
            ));
        }
        let metrics = C6CacheFoldSourceOrdinalMetrics {
            groups: groups.len() as u64,
            source_cells,
            coefficient_applications: snapshot.identity.coefficient_applications,
            target_accumulators: targets.len() as u64,
        };
        Ok(Self { identity: snapshot.identity, targets, groups, metrics })
    }

    pub fn metrics(&self) -> C6CacheFoldSourceOrdinalMetrics {
        self.metrics
    }

    pub fn schedule(&self) -> Result<C6CacheFoldTargetSchedule, C6CacheFoldTraceError> {
        C6CacheFoldTargetSchedule::new(
            self.identity,
            self.targets.iter().map(|target| target.kind).collect(),
        )
    }

    pub fn start_prover(&self) -> C6CacheFoldSourceOrdinalProver<'_> {
        C6CacheFoldSourceOrdinalProver {
            plan: self,
            aggregates: vec![[Fp2::ZERO; C6_CACHE_FOLD_TARGET_TAPES]; self.targets.len()],
            next_group: 0,
            applications: 0,
            poisoned: false,
        }
    }

    pub fn start_verifier(&self) -> C6CacheFoldSourceOrdinalVerifier<'_> {
        C6CacheFoldSourceOrdinalVerifier {
            plan: self,
            aggregates: vec![[VerifierKey::ZERO; C6_CACHE_FOLD_TARGET_TAPES]; self.targets.len()],
            next_group: 0,
            applications: 0,
            poisoned: false,
        }
    }
}

pub struct C6CacheFoldSourceOrdinalProver<'a> {
    plan: &'a C6CacheFoldSourceOrdinalPlan,
    aggregates: Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
    next_group: usize,
    applications: u64,
    poisoned: bool,
}

impl C6CacheFoldSourceOrdinalProver<'_> {
    /// Replay already consumed direct-source masks in segment/global-row
    /// order. Replays are counter-neutral and each source cell visits this
    /// compiler exactly once.
    pub fn absorb_consumed_subfield_segments(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        segments: &[C6CacheFoldDirectSourceSegment],
        streams: &mut [volta_mac::CorrelationStream; C6_CACHE_FOLD_TARGET_TAPES],
    ) -> Result<(), C6CacheFoldTraceError> {
        let group = self.begin_group(model_layer, kind, segments)?;
        let counters = [streams[0].counters, streams[1].counters];
        let allocations = [streams[0].allocation_digest_hex(), streams[1].allocation_digest_hex()];
        let mut global_row = 0usize;
        for segment in segments {
            for local_row in 0..segment.rows {
                let domain =
                    segment.base_domain.checked_add(local_row as u64).ok_or_else(|| {
                        self.poisoned = true;
                        C6CacheFoldTraceError::new("C6 prover source domain range overflow")
                    })?;
                let left =
                    streams[0].replay_consumed_sub_masks(domain, C6_CACHE_FOLD_SOURCE_COLUMNS);
                let right =
                    streams[1].replay_consumed_sub_masks(domain, C6_CACHE_FOLD_SOURCE_COLUMNS);
                for channel in 0..C6_CACHE_FOLD_SOURCE_COLUMNS {
                    self.accumulate_cell(
                        group,
                        global_row,
                        channel,
                        [Fp2::from_base(left[channel]), Fp2::from_base(right[channel])],
                    );
                }
                global_row += 1;
            }
        }
        if [streams[0].counters, streams[1].counters] != counters
            || [streams[0].allocation_digest_hex(), streams[1].allocation_digest_hex()]
                != allocations
        {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new(
                "C6 source mask replay changed correlation state",
            ));
        }
        self.end_group(group);
        Ok(())
    }

    pub fn absorb_group<I>(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        rows: usize,
        values: I,
    ) -> Result<(), C6CacheFoldTraceError>
    where
        I: IntoIterator<Item = [Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
    {
        let synthetic = [C6CacheFoldDirectSourceSegment { base_domain: 0, rows }];
        let group = self.begin_group(model_layer, kind, &synthetic)?;
        let mut values = values.into_iter();
        let cells = rows.checked_mul(C6_CACHE_FOLD_SOURCE_COLUMNS).ok_or_else(|| {
            self.poisoned = true;
            C6CacheFoldTraceError::new("C6 prover source group cells overflow")
        })?;
        for index in 0..cells {
            let Some(value) = values.next() else {
                self.poisoned = true;
                return Err(C6CacheFoldTraceError::new("truncated C6 prover source group"));
            };
            self.accumulate_cell(
                group,
                index / C6_CACHE_FOLD_SOURCE_COLUMNS,
                index % C6_CACHE_FOLD_SOURCE_COLUMNS,
                value,
            );
        }
        if values.next().is_some() {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new("trailing C6 prover source cells"));
        }
        self.end_group(group);
        Ok(())
    }

    pub fn finish(
        self,
    ) -> Result<
        (Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>, C6CacheFoldSourceOrdinalMetrics),
        C6CacheFoldTraceError,
    > {
        self.validate_finish()?;
        Ok((self.aggregates, self.plan.metrics))
    }

    fn begin_group(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        segments: &[C6CacheFoldDirectSourceSegment],
    ) -> Result<usize, C6CacheFoldTraceError> {
        if self.poisoned {
            return Err(C6CacheFoldTraceError::new("poisoned C6 prover source compiler"));
        }
        let group = self
            .plan
            .groups
            .get(self.next_group)
            .ok_or_else(|| C6CacheFoldTraceError::new("trailing C6 prover source group"))?;
        let rows = segments.iter().try_fold(0usize, |sum, segment| {
            if segment.rows == 0 {
                return Err(C6CacheFoldTraceError::new("empty C6 direct-source segment"));
            }
            sum.checked_add(segment.rows)
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 direct-source rows overflow"))
        })?;
        if group.model_layer != model_layer || group.kind != kind || group.rows != rows {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new("C6 prover source group order mismatch"));
        }
        Ok(self.next_group)
    }

    fn accumulate_cell(
        &mut self,
        group: usize,
        row: usize,
        channel: usize,
        value: [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
    ) {
        for &ordinal in &self.plan.groups[group].target_ordinals {
            if let Some(coefficient) =
                source_target_coefficient(&self.plan.targets[ordinal], row, channel)
            {
                for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                    self.aggregates[ordinal][tape] += coefficient * value[tape];
                }
                self.applications += 1;
            }
        }
    }

    fn end_group(&mut self, group: usize) {
        debug_assert_eq!(group, self.next_group);
        self.next_group += 1;
    }

    fn validate_finish(&self) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned
            || self.next_group != self.plan.groups.len()
            || self.applications != self.plan.metrics.coefficient_applications
        {
            return Err(C6CacheFoldTraceError::new("incomplete C6 prover source compiler"));
        }
        Ok(())
    }
}

pub struct C6CacheFoldSourceOrdinalVerifier<'a> {
    plan: &'a C6CacheFoldSourceOrdinalPlan,
    aggregates: Vec<[VerifierKey; C6_CACHE_FOLD_TARGET_TAPES]>,
    next_group: usize,
    applications: u64,
    poisoned: bool,
}

impl C6CacheFoldSourceOrdinalVerifier<'_> {
    /// Replay each already-reserved direct base-key source exactly once.  A
    /// C6 verifier reserves in phase-1 allocation order, then chooses this
    /// path instead of materializing corrected CacheSegK.
    pub fn absorb_reserved_subfield_segments(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        segments: &[C6CacheFoldDirectSourceSegment],
        contexts: &mut [volta_mac::VerifierCtx; C6_CACHE_FOLD_TARGET_TAPES],
    ) -> Result<(), C6CacheFoldTraceError> {
        if contexts[0].delta == contexts[1].delta {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new("C6 source MAC tapes are not independent"));
        }
        let group = self.begin_group(model_layer, kind, segments)?;
        let mut global_row = 0usize;
        for segment in segments {
            for local_row in 0..segment.rows {
                let domain =
                    segment.base_domain.checked_add(local_row as u64).ok_or_else(|| {
                        self.poisoned = true;
                        C6CacheFoldTraceError::new("C6 verifier source domain range overflow")
                    })?;
                let left = contexts[0]
                    .replay_consumed_sub_verifier_keys(domain, C6_CACHE_FOLD_SOURCE_COLUMNS);
                let right = contexts[1]
                    .replay_consumed_sub_verifier_keys(domain, C6_CACHE_FOLD_SOURCE_COLUMNS);
                for channel in 0..C6_CACHE_FOLD_SOURCE_COLUMNS {
                    self.accumulate_cell(
                        group,
                        global_row,
                        channel,
                        [left[channel], right[channel]],
                    );
                }
                global_row += 1;
            }
        }
        self.end_group(group);
        Ok(())
    }

    pub fn absorb_group<I>(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        rows: usize,
        values: I,
    ) -> Result<(), C6CacheFoldTraceError>
    where
        I: IntoIterator<Item = [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES]>,
    {
        let synthetic = [C6CacheFoldDirectSourceSegment { base_domain: 0, rows }];
        let group = self.begin_group(model_layer, kind, &synthetic)?;
        let mut values = values.into_iter();
        let cells = rows.checked_mul(C6_CACHE_FOLD_SOURCE_COLUMNS).ok_or_else(|| {
            self.poisoned = true;
            C6CacheFoldTraceError::new("C6 verifier source group cells overflow")
        })?;
        for index in 0..cells {
            let Some(value) = values.next() else {
                self.poisoned = true;
                return Err(C6CacheFoldTraceError::new("truncated C6 verifier source group"));
            };
            self.accumulate_cell(
                group,
                index / C6_CACHE_FOLD_SOURCE_COLUMNS,
                index % C6_CACHE_FOLD_SOURCE_COLUMNS,
                value,
            );
        }
        if values.next().is_some() {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new("trailing C6 verifier source cells"));
        }
        self.end_group(group);
        Ok(())
    }

    pub fn finish(
        self,
    ) -> Result<
        (C6CacheFoldPairedVerifierBaseTargets, C6CacheFoldSourceOrdinalMetrics),
        C6CacheFoldTraceError,
    > {
        self.validate_finish()?;
        let terms =
            self.plan.targets.iter().map(|target| target.kind).zip(self.aggregates).collect();
        Ok((
            C6CacheFoldPairedVerifierBaseTargets::new(self.plan.identity, terms)?,
            self.plan.metrics,
        ))
    }

    fn begin_group(
        &mut self,
        model_layer: u16,
        kind: C6CacheFoldKind,
        segments: &[C6CacheFoldDirectSourceSegment],
    ) -> Result<usize, C6CacheFoldTraceError> {
        if self.poisoned {
            return Err(C6CacheFoldTraceError::new("poisoned C6 verifier source compiler"));
        }
        let group = self
            .plan
            .groups
            .get(self.next_group)
            .ok_or_else(|| C6CacheFoldTraceError::new("trailing C6 verifier source group"))?;
        let rows = segments.iter().try_fold(0usize, |sum, segment| {
            if segment.rows == 0 {
                return Err(C6CacheFoldTraceError::new("empty C6 direct-source segment"));
            }
            sum.checked_add(segment.rows)
                .ok_or_else(|| C6CacheFoldTraceError::new("C6 direct-source rows overflow"))
        })?;
        if group.model_layer != model_layer || group.kind != kind || group.rows != rows {
            self.poisoned = true;
            return Err(C6CacheFoldTraceError::new("C6 verifier source group order mismatch"));
        }
        Ok(self.next_group)
    }

    fn accumulate_cell(
        &mut self,
        group: usize,
        row: usize,
        channel: usize,
        value: [VerifierKey; C6_CACHE_FOLD_TARGET_TAPES],
    ) {
        for &ordinal in &self.plan.groups[group].target_ordinals {
            if let Some(coefficient) =
                source_target_coefficient(&self.plan.targets[ordinal], row, channel)
            {
                for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                    self.aggregates[ordinal][tape] =
                        self.aggregates[ordinal][tape].add(value[tape].scale(coefficient));
                }
                self.applications += 1;
            }
        }
    }

    fn end_group(&mut self, group: usize) {
        debug_assert_eq!(group, self.next_group);
        self.next_group += 1;
    }

    fn validate_finish(&self) -> Result<(), C6CacheFoldTraceError> {
        if self.poisoned
            || self.next_group != self.plan.groups.len()
            || self.applications != self.plan.metrics.coefficient_applications
        {
            return Err(C6CacheFoldTraceError::new("incomplete C6 verifier source compiler"));
        }
        Ok(())
    }
}

fn source_target_coefficient(
    target: &C6CacheFoldSourceTarget,
    row: usize,
    channel: usize,
) -> Option<Fp2> {
    let column = channel.checked_sub(target.column_offset)?;
    if row >= target.row_weights.len() || column >= target.column_weights.len() {
        return None;
    }
    Some(target.row_weights[row] * target.column_weights[column])
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

pub(crate) fn normalize_c6_cache_fold_model_layer(
    schedule_section: u16,
) -> Result<u16, C6CacheFoldTraceError> {
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

fn model_layer(schedule_section: u16) -> Result<u16, C6CacheFoldTraceError> {
    normalize_c6_cache_fold_model_layer(schedule_section)
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
    use crate::prod_check::{prod_batch_prover, prod_batch_verify};
    use volta_field::Fp;
    use volta_mac::{CorrelationStream, ProverAuthed, VerifierCtx, VerifierKey};

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

    fn c6ft1_fixture() -> (
        C6CacheFoldPairedProverTargets,
        Vec<[Fp2; C6_CACHE_FOLD_TARGET_TAPES]>,
        C6CacheFoldPairedVerifierBaseTargets,
        [Fp2; C6_CACHE_FOLD_TARGET_TAPES],
    ) {
        let mut left = capture(true);
        let mut right = left.clone();
        let deltas =
            [Fp2::new(Fp::new(0xD1), Fp::new(0xD2)), Fp2::new(Fp::new(0xE1), Fp::new(0xE2))];
        let mut masks = Vec::with_capacity(left.targets.len());
        for (ordinal, (left_target, right_target)) in
            left.targets.iter_mut().zip(&mut right.targets).enumerate()
        {
            let x = Fp2::new(Fp::new(1_000 + ordinal as u64), Fp::new(2_000 + ordinal as u64));
            let tags = [
                Fp2::new(Fp::new(3_000 + ordinal as u64), Fp::new(4_000 + ordinal as u64)),
                Fp2::new(Fp::new(5_000 + ordinal as u64), Fp::new(6_000 + ordinal as u64)),
            ];
            let target_masks = [
                Fp2::new(Fp::new(7_000 + ordinal as u64), Fp::new(8_000 + ordinal as u64)),
                Fp2::new(Fp::new(9_000 + ordinal as u64), Fp::new(10_000 + ordinal as u64)),
            ];
            *left_target = C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(x, tags[0]));
            *right_target = C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(x, tags[1]));
            masks.push(target_masks);
        }
        let prover = C6CacheFoldPairedProverTargets::pair([&left, &right]).unwrap();
        let base_terms = prover
            .terms()
            .zip(&masks)
            .map(|((kind, targets), masks)| {
                (
                    kind,
                    std::array::from_fn(|tape| {
                        VerifierKey::new(targets[tape].m + deltas[tape] * masks[tape])
                    }),
                )
            })
            .collect();
        let verifier =
            C6CacheFoldPairedVerifierBaseTargets::new(prover.identity, base_terms).unwrap();
        (prover, masks, verifier, deltas)
    }

    #[test]
    fn c6ft1_codec_is_fixed_canonical_and_fail_closed() {
        let (prover, masks, _, _) = c6ft1_fixture();
        let statement_digest = [0xA6; 32];
        let frame = C6CacheFoldTargetCorrectionFrame::from_prover_targets(
            statement_digest,
            &prover,
            &masks,
        )
        .unwrap();
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded.len() as u64, C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);
        assert_eq!(C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES, 18_480);
        assert_eq!(
            C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES,
            crate::C6_RESPONSE_CACHE_FOLD_TARGET_BYTES
        );
        assert_eq!(frame.live_count(), 24);
        assert_eq!(
            C6CacheFoldTargetCorrectionFrame::decode(statement_digest, prover.identity, &encoded)
                .unwrap(),
            frame
        );
        let live_end = C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize
            + frame.live_count() * C6_CACHE_FOLD_TARGET_SLOT_BYTES as usize;
        assert!(encoded[live_end..].iter().all(|&byte| byte == 0));

        let mut nonzero_tail = encoded.clone();
        *nonzero_tail.last_mut().unwrap() = 1;
        assert!(C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &nonzero_tail,
        )
        .is_err());
        let mut noncanonical = encoded.clone();
        noncanonical[C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize
            ..C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize + 8]
            .copy_from_slice(&P.to_le_bytes());
        assert!(C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &noncanonical,
        )
        .is_err());
        let mut wrong_capacity = encoded.clone();
        wrong_capacity[14..16].copy_from_slice(&575u16.to_le_bytes());
        assert!(C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &wrong_capacity,
        )
        .is_err());
        assert!(C6CacheFoldTargetCorrectionFrame::decode([0xB6; 32], prover.identity, &encoded,)
            .is_err());
        let mut wrong_identity = prover.identity;
        wrong_identity.instance_digest[0] ^= 1;
        let wrong_base_targets = C6CacheFoldPairedVerifierBaseTargets::new(
            wrong_identity,
            prover
                .terms()
                .map(|(kind, _)| (kind, [VerifierKey::ZERO; C6_CACHE_FOLD_TARGET_TAPES]))
                .collect(),
        )
        .unwrap();
        let mut transcript = Transcript::new([0xB7; 32]);
        assert!(frame
            .start_verifier_stream(
                &wrong_base_targets,
                [Fp2::ONE, Fp2::new(Fp::new(2), Fp::ZERO)],
                &mut transcript,
            )
            .is_err());
        let schedule = C6CacheFoldTargetSchedule::from_prover_targets(&prover).unwrap();
        let mut early_tx = Transcript::new([0xB8; 32]);
        let early = C6CacheFoldTargetInlineProver::start(statement_digest, schedule, &mut early_tx)
            .unwrap();
        assert!(early.finish_before_successor_root(&mut early_tx).is_err());
        assert!(C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &encoded[..encoded.len() - 1],
        )
        .is_err());
    }

    #[test]
    fn c6ft1_online_start_defers_runtime_identity_until_before_root() {
        let (prover, masks, verifier, deltas) = c6ft1_fixture();
        let statement_digest = [0xBA; 32];
        let full_schedule = C6CacheFoldTargetSchedule::from_prover_targets(&prover).unwrap();
        let public_schedule =
            C6CacheFoldTargetPublicSchedule::new(full_schedule.kinds().collect::<Vec<_>>())
                .unwrap();
        let mut prover_tx = Transcript::new([0xBB; 32]);
        let mut online = C6CacheFoldTargetInlineProver::start_public(
            statement_digest,
            public_schedule.clone(),
            &mut prover_tx,
        )
        .unwrap();
        for (ordinal, (kind, targets)) in prover.terms().enumerate() {
            online
                .push_target_before_product(kind, targets, masks[ordinal], &mut prover_tx)
                .unwrap();
            let _ = prover_tx.challenge_fp2();
        }
        let (frame, fixed) = online
            .finish_before_successor_root_with_identity(prover.identity, &mut prover_tx)
            .unwrap();
        assert_eq!(fixed.identity(), prover.identity);
        assert_eq!(prover_tx.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);
        let disk_frame = C6CacheFoldTargetPublicCorrectionFrame::decode(
            statement_digest,
            &frame.encode().unwrap(),
        )
        .unwrap();
        assert_eq!(disk_frame.statement_digest(), statement_digest);
        assert_eq!(disk_frame.live_count(), prover.terms().count());

        let verifier_terms = verifier.terms().collect::<Vec<_>>();
        let run_verifier = |identity: C6CacheFoldTraceIdentity| {
            let mut tx = Transcript::new([0xBB; 32]);
            let mut online = C6CacheFoldTargetInlineVerifier::start_public(
                &frame,
                public_schedule.clone(),
                deltas,
                &mut tx,
            )
            .unwrap();
            for &(kind, base) in &verifier_terms {
                online.correct_next_before_product(kind, base, &mut tx).unwrap();
                let _ = tx.challenge_fp2();
            }
            let result = online.finish_before_successor_root_with_identity(identity, &mut tx);
            (result, tx)
        };
        let (accepted, accepted_tx) = run_verifier(prover.identity);
        assert!(accepted.is_ok());
        assert_eq!(accepted_tx.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);
        assert_eq!(accepted_tx.ledger(), prover_tx.ledger());

        let mut disk_tx = Transcript::new([0xBB; 32]);
        let mut disk = C6CacheFoldTargetInlineVerifier::start_decoded_public(
            &disk_frame,
            public_schedule.clone(),
            deltas,
            &mut disk_tx,
        )
        .unwrap();
        for &(kind, base) in &verifier_terms {
            disk.correct_next_before_product(kind, base, &mut disk_tx).unwrap();
            let _ = disk_tx.challenge_fp2();
        }
        assert_eq!(
            disk.finish_before_successor_root_with_identity(prover.identity, &mut disk_tx)
                .unwrap()
                .identity(),
            prover.identity
        );
        assert_eq!(disk_tx.ledger(), prover_tx.ledger());

        let mut wrong = prover.identity;
        wrong.instance_digest[0] ^= 1;
        let (rejected, rejected_tx) = run_verifier(wrong);
        assert!(rejected.is_err());
        assert_eq!(rejected_tx.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);

        let mut early_tx = Transcript::new([0xBC; 32]);
        let early = C6CacheFoldTargetInlineVerifier::start_public(
            &frame,
            public_schedule,
            deltas,
            &mut early_tx,
        )
        .unwrap();
        assert!(early
            .finish_before_successor_root_with_identity(prover.identity, &mut early_tx)
            .is_err());
        assert_eq!(early_tx.total_bytes(), C6_CACHE_FOLD_TARGET_HEADER_BYTES);
    }

    #[test]
    fn c6ft1_stream_feeds_product_closure_and_exact_c6ps1_fold() {
        let (prover, masks, verifier, deltas) = c6ft1_fixture();
        let statement_digest = [0xC6; 32];
        let frame = C6CacheFoldTargetCorrectionFrame::from_prover_targets(
            statement_digest,
            &prover,
            &masks,
        )
        .unwrap();
        let decoded = C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &frame.encode().unwrap(),
        )
        .unwrap();
        let mut prover_tx = Transcript::new([0x31; 32]);
        let mut verifier_tx = Transcript::new([0x31; 32]);
        let schedule = C6CacheFoldTargetSchedule::from_prover_targets(&prover).unwrap();
        let mut prover_stream = C6CacheFoldTargetInlineProver::start(
            statement_digest,
            schedule.clone(),
            &mut prover_tx,
        )
        .unwrap();
        let mut verifier_stream =
            C6CacheFoldTargetInlineVerifier::start(&decoded, schedule, deltas, &mut verifier_tx)
                .unwrap();
        let seeds = [[0x41; 32], [0x42; 32]];
        let mut correlation_streams =
            [CorrelationStream::new(seeds[0]), CorrelationStream::new(seeds[1])];
        let mut contexts =
            [VerifierCtx::new(seeds[0], deltas[0]), VerifierCtx::new(seeds[1], deltas[1])];
        let prover_terms = prover.terms().collect::<Vec<_>>();
        let verifier_terms = verifier.terms().collect::<Vec<_>>();
        for ordinal in 0..prover_terms.len() {
            let (prover_kind, raw_targets) = prover_terms[ordinal];
            let targets = prover_stream
                .push_target_before_product(
                    prover_kind,
                    raw_targets,
                    masks[ordinal],
                    &mut prover_tx,
                )
                .unwrap();
            let (verifier_kind, base_keys) = verifier_terms[ordinal];
            let corrected_keys = verifier_stream
                .correct_next_before_product(verifier_kind, base_keys, &mut verifier_tx)
                .unwrap();
            assert_eq!(prover_kind, verifier_kind);
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                assert_eq!(
                    corrected_keys[tape].k,
                    targets[tape].m + deltas[tape] * targets[tape].x
                );
            }
            let chi = prover_tx.challenge_fp2();
            assert_eq!(chi, verifier_tx.challenge_fp2());
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                let multiplier = Fp2::from_base(Fp::new(17 + ordinal as u64));
                let output = targets[tape].scale(multiplier);
                let output_key = VerifierKey::new(output.m + deltas[tape] * output.x);
                let mask = correlation_streams[tape].draw_product_mask(0x6000 + ordinal as u64, 1);
                let key_mask =
                    contexts[tape].expand_product_mask_verifier_key(0x6000 + ordinal as u64, 1);
                let proof = prod_batch_prover(
                    &[(ProverAuthed::from_public(multiplier), targets[tape], output)],
                    chi,
                    mask,
                    &mut prover_tx,
                );
                assert!(prod_batch_verify(
                    &[(
                        VerifierKey::from_public(multiplier, deltas[tape]),
                        corrected_keys[tape],
                        output_key,
                    )],
                    key_mask,
                    deltas[tape],
                    chi,
                    &proof,
                ));
                verifier_tx.append("prod_check_m0_m1", 32);
            }
        }
        let (streamed_frame, prover_fixed) =
            prover_stream.finish_before_successor_root(&mut prover_tx).unwrap();
        assert_eq!(streamed_frame, frame);
        let verifier_fixed =
            verifier_stream.finish_before_successor_root(&mut verifier_tx).unwrap();
        assert_eq!(prover_tx.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES + 24 * 64);
        assert_eq!(prover_tx.total_bytes(), verifier_tx.total_bytes());
        assert_eq!(
            prover_tx.bytes_for(C6_CACHE_FOLD_TARGET_HEADER_LABEL),
            C6_CACHE_FOLD_TARGET_HEADER_BYTES
        );
        assert_eq!(
            prover_tx.bytes_for(C6_CACHE_FOLD_TARGET_SLOT_LABEL),
            24 * C6_CACHE_FOLD_TARGET_SLOT_BYTES
        );
        assert_eq!(
            prover_tx.bytes_for(C6_CACHE_FOLD_TARGET_PADDING_LABEL),
            (C6_CACHE_FOLD_MAX_RECORDS as u64 - 24) * C6_CACHE_FOLD_TARGET_SLOT_BYTES
        );
        let scalar_root = prover_tx.challenge_fp2();
        assert_eq!(scalar_root, verifier_tx.challenge_fp2());
        let folded = prover_fixed.fold_corrections(scalar_root);
        assert_eq!(folded, verifier_fixed.fold_corrections(scalar_root));
        let mut direct = [[Fp2::ZERO; C6_CACHE_FOLD_TARGET_TAPES]; 2];
        let mut weight = scalar_root;
        for (((kind, targets), masks), correction) in
            prover_terms.iter().zip(&masks).zip(&frame.corrections)
        {
            let kv = match kind {
                C6CacheFoldKind::KeyRows => 0,
                C6CacheFoldKind::ValueColumns => 1,
            };
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                assert_eq!(correction[tape], targets[tape].x - masks[tape]);
                direct[kv][tape] += weight * (targets[tape].x - masks[tape]);
            }
            weight = weight * scalar_root;
        }
        assert_eq!(folded, direct);
    }

    #[test]
    fn c6ft1_tamper_is_rejected_by_independent_product_target_key() {
        let (prover, masks, verifier, deltas) = c6ft1_fixture();
        let statement_digest = [0xD6; 32];
        let honest = C6CacheFoldTargetCorrectionFrame::from_prover_targets(
            statement_digest,
            &prover,
            &masks,
        )
        .unwrap();
        let mut tampered_bytes = honest.encode().unwrap();
        tampered_bytes[C6_CACHE_FOLD_TARGET_HEADER_BYTES as usize] ^= 1;
        let tampered = C6CacheFoldTargetCorrectionFrame::decode(
            statement_digest,
            prover.identity,
            &tampered_bytes,
        )
        .unwrap();
        let mut prover_tx = Transcript::new([0x51; 32]);
        let mut verifier_tx = Transcript::new([0x51; 32]);
        let mut prover_stream =
            honest.start_prover_stream(&prover, &masks, &mut prover_tx).unwrap();
        let mut verifier_stream =
            tampered.start_verifier_stream(&verifier, deltas, &mut verifier_tx).unwrap();
        let (_, targets) = prover_stream.next_target(&mut prover_tx).unwrap();
        let (_, corrected_keys) = verifier_stream.next_target(&mut verifier_tx).unwrap();
        let chi = prover_tx.challenge_fp2();
        assert_eq!(chi, verifier_tx.challenge_fp2());
        let multiplier = Fp2::from_base(Fp::new(19));
        let output = targets[0].scale(multiplier);
        let output_key = VerifierKey::new(output.m + deltas[0] * output.x);
        let seed = [0x61; 32];
        let mut correlation_stream = CorrelationStream::new(seed);
        let mut context = VerifierCtx::new(seed, deltas[0]);
        let proof = prod_batch_prover(
            &[(ProverAuthed::from_public(multiplier), targets[0], output)],
            chi,
            correlation_stream.draw_product_mask(0x7000, 1),
            &mut prover_tx,
        );
        assert!(!prod_batch_verify(
            &[(VerifierKey::from_public(multiplier, deltas[0]), corrected_keys[0], output_key,)],
            context.expand_product_mask_verifier_key(0x7000, 1),
            deltas[0],
            chi,
            &proof,
        ));
    }

    fn dense_source_fold(target: &C6CacheFoldSourceTarget, source: &[Fp2]) -> Fp2 {
        let mut result = Fp2::ZERO;
        for (row, &row_weight) in target.row_weights.iter().enumerate() {
            for (column, &column_weight) in target.column_weights.iter().enumerate() {
                result += row_weight
                    * column_weight
                    * source[row * C6_CACHE_FOLD_SOURCE_COLUMNS + target.column_offset + column];
            }
        }
        result
    }

    #[test]
    fn source_ordinal_stream_replaces_dense_cache_keys_and_feeds_c6ft1() {
        let mut left = capture(true);
        let mut right = left.clone();
        let plan = C6CacheFoldSourceOrdinalPlan::compile(&left).unwrap();
        assert_eq!(
            plan.metrics(),
            C6CacheFoldSourceOrdinalMetrics {
                groups: 2,
                source_cells: 2 * 4 * C6_CACHE_FOLD_SOURCE_COLUMNS as u64,
                coefficient_applications: 24 * 4 * C6_CACHE_HEAD_WIDTH as u64,
                target_accumulators: 24,
            }
        );
        let seeds = [[0x71; 32], [0x72; 32]];
        let deltas =
            [Fp2::new(Fp::new(0x711), Fp::new(0x712)), Fp2::new(Fp::new(0x721), Fp::new(0x722))];
        let mut streams = [CorrelationStream::new(seeds[0]), CorrelationStream::new(seeds[1])];
        let mut contexts =
            [VerifierCtx::new(seeds[0], deltas[0]), VerifierCtx::new(seeds[1], deltas[1])];
        let groups =
            [(C6CacheFoldKind::KeyRows, 0x7100u64), (C6CacheFoldKind::ValueColumns, 0x7200u64)];
        let mut plaintexts = Vec::new();
        let mut source_masks: [Vec<Vec<Fp2>>; C6_CACHE_FOLD_TARGET_TAPES] =
            std::array::from_fn(|_| Vec::new());
        let mut source_tags: [Vec<Vec<Fp2>>; C6_CACHE_FOLD_TARGET_TAPES] =
            std::array::from_fn(|_| Vec::new());
        for (group_index, (_, base_domain)) in groups.iter().enumerate() {
            let values = (0..4 * C6_CACHE_FOLD_SOURCE_COLUMNS)
                .map(|index| {
                    Fp2::from_base(Fp::new(1 + group_index as u64 * 10_000 + index as u64))
                })
                .collect::<Vec<_>>();
            plaintexts.push(values);
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                let mut masks = Vec::new();
                let mut tags = Vec::new();
                for row in 0..4 {
                    masks.extend(
                        streams[tape]
                            .draw_sub_masks(base_domain + row as u64, C6_CACHE_FOLD_SOURCE_COLUMNS)
                            .into_iter()
                            .map(Fp2::from_base),
                    );
                    tags.extend(
                        streams[tape]
                            .draw_sub_tags(base_domain + row as u64, C6_CACHE_FOLD_SOURCE_COLUMNS),
                    );
                }
                source_masks[tape].push(masks);
                source_tags[tape].push(tags);
                contexts[tape].reserve_sub_key_rows(*base_domain, 4, C6_CACHE_FOLD_SOURCE_COLUMNS);
            }
        }
        for (ordinal, target) in plan.targets.iter().enumerate() {
            let group = match target.kind {
                C6CacheFoldKind::KeyRows => 0,
                C6CacheFoldKind::ValueColumns => 1,
            };
            let x = dense_source_fold(target, &plaintexts[group]);
            let tags: [Fp2; C6_CACHE_FOLD_TARGET_TAPES] =
                std::array::from_fn(|tape| dense_source_fold(target, &source_tags[tape][group]));
            left.targets[ordinal] =
                C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(x, tags[0]));
            right.targets[ordinal] =
                C6CacheFoldAuthenticatedTarget::Prover(ProverAuthed::new(x, tags[1]));
        }
        let paired = C6CacheFoldPairedProverTargets::pair([&left, &right]).unwrap();
        let prover_counters = [streams[0].counters, streams[1].counters];
        let mut prover_compiler = plan.start_prover();
        for &(kind, base_domain) in &groups {
            prover_compiler
                .absorb_consumed_subfield_segments(
                    0,
                    kind,
                    &[C6CacheFoldDirectSourceSegment { base_domain, rows: 4 }],
                    &mut streams,
                )
                .unwrap();
        }
        let (target_masks, prover_metrics) = prover_compiler.finish().unwrap();
        assert_eq!(prover_metrics, plan.metrics());
        assert_eq!([streams[0].counters, streams[1].counters], prover_counters);

        let mut verifier_compiler = plan.start_verifier();
        for &(kind, base_domain) in &groups {
            verifier_compiler
                .absorb_reserved_subfield_segments(
                    0,
                    kind,
                    &[C6CacheFoldDirectSourceSegment { base_domain, rows: 4 }],
                    &mut contexts,
                )
                .unwrap();
        }
        let (base_targets, verifier_metrics) = verifier_compiler.finish().unwrap();
        assert_eq!(verifier_metrics, plan.metrics());
        assert_eq!(contexts[0].counters, streams[0].counters);
        assert_eq!(contexts[1].counters, streams[1].counters);

        for (ordinal, target) in plan.targets.iter().enumerate() {
            let group = match target.kind {
                C6CacheFoldKind::KeyRows => 0,
                C6CacheFoldKind::ValueColumns => 1,
            };
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                assert_eq!(
                    target_masks[ordinal][tape],
                    dense_source_fold(target, &source_masks[tape][group])
                );
            }
        }

        let statement_digest = [0x73; 32];
        let frame = C6CacheFoldTargetCorrectionFrame::from_prover_targets(
            statement_digest,
            &paired,
            &target_masks,
        )
        .unwrap();
        let schedule = plan.schedule().unwrap();
        let mut transcript = Transcript::new([0x74; 32]);
        let mut verifier_stream =
            C6CacheFoldTargetInlineVerifier::start(&frame, schedule, deltas, &mut transcript)
                .unwrap();
        for ((kind, targets), (base_kind, base)) in paired.terms().zip(base_targets.terms()) {
            assert_eq!(kind, base_kind);
            let corrected =
                verifier_stream.correct_next_before_product(kind, base, &mut transcript).unwrap();
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                assert_eq!(corrected[tape].k, targets[tape].m + deltas[tape] * targets[tape].x);
            }
        }
        let _ = verifier_stream.finish_before_successor_root(&mut transcript).unwrap();
        assert_eq!(transcript.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);

        let mut reordered = plan.start_prover();
        assert!(reordered
            .absorb_group(
                0,
                C6CacheFoldKind::ValueColumns,
                4,
                std::iter::repeat_n([Fp2::ZERO; 2], 4 * C6_CACHE_FOLD_SOURCE_COLUMNS),
            )
            .is_err());
        assert!(reordered.finish().is_err());
        let mut truncated = plan.start_prover();
        assert!(truncated
            .absorb_group(
                0,
                C6CacheFoldKind::KeyRows,
                4,
                std::iter::repeat_n([Fp2::ZERO; 2], 4 * C6_CACHE_FOLD_SOURCE_COLUMNS - 1,),
            )
            .is_err());
        assert!(truncated.finish().is_err());
    }

    #[test]
    fn online_layer_family_stream_is_inline_and_keeps_auxiliary_claims_linear() {
        let snapshot = capture(true);
        let plan = C6CacheFoldSourceOrdinalPlan::compile(&snapshot).unwrap();
        let full_schedule = plan.schedule().unwrap();
        let public_schedule = full_schedule.public_schedule();
        let statement_digest = [0x91; 32];
        let seeds = [[0x92; 32], [0x93; 32]];
        let deltas =
            [Fp2::new(Fp::new(0x921), Fp::new(0x922)), Fp2::new(Fp::new(0x931), Fp::new(0x932))];
        let groups =
            [(C6CacheFoldKind::KeyRows, 0x9100u64), (C6CacheFoldKind::ValueColumns, 0x9200u64)];
        let plaintexts = [
            (0..4 * C6_CACHE_FOLD_SOURCE_COLUMNS)
                .map(|index| Fp2::from_base(Fp::new(10_000 + index as u64)))
                .collect::<Vec<_>>(),
            (0..4 * C6_CACHE_FOLD_SOURCE_COLUMNS)
                .map(|index| Fp2::from_base(Fp::new(20_000 + index as u64)))
                .collect::<Vec<_>>(),
        ];
        let mut streams = [CorrelationStream::new(seeds[0]), CorrelationStream::new(seeds[1])];
        let mut contexts =
            [VerifierCtx::new(seeds[0], deltas[0]), VerifierCtx::new(seeds[1], deltas[1])];
        let mut masks: [[Vec<Fp2>; 2]; C6_CACHE_FOLD_TARGET_TAPES] =
            std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
        let mut tags: [[Vec<Fp2>; 2]; C6_CACHE_FOLD_TARGET_TAPES] =
            std::array::from_fn(|_| std::array::from_fn(|_| Vec::new()));
        for (group_index, (_, base_domain)) in groups.iter().enumerate() {
            for tape in 0..C6_CACHE_FOLD_TARGET_TAPES {
                for row in 0..4 {
                    masks[tape][group_index].extend(
                        streams[tape]
                            .draw_sub_masks(base_domain + row as u64, C6_CACHE_FOLD_SOURCE_COLUMNS)
                            .into_iter()
                            .map(Fp2::from_base),
                    );
                    tags[tape][group_index].extend(
                        streams[tape]
                            .draw_sub_tags(base_domain + row as u64, C6_CACHE_FOLD_SOURCE_COLUMNS),
                    );
                }
                contexts[tape].reserve_sub_key_rows(*base_domain, 4, C6_CACHE_FOLD_SOURCE_COLUMNS);
            }
        }

        let prover_targets = plan
            .targets
            .iter()
            .map(|target| {
                let group = match target.kind {
                    C6CacheFoldKind::KeyRows => 0,
                    C6CacheFoldKind::ValueColumns => 1,
                };
                let x = dense_source_fold(target, &plaintexts[group]);
                (
                    target.kind,
                    [
                        ProverAuthed::new(x, dense_source_fold(target, &tags[0][group])),
                        ProverAuthed::new(x, dense_source_fold(target, &tags[1][group])),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let value_rows = plan.targets[..C6_CACHE_HEADS]
            .iter()
            .map(|target| target.row_weights.clone())
            .collect::<Vec<_>>();
        let value_columns = plan.targets[..C6_CACHE_HEADS]
            .iter()
            .map(|target| target.column_weights.clone())
            .collect::<Vec<_>>();
        let key_rows = plan.targets[C6_CACHE_HEADS..]
            .iter()
            .map(|target| target.row_weights.clone())
            .collect::<Vec<_>>();
        let key_columns = plan.targets[C6_CACHE_HEADS..]
            .iter()
            .map(|target| target.column_weights.clone())
            .collect::<Vec<_>>();
        let key_segments = vec![C6CacheFoldDirectSourceSegment { base_domain: 0x9100, rows: 4 }];
        let value_segments = vec![C6CacheFoldDirectSourceSegment { base_domain: 0x9200, rows: 4 }];

        let mut prover_tx = Transcript::new([0x94; 32]);
        let mut builder = C6CacheFoldTargetInlineProver::start_public(
            statement_digest,
            public_schedule.clone(),
            &mut prover_tx,
        )
        .unwrap();
        let (primary_stream, secondary_stream) = streams.split_at_mut(1);
        let mut online_prover = C6CacheFoldOnlineLayerProver::new(
            0,
            key_segments.clone(),
            value_segments.clone(),
            &mut secondary_stream[0],
            &mut builder,
        )
        .unwrap();
        online_prover
            .prepare_family(
                &mut primary_stream[0],
                C6CacheFoldKind::ValueColumns,
                0,
                &value_rows,
                &value_columns,
            )
            .unwrap();
        let mut product_challenges = Vec::with_capacity(2 * C6_CACHE_HEADS);
        for &(kind, targets) in &prover_targets[..C6_CACHE_HEADS] {
            let accepted = online_prover.push_target(kind, targets[0], &mut prover_tx).unwrap();
            assert_eq!(accepted, targets[0]);
            product_challenges.push(prover_tx.challenge_fp2());
        }
        online_prover
            .prepare_family(
                &mut primary_stream[0],
                C6CacheFoldKind::KeyRows,
                0,
                &key_rows,
                &key_columns,
            )
            .unwrap();
        for &(kind, targets) in &prover_targets[C6_CACHE_HEADS..] {
            let accepted = online_prover.push_target(kind, targets[0], &mut prover_tx).unwrap();
            assert_eq!(accepted, targets[0]);
            product_challenges.push(prover_tx.challenge_fp2());
        }
        online_prover.finish().unwrap();
        assert_eq!(
            online_prover.metrics(),
            C6CacheFoldOnlineLayerMetrics {
                source_groups: 2,
                source_cells: 2 * 4 * C6_CACHE_FOLD_SOURCE_COLUMNS as u64,
                coefficient_applications: 2 * 4 * C6_CACHE_FOLD_SOURCE_COLUMNS as u64,
                corrected_targets: 24,
                linear_auxiliary_source_cells: 0,
            }
        );
        assert_eq!(online_prover.paired_targets(), prover_targets);
        drop(online_prover);
        let (frame, _) = builder
            .finish_before_successor_root_with_identity(snapshot.identity, &mut prover_tx)
            .unwrap();

        let mut verifier_tx = Transcript::new([0x94; 32]);
        let mut cursor = C6CacheFoldTargetInlineVerifier::start_public(
            &frame,
            public_schedule,
            deltas,
            &mut verifier_tx,
        )
        .unwrap();
        let (primary_context, secondary_context) = contexts.split_at_mut(1);
        let mut online_verifier = C6CacheFoldOnlineLayerVerifier::new(
            0,
            key_segments,
            value_segments,
            &mut secondary_context[0],
            &mut cursor,
        )
        .unwrap();
        online_verifier
            .prepare_family(
                &mut primary_context[0],
                C6CacheFoldKind::ValueColumns,
                0,
                &value_rows,
                &value_columns,
            )
            .unwrap();
        for &(kind, targets) in &prover_targets[..C6_CACHE_HEADS] {
            let key = online_verifier.correct_next(kind, &mut verifier_tx).unwrap();
            assert_eq!(key.k, targets[0].m + deltas[0] * targets[0].x);
            assert_eq!(
                product_challenges[online_verifier.paired_targets().len() - 1],
                verifier_tx.challenge_fp2()
            );
        }
        online_verifier
            .prepare_family(
                &mut primary_context[0],
                C6CacheFoldKind::KeyRows,
                0,
                &key_rows,
                &key_columns,
            )
            .unwrap();
        for &(kind, targets) in &prover_targets[C6_CACHE_HEADS..] {
            let key = online_verifier.correct_next(kind, &mut verifier_tx).unwrap();
            assert_eq!(key.k, targets[0].m + deltas[0] * targets[0].x);
            assert_eq!(
                product_challenges[online_verifier.paired_targets().len() - 1],
                verifier_tx.challenge_fp2()
            );
        }

        for (kind, group) in [(C6CacheFoldKind::KeyRows, 0), (C6CacheFoldKind::ValueColumns, 1)] {
            let point = (0..12)
                .map(|index| Fp2::new(Fp::new(31 + index as u64), Fp::new(61 + index as u64)))
                .collect::<Vec<_>>();
            let base =
                online_verifier.open_current_base(&mut primary_context[0], kind, &point).unwrap();
            let column_weights = crate::mle::eq_vec(&point[..10]);
            let row_weights = crate::mle::eq_vec(&point[10..]);
            let target = C6CacheFoldSourceTarget {
                kind,
                model_layer: 0,
                column_offset: 0,
                row_weights,
                column_weights: column_weights[..C6_CACHE_FOLD_SOURCE_COLUMNS].to_vec(),
            };
            let x = dense_source_fold(&target, &plaintexts[group]);
            let mask = dense_source_fold(&target, &masks[0][group]);
            let tag = dense_source_fold(&target, &tags[0][group]);
            assert_eq!(base.k + deltas[0] * (x - mask), tag + deltas[0] * x);
        }
        online_verifier.finish().unwrap();
        assert_eq!(online_verifier.paired_targets().len(), 24);
        assert_eq!(online_verifier.metrics().linear_auxiliary_source_cells, 2 * 4 * 768);
        drop(online_verifier);
        cursor
            .finish_before_successor_root_with_identity(snapshot.identity, &mut verifier_tx)
            .unwrap();
        assert_eq!(verifier_tx.ledger(), prover_tx.ledger());
        assert_eq!(verifier_tx.total_bytes(), C6_CACHE_FOLD_TARGET_PRODUCTION_BYTES);
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
        let mut layer = vec![Fp2::ONE; C6_CACHE_MAX_CONTEXT * (1 << 10)];
        assert_eq!(
            plan.write_padded_layer_coefficients(C6CacheFoldKind::ValueColumns, 0, &mut layer)
                .unwrap(),
            (C6_CACHE_HEADS * 4 * C6_CACHE_HEAD_WIDTH) as u64
        );
        for row in 0..C6_CACHE_MAX_CONTEXT {
            for channel in 0..(1 << 10) {
                let expected = if row < 4 && channel < C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH {
                    dense_value[row * C6_CACHE_HEADS * C6_CACHE_HEAD_WIDTH + channel]
                } else {
                    Fp2::ZERO
                };
                assert_eq!(layer[row * (1 << 10) + channel], expected);
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
