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
use volta_mac::C6TraceToken;

pub const C6_CACHE_FOLD_TRACE_VERSION: u32 = 1;

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

/// Completed role-local capture. Targets remain opaque provenance handles;
/// they do not participate in prover/verifier digest equality because the
/// two operation traces use distinct namespaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct C6CacheFoldTraceSnapshot {
    pub party: C6CacheFoldParty,
    pub identity: C6CacheFoldTraceIdentity,
    pub records: Vec<C6CacheFoldRecord>,
    pub targets: Vec<C6TraceToken>,
}

#[derive(Debug)]
struct C6CacheFoldTraceRuntime {
    capture_id: u64,
    party: C6CacheFoldParty,
    records: Vec<C6CacheFoldRecord>,
    targets: Vec<C6TraceToken>,
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
    target: C6TraceToken,
) -> Result<(), C6CacheFoldTraceError> {
    C6_CACHE_FOLD_TRACE_RUNTIME.with(|cell| {
        let mut slot = cell
            .try_borrow_mut()
            .map_err(|_| C6CacheFoldTraceError::new("C6 cache-fold trace is borrowed"))?;
        let Some(runtime) = slot.as_mut() else {
            return Ok(());
        };
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
    if runtime.records.is_empty() || runtime.records.len() != runtime.targets.len() {
        return Err(C6CacheFoldTraceError::new(
            "C6 cache-fold trace is empty or has a target-count mismatch",
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

#[cfg(test)]
mod tests {
    use super::*;
    use volta_field::Fp;
    use volta_mac::ProverAuthed;

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
                ProverAuthed::ZERO.c6_trace_token(),
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
    fn malformed_geometry_and_nested_capture_fail_closed() {
        let guard = begin_c6_cache_fold_trace(C6CacheFoldParty::Verifier).unwrap();
        assert!(begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).is_err());
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
            ProverAuthed::ZERO.c6_trace_token(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("do not cover"));
        drop(guard);
        let next = begin_c6_cache_fold_trace(C6CacheFoldParty::Prover).unwrap();
        drop(next);
    }
}
