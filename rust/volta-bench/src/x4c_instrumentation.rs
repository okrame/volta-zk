//! Fail-closed, coarse wall-only instrumentation for X4c lifecycle work.
//!
//! The collector deliberately does not infer ownership from process-wide
//! counters.  Callers provide the logical sealed-state, temporary-file and
//! CUDA ownership ledgers; this module anchors those ledgers to monotonic
//! wall time and Linux process counters.  Every optional host facility emits
//! an explicit availability marker so a production validator can reject an
//! incomplete record without confusing "unavailable" with an exact zero.

use serde::{Deserialize, Serialize};
use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::fs;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub const X4C_PRODUCTION_FOLD_CODEWORD_BYTES: u64 = 17_179_869_056;
pub const X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES: u64 = 34_359_737_248;
pub const X4C_PRODUCTION_SEALED_STATE_BYTES: u64 =
    X4C_PRODUCTION_FOLD_CODEWORD_BYTES + X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES;

static ALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_ZEROED_CALLS: AtomicU64 = AtomicU64::new(0);
static REALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATION_CALLS: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_DEALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);
static OUTSTANDING_REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

/// A system allocator with successful-call and exact requested-byte census.
///
/// Binaries that need allocator attribution install this as their one
/// `#[global_allocator]`.  Counters are lifetime-absolute and are never reset:
/// boundary deltas therefore remain monotonic even when allocations made
/// before a measured phase are released during that phase.
pub struct X4cCountingAllocator;

#[inline]
fn record_successful_allocation(size: usize, zeroed: bool) {
    ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
    if zeroed {
        ALLOC_ZEROED_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    CUMULATIVE_ALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
    OUTSTANDING_REQUESTED_BYTES.fetch_add(size, Ordering::Relaxed);
}

#[inline]
fn record_deallocation(size: usize) {
    DEALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
    let size = u64::try_from(size).unwrap_or(u64::MAX);
    CUMULATIVE_DEALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
    let _ =
        OUTSTANDING_REQUESTED_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_sub(size)
        });
}

// SAFETY: every operation is forwarded unchanged to `System`; accounting is
// updated only after successful allocation/reallocation.
unsafe impl GlobalAlloc for X4cCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged.
        let allocation = unsafe { System.alloc(layout) };
        if !allocation.is_null() {
            record_successful_allocation(layout.size(), false);
        }
        allocation
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is forwarded unchanged.
        let allocation = unsafe { System.alloc_zeroed(layout) };
        if !allocation.is_null() {
            record_successful_allocation(layout.size(), true);
        }
        allocation
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        record_deallocation(layout.size());
        // SAFETY: the caller supplies the allocation/layout pair.
        unsafe { System.dealloc(allocation, layout) };
    }

    unsafe fn realloc(&self, allocation: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: arguments are forwarded unchanged.
        let replacement = unsafe { System.realloc(allocation, layout, new_size) };
        if !replacement.is_null() {
            REALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
            let old_size = u64::try_from(layout.size()).unwrap_or(u64::MAX);
            let new_size_u64 = u64::try_from(new_size).unwrap_or(u64::MAX);
            CUMULATIVE_ALLOCATED_BYTES.fetch_add(new_size_u64, Ordering::Relaxed);
            CUMULATIVE_DEALLOCATED_BYTES.fetch_add(old_size, Ordering::Relaxed);
            if new_size_u64 >= old_size {
                OUTSTANDING_REQUESTED_BYTES.fetch_add(new_size_u64 - old_size, Ordering::Relaxed);
            } else {
                let decrease = old_size - new_size_u64;
                let _ = OUTSTANDING_REQUESTED_BYTES.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| current.checked_sub(decrease),
                );
            }
        }
        replacement
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvailabilityV1 {
    pub available: bool,
    /// Empty exactly when `available` is true.
    pub reason: String,
}

impl AvailabilityV1 {
    pub fn available() -> Self {
        Self { available: true, reason: String::new() }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self { available: false, reason: reason.into() }
    }

    pub fn is_consistent(&self) -> bool {
        self.available == self.reason.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocatorCounterValuesV1 {
    pub allocation_calls: u64,
    pub alloc_zeroed_calls: u64,
    pub reallocation_calls: u64,
    pub deallocation_calls: u64,
    pub cumulative_allocated_bytes: u64,
    pub cumulative_deallocated_bytes: u64,
    pub outstanding_requested_bytes: u64,
}

pub fn allocator_counter_values_v1() -> AllocatorCounterValuesV1 {
    // A boundary can be sampled while another Rayon worker allocates. Retry
    // until the byte census is a self-consistent stable observation instead
    // of emitting a transient identity violation.
    loop {
        let allocated_before = CUMULATIVE_ALLOCATED_BYTES.load(Ordering::Acquire);
        let deallocated_before = CUMULATIVE_DEALLOCATED_BYTES.load(Ordering::Acquire);
        let outstanding_before = OUTSTANDING_REQUESTED_BYTES.load(Ordering::Acquire);
        let allocation_calls = ALLOCATION_CALLS.load(Ordering::Acquire);
        let alloc_zeroed_calls = ALLOC_ZEROED_CALLS.load(Ordering::Acquire);
        let reallocation_calls = REALLOCATION_CALLS.load(Ordering::Acquire);
        let deallocation_calls = DEALLOCATION_CALLS.load(Ordering::Acquire);
        let allocated_after = CUMULATIVE_ALLOCATED_BYTES.load(Ordering::Acquire);
        let deallocated_after = CUMULATIVE_DEALLOCATED_BYTES.load(Ordering::Acquire);
        let outstanding_after = OUTSTANDING_REQUESTED_BYTES.load(Ordering::Acquire);
        if allocated_before == allocated_after
            && deallocated_before == deallocated_after
            && outstanding_before == outstanding_after
            && allocated_after.checked_sub(deallocated_after) == Some(outstanding_after)
        {
            return AllocatorCounterValuesV1 {
                allocation_calls,
                alloc_zeroed_calls,
                reallocation_calls,
                deallocation_calls,
                cumulative_allocated_bytes: allocated_after,
                cumulative_deallocated_bytes: deallocated_after,
                outstanding_requested_bytes: outstanding_after,
            };
        }
        std::hint::spin_loop();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllocatorSnapshotV1 {
    pub availability: AvailabilityV1,
    pub allocation_calls: u64,
    pub alloc_zeroed_calls: u64,
    pub reallocation_calls: u64,
    pub deallocation_calls: u64,
    pub cumulative_allocated_bytes: u64,
    pub cumulative_deallocated_bytes: u64,
    pub outstanding_requested_bytes: u64,
    /// glibc bytes currently allocated, including mmap-backed regions.
    pub allocator_allocated_bytes: u64,
    /// glibc arena plus mmap region bytes currently mapped.
    pub allocator_mapped_bytes: u64,
    pub arena_bytes: u64,
    pub mmap_region_bytes: u64,
    pub free_arena_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIoSnapshotV1 {
    pub availability: AvailabilityV1,
    pub rchar: u64,
    pub wchar: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageFaultSnapshotV1 {
    pub availability: AvailabilityV1,
    pub minor_faults: u64,
    pub major_faults: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessMemorySnapshotV1 {
    pub availability: AvailabilityV1,
    pub rss_bytes: u64,
    pub locked_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SmapsRollupSnapshotV1 {
    pub availability: AvailabilityV1,
    pub rss_bytes: u64,
    pub pss_bytes: u64,
    pub anonymous_bytes: u64,
    pub file_bytes: u64,
    pub shmem_bytes: u64,
    pub private_clean_bytes: u64,
    pub private_dirty_bytes: u64,
    pub shared_clean_bytes: u64,
    pub shared_dirty_bytes: u64,
    pub swap_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NumaSnapshotV1 {
    pub availability: AvailabilityV1,
    pub page_size_bytes: u64,
    pub total_node_pages: u64,
    pub node_pages: BTreeMap<String, u64>,
}

/// CUDA state supplied by the owning backend without imposing a CUDA
/// dependency on the benchmark support library.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CudaSnapshotV1 {
    pub availability: AvailabilityV1,
    pub device_workspace_bytes: u64,
    pub device_resident_bytes: u64,
    pub device_cached_bytes: u64,
    pub device_live_bytes: u64,
    pub pinned_host_bytes: u64,
    pub outstanding_operations: u64,
    pub measurement_active: bool,
    pub synchronized: bool,
}

impl CudaSnapshotV1 {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: AvailabilityV1::unavailable(reason),
            device_workspace_bytes: 0,
            device_resident_bytes: 0,
            device_cached_bytes: 0,
            device_live_bytes: 0,
            pinned_host_bytes: 0,
            outstanding_operations: 0,
            measurement_active: false,
            synchronized: false,
        }
    }

    pub fn cpu_only_zero() -> Self {
        Self {
            availability: AvailabilityV1::available(),
            device_workspace_bytes: 0,
            device_resident_bytes: 0,
            device_cached_bytes: 0,
            device_live_bytes: 0,
            pinned_host_bytes: 0,
            outstanding_operations: 0,
            measurement_active: false,
            synchronized: true,
        }
    }

    pub fn from_x4c_control_state(state: volta_accel::X4cControlState) -> Option<Self> {
        let pinned_host_bytes = state.active_pinned_bytes.checked_add(state.cached_pinned_bytes)?;
        let device_live_bytes = state
            .workspace_device_bytes
            .checked_add(state.active_device_bytes)?
            .checked_add(state.cached_device_bytes)?;
        Some(Self {
            availability: AvailabilityV1::available(),
            device_workspace_bytes: state.workspace_device_bytes,
            device_resident_bytes: state.active_device_bytes,
            device_cached_bytes: state.cached_device_bytes,
            device_live_bytes,
            pinned_host_bytes,
            outstanding_operations: state.outstanding_cuda_operations,
            measurement_active: state.measurement_active,
            synchronized: state.stream_state == volta_accel::CudaStreamState::Idle
                && state.outstanding_cuda_operations == 0,
        })
    }

    pub fn is_consistent(&self) -> bool {
        self.availability.is_consistent()
            && self
                .device_workspace_bytes
                .checked_add(self.device_resident_bytes)
                .and_then(|value| value.checked_add(self.device_cached_bytes))
                == Some(self.device_live_bytes)
            && (!self.synchronized || self.outstanding_operations == 0)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporaryFileStateV1 {
    pub live_file_count: u64,
    pub live_file_bytes: u64,
    pub live_directory_count: u64,
    pub cumulative_created_files: u64,
    pub cumulative_deleted_files: u64,
    pub cumulative_created_directories: u64,
    pub cumulative_deleted_directories: u64,
}

impl TemporaryFileStateV1 {
    pub fn is_consistent(&self) -> bool {
        self.cumulative_deleted_files <= self.cumulative_created_files
            && self.cumulative_deleted_directories <= self.cumulative_created_directories
            && self.live_file_count == self.cumulative_created_files - self.cumulative_deleted_files
            && self.live_directory_count
                == self.cumulative_created_directories - self.cumulative_deleted_directories
    }
}

/// Logical ownership of the sealed state.  Borrowed initial-oracle files are
/// deliberately separate from files owned by the sealed response state.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedOwnershipSnapshotV1 {
    pub fold_codeword_bytes: u64,
    pub fold_outer_cache_bytes: u64,
    pub other_ordinary_host_bytes: u64,
    pub ordinary_host_bytes: u64,
    pub pinned_host_bytes: u64,
    pub device_bytes: u64,
    pub file_backed_bytes: u64,
    pub owned_file_count: u64,
    pub owned_mapping_count: u64,
    pub owned_files: Vec<String>,
    pub owned_mappings: Vec<String>,
    pub borrowed_initial_source_file_count: u64,
    pub borrowed_initial_source_files: Vec<String>,
}

impl SealedOwnershipSnapshotV1 {
    pub fn is_consistent(&self) -> bool {
        self.fold_codeword_bytes
            .checked_add(self.fold_outer_cache_bytes)
            .and_then(|value| value.checked_add(self.other_ordinary_host_bytes))
            == Some(self.ordinary_host_bytes)
            && self.owned_file_count >= self.owned_files.len() as u64
            && self.owned_mapping_count >= self.owned_mappings.len() as u64
            && self.borrowed_initial_source_file_count
                >= self.borrowed_initial_source_files.len() as u64
            && (self.file_backed_bytes > 0
                || (self.owned_file_count == 0 && self.owned_mapping_count == 0))
            && (self.file_backed_bytes == 0
                || self.owned_file_count > 0
                || self.owned_mapping_count > 0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoundarySnapshotV1 {
    pub schema: u64,
    pub seq: u64,
    pub label: String,
    pub monotonic_enter_ns: u64,
    pub monotonic_exit_ns: u64,
    pub snapshot_probe_wall_ns: u64,
    pub process_io: ProcessIoSnapshotV1,
    pub page_faults: PageFaultSnapshotV1,
    pub process_memory: ProcessMemorySnapshotV1,
    pub smaps_rollup: SmapsRollupSnapshotV1,
    pub allocator: AllocatorSnapshotV1,
    pub numa: NumaSnapshotV1,
    pub cuda: CudaSnapshotV1,
    pub sealed_ownership: SealedOwnershipSnapshotV1,
    pub temporary_files: TemporaryFileStateV1,
}

impl BoundarySnapshotV1 {
    pub fn is_internally_consistent(&self) -> bool {
        self.schema == 1
            && !self.label.is_empty()
            && self.monotonic_exit_ns >= self.monotonic_enter_ns
            && self.snapshot_probe_wall_ns == self.monotonic_exit_ns - self.monotonic_enter_ns
            && self.process_io.availability.is_consistent()
            && self.page_faults.availability.is_consistent()
            && self.process_memory.availability.is_consistent()
            && self.smaps_rollup.availability.is_consistent()
            && self.allocator.availability.is_consistent()
            && self.numa.availability.is_consistent()
            && self.cuda.is_consistent()
            && self.sealed_ownership.is_consistent()
            && self.temporary_files.is_consistent()
            && self.allocator.cumulative_allocated_bytes
                >= self.allocator.cumulative_deallocated_bytes
            && self.allocator.outstanding_requested_bytes
                == self.allocator.cumulative_allocated_bytes
                    - self.allocator.cumulative_deallocated_bytes
            && self.numa.total_node_pages == self.numa.node_pages.values().sum::<u64>()
    }

    pub fn host_counters_available(&self) -> bool {
        self.process_io.availability.available
            && self.page_faults.availability.available
            && self.process_memory.availability.available
            && self.smaps_rollup.availability.available
            && self.allocator.availability.available
            && self.numa.availability.available
    }
}

pub struct BoundaryCollectorV1 {
    epoch: Instant,
    next_seq: u64,
    allocator_installed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleContextRecordV1 {
    pub cohort_id: Option<u32>,
    pub fold_round: Option<u8>,
    pub slot_index: Option<u16>,
    pub initial_group_index: Option<u32>,
    pub outer_level: Option<u8>,
    pub segment_index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleEventRecordV1 {
    pub schema: u64,
    pub track: String,
    pub phase: String,
    pub transition: String,
    pub nesting: String,
    pub context: LifecycleContextRecordV1,
    pub boundary_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleSpanRecordV1 {
    pub track: String,
    pub phase: String,
    pub nesting: String,
    pub context: LifecycleContextRecordV1,
    pub start_seq: u64,
    pub end_seq: u64,
    /// Phase subject wall with both boundary probes excluded.
    pub subject_wall_ns: u64,
    /// Start-probe + subject + end-probe wall.
    pub inclusive_wall_ns: u64,
    pub boundary_probe_wall_ns: u64,
}

/// Recorder adapter for the protocol-library observer seam. The CUDA
/// provider must be a non-synchronizing state query; an unavailable provider
/// should return an explicit unavailable `CudaSnapshotV1`, never fabricated
/// zeroes.
pub struct CausalObserverV1<F>
where
    F: FnMut() -> CudaSnapshotV1,
{
    collector: BoundaryCollectorV1,
    cuda_snapshot: F,
    borrowed_initial_source_files: Vec<String>,
    events: Vec<LifecycleEventRecordV1>,
    boundaries: Vec<BoundarySnapshotV1>,
    active_spans: Vec<LifecycleEventRecordV1>,
    spans: Vec<LifecycleSpanRecordV1>,
    integrity_errors: Vec<String>,
}

impl<F> CausalObserverV1<F>
where
    F: FnMut() -> CudaSnapshotV1,
{
    pub fn new(allocator_installed: bool, cuda_snapshot: F) -> Self {
        Self {
            collector: BoundaryCollectorV1::new(allocator_installed),
            cuda_snapshot,
            borrowed_initial_source_files: Vec::new(),
            events: Vec::new(),
            boundaries: Vec::new(),
            active_spans: Vec::new(),
            spans: Vec::new(),
            integrity_errors: Vec::new(),
        }
    }

    pub fn set_borrowed_initial_source_files(&mut self, paths: Vec<String>) {
        self.borrowed_initial_source_files = paths;
    }

    pub fn events(&self) -> &[LifecycleEventRecordV1] {
        &self.events
    }

    pub fn boundaries(&self) -> &[BoundarySnapshotV1] {
        &self.boundaries
    }

    pub fn spans(&self) -> &[LifecycleSpanRecordV1] {
        &self.spans
    }

    pub fn timeline_complete(&self) -> bool {
        self.active_spans.is_empty() && self.integrity_errors.is_empty()
    }

    pub fn integrity_errors(&self) -> &[String] {
        &self.integrity_errors
    }

    pub fn into_records(self) -> (Vec<LifecycleEventRecordV1>, Vec<BoundarySnapshotV1>) {
        (self.events, self.boundaries)
    }

    pub fn into_timeline(
        self,
    ) -> Result<
        (Vec<LifecycleEventRecordV1>, Vec<LifecycleSpanRecordV1>, Vec<BoundarySnapshotV1>),
        Vec<String>,
    > {
        let mut errors = self.integrity_errors;
        if !self.active_spans.is_empty() {
            errors.push(format!("{} lifecycle span(s) were not closed", self.active_spans.len()));
        }
        if errors.is_empty() {
            Ok((self.events, self.spans, self.boundaries))
        } else {
            Err(errors)
        }
    }
}

impl CausalObserverV1<fn() -> CudaSnapshotV1> {
    pub fn cpu_only(allocator_installed: bool) -> Self {
        fn snapshot() -> CudaSnapshotV1 {
            CudaSnapshotV1::cpu_only_zero()
        }
        Self::new(allocator_installed, snapshot)
    }
}

impl<F> volta_pcs::x4::X4LifecycleObserverV4 for CausalObserverV1<F>
where
    F: FnMut() -> CudaSnapshotV1,
{
    fn observe(&mut self, event: &volta_pcs::x4::X4LifecycleEventV4) {
        let core_ownership = event.sealed_ownership;
        let borrowed_initial_source_file_count = self.borrowed_initial_source_files.len() as u64;
        let ownership = SealedOwnershipSnapshotV1 {
            fold_codeword_bytes: core_ownership.fold_codeword_bytes,
            fold_outer_cache_bytes: core_ownership.fold_outer_cache_bytes,
            other_ordinary_host_bytes: 0,
            ordinary_host_bytes: core_ownership.accounted_ordinary_host_bytes,
            pinned_host_bytes: core_ownership.pinned_host_bytes,
            device_bytes: core_ownership.device_bytes,
            file_backed_bytes: core_ownership.file_backed_bytes,
            owned_file_count: core_ownership.owned_files,
            owned_mapping_count: core_ownership.owned_mappings,
            owned_files: Vec::new(),
            owned_mappings: Vec::new(),
            borrowed_initial_source_file_count,
            borrowed_initial_source_files: self.borrowed_initial_source_files.clone(),
        };
        let core_files = event.temporary_files;
        let temporary_files = TemporaryFileStateV1 {
            live_file_count: core_files.live_files,
            live_file_bytes: core_files.live_file_bytes,
            live_directory_count: core_files.live_directories,
            cumulative_created_files: core_files.files_created,
            cumulative_deleted_files: core_files.files_deleted,
            cumulative_created_directories: core_files.directories_created,
            cumulative_deleted_directories: core_files.directories_deleted,
        };
        let context = LifecycleContextRecordV1 {
            cohort_id: event.context.cohort_id,
            fold_round: event.context.fold_round,
            slot_index: event.context.slot_index,
            initial_group_index: event.context.initial_group_index,
            outer_level: event.context.outer_level,
            segment_index: event.context.segment_index,
        };
        let label = format!(
            "{}:{}:{}:{}:{}",
            event.track.as_str(),
            event.phase.as_str(),
            event.transition.as_str(),
            event.nesting.as_str(),
            event.context.segment_index,
        );
        let accelerator = core_ownership.accelerator_control;
        let cuda = if accelerator.available {
            CudaSnapshotV1 {
                availability: AvailabilityV1::available(),
                device_workspace_bytes: accelerator.device_workspace_bytes,
                device_resident_bytes: accelerator.device_resident_bytes,
                device_cached_bytes: accelerator.device_cached_bytes,
                device_live_bytes: accelerator.device_live_bytes,
                pinned_host_bytes: accelerator.pinned_host_bytes,
                outstanding_operations: accelerator.outstanding_operations,
                measurement_active: accelerator.measurement_active,
                synchronized: accelerator.synchronized,
            }
        } else {
            (self.cuda_snapshot)()
        };
        let boundary = self.collector.capture(label, ownership, temporary_files, cuda);
        let record = LifecycleEventRecordV1 {
            schema: 1,
            track: event.track.as_str().to_owned(),
            phase: event.phase.as_str().to_owned(),
            transition: event.transition.as_str().to_owned(),
            nesting: event.nesting.as_str().to_owned(),
            context,
            boundary_seq: boundary.seq,
        };
        self.boundaries.push(boundary);
        match record.transition.as_str() {
            "span_start" => self.active_spans.push(record.clone()),
            "span_end" => {
                let matching = self.active_spans.iter().rposition(|start| {
                    start.track == record.track
                        && start.phase == record.phase
                        && start.nesting == record.nesting
                        && start.context == record.context
                });
                if let Some(index) = matching {
                    if index + 1 != self.active_spans.len() {
                        self.integrity_errors.push(format!(
                            "crossing lifecycle spans at {}:{}",
                            record.track, record.phase
                        ));
                    }
                    let start = self.active_spans.remove(index);
                    let start_boundary = &self.boundaries[start.boundary_seq as usize];
                    let end_boundary = &self.boundaries[record.boundary_seq as usize];
                    let subject_wall_ns = end_boundary
                        .monotonic_enter_ns
                        .saturating_sub(start_boundary.monotonic_exit_ns);
                    let inclusive_wall_ns = end_boundary
                        .monotonic_exit_ns
                        .saturating_sub(start_boundary.monotonic_enter_ns);
                    let boundary_probe_wall_ns = start_boundary
                        .snapshot_probe_wall_ns
                        .saturating_add(end_boundary.snapshot_probe_wall_ns);
                    if inclusive_wall_ns != subject_wall_ns.saturating_add(boundary_probe_wall_ns) {
                        self.integrity_errors.push(format!(
                            "lifecycle wall reconciliation failed for {}:{}",
                            record.track, record.phase
                        ));
                    }
                    self.spans.push(LifecycleSpanRecordV1 {
                        track: record.track.clone(),
                        phase: record.phase.clone(),
                        nesting: record.nesting.clone(),
                        context: record.context.clone(),
                        start_seq: start.boundary_seq,
                        end_seq: record.boundary_seq,
                        subject_wall_ns,
                        inclusive_wall_ns,
                        boundary_probe_wall_ns,
                    });
                } else {
                    self.integrity_errors.push(format!(
                        "unmatched lifecycle span end for {}:{}",
                        record.track, record.phase
                    ));
                }
            }
            "boundary" => {}
            other => self.integrity_errors.push(format!("unknown lifecycle transition {other}")),
        }
        self.events.push(record);
    }
}

impl BoundaryCollectorV1 {
    pub fn new(allocator_installed: bool) -> Self {
        Self { epoch: Instant::now(), next_seq: 0, allocator_installed }
    }

    pub fn capture(
        &mut self,
        label: impl Into<String>,
        sealed_ownership: SealedOwnershipSnapshotV1,
        temporary_files: TemporaryFileStateV1,
        cuda: CudaSnapshotV1,
    ) -> BoundarySnapshotV1 {
        let entered = self.epoch.elapsed().as_nanos();
        let monotonic_enter_ns = u64::try_from(entered).unwrap_or(u64::MAX);
        // Capture allocator counters first: the remaining /proc probes use
        // temporary buffers and their overhead belongs after the boundary.
        let allocator = allocator_snapshot(self.allocator_installed);
        let process_io = process_io_snapshot();
        let page_faults = page_fault_snapshot();
        let process_memory = process_memory_snapshot();
        let smaps_rollup = smaps_rollup_snapshot();
        let numa = numa_snapshot();
        let exited = self.epoch.elapsed().as_nanos();
        let monotonic_exit_ns = u64::try_from(exited).unwrap_or(u64::MAX);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        BoundarySnapshotV1 {
            schema: 1,
            seq,
            label: label.into(),
            monotonic_enter_ns,
            monotonic_exit_ns,
            snapshot_probe_wall_ns: monotonic_exit_ns.saturating_sub(monotonic_enter_ns),
            process_io,
            page_faults,
            process_memory,
            smaps_rollup,
            allocator,
            numa,
            cuda,
            sealed_ownership,
            temporary_files,
        }
    }
}

fn parse_colon_u64(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then(|| value.trim().parse::<u64>().ok()).flatten()
    })
}

fn parse_kib_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        if candidate.trim() != key {
            return None;
        }
        let mut fields = value.split_whitespace();
        let kib = fields.next()?.parse::<u64>().ok()?;
        match fields.next() {
            Some("kB") | None => kib.checked_mul(1024),
            _ => None,
        }
    })
}

fn process_io_snapshot() -> ProcessIoSnapshotV1 {
    match fs::read_to_string("/proc/self/io") {
        Ok(text) => {
            let values = (
                parse_colon_u64(&text, "rchar"),
                parse_colon_u64(&text, "wchar"),
                parse_colon_u64(&text, "read_bytes"),
                parse_colon_u64(&text, "write_bytes"),
            );
            match values {
                (Some(rchar), Some(wchar), Some(read_bytes), Some(write_bytes)) => {
                    ProcessIoSnapshotV1 {
                        availability: AvailabilityV1::available(),
                        rchar,
                        wchar,
                        read_bytes,
                        write_bytes,
                    }
                }
                _ => ProcessIoSnapshotV1 {
                    availability: AvailabilityV1::unavailable(
                        "missing required fields in /proc/self/io",
                    ),
                    rchar: 0,
                    wchar: 0,
                    read_bytes: 0,
                    write_bytes: 0,
                },
            }
        }
        Err(error) => ProcessIoSnapshotV1 {
            availability: AvailabilityV1::unavailable(format!(
                "cannot read /proc/self/io: {error}"
            )),
            rchar: 0,
            wchar: 0,
            read_bytes: 0,
            write_bytes: 0,
        },
    }
}

fn page_fault_snapshot() -> PageFaultSnapshotV1 {
    match fs::read_to_string("/proc/self/stat") {
        Ok(text) => {
            // The command name is parenthesized and can contain spaces.
            let values = text.rsplit_once(") ").and_then(|(_, tail)| {
                let fields = tail.split_whitespace().collect::<Vec<_>>();
                Some((fields.get(7)?.parse::<u64>().ok()?, fields.get(9)?.parse::<u64>().ok()?))
            });
            match values {
                Some((minor_faults, major_faults)) => PageFaultSnapshotV1 {
                    availability: AvailabilityV1::available(),
                    minor_faults,
                    major_faults,
                },
                None => PageFaultSnapshotV1 {
                    availability: AvailabilityV1::unavailable(
                        "cannot parse minflt/majflt from /proc/self/stat",
                    ),
                    minor_faults: 0,
                    major_faults: 0,
                },
            }
        }
        Err(error) => PageFaultSnapshotV1 {
            availability: AvailabilityV1::unavailable(format!(
                "cannot read /proc/self/stat: {error}"
            )),
            minor_faults: 0,
            major_faults: 0,
        },
    }
}

fn process_memory_snapshot() -> ProcessMemorySnapshotV1 {
    match fs::read_to_string("/proc/self/status") {
        Ok(text) => match (parse_kib_field(&text, "VmRSS"), parse_kib_field(&text, "VmLck")) {
            (Some(rss_bytes), Some(locked_bytes)) => ProcessMemorySnapshotV1 {
                availability: AvailabilityV1::available(),
                rss_bytes,
                locked_bytes,
            },
            _ => ProcessMemorySnapshotV1 {
                availability: AvailabilityV1::unavailable(
                    "missing VmRSS/VmLck in /proc/self/status",
                ),
                rss_bytes: 0,
                locked_bytes: 0,
            },
        },
        Err(error) => ProcessMemorySnapshotV1 {
            availability: AvailabilityV1::unavailable(format!(
                "cannot read /proc/self/status: {error}"
            )),
            rss_bytes: 0,
            locked_bytes: 0,
        },
    }
}

fn smaps_rollup_snapshot() -> SmapsRollupSnapshotV1 {
    match fs::read_to_string("/proc/self/smaps_rollup") {
        Ok(text) => {
            let file_bytes = parse_kib_field(&text, "Pss_File")
                .or_else(|| parse_kib_field(&text, "FilePmdMapped"));
            let fields = (
                parse_kib_field(&text, "Rss"),
                parse_kib_field(&text, "Pss"),
                parse_kib_field(&text, "Anonymous"),
                file_bytes,
                parse_kib_field(&text, "Pss_Shmem")
                    .or_else(|| parse_kib_field(&text, "ShmemPmdMapped")),
                parse_kib_field(&text, "Private_Clean"),
                parse_kib_field(&text, "Private_Dirty"),
                parse_kib_field(&text, "Shared_Clean"),
                parse_kib_field(&text, "Shared_Dirty"),
                parse_kib_field(&text, "Swap"),
            );
            match fields {
                (
                    Some(rss_bytes),
                    Some(pss_bytes),
                    Some(anonymous_bytes),
                    Some(file_bytes),
                    Some(shmem_bytes),
                    Some(private_clean_bytes),
                    Some(private_dirty_bytes),
                    Some(shared_clean_bytes),
                    Some(shared_dirty_bytes),
                    Some(swap_bytes),
                ) => SmapsRollupSnapshotV1 {
                    availability: AvailabilityV1::available(),
                    rss_bytes,
                    pss_bytes,
                    anonymous_bytes,
                    file_bytes,
                    shmem_bytes,
                    private_clean_bytes,
                    private_dirty_bytes,
                    shared_clean_bytes,
                    shared_dirty_bytes,
                    swap_bytes,
                },
                _ => SmapsRollupSnapshotV1 {
                    availability: AvailabilityV1::unavailable(
                        "missing required fields in /proc/self/smaps_rollup",
                    ),
                    rss_bytes: 0,
                    pss_bytes: 0,
                    anonymous_bytes: 0,
                    file_bytes: 0,
                    shmem_bytes: 0,
                    private_clean_bytes: 0,
                    private_dirty_bytes: 0,
                    shared_clean_bytes: 0,
                    shared_dirty_bytes: 0,
                    swap_bytes: 0,
                },
            }
        }
        Err(error) => SmapsRollupSnapshotV1 {
            availability: AvailabilityV1::unavailable(format!(
                "cannot read /proc/self/smaps_rollup: {error}"
            )),
            rss_bytes: 0,
            pss_bytes: 0,
            anonymous_bytes: 0,
            file_bytes: 0,
            shmem_bytes: 0,
            private_clean_bytes: 0,
            private_dirty_bytes: 0,
            shared_clean_bytes: 0,
            shared_dirty_bytes: 0,
            swap_bytes: 0,
        },
    }
}

#[cfg(target_os = "linux")]
fn system_page_size() -> Option<u64> {
    unsafe extern "C" {
        fn getpagesize() -> std::os::raw::c_int;
    }
    // SAFETY: `getpagesize` takes no arguments and has no side effects.
    let value = unsafe { getpagesize() };
    (value > 0).then_some(value as u64)
}

#[cfg(not(target_os = "linux"))]
fn system_page_size() -> Option<u64> {
    None
}

fn numa_snapshot() -> NumaSnapshotV1 {
    let page_size = system_page_size();
    match (page_size, fs::read_to_string("/proc/self/numa_maps")) {
        (Some(page_size_bytes), Ok(text)) => {
            let mut node_pages = BTreeMap::<String, u64>::new();
            for token in text.split_whitespace() {
                let Some((node, pages)) = token.split_once('=') else {
                    continue;
                };
                if node.len() < 2
                    || !node.starts_with('N')
                    || !node[1..].chars().all(|c| c.is_ascii_digit())
                {
                    continue;
                }
                if let Ok(pages) = pages.parse::<u64>() {
                    *node_pages.entry(node.to_owned()).or_default() += pages;
                }
            }
            if node_pages.is_empty() {
                NumaSnapshotV1 {
                    availability: AvailabilityV1::unavailable(
                        "no NUMA node counters in /proc/self/numa_maps",
                    ),
                    page_size_bytes,
                    total_node_pages: 0,
                    node_pages,
                }
            } else {
                let total_node_pages = node_pages.values().sum();
                NumaSnapshotV1 {
                    availability: AvailabilityV1::available(),
                    page_size_bytes,
                    total_node_pages,
                    node_pages,
                }
            }
        }
        (None, _) => NumaSnapshotV1 {
            availability: AvailabilityV1::unavailable("system page size unavailable"),
            page_size_bytes: 0,
            total_node_pages: 0,
            node_pages: BTreeMap::new(),
        },
        (_, Err(error)) => NumaSnapshotV1 {
            availability: AvailabilityV1::unavailable(format!(
                "cannot read /proc/self/numa_maps: {error}"
            )),
            page_size_bytes: page_size.unwrap_or(0),
            total_node_pages: 0,
            node_pages: BTreeMap::new(),
        },
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct MallInfo2 {
    arena: usize,
    ordblks: usize,
    smblks: usize,
    hblks: usize,
    hblkhd: usize,
    usmblks: usize,
    fsmblks: usize,
    uordblks: usize,
    fordblks: usize,
    keepcost: usize,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn mallinfo_values() -> Option<(u64, u64, u64, u64, u64)> {
    unsafe extern "C" {
        fn mallinfo2() -> MallInfo2;
    }
    // SAFETY: glibc returns the structure by value.
    let info = unsafe { mallinfo2() };
    let arena = u64::try_from(info.arena).ok()?;
    let mmap = u64::try_from(info.hblkhd).ok()?;
    let used_arena = u64::try_from(info.uordblks).ok()?;
    let free_arena = u64::try_from(info.fordblks).ok()?;
    Some((used_arena.checked_add(mmap)?, arena.checked_add(mmap)?, arena, mmap, free_arena))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn mallinfo_values() -> Option<(u64, u64, u64, u64, u64)> {
    None
}

fn allocator_snapshot(installed: bool) -> AllocatorSnapshotV1 {
    let counters = allocator_counter_values_v1();
    let mallinfo = mallinfo_values();
    let availability = if !installed {
        AvailabilityV1::unavailable("X4cCountingAllocator is not installed")
    } else if mallinfo.is_none() {
        AvailabilityV1::unavailable("mallinfo2 is unavailable on this allocator/runtime")
    } else {
        AvailabilityV1::available()
    };
    let (
        allocator_allocated_bytes,
        allocator_mapped_bytes,
        arena_bytes,
        mmap_region_bytes,
        free_arena_bytes,
    ) = mallinfo.unwrap_or((0, 0, 0, 0, 0));
    AllocatorSnapshotV1 {
        availability,
        allocation_calls: counters.allocation_calls,
        alloc_zeroed_calls: counters.alloc_zeroed_calls,
        reallocation_calls: counters.reallocation_calls,
        deallocation_calls: counters.deallocation_calls,
        cumulative_allocated_bytes: counters.cumulative_allocated_bytes,
        cumulative_deallocated_bytes: counters.cumulative_deallocated_bytes,
        outstanding_requested_bytes: counters.outstanding_requested_bytes,
        allocator_allocated_bytes,
        allocator_mapped_bytes,
        arena_bytes,
        mmap_region_bytes,
        free_arena_bytes,
    }
}

/// Volatilely touches one byte per host page and the final byte.  The caller
/// still fills every logical byte; this extra pass makes population observable
/// to the optimizer and provides a page-count anchor.
pub fn touch_populated_bytes(bytes: &mut [u8]) -> u64 {
    if bytes.is_empty() {
        return 0;
    }
    let page_size = system_page_size().unwrap_or(4096).max(1) as usize;
    let mut touched = 0u64;
    for index in (0..bytes.len()).step_by(page_size) {
        // SAFETY: `index` is in bounds and the pointer is derived from the
        // unique mutable slice.
        unsafe {
            let pointer = bytes.as_mut_ptr().add(index);
            let value = ptr::read_volatile(pointer);
            ptr::write_volatile(pointer, value);
        }
        touched += 1;
    }
    if (bytes.len() - 1) % page_size != 0 {
        let index = bytes.len() - 1;
        // SAFETY: final element is in bounds.
        unsafe {
            let pointer = bytes.as_mut_ptr().add(index);
            let value = ptr::read_volatile(pointer);
            ptr::write_volatile(pointer, value);
        }
        touched += 1;
    }
    touched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_state_identity_is_exact() {
        assert_eq!(X4C_PRODUCTION_SEALED_STATE_BYTES, 51_539_606_304);
        let codewords = (3u32..=29).map(|log| (1u64 << log) * 16).sum::<u64>();
        let caches = (3u32..=29).map(|log| ((1u64 << log) - 1) * 32).sum::<u64>();
        assert_eq!(codewords, X4C_PRODUCTION_FOLD_CODEWORD_BYTES);
        assert_eq!(caches, X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES);
    }

    #[test]
    fn ownership_reconciliation_rejects_unanchored_files() {
        let mut ownership = SealedOwnershipSnapshotV1 {
            fold_codeword_bytes: 16,
            ordinary_host_bytes: 16,
            ..SealedOwnershipSnapshotV1::default()
        };
        assert!(ownership.is_consistent());
        ownership.owned_files.push("/tmp/unanchored".to_owned());
        assert!(!ownership.is_consistent());
        ownership.owned_file_count = 1;
        ownership.file_backed_bytes = 1;
        assert!(ownership.is_consistent());
    }

    #[test]
    fn local_boundary_has_no_missing_structural_fields() {
        let mut collector = BoundaryCollectorV1::new(false);
        let boundary = collector.capture(
            "local-smoke",
            SealedOwnershipSnapshotV1::default(),
            TemporaryFileStateV1::default(),
            CudaSnapshotV1::cpu_only_zero(),
        );
        assert!(boundary.is_internally_consistent());
        assert!(!boundary.allocator.availability.available);
        assert!(!boundary.allocator.availability.reason.is_empty());
    }

    #[test]
    fn population_touch_covers_first_and_final_pages() {
        let mut bytes = vec![7u8; 8193];
        assert!(touch_populated_bytes(&mut bytes) >= 3);
        assert!(bytes.iter().all(|value| *value == 7));
    }

    #[test]
    fn observer_derives_probe_exclusive_span_wall() {
        use volta_pcs::x4::{
            X4LegacySealedOwnershipV4, X4LifecycleContextV4, X4LifecycleEventV4,
            X4LifecycleNestingV4, X4LifecycleObserverV4, X4LifecyclePhaseV4, X4LifecycleTrackV4,
            X4TemporaryFileStateV4,
        };

        let ownership = X4LegacySealedOwnershipV4::from_fold_payload(16, 32).unwrap();
        let files = X4TemporaryFileStateV4::default();
        let context = X4LifecycleContextV4::default();
        let mut observer = CausalObserverV1::cpu_only(false);
        observer.observe(&X4LifecycleEventV4::span_start(
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DrawValidationSchedule,
            X4LifecycleNestingV4::TopLevel,
            context,
            ownership,
            files,
        ));
        observer.observe(&X4LifecycleEventV4::span_end(
            X4LifecycleTrackV4::LegacyOpening,
            X4LifecyclePhaseV4::DrawValidationSchedule,
            X4LifecycleNestingV4::TopLevel,
            context,
            ownership,
            files,
        ));
        assert!(observer.timeline_complete());
        let (_, spans, boundaries) = observer.into_timeline().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start_seq, 0);
        assert_eq!(spans[0].end_seq, 1);
        assert_eq!(
            spans[0].inclusive_wall_ns,
            spans[0].subject_wall_ns + spans[0].boundary_probe_wall_ns
        );
        assert_eq!(boundaries.len(), 2);
    }
}
