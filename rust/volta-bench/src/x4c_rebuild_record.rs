//! Shared schema-2 record surface for file-free accelerated X4c rebuilds.
//!
//! Both the real-weight E2E driver and the progressive preflight use these
//! exact counters.  Keeping the conversion here prevents the two record
//! producers from drifting on CUDA ownership, traffic or scratch semantics.

use std::fs;

use serde::Serialize;
use volta_accel::{
    BackendStats, CudaStreamState, DeviceMemoryBreakdown, Operation, X4cControlState,
};
use volta_pcs::x4::{X4cRamRebuildMetricsV4, X4cRamRebuildStrategyV4};

#[derive(Clone, Debug, Serialize)]
pub struct RebuildPhaseRecord {
    pub e_ntt_ns: u64,
    pub n4_inner_ns: u64,
    pub n4_outer_ns: u64,
    pub assemble_and_root_check_ns: u64,
    pub cleanup_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceMemoryRecord {
    pub workspace_bytes: u64,
    pub resident_bytes: u64,
    pub cached_resident_bytes: u64,
}

impl From<DeviceMemoryBreakdown> for DeviceMemoryRecord {
    fn from(value: DeviceMemoryBreakdown) -> Self {
        Self {
            workspace_bytes: value.workspace_bytes,
            resident_bytes: value.resident_bytes,
            cached_resident_bytes: value.cached_resident_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RebuildControlRecord {
    pub stream_state: String,
    pub measurement_active: bool,
    pub coarse_timing_active: bool,
    pub timing_record_active: bool,
    pub measurement_poisoned: bool,
    pub outstanding_cuda_operations: u64,
    pub pending_timing_records: u64,
    pub active_device_allocations: u64,
    pub cached_device_allocations: u64,
    pub workspace_device_bytes: u64,
    pub active_device_bytes: u64,
    pub cached_device_bytes: u64,
    pub active_pinned_allocations: u64,
    pub cached_pinned_allocations: u64,
    pub in_flight_pinned_allocations: u64,
    pub active_pinned_bytes: u64,
    pub cached_pinned_bytes: u64,
}

impl From<X4cControlState> for RebuildControlRecord {
    fn from(value: X4cControlState) -> Self {
        Self {
            stream_state: match value.stream_state {
                CudaStreamState::Idle => "idle",
                CudaStreamState::Pending => "pending",
            }
            .to_owned(),
            measurement_active: value.measurement_active,
            coarse_timing_active: value.coarse_timing_active,
            timing_record_active: value.timing_record_active,
            measurement_poisoned: value.measurement_poisoned,
            outstanding_cuda_operations: value.outstanding_cuda_operations,
            pending_timing_records: value.pending_timing_records,
            active_device_allocations: value.active_device_allocations,
            cached_device_allocations: value.cached_device_allocations,
            workspace_device_bytes: value.workspace_device_bytes,
            active_device_bytes: value.active_device_bytes,
            cached_device_bytes: value.cached_device_bytes,
            active_pinned_allocations: value.active_pinned_allocations,
            cached_pinned_allocations: value.cached_pinned_allocations,
            in_flight_pinned_allocations: value.in_flight_pinned_allocations,
            active_pinned_bytes: value.active_pinned_bytes,
            cached_pinned_bytes: value.cached_pinned_bytes,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessMemoryRecord {
    pub rss_bytes: u64,
    pub peak_rss_bytes: u64,
}

pub fn process_memory_record() -> Result<ProcessMemoryRecord, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("read process memory census: {error}"))?;
    let parse = |label: &str| {
        let kib = status
            .lines()
            .find_map(|line| {
                let mut fields = line.strip_prefix(label)?.split_whitespace();
                fields.next()?.parse::<u64>().ok()
            })
            .ok_or_else(|| format!("{label} missing from /proc/self/status"))?;
        kib.checked_mul(1024).ok_or_else(|| format!("{label} byte count overflows"))
    };
    Ok(ProcessMemoryRecord { rss_bytes: parse("VmRSS:")?, peak_rss_bytes: parse("VmHWM:")? })
}

#[derive(Clone, Debug, Serialize)]
pub struct RebuildBackendRecord {
    pub measurement_wall_ns: u64,
    pub operations: Vec<(String, u64)>,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub explicit_d2d_copy_bytes: u64,
    pub device_zeroed_bytes: u64,
    pub device_generated_bytes: u64,
    pub resident_alloc_requests: u64,
    pub resident_reuse_hits: u64,
    pub resident_free_requests: u64,
    pub live_device_bytes: u64,
    pub peak_device_bytes: u64,
    pub pinned_allocation_calls: u64,
    pub pinned_alloc_requests: u64,
    pub pinned_reuse_hits: u64,
    pub pinned_free_requests: u64,
    pub pinned_physical_free_calls: u64,
    pub live_pinned_bytes: u64,
    pub peak_pinned_bytes: u64,
    pub x4c_arena_reset_calls: u64,
    pub x4c_arena_reset_bytes: u64,
    pub timing_event_api_calls: u64,
    pub outstanding_timing_records: u64,
}

impl From<BackendStats> for RebuildBackendRecord {
    fn from(stats: BackendStats) -> Self {
        Self {
            measurement_wall_ns: stats.measurement_wall_ns,
            operations: Operation::ALL
                .into_iter()
                .map(|operation| (operation.name().to_owned(), stats.operation(operation).calls))
                .collect(),
            h2d_bytes: stats.h2d_bytes,
            d2h_bytes: stats.d2h_bytes,
            explicit_d2d_copy_bytes: stats.explicit_d2d_copy_bytes,
            device_zeroed_bytes: stats.device_zeroed_bytes,
            device_generated_bytes: stats.device_generated_bytes,
            resident_alloc_requests: stats.resident_alloc_requests,
            resident_reuse_hits: stats.resident_reuse_hits,
            resident_free_requests: stats.resident_free_requests,
            live_device_bytes: stats.live_device_bytes,
            peak_device_bytes: stats.peak_device_bytes,
            pinned_allocation_calls: stats.pinned_allocation_calls,
            pinned_alloc_requests: stats.pinned_alloc_requests,
            pinned_reuse_hits: stats.pinned_reuse_hits,
            pinned_free_requests: stats.pinned_free_requests,
            pinned_physical_free_calls: stats.pinned_physical_free_calls,
            live_pinned_bytes: stats.live_pinned_bytes,
            peak_pinned_bytes: stats.peak_pinned_bytes,
            x4c_arena_reset_calls: stats.x4c_arena_reset_calls,
            x4c_arena_reset_bytes: stats.x4c_arena_reset_bytes,
            timing_event_api_calls: stats.timing_event_api_calls,
            outstanding_timing_records: stats.timing_records,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceleratedRebuildCohortRecord {
    pub cohort_id: u32,
    pub strategy: String,
    pub wall_s: f64,
    pub phases: RebuildPhaseRecord,
    pub process_memory_before: ProcessMemoryRecord,
    pub process_memory_after: ProcessMemoryRecord,
    pub backend: RebuildBackendRecord,
    pub device_memory_before: DeviceMemoryRecord,
    pub device_memory_after: DeviceMemoryRecord,
    pub control_before: RebuildControlRecord,
    pub control_after: RebuildControlRecord,
    pub structural_slots: u64,
    pub present_slots: u64,
    pub coefficient_bytes: u64,
    pub host_oracle_bytes: u64,
    pub host_outer_cache_bytes: u64,
    pub ntt_calls: u64,
    pub n4_inner_calls: u64,
    pub n4_outer_calls: u64,
    pub expected_h2d_bytes: u64,
    pub expected_d2h_bytes: u64,
    pub scratch_files_created: u64,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub file_backed_bytes: u64,
    pub owned_file_count: u64,
    pub owned_mapping_count: u64,
    pub root_equal: bool,
    pub traffic_exact: bool,
    pub cleanup_complete: bool,
    pub accepted: bool,
}

pub fn accelerated_rebuild_cohort_record(
    cohort_id: u32,
    metrics: X4cRamRebuildMetricsV4,
    process_memory_before: ProcessMemoryRecord,
    process_memory_after: ProcessMemoryRecord,
) -> Result<AcceleratedRebuildCohortRecord, String> {
    if metrics.strategy != X4cRamRebuildStrategyV4::CudaRam {
        return Err("accelerated record received non-CUDA rebuild metrics".to_owned());
    }
    let backend = metrics
        .backend_stats
        .ok_or_else(|| "accelerated rebuild backend counters missing".to_owned())?;
    let device_memory_before = metrics
        .device_memory_before
        .ok_or_else(|| "accelerated rebuild initial VRAM census missing".to_owned())?;
    let device_memory_after = metrics
        .device_memory_after
        .ok_or_else(|| "accelerated rebuild final VRAM census missing".to_owned())?;
    let control_before = metrics
        .control_before
        .ok_or_else(|| "accelerated rebuild initial ownership census missing".to_owned())?;
    let control_after = metrics
        .control_after
        .ok_or_else(|| "accelerated rebuild final ownership census missing".to_owned())?;
    let accepted = metrics.root_equal
        && metrics.traffic_exact
        && metrics.cleanup_complete
        && metrics.scratch_files_created == 0
        && metrics.scratch_bytes_read == 0
        && metrics.scratch_bytes_written == 0
        && metrics.file_backed_bytes == 0
        && metrics.owned_file_count == 0
        && metrics.owned_mapping_count == 0
        && control_after.stream_state == CudaStreamState::Idle
        && !control_after.measurement_active
        && !control_after.coarse_timing_active
        && !control_after.timing_record_active
        && control_after.outstanding_cuda_operations == 0
        && control_after.pending_timing_records == 0
        && backend.timing_event_api_calls == 0
        && backend.timing_records == 0;
    Ok(AcceleratedRebuildCohortRecord {
        cohort_id,
        strategy: metrics.strategy.as_str().to_owned(),
        wall_s: metrics.phase_walls.total_ns as f64 / 1e9,
        phases: RebuildPhaseRecord {
            e_ntt_ns: metrics.phase_walls.e_ntt_ns,
            n4_inner_ns: metrics.phase_walls.n4_inner_ns,
            n4_outer_ns: metrics.phase_walls.n4_outer_ns,
            assemble_and_root_check_ns: metrics.phase_walls.assemble_and_root_check_ns,
            cleanup_ns: metrics.phase_walls.cleanup_ns,
            total_ns: metrics.phase_walls.total_ns,
        },
        process_memory_before,
        process_memory_after,
        backend: backend.into(),
        device_memory_before: device_memory_before.into(),
        device_memory_after: device_memory_after.into(),
        control_before: control_before.into(),
        control_after: control_after.into(),
        structural_slots: metrics.structural_slots,
        present_slots: metrics.present_slots,
        coefficient_bytes: metrics.coefficient_bytes,
        host_oracle_bytes: metrics.host_oracle_bytes,
        host_outer_cache_bytes: metrics.host_outer_cache_bytes,
        ntt_calls: metrics.ntt_calls,
        n4_inner_calls: metrics.n4_inner_calls,
        n4_outer_calls: metrics.n4_outer_calls,
        expected_h2d_bytes: metrics.expected_h2d_bytes,
        expected_d2h_bytes: metrics.expected_d2h_bytes,
        scratch_files_created: metrics.scratch_files_created,
        scratch_bytes_read: metrics.scratch_bytes_read,
        scratch_bytes_written: metrics.scratch_bytes_written,
        file_backed_bytes: metrics.file_backed_bytes,
        owned_file_count: metrics.owned_file_count,
        owned_mapping_count: metrics.owned_mapping_count,
        root_equal: metrics.root_equal,
        traffic_exact: metrics.traffic_exact,
        cleanup_complete: metrics.cleanup_complete,
        accepted,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct AcceleratedRebuildRecord {
    pub contract: String,
    pub strategy: String,
    pub deterministic_schedule: Vec<u32>,
    pub cuda_cohort_concurrency: u64,
    pub mu26_mu22_overlap: bool,
    pub automatic_cpu_fallback: bool,
    pub cpu_fallback_opt_in_only: bool,
    pub evaluation_table_wall_s: f64,
    pub cohorts: Vec<AcceleratedRebuildCohortRecord>,
    pub expected_h2d_bytes: u64,
    pub expected_d2h_bytes: u64,
    pub peak_host_rss_bytes: u64,
    pub peak_device_bytes: u64,
    pub scratch_files_created: u64,
    pub scratch_bytes_read: u64,
    pub scratch_bytes_written: u64,
    pub outstanding_cuda_operations: u64,
    pub rebuild_workspace_bytes_before_context_drop: u64,
    pub rebuild_live_device_bytes_before_context_drop: u64,
    pub backend_context_cleanup_wall_s: f64,
    pub backend_context_dropped_before_response: bool,
    pub online_backend_fresh_context: bool,
    pub fresh_online_backend_device_bytes: u64,
    pub fresh_online_backend_outstanding_cuda_operations: u64,
    pub cleanup_complete: bool,
    pub traffic_exact: bool,
    pub accepted: bool,
}
