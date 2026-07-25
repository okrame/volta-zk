//! Fail-closed host-RAM rebuild for the frozen schema-4 X4c initial sources.
//!
//! The accelerated path composes the existing byte-identical X4b CUDA
//! primitives.  It never creates an oracle, cache or staging artifact and it
//! never falls back to the CPU after an accelerator error.

use std::time::Instant;

use volta_accel::{
    Backend, BackendKind, BackendStats, CudaStreamState, DeviceMemoryBreakdown, X4cControlState,
};
use volta_field::Fp2;

use super::cuda_v4::{x4b_inner_tile_coordinates_v4, x4b_outer_tile_parents_v4};
use super::frame::Digest;
use super::merkle_v4::{CohortVerifierConfigV4, DenseOuterNodeCacheV4, OuterCachePolicyV4};
use super::x4c_v4::X4cRamModelGlobalCohortV4;

const FP2_BYTES: u64 = 16;
const DIGEST_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X4cRamRebuildStrategyV4 {
    CudaRam,
    CpuExplicit,
}

impl X4cRamRebuildStrategyV4 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CudaRam => "cuda-ram-v1",
            Self::CpuExplicit => "cpu-explicit-v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4cRamRebuildPhaseWallsV4 {
    pub e_ntt_ns: u64,
    pub n4_inner_ns: u64,
    pub n4_outer_ns: u64,
    pub assemble_and_root_check_ns: u64,
    pub cleanup_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug)]
pub struct X4cRamRebuildMetricsV4 {
    pub strategy: X4cRamRebuildStrategyV4,
    pub phase_walls: X4cRamRebuildPhaseWallsV4,
    pub rayon_workers: usize,
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
    pub backend_stats: Option<BackendStats>,
    pub device_memory_before: Option<DeviceMemoryBreakdown>,
    pub device_memory_after: Option<DeviceMemoryBreakdown>,
    pub control_before: Option<X4cControlState>,
    pub control_after: Option<X4cControlState>,
    pub root_equal: bool,
    pub traffic_exact: bool,
    pub cleanup_complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X4cRamRebuildErrorV4 {
    Invalid(&'static str),
    Overflow,
    Runtime(String),
}

impl std::fmt::Display for X4cRamRebuildErrorV4 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid X4c RAM rebuild: {message}"),
            Self::Overflow => write!(formatter, "X4c RAM rebuild byte geometry overflow"),
            Self::Runtime(message) => write!(formatter, "X4c RAM rebuild runtime error: {message}"),
        }
    }
}

impl std::error::Error for X4cRamRebuildErrorV4 {}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn add_u64(left: u64, right: u64) -> Result<u64, X4cRamRebuildErrorV4> {
    left.checked_add(right).ok_or(X4cRamRebuildErrorV4::Overflow)
}

fn coefficient_bytes(
    config: &CohortVerifierConfigV4,
    coefficients: &[Option<Vec<Fp2>>],
) -> Result<u64, X4cRamRebuildErrorV4> {
    if coefficients.len() != config.slot_descriptors.len() {
        return Err(X4cRamRebuildErrorV4::Invalid("coefficient slot count"));
    }
    let coefficient_len = config.outer_len / 8;
    config.slot_descriptors.iter().zip(coefficients).try_fold(0u64, |sum, (descriptor, values)| {
        match (descriptor, values) {
            (Some(_), Some(values)) if values.len() == coefficient_len => {
                let bytes = u64::try_from(values.len())
                    .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                    .checked_mul(FP2_BYTES)
                    .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                add_u64(sum, bytes)
            }
            (None, None) => Ok(sum),
            _ => Err(X4cRamRebuildErrorV4::Invalid("coefficient slot geometry")),
        }
    })
}

fn ownership_restored(before: X4cControlState, after: X4cControlState) -> bool {
    after.stream_state == CudaStreamState::Idle
        && !after.measurement_active
        && !after.coarse_timing_active
        && !after.timing_record_active
        && !after.measurement_poisoned
        && after.outstanding_cuda_operations == 0
        && after.pending_timing_records == 0
        && after.active_device_allocations == before.active_device_allocations
        && after.active_device_bytes == before.active_device_bytes
        && after.active_pinned_allocations == before.active_pinned_allocations
        && after.active_pinned_bytes == before.active_pinned_bytes
        && after.in_flight_pinned_allocations == 0
}

trait X4cRamAcceleratorV4 {
    fn native_counters_required(&self) -> bool;
    fn begin_measurement(&mut self) -> Result<(), String>;
    fn finish_measurement(
        &mut self,
        expected_h2d_bytes: u64,
        expected_d2h_bytes: u64,
    ) -> Result<BackendStats, String>;
    fn reset_measurement(&mut self) -> Result<(), String>;
    fn memory(&self) -> Result<DeviceMemoryBreakdown, String>;
    fn control(&self) -> Result<X4cControlState, String>;
    fn encode(&mut self, coefficients: &[Fp2], size: usize) -> Result<Vec<Fp2>, String>;
    fn n4_inner(
        &mut self,
        config: &CohortVerifierConfigV4,
        codewords: &[Option<Vec<Fp2>>],
        coordinate_start: usize,
        coordinates: usize,
    ) -> Result<Vec<Digest>, String>;
    fn n4_outer(
        &mut self,
        config: &CohortVerifierConfigV4,
        children: &[Digest],
        node_start: u64,
        level: u8,
    ) -> Result<Vec<Digest>, String>;
}

struct BackendAcceleratorV4<'a>(&'a mut Backend);

impl X4cRamAcceleratorV4 for BackendAcceleratorV4<'_> {
    fn native_counters_required(&self) -> bool {
        true
    }

    fn begin_measurement(&mut self) -> Result<(), String> {
        self.0.begin_measurement().map_err(|error| error.to_string())
    }

    fn finish_measurement(
        &mut self,
        _expected_h2d_bytes: u64,
        _expected_d2h_bytes: u64,
    ) -> Result<BackendStats, String> {
        self.0.finish_measurement().map_err(|error| error.to_string())
    }

    fn reset_measurement(&mut self) -> Result<(), String> {
        self.0.reset_measurement().map_err(|error| error.to_string())
    }

    fn memory(&self) -> Result<DeviceMemoryBreakdown, String> {
        self.0.device_memory_breakdown().map_err(|error| error.to_string())
    }

    fn control(&self) -> Result<X4cControlState, String> {
        self.0.x4c_control_state().map_err(|error| error.to_string())
    }

    fn encode(&mut self, coefficients: &[Fp2], size: usize) -> Result<Vec<Fp2>, String> {
        self.0.x4b_ntt_fp2(coefficients, size).map_err(|error| error.to_string())
    }

    fn n4_inner(
        &mut self,
        config: &CohortVerifierConfigV4,
        codewords: &[Option<Vec<Fp2>>],
        coordinate_start: usize,
        coordinates: usize,
    ) -> Result<Vec<Digest>, String> {
        let mut ranks = Vec::with_capacity(config.slot_descriptors.len());
        let mut descriptors = Vec::with_capacity(config.slot_descriptors.len());
        let mut present_rank = 0u16;
        let mut symbols = Vec::new();
        for (descriptor, codeword) in config.slot_descriptors.iter().zip(codewords) {
            match (descriptor, codeword) {
                (Some(descriptor), Some(codeword)) => {
                    ranks.push(present_rank);
                    descriptors.push(*descriptor);
                    present_rank = present_rank
                        .checked_add(1)
                        .ok_or_else(|| "present-slot rank overflow".to_owned())?;
                    let end = coordinate_start
                        .checked_add(coordinates)
                        .ok_or_else(|| "coordinate range overflow".to_owned())?;
                    symbols.extend_from_slice(
                        codeword
                            .get(coordinate_start..end)
                            .ok_or_else(|| "codeword tile range".to_owned())?,
                    );
                }
                (None, None) => {
                    ranks.push(u16::MAX);
                    descriptors.push([0u8; 32]);
                }
                _ => return Err("codeword slot geometry".to_owned()),
            }
        }
        self.0
            .x4b_n4_inner_tile(
                &symbols,
                coordinates,
                &ranks,
                &descriptors,
                u64::try_from(coordinate_start)
                    .map_err(|_| "coordinate start overflows u64".to_owned())?,
                config.identity.cohort_id,
                config.identity.oracle_kind as u8,
                config.identity.fold_round,
            )
            .map_err(|error| error.to_string())
    }

    fn n4_outer(
        &mut self,
        config: &CohortVerifierConfigV4,
        children: &[Digest],
        node_start: u64,
        level: u8,
    ) -> Result<Vec<Digest>, String> {
        self.0
            .x4b_n4_outer_nodes(
                children,
                node_start,
                config.identity.cohort_id,
                config.identity.oracle_kind as u8,
                config.identity.fold_round,
                level,
            )
            .map_err(|error| error.to_string())
    }
}

fn rebuild_cuda_with_accelerator_v4<A: X4cRamAcceleratorV4>(
    accelerator: &mut A,
    config: CohortVerifierConfigV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    expected_root: Digest,
) -> Result<(X4cRamModelGlobalCohortV4, X4cRamRebuildMetricsV4), X4cRamRebuildErrorV4> {
    config
        .validate()
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("config: {error:?}")))?;
    if expected_root == [0u8; 32] {
        return Err(X4cRamRebuildErrorV4::Invalid("zero expected root"));
    }
    let total_started = Instant::now();
    let coefficient_bytes = coefficient_bytes(&config, &coefficients)?;
    let structural_slots =
        u64::try_from(config.slot_descriptors.len()).map_err(|_| X4cRamRebuildErrorV4::Overflow)?;
    let present_slots = u64::try_from(config.slot_descriptors.iter().flatten().count())
        .map_err(|_| X4cRamRebuildErrorV4::Overflow)?;
    let before_memory =
        accelerator.memory().map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_owned()))?;
    let before_control =
        accelerator.control().map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_owned()))?;
    if before_control.measurement_active
        || before_control.coarse_timing_active
        || before_control.timing_record_active
        || before_control.measurement_poisoned
        || before_control.outstanding_cuda_operations != 0
        || before_control.in_flight_pinned_allocations != 0
        || before_control.stream_state != CudaStreamState::Idle
    {
        return Err(X4cRamRebuildErrorV4::Invalid("dirty accelerator boundary"));
    }
    accelerator
        .begin_measurement()
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("begin measurement: {error}")))?;

    let mut phase_walls = X4cRamRebuildPhaseWallsV4::default();
    let mut expected_h2d_bytes = 0u64;
    let mut expected_d2h_bytes = 0u64;
    let mut ntt_calls = 0u64;
    let mut n4_inner_calls = 0u64;
    let mut n4_outer_calls = 0u64;

    let build = (|| {
        let ntt_started = Instant::now();
        let codewords = config
            .slot_descriptors
            .iter()
            .zip(&coefficients)
            .map(|(descriptor, values)| match (descriptor, values) {
                (Some(_), Some(values)) => {
                    let encoded = accelerator
                        .encode(values, config.outer_len)
                        .map_err(X4cRamRebuildErrorV4::Runtime)?;
                    ntt_calls = ntt_calls.checked_add(1).ok_or(X4cRamRebuildErrorV4::Overflow)?;
                    let input_bytes = u64::try_from(values.len())
                        .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                        .checked_mul(FP2_BYTES)
                        .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                    let output_bytes = u64::try_from(encoded.len())
                        .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                        .checked_mul(FP2_BYTES)
                        .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                    expected_h2d_bytes = add_u64(expected_h2d_bytes, input_bytes)?;
                    expected_d2h_bytes = add_u64(expected_d2h_bytes, output_bytes)?;
                    Ok(Some(encoded))
                }
                (None, None) => Ok(None),
                _ => Err(X4cRamRebuildErrorV4::Invalid("coefficient presence")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        phase_walls.e_ntt_ns = elapsed_ns(ntt_started);

        let tile = x4b_inner_tile_coordinates_v4(
            config.slot_descriptors.len(),
            usize::try_from(present_slots).map_err(|_| X4cRamRebuildErrorV4::Overflow)?,
            config.outer_len,
        )
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_string()))?;
        let inner_started = Instant::now();
        let mut outer_leaves = Vec::with_capacity(config.outer_len);
        for start in (0..config.outer_len).step_by(tile) {
            let count = tile.min(config.outer_len - start);
            let leaves = accelerator
                .n4_inner(&config, &codewords, start, count)
                .map_err(X4cRamRebuildErrorV4::Runtime)?;
            if leaves.len() != count {
                return Err(X4cRamRebuildErrorV4::Invalid("N4 inner output length"));
            }
            outer_leaves.extend_from_slice(&leaves);
            n4_inner_calls = n4_inner_calls.checked_add(1).ok_or(X4cRamRebuildErrorV4::Overflow)?;
            let symbol_bytes = present_slots
                .checked_mul(u64::try_from(count).map_err(|_| X4cRamRebuildErrorV4::Overflow)?)
                .and_then(|value| value.checked_mul(FP2_BYTES))
                .ok_or(X4cRamRebuildErrorV4::Overflow)?;
            let metadata_bytes = structural_slots
                .checked_mul(2 + DIGEST_BYTES)
                .ok_or(X4cRamRebuildErrorV4::Overflow)?;
            expected_h2d_bytes =
                add_u64(expected_h2d_bytes, add_u64(symbol_bytes, metadata_bytes)?)?;
            expected_d2h_bytes = add_u64(
                expected_d2h_bytes,
                u64::try_from(count)
                    .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                    .checked_mul(DIGEST_BYTES)
                    .ok_or(X4cRamRebuildErrorV4::Overflow)?,
            )?;
        }
        phase_walls.n4_inner_ns = elapsed_ns(inner_started);

        let outer_started = Instant::now();
        let depth = config.outer_len.ilog2() as u8;
        let mut retained_levels = vec![None; usize::from(depth)];
        let mut previous = outer_leaves;
        for level in 1..=depth {
            let parent_count = previous.len() / 2;
            let parent_tile = x4b_outer_tile_parents_v4(parent_count)
                .map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_string()))?;
            let mut next = Vec::with_capacity(parent_count);
            for node_start in (0..parent_count).step_by(parent_tile) {
                let parents = parent_tile.min(parent_count - node_start);
                let child_start =
                    node_start.checked_mul(2).ok_or(X4cRamRebuildErrorV4::Overflow)?;
                let child_end = child_start
                    .checked_add(parents.checked_mul(2).ok_or(X4cRamRebuildErrorV4::Overflow)?)
                    .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                let output = accelerator
                    .n4_outer(
                        &config,
                        &previous[child_start..child_end],
                        u64::try_from(node_start).map_err(|_| X4cRamRebuildErrorV4::Overflow)?,
                        level,
                    )
                    .map_err(X4cRamRebuildErrorV4::Runtime)?;
                if output.len() != parents {
                    return Err(X4cRamRebuildErrorV4::Invalid("N4 outer output length"));
                }
                next.extend_from_slice(&output);
                n4_outer_calls =
                    n4_outer_calls.checked_add(1).ok_or(X4cRamRebuildErrorV4::Overflow)?;
                let input_bytes = u64::try_from(parents)
                    .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                    .checked_mul(2 * DIGEST_BYTES)
                    .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                let output_bytes = u64::try_from(parents)
                    .map_err(|_| X4cRamRebuildErrorV4::Overflow)?
                    .checked_mul(DIGEST_BYTES)
                    .ok_or(X4cRamRebuildErrorV4::Overflow)?;
                expected_h2d_bytes = add_u64(expected_h2d_bytes, input_bytes)?;
                expected_d2h_bytes = add_u64(expected_d2h_bytes, output_bytes)?;
            }
            if level > 1 {
                retained_levels[usize::from(level - 2)] = Some(previous);
            }
            previous = next;
        }
        let root = *previous.first().ok_or(X4cRamRebuildErrorV4::Invalid("empty N4 root"))?;
        retained_levels[usize::from(depth - 1)] = Some(previous);
        phase_walls.n4_outer_ns = elapsed_ns(outer_started);

        let assemble_started = Instant::now();
        let outer_cache = DenseOuterNodeCacheV4::from_levels(
            config.outer_len,
            OuterCachePolicyV4::FULL,
            retained_levels,
            root,
        )
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("outer cache: {error:?}")))?;
        let source = X4cRamModelGlobalCohortV4::from_parts(
            config.clone(),
            coefficients,
            codewords,
            outer_cache,
        )
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("RAM source: {error:?}")))?;
        if source.root() != expected_root {
            return Err(X4cRamRebuildErrorV4::Invalid("durable root mismatch"));
        }
        phase_walls.assemble_and_root_check_ns = elapsed_ns(assemble_started);
        Ok(source)
    })();

    let source = match build {
        Ok(source) => source,
        Err(error) => {
            let reset_error = accelerator.reset_measurement().err();
            return match reset_error {
                Some(reset) => Err(X4cRamRebuildErrorV4::Runtime(format!(
                    "{error}; abort cleanup failed: {reset}"
                ))),
                None => Err(error),
            };
        }
    };
    let cleanup_started = Instant::now();
    let backend_stats = match accelerator.finish_measurement(expected_h2d_bytes, expected_d2h_bytes)
    {
        Ok(stats) => stats,
        Err(error) => {
            let reset_error = accelerator.reset_measurement().err();
            return match reset_error {
                Some(reset) => Err(X4cRamRebuildErrorV4::Runtime(format!(
                    "finish measurement: {error}; abort cleanup failed: {reset}"
                ))),
                None => Err(X4cRamRebuildErrorV4::Runtime(format!("finish measurement: {error}"))),
            };
        }
    };
    let after_control =
        accelerator.control().map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_owned()))?;
    let after_memory =
        accelerator.memory().map_err(|error| X4cRamRebuildErrorV4::Runtime(error.to_owned()))?;
    phase_walls.cleanup_ns = elapsed_ns(cleanup_started);
    phase_walls.total_ns = elapsed_ns(total_started);

    let cleanup_complete = ownership_restored(before_control, after_control);
    let traffic_exact = !accelerator.native_counters_required()
        || (backend_stats.h2d_bytes == expected_h2d_bytes
            && backend_stats.d2h_bytes == expected_d2h_bytes);
    if !cleanup_complete {
        return Err(X4cRamRebuildErrorV4::Invalid("accelerator ownership cleanup"));
    }
    if !traffic_exact {
        return Err(X4cRamRebuildErrorV4::Invalid("accelerator traffic counters"));
    }
    let host_oracle_bytes = source
        .host_oracle_bytes()
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("oracle census: {error:?}")))?;
    let host_outer_cache_bytes = source
        .host_outer_cache_bytes()
        .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("cache census: {error:?}")))?;
    let metrics = X4cRamRebuildMetricsV4 {
        strategy: X4cRamRebuildStrategyV4::CudaRam,
        phase_walls,
        rayon_workers: rayon::current_num_threads(),
        structural_slots,
        present_slots,
        coefficient_bytes,
        host_oracle_bytes,
        host_outer_cache_bytes,
        ntt_calls,
        n4_inner_calls,
        n4_outer_calls,
        expected_h2d_bytes,
        expected_d2h_bytes,
        scratch_files_created: 0,
        scratch_bytes_read: 0,
        scratch_bytes_written: 0,
        file_backed_bytes: 0,
        owned_file_count: 0,
        owned_mapping_count: 0,
        backend_stats: Some(backend_stats),
        device_memory_before: Some(before_memory),
        device_memory_after: Some(after_memory),
        control_before: Some(before_control),
        control_after: Some(after_control),
        root_equal: true,
        traffic_exact,
        cleanup_complete,
    };
    Ok((source, metrics))
}

pub fn rebuild_cohort_ram_v4(
    strategy: X4cRamRebuildStrategyV4,
    backend: Option<&mut Backend>,
    config: CohortVerifierConfigV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    expected_root: Digest,
) -> Result<(X4cRamModelGlobalCohortV4, X4cRamRebuildMetricsV4), X4cRamRebuildErrorV4> {
    match strategy {
        X4cRamRebuildStrategyV4::CudaRam => {
            let backend =
                backend.ok_or(X4cRamRebuildErrorV4::Invalid("CUDA backend is required"))?;
            if backend.kind() == BackendKind::Cpu {
                return Err(X4cRamRebuildErrorV4::Invalid("CPU backend supplied to CUDA rebuild"));
            }
            rebuild_cuda_with_accelerator_v4(
                &mut BackendAcceleratorV4(backend),
                config,
                coefficients,
                expected_root,
            )
        }
        X4cRamRebuildStrategyV4::CpuExplicit => {
            let started = Instant::now();
            let structural_slots = u64::try_from(config.slot_descriptors.len())
                .map_err(|_| X4cRamRebuildErrorV4::Overflow)?;
            let present_slots = u64::try_from(config.slot_descriptors.iter().flatten().count())
                .map_err(|_| X4cRamRebuildErrorV4::Overflow)?;
            let coefficient_bytes = coefficient_bytes(&config, &coefficients)?;
            let source = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
                config,
                coefficients,
                expected_root,
            )
            .map_err(|error| X4cRamRebuildErrorV4::Runtime(format!("CPU rebuild: {error:?}")))?;
            let phase_walls = X4cRamRebuildPhaseWallsV4 {
                total_ns: elapsed_ns(started),
                ..X4cRamRebuildPhaseWallsV4::default()
            };
            let metrics = X4cRamRebuildMetricsV4 {
                strategy,
                phase_walls,
                rayon_workers: rayon::current_num_threads(),
                structural_slots,
                present_slots,
                coefficient_bytes,
                host_oracle_bytes: source.host_oracle_bytes().map_err(|error| {
                    X4cRamRebuildErrorV4::Runtime(format!("CPU oracle census: {error:?}"))
                })?,
                host_outer_cache_bytes: source.host_outer_cache_bytes().map_err(|error| {
                    X4cRamRebuildErrorV4::Runtime(format!("CPU cache census: {error:?}"))
                })?,
                ntt_calls: present_slots,
                n4_inner_calls: 0,
                n4_outer_calls: 0,
                expected_h2d_bytes: 0,
                expected_d2h_bytes: 0,
                scratch_files_created: 0,
                scratch_bytes_read: 0,
                scratch_bytes_written: 0,
                file_backed_bytes: 0,
                owned_file_count: 0,
                owned_mapping_count: 0,
                backend_stats: None,
                device_memory_before: None,
                device_memory_after: None,
                control_before: None,
                control_after: None,
                root_equal: true,
                traffic_exact: true,
                cleanup_complete: true,
            };
            Ok((source, metrics))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x4::merkle_v4::outer_leaf_hashes_from_flat_tile_v4;
    use crate::x4::{
        encode_rate_eighth, hash_pcs_node_fields_v4, CohortIdentityV4, CohortTreeV4, OracleKindV4,
        TreeRole,
    };
    use volta_field::{Fp, Fp2};

    #[derive(Default)]
    struct CpuAccelerator {
        measurement_active: bool,
        measurement_finished: bool,
        expected_h2d_bytes: u64,
        expected_d2h_bytes: u64,
        fail_encode: bool,
        fail_finish: bool,
        traffic_mismatch: bool,
        initial_outstanding_operations: u64,
        final_outstanding_operations: u64,
        reset_calls: u64,
        cpu_fallback_calls: u64,
    }

    impl X4cRamAcceleratorV4 for CpuAccelerator {
        fn native_counters_required(&self) -> bool {
            true
        }

        fn begin_measurement(&mut self) -> Result<(), String> {
            if self.measurement_active {
                return Err("measurement already active".to_owned());
            }
            self.measurement_active = true;
            Ok(())
        }

        fn finish_measurement(
            &mut self,
            expected_h2d_bytes: u64,
            expected_d2h_bytes: u64,
        ) -> Result<BackendStats, String> {
            if self.fail_finish {
                return Err("injected finish failure".to_owned());
            }
            self.measurement_active = false;
            self.measurement_finished = true;
            self.expected_h2d_bytes = expected_h2d_bytes;
            self.expected_d2h_bytes = expected_d2h_bytes;
            Ok(BackendStats {
                h2d_bytes: expected_h2d_bytes + u64::from(self.traffic_mismatch),
                d2h_bytes: expected_d2h_bytes,
                ..BackendStats::default()
            })
        }

        fn reset_measurement(&mut self) -> Result<(), String> {
            self.measurement_active = false;
            self.measurement_finished = false;
            self.reset_calls += 1;
            Ok(())
        }

        fn memory(&self) -> Result<DeviceMemoryBreakdown, String> {
            Ok(DeviceMemoryBreakdown::default())
        }

        fn control(&self) -> Result<X4cControlState, String> {
            Ok(X4cControlState {
                measurement_active: self.measurement_active,
                outstanding_cuda_operations: if self.measurement_finished {
                    self.final_outstanding_operations
                } else {
                    self.initial_outstanding_operations
                },
                ..X4cControlState::default()
            })
        }

        fn encode(&mut self, coefficients: &[Fp2], _size: usize) -> Result<Vec<Fp2>, String> {
            if self.fail_encode {
                return Err("injected CUDA failure".to_owned());
            }
            encode_rate_eighth(coefficients).map_err(|error| format!("{error:?}"))
        }

        fn n4_inner(
            &mut self,
            config: &CohortVerifierConfigV4,
            codewords: &[Option<Vec<Fp2>>],
            coordinate_start: usize,
            coordinates: usize,
        ) -> Result<Vec<Digest>, String> {
            outer_leaf_hashes_from_flat_tile_v4(config, codewords, coordinate_start, coordinates)
                .map_err(|error| format!("{error:?}"))
        }

        fn n4_outer(
            &mut self,
            config: &CohortVerifierConfigV4,
            children: &[Digest],
            node_start: u64,
            level: u8,
        ) -> Result<Vec<Digest>, String> {
            children
                .chunks_exact(2)
                .enumerate()
                .map(|(offset, pair)| {
                    hash_pcs_node_fields_v4(
                        config.identity.cohort_id,
                        TreeRole::Outer,
                        config.identity.oracle_kind,
                        config.identity.fold_round,
                        u64::MAX,
                        level,
                        node_start + offset as u64,
                        pair[0],
                        pair[1],
                    )
                    .map_err(|error| format!("{error:?}"))
                })
                .collect()
        }
    }

    fn fixture() -> (CohortVerifierConfigV4, Vec<Option<Vec<Fp2>>>, Digest) {
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 0xA500_C001,
                oracle_kind: OracleKindV4::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some([1; 32]), None, Some([2; 32]), None],
            outer_len: 64,
            expected_symbol_count: 1,
        };
        let coefficients: Vec<Option<Vec<Fp2>>> = vec![
            Some((0..8).map(|value| Fp2::from_base(Fp::new(value + 1))).collect::<Vec<_>>()),
            None,
            Some((0..8).map(|value| Fp2::from_base(Fp::new(value + 11))).collect::<Vec<_>>()),
            None,
        ];
        let codewords = coefficients
            .iter()
            .map(|slot| slot.as_ref().map(|values| encode_rate_eighth(values).unwrap()))
            .collect::<Vec<_>>();
        let root = CohortTreeV4::build_flat(config.clone(), codewords).unwrap().root();
        (config, coefficients, root)
    }

    #[test]
    fn accelerated_ram_rebuild_matches_cpu_root_and_ownership() {
        let (config, coefficients, root) = fixture();
        let mut backend = CpuAccelerator::default();
        let (source, metrics) =
            rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root).unwrap();
        assert_eq!(source.root(), root);
        assert!(metrics.root_equal);
        assert!(metrics.traffic_exact);
        assert!(metrics.cleanup_complete);
        assert_eq!(metrics.scratch_files_created, 0);
        assert_eq!(metrics.scratch_bytes_read, 0);
        assert_eq!(metrics.scratch_bytes_written, 0);
        assert_eq!(metrics.file_backed_bytes, 0);
        assert_eq!(metrics.owned_file_count, 0);
        assert_eq!(metrics.owned_mapping_count, 0);
        assert_eq!(metrics.control_after.unwrap().outstanding_cuda_operations, 0);
    }

    #[test]
    fn accelerated_ram_rebuild_rejects_root_mismatch() {
        let (config, coefficients, mut root) = fixture();
        root[0] ^= 1;
        let mut backend = CpuAccelerator::default();
        assert!(matches!(
            rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root),
            Err(X4cRamRebuildErrorV4::Invalid("durable root mismatch"))
        ));
        assert!(!backend.measurement_active);
    }

    #[test]
    fn accelerator_failure_cleans_up_without_cpu_fallback() {
        let (config, coefficients, root) = fixture();
        let mut backend = CpuAccelerator { fail_encode: true, ..CpuAccelerator::default() };
        assert!(rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root).is_err());
        assert!(!backend.measurement_active);
        assert_eq!(backend.reset_calls, 1);
        backend.reset_measurement().unwrap();
        assert_eq!(backend.reset_calls, 2);
        assert_eq!(backend.cpu_fallback_calls, 0);
    }

    #[test]
    fn finish_failure_uses_the_same_idempotent_abort_cleanup() {
        let (config, coefficients, root) = fixture();
        let mut backend = CpuAccelerator { fail_finish: true, ..CpuAccelerator::default() };
        assert!(rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root).is_err());
        assert!(!backend.measurement_active);
        assert_eq!(backend.reset_calls, 1);
        backend.reset_measurement().unwrap();
        assert_eq!(backend.reset_calls, 2);
        assert_eq!(backend.cpu_fallback_calls, 0);
    }

    #[test]
    fn dirty_or_contradictory_native_counters_fail_closed() {
        let (config, coefficients, root) = fixture();
        let mut dirty =
            CpuAccelerator { initial_outstanding_operations: 1, ..CpuAccelerator::default() };
        assert!(matches!(
            rebuild_cuda_with_accelerator_v4(
                &mut dirty,
                config.clone(),
                coefficients.clone(),
                root
            ),
            Err(X4cRamRebuildErrorV4::Invalid("dirty accelerator boundary"))
        ));
        assert_eq!(dirty.cpu_fallback_calls, 0);

        let mut traffic = CpuAccelerator { traffic_mismatch: true, ..CpuAccelerator::default() };
        assert!(matches!(
            rebuild_cuda_with_accelerator_v4(
                &mut traffic,
                config.clone(),
                coefficients.clone(),
                root
            ),
            Err(X4cRamRebuildErrorV4::Invalid("accelerator traffic counters"))
        ));
        assert_eq!(traffic.cpu_fallback_calls, 0);

        let mut outstanding =
            CpuAccelerator { final_outstanding_operations: 1, ..CpuAccelerator::default() };
        assert!(matches!(
            rebuild_cuda_with_accelerator_v4(&mut outstanding, config, coefficients, root),
            Err(X4cRamRebuildErrorV4::Invalid("accelerator ownership cleanup"))
        ));
        assert_eq!(outstanding.cpu_fallback_calls, 0);
    }

    #[test]
    fn accelerated_ntt_n4_outer_cache_and_opening_match_cpu() {
        use crate::x4::ModelGlobalOpeningSourceV4;

        let (config, coefficients, root) = fixture();
        let cpu = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
            config.clone(),
            coefficients.clone(),
            root,
        )
        .unwrap();
        let mut backend = CpuAccelerator::default();
        let (accelerated, _) =
            rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root).unwrap();
        assert_eq!(accelerated.root(), cpu.root());
        assert_eq!(accelerated.host_oracle_bytes().unwrap(), cpu.host_oracle_bytes().unwrap());
        assert_eq!(
            accelerated.host_outer_cache_bytes().unwrap(),
            cpu.host_outer_cache_bytes().unwrap()
        );
        let draws = (0..111).map(|index| ((index * 29 + 5) & 63) as u64).collect::<Vec<_>>();
        let (accelerated_opening, accelerated_traffic) =
            accelerated.open_initial_source(&draws, &[0, 2]).unwrap();
        let (cpu_opening, cpu_traffic) = cpu.open_initial_source(&draws, &[0, 2]).unwrap();
        assert_eq!(accelerated_opening, cpu_opening);
        assert_eq!(accelerated_traffic, cpu_traffic);
        let point = vec![Fp2::new(Fp::new(3), Fp::new(7)); 3];
        let (accelerated_combined, _) =
            accelerated.combine_source(&[0, 2], &[Fp2::ONE, Fp2::ONE], &point).unwrap();
        let (cpu_combined, _) = cpu.combine_source(&[0, 2], &[Fp2::ONE, Fp2::ONE], &point).unwrap();
        assert_eq!(accelerated_combined.codeword, cpu_combined.codeword);
        assert_eq!(accelerated_combined.coefficients, cpu_combined.coefficients);
        assert_eq!(accelerated_combined.claimed_value, cpu_combined.claimed_value);
    }

    #[test]
    fn accelerated_rebuild_rejects_cohort_and_config_mismatch() {
        let (mut config, coefficients, root) = fixture();
        config.identity.cohort_id ^= 1;
        let mut backend = CpuAccelerator::default();
        assert!(matches!(
            rebuild_cuda_with_accelerator_v4(&mut backend, config, coefficients, root),
            Err(X4cRamRebuildErrorV4::Invalid("durable root mismatch"))
        ));
        assert_eq!(backend.cpu_fallback_calls, 0);
    }

    #[test]
    fn explicit_cpu_rebuild_is_separate_and_root_checked() {
        let (config, coefficients, root) = fixture();
        let (source, metrics) = rebuild_cohort_ram_v4(
            X4cRamRebuildStrategyV4::CpuExplicit,
            None,
            config,
            coefficients,
            root,
        )
        .unwrap();
        assert_eq!(source.root(), root);
        assert_eq!(metrics.strategy, X4cRamRebuildStrategyV4::CpuExplicit);
        assert!(metrics.backend_stats.is_none());
    }
}
