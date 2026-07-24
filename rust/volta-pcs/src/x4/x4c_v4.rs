//! X4c byte-identical response-lifecycle primitives.
//!
//! This module contains the protocol-neutral geometry and CPU reference
//! boundary for the approved X4c implementation.  It does not define a new
//! proof frame, query schedule, root, or soundness parameter.  The frozen v4
//! codec remains the only wire format.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::time::Instant;

use volta_accel::{
    AccelError, Backend, BackendStats, CudaStreamState, DeviceBuffer, Fp2Repr, PinnedHostBuffer,
    X4cCanonicalGatherOperation, X4cOneSlotN4Layout, X4C_GATHER_CACHED_OUTER_DIGEST,
    X4C_GATHER_CODEWORD_SYMBOL, X4C_GATHER_REBUILT_OUTER_DIGEST,
};
use volta_field::{Fp, Fp2, P};
use volta_mac::Transcript;

use super::accounting::{merkle_aux_node_count, projected_query_indices};
use super::folding_v4::{
    accumulate_recompute_traffic, claim_line_v4, interpolate_v4, packed_schedule_from_verifier,
    validate_query_draws, FoldingErrorV4, GlobalChainDraftV4, GlobalFoldChallengesV4,
    GlobalFoldingProofV4, GlobalOpenMetricsV4, GlobalProverGroupV4, GlobalVerifierGroupV4,
    ModelGlobalCohortCommitmentV4, ModelGlobalOpeningSourceV4, SourceRecomputeTrafficV4,
};
use super::frame::{Digest, FrameError, TreeRole};
use super::frame_v4::{
    decode_v4, gpt2_codec_reference_packed_opening_v4, hash_pcs_inner_leaf_fields_v4,
    hash_pcs_node_fields_v4, hash_pcs_outer_leaf_fields_v4, opening_schedule_digest_v4,
    FoldCommitmentFrameV4, FoldRoundOpeningV4, FrameV4, InitialOpeningGroupV4, OracleKindV4,
    PackedBatchOpeningFrameV4, PackedOpeningScheduleV4, PRODUCTION_QUERY_COUNT_V4,
};
use super::merkle_v4::{
    open_initial_from_sources_v4, CohortIdentityV4, CohortTreeV4, CohortVerifierConfigV4,
    DenseOuterNodeCacheV4, OracleSymbolSourceV4, OuterCachePolicyV4, OuterNodeSourceV4,
};
use super::ntt::{encode_rate_eighth, fold_codeword, fold_coefficients, fp2_pow, root_of_unity};

pub const X4C_RATE_V4: &str = "1/8";
pub const X4C_QUERY_COUNT_V4: usize = 111;
pub const X4C_PRODUCTION_MAX_OUTER_LOG2_V4: u8 = 30;
pub const X4C_PRODUCTION_FINAL_OUTER_LOG2_V4: u8 = 3;
pub const X4C_PRODUCTION_FOLD_ROUNDS_V4: usize = 27;
pub const X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4: usize = 64;
/// Exact diagnostic comparison count for production output lengths 2^29
/// through 2^3 under `min(64, output_len)` unique coordinates per round.
pub const X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4: usize =
    24 * X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4 + 32 + 16 + 8;
/// One output gather in every round plus one positive/negative input-pair
/// gather after the first round.
pub const X4C_DIRECT_FOLD_DIAGNOSTIC_GATHER_CALLS_V4: u64 =
    2 * X4C_PRODUCTION_FOLD_ROUNDS_V4 as u64 - 1;
/// Output observations plus the two resident input symbols needed by the CPU
/// equation after round one.
pub const X4C_DIRECT_FOLD_DIAGNOSTIC_SYMBOLS_V4: u64 = X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 as u64
    + 2 * (X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 as u64
        - X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4 as u64);
pub const X4C_DIRECT_FOLD_DIAGNOSTIC_INDEX_H2D_BYTES_V4: u64 =
    X4C_DIRECT_FOLD_DIAGNOSTIC_SYMBOLS_V4 * size_of::<u64>() as u64;
pub const X4C_DIRECT_FOLD_DIAGNOSTIC_VALUE_D2H_BYTES_V4: u64 =
    X4C_DIRECT_FOLD_DIAGNOSTIC_SYMBOLS_V4 * FP2_BYTES;

pub const X4C_FOLD_CODEWORD_BYTES_V4: u64 = 17_179_869_056;
pub const X4C_FOLD_OUTER_CACHE_BYTES_V4: u64 = 17_179_868_192;
pub const X4C_RETAINED_GPU_PAYLOAD_BYTES_V4: u64 =
    X4C_FOLD_CODEWORD_BYTES_V4 + X4C_FOLD_OUTER_CACHE_BYTES_V4;
pub const X4C_REGISTERED_WORKSPACE_BYTES_V4: u64 = 9_126_808_800;
pub const X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4: u64 =
    X4C_RETAINED_GPU_PAYLOAD_BYTES_V4 + X4C_REGISTERED_WORKSPACE_BYTES_V4;

pub const X4C_INITIAL_ORACLE_HOST_BYTES_V4: u64 = 76_948_701_184;
pub const X4C_INITIAL_OUTER_CACHE_HOST_BYTES_V4: u64 = 37_094_424_416;
pub const X4C_DURABLE_COEFFICIENT_BYTES_V4: u64 = 9_618_587_648;
pub const X4C_DURABLE_ROOT_BYTES_V4: u64 = 160;
pub const X4C_DURABLE_TIER_BYTES_V4: u64 =
    X4C_DURABLE_COEFFICIENT_BYTES_V4 + X4C_DURABLE_ROOT_BYTES_V4;

pub const X4C_PACKED_OPENING_BYTES_V4: u64 = 2_615_414;
pub const X4C_MANDATORY_NON_QUERY_BYTES_V4: u64 = 67_822;
pub const X4C_FOLD_FRAME_BYTES_V4: u64 = 2_446;
pub const X4C_GLOBAL_FOLDING_PROOF_BYTES_V4: u64 =
    X4C_PACKED_OPENING_BYTES_V4 + X4C_FOLD_FRAME_BYTES_V4;
pub const X4C_COMPLETE_PCS_BYTES_V4: u64 = 2_683_236;
pub const X4C_RESPONSE_BYTES_V4: u64 = 43_953_700;
pub const X4C_DIRECT_FOLD_PARITY_DOMAIN_V4: &str = "volta-zk/x4c/direct-fold-parity/v1";
pub const X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4: usize = 1 << 24;
pub const X4C_PINNED_TRANSFER_RING_V4: usize = 2;
pub const X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4: usize =
    X4C_PACKED_OPENING_BYTES_V4 as usize / FP2_BYTES as usize;
pub const X4C_DESIGN_SHA256_HEX_V4: &str =
    "9a3c64a65902046ba0a2b1891ff8fce03690d870773a346f7128b9f75f7a1164";
pub const X4C_DESIGN_SHA256_V4: Digest = [
    0x9a, 0x3c, 0x64, 0xa6, 0x59, 0x02, 0x04, 0x6b, 0xa0, 0xa2, 0xb1, 0x89, 0x1f, 0xf8, 0xfc, 0xe0,
    0x36, 0x90, 0xd8, 0x70, 0x77, 0x3a, 0x34, 0x6f, 0x71, 0x28, 0xb9, 0xf7, 0x5f, 0x7a, 0x11, 0x64,
];

const FP2_BYTES: u64 = 16;
const DIGEST_BYTES: u64 = 32;

pub(crate) struct X4cDraftPartsV4<'a> {
    pub(crate) model_root: Digest,
    pub(crate) epoch: u64,
    pub(crate) global_cohort_id: u32,
    pub(crate) global_descriptor_digest: Digest,
    pub(crate) common_point: Vec<Fp2>,
    pub(crate) groups: Vec<GlobalProverGroupV4<'a>>,
    pub(crate) fixed_challenges: Option<GlobalFoldChallengesV4>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X4cErrorV4 {
    InvalidGeometry(&'static str),
    Overflow,
    Runtime(String),
    Frame(FrameError),
    Folding(FoldingErrorV4),
}

impl From<FrameError> for X4cErrorV4 {
    fn from(value: FrameError) -> Self {
        Self::Frame(value)
    }
}

impl From<FoldingErrorV4> for X4cErrorV4 {
    fn from(value: FoldingErrorV4) -> Self {
        Self::Folding(value)
    }
}

impl From<AccelError> for X4cErrorV4 {
    fn from(value: AccelError) -> Self {
        Self::Runtime(value.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cArenaLevelV4 {
    pub level: u8,
    pub node_count: usize,
    pub byte_offset: u64,
    pub byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cArenaRoundV4 {
    pub fold_round: u8,
    pub input_len: usize,
    pub output_len: usize,
    pub codeword_byte_offset: u64,
    pub codeword_byte_len: u64,
    /// Retained outer levels 2..=depth. Levels zero and one are reconstructed
    /// by the one batched gather and never consume arena capacity.
    pub retained_outer_levels: Vec<X4cArenaLevelV4>,
}

impl X4cArenaRoundV4 {
    pub fn root_byte_offset(&self) -> Result<u64, X4cErrorV4> {
        self.retained_outer_levels
            .last()
            .map(|level| level.byte_offset)
            .ok_or(X4cErrorV4::InvalidGeometry("X4c round has no retained root"))
    }

    pub fn retained_outer_bytes(&self) -> Result<u64, X4cErrorV4> {
        self.retained_outer_levels.iter().try_fold(0u64, |sum, level| {
            sum.checked_add(level.byte_len).ok_or(X4cErrorV4::Overflow)
        })
    }
}

/// One allocation layout for all response-local fold codewords, every
/// one-level-omitted outer tree, and the registered runtime workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cArenaLayoutV4 {
    pub max_outer_log2: u8,
    pub final_outer_log2: u8,
    pub rounds: Vec<X4cArenaRoundV4>,
    pub codeword_bytes: u64,
    pub outer_cache_bytes: u64,
    pub retained_payload_bytes: u64,
    pub workspace_byte_offset: u64,
    pub workspace_bytes: u64,
    pub capacity_bytes: u64,
}

impl X4cArenaLayoutV4 {
    pub fn production() -> Result<Self, X4cErrorV4> {
        let layout = Self::new(
            X4C_PRODUCTION_MAX_OUTER_LOG2_V4,
            X4C_PRODUCTION_FINAL_OUTER_LOG2_V4,
            X4C_REGISTERED_WORKSPACE_BYTES_V4,
        )?;
        if layout.rounds.len() != X4C_PRODUCTION_FOLD_ROUNDS_V4
            || layout.codeword_bytes != X4C_FOLD_CODEWORD_BYTES_V4
            || layout.outer_cache_bytes != X4C_FOLD_OUTER_CACHE_BYTES_V4
            || layout.retained_payload_bytes != X4C_RETAINED_GPU_PAYLOAD_BYTES_V4
            || layout.capacity_bytes != X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c production arena constants"));
        }
        Ok(layout)
    }

    pub fn new(
        max_outer_log2: u8,
        final_outer_log2: u8,
        workspace_bytes: u64,
    ) -> Result<Self, X4cErrorV4> {
        if max_outer_log2 <= final_outer_log2 || final_outer_log2 < 3 || max_outer_log2 > 33 {
            return Err(X4cErrorV4::InvalidGeometry("X4c arena domain"));
        }
        let mut rounds = Vec::with_capacity(usize::from(max_outer_log2 - final_outer_log2));
        let mut next_codeword_offset = 0u64;
        for (ordinal, output_log2) in (final_outer_log2..max_outer_log2).rev().enumerate() {
            let output_len =
                1usize.checked_shl(u32::from(output_log2)).ok_or(X4cErrorV4::Overflow)?;
            let input_len = output_len.checked_mul(2).ok_or(X4cErrorV4::Overflow)?;
            let codeword_byte_len = u64::try_from(output_len)
                .map_err(|_| X4cErrorV4::Overflow)?
                .checked_mul(FP2_BYTES)
                .ok_or(X4cErrorV4::Overflow)?;
            let round = X4cArenaRoundV4 {
                fold_round: u8::try_from(ordinal + 1).map_err(|_| X4cErrorV4::Overflow)?,
                input_len,
                output_len,
                codeword_byte_offset: next_codeword_offset,
                codeword_byte_len,
                retained_outer_levels: Vec::new(),
            };
            next_codeword_offset =
                next_codeword_offset.checked_add(codeword_byte_len).ok_or(X4cErrorV4::Overflow)?;
            rounds.push(round);
        }
        let codeword_bytes = next_codeword_offset;
        let mut next_cache_offset = codeword_bytes;
        for round in &mut rounds {
            let depth = round.output_len.ilog2() as u8;
            for level in 2..=depth {
                let node_count = round.output_len >> level;
                let byte_len = u64::try_from(node_count)
                    .map_err(|_| X4cErrorV4::Overflow)?
                    .checked_mul(DIGEST_BYTES)
                    .ok_or(X4cErrorV4::Overflow)?;
                round.retained_outer_levels.push(X4cArenaLevelV4 {
                    level,
                    node_count,
                    byte_offset: next_cache_offset,
                    byte_len,
                });
                next_cache_offset =
                    next_cache_offset.checked_add(byte_len).ok_or(X4cErrorV4::Overflow)?;
            }
        }
        let outer_cache_bytes =
            next_cache_offset.checked_sub(codeword_bytes).ok_or(X4cErrorV4::Overflow)?;
        let retained_payload_bytes = next_cache_offset;
        let capacity_bytes =
            retained_payload_bytes.checked_add(workspace_bytes).ok_or(X4cErrorV4::Overflow)?;
        let layout = Self {
            max_outer_log2,
            final_outer_log2,
            rounds,
            codeword_bytes,
            outer_cache_bytes,
            retained_payload_bytes,
            workspace_byte_offset: retained_payload_bytes,
            workspace_bytes,
            capacity_bytes,
        };
        layout.validate()?;
        Ok(layout)
    }

    pub fn validate(&self) -> Result<(), X4cErrorV4> {
        if self.rounds.len() != usize::from(self.max_outer_log2 - self.final_outer_log2)
            || self.rounds.is_empty()
            || self.workspace_byte_offset != self.retained_payload_bytes
            || self.capacity_bytes
                != self
                    .retained_payload_bytes
                    .checked_add(self.workspace_bytes)
                    .ok_or(X4cErrorV4::Overflow)?
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c arena header"));
        }
        let mut cursor = 0u64;
        for (ordinal, round) in self.rounds.iter().enumerate() {
            let expected_output_log2 = self
                .max_outer_log2
                .checked_sub(u8::try_from(ordinal + 1).map_err(|_| X4cErrorV4::Overflow)?)
                .ok_or(X4cErrorV4::Overflow)?;
            if round.fold_round as usize != ordinal + 1
                || round.output_len.ilog2() as u8 != expected_output_log2
                || round.input_len != 2 * round.output_len
                || round.codeword_byte_offset != cursor
                || round.codeword_byte_len != round.output_len as u64 * FP2_BYTES
            {
                return Err(X4cErrorV4::InvalidGeometry("X4c arena codeword layout"));
            }
            cursor = cursor.checked_add(round.codeword_byte_len).ok_or(X4cErrorV4::Overflow)?;
        }
        if cursor != self.codeword_bytes {
            return Err(X4cErrorV4::InvalidGeometry("X4c codeword byte total"));
        }
        for round in &self.rounds {
            let depth = round.output_len.ilog2() as u8;
            if round.retained_outer_levels.len() != usize::from(depth.saturating_sub(1)) {
                return Err(X4cErrorV4::InvalidGeometry("X4c retained level count"));
            }
            for (ordinal, level) in round.retained_outer_levels.iter().enumerate() {
                let expected_level = u8::try_from(ordinal + 2).map_err(|_| X4cErrorV4::Overflow)?;
                if level.level != expected_level
                    || level.node_count != round.output_len >> expected_level
                    || level.byte_len != level.node_count as u64 * DIGEST_BYTES
                    || level.byte_offset != cursor
                {
                    return Err(X4cErrorV4::InvalidGeometry("X4c retained level layout"));
                }
                cursor = cursor.checked_add(level.byte_len).ok_or(X4cErrorV4::Overflow)?;
            }
        }
        if cursor != self.retained_payload_bytes
            || self.outer_cache_bytes
                != self
                    .retained_payload_bytes
                    .checked_sub(self.codeword_bytes)
                    .ok_or(X4cErrorV4::Overflow)?
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c retained payload total"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct X4cResponseIoCountersV4 {
    pub response_e_ntt_calls: u64,
    pub response_coefficient_files_created: u64,
    pub response_coefficient_bytes_read: u64,
    pub response_coefficient_bytes_written: u64,
    pub response_oracle_files_created: u64,
    pub response_oracle_bytes_read: u64,
    pub response_oracle_bytes_written: u64,
    pub response_full_oracle_comparison_bytes: u64,
    pub staging_files_created: u64,
    pub staging_bytes_read: u64,
    pub staging_bytes_written: u64,
    pub cpu_fold_tree_clone_bytes: u64,
    pub response_overlay_reread_bytes: u64,
    pub response_fadv_dontneed_calls: u64,
}

impl X4cResponseIoCountersV4 {
    pub fn validate_hard_zero(&self) -> Result<(), X4cErrorV4> {
        if self != &Self::default() {
            return Err(X4cErrorV4::InvalidGeometry("nonzero X4c response staging/I/O"));
        }
        Ok(())
    }
}

/// Exact ownership census for the single response arena.  The physical CUDA
/// allocator may cache the released allocation, but response-round ownership
/// may never fan out into per-round allocations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4cArenaCensusV4 {
    pub arena_capacity_bytes: u64,
    pub arena_committed_bytes: u64,
    pub arena_peak_bytes: u64,
    pub logical_allocation_count: u64,
    pub response_round_allocation_count: u64,
    pub reallocation_count: u64,
    pub logical_deallocation_count: u64,
    pub reset_count: u64,
    pub zeroed_bytes: u64,
    pub outstanding_allocation_count: u64,
    pub outstanding_bytes: u64,
    pub cached_reusable_bytes: u64,
    pub accelerator_available: bool,
    pub backend_workspace_bytes: u64,
    pub backend_baseline_resident_bytes: u64,
    pub backend_resident_bytes: u64,
    pub backend_cached_resident_bytes: u64,
    pub backend_baseline_active_device_allocations: u64,
    pub backend_active_device_allocations: u64,
    pub backend_cached_device_allocations: u64,
    pub backend_baseline_active_pinned_allocations: u64,
    pub backend_baseline_active_pinned_bytes: u64,
    pub backend_active_pinned_allocations: u64,
    pub backend_cached_pinned_allocations: u64,
    pub backend_in_flight_pinned_allocations: u64,
    pub backend_active_pinned_bytes: u64,
    pub backend_cached_pinned_bytes: u64,
    pub backend_outstanding_cuda_operations: u64,
    pub backend_stream_synchronized: bool,
    pub x4c_pinned_pool_allocations: u64,
    pub x4c_pinned_pool_requested_bytes: u64,
    /// Native allocator/reset counters sampled at this exact census boundary.
    /// These duplicate the logical fields deliberately: validation requires
    /// agreement so the census cannot manufacture lifecycle evidence from
    /// layout constants.
    pub native_live_device_bytes: u64,
    pub native_peak_device_bytes: u64,
    pub native_resident_alloc_requests: u64,
    pub native_resident_reuse_hits: u64,
    pub native_resident_free_requests: u64,
    pub native_arena_reset_calls: u64,
    pub native_arena_reset_bytes: u64,
    pub native_device_zeroed_bytes: u64,
}

impl X4cArenaCensusV4 {
    pub fn validate_proof_ready(&self, layout: &X4cArenaLayoutV4) -> Result<(), X4cErrorV4> {
        layout.validate()?;
        if self.arena_capacity_bytes != layout.capacity_bytes
            || self.arena_committed_bytes < layout.retained_payload_bytes
            || self.arena_committed_bytes > self.arena_capacity_bytes
            || self.arena_peak_bytes < self.arena_committed_bytes
            || self.logical_allocation_count != 1
            || self.response_round_allocation_count != 0
            || self.reallocation_count != 0
            || self.logical_deallocation_count != 0
            || self.reset_count != 0
            || self.outstanding_allocation_count != 1
            || self.outstanding_bytes != self.arena_capacity_bytes
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c proof-ready arena census"));
        }
        if self.accelerator_available
            && (self.arena_committed_bytes != self.outstanding_bytes
                || self.arena_peak_bytes != self.native_peak_device_bytes
                || self.logical_allocation_count != self.native_resident_alloc_requests
                || self.logical_deallocation_count != self.native_resident_free_requests
                || self.reset_count != self.native_arena_reset_calls
                || self.zeroed_bytes != self.native_device_zeroed_bytes
                || self.native_arena_reset_bytes != 0
                || self.backend_resident_bytes
                    < self
                        .backend_baseline_resident_bytes
                        .checked_add(layout.capacity_bytes)
                        .ok_or(X4cErrorV4::Overflow)?
                || self.backend_active_device_allocations
                    != self
                        .backend_baseline_active_device_allocations
                        .checked_add(1)
                        .ok_or(X4cErrorV4::Overflow)?
                || self.backend_active_pinned_allocations
                    != self
                        .backend_baseline_active_pinned_allocations
                        .checked_add(self.x4c_pinned_pool_allocations)
                        .ok_or(X4cErrorV4::Overflow)?
                || self.backend_active_pinned_bytes
                    < self
                        .backend_baseline_active_pinned_bytes
                        .checked_add(self.x4c_pinned_pool_requested_bytes)
                        .ok_or(X4cErrorV4::Overflow)?
                || self.x4c_pinned_pool_allocations
                    != u64::try_from(X4C_PINNED_TRANSFER_RING_V4 + 2)
                        .map_err(|_| X4cErrorV4::Overflow)?
                || self.x4c_pinned_pool_requested_bytes != x4c_pinned_pool_requested_bytes_v4()?
                || self.backend_in_flight_pinned_allocations != 0
                || self.backend_outstanding_cuda_operations != 0
                || !self.backend_stream_synchronized)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c proof-ready accelerator census"));
        }
        Ok(())
    }

    pub fn validate_session_reusable(
        &self,
        proof_ready: &Self,
        layout: &X4cArenaLayoutV4,
    ) -> Result<(), X4cErrorV4> {
        proof_ready.validate_proof_ready(layout)?;
        if self.arena_capacity_bytes != proof_ready.arena_capacity_bytes
            || self.arena_committed_bytes != proof_ready.arena_committed_bytes
            || self.arena_peak_bytes < proof_ready.arena_peak_bytes
            || self.logical_allocation_count != proof_ready.logical_allocation_count
            || self.response_round_allocation_count != 0
            || self.reallocation_count != 0
            || self.logical_deallocation_count != 1
            || self.reset_count != 1
            || self.zeroed_bytes != layout.capacity_bytes
            || self.outstanding_allocation_count != 0
            || self.outstanding_bytes != 0
            || self.cached_reusable_bytes < layout.capacity_bytes
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c reusable arena census"));
        }
        if self.accelerator_available
            && (self.cached_reusable_bytes < self.arena_committed_bytes
                || self.arena_peak_bytes != self.native_peak_device_bytes
                || self.logical_allocation_count != self.native_resident_alloc_requests
                || self.logical_deallocation_count != self.native_resident_free_requests
                || self.reset_count != self.native_arena_reset_calls
                || self.zeroed_bytes != self.native_device_zeroed_bytes
                || self.native_arena_reset_bytes != layout.capacity_bytes
                || !proof_ready.accelerator_available
                || self.backend_baseline_resident_bytes
                    != proof_ready.backend_baseline_resident_bytes
                || self.backend_resident_bytes != self.backend_baseline_resident_bytes
                || self.backend_cached_resident_bytes
                    < proof_ready
                        .backend_cached_resident_bytes
                        .checked_add(layout.capacity_bytes)
                        .ok_or(X4cErrorV4::Overflow)?
                || self.backend_baseline_active_device_allocations
                    != proof_ready.backend_baseline_active_device_allocations
                || self.backend_active_device_allocations
                    != self.backend_baseline_active_device_allocations
                || self.backend_cached_device_allocations == 0
                || self.backend_baseline_active_pinned_allocations
                    != proof_ready.backend_baseline_active_pinned_allocations
                || self.backend_baseline_active_pinned_bytes
                    != proof_ready.backend_baseline_active_pinned_bytes
                || self.backend_active_pinned_allocations
                    != proof_ready.backend_active_pinned_allocations
                || self.backend_in_flight_pinned_allocations != 0
                || self.backend_active_pinned_bytes != proof_ready.backend_active_pinned_bytes
                || self.x4c_pinned_pool_allocations != proof_ready.x4c_pinned_pool_allocations
                || self.x4c_pinned_pool_requested_bytes
                    != proof_ready.x4c_pinned_pool_requested_bytes
                || self.backend_outstanding_cuda_operations != 0
                || !self.backend_stream_synchronized)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c reusable accelerator census"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4cLifecycleWallsV4 {
    pub proof_ready_wall_ns: u64,
    pub session_reusable_wall_ns: u64,
}

impl X4cLifecycleWallsV4 {
    pub fn validate(&self) -> Result<(), X4cErrorV4> {
        if self.proof_ready_wall_ns == 0
            || self.session_reusable_wall_ns == 0
            || self.session_reusable_wall_ns < self.proof_ready_wall_ns
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c lifecycle walls"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X4cResponseExecutionCountersV4 {
    pub direct_fold_calls: u64,
    pub direct_fold_sample_comparisons: u64,
    pub direct_fold_sample_mismatches: u64,
    /// Diagnostic traffic only; it is not an opening, transcript message or
    /// soundness contribution.
    pub direct_fold_diagnostic_gather_calls: u64,
    pub direct_fold_diagnostic_index_h2d_bytes: u64,
    pub direct_fold_diagnostic_value_d2h_bytes: u64,
    pub n4_tree_calls: u64,
    pub query_gather_calls: u64,
    pub query_gather_operation_count: u64,
    pub query_gather_operation_h2d_bytes: u64,
    pub canonical_template_h2d_bytes: u64,
    pub query_draw_count: u64,
    pub canonical_opening_d2h_bytes: u64,
    pub noncanonical_opening_d2h_bytes: u64,
    pub cpu_fold_tree_clone_bytes: u64,
}

impl X4cResponseExecutionCountersV4 {
    pub fn validate_production(&self) -> Result<(), X4cErrorV4> {
        if self.direct_fold_calls != X4C_PRODUCTION_FOLD_ROUNDS_V4 as u64
            || self.direct_fold_sample_comparisons != X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 as u64
            || self.direct_fold_sample_mismatches != 0
            || self.direct_fold_diagnostic_gather_calls
                != X4C_DIRECT_FOLD_DIAGNOSTIC_GATHER_CALLS_V4
            || self.direct_fold_diagnostic_index_h2d_bytes
                != X4C_DIRECT_FOLD_DIAGNOSTIC_INDEX_H2D_BYTES_V4
            || self.direct_fold_diagnostic_value_d2h_bytes
                != X4C_DIRECT_FOLD_DIAGNOSTIC_VALUE_D2H_BYTES_V4
            || self.n4_tree_calls != X4C_PRODUCTION_FOLD_ROUNDS_V4 as u64
            || self.query_gather_calls != 1
            || self.query_gather_operation_count == 0
            || self.query_gather_operation_h2d_bytes
                != self
                    .query_gather_operation_count
                    .checked_mul(size_of::<X4cCanonicalGatherOperation>() as u64)
                    .ok_or(X4cErrorV4::Overflow)?
            || self.canonical_template_h2d_bytes != X4C_PACKED_OPENING_BYTES_V4
            || self.query_draw_count != X4C_QUERY_COUNT_V4 as u64
            || self.canonical_opening_d2h_bytes != X4C_PACKED_OPENING_BYTES_V4
            || self.noncanonical_opening_d2h_bytes != 0
            || self.cpu_fold_tree_clone_bytes != 0
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c production execution counters"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X4cFoldGatherMetadataV4 {
    pub cohort_id: u32,
    pub fold_round: u8,
    pub domain_log2: u8,
    pub descriptor_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum X4cGatherSourceV4 {
    CodewordSymbol { round_ordinal: usize, index: u64, source_byte_offset: u64 },
    CachedOuterDigest { round_ordinal: usize, level: u8, index: u64, source_byte_offset: u64 },
    RebuiltOuterDigest { round_ordinal: usize, level: u8, index: u64 },
}

impl X4cGatherSourceV4 {
    pub fn byte_len(&self) -> u64 {
        match self {
            Self::CodewordSymbol { .. } => FP2_BYTES,
            Self::CachedOuterDigest { .. } | Self::RebuiltOuterDigest { .. } => DIGEST_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cCanonicalGatherOperationV4 {
    pub source: X4cGatherSourceV4,
    pub destination_byte_offset: u64,
}

/// Device mailbox plan for all response fold openings.  `canonical_template`
/// is already a complete schema-4 frame: the initial host-RAM openings and
/// all metadata are final, while fold payload slots are zero until the single
/// batched gather fills them in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cCanonicalGatherPlanV4 {
    pub canonical_template: Vec<u8>,
    pub round_metadata: Vec<X4cFoldGatherMetadataV4>,
    pub operations: Vec<X4cCanonicalGatherOperationV4>,
    pub opened_fold_symbol_count: u64,
    pub fold_sibling_digest_count: u64,
}

impl X4cCanonicalGatherPlanV4 {
    pub fn build(
        schedule: &PackedOpeningScheduleV4,
        initial_groups: Vec<InitialOpeningGroupV4>,
        global_descriptor_digest: Digest,
        layout: &X4cArenaLayoutV4,
    ) -> Result<Self, X4cErrorV4> {
        schedule.validate()?;
        layout.validate()?;
        if global_descriptor_digest == [0; 32]
            || schedule.fold_frames.len() != layout.rounds.len()
            || schedule.fold_frames.len()
                != layout.max_outer_log2 as usize - layout.final_outer_log2 as usize
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c gather schedule/layout"));
        }

        let mut fold_rounds = Vec::with_capacity(schedule.fold_frames.len());
        for frame in &schedule.fold_frames {
            let indices = projected_query_indices(&schedule.query_draws, frame.output_log2)
                .map_err(|_| X4cErrorV4::InvalidGeometry("X4c gather projected indices"))?;
            let sibling_count = merkle_aux_node_count(frame.output_log2, &indices)
                .map_err(|_| X4cErrorV4::InvalidGeometry("X4c gather frontier"))?;
            fold_rounds.push(FoldRoundOpeningV4 {
                fold_round: frame.fold_round,
                domain_log2: frame.output_log2,
                opened_symbols: vec![Fp2::ZERO; indices.len()],
                outer_sibling_digests: vec![
                    [0; 32];
                    usize::try_from(sibling_count)
                        .map_err(|_| X4cErrorV4::Overflow)?
                ],
            });
        }
        let packed = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: opening_schedule_digest_v4(schedule)?,
            initial_groups,
            fold_rounds,
        };
        packed.validate_against_schedule(schedule)?;
        let canonical_template = FrameV4::PackedBatchOpening(packed.clone()).encode()?;

        let mut cursor = canonical_initial_prefix_bytes_v4(&packed)?;
        let mut operations = Vec::new();
        let mut round_metadata = Vec::with_capacity(layout.rounds.len());
        let mut opened_fold_symbol_count = 0u64;
        let mut fold_sibling_digest_count = 0u64;
        for (round_ordinal, ((frame, opening), round_layout)) in
            schedule.fold_frames.iter().zip(&packed.fold_rounds).zip(&layout.rounds).enumerate()
        {
            if frame.oracle_kind != OracleKindV4::GlobalFoldAggregate
                || frame.fold_round != round_layout.fold_round
                || frame.output_log2 != round_layout.output_len.ilog2() as u8
            {
                return Err(X4cErrorV4::InvalidGeometry("X4c gather round identity"));
            }
            round_metadata.push(X4cFoldGatherMetadataV4 {
                cohort_id: frame.cohort_id,
                fold_round: frame.fold_round,
                domain_log2: frame.output_log2,
                descriptor_digest: global_descriptor_digest,
            });

            // fold_round, domain_log2, symbol_count
            cursor = checked_add_usize(cursor, 1 + 1 + 4)?;
            let indices = projected_query_indices(&schedule.query_draws, frame.output_log2)
                .map_err(|_| X4cErrorV4::InvalidGeometry("X4c gather projected indices"))?;
            if indices.len() != opening.opened_symbols.len() {
                return Err(X4cErrorV4::InvalidGeometry("X4c gather symbol count"));
            }
            for index in &indices {
                let source_byte_offset = round_layout
                    .codeword_byte_offset
                    .checked_add(index.checked_mul(FP2_BYTES).ok_or(X4cErrorV4::Overflow)?)
                    .ok_or(X4cErrorV4::Overflow)?;
                operations.push(X4cCanonicalGatherOperationV4 {
                    source: X4cGatherSourceV4::CodewordSymbol {
                        round_ordinal,
                        index: *index,
                        source_byte_offset,
                    },
                    destination_byte_offset: u64::try_from(cursor)
                        .map_err(|_| X4cErrorV4::Overflow)?,
                });
                cursor = checked_add_usize(cursor, FP2_BYTES as usize)?;
            }
            opened_fold_symbol_count = opened_fold_symbol_count
                .checked_add(u64::try_from(indices.len()).map_err(|_| X4cErrorV4::Overflow)?)
                .ok_or(X4cErrorV4::Overflow)?;

            // sibling_count
            cursor = checked_add_usize(cursor, 4)?;
            let frontier = canonical_outer_frontier_positions_v4(frame.output_log2, &indices)?;
            if frontier.len() != opening.outer_sibling_digests.len() {
                return Err(X4cErrorV4::InvalidGeometry("X4c gather sibling count"));
            }
            for (level, index) in frontier {
                let source = if level <= 1 {
                    X4cGatherSourceV4::RebuiltOuterDigest { round_ordinal, level, index }
                } else {
                    let retained = round_layout
                        .retained_outer_levels
                        .iter()
                        .find(|candidate| candidate.level == level)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather retained level"))?;
                    if index >= retained.node_count as u64 {
                        return Err(X4cErrorV4::InvalidGeometry(
                            "X4c gather retained digest index",
                        ));
                    }
                    X4cGatherSourceV4::CachedOuterDigest {
                        round_ordinal,
                        level,
                        index,
                        source_byte_offset: retained
                            .byte_offset
                            .checked_add(
                                index.checked_mul(DIGEST_BYTES).ok_or(X4cErrorV4::Overflow)?,
                            )
                            .ok_or(X4cErrorV4::Overflow)?,
                    }
                };
                operations.push(X4cCanonicalGatherOperationV4 {
                    source,
                    destination_byte_offset: u64::try_from(cursor)
                        .map_err(|_| X4cErrorV4::Overflow)?,
                });
                cursor = checked_add_usize(cursor, DIGEST_BYTES as usize)?;
            }
            fold_sibling_digest_count = fold_sibling_digest_count
                .checked_add(
                    u64::try_from(opening.outer_sibling_digests.len())
                        .map_err(|_| X4cErrorV4::Overflow)?,
                )
                .ok_or(X4cErrorV4::Overflow)?;
        }
        if cursor != canonical_template.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c gather canonical cursor"));
        }
        let plan = Self {
            canonical_template,
            round_metadata,
            operations,
            opened_fold_symbol_count,
            fold_sibling_digest_count,
        };
        plan.validate(layout)?;
        Ok(plan)
    }

    pub fn validate(&self, layout: &X4cArenaLayoutV4) -> Result<(), X4cErrorV4> {
        layout.validate()?;
        if self.round_metadata.len() != layout.rounds.len()
            || self.canonical_template.is_empty()
            || self.operations.is_empty()
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c gather plan header"));
        }
        let mut destinations = BTreeSet::new();
        let mut symbol_count = 0u64;
        let mut digest_count = 0u64;
        for operation in &self.operations {
            let byte_len = operation.source.byte_len();
            let end = operation
                .destination_byte_offset
                .checked_add(byte_len)
                .ok_or(X4cErrorV4::Overflow)?;
            if end > self.canonical_template.len() as u64
                || !destinations.insert((operation.destination_byte_offset, end))
            {
                return Err(X4cErrorV4::InvalidGeometry("X4c gather destination"));
            }
            match &operation.source {
                X4cGatherSourceV4::CodewordSymbol { round_ordinal, index, source_byte_offset } => {
                    let round = layout
                        .rounds
                        .get(*round_ordinal)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather round"))?;
                    if *index >= round.output_len as u64
                        || *source_byte_offset < round.codeword_byte_offset
                        || source_byte_offset.checked_add(FP2_BYTES).ok_or(X4cErrorV4::Overflow)?
                            > round
                                .codeword_byte_offset
                                .checked_add(round.codeword_byte_len)
                                .ok_or(X4cErrorV4::Overflow)?
                    {
                        return Err(X4cErrorV4::InvalidGeometry("X4c gather codeword source"));
                    }
                    symbol_count = symbol_count.checked_add(1).ok_or(X4cErrorV4::Overflow)?;
                }
                X4cGatherSourceV4::CachedOuterDigest {
                    round_ordinal,
                    level,
                    index,
                    source_byte_offset,
                } => {
                    let round = layout
                        .rounds
                        .get(*round_ordinal)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather round"))?;
                    let retained = round
                        .retained_outer_levels
                        .iter()
                        .find(|candidate| candidate.level == *level)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather cached level"))?;
                    if *index >= retained.node_count as u64
                        || *source_byte_offset < retained.byte_offset
                        || source_byte_offset
                            .checked_add(DIGEST_BYTES)
                            .ok_or(X4cErrorV4::Overflow)?
                            > retained
                                .byte_offset
                                .checked_add(retained.byte_len)
                                .ok_or(X4cErrorV4::Overflow)?
                    {
                        return Err(X4cErrorV4::InvalidGeometry("X4c gather cached source"));
                    }
                    digest_count = digest_count.checked_add(1).ok_or(X4cErrorV4::Overflow)?;
                }
                X4cGatherSourceV4::RebuiltOuterDigest { round_ordinal, level, index } => {
                    let round = layout
                        .rounds
                        .get(*round_ordinal)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather round"))?;
                    if *level > 1 || *index >= (round.output_len >> *level) as u64 {
                        return Err(X4cErrorV4::InvalidGeometry("X4c gather rebuild source"));
                    }
                    digest_count = digest_count.checked_add(1).ok_or(X4cErrorV4::Overflow)?;
                }
            }
        }
        let mut ordered = self
            .operations
            .iter()
            .map(|operation| {
                (
                    operation.destination_byte_offset,
                    operation.destination_byte_offset + operation.source.byte_len(),
                )
            })
            .collect::<Vec<_>>();
        ordered.sort_unstable();
        if ordered.windows(2).any(|pair| pair[0].1 > pair[1].0)
            || symbol_count != self.opened_fold_symbol_count
            || digest_count != self.fold_sibling_digest_count
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c gather payload census"));
        }
        match decode_v4(&self.canonical_template)? {
            FrameV4::PackedBatchOpening(_) => Ok(()),
            _ => Err(X4cErrorV4::InvalidGeometry("X4c gather canonical frame")),
        }
    }
}

fn checked_add_usize(left: usize, right: usize) -> Result<usize, X4cErrorV4> {
    left.checked_add(right).ok_or(X4cErrorV4::Overflow)
}

fn canonical_initial_prefix_bytes_v4(
    opening: &PackedBatchOpeningFrameV4,
) -> Result<usize, X4cErrorV4> {
    // schema header, schedule digest and initial-group count
    let mut bytes = 16usize + 32 + 2;
    for group in &opening.initial_groups {
        bytes = checked_add_usize(bytes, 4 + 1 + 2 + 2)?;
        bytes = checked_add_usize(
            bytes,
            group.touched_slots.len().checked_mul(2).ok_or(X4cErrorV4::Overflow)?,
        )?;
        bytes = checked_add_usize(bytes, 4)?;
        bytes = checked_add_usize(
            bytes,
            group
                .opened_symbols
                .len()
                .checked_mul(FP2_BYTES as usize)
                .ok_or(X4cErrorV4::Overflow)?,
        )?;
        bytes = checked_add_usize(bytes, 4)?;
        bytes = checked_add_usize(
            bytes,
            group
                .inner_sibling_digests
                .len()
                .checked_mul(DIGEST_BYTES as usize)
                .ok_or(X4cErrorV4::Overflow)?,
        )?;
        bytes = checked_add_usize(bytes, 4)?;
        bytes = checked_add_usize(
            bytes,
            group
                .outer_sibling_digests
                .len()
                .checked_mul(DIGEST_BYTES as usize)
                .ok_or(X4cErrorV4::Overflow)?,
        )?;
    }
    // fold-round count
    checked_add_usize(bytes, 1)
}

fn canonical_outer_frontier_positions_v4(
    depth: u8,
    opened_indices: &[u64],
) -> Result<Vec<(u8, u64)>, X4cErrorV4> {
    if opened_indices.is_empty()
        || !opened_indices.windows(2).all(|pair| pair[0] < pair[1])
        || opened_indices
            .iter()
            .any(|index| *index >= 1u64.checked_shl(u32::from(depth)).unwrap_or(0))
    {
        return Err(X4cErrorV4::InvalidGeometry("X4c frontier indices"));
    }
    let mut current = opened_indices.iter().copied().collect::<BTreeSet<_>>();
    let mut output = Vec::new();
    for level in 0..depth {
        let mut next = BTreeSet::new();
        for index in &current {
            let sibling = *index ^ 1;
            if !current.contains(&sibling) {
                output.push((level, sibling));
            }
            next.insert(*index / 2);
        }
        current = next;
    }
    Ok(output)
}

#[derive(Debug)]
pub struct X4cCpuGatherRoundSourceV4<'a> {
    pub codeword: &'a [Fp2],
    pub outer_cache: &'a dyn OuterNodeSourceV4,
}

/// CPU materialization of the device mailbox plan.  This is the permanent
/// byte-identity oracle for the GPU gather and is not the production path.
pub fn materialize_x4c_gather_plan_cpu_v4(
    plan: &X4cCanonicalGatherPlanV4,
    layout: &X4cArenaLayoutV4,
    sources: &[X4cCpuGatherRoundSourceV4<'_>],
) -> Result<Vec<u8>, X4cErrorV4> {
    plan.validate(layout)?;
    if sources.len() != layout.rounds.len() {
        return Err(X4cErrorV4::InvalidGeometry("X4c CPU gather sources"));
    }
    let mut output = plan.canonical_template.clone();
    let mut memo = BTreeMap::<(usize, u8, u64), Digest>::new();
    for operation in &plan.operations {
        let destination =
            usize::try_from(operation.destination_byte_offset).map_err(|_| X4cErrorV4::Overflow)?;
        match operation.source {
            X4cGatherSourceV4::CodewordSymbol { round_ordinal, index, .. } => {
                let symbol = *sources
                    .get(round_ordinal)
                    .and_then(|source| source.codeword.get(index as usize))
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU gather symbol"))?;
                output[destination..destination + 8]
                    .copy_from_slice(&symbol.c0.value().to_le_bytes());
                output[destination + 8..destination + 16]
                    .copy_from_slice(&symbol.c1.value().to_le_bytes());
            }
            X4cGatherSourceV4::CachedOuterDigest { round_ordinal, level, index, .. } => {
                let digest = sources
                    .get(round_ordinal)
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU gather cached source"))?
                    .outer_cache
                    .read_cached_digest(level, index)
                    .map_err(|_| X4cErrorV4::InvalidGeometry("X4c CPU gather cached digest"))?;
                output[destination..destination + DIGEST_BYTES as usize].copy_from_slice(&digest);
            }
            X4cGatherSourceV4::RebuiltOuterDigest { round_ordinal, level, index } => {
                let digest = rebuilt_outer_digest_cpu_v4(
                    round_ordinal,
                    level,
                    index,
                    plan,
                    sources,
                    &mut memo,
                )?;
                output[destination..destination + DIGEST_BYTES as usize].copy_from_slice(&digest);
            }
        }
    }
    Ok(output)
}

fn rebuilt_outer_digest_cpu_v4(
    round_ordinal: usize,
    level: u8,
    index: u64,
    plan: &X4cCanonicalGatherPlanV4,
    sources: &[X4cCpuGatherRoundSourceV4<'_>],
    memo: &mut BTreeMap<(usize, u8, u64), Digest>,
) -> Result<Digest, X4cErrorV4> {
    if let Some(digest) = memo.get(&(round_ordinal, level, index)) {
        return Ok(*digest);
    }
    let metadata = plan
        .round_metadata
        .get(round_ordinal)
        .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU gather metadata"))?;
    let source =
        sources.get(round_ordinal).ok_or(X4cErrorV4::InvalidGeometry("X4c CPU gather source"))?;
    let digest = if level == 0 {
        let symbol = *source
            .codeword
            .get(usize::try_from(index).map_err(|_| X4cErrorV4::Overflow)?)
            .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU gather leaf"))?;
        let inner = hash_pcs_inner_leaf_fields_v4(
            metadata.cohort_id,
            OracleKindV4::GlobalFoldAggregate,
            metadata.fold_round,
            index,
            metadata.descriptor_digest,
            0,
            Some(symbol),
        )?;
        hash_pcs_outer_leaf_fields_v4(
            metadata.cohort_id,
            OracleKindV4::GlobalFoldAggregate,
            metadata.fold_round,
            index,
            inner,
        )?
    } else if level == 1 {
        let left_index = index.checked_mul(2).ok_or(X4cErrorV4::Overflow)?;
        let left = rebuilt_outer_digest_cpu_v4(round_ordinal, 0, left_index, plan, sources, memo)?;
        let right =
            rebuilt_outer_digest_cpu_v4(round_ordinal, 0, left_index + 1, plan, sources, memo)?;
        hash_pcs_node_fields_v4(
            metadata.cohort_id,
            TreeRole::Outer,
            OracleKindV4::GlobalFoldAggregate,
            metadata.fold_round,
            u64::MAX,
            1,
            index,
            left,
            right,
        )?
    } else {
        return Err(X4cErrorV4::InvalidGeometry("X4c CPU gather rebuild level"));
    };
    memo.insert((round_ordinal, level, index), digest);
    Ok(digest)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cDirectFoldSamplePlanV4 {
    pub design_sha256: Digest,
    pub clean_source_sha256: Digest,
    pub response_ordinal: u64,
    pub fold_round: u8,
    pub output_len: usize,
    pub indices: Vec<u64>,
    pub ordered_indices_digest: Digest,
}

impl X4cDirectFoldSamplePlanV4 {
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        design_sha256: Digest,
        source_sha256: Digest,
        response_ordinal: u64,
        fold_round: u8,
        challenge: Fp2,
        root: Digest,
        output_len: usize,
    ) -> Result<Self, X4cErrorV4> {
        if design_sha256 == [0; 32]
            || source_sha256 == [0; 32]
            || root == [0; 32]
            || fold_round == 0
            || output_len < 2
            || !output_len.is_power_of_two()
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold sample geometry"));
        }
        let target = X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4.min(output_len);
        let mut indices = Vec::with_capacity(target);
        let mut seen = BTreeSet::new();
        for fixed in [0u64, output_len as u64 - 1] {
            if indices.len() < target && seen.insert(fixed) {
                indices.push(fixed);
            }
        }
        let mut hasher = blake3::Hasher::new_derive_key(X4C_DIRECT_FOLD_PARITY_DOMAIN_V4);
        hasher.update(&design_sha256);
        hasher.update(&source_sha256);
        hasher.update(&response_ordinal.to_le_bytes());
        hasher.update(&[fold_round]);
        hasher.update(&challenge.c0.value().to_le_bytes());
        hasher.update(&challenge.c1.value().to_le_bytes());
        hasher.update(&root);
        let mut reader = hasher.finalize_xof();
        let mask = output_len as u64 - 1;
        while indices.len() < target {
            let mut bytes = [0u8; 8];
            reader.fill(&mut bytes);
            let candidate = u64::from_le_bytes(bytes) & mask;
            if seen.insert(candidate) {
                indices.push(candidate);
            }
        }
        let mut digest =
            blake3::Hasher::new_derive_key("volta-zk/x4c/direct-fold-parity-indices/v1");
        for index in &indices {
            digest.update(&index.to_le_bytes());
        }
        Ok(Self {
            design_sha256,
            clean_source_sha256: source_sha256,
            response_ordinal,
            fold_round,
            output_len,
            indices,
            ordered_indices_digest: *digest.finalize().as_bytes(),
        })
    }
}

/// Evaluate selected outputs of the frozen direct-fold equation without
/// constructing a full second result vector.
pub fn direct_fold_selected_v4(
    input: &[Fp2],
    challenge: Fp2,
    indices: &[u64],
) -> Result<Vec<Fp2>, X4cErrorV4> {
    if input.len() < 2 || !input.len().is_power_of_two() {
        return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold input"));
    }
    let half = input.len() / 2;
    if indices.iter().any(|index| *index >= half as u64) {
        return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold sample index"));
    }
    let omega_inverse =
        root_of_unity(input.len().ilog2()).map_err(|_| X4cErrorV4::InvalidGeometry("root"))?.inv();
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    indices
        .iter()
        .map(|index| {
            let index = usize::try_from(*index).map_err(|_| X4cErrorV4::Overflow)?;
            let positive = input[index];
            let negative = input[index + half];
            let even = (positive + negative) * inverse_two;
            let inverse_x = fp2_pow(omega_inverse, index as u128);
            let odd = (positive - negative) * inverse_two * inverse_x;
            Ok(even + challenge * odd)
        })
        .collect()
}

/// Evaluate selected direct-fold outputs from already gathered positive and
/// negative input pairs. Production uses this bounded CPU diagnostic after
/// the resident fold; it never materializes a response-round CPU codeword.
pub fn direct_fold_selected_pairs_v4(
    input_len: usize,
    challenge: Fp2,
    indices: &[u64],
    positive: &[Fp2],
    negative: &[Fp2],
) -> Result<Vec<Fp2>, X4cErrorV4> {
    if input_len < 2
        || !input_len.is_power_of_two()
        || positive.len() != indices.len()
        || negative.len() != indices.len()
    {
        return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold sampled pair geometry"));
    }
    let half = input_len / 2;
    if indices.iter().any(|index| *index >= half as u64) {
        return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold sampled pair index"));
    }
    let omega_inverse =
        root_of_unity(input_len.ilog2()).map_err(|_| X4cErrorV4::InvalidGeometry("root"))?.inv();
    let inverse_two = Fp2::from_base(Fp::new(2).inv());
    indices
        .iter()
        .zip(positive)
        .zip(negative)
        .map(|((index, positive), negative)| {
            let index = usize::try_from(*index).map_err(|_| X4cErrorV4::Overflow)?;
            let even = (*positive + *negative) * inverse_two;
            let inverse_x = fp2_pow(omega_inverse, index as u128);
            let odd = (*positive - *negative) * inverse_two * inverse_x;
            Ok(even + challenge * odd)
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cDirectFoldParityResultV4 {
    pub comparison_count: u64,
    pub mismatch_count: u64,
    pub ordered_indices_digest: Digest,
}

pub fn compare_direct_fold_samples_v4(
    plan: &X4cDirectFoldSamplePlanV4,
    input: &[Fp2],
    challenge: Fp2,
    observed: &[Fp2],
) -> Result<X4cDirectFoldParityResultV4, X4cErrorV4> {
    if observed.len() != plan.indices.len() {
        return Err(X4cErrorV4::InvalidGeometry("X4c parity observation count"));
    }
    let expected = direct_fold_selected_v4(input, challenge, &plan.indices)?;
    let mismatch_count = expected.iter().zip(observed).filter(|(a, b)| a != b).count() as u64;
    Ok(X4cDirectFoldParityResultV4 {
        comparison_count: observed.len() as u64,
        mismatch_count,
        ordered_indices_digest: plan.ordered_indices_digest,
    })
}

/// Runtime seam for the one-allocation response path. The CUDA implementation
/// is the production implementation. The CPU implementation is a local
/// differential oracle only: at round zero it compares CUDA output with the
/// host input, while at later rounds both sampled inputs and outputs originate
/// from the same resident device chain. It is not an independent track-to-track
/// binding and receives zero soundness credit.
pub trait X4cArenaRuntimeV4 {
    type Arena;

    fn allocate_arena(&mut self, layout: &X4cArenaLayoutV4) -> Result<Self::Arena, X4cErrorV4>;

    fn direct_fold_host(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        input: &[Fp2],
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4>;

    fn direct_fold_resident(
        &mut self,
        arena: &mut Self::Arena,
        previous: &X4cArenaRoundV4,
        round: &X4cArenaRoundV4,
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4>;

    fn add_activation(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        codeword: &[Fp2],
        activation: Fp2,
    ) -> Result<(), X4cErrorV4>;

    fn build_one_slot_n4(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        descriptor: Digest,
        cohort_id: u32,
    ) -> Result<Digest, X4cErrorV4>;

    fn gather_samples(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        indices: &[u64],
    ) -> Result<Vec<Fp2>, X4cErrorV4>;

    fn gather_canonical_opening(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
        plan: &X4cCanonicalGatherPlanV4,
    ) -> Result<Vec<u8>, X4cErrorV4>;

    fn proof_ready_census(
        &mut self,
        arena: &Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4>;

    fn reset_arena(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<(), X4cErrorV4>;

    fn release_arena(
        &mut self,
        arena: Self::Arena,
        layout: &X4cArenaLayoutV4,
        proof_ready: &X4cArenaCensusV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cSealConfigV4 {
    pub design_sha256: Digest,
    pub clean_source_sha256: Digest,
    pub response_ordinal: u64,
    pub arena_layout: X4cArenaLayoutV4,
}

impl X4cSealConfigV4 {
    pub fn production(
        clean_source_sha256: Digest,
        response_ordinal: u64,
    ) -> Result<Self, X4cErrorV4> {
        if clean_source_sha256 == [0; 32] {
            return Err(X4cErrorV4::InvalidGeometry("X4c clean source SHA"));
        }
        let config = Self {
            design_sha256: X4C_DESIGN_SHA256_V4,
            clean_source_sha256,
            response_ordinal,
            arena_layout: X4cArenaLayoutV4::production()?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), X4cErrorV4> {
        self.arena_layout.validate()?;
        if self.design_sha256 != X4C_DESIGN_SHA256_V4
            || self.clean_source_sha256 == [0; 32]
            || self.arena_layout.rounds.len()
                != usize::from(
                    self.arena_layout.max_outer_log2 - self.arena_layout.final_outer_log2,
                )
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c seal configuration"));
        }
        if self.arena_layout.max_outer_log2 == X4C_PRODUCTION_MAX_OUTER_LOG2_V4
            && self.arena_layout.final_outer_log2 == X4C_PRODUCTION_FINAL_OUTER_LOG2_V4
        {
            validate_production_sample_geometry_v4(&self.arena_layout)?;
        }
        Ok(())
    }
}

fn validate_production_sample_geometry_v4(layout: &X4cArenaLayoutV4) -> Result<(), X4cErrorV4> {
    let available = layout.rounds.iter().try_fold(0usize, |total, round| {
        total
            .checked_add(round.output_len.min(X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4))
            .ok_or(X4cErrorV4::Overflow)
    })?;
    if available != X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4 {
        return Err(X4cErrorV4::InvalidGeometry(
            "X4c production direct-fold diagnostic sample geometry",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cRoundParityRecordV4 {
    pub fold_round: u8,
    pub challenge: Fp2,
    pub root: Digest,
    pub plan: X4cDirectFoldSamplePlanV4,
    pub result: X4cDirectFoldParityResultV4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X4cResponseMetricsV4 {
    pub io: X4cResponseIoCountersV4,
    pub execution: X4cResponseExecutionCountersV4,
    pub parity: Vec<X4cRoundParityRecordV4>,
    pub proof_ready_arena: X4cArenaCensusV4,
    pub session_reusable_arena: X4cArenaCensusV4,
    pub lifecycle_walls: X4cLifecycleWallsV4,
    pub global_open: GlobalOpenMetricsV4,
    /// The parity sample is a differential engineering check only.
    pub sampling_soundness_credit_bits: u64,
}

pub struct SealedGlobalChainX4cV4<'a, A> {
    model_root: Digest,
    epoch: u64,
    global_descriptor_digest: Digest,
    common_point: Vec<Fp2>,
    groups: Vec<GlobalProverGroupV4<'a>>,
    verifier_groups: Vec<GlobalVerifierGroupV4>,
    challenges: GlobalFoldChallengesV4,
    fold_frames: Vec<FoldCommitmentFrameV4>,
    arena: A,
    config: X4cSealConfigV4,
    parity: Vec<X4cRoundParityRecordV4>,
    metrics: GlobalOpenMetricsV4,
    lifecycle_started: Instant,
}

impl<'a> GlobalChainDraftV4<'a> {
    /// Seal every root into a single response arena. Exact-bit query draws are
    /// deliberately unavailable until the returned sealed type is consumed.
    pub fn seal_interactive_x4c<R: X4cArenaRuntimeV4>(
        self,
        tx: &mut Transcript,
        runtime: &mut R,
        config: X4cSealConfigV4,
    ) -> Result<SealedGlobalChainX4cV4<'a, R::Arena>, X4cErrorV4> {
        config.validate()?;
        let parts = self.into_x4c_parts();
        if parts.fixed_challenges.is_some()
            || parts.common_point.len() != config.arena_layout.rounds.len()
            || parts.groups[0].cohort.commitment().config.outer_depth()
                != config.arena_layout.max_outer_log2
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c interactive seal geometry"));
        }
        let mut arena = runtime.allocate_arena(&config.arena_layout)?;
        match seal_x4c_into_arena_v4(parts, tx, runtime, &mut arena, &config) {
            Ok(sealed) => Ok(SealedGlobalChainX4cV4 {
                model_root: sealed.model_root,
                epoch: sealed.epoch,
                global_descriptor_digest: sealed.global_descriptor_digest,
                common_point: sealed.common_point,
                groups: sealed.groups,
                verifier_groups: sealed.verifier_groups,
                challenges: sealed.challenges,
                fold_frames: sealed.fold_frames,
                arena,
                config,
                parity: sealed.parity,
                metrics: sealed.metrics,
                lifecycle_started: sealed.lifecycle_started,
            }),
            Err(error) => {
                Err(cleanup_failed_x4c_arena_v4(runtime, arena, &config.arena_layout, error))
            }
        }
    }
}

struct X4cSealedFieldsV4<'a> {
    model_root: Digest,
    epoch: u64,
    global_descriptor_digest: Digest,
    common_point: Vec<Fp2>,
    groups: Vec<GlobalProverGroupV4<'a>>,
    verifier_groups: Vec<GlobalVerifierGroupV4>,
    challenges: GlobalFoldChallengesV4,
    fold_frames: Vec<FoldCommitmentFrameV4>,
    parity: Vec<X4cRoundParityRecordV4>,
    metrics: GlobalOpenMetricsV4,
    lifecycle_started: Instant,
}

fn seal_x4c_into_arena_v4<'a, R: X4cArenaRuntimeV4>(
    parts: X4cDraftPartsV4<'a>,
    tx: &mut Transcript,
    runtime: &mut R,
    arena: &mut R::Arena,
    seal_config: &X4cSealConfigV4,
) -> Result<X4cSealedFieldsV4<'a>, X4cErrorV4> {
    let X4cDraftPartsV4 {
        model_root,
        epoch,
        global_cohort_id,
        global_descriptor_digest,
        common_point,
        groups,
        fixed_challenges: _,
    } = parts;
    let layout = &seal_config.arena_layout;
    let max_outer_len = groups[0].cohort.commitment().config.outer_len;
    let max_coefficient_len = max_outer_len / 8;
    let verifier_groups = groups
        .iter()
        .map(|group| GlobalVerifierGroupV4 {
            commitment: group.cohort.commitment().clone(),
            touched_slots: group.touched_slots.clone(),
            weights: group.weights.clone(),
            target_point: group.target_point.clone(),
            activation_challenge: group.activation_challenge,
        })
        .collect::<Vec<_>>();
    let mut metrics = GlobalOpenMetricsV4::default();
    let mut current_coefficients = vec![Fp2::ZERO; max_coefficient_len];
    let mut initial_codeword = Some(vec![Fp2::ZERO; max_outer_len]);
    let mut current_claim = Fp2::ZERO;
    let mut activated = activate_groups_x4c_v4(
        max_outer_len,
        &groups,
        &mut current_coefficients,
        initial_codeword.as_deref_mut(),
        &mut current_claim,
        &mut metrics,
        |_activation, _codeword| Ok(()),
    )?;
    if activated == 0 {
        return Err(X4cErrorV4::InvalidGeometry("X4c initial activation"));
    }

    let mut fold_frames = Vec::with_capacity(common_point.len());
    let mut fold_challenges = Vec::with_capacity(common_point.len());
    let mut parity = Vec::with_capacity(common_point.len());
    let mut lifecycle_started = None;
    for (round_index, round_layout) in layout.rounds.iter().enumerate() {
        if round_index == 0
            && initial_codeword.as_ref().map(Vec::len) != Some(round_layout.input_len)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c round input geometry"));
        }
        let (line_zero, line_one) =
            claim_line_v4(&current_coefficients, &common_point[round_index + 1..])?;
        if interpolate_v4(line_zero, line_one, common_point[round_index]) != current_claim {
            return Err(X4cErrorV4::InvalidGeometry("X4c claim-line input"));
        }
        tx.append("x4_v4_global_fold_line", 32);
        let challenge = tx.challenge_fp2();
        if lifecycle_started.is_none() {
            lifecycle_started = Some(Instant::now());
        }
        fold_challenges.push(challenge);
        current_claim = interpolate_v4(line_zero, line_one, challenge);
        current_coefficients = fold_coefficients(&current_coefficients, challenge)
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c coefficient fold"))?;

        if round_index == 0 {
            runtime.direct_fold_host(
                arena,
                round_layout,
                initial_codeword
                    .as_deref()
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c missing initial codeword"))?,
                challenge,
            )?;
        } else {
            runtime.direct_fold_resident(
                arena,
                &layout.rounds[round_index - 1],
                round_layout,
                challenge,
            )?;
        }
        let mut round_activation_codeword = groups
            .iter()
            .any(|group| group.cohort.commitment().config.outer_len == round_layout.output_len)
            .then(|| vec![Fp2::ZERO; round_layout.output_len]);
        activated = activated
            .checked_add(activate_groups_x4c_v4(
                round_layout.output_len,
                &groups,
                &mut current_coefficients,
                round_activation_codeword.as_deref_mut(),
                &mut current_claim,
                &mut metrics,
                |activation, codeword| {
                    runtime.add_activation(arena, round_layout, codeword, activation)
                },
            )?)
            .ok_or(X4cErrorV4::Overflow)?;

        let root = runtime.build_one_slot_n4(
            arena,
            round_layout,
            global_descriptor_digest,
            global_cohort_id,
        )?;
        let plan = X4cDirectFoldSamplePlanV4::derive(
            seal_config.design_sha256,
            seal_config.clean_source_sha256,
            seal_config.response_ordinal,
            round_layout.fold_round,
            challenge,
            root,
            round_layout.output_len,
        )?;
        let observed = runtime.gather_samples(arena, round_layout, &plan.indices)?;
        let mut expected = if round_index == 0 {
            direct_fold_selected_v4(
                initial_codeword
                    .as_deref()
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c missing initial codeword"))?,
                challenge,
                &plan.indices,
            )?
        } else {
            let previous = &layout.rounds[round_index - 1];
            let mut paired_indices = Vec::with_capacity(plan.indices.len() * 2);
            paired_indices.extend_from_slice(&plan.indices);
            for index in &plan.indices {
                paired_indices.push(
                    index
                        .checked_add(
                            u64::try_from(round_layout.output_len)
                                .map_err(|_| X4cErrorV4::Overflow)?,
                        )
                        .ok_or(X4cErrorV4::Overflow)?,
                );
            }
            let paired = runtime.gather_samples(arena, previous, &paired_indices)?;
            let split = plan.indices.len();
            direct_fold_selected_pairs_v4(
                round_layout.input_len,
                challenge,
                &plan.indices,
                paired
                    .get(..split)
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c sampled positive fold inputs"))?,
                paired
                    .get(split..)
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c sampled negative fold inputs"))?,
            )?
        };
        if let Some(activation_codeword) = round_activation_codeword.as_deref() {
            for (expected, index) in expected.iter_mut().zip(&plan.indices) {
                *expected += *activation_codeword
                    .get(usize::try_from(*index).map_err(|_| X4cErrorV4::Overflow)?)
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c sampled activation codeword"))?;
            }
        }
        let mismatch_count =
            u64::try_from(expected.iter().zip(&observed).filter(|(a, b)| a != b).count())
                .map_err(|_| X4cErrorV4::Overflow)?;
        let result = X4cDirectFoldParityResultV4 {
            comparison_count: u64::try_from(observed.len()).map_err(|_| X4cErrorV4::Overflow)?,
            mismatch_count,
            ordered_indices_digest: plan.ordered_indices_digest,
        };
        if mismatch_count != 0 || observed.len() != plan.indices.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c direct-fold parity mismatch"));
        }
        if round_index == 0 {
            initial_codeword = None;
        }
        parity.push(X4cRoundParityRecordV4 {
            fold_round: round_layout.fold_round,
            challenge,
            root,
            plan,
            result,
        });

        metrics.folded_symbols_written = metrics
            .folded_symbols_written
            .checked_add(u64::try_from(round_layout.output_len).map_err(|_| X4cErrorV4::Overflow)?)
            .ok_or(X4cErrorV4::Overflow)?;
        let round_digests = u64::try_from(round_layout.output_len)
            .map_err(|_| X4cErrorV4::Overflow)?
            .checked_mul(3)
            .and_then(|value| value.checked_sub(1))
            .ok_or(X4cErrorV4::Overflow)?;
        metrics.aggregate_merkle_digests_written = metrics
            .aggregate_merkle_digests_written
            .checked_add(round_digests)
            .ok_or(X4cErrorV4::Overflow)?;
        let mut messages = vec![line_zero, line_one];
        if round_index + 1 == common_point.len() {
            if current_coefficients.as_slice() != [current_claim] {
                return Err(X4cErrorV4::InvalidGeometry("X4c final folded scalar"));
            }
            messages.push(current_claim);
        }
        let frame = FoldCommitmentFrameV4 {
            cohort_id: global_cohort_id,
            oracle_kind: OracleKindV4::GlobalFoldAggregate,
            fold_round: round_layout.fold_round,
            input_log2: round_layout.input_len.ilog2() as u8,
            output_log2: round_layout.output_len.ilog2() as u8,
            root_digest: root,
            ordered_message_symbols: messages,
        };
        let frame_bytes = FrameV4::FoldCommitment(frame.clone()).encode()?.len();
        tx.append(
            "x4_v4_global_fold_post_challenge",
            u64::try_from(
                frame_bytes
                    .checked_sub(32)
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c fold frame line width"))?,
            )
            .map_err(|_| X4cErrorV4::Overflow)?,
        );
        fold_frames.push(frame);
    }
    if layout.rounds.last().map(|round| round.output_len) != Some(8)
        || initial_codeword.is_some()
        || activated != groups.len()
    {
        return Err(X4cErrorV4::InvalidGeometry("X4c final activation schedule"));
    }
    metrics.aggregate_merkle_symbols_written = metrics.folded_symbols_written;
    metrics.sealed_fold_codeword_bytes = layout.codeword_bytes;
    metrics.sealed_fold_outer_cache_bytes = layout.outer_cache_bytes;
    metrics.sealed_fold_tree_count =
        u64::try_from(layout.rounds.len()).map_err(|_| X4cErrorV4::Overflow)?;
    metrics.sealed_fold_outer_level_vectors = 0;
    metrics.serialized_fold_bytes = fold_frames.iter().try_fold(0u64, |sum, frame| {
        sum.checked_add(
            u64::try_from(FrameV4::FoldCommitment(frame.clone()).encode()?.len())
                .map_err(|_| X4cErrorV4::Overflow)?,
        )
        .ok_or(X4cErrorV4::Overflow)
    })?;
    Ok(X4cSealedFieldsV4 {
        model_root,
        epoch,
        global_descriptor_digest,
        common_point,
        groups,
        verifier_groups,
        challenges: GlobalFoldChallengesV4 { folds: fold_challenges },
        fold_frames,
        parity,
        metrics,
        lifecycle_started: lifecycle_started
            .ok_or(X4cErrorV4::InvalidGeometry("X4c lifecycle start"))?,
    })
}

#[allow(clippy::too_many_arguments)]
fn activate_groups_x4c_v4(
    output_len: usize,
    groups: &[GlobalProverGroupV4<'_>],
    current_coefficients: &mut [Fp2],
    mut current_codeword: Option<&mut [Fp2]>,
    current_claim: &mut Fp2,
    metrics: &mut GlobalOpenMetricsV4,
    mut resident_activation: impl FnMut(Fp2, &[Fp2]) -> Result<(), X4cErrorV4>,
) -> Result<usize, X4cErrorV4> {
    let mut activated = 0usize;
    for group in groups {
        if group.cohort.commitment().config.outer_len != output_len {
            continue;
        }
        let (initial, traffic) = group.cohort.combine_source(
            &group.touched_slots,
            &group.weights,
            &group.target_point,
        )?;
        if traffic.persisted_oracle_bytes_read != 0
            || traffic.persisted_page_cache_dontneed_bytes != 0
            || traffic.persisted_page_cache_advice_calls != 0
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c activation used persisted oracle I/O"));
        }
        accumulate_recompute_traffic(metrics, traffic)?;
        let touched = u64::try_from(group.touched_slots.len()).map_err(|_| X4cErrorV4::Overflow)?;
        let coefficient_symbols =
            u64::try_from(initial.coefficients.len()).map_err(|_| X4cErrorV4::Overflow)?;
        let codeword_symbols =
            u64::try_from(initial.codeword.len()).map_err(|_| X4cErrorV4::Overflow)?;
        metrics.source_coefficients_read = metrics
            .source_coefficients_read
            .checked_add(touched.checked_mul(coefficient_symbols).ok_or(X4cErrorV4::Overflow)?)
            .ok_or(X4cErrorV4::Overflow)?;
        metrics.initial_encoded_symbols_read = metrics
            .initial_encoded_symbols_read
            .checked_add(touched.checked_mul(codeword_symbols).ok_or(X4cErrorV4::Overflow)?)
            .ok_or(X4cErrorV4::Overflow)?;
        metrics.combined_coefficient_symbols = metrics
            .combined_coefficient_symbols
            .checked_add(coefficient_symbols)
            .ok_or(X4cErrorV4::Overflow)?;
        metrics.combined_codeword_symbols = metrics
            .combined_codeword_symbols
            .checked_add(codeword_symbols)
            .ok_or(X4cErrorV4::Overflow)?;
        if current_coefficients.len() != initial.coefficients.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c activation domain"));
        }
        let host_codeword = current_codeword
            .as_deref_mut()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c missing activation diagnostic"))?;
        if host_codeword.len() != initial.codeword.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c activation domain"));
        }
        resident_activation(group.activation_challenge, &initial.codeword)?;
        for (output, value) in current_coefficients.iter_mut().zip(&initial.coefficients) {
            *output += group.activation_challenge * *value;
        }
        for (output, value) in host_codeword.iter_mut().zip(&initial.codeword) {
            *output += group.activation_challenge * *value;
        }
        *current_claim += group.activation_challenge * initial.claimed_value;
        activated = activated.checked_add(1).ok_or(X4cErrorV4::Overflow)?;
    }
    Ok(activated)
}

impl<A> SealedGlobalChainX4cV4<'_, A> {
    pub fn model_root(&self) -> Digest {
        self.model_root
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn common_point(&self) -> &[Fp2] {
        &self.common_point
    }

    pub fn fold_frames(&self) -> &[FoldCommitmentFrameV4] {
        &self.fold_frames
    }

    pub fn challenges(&self) -> &GlobalFoldChallengesV4 {
        &self.challenges
    }

    pub fn verifier_groups(&self) -> &[GlobalVerifierGroupV4] {
        &self.verifier_groups
    }

    pub fn parity_records(&self) -> &[X4cRoundParityRecordV4] {
        &self.parity
    }

    pub fn issue_queries_interactive_x4c<R: X4cArenaRuntimeV4<Arena = A>>(
        self,
        tx: &mut Transcript,
        runtime: &mut R,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, X4cResponseMetricsV4, Vec<u64>),
        X4cErrorV4,
    > {
        let draw_width = self.groups[0].cohort.commitment().config.outer_depth();
        let draws = (0..PRODUCTION_QUERY_COUNT_V4)
            .map(|_| tx.challenge_bits(draw_width))
            .collect::<Vec<_>>();
        self.issue_queries_x4c(draws, tx, runtime)
    }

    /// Consume the sealed state with verifier-owned exact-bit query draws.
    ///
    /// This method exists only on [`SealedGlobalChainX4cV4`], so neither the
    /// draft nor the seal path can consume or act on a query before every
    /// fold root has been fixed. The production record uses this boundary to
    /// replay the frozen selected tape byte-for-byte.
    pub fn issue_queries_x4c<R: X4cArenaRuntimeV4<Arena = A>>(
        self,
        draws: Vec<u64>,
        tx: &mut Transcript,
        runtime: &mut R,
    ) -> Result<
        (GlobalFoldingProofV4, Vec<GlobalVerifierGroupV4>, X4cResponseMetricsV4, Vec<u64>),
        X4cErrorV4,
    > {
        let SealedGlobalChainX4cV4 {
            model_root,
            epoch,
            global_descriptor_digest,
            common_point: _,
            groups,
            verifier_groups,
            challenges: _,
            fold_frames,
            mut arena,
            config,
            parity,
            mut metrics,
            lifecycle_started,
        } = self;

        let opening_result = (|| {
            validate_query_draws(&draws, groups[0].cohort.commitment().config.outer_len)?;
            let schedule = packed_schedule_from_verifier(
                model_root,
                epoch,
                &verifier_groups,
                &fold_frames,
                draws.clone(),
            )?;
            let mut initial_groups = Vec::with_capacity(groups.len());
            for group in &groups {
                let (opening, traffic) = group
                    .cohort
                    .open_initial_source(&schedule.query_draws, &group.touched_slots)?;
                if traffic.persisted_oracle_bytes_read != 0
                    || traffic.persisted_page_cache_dontneed_bytes != 0
                    || traffic.persisted_page_cache_advice_calls != 0
                {
                    return Err(X4cErrorV4::InvalidGeometry(
                        "X4c opening used persisted oracle I/O",
                    ));
                }
                accumulate_recompute_traffic(&mut metrics, traffic)?;
                initial_groups.push(opening);
            }
            let plan = X4cCanonicalGatherPlanV4::build(
                &schedule,
                initial_groups,
                global_descriptor_digest,
                &config.arena_layout,
            )?;
            let canonical =
                runtime.gather_canonical_opening(&mut arena, &config.arena_layout, &plan)?;
            let packed_opening = match decode_v4(&canonical)? {
                FrameV4::PackedBatchOpening(opening) => opening,
                _ => return Err(X4cErrorV4::InvalidGeometry("X4c gathered frame kind")),
            };
            packed_opening.validate_against_schedule(&schedule)?;
            if FrameV4::PackedBatchOpening(packed_opening.clone()).encode()? != canonical {
                return Err(X4cErrorV4::InvalidGeometry("X4c gathered opening is not canonical"));
            }
            metrics.serialized_packed_opening_bytes =
                u64::try_from(canonical.len()).map_err(|_| X4cErrorV4::Overflow)?;
            Ok((packed_opening, canonical, plan.operations.len()))
        })();

        let (packed_opening, canonical, query_gather_operation_count) = match opening_result {
            Ok(value) => value,
            Err(error) => {
                return Err(cleanup_failed_x4c_arena_v4(
                    runtime,
                    arena,
                    &config.arena_layout,
                    error,
                ));
            }
        };
        tx.append(
            "x4_v4_packed_opening",
            u64::try_from(canonical.len()).map_err(|_| X4cErrorV4::Overflow)?,
        );
        let proof = GlobalFoldingProofV4 { fold_frames, packed_opening };
        let proof_ready_wall_ns = elapsed_x4c_ns_v4(lifecycle_started)?;
        let proof_ready = match runtime.proof_ready_census(&arena, &config.arena_layout) {
            Ok(census) => {
                if let Err(error) = census.validate_proof_ready(&config.arena_layout) {
                    return Err(cleanup_failed_x4c_arena_v4(
                        runtime,
                        arena,
                        &config.arena_layout,
                        error,
                    ));
                }
                census
            }
            Err(error) => {
                return Err(cleanup_failed_x4c_arena_v4(
                    runtime,
                    arena,
                    &config.arena_layout,
                    error,
                ));
            }
        };

        if let Err(error) = runtime.reset_arena(&mut arena, &config.arena_layout) {
            let release = runtime.release_arena(arena, &config.arena_layout, &proof_ready);
            return Err(X4cErrorV4::Runtime(format!(
                "X4c arena reset failed ({error:?}); cleanup release={release:?}"
            )));
        }
        let reusable = runtime.release_arena(arena, &config.arena_layout, &proof_ready)?;
        reusable.validate_session_reusable(&proof_ready, &config.arena_layout)?;
        let lifecycle_walls = X4cLifecycleWallsV4 {
            proof_ready_wall_ns,
            session_reusable_wall_ns: elapsed_x4c_ns_v4(lifecycle_started)?,
        };
        lifecycle_walls.validate()?;
        let diagnostic_symbols = direct_fold_diagnostic_symbols_v4(&parity)?;
        let execution = X4cResponseExecutionCountersV4 {
            direct_fold_calls: u64::try_from(config.arena_layout.rounds.len())
                .map_err(|_| X4cErrorV4::Overflow)?,
            direct_fold_sample_comparisons: parity.iter().try_fold(0u64, |sum, round| {
                sum.checked_add(round.result.comparison_count).ok_or(X4cErrorV4::Overflow)
            })?,
            direct_fold_sample_mismatches: parity.iter().try_fold(0u64, |sum, round| {
                sum.checked_add(round.result.mismatch_count).ok_or(X4cErrorV4::Overflow)
            })?,
            direct_fold_diagnostic_gather_calls: u64::try_from(
                config
                    .arena_layout
                    .rounds
                    .len()
                    .checked_mul(2)
                    .and_then(|calls| calls.checked_sub(1))
                    .ok_or(X4cErrorV4::Overflow)?,
            )
            .map_err(|_| X4cErrorV4::Overflow)?,
            direct_fold_diagnostic_index_h2d_bytes: diagnostic_symbols
                .checked_mul(size_of::<u64>() as u64)
                .ok_or(X4cErrorV4::Overflow)?,
            direct_fold_diagnostic_value_d2h_bytes: diagnostic_symbols
                .checked_mul(FP2_BYTES)
                .ok_or(X4cErrorV4::Overflow)?,
            n4_tree_calls: u64::try_from(config.arena_layout.rounds.len())
                .map_err(|_| X4cErrorV4::Overflow)?,
            query_gather_calls: 1,
            query_gather_operation_count: u64::try_from(query_gather_operation_count)
                .map_err(|_| X4cErrorV4::Overflow)?,
            query_gather_operation_h2d_bytes: u64::try_from(query_gather_operation_count)
                .map_err(|_| X4cErrorV4::Overflow)?
                .checked_mul(size_of::<X4cCanonicalGatherOperation>() as u64)
                .ok_or(X4cErrorV4::Overflow)?,
            canonical_template_h2d_bytes: u64::try_from(canonical.len())
                .map_err(|_| X4cErrorV4::Overflow)?,
            query_draw_count: u64::try_from(draws.len()).map_err(|_| X4cErrorV4::Overflow)?,
            canonical_opening_d2h_bytes: u64::try_from(canonical.len())
                .map_err(|_| X4cErrorV4::Overflow)?,
            noncanonical_opening_d2h_bytes: 0,
            cpu_fold_tree_clone_bytes: 0,
        };
        let io = X4cResponseIoCountersV4::default();
        io.validate_hard_zero()?;
        if config.arena_layout == X4cArenaLayoutV4::production()? {
            let observed_components = proof.packed_opening.byte_components()?;
            let expected_components = gpt2_codec_reference_packed_opening_v4().byte_components()?;
            let global_folding_proof_bytes =
                u64::try_from(proof.canonical_bytes()?.len()).map_err(|_| X4cErrorV4::Overflow)?;
            let assembled_complete_pcs_bytes = observed_components
                .serialized_bytes
                .checked_add(X4C_MANDATORY_NON_QUERY_BYTES_V4)
                .ok_or(X4cErrorV4::Overflow)?;
            if observed_components != expected_components
                || metrics.serialized_packed_opening_bytes != X4C_PACKED_OPENING_BYTES_V4
                || metrics.serialized_fold_bytes != X4C_FOLD_FRAME_BYTES_V4
                || global_folding_proof_bytes != X4C_GLOBAL_FOLDING_PROOF_BYTES_V4
                || assembled_complete_pcs_bytes != X4C_COMPLETE_PCS_BYTES_V4
            {
                return Err(X4cErrorV4::Runtime(format!(
                    "X4c production canonical-byte diagnostic: \
                     packed_observed={}; packed_expected={}; \
                     fold_frames_observed={}; fold_frames_expected={X4C_FOLD_FRAME_BYTES_V4}; \
                     global_folding_proof_observed={global_folding_proof_bytes}; \
                     global_folding_proof_expected={X4C_GLOBAL_FOLDING_PROOF_BYTES_V4}; \
                     assembled_complete_pcs_observed={assembled_complete_pcs_bytes}; \
                     complete_pcs_expected={X4C_COMPLETE_PCS_BYTES_V4}; \
                     opened_symbols_observed={}; opened_symbols_expected={}; \
                     initial_inner_siblings_observed={}; \
                     initial_inner_siblings_expected={}; \
                     initial_outer_siblings_observed={}; \
                     initial_outer_siblings_expected={}; \
                     fold_outer_siblings_observed={}; \
                     fold_outer_siblings_expected={}; \
                     metadata_bytes_observed={}; metadata_bytes_expected={}",
                    observed_components.serialized_bytes,
                    expected_components.serialized_bytes,
                    metrics.serialized_fold_bytes,
                    observed_components.opened_symbols,
                    expected_components.opened_symbols,
                    observed_components.initial_inner_siblings,
                    expected_components.initial_inner_siblings,
                    observed_components.initial_outer_siblings,
                    expected_components.initial_outer_siblings,
                    observed_components.fold_outer_siblings,
                    expected_components.fold_outer_siblings,
                    observed_components.metadata_bytes,
                    expected_components.metadata_bytes,
                )));
            }
            execution.validate_production()?;
        }
        Ok((
            proof,
            verifier_groups,
            X4cResponseMetricsV4 {
                io,
                execution,
                parity,
                proof_ready_arena: proof_ready,
                session_reusable_arena: reusable,
                lifecycle_walls,
                global_open: metrics,
                sampling_soundness_credit_bits: 0,
            },
            draws,
        ))
    }
}

fn cleanup_failed_x4c_arena_v4<R: X4cArenaRuntimeV4>(
    runtime: &mut R,
    mut arena: R::Arena,
    layout: &X4cArenaLayoutV4,
    primary: X4cErrorV4,
) -> X4cErrorV4 {
    let reset = runtime.reset_arena(&mut arena, layout);
    let proof_ready = X4cArenaCensusV4::default();
    let release = runtime.release_arena(arena, layout, &proof_ready);
    if reset.is_err() || release.is_err() {
        X4cErrorV4::Runtime(format!(
            "X4c operation failed ({primary:?}); cleanup reset={reset:?}, release={release:?}"
        ))
    } else {
        primary
    }
}

fn direct_fold_diagnostic_symbols_v4(parity: &[X4cRoundParityRecordV4]) -> Result<u64, X4cErrorV4> {
    let output_symbols = parity.iter().try_fold(0u64, |sum, round| {
        sum.checked_add(round.result.comparison_count).ok_or(X4cErrorV4::Overflow)
    })?;
    let first_round = parity
        .first()
        .ok_or(X4cErrorV4::InvalidGeometry("X4c empty parity record"))?
        .result
        .comparison_count;
    output_symbols
        .checked_add(
            output_symbols
                .checked_sub(first_round)
                .and_then(|symbols| symbols.checked_mul(2))
                .ok_or(X4cErrorV4::Overflow)?,
        )
        .ok_or(X4cErrorV4::Overflow)
}

fn elapsed_x4c_ns_v4(started: Instant) -> Result<u64, X4cErrorV4> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|_| X4cErrorV4::Overflow)
}

fn x4c_pinned_pool_requested_bytes_v4() -> Result<u64, X4cErrorV4> {
    let transfer = u64::try_from(X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4)
        .map_err(|_| X4cErrorV4::Overflow)?
        .checked_mul(2)
        .and_then(|value| value.checked_mul(size_of::<Fp2Repr>() as u64))
        .and_then(|value| value.checked_mul(X4C_PINNED_TRANSFER_RING_V4 as u64))
        .ok_or(X4cErrorV4::Overflow)?;
    let operations = u64::try_from(X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4)
        .map_err(|_| X4cErrorV4::Overflow)?
        .checked_mul(size_of::<X4cCanonicalGatherOperation>() as u64)
        .ok_or(X4cErrorV4::Overflow)?;
    transfer
        .checked_add(X4C_PACKED_OPENING_BYTES_V4)
        .and_then(|value| value.checked_add(operations))
        .ok_or(X4cErrorV4::Overflow)
}

fn x4c_usize_v4(value: u64) -> Result<usize, X4cErrorV4> {
    usize::try_from(value).map_err(|_| X4cErrorV4::Overflow)
}

fn x4c_align_up_v4(value: usize, alignment: usize) -> Result<usize, X4cErrorV4> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(X4cErrorV4::InvalidGeometry("X4c workspace alignment"));
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(X4cErrorV4::Overflow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct X4cCudaWorkspaceV4 {
    tile_scratch_offset: usize,
    mailbox_offset: usize,
    operation_scratch_offset: usize,
}

impl X4cCudaWorkspaceV4 {
    fn production(layout: &X4cArenaLayoutV4) -> Result<Self, X4cErrorV4> {
        layout.validate()?;
        let workspace_start = x4c_usize_v4(layout.workspace_byte_offset)?;
        let tile_scratch_bytes = X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4
            .checked_mul(2)
            .and_then(|value| value.checked_mul(size_of::<Fp2Repr>()))
            .ok_or(X4cErrorV4::Overflow)?;
        let mailbox_offset = x4c_align_up_v4(
            workspace_start.checked_add(tile_scratch_bytes).ok_or(X4cErrorV4::Overflow)?,
            8,
        )?;
        let mailbox_bytes = x4c_usize_v4(X4C_PACKED_OPENING_BYTES_V4)?;
        let operation_scratch_offset = x4c_align_up_v4(
            mailbox_offset.checked_add(mailbox_bytes).ok_or(X4cErrorV4::Overflow)?,
            8,
        )?;
        let operation_scratch_bytes = X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4
            .checked_mul(size_of::<X4cCanonicalGatherOperation>())
            .ok_or(X4cErrorV4::Overflow)?;
        let end = operation_scratch_offset
            .checked_add(operation_scratch_bytes)
            .ok_or(X4cErrorV4::Overflow)?;
        if end > x4c_usize_v4(layout.capacity_bytes)? {
            return Err(X4cErrorV4::InvalidGeometry("X4c registered workspace capacity"));
        }
        Ok(Self { tile_scratch_offset: workspace_start, mailbox_offset, operation_scratch_offset })
    }
}

/// Concrete X4c CUDA runtime. The transfer ring and canonical gather buffers
/// are allocated before any response and remain active across responses;
/// `release_pinned_pool`
/// returns them to the registered cache only at an explicit session boundary.
pub struct X4cCudaArenaRuntimeV4<'a> {
    backend: &'a mut Backend,
    transfer_ring: Vec<PinnedHostBuffer<Fp2Repr>>,
    transfer_cursor: usize,
    canonical_template: Option<PinnedHostBuffer<u8>>,
    canonical_operations: Option<PinnedHostBuffer<X4cCanonicalGatherOperation>>,
    transfer_staging: Vec<Fp2Repr>,
    operation_staging: Vec<X4cCanonicalGatherOperation>,
    baseline_resident_bytes: u64,
    baseline_cached_resident_bytes: u64,
    baseline_active_device_allocations: u64,
    baseline_active_pinned_allocations: u64,
    baseline_active_pinned_bytes: u64,
    response_cache_baseline_finalized: bool,
    arena_live: bool,
}

#[derive(Debug)]
pub struct X4cCudaArenaV4 {
    buffer: Option<DeviceBuffer<u8>>,
    capacity_bytes: u64,
    workspace: X4cCudaWorkspaceV4,
    reset: bool,
}

impl<'a> X4cCudaArenaRuntimeV4<'a> {
    pub fn production(backend: &'a mut Backend) -> Result<Self, X4cErrorV4> {
        let control = backend.x4c_control_state()?;
        if control.stream_state != CudaStreamState::Idle
            || control.outstanding_cuda_operations != 0
            || control.measurement_active
            || control.coarse_timing_active
            || control.timing_record_active
            || control.measurement_poisoned
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c pinned-pool prewarm boundary"));
        }
        let memory = backend.device_memory_breakdown()?;
        let baseline_pinned = backend.pinned_memory_stats()?;
        if baseline_pinned.in_flight_allocations != 0 {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c pinned-pool baseline has in-flight ownership",
            ));
        }
        let transfer_len =
            X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4.checked_mul(2).ok_or(X4cErrorV4::Overflow)?;
        let mut transfer_ring = Vec::with_capacity(X4C_PINNED_TRANSFER_RING_V4);
        for _ in 0..X4C_PINNED_TRANSFER_RING_V4 {
            match backend.alloc_pinned_host::<Fp2Repr>(transfer_len) {
                Ok(buffer) => transfer_ring.push(buffer),
                Err(error) => {
                    for buffer in transfer_ring {
                        let _ = backend.free_pinned_host(buffer);
                    }
                    return Err(error.into());
                }
            }
        }
        let canonical_template =
            match backend.alloc_pinned_host::<u8>(x4c_usize_v4(X4C_PACKED_OPENING_BYTES_V4)?) {
                Ok(buffer) => buffer,
                Err(error) => {
                    for buffer in transfer_ring {
                        let _ = backend.free_pinned_host(buffer);
                    }
                    return Err(error.into());
                }
            };
        let canonical_operations = match backend.alloc_pinned_host::<X4cCanonicalGatherOperation>(
            X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4,
        ) {
            Ok(buffer) => buffer,
            Err(error) => {
                let _ = backend.free_pinned_host(canonical_template);
                for buffer in transfer_ring {
                    let _ = backend.free_pinned_host(buffer);
                }
                return Err(error.into());
            }
        };
        let pinned = backend.pinned_memory_stats()?;
        if pinned.active_allocations
            != baseline_pinned
                .active_allocations
                .checked_add((X4C_PINNED_TRANSFER_RING_V4 + 2) as u64)
                .ok_or(X4cErrorV4::Overflow)?
            || pinned.active_bytes
                < baseline_pinned
                    .active_bytes
                    .checked_add(x4c_pinned_pool_requested_bytes_v4()?)
                    .ok_or(X4cErrorV4::Overflow)?
            || pinned.in_flight_allocations != 0
        {
            let _ = backend.free_pinned_host(canonical_operations);
            let _ = backend.free_pinned_host(canonical_template);
            for buffer in transfer_ring {
                let _ = backend.free_pinned_host(buffer);
            }
            return Err(X4cErrorV4::InvalidGeometry("X4c pinned-pool ownership census"));
        }
        Ok(Self {
            backend,
            transfer_ring,
            transfer_cursor: 0,
            canonical_template: Some(canonical_template),
            canonical_operations: Some(canonical_operations),
            transfer_staging: Vec::with_capacity(
                X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4.checked_mul(2).ok_or(X4cErrorV4::Overflow)?,
            ),
            operation_staging: Vec::with_capacity(X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4),
            baseline_resident_bytes: memory.resident_bytes,
            baseline_cached_resident_bytes: memory.cached_resident_bytes,
            baseline_active_device_allocations: control.active_device_allocations,
            baseline_active_pinned_allocations: baseline_pinned.active_allocations,
            baseline_active_pinned_bytes: baseline_pinned.active_bytes,
            response_cache_baseline_finalized: false,
            arena_live: false,
        })
    }

    /// Borrow the shared backend between responses while retaining the
    /// prewarmed pinned transfer pool.
    ///
    /// The response arena must already be released. This lets the real-weight
    /// driver run the next resident witness/model proof without
    /// registering/deregistering X4c transfer buffers per response.
    pub fn backend_between_responses(&mut self) -> Result<&mut Backend, X4cErrorV4> {
        if self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c backend borrowed while response arena is live",
            ));
        }
        let control = self.backend.x4c_control_state()?;
        if control.stream_state != CudaStreamState::Idle
            || control.outstanding_cuda_operations != 0
            || control.measurement_active
            || control.coarse_timing_active
            || control.timing_record_active
            || control.measurement_poisoned
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c backend between-response boundary"));
        }
        Ok(self.backend)
    }

    pub fn backend_control_state(&self) -> Result<volta_accel::X4cControlState, X4cErrorV4> {
        self.backend.x4c_control_state().map_err(Into::into)
    }

    pub fn begin_response_measurement(&mut self) -> Result<(), X4cErrorV4> {
        if self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c response measurement begins with live arena",
            ));
        }
        let memory = self.backend.device_memory_breakdown()?;
        let control = self.backend.x4c_control_state()?;
        if memory.resident_bytes != self.baseline_resident_bytes
            || control.active_device_allocations != self.baseline_active_device_allocations
            || control.stream_state != CudaStreamState::Idle
            || control.outstanding_cuda_operations != 0
            || control.measurement_active
            || control.coarse_timing_active
            || control.timing_record_active
            || control.measurement_poisoned
        {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c response baseline active ownership changed",
            ));
        }
        if !self.response_cache_baseline_finalized {
            // The resident model proof runs after runtime construction but
            // before the first response window. Its inactive cache is not
            // response-arena ownership. Freeze that cache exactly once;
            // later responses keep the released arena above this baseline.
            self.baseline_cached_resident_bytes = memory.cached_resident_bytes;
            self.response_cache_baseline_finalized = true;
        }
        self.backend.begin_measurement().map_err(Into::into)
    }

    pub fn finish_response_measurement(&mut self) -> Result<BackendStats, X4cErrorV4> {
        if self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c response measurement ends with live arena",
            ));
        }
        self.backend.finish_measurement().map_err(Into::into)
    }

    /// Logical session teardown for the pinned transfer pool. This does not
    /// physically deregister memory; a later runtime may reuse the cache.
    pub fn release_pinned_pool(&mut self) -> Result<(), X4cErrorV4> {
        if self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry("X4c pinned pool released with live arena"));
        }
        let operations = self
            .canonical_operations
            .as_ref()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c pinned pool already released"))?;
        let template = self
            .canonical_template
            .as_ref()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c pinned pool already released"))?;
        if self.transfer_ring.len() != X4C_PINNED_TRANSFER_RING_V4 {
            return Err(X4cErrorV4::InvalidGeometry("X4c pinned pool already released"));
        }
        self.backend.wait_pinned_host_ready(&operations)?;
        self.backend.wait_pinned_host_ready(&template)?;
        for transfer in &self.transfer_ring {
            self.backend.wait_pinned_host_ready(&transfer)?;
        }

        let operations = self
            .canonical_operations
            .take()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c pinned pool already released"))?;
        let template = self
            .canonical_template
            .take()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c pinned pool already released"))?;
        let transfer_ring = std::mem::take(&mut self.transfer_ring);
        let mut first_error = None;
        for result in
            [self.backend.free_pinned_host(operations), self.backend.free_pinned_host(template)]
        {
            if first_error.is_none() {
                first_error = result.err();
            }
        }
        for transfer in transfer_ring {
            if let Err(error) = self.backend.free_pinned_host(transfer) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        let pinned = self.backend.pinned_memory_stats()?;
        if pinned.in_flight_allocations != 0
            || pinned.active_allocations != self.baseline_active_pinned_allocations
            || pinned.active_bytes != self.baseline_active_pinned_bytes
        {
            return Err(X4cErrorV4::InvalidGeometry(
                "X4c pinned pool ownership mismatch at release",
            ));
        }
        Ok(())
    }

    fn fill_transfer_staging(
        &mut self,
        values: impl IntoIterator<Item = Fp2>,
    ) -> Result<(), X4cErrorV4> {
        self.transfer_staging.clear();
        self.transfer_staging.extend(values.into_iter().map(Fp2Repr::from));
        if self.transfer_staging.len()
            > X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4.checked_mul(2).ok_or(X4cErrorV4::Overflow)?
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c pinned transfer tile overflow"));
        }
        Ok(())
    }

    fn census(
        &mut self,
        layout: &X4cArenaLayoutV4,
        proof_ready: bool,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4> {
        let memory = self.backend.device_memory_breakdown()?;
        let pinned = self.backend.pinned_memory_stats()?;
        let control = self.backend.x4c_control_state()?;
        let stats = self.backend.stats()?;
        let stream_synchronized = control.stream_state == CudaStreamState::Idle
            && control.outstanding_cuda_operations == 0;
        let outstanding_allocations = control
            .active_device_allocations
            .checked_sub(self.baseline_active_device_allocations)
            .ok_or(X4cErrorV4::InvalidGeometry("X4c native active-allocation baseline"))?;
        let outstanding_bytes = memory
            .resident_bytes
            .checked_sub(self.baseline_resident_bytes)
            .ok_or(X4cErrorV4::InvalidGeometry("X4c native resident-byte baseline"))?;
        let cached_reusable_bytes = memory
            .cached_resident_bytes
            .checked_sub(self.baseline_cached_resident_bytes)
            .ok_or(X4cErrorV4::InvalidGeometry("X4c native cached-byte baseline"))?;
        let committed_bytes =
            if proof_ready { outstanding_bytes } else { stats.x4c_arena_reset_bytes };
        Ok(X4cArenaCensusV4 {
            arena_capacity_bytes: layout.capacity_bytes,
            arena_committed_bytes: committed_bytes,
            arena_peak_bytes: stats.peak_device_bytes,
            logical_allocation_count: stats.resident_alloc_requests,
            logical_deallocation_count: stats.resident_free_requests,
            reset_count: stats.x4c_arena_reset_calls,
            zeroed_bytes: stats.device_zeroed_bytes,
            outstanding_allocation_count: outstanding_allocations,
            outstanding_bytes,
            cached_reusable_bytes,
            accelerator_available: true,
            backend_workspace_bytes: memory.workspace_bytes,
            backend_baseline_resident_bytes: self.baseline_resident_bytes,
            backend_resident_bytes: memory.resident_bytes,
            backend_cached_resident_bytes: memory.cached_resident_bytes,
            backend_baseline_active_device_allocations: self.baseline_active_device_allocations,
            backend_active_device_allocations: control.active_device_allocations,
            backend_cached_device_allocations: control.cached_device_allocations,
            backend_baseline_active_pinned_allocations: self.baseline_active_pinned_allocations,
            backend_baseline_active_pinned_bytes: self.baseline_active_pinned_bytes,
            backend_active_pinned_allocations: pinned.active_allocations,
            backend_cached_pinned_allocations: pinned.cached_allocations,
            backend_in_flight_pinned_allocations: pinned.in_flight_allocations,
            backend_active_pinned_bytes: pinned.active_bytes,
            backend_cached_pinned_bytes: pinned.cached_bytes,
            backend_outstanding_cuda_operations: control.outstanding_cuda_operations,
            backend_stream_synchronized: stream_synchronized,
            x4c_pinned_pool_allocations: u64::try_from(X4C_PINNED_TRANSFER_RING_V4 + 2)
                .map_err(|_| X4cErrorV4::Overflow)?,
            x4c_pinned_pool_requested_bytes: x4c_pinned_pool_requested_bytes_v4()?,
            native_live_device_bytes: stats.live_device_bytes,
            native_peak_device_bytes: stats.peak_device_bytes,
            native_resident_alloc_requests: stats.resident_alloc_requests,
            native_resident_reuse_hits: stats.resident_reuse_hits,
            native_resident_free_requests: stats.resident_free_requests,
            native_arena_reset_calls: stats.x4c_arena_reset_calls,
            native_arena_reset_bytes: stats.x4c_arena_reset_bytes,
            native_device_zeroed_bytes: stats.device_zeroed_bytes,
            ..X4cArenaCensusV4::default()
        })
    }
}

impl X4cCudaArenaV4 {
    fn buffer(&self) -> Result<&DeviceBuffer<u8>, X4cErrorV4> {
        self.buffer.as_ref().ok_or(X4cErrorV4::InvalidGeometry("X4c CUDA arena released"))
    }
}

impl X4cArenaRuntimeV4 for X4cCudaArenaRuntimeV4<'_> {
    type Arena = X4cCudaArenaV4;

    fn allocate_arena(&mut self, layout: &X4cArenaLayoutV4) -> Result<Self::Arena, X4cErrorV4> {
        layout.validate()?;
        let workspace = X4cCudaWorkspaceV4::production(layout)?;
        if self.arena_live
            || self.transfer_ring.len() != X4C_PINNED_TRANSFER_RING_V4
            || self.canonical_template.is_none()
            || self.canonical_operations.is_none()
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA arena allocation ownership"));
        }
        let buffer = self.backend.alloc_device::<u8>(x4c_usize_v4(layout.capacity_bytes)?)?;
        if buffer.len() != x4c_usize_v4(layout.capacity_bytes)? || !buffer.is_owned_by(self.backend)
        {
            let _ = self.backend.free_device(buffer);
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA arena allocation"));
        }
        self.arena_live = true;
        Ok(X4cCudaArenaV4 {
            buffer: Some(buffer),
            capacity_bytes: layout.capacity_bytes,
            workspace,
            reset: false,
        })
    }

    fn direct_fold_host(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        input: &[Fp2],
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4> {
        if input.len() != round.input_len || arena.reset {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA host fold geometry"));
        }
        let workspace = arena.workspace;
        let half = round.output_len;
        for output_start in (0..half).step_by(X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4) {
            let count = (half - output_start).min(X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4);
            let positive = input[output_start..output_start + count].iter().copied();
            let negative = input[output_start + half..output_start + half + count].iter().copied();
            self.fill_transfer_staging(positive.chain(negative))?;
            let transfer_index = self.transfer_cursor;
            self.transfer_cursor = (self.transfer_cursor + 1) % self.transfer_ring.len();
            let transfer = &self.transfer_ring[transfer_index];
            self.backend.wait_pinned_host_ready(transfer)?;
            self.backend.write_pinned_host(transfer, 0, &self.transfer_staging)?;
            self.backend.x4c_direct_fold_pinned_tile_into_arena(
                transfer,
                0,
                round.input_len,
                output_start,
                count,
                arena.buffer()?,
                x4c_usize_v4(round.codeword_byte_offset)?,
                workspace.tile_scratch_offset,
                challenge,
            )?;
        }
        Ok(())
    }

    fn direct_fold_resident(
        &mut self,
        arena: &mut Self::Arena,
        previous: &X4cArenaRoundV4,
        round: &X4cArenaRoundV4,
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4> {
        if arena.reset
            || previous.output_len != round.input_len
            || previous.fold_round.checked_add(1) != Some(round.fold_round)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA resident fold geometry"));
        }
        self.backend.x4c_direct_fold_arena_into_arena(
            arena.buffer()?,
            x4c_usize_v4(previous.codeword_byte_offset)?,
            previous.output_len,
            x4c_usize_v4(round.codeword_byte_offset)?,
            challenge,
        )?;
        Ok(())
    }

    fn add_activation(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        codeword: &[Fp2],
        activation: Fp2,
    ) -> Result<(), X4cErrorV4> {
        if arena.reset || codeword.len() != round.output_len {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA activation geometry"));
        }
        let workspace = arena.workspace;
        for start in (0..codeword.len()).step_by(X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4) {
            let count = (codeword.len() - start).min(X4C_PINNED_TILE_OUTPUT_SYMBOLS_V4);
            self.fill_transfer_staging(codeword[start..start + count].iter().copied())?;
            let transfer_index = self.transfer_cursor;
            self.transfer_cursor = (self.transfer_cursor + 1) % self.transfer_ring.len();
            let transfer = &self.transfer_ring[transfer_index];
            self.backend.wait_pinned_host_ready(transfer)?;
            self.backend.write_pinned_host(transfer, 0, &self.transfer_staging)?;
            self.backend.x4c_activation_add_pinned_tile_into_arena(
                transfer,
                0,
                arena.buffer()?,
                x4c_usize_v4(round.codeword_byte_offset)?,
                round.output_len,
                start,
                count,
                workspace.tile_scratch_offset,
                activation,
            )?;
        }
        Ok(())
    }

    fn build_one_slot_n4(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        descriptor: Digest,
        cohort_id: u32,
    ) -> Result<Digest, X4cErrorV4> {
        if arena.reset || descriptor == [0; 32] {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA N4 identity"));
        }
        let cache_offset = round
            .retained_outer_levels
            .first()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c CUDA N4 cache"))?
            .byte_offset;
        let native_layout = X4cOneSlotN4Layout::new(round.output_len, x4c_usize_v4(cache_offset)?)?;
        if u64::try_from(native_layout.cache_bytes()).map_err(|_| X4cErrorV4::Overflow)?
            != round.retained_outer_bytes()?
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA N4 cache bytes"));
        }
        self.backend
            .x4c_build_one_slot_n4(
                arena.buffer()?,
                x4c_usize_v4(round.codeword_byte_offset)?,
                native_layout,
                descriptor,
                cohort_id,
                OracleKindV4::GlobalFoldAggregate as u8,
                round.fold_round,
            )
            .map_err(Into::into)
    }

    fn gather_samples(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        indices: &[u64],
    ) -> Result<Vec<Fp2>, X4cErrorV4> {
        if arena.reset {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA sample after reset"));
        }
        self.backend
            .x4c_gather_fp2_samples(
                arena.buffer()?,
                x4c_usize_v4(round.codeword_byte_offset)?,
                round.output_len,
                indices,
            )
            .map_err(Into::into)
    }

    fn gather_canonical_opening(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
        plan: &X4cCanonicalGatherPlanV4,
    ) -> Result<Vec<u8>, X4cErrorV4> {
        plan.validate(layout)?;
        if arena.reset
            || plan.canonical_template.len() > x4c_usize_v4(X4C_PACKED_OPENING_BYTES_V4)?
            || plan.operations.len() > X4C_CANONICAL_GATHER_MAX_OPERATIONS_V4
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA canonical gather capacity"));
        }
        let workspace = X4cCudaWorkspaceV4::production(layout)?;
        let template = self
            .canonical_template
            .as_ref()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c canonical template pool unavailable"))?;
        self.backend.wait_pinned_host_ready(template)?;
        self.backend.write_pinned_host(template, 0, &plan.canonical_template)?;
        self.backend.x4c_upload_pinned_into_arena(
            template,
            0,
            arena.buffer()?,
            workspace.mailbox_offset,
            plan.canonical_template.len(),
        )?;

        self.operation_staging.clear();
        for operation in &plan.operations {
            let (round_ordinal, index, source_offset_bytes, source_kind, level) = match operation
                .source
            {
                X4cGatherSourceV4::CodewordSymbol { round_ordinal, index, source_byte_offset } => {
                    (round_ordinal, index, source_byte_offset, X4C_GATHER_CODEWORD_SYMBOL, 0)
                }
                X4cGatherSourceV4::CachedOuterDigest {
                    round_ordinal,
                    level,
                    index,
                    source_byte_offset,
                } => (
                    round_ordinal,
                    index,
                    source_byte_offset,
                    X4C_GATHER_CACHED_OUTER_DIGEST,
                    level,
                ),
                X4cGatherSourceV4::RebuiltOuterDigest { round_ordinal, level, index } => {
                    let round = layout
                        .rounds
                        .get(round_ordinal)
                        .ok_or(X4cErrorV4::InvalidGeometry("X4c gather rebuilt round"))?;
                    (
                        round_ordinal,
                        index,
                        round.codeword_byte_offset,
                        X4C_GATHER_REBUILT_OUTER_DIGEST,
                        level,
                    )
                }
            };
            let round = layout
                .rounds
                .get(round_ordinal)
                .ok_or(X4cErrorV4::InvalidGeometry("X4c gather native round"))?;
            let metadata = plan
                .round_metadata
                .get(round_ordinal)
                .ok_or(X4cErrorV4::InvalidGeometry("X4c gather native metadata"))?;
            let cache_offset_bytes = round
                .retained_outer_levels
                .first()
                .ok_or(X4cErrorV4::InvalidGeometry("X4c gather native cache"))?
                .byte_offset;
            self.operation_staging.push(X4cCanonicalGatherOperation {
                codeword_offset_bytes: round.codeword_byte_offset,
                cache_offset_bytes,
                source_offset_bytes,
                outer_len: u64::try_from(round.output_len).map_err(|_| X4cErrorV4::Overflow)?,
                index,
                destination_offset_bytes: u64::try_from(workspace.mailbox_offset)
                    .map_err(|_| X4cErrorV4::Overflow)?
                    .checked_add(operation.destination_byte_offset)
                    .ok_or(X4cErrorV4::Overflow)?,
                descriptor: metadata.descriptor_digest,
                cohort_id: metadata.cohort_id,
                source_kind,
                level,
                oracle_kind: OracleKindV4::GlobalFoldAggregate as u8,
                fold_round: metadata.fold_round,
            });
        }
        let operations = self
            .canonical_operations
            .as_ref()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c canonical-operation pool unavailable"))?;
        self.backend.wait_pinned_host_ready(operations)?;
        self.backend.write_pinned_host(operations, 0, &self.operation_staging)?;
        self.backend.x4c_batch_gather_canonical_operations(
            arena.buffer()?,
            operations,
            0,
            self.operation_staging.len(),
            workspace.operation_scratch_offset,
            workspace.mailbox_offset,
            plan.canonical_template.len(),
        )?;
        self.backend
            .download_device::<u8>(
                arena.buffer()?,
                workspace.mailbox_offset,
                plan.canonical_template.len(),
            )
            .map_err(Into::into)
    }

    fn proof_ready_census(
        &mut self,
        arena: &Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4> {
        if arena.reset
            || arena.capacity_bytes != layout.capacity_bytes
            || !self.arena_live
            || !arena.buffer()?.is_owned_by(self.backend)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA proof-ready ownership"));
        }
        self.census(layout, true)
    }

    fn reset_arena(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<(), X4cErrorV4> {
        if arena.reset || arena.capacity_bytes != layout.capacity_bytes || !self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA arena reset"));
        }
        self.backend.x4c_arena_reset(
            arena.buffer()?,
            0,
            x4c_usize_v4(layout.capacity_bytes)?,
            true,
        )?;
        self.backend.x4c_session_reusable_boundary()?;
        arena.reset = true;
        Ok(())
    }

    fn release_arena(
        &mut self,
        mut arena: Self::Arena,
        layout: &X4cArenaLayoutV4,
        _proof_ready: &X4cArenaCensusV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4> {
        if !arena.reset || arena.capacity_bytes != layout.capacity_bytes || !self.arena_live {
            return Err(X4cErrorV4::InvalidGeometry("X4c CUDA arena release"));
        }
        let buffer = arena
            .buffer
            .take()
            .ok_or(X4cErrorV4::InvalidGeometry("X4c CUDA arena released twice"))?;
        self.backend.free_device(buffer)?;
        self.arena_live = false;
        self.census(layout, false)
    }
}

/// CPU-only arena oracle for local end-to-end byte tests.  It deliberately
/// cannot produce a record-eligible runtime census; production uses the CUDA
/// implementation of [`X4cArenaRuntimeV4`].
#[derive(Debug, Default)]
pub struct X4cCpuReferenceRuntimeV4;

#[derive(Debug)]
pub struct X4cCpuReferenceArenaV4 {
    capacity_bytes: u64,
    rounds: Vec<Option<X4cCpuReferenceRoundV4>>,
    reset: bool,
}

#[derive(Debug)]
struct X4cCpuReferenceRoundV4 {
    codeword: Vec<Fp2>,
    tree: Option<CohortTreeV4>,
}

impl X4cArenaRuntimeV4 for X4cCpuReferenceRuntimeV4 {
    type Arena = X4cCpuReferenceArenaV4;

    fn allocate_arena(&mut self, layout: &X4cArenaLayoutV4) -> Result<Self::Arena, X4cErrorV4> {
        layout.validate()?;
        Ok(X4cCpuReferenceArenaV4 {
            capacity_bytes: layout.capacity_bytes,
            rounds: (0..layout.rounds.len()).map(|_| None).collect(),
            reset: false,
        })
    }

    fn direct_fold_host(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        input: &[Fp2],
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4> {
        if input.len() != round.input_len {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU first fold"));
        }
        let output = fold_codeword(input, challenge)
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c CPU first fold"))?;
        cpu_reference_store_round_v4(arena, round, output)
    }

    fn direct_fold_resident(
        &mut self,
        arena: &mut Self::Arena,
        previous: &X4cArenaRoundV4,
        round: &X4cArenaRoundV4,
        challenge: Fp2,
    ) -> Result<(), X4cErrorV4> {
        let previous_codeword = cpu_reference_round_v4(arena, previous)?.codeword.as_slice();
        if previous_codeword.len() != round.input_len {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU resident fold"));
        }
        let output = fold_codeword(previous_codeword, challenge)
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c CPU resident fold"))?;
        cpu_reference_store_round_v4(arena, round, output)
    }

    fn add_activation(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        codeword: &[Fp2],
        activation: Fp2,
    ) -> Result<(), X4cErrorV4> {
        let resident = &mut cpu_reference_round_mut_v4(arena, round)?.codeword;
        if codeword.len() != resident.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU activation"));
        }
        for (output, value) in resident.iter_mut().zip(codeword) {
            *output += activation * *value;
        }
        Ok(())
    }

    fn build_one_slot_n4(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        descriptor: Digest,
        cohort_id: u32,
    ) -> Result<Digest, X4cErrorV4> {
        let resident = cpu_reference_round_mut_v4(arena, round)?;
        if resident.tree.is_some() {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU duplicate N4 build"));
        }
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round: round.fold_round,
            },
            slot_descriptors: vec![Some(descriptor)],
            outer_len: round.output_len,
            expected_symbol_count: 1,
        };
        let tree = CohortTreeV4::build_flat_with_cache_policy(
            config,
            vec![Some(resident.codeword.clone())],
            OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL,
        )
        .map_err(|_| X4cErrorV4::InvalidGeometry("X4c CPU N4 build"))?;
        if tree
            .outer_cache_bytes()
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c CPU N4 cache bytes"))?
            != round.retained_outer_bytes()?
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU N4 cache bytes"));
        }
        let root = tree.root();
        resident.tree = Some(tree);
        Ok(root)
    }

    fn gather_samples(
        &mut self,
        arena: &mut Self::Arena,
        round: &X4cArenaRoundV4,
        indices: &[u64],
    ) -> Result<Vec<Fp2>, X4cErrorV4> {
        let resident = cpu_reference_round_v4(arena, round)?;
        indices
            .iter()
            .map(|index| {
                resident
                    .codeword
                    .get(usize::try_from(*index).map_err(|_| X4cErrorV4::Overflow)?)
                    .copied()
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU sample"))
            })
            .collect()
    }

    fn gather_canonical_opening(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
        plan: &X4cCanonicalGatherPlanV4,
    ) -> Result<Vec<u8>, X4cErrorV4> {
        let sources = layout
            .rounds
            .iter()
            .map(|round| {
                let resident = cpu_reference_round_v4(arena, round)?;
                let tree = resident
                    .tree
                    .as_ref()
                    .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU missing N4 tree"))?;
                Ok(X4cCpuGatherRoundSourceV4 {
                    codeword: &resident.codeword,
                    outer_cache: tree.outer_cache(),
                })
            })
            .collect::<Result<Vec<_>, X4cErrorV4>>()?;
        materialize_x4c_gather_plan_cpu_v4(plan, layout, &sources)
    }

    fn proof_ready_census(
        &mut self,
        arena: &Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4> {
        if arena.reset
            || arena.capacity_bytes != layout.capacity_bytes
            || arena.rounds.iter().any(Option::is_none)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU proof-ready arena"));
        }
        Ok(X4cArenaCensusV4 {
            arena_capacity_bytes: layout.capacity_bytes,
            arena_committed_bytes: layout.capacity_bytes,
            arena_peak_bytes: layout.capacity_bytes,
            logical_allocation_count: 1,
            outstanding_allocation_count: 1,
            outstanding_bytes: layout.capacity_bytes,
            ..X4cArenaCensusV4::default()
        })
    }

    fn reset_arena(
        &mut self,
        arena: &mut Self::Arena,
        layout: &X4cArenaLayoutV4,
    ) -> Result<(), X4cErrorV4> {
        if arena.reset || arena.capacity_bytes != layout.capacity_bytes {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU arena reset"));
        }
        arena.rounds.iter_mut().for_each(|round| *round = None);
        arena.reset = true;
        Ok(())
    }

    fn release_arena(
        &mut self,
        arena: Self::Arena,
        layout: &X4cArenaLayoutV4,
        proof_ready: &X4cArenaCensusV4,
    ) -> Result<X4cArenaCensusV4, X4cErrorV4> {
        if !arena.reset
            || arena.capacity_bytes != layout.capacity_bytes
            || arena.rounds.iter().any(Option::is_some)
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c CPU arena release"));
        }
        Ok(X4cArenaCensusV4 {
            logical_deallocation_count: 1,
            reset_count: 1,
            zeroed_bytes: layout.capacity_bytes,
            outstanding_allocation_count: 0,
            outstanding_bytes: 0,
            cached_reusable_bytes: layout.capacity_bytes,
            ..*proof_ready
        })
    }
}

fn cpu_reference_round_index_v4(round: &X4cArenaRoundV4) -> Result<usize, X4cErrorV4> {
    usize::from(round.fold_round)
        .checked_sub(1)
        .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU round index"))
}

fn cpu_reference_store_round_v4(
    arena: &mut X4cCpuReferenceArenaV4,
    round: &X4cArenaRoundV4,
    codeword: Vec<Fp2>,
) -> Result<(), X4cErrorV4> {
    if codeword.len() != round.output_len {
        return Err(X4cErrorV4::InvalidGeometry("X4c CPU round output"));
    }
    let slot = arena
        .rounds
        .get_mut(cpu_reference_round_index_v4(round)?)
        .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU round slot"))?;
    if slot.is_some() {
        return Err(X4cErrorV4::InvalidGeometry("X4c CPU duplicate round"));
    }
    *slot = Some(X4cCpuReferenceRoundV4 { codeword, tree: None });
    Ok(())
}

fn cpu_reference_round_v4<'a>(
    arena: &'a X4cCpuReferenceArenaV4,
    round: &X4cArenaRoundV4,
) -> Result<&'a X4cCpuReferenceRoundV4, X4cErrorV4> {
    arena
        .rounds
        .get(cpu_reference_round_index_v4(round)?)
        .and_then(Option::as_ref)
        .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU absent round"))
}

fn cpu_reference_round_mut_v4<'a>(
    arena: &'a mut X4cCpuReferenceArenaV4,
    round: &X4cArenaRoundV4,
) -> Result<&'a mut X4cCpuReferenceRoundV4, X4cErrorV4> {
    arena
        .rounds
        .get_mut(cpu_reference_round_index_v4(round)?)
        .and_then(Option::as_mut)
        .ok_or(X4cErrorV4::InvalidGeometry("X4c CPU absent round"))
}

#[derive(Clone, Debug)]
struct X4cRamOracleV4 {
    slot_symbols: Vec<Option<Vec<Fp2>>>,
}

impl OracleSymbolSourceV4 for X4cRamOracleV4 {
    fn read_symbol(&self, slot: u16, coordinate: u64) -> Result<Fp2, super::merkle::MerkleError> {
        self.slot_symbols
            .get(usize::from(slot))
            .and_then(Option::as_ref)
            .and_then(|symbols| symbols.get(usize::try_from(coordinate).ok()?))
            .copied()
            .ok_or(super::merkle::MerkleError::InvalidOpening("X4c RAM oracle read"))
    }
}

/// File-free initial opening source.  Coefficients support the unchanged
/// claim-line calculation; the encoded oracle and outer cache are ordinary
/// host-RAM session caches.
#[derive(Clone, Debug)]
pub struct X4cRamModelGlobalCohortV4 {
    commitment: ModelGlobalCohortCommitmentV4,
    coefficients: Vec<Option<Vec<Fp2>>>,
    oracle: X4cRamOracleV4,
    outer_cache: DenseOuterNodeCacheV4,
}

impl X4cRamModelGlobalCohortV4 {
    /// Reconstruct the complete host-RAM oracle and full outer cache from the
    /// durable coefficient tier only. The returned owner contains no file
    /// handles or mappings; callers must compare `root()` with the separately
    /// durable root before admitting a response.
    pub fn rebuild_from_coefficients(
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
    ) -> Result<Self, X4cErrorV4> {
        config.validate().map_err(|_| X4cErrorV4::InvalidGeometry("X4c rebuild config"))?;
        if coefficients.len() != config.slot_descriptors.len() {
            return Err(X4cErrorV4::InvalidGeometry("X4c rebuild coefficient slots"));
        }
        let codewords = config
            .slot_descriptors
            .iter()
            .zip(&coefficients)
            .map(|(descriptor, coefficients)| match (descriptor, coefficients) {
                (Some(_), Some(coefficients)) => encode_rate_eighth(coefficients)
                    .map(Some)
                    .map_err(|_| X4cErrorV4::InvalidGeometry("X4c rebuild encode")),
                (None, None) => Ok(None),
                _ => Err(X4cErrorV4::InvalidGeometry("X4c rebuild coefficient presence")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tree = CohortTreeV4::build_flat(config, codewords)
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c rebuild N4"))?;
        let parts = tree.into_lifecycle_parts();
        Self::from_parts(parts.config, coefficients, parts.slot_symbols, parts.outer_cache)
    }

    pub fn rebuild_from_coefficients_checked(
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
        expected_root: Digest,
    ) -> Result<Self, X4cErrorV4> {
        if expected_root == [0; 32] {
            return Err(X4cErrorV4::InvalidGeometry("X4c durable root"));
        }
        let rebuilt = Self::rebuild_from_coefficients(config, coefficients)?;
        if rebuilt.root() != expected_root {
            return Err(X4cErrorV4::InvalidGeometry("X4c durable rebuild root"));
        }
        Ok(rebuilt)
    }

    pub fn from_parts(
        config: CohortVerifierConfigV4,
        coefficients: Vec<Option<Vec<Fp2>>>,
        codewords: Vec<Option<Vec<Fp2>>>,
        outer_cache: DenseOuterNodeCacheV4,
    ) -> Result<Self, X4cErrorV4> {
        config.validate().map_err(|_| X4cErrorV4::InvalidGeometry("X4c RAM config"))?;
        if matches!(config.identity.oracle_kind, OracleKindV4::GlobalFoldAggregate)
            || coefficients.len() != config.slot_descriptors.len()
            || codewords.len() != config.slot_descriptors.len()
            || outer_cache.root() == [0; 32]
        {
            return Err(X4cErrorV4::InvalidGeometry("X4c RAM source"));
        }
        let coefficient_len = config.outer_len / 8;
        for ((descriptor, coefficients), codeword) in
            config.slot_descriptors.iter().zip(&coefficients).zip(&codewords)
        {
            match (descriptor, coefficients, codeword) {
                (Some(_), Some(coefficients), Some(codeword))
                    if coefficients.len() == coefficient_len
                        && codeword.len() == config.outer_len => {}
                (None, None, None) => {}
                _ => return Err(X4cErrorV4::InvalidGeometry("X4c RAM slot geometry")),
            }
        }
        let commitment = ModelGlobalCohortCommitmentV4 { root: outer_cache.root(), config };
        Ok(Self {
            commitment,
            coefficients,
            oracle: X4cRamOracleV4 { slot_symbols: codewords },
            outer_cache,
        })
    }

    pub fn host_oracle_bytes(&self) -> Result<u64, X4cErrorV4> {
        self.oracle.slot_symbols.iter().try_fold(0u64, |sum, slot| {
            let bytes = slot.as_ref().map_or(0u64, |symbols| symbols.len() as u64 * FP2_BYTES);
            sum.checked_add(bytes).ok_or(X4cErrorV4::Overflow)
        })
    }

    pub fn host_outer_cache_bytes(&self) -> Result<u64, X4cErrorV4> {
        self.outer_cache
            .retained_bytes()
            .map_err(|_| X4cErrorV4::InvalidGeometry("X4c RAM outer-cache byte accounting"))
    }

    pub fn root(&self) -> Digest {
        self.commitment.root
    }
}

impl ModelGlobalOpeningSourceV4 for X4cRamModelGlobalCohortV4 {
    fn commitment(&self) -> &ModelGlobalCohortCommitmentV4 {
        &self.commitment
    }

    fn combine_source(
        &self,
        touched_slots: &[u16],
        weights: &[Fp2],
        target_point: &[Fp2],
    ) -> Result<(super::folding_v4::CombinedInitialV4, SourceRecomputeTrafficV4), FoldingErrorV4>
    {
        if touched_slots.is_empty()
            || touched_slots.len() != weights.len()
            || !touched_slots.windows(2).all(|pair| pair[0] < pair[1])
            || target_point.len() != (self.commitment.config.outer_len / 8).ilog2() as usize
        {
            return Err(FoldingErrorV4::InvalidGeometry("X4c RAM combine geometry"));
        }
        let coefficient_len = self.commitment.config.outer_len / 8;
        let mut coefficients = vec![Fp2::ZERO; coefficient_len];
        let mut codeword = vec![Fp2::ZERO; self.commitment.config.outer_len];
        for (slot, weight) in touched_slots.iter().zip(weights) {
            let index = usize::from(*slot);
            let source_coefficients = self
                .coefficients
                .get(index)
                .and_then(Option::as_ref)
                .ok_or(FoldingErrorV4::InvalidGeometry("X4c RAM touched coefficients"))?;
            let source_codeword = self
                .oracle
                .slot_symbols
                .get(index)
                .and_then(Option::as_ref)
                .ok_or(FoldingErrorV4::InvalidGeometry("X4c RAM touched codeword"))?;
            for (output, value) in coefficients.iter_mut().zip(source_coefficients) {
                *output += *weight * *value;
            }
            for (output, value) in codeword.iter_mut().zip(source_codeword) {
                *output += *weight * *value;
            }
        }
        let claimed_value =
            super::ntt::evaluate_multilinear_coefficients(&coefficients, target_point)
                .map_err(|_| FoldingErrorV4::InvalidGeometry("X4c RAM target evaluation"))?;
        Ok((
            super::folding_v4::CombinedInitialV4 { coefficients, codeword, claimed_value },
            SourceRecomputeTrafficV4::default(),
        ))
    }

    fn open_initial_source(
        &self,
        query_draws: &[u64],
        touched_slots: &[u16],
    ) -> Result<(InitialOpeningGroupV4, SourceRecomputeTrafficV4), FoldingErrorV4> {
        let (opening, metrics) = open_initial_from_sources_v4(
            &self.commitment.config,
            query_draws,
            touched_slots,
            &self.oracle,
            &self.outer_cache,
        )?;
        Ok((
            opening,
            SourceRecomputeTrafficV4 {
                outer_cache_bytes_read: metrics
                    .cached_outer_digests_read
                    .checked_mul(DIGEST_BYTES)
                    .ok_or(FoldingErrorV4::Overflow)?,
                inner_trees_rebuilt: metrics.inner_trees_rebuilt,
                outer_frontier_leaves_rebuilt: metrics.outer_frontier_leaves_rebuilt,
                outer_internal_nodes_rebuilt: metrics.outer_internal_nodes_rebuilt,
                ..SourceRecomputeTrafficV4::default()
            },
        ))
    }
}

pub fn validate_x4c_frozen_surface_v4(
    rate: &str,
    query_count: usize,
    pcs_bytes: u64,
    response_bytes: u64,
) -> Result<(), X4cErrorV4> {
    if rate != X4C_RATE_V4
        || query_count != X4C_QUERY_COUNT_V4
        || pcs_bytes != X4C_COMPLETE_PCS_BYTES_V4
        || response_bytes != X4C_RESPONSE_BYTES_V4
        || P != 0xffff_ffff_0000_0001
    {
        return Err(X4cErrorV4::InvalidGeometry("X4c frozen protocol surface"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::folding_v4::{
        global_fold_descriptor_digest_v4, verify_global_folding_v4, CommittedModelGlobalCohortV4,
    };
    use super::super::frame_v4::{
        profile_digest_v4, FoldCommitmentFrameV4, InitialOpeningScheduleV4,
    };
    use super::super::merkle_v4::{CohortIdentityV4, CohortTreeV4, OuterCachePolicyV4};
    use super::super::ntt::fold_codeword;
    use super::*;

    fn symbol(index: usize) -> Fp2 {
        let value = index as u64 + 1;
        Fp2::new(Fp::new(value.wrapping_mul(0x1_0001)), Fp::new(17 * value + 9))
    }

    #[cfg(feature = "cuda")]
    fn x4c_cuda_or_skip() -> Option<Backend> {
        match Backend::cuda_resident_with_timing(
            volta_accel::ResidentTimingPolicy::WallOnlyCounters,
        ) {
            Ok(backend) => Some(backend),
            Err(error) if std::env::var("VOLTA_REQUIRE_CUDA").as_deref() != Ok("1") => {
                eprintln!("skipping X4c CUDA differential: {error}");
                None
            }
            Err(error) => panic!("CUDA is required for X4c differential tests: {error}"),
        }
    }

    #[cfg(feature = "cuda")]
    fn decode_fp2_bytes(bytes: &[u8]) -> Vec<Fp2> {
        assert_eq!(bytes.len() % FP2_BYTES as usize, 0);
        bytes
            .chunks_exact(FP2_BYTES as usize)
            .map(|chunk| {
                let mut c0 = [0u8; 8];
                let mut c1 = [0u8; 8];
                c0.copy_from_slice(&chunk[..8]);
                c1.copy_from_slice(&chunk[8..]);
                Fp2::new(Fp::new(u64::from_le_bytes(c0)), Fp::new(u64::from_le_bytes(c1)))
            })
            .collect()
    }

    #[test]
    fn production_arena_geometry_is_exact_and_one_level_omitted() {
        let layout = X4cArenaLayoutV4::production().unwrap();
        assert_eq!(layout.rounds.len(), 27);
        assert_eq!(layout.rounds[0].output_len, 1 << 29);
        assert_eq!(layout.rounds[26].output_len, 1 << 3);
        assert_eq!(layout.codeword_bytes, X4C_FOLD_CODEWORD_BYTES_V4);
        assert_eq!(layout.outer_cache_bytes, X4C_FOLD_OUTER_CACHE_BYTES_V4);
        assert_eq!(layout.capacity_bytes, X4C_REGISTERED_DEVICE_ANCHOR_BYTES_V4);
        for round in &layout.rounds {
            assert_eq!(round.retained_outer_levels[0].level, 2);
            assert_eq!(round.retained_outer_levels.last().unwrap().node_count, 1);
            assert_eq!(round.retained_outer_levels.last().unwrap().byte_len, 32);
        }
    }

    #[test]
    fn selected_reference_matches_full_direct_fold_at_all_registered_lengths() {
        let challenges = [
            Fp2::ZERO,
            Fp2::ONE,
            Fp2::new(Fp::new(3), Fp::new(11)),
            Fp2::new(Fp::new(P - 1), Fp::new(P - 2)),
        ];
        for log2 in [3u8, 4, 5, 6, 7, 8, 12, 16, 20] {
            let input = (0..1usize << log2).map(symbol).collect::<Vec<_>>();
            let indices = [0, 1, (input.len() / 4) as u64, (input.len() / 2 - 1) as u64];
            for challenge in challenges {
                let full = fold_codeword(&input, challenge).unwrap();
                let selected = direct_fold_selected_v4(&input, challenge, &indices).unwrap();
                let positive =
                    indices.iter().map(|index| input[*index as usize]).collect::<Vec<_>>();
                let negative = indices
                    .iter()
                    .map(|index| input[*index as usize + input.len() / 2])
                    .collect::<Vec<_>>();
                let selected_pairs = direct_fold_selected_pairs_v4(
                    input.len(),
                    challenge,
                    &indices,
                    &positive,
                    &negative,
                )
                .unwrap();
                assert_eq!(
                    selected,
                    indices.iter().map(|index| full[*index as usize]).collect::<Vec<_>>()
                );
                assert_eq!(selected_pairs, selected);
            }
        }
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_host_and_resident_direct_fold_match_cpu_at_registered_lengths() {
        let Some(mut backend) = x4c_cuda_or_skip() else {
            return;
        };
        let challenges = [
            Fp2::ZERO,
            Fp2::ONE,
            Fp2::new(Fp::new(3), Fp::new(11)),
            Fp2::new(Fp::new(P - 1), Fp::new(P - 2)),
        ];
        for log2 in [3u8, 4, 5, 6, 7, 8, 12, 16, 20] {
            let input = (0..1usize << log2).map(symbol).collect::<Vec<_>>();
            let input_raw = input.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
            let input_bytes = input.len() * FP2_BYTES as usize;
            let output_bytes = input_bytes / 2;
            let resident_output_offset = input_bytes;
            let host_output_offset = resident_output_offset + output_bytes;
            let tiled_output_offset = host_output_offset + output_bytes;
            let scratch_offset = tiled_output_offset + output_bytes;
            let arena_bytes = scratch_offset + input_bytes;
            let input_pinned = backend.alloc_pinned_host::<Fp2Repr>(input.len()).unwrap();
            backend.write_pinned_host(&input_pinned, 0, &input_raw).unwrap();
            let arena = backend.alloc_device::<u8>(arena_bytes).unwrap();
            backend.x4c_upload_pinned_into_arena(&input_pinned, 0, &arena, 0, input.len()).unwrap();

            for challenge in challenges {
                let expected = fold_codeword(&input, challenge).unwrap();
                backend
                    .x4c_direct_fold_arena_into_arena(
                        &arena,
                        0,
                        input.len(),
                        resident_output_offset,
                        challenge,
                    )
                    .unwrap();
                backend.wait_pinned_host_ready(&input_pinned).unwrap();
                backend.write_pinned_host(&input_pinned, 0, &input_raw).unwrap();
                backend
                    .x4c_direct_fold_pinned_into_arena(
                        &input_pinned,
                        input.len(),
                        &arena,
                        host_output_offset,
                        scratch_offset,
                        challenge,
                    )
                    .unwrap();
                let tile_outputs = (input.len() / 6).max(1);
                for output_start in (0..input.len() / 2).step_by(tile_outputs) {
                    let count = (input.len() / 2 - output_start).min(tile_outputs);
                    let raw_tile = input[output_start..output_start + count]
                        .iter()
                        .chain(
                            &input[output_start + input.len() / 2
                                ..output_start + input.len() / 2 + count],
                        )
                        .copied()
                        .map(Fp2Repr::from)
                        .collect::<Vec<_>>();
                    backend.wait_pinned_host_ready(&input_pinned).unwrap();
                    backend.write_pinned_host(&input_pinned, 0, &raw_tile).unwrap();
                    backend
                        .x4c_direct_fold_pinned_tile_into_arena(
                            &input_pinned,
                            0,
                            input.len(),
                            output_start,
                            count,
                            &arena,
                            tiled_output_offset,
                            scratch_offset,
                            challenge,
                        )
                        .unwrap();
                }
                let resident = decode_fp2_bytes(
                    &backend
                        .download_device::<u8>(&arena, resident_output_offset, output_bytes)
                        .unwrap(),
                );
                let host = decode_fp2_bytes(
                    &backend
                        .download_device::<u8>(&arena, host_output_offset, output_bytes)
                        .unwrap(),
                );
                let tiled = decode_fp2_bytes(
                    &backend
                        .download_device::<u8>(&arena, tiled_output_offset, output_bytes)
                        .unwrap(),
                );
                assert_eq!(resident, expected);
                assert_eq!(host, expected);
                assert_eq!(tiled, expected);

                let activation = Fp2::new(Fp::new(31), Fp::new(37));
                let activation_source =
                    (0..input.len() / 2).map(|index| symbol(index + 1_000_000)).collect::<Vec<_>>();
                let activated = expected
                    .iter()
                    .zip(&activation_source)
                    .map(|(value, source)| *value + activation * *source)
                    .collect::<Vec<_>>();
                for start in (0..activation_source.len()).step_by(tile_outputs) {
                    let count = (activation_source.len() - start).min(tile_outputs);
                    let raw_tile = activation_source[start..start + count]
                        .iter()
                        .copied()
                        .map(Fp2Repr::from)
                        .collect::<Vec<_>>();
                    backend.wait_pinned_host_ready(&input_pinned).unwrap();
                    backend.write_pinned_host(&input_pinned, 0, &raw_tile).unwrap();
                    backend
                        .x4c_activation_add_pinned_tile_into_arena(
                            &input_pinned,
                            0,
                            &arena,
                            resident_output_offset,
                            activation_source.len(),
                            start,
                            count,
                            scratch_offset,
                            activation,
                        )
                        .unwrap();
                }
                assert_eq!(
                    decode_fp2_bytes(
                        &backend
                            .download_device::<u8>(&arena, resident_output_offset, output_bytes)
                            .unwrap(),
                    ),
                    activated,
                );
            }
            backend.wait_pinned_host_ready(&input_pinned).unwrap();
            backend.free_pinned_host(input_pinned).unwrap();
            backend.free_device(arena).unwrap();
        }
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn cuda_one_slot_n4_root_and_retained_levels_match_cpu() {
        let Some(mut backend) = x4c_cuda_or_skip() else {
            return;
        };
        let descriptor = [0x5au8; 32];
        for output_len in [8usize, 32, 256] {
            let codeword = (0..output_len).map(symbol).collect::<Vec<_>>();
            let config = CohortVerifierConfigV4 {
                identity: CohortIdentityV4 {
                    cohort_id: 0xA500_F001,
                    oracle_kind: OracleKindV4::GlobalFoldAggregate,
                    fold_round: 7,
                },
                slot_descriptors: vec![Some(descriptor)],
                outer_len: output_len,
                expected_symbol_count: 1,
            };
            let cpu =
                CohortTreeV4::build_flat(config.clone(), vec![Some(codeword.clone())]).unwrap();
            let codeword_bytes = output_len * FP2_BYTES as usize;
            let native_layout = X4cOneSlotN4Layout::new(output_len, codeword_bytes).unwrap();
            let arena =
                backend.alloc_device::<u8>(codeword_bytes + native_layout.cache_bytes()).unwrap();
            let pinned = backend.alloc_pinned_host::<Fp2Repr>(output_len).unwrap();
            let raw = codeword.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
            backend.write_pinned_host(&pinned, 0, &raw).unwrap();
            backend.x4c_upload_pinned_into_arena(&pinned, 0, &arena, 0, output_len).unwrap();
            let root = backend
                .x4c_build_one_slot_n4(
                    &arena,
                    0,
                    native_layout,
                    descriptor,
                    config.identity.cohort_id,
                    OracleKindV4::GlobalFoldAggregate as u8,
                    config.identity.fold_round,
                )
                .unwrap();
            assert_eq!(root, cpu.root());
            let retained = backend
                .download_device::<u8>(&arena, codeword_bytes, native_layout.cache_bytes())
                .unwrap();
            for level in 2..=output_len.ilog2() as u8 {
                let relative = native_layout.level_offset_bytes(level).unwrap() - codeword_bytes;
                let nodes = output_len >> level;
                for index in 0..nodes {
                    let start = relative + index * DIGEST_BYTES as usize;
                    let mut observed = [0u8; 32];
                    observed.copy_from_slice(&retained[start..start + DIGEST_BYTES as usize]);
                    assert_eq!(
                        observed,
                        cpu.outer_cache().read_cached_digest(level, index as u64).unwrap()
                    );
                }
            }
            backend.wait_pinned_host_ready(&pinned).unwrap();
            backend.free_pinned_host(pinned).unwrap();
            backend.free_device(arena).unwrap();
        }
    }

    #[test]
    fn parity_sampling_is_exact_unique_and_domain_bound() {
        let plan = X4cDirectFoldSamplePlanV4::derive(
            [1; 32],
            [2; 32],
            7,
            3,
            Fp2::new(Fp::new(3), Fp::new(11)),
            [4; 32],
            1 << 20,
        )
        .unwrap();
        assert_eq!(plan.indices.len(), 64);
        assert_eq!(plan.indices[0], 0);
        assert_eq!(plan.indices[1], (1 << 20) - 1);
        assert_eq!(plan.indices.iter().copied().collect::<BTreeSet<_>>().len(), 64);
        let changed = X4cDirectFoldSamplePlanV4::derive(
            [1; 32],
            [2; 32],
            8,
            3,
            Fp2::new(Fp::new(3), Fp::new(11)),
            [4; 32],
            1 << 20,
        )
        .unwrap();
        assert_ne!(plan.ordered_indices_digest, changed.ordered_indices_digest);
    }

    #[test]
    fn production_sample_geometry_is_exactly_1592_unique_coordinates() {
        let layout = X4cArenaLayoutV4::production().unwrap();
        let mut targets = Vec::with_capacity(layout.rounds.len());
        for round in &layout.rounds {
            let target = round.output_len.min(X4C_DIRECT_FOLD_SAMPLES_PER_ROUND_V4);
            let plan = X4cDirectFoldSamplePlanV4::derive(
                X4C_DESIGN_SHA256_V4,
                [0x77; 32],
                9,
                round.fold_round,
                Fp2::new(Fp::new(3), Fp::new(11)),
                [round.fold_round; 32],
                round.output_len,
            )
            .unwrap();
            assert_eq!(plan.indices.len(), target);
            assert_eq!(plan.indices.iter().copied().collect::<BTreeSet<_>>().len(), target);
            assert_eq!(plan.indices[0], 0);
            assert_eq!(plan.indices[1], round.output_len as u64 - 1);
            targets.push(target);
        }
        assert_eq!(targets.iter().rev().take(3).copied().collect::<Vec<_>>(), vec![8, 16, 32],);
        assert_eq!(targets.iter().sum::<usize>(), 1_592);
        assert_eq!(X4C_DIRECT_FOLD_PRODUCTION_SAMPLES_V4, 1_592);
        assert_eq!(X4C_DIRECT_FOLD_DIAGNOSTIC_GATHER_CALLS_V4, 53);
        assert_eq!(X4C_DIRECT_FOLD_DIAGNOSTIC_SYMBOLS_V4, 4_648);
        assert_eq!(X4C_DIRECT_FOLD_DIAGNOSTIC_INDEX_H2D_BYTES_V4, 37_184);
        assert_eq!(X4C_DIRECT_FOLD_DIAGNOSTIC_VALUE_D2H_BYTES_V4, 74_368);
        X4cSealConfigV4::production([0x77; 32], 0).unwrap();
    }

    #[test]
    fn response_io_hard_zero_rejects_every_legacy_artifact_class() {
        X4cResponseIoCountersV4::default().validate_hard_zero().unwrap();
        let mut bad = X4cResponseIoCountersV4::default();
        bad.staging_files_created = 1;
        assert!(bad.validate_hard_zero().is_err());
        let mut bad = X4cResponseIoCountersV4::default();
        bad.response_e_ntt_calls = 1;
        assert!(bad.validate_hard_zero().is_err());
        let mut bad = X4cResponseIoCountersV4::default();
        bad.cpu_fold_tree_clone_bytes = 16;
        assert!(bad.validate_hard_zero().is_err());
    }

    #[test]
    fn frozen_surface_and_storage_tiers_are_pinned() {
        validate_x4c_frozen_surface_v4("1/8", 111, 2_683_236, 43_953_700).unwrap();
        assert_eq!(
            X4C_PACKED_OPENING_BYTES_V4 + X4C_MANDATORY_NON_QUERY_BYTES_V4,
            X4C_COMPLETE_PCS_BYTES_V4
        );
        assert_eq!(
            X4C_PACKED_OPENING_BYTES_V4 + X4C_FOLD_FRAME_BYTES_V4,
            X4C_GLOBAL_FOLDING_PROOF_BYTES_V4
        );
        assert_eq!(X4C_DURABLE_TIER_BYTES_V4, 9_618_587_808);
        assert_eq!(
            X4C_INITIAL_ORACLE_HOST_BYTES_V4 + X4C_INITIAL_OUTER_CACHE_HOST_BYTES_V4,
            114_043_125_600
        );
        assert_eq!(x4c_pinned_pool_requested_bytes_v4().unwrap(), 1_090_741_982);
    }

    #[test]
    fn canonical_batched_gather_matches_ordinary_opening_byte_for_byte() {
        let descriptor = [9u8; 32];
        let initial_config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 41,
                oracle_kind: OracleKindV4::WeightExtension,
                fold_round: 0,
            },
            slot_descriptors: vec![Some(descriptor)],
            outer_len: 64,
            expected_symbol_count: 1,
        };
        let initial_codeword = (0..64).map(symbol).collect::<Vec<_>>();
        let initial_tree =
            CohortTreeV4::build_flat(initial_config.clone(), vec![Some(initial_codeword.clone())])
                .unwrap();
        let query_draws = vec![7; X4C_QUERY_COUNT_V4];
        let initial_opening = initial_tree.open_initial(&query_draws, &[0]).unwrap();

        let challenges = [
            Fp2::new(Fp::new(3), Fp::new(11)),
            Fp2::new(Fp::new(5), Fp::new(19)),
            Fp2::new(Fp::new(7), Fp::new(23)),
        ];
        let mut codeword = initial_codeword;
        let mut round_codewords = Vec::new();
        let mut round_trees = Vec::new();
        let mut fold_frames = Vec::new();
        for (ordinal, challenge) in challenges.into_iter().enumerate() {
            let input_log2 = codeword.len().ilog2() as u8;
            codeword = fold_codeword(&codeword, challenge).unwrap();
            let fold_round = (ordinal + 1) as u8;
            let config = CohortVerifierConfigV4 {
                identity: CohortIdentityV4 {
                    cohort_id: 77,
                    oracle_kind: OracleKindV4::GlobalFoldAggregate,
                    fold_round,
                },
                slot_descriptors: vec![Some(descriptor)],
                outer_len: codeword.len(),
                expected_symbol_count: 1,
            };
            let tree = CohortTreeV4::build_flat_with_cache_policy(
                config,
                vec![Some(codeword.clone())],
                OuterCachePolicyV4::RAM_DEGRADED_ONE_LEVEL,
            )
            .unwrap();
            fold_frames.push(FoldCommitmentFrameV4 {
                cohort_id: 77,
                oracle_kind: OracleKindV4::GlobalFoldAggregate,
                fold_round,
                input_log2,
                output_log2: codeword.len().ilog2() as u8,
                root_digest: tree.root(),
                ordered_message_symbols: vec![Fp2::ZERO, Fp2::ONE],
            });
            round_codewords.push(codeword.clone());
            round_trees.push(tree);
        }
        let schedule = PackedOpeningScheduleV4 {
            profile_digest: profile_digest_v4(),
            model_root: initial_tree.root(),
            epoch: 3,
            initial_groups: vec![InitialOpeningScheduleV4 {
                cohort_id: initial_config.identity.cohort_id,
                domain_log2: initial_config.outer_depth(),
                slot_count: 1,
                touched_slots: vec![0],
                root_digest: initial_tree.root(),
            }],
            fold_frames,
            draw_width: 6,
            query_draws,
        };
        let layout = X4cArenaLayoutV4::new(6, 3, 1 << 20).unwrap();
        let plan = X4cCanonicalGatherPlanV4::build(
            &schedule,
            vec![initial_opening.clone()],
            descriptor,
            &layout,
        )
        .unwrap();
        let sources = round_codewords
            .iter()
            .zip(&round_trees)
            .map(|(codeword, tree)| X4cCpuGatherRoundSourceV4 {
                codeword,
                outer_cache: tree.outer_cache(),
            })
            .collect::<Vec<_>>();
        let gathered = materialize_x4c_gather_plan_cpu_v4(&plan, &layout, &sources).unwrap();
        let expected_opening = PackedBatchOpeningFrameV4 {
            opening_schedule_digest: opening_schedule_digest_v4(&schedule).unwrap(),
            initial_groups: vec![initial_opening],
            fold_rounds: round_trees
                .iter()
                .map(|tree| tree.open_fold_round(&schedule.query_draws).unwrap())
                .collect(),
        };
        expected_opening.validate_against_schedule(&schedule).unwrap();
        let expected = FrameV4::PackedBatchOpening(expected_opening).encode().unwrap();
        assert_eq!(gathered, expected);
        assert_eq!(decode_v4(&gathered).unwrap(), decode_v4(&expected).unwrap());
        assert!(plan.operations.iter().any(|operation| {
            matches!(operation.source, X4cGatherSourceV4::RebuiltOuterDigest { level: 0 | 1, .. })
        }));
    }

    #[test]
    fn ram_rebuild_source_matches_warm_commitment_and_opening() {
        let descriptor = [0xabu8; 32];
        let config = CohortVerifierConfigV4 {
            identity: CohortIdentityV4 {
                cohort_id: 19,
                oracle_kind: OracleKindV4::Auxiliary,
                fold_round: 0,
            },
            slot_descriptors: vec![Some(descriptor), None],
            outer_len: 64,
            expected_symbol_count: 1,
        };
        let coefficients = (0..8).map(symbol).collect::<Vec<_>>();
        let durable_coefficients = vec![Some(coefficients.clone()), None];
        let warm = super::super::folding_v4::CommittedModelGlobalCohortV4::commit(
            config.clone(),
            durable_coefficients.clone(),
        )
        .unwrap();
        let rebuilt = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
            config.clone(),
            durable_coefficients.clone(),
            warm.commitment().root,
        )
        .unwrap();
        assert!(X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
            config,
            durable_coefficients,
            [0x55; 32],
        )
        .is_err());
        assert_eq!(rebuilt.root(), warm.commitment().root);
        let draws =
            (0..X4C_QUERY_COUNT_V4).map(|index| ((29 * index + 5) & 63) as u64).collect::<Vec<_>>();
        let (warm_opening, _) = warm.open_initial_source(&draws, &[0]).unwrap();
        let (rebuilt_opening, traffic) = rebuilt.open_initial_source(&draws, &[0]).unwrap();
        assert_eq!(rebuilt_opening, warm_opening);
        assert_eq!(traffic.persisted_oracle_bytes_read, 0);
        assert_eq!(traffic.persisted_page_cache_dontneed_bytes, 0);
        assert_eq!(traffic.persisted_page_cache_advice_calls, 0);
        let point = vec![Fp2::new(Fp::new(3), Fp::new(7)); 3];
        let (warm_combined, _) = warm.combine_source(&[0], &[Fp2::ONE], &point).unwrap();
        let (rebuilt_combined, _) = rebuilt.combine_source(&[0], &[Fp2::ONE], &point).unwrap();
        assert_eq!(warm_combined.coefficients, rebuilt_combined.coefficients);
        assert_eq!(warm_combined.codeword, rebuilt_combined.codeword);
        assert_eq!(warm_combined.claimed_value, rebuilt_combined.claimed_value);
    }

    #[test]
    fn arena_census_requires_accounted_reset_and_reuse() {
        let layout = X4cArenaLayoutV4::new(6, 3, 4096).unwrap();
        let proof_ready = X4cArenaCensusV4 {
            arena_capacity_bytes: layout.capacity_bytes,
            arena_committed_bytes: layout.capacity_bytes,
            arena_peak_bytes: layout.capacity_bytes,
            logical_allocation_count: 1,
            outstanding_allocation_count: 1,
            outstanding_bytes: layout.capacity_bytes,
            ..X4cArenaCensusV4::default()
        };
        proof_ready.validate_proof_ready(&layout).unwrap();
        let reusable = X4cArenaCensusV4 {
            logical_deallocation_count: 1,
            reset_count: 1,
            zeroed_bytes: layout.capacity_bytes,
            outstanding_allocation_count: 0,
            outstanding_bytes: 0,
            cached_reusable_bytes: layout.capacity_bytes,
            ..proof_ready
        };
        reusable.validate_session_reusable(&proof_ready, &layout).unwrap();
        let mut hidden = reusable;
        hidden.response_round_allocation_count = 1;
        assert!(hidden.validate_session_reusable(&proof_ready, &layout).is_err());

        let pinned_pool_bytes = x4c_pinned_pool_requested_bytes_v4().unwrap();
        let accelerated_proof_ready = X4cArenaCensusV4 {
            accelerator_available: true,
            backend_baseline_resident_bytes: 4096,
            backend_resident_bytes: 4096 + layout.capacity_bytes,
            backend_baseline_active_device_allocations: 2,
            backend_active_device_allocations: 3,
            backend_baseline_active_pinned_allocations: 7,
            backend_baseline_active_pinned_bytes: 1024,
            backend_active_pinned_allocations: 11,
            backend_active_pinned_bytes: 1024 + pinned_pool_bytes,
            backend_stream_synchronized: true,
            x4c_pinned_pool_allocations: 4,
            x4c_pinned_pool_requested_bytes: pinned_pool_bytes,
            native_peak_device_bytes: layout.capacity_bytes,
            native_resident_alloc_requests: 1,
            ..proof_ready
        };
        accelerated_proof_ready.validate_proof_ready(&layout).unwrap();
        let accelerated_reusable = X4cArenaCensusV4 {
            backend_resident_bytes: 4096,
            backend_cached_resident_bytes: layout.capacity_bytes,
            backend_active_device_allocations: 2,
            backend_cached_device_allocations: 1,
            logical_deallocation_count: 1,
            reset_count: 1,
            zeroed_bytes: layout.capacity_bytes,
            outstanding_allocation_count: 0,
            outstanding_bytes: 0,
            cached_reusable_bytes: layout.capacity_bytes,
            native_resident_free_requests: 1,
            native_arena_reset_calls: 1,
            native_arena_reset_bytes: layout.capacity_bytes,
            native_device_zeroed_bytes: layout.capacity_bytes,
            ..accelerated_proof_ready
        };
        accelerated_reusable.validate_session_reusable(&accelerated_proof_ready, &layout).unwrap();
        let mut extra_pre_response_cache = accelerated_reusable;
        extra_pre_response_cache.cached_reusable_bytes += 2048;
        extra_pre_response_cache.backend_cached_resident_bytes += 2048;
        extra_pre_response_cache
            .validate_session_reusable(&accelerated_proof_ready, &layout)
            .unwrap();
        let mut missing_arena_cache = accelerated_reusable;
        missing_arena_cache.cached_reusable_bytes = layout.capacity_bytes - 1;
        assert!(missing_arena_cache
            .validate_session_reusable(&accelerated_proof_ready, &layout)
            .is_err());
    }

    #[test]
    fn durable_rebuild_x4c_chain_is_byte_identical_to_warm_chain_and_verifies() {
        fn fixture(
            cohort_id: u32,
            outer_len: usize,
            seed: u64,
        ) -> (CohortVerifierConfigV4, Vec<Option<Vec<Fp2>>>) {
            let descriptor = {
                let mut digest = [0u8; 32];
                digest[..4].copy_from_slice(&cohort_id.to_le_bytes());
                digest[4..12].copy_from_slice(&seed.to_le_bytes());
                digest
            };
            let coefficients =
                (0..outer_len / 8).map(|index| symbol(index + seed as usize)).collect::<Vec<_>>();
            (
                CohortVerifierConfigV4 {
                    identity: CohortIdentityV4 {
                        cohort_id,
                        oracle_kind: OracleKindV4::Auxiliary,
                        fold_round: 0,
                    },
                    slot_descriptors: vec![Some(descriptor)],
                    outer_len,
                    expected_symbol_count: 1,
                },
                vec![Some(coefficients)],
            )
        }

        fn run_chain(
            large: &dyn ModelGlobalOpeningSourceV4,
            small: &dyn ModelGlobalOpeningSourceV4,
        ) -> (Vec<u8>, Vec<u64>, u64, std::collections::BTreeMap<&'static str, u64>) {
            let common_point = vec![
                Fp2::new(Fp::new(3), Fp::new(7)),
                Fp2::new(Fp::new(5), Fp::new(11)),
                Fp2::new(Fp::new(13), Fp::new(17)),
            ];
            let groups = vec![
                GlobalProverGroupV4 {
                    cohort: large,
                    touched_slots: vec![0],
                    weights: vec![Fp2::new(Fp::new(19), Fp::new(23))],
                    target_point: common_point.clone(),
                    activation_challenge: Fp2::new(Fp::new(29), Fp::new(31)),
                },
                GlobalProverGroupV4 {
                    cohort: small,
                    touched_slots: vec![0],
                    weights: vec![Fp2::new(Fp::new(37), Fp::new(41))],
                    target_point: common_point[2..].to_vec(),
                    activation_challenge: Fp2::new(Fp::new(43), Fp::new(47)),
                },
            ];
            let descriptor = global_fold_descriptor_digest_v4(
                &groups
                    .iter()
                    .map(|group| {
                        (
                            group.cohort.commitment().config.identity.cohort_id,
                            group.cohort.commitment().root,
                        )
                    })
                    .collect::<Vec<_>>(),
            );
            let model_root = [0x55; 32];
            let epoch = 9;
            let draft = GlobalChainDraftV4::new_interactive(
                model_root,
                epoch,
                77,
                descriptor,
                common_point.clone(),
                groups,
            )
            .unwrap();
            let seed = [0x42; 32];
            let mut prover_tx = Transcript::new(seed);
            let mut runtime = X4cCpuReferenceRuntimeV4;
            let layout = X4cArenaLayoutV4::new(6, 3, 4096).unwrap();
            let sealed = draft
                .seal_interactive_x4c(
                    &mut prover_tx,
                    &mut runtime,
                    X4cSealConfigV4 {
                        design_sha256: X4C_DESIGN_SHA256_V4,
                        clean_source_sha256: [0x77; 32],
                        response_ordinal: 4,
                        arena_layout: layout.clone(),
                    },
                )
                .unwrap();
            assert_eq!(sealed.fold_frames().len(), 3);
            assert_eq!(
                sealed
                    .parity_records()
                    .iter()
                    .map(|round| round.result.comparison_count)
                    .sum::<u64>(),
                32 + 16 + 8
            );
            let challenges = sealed.challenges().clone();
            let selected_draws =
                (0..X4C_QUERY_COUNT_V4).map(|index| (index as u64 * 13) & 63).collect::<Vec<_>>();
            let (proof, verifier_groups, metrics, draws) = sealed
                .issue_queries_x4c(selected_draws.clone(), &mut prover_tx, &mut runtime)
                .unwrap();
            assert_eq!(draws, selected_draws);
            assert_eq!(metrics.io, X4cResponseIoCountersV4::default());
            assert_eq!(metrics.execution.query_gather_calls, 1);
            assert_eq!(metrics.execution.noncanonical_opening_d2h_bytes, 0);
            assert_eq!(metrics.execution.cpu_fold_tree_clone_bytes, 0);
            assert_eq!(metrics.execution.direct_fold_diagnostic_gather_calls, 5);
            assert_eq!(metrics.execution.direct_fold_diagnostic_index_h2d_bytes, 832);
            assert_eq!(metrics.execution.direct_fold_diagnostic_value_d2h_bytes, 1_664);
            assert_eq!(metrics.sampling_soundness_credit_bits, 0);
            metrics
                .session_reusable_arena
                .validate_session_reusable(&metrics.proof_ready_arena, &layout)
                .unwrap();

            verify_global_folding_v4(
                model_root,
                epoch,
                &common_point,
                &verifier_groups,
                &challenges,
                &draws,
                &proof,
            )
            .unwrap();
            let canonical = proof.canonical_bytes().unwrap();
            assert!(!canonical.is_empty());
            (canonical, draws, prover_tx.total_bytes(), prover_tx.ledger().clone())
        }

        let (large_config, large_coefficients) = fixture(10, 64, 100);
        let (small_config, small_coefficients) = fixture(20, 16, 200);
        let warm_large =
            CommittedModelGlobalCohortV4::commit(large_config.clone(), large_coefficients.clone())
                .unwrap();
        let warm_small =
            CommittedModelGlobalCohortV4::commit(small_config.clone(), small_coefficients.clone())
                .unwrap();
        let rebuilt_large = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
            large_config,
            large_coefficients,
            warm_large.commitment().root,
        )
        .unwrap();
        let rebuilt_small = X4cRamModelGlobalCohortV4::rebuild_from_coefficients_checked(
            small_config,
            small_coefficients,
            warm_small.commitment().root,
        )
        .unwrap();
        assert_eq!(rebuilt_large.root(), warm_large.commitment().root);
        assert_eq!(rebuilt_small.root(), warm_small.commitment().root);

        let warm = run_chain(&warm_large, &warm_small);
        let rebuilt = run_chain(&rebuilt_large, &rebuilt_small);
        assert_eq!(rebuilt, warm);
    }
}
