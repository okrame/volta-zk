use super::{
    AccelError, BackendStats, DeviceMemoryBreakdown, DeviceTimingMode, Fp2Repr, Operation,
    OperationStats, TimingCapacityPreflight, CUDA_ABI_VERSION, DEFERRED_TIMING_CAPACITY,
    OPERATION_COUNT,
};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;
use volta_field::{Fp, Fp2};

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
    fn dlclose(handle: *mut c_void) -> c_int;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawStats {
    calls: [u64; OPERATION_COUNT],
    kernel_ns: [u64; OPERATION_COUNT],
    h2d_bytes: u64,
    d2h_bytes: u64,
    d2d_bytes: u64,
    device_zeroed_bytes: u64,
    device_generated_bytes: u64,
    h2d_ns: u64,
    d2h_ns: u64,
    synchronizations: u64,
    synchronization_ns: u64,
    sync_host_output: u64,
    sync_upload_lifetime: u64,
    sync_timing_flush: u64,
    sync_profiling_legacy: u64,
    sync_allocator_flush: u64,
    allocation_calls: u64,
    resident_alloc_requests: u64,
    resident_reuse_hits: u64,
    resident_free_requests: u64,
    physical_free_calls: u64,
    live_device_bytes: u64,
    peak_device_bytes: u64,
    timing_records: u64,
    timing_elapsed_query_attempts: u64,
    timing_elapsed_no_write: u64,
    timing_event_queries: u64,
    timing_pending_high_water: u64,
    timing_flush_count: u64,
    coarse_timing_scopes: u64,
    coarse_timing_ns: u64,
    timing_mode: u32,
    reserved: u32,
}

const _: () = assert!(std::mem::size_of::<RawStats>() == 352);

type AbiVersion = unsafe extern "C" fn() -> u32;
type Create = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
type Destroy = unsafe extern "C" fn(*mut c_void);
type LastError = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type EnableDeferredProfiling = unsafe extern "C" fn(*mut c_void) -> c_int;
#[cfg(test)]
type TestInjectElapsedNoWriteOnce = unsafe extern "C" fn(*mut c_void) -> c_int;
type BeginCoarseTiming = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type EndCoarseTiming = unsafe extern "C" fn(*mut c_void) -> c_int;
type AbortCoarseTiming = unsafe extern "C" fn(*mut c_void) -> c_int;
type EnsureTimingCapacity =
    unsafe extern "C" fn(*mut c_void, usize, *mut usize, *mut usize, *mut c_int) -> c_int;
type FlushProfiling = unsafe extern "C" fn(*mut c_void) -> c_int;
type ResetStats = unsafe extern "C" fn(*mut c_void) -> c_int;
type GetStats = unsafe extern "C" fn(*mut c_void, *mut RawStats) -> c_int;
type MemoryBreakdown = unsafe extern "C" fn(*mut c_void, *mut u64, *mut u64, *mut u64) -> c_int;
type TrimResidentCache = unsafe extern "C" fn(*mut c_void) -> c_int;
type ResidentAlloc = unsafe extern "C" fn(*mut c_void, usize, *mut u64) -> c_int;
type ResidentFree = unsafe extern "C" fn(*mut c_void, u64) -> c_int;
type ResidentUpload = unsafe extern "C" fn(*mut c_void, u64, usize, *const c_void, usize) -> c_int;
type ResidentDownload = unsafe extern "C" fn(*mut c_void, u64, usize, *mut c_void, usize) -> c_int;
type ResidentZero = unsafe extern "C" fn(*mut c_void, u64, usize, usize) -> c_int;
type ResidentCopyRows =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize, usize, usize, usize) -> c_int;
type ResidentMailboxCopyRows = ResidentCopyRows;
type Chacha8ProverSecretFpRowsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, *const u8, u64, usize, usize) -> c_int;
type MockCorrelationSubMasksDevice = Chacha8ProverSecretFpRowsDevice;
type Chacha8ProverSecretFp2RowsPaddedDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, *const u8, u64, usize, usize, usize) -> c_int;
type Fp2RowDotsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    usize,
    u64,
    usize,
    usize,
    u64,
    usize,
    usize,
    usize,
) -> c_int;
type Fp2PowersDevice = unsafe extern "C" fn(*mut c_void, u64, u64, u64, usize, usize) -> c_int;
type GemmI64 = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const i16,
    *mut i64,
    usize,
    usize,
    usize,
) -> c_int;
type GemmI64Device = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
) -> c_int;
type GemmRequantAuth = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const i16,
    *const u64,
    *mut i16,
    *mut u64,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type GemmRequantAuthDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type FixedEmbedDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    i32,
) -> c_int;
type FixedLayerNormDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize, // input
    u64,
    usize, // gain
    u64,
    usize, // bias
    u64,
    usize, // LUT
    u64,
    usize, // mean
    u64,
    usize, // variance
    u64,
    usize, // rsqrt input
    u64,
    usize, // rsqrt output
    u64,
    usize, // affine accumulator
    u64,
    usize, // requantized output
    u64,
    usize, // error flag
    usize,
    usize,
    u32,
    u32,
) -> c_int;
type FixedGemmDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type FixedQkvSplitDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
) -> c_int;
type FixedAttentionScoresDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type FixedSoftmaxDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    u32,
    u32,
    c_int,
) -> c_int;
type FixedAvDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    u32,
) -> c_int;
type FixedLookupDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, u64, usize, usize) -> c_int;
type FixedRequantI16Device =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, u64, usize, usize, u32) -> c_int;
type FixedLogitsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
) -> c_int;
type SubfieldCorrectionsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, u64, usize, usize, c_int) -> c_int;
type PadBaseVectorDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, usize, u64, c_int) -> c_int;
type MatrixFoldDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    c_int,
    c_int,
) -> c_int;
type Fp2DotDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, *mut Fp2Repr) -> c_int;
type Fp2ProductRoundDevice = Fp2DotDevice;
type Fp2ProductRoundIntoDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, u64, usize) -> c_int;
type Fp2TripleProductRoundDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    *mut Fp2Repr,
) -> c_int;
type Fp2TripleProductRoundIntoDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    u64,
    usize,
) -> c_int;
type LnHadamardFactorsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> c_int;
type BaseBroadcastFp2Device =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, usize, c_int) -> c_int;
type RepeatVectorDevice = BaseBroadcastFp2Device;
type CompactStridedRowsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, usize, usize, c_int) -> c_int;
type AttentionAboveMaskDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
    usize,
) -> c_int;
#[repr(C)]
struct RawAttentionProofWiresArgs {
    q_id: u64,
    q_offset: usize,
    k_cache_id: u64,
    k_cache_offset: usize,
    own_k_id: u64,
    own_k_offset: usize,
    v_id: u64,
    v_offset: usize,
    scores_acc_id: u64,
    scores_acc_offset: usize,
    scores_q_id: u64,
    scores_q_offset: usize,
    row_shifts_id: u64,
    row_shifts_offset: usize,
    exp_outputs_id: u64,
    exp_outputs_offset: usize,
    denoms_id: u64,
    denoms_offset: usize,
    recips_id: u64,
    recips_offset: usize,
    softmax_weights_id: u64,
    softmax_weights_offset: usize,
    recip_lut_id: u64,
    recip_lut_offset: usize,
    qkv_acc_id: u64,
    qkv_acc_offset: usize,
    error_id: u64,
    error_offset: usize,
    rect_id: u64,
    rect_offset: usize,
    rows_id: u64,
    rows_offset: usize,
    above_id: u64,
    above_offset: usize,
    qkv_id: u64,
    qkv_offset: usize,
    query_rows: usize,
    seq: usize,
    pos0: usize,
    heads: usize,
    head_pad: usize,
    head_dim: usize,
    query_pad: usize,
    seq_pad: usize,
    d_pad: usize,
    shift_scores: u32,
    shift_softmax_norm: u32,
    shift_qkv: u32,
    recip_den_shift: u32,
    exp_pad_input: c_int,
    recip_pad_output: c_int,
    use_row_shift: c_int,
}
type AttentionProofWiresDevice =
    unsafe extern "C" fn(*mut c_void, *const RawAttentionProofWiresArgs) -> c_int;
type RequantColumnsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    c_int,
    u32,
) -> c_int;
type PairColumnsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    u64,
    u64,
    c_int,
    c_int,
) -> c_int;
type HistogramFpDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, usize) -> c_int;
type HistogramLutDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, c_int) -> c_int;
type U32AddInplaceDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize) -> c_int;
type PackLookupLeafDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    u64,
) -> c_int;
type DeinterleaveBaseColumnsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize, usize) -> c_int;
type NttFp = unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, *mut u64) -> c_int;
type NttFpBatch =
    unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, usize, *mut u64) -> c_int;
type NttFp2 =
    unsafe extern "C" fn(*mut c_void, *const Fp2Repr, usize, usize, *mut Fp2Repr) -> c_int;
type NttBatchDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, usize, u64, usize) -> c_int;
type LogupTree = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    *const u32,
    usize,
    u64,
    c_int,
    *mut Fp2Repr,
    *mut Fp2Repr,
) -> c_int;
type LogupTreeDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    usize,
    u64,
    c_int,
    u64,
    usize,
    u64,
    usize,
) -> c_int;
type LogupMaterializeLeavesDevice = LogupTreeDevice;
type LogupGeneralRound = unsafe extern "C" fn(
    *mut c_void,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    usize,
    *mut Fp2Repr,
) -> c_int;
type LogupGeneralRoundDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    *mut Fp2Repr,
) -> c_int;
type LogupGeneralRoundIntoDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    u64,
    usize,
) -> c_int;
type LogupFold4 = unsafe extern "C" fn(
    *mut c_void,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    *const Fp2Repr,
    usize,
    Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
    *mut Fp2Repr,
) -> c_int;
type LogupFold4Device = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    Fp2Repr,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
) -> c_int;
type Fp2DeinterleaveDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize, u64, usize) -> c_int;
type LogupSuffixEqDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize) -> c_int;
type Fp2FoldRowsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, usize, Fp2Repr, u64, usize) -> c_int;
type LogupEqRowsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, usize, u64, usize) -> c_int;
type LogupAuxRoundDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    Fp2Repr,
    Fp2Repr,
    Fp2Repr,
    *mut Fp2Repr,
) -> c_int;
type LogupAuxRoundIntoDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    Fp2Repr,
    Fp2Repr,
    Fp2Repr,
    u64,
    usize,
) -> c_int;
type HashFpColumns = unsafe extern "C" fn(*mut c_void, *const u64, usize, usize, *mut u8) -> c_int;
type PcsCombineRows = unsafe extern "C" fn(
    *mut c_void,
    *const i16,
    *const u64,
    *const Fp2Repr,
    usize,
    usize,
    usize,
    usize,
    *mut Fp2Repr,
) -> c_int;
type PcsGatherColumns = unsafe extern "C" fn(
    *mut c_void,
    *const u64,
    usize,
    usize,
    *const u32,
    usize,
    *mut u64,
) -> c_int;
type PcsMessagesDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    u64,
    usize,
) -> c_int;
type PcsCombineRowsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    u64,
    usize,
    u64,
    usize,
    usize,
    usize,
    usize,
    usize,
    u64,
    usize,
) -> c_int;
type Fp2AddInplaceDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, u64, usize, usize) -> c_int;
type HashTreeDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, usize, u64, usize) -> c_int;
type MerklePathsDevice =
    unsafe extern "C" fn(*mut c_void, u64, usize, usize, u64, usize, usize, u64, usize) -> c_int;
type PcsGatherColumnsDevice = unsafe extern "C" fn(
    *mut c_void,
    u64,
    usize,
    usize,
    usize,
    u64,
    usize,
    usize,
    u64,
    usize,
    c_int,
) -> c_int;
type ReserveFp2ProductRoundWorkspace = unsafe extern "C" fn(*mut c_void, usize) -> c_int;
type ReserveLogupRoundWorkspace = unsafe extern "C" fn(*mut c_void, usize) -> c_int;

struct Api {
    handle: *mut c_void,
    create: Create,
    destroy: Destroy,
    last_error: LastError,
    enable_deferred_profiling: EnableDeferredProfiling,
    #[cfg(test)]
    test_inject_elapsed_no_write_once: TestInjectElapsedNoWriteOnce,
    begin_coarse_timing: BeginCoarseTiming,
    end_coarse_timing: EndCoarseTiming,
    abort_coarse_timing: AbortCoarseTiming,
    ensure_timing_capacity: EnsureTimingCapacity,
    flush_profiling: FlushProfiling,
    reset_stats: ResetStats,
    get_stats: GetStats,
    memory_breakdown: MemoryBreakdown,
    trim_resident_cache: TrimResidentCache,
    resident_alloc: ResidentAlloc,
    resident_free: ResidentFree,
    resident_upload: ResidentUpload,
    resident_download: ResidentDownload,
    resident_zero: ResidentZero,
    resident_copy_rows: ResidentCopyRows,
    resident_mailbox_copy_rows: ResidentMailboxCopyRows,
    chacha8_prover_secret_fp_rows_device: Chacha8ProverSecretFpRowsDevice,
    mock_correlation_sub_masks_device: MockCorrelationSubMasksDevice,
    chacha8_prover_secret_fp2_rows_padded_device: Chacha8ProverSecretFp2RowsPaddedDevice,
    fp2_row_dots_device: Fp2RowDotsDevice,
    fp2_powers_device: Fp2PowersDevice,
    gemm_i64: GemmI64,
    gemm_i64_device: GemmI64Device,
    gemm_requant_auth: GemmRequantAuth,
    gemm_requant_auth_device: GemmRequantAuthDevice,
    fixed_embed_device: FixedEmbedDevice,
    fixed_layer_norm_device: FixedLayerNormDevice,
    fixed_gemm_device: FixedGemmDevice,
    fixed_qkv_split_device: FixedQkvSplitDevice,
    fixed_attention_scores_device: FixedAttentionScoresDevice,
    fixed_softmax_device: FixedSoftmaxDevice,
    fixed_av_device: FixedAvDevice,
    fixed_lookup_device: FixedLookupDevice,
    fixed_requant_i16_device: FixedRequantI16Device,
    fixed_logits_device: FixedLogitsDevice,
    subfield_corrections_device: SubfieldCorrectionsDevice,
    pad_base_vector_device: PadBaseVectorDevice,
    matrix_fold_device: MatrixFoldDevice,
    fp2_dot_device: Fp2DotDevice,
    fp2_product_round_device: Fp2ProductRoundDevice,
    fp2_product_round_into_device: Fp2ProductRoundIntoDevice,
    reserve_fp2_product_round_workspace: ReserveFp2ProductRoundWorkspace,
    reserve_logup_round_workspace: ReserveLogupRoundWorkspace,
    fp2_triple_product_round_device: Fp2TripleProductRoundDevice,
    fp2_triple_product_round_into_device: Fp2TripleProductRoundIntoDevice,
    ln_hadamard_factors_device: LnHadamardFactorsDevice,
    base_broadcast_fp2_device: BaseBroadcastFp2Device,
    repeat_vector_device: RepeatVectorDevice,
    compact_strided_rows_device: CompactStridedRowsDevice,
    attention_above_mask_device: AttentionAboveMaskDevice,
    attention_proof_wires_device: AttentionProofWiresDevice,
    requant_columns_device: RequantColumnsDevice,
    pair_columns_device: PairColumnsDevice,
    histogram_fp_device: HistogramFpDevice,
    histogram_lut_device: HistogramLutDevice,
    u32_add_inplace_device: U32AddInplaceDevice,
    pack_lookup_leaf_device: PackLookupLeafDevice,
    deinterleave_base_columns_device: DeinterleaveBaseColumnsDevice,
    ntt_fp: NttFp,
    ntt_fp_batch: NttFpBatch,
    ntt_fp2: NttFp2,
    ntt_fp_batch_device: NttBatchDevice,
    ntt_fp2_batch_device: NttBatchDevice,
    logup_tree: LogupTree,
    logup_tree_device: LogupTreeDevice,
    logup_materialize_leaves_device: LogupMaterializeLeavesDevice,
    logup_general_round: LogupGeneralRound,
    logup_general_round_device: LogupGeneralRoundDevice,
    logup_general_round_into_device: LogupGeneralRoundIntoDevice,
    logup_fold4: LogupFold4,
    logup_fold4_device: LogupFold4Device,
    fp2_deinterleave_device: Fp2DeinterleaveDevice,
    logup_suffix_eq_device: LogupSuffixEqDevice,
    fp2_fold_rows_device: Fp2FoldRowsDevice,
    logup_eq_rows_device: LogupEqRowsDevice,
    logup_aux_round_device: LogupAuxRoundDevice,
    logup_aux_round_into_device: LogupAuxRoundIntoDevice,
    pcs_combine_rows: PcsCombineRows,
    pcs_gather_columns: PcsGatherColumns,
    hash_fp_columns: HashFpColumns,
    pcs_messages_device: PcsMessagesDevice,
    pcs_combine_rows_device: PcsCombineRowsDevice,
    fp2_add_inplace_device: Fp2AddInplaceDevice,
    hash_fp_tree_device: HashTreeDevice,
    hash_fp2_tree_device: HashTreeDevice,
    merkle_paths_device: MerklePathsDevice,
    pcs_gather_columns_device: PcsGatherColumnsDevice,
}

pub(super) struct CudaContext {
    raw: *mut c_void,
    api: Api,
}

impl CudaContext {
    pub(super) fn load() -> Result<CudaContext, AccelError> {
        let path = std::env::var("VOLTA_CUDA_LIBRARY")
            .unwrap_or_else(|_| "libvolta_cuda_backend.so".to_owned());
        let cpath = CString::new(path.clone())
            .map_err(|_| AccelError::LibraryLoad("library path contains NUL".to_owned()))?;
        // SAFETY: cpath is NUL terminated and remains alive for this call.
        let handle = unsafe { dlopen(cpath.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if handle.is_null() {
            return Err(AccelError::LibraryLoad(format!("{path}: {}", dl_error())));
        }
        let api_result = unsafe { Self::load_api(handle) };
        let api = match api_result {
            Ok(api) => api,
            Err(e) => {
                // SAFETY: handle was returned by dlopen and is not otherwise owned.
                unsafe { dlclose(handle) };
                return Err(e);
            }
        };
        let mut raw = ptr::null_mut();
        // SAFETY: function pointer and out parameter follow the versioned C ABI.
        let rc = unsafe { (api.create)(&mut raw) };
        if rc != 0 || raw.is_null() {
            let msg = if raw.is_null() {
                format!("initialization failed with status {rc}")
            } else {
                // SAFETY: raw came from the backend and last_error accepts it.
                unsafe { c_error((api.last_error)(raw), rc) }
            };
            if !raw.is_null() {
                // SAFETY: partially initialized context is owned here.
                unsafe { (api.destroy)(raw) };
            }
            // SAFETY: api.handle remains live and is owned here.
            unsafe { dlclose(api.handle) };
            return Err(AccelError::Cuda(msg));
        }
        Ok(CudaContext { raw, api })
    }

    unsafe fn load_api(handle: *mut c_void) -> Result<Api, AccelError> {
        let abi: AbiVersion = unsafe { load_symbol(handle, b"volta_cuda_abi_version\0")? };
        // SAFETY: loaded symbol has the declared ABI by contract.
        let found = unsafe { abi() };
        if found != CUDA_ABI_VERSION {
            return Err(AccelError::AbiMismatch { expected: CUDA_ABI_VERSION, found });
        }
        Ok(Api {
            handle,
            create: unsafe { load_symbol(handle, b"volta_cuda_create\0")? },
            destroy: unsafe { load_symbol(handle, b"volta_cuda_destroy\0")? },
            last_error: unsafe { load_symbol(handle, b"volta_cuda_last_error\0")? },
            enable_deferred_profiling: unsafe {
                load_symbol(handle, b"volta_cuda_enable_deferred_profiling\0")?
            },
            #[cfg(test)]
            test_inject_elapsed_no_write_once: unsafe {
                load_symbol(handle, b"volta_cuda_test_inject_elapsed_no_write_once\0")?
            },
            begin_coarse_timing: unsafe {
                load_symbol(handle, b"volta_cuda_begin_coarse_timing\0")?
            },
            end_coarse_timing: unsafe { load_symbol(handle, b"volta_cuda_end_coarse_timing\0")? },
            abort_coarse_timing: unsafe {
                load_symbol(handle, b"volta_cuda_abort_coarse_timing\0")?
            },
            ensure_timing_capacity: unsafe {
                load_symbol(handle, b"volta_cuda_ensure_timing_capacity\0")?
            },
            flush_profiling: unsafe { load_symbol(handle, b"volta_cuda_flush_profiling\0")? },
            reset_stats: unsafe { load_symbol(handle, b"volta_cuda_reset_stats\0")? },
            get_stats: unsafe { load_symbol(handle, b"volta_cuda_get_stats\0")? },
            memory_breakdown: unsafe { load_symbol(handle, b"volta_cuda_memory_breakdown\0")? },
            trim_resident_cache: unsafe {
                load_symbol(handle, b"volta_cuda_trim_resident_cache\0")?
            },
            resident_alloc: unsafe { load_symbol(handle, b"volta_cuda_resident_alloc\0")? },
            resident_free: unsafe { load_symbol(handle, b"volta_cuda_resident_free\0")? },
            resident_upload: unsafe { load_symbol(handle, b"volta_cuda_resident_upload\0")? },
            resident_download: unsafe { load_symbol(handle, b"volta_cuda_resident_download\0")? },
            resident_zero: unsafe { load_symbol(handle, b"volta_cuda_resident_zero\0")? },
            resident_copy_rows: unsafe { load_symbol(handle, b"volta_cuda_resident_copy_rows\0")? },
            resident_mailbox_copy_rows: unsafe {
                load_symbol(handle, b"volta_cuda_resident_mailbox_copy_rows\0")?
            },
            chacha8_prover_secret_fp_rows_device: unsafe {
                load_symbol(handle, b"volta_cuda_chacha8_prover_secret_fp_rows_device\0")?
            },
            mock_correlation_sub_masks_device: unsafe {
                load_symbol(handle, b"volta_cuda_mock_correlation_sub_masks_device\0")?
            },
            chacha8_prover_secret_fp2_rows_padded_device: unsafe {
                load_symbol(handle, b"volta_cuda_chacha8_prover_secret_fp2_rows_padded_device\0")?
            },
            fp2_row_dots_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_row_dots_device\0")?
            },
            fp2_powers_device: unsafe { load_symbol(handle, b"volta_cuda_fp2_powers_device\0")? },
            gemm_i64: unsafe { load_symbol(handle, b"volta_cuda_gemm_i64\0")? },
            gemm_i64_device: unsafe { load_symbol(handle, b"volta_cuda_gemm_i64_device\0")? },
            gemm_requant_auth: unsafe { load_symbol(handle, b"volta_cuda_gemm_requant_auth\0")? },
            gemm_requant_auth_device: unsafe {
                load_symbol(handle, b"volta_cuda_gemm_requant_auth_device\0")?
            },
            fixed_embed_device: unsafe { load_symbol(handle, b"volta_cuda_fixed_embed_device\0")? },
            fixed_layer_norm_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_layer_norm_device\0")?
            },
            fixed_gemm_device: unsafe { load_symbol(handle, b"volta_cuda_fixed_gemm_device\0")? },
            fixed_qkv_split_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_qkv_split_device\0")?
            },
            fixed_attention_scores_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_attention_scores_device\0")?
            },
            fixed_softmax_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_softmax_device\0")?
            },
            fixed_av_device: unsafe { load_symbol(handle, b"volta_cuda_fixed_av_device\0")? },
            fixed_lookup_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_lookup_device\0")?
            },
            fixed_requant_i16_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_requant_i16_device\0")?
            },
            fixed_logits_device: unsafe {
                load_symbol(handle, b"volta_cuda_fixed_logits_device\0")?
            },
            subfield_corrections_device: unsafe {
                load_symbol(handle, b"volta_cuda_subfield_corrections_device\0")?
            },
            pad_base_vector_device: unsafe {
                load_symbol(handle, b"volta_cuda_pad_base_vector_device\0")?
            },
            matrix_fold_device: unsafe { load_symbol(handle, b"volta_cuda_matrix_fold_device\0")? },
            fp2_dot_device: unsafe { load_symbol(handle, b"volta_cuda_fp2_dot_device\0")? },
            fp2_product_round_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_product_round_device\0")?
            },
            fp2_product_round_into_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_product_round_into_device\0")?
            },
            reserve_fp2_product_round_workspace: unsafe {
                load_symbol(handle, b"volta_cuda_reserve_fp2_product_round_workspace\0")?
            },
            reserve_logup_round_workspace: unsafe {
                load_symbol(handle, b"volta_cuda_reserve_logup_round_workspace\0")?
            },
            fp2_triple_product_round_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_triple_product_round_device\0")?
            },
            fp2_triple_product_round_into_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_triple_product_round_into_device\0")?
            },
            ln_hadamard_factors_device: unsafe {
                load_symbol(handle, b"volta_cuda_ln_hadamard_factors_device\0")?
            },
            base_broadcast_fp2_device: unsafe {
                load_symbol(handle, b"volta_cuda_base_broadcast_fp2_device\0")?
            },
            repeat_vector_device: unsafe {
                load_symbol(handle, b"volta_cuda_repeat_vector_device\0")?
            },
            compact_strided_rows_device: unsafe {
                load_symbol(handle, b"volta_cuda_compact_strided_rows_device\0")?
            },
            attention_above_mask_device: unsafe {
                load_symbol(handle, b"volta_cuda_attention_above_mask_device\0")?
            },
            attention_proof_wires_device: unsafe {
                load_symbol(handle, b"volta_cuda_attention_proof_wires_device\0")?
            },
            requant_columns_device: unsafe {
                load_symbol(handle, b"volta_cuda_requant_columns_device\0")?
            },
            pair_columns_device: unsafe {
                load_symbol(handle, b"volta_cuda_pair_columns_device\0")?
            },
            histogram_fp_device: unsafe {
                load_symbol(handle, b"volta_cuda_histogram_fp_device\0")?
            },
            histogram_lut_device: unsafe {
                load_symbol(handle, b"volta_cuda_histogram_lut_device\0")?
            },
            u32_add_inplace_device: unsafe {
                load_symbol(handle, b"volta_cuda_u32_add_inplace_device\0")?
            },
            pack_lookup_leaf_device: unsafe {
                load_symbol(handle, b"volta_cuda_pack_lookup_leaf_device\0")?
            },
            deinterleave_base_columns_device: unsafe {
                load_symbol(handle, b"volta_cuda_deinterleave_base_columns_device\0")?
            },
            ntt_fp: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp\0")? },
            ntt_fp_batch: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp_batch\0")? },
            ntt_fp2: unsafe { load_symbol(handle, b"volta_cuda_ntt_fp2\0")? },
            ntt_fp_batch_device: unsafe {
                load_symbol(handle, b"volta_cuda_ntt_fp_batch_device\0")?
            },
            ntt_fp2_batch_device: unsafe {
                load_symbol(handle, b"volta_cuda_ntt_fp2_batch_device\0")?
            },
            logup_tree: unsafe { load_symbol(handle, b"volta_cuda_logup_tree\0")? },
            logup_tree_device: unsafe { load_symbol(handle, b"volta_cuda_logup_tree_device\0")? },
            logup_materialize_leaves_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_materialize_leaves_device\0")?
            },
            logup_general_round: unsafe {
                load_symbol(handle, b"volta_cuda_logup_general_round\0")?
            },
            logup_general_round_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_general_round_device\0")?
            },
            logup_general_round_into_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_general_round_into_device\0")?
            },
            logup_fold4: unsafe { load_symbol(handle, b"volta_cuda_logup_fold4\0")? },
            logup_fold4_device: unsafe { load_symbol(handle, b"volta_cuda_logup_fold4_device\0")? },
            fp2_deinterleave_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_deinterleave_device\0")?
            },
            logup_suffix_eq_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_suffix_eq_device\0")?
            },
            fp2_fold_rows_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_fold_rows_device\0")?
            },
            logup_eq_rows_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_eq_rows_device\0")?
            },
            logup_aux_round_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_aux_round_device\0")?
            },
            logup_aux_round_into_device: unsafe {
                load_symbol(handle, b"volta_cuda_logup_aux_round_into_device\0")?
            },
            pcs_combine_rows: unsafe { load_symbol(handle, b"volta_cuda_pcs_combine_rows\0")? },
            pcs_gather_columns: unsafe { load_symbol(handle, b"volta_cuda_pcs_gather_columns\0")? },
            hash_fp_columns: unsafe { load_symbol(handle, b"volta_cuda_hash_fp_columns\0")? },
            pcs_messages_device: unsafe {
                load_symbol(handle, b"volta_cuda_pcs_messages_device\0")?
            },
            pcs_combine_rows_device: unsafe {
                load_symbol(handle, b"volta_cuda_pcs_combine_rows_device\0")?
            },
            fp2_add_inplace_device: unsafe {
                load_symbol(handle, b"volta_cuda_fp2_add_inplace_device\0")?
            },
            hash_fp_tree_device: unsafe {
                load_symbol(handle, b"volta_cuda_hash_fp_tree_device\0")?
            },
            hash_fp2_tree_device: unsafe {
                load_symbol(handle, b"volta_cuda_hash_fp2_tree_device\0")?
            },
            merkle_paths_device: unsafe {
                load_symbol(handle, b"volta_cuda_merkle_paths_device\0")?
            },
            pcs_gather_columns_device: unsafe {
                load_symbol(handle, b"volta_cuda_pcs_gather_columns_device\0")?
            },
        })
    }

    fn check(&self, rc: c_int) -> Result<(), AccelError> {
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: context is live for the lifetime of self.
            Err(AccelError::Cuda(unsafe { c_error((self.api.last_error)(self.raw), rc) }))
        }
    }

    pub(super) fn enable_deferred_profiling(&mut self) -> Result<(), AccelError> {
        // SAFETY: context is live and the ABI mutates only its timing mode.
        self.check(unsafe { (self.api.enable_deferred_profiling)(self.raw) })
    }

    #[cfg(test)]
    pub(super) fn test_inject_elapsed_no_write_once(&mut self) -> Result<(), AccelError> {
        // SAFETY: this diagnostic ABI mutates only a per-context one-shot
        // counter and is called by the exact deferred-retry regression.
        self.check(unsafe { (self.api.test_inject_elapsed_no_write_once)(self.raw) })
    }

    pub(super) fn begin_coarse_timing(&mut self, operation: Operation) -> Result<(), AccelError> {
        // SAFETY: context is live, exclusively borrowed, and Operation uses the
        // same stable discriminants as the versioned CUDA ABI.
        self.check(unsafe { (self.api.begin_coarse_timing)(self.raw, operation as c_int) })
    }

    pub(super) fn end_coarse_timing(&mut self) -> Result<(), AccelError> {
        // SAFETY: context is live and exclusively borrowed by the Rust guard.
        self.check(unsafe { (self.api.end_coarse_timing)(self.raw) })
    }

    pub(super) fn abort_coarse_timing(&mut self) -> Result<(), AccelError> {
        // SAFETY: the abort entry point is idempotent in deferred mode.
        self.check(unsafe { (self.api.abort_coarse_timing)(self.raw) })
    }

    pub(super) fn ensure_timing_capacity(
        &mut self,
        bound: usize,
    ) -> Result<TimingCapacityPreflight, AccelError> {
        let mut pending_before = 0usize;
        let mut pending_after = 0usize;
        let mut flushed = 0;
        // SAFETY: all output pointers are live and exclusive. The C boundary
        // repeats the fixed-capacity and inactive-record checks.
        self.check(unsafe {
            (self.api.ensure_timing_capacity)(
                self.raw,
                bound,
                &mut pending_before,
                &mut pending_after,
                &mut flushed,
            )
        })?;
        Ok(TimingCapacityPreflight {
            requested_records: bound,
            capacity: DEFERRED_TIMING_CAPACITY,
            pending_before,
            pending_after,
            flushed: flushed != 0,
        })
    }

    pub(super) fn flush_profiling(&mut self) -> Result<(), AccelError> {
        // SAFETY: context is live and exclusively borrowed by the backend.
        self.check(unsafe { (self.api.flush_profiling)(self.raw) })
    }

    pub(super) fn reset_stats(&mut self) -> Result<(), AccelError> {
        // SAFETY: context is live and exclusively borrowed.
        self.check(unsafe { (self.api.reset_stats)(self.raw) })
    }

    pub(super) fn stats(&self) -> Result<BackendStats, AccelError> {
        let mut raw = RawStats::default();
        // SAFETY: output points to a correctly sized C representation.
        self.check(unsafe { (self.api.get_stats)(self.raw, &mut raw) })?;
        let mut out = BackendStats {
            timing_mode: match raw.timing_mode {
                1 => DeviceTimingMode::CudaEvents,
                2 => DeviceTimingMode::HostBarrierWall,
                3 => DeviceTimingMode::CudaEventsDeferred,
                value => {
                    return Err(AccelError::Cuda(format!(
                        "CUDA backend returned unknown timing mode {value}"
                    )));
                }
            },
            h2d_bytes: raw.h2d_bytes,
            d2h_bytes: raw.d2h_bytes,
            explicit_d2d_copy_bytes: raw.d2d_bytes,
            device_zeroed_bytes: raw.device_zeroed_bytes,
            device_generated_bytes: raw.device_generated_bytes,
            h2d_ns: raw.h2d_ns,
            d2h_ns: raw.d2h_ns,
            synchronizations: raw.synchronizations,
            synchronization_ns: raw.synchronization_ns,
            sync_host_output: raw.sync_host_output,
            sync_upload_lifetime: raw.sync_upload_lifetime,
            sync_timing_flush: raw.sync_timing_flush,
            sync_profiling_legacy: raw.sync_profiling_legacy,
            sync_allocator_flush: raw.sync_allocator_flush,
            allocation_calls: raw.allocation_calls,
            resident_alloc_requests: raw.resident_alloc_requests,
            resident_reuse_hits: raw.resident_reuse_hits,
            resident_free_requests: raw.resident_free_requests,
            physical_free_calls: raw.physical_free_calls,
            live_device_bytes: raw.live_device_bytes,
            peak_device_bytes: raw.peak_device_bytes,
            timing_records: raw.timing_records,
            timing_elapsed_query_attempts: raw.timing_elapsed_query_attempts,
            timing_elapsed_no_write: raw.timing_elapsed_no_write,
            timing_event_queries: raw.timing_event_queries,
            timing_pending_high_water: raw.timing_pending_high_water,
            timing_flush_count: raw.timing_flush_count,
            coarse_timing_scopes: raw.coarse_timing_scopes,
            coarse_timing_ns: raw.coarse_timing_ns,
            ..Default::default()
        };
        for i in 0..OPERATION_COUNT {
            out.operations[i] = OperationStats {
                calls: raw.calls[i],
                kernel_ns: raw.kernel_ns[i],
                cpu_residual_ns: 0,
            };
        }
        Ok(out)
    }

    pub(super) fn memory_breakdown(&self) -> Result<DeviceMemoryBreakdown, AccelError> {
        let mut workspace_bytes = 0;
        let mut resident_bytes = 0;
        let mut cached_resident_bytes = 0;
        // SAFETY: all outputs point to one u64 and the context is live.
        self.check(unsafe {
            (self.api.memory_breakdown)(
                self.raw,
                &mut workspace_bytes,
                &mut resident_bytes,
                &mut cached_resident_bytes,
            )
        })?;
        Ok(DeviceMemoryBreakdown { workspace_bytes, resident_bytes, cached_resident_bytes })
    }

    pub(super) fn trim_resident_cache(&mut self) -> Result<(), AccelError> {
        // SAFETY: the context is live and exclusively borrowed.
        self.check(unsafe { (self.api.trim_resident_cache)(self.raw) })
    }

    pub(super) fn resident_alloc(&mut self, bytes: usize) -> Result<u64, AccelError> {
        let mut id = 0;
        // SAFETY: context is live and id points to one u64 result.
        self.check(unsafe { (self.api.resident_alloc)(self.raw, bytes, &mut id) })?;
        Ok(id)
    }

    pub(super) fn resident_free(&mut self, id: u64) -> Result<(), AccelError> {
        // SAFETY: context validates the opaque allocation id.
        self.check(unsafe { (self.api.resident_free)(self.raw, id) })
    }

    pub(super) fn resident_upload(
        &mut self,
        id: u64,
        offset_bytes: usize,
        src: *const c_void,
        bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: safe caller retains the typed input slice for the synchronous ABI call.
        self.check(unsafe { (self.api.resident_upload)(self.raw, id, offset_bytes, src, bytes) })
    }

    pub(super) fn resident_download(
        &mut self,
        id: u64,
        offset_bytes: usize,
        dst: *mut c_void,
        bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: safe caller allocated the typed output slice and the ABI synchronizes.
        self.check(unsafe { (self.api.resident_download)(self.raw, id, offset_bytes, dst, bytes) })
    }

    pub(super) fn resident_zero(
        &mut self,
        id: u64,
        offset_bytes: usize,
        bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the safe caller validated the typed destination region.
        self.check(unsafe { (self.api.resident_zero)(self.raw, id, offset_bytes, bytes) })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resident_copy_rows(
        &mut self,
        src_id: u64,
        src_offset_bytes: usize,
        src_stride_bytes: usize,
        dst_id: u64,
        dst_offset_bytes: usize,
        dst_stride_bytes: usize,
        rows: usize,
        row_bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: both typed strided envelopes and non-overlap were checked by
        // the safe caller; the C boundary repeats bounds and overlap checks.
        self.check(unsafe {
            (self.api.resident_copy_rows)(
                self.raw,
                src_id,
                src_offset_bytes,
                src_stride_bytes,
                dst_id,
                dst_offset_bytes,
                dst_stride_bytes,
                rows,
                row_bytes,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resident_mailbox_copy_rows(
        &mut self,
        src_id: u64,
        src_offset_bytes: usize,
        src_stride_bytes: usize,
        dst_id: u64,
        dst_offset_bytes: usize,
        dst_stride_bytes: usize,
        rows: usize,
        row_bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the safe caller performs the same geometry/non-overlap
        // validation as PCS copies; only the timing classification differs.
        self.check(unsafe {
            (self.api.resident_mailbox_copy_rows)(
                self.raw,
                src_id,
                src_offset_bytes,
                src_stride_bytes,
                dst_id,
                dst_offset_bytes,
                dst_stride_bytes,
                rows,
                row_bytes,
            )
        })
    }

    pub(super) fn chacha8_prover_secret_fp_rows_device(
        &mut self,
        output_id: u64,
        output_offset_bytes: usize,
        prover_secret_seed: &[u8; 32],
        base_domain: u64,
        rows: usize,
        count: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: seed points to exactly 32 live bytes for this launch call;
        // CUDA receives its copied key as kernel arguments, not retained H2D.
        self.check(unsafe {
            (self.api.chacha8_prover_secret_fp_rows_device)(
                self.raw,
                output_id,
                output_offset_bytes,
                prover_secret_seed.as_ptr(),
                base_domain,
                rows,
                count,
            )
        })
    }

    pub(super) fn mock_correlation_sub_masks_device(
        &mut self,
        output_id: u64,
        output_offset_bytes: usize,
        mock_correlation_seed: &[u8; 32],
        base_domain: u64,
        rows: usize,
        cols: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the safe caller validates the mock-only domain namespace,
        // exact output region, and seed lifetime. The seed is a copied launch
        // argument and is never retained by CUDA.
        self.check(unsafe {
            (self.api.mock_correlation_sub_masks_device)(
                self.raw,
                output_id,
                output_offset_bytes,
                mock_correlation_seed.as_ptr(),
                base_domain,
                rows,
                cols,
            )
        })
    }

    /// Test-only direct C-ABI call that deliberately bypasses the safe Rust
    /// domain preflight. This proves that a non-Rust caller cannot enter the
    /// reserved mock-correlation namespace through ABI 26.
    #[cfg(test)]
    pub(super) fn test_mock_correlation_sub_masks_device_raw(
        &mut self,
        output_id: u64,
        mock_correlation_seed: &[u8; 32],
        base_domain: u64,
        rows: usize,
        cols: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the output allocation and seed are live. Geometry/domain
        // values are intentionally untrusted so the C boundary validates them.
        self.check(unsafe {
            (self.api.mock_correlation_sub_masks_device)(
                self.raw,
                output_id,
                0,
                mock_correlation_seed.as_ptr(),
                base_domain,
                rows,
                cols,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn chacha8_prover_secret_fp2_rows_padded_device(
        &mut self,
        output_id: u64,
        output_offset_bytes: usize,
        prover_secret_seed: &[u8; 32],
        base_domain: u64,
        rows: usize,
        count: usize,
        padded_count: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: output and geometry are validated by the safe caller; the
        // seed is copied into kernel arguments during this call.
        self.check(unsafe {
            (self.api.chacha8_prover_secret_fp2_rows_padded_device)(
                self.raw,
                output_id,
                output_offset_bytes,
                prover_secret_seed.as_ptr(),
                base_domain,
                rows,
                count,
                padded_count,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_row_dots_device(
        &mut self,
        a_id: u64,
        a_offset: usize,
        a_stride: usize,
        b_id: u64,
        b_offset: usize,
        b_stride: usize,
        output_id: u64,
        output_offset: usize,
        rows: usize,
        len: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: safe caller checks context ownership and all strided regions.
        self.check(unsafe {
            (self.api.fp2_row_dots_device)(
                self.raw,
                a_id,
                a_offset,
                a_stride,
                b_id,
                b_offset,
                b_stride,
                output_id,
                output_offset,
                rows,
                len,
            )
        })
    }

    pub(super) fn fp2_powers_device(
        &mut self,
        base: Fp2,
        output_id: u64,
        output_offset: usize,
        count: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Fp/Fp2 expose canonical limbs and the output was validated.
        self.check(unsafe {
            (self.api.fp2_powers_device)(
                self.raw,
                base.c0.value(),
                base.c1.value(),
                output_id,
                output_offset,
                count,
            )
        })
    }

    pub(super) fn gemm_i64(
        &mut self,
        a: &[i16],
        b: &[i16],
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<Vec<i64>, AccelError> {
        let mut out = vec![0i64; m * n];
        // SAFETY: slice lengths were validated by the safe caller.
        self.check(unsafe {
            (self.api.gemm_i64)(self.raw, a.as_ptr(), b.as_ptr(), out.as_mut_ptr(), m, k, n)
        })?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gemm_i64_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        out: u64,
        out_offset: usize,
        m: usize,
        k: usize,
        n: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: context owns every opaque id; Rust validated typed regions.
        self.check(unsafe {
            (self.api.gemm_i64_device)(self.raw, a, a_offset, b, b_offset, out, out_offset, m, k, n)
        })
    }

    pub(super) fn gemm_requant_auth(
        &mut self,
        a: &[i16],
        b: &[i16],
        masks: &[Fp],
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(Vec<i16>, Vec<u64>), AccelError> {
        let raw_masks: Vec<u64> = masks.iter().map(|x| x.value()).collect();
        let mut out = vec![0i16; m * n];
        let mut corr = vec![0u64; m * n];
        // SAFETY: all buffers have the dimensions supplied to the C ABI.
        self.check(unsafe {
            (self.api.gemm_requant_auth)(
                self.raw,
                a.as_ptr(),
                b.as_ptr(),
                raw_masks.as_ptr(),
                out.as_mut_ptr(),
                corr.as_mut_ptr(),
                m,
                k,
                n,
                shift,
            )
        })?;
        Ok((out, corr))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn gemm_requant_auth_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        masks: u64,
        masks_offset: usize,
        out: u64,
        out_offset: usize,
        corr: u64,
        corr_offset: usize,
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: context owns every opaque id; Rust validated typed regions.
        self.check(unsafe {
            (self.api.gemm_requant_auth_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                masks,
                masks_offset,
                out,
                out_offset,
                corr,
                corr_offset,
                m,
                k,
                n,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_embed_device(
        &mut self,
        tokens: u64,
        tokens_offset: usize,
        wte: u64,
        wte_offset: usize,
        wpe: u64,
        wpe_offset: usize,
        acc: u64,
        acc_offset: usize,
        out: u64,
        out_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        d: usize,
        vocab: usize,
        positions: usize,
        pos0: usize,
        shift: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_embed_device)(
                self.raw,
                tokens,
                tokens_offset,
                wte,
                wte_offset,
                wpe,
                wpe_offset,
                acc,
                acc_offset,
                out,
                out_offset,
                error,
                error_offset,
                rows,
                d,
                vocab,
                positions,
                pos0,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_layer_norm_device(
        &mut self,
        input: u64,
        input_offset: usize,
        gain: u64,
        gain_offset: usize,
        bias: u64,
        bias_offset: usize,
        lut: u64,
        lut_offset: usize,
        mean: u64,
        mean_offset: usize,
        var: u64,
        var_offset: usize,
        rin: u64,
        rin_offset: usize,
        rout: u64,
        rout_offset: usize,
        accumulators: u64,
        accumulators_offset: usize,
        out: u64,
        out_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        d: usize,
        var_shift: u32,
        norm_shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_layer_norm_device)(
                self.raw,
                input,
                input_offset,
                gain,
                gain_offset,
                bias,
                bias_offset,
                lut,
                lut_offset,
                mean,
                mean_offset,
                var,
                var_offset,
                rin,
                rin_offset,
                rout,
                rout_offset,
                accumulators,
                accumulators_offset,
                out,
                out_offset,
                error,
                error_offset,
                rows,
                d,
                var_shift,
                norm_shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_gemm_device(
        &mut self,
        input: u64,
        input_offset: usize,
        weights: u64,
        weights_offset: usize,
        bias: Option<(u64, usize)>,
        residual: Option<(u64, usize)>,
        acc: u64,
        acc_offset: usize,
        requant: u64,
        requant_offset: usize,
        residual_out: Option<(u64, usize)>,
        error: u64,
        error_offset: usize,
        m: usize,
        k: usize,
        n: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        let (bias, bias_offset) = bias.unwrap_or((0, 0));
        let (residual, residual_offset) = residual.unwrap_or((0, 0));
        let (residual_out, residual_out_offset) = residual_out.unwrap_or((0, 0));
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_gemm_device)(
                self.raw,
                input,
                input_offset,
                weights,
                weights_offset,
                bias,
                bias_offset,
                residual,
                residual_offset,
                acc,
                acc_offset,
                requant,
                requant_offset,
                residual_out,
                residual_out_offset,
                error,
                error_offset,
                m,
                k,
                n,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_qkv_split_device(
        &mut self,
        input: u64,
        input_offset: usize,
        q: u64,
        q_offset: usize,
        k: u64,
        k_offset: usize,
        v: u64,
        v_offset: usize,
        rows: usize,
        d: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_qkv_split_device)(
                self.raw,
                input,
                input_offset,
                q,
                q_offset,
                k,
                k_offset,
                v,
                v_offset,
                rows,
                d,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_attention_scores_device(
        &mut self,
        q: u64,
        q_offset: usize,
        k: u64,
        k_offset: usize,
        acc: u64,
        acc_offset: usize,
        out: u64,
        out_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_dim: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_attention_scores_device)(
                self.raw,
                q,
                q_offset,
                k,
                k_offset,
                acc,
                acc_offset,
                out,
                out_offset,
                error,
                error_offset,
                rows,
                seq,
                pos0,
                heads,
                head_dim,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_softmax_device(
        &mut self,
        scores: u64,
        scores_offset: usize,
        exp_lut: u64,
        exp_lut_offset: usize,
        recip_lut: u64,
        recip_lut_offset: usize,
        row_shift: u64,
        row_shift_offset: usize,
        exp: u64,
        exp_offset: usize,
        denoms: u64,
        denoms_offset: usize,
        recips: u64,
        recips_offset: usize,
        weights: u64,
        weights_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        recip_den_shift: u32,
        norm_shift: u32,
        use_row_shift: bool,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_softmax_device)(
                self.raw,
                scores,
                scores_offset,
                exp_lut,
                exp_lut_offset,
                recip_lut,
                recip_lut_offset,
                row_shift,
                row_shift_offset,
                exp,
                exp_offset,
                denoms,
                denoms_offset,
                recips,
                recips_offset,
                weights,
                weights_offset,
                error,
                error_offset,
                rows,
                seq,
                pos0,
                heads,
                recip_den_shift,
                norm_shift,
                i32::from(use_row_shift),
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_av_device(
        &mut self,
        weights: u64,
        weights_offset: usize,
        values: u64,
        values_offset: usize,
        acc: u64,
        acc_offset: usize,
        out: u64,
        out_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        seq: usize,
        pos0: usize,
        d: usize,
        heads: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_av_device)(
                self.raw,
                weights,
                weights_offset,
                values,
                values_offset,
                acc,
                acc_offset,
                out,
                out_offset,
                error,
                error_offset,
                rows,
                seq,
                pos0,
                d,
                heads,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_lookup_device(
        &mut self,
        input: u64,
        input_offset: usize,
        lut: u64,
        lut_offset: usize,
        out: u64,
        out_offset: usize,
        n: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_lookup_device)(
                self.raw,
                input,
                input_offset,
                lut,
                lut_offset,
                out,
                out_offset,
                n,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_requant_i16_device(
        &mut self,
        input: u64,
        input_offset: usize,
        out: u64,
        out_offset: usize,
        error: u64,
        error_offset: usize,
        n: usize,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_requant_i16_device)(
                self.raw,
                input,
                input_offset,
                out,
                out_offset,
                error,
                error_offset,
                n,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fixed_logits_device(
        &mut self,
        input: u64,
        input_offset: usize,
        weights: u64,
        weights_offset: usize,
        out: u64,
        out_offset: usize,
        rows: usize,
        d: usize,
        vocab: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed regions.
        self.check(unsafe {
            (self.api.fixed_logits_device)(
                self.raw,
                input,
                input_offset,
                weights,
                weights_offset,
                out,
                out_offset,
                rows,
                d,
                vocab,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn subfield_corrections_device(
        &mut self,
        input: u64,
        input_offset: usize,
        masks: u64,
        masks_offset: usize,
        output: u64,
        output_offset: usize,
        n: usize,
        kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates typed regions and the scalar-kind tag.
        self.check(unsafe {
            (self.api.subfield_corrections_device)(
                self.raw,
                input,
                input_offset,
                masks,
                masks_offset,
                output,
                output_offset,
                n,
                kind,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pad_base_vector_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        real: usize,
        padded: usize,
        pad: Fp,
        kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates typed regions, padding, and scalar kind.
        self.check(unsafe {
            (self.api.pad_base_vector_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                real,
                padded,
                pad.value(),
                kind,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn matrix_fold_device(
        &mut self,
        input: u64,
        input_offset: usize,
        weights: u64,
        weights_offset: usize,
        output: u64,
        output_offset: usize,
        rows: usize,
        stride: usize,
        column_offset: usize,
        cols: usize,
        out_pad: usize,
        kind: i32,
        axis: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates typed regions, shape, axis, and scalar kind.
        self.check(unsafe {
            (self.api.matrix_fold_device)(
                self.raw,
                input,
                input_offset,
                weights,
                weights_offset,
                output,
                output_offset,
                rows,
                stride,
                column_offset,
                cols,
                out_pad,
                kind,
                axis,
            )
        })
    }

    pub(super) fn fp2_dot_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        n: usize,
    ) -> Result<Fp2, AccelError> {
        let mut output = Fp2Repr::default();
        // SAFETY: Backend validates both resident Fp2 ranges; output is one
        // protocol scalar and the ABI synchronizes before returning.
        self.check(unsafe {
            (self.api.fp2_dot_device)(self.raw, a, a_offset, b, b_offset, n, &mut output)
        })?;
        Ok(output.into())
    }

    pub(super) fn fp2_product_round_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        pairs: usize,
    ) -> Result<[Fp2; 2], AccelError> {
        let mut output = [Fp2Repr::default(); 2];
        // SAFETY: Backend validates both 2*pairs resident ranges; output is
        // the compressed round message and the ABI synchronizes.
        self.check(unsafe {
            (self.api.fp2_product_round_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                pairs,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output.map(Into::into))
    }

    pub(super) fn reserve_fp2_product_round_workspace(
        &mut self,
        max_pairs: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the safe caller rejects zero. The C boundary performs all
        // byte-overflow checks and only grows the two private scratch slots.
        self.check(unsafe { (self.api.reserve_fp2_product_round_workspace)(self.raw, max_pairs) })
    }

    pub(super) fn reserve_logup_round_workspace(
        &mut self,
        max_pairs: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: the safe caller rejects zero. The C boundary preflights
        // byte arithmetic and grows only private general/aux reduction slots.
        self.check(unsafe { (self.api.reserve_logup_round_workspace)(self.raw, max_pairs) })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_product_round_into_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        pairs: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both input regions and the two-element
        // mailbox slot. All work remains ordered on the context stream.
        self.check(unsafe {
            (self.api.fp2_product_round_into_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                pairs,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_triple_product_round_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        c: u64,
        c_offset: usize,
        pairs: usize,
    ) -> Result<[Fp2; 3], AccelError> {
        let mut output = [Fp2Repr::default(); 3];
        // SAFETY: Backend validates all three 2*pairs Fp2 regions; output is
        // one compressed degree-3 round message.
        self.check(unsafe {
            (self.api.fp2_triple_product_round_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                c,
                c_offset,
                pairs,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_triple_product_round_into_device(
        &mut self,
        a: u64,
        a_offset: usize,
        b: u64,
        b_offset: usize,
        c: u64,
        c_offset: usize,
        pairs: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates every input region and the three-element
        // mailbox slot. The call enqueues no device-to-host transfer.
        self.check(unsafe {
            (self.api.fp2_triple_product_round_into_device)(
                self.raw,
                a,
                a_offset,
                b,
                b_offset,
                c,
                c_offset,
                pairs,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn ln_hadamard_factors_device(
        &mut self,
        input: u64,
        input_offset: usize,
        mean: u64,
        mean_offset: usize,
        rsqrt: u64,
        rsqrt_offset: usize,
        gain: u64,
        gain_offset: usize,
        centered: u64,
        centered_offset: usize,
        scaled: u64,
        scaled_offset: usize,
        rows: usize,
        cols: usize,
        row_pad: usize,
        col_pad: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates every typed region and padded geometry.
        self.check(unsafe {
            (self.api.ln_hadamard_factors_device)(
                self.raw,
                input,
                input_offset,
                mean,
                mean_offset,
                rsqrt,
                rsqrt_offset,
                gain,
                gain_offset,
                centered,
                centered_offset,
                scaled,
                scaled_offset,
                rows,
                cols,
                row_pad,
                col_pad,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn base_broadcast_fp2_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        input_len: usize,
        repeat: usize,
        kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed regions, scalar kind and product length.
        self.check(unsafe {
            (self.api.base_broadcast_fp2_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                input_len,
                repeat,
                kind,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn repeat_vector_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        input_len: usize,
        repeat: usize,
        kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both regions and the sealed element kind.
        self.check(unsafe {
            (self.api.repeat_vector_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                input_len,
                repeat,
                kind,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compact_strided_rows_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        rows: usize,
        source_stride: usize,
        width: usize,
        kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed regions and every pitch.
        self.check(unsafe {
            (self.api.compact_strided_rows_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                rows,
                source_stride,
                width,
                kind,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn attention_above_mask_device(
        &mut self,
        equality: u64,
        equality_offset: usize,
        entries: usize,
        rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_pad: usize,
        query_pad: usize,
        seq_pad: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates the full Fp2 region and all padded shape invariants.
        self.check(unsafe {
            (self.api.attention_above_mask_device)(
                self.raw,
                equality,
                equality_offset,
                entries,
                rows,
                seq,
                pos0,
                heads,
                head_pad,
                query_pad,
                seq_pad,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn attention_proof_wires_device(
        &mut self,
        q_id: u64,
        q_offset: usize,
        k_cache_id: u64,
        k_cache_offset: usize,
        own_k_id: u64,
        own_k_offset: usize,
        v_id: u64,
        v_offset: usize,
        scores_acc_id: u64,
        scores_acc_offset: usize,
        scores_q_id: u64,
        scores_q_offset: usize,
        row_shifts_id: u64,
        row_shifts_offset: usize,
        exp_outputs_id: u64,
        exp_outputs_offset: usize,
        denoms_id: u64,
        denoms_offset: usize,
        recips_id: u64,
        recips_offset: usize,
        softmax_weights_id: u64,
        softmax_weights_offset: usize,
        recip_lut_id: u64,
        recip_lut_offset: usize,
        qkv_acc_id: u64,
        qkv_acc_offset: usize,
        error_id: u64,
        error_offset: usize,
        rect_id: u64,
        rect_offset: usize,
        rows_id: u64,
        rows_offset: usize,
        above_id: u64,
        above_offset: usize,
        qkv_id: u64,
        qkv_offset: usize,
        query_rows: usize,
        seq: usize,
        pos0: usize,
        heads: usize,
        head_pad: usize,
        head_dim: usize,
        query_pad: usize,
        seq_pad: usize,
        d_pad: usize,
        shift_scores: u32,
        shift_softmax_norm: u32,
        shift_qkv: u32,
        recip_den_shift: u32,
        exp_pad_input: i16,
        recip_pad_output: i16,
        use_row_shift: bool,
    ) -> Result<(), AccelError> {
        let args = RawAttentionProofWiresArgs {
            q_id,
            q_offset,
            k_cache_id,
            k_cache_offset,
            own_k_id,
            own_k_offset,
            v_id,
            v_offset,
            scores_acc_id,
            scores_acc_offset,
            scores_q_id,
            scores_q_offset,
            row_shifts_id,
            row_shifts_offset,
            exp_outputs_id,
            exp_outputs_offset,
            denoms_id,
            denoms_offset,
            recips_id,
            recips_offset,
            softmax_weights_id,
            softmax_weights_offset,
            recip_lut_id,
            recip_lut_offset,
            qkv_acc_id,
            qkv_acc_offset,
            error_id,
            error_offset,
            rect_id,
            rect_offset,
            rows_id,
            rows_offset,
            above_id,
            above_offset,
            qkv_id,
            qkv_offset,
            query_rows,
            seq,
            pos0,
            heads,
            head_pad,
            head_dim,
            query_pad,
            seq_pad,
            d_pad,
            shift_scores,
            shift_softmax_norm,
            shift_qkv,
            recip_den_shift,
            exp_pad_input: i32::from(exp_pad_input),
            recip_pad_output: i32::from(recip_pad_output),
            use_row_shift: i32::from(use_row_shift),
        };
        // SAFETY: Backend validates all ids, typed regions and output sizes;
        // this versioned POD argument has the matching C++ layout.
        self.check(unsafe { (self.api.attention_proof_wires_device)(self.raw, &args) })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn requant_columns_device(
        &mut self,
        acc: u64,
        acc_offset: usize,
        out: u64,
        out_offset: usize,
        columns: u64,
        columns_offset: usize,
        error: u64,
        error_offset: usize,
        rows: usize,
        cols: usize,
        row_pad: usize,
        col_pad: usize,
        acc_kind: i32,
        shift: u32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates every typed region and padded geometry.
        self.check(unsafe {
            (self.api.requant_columns_device)(
                self.raw,
                acc,
                acc_offset,
                out,
                out_offset,
                columns,
                columns_offset,
                error,
                error_offset,
                rows,
                cols,
                row_pad,
                col_pad,
                acc_kind,
                shift,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pair_columns_device(
        &mut self,
        input: u64,
        input_offset: usize,
        out: u64,
        out_offset: usize,
        columns: u64,
        columns_offset: usize,
        rows: usize,
        cols: usize,
        row_pad: usize,
        col_pad: usize,
        pad_input: Fp,
        pad_output: Fp,
        input_kind: i32,
        output_kind: i32,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates every typed region and padded geometry.
        self.check(unsafe {
            (self.api.pair_columns_device)(
                self.raw,
                input,
                input_offset,
                out,
                out_offset,
                columns,
                columns_offset,
                rows,
                cols,
                row_pad,
                col_pad,
                pad_input.value(),
                pad_output.value(),
                input_kind,
                output_kind,
            )
        })
    }

    pub(super) fn histogram_lut_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        n: usize,
        signed_input: bool,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed ranges; the mode is sealed.
        self.check(unsafe {
            (self.api.histogram_lut_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                n,
                i32::from(signed_input),
            )
        })
    }

    pub(super) fn histogram_fp_device(
        &mut self,
        input: u64,
        input_offset: usize,
        output: u64,
        output_offset: usize,
        n: usize,
        bins: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed ranges and bin count.
        self.check(unsafe {
            (self.api.histogram_fp_device)(
                self.raw,
                input,
                input_offset,
                output,
                output_offset,
                n,
                bins,
            )
        })
    }

    pub(super) fn u32_add_inplace_device(
        &mut self,
        target: u64,
        target_offset: usize,
        add: u64,
        add_offset: usize,
        n: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed regions.
        self.check(unsafe {
            (self.api.u32_add_inplace_device)(self.raw, target, target_offset, add, add_offset, n)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pack_lookup_leaf_device(
        &mut self,
        columns: u64,
        columns_offset: usize,
        shifts: u64,
        shifts_offset: usize,
        leaf: u64,
        leaf_offset: usize,
        column_count: usize,
        n: usize,
        alpha0: Fp,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all buffers, shifts, and power-of-two n.
        self.check(unsafe {
            (self.api.pack_lookup_leaf_device)(
                self.raw,
                columns,
                columns_offset,
                shifts,
                shifts_offset,
                leaf,
                leaf_offset,
                column_count,
                n,
                alpha0.value(),
            )
        })
    }

    pub(super) fn deinterleave_base_columns_device(
        &mut self,
        columns: u64,
        columns_offset: usize,
        output: u64,
        output_offset: usize,
        column_count: usize,
        n: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates both typed regions and even n.
        self.check(unsafe {
            (self.api.deinterleave_base_columns_device)(
                self.raw,
                columns,
                columns_offset,
                output,
                output_offset,
                column_count,
                n,
            )
        })
    }

    pub(super) fn ntt_fp(&mut self, msg: &[Fp], size: usize) -> Result<Vec<Fp>, AccelError> {
        let input: Vec<u64> = msg.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; size];
        // SAFETY: input/output lengths match the supplied geometry.
        self.check(unsafe {
            (self.api.ntt_fp)(self.raw, input.as_ptr(), input.len(), size, output.as_mut_ptr())
        })?;
        Ok(output.into_iter().map(Fp::new).collect())
    }

    pub(super) fn ntt_fp_batch(
        &mut self,
        messages: &[Fp],
        rows: usize,
        msg_len: usize,
        size: usize,
    ) -> Result<Vec<Fp>, AccelError> {
        let input: Vec<u64> = messages.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; rows * size];
        // SAFETY: compact input and padded output geometries were validated.
        self.check(unsafe {
            (self.api.ntt_fp_batch)(
                self.raw,
                input.as_ptr(),
                rows,
                msg_len,
                size,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output.into_iter().map(Fp::new).collect())
    }

    pub(super) fn ntt_fp2(&mut self, msg: &[Fp2], size: usize) -> Result<Vec<Fp2>, AccelError> {
        let input: Vec<Fp2Repr> = msg.iter().copied().map(Into::into).collect();
        let mut output = vec![Fp2Repr::default(); size];
        // SAFETY: input/output lengths match the supplied geometry.
        self.check(unsafe {
            (self.api.ntt_fp2)(self.raw, input.as_ptr(), input.len(), size, output.as_mut_ptr())
        })?;
        Ok(output.into_iter().map(Into::into).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn ntt_fp_batch_device(
        &mut self,
        input: u64,
        input_offset: usize,
        rows: usize,
        size: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and padded geometries.
        self.check(unsafe {
            (self.api.ntt_fp_batch_device)(
                self.raw,
                input,
                input_offset,
                rows,
                size,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn ntt_fp2_batch_device(
        &mut self,
        input: u64,
        input_offset: usize,
        rows: usize,
        size: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and padded geometries.
        self.check(unsafe {
            (self.api.ntt_fp2_batch_device)(
                self.raw,
                input,
                input_offset,
                rows,
                size,
                output,
                output_offset,
            )
        })
    }

    pub(super) fn logup_tree(
        &mut self,
        leaf_a: &[Fp],
        alpha1: Fp,
        mult: Option<&[u32]>,
    ) -> Result<(Vec<Vec<Fp2>>, Vec<Vec<Fp2>>), AccelError> {
        let n = leaf_a.len();
        let input: Vec<u64> = leaf_a.iter().map(|x| x.value()).collect();
        let mut p = vec![Fp2Repr::default(); n - 1];
        let mut q = vec![Fp2Repr::default(); n - 1];
        let (mp, kind) = mult.map_or((ptr::null(), 0), |m| (m.as_ptr(), 1));
        // SAFETY: all vectors have n or n-1 entries as required by the ABI.
        self.check(unsafe {
            (self.api.logup_tree)(
                self.raw,
                input.as_ptr(),
                mp,
                n,
                alpha1.value(),
                kind,
                p.as_mut_ptr(),
                q.as_mut_ptr(),
            )
        })?;
        Ok((unflatten_tree(p, n), unflatten_tree(q, n)))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_tree_device(
        &mut self,
        leaf: u64,
        leaf_offset: usize,
        mult: Option<(u64, usize)>,
        n: usize,
        alpha1: Fp,
        p: u64,
        p_offset: usize,
        q: u64,
        q_offset: usize,
    ) -> Result<(), AccelError> {
        let (mult_id, mult_offset, kind) = mult.map_or((0, 0, 0), |(id, offset)| (id, offset, 1));
        // SAFETY: opaque ids and typed ranges were validated by Backend.
        self.check(unsafe {
            (self.api.logup_tree_device)(
                self.raw,
                leaf,
                leaf_offset,
                mult_id,
                mult_offset,
                n,
                alpha1.value(),
                kind,
                p,
                p_offset,
                q,
                q_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_materialize_leaves_device(
        &mut self,
        leaf: u64,
        leaf_offset: usize,
        mult: Option<(u64, usize)>,
        n: usize,
        alpha1: Fp,
        p: u64,
        p_offset: usize,
        q: u64,
        q_offset: usize,
    ) -> Result<(), AccelError> {
        let (mult_id, mult_offset, kind) = mult.map_or((0, 0, 0), |(id, offset)| (id, offset, 1));
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.logup_materialize_leaves_device)(
                self.raw,
                leaf,
                leaf_offset,
                mult_id,
                mult_offset,
                n,
                alpha1.value(),
                kind,
                p,
                p_offset,
                q,
                q_offset,
            )
        })
    }

    pub(super) fn logup_general_round(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        suffix_eq: &[Fp2],
    ) -> Result<[Fp2; 4], AccelError> {
        let cvt = |v: &[Fp2]| v.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let (p0, p1, q0, q1, suffix) = (cvt(p0), cvt(p1), cvt(q0), cvt(q1), cvt(suffix_eq));
        let mut out = [Fp2Repr::default(); 4];
        // SAFETY: every vector geometry was validated by the safe caller.
        self.check(unsafe {
            (self.api.logup_general_round)(
                self.raw,
                p0.as_ptr(),
                p1.as_ptr(),
                q0.as_ptr(),
                q1.as_ptr(),
                suffix.as_ptr(),
                suffix.len(),
                out.as_mut_ptr(),
            )
        })?;
        Ok(out.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_general_round_device(
        &mut self,
        p0: u64,
        p0_offset: usize,
        p1: u64,
        p1_offset: usize,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        suffix: u64,
        suffix_offset: usize,
        pairs: usize,
    ) -> Result<[Fp2; 4], AccelError> {
        let mut out = [Fp2Repr::default(); 4];
        // SAFETY: opaque ids and typed ranges were validated by Backend; the
        // output is one protocol round message and the ABI synchronizes it.
        self.check(unsafe {
            (self.api.logup_general_round_device)(
                self.raw,
                p0,
                p0_offset,
                p1,
                p1_offset,
                q0,
                q0_offset,
                q1,
                q1_offset,
                suffix,
                suffix_offset,
                pairs,
                out.as_mut_ptr(),
            )
        })?;
        Ok(out.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_general_round_into_device(
        &mut self,
        p0: u64,
        p0_offset: usize,
        p1: u64,
        p1_offset: usize,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        suffix: u64,
        suffix_offset: usize,
        pairs: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident regions. The four raw
        // accumulators are copied D2D into one caller-owned mailbox slot.
        self.check(unsafe {
            (self.api.logup_general_round_into_device)(
                self.raw,
                p0,
                p0_offset,
                p1,
                p1_offset,
                q0,
                q0_offset,
                q1,
                q1_offset,
                suffix,
                suffix_offset,
                pairs,
                output,
                output_offset,
            )
        })
    }

    pub(super) fn logup_fold4(
        &mut self,
        p0: &[Fp2],
        p1: &[Fp2],
        q0: &[Fp2],
        q1: &[Fp2],
        r: Fp2,
    ) -> Result<[Vec<Fp2>; 4], AccelError> {
        let cvt = |v: &[Fp2]| v.iter().copied().map(Fp2Repr::from).collect::<Vec<_>>();
        let input = [cvt(p0), cvt(p1), cvt(q0), cvt(q1)];
        let half = p0.len() / 2;
        let mut output: [Vec<Fp2Repr>; 4] = std::array::from_fn(|_| vec![Fp2Repr::default(); half]);
        // SAFETY: inputs have 2*half entries and outputs half entries.
        self.check(unsafe {
            (self.api.logup_fold4)(
                self.raw,
                input[0].as_ptr(),
                input[1].as_ptr(),
                input[2].as_ptr(),
                input[3].as_ptr(),
                half,
                r.into(),
                output[0].as_mut_ptr(),
                output[1].as_mut_ptr(),
                output[2].as_mut_ptr(),
                output[3].as_mut_ptr(),
            )
        })?;
        Ok(output.map(|v| v.into_iter().map(Into::into).collect()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_fold4_device(
        &mut self,
        p0: u64,
        p0_offset: usize,
        p1: u64,
        p1_offset: usize,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        pairs: usize,
        r: Fp2,
        o0: u64,
        o0_offset: usize,
        o1: u64,
        o1_offset: usize,
        o2: u64,
        o2_offset: usize,
        o3: u64,
        o3_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: opaque ids and typed ranges were validated by Backend.
        self.check(unsafe {
            (self.api.logup_fold4_device)(
                self.raw,
                p0,
                p0_offset,
                p1,
                p1_offset,
                q0,
                q0_offset,
                q1,
                q1_offset,
                pairs,
                r.into(),
                o0,
                o0_offset,
                o1,
                o1_offset,
                o2,
                o2_offset,
                o3,
                o3_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_deinterleave_device(
        &mut self,
        input: u64,
        input_offset: usize,
        pairs: usize,
        even: u64,
        even_offset: usize,
        odd: u64,
        odd_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.fp2_deinterleave_device)(
                self.raw,
                input,
                input_offset,
                pairs,
                even,
                even_offset,
                odd,
                odd_offset,
            )
        })
    }

    pub(super) fn logup_suffix_eq_device(
        &mut self,
        points: u64,
        points_offset: usize,
        point_len: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.logup_suffix_eq_device)(
                self.raw,
                points,
                points_offset,
                point_len,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn fp2_fold_rows_device(
        &mut self,
        input: u64,
        input_offset: usize,
        rows: usize,
        len: usize,
        r: Fp2,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.fp2_fold_rows_device)(
                self.raw,
                input,
                input_offset,
                rows,
                len,
                r.into(),
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_eq_rows_device(
        &mut self,
        points: u64,
        points_offset: usize,
        rows: usize,
        dims: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all opaque ids and typed ranges.
        self.check(unsafe {
            (self.api.logup_eq_rows_device)(
                self.raw,
                points,
                points_offset,
                rows,
                dims,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_aux_round_device(
        &mut self,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        suffix: u64,
        suffix_offset: usize,
        columns: u64,
        columns_offset: usize,
        eq: u64,
        eq_offset: usize,
        claim_cols: u64,
        claim_cols_offset: usize,
        weights: u64,
        weights_offset: usize,
        column_count: usize,
        claim_count: usize,
        vector_len: usize,
        lambda: Fp2,
        cpref: Fp2,
        point: Fp2,
    ) -> Result<[Fp2; 3], AccelError> {
        let mut output = [Fp2Repr::default(); 3];
        // SAFETY: Backend validates all opaque ids and typed ranges; output is
        // exactly the degree-3 protocol message and the ABI synchronizes it.
        self.check(unsafe {
            (self.api.logup_aux_round_device)(
                self.raw,
                q0,
                q0_offset,
                q1,
                q1_offset,
                suffix,
                suffix_offset,
                columns,
                columns_offset,
                eq,
                eq_offset,
                claim_cols,
                claim_cols_offset,
                weights,
                weights_offset,
                column_count,
                claim_count,
                vector_len,
                lambda.into(),
                cpref.into(),
                point.into(),
                output.as_mut_ptr(),
            )
        })?;
        Ok(output.map(Into::into))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn logup_aux_round_into_device(
        &mut self,
        q0: u64,
        q0_offset: usize,
        q1: u64,
        q1_offset: usize,
        suffix: u64,
        suffix_offset: usize,
        columns: u64,
        columns_offset: usize,
        eq: u64,
        eq_offset: usize,
        claim_cols: u64,
        claim_cols_offset: usize,
        weights: u64,
        weights_offset: usize,
        column_count: usize,
        claim_count: usize,
        vector_len: usize,
        lambda: Fp2,
        cpref: Fp2,
        point: Fp2,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident inputs and the three-element
        // output slot. No host pointer crosses this ABI boundary.
        self.check(unsafe {
            (self.api.logup_aux_round_into_device)(
                self.raw,
                q0,
                q0_offset,
                q1,
                q1_offset,
                suffix,
                suffix_offset,
                columns,
                columns_offset,
                eq,
                eq_offset,
                claim_cols,
                claim_cols_offset,
                weights,
                weights_offset,
                column_count,
                claim_count,
                vector_len,
                lambda.into(),
                cpref.into(),
                point.into(),
                output,
                output_offset,
            )
        })
    }

    pub(super) fn hash_fp_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
    ) -> Result<Vec<[u8; 32]>, AccelError> {
        let input: Vec<u64> = matrix.iter().map(|x| x.value()).collect();
        let mut bytes = vec![0u8; cols * 32];
        // SAFETY: matrix and output geometries were checked by the safe caller.
        self.check(unsafe {
            (self.api.hash_fp_columns)(self.raw, input.as_ptr(), rows, cols, bytes.as_mut_ptr())
        })?;
        Ok(bytes.chunks_exact(32).map(|x| x.try_into().unwrap()).collect())
    }

    pub(super) fn pcs_combine_rows(
        &mut self,
        weights: &[i16],
        pads: &[Fp],
        coeffs: &[Fp2],
        rows: usize,
        cols: usize,
        pad: usize,
        combinations: usize,
    ) -> Result<Vec<Vec<Fp2>>, AccelError> {
        let raw_pads: Vec<u64> = pads.iter().map(|x| x.value()).collect();
        let raw_coeffs: Vec<Fp2Repr> = coeffs.iter().copied().map(Into::into).collect();
        let msg_len = cols + pad;
        let mut output = vec![Fp2Repr::default(); combinations * msg_len];
        // SAFETY: every buffer follows the checked matrix geometry.
        self.check(unsafe {
            (self.api.pcs_combine_rows)(
                self.raw,
                weights.as_ptr(),
                raw_pads.as_ptr(),
                raw_coeffs.as_ptr(),
                rows,
                cols,
                pad,
                combinations,
                output.as_mut_ptr(),
            )
        })?;
        Ok(output
            .chunks_exact(msg_len)
            .map(|row| row.iter().copied().map(Into::into).collect())
            .collect())
    }

    pub(super) fn pcs_gather_columns(
        &mut self,
        matrix: &[Fp],
        rows: usize,
        cols: usize,
        indices: &[u32],
    ) -> Result<Vec<Vec<Fp>>, AccelError> {
        let raw: Vec<u64> = matrix.iter().map(|x| x.value()).collect();
        let mut output = vec![0u64; rows * indices.len()];
        // SAFETY: matrix, index and output lengths follow the checked geometry.
        self.check(unsafe {
            (self.api.pcs_gather_columns)(
                self.raw,
                raw.as_ptr(),
                rows,
                cols,
                indices.as_ptr(),
                indices.len(),
                output.as_mut_ptr(),
            )
        })?;
        Ok(output
            .chunks_exact(rows)
            .map(|col| col.iter().copied().map(Fp::new).collect())
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pcs_messages_device(
        &mut self,
        weights: u64,
        weights_offset: usize,
        pads: u64,
        pads_offset: usize,
        rows: usize,
        cols: usize,
        pad: usize,
        code_len: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and matrix geometries.
        self.check(unsafe {
            (self.api.pcs_messages_device)(
                self.raw,
                weights,
                weights_offset,
                pads,
                pads_offset,
                rows,
                cols,
                pad,
                code_len,
                output,
                output_offset,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pcs_combine_rows_device(
        &mut self,
        weights: u64,
        weights_offset: usize,
        pads: u64,
        pads_offset: usize,
        coeffs: u64,
        coeffs_offset: usize,
        rows: usize,
        cols: usize,
        pad: usize,
        combinations: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and matrix geometries.
        self.check(unsafe {
            (self.api.pcs_combine_rows_device)(
                self.raw,
                weights,
                weights_offset,
                pads,
                pads_offset,
                coeffs,
                coeffs_offset,
                rows,
                cols,
                pad,
                combinations,
                output,
                output_offset,
            )
        })
    }

    pub(super) fn fp2_add_inplace_device(
        &mut self,
        target: u64,
        target_offset: usize,
        add: u64,
        add_offset: usize,
        len: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and typed regions.
        self.check(unsafe {
            (self.api.fp2_add_inplace_device)(self.raw, target, target_offset, add, add_offset, len)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn hash_tree_device(
        &mut self,
        fp2: bool,
        matrix: u64,
        matrix_offset: usize,
        rows: usize,
        cols: usize,
        tree: u64,
        tree_offset_bytes: usize,
    ) -> Result<(), AccelError> {
        let function =
            if fp2 { self.api.hash_fp2_tree_device } else { self.api.hash_fp_tree_device };
        // SAFETY: Backend validates all resident ids and matrix/tree regions.
        self.check(unsafe {
            function(self.raw, matrix, matrix_offset, rows, cols, tree, tree_offset_bytes)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn merkle_paths_device(
        &mut self,
        tree: u64,
        tree_offset_bytes: usize,
        leaves: usize,
        indices: u64,
        indices_offset: usize,
        queries: usize,
        paths: u64,
        paths_offset_bytes: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and tree/path regions.
        self.check(unsafe {
            (self.api.merkle_paths_device)(
                self.raw,
                tree,
                tree_offset_bytes,
                leaves,
                indices,
                indices_offset,
                queries,
                paths,
                paths_offset_bytes,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn pcs_gather_columns_device(
        &mut self,
        fp2: bool,
        matrix: u64,
        matrix_offset: usize,
        rows: usize,
        cols: usize,
        indices: u64,
        indices_offset: usize,
        queries: usize,
        output: u64,
        output_offset: usize,
    ) -> Result<(), AccelError> {
        // SAFETY: Backend validates all resident ids and typed regions.
        self.check(unsafe {
            (self.api.pcs_gather_columns_device)(
                self.raw,
                matrix,
                matrix_offset,
                rows,
                cols,
                indices,
                indices_offset,
                queries,
                output,
                output_offset,
                fp2 as c_int,
            )
        })
    }
}

impl Drop for CudaContext {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns both the context and dlopen handle.
        unsafe {
            (self.api.destroy)(self.raw);
            dlclose(self.api.handle);
        }
    }
}

fn unflatten_tree(flat: Vec<Fp2Repr>, n: usize) -> Vec<Vec<Fp2>> {
    let depth = n.trailing_zeros() as usize;
    let mut out = Vec::with_capacity(depth);
    let mut off = 0;
    for level in 0..depth {
        let len = 1usize << level;
        out.push(flat[off..off + len].iter().copied().map(Into::into).collect());
        off += len;
    }
    debug_assert_eq!(off, n - 1);
    out
}

unsafe fn load_symbol<T: Copy>(handle: *mut c_void, name: &'static [u8]) -> Result<T, AccelError> {
    debug_assert_eq!(name.last(), Some(&0));
    // Clear an old loader error, then resolve the NUL-terminated static name.
    unsafe { dlerror() };
    let p = unsafe { dlsym(handle, name.as_ptr().cast()) };
    let error = unsafe { dlerror() };
    if p.is_null() || !error.is_null() {
        let label = String::from_utf8_lossy(&name[..name.len() - 1]).into_owned();
        return Err(AccelError::MissingSymbol(label));
    }
    // POSIX specifies conversion between dlsym's void pointer and a function
    // pointer. transmute_copy avoids imposing a generic-size proof on T.
    Ok(unsafe { std::mem::transmute_copy(&p) })
}

fn dl_error() -> String {
    // SAFETY: dlerror returns either null or a process-owned NUL string.
    unsafe {
        let p = dlerror();
        if p.is_null() {
            "unknown dynamic-loader error".to_owned()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

unsafe fn c_error(p: *const c_char, rc: c_int) -> String {
    if p.is_null() {
        format!("status {rc}")
    } else {
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}
