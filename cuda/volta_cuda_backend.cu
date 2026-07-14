#include <cuda_runtime.h>

#include "volta_chacha8_fp.cuh"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <string>
#include <vector>

namespace volta_cuda_internal {

constexpr uint32_t ABI_VERSION = 28;
constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;
constexpr int BLOCK = 256;
constexpr int OP_COUNT = 7;
constexpr int OP_GEMM = 0;
constexpr int OP_LOGUP = 1;
constexpr int OP_PCS_ROWS = 2;
constexpr int OP_PCS_NTT = 3;
constexpr int OP_PCS_MERKLE = 4;
constexpr int OP_AUTH_MASKS = 5;
constexpr int OP_MAILBOX = 6;
constexpr uint64_t MOCK_CORRELATION_RESERVED_DOMAIN_BITS =
    (uint64_t{1} << 63) | (uint64_t{1} << 62) | (uint64_t{1} << 61);
constexpr int BUFFER_COUNT = 16;
constexpr size_t MATRIX_FOLD_TARGET_BLOCKS = 1024;
constexpr size_t MATRIX_FOLD_MAX_PARALLEL_OUTPUTS = 1024;
constexpr size_t MATRIX_FOLD_MAX_PARTIALS = 2 * MATRIX_FOLD_TARGET_BLOCKS - 2;
constexpr uint32_t TIMING_CUDA_EVENTS = 1;
constexpr uint32_t TIMING_HOST_BARRIER_WALL = 2;
constexpr uint32_t TIMING_CUDA_EVENTS_DEFERRED = 3;
constexpr uint32_t TIMING_WALL_ONLY_COUNTERS = 4;
constexpr size_t TIMING_RING_SIZE = 512;

struct alignas(16) Fp2 {
    uint64_t c0;
    uint64_t c1;
};

struct RawStats {
    uint64_t calls[OP_COUNT];
    uint64_t kernel_ns[OP_COUNT];
    uint64_t h2d_bytes;
    uint64_t d2h_bytes;
    /// Bytes copied entirely within this CUDA context. These are never H2D.
    uint64_t d2d_bytes;
    /// Bytes explicitly written as zero by resident device operations.
    uint64_t device_zeroed_bytes;
    /// Non-zero-tail output bytes materialized by device generators.
    uint64_t device_generated_bytes;
    uint64_t h2d_ns;
    uint64_t d2h_ns;
    /// Host wall around successful resident cudaMemcpyAsync API calls. These
    /// clocks add no CUDA work and are distinct from CUDA-event attribution.
    uint64_t resident_h2d_host_calls;
    uint64_t resident_d2h_host_calls;
    uint64_t resident_h2d_host_call_ns;
    uint64_t resident_d2h_host_call_ns;
    uint64_t synchronizations;
    uint64_t synchronization_ns;
    uint64_t sync_host_output;
    uint64_t sync_upload_lifetime;
    uint64_t sync_timing_flush;
    uint64_t sync_profiling_legacy;
    uint64_t sync_allocator_flush;
    uint64_t allocation_calls;
    uint64_t resident_alloc_requests;
    uint64_t resident_reuse_hits;
    uint64_t resident_free_requests;
    uint64_t physical_free_calls;
    uint64_t live_device_bytes;
    uint64_t peak_device_bytes;
    uint64_t timing_records;
    /// Every cudaEventElapsedTime attempt, including success/no-write.
    uint64_t timing_elapsed_query_attempts;
    /// cudaSuccess responses that did not populate a finite duration.
    uint64_t timing_elapsed_no_write;
    uint64_t timing_event_queries;
    /// Every CUDA event API call issued inside the measurement window.
    /// Wall-only counter mode must keep this exactly zero.
    uint64_t timing_event_api_calls;
    uint64_t timing_pending_high_water;
    uint64_t timing_flush_count;
    uint64_t coarse_timing_scopes;
    /// Sum of CUDA-event intervals sealed by coarse timing scopes. Unlike a
    /// per-kernel event, an interval may include device idle time while a
    /// remote runtime waits for the host to submit the next launch.
    uint64_t coarse_timing_ns;
    uint32_t timing_mode;
    uint32_t reserved;
};

static_assert(sizeof(RawStats) == 392, "RawStats ABI layout changed");

enum class SyncReason {
    HostOutput,
    UploadLifetime,
    TimingFlush,
    ProfilingLegacy,
    AllocatorFlush,
};

struct Buffer {
    void* ptr = nullptr;
    size_t capacity = 0;
};

/// Physical allocation owned by a CUDA context and addressed through a
/// generational opaque id while active. Inactive slots retain their physical
/// storage for best-fit reuse. Active pointers never move.
struct ResidentBuffer {
    void* ptr = nullptr;
    size_t capacity = 0;
    size_t logical_bytes = 0;
    uint32_t generation = 0;
    bool active = false;
};

enum class TimingRecordKind {
    Operation,
    CoarseOperation,
    TransferH2D,
    TransferD2H,
};

/// One lazy slot in the deferred event ring. Pageable H2D source lifetime is
/// governed by the CUDA runtime staging contract and validated by the Rust
/// mutate-after-upload differential; records deliberately retain no payload.
struct TimingRecord {
    cudaEvent_t events[4]{};
    TimingRecordKind kind = TimingRecordKind::Operation;
    int operation = -1;
    /// Internal ring invariants and failure diagnostics. These fields are not
    /// part of the C ABI and add no CUDA calls on the success path.
    uint64_t generation = 0;
    uint8_t event_mask = 0;
    uint8_t fresh_event_mask = 0;
    bool committed = false;
    uint64_t h2d_bytes = 0;
    uint64_t d2h_bytes = 0;
    uint64_t d2d_bytes = 0;
    uint64_t device_zeroed_bytes = 0;
    uint64_t device_generated_bytes = 0;
    uint64_t measured_ns[3]{};
};

constexpr uint64_t RESIDENT_SLOT_MASK = std::numeric_limits<uint32_t>::max();
constexpr uint32_t RESIDENT_GENERATION_MAX = std::numeric_limits<uint32_t>::max();

struct Context {
    cudaStream_t stream = nullptr;
    cudaEvent_t events[4]{};
    Buffer buffers[BUFFER_COUNT];
    std::vector<ResidentBuffer> resident;
    std::vector<size_t> inactive_resident;
    RawStats stats{};
    size_t twiddle_size = 0;
    uint32_t timing_mode = TIMING_CUDA_EVENTS;
    std::array<TimingRecord, TIMING_RING_SIZE> timing_ring;
    size_t timing_ring_begin = 0;
    size_t timing_ring_pending = 0;
    size_t active_timing_record = TIMING_RING_SIZE;
    uint64_t timing_record_generation = 0;
    uint64_t timing_event_count = 0;
    uint32_t test_elapsed_no_write_remaining = 0;
    bool coarse_timing_active = false;
    bool coarse_inner_active = false;
    bool counter_timing_active = false;
    /// Counter-only mode has enqueued stream work not yet covered by a
    /// required synchronization boundary.
    bool counter_stream_pending = false;
    /// At least one primitive has committed call/byte accounting into the
    /// currently active coarse scope. Aborting such a scope loses its only
    /// timing interval, so the measurement must become unreadable.
    bool coarse_accounted_work = false;
    /// Fail-closed latch for call/byte accounting whose enclosing timing
    /// interval was discarded. This is internal state, not part of ABI 27.
    bool measurement_poisoned = false;
    int coarse_timing_operation = -1;
    std::chrono::steady_clock::time_point phase_started{};
    std::array<uint64_t, 3> phase_ns{};
    std::string error;
};

int fail_message(Context* c, const char* message) noexcept;

void abort_active_timing_record(Context* c) noexcept {
    if (!c) return;
    if (c->coarse_accounted_work) c->measurement_poisoned = true;
    if (c->active_timing_record != TIMING_RING_SIZE) {
        TimingRecord& record = c->timing_ring[c->active_timing_record];
        record.event_mask = 0;
        record.committed = false;
    }
    c->active_timing_record = TIMING_RING_SIZE;
    c->coarse_timing_active = false;
    c->coarse_inner_active = false;
    c->counter_timing_active = false;
    c->coarse_accounted_work = false;
    c->coarse_timing_operation = -1;
}

uint64_t resident_id(size_t slot, uint32_t generation) {
    return (static_cast<uint64_t>(generation) << 32) | (slot + 1);
}

ResidentBuffer* find_resident(Context* c, uint64_t id) {
    if (!c || id == 0) return nullptr;
    const uint64_t encoded_slot = id & RESIDENT_SLOT_MASK;
    const uint32_t generation = static_cast<uint32_t>(id >> 32);
    if (encoded_slot == 0 || generation == 0) return nullptr;
    const size_t slot = static_cast<size_t>(encoded_slot - 1);
    if (slot >= c->resident.size()) return nullptr;
    ResidentBuffer& b = c->resident[slot];
    return b.active && b.generation == generation ? &b : nullptr;
}

int resident_region(
    Context* c, uint64_t id, size_t offset, size_t bytes, void** out) {
    ResidentBuffer* b = find_resident(c, id);
    if (!b) return fail_message(c, "unknown resident buffer id");
    if (offset > b->logical_bytes || bytes > b->logical_bytes - offset)
        return fail_message(c, "resident buffer region is out of bounds");
    *out = static_cast<unsigned char*>(b->ptr) + offset;
    return 0;
}

bool checked_mul_size(size_t a, size_t b, size_t* out) {
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
    *out = a * b;
    return true;
}

bool checked_add_size(size_t a, size_t b, size_t* out) {
    if (b > std::numeric_limits<size_t>::max() - a) return false;
    *out = a + b;
    return true;
}

int resident_strided_region(
    Context* c, uint64_t id, size_t offset, size_t stride,
    size_t row_bytes, size_t rows, void** out, size_t* span_bytes) {
    if (!rows || !row_bytes || stride < row_bytes)
        return fail_message(c, "invalid resident strided-row geometry");
    size_t prefix = 0;
    if (!checked_mul_size(rows - 1, stride, &prefix) ||
        !checked_add_size(prefix, row_bytes, span_bytes))
        return fail_message(c, "resident strided-row geometry overflows size_t");
    return resident_region(c, id, offset, *span_bytes, out);
}

int fail(Context* c, const char* expr, cudaError_t e) noexcept {
    abort_active_timing_record(c);
    if (c) {
        try {
            c->error = std::string(expr) + ": " + cudaGetErrorString(e);
        } catch (...) {
            // A diagnostic allocation failure must not escape the C ABI.
        }
    }
    return e == cudaSuccess ? -1 : static_cast<int>(e);
}

int fail_message(Context* c, const char* message) noexcept {
    abort_active_timing_record(c);
    if (c) {
        try {
            c->error = message;
        } catch (...) {
            // A diagnostic allocation failure must not escape the C ABI.
        }
    }
    return -1;
}

/// Reject a control operation without aborting a valid surrounding coarse
/// timing scope. This is used for nested-scope attempts and forbidden host
/// boundaries that fail before any CUDA work is enqueued.
int reject_message(Context* c, const char* message) noexcept {
    if (c) {
        try {
            c->error = message;
        } catch (...) {
            // Reporting a rejected control operation must remain noexcept.
        }
    }
    return -1;
}

int fail_exception(Context* c, const char* message) noexcept {
    abort_active_timing_record(c);
    if (c) {
        try {
            c->error = message;
        } catch (...) {
            // Reporting an allocation failure must itself remain noexcept.
        }
    }
    return -1;
}

uint64_t& sync_reason_counter(RawStats& stats, SyncReason reason) {
    switch (reason) {
        case SyncReason::HostOutput: return stats.sync_host_output;
        case SyncReason::UploadLifetime: return stats.sync_upload_lifetime;
        case SyncReason::TimingFlush: return stats.sync_timing_flush;
        case SyncReason::ProfilingLegacy: return stats.sync_profiling_legacy;
        case SyncReason::AllocatorFlush: return stats.sync_allocator_flush;
    }
    return stats.sync_profiling_legacy;
}

uint64_t synchronization_reason_total(const RawStats& stats) {
    return stats.sync_host_output + stats.sync_upload_lifetime +
           stats.sync_timing_flush + stats.sync_profiling_legacy +
           stats.sync_allocator_flush;
}

int synchronize_stream_unclassified(Context* c) {
    const auto started = std::chrono::steady_clock::now();
    const cudaError_t e = cudaStreamSynchronize(c->stream);
    const auto finished = std::chrono::steady_clock::now();
    if (e != cudaSuccess) return fail(c, "cudaStreamSynchronize(c->stream)", e);
    c->counter_stream_pending = false;
    ++c->stats.synchronizations;
    c->stats.synchronization_ns +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(finished - started).count();
    return 0;
}

int synchronize_stream(Context* c, SyncReason reason) {
    if (synchronize_stream_unclassified(c)) return -1;
    ++sync_reason_counter(c->stats, reason);
    return 0;
}

int flush_deferred_timing(Context* c, SyncReason reason);

int synchronize_for_reclamation(Context* c) {
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED && c->timing_ring_pending)
        return flush_deferred_timing(c, SyncReason::AllocatorFlush);
    return synchronize_stream(c, SyncReason::AllocatorFlush);
}

int ensure_resident_slot_capacity(Context* c) {
    if (c->resident.size() < c->resident.capacity() &&
        c->resident.size() < c->inactive_resident.capacity())
        return 0;
    const size_t current = c->resident.capacity();
    const size_t next = current == 0 ? 16 : current * 2;
    if (next <= current || next > RESIDENT_SLOT_MASK)
        return fail_message(c, "resident slot id space exhausted");
    c->resident.reserve(next);
    c->inactive_resident.reserve(next);
    return 0;
}

size_t take_best_fit_resident(Context* c, size_t bytes) {
    size_t best_position = std::numeric_limits<size_t>::max();
    size_t best_capacity = std::numeric_limits<size_t>::max();
    size_t best_slot = std::numeric_limits<size_t>::max();
    for (size_t position = 0; position < c->inactive_resident.size(); ++position) {
        const size_t slot = c->inactive_resident[position];
        const ResidentBuffer& b = c->resident[slot];
        if (b.active || !b.ptr || b.generation == RESIDENT_GENERATION_MAX ||
            b.capacity < bytes)
            continue;
        if (b.capacity < best_capacity ||
            (b.capacity == best_capacity && slot < best_slot)) {
            best_position = position;
            best_capacity = b.capacity;
            best_slot = slot;
        }
    }
    if (best_position == std::numeric_limits<size_t>::max()) return best_position;
    c->inactive_resident[best_position] = c->inactive_resident.back();
    c->inactive_resident.pop_back();
    return best_slot;
}

size_t take_empty_resident_slot(Context* c) {
    for (size_t position = 0; position < c->inactive_resident.size(); ++position) {
        const size_t slot = c->inactive_resident[position];
        const ResidentBuffer& b = c->resident[slot];
        if (b.active || b.ptr || b.generation == RESIDENT_GENERATION_MAX) continue;
        c->inactive_resident[position] = c->inactive_resident.back();
        c->inactive_resident.pop_back();
        return slot;
    }
    return std::numeric_limits<size_t>::max();
}

int trim_inactive_resident(Context* c) {
    bool has_cached_allocation = false;
    for (const size_t slot : c->inactive_resident) {
        const ResidentBuffer& b = c->resident[slot];
        if (!b.active && b.ptr) {
            has_cached_allocation = true;
            break;
        }
    }
    if (!has_cached_allocation) return 0;

    if (synchronize_for_reclamation(c)) return -1;
    for (const size_t slot : c->inactive_resident) {
        ResidentBuffer& b = c->resident[slot];
        if (b.active || !b.ptr) continue;
        const cudaError_t e = cudaFree(b.ptr);
        if (e != cudaSuccess) return fail(c, "cudaFree(cached resident buffer)", e);
        ++c->stats.physical_free_calls;
        c->stats.live_device_bytes -= b.capacity;
        b.ptr = nullptr;
        b.capacity = 0;
        b.logical_bytes = 0;
    }
    return 0;
}

#define CUDA_OR_RETURN(c, call)                                                           \
    do {                                                                                  \
        cudaError_t volta_e_ = (call);                                                    \
        if (volta_e_ != cudaSuccess) return fail((c), #call, volta_e_);                   \
    } while (0)

cudaError_t timing_event_create(Context* c, cudaEvent_t* event) {
    ++c->stats.timing_event_api_calls;
    return cudaEventCreate(event);
}

cudaError_t timing_event_record(Context* c, cudaEvent_t event) {
    ++c->stats.timing_event_api_calls;
    return cudaEventRecord(event, c->stream);
}

cudaError_t timing_event_elapsed(
    Context* c, float* ms, cudaEvent_t start, cudaEvent_t end) {
    ++c->stats.timing_event_api_calls;
    return cudaEventElapsedTime(ms, start, end);
}

cudaError_t timing_event_query(Context* c, cudaEvent_t event) {
    ++c->stats.timing_event_api_calls;
    return cudaEventQuery(event);
}

int ensure(Context* c, int slot, size_t bytes) {
    if (slot < 0 || slot >= BUFFER_COUNT) return fail_message(c, "invalid workspace slot");
    Buffer& b = c->buffers[slot];
    if (b.capacity >= bytes) return 0;
    if (c->coarse_timing_active) {
        const std::string message =
            "workspace slot " + std::to_string(slot) + " growth from " +
            std::to_string(b.capacity) + " to " + std::to_string(bytes) +
            " bytes is forbidden inside a coarse timing scope";
        return reject_message(c, message.c_str());
    }
    if (b.ptr) {
        if (synchronize_for_reclamation(c)) return -1;
        CUDA_OR_RETURN(c, cudaFree(b.ptr));
        ++c->stats.physical_free_calls;
        c->stats.live_device_bytes -= b.capacity;
        b = Buffer{};
    }
    CUDA_OR_RETURN(c, cudaMalloc(&b.ptr, bytes));
    b.capacity = bytes;
    ++c->stats.allocation_calls;
    c->stats.live_device_bytes += bytes;
    c->stats.peak_device_bytes =
        std::max(c->stats.peak_device_bytes, c->stats.live_device_bytes);
    return 0;
}

template <typename T>
T* buf(Context* c, int slot) {
    return reinterpret_cast<T*>(c->buffers[slot].ptr);
}

const char* timing_record_kind_name(TimingRecordKind kind) {
    switch (kind) {
        case TimingRecordKind::Operation: return "operation";
        case TimingRecordKind::CoarseOperation: return "coarse";
        case TimingRecordKind::TransferH2D: return "transfer-h2d";
        case TimingRecordKind::TransferD2H: return "transfer-d2h";
    }
    return "unknown";
}

uint8_t expected_event_mask(TimingRecordKind kind) {
    return kind == TimingRecordKind::Operation ? 0x0f : 0x03;
}

int query_event_ns_once(
    Context* c, cudaEvent_t a, cudaEvent_t b, uint64_t* out, bool* resolved) {
    ++c->stats.timing_elapsed_query_attempts;
    if (c->test_elapsed_no_write_remaining) {
        --c->test_elapsed_no_write_remaining;
        ++c->stats.timing_elapsed_no_write;
        *resolved = false;
        return 0;
    }
    float ms = -1.0f;
    const cudaError_t e = timing_event_elapsed(c, &ms, a, b);
    if (e != cudaSuccess) return fail(c, "cudaEventElapsedTime", e);
    if (std::isfinite(ms) && ms >= 0.0f) {
        *out = static_cast<uint64_t>(ms * 1'000'000.0f);
        ++c->stats.timing_event_queries;
        *resolved = true;
    } else {
        ++c->stats.timing_elapsed_no_write;
        *resolved = false;
    }
    return 0;
}

int event_ns(Context* c, cudaEvent_t a, cudaEvent_t b, uint64_t* out) {
    // Legacy mode cannot interleave multiple records, but remains bounded and
    // exact: an absent duration never becomes zero or a host-wall estimate.
    constexpr int ELAPSED_QUERY_ATTEMPTS = 4;
    for (int attempt = 0; attempt < ELAPSED_QUERY_ATTEMPTS; ++attempt) {
        bool resolved = false;
        if (query_event_ns_once(c, a, b, out, &resolved)) return -1;
        if (resolved) return 0;
    }
    return fail_message(
        c, "cudaEventElapsedTime returned success without a duration after bounded retries");
}

struct DeferredElapsedQuery {
    TimingRecord* record = nullptr;
    cudaEvent_t start = nullptr;
    cudaEvent_t end = nullptr;
    uint64_t* out = nullptr;
    size_t slot = TIMING_RING_SIZE;
    size_t offset = TIMING_RING_SIZE;
    int start_event = -1;
    int end_event = -1;
};

int fail_unresolved_elapsed(
    Context* c, const DeferredElapsedQuery& query, size_t unresolved_count,
    int retry_sweeps) {
    const TimingRecord& record = *query.record;
    const cudaError_t start_status = timing_event_query(c, query.start);
    const cudaError_t end_status = timing_event_query(c, query.end);
    char message[1024];
    std::snprintf(
        message, sizeof(message),
        "deferred timing elapsed no-write: slot=%zu offset=%zu kind=%s op=%d "
        "generation=%llu event_mask=0x%02x expected_mask=0x%02x fresh_mask=0x%02x "
        "event_count=%llu query_attempts=%llu successful_queries=%llu no_write=%llu "
        "h2d_bytes=%llu d2h_bytes=%llu pair=%d->%d unresolved=%zu retry_sweeps=%d "
        "ring_begin=%zu pending=%zu active=%zu start_event=%p end_event=%p "
        "start_query=%s(%d) end_query=%s(%d)",
        query.slot, query.offset, timing_record_kind_name(record.kind), record.operation,
        static_cast<unsigned long long>(record.generation), record.event_mask,
        expected_event_mask(record.kind), record.fresh_event_mask,
        static_cast<unsigned long long>(c->timing_event_count),
        static_cast<unsigned long long>(c->stats.timing_elapsed_query_attempts),
        static_cast<unsigned long long>(c->stats.timing_event_queries),
        static_cast<unsigned long long>(c->stats.timing_elapsed_no_write),
        static_cast<unsigned long long>(record.h2d_bytes),
        static_cast<unsigned long long>(record.d2h_bytes), query.start_event,
        query.end_event, unresolved_count, retry_sweeps,
        c->timing_ring_begin, c->timing_ring_pending, c->active_timing_record,
        static_cast<void*>(query.start), static_cast<void*>(query.end),
        cudaGetErrorString(start_status), static_cast<int>(start_status),
        cudaGetErrorString(end_status), static_cast<int>(end_status));
    return fail_message(c, message);
}

int validate_deferred_record(
    Context* c, const TimingRecord& record, size_t slot, size_t offset) {
    const uint8_t expected = expected_event_mask(record.kind);
    if (record.committed && record.event_mask == expected) return 0;
    char message[512];
    std::snprintf(
        message, sizeof(message),
        "invalid deferred timing record: slot=%zu offset=%zu kind=%s op=%d "
        "generation=%llu committed=%d event_mask=0x%02x expected_mask=0x%02x "
        "ring_begin=%zu pending=%zu active=%zu",
        slot, offset, timing_record_kind_name(record.kind), record.operation,
        static_cast<unsigned long long>(record.generation), record.committed ? 1 : 0,
        record.event_mask, expected, c->timing_ring_begin, c->timing_ring_pending,
        c->active_timing_record);
    return fail_message(c, message);
}

int ensure_record_events(Context* c, TimingRecord& record, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        if (record.events[i]) continue;
        CUDA_OR_RETURN(c, timing_event_create(c, &record.events[i]));
        record.fresh_event_mask |= 1u << i;
        ++c->timing_event_count;
    }
    return 0;
}

int flush_deferred_timing(Context* c, SyncReason reason) {
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED || !c->timing_ring_pending) return 0;
    if (synchronize_stream(c, reason)) return -1;
    ++c->stats.timing_flush_count;

    // Query every required phase once before retrying any provider no-write.
    // Thunder can return cudaSuccess without populating the duration; issuing
    // other endpoint queries before a bounded retry breaks that provider
    // cache/burst condition while preserving exact CUDA-event attribution.
    // Attribution is committed only after every phase has resolved.
    std::array<DeferredElapsedQuery, TIMING_RING_SIZE * 3> unresolved{};
    size_t unresolved_count = 0;
    const auto query_or_defer = [&c, &unresolved, &unresolved_count](
        TimingRecord& record, size_t slot, size_t offset,
        int start_event, int end_event, uint64_t* out) -> int {
        bool resolved = false;
        if (query_event_ns_once(
                c, record.events[start_event], record.events[end_event], out,
                &resolved)) return -1;
        if (resolved) return 0;
        if (unresolved_count == unresolved.size())
            return fail_message(c, "deferred elapsed retry set exceeds fixed capacity");
        unresolved[unresolved_count++] = DeferredElapsedQuery{
            &record,
            record.events[start_event],
            record.events[end_event],
            out,
            slot,
            offset,
            start_event,
            end_event,
        };
        return 0;
    };
    for (size_t offset = 0; offset < c->timing_ring_pending; ++offset) {
        const size_t slot = (c->timing_ring_begin + offset) % TIMING_RING_SIZE;
        TimingRecord& record = c->timing_ring[slot];
        if (validate_deferred_record(c, record, slot, offset)) return -1;
        if (record.kind == TimingRecordKind::Operation) {
            // Every elapsed-time query is itself a CUDA API call. On a
            // remote runtime, do not issue empty phase queries merely to
            // recover a zero already known from the byte counters.
            if ((record.h2d_bytes &&
                 query_or_defer(record, slot, offset, 0, 1, &record.measured_ns[0])) ||
                query_or_defer(record, slot, offset, 1, 2, &record.measured_ns[1]) ||
                (record.d2h_bytes &&
                 query_or_defer(record, slot, offset, 2, 3, &record.measured_ns[2])))
                return -1;
        } else if (record.kind == TimingRecordKind::CoarseOperation) {
            if (query_or_defer(record, slot, offset, 0, 1, &record.measured_ns[1])) return -1;
        } else {
            if (query_or_defer(record, slot, offset, 0, 1, &record.measured_ns[0])) return -1;
        }
    }

    constexpr int ELAPSED_RETRY_SWEEPS = 3;
    int retry_sweeps = 0;
    for (; retry_sweeps < ELAPSED_RETRY_SWEEPS && unresolved_count; ++retry_sweeps) {
        size_t still_unresolved = 0;
        for (size_t i = 0; i < unresolved_count; ++i) {
            DeferredElapsedQuery query = unresolved[i];
            // Failure-path only: endpoint readiness calls interpose different
            // provider messages and prove that both recorded events remain
            // complete. No stream synchronization is added.
            const cudaError_t start_status = timing_event_query(c, query.start);
            if (start_status != cudaSuccess)
                return fail(c, "cudaEventQuery(deferred start)", start_status);
            const cudaError_t end_status = timing_event_query(c, query.end);
            if (end_status != cudaSuccess)
                return fail(c, "cudaEventQuery(deferred end)", end_status);
            bool resolved = false;
            if (query_event_ns_once(c, query.start, query.end, query.out, &resolved)) return -1;
            if (!resolved) unresolved[still_unresolved++] = query;
        }
        unresolved_count = still_unresolved;
    }
    if (unresolved_count)
        return fail_unresolved_elapsed(c, unresolved[0], unresolved_count, retry_sweeps);

    for (size_t offset = 0; offset < c->timing_ring_pending; ++offset) {
        TimingRecord& record =
            c->timing_ring[(c->timing_ring_begin + offset) % TIMING_RING_SIZE];
        if (record.kind == TimingRecordKind::Operation) {
            ++c->stats.calls[record.operation];
            c->stats.h2d_bytes += record.h2d_bytes;
            c->stats.d2h_bytes += record.d2h_bytes;
            c->stats.d2d_bytes += record.d2d_bytes;
            c->stats.device_zeroed_bytes += record.device_zeroed_bytes;
            c->stats.device_generated_bytes += record.device_generated_bytes;
            if (record.h2d_bytes) c->stats.h2d_ns += record.measured_ns[0];
            c->stats.kernel_ns[record.operation] += record.measured_ns[1];
            if (record.d2h_bytes) c->stats.d2h_ns += record.measured_ns[2];
        } else if (record.kind == TimingRecordKind::CoarseOperation) {
            // Inner primitive calls and byte materialization were accounted at
            // their ordinary finish boundary. The coarse record contributes
            // only the aggregate device interval and must not invent a call.
            // Keep its exact total separately: this interval is an upper bound
            // on kernel execution because remote launch-submit gaps can be
            // visible between the enclosing CUDA events.
            c->stats.kernel_ns[record.operation] += record.measured_ns[1];
            c->stats.coarse_timing_ns += record.measured_ns[1];
        } else {
            if (record.kind == TimingRecordKind::TransferH2D) {
                c->stats.h2d_bytes += record.h2d_bytes;
                c->stats.h2d_ns += record.measured_ns[0];
            } else {
                c->stats.d2h_bytes += record.d2h_bytes;
                c->stats.d2h_ns += record.measured_ns[0];
            }
        }
        record.committed = false;
        record.event_mask = 0;
    }
    c->timing_ring_begin =
        (c->timing_ring_begin + c->timing_ring_pending) % TIMING_RING_SIZE;
    c->timing_ring_pending = 0;
    return 0;
}

/// Establish a measurement boundary for work that is explicitly outside the
/// next stats window. The stream must complete before records can be reused;
/// once that synchronization succeeds, elapsed attribution would be thrown
/// away by reset and is therefore deliberately not queried. In-window flushes
/// continue to use the exact fail-closed path above.
int discard_deferred_timing(Context* c, SyncReason reason) {
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED || !c->timing_ring_pending) return 0;
    if (synchronize_stream(c, reason)) return -1;
    for (size_t offset = 0; offset < c->timing_ring_pending; ++offset) {
        const size_t slot = (c->timing_ring_begin + offset) % TIMING_RING_SIZE;
        if (validate_deferred_record(c, c->timing_ring[slot], slot, offset)) return -1;
    }
    for (size_t offset = 0; offset < c->timing_ring_pending; ++offset) {
        const size_t slot = (c->timing_ring_begin + offset) % TIMING_RING_SIZE;
        TimingRecord& record = c->timing_ring[slot];
        record.committed = false;
        record.event_mask = 0;
    }
    c->timing_ring_begin =
        (c->timing_ring_begin + c->timing_ring_pending) % TIMING_RING_SIZE;
    c->timing_ring_pending = 0;
    return 0;
}

int begin_deferred_record(Context* c, TimingRecordKind kind, size_t event_count) {
    if (c->active_timing_record != TIMING_RING_SIZE)
        return fail_message(c, "nested deferred timing record");
    if (c->timing_ring_pending == TIMING_RING_SIZE &&
        flush_deferred_timing(c, SyncReason::TimingFlush))
        return -1;
    const size_t slot =
        (c->timing_ring_begin + c->timing_ring_pending) % TIMING_RING_SIZE;
    TimingRecord& record = c->timing_ring[slot];
    if (record.committed)
        return fail_message(c, "deferred timing ring would overwrite a committed record");
    record.fresh_event_mask = 0;
    if (ensure_record_events(c, record, event_count)) return -1;
    record.kind = kind;
    record.operation = -1;
    ++c->timing_record_generation;
    if (!c->timing_record_generation) ++c->timing_record_generation;
    record.generation = c->timing_record_generation;
    record.event_mask = 0;
    record.committed = false;
    record.h2d_bytes = 0;
    record.d2h_bytes = 0;
    record.d2d_bytes = 0;
    record.device_zeroed_bytes = 0;
    record.device_generated_bytes = 0;
    record.measured_ns[0] = record.measured_ns[1] = record.measured_ns[2] = 0;
    CUDA_OR_RETURN(c, timing_event_record(c, record.events[0]));
    record.event_mask |= 1u << 0;
    c->active_timing_record = slot;
    return 0;
}

int commit_deferred_record(Context* c) {
    if (c->active_timing_record == TIMING_RING_SIZE)
        return fail_message(c, "no active deferred timing record");
    const size_t expected_slot =
        (c->timing_ring_begin + c->timing_ring_pending) % TIMING_RING_SIZE;
    if (c->active_timing_record != expected_slot)
        return fail_message(c, "deferred timing commit is not at the pending-ring tail");
    TimingRecord& record = c->timing_ring[c->active_timing_record];
    if (record.committed || record.event_mask != expected_event_mask(record.kind))
        return fail_message(c, "deferred timing commit has incomplete event markers");
    record.committed = true;
    c->active_timing_record = TIMING_RING_SIZE;
    ++c->timing_ring_pending;
    ++c->stats.timing_records;
    c->stats.timing_pending_high_water =
        std::max<uint64_t>(c->stats.timing_pending_high_water, c->timing_ring_pending);
    return 0;
}

int begin_timing(Context* c) {
    c->phase_ns.fill(0);
    if (c->coarse_timing_active) {
        if (c->coarse_inner_active)
            return reject_message(c, "nested primitive timing inside a coarse timing scope");
        c->coarse_inner_active = true;
        return 0;
    }
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        if (c->counter_timing_active)
            return reject_message(c, "nested counter-only timing record");
        c->counter_timing_active = true;
        return 0;
    }
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED)
        return begin_deferred_record(c, TimingRecordKind::Operation, 4);
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, timing_event_record(c, c->events[0]));
    } else {
        c->phase_started = std::chrono::steady_clock::now();
    }
    return 0;
}

int finish_host_phase(Context* c, int phase) {
    if (phase < 0 || phase >= 3) return fail_message(c, "invalid timing phase");
    // The host-barrier fallback has three distinct barriers. Their causes are
    // classified together in finish_timing once the operation's H2D/D2H
    // shape is known, rather than mislabelling every phase as profiling.
    if (synchronize_stream_unclassified(c)) return -1;
    const auto finished = std::chrono::steady_clock::now();
    c->phase_ns[phase] =
        std::chrono::duration_cast<std::chrono::nanoseconds>(finished - c->phase_started).count();
    c->phase_started = finished;
    return 0;
}

int mark_timing(Context* c, int event) {
    if (event != 1 && event != 2) return fail_message(c, "invalid timing event");
    if (c->coarse_timing_active) {
        if (!c->coarse_inner_active)
            return fail_message(c, "coarse timing marker without an active primitive");
        return 0;
    }
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        if (!c->counter_timing_active)
            return fail_message(c, "counter-only timing marker without active operation");
        return 0;
    }
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED) {
        if (c->active_timing_record == TIMING_RING_SIZE)
            return fail_message(c, "deferred timing marker without active record");
        CUDA_OR_RETURN(c, timing_event_record(
            c, c->timing_ring[c->active_timing_record].events[event]));
        c->timing_ring[c->active_timing_record].event_mask |= 1u << event;
        return 0;
    }
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, timing_event_record(c, c->events[event]));
        return 0;
    }
    return finish_host_phase(c, event - 1);
}

int select_timing_mode(Context* c) {
    CUDA_OR_RETURN(c, timing_event_record(c, c->events[0]));
    CUDA_OR_RETURN(c, timing_event_record(c, c->events[1]));
    CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
    float ms = -1.0f;
    const cudaError_t e = timing_event_elapsed(c, &ms, c->events[0], c->events[1]);
    if (e == cudaSuccess && ms >= 0.0f) {
        c->timing_mode = TIMING_CUDA_EVENTS;
    } else {
        // Some virtualized CUDA runtimes return success without writing the
        // elapsed-time output. Clear any sticky error and use explicit host
        // barriers rather than silently reporting zero device time.
        cudaGetLastError();
        c->timing_mode = TIMING_HOST_BARRIER_WALL;
    }
    c->stats.timing_mode = c->timing_mode;
    return 0;
}

int finish_timing(
    Context* c, int operation, uint64_t h2d, uint64_t d2h,
    uint64_t d2d = 0, uint64_t device_zeroed = 0,
    uint64_t device_generated = 0) {
    uint64_t h2d_ns = 0, kernel_ns = 0, d2h_ns = 0;
    if (c->coarse_timing_active) {
        if (!c->coarse_inner_active)
            return fail_message(c, "coarse timing finish without an active primitive");
        if (operation != c->coarse_timing_operation)
            return fail_message(c, "coarse timing scope received a different operation kind");
        if (h2d || d2h) {
            // A legacy staged primitive discovered only at its finish boundary
            // may already have enqueued a host transfer. Synchronize before
            // returning the error so no caller-owned host pointer can expire
            // while CUDA still references it. Resident upload/download reject
            // earlier in begin_transfer_timing and do not take this path.
            const SyncReason reason = d2h ? SyncReason::HostOutput : SyncReason::UploadLifetime;
            if (synchronize_stream(c, reason)) return -1;
            return fail_message(c, "host transfer is forbidden inside a coarse timing scope");
        }
        ++c->stats.calls[operation];
        c->stats.d2d_bytes += d2d;
        c->stats.device_zeroed_bytes += device_zeroed;
        c->stats.device_generated_bytes += device_generated;
        c->coarse_accounted_work = true;
        if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS)
            c->counter_stream_pending = true;
        c->coarse_inner_active = false;
        return 0;
    }
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        if (!c->counter_timing_active)
            return fail_message(c, "counter-only finish without active operation");
        c->counter_timing_active = false;
        c->counter_stream_pending = true;
        if (d2h && synchronize_stream(c, SyncReason::HostOutput)) return -1;
        ++c->stats.calls[operation];
        c->stats.h2d_bytes += h2d;
        c->stats.d2h_bytes += d2h;
        c->stats.d2d_bytes += d2d;
        c->stats.device_zeroed_bytes += device_zeroed;
        c->stats.device_generated_bytes += device_generated;
        return 0;
    } else if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED) {
        if (c->active_timing_record == TIMING_RING_SIZE)
            return fail_message(c, "deferred finish without active record");
        TimingRecord& record = c->timing_ring[c->active_timing_record];
        CUDA_OR_RETURN(c, timing_event_record(c, record.events[3]));
        record.event_mask |= 1u << 3;
        record.kind = TimingRecordKind::Operation;
        record.operation = operation;
        record.h2d_bytes = h2d;
        record.d2h_bytes = d2h;
        record.d2d_bytes = d2d;
        record.device_zeroed_bytes = device_zeroed;
        record.device_generated_bytes = device_generated;
        if (commit_deferred_record(c)) return -1;
        return d2h ? flush_deferred_timing(c, SyncReason::HostOutput) : 0;
    } else if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, timing_event_record(c, c->events[3]));
        const SyncReason reason = d2h ? SyncReason::HostOutput
            : (h2d ? SyncReason::UploadLifetime : SyncReason::ProfilingLegacy);
        if (synchronize_stream(c, reason)) return -1;
        if (event_ns(c, c->events[0], c->events[1], &h2d_ns) ||
            event_ns(c, c->events[1], c->events[2], &kernel_ns) ||
            event_ns(c, c->events[2], c->events[3], &d2h_ns)) return -1;
    } else {
        if (finish_host_phase(c, 2)) return -1;
        if (h2d) ++c->stats.sync_upload_lifetime;
        if (d2h) ++c->stats.sync_host_output;
        c->stats.sync_profiling_legacy += 3 - (h2d ? 1 : 0) - (d2h ? 1 : 0);
        h2d_ns = c->phase_ns[0];
        kernel_ns = c->phase_ns[1];
        d2h_ns = c->phase_ns[2];
    }
    ++c->stats.calls[operation];
    c->stats.h2d_bytes += h2d;
    c->stats.d2h_bytes += d2h;
    c->stats.d2d_bytes += d2d;
    c->stats.device_zeroed_bytes += device_zeroed;
    c->stats.device_generated_bytes += device_generated;
    if (h2d) c->stats.h2d_ns += h2d_ns;
    c->stats.kernel_ns[operation] += kernel_ns;
    if (d2h) c->stats.d2h_ns += d2h_ns;
    return 0;
}

/// Time one explicit host/device transfer without inventing a kernel call.
/// Resident uploads/downloads are protocol-visible boundaries and therefore
/// remain fully counted even when they happen outside a staged primitive.
int begin_transfer_timing(Context* c) {
    if (c->coarse_timing_active)
        return reject_message(c, "host transfer is forbidden inside a coarse timing scope");
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        if (c->counter_timing_active)
            return reject_message(c, "nested counter-only timing record");
        c->counter_timing_active = true;
        return 0;
    }
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED)
        return begin_deferred_record(c, TimingRecordKind::TransferH2D, 2);
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, timing_event_record(c, c->events[0]));
    } else {
        c->phase_started = std::chrono::steady_clock::now();
    }
    return 0;
}

int finish_transfer_timing(Context* c, size_t bytes, bool h2d) {
    uint64_t elapsed_ns = 0;
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        if (!c->counter_timing_active)
            return fail_message(c, "counter-only transfer finish without active transfer");
        c->counter_timing_active = false;
        c->counter_stream_pending = true;
        if (!h2d && synchronize_stream(c, SyncReason::HostOutput)) return -1;
        if (h2d) c->stats.h2d_bytes += bytes;
        else c->stats.d2h_bytes += bytes;
        return 0;
    } else if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED) {
        if (c->active_timing_record == TIMING_RING_SIZE)
            return fail_message(c, "deferred transfer finish without active record");
        TimingRecord& record = c->timing_ring[c->active_timing_record];
        CUDA_OR_RETURN(c, timing_event_record(c, record.events[1]));
        record.event_mask |= 1u << 1;
        record.kind = h2d ? TimingRecordKind::TransferH2D : TimingRecordKind::TransferD2H;
        record.h2d_bytes = h2d ? bytes : 0;
        record.d2h_bytes = h2d ? 0 : bytes;
        if (commit_deferred_record(c)) return -1;
        return h2d ? 0 : flush_deferred_timing(c, SyncReason::HostOutput);
    } else if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, timing_event_record(c, c->events[1]));
        if (synchronize_stream(
                c, h2d ? SyncReason::UploadLifetime : SyncReason::HostOutput)) return -1;
        if (event_ns(c, c->events[0], c->events[1], &elapsed_ns)) return -1;
    } else {
        if (synchronize_stream(
                c, h2d ? SyncReason::UploadLifetime : SyncReason::HostOutput)) return -1;
        const auto s1 = std::chrono::steady_clock::now();
        elapsed_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(s1 - c->phase_started).count();
    }
    if (h2d) {
        c->stats.h2d_bytes += bytes;
        c->stats.h2d_ns += elapsed_ns;
    } else {
        c->stats.d2h_bytes += bytes;
        c->stats.d2h_ns += elapsed_ns;
    }
    return 0;
}

__host__ __device__ inline uint64_t fp_add(uint64_t a, uint64_t b) {
    const uint64_t r0 = a + b;
    const bool carry = r0 < a;
    uint64_t r = carry ? r0 + EPSILON : r0;
    if (r >= P) r -= P;
    return r;
}

__host__ __device__ inline uint64_t fp_sub(uint64_t a, uint64_t b) {
    const uint64_t r = a - b;
    return a < b ? r - EPSILON : r;
}

__host__ __device__ inline uint64_t fp_neg(uint64_t a) {
    return a == 0 ? 0 : P - a;
}

__host__ __device__ inline uint64_t fp_mul(uint64_t a, uint64_t b) {
#ifdef __CUDA_ARCH__
    const uint64_t lo = a * b;
    const uint64_t hi = __umul64hi(a, b);
#else
    const unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
    const uint64_t lo = static_cast<uint64_t>(product);
    const uint64_t hi = static_cast<uint64_t>(product >> 64);
#endif
    const uint64_t hi_hi = hi >> 32;
    const uint64_t hi_lo = hi & EPSILON;
    const bool borrow = lo < hi_hi;
    uint64_t t = lo - hi_hi;
    if (borrow) t -= EPSILON;
    const uint64_t t1 = hi_lo * EPSILON;
    const uint64_t r0 = t + t1;
    const bool carry = r0 < t;
    uint64_t r = carry ? r0 + EPSILON : r0;
    if (r >= P) r -= P;
    return r;
}

uint64_t fp_pow(uint64_t base, uint64_t exponent) {
    uint64_t acc = 1;
    while (exponent) {
        if (exponent & 1) acc = fp_mul(acc, base);
        base = fp_mul(base, base);
        exponent >>= 1;
    }
    return acc;
}

__host__ __device__ inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    return Fp2{fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 fp2_sub(Fp2 a, Fp2 b) {
    return Fp2{fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    return Fp2{
        fp_add(fp_mul(a.c0, b.c0), fp_mul(7, fp_mul(a.c1, b.c1))),
        fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
    };
}

__host__ __device__ inline Fp2 fp2_mul_base(Fp2 a, uint64_t b) {
    return Fp2{fp_mul(a.c0, b), fp_mul(a.c1, b)};
}

// -------------------------------------------------------------------------
// Resident-only device materialization and device-to-device movement
// -------------------------------------------------------------------------

__global__ void chacha8_prover_secret_fp_rows_kernel(
    volta::chacha8_fp::Key key, uint64_t base_domain,
    size_t rows, size_t count, uint64_t* output) {
    const size_t first = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t row = first; row < rows; row += stride) {
        volta::chacha8_fp::Stream stream(key, base_domain + static_cast<uint64_t>(row));
        uint64_t* out = output + row * count;
        for (size_t column = 0; column < count; ++column) out[column] = stream.next_fp();
    }
}

__global__ void chacha8_prover_secret_fp2_padded_rows_kernel(
    volta::chacha8_fp::Key key, uint64_t base_domain,
    size_t rows, size_t count, size_t padded_count, Fp2* output) {
    const size_t first = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t stride = static_cast<size_t>(gridDim.x) * blockDim.x;
    for (size_t row = first; row < rows; row += stride) {
        volta::chacha8_fp::Stream stream(key, base_domain + static_cast<uint64_t>(row));
        Fp2* out = output + row * padded_count;
        for (size_t column = 0; column < count; ++column) {
            const volta::chacha8_fp::Fp2 value = stream.next_fp2();
            out[column] = Fp2{value.c0, value.c1};
        }
        for (size_t column = count; column < padded_count; ++column)
            out[column] = Fp2{0, 0};
    }
}

__global__ void fp2_row_dots_kernel(
    const Fp2* a, size_t a_stride, const Fp2* b, size_t b_stride,
    Fp2* output, size_t rows, size_t len) {
    __shared__ Fp2 partial[BLOCK];
    for (size_t row = blockIdx.x; row < rows; row += gridDim.x) {
        Fp2 acc{0, 0};
        for (size_t column = threadIdx.x; column < len; column += blockDim.x)
            acc = fp2_add(acc, fp2_mul(a[row * a_stride + column], b[row * b_stride + column]));
        partial[threadIdx.x] = acc;
        __syncthreads();
        for (unsigned int width = blockDim.x / 2; width != 0; width >>= 1) {
            if (threadIdx.x < width)
                partial[threadIdx.x] = fp2_add(partial[threadIdx.x], partial[threadIdx.x + width]);
            __syncthreads();
        }
        if (threadIdx.x == 0) output[row] = partial[0];
        __syncthreads();
    }
}

__global__ void fp2_powers_kernel(Fp2 base, Fp2* output, size_t count) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    Fp2 current = base;
    for (size_t i = 0; i < count; ++i) {
        output[i] = current;
        current = fp2_mul(current, base);
    }
}

// -------------------------------------------------------------------------
// GEMM + fused requant/authentication
// -------------------------------------------------------------------------

__device__ inline int16_t requant_clamped(int64_t acc, uint32_t shift) {
    const int64_t rounded = (acc + (int64_t{1} << (shift - 1))) >> shift;
    return static_cast<int16_t>(max(int64_t{-32768}, min(int64_t{32767}, rounded)));
}

__global__ void gemm_i64_kernel(
    const int16_t* a, const int16_t* b, int64_t* out, size_t m, size_t k, size_t n) {
    const size_t j = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t i = static_cast<size_t>(blockIdx.y) * blockDim.y + threadIdx.y;
    if (i >= m || j >= n) return;
    int64_t acc = 0;
    for (size_t q = 0; q < k; ++q) {
        acc += static_cast<int64_t>(a[i * k + q]) * static_cast<int64_t>(b[q * n + j]);
    }
    out[i * n + j] = acc;
}

__global__ void gemm_requant_auth_kernel(
    const int16_t* a, const int16_t* b, const uint64_t* masks, int16_t* out,
    uint64_t* corrections, size_t m, size_t k, size_t n, uint32_t shift) {
    const size_t j = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t i = static_cast<size_t>(blockIdx.y) * blockDim.y + threadIdx.y;
    if (i >= m || j >= n) return;
    int64_t acc = 0;
    for (size_t q = 0; q < k; ++q) {
        acc += static_cast<int64_t>(a[i * k + q]) * static_cast<int64_t>(b[q * n + j]);
    }
    const size_t z = i * n + j;
    const int16_t y = requant_clamped(acc, shift);
    out[z] = y;
    const uint64_t fy = y >= 0 ? static_cast<uint64_t>(y) : P - static_cast<uint64_t>(-int64_t{y});
    corrections[z] = fp_sub(fy, masks[z]);
}

// -------------------------------------------------------------------------
// Shape-parametric fixed-point forward primitives
// -------------------------------------------------------------------------

__device__ inline int64_t fixed_floor_div(int64_t a, int64_t b) {
    const int64_t q = a / b;
    const int64_t r = a % b;
    return r < 0 ? q - 1 : q;
}

/// Frozen quantization semantics: shifts above 16 are two round-half-up
/// stages (s-16, then 16), and saturation is forbidden rather than clamped.
__device__ inline int16_t fixed_requant_no_clamp(
    int64_t acc, uint32_t shift, uint32_t* error) {
    int64_t stage = acc;
    uint32_t final_shift = shift;
    if (shift > 16) {
        const uint32_t first = shift - 16;
        stage = (stage + (int64_t{1} << (first - 1))) >> first;
        final_shift = 16;
    }
    const int64_t rounded =
        (stage + (int64_t{1} << (final_shift - 1))) >> final_shift;
    if (rounded < INT16_MIN || rounded > INT16_MAX) atomicExch(error, 1u);
    return static_cast<int16_t>(rounded);
}

__global__ void fixed_embed_kernel(
    const uint32_t* tokens, const int16_t* wte, const int16_t* wpe,
    int64_t* acc_out, int16_t* out, uint32_t* error, size_t rows,
    size_t d, size_t vocab, size_t positions, size_t pos0, int32_t shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = rows * d;
    if (z >= total) return;
    const size_t row = z / d;
    const size_t col = z % d;
    const uint32_t token = tokens[row];
    if (token >= vocab || pos0 + row >= positions) {
        atomicExch(error, 1u);
        acc_out[z] = 0;
        out[z] = 0;
        return;
    }
    const int64_t acc = static_cast<int64_t>(wte[static_cast<size_t>(token) * d + col]) +
        static_cast<int64_t>(wpe[(pos0 + row) * d + col]);
    acc_out[z] = acc;
    if (shift > 0) {
        out[z] = fixed_requant_no_clamp(acc, static_cast<uint32_t>(shift), error);
    } else {
        const int64_t value = acc << static_cast<uint32_t>(-shift);
        if (value < INT16_MIN || value > INT16_MAX) atomicExch(error, 1u);
        out[z] = static_cast<int16_t>(value);
    }
}

__global__ void fixed_layer_norm_kernel(
    const int16_t* input, const int16_t* gain, const int16_t* bias,
    const int16_t* rsqrt_lut, int64_t* means, int64_t* vars,
    int64_t* rsqrt_inputs, int16_t* rsqrt_outputs, int64_t* accumulators,
    int16_t* outputs,
    uint32_t* error, size_t rows, size_t d, uint32_t var_shift,
    uint32_t norm_shift) {
    const size_t row_index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (row_index >= rows) return;
    const int16_t* row = input + row_index * d;
    int64_t sum = 0;
    for (size_t j = 0; j < d; ++j) sum += row[j];
    const int64_t di = static_cast<int64_t>(d);
    const int64_t mean = fixed_floor_div(sum + di / 2, di);
    int64_t variance_sum = 0;
    for (size_t j = 0; j < d; ++j) {
        const int64_t delta = static_cast<int64_t>(row[j]) - mean;
        variance_sum += delta * delta;
    }
    const int64_t variance = fixed_floor_div(variance_sum + di / 2, di);
    int64_t rsqrt_input = variance >> var_shift;
    if (rsqrt_input < 0 || rsqrt_input >= (int64_t{1} << 16)) {
        atomicExch(error, 1u);
        rsqrt_input = 0;
    }
    const int16_t rsqrt_output = rsqrt_lut[rsqrt_input];
    means[row_index] = mean;
    vars[row_index] = variance;
    rsqrt_inputs[row_index] = rsqrt_input;
    rsqrt_outputs[row_index] = rsqrt_output;
    for (size_t j = 0; j < d; ++j) {
        const int64_t delta = static_cast<int64_t>(row[j]) - mean;
        const int64_t acc = delta * static_cast<int64_t>(rsqrt_output) *
            static_cast<int64_t>(gain[j]) +
            (static_cast<int64_t>(bias[j]) << norm_shift);
        accumulators[row_index * d + j] = acc;
        outputs[row_index * d + j] =
            fixed_requant_no_clamp(acc, norm_shift, error);
    }
}

__global__ void fixed_gemm_kernel(
    const int16_t* input, const int16_t* weights, const int16_t* bias,
    const int16_t* residual, int64_t* accumulators, int16_t* requantized,
    int16_t* residual_out, uint32_t* error, size_t m, size_t k, size_t n,
    uint32_t shift) {
    const size_t j = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t i = static_cast<size_t>(blockIdx.y) * blockDim.y + threadIdx.y;
    if (i >= m || j >= n) return;
    int64_t acc = 0;
    for (size_t q = 0; q < k; ++q) {
        acc += static_cast<int64_t>(input[i * k + q]) *
            static_cast<int64_t>(weights[q * n + j]);
    }
    if (bias) acc += static_cast<int64_t>(bias[j]) << shift;
    const size_t z = i * n + j;
    accumulators[z] = acc;
    const int16_t q = fixed_requant_no_clamp(acc, shift, error);
    requantized[z] = q;
    if (residual_out) {
        const int32_t value = static_cast<int32_t>(q) + residual[z];
        if (value < INT16_MIN || value > INT16_MAX) atomicExch(error, 1u);
        residual_out[z] = static_cast<int16_t>(value);
    }
}

__global__ void fixed_qkv_split_kernel(
    const int16_t* qkv, int16_t* q, int16_t* k, int16_t* v,
    size_t rows, size_t d) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * d) return;
    const size_t row = z / d;
    const size_t col = z % d;
    const int16_t* source = qkv + row * 3 * d;
    q[z] = source[col];
    k[z] = source[d + col];
    v[z] = source[2 * d + col];
}

__host__ __device__ inline size_t packed_row_prefix(size_t row, size_t pos0) {
    return row * pos0 + row * (row + 1) / 2;
}

__global__ void fixed_attention_scores_kernel(
    const int16_t* q, const int16_t* k, int64_t* accumulators,
    int16_t* outputs, uint32_t* error, size_t rows, size_t seq,
    size_t pos0, size_t heads, size_t head_dim, uint32_t shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = heads * rows * seq;
    if (z >= total) return;
    const size_t col = z % seq;
    const size_t tmp = z / seq;
    const size_t row = tmp % rows;
    const size_t head = tmp / rows;
    const size_t qpos = pos0 + row;
    if (col > qpos) return;
    const size_t d = heads * head_dim;
    int64_t acc = 0;
    for (size_t l = 0; l < head_dim; ++l) {
        acc += static_cast<int64_t>(q[row * d + head * head_dim + l]) *
            static_cast<int64_t>(k[col * d + head * head_dim + l]);
    }
    const size_t per_head = rows * pos0 + rows * (rows + 1) / 2;
    const size_t packed = head * per_head + packed_row_prefix(row, pos0) + col;
    accumulators[packed] = acc;
    outputs[packed] = fixed_requant_no_clamp(acc, shift, error);
}

__global__ void fixed_softmax_kernel(
    const int16_t* scores, const int16_t* exp_lut, const int16_t* recip_lut,
    int16_t* row_shifts, int16_t* exp_outputs, int64_t* denoms,
    int16_t* recips, int16_t* weights, uint32_t* error, size_t rows,
    size_t pos0, size_t heads, uint32_t recip_den_shift,
    uint32_t norm_shift, int use_row_shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= heads * rows) return;
    const size_t row = z % rows;
    const size_t head = z / rows;
    const size_t width = pos0 + row + 1;
    const size_t per_head = rows * pos0 + rows * (rows + 1) / 2;
    const size_t start = head * per_head + packed_row_prefix(row, pos0);
    int16_t shift_value = 0;
    if (use_row_shift) {
        shift_value = scores[start];
        for (size_t j = 1; j < width; ++j) {
            if (scores[start + j] > shift_value) shift_value = scores[start + j];
        }
    }
    row_shifts[head * rows + row] = shift_value;
    int64_t denom = 0;
    for (size_t j = 0; j < width; ++j) {
        const int32_t shifted = static_cast<int32_t>(scores[start + j]) -
            static_cast<int32_t>(shift_value);
        if (shifted < INT16_MIN || shifted > INT16_MAX) atomicExch(error, 1u);
        const int16_t table_input = static_cast<int16_t>(shifted);
        const int16_t value = exp_lut[static_cast<uint16_t>(table_input)];
        exp_outputs[start + j] = value;
        denom += value;
    }
    int64_t recip_input = denom >> recip_den_shift;
    if (recip_input < 0 || recip_input >= (int64_t{1} << 16)) {
        atomicExch(error, 1u);
        recip_input = 0;
    }
    const int16_t recip = recip_lut[recip_input];
    denoms[head * rows + row] = denom;
    recips[head * rows + row] = recip;
    for (size_t j = 0; j < width; ++j) {
        weights[start + j] = fixed_requant_no_clamp(
            static_cast<int64_t>(exp_outputs[start + j]) * recip,
            norm_shift, error);
    }
}

__global__ void fixed_av_kernel(
    const int16_t* weights, const int16_t* values, int64_t* accumulators,
    int16_t* outputs, uint32_t* error, size_t rows, size_t seq,
    size_t pos0, size_t d, size_t heads, uint32_t shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * d) return;
    const size_t row = z / d;
    const size_t col = z % d;
    const size_t head_dim = d / heads;
    const size_t head = col / head_dim;
    const size_t width = pos0 + row + 1;
    const size_t per_head = rows * pos0 + rows * (rows + 1) / 2;
    const size_t start = head * per_head + packed_row_prefix(row, pos0);
    int64_t acc = 0;
    for (size_t j = 0; j < width; ++j) {
        acc += static_cast<int64_t>(weights[start + j]) *
            static_cast<int64_t>(values[j * d + col]);
    }
    accumulators[z] = acc;
    outputs[z] = fixed_requant_no_clamp(acc, shift, error);
}

__global__ void fixed_lookup_kernel(
    const int16_t* input, const int16_t* lut, int16_t* output, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < n) output[z] = lut[static_cast<uint16_t>(input[z])];
}

__global__ void fixed_requant_i16_kernel(
    const int16_t* input, int16_t* output, uint32_t* error, size_t n,
    uint32_t shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= n) return;
    output[z] = shift == 0 ? input[z] :
        fixed_requant_no_clamp(static_cast<int64_t>(input[z]), shift, error);
}

__global__ void fixed_logits_kernel(
    const int16_t* input, const int16_t* weights, int64_t* output,
    size_t rows, size_t d, size_t vocab) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * vocab) return;
    const size_t row = z / vocab;
    const size_t word = z % vocab;
    int64_t acc = 0;
    for (size_t j = 0; j < d; ++j) {
        acc += static_cast<int64_t>(input[row * d + j]) *
            static_cast<int64_t>(weights[word * d + j]);
    }
    output[z] = acc;
}

// -------------------------------------------------------------------------
// Generic resident field algebra used by protocol proofs
// -------------------------------------------------------------------------

enum ResidentScalarKind : int {
    SCALAR_I16 = 0,
    SCALAR_I64 = 1,
    SCALAR_FP = 2,
    SCALAR_FP2 = 3,
    SCALAR_U32 = 4,
};

__device__ inline uint64_t fp_from_i64_device(int64_t value) {
    if (value >= 0) return static_cast<uint64_t>(value) % P;
    const uint64_t magnitude = static_cast<uint64_t>(-(value + 1)) + 1;
    const uint64_t reduced = magnitude % P;
    return reduced == 0 ? 0 : P - reduced;
}

__device__ inline uint64_t load_base_scalar(const void* input, size_t index, int kind) {
    if (kind == SCALAR_I16)
        return fp_from_i64_device(static_cast<const int16_t*>(input)[index]);
    if (kind == SCALAR_I64)
        return fp_from_i64_device(static_cast<const int64_t*>(input)[index]);
    if (kind == SCALAR_U32)
        return static_cast<const uint32_t*>(input)[index];
    return static_cast<const uint64_t*>(input)[index];
}

__global__ void subfield_corrections_kernel(
    const void* input, const uint64_t* masks, uint64_t* output,
    size_t n, int kind) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < n) output[z] = fp_sub(load_base_scalar(input, z, kind), masks[z]);
}

__global__ void pad_base_vector_kernel(
    const void* input, uint64_t* output, size_t real, size_t padded,
    uint64_t pad, int kind) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < padded) output[z] = z < real ? load_base_scalar(input, z, kind) : pad;
}

/// Axis 0 folds matrix rows and returns `out_pad` columns; axis 1 folds
/// columns and returns `out_pad` rows. Inputs are row-major and only the real
/// `rows × cols` rectangle is read; padded outputs are zero.
__global__ void matrix_fold_kernel(
    const void* input, const Fp2* weights, Fp2* output,
    size_t rows, size_t stride, size_t column_offset, size_t cols,
    size_t out_pad, int kind, int axis) {
    const size_t out_index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (out_index >= out_pad) return;
    const size_t real_outputs = axis == 0 ? cols : rows;
    if (out_index >= real_outputs) {
        output[out_index] = Fp2{0, 0};
        return;
    }
    const size_t terms = axis == 0 ? rows : cols;
    Fp2 acc{0, 0};
    for (size_t term = 0; term < terms; ++term) {
        const size_t index = axis == 0
            ? term * stride + column_offset + out_index
            : out_index * stride + column_offset + term;
        if (kind == SCALAR_FP2) {
            acc = fp2_add(acc, fp2_mul(weights[term], static_cast<const Fp2*>(input)[index]));
        } else {
            const uint64_t value = load_base_scalar(input, index, kind);
            if (value != 0) acc = fp2_add(acc, fp2_mul_base(weights[term], value));
        }
    }
    output[out_index] = acc;
}

/// Term-parallel matrix fold for small output vectors. The legacy kernel
/// above maps one thread to one output, which is efficient only when the
/// untouched axis exposes enough outputs. Scalar MLEs otherwise serialize a
/// full model-sized vector in one thread. Here each output receives one or
/// more blocks; every block reduces a disjoint strided subset of terms.
__global__ void matrix_fold_parts_kernel(
    const void* input, const Fp2* weights, Fp2* destination,
    size_t rows, size_t stride, size_t column_offset, size_t cols,
    size_t real_outputs, size_t out_pad, size_t parts, int kind, int axis) {
    const size_t output_index = static_cast<size_t>(blockIdx.x) / parts;
    const size_t part = static_cast<size_t>(blockIdx.x) % parts;
    if (output_index >= real_outputs) {
        if (parts == 1 && output_index < out_pad && threadIdx.x == 0)
            destination[output_index] = Fp2{0, 0};
        return;
    }

    const size_t terms = axis == 0 ? rows : cols;
    Fp2 acc{0, 0};
    for (size_t term = part * BLOCK + threadIdx.x;
         term < terms;
         term += parts * BLOCK) {
        const size_t index = axis == 0
            ? term * stride + column_offset + output_index
            : output_index * stride + column_offset + term;
        if (kind == SCALAR_FP2) {
            acc = fp2_add(acc, fp2_mul(weights[term], static_cast<const Fp2*>(input)[index]));
        } else {
            const uint64_t value = load_base_scalar(input, index, kind);
            if (value != 0) acc = fp2_add(acc, fp2_mul_base(weights[term], value));
        }
    }

    __shared__ Fp2 shared[BLOCK];
    shared[threadIdx.x] = acc;
    __syncthreads();
    for (int width = BLOCK / 2; width > 0; width >>= 1) {
        if (threadIdx.x < width)
            shared[threadIdx.x] = fp2_add(shared[threadIdx.x], shared[threadIdx.x + width]);
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        if (parts == 1)
            destination[output_index] = shared[0];
        else
            destination[output_index * parts + part] = shared[0];
    }
}

__global__ void matrix_fold_finish_kernel(
    const Fp2* partials, Fp2* output,
    size_t real_outputs, size_t out_pad, size_t parts) {
    const size_t output_index = blockIdx.x;
    if (output_index >= out_pad) return;
    if (output_index >= real_outputs) {
        if (threadIdx.x == 0) output[output_index] = Fp2{0, 0};
        return;
    }

    Fp2 acc{0, 0};
    for (size_t part = threadIdx.x; part < parts; part += BLOCK)
        acc = fp2_add(acc, partials[output_index * parts + part]);
    __shared__ Fp2 shared[BLOCK];
    shared[threadIdx.x] = acc;
    __syncthreads();
    for (int width = BLOCK / 2; width > 0; width >>= 1) {
        if (threadIdx.x < width)
            shared[threadIdx.x] = fp2_add(shared[threadIdx.x], shared[threadIdx.x + width]);
        __syncthreads();
    }
    if (threadIdx.x == 0) output[output_index] = shared[0];
}

struct DotAcc {
    Fp2 value;
};

__global__ void fp2_dot_terms(const Fp2* a, const Fp2* b, DotAcc* output, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < n) output[z].value = fp2_mul(a[z], b[z]);
}

__global__ void reduce_dot(const DotAcc* input, DotAcc* output, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= (n + 1) / 2) return;
    DotAcc value = input[2 * z];
    if (2 * z + 1 < n) value.value = fp2_add(value.value, input[2 * z + 1].value);
    output[z] = value;
}

struct ProductRoundAcc {
    Fp2 g0;
    Fp2 g2;
};

struct TripleRoundAcc {
    Fp2 g0;
    Fp2 g2;
    Fp2 g3;
};

__device__ inline Fp2 line_at2(Fp2 v0, Fp2 v1) {
    const Fp2 d = fp2_sub(v1, v0);
    return fp2_add(fp2_add(v0, d), d);
}

__device__ inline Fp2 line_at3(Fp2 v0, Fp2 v1) {
    const Fp2 d = fp2_sub(v1, v0);
    return fp2_add(line_at2(v0, v1), d);
}

__global__ void fp2_product_round_terms(
    const Fp2* a, const Fp2* b, ProductRoundAcc* output, size_t pairs) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= pairs) return;
    const Fp2 a0 = a[2 * z], a1 = a[2 * z + 1];
    const Fp2 b0 = b[2 * z], b1 = b[2 * z + 1];
    const Fp2 da = fp2_sub(a1, a0), db = fp2_sub(b1, b0);
    const Fp2 a2 = fp2_add(fp2_add(a0, da), da);
    const Fp2 b2 = fp2_add(fp2_add(b0, db), db);
    output[z] = ProductRoundAcc{fp2_mul(a0, b0), fp2_mul(a2, b2)};
}

__global__ void reduce_product_round(
    const ProductRoundAcc* input, ProductRoundAcc* output, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= (n + 1) / 2) return;
    ProductRoundAcc value = input[2 * z];
    if (2 * z + 1 < n) {
        value.g0 = fp2_add(value.g0, input[2 * z + 1].g0);
        value.g2 = fp2_add(value.g2, input[2 * z + 1].g2);
    }
    output[z] = value;
}

__global__ void fp2_triple_product_round_terms(
    const Fp2* a, const Fp2* b, const Fp2* c, TripleRoundAcc* output,
    size_t pairs) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= pairs) return;
    const Fp2 a0 = a[2 * z], a1 = a[2 * z + 1];
    const Fp2 b0 = b[2 * z], b1 = b[2 * z + 1];
    const Fp2 c0 = c[2 * z], c1 = c[2 * z + 1];
    output[z] = TripleRoundAcc{
        fp2_mul(fp2_mul(a0, b0), c0),
        fp2_mul(fp2_mul(line_at2(a0, a1), line_at2(b0, b1)), line_at2(c0, c1)),
        fp2_mul(fp2_mul(line_at3(a0, a1), line_at3(b0, b1)), line_at3(c0, c1)),
    };
}

__global__ void reduce_triple_product_round(
    const TripleRoundAcc* input, TripleRoundAcc* output, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= (n + 1) / 2) return;
    TripleRoundAcc value = input[2 * z];
    if (2 * z + 1 < n) {
        value.g0 = fp2_add(value.g0, input[2 * z + 1].g0);
        value.g2 = fp2_add(value.g2, input[2 * z + 1].g2);
        value.g3 = fp2_add(value.g3, input[2 * z + 1].g3);
    }
    output[z] = value;
}

__global__ void ln_hadamard_factors_kernel(
    const int16_t* input, const uint64_t* means, const uint64_t* rsqrt,
    const int16_t* gain, Fp2* centered, Fp2* scaled, size_t rows,
    size_t cols, size_t row_pad, size_t col_pad) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = row_pad * col_pad;
    if (z >= total) return;
    const size_t row = z / col_pad;
    const size_t col = z - row * col_pad;
    if (row < rows) {
        const uint64_t value = col < cols
            ? fp_from_i64_device(input[row * cols + col]) : 0;
        centered[z] = Fp2{fp_sub(value, means[row]), 0};
    } else {
        centered[z] = Fp2{0, 0};
    }
    scaled[z] = col < cols
        ? Fp2{fp_mul(rsqrt[row], fp_from_i64_device(gain[col])), 0}
        : Fp2{0, 0};
}

__global__ void base_broadcast_fp2_kernel(
    const void* input, Fp2* output, size_t input_len, size_t repeat,
    size_t output_len, int kind) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < output_len) output[z] = Fp2{load_base_scalar(input, z / repeat, kind), 0};
}

__global__ void attention_above_mask_kernel(
    Fp2* equality, size_t entries, size_t rows, size_t seq, size_t pos0,
    size_t heads, size_t query_pad, size_t seq_pad) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= entries) return;
    const size_t sp2 = query_pad * seq_pad;
    const size_t head = z / sp2;
    const size_t rem = z - head * sp2;
    const size_t row = rem / seq_pad;
    const size_t col = rem - row * seq_pad;
    if (head >= heads || row >= rows || col >= seq || col < pos0 + row + 1)
        equality[z] = Fp2{0, 0};
}

struct AttentionProofWiresArgs {
    uint64_t q_id; size_t q_offset;
    uint64_t k_cache_id; size_t k_cache_offset;
    uint64_t own_k_id; size_t own_k_offset;
    uint64_t v_id; size_t v_offset;
    uint64_t scores_acc_id; size_t scores_acc_offset;
    uint64_t scores_q_id; size_t scores_q_offset;
    uint64_t row_shifts_id; size_t row_shifts_offset;
    uint64_t exp_outputs_id; size_t exp_outputs_offset;
    uint64_t denoms_id; size_t denoms_offset;
    uint64_t recips_id; size_t recips_offset;
    uint64_t softmax_weights_id; size_t softmax_weights_offset;
    uint64_t recip_lut_id; size_t recip_lut_offset;
    uint64_t qkv_acc_id; size_t qkv_acc_offset;
    uint64_t error_id; size_t error_offset;
    uint64_t rect_id; size_t rect_offset;
    uint64_t rows_id; size_t rows_offset;
    uint64_t above_id; size_t above_offset;
    uint64_t qkv_id; size_t qkv_offset;
    size_t query_rows;
    size_t seq;
    size_t pos0;
    size_t heads;
    size_t head_pad;
    size_t head_dim;
    size_t query_pad;
    size_t seq_pad;
    size_t d_pad;
    uint32_t shift_scores;
    uint32_t shift_softmax_norm;
    uint32_t shift_qkv;
    uint32_t recip_den_shift;
    int exp_pad_input;
    int recip_pad_output;
    int use_row_shift;
};

__global__ void attention_rect_columns_kernel(
    const int16_t* q, const int16_t* k_cache,
    const int64_t* scores_acc, const int16_t* scores_q,
    const int16_t* row_shifts, const int16_t* exp_outputs,
    const int16_t* recips, const int16_t* softmax_weights,
    uint64_t* rect, uint64_t* above, uint32_t* error,
    size_t query_rows, size_t seq, size_t pos0, size_t heads,
    size_t head_pad, size_t head_dim, size_t query_pad, size_t seq_pad,
    uint32_t shift_scores, uint32_t shift_softmax_norm,
    int16_t exp_pad_input, int use_row_shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t sp2 = query_pad * seq_pad;
    const size_t entries = head_pad * sp2;
    if (z >= entries) return;
    const size_t head = z / sp2;
    const size_t rem = z - head * sp2;
    const size_t row = rem / seq_pad;
    const size_t col = rem - row * seq_pad;
    const int64_t half_scores = int64_t{1} << (shift_scores - 1);
    const int64_t half_norm = int64_t{1} << (shift_softmax_norm - 1);
    int64_t norm_rem = half_norm;
    int64_t weight = 0;
    int64_t score_rem = half_scores;
    int64_t shifted_score = exp_pad_input;
    int64_t exp_value = 0;
    int64_t is_max = 0;
    int64_t full_score = 0;
    if (head < heads && row < query_rows && col < seq) {
        const size_t d = heads * head_dim;
        for (size_t l = 0; l < head_dim; ++l) {
            full_score += static_cast<int64_t>(q[row * d + head * head_dim + l]) *
                static_cast<int64_t>(k_cache[col * d + head * head_dim + l]);
        }
        const size_t width = pos0 + row + 1;
        if (col < width) {
            const size_t per_head =
                query_rows * pos0 + query_rows * (query_rows + 1) / 2;
            const size_t packed =
                head * per_head + packed_row_prefix(row, pos0) + col;
            const int64_t score = scores_q[packed];
            const int64_t row_shift = use_row_shift ? row_shifts[head * query_rows + row] : 0;
            shifted_score = score - row_shift;
            if (shifted_score < INT16_MIN || shifted_score > INT16_MAX)
                atomicExch(error, 1u);
            score_rem = scores_acc[packed] + half_scores -
                score * (int64_t{1} << shift_scores);
            if (score_rem < 0 || score_rem >= (int64_t{1} << shift_scores))
                atomicExch(error, 1u);
            if (scores_acc[packed] != full_score) atomicExch(error, 1u);
            exp_value = exp_outputs[packed];
            weight = softmax_weights[packed];
            const int64_t recip = recips[head * query_rows + row];
            norm_rem = exp_value * recip + half_norm -
                weight * (int64_t{1} << shift_softmax_norm);
            if (norm_rem < 0 || norm_rem >= (int64_t{1} << shift_softmax_norm))
                atomicExch(error, 1u);
            if (use_row_shift && shifted_score == 0) {
                bool first = true;
                const size_t start = head * per_head + packed_row_prefix(row, pos0);
                for (size_t prior = 0; prior < col; ++prior) {
                    if (static_cast<int64_t>(scores_q[start + prior]) - row_shift == 0) {
                        first = false;
                        break;
                    }
                }
                is_max = first ? 1 : 0;
            }
        } else {
            const size_t local = col - width;
            const size_t row_prefix = row * (query_rows - 1) - row * (row - 1) / 2;
            const size_t above_per_head = query_rows * (query_rows - 1) / 2;
            above[head * above_per_head + row_prefix + local] =
                fp_from_i64_device(full_score);
        }
    }
    rect[z] = static_cast<uint64_t>(norm_rem);
    rect[entries + z] = fp_from_i64_device(weight);
    rect[2 * entries + z] = static_cast<uint64_t>(score_rem);
    rect[3 * entries + z] = fp_from_i64_device(shifted_score);
    rect[4 * entries + z] = fp_from_i64_device(exp_value);
    rect[5 * entries + z] = static_cast<uint64_t>(is_max);
    rect[6 * entries + z] = fp_from_i64_device(full_score);
}

__global__ void attention_row_columns_kernel(
    const int64_t* denoms, const int16_t* recips, const int16_t* row_shifts,
    const int16_t* recip_lut, uint64_t* rows_out, uint32_t* error,
    size_t query_rows, size_t heads, size_t head_pad, size_t query_pad,
    size_t seq, size_t pos0, uint32_t recip_den_shift,
    int16_t recip_pad_output, int use_row_shift,
    const int16_t* scores_q) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t entries = head_pad * query_pad;
    if (z >= entries) return;
    const size_t head = z / query_pad;
    const size_t row = z - head * query_pad;
    int64_t denom = 0;
    int64_t recip_input = 0;
    int64_t recip = recip_pad_output;
    int64_t row_shift = 0;
    if (head < heads && row < query_rows) {
        denom = denoms[head * query_rows + row];
        recip_input = denom >> recip_den_shift;
        recip = recips[head * query_rows + row];
        row_shift = use_row_shift ? row_shifts[head * query_rows + row] : 0;
        if (recip_input < 0 || recip_input >= (int64_t{1} << 16)) {
            atomicExch(error, 1u);
            recip_input = 0;
        } else if (recip_lut[static_cast<size_t>(recip_input)] != recip) {
            atomicExch(error, 1u);
        }
        if (use_row_shift) {
            const size_t per_head =
                query_rows * pos0 + query_rows * (query_rows + 1) / 2;
            const size_t start = head * per_head + packed_row_prefix(row, pos0);
            const size_t width = pos0 + row + 1;
            bool found = false;
            for (size_t col = 0; col < width; ++col) {
                if (scores_q[start + col] == row_shift) {
                    found = true;
                    break;
                }
            }
            if (!found || width > seq) atomicExch(error, 1u);
        }
    }
    rows_out[z] = fp_from_i64_device(denom);
    rows_out[entries + z] = static_cast<uint64_t>(recip_input);
    rows_out[2 * entries + z] = fp_from_i64_device(recip);
    rows_out[3 * entries + z] = fp_from_i64_device(row_shift);
}

__global__ void attention_qkv_columns_kernel(
    const int64_t* qkv_acc, const int16_t* q, const int16_t* own_k,
    const int16_t* v, uint64_t* qkv_columns, uint32_t* error,
    size_t query_rows, size_t d, size_t query_pad, size_t d_pad,
    uint32_t shift_qkv) {
    const size_t width = 4 * d_pad;
    const size_t entries = query_pad * width;
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= entries) return;
    const size_t row = z / width;
    const size_t col = z - row * width;
    const size_t third = col / d_pad;
    const size_t rest = col - third * d_pad;
    const int64_t half = int64_t{1} << (shift_qkv - 1);
    int64_t remainder = half;
    int64_t output = 0;
    if (row < query_rows && third < 3 && rest < d) {
        const size_t natural = row * 3 * d + third * d + rest;
        output = third == 0 ? q[row * d + rest]
            : (third == 1 ? own_k[row * d + rest] : v[row * d + rest]);
        remainder = qkv_acc[natural] + half - output * (int64_t{1} << shift_qkv);
        if (remainder < 0 || remainder >= (int64_t{1} << shift_qkv))
            atomicExch(error, 1u);
    }
    qkv_columns[z] = static_cast<uint64_t>(remainder);
    qkv_columns[entries + z] = fp_from_i64_device(output);
}

__device__ inline int64_t round_stage_i64(int64_t value, uint32_t shift) {
    return (value + (int64_t{1} << (shift - 1))) >> shift;
}

/// Columns are stored column-major by proof column: `[col0[n], col1[n], …]`.
/// For chained shifts the order is `[rem1, y1, rem2, out]`; otherwise it is
/// `[rem, out]`.
__device__ inline int64_t load_signed_scalar(const void* input, size_t index, int kind) {
    return kind == SCALAR_I16
        ? static_cast<int64_t>(static_cast<const int16_t*>(input)[index])
        : static_cast<const int64_t*>(input)[index];
}

__global__ void requant_columns_kernel(
    const void* accumulators, const int16_t* outputs, uint64_t* columns,
    uint32_t* error, size_t rows, size_t cols, size_t row_pad,
    size_t col_pad, int acc_kind, uint32_t shift) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t padded = row_pad * col_pad;
    if (z >= padded) return;
    const size_t row = z / col_pad;
    const size_t col = z - row * col_pad;
    const bool real = row < rows && col < cols;
    const int64_t acc = real ? load_signed_scalar(accumulators, row * cols + col, acc_kind) : 0;
    const int64_t out = real ? outputs[row * cols + col] : 0;
    if (shift <= 16) {
        const int64_t half = int64_t{1} << (shift - 1);
        const int64_t rem = acc + half - (out << shift);
        if (real && (rem < 0 || rem >= (int64_t{1} << shift) ||
                     round_stage_i64(acc, shift) != out)) atomicExch(error, 1u);
        columns[z] = static_cast<uint64_t>(rem);
        columns[padded + z] = fp_from_i64_device(out);
        return;
    }
    const uint32_t first = shift - 16;
    const int64_t half1 = int64_t{1} << (first - 1);
    const int64_t half2 = int64_t{1} << 15;
    const int64_t y1 = round_stage_i64(acc, first);
    const int64_t rem1 = acc + half1 - (y1 << first);
    const int64_t rem2 = y1 + half2 - (out << 16);
    if (real && (rem1 < 0 || rem1 >= (int64_t{1} << first) ||
                 rem2 < 0 || rem2 >= (int64_t{1} << 16) ||
                 round_stage_i64(y1, 16) != out)) atomicExch(error, 1u);
    columns[z] = static_cast<uint64_t>(rem1);
    columns[padded + z] = fp_from_i64_device(y1);
    columns[2 * padded + z] = static_cast<uint64_t>(rem2);
    columns[3 * padded + z] = fp_from_i64_device(out);
}

__global__ void pair_columns_kernel(
    const void* inputs, const void* outputs, uint64_t* columns,
    size_t rows, size_t cols, size_t row_pad, size_t col_pad,
    uint64_t pad_input, uint64_t pad_output, int input_kind, int output_kind) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t padded = row_pad * col_pad;
    if (z >= padded) return;
    const size_t row = z / col_pad;
    const size_t col = z - row * col_pad;
    const bool real = row < rows && col < cols;
    columns[z] = real ? load_base_scalar(inputs, row * cols + col, input_kind) : pad_input;
    columns[padded + z] =
        real ? load_base_scalar(outputs, row * cols + col, output_kind) : pad_output;
}

__global__ void histogram_fp_kernel(
    const uint64_t* input, uint32_t* output, size_t n, size_t bins) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < n && input[z] < bins) atomicAdd(output + input[z], 1u);
}

__global__ void histogram_lut_kernel(
    const uint64_t* input, uint32_t* output, size_t n, int signed_input) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= n) return;
    const uint64_t value = input[z];
    uint32_t index = 0;
    if (!signed_input) {
        if (value >= (uint64_t{1} << 16)) return;
        index = static_cast<uint32_t>(value);
    } else if (value <= INT16_MAX) {
        index = static_cast<uint32_t>(value);
    } else {
        if (value < P - (uint64_t{1} << 15)) return;
        index = static_cast<uint32_t>((uint64_t{1} << 16) - (P - value));
    }
    atomicAdd(output + index, 1u);
}

__global__ void u32_add_inplace_kernel(uint32_t* target, const uint32_t* add, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z < n) target[z] += add[z];
}

__global__ void pack_lookup_leaf_kernel(
    const uint64_t* columns, const uint32_t* shifts, uint64_t* leaf,
    size_t column_count, size_t n, uint64_t alpha0) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= n) return;
    uint64_t packed = 0;
    for (size_t column = 0; column < column_count; ++column) {
        const uint32_t shift = shifts[column];
        if (shift != UINT32_MAX) {
            packed = fp_add(packed, fp_mul(columns[column * n + z], uint64_t{1} << shift));
        }
    }
    leaf[z] = fp_sub(alpha0, packed);
}

__global__ void deinterleave_base_columns_kernel(
    const uint64_t* columns, Fp2* output, size_t column_count, size_t n) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= column_count * n) return;
    const size_t column = z / n;
    const size_t local = z - column * n;
    const size_t half = n / 2;
    const size_t source_local = local < half ? 2 * local : 2 * (local - half) + 1;
    output[z] = Fp2{columns[column * n + source_local], 0};
}

// -------------------------------------------------------------------------
// NTT
// -------------------------------------------------------------------------

__global__ void bit_reverse_fp(
    const uint64_t* in, uint64_t* out, size_t n, int bits) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) out[__brevll(i) >> (64 - bits)] = in[i];
}

__global__ void bit_reverse_fp2(const Fp2* in, Fp2* out, size_t n, int bits) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) out[__brevll(i) >> (64 - bits)] = in[i];
}

__global__ void ntt_stage_fp(uint64_t* values, const uint64_t* tw, size_t n, size_t len) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n / 2) return;
    const size_t half = len / 2;
    const size_t group = i / half;
    const size_t k = i - group * half;
    const size_t i0 = group * len + k;
    const size_t i1 = i0 + half;
    const uint64_t u = values[i0];
    const uint64_t v = fp_mul(values[i1], tw[k * (n / len)]);
    values[i0] = fp_add(u, v);
    values[i1] = fp_sub(u, v);
}

__global__ void ntt_stage_fp2(Fp2* values, const uint64_t* tw, size_t n, size_t len) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n / 2) return;
    const size_t half = len / 2;
    const size_t group = i / half;
    const size_t k = i - group * half;
    const size_t i0 = group * len + k;
    const size_t i1 = i0 + half;
    const Fp2 u = values[i0];
    const Fp2 v = fp2_mul_base(values[i1], tw[k * (n / len)]);
    values[i0] = fp2_add(u, v);
    values[i1] = fp2_sub(u, v);
}

__global__ void bit_reverse_fp_batch(
    const uint64_t* in, uint64_t* out, size_t rows, size_t n, int bits) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * n) return;
    const size_t row = z / n;
    const size_t i = z - row * n;
    out[row * n + (__brevll(i) >> (64 - bits))] = in[z];
}

__global__ void ntt_stage_fp_batch(
    uint64_t* values, const uint64_t* tw, size_t rows, size_t n, size_t len) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t per_row = n / 2;
    if (z >= rows * per_row) return;
    const size_t row = z / per_row;
    const size_t i = z - row * per_row;
    const size_t half = len / 2;
    const size_t group = i / half;
    const size_t k = i - group * half;
    const size_t i0 = row * n + group * len + k;
    const size_t i1 = i0 + half;
    const uint64_t u = values[i0];
    const uint64_t v = fp_mul(values[i1], tw[k * (n / len)]);
    values[i0] = fp_add(u, v);
    values[i1] = fp_sub(u, v);
}

__global__ void bit_reverse_fp2_batch(
    const Fp2* in, Fp2* out, size_t rows, size_t n, int bits) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * n) return;
    const size_t row = z / n;
    const size_t i = z - row * n;
    out[row * n + (__brevll(i) >> (64 - bits))] = in[z];
}

__global__ void ntt_stage_fp2_batch(
    Fp2* values, const uint64_t* tw, size_t rows, size_t n, size_t len) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t per_row = n / 2;
    if (z >= rows * per_row) return;
    const size_t row = z / per_row;
    const size_t i = z - row * per_row;
    const size_t half = len / 2;
    const size_t group = i / half;
    const size_t k = i - group * half;
    const size_t i0 = row * n + group * len + k;
    const size_t i1 = i0 + half;
    const Fp2 u = values[i0];
    const Fp2 v = fp2_mul_base(values[i1], tw[k * (n / len)]);
    values[i0] = fp2_add(u, v);
    values[i1] = fp2_sub(u, v);
}

int ensure_twiddles(Context* c, size_t n, uint64_t* h2d) {
    if (ensure(c, 11, (n / 2) * sizeof(uint64_t))) return -1;
    if (c->twiddle_size == n) return 0;
    std::vector<uint64_t> tw(n / 2);
    const int bits = __builtin_ctzll(n);
    const uint64_t root = fp_pow(7, (P - 1) >> bits);
    tw[0] = 1;
    for (size_t i = 1; i < n / 2; ++i) tw[i] = fp_mul(tw[i - 1], root);
    CUDA_OR_RETURN(c, cudaMemcpyAsync(
        buf<uint64_t>(c, 11), tw.data(), tw.size() * sizeof(uint64_t),
        cudaMemcpyHostToDevice, c->stream));
    *h2d += tw.size() * sizeof(uint64_t);
    c->twiddle_size = n;
    return 0;
}

// -------------------------------------------------------------------------
// LogUp tree / general rounds
// -------------------------------------------------------------------------

__global__ void logup_first_combine(
    const uint64_t* a, const uint32_t* mult, Fp2* p, Fp2* q, size_t pairs,
    size_t offset, uint64_t alpha1, int neg_mult) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const uint64_t av = a[2 * i], bv = a[2 * i + 1];
    const uint64_t sum = fp_add(av, bv);
    const uint64_t a1sq7 = fp_mul(7, fp_mul(alpha1, alpha1));
    if (neg_mult) {
        const uint64_t ma = mult[2 * i], mb = mult[2 * i + 1];
        p[offset + i] = Fp2{
            fp_neg(fp_add(fp_mul(ma, bv), fp_mul(mb, av))),
            fp_neg(fp_mul(fp_add(ma, mb), alpha1)),
        };
    } else {
        p[offset + i] = Fp2{sum, fp_add(alpha1, alpha1)};
    }
    q[offset + i] = Fp2{fp_add(fp_mul(av, bv), a1sq7), fp_mul(sum, alpha1)};
}

__global__ void logup_materialize_leaves(
    const uint64_t* a, const uint32_t* mult, Fp2* p, Fp2* q, size_t n,
    uint64_t alpha1, int neg_mult) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n) return;
    p[i] = neg_mult ? Fp2{fp_neg(static_cast<uint64_t>(mult[i])), 0} : Fp2{1, 0};
    q[i] = Fp2{a[i], alpha1};
}

__global__ void logup_general_combine(
    const Fp2* p, const Fp2* q, Fp2* po, Fp2* qo, size_t pairs,
    size_t child_offset, size_t parent_offset) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2 pa = p[child_offset + 2 * i], pb = p[child_offset + 2 * i + 1];
    const Fp2 qa = q[child_offset + 2 * i], qb = q[child_offset + 2 * i + 1];
    po[parent_offset + i] = fp2_add(fp2_mul(pa, qb), fp2_mul(pb, qa));
    qo[parent_offset + i] = fp2_mul(qa, qb);
}

__host__ __device__ inline Fp2 at2(Fp2 a, Fp2 b) {
    const Fp2 d = fp2_sub(b, a);
    return fp2_add(fp2_add(a, d), d);
}

struct RoundAcc {
    Fp2 pq0, pq2, qq0, qq2;
};

__host__ __device__ inline RoundAcc acc_add(RoundAcc a, RoundAcc b) {
    return RoundAcc{
        fp2_add(a.pq0, b.pq0), fp2_add(a.pq2, b.pq2),
        fp2_add(a.qq0, b.qq0), fp2_add(a.qq2, b.qq2),
    };
}

__global__ void logup_round_eval(
    const Fp2* p0, const Fp2* p1, const Fp2* q0, const Fp2* q1,
    const Fp2* suffix, RoundAcc* out, size_t pairs) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2 a0 = p0[2 * i], a2 = at2(a0, p0[2 * i + 1]);
    const Fp2 b0 = p1[2 * i], b2 = at2(b0, p1[2 * i + 1]);
    const Fp2 c0 = q0[2 * i], c2 = at2(c0, q0[2 * i + 1]);
    const Fp2 d0 = q1[2 * i], d2 = at2(d0, q1[2 * i + 1]);
    const Fp2 s = suffix[i];
    out[i] = RoundAcc{
        fp2_mul(s, fp2_add(fp2_mul(a0, d0), fp2_mul(b0, c0))),
        fp2_mul(s, fp2_add(fp2_mul(a2, d2), fp2_mul(b2, c2))),
        fp2_mul(s, fp2_mul(c0, d0)),
        fp2_mul(s, fp2_mul(c2, d2)),
    };
}

__global__ void reduce_round(const RoundAcc* in, RoundAcc* out, size_t n) {
    __shared__ RoundAcc shared[BLOCK];
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    shared[threadIdx.x] = i < n ? in[i] : RoundAcc{};
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride) shared[threadIdx.x] = acc_add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) out[blockIdx.x] = shared[0];
}

__global__ void logup_fold(
    const Fp2* p0, const Fp2* p1, const Fp2* q0, const Fp2* q1,
    Fp2* o0, Fp2* o1, Fp2* o2, Fp2* o3, size_t pairs, Fp2 r) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2* inputs[4] = {p0, p1, q0, q1};
    Fp2* outputs[4] = {o0, o1, o2, o3};
    for (int c = 0; c < 4; ++c) {
        const Fp2 a = inputs[c][2 * i];
        outputs[c][i] = fp2_add(a, fp2_mul(fp2_sub(inputs[c][2 * i + 1], a), r));
    }
}

__global__ void fp2_deinterleave(
    const Fp2* input, Fp2* even, Fp2* odd, size_t pairs) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    even[i] = input[2 * i];
    odd[i] = input[2 * i + 1];
}

__global__ void fp2_set_one(Fp2* output) {
    if (blockIdx.x == 0 && threadIdx.x == 0) output[0] = Fp2{1, 0};
}

__global__ void suffix_eq_expand(
    const Fp2* input, Fp2* output, size_t n, const Fp2* challenge) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const Fp2 v1 = fp2_mul(input[i], challenge[0]);
    output[2 * i] = fp2_sub(input[i], v1);
    output[2 * i + 1] = v1;
}

__global__ void fp2_fold_rows(
    const Fp2* input, Fp2* output, size_t rows, size_t pairs, Fp2 r) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * pairs) return;
    const size_t row = z / pairs;
    const size_t i = z - row * pairs;
    const Fp2* src = input + row * (2 * pairs);
    const Fp2 a = src[2 * i];
    output[z] = fp2_add(a, fp2_mul(fp2_sub(src[2 * i + 1], a), r));
}

__global__ void eq_rows_init(Fp2* output, size_t rows) {
    const size_t row = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (row < rows) output[row] = Fp2{1, 0};
}

__global__ void eq_rows_expand(
    const Fp2* input, Fp2* output, const Fp2* points, size_t rows,
    size_t dims, size_t dim, size_t current) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * current) return;
    const size_t row = z / current;
    const size_t i = z - row * current;
    const Fp2 v = input[row * current + i];
    const Fp2 v1 = fp2_mul(v, points[row * dims + dim]);
    output[row * (2 * current) + 2 * i] = fp2_sub(v, v1);
    output[row * (2 * current) + 2 * i + 1] = v1;
}

struct AuxRoundAcc {
    Fp2 pq0, pq2, pq3, qq0, qq2, qq3, aux0, aux2, aux3;
};

__host__ __device__ inline AuxRoundAcc aux_acc_add(AuxRoundAcc a, AuxRoundAcc b) {
    return AuxRoundAcc{
        fp2_add(a.pq0,b.pq0),fp2_add(a.pq2,b.pq2),fp2_add(a.pq3,b.pq3),
        fp2_add(a.qq0,b.qq0),fp2_add(a.qq2,b.qq2),fp2_add(a.qq3,b.qq3),
        fp2_add(a.aux0,b.aux0),fp2_add(a.aux2,b.aux2),fp2_add(a.aux3,b.aux3)};
}

__host__ __device__ inline Fp2 at3(Fp2 a, Fp2 b) {
    const Fp2 d = fp2_sub(b, a);
    return fp2_add(fp2_add(fp2_add(a, d), d), d);
}

__global__ void logup_aux_round_eval(
    const Fp2* q0, const Fp2* q1, const Fp2* suffix,
    const Fp2* columns, const Fp2* eq_rows, const uint32_t* claim_cols,
    const Fp2* weights, size_t column_count, size_t claim_count,
    size_t vector_len, size_t pairs, AuxRoundAcc* output) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2 c0=q0[2*i], c2=at2(c0,q0[2*i+1]), c3=at3(c0,q0[2*i+1]);
    const Fp2 d0=q1[2*i], d2=at2(d0,q1[2*i+1]), d3=at3(d0,q1[2*i+1]);
    const Fp2 s=suffix[i];
    AuxRoundAcc acc{};
    acc.pq0=fp2_mul(s,fp2_add(c0,d0));acc.pq2=fp2_mul(s,fp2_add(c2,d2));
    acc.pq3=fp2_mul(s,fp2_add(c3,d3));acc.qq0=fp2_mul(s,fp2_mul(c0,d0));
    acc.qq2=fp2_mul(s,fp2_mul(c2,d2));acc.qq3=fp2_mul(s,fp2_mul(c3,d3));
    for(size_t k=0;k<claim_count;++k){
        const size_t col=claim_cols[k];
        if(col>=column_count)continue;
        const Fp2* v0=columns+(2*col)*vector_len;
        const Fp2* v1=columns+(2*col+1)*vector_len;
        const Fp2* eq=eq_rows+k*vector_len;
        const Fp2 v00=v0[2*i],v02=at2(v00,v0[2*i+1]),v03=at3(v00,v0[2*i+1]);
        const Fp2 v10=v1[2*i],v12=at2(v10,v1[2*i+1]),v13=at3(v10,v1[2*i+1]);
        const Fp2 e0=eq[2*i],e2=at2(e0,eq[2*i+1]),e3=at3(e0,eq[2*i+1]);
        const Fp2 w0=weights[2*k],w1=weights[2*k+1];
        acc.aux0=fp2_add(acc.aux0,fp2_mul(e0,fp2_add(fp2_mul(w0,v00),fp2_mul(w1,v10))));
        acc.aux2=fp2_add(acc.aux2,fp2_mul(e2,fp2_add(fp2_mul(w0,v02),fp2_mul(w1,v12))));
        acc.aux3=fp2_add(acc.aux3,fp2_mul(e3,fp2_add(fp2_mul(w0,v03),fp2_mul(w1,v13))));
    }
    output[i]=acc;
}

__global__ void reduce_aux_round(const AuxRoundAcc* input, AuxRoundAcc* output, size_t n) {
    __shared__ AuxRoundAcc shared[BLOCK];
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    shared[threadIdx.x]=i<n?input[i]:AuxRoundAcc{};__syncthreads();
    for(int stride=BLOCK/2;stride;stride>>=1){if(threadIdx.x<stride)
        shared[threadIdx.x]=aux_acc_add(shared[threadIdx.x],shared[threadIdx.x+stride]);__syncthreads();}
    if(threadIdx.x==0)output[blockIdx.x]=shared[0];
}

__global__ void assemble_aux_round(
    const AuxRoundAcc* input, Fp2* output, Fp2 lambda, Fp2 cpref, Fp2 point) {
    if(blockIdx.x||threadIdx.x)return;const AuxRoundAcc a=input[0];
    const Fp2 l0=fp2_sub(Fp2{1,0},point);
    const Fp2 l2=fp2_sub(fp2_add(fp2_add(point,point),point),Fp2{1,0});
    const Fp2 fivep=fp2_add(fp2_add(fp2_add(point,point),fp2_add(point,point)),point);
    const Fp2 l3=fp2_sub(fivep,Fp2{2,0});
    const Fp2 pq[3]={a.pq0,a.pq2,a.pq3},qq[3]={a.qq0,a.qq2,a.qq3};
    const Fp2 aux[3]={a.aux0,a.aux2,a.aux3},ell[3]={l0,l2,l3};
    for(int i=0;i<3;++i)output[i]=fp2_add(
        fp2_mul(ell[i],fp2_mul(cpref,fp2_add(fp2_mul(lambda,pq[i]),qq[i]))),aux[i]);
}

// -------------------------------------------------------------------------
// PCS row combinations and selected-column gather
// -------------------------------------------------------------------------

__host__ __device__ inline uint64_t fp_from_i16(int16_t x) {
    return x >= 0 ? static_cast<uint64_t>(x) : P - static_cast<uint64_t>(-static_cast<int64_t>(x));
}

__global__ void pcs_messages_kernel(
    const int16_t* weights,const uint64_t* pads,uint64_t* messages,
    size_t rows,size_t cols,size_t pad,size_t code_len){
    const size_t z=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(z>=rows*code_len)return;const size_t row=z/code_len,j=z-row*code_len;
    if(j<cols)messages[z]=fp_from_i16(weights[row*cols+j]);
    else if(j<cols+pad)messages[z]=pads[row*pad+j-cols];
    else messages[z]=0;
}

__global__ void fp2_add_inplace_kernel(Fp2* target,const Fp2* add,size_t n){
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<n)target[i]=fp2_add(target[i],add[i]);
}

__global__ void pcs_combine_rows_kernel(
    const int16_t* weights, const uint64_t* pads, const Fp2* coeffs, Fp2* out,
    size_t rows, size_t cols, size_t pad, size_t combinations) {
    const size_t msg_len = cols + pad;
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= combinations * msg_len) return;
    const size_t combo = z / msg_len;
    const size_t j = z - combo * msg_len;
    Fp2 acc{};
    for (size_t i = 0; i < rows; ++i) {
        const uint64_t x = j < cols ? fp_from_i16(weights[i * cols + j])
                                    : pads[i * pad + j - cols];
        acc = fp2_add(acc, fp2_mul_base(coeffs[combo * rows + i], x));
    }
    out[z] = acc;
}

__global__ void gather_columns_kernel(
    const uint64_t* matrix, const uint32_t* indices, uint64_t* out,
    size_t rows, size_t cols, size_t queries) {
    const size_t z = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (z >= rows * queries) return;
    const size_t q = z / rows;
    const size_t i = z - q * rows;
    out[z] = matrix[i * cols + indices[q]];
}

__global__ void gather_fp2_columns_kernel(
    const Fp2* matrix,const uint32_t* indices,Fp2* out,
    size_t rows,size_t cols,size_t queries){
    const size_t z=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(z>=rows*queries)return;const size_t q=z/rows,i=z-q*rows;
    out[z]=matrix[i*cols+indices[q]];
}

// -------------------------------------------------------------------------
// BLAKE3 column leaves (exact unkeyed hash semantics)
// -------------------------------------------------------------------------

constexpr uint32_t CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8;
struct Hash32 { uint32_t w[8]; };
struct HashOutput {
    uint32_t cv[8], block[16];
    uint64_t counter;
    uint32_t block_len, flags;
};

__host__ __device__ constexpr uint32_t iv(int i) {
    constexpr uint32_t v[8] = {0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,
        0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19};
    return v[i];
}
__host__ __device__ constexpr uint8_t perm(int i) {
    constexpr uint8_t p[16] = {2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8};
    return p[i];
}
__host__ __device__ inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
__host__ __device__ inline void bg(uint32_t s[16], int a,int b,int c,int d,uint32_t x,uint32_t y) {
    s[a]=s[a]+s[b]+x;s[d]=rotr(s[d]^s[a],16);s[c]+=s[d];s[b]=rotr(s[b]^s[c],12);
    s[a]=s[a]+s[b]+y;s[d]=rotr(s[d]^s[a],8);s[c]+=s[d];s[b]=rotr(s[b]^s[c],7);
}
__host__ __device__ void compress(const uint32_t cv[8],const uint32_t block[16],uint64_t counter,
    uint32_t block_len,uint32_t flags,uint32_t out[16]) {
    uint32_t s[16],m[16],tmp[16];
    for(int i=0;i<8;++i)s[i]=cv[i];for(int i=0;i<4;++i)s[8+i]=iv(i);
    s[12]=counter;s[13]=counter>>32;s[14]=block_len;s[15]=flags;
    for(int i=0;i<16;++i)m[i]=block[i];
    for(int r=0;r<7;++r){
        bg(s,0,4,8,12,m[0],m[1]);bg(s,1,5,9,13,m[2],m[3]);
        bg(s,2,6,10,14,m[4],m[5]);bg(s,3,7,11,15,m[6],m[7]);
        bg(s,0,5,10,15,m[8],m[9]);bg(s,1,6,11,12,m[10],m[11]);
        bg(s,2,7,8,13,m[12],m[13]);bg(s,3,4,9,14,m[14],m[15]);
        for(int i=0;i<16;++i)tmp[i]=m[perm(i)];for(int i=0;i<16;++i)m[i]=tmp[i];
    }
    for(int i=0;i<8;++i){out[i]=s[i]^s[i+8];out[i+8]=s[i+8]^cv[i];}
}
__host__ __device__ Hash32 chaining_value(const HashOutput& o) {
    uint32_t v[16];compress(o.cv,o.block,o.counter,o.block_len,o.flags,v);Hash32 h{};
    for(int i=0;i<8;++i)h.w[i]=v[i];return h;
}
__host__ __device__ Hash32 root_hash(const HashOutput& o) {
    uint32_t v[16];compress(o.cv,o.block,0,o.block_len,o.flags|ROOT,v);Hash32 h{};
    for(int i=0;i<8;++i)h.w[i]=v[i];return h;
}
__host__ __device__ HashOutput parent_output(Hash32 l,Hash32 r) {
    HashOutput o{};for(int i=0;i<8;++i){o.cv[i]=iv(i);o.block[i]=l.w[i];o.block[8+i]=r.w[i];}
    o.block_len=64;o.flags=PARENT;return o;
}
__device__ uint64_t column_word(
    const uint64_t* matrix,size_t cols,size_t col,size_t word,size_t words_per_value) {
    const size_t row=word/words_per_value,part=word-row*words_per_value;
    if(words_per_value==1)return matrix[row*cols+col];
    const Fp2 x=reinterpret_cast<const Fp2*>(matrix)[row*cols+col];
    return part?x.c1:x.c0;
}
__device__ HashOutput chunk_output_column_words(
    const uint64_t* matrix,size_t total_words,size_t cols,size_t col,size_t chunk,
    size_t words_per_value) {
    HashOutput o{};uint32_t cv[8];for(int i=0;i<8;++i)cv[i]=iv(i);
    const size_t word0=chunk*128,take=min(size_t{128},total_words-word0);
    const int blocks=(take+7)/8;
    for(int b=0;b<blocks;++b){uint32_t words[16]{};
        const size_t block_words=min(size_t{8},take-static_cast<size_t>(b)*8);
        for(size_t i=0;i<block_words;++i){const uint64_t x=column_word(
            matrix,cols,col,word0+static_cast<size_t>(b)*8+i,words_per_value);
            words[2*i]=x;words[2*i+1]=x>>32;}
        const uint32_t flags=(b==0?CHUNK_START:0)|(b+1==blocks?CHUNK_END:0);
        const uint32_t block_len=static_cast<uint32_t>(block_words*8);
        if(b+1==blocks){for(int i=0;i<8;++i)o.cv[i]=cv[i];for(int i=0;i<16;++i)o.block[i]=words[i];
            o.counter=chunk;o.block_len=block_len;o.flags=flags;}
        else{uint32_t v[16];compress(cv,words,chunk,block_len,flags,v);for(int i=0;i<8;++i)cv[i]=v[i];}
    }return o;
}
__device__ Hash32 hash_column_words(
    const uint64_t* matrix,size_t rows,size_t cols,size_t col,size_t words_per_value) {
    const size_t total_words=rows*words_per_value,chunks=(total_words+127)/128;
    Hash32 stack[16];int depth=0;HashOutput root_out{},single{};
    for(size_t c=0;c<chunks;++c){HashOutput co=chunk_output_column_words(
        matrix,total_words,cols,col,c,words_per_value);if(chunks==1)single=co;
        Hash32 cv=chaining_value(co);size_t total=c;
        while(total&1){root_out=parent_output(stack[--depth],cv);cv=chaining_value(root_out);total>>=1;}
        stack[depth++]=cv;}
    if(chunks==1)return root_hash(single);Hash32 cv=stack[--depth];
    while(depth){root_out=parent_output(stack[--depth],cv);cv=chaining_value(root_out);}return root_hash(root_out);
}
__global__ void hash_columns_kernel(const uint64_t* matrix,Hash32* leaves,size_t rows,size_t cols) {
    const size_t col=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(col<cols)leaves[col]=hash_column_words(matrix,rows,cols,col,1);
}
__global__ void hash_fp2_columns_kernel(const Fp2* matrix,Hash32* leaves,size_t rows,size_t cols) {
    const size_t col=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(col<cols)leaves[col]=hash_column_words(reinterpret_cast<const uint64_t*>(matrix),rows,cols,col,2);
}
__device__ Hash32 hash_merkle_pair(Hash32 left,Hash32 right){
    HashOutput o{};for(int i=0;i<8;++i)o.cv[i]=iv(i);
    for(int i=0;i<8;++i){o.block[i]=left.w[i];o.block[8+i]=right.w[i];}
    o.block_len=64;o.flags=CHUNK_START|CHUNK_END;return root_hash(o);
}
__global__ void merkle_parent_kernel(
    const Hash32* children,Hash32* parents,size_t parent_count){
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<parent_count)parents[i]=hash_merkle_pair(children[2*i],children[2*i+1]);
}
__global__ void merkle_paths_kernel(
    const Hash32* tree,const uint32_t* indices,Hash32* paths,
    size_t leaves,size_t queries,size_t bits){
    const size_t z=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(z>=queries*bits)return;const size_t q=z/bits,level=z-q*bits;
    size_t idx=indices[q],len=leaves,off=0;
    for(size_t l=0;l<level;++l){off+=len;len>>=1;idx>>=1;}
    paths[z]=tree[off+(idx^1)];
}

} // namespace volta_cuda_internal

using namespace volta_cuda_internal;

extern "C" uint32_t volta_cuda_abi_version() { return ABI_VERSION; }

extern "C" int volta_cuda_create(void** out) {
    if (!out) return -1;
    *out = nullptr;
    Context* c = nullptr;
    try {
        c = new (std::nothrow) Context;
        if (!c) return -1;
        *out = c;
        int count = 0;
        cudaError_t e = cudaGetDeviceCount(&count);
        if (e != cudaSuccess) return fail(c, "cudaGetDeviceCount", e);
        if (count < 1) return fail_message(c, "no CUDA device is available");
        if ((e = cudaStreamCreateWithFlags(&c->stream, cudaStreamNonBlocking)) != cudaSuccess)
            return fail(c, "cudaStreamCreateWithFlags", e);
        for (auto& event : c->events) {
            if ((e = timing_event_create(c, &event)) != cudaSuccess)
                return fail(c, "cudaEventCreate", e);
        }
        if (select_timing_mode(c)) return -1;
        return 0;
    } catch (const std::exception&) {
        return fail_exception(c, "CUDA context construction threw a C++ exception");
    } catch (...) {
        return fail_exception(c, "CUDA context construction threw an unknown exception");
    }
}

extern "C" void volta_cuda_destroy(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return;
    // An RAII guard may be abandoned because its owner is itself being
    // destroyed. Discard the uncommitted coarse record before flushing older
    // records; the final stream synchronization below still protects storage.
    if (c->coarse_timing_active) abort_active_timing_record(c);
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED)
        (void)flush_deferred_timing(c, SyncReason::TimingFlush);
    // Also covers a CUDA failure after begin_timing: that record is aborted
    // for reuse, but already-enqueued work must still finish before storage
    // or events are destroyed.
    if (c->stream) (void)cudaStreamSynchronize(c->stream);
    for (auto& b : c->buffers) if (b.ptr) cudaFree(b.ptr);
    for (auto& b : c->resident) if (b.ptr) cudaFree(b.ptr);
    for (auto& record : c->timing_ring)
        for (auto event : record.events) if (event) cudaEventDestroy(event);
    for (auto event : c->events) if (event) cudaEventDestroy(event);
    if (c->stream) cudaStreamDestroy(c->stream);
    delete c;
}

extern "C" const char* volta_cuda_last_error(void* raw) {
    Context* c = static_cast<Context*>(raw);
    return c ? c->error.c_str() : "null CUDA context";
}

/// Select the resident observation policy exactly once after context
/// construction. Policy 0 enables deferred CUDA events when the runtime
/// supports them (otherwise retaining the host-barrier fallback); policy 1
/// keeps wall/counters while issuing no CUDA event calls in measured work.
/// Hybrid contexts never call this entry point.
extern "C" int volta_cuda_set_resident_timing_policy(void* raw, int policy) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->active_timing_record != TIMING_RING_SIZE || c->coarse_timing_active ||
        c->counter_timing_active || c->timing_ring_pending || c->counter_stream_pending)
        return reject_message(c, "cannot change resident timing policy after work has started");
    if (policy == 0) {
        if (c->timing_mode == TIMING_CUDA_EVENTS)
            c->timing_mode = TIMING_CUDA_EVENTS_DEFERRED;
    } else if (policy == 1) {
        c->timing_mode = TIMING_WALL_ONLY_COUNTERS;
    } else {
        return reject_message(c, "unknown resident timing policy");
    }
    // Context construction probes event support before the resident policy is
    // known. Those calls are outside every measurement window and must not be
    // attributed to either arm of the A/B.
    c->stats.timing_elapsed_query_attempts = 0;
    c->stats.timing_elapsed_no_write = 0;
    c->stats.timing_event_queries = 0;
    c->stats.timing_event_api_calls = 0;
    c->stats.timing_mode = c->timing_mode;
    return 0;
}

/// Deterministic fault injection for the exact deferred retry regression.
/// This simulates one provider cudaSuccess/no-write response without changing
/// event state; production callers never invoke this diagnostic ABI.
extern "C" int volta_cuda_test_inject_elapsed_no_write_once(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->active_timing_record != TIMING_RING_SIZE)
        return reject_message(c, "cannot inject elapsed no-write during an active record");
    c->test_elapsed_no_write_remaining = 1;
    return 0;
}

/// Begin one resident epoch-level timing interval. Inner device-only
/// primitives retain their ordinary operation/byte accounting but suppress
/// their per-call CUDA events until this scope is ended.
extern "C" int volta_cuda_begin_coarse_timing(void* raw, int operation) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED &&
        c->timing_mode != TIMING_WALL_ONLY_COUNTERS)
        return reject_message(c, "coarse timing requires a resident observation mode");
    if (c->measurement_poisoned)
        return reject_message(c, "measurement timing is poisoned; reset stats before continuing");
    if (operation < 0 || operation >= OP_COUNT)
        return reject_message(c, "invalid coarse timing operation");
    if (c->coarse_timing_active || c->active_timing_record != TIMING_RING_SIZE ||
        c->counter_timing_active)
        return reject_message(c, "nested coarse timing scope");
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED &&
        begin_deferred_record(c, TimingRecordKind::CoarseOperation, 2)) return -1;
    c->coarse_timing_operation = operation;
    c->coarse_timing_active = true;
    c->coarse_inner_active = false;
    c->coarse_accounted_work = false;
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED)
        c->timing_ring[c->active_timing_record].operation = operation;
    return 0;
}

extern "C" int volta_cuda_end_coarse_timing(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED &&
        c->timing_mode != TIMING_WALL_ONLY_COUNTERS)
        return reject_message(c, "coarse timing requires a resident observation mode");
    if (!c->coarse_timing_active ||
        (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED &&
         c->active_timing_record == TIMING_RING_SIZE))
        return reject_message(c, "no active coarse timing scope");
    if (c->coarse_inner_active)
        return reject_message(c, "cannot end coarse timing during an active primitive");
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED) {
        TimingRecord& record = c->timing_ring[c->active_timing_record];
        CUDA_OR_RETURN(c, timing_event_record(c, record.events[1]));
        record.event_mask |= 1u << 1;
        record.kind = TimingRecordKind::CoarseOperation;
        record.operation = c->coarse_timing_operation;
    }
    c->coarse_timing_active = false;
    c->coarse_timing_operation = -1;
    if (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED && commit_deferred_record(c)) return -1;
    c->coarse_accounted_work = false;
    ++c->stats.coarse_timing_scopes;
    return 0;
}

/// Best-effort idempotent recovery for a dropped Rust guard or an inner CUDA
/// error. The start event is discarded and the ring slot remains reusable.
extern "C" int volta_cuda_abort_coarse_timing(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED &&
        c->timing_mode != TIMING_WALL_ONLY_COUNTERS)
        return reject_message(c, "coarse timing requires a resident observation mode");
    if (c->coarse_timing_active) abort_active_timing_record(c);
    return 0;
}

/// Preflight one sealed cohort against the fixed deferred-event ring. The
/// equality boundary fits exactly; overflow performs one classified flush
/// before the cohort starts, never in its middle.
extern "C" int volta_cuda_ensure_timing_capacity(
    void* raw, size_t bound, size_t* pending_before,
    size_t* pending_after, int* flushed) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pending_before || !pending_after || !flushed)
        return reject_message(c, "invalid timing-capacity output");
    if (c->timing_mode != TIMING_CUDA_EVENTS_DEFERRED &&
        c->timing_mode != TIMING_WALL_ONLY_COUNTERS)
        return reject_message(c, "timing-capacity preflight requires a resident observation mode");
    if (c->active_timing_record != TIMING_RING_SIZE || c->counter_timing_active)
        return reject_message(c, "cannot preflight timing capacity during an active record");
    if (bound > TIMING_RING_SIZE)
        return reject_message(c, "deferred timing cohort bound exceeds ring capacity");
    *pending_before = c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED
        ? c->timing_ring_pending : 0;
    *flushed = 0;
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        *pending_after = 0;
        return 0;
    }
    if (c->timing_ring_pending > TIMING_RING_SIZE - bound) {
        if (flush_deferred_timing(c, SyncReason::TimingFlush)) return -1;
        *flushed = 1;
    }
    *pending_after = c->timing_ring_pending;
    return 0;
}

extern "C" int volta_cuda_flush_profiling(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->measurement_poisoned)
        return reject_message(c, "measurement timing is poisoned; reset stats before reading it");
    if (c->active_timing_record != TIMING_RING_SIZE || c->counter_timing_active)
        return reject_message(c, "cannot flush an active timing record");
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS && c->counter_stream_pending)
        return synchronize_stream(c, SyncReason::TimingFlush);
    return flush_deferred_timing(c, SyncReason::TimingFlush);
}

extern "C" int volta_cuda_reset_stats(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    if (c->active_timing_record != TIMING_RING_SIZE || c->counter_timing_active)
        return reject_message(c, "cannot reset stats during an active timing record");
    const bool had_pending_timing =
        (c->timing_mode == TIMING_CUDA_EVENTS_DEFERRED && c->timing_ring_pending != 0) ||
        (c->timing_mode == TIMING_WALL_ONLY_COUNTERS && c->counter_stream_pending);
    if (discard_deferred_timing(c, SyncReason::TimingFlush)) return -1;
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS && c->counter_stream_pending &&
        synchronize_stream(c, SyncReason::TimingFlush)) return -1;
    // An aborted coarse scope is not a committed ring record, but its kernels
    // may still be in flight. If no pending record forced the barrier above,
    // synchronize explicitly before making the poisoned counters reusable.
    if (c->measurement_poisoned && !had_pending_timing &&
        synchronize_stream(c, SyncReason::TimingFlush)) return -1;
    const uint64_t live = c->stats.live_device_bytes;
    const uint32_t timing_mode = c->timing_mode;
    c->stats = RawStats{};
    c->stats.live_device_bytes = live;
    c->stats.peak_device_bytes = live;
    c->stats.timing_mode = timing_mode;
    c->measurement_poisoned = false;
    c->coarse_accounted_work = false;
    c->counter_timing_active = false;
    c->counter_stream_pending = false;
    return 0;
}

extern "C" int volta_cuda_get_stats(void* raw, RawStats* out) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !out) return -1;
    if (c->measurement_poisoned)
        return reject_message(c, "measurement timing is poisoned; reset stats before reading it");
    if (c->active_timing_record != TIMING_RING_SIZE || c->counter_timing_active)
        return reject_message(c, "cannot read stats during an active timing record");
    if (volta_cuda_flush_profiling(raw)) return -1;
    if (synchronization_reason_total(c->stats) != c->stats.synchronizations)
        return fail_message(c, "synchronization reason accounting mismatch");
    if (c->stats.timing_elapsed_query_attempts !=
        c->stats.timing_event_queries + c->stats.timing_elapsed_no_write)
        return fail_message(c, "elapsed timing query accounting mismatch");
    if (c->timing_mode == TIMING_WALL_ONLY_COUNTERS) {
        uint64_t kernel_ns = 0;
        for (const auto value : c->stats.kernel_ns) kernel_ns += value;
        if (c->stats.timing_records || c->stats.timing_elapsed_query_attempts ||
            c->stats.timing_elapsed_no_write || c->stats.timing_event_queries ||
            c->stats.timing_event_api_calls || c->stats.timing_pending_high_water ||
            c->stats.timing_flush_count || c->stats.h2d_ns || c->stats.d2h_ns ||
            c->stats.coarse_timing_ns || kernel_ns)
            return fail_message(c, "wall-only counter mode emitted CUDA-event attribution");
    }
    *out = c->stats;
    return 0;
}

extern "C" int volta_cuda_memory_breakdown(
    void* raw, uint64_t* workspace_bytes, uint64_t* resident_bytes,
    uint64_t* cached_resident_bytes) {
    Context* c = static_cast<Context*>(raw);
    try {
        if (!c || !workspace_bytes || !resident_bytes || !cached_resident_bytes)
            return fail_message(c, "invalid memory-breakdown output");
        uint64_t workspace = 0;
        uint64_t resident = 0;
        uint64_t cached = 0;
        for (const auto& b : c->buffers) workspace += b.capacity;
        for (const auto& b : c->resident) {
            if (!b.ptr) continue;
            if (b.active) resident += b.capacity;
            else cached += b.capacity;
        }
        if (workspace + resident + cached != c->stats.live_device_bytes)
            return fail_message(c, "device-memory accounting mismatch");
        *workspace_bytes = workspace;
        *resident_bytes = resident;
        *cached_resident_bytes = cached;
        return 0;
    } catch (const std::exception&) {
        return fail_exception(c, "device-memory accounting threw a C++ exception");
    } catch (...) {
        return fail_exception(c, "device-memory accounting threw an unknown exception");
    }
}

/// Release inactive arena storage while retaining active resident handles and
/// primitive workspaces. This is a teardown/pressure operation, never an
/// implicit part of logical `resident_free`.
extern "C" int volta_cuda_trim_resident_cache(void* raw) {
    Context* c = static_cast<Context*>(raw);
    try {
        if (!c) return fail_message(c, "invalid resident-cache trim context");
        if (c->coarse_timing_active)
            return reject_message(c, "resident-cache trim is forbidden inside a coarse timing scope");
        return trim_inactive_resident(c);
    } catch (const std::exception&) {
        return fail_exception(c, "resident-cache trim threw a C++ exception");
    } catch (...) {
        return fail_exception(c, "resident-cache trim threw an unknown exception");
    }
}

extern "C" int volta_cuda_resident_alloc(void* raw, size_t bytes, uint64_t* out_id) {
    Context* c = static_cast<Context*>(raw);
    try {
        if (!c || !bytes || !out_id) return fail_message(c, "invalid resident allocation");
        if (c->coarse_timing_active)
            return reject_message(c, "resident allocation is forbidden inside a coarse timing scope");
        ++c->stats.resident_alloc_requests;

        const size_t reused_slot = take_best_fit_resident(c, bytes);
        if (reused_slot != std::numeric_limits<size_t>::max()) {
            ResidentBuffer& b = c->resident[reused_slot];
            ++b.generation;
            b.logical_bytes = bytes;
            b.active = true;
            ++c->stats.resident_reuse_hits;
            *out_id = resident_id(reused_slot, b.generation);
            return 0;
        }

        bool has_empty_slot = false;
        for (const size_t slot : c->inactive_resident) {
            const ResidentBuffer& b = c->resident[slot];
            if (!b.active && !b.ptr && b.generation != RESIDENT_GENERATION_MAX) {
                has_empty_slot = true;
                break;
            }
        }
        if (!has_empty_slot && ensure_resident_slot_capacity(c)) return -1;

        void* ptr = nullptr;
        cudaError_t e = cudaMalloc(&ptr, bytes);
        if (e == cudaErrorMemoryAllocation) {
            // cudaMalloc/cudaFree are used only on arena misses or pressure.
            // Reuse itself is host metadata and relies on this context's
            // single-stream ordering. It does not pin storage for CUDA graphs.
            cudaGetLastError();
            if (trim_inactive_resident(c)) return -1;
            e = cudaMalloc(&ptr, bytes);
        }
        if (e != cudaSuccess) return fail(c, "cudaMalloc(&resident, bytes)", e);
        // Account the physical allocation at the CUDA success boundary. If
        // the following metadata insertion were to throw, its catch records
        // the compensating physical free and rolls live bytes back without
        // erasing this allocation event.
        ++c->stats.allocation_calls;
        c->stats.live_device_bytes += bytes;
        c->stats.peak_device_bytes =
            std::max(c->stats.peak_device_bytes, c->stats.live_device_bytes);

        size_t slot = take_empty_resident_slot(c);
        if (slot == std::numeric_limits<size_t>::max()) {
            ResidentBuffer b;
            b.ptr = ptr;
            b.capacity = bytes;
            b.logical_bytes = bytes;
            b.generation = 1;
            b.active = true;
            try {
                c->resident.push_back(b);
            } catch (...) {
                const cudaError_t free_error = cudaFree(ptr);
                if (free_error == cudaSuccess) {
                    ++c->stats.physical_free_calls;
                    c->stats.live_device_bytes -= bytes;
                }
                throw;
            }
            slot = c->resident.size() - 1;
        } else {
            ResidentBuffer& b = c->resident[slot];
            ++b.generation;
            b.ptr = ptr;
            b.capacity = bytes;
            b.logical_bytes = bytes;
            b.active = true;
        }
        *out_id = resident_id(slot, c->resident[slot].generation);
        return 0;
    } catch (const std::exception&) {
        return fail_exception(c, "resident allocation threw a C++ exception");
    } catch (...) {
        return fail_exception(c, "resident allocation threw an unknown exception");
    }
}

extern "C" int volta_cuda_resident_free(void* raw, uint64_t id) {
    Context* c = static_cast<Context*>(raw);
    try {
        if (!c || !id) return fail_message(c, "invalid resident free");
        if (c->coarse_timing_active)
            return reject_message(c, "resident free is forbidden inside a coarse timing scope");
        ++c->stats.resident_free_requests;
        ResidentBuffer* b = find_resident(c, id);
        if (!b) return fail_message(c, "unknown or stale resident buffer id");
        const uint64_t encoded_slot = id & RESIDENT_SLOT_MASK;
        const size_t slot = static_cast<size_t>(encoded_slot - 1);
        // All context work is enqueued on one stream. A later user of this
        // cached pointer is therefore ordered after its previous user. A
        // future graph must retain its DeviceBuffers instead of freeing them.
        c->inactive_resident.push_back(slot);
        b->logical_bytes = 0;
        b->active = false;
        return 0;
    } catch (const std::exception&) {
        return fail_exception(c, "resident free threw a C++ exception");
    } catch (...) {
        return fail_exception(c, "resident free threw an unknown exception");
    }
}

extern "C" int volta_cuda_resident_upload(
    void* raw, uint64_t id, size_t offset_bytes, const void* src, size_t bytes) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !src || !bytes) return fail_message(c, "invalid resident upload");
    void* dst = nullptr;
    if (resident_region(c, id, offset_bytes, bytes, &dst)) return -1;
    if (begin_transfer_timing(c)) return -1;
    const auto host_call_started = std::chrono::steady_clock::now();
    const cudaError_t copy_status =
        cudaMemcpyAsync(dst, src, bytes, cudaMemcpyHostToDevice, c->stream);
    const auto host_call_finished = std::chrono::steady_clock::now();
    if (copy_status != cudaSuccess)
        return fail(c, "cudaMemcpyAsync(resident H2D)", copy_status);
    ++c->stats.resident_h2d_host_calls;
    c->stats.resident_h2d_host_call_ns +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            host_call_finished - host_call_started).count();
    return finish_transfer_timing(c, bytes, true);
}

extern "C" int volta_cuda_resident_download(
    void* raw, uint64_t id, size_t offset_bytes, void* dst, size_t bytes) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !dst || !bytes) return fail_message(c, "invalid resident download");
    void* src = nullptr;
    if (resident_region(c, id, offset_bytes, bytes, &src)) return -1;
    if (begin_transfer_timing(c)) return -1;
    const auto host_call_started = std::chrono::steady_clock::now();
    const cudaError_t copy_status =
        cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDeviceToHost, c->stream);
    const auto host_call_finished = std::chrono::steady_clock::now();
    if (copy_status != cudaSuccess)
        return fail(c, "cudaMemcpyAsync(resident D2H)", copy_status);
    ++c->stats.resident_d2h_host_calls;
    c->stats.resident_d2h_host_call_ns +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            host_call_finished - host_call_started).count();
    return finish_transfer_timing(c, bytes, false);
}

extern "C" int volta_cuda_resident_zero(
    void* raw, uint64_t id, size_t offset_bytes, size_t bytes) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !bytes) return fail_message(c, "invalid resident zero");
    void* dst = nullptr;
    if (resident_region(c, id, offset_bytes, bytes, &dst)) return -1;
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    CUDA_OR_RETURN(c, cudaMemsetAsync(dst, 0, bytes, c->stream));
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_PCS_ROWS, 0, 0, 0, bytes, 0);
}

int resident_copy_rows_impl(
    Context* c,
    uint64_t src_id, size_t src_offset_bytes, size_t src_stride_bytes,
    uint64_t dst_id, size_t dst_offset_bytes, size_t dst_stride_bytes,
    size_t rows, size_t row_bytes, int operation) {
    if (!c) return fail_message(c, "invalid resident D2D copy context");
    if (operation != OP_PCS_ROWS && operation != OP_MAILBOX)
        return fail_message(c, "invalid resident D2D copy operation");
    void* src = nullptr;
    void* dst = nullptr;
    size_t src_span = 0;
    size_t dst_span = 0;
    if (resident_strided_region(
            c, src_id, src_offset_bytes, src_stride_bytes,
            row_bytes, rows, &src, &src_span) ||
        resident_strided_region(
            c, dst_id, dst_offset_bytes, dst_stride_bytes,
            row_bytes, rows, &dst, &dst_span))
        return -1;
    if (src_id == dst_id) {
        size_t src_end = 0;
        size_t dst_end = 0;
        if (!checked_add_size(src_offset_bytes, src_span, &src_end) ||
            !checked_add_size(dst_offset_bytes, dst_span, &dst_end))
            return fail_message(c, "resident D2D copy envelope overflows size_t");
        if (src_offset_bytes < dst_end && dst_offset_bytes < src_end)
            return fail_message(c, "resident D2D copy source and destination overlap");
    }
    size_t total_bytes = 0;
    if (!checked_mul_size(rows, row_bytes, &total_bytes))
        return fail_message(c, "resident D2D byte count overflows size_t");
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpy2DAsync(
        dst, dst_stride_bytes, src, src_stride_bytes, row_bytes, rows,
        cudaMemcpyDeviceToDevice, c->stream));
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, operation, 0, 0, total_bytes, 0, 0);
}

/// Copy PCS-owned non-overlapping strided rows entirely within this CUDA
/// context. Pitches, offsets, and row width are byte counts.
extern "C" int volta_cuda_resident_copy_rows(
    void* raw,
    uint64_t src_id, size_t src_offset_bytes, size_t src_stride_bytes,
    uint64_t dst_id, size_t dst_offset_bytes, size_t dst_stride_bytes,
    size_t rows, size_t row_bytes) {
    return resident_copy_rows_impl(
        static_cast<Context*>(raw), src_id, src_offset_bytes, src_stride_bytes,
        dst_id, dst_offset_bytes, dst_stride_bytes, rows, row_bytes, OP_PCS_ROWS);
}

/// The same D2D primitive explicitly classified as protocol-mailbox work.
extern "C" int volta_cuda_resident_mailbox_copy_rows(
    void* raw,
    uint64_t src_id, size_t src_offset_bytes, size_t src_stride_bytes,
    uint64_t dst_id, size_t dst_offset_bytes, size_t dst_stride_bytes,
    size_t rows, size_t row_bytes) {
    return resident_copy_rows_impl(
        static_cast<Context*>(raw), src_id, src_offset_bytes, src_stride_bytes,
        dst_id, dst_offset_bytes, dst_stride_bytes, rows, row_bytes, OP_MAILBOX);
}

int chacha8_fp_rows_device_impl(
    Context* c, uint64_t output_id, size_t output_offset_bytes,
    const uint8_t* seed, uint64_t base_domain, size_t rows, size_t count,
    int operation) {
    if (!c || !seed || !rows || !count)
        return fail_message(c, "invalid ChaCha8 Fp row generation");
    if (operation != OP_PCS_ROWS && operation != OP_AUTH_MASKS)
        return fail_message(c, "invalid ChaCha8 Fp row operation");
    if (rows - 1 > std::numeric_limits<uint64_t>::max() - base_domain)
        return fail_message(c, "ChaCha8 Fp row domain overflows u64");
    const uint64_t last_domain = base_domain + static_cast<uint64_t>(rows - 1);
    if (operation == OP_AUTH_MASKS &&
        ((base_domain | last_domain) & MOCK_CORRELATION_RESERVED_DOMAIN_BITS) != 0)
        return fail_message(c, "mock correlation mask domain sets reserved correlation bits");
    size_t elements = 0;
    size_t bytes = 0;
    if (!checked_mul_size(rows, count, &elements) ||
        !checked_mul_size(elements, sizeof(uint64_t), &bytes))
        return fail_message(c, "ChaCha8 Fp row geometry overflows size_t");
    void* output = nullptr;
    if (resident_region(c, output_id, output_offset_bytes, bytes, &output)) return -1;
    const volta::chacha8_fp::Key key = volta::chacha8_fp::key_from_seed(seed);
    const size_t blocks_needed = (rows - 1) / BLOCK + 1;
    const unsigned int blocks = static_cast<unsigned int>(std::min<size_t>(blocks_needed, 65535));
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    chacha8_prover_secret_fp_rows_kernel<<<blocks, BLOCK, 0, c->stream>>>(
        key, base_domain, rows, count, static_cast<uint64_t*>(output));
    CUDA_OR_RETURN(c, cudaGetLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, operation, 0, 0, 0, 0, bytes);
}

/// Expand compact Fp rows from a prover-secret PCS seed. The 32-byte seed and
/// geometry are kernel launch arguments, not host-to-device payload bytes.
extern "C" int volta_cuda_chacha8_prover_secret_fp_rows_device(
    void* raw, uint64_t output_id, size_t output_offset_bytes,
    const uint8_t* prover_secret_seed, uint64_t base_domain,
    size_t rows, size_t count) {
    return chacha8_fp_rows_device_impl(
        static_cast<Context*>(raw), output_id, output_offset_bytes,
        prover_secret_seed, base_domain, rows, count, OP_PCS_ROWS);
}

/// The same byte-exact expansion kernel, semantically classified as mock
/// authentication/correlation work rather than PCS work.
extern "C" int volta_cuda_mock_correlation_sub_masks_device(
    void* raw, uint64_t output_id, size_t output_offset_bytes,
    const uint8_t* mock_correlation_seed, uint64_t base_domain,
    size_t rows, size_t cols) {
    return chacha8_fp_rows_device_impl(
        static_cast<Context*>(raw), output_id, output_offset_bytes,
        mock_correlation_seed, base_domain, rows, cols, OP_AUTH_MASKS);
}

/// Expand Fp2 rows from a prover-secret seed and write canonical zeroes in
/// every tail slot [count, padded_count). Seed/control arguments are not H2D.
extern "C" int volta_cuda_chacha8_prover_secret_fp2_rows_padded_device(
    void* raw, uint64_t output_id, size_t output_offset_bytes,
    const uint8_t* prover_secret_seed, uint64_t base_domain,
    size_t rows, size_t count, size_t padded_count) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !prover_secret_seed || !rows || !count || count > padded_count)
        return fail_message(c, "invalid prover-secret padded Fp2 row generation");
    if (rows - 1 > std::numeric_limits<uint64_t>::max() - base_domain)
        return fail_message(c, "prover-secret Fp2 row domain overflows u64");
    size_t output_elements = 0;
    size_t output_bytes = 0;
    size_t generated_elements = 0;
    size_t generated_bytes = 0;
    size_t zeroed_elements = 0;
    size_t zeroed_bytes = 0;
    if (!checked_mul_size(rows, padded_count, &output_elements) ||
        !checked_mul_size(output_elements, sizeof(Fp2), &output_bytes) ||
        !checked_mul_size(rows, count, &generated_elements) ||
        !checked_mul_size(generated_elements, sizeof(Fp2), &generated_bytes) ||
        !checked_mul_size(rows, padded_count - count, &zeroed_elements) ||
        !checked_mul_size(zeroed_elements, sizeof(Fp2), &zeroed_bytes))
        return fail_message(c, "prover-secret Fp2 row geometry overflows size_t");
    void* output = nullptr;
    if (resident_region(c, output_id, output_offset_bytes, output_bytes, &output)) return -1;
    const volta::chacha8_fp::Key key = volta::chacha8_fp::key_from_seed(prover_secret_seed);
    const size_t blocks_needed = (rows - 1) / BLOCK + 1;
    const unsigned int blocks = static_cast<unsigned int>(std::min<size_t>(blocks_needed, 65535));
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    chacha8_prover_secret_fp2_padded_rows_kernel<<<blocks, BLOCK, 0, c->stream>>>(
        key, base_domain, rows, count, padded_count, static_cast<Fp2*>(output));
    CUDA_OR_RETURN(c, cudaGetLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(
        c, OP_PCS_ROWS, 0, 0, 0, zeroed_bytes, generated_bytes);
}

extern "C" int volta_cuda_fp2_row_dots_device(
    void* raw,
    uint64_t a_id, size_t a_offset, size_t a_stride,
    uint64_t b_id, size_t b_offset, size_t b_stride,
    uint64_t output_id, size_t output_offset,
    size_t rows, size_t len) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !len || a_stride < len || b_stride < len)
        return fail_message(c, "invalid Fp2 row-dot geometry");
    size_t a_offset_bytes = 0;
    size_t a_stride_bytes = 0;
    size_t b_offset_bytes = 0;
    size_t b_stride_bytes = 0;
    size_t output_offset_bytes = 0;
    size_t output_bytes = 0;
    size_t row_bytes = 0;
    if (!checked_mul_size(a_offset, sizeof(Fp2), &a_offset_bytes) ||
        !checked_mul_size(a_stride, sizeof(Fp2), &a_stride_bytes) ||
        !checked_mul_size(b_offset, sizeof(Fp2), &b_offset_bytes) ||
        !checked_mul_size(b_stride, sizeof(Fp2), &b_stride_bytes) ||
        !checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes) ||
        !checked_mul_size(len, sizeof(Fp2), &row_bytes) ||
        !checked_mul_size(rows, sizeof(Fp2), &output_bytes))
        return fail_message(c, "Fp2 row-dot geometry overflows size_t");
    void* a = nullptr;
    void* b = nullptr;
    void* output = nullptr;
    size_t a_span = 0;
    size_t b_span = 0;
    if (resident_strided_region(
            c, a_id, a_offset_bytes, a_stride_bytes,
            row_bytes, rows, &a, &a_span) ||
        resident_strided_region(
            c, b_id, b_offset_bytes, b_stride_bytes,
            row_bytes, rows, &b, &b_span) ||
        resident_region(c, output_id, output_offset_bytes, output_bytes, &output))
        return -1;
    size_t output_end = 0;
    size_t a_end = 0;
    size_t b_end = 0;
    if (!checked_add_size(output_offset_bytes, output_bytes, &output_end) ||
        !checked_add_size(a_offset_bytes, a_span, &a_end) ||
        !checked_add_size(b_offset_bytes, b_span, &b_end))
        return fail_message(c, "Fp2 row-dot envelope overflows size_t");
    if ((output_id == a_id && output_offset_bytes < a_end && a_offset_bytes < output_end) ||
        (output_id == b_id && output_offset_bytes < b_end && b_offset_bytes < output_end))
        return fail_message(c, "Fp2 row-dot output overlaps an input");
    const unsigned int blocks = static_cast<unsigned int>(std::min<size_t>(rows, 65535));
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    fp2_row_dots_kernel<<<blocks, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(a), a_stride,
        static_cast<const Fp2*>(b), b_stride,
        static_cast<Fp2*>(output), rows, len);
    CUDA_OR_RETURN(c, cudaGetLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_PCS_ROWS, 0, 0);
}

extern "C" int volta_cuda_fp2_powers_device(
    void* raw, uint64_t base_c0, uint64_t base_c1,
    uint64_t output_id, size_t output_offset, size_t count) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !count || base_c0 >= P || base_c1 >= P)
        return fail_message(c, "invalid Fp2 powers input");
    size_t output_offset_bytes = 0;
    size_t output_bytes = 0;
    if (!checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes) ||
        !checked_mul_size(count, sizeof(Fp2), &output_bytes))
        return fail_message(c, "Fp2 powers geometry overflows size_t");
    void* output = nullptr;
    if (resident_region(c, output_id, output_offset_bytes, output_bytes, &output)) return -1;
    if (begin_timing(c) || mark_timing(c, 1)) return -1;
    fp2_powers_kernel<<<1, 1, 0, c->stream>>>(
        Fp2{base_c0, base_c1}, static_cast<Fp2*>(output), count);
    CUDA_OR_RETURN(c, cudaGetLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_PCS_ROWS, 0, 0, 0, 0, output_bytes);
}

extern "C" int volta_cuda_gemm_i64(
    void* raw,const int16_t* a,const int16_t* b,int64_t* out,size_t m,size_t k,size_t n) {
    Context* c=static_cast<Context*>(raw);if(!c||!a||!b||!out||!m||!k||!n)return -1;
    const size_t ab=m*k*2,bb=k*n*2,ob=m*n*8;
    if(ensure(c,0,ab)||ensure(c,1,bb)||ensure(c,2,ob))return -1;
    if(begin_timing(c))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<int16_t>(c,0),a,ab,cudaMemcpyHostToDevice,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<int16_t>(c,1),b,bb,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;dim3 block(16,16),grid((n+15)/16,(m+15)/16);
    gemm_i64_kernel<<<grid,block,0,c->stream>>>(buf<int16_t>(c,0),buf<int16_t>(c,1),buf<int64_t>(c,2),m,k,n);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<int64_t>(c,2),ob,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_GEMM,ab+bb,ob);
}

extern "C" int volta_cuda_gemm_i64_device(
    void* raw, uint64_t a_id, size_t a_offset, uint64_t b_id, size_t b_offset,
    uint64_t out_id, size_t out_offset, size_t m, size_t k, size_t n) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !m || !k || !n) return fail_message(c, "invalid resident GEMM geometry");
    void *av = nullptr, *bv = nullptr, *ov = nullptr;
    if (resident_region(c, a_id, a_offset * sizeof(int16_t), m * k * sizeof(int16_t), &av) ||
        resident_region(c, b_id, b_offset * sizeof(int16_t), k * n * sizeof(int16_t), &bv) ||
        resident_region(c, out_id, out_offset * sizeof(int64_t), m * n * sizeof(int64_t), &ov))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    dim3 block(16, 16), grid((n + 15) / 16, (m + 15) / 16);
    gemm_i64_kernel<<<grid, block, 0, c->stream>>>(
        static_cast<const int16_t*>(av), static_cast<const int16_t*>(bv),
        static_cast<int64_t*>(ov), m, k, n);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_gemm_requant_auth(void* raw,const int16_t* a,const int16_t* b,
    const uint64_t* masks,int16_t* out,uint64_t* corr,size_t m,size_t k,size_t n,uint32_t shift) {
    Context* c=static_cast<Context*>(raw);if(!c||!a||!b||!masks||!out||!corr||!shift||shift>=63)return -1;
    const size_t ab=m*k*2,bb=k*n*2,mb=m*n*8,ob=m*n*2,cb=m*n*8;
    if(ensure(c,0,ab)||ensure(c,1,bb)||ensure(c,2,mb)||ensure(c,3,ob)||ensure(c,4,cb))return -1;
    if(begin_timing(c))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<int16_t>(c,0),a,ab,cudaMemcpyHostToDevice,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<int16_t>(c,1),b,bb,cudaMemcpyHostToDevice,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,2),masks,mb,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;dim3 block(16,16),grid((n+15)/16,(m+15)/16);
    gemm_requant_auth_kernel<<<grid,block,0,c->stream>>>(buf<int16_t>(c,0),buf<int16_t>(c,1),
        buf<uint64_t>(c,2),buf<int16_t>(c,3),buf<uint64_t>(c,4),m,k,n,shift);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<int16_t>(c,3),ob,cudaMemcpyDeviceToHost,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(corr,buf<uint64_t>(c,4),cb,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_GEMM,ab+bb+mb,ob+cb);
}

extern "C" int volta_cuda_gemm_requant_auth_device(
    void* raw, uint64_t a_id, size_t a_offset, uint64_t b_id, size_t b_offset,
    uint64_t masks_id, size_t masks_offset, uint64_t out_id, size_t out_offset,
    uint64_t corr_id, size_t corr_offset, size_t m, size_t k, size_t n, uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !m || !k || !n || !shift || shift >= 63)
        return fail_message(c, "invalid resident fused GEMM geometry");
    void *av = nullptr, *bv = nullptr, *mv = nullptr, *ov = nullptr, *cv = nullptr;
    if (resident_region(c, a_id, a_offset * sizeof(int16_t), m * k * sizeof(int16_t), &av) ||
        resident_region(c, b_id, b_offset * sizeof(int16_t), k * n * sizeof(int16_t), &bv) ||
        resident_region(c, masks_id, masks_offset * sizeof(uint64_t), m * n * sizeof(uint64_t), &mv) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), m * n * sizeof(int16_t), &ov) ||
        resident_region(c, corr_id, corr_offset * sizeof(uint64_t), m * n * sizeof(uint64_t), &cv))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    dim3 block(16, 16), grid((n + 15) / 16, (m + 15) / 16);
    gemm_requant_auth_kernel<<<grid, block, 0, c->stream>>>(
        static_cast<const int16_t*>(av), static_cast<const int16_t*>(bv),
        static_cast<const uint64_t*>(mv), static_cast<int16_t*>(ov),
        static_cast<uint64_t*>(cv), m, k, n, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_embed_device(
    void* raw, uint64_t tokens_id, size_t tokens_offset,
    uint64_t wte_id, size_t wte_offset, uint64_t wpe_id, size_t wpe_offset,
    uint64_t acc_id, size_t acc_offset, uint64_t out_id, size_t out_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t d,
    size_t vocab, size_t positions, size_t pos0, int32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !d || !vocab || pos0 + rows > positions || shift >= 63 || shift <= -63)
        return fail_message(c, "invalid resident embedding geometry");
    void *tokens = nullptr, *wte = nullptr, *wpe = nullptr, *acc = nullptr,
         *out = nullptr, *error = nullptr;
    if (resident_region(c, tokens_id, tokens_offset * sizeof(uint32_t), rows * sizeof(uint32_t), &tokens) ||
        resident_region(c, wte_id, wte_offset * sizeof(int16_t), vocab * d * sizeof(int16_t), &wte) ||
        resident_region(c, wpe_id, wpe_offset * sizeof(int16_t), positions * d * sizeof(int16_t), &wpe) ||
        resident_region(c, acc_id, acc_offset * sizeof(int64_t), rows * d * sizeof(int64_t), &acc) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &out) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = rows * d;
    fixed_embed_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint32_t*>(tokens), static_cast<const int16_t*>(wte),
        static_cast<const int16_t*>(wpe), static_cast<int64_t*>(acc),
        static_cast<int16_t*>(out), static_cast<uint32_t*>(error), rows, d,
        vocab, positions, pos0, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_layer_norm_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t gain_id, size_t gain_offset, uint64_t bias_id, size_t bias_offset,
    uint64_t lut_id, size_t lut_offset, uint64_t mean_id, size_t mean_offset,
    uint64_t var_id, size_t var_offset, uint64_t rin_id, size_t rin_offset,
    uint64_t rout_id, size_t rout_offset, uint64_t acc_id, size_t acc_offset,
    uint64_t out_id, size_t out_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t d,
    uint32_t var_shift, uint32_t norm_shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !d || !norm_shift || norm_shift >= 63 || var_shift >= 63)
        return fail_message(c, "invalid resident layer-norm geometry");
    void *input = nullptr, *gain = nullptr, *bias = nullptr, *lut = nullptr,
         *mean = nullptr, *var = nullptr, *rin = nullptr, *rout = nullptr,
         *out = nullptr, *acc = nullptr, *error = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &input) ||
        resident_region(c, gain_id, gain_offset * sizeof(int16_t), d * sizeof(int16_t), &gain) ||
        resident_region(c, bias_id, bias_offset * sizeof(int16_t), d * sizeof(int16_t), &bias) ||
        resident_region(c, lut_id, lut_offset * sizeof(int16_t), (size_t{1} << 16) * sizeof(int16_t), &lut) ||
        resident_region(c, mean_id, mean_offset * sizeof(int64_t), rows * sizeof(int64_t), &mean) ||
        resident_region(c, var_id, var_offset * sizeof(int64_t), rows * sizeof(int64_t), &var) ||
        resident_region(c, rin_id, rin_offset * sizeof(int64_t), rows * sizeof(int64_t), &rin) ||
        resident_region(c, rout_id, rout_offset * sizeof(int16_t), rows * sizeof(int16_t), &rout) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &out) ||
        resident_region(c, acc_id, acc_offset * sizeof(int64_t), rows * d * sizeof(int64_t), &acc) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fixed_layer_norm_kernel<<<(rows + 31) / 32, 32, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<const int16_t*>(gain),
        static_cast<const int16_t*>(bias), static_cast<const int16_t*>(lut),
        static_cast<int64_t*>(mean), static_cast<int64_t*>(var),
        static_cast<int64_t*>(rin), static_cast<int16_t*>(rout),
        static_cast<int64_t*>(acc), static_cast<int16_t*>(out),
        static_cast<uint32_t*>(error), rows, d,
        var_shift, norm_shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_gemm_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t weights_id, size_t weights_offset,
    uint64_t bias_id, size_t bias_offset,
    uint64_t residual_id, size_t residual_offset,
    uint64_t acc_id, size_t acc_offset, uint64_t requant_id, size_t requant_offset,
    uint64_t residual_out_id, size_t residual_out_offset,
    uint64_t error_id, size_t error_offset, size_t m, size_t k, size_t n,
    uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !m || !k || !n || !shift || shift >= 63 ||
        ((residual_id == 0) != (residual_out_id == 0)))
        return fail_message(c, "invalid resident fixed GEMM geometry");
    void *input = nullptr, *weights = nullptr, *bias = nullptr, *residual = nullptr,
         *acc = nullptr, *requant = nullptr, *residual_out = nullptr, *error = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), m * k * sizeof(int16_t), &input) ||
        resident_region(c, weights_id, weights_offset * sizeof(int16_t), k * n * sizeof(int16_t), &weights) ||
        (bias_id && resident_region(c, bias_id, bias_offset * sizeof(int16_t), n * sizeof(int16_t), &bias)) ||
        (residual_id && resident_region(c, residual_id, residual_offset * sizeof(int16_t), m * n * sizeof(int16_t), &residual)) ||
        resident_region(c, acc_id, acc_offset * sizeof(int64_t), m * n * sizeof(int64_t), &acc) ||
        resident_region(c, requant_id, requant_offset * sizeof(int16_t), m * n * sizeof(int16_t), &requant) ||
        (residual_out_id && resident_region(c, residual_out_id, residual_out_offset * sizeof(int16_t), m * n * sizeof(int16_t), &residual_out)) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    dim3 block(16, 16), grid((n + 15) / 16, (m + 15) / 16);
    fixed_gemm_kernel<<<grid, block, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<const int16_t*>(weights),
        static_cast<const int16_t*>(bias), static_cast<const int16_t*>(residual),
        static_cast<int64_t*>(acc), static_cast<int16_t*>(requant),
        static_cast<int16_t*>(residual_out), static_cast<uint32_t*>(error),
        m, k, n, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_qkv_split_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t q_id, size_t q_offset, uint64_t k_id, size_t k_offset,
    uint64_t v_id, size_t v_offset, size_t rows, size_t d) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !d) return fail_message(c, "invalid resident QKV split geometry");
    void *input = nullptr, *q = nullptr, *k = nullptr, *v = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), rows * 3 * d * sizeof(int16_t), &input) ||
        resident_region(c, q_id, q_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &q) ||
        resident_region(c, k_id, k_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &k) ||
        resident_region(c, v_id, v_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &v)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = rows * d;
    fixed_qkv_split_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<int16_t*>(q),
        static_cast<int16_t*>(k), static_cast<int16_t*>(v), rows, d);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_attention_scores_device(
    void* raw, uint64_t q_id, size_t q_offset, uint64_t k_id, size_t k_offset,
    uint64_t acc_id, size_t acc_offset, uint64_t out_id, size_t out_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t seq,
    size_t pos0, size_t heads, size_t head_dim, uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !seq || !heads || !head_dim || pos0 + rows > seq ||
        !shift || shift >= 63)
        return fail_message(c, "invalid resident attention-score geometry");
    const size_t d = heads * head_dim;
    const size_t packed = heads * (rows * pos0 + rows * (rows + 1) / 2);
    void *q = nullptr, *k = nullptr, *acc = nullptr, *out = nullptr, *error = nullptr;
    if (resident_region(c, q_id, q_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &q) ||
        resident_region(c, k_id, k_offset * sizeof(int16_t), seq * d * sizeof(int16_t), &k) ||
        resident_region(c, acc_id, acc_offset * sizeof(int64_t), packed * sizeof(int64_t), &acc) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), packed * sizeof(int16_t), &out) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = heads * rows * seq;
    fixed_attention_scores_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(q), static_cast<const int16_t*>(k),
        static_cast<int64_t*>(acc), static_cast<int16_t*>(out),
        static_cast<uint32_t*>(error), rows, seq, pos0, heads, head_dim, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_softmax_device(
    void* raw, uint64_t scores_id, size_t scores_offset,
    uint64_t exp_lut_id, size_t exp_lut_offset,
    uint64_t recip_lut_id, size_t recip_lut_offset,
    uint64_t row_shift_id, size_t row_shift_offset,
    uint64_t exp_id, size_t exp_offset, uint64_t denoms_id, size_t denoms_offset,
    uint64_t recips_id, size_t recips_offset, uint64_t weights_id, size_t weights_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t seq,
    size_t pos0, size_t heads, uint32_t recip_den_shift,
    uint32_t norm_shift, int use_row_shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !seq || !heads || pos0 + rows > seq || !norm_shift ||
        norm_shift >= 63 || recip_den_shift >= 63)
        return fail_message(c, "invalid resident softmax geometry");
    const size_t packed = heads * (rows * pos0 + rows * (rows + 1) / 2);
    const size_t row_count = heads * rows;
    void *scores = nullptr, *exp_lut = nullptr, *recip_lut = nullptr,
         *row_shift = nullptr, *exp = nullptr, *denoms = nullptr,
         *recips = nullptr, *weights = nullptr, *error = nullptr;
    if (resident_region(c, scores_id, scores_offset * sizeof(int16_t), packed * sizeof(int16_t), &scores) ||
        resident_region(c, exp_lut_id, exp_lut_offset * sizeof(int16_t), (size_t{1} << 16) * sizeof(int16_t), &exp_lut) ||
        resident_region(c, recip_lut_id, recip_lut_offset * sizeof(int16_t), (size_t{1} << 16) * sizeof(int16_t), &recip_lut) ||
        resident_region(c, row_shift_id, row_shift_offset * sizeof(int16_t), row_count * sizeof(int16_t), &row_shift) ||
        resident_region(c, exp_id, exp_offset * sizeof(int16_t), packed * sizeof(int16_t), &exp) ||
        resident_region(c, denoms_id, denoms_offset * sizeof(int64_t), row_count * sizeof(int64_t), &denoms) ||
        resident_region(c, recips_id, recips_offset * sizeof(int16_t), row_count * sizeof(int16_t), &recips) ||
        resident_region(c, weights_id, weights_offset * sizeof(int16_t), packed * sizeof(int16_t), &weights) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fixed_softmax_kernel<<<(row_count + 63) / 64, 64, 0, c->stream>>>(
        static_cast<const int16_t*>(scores), static_cast<const int16_t*>(exp_lut),
        static_cast<const int16_t*>(recip_lut), static_cast<int16_t*>(row_shift),
        static_cast<int16_t*>(exp), static_cast<int64_t*>(denoms),
        static_cast<int16_t*>(recips), static_cast<int16_t*>(weights),
        static_cast<uint32_t*>(error), rows, pos0, heads, recip_den_shift,
        norm_shift, use_row_shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_av_device(
    void* raw, uint64_t weights_id, size_t weights_offset,
    uint64_t values_id, size_t values_offset,
    uint64_t acc_id, size_t acc_offset, uint64_t out_id, size_t out_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t seq,
    size_t pos0, size_t d, size_t heads, uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !seq || !d || !heads || d % heads || pos0 + rows > seq ||
        !shift || shift >= 63)
        return fail_message(c, "invalid resident AV geometry");
    const size_t packed = heads * (rows * pos0 + rows * (rows + 1) / 2);
    void *weights = nullptr, *values = nullptr, *acc = nullptr, *out = nullptr, *error = nullptr;
    if (resident_region(c, weights_id, weights_offset * sizeof(int16_t), packed * sizeof(int16_t), &weights) ||
        resident_region(c, values_id, values_offset * sizeof(int16_t), seq * d * sizeof(int16_t), &values) ||
        resident_region(c, acc_id, acc_offset * sizeof(int64_t), rows * d * sizeof(int64_t), &acc) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &out) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = rows * d;
    fixed_av_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(weights), static_cast<const int16_t*>(values),
        static_cast<int64_t*>(acc), static_cast<int16_t*>(out),
        static_cast<uint32_t*>(error), rows, seq, pos0, d, heads, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_lookup_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t lut_id, size_t lut_offset, uint64_t out_id, size_t out_offset,
    size_t n) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n) return fail_message(c, "invalid resident lookup geometry");
    void *input = nullptr, *lut = nullptr, *out = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), n * sizeof(int16_t), &input) ||
        resident_region(c, lut_id, lut_offset * sizeof(int16_t), (size_t{1} << 16) * sizeof(int16_t), &lut) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), n * sizeof(int16_t), &out)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fixed_lookup_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<const int16_t*>(lut),
        static_cast<int16_t*>(out), n);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_requant_i16_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t out_id, size_t out_offset, uint64_t error_id, size_t error_offset,
    size_t n, uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n || shift >= 63)
        return fail_message(c, "invalid resident i16 requant geometry");
    void *input = nullptr, *out = nullptr, *error = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), n * sizeof(int16_t), &input) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), n * sizeof(int16_t), &out) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fixed_requant_i16_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<int16_t*>(out),
        static_cast<uint32_t*>(error), n, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fixed_logits_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t weights_id, size_t weights_offset,
    uint64_t out_id, size_t out_offset, size_t rows, size_t d, size_t vocab) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || !d || !vocab)
        return fail_message(c, "invalid resident logits geometry");
    void *input = nullptr, *weights = nullptr, *out = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(int16_t), rows * d * sizeof(int16_t), &input) ||
        resident_region(c, weights_id, weights_offset * sizeof(int16_t), vocab * d * sizeof(int16_t), &weights) ||
        resident_region(c, out_id, out_offset * sizeof(int64_t), rows * vocab * sizeof(int64_t), &out)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = rows * vocab;
    fixed_logits_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(input), static_cast<const int16_t*>(weights),
        static_cast<int64_t*>(out), rows, d, vocab);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

size_t resident_scalar_size(int kind) {
    if (kind == SCALAR_I16) return sizeof(int16_t);
    if (kind == SCALAR_U32) return sizeof(uint32_t);
    if (kind == SCALAR_I64 || kind == SCALAR_FP) return sizeof(uint64_t);
    if (kind == SCALAR_FP2) return sizeof(Fp2);
    return 0;
}

extern "C" int volta_cuda_subfield_corrections_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t masks_id, size_t masks_offset,
    uint64_t output_id, size_t output_offset, size_t n, int kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    if (!c || !n || !elem || kind == SCALAR_FP2)
        return fail_message(c, "invalid resident subfield-correction geometry");
    void *input = nullptr, *masks = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, n * elem, &input) ||
        resident_region(c, masks_id, masks_offset * sizeof(uint64_t), n * sizeof(uint64_t), &masks) ||
        resident_region(c, output_id, output_offset * sizeof(uint64_t), n * sizeof(uint64_t), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    subfield_corrections_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        input, static_cast<const uint64_t*>(masks), static_cast<uint64_t*>(output), n, kind);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_pad_base_vector_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t real, size_t padded,
    uint64_t pad, int kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    if (!c || !real || padded < real || (padded & (padded - 1)) || !elem ||
        kind == SCALAR_FP2 || pad >= P)
        return fail_message(c, "invalid resident base-vector padding geometry");
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, real * elem, &input) ||
        resident_region(c, output_id, output_offset * sizeof(uint64_t),
                        padded * sizeof(uint64_t), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    pad_base_vector_kernel<<<(padded + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        input, static_cast<uint64_t*>(output), real, padded, pad, kind);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_matrix_fold_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t weights_id, size_t weights_offset,
    uint64_t output_id, size_t output_offset, size_t rows, size_t stride,
    size_t column_offset, size_t cols, size_t out_pad, int kind, int axis) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    const size_t terms = axis == 0 ? rows : cols;
    const size_t real_outputs = axis == 0 ? cols : rows;
    if (!c || !rows || !stride || !cols || column_offset > stride ||
        cols > stride - column_offset || !elem || (axis != 0 && axis != 1) ||
        out_pad < real_outputs || (out_pad & (out_pad - 1)))
        return fail_message(c, "invalid resident matrix-window fold geometry");
    void *input = nullptr, *weights = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, rows * stride * elem, &input) ||
        resident_region(c, weights_id, weights_offset * sizeof(Fp2), terms * sizeof(Fp2), &weights) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2), out_pad * sizeof(Fp2), &output)) return -1;

    const bool term_parallel =
        terms >= BLOCK && real_outputs <= MATRIX_FOLD_MAX_PARALLEL_OUTPUTS;
    size_t parts = 1;
    Fp2* partials = nullptr;
    if (term_parallel) {
        const size_t term_blocks = terms / BLOCK + (terms % BLOCK != 0);
        const size_t target_parts =
            MATRIX_FOLD_TARGET_BLOCKS / real_outputs +
            (MATRIX_FOLD_TARGET_BLOCKS % real_outputs != 0);
        parts = std::min(term_blocks, target_parts);
        if (parts > 1) {
            size_t partial_count = 0;
            if (!checked_mul_size(real_outputs, parts, &partial_count) ||
                partial_count > MATRIX_FOLD_MAX_PARTIALS)
                return fail_message(c, "parallel matrix-fold partial bound exceeded");
            if (ensure(c, 15, MATRIX_FOLD_MAX_PARTIALS * sizeof(Fp2))) return -1;
            partials = buf<Fp2>(c, 15);
        }
    }
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    if (!term_parallel) {
        matrix_fold_kernel<<<(out_pad + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
            input, static_cast<const Fp2*>(weights), static_cast<Fp2*>(output),
            rows, stride, column_offset, cols, out_pad, kind, axis);
    } else {
        const size_t first_blocks = parts == 1 ? out_pad : real_outputs * parts;
        matrix_fold_parts_kernel<<<first_blocks, BLOCK, 0, c->stream>>>(
            input, static_cast<const Fp2*>(weights),
            parts == 1 ? static_cast<Fp2*>(output) : partials,
            rows, stride, column_offset, cols, real_outputs, out_pad,
            parts, kind, axis);
        if (parts > 1) {
            matrix_fold_finish_kernel<<<out_pad, BLOCK, 0, c->stream>>>(
                partials, static_cast<Fp2*>(output), real_outputs, out_pad, parts);
        }
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_fp2_dot_device(
    void* raw, uint64_t a_id, size_t a_offset,
    uint64_t b_id, size_t b_offset, size_t n, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n || !output) return fail_message(c, "invalid resident Fp2 dot geometry");
    void *a = nullptr, *b = nullptr;
    if (resident_region(c, a_id, a_offset * sizeof(Fp2), n * sizeof(Fp2), &a) ||
        resident_region(c, b_id, b_offset * sizeof(Fp2), n * sizeof(Fp2), &b) ||
        ensure(c, 12, n * sizeof(DotAcc)) ||
        ensure(c, 13, std::max(size_t{1}, (n + 1) / 2) * sizeof(DotAcc))) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    DotAcc* src = buf<DotAcc>(c, 12);
    DotAcc* dst = buf<DotAcc>(c, 13);
    fp2_dot_terms<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(a), static_cast<const Fp2*>(b), src, n);
    size_t len = n;
    while (len > 1) {
        const size_t next = (len + 1) / 2;
        reduce_dot<<<(next + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(src, dst, len);
        std::swap(src, dst);
        len = next;
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(output, &src[0].value, sizeof(Fp2),
                                     cudaMemcpyDeviceToHost, c->stream));
    return finish_timing(c, OP_GEMM, 0, sizeof(Fp2));
}

/// Allocate-only preflight for the two product-reduction scratch slots. It
/// launches no kernel and creates no timing record; subsequent rounds up to
/// `max_pairs` cannot grow workspace inside a coarse timing scope.
extern "C" int volta_cuda_reserve_fp2_product_round_workspace(
    void* raw, size_t max_pairs) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !max_pairs)
        return reject_message(c, "invalid product-round workspace reservation");
    if (c->coarse_timing_active || c->active_timing_record != TIMING_RING_SIZE)
        return reject_message(c, "cannot reserve product-round workspace during active timing");
    size_t workspace_bytes = 0;
    size_t reduced_bytes = 0;
    const size_t reduced_pairs = max_pairs / 2 + max_pairs % 2;
    if (!checked_mul_size(max_pairs, sizeof(ProductRoundAcc), &workspace_bytes) ||
        !checked_mul_size(reduced_pairs, sizeof(ProductRoundAcc), &reduced_bytes))
        return reject_message(c, "product-round workspace reservation overflows size_t");
    if (ensure(c, 12, workspace_bytes) || ensure(c, 13, reduced_bytes)) return -1;
    return 0;
}

/// Allocate-only preflight for every private reduction slot used by resident
/// LogUp general/aux rounds. It deliberately stays separate from the product
/// reservation so blind-sumcheck cohorts do not pay for wider LogUp scratch.
extern "C" int volta_cuda_reserve_logup_round_workspace(
    void* raw, size_t max_pairs) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !max_pairs)
        return reject_message(c, "invalid LogUp round workspace reservation");
    if (c->coarse_timing_active || c->active_timing_record != TIMING_RING_SIZE)
        return reject_message(c, "cannot reserve LogUp round workspace during active timing");
    size_t general_bytes = 0;
    size_t aux_bytes = 0;
    if (!checked_mul_size(max_pairs, sizeof(RoundAcc), &general_bytes) ||
        !checked_mul_size(max_pairs, sizeof(AuxRoundAcc), &aux_bytes))
        return reject_message(c, "LogUp round workspace reservation overflows size_t");
    if (ensure(c, 5, general_bytes) || ensure(c, 6, general_bytes) ||
        ensure(c, 12, aux_bytes) || ensure(c, 13, aux_bytes) ||
        ensure(c, 14, 3 * sizeof(Fp2))) return -1;
    return 0;
}

int fp2_product_round_resident_impl(
    Context* c, const Fp2* a, const Fp2* b, size_t pairs,
    Fp2* output, bool output_is_device) {
    size_t workspace_bytes = 0;
    size_t reduced_bytes = 0;
    if (!checked_mul_size(pairs, sizeof(ProductRoundAcc), &workspace_bytes) ||
        !checked_mul_size(std::max(size_t{1}, (pairs + 1) / 2),
                          sizeof(ProductRoundAcc), &reduced_bytes))
        return fail_message(c, "resident product-round workspace overflows size_t");
    if (ensure(c, 12, workspace_bytes) || ensure(c, 13, reduced_bytes)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    ProductRoundAcc* src = buf<ProductRoundAcc>(c, 12);
    ProductRoundAcc* dst = buf<ProductRoundAcc>(c, 13);
    fp2_product_round_terms<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        a, b, src, pairs);
    size_t len = pairs;
    while (len > 1) {
        const size_t next = (len + 1) / 2;
        reduce_product_round<<<(next + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(src, dst, len);
        std::swap(src, dst);
        len = next;
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (output_is_device) {
        CUDA_OR_RETURN(c, cudaMemcpyAsync(output, &src[0], sizeof(ProductRoundAcc),
                                         cudaMemcpyDeviceToDevice, c->stream));
        if (mark_timing(c, 2)) return -1;
        return finish_timing(c, OP_GEMM, 0, 0);
    }
    if (mark_timing(c, 2)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(output, &src[0], sizeof(ProductRoundAcc),
                                     cudaMemcpyDeviceToHost, c->stream));
    return finish_timing(c, OP_GEMM, 0, sizeof(ProductRoundAcc));
}

extern "C" int volta_cuda_fp2_product_round_device(
    void* raw, uint64_t a_id, size_t a_offset,
    uint64_t b_id, size_t b_offset, size_t pairs, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs || !output)
        return fail_message(c, "invalid resident product-round geometry");
    size_t a_offset_bytes = 0, b_offset_bytes = 0, input_bytes = 0;
    if (!checked_mul_size(a_offset, sizeof(Fp2), &a_offset_bytes) ||
        !checked_mul_size(b_offset, sizeof(Fp2), &b_offset_bytes) ||
        !checked_mul_size(pairs, 2 * sizeof(Fp2), &input_bytes))
        return fail_message(c, "resident product-round geometry overflows size_t");
    void *a = nullptr, *b = nullptr;
    if (resident_region(c, a_id, a_offset_bytes, input_bytes, &a) ||
        resident_region(c, b_id, b_offset_bytes, input_bytes, &b)) return -1;
    return fp2_product_round_resident_impl(
        c, static_cast<const Fp2*>(a), static_cast<const Fp2*>(b),
        pairs, output, false);
}

extern "C" int volta_cuda_fp2_product_round_into_device(
    void* raw, uint64_t a_id, size_t a_offset,
    uint64_t b_id, size_t b_offset, size_t pairs,
    uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs)
        return fail_message(c, "invalid resident product-round mailbox geometry");
    size_t a_offset_bytes = 0, b_offset_bytes = 0, input_bytes = 0;
    size_t output_offset_bytes = 0;
    if (!checked_mul_size(a_offset, sizeof(Fp2), &a_offset_bytes) ||
        !checked_mul_size(b_offset, sizeof(Fp2), &b_offset_bytes) ||
        !checked_mul_size(pairs, 2 * sizeof(Fp2), &input_bytes) ||
        !checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes))
        return fail_message(c, "resident product-round mailbox geometry overflows size_t");
    void *a = nullptr, *b = nullptr, *output = nullptr;
    if (resident_region(c, a_id, a_offset_bytes, input_bytes, &a) ||
        resident_region(c, b_id, b_offset_bytes, input_bytes, &b) ||
        resident_region(c, output_id, output_offset_bytes,
                        sizeof(ProductRoundAcc), &output)) return -1;
    return fp2_product_round_resident_impl(
        c, static_cast<const Fp2*>(a), static_cast<const Fp2*>(b), pairs,
        static_cast<Fp2*>(output), true);
}

int fp2_triple_product_round_resident_impl(
    Context* context, const Fp2* a, const Fp2* b, const Fp2* c,
    size_t pairs, Fp2* output, bool output_is_device) {
    size_t workspace_bytes = 0;
    size_t reduced_bytes = 0;
    if (!checked_mul_size(pairs, sizeof(TripleRoundAcc), &workspace_bytes) ||
        !checked_mul_size(std::max(size_t{1}, (pairs + 1) / 2),
                          sizeof(TripleRoundAcc), &reduced_bytes))
        return fail_message(context, "resident triple-product workspace overflows size_t");
    if (ensure(context, 12, workspace_bytes) || ensure(context, 13, reduced_bytes)) return -1;
    if (begin_timing(context)) return -1;
    if (mark_timing(context, 1)) return -1;
    TripleRoundAcc* src = buf<TripleRoundAcc>(context, 12);
    TripleRoundAcc* dst = buf<TripleRoundAcc>(context, 13);
    fp2_triple_product_round_terms<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, context->stream>>>(
        a, b, c, src, pairs);
    size_t len = pairs;
    while (len > 1) {
        const size_t next = (len + 1) / 2;
        reduce_triple_product_round<<<(next + BLOCK - 1) / BLOCK, BLOCK, 0, context->stream>>>(
            src, dst, len);
        std::swap(src, dst);
        len = next;
    }
    CUDA_OR_RETURN(context, cudaPeekAtLastError());
    if (output_is_device) {
        CUDA_OR_RETURN(context, cudaMemcpyAsync(output, &src[0], sizeof(TripleRoundAcc),
                                                cudaMemcpyDeviceToDevice, context->stream));
        if (mark_timing(context, 2)) return -1;
        return finish_timing(context, OP_GEMM, 0, 0);
    }
    if (mark_timing(context, 2)) return -1;
    CUDA_OR_RETURN(context, cudaMemcpyAsync(output, &src[0], sizeof(TripleRoundAcc),
                                            cudaMemcpyDeviceToHost, context->stream));
    return finish_timing(context, OP_GEMM, 0, sizeof(TripleRoundAcc));
}

extern "C" int volta_cuda_fp2_triple_product_round_device(
    void* raw, uint64_t a_id, size_t a_offset,
    uint64_t b_id, size_t b_offset, uint64_t c_id, size_t c_offset,
    size_t pairs, Fp2* output) {
    Context* context = static_cast<Context*>(raw);
    if (!context || !pairs || !output)
        return fail_message(context, "invalid resident triple-product round geometry");
    size_t a_offset_bytes = 0, b_offset_bytes = 0, c_offset_bytes = 0;
    size_t input_bytes = 0;
    if (!checked_mul_size(a_offset, sizeof(Fp2), &a_offset_bytes) ||
        !checked_mul_size(b_offset, sizeof(Fp2), &b_offset_bytes) ||
        !checked_mul_size(c_offset, sizeof(Fp2), &c_offset_bytes) ||
        !checked_mul_size(pairs, 2 * sizeof(Fp2), &input_bytes))
        return fail_message(context, "resident triple-product geometry overflows size_t");
    void *a = nullptr, *b = nullptr, *c = nullptr;
    if (resident_region(context, a_id, a_offset_bytes, input_bytes, &a) ||
        resident_region(context, b_id, b_offset_bytes, input_bytes, &b) ||
        resident_region(context, c_id, c_offset_bytes, input_bytes, &c)) return -1;
    return fp2_triple_product_round_resident_impl(
        context, static_cast<const Fp2*>(a), static_cast<const Fp2*>(b),
        static_cast<const Fp2*>(c), pairs, output, false);
}

extern "C" int volta_cuda_fp2_triple_product_round_into_device(
    void* raw, uint64_t a_id, size_t a_offset,
    uint64_t b_id, size_t b_offset, uint64_t c_id, size_t c_offset,
    size_t pairs, uint64_t output_id, size_t output_offset) {
    Context* context = static_cast<Context*>(raw);
    if (!context || !pairs)
        return fail_message(context, "invalid resident triple-product mailbox geometry");
    size_t a_offset_bytes = 0, b_offset_bytes = 0, c_offset_bytes = 0;
    size_t input_bytes = 0, output_offset_bytes = 0;
    if (!checked_mul_size(a_offset, sizeof(Fp2), &a_offset_bytes) ||
        !checked_mul_size(b_offset, sizeof(Fp2), &b_offset_bytes) ||
        !checked_mul_size(c_offset, sizeof(Fp2), &c_offset_bytes) ||
        !checked_mul_size(pairs, 2 * sizeof(Fp2), &input_bytes) ||
        !checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes))
        return fail_message(context, "resident triple-product mailbox geometry overflows size_t");
    void *a = nullptr, *b = nullptr, *c = nullptr, *output = nullptr;
    if (resident_region(context, a_id, a_offset_bytes, input_bytes, &a) ||
        resident_region(context, b_id, b_offset_bytes, input_bytes, &b) ||
        resident_region(context, c_id, c_offset_bytes, input_bytes, &c) ||
        resident_region(context, output_id, output_offset_bytes,
                        sizeof(TripleRoundAcc), &output)) return -1;
    return fp2_triple_product_round_resident_impl(
        context, static_cast<const Fp2*>(a), static_cast<const Fp2*>(b),
        static_cast<const Fp2*>(c), pairs, static_cast<Fp2*>(output), true);
}

extern "C" int volta_cuda_ln_hadamard_factors_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t mean_id, size_t mean_offset, uint64_t rsqrt_id, size_t rsqrt_offset,
    uint64_t gain_id, size_t gain_offset, uint64_t centered_id, size_t centered_offset,
    uint64_t scaled_id, size_t scaled_offset, size_t rows, size_t cols,
    size_t row_pad, size_t col_pad) {
    Context* context = static_cast<Context*>(raw);
    if (!context || !rows || !cols || row_pad < rows || col_pad < cols ||
        (row_pad & (row_pad - 1)) || (col_pad & (col_pad - 1)))
        return fail_message(context, "invalid resident LN Hadamard factor geometry");
    void *input = nullptr, *mean = nullptr, *rsqrt = nullptr, *gain = nullptr,
         *centered = nullptr, *scaled = nullptr;
    const size_t total = row_pad * col_pad;
    if (resident_region(context, input_id, input_offset * sizeof(int16_t), rows * cols * sizeof(int16_t), &input) ||
        resident_region(context, mean_id, mean_offset * sizeof(uint64_t), row_pad * sizeof(uint64_t), &mean) ||
        resident_region(context, rsqrt_id, rsqrt_offset * sizeof(uint64_t), row_pad * sizeof(uint64_t), &rsqrt) ||
        resident_region(context, gain_id, gain_offset * sizeof(int16_t), cols * sizeof(int16_t), &gain) ||
        resident_region(context, centered_id, centered_offset * sizeof(Fp2), total * sizeof(Fp2), &centered) ||
        resident_region(context, scaled_id, scaled_offset * sizeof(Fp2), total * sizeof(Fp2), &scaled)) return -1;
    if (begin_timing(context)) return -1;
    if (mark_timing(context, 1)) return -1;
    ln_hadamard_factors_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, context->stream>>>(
        static_cast<const int16_t*>(input), static_cast<const uint64_t*>(mean),
        static_cast<const uint64_t*>(rsqrt), static_cast<const int16_t*>(gain),
        static_cast<Fp2*>(centered), static_cast<Fp2*>(scaled), rows, cols,
        row_pad, col_pad);
    CUDA_OR_RETURN(context, cudaPeekAtLastError());
    if (mark_timing(context, 2)) return -1;
    return finish_timing(context, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_base_broadcast_fp2_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t input_len,
    size_t repeat, int kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    if (!c || !input_len || !repeat || !elem || kind == SCALAR_FP2)
        return fail_message(c, "invalid resident base broadcast geometry");
    const size_t output_len = input_len * repeat;
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, input_len * elem, &input) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2),
                        output_len * sizeof(Fp2), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    base_broadcast_fp2_kernel<<<(output_len + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        input, static_cast<Fp2*>(output), input_len, repeat, output_len, kind);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_repeat_vector_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t input_len,
    size_t repeat, int kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    if (!c || !input_len || !repeat || !elem)
        return fail_message(c, "invalid resident vector repeat geometry");
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, input_len * elem, &input) ||
        resident_region(c, output_id, output_offset * elem,
                        input_len * repeat * elem, &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    for (size_t copy = 0; copy < repeat; ++copy) {
        CUDA_OR_RETURN(c, cudaMemcpyAsync(
            static_cast<uint8_t*>(output) + copy * input_len * elem,
            input, input_len * elem, cudaMemcpyDeviceToDevice, c->stream));
    }
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_compact_strided_rows_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t rows,
    size_t source_stride, size_t width, int kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t elem = resident_scalar_size(kind);
    if (!c || !rows || !width || source_stride < width || !elem)
        return fail_message(c, "invalid resident strided-copy geometry");
    const size_t source_len = (rows - 1) * source_stride + width;
    const size_t output_len = rows * width;
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * elem, source_len * elem, &input) ||
        resident_region(c, output_id, output_offset * elem, output_len * elem, &output))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpy2DAsync(
        output, width * elem, input, source_stride * elem,
        width * elem, rows, cudaMemcpyDeviceToDevice, c->stream));
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_attention_above_mask_device(
    void* raw, uint64_t equality_id, size_t equality_offset, size_t entries,
    size_t rows, size_t seq, size_t pos0, size_t heads, size_t head_pad,
    size_t query_pad, size_t seq_pad) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !entries || !rows || !seq || !heads || head_pad < heads ||
        (head_pad & (head_pad - 1)) || query_pad < rows ||
        (query_pad & (query_pad - 1)) || seq_pad < seq ||
        (seq_pad & (seq_pad - 1)) || pos0 + rows != seq ||
        entries != head_pad * query_pad * seq_pad)
        return fail_message(c, "invalid resident above-causal mask geometry");
    void* equality = nullptr;
    if (resident_region(c, equality_id, equality_offset * sizeof(Fp2),
                        entries * sizeof(Fp2), &equality)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    attention_above_mask_kernel<<<(entries + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<Fp2*>(equality), entries, rows, seq, pos0, heads,
        query_pad, seq_pad);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_GEMM, 0, 0);
}

extern "C" int volta_cuda_attention_proof_wires_device(
    void* raw, const AttentionProofWiresArgs* a) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !a || a->query_rows < 2 || !a->seq || !a->heads ||
        !a->head_dim || a->head_pad < a->heads ||
        (a->head_pad & (a->head_pad - 1)) || a->pos0 + a->query_rows != a->seq ||
        a->query_pad < a->query_rows || (a->query_pad & (a->query_pad - 1)) ||
        a->seq_pad < a->seq || (a->seq_pad & (a->seq_pad - 1)) ||
        a->d_pad < a->heads * a->head_dim || (a->d_pad & (a->d_pad - 1)) ||
        !a->shift_scores || a->shift_scores > 16 ||
        !a->shift_softmax_norm || a->shift_softmax_norm > 16 ||
        !a->shift_qkv || a->shift_qkv > 16 || a->recip_den_shift >= 63 ||
        a->exp_pad_input < INT16_MIN || a->exp_pad_input > INT16_MAX ||
        a->recip_pad_output < INT16_MIN || a->recip_pad_output > INT16_MAX ||
        (a->use_row_shift != 0 && a->use_row_shift != 1))
        return fail_message(c, "invalid resident attention-proof geometry");
    const size_t d = a->heads * a->head_dim;
    const size_t packed_per_head =
        a->query_rows * a->pos0 + a->query_rows * (a->query_rows + 1) / 2;
    const size_t packed = a->heads * packed_per_head;
    const size_t real_rows = a->heads * a->query_rows;
    const size_t rect_entries = a->head_pad * a->query_pad * a->seq_pad;
    const size_t row_entries = a->head_pad * a->query_pad;
    const size_t above_entries =
        a->heads * a->query_rows * (a->query_rows - 1) / 2;
    const size_t qkv_entries = a->query_pad * 4 * a->d_pad;
    void *q = nullptr, *k_cache = nullptr, *own_k = nullptr, *v = nullptr,
         *scores_acc = nullptr, *scores_q = nullptr, *row_shifts = nullptr,
         *exp_outputs = nullptr, *denoms = nullptr, *recips = nullptr,
         *softmax_weights = nullptr, *recip_lut = nullptr, *qkv_acc = nullptr,
         *error = nullptr, *rect = nullptr, *row_values = nullptr,
         *above = nullptr, *qkv = nullptr;
    if (resident_region(c, a->q_id, a->q_offset * sizeof(int16_t),
                        a->query_rows * d * sizeof(int16_t), &q) ||
        resident_region(c, a->k_cache_id, a->k_cache_offset * sizeof(int16_t),
                        a->seq * d * sizeof(int16_t), &k_cache) ||
        resident_region(c, a->own_k_id, a->own_k_offset * sizeof(int16_t),
                        a->query_rows * d * sizeof(int16_t), &own_k) ||
        resident_region(c, a->v_id, a->v_offset * sizeof(int16_t),
                        a->query_rows * d * sizeof(int16_t), &v) ||
        resident_region(c, a->scores_acc_id, a->scores_acc_offset * sizeof(int64_t),
                        packed * sizeof(int64_t), &scores_acc) ||
        resident_region(c, a->scores_q_id, a->scores_q_offset * sizeof(int16_t),
                        packed * sizeof(int16_t), &scores_q) ||
        resident_region(c, a->row_shifts_id, a->row_shifts_offset * sizeof(int16_t),
                        real_rows * sizeof(int16_t), &row_shifts) ||
        resident_region(c, a->exp_outputs_id, a->exp_outputs_offset * sizeof(int16_t),
                        packed * sizeof(int16_t), &exp_outputs) ||
        resident_region(c, a->denoms_id, a->denoms_offset * sizeof(int64_t),
                        real_rows * sizeof(int64_t), &denoms) ||
        resident_region(c, a->recips_id, a->recips_offset * sizeof(int16_t),
                        real_rows * sizeof(int16_t), &recips) ||
        resident_region(c, a->softmax_weights_id,
                        a->softmax_weights_offset * sizeof(int16_t),
                        packed * sizeof(int16_t), &softmax_weights) ||
        resident_region(c, a->recip_lut_id, a->recip_lut_offset * sizeof(int16_t),
                        (size_t{1} << 16) * sizeof(int16_t), &recip_lut) ||
        resident_region(c, a->qkv_acc_id, a->qkv_acc_offset * sizeof(int64_t),
                        a->query_rows * 3 * d * sizeof(int64_t), &qkv_acc) ||
        resident_region(c, a->error_id, a->error_offset * sizeof(uint32_t),
                        sizeof(uint32_t), &error) ||
        resident_region(c, a->rect_id, a->rect_offset * sizeof(uint64_t),
                        7 * rect_entries * sizeof(uint64_t), &rect) ||
        resident_region(c, a->rows_id, a->rows_offset * sizeof(uint64_t),
                        4 * row_entries * sizeof(uint64_t), &row_values) ||
        resident_region(c, a->above_id, a->above_offset * sizeof(uint64_t),
                        above_entries * sizeof(uint64_t), &above) ||
        resident_region(c, a->qkv_id, a->qkv_offset * sizeof(uint64_t),
                        2 * qkv_entries * sizeof(uint64_t), &qkv)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    attention_rect_columns_kernel<<<(rect_entries + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int16_t*>(q), static_cast<const int16_t*>(k_cache),
        static_cast<const int64_t*>(scores_acc), static_cast<const int16_t*>(scores_q),
        static_cast<const int16_t*>(row_shifts), static_cast<const int16_t*>(exp_outputs),
        static_cast<const int16_t*>(recips), static_cast<const int16_t*>(softmax_weights),
        static_cast<uint64_t*>(rect), static_cast<uint64_t*>(above),
        static_cast<uint32_t*>(error), a->query_rows, a->seq, a->pos0,
        a->heads, a->head_pad, a->head_dim, a->query_pad, a->seq_pad,
        a->shift_scores, a->shift_softmax_norm,
        static_cast<int16_t>(a->exp_pad_input), a->use_row_shift);
    attention_row_columns_kernel<<<(row_entries + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int64_t*>(denoms), static_cast<const int16_t*>(recips),
        static_cast<const int16_t*>(row_shifts), static_cast<const int16_t*>(recip_lut),
        static_cast<uint64_t*>(row_values), static_cast<uint32_t*>(error),
        a->query_rows, a->heads, a->head_pad, a->query_pad, a->seq, a->pos0,
        a->recip_den_shift, static_cast<int16_t>(a->recip_pad_output),
        a->use_row_shift, static_cast<const int16_t*>(scores_q));
    attention_qkv_columns_kernel<<<(qkv_entries + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const int64_t*>(qkv_acc), static_cast<const int16_t*>(q),
        static_cast<const int16_t*>(own_k), static_cast<const int16_t*>(v),
        static_cast<uint64_t*>(qkv), static_cast<uint32_t*>(error),
        a->query_rows, d, a->query_pad, a->d_pad, a->shift_qkv);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_requant_columns_device(
    void* raw, uint64_t acc_id, size_t acc_offset,
    uint64_t out_id, size_t out_offset,
    uint64_t columns_id, size_t columns_offset,
    uint64_t error_id, size_t error_offset, size_t rows, size_t cols,
    size_t row_pad, size_t col_pad, int acc_kind, uint32_t shift) {
    Context* c = static_cast<Context*>(raw);
    const size_t acc_elem = resident_scalar_size(acc_kind);
    if (!c || !rows || !cols || row_pad < rows || col_pad < cols ||
        (row_pad & (row_pad - 1)) || (col_pad & (col_pad - 1)) ||
        (acc_kind != SCALAR_I16 && acc_kind != SCALAR_I64) || !acc_elem ||
        !shift || shift >= 63)
        return fail_message(c, "invalid resident requant-column geometry");
    const size_t real = rows * cols, padded = row_pad * col_pad;
    const size_t count = shift > 16 ? 4 : 2;
    void *acc = nullptr, *out = nullptr, *columns = nullptr, *error = nullptr;
    if (resident_region(c, acc_id, acc_offset * acc_elem, real * acc_elem, &acc) ||
        resident_region(c, out_id, out_offset * sizeof(int16_t), real * sizeof(int16_t), &out) ||
        resident_region(c, columns_id, columns_offset * sizeof(uint64_t), count * padded * sizeof(uint64_t), &columns) ||
        resident_region(c, error_id, error_offset * sizeof(uint32_t), sizeof(uint32_t), &error)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    requant_columns_kernel<<<(padded + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        acc, static_cast<const int16_t*>(out),
        static_cast<uint64_t*>(columns), static_cast<uint32_t*>(error),
        rows, cols, row_pad, col_pad, acc_kind, shift);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_pair_columns_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t out_id, size_t out_offset,
    uint64_t columns_id, size_t columns_offset, size_t rows, size_t cols,
    size_t row_pad, size_t col_pad, uint64_t pad_input, uint64_t pad_output,
    int input_kind, int output_kind) {
    Context* c = static_cast<Context*>(raw);
    const size_t input_elem = resident_scalar_size(input_kind);
    const size_t output_elem = resident_scalar_size(output_kind);
    if (!c || !rows || !cols || row_pad < rows || col_pad < cols ||
        (row_pad & (row_pad - 1)) || (col_pad & (col_pad - 1)) ||
        !input_elem || !output_elem || input_kind == SCALAR_FP2 ||
        output_kind == SCALAR_FP2 || pad_input >= P || pad_output >= P)
        return fail_message(c, "invalid resident pair-column geometry");
    const size_t real = rows * cols, padded = row_pad * col_pad;
    void *input = nullptr, *out = nullptr, *columns = nullptr;
    if (resident_region(c, input_id, input_offset * input_elem, real * input_elem, &input) ||
        resident_region(c, out_id, out_offset * output_elem, real * output_elem, &out) ||
        resident_region(c, columns_id, columns_offset * sizeof(uint64_t), 2 * padded * sizeof(uint64_t), &columns)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    pair_columns_kernel<<<(padded + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        input, out, static_cast<uint64_t*>(columns), rows, cols, row_pad, col_pad,
        pad_input, pad_output, input_kind, output_kind);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_histogram_lut_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t n, int signed_input) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n || (signed_input != 0 && signed_input != 1))
        return fail_message(c, "invalid resident LUT histogram geometry");
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(uint64_t), n * sizeof(uint64_t), &input) ||
        resident_region(c, output_id, output_offset * sizeof(uint32_t),
                        (size_t{1} << 16) * sizeof(uint32_t), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    CUDA_OR_RETURN(c, cudaMemsetAsync(output, 0, (size_t{1} << 16) * sizeof(uint32_t), c->stream));
    histogram_lut_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(input), static_cast<uint32_t*>(output), n, signed_input);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_histogram_fp_device(
    void* raw, uint64_t input_id, size_t input_offset,
    uint64_t output_id, size_t output_offset, size_t n, size_t bins) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n || !bins) return fail_message(c, "invalid resident histogram geometry");
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(uint64_t), n * sizeof(uint64_t), &input) ||
        resident_region(c, output_id, output_offset * sizeof(uint32_t), bins * sizeof(uint32_t), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    CUDA_OR_RETURN(c, cudaMemsetAsync(output, 0, bins * sizeof(uint32_t), c->stream));
    histogram_fp_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(input), static_cast<uint32_t*>(output), n, bins);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_u32_add_inplace_device(
    void* raw, uint64_t target_id, size_t target_offset,
    uint64_t add_id, size_t add_offset, size_t n) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n) return fail_message(c, "invalid resident u32-add geometry");
    void *target = nullptr, *add = nullptr;
    if (resident_region(c, target_id, target_offset * sizeof(uint32_t), n * sizeof(uint32_t), &target) ||
        resident_region(c, add_id, add_offset * sizeof(uint32_t), n * sizeof(uint32_t), &add)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    u32_add_inplace_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<uint32_t*>(target), static_cast<const uint32_t*>(add), n);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_pack_lookup_leaf_device(
    void* raw, uint64_t columns_id, size_t columns_offset,
    uint64_t shifts_id, size_t shifts_offset,
    uint64_t leaf_id, size_t leaf_offset, size_t column_count, size_t n,
    uint64_t alpha0) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !column_count || n < 2 || (n & (n - 1)))
        return fail_message(c, "invalid resident lookup-leaf geometry");
    void *columns = nullptr, *shifts = nullptr, *leaf = nullptr;
    if (resident_region(c, columns_id, columns_offset * sizeof(uint64_t), column_count * n * sizeof(uint64_t), &columns) ||
        resident_region(c, shifts_id, shifts_offset * sizeof(uint32_t), column_count * sizeof(uint32_t), &shifts) ||
        resident_region(c, leaf_id, leaf_offset * sizeof(uint64_t), n * sizeof(uint64_t), &leaf)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    pack_lookup_leaf_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(columns), static_cast<const uint32_t*>(shifts),
        static_cast<uint64_t*>(leaf), column_count, n, alpha0);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_deinterleave_base_columns_device(
    void* raw, uint64_t columns_id, size_t columns_offset,
    uint64_t output_id, size_t output_offset, size_t column_count, size_t n) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !column_count || n < 2 || n % 2)
        return fail_message(c, "invalid resident base-column deinterleave geometry");
    void *columns = nullptr, *output = nullptr;
    if (resident_region(c, columns_id, columns_offset * sizeof(uint64_t), column_count * n * sizeof(uint64_t), &columns) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2), column_count * n * sizeof(Fp2), &output)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    const size_t total = column_count * n;
    deinterleave_base_columns_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(columns), static_cast<Fp2*>(output), column_count, n);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_ntt_fp(void* raw,const uint64_t* msg,size_t msg_len,size_t n,uint64_t* out) {
    Context* c=static_cast<Context*>(raw);if(!c||!msg||!out||n<2||(n&(n-1))||msg_len>n)return -1;
    if(ensure(c,0,n*8)||ensure(c,1,n*8))return -1;std::vector<uint64_t> host(n);std::copy(msg,msg+msg_len,host.begin());
    uint64_t h2d=0;if(begin_timing(c))return -1;CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,0),host.data(),n*8,cudaMemcpyHostToDevice,c->stream));h2d+=n*8;
    if(ensure_twiddles(c,n,&h2d))return -1;if(mark_timing(c,1))return -1;const int bits=__builtin_ctzll(n);
    bit_reverse_fp<<<(n+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,0),buf<uint64_t>(c,1),n,bits);
    for(size_t len=2;len<=n;len*=2)ntt_stage_fp<<<(n/2+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,1),buf<uint64_t>(c,11),n,len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<uint64_t>(c,1),n*8,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_NTT,h2d,n*8);
}

extern "C" int volta_cuda_ntt_fp_batch(void* raw,const uint64_t* messages,size_t rows,
    size_t msg_len,size_t n,uint64_t* out) {
    Context* c=static_cast<Context*>(raw);if(!c||!messages||!out||!rows||n<2||(n&(n-1))||msg_len>n)return -1;
    const size_t total=rows*n,bytes=total*8;std::vector<uint64_t> host(total);
    for(size_t row=0;row<rows;++row)std::copy(messages+row*msg_len,messages+(row+1)*msg_len,host.begin()+row*n);
    if(ensure(c,0,bytes)||ensure(c,1,bytes))return -1;uint64_t h2d=0;if(begin_timing(c))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,0),host.data(),bytes,cudaMemcpyHostToDevice,c->stream));h2d+=bytes;
    if(ensure_twiddles(c,n,&h2d))return -1;if(mark_timing(c,1))return -1;const int bits=__builtin_ctzll(n);
    bit_reverse_fp_batch<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,0),buf<uint64_t>(c,1),rows,n,bits);
    for(size_t len=2;len<=n;len*=2)ntt_stage_fp_batch<<<(rows*n/2+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,1),buf<uint64_t>(c,11),rows,n,len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<uint64_t>(c,1),bytes,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_NTT,h2d,bytes);
}

extern "C" int volta_cuda_ntt_fp2(void* raw,const Fp2* msg,size_t msg_len,size_t n,Fp2* out) {
    Context* c=static_cast<Context*>(raw);if(!c||!msg||!out||n<2||(n&(n-1))||msg_len>n)return -1;
    if(ensure(c,0,n*sizeof(Fp2))||ensure(c,1,n*sizeof(Fp2)))return -1;std::vector<Fp2> host(n);std::copy(msg,msg+msg_len,host.begin());
    uint64_t h2d=0;if(begin_timing(c))return -1;CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<Fp2>(c,0),host.data(),n*sizeof(Fp2),cudaMemcpyHostToDevice,c->stream));h2d+=n*sizeof(Fp2);
    if(ensure_twiddles(c,n,&h2d))return -1;if(mark_timing(c,1))return -1;const int bits=__builtin_ctzll(n);
    bit_reverse_fp2<<<(n+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<Fp2>(c,0),buf<Fp2>(c,1),n,bits);
    for(size_t len=2;len<=n;len*=2)ntt_stage_fp2<<<(n/2+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<Fp2>(c,1),buf<uint64_t>(c,11),n,len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<Fp2>(c,1),n*sizeof(Fp2),cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_NTT,h2d,n*sizeof(Fp2));
}

extern "C" int volta_cuda_ntt_fp_batch_device(
    void* raw,uint64_t input_id,size_t input_offset,size_t rows,size_t n,
    uint64_t output_id,size_t output_offset){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||n<2||(n&(n-1)))
        return fail_message(c,"invalid resident Fp NTT geometry");
    void *input=nullptr,*output=nullptr;const size_t total=rows*n,bytes=total*sizeof(uint64_t);
    if(resident_region(c,input_id,input_offset*sizeof(uint64_t),bytes,&input)||
       resident_region(c,output_id,output_offset*sizeof(uint64_t),bytes,&output))return -1;
    uint64_t h2d=0;if(begin_timing(c))return -1;if(ensure_twiddles(c,n,&h2d))return -1;
    if(mark_timing(c,1))return -1;const int bits=__builtin_ctzll(n);
    bit_reverse_fp_batch<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const uint64_t*>(input),static_cast<uint64_t*>(output),rows,n,bits);
    for(size_t len=2;len<=n;len*=2)ntt_stage_fp_batch<<<(rows*n/2+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<uint64_t*>(output),buf<uint64_t>(c,11),rows,n,len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_NTT,h2d,0);
}

extern "C" int volta_cuda_ntt_fp2_batch_device(
    void* raw,uint64_t input_id,size_t input_offset,size_t rows,size_t n,
    uint64_t output_id,size_t output_offset){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||n<2||(n&(n-1)))
        return fail_message(c,"invalid resident Fp2 NTT geometry");
    void *input=nullptr,*output=nullptr;const size_t total=rows*n,bytes=total*sizeof(Fp2);
    if(resident_region(c,input_id,input_offset*sizeof(Fp2),bytes,&input)||
       resident_region(c,output_id,output_offset*sizeof(Fp2),bytes,&output))return -1;
    uint64_t h2d=0;if(begin_timing(c))return -1;if(ensure_twiddles(c,n,&h2d))return -1;
    if(mark_timing(c,1))return -1;const int bits=__builtin_ctzll(n);
    bit_reverse_fp2_batch<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const Fp2*>(input),static_cast<Fp2*>(output),rows,n,bits);
    for(size_t len=2;len<=n;len*=2)ntt_stage_fp2_batch<<<(rows*n/2+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<Fp2*>(output),buf<uint64_t>(c,11),rows,n,len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_NTT,h2d,0);
}

extern "C" int volta_cuda_logup_tree(void* raw,const uint64_t* leaf,const uint32_t* mult,size_t n,
    uint64_t alpha1,int neg_mult,Fp2* hp,Fp2* hq) {
    Context* c=static_cast<Context*>(raw);if(!c||!leaf||!hp||!hq||n<2||(n&(n-1))||(neg_mult&&!mult))return -1;
    const size_t lb=n*8,mb=neg_mult?n*4:0,tb=(n-1)*sizeof(Fp2);
    if(ensure(c,0,lb)||ensure(c,1,std::max(size_t{1},mb))||ensure(c,2,tb)||ensure(c,3,tb))return -1;
    if(begin_timing(c))return -1;CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,0),leaf,lb,cudaMemcpyHostToDevice,c->stream));
    if(neg_mult)CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint32_t>(c,1),mult,mb,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;size_t len=n/2,off=len-1;
    logup_first_combine<<<(len+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,0),buf<uint32_t>(c,1),buf<Fp2>(c,2),buf<Fp2>(c,3),len,off,alpha1,neg_mult);
    while(len>1){const size_t parent=len/2;logup_general_combine<<<(parent+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        buf<Fp2>(c,2),buf<Fp2>(c,3),buf<Fp2>(c,2),buf<Fp2>(c,3),parent,len-1,parent-1);len=parent;}
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(hp,buf<Fp2>(c,2),tb,cudaMemcpyDeviceToHost,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(hq,buf<Fp2>(c,3),tb,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_LOGUP,lb+mb,2*tb);
}

extern "C" int volta_cuda_logup_tree_device(
    void* raw, uint64_t leaf_id, size_t leaf_offset, uint64_t mult_id, size_t mult_offset,
    size_t n, uint64_t alpha1, int neg_mult, uint64_t p_id, size_t p_offset,
    uint64_t q_id, size_t q_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || n < 2 || (n & (n - 1)) || (neg_mult && !mult_id))
        return fail_message(c, "invalid resident LogUp tree geometry");
    void *leafv = nullptr, *multv = nullptr, *pv = nullptr, *qv = nullptr;
    if (resident_region(c, leaf_id, leaf_offset * sizeof(uint64_t), n * sizeof(uint64_t), &leafv) ||
        (neg_mult && resident_region(c, mult_id, mult_offset * sizeof(uint32_t),
                                     n * sizeof(uint32_t), &multv)) ||
        resident_region(c, p_id, p_offset * sizeof(Fp2), (n - 1) * sizeof(Fp2), &pv) ||
        resident_region(c, q_id, q_offset * sizeof(Fp2), (n - 1) * sizeof(Fp2), &qv))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    size_t len = n / 2, off = len - 1;
    logup_first_combine<<<(len + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(leafv), static_cast<const uint32_t*>(multv),
        static_cast<Fp2*>(pv), static_cast<Fp2*>(qv), len, off, alpha1, neg_mult);
    while (len > 1) {
        const size_t parent = len / 2;
        logup_general_combine<<<(parent + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
            static_cast<Fp2*>(pv), static_cast<Fp2*>(qv),
            static_cast<Fp2*>(pv), static_cast<Fp2*>(qv), parent, len - 1, parent - 1);
        len = parent;
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_logup_materialize_leaves_device(
    void* raw, uint64_t leaf_id, size_t leaf_offset, uint64_t mult_id,
    size_t mult_offset, size_t n, uint64_t alpha1, int neg_mult,
    uint64_t p_id, size_t p_offset, uint64_t q_id, size_t q_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !n || (neg_mult && !mult_id))
        return fail_message(c, "invalid resident LogUp leaf geometry");
    void *leaf = nullptr, *mult = nullptr, *p = nullptr, *q = nullptr;
    if (resident_region(c, leaf_id, leaf_offset * sizeof(uint64_t),
                        n * sizeof(uint64_t), &leaf) ||
        (neg_mult && resident_region(c, mult_id, mult_offset * sizeof(uint32_t),
                                     n * sizeof(uint32_t), &mult)) ||
        resident_region(c, p_id, p_offset * sizeof(Fp2), n * sizeof(Fp2), &p) ||
        resident_region(c, q_id, q_offset * sizeof(Fp2), n * sizeof(Fp2), &q))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    logup_materialize_leaves<<<(n + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const uint64_t*>(leaf), static_cast<const uint32_t*>(mult),
        static_cast<Fp2*>(p), static_cast<Fp2*>(q), n, alpha1, neg_mult);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_logup_general_round(void* raw,const Fp2* p0,const Fp2* p1,const Fp2* q0,
    const Fp2* q1,const Fp2* suffix,size_t pairs,Fp2* output) {
    Context* c=static_cast<Context*>(raw);if(!c||!p0||!p1||!q0||!q1||!suffix||!output||!pairs)return -1;
    const size_t vb=2*pairs*sizeof(Fp2),sb=pairs*sizeof(Fp2),ab=pairs*sizeof(RoundAcc);
    for(int i=0;i<5;++i)if(ensure(c,i,i==4?sb:vb))return -1;if(ensure(c,5,ab)||ensure(c,6,ab))return -1;
    if(begin_timing(c))return -1;const Fp2* src[5]={p0,p1,q0,q1,suffix};for(int i=0;i<5;++i)
        CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<Fp2>(c,i),src[i],i==4?sb:vb,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;logup_round_eval<<<(pairs+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<Fp2>(c,0),buf<Fp2>(c,1),buf<Fp2>(c,2),buf<Fp2>(c,3),buf<Fp2>(c,4),buf<RoundAcc>(c,5),pairs);
    size_t count=pairs;RoundAcc* in=buf<RoundAcc>(c,5);RoundAcc* out=buf<RoundAcc>(c,6);
    while(count>1){size_t blocks=(count+BLOCK-1)/BLOCK;reduce_round<<<blocks,BLOCK,0,c->stream>>>(in,out,count);count=blocks;std::swap(in,out);}
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(output,in,sizeof(RoundAcc),cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_LOGUP,4*vb+sb,sizeof(RoundAcc));
}

int logup_general_round_resident_impl(
    Context* c, const Fp2* p0, const Fp2* p1, const Fp2* q0,
    const Fp2* q1, const Fp2* suffix, size_t pairs,
    Fp2* output, bool output_is_device) {
    size_t accumulator_bytes = 0;
    if (!checked_mul_size(pairs, sizeof(RoundAcc), &accumulator_bytes))
        return fail_message(c, "resident LogUp round workspace overflows size_t");
    if (ensure(c, 5, accumulator_bytes) || ensure(c, 6, accumulator_bytes)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    logup_round_eval<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        p0, p1, q0, q1, suffix, buf<RoundAcc>(c, 5), pairs);
    size_t count = pairs;
    RoundAcc* in = buf<RoundAcc>(c, 5);
    RoundAcc* out = buf<RoundAcc>(c, 6);
    while (count > 1) {
        const size_t blocks = (count + BLOCK - 1) / BLOCK;
        reduce_round<<<blocks, BLOCK, 0, c->stream>>>(in, out, count);
        count = blocks;
        std::swap(in, out);
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (output_is_device) {
        CUDA_OR_RETURN(c, cudaMemcpyAsync(output, in, sizeof(RoundAcc),
                                         cudaMemcpyDeviceToDevice, c->stream));
        if (mark_timing(c, 2)) return -1;
        return finish_timing(c, OP_LOGUP, 0, 0);
    }
    if (mark_timing(c, 2)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(output, in, sizeof(RoundAcc),
                                     cudaMemcpyDeviceToHost, c->stream));
    return finish_timing(c, OP_LOGUP, 0, sizeof(RoundAcc));
}

int resolve_logup_general_round_inputs(
    Context* c, uint64_t p0_id, size_t p0_offset, uint64_t p1_id, size_t p1_offset,
    uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, size_t pairs,
    void** p0, void** p1, void** q0, void** q1, void** suffix) {
    size_t vector_bytes = 0, suffix_bytes = 0;
    size_t p0_offset_bytes = 0, p1_offset_bytes = 0;
    size_t q0_offset_bytes = 0, q1_offset_bytes = 0, suffix_offset_bytes = 0;
    if (!checked_mul_size(pairs, 2 * sizeof(Fp2), &vector_bytes) ||
        !checked_mul_size(pairs, sizeof(Fp2), &suffix_bytes) ||
        !checked_mul_size(p0_offset, sizeof(Fp2), &p0_offset_bytes) ||
        !checked_mul_size(p1_offset, sizeof(Fp2), &p1_offset_bytes) ||
        !checked_mul_size(q0_offset, sizeof(Fp2), &q0_offset_bytes) ||
        !checked_mul_size(q1_offset, sizeof(Fp2), &q1_offset_bytes) ||
        !checked_mul_size(suffix_offset, sizeof(Fp2), &suffix_offset_bytes))
        return fail_message(c, "resident LogUp round geometry overflows size_t");
    return resident_region(c, p0_id, p0_offset_bytes, vector_bytes, p0) ||
           resident_region(c, p1_id, p1_offset_bytes, vector_bytes, p1) ||
           resident_region(c, q0_id, q0_offset_bytes, vector_bytes, q0) ||
           resident_region(c, q1_id, q1_offset_bytes, vector_bytes, q1) ||
           resident_region(c, suffix_id, suffix_offset_bytes, suffix_bytes, suffix)
        ? -1 : 0;
}

extern "C" int volta_cuda_logup_general_round_device(
    void* raw, uint64_t p0_id, size_t p0_offset, uint64_t p1_id, size_t p1_offset,
    uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, size_t pairs, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs || !output)
        return fail_message(c, "invalid resident LogUp round geometry");
    void *p0 = nullptr, *p1 = nullptr, *q0 = nullptr, *q1 = nullptr, *suffix = nullptr;
    if (resolve_logup_general_round_inputs(
            c, p0_id, p0_offset, p1_id, p1_offset, q0_id, q0_offset,
            q1_id, q1_offset, suffix_id, suffix_offset, pairs,
            &p0, &p1, &q0, &q1, &suffix)) return -1;
    return logup_general_round_resident_impl(
        c, static_cast<const Fp2*>(p0), static_cast<const Fp2*>(p1),
        static_cast<const Fp2*>(q0), static_cast<const Fp2*>(q1),
        static_cast<const Fp2*>(suffix), pairs, output, false);
}

extern "C" int volta_cuda_logup_general_round_into_device(
    void* raw, uint64_t p0_id, size_t p0_offset, uint64_t p1_id, size_t p1_offset,
    uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, size_t pairs,
    uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs)
        return fail_message(c, "invalid resident LogUp round mailbox geometry");
    void *p0 = nullptr, *p1 = nullptr, *q0 = nullptr, *q1 = nullptr;
    void *suffix = nullptr, *output = nullptr;
    size_t output_offset_bytes = 0;
    if (!checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes))
        return fail_message(c, "resident LogUp round mailbox offset overflows size_t");
    if (resolve_logup_general_round_inputs(
            c, p0_id, p0_offset, p1_id, p1_offset, q0_id, q0_offset,
            q1_id, q1_offset, suffix_id, suffix_offset, pairs,
            &p0, &p1, &q0, &q1, &suffix) ||
        resident_region(c, output_id, output_offset_bytes, sizeof(RoundAcc), &output))
        return -1;
    return logup_general_round_resident_impl(
        c, static_cast<const Fp2*>(p0), static_cast<const Fp2*>(p1),
        static_cast<const Fp2*>(q0), static_cast<const Fp2*>(q1),
        static_cast<const Fp2*>(suffix), pairs, static_cast<Fp2*>(output), true);
}

extern "C" int volta_cuda_logup_fold4(void* raw,const Fp2* p0,const Fp2* p1,const Fp2* q0,const Fp2* q1,
    size_t pairs,Fp2 r,Fp2* o0,Fp2* o1,Fp2* o2,Fp2* o3) {
    Context* c=static_cast<Context*>(raw);if(!c||!p0||!p1||!q0||!q1||!o0||!o1||!o2||!o3||!pairs)return -1;
    const size_t ib=2*pairs*sizeof(Fp2),ob=pairs*sizeof(Fp2);for(int i=0;i<4;++i)if(ensure(c,i,ib)||ensure(c,4+i,ob))return -1;
    if(begin_timing(c))return -1;const Fp2* src[4]={p0,p1,q0,q1};for(int i=0;i<4;++i)CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<Fp2>(c,i),src[i],ib,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;logup_fold<<<(pairs+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<Fp2>(c,0),buf<Fp2>(c,1),buf<Fp2>(c,2),buf<Fp2>(c,3),buf<Fp2>(c,4),buf<Fp2>(c,5),buf<Fp2>(c,6),buf<Fp2>(c,7),pairs,r);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;Fp2* dst[4]={o0,o1,o2,o3};for(int i=0;i<4;++i)CUDA_OR_RETURN(c,cudaMemcpyAsync(dst[i],buf<Fp2>(c,4+i),ob,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_LOGUP,4*ib,4*ob);
}

extern "C" int volta_cuda_logup_fold4_device(
    void* raw, uint64_t p0_id, size_t p0_offset, uint64_t p1_id, size_t p1_offset,
    uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset, size_t pairs,
    Fp2 r, uint64_t o0_id, size_t o0_offset, uint64_t o1_id, size_t o1_offset,
    uint64_t o2_id, size_t o2_offset, uint64_t o3_id, size_t o3_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs) return fail_message(c, "invalid resident LogUp fold geometry");
    void *iv[4]{}, *ov[4]{};
    const uint64_t ii[4] = {p0_id, p1_id, q0_id, q1_id};
    const size_t io[4] = {p0_offset, p1_offset, q0_offset, q1_offset};
    const uint64_t oi[4] = {o0_id, o1_id, o2_id, o3_id};
    const size_t oo[4] = {o0_offset, o1_offset, o2_offset, o3_offset};
    for (int i = 0; i < 4; ++i) {
        if (resident_region(c, ii[i], io[i] * sizeof(Fp2), 2 * pairs * sizeof(Fp2), &iv[i]) ||
            resident_region(c, oi[i], oo[i] * sizeof(Fp2), pairs * sizeof(Fp2), &ov[i]))
            return -1;
    }
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    logup_fold<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(iv[0]), static_cast<const Fp2*>(iv[1]),
        static_cast<const Fp2*>(iv[2]), static_cast<const Fp2*>(iv[3]),
        static_cast<Fp2*>(ov[0]), static_cast<Fp2*>(ov[1]),
        static_cast<Fp2*>(ov[2]), static_cast<Fp2*>(ov[3]), pairs, r);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_fp2_deinterleave_device(
    void* raw, uint64_t input_id, size_t input_offset, size_t pairs,
    uint64_t even_id, size_t even_offset, uint64_t odd_id, size_t odd_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs) return fail_message(c, "invalid resident deinterleave geometry");
    void *input = nullptr, *even = nullptr, *odd = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(Fp2),
                        2 * pairs * sizeof(Fp2), &input) ||
        resident_region(c, even_id, even_offset * sizeof(Fp2),
                        pairs * sizeof(Fp2), &even) ||
        resident_region(c, odd_id, odd_offset * sizeof(Fp2),
                        pairs * sizeof(Fp2), &odd))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fp2_deinterleave<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(input), static_cast<Fp2*>(even),
        static_cast<Fp2*>(odd), pairs);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_logup_suffix_eq_device(
    void* raw, uint64_t points_id, size_t points_offset, size_t point_len,
    uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !point_len || point_len >= 63)
        return fail_message(c, "invalid resident suffix-eq geometry");
    const size_t total = (size_t{1} << point_len) - 1;
    void *points = nullptr, *output = nullptr;
    if (resident_region(c, points_id, points_offset * sizeof(Fp2),
                        point_len * sizeof(Fp2), &points) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2),
                        total * sizeof(Fp2), &output))
        return -1;
    Fp2* out = static_cast<Fp2*>(output);
    const Fp2* pts = static_cast<const Fp2*>(points);
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fp2_set_one<<<1, 1, 0, c->stream>>>(out);
    size_t size = 1;
    for (size_t j = point_len - 1; j > 0; --j) {
        suffix_eq_expand<<<(size + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
            out + size - 1, out + 2 * size - 1, size, pts + j);
        size *= 2;
    }
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_fp2_fold_rows_device(
    void* raw, uint64_t input_id, size_t input_offset, size_t rows, size_t len,
    Fp2 r, uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || len < 2 || (len & 1))
        return fail_message(c, "invalid resident row-fold geometry");
    const size_t pairs = len / 2;
    void *input = nullptr, *output = nullptr;
    if (resident_region(c, input_id, input_offset * sizeof(Fp2),
                        rows * len * sizeof(Fp2), &input) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2),
                        rows * pairs * sizeof(Fp2), &output))
        return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    fp2_fold_rows<<<(rows * pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(input), static_cast<Fp2*>(output), rows, pairs, r);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

extern "C" int volta_cuda_logup_eq_rows_device(
    void* raw, uint64_t points_id, size_t points_offset, size_t rows, size_t dims,
    uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !rows || dims >= 63 || (dims && !points_id))
        return fail_message(c, "invalid resident eq-row geometry");
    const size_t width = size_t{1} << dims, total = rows * width;
    void *points = nullptr, *output = nullptr;
    if ((dims && resident_region(c, points_id, points_offset * sizeof(Fp2),
                                 rows * dims * sizeof(Fp2), &points)) ||
        resident_region(c, output_id, output_offset * sizeof(Fp2),
                        total * sizeof(Fp2), &output))
        return -1;
    if (ensure(c, 8, total * sizeof(Fp2))) return -1;
    Fp2* final_out = static_cast<Fp2*>(output);
    Fp2* in = final_out;
    Fp2* out = buf<Fp2>(c, 8);
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    eq_rows_init<<<(rows + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(in, rows);
    size_t current = 1;
    for (size_t dim = dims; dim-- > 0;) {
        eq_rows_expand<<<(rows * current + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
            in, out, static_cast<const Fp2*>(points), rows, dims, dim, current);
        current *= 2;
        std::swap(in, out);
    }
    if (in != final_out)
        CUDA_OR_RETURN(c, cudaMemcpyAsync(final_out, in, total * sizeof(Fp2),
                                          cudaMemcpyDeviceToDevice, c->stream));
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (mark_timing(c, 2)) return -1;
    return finish_timing(c, OP_LOGUP, 0, 0);
}

int logup_aux_round_resident_impl(
    Context* c, const Fp2* q0, const Fp2* q1, const Fp2* suffix,
    const Fp2* columns, const Fp2* eq, const uint32_t* claim_cols,
    const Fp2* weights, size_t column_count, size_t claim_count,
    size_t vector_len, Fp2 lambda, Fp2 cpref, Fp2 point,
    Fp2* output, bool output_is_device) {
    const size_t pairs = vector_len / 2;
    size_t bytes = 0;
    if (!checked_mul_size(pairs, sizeof(AuxRoundAcc), &bytes))
        return fail_message(c, "resident aux-round workspace overflows size_t");
    if (ensure(c, 12, bytes) || ensure(c, 13, bytes) ||
        ensure(c, 14, 3 * sizeof(Fp2))) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    logup_aux_round_eval<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        q0, q1, suffix, columns, eq, claim_cols, weights,
        column_count, claim_count, vector_len, pairs, buf<AuxRoundAcc>(c, 12));
    size_t count = pairs;
    AuxRoundAcc* in = buf<AuxRoundAcc>(c, 12);
    AuxRoundAcc* out = buf<AuxRoundAcc>(c, 13);
    while (count > 1) {
        const size_t blocks = (count + BLOCK - 1) / BLOCK;
        reduce_aux_round<<<blocks, BLOCK, 0, c->stream>>>(in, out, count);
        count = blocks;
        std::swap(in, out);
    }
    assemble_aux_round<<<1, 1, 0, c->stream>>>(
        in, buf<Fp2>(c, 14), lambda, cpref, point);
    CUDA_OR_RETURN(c, cudaPeekAtLastError());
    if (output_is_device) {
        CUDA_OR_RETURN(c, cudaMemcpyAsync(output, buf<Fp2>(c, 14), 3 * sizeof(Fp2),
                                         cudaMemcpyDeviceToDevice, c->stream));
        if (mark_timing(c, 2)) return -1;
        return finish_timing(c, OP_LOGUP, 0, 0);
    }
    if (mark_timing(c, 2)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(output, buf<Fp2>(c, 14), 3 * sizeof(Fp2),
                                     cudaMemcpyDeviceToHost, c->stream));
    return finish_timing(c, OP_LOGUP, 0, 3 * sizeof(Fp2));
}

int resolve_logup_aux_round_inputs(
    Context* c, uint64_t q0_id, size_t q0_offset,
    uint64_t q1_id, size_t q1_offset, uint64_t suffix_id, size_t suffix_offset,
    uint64_t columns_id, size_t columns_offset, uint64_t eq_id, size_t eq_offset,
    uint64_t claim_cols_id, size_t claim_cols_offset,
    uint64_t weights_id, size_t weights_offset, size_t column_count,
    size_t claim_count, size_t vector_len, void** q0, void** q1,
    void** suffix, void** columns, void** eq, void** claim_cols, void** weights) {
    const size_t pairs = vector_len / 2;
    size_t q_bytes = 0, suffix_bytes = 0, columns_elements = 0, columns_bytes = 0;
    size_t eq_elements = 0, eq_bytes = 0, claim_cols_bytes = 0, weights_bytes = 0;
    size_t q0_offset_bytes = 0, q1_offset_bytes = 0, suffix_offset_bytes = 0;
    size_t columns_offset_bytes = 0, eq_offset_bytes = 0;
    size_t claim_cols_offset_bytes = 0, weights_offset_bytes = 0;
    if (!checked_mul_size(vector_len, sizeof(Fp2), &q_bytes) ||
        !checked_mul_size(pairs, sizeof(Fp2), &suffix_bytes) ||
        !checked_mul_size(column_count, vector_len, &columns_elements) ||
        !checked_mul_size(columns_elements, 2 * sizeof(Fp2), &columns_bytes) ||
        !checked_mul_size(claim_count, vector_len, &eq_elements) ||
        !checked_mul_size(eq_elements, sizeof(Fp2), &eq_bytes) ||
        !checked_mul_size(claim_count, sizeof(uint32_t), &claim_cols_bytes) ||
        !checked_mul_size(claim_count, 2 * sizeof(Fp2), &weights_bytes) ||
        !checked_mul_size(q0_offset, sizeof(Fp2), &q0_offset_bytes) ||
        !checked_mul_size(q1_offset, sizeof(Fp2), &q1_offset_bytes) ||
        !checked_mul_size(suffix_offset, sizeof(Fp2), &suffix_offset_bytes) ||
        !checked_mul_size(columns_offset, sizeof(Fp2), &columns_offset_bytes) ||
        !checked_mul_size(eq_offset, sizeof(Fp2), &eq_offset_bytes) ||
        !checked_mul_size(claim_cols_offset, sizeof(uint32_t), &claim_cols_offset_bytes) ||
        !checked_mul_size(weights_offset, sizeof(Fp2), &weights_offset_bytes))
        return fail_message(c, "resident aux-round geometry overflows size_t");
    if (resident_region(c, q0_id, q0_offset_bytes, q_bytes, q0) ||
        resident_region(c, q1_id, q1_offset_bytes, q_bytes, q1) ||
        resident_region(c, suffix_id, suffix_offset_bytes, suffix_bytes, suffix) ||
        resident_region(c, columns_id, columns_offset_bytes, columns_bytes, columns))
        return -1;
    if (!claim_count) {
        *eq = nullptr;
        *claim_cols = nullptr;
        *weights = nullptr;
        return 0;
    }
    return resident_region(c, eq_id, eq_offset_bytes, eq_bytes, eq) ||
           resident_region(c, claim_cols_id, claim_cols_offset_bytes,
                           claim_cols_bytes, claim_cols) ||
           resident_region(c, weights_id, weights_offset_bytes, weights_bytes, weights)
        ? -1 : 0;
}

extern "C" int volta_cuda_logup_aux_round_device(
    void* raw, uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, uint64_t columns_id, size_t columns_offset,
    uint64_t eq_id, size_t eq_offset, uint64_t claim_cols_id, size_t claim_cols_offset,
    uint64_t weights_id, size_t weights_offset, size_t column_count, size_t claim_count,
    size_t vector_len, Fp2 lambda, Fp2 cpref, Fp2 point, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !output || !column_count || vector_len < 2 || (vector_len & 1))
        return fail_message(c, "invalid resident aux-round geometry");
    void *q0 = nullptr, *q1 = nullptr, *suffix = nullptr, *columns = nullptr;
    void *eq = nullptr, *claim_cols = nullptr, *weights = nullptr;
    if (resolve_logup_aux_round_inputs(
            c, q0_id, q0_offset, q1_id, q1_offset, suffix_id, suffix_offset,
            columns_id, columns_offset, eq_id, eq_offset, claim_cols_id,
            claim_cols_offset, weights_id, weights_offset, column_count,
            claim_count, vector_len, &q0, &q1, &suffix, &columns, &eq,
            &claim_cols, &weights)) return -1;
    return logup_aux_round_resident_impl(
        c, static_cast<const Fp2*>(q0), static_cast<const Fp2*>(q1),
        static_cast<const Fp2*>(suffix), static_cast<const Fp2*>(columns),
        static_cast<const Fp2*>(eq), static_cast<const uint32_t*>(claim_cols),
        static_cast<const Fp2*>(weights), column_count, claim_count, vector_len,
        lambda, cpref, point, output, false);
}

extern "C" int volta_cuda_logup_aux_round_into_device(
    void* raw, uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, uint64_t columns_id, size_t columns_offset,
    uint64_t eq_id, size_t eq_offset, uint64_t claim_cols_id, size_t claim_cols_offset,
    uint64_t weights_id, size_t weights_offset, size_t column_count, size_t claim_count,
    size_t vector_len, Fp2 lambda, Fp2 cpref, Fp2 point,
    uint64_t output_id, size_t output_offset) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !column_count || vector_len < 2 || (vector_len & 1))
        return fail_message(c, "invalid resident aux-round mailbox geometry");
    void *q0 = nullptr, *q1 = nullptr, *suffix = nullptr, *columns = nullptr;
    void *eq = nullptr, *claim_cols = nullptr, *weights = nullptr, *output = nullptr;
    size_t output_offset_bytes = 0;
    if (!checked_mul_size(output_offset, sizeof(Fp2), &output_offset_bytes))
        return fail_message(c, "resident aux-round mailbox offset overflows size_t");
    if (resolve_logup_aux_round_inputs(
            c, q0_id, q0_offset, q1_id, q1_offset, suffix_id, suffix_offset,
            columns_id, columns_offset, eq_id, eq_offset, claim_cols_id,
            claim_cols_offset, weights_id, weights_offset, column_count,
            claim_count, vector_len, &q0, &q1, &suffix, &columns, &eq,
            &claim_cols, &weights) ||
        resident_region(c, output_id, output_offset_bytes, 3 * sizeof(Fp2), &output))
        return -1;
    return logup_aux_round_resident_impl(
        c, static_cast<const Fp2*>(q0), static_cast<const Fp2*>(q1),
        static_cast<const Fp2*>(suffix), static_cast<const Fp2*>(columns),
        static_cast<const Fp2*>(eq), static_cast<const uint32_t*>(claim_cols),
        static_cast<const Fp2*>(weights), column_count, claim_count, vector_len,
        lambda, cpref, point, static_cast<Fp2*>(output), true);
}

extern "C" int volta_cuda_pcs_messages_device(
    void* raw,uint64_t weights_id,size_t weights_offset,uint64_t pads_id,size_t pads_offset,
    size_t rows,size_t cols,size_t pad,size_t code_len,uint64_t output_id,size_t output_offset){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||!cols||!code_len||cols+pad>code_len)
        return fail_message(c,"invalid resident PCS message geometry");
    void *weights=nullptr,*pads=nullptr,*output=nullptr;
    if(resident_region(c,weights_id,weights_offset*sizeof(int16_t),rows*cols*sizeof(int16_t),&weights)||
       (pad&&resident_region(c,pads_id,pads_offset*sizeof(uint64_t),rows*pad*sizeof(uint64_t),&pads))||
       resident_region(c,output_id,output_offset*sizeof(uint64_t),rows*code_len*sizeof(uint64_t),&output))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    const size_t total=rows*code_len;pcs_messages_kernel<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const int16_t*>(weights),static_cast<const uint64_t*>(pads),
        static_cast<uint64_t*>(output),rows,cols,pad,code_len);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_ROWS,0,0);
}

extern "C" int volta_cuda_pcs_combine_rows_device(
    void* raw,uint64_t weights_id,size_t weights_offset,uint64_t pads_id,size_t pads_offset,
    uint64_t coeffs_id,size_t coeffs_offset,size_t rows,size_t cols,size_t pad,
    size_t combinations,uint64_t output_id,size_t output_offset){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||!cols||!combinations)
        return fail_message(c,"invalid resident PCS combination geometry");
    void *weights=nullptr,*pads=nullptr,*coeffs=nullptr,*output=nullptr;
    const size_t msg_len=cols+pad;
    if(resident_region(c,weights_id,weights_offset*sizeof(int16_t),rows*cols*sizeof(int16_t),&weights)||
       (pad&&resident_region(c,pads_id,pads_offset*sizeof(uint64_t),rows*pad*sizeof(uint64_t),&pads))||
       resident_region(c,coeffs_id,coeffs_offset*sizeof(Fp2),combinations*rows*sizeof(Fp2),&coeffs)||
       resident_region(c,output_id,output_offset*sizeof(Fp2),combinations*msg_len*sizeof(Fp2),&output))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    const size_t count=combinations*msg_len;pcs_combine_rows_kernel<<<(count+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const int16_t*>(weights),static_cast<const uint64_t*>(pads),
        static_cast<const Fp2*>(coeffs),static_cast<Fp2*>(output),rows,cols,pad,combinations);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_ROWS,0,0);
}

extern "C" int volta_cuda_fp2_add_inplace_device(
    void* raw,uint64_t target_id,size_t target_offset,uint64_t add_id,size_t add_offset,size_t n){
    Context* c=static_cast<Context*>(raw);if(!c||!n)return fail_message(c,"invalid resident Fp2 add");
    void *target=nullptr,*add=nullptr;
    if(resident_region(c,target_id,target_offset*sizeof(Fp2),n*sizeof(Fp2),&target)||
       resident_region(c,add_id,add_offset*sizeof(Fp2),n*sizeof(Fp2),&add))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    fp2_add_inplace_kernel<<<(n+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<Fp2*>(target),static_cast<const Fp2*>(add),n);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_ROWS,0,0);
}

int hash_tree_device_impl(
    Context* c,void* matrix,size_t rows,size_t cols,bool fp2,Hash32* tree){
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    if(fp2)hash_fp2_columns_kernel<<<(cols+127)/128,128,0,c->stream>>>(
        static_cast<const Fp2*>(matrix),tree,rows,cols);
    else hash_columns_kernel<<<(cols+127)/128,128,0,c->stream>>>(
        static_cast<const uint64_t*>(matrix),tree,rows,cols);
    size_t len=cols,off=0;
    while(len>1){const size_t parent=len/2;
        merkle_parent_kernel<<<(parent+127)/128,128,0,c->stream>>>(tree+off,tree+off+len,parent);
        off+=len;len=parent;}
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_MERKLE,0,0);
}

extern "C" int volta_cuda_hash_fp_tree_device(
    void* raw,uint64_t matrix_id,size_t matrix_offset,size_t rows,size_t cols,
    uint64_t tree_id,size_t tree_offset_bytes){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||!cols||(cols&(cols-1)))
        return fail_message(c,"invalid resident Fp Merkle geometry");
    void *matrix=nullptr,*tree=nullptr;
    if(resident_region(c,matrix_id,matrix_offset*sizeof(uint64_t),rows*cols*sizeof(uint64_t),&matrix)||
       resident_region(c,tree_id,tree_offset_bytes,(2*cols-1)*sizeof(Hash32),&tree))return -1;
    return hash_tree_device_impl(c,matrix,rows,cols,false,static_cast<Hash32*>(tree));
}

extern "C" int volta_cuda_hash_fp2_tree_device(
    void* raw,uint64_t matrix_id,size_t matrix_offset,size_t rows,size_t cols,
    uint64_t tree_id,size_t tree_offset_bytes){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||!cols||(cols&(cols-1)))
        return fail_message(c,"invalid resident Fp2 Merkle geometry");
    void *matrix=nullptr,*tree=nullptr;
    if(resident_region(c,matrix_id,matrix_offset*sizeof(Fp2),rows*cols*sizeof(Fp2),&matrix)||
       resident_region(c,tree_id,tree_offset_bytes,(2*cols-1)*sizeof(Hash32),&tree))return -1;
    return hash_tree_device_impl(c,matrix,rows,cols,true,static_cast<Hash32*>(tree));
}

extern "C" int volta_cuda_merkle_paths_device(
    void* raw,uint64_t tree_id,size_t tree_offset_bytes,size_t leaves,
    uint64_t indices_id,size_t indices_offset,size_t queries,
    uint64_t paths_id,size_t paths_offset_bytes){
    Context* c=static_cast<Context*>(raw);if(!c||leaves<2||(leaves&(leaves-1))||!queries)
        return fail_message(c,"invalid resident Merkle path geometry");
    const size_t bits=__builtin_ctzll(leaves);void *tree=nullptr,*indices=nullptr,*paths=nullptr;
    if(resident_region(c,tree_id,tree_offset_bytes,(2*leaves-1)*sizeof(Hash32),&tree)||
       resident_region(c,indices_id,indices_offset*sizeof(uint32_t),queries*sizeof(uint32_t),&indices)||
       resident_region(c,paths_id,paths_offset_bytes,queries*bits*sizeof(Hash32),&paths))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    merkle_paths_kernel<<<(queries*bits+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const Hash32*>(tree),static_cast<const uint32_t*>(indices),
        static_cast<Hash32*>(paths),leaves,queries,bits);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_MERKLE,0,0);
}

extern "C" int volta_cuda_pcs_gather_columns_device(
    void* raw,uint64_t matrix_id,size_t matrix_offset,size_t rows,size_t cols,
    uint64_t indices_id,size_t indices_offset,size_t queries,
    uint64_t output_id,size_t output_offset,int fp2){
    Context* c=static_cast<Context*>(raw);if(!c||!rows||!cols||!queries)
        return fail_message(c,"invalid resident PCS gather geometry");
    const size_t elem=fp2?sizeof(Fp2):sizeof(uint64_t);void *matrix=nullptr,*indices=nullptr,*output=nullptr;
    if(resident_region(c,matrix_id,matrix_offset*elem,rows*cols*elem,&matrix)||
       resident_region(c,indices_id,indices_offset*sizeof(uint32_t),queries*sizeof(uint32_t),&indices)||
       resident_region(c,output_id,output_offset*elem,rows*queries*elem,&output))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    const size_t total=rows*queries;
    if(fp2)gather_fp2_columns_kernel<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const Fp2*>(matrix),static_cast<const uint32_t*>(indices),
        static_cast<Fp2*>(output),rows,cols,queries);
    else gather_columns_kernel<<<(total+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const uint64_t*>(matrix),static_cast<const uint32_t*>(indices),
        static_cast<uint64_t*>(output),rows,cols,queries);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    return finish_timing(c,OP_PCS_ROWS,0,0);
}

extern "C" int volta_cuda_pcs_combine_rows(void* raw,const int16_t* weights,const uint64_t* pads,
    const Fp2* coeffs,size_t rows,size_t cols,size_t pad,size_t combinations,Fp2* out) {
    Context* c=static_cast<Context*>(raw);if(!c||!weights||!coeffs||!out||!rows||!cols||!combinations||(pad&&!pads))return -1;
    const size_t wb=rows*cols*2,pb=rows*pad*8,cb=combinations*rows*sizeof(Fp2),ob=combinations*(cols+pad)*sizeof(Fp2);
    if(ensure(c,0,wb)||ensure(c,1,std::max(size_t{1},pb))||ensure(c,2,cb)||ensure(c,3,ob))return -1;
    if(begin_timing(c))return -1;CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<int16_t>(c,0),weights,wb,cudaMemcpyHostToDevice,c->stream));
    if(pb)CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,1),pads,pb,cudaMemcpyHostToDevice,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<Fp2>(c,2),coeffs,cb,cudaMemcpyHostToDevice,c->stream));if(mark_timing(c,1))return -1;
    const size_t count=combinations*(cols+pad);pcs_combine_rows_kernel<<<(count+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        buf<int16_t>(c,0),buf<uint64_t>(c,1),buf<Fp2>(c,2),buf<Fp2>(c,3),rows,cols,pad,combinations);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<Fp2>(c,3),ob,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_ROWS,wb+pb+cb,ob);
}

extern "C" int volta_cuda_pcs_gather_columns(void* raw,const uint64_t* matrix,size_t rows,size_t cols,
    const uint32_t* indices,size_t queries,uint64_t* out) {
    Context* c=static_cast<Context*>(raw);if(!c||!matrix||!indices||!out||!rows||!cols||!queries)return -1;
    const size_t mb=rows*cols*8,ib=queries*4,ob=rows*queries*8;
    if(ensure(c,0,mb)||ensure(c,1,ib)||ensure(c,2,ob))return -1;if(begin_timing(c))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,0),matrix,mb,cudaMemcpyHostToDevice,c->stream));
    CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint32_t>(c,1),indices,ib,cudaMemcpyHostToDevice,c->stream));if(mark_timing(c,1))return -1;
    gather_columns_kernel<<<(rows*queries+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<uint64_t>(c,0),buf<uint32_t>(c,1),buf<uint64_t>(c,2),rows,cols,queries);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(out,buf<uint64_t>(c,2),ob,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_ROWS,mb+ib,ob);
}

extern "C" int volta_cuda_hash_fp_columns(void* raw,const uint64_t* matrix,size_t rows,size_t cols,uint8_t* leaves) {
    Context* c=static_cast<Context*>(raw);if(!c||!matrix||!leaves||rows<8||rows%8||!cols||(cols&(cols-1)))return -1;
    const size_t mb=rows*cols*8,hb=cols*sizeof(Hash32);if(ensure(c,0,mb)||ensure(c,1,hb))return -1;
    if(begin_timing(c))return -1;CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<uint64_t>(c,0),matrix,mb,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;hash_columns_kernel<<<(cols+127)/128,128,0,c->stream>>>(buf<uint64_t>(c,0),buf<Hash32>(c,1),rows,cols);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(leaves,buf<Hash32>(c,1),hb,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_PCS_MERKLE,mb,hb);
}
