#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace volta_cuda_internal {

constexpr uint32_t ABI_VERSION = 6;
constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;
constexpr int BLOCK = 256;
constexpr int OP_COUNT = 5;
constexpr int OP_GEMM = 0;
constexpr int OP_LOGUP = 1;
constexpr int OP_PCS_ROWS = 2;
constexpr int OP_PCS_NTT = 3;
constexpr int OP_PCS_MERKLE = 4;
constexpr int BUFFER_COUNT = 16;
constexpr uint32_t TIMING_CUDA_EVENTS = 1;
constexpr uint32_t TIMING_HOST_BARRIER_WALL = 2;

struct alignas(16) Fp2 {
    uint64_t c0;
    uint64_t c1;
};

struct RawStats {
    uint64_t calls[OP_COUNT];
    uint64_t kernel_ns[OP_COUNT];
    uint64_t h2d_bytes;
    uint64_t d2h_bytes;
    uint64_t h2d_ns;
    uint64_t d2h_ns;
    uint64_t synchronizations;
    uint64_t synchronization_ns;
    uint64_t allocation_calls;
    uint64_t live_device_bytes;
    uint64_t peak_device_bytes;
    uint32_t timing_mode;
    uint32_t reserved;
};

static_assert(sizeof(RawStats) == 160, "RawStats ABI layout changed");

struct Buffer {
    void* ptr = nullptr;
    size_t capacity = 0;
};

/// Allocation owned by a CUDA context and addressed through an opaque id.
/// The Rust side never observes a device pointer.  Workspace slots above are
/// still free to grow/reuse independently, so resident values cannot be
/// invalidated by a later staged primitive.
struct ResidentBuffer {
    uint64_t id = 0;
    void* ptr = nullptr;
    size_t bytes = 0;
};

std::atomic<uint64_t> next_resident_id{1};

struct Context {
    cudaStream_t stream = nullptr;
    cudaEvent_t events[4]{};
    Buffer buffers[BUFFER_COUNT];
    std::vector<ResidentBuffer> resident;
    RawStats stats{};
    size_t twiddle_size = 0;
    uint32_t timing_mode = TIMING_CUDA_EVENTS;
    std::chrono::steady_clock::time_point phase_started{};
    std::array<uint64_t, 3> phase_ns{};
    std::string error;
};

int fail_message(Context* c, const char* message);

ResidentBuffer* find_resident(Context* c, uint64_t id) {
    if (!c || id == 0) return nullptr;
    for (auto& b : c->resident) if (b.id == id) return &b;
    return nullptr;
}

int resident_region(
    Context* c, uint64_t id, size_t offset, size_t bytes, void** out) {
    ResidentBuffer* b = find_resident(c, id);
    if (!b) return fail_message(c, "unknown resident buffer id");
    if (offset > b->bytes || bytes > b->bytes - offset)
        return fail_message(c, "resident buffer region is out of bounds");
    *out = static_cast<unsigned char*>(b->ptr) + offset;
    return 0;
}

int fail(Context* c, const char* expr, cudaError_t e) {
    if (c) c->error = std::string(expr) + ": " + cudaGetErrorString(e);
    return e == cudaSuccess ? -1 : static_cast<int>(e);
}

int fail_message(Context* c, const char* message) {
    if (c) c->error = message;
    return -1;
}

#define CUDA_OR_RETURN(c, call)                                                           \
    do {                                                                                  \
        cudaError_t volta_e_ = (call);                                                    \
        if (volta_e_ != cudaSuccess) return fail((c), #call, volta_e_);                   \
    } while (0)

int ensure(Context* c, int slot, size_t bytes) {
    if (slot < 0 || slot >= BUFFER_COUNT) return fail_message(c, "invalid workspace slot");
    Buffer& b = c->buffers[slot];
    if (b.capacity >= bytes) return 0;
    if (b.ptr) {
        CUDA_OR_RETURN(c, cudaFree(b.ptr));
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

int begin_timing(Context* c) {
    c->phase_ns.fill(0);
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, cudaEventRecord(c->events[0], c->stream));
    } else {
        c->phase_started = std::chrono::steady_clock::now();
    }
    return 0;
}

int finish_host_phase(Context* c, int phase) {
    if (phase < 0 || phase >= 3) return fail_message(c, "invalid timing phase");
    const auto sync_started = std::chrono::steady_clock::now();
    CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
    const auto finished = std::chrono::steady_clock::now();
    c->phase_ns[phase] =
        std::chrono::duration_cast<std::chrono::nanoseconds>(finished - c->phase_started).count();
    ++c->stats.synchronizations;
    c->stats.synchronization_ns +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(finished - sync_started).count();
    c->phase_started = finished;
    return 0;
}

int mark_timing(Context* c, int event) {
    if (event != 1 && event != 2) return fail_message(c, "invalid timing event");
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, cudaEventRecord(c->events[event], c->stream));
        return 0;
    }
    return finish_host_phase(c, event - 1);
}

int event_ns(Context* c, cudaEvent_t a, cudaEvent_t b, uint64_t* out) {
    float ms = -1.0f;
    const cudaError_t e = cudaEventElapsedTime(&ms, a, b);
    if (e != cudaSuccess) return fail(c, "cudaEventElapsedTime", e);
    if (ms < 0.0f) {
        return fail_message(c, "cudaEventElapsedTime returned success without a duration");
    }
    *out = static_cast<uint64_t>(ms * 1'000'000.0f);
    return 0;
}

int select_timing_mode(Context* c) {
    CUDA_OR_RETURN(c, cudaEventRecord(c->events[0], c->stream));
    CUDA_OR_RETURN(c, cudaEventRecord(c->events[1], c->stream));
    CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
    float ms = -1.0f;
    const cudaError_t e = cudaEventElapsedTime(&ms, c->events[0], c->events[1]);
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

int finish_timing(Context* c, int operation, uint64_t h2d, uint64_t d2h) {
    uint64_t h2d_ns = 0, kernel_ns = 0, d2h_ns = 0;
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, cudaEventRecord(c->events[3], c->stream));
        const auto s0 = std::chrono::steady_clock::now();
        CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
        const auto s1 = std::chrono::steady_clock::now();
        ++c->stats.synchronizations;
        c->stats.synchronization_ns +=
            std::chrono::duration_cast<std::chrono::nanoseconds>(s1 - s0).count();
        if (event_ns(c, c->events[0], c->events[1], &h2d_ns) ||
            event_ns(c, c->events[1], c->events[2], &kernel_ns) ||
            event_ns(c, c->events[2], c->events[3], &d2h_ns)) return -1;
    } else {
        if (finish_host_phase(c, 2)) return -1;
        h2d_ns = c->phase_ns[0];
        kernel_ns = c->phase_ns[1];
        d2h_ns = c->phase_ns[2];
    }
    ++c->stats.calls[operation];
    c->stats.h2d_bytes += h2d;
    c->stats.d2h_bytes += d2h;
    if (h2d) c->stats.h2d_ns += h2d_ns;
    c->stats.kernel_ns[operation] += kernel_ns;
    if (d2h) c->stats.d2h_ns += d2h_ns;
    return 0;
}

/// Time one explicit host/device transfer without inventing a kernel call.
/// Resident uploads/downloads are protocol-visible boundaries and therefore
/// remain fully counted even when they happen outside a staged primitive.
int begin_transfer_timing(Context* c) {
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, cudaEventRecord(c->events[0], c->stream));
    } else {
        c->phase_started = std::chrono::steady_clock::now();
    }
    return 0;
}

int finish_transfer_timing(Context* c, size_t bytes, bool h2d) {
    uint64_t elapsed_ns = 0;
    if (c->timing_mode == TIMING_CUDA_EVENTS) {
        CUDA_OR_RETURN(c, cudaEventRecord(c->events[1], c->stream));
        const auto s0 = std::chrono::steady_clock::now();
        CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
        const auto s1 = std::chrono::steady_clock::now();
        ++c->stats.synchronizations;
        c->stats.synchronization_ns +=
            std::chrono::duration_cast<std::chrono::nanoseconds>(s1 - s0).count();
        if (event_ns(c, c->events[0], c->events[1], &elapsed_ns)) return -1;
    } else {
        const auto s0 = std::chrono::steady_clock::now();
        CUDA_OR_RETURN(c, cudaStreamSynchronize(c->stream));
        const auto s1 = std::chrono::steady_clock::now();
        elapsed_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(s1 - c->phase_started).count();
        ++c->stats.synchronizations;
        c->stats.synchronization_ns +=
            std::chrono::duration_cast<std::chrono::nanoseconds>(s1 - s0).count();
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
    Context* c = new (std::nothrow) Context;
    if (!c) return -1;
    *out = c;
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    if (e != cudaSuccess) return fail(c, "cudaGetDeviceCount", e);
    if (count < 1) return fail_message(c, "no CUDA device is available");
    if ((e = cudaStreamCreateWithFlags(&c->stream, cudaStreamNonBlocking)) != cudaSuccess)
        return fail(c, "cudaStreamCreateWithFlags", e);
    for (auto& event : c->events) {
        if ((e = cudaEventCreate(&event)) != cudaSuccess) return fail(c, "cudaEventCreate", e);
    }
    if (select_timing_mode(c)) return -1;
    return 0;
}

extern "C" void volta_cuda_destroy(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return;
    for (auto& b : c->buffers) if (b.ptr) cudaFree(b.ptr);
    for (auto& b : c->resident) if (b.ptr) cudaFree(b.ptr);
    for (auto event : c->events) if (event) cudaEventDestroy(event);
    if (c->stream) cudaStreamDestroy(c->stream);
    delete c;
}

extern "C" const char* volta_cuda_last_error(void* raw) {
    Context* c = static_cast<Context*>(raw);
    return c ? c->error.c_str() : "null CUDA context";
}

extern "C" int volta_cuda_reset_stats(void* raw) {
    Context* c = static_cast<Context*>(raw);
    if (!c) return -1;
    const uint64_t live = c->stats.live_device_bytes;
    const uint32_t timing_mode = c->timing_mode;
    c->stats = RawStats{};
    c->stats.live_device_bytes = live;
    c->stats.peak_device_bytes = live;
    c->stats.timing_mode = timing_mode;
    return 0;
}

extern "C" int volta_cuda_get_stats(void* raw, RawStats* out) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !out) return -1;
    *out = c->stats;
    return 0;
}

extern "C" int volta_cuda_resident_alloc(void* raw, size_t bytes, uint64_t* out_id) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !bytes || !out_id) return fail_message(c, "invalid resident allocation");
    ResidentBuffer b;
    b.id = next_resident_id.fetch_add(1, std::memory_order_relaxed);
    if (b.id == 0) return fail_message(c, "resident buffer id space exhausted");
    CUDA_OR_RETURN(c, cudaMalloc(&b.ptr, bytes));
    b.bytes = bytes;
    c->resident.push_back(b);
    ++c->stats.allocation_calls;
    c->stats.live_device_bytes += bytes;
    c->stats.peak_device_bytes =
        std::max(c->stats.peak_device_bytes, c->stats.live_device_bytes);
    *out_id = b.id;
    return 0;
}

extern "C" int volta_cuda_resident_free(void* raw, uint64_t id) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !id) return fail_message(c, "invalid resident free");
    for (size_t i = 0; i < c->resident.size(); ++i) {
        if (c->resident[i].id != id) continue;
        CUDA_OR_RETURN(c, cudaFree(c->resident[i].ptr));
        c->stats.live_device_bytes -= c->resident[i].bytes;
        c->resident.erase(c->resident.begin() + i);
        return 0;
    }
    return fail_message(c, "unknown resident buffer id");
}

extern "C" int volta_cuda_resident_upload(
    void* raw, uint64_t id, size_t offset_bytes, const void* src, size_t bytes) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !src || !bytes) return fail_message(c, "invalid resident upload");
    void* dst = nullptr;
    if (resident_region(c, id, offset_bytes, bytes, &dst)) return -1;
    if (begin_transfer_timing(c)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(dst, src, bytes, cudaMemcpyHostToDevice, c->stream));
    return finish_transfer_timing(c, bytes, true);
}

extern "C" int volta_cuda_resident_download(
    void* raw, uint64_t id, size_t offset_bytes, void* dst, size_t bytes) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !dst || !bytes) return fail_message(c, "invalid resident download");
    void* src = nullptr;
    if (resident_region(c, id, offset_bytes, bytes, &src)) return -1;
    if (begin_transfer_timing(c)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(dst, src, bytes, cudaMemcpyDeviceToHost, c->stream));
    return finish_transfer_timing(c, bytes, false);
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

extern "C" int volta_cuda_logup_general_round_device(
    void* raw, uint64_t p0_id, size_t p0_offset, uint64_t p1_id, size_t p1_offset,
    uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, size_t pairs, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !pairs || !output)
        return fail_message(c, "invalid resident LogUp round geometry");
    void *p0v = nullptr, *p1v = nullptr, *q0v = nullptr, *q1v = nullptr, *sv = nullptr;
    const size_t vb = 2 * pairs * sizeof(Fp2), sb = pairs * sizeof(Fp2);
    if (resident_region(c, p0_id, p0_offset * sizeof(Fp2), vb, &p0v) ||
        resident_region(c, p1_id, p1_offset * sizeof(Fp2), vb, &p1v) ||
        resident_region(c, q0_id, q0_offset * sizeof(Fp2), vb, &q0v) ||
        resident_region(c, q1_id, q1_offset * sizeof(Fp2), vb, &q1v) ||
        resident_region(c, suffix_id, suffix_offset * sizeof(Fp2), sb, &sv))
        return -1;
    const size_t ab = pairs * sizeof(RoundAcc);
    if (ensure(c, 5, ab) || ensure(c, 6, ab)) return -1;
    if (begin_timing(c)) return -1;
    if (mark_timing(c, 1)) return -1;
    logup_round_eval<<<(pairs + BLOCK - 1) / BLOCK, BLOCK, 0, c->stream>>>(
        static_cast<const Fp2*>(p0v), static_cast<const Fp2*>(p1v),
        static_cast<const Fp2*>(q0v), static_cast<const Fp2*>(q1v),
        static_cast<const Fp2*>(sv), buf<RoundAcc>(c, 5), pairs);
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
    if (mark_timing(c, 2)) return -1;
    CUDA_OR_RETURN(c, cudaMemcpyAsync(output, in, sizeof(RoundAcc), cudaMemcpyDeviceToHost, c->stream));
    return finish_timing(c, OP_LOGUP, 0, sizeof(RoundAcc));
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

extern "C" int volta_cuda_logup_aux_round_device(
    void* raw, uint64_t q0_id, size_t q0_offset, uint64_t q1_id, size_t q1_offset,
    uint64_t suffix_id, size_t suffix_offset, uint64_t columns_id, size_t columns_offset,
    uint64_t eq_id, size_t eq_offset, uint64_t claim_cols_id, size_t claim_cols_offset,
    uint64_t weights_id, size_t weights_offset, size_t column_count, size_t claim_count,
    size_t vector_len, Fp2 lambda, Fp2 cpref, Fp2 point, Fp2* output) {
    Context* c = static_cast<Context*>(raw);
    if (!c || !output || !column_count || vector_len < 2 || (vector_len & 1))
        return fail_message(c, "invalid resident aux-round geometry");
    const size_t pairs = vector_len / 2;
    void *q0 = nullptr, *q1 = nullptr, *suffix = nullptr, *columns = nullptr;
    void *eq = nullptr, *claim_cols = nullptr, *weights = nullptr;
    if (resident_region(c,q0_id,q0_offset*sizeof(Fp2),vector_len*sizeof(Fp2),&q0) ||
        resident_region(c,q1_id,q1_offset*sizeof(Fp2),vector_len*sizeof(Fp2),&q1) ||
        resident_region(c,suffix_id,suffix_offset*sizeof(Fp2),pairs*sizeof(Fp2),&suffix) ||
        resident_region(c,columns_id,columns_offset*sizeof(Fp2),
                        2*column_count*vector_len*sizeof(Fp2),&columns) ||
        (claim_count && resident_region(c,eq_id,eq_offset*sizeof(Fp2),
                                       claim_count*vector_len*sizeof(Fp2),&eq)) ||
        (claim_count && resident_region(c,claim_cols_id,claim_cols_offset*sizeof(uint32_t),
                                       claim_count*sizeof(uint32_t),&claim_cols)) ||
        (claim_count && resident_region(c,weights_id,weights_offset*sizeof(Fp2),
                                       2*claim_count*sizeof(Fp2),&weights)))
        return -1;
    const size_t bytes=pairs*sizeof(AuxRoundAcc);
    if(ensure(c,12,bytes)||ensure(c,13,bytes)||ensure(c,14,3*sizeof(Fp2)))return -1;
    if(begin_timing(c))return -1;if(mark_timing(c,1))return -1;
    logup_aux_round_eval<<<(pairs+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(
        static_cast<const Fp2*>(q0),static_cast<const Fp2*>(q1),
        static_cast<const Fp2*>(suffix),static_cast<const Fp2*>(columns),
        static_cast<const Fp2*>(eq),static_cast<const uint32_t*>(claim_cols),
        static_cast<const Fp2*>(weights),column_count,claim_count,vector_len,pairs,
        buf<AuxRoundAcc>(c,12));
    size_t count=pairs;AuxRoundAcc* in=buf<AuxRoundAcc>(c,12);AuxRoundAcc* out=buf<AuxRoundAcc>(c,13);
    while(count>1){const size_t blocks=(count+BLOCK-1)/BLOCK;
        reduce_aux_round<<<blocks,BLOCK,0,c->stream>>>(in,out,count);count=blocks;std::swap(in,out);}
    assemble_aux_round<<<1,1,0,c->stream>>>(in,buf<Fp2>(c,14),lambda,cpref,point);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;
    CUDA_OR_RETURN(c,cudaMemcpyAsync(output,buf<Fp2>(c,14),3*sizeof(Fp2),
                                     cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_LOGUP,0,3*sizeof(Fp2));
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
