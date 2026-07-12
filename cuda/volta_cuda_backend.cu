#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

namespace volta_cuda_internal {

constexpr uint32_t ABI_VERSION = 2;
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

struct Context {
    cudaStream_t stream = nullptr;
    cudaEvent_t events[4]{};
    Buffer buffers[BUFFER_COUNT];
    RawStats stats{};
    size_t twiddle_size = 0;
    uint32_t timing_mode = TIMING_CUDA_EVENTS;
    std::chrono::steady_clock::time_point phase_started{};
    std::array<uint64_t, 3> phase_ns{};
    std::string error;
};

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
    c->stats.h2d_ns += h2d_ns;
    c->stats.kernel_ns[operation] += kernel_ns;
    c->stats.d2h_ns += d2h_ns;
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

// -------------------------------------------------------------------------
// PCS row combinations and selected-column gather
// -------------------------------------------------------------------------

__host__ __device__ inline uint64_t fp_from_i16(int16_t x) {
    return x >= 0 ? static_cast<uint64_t>(x) : P - static_cast<uint64_t>(-static_cast<int64_t>(x));
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
__device__ HashOutput chunk_output_column(const uint64_t* matrix,size_t rows,size_t cols,size_t col,size_t chunk) {
    HashOutput o{};uint32_t cv[8];for(int i=0;i<8;++i)cv[i]=iv(i);
    const size_t row0=chunk*128, take=min(size_t{128},rows-row0);const int blocks=take/8;
    for(int b=0;b<blocks;++b){uint32_t words[16];for(int i=0;i<8;++i){
        const uint64_t x=matrix[(row0+b*8+i)*cols+col];words[2*i]=x;words[2*i+1]=x>>32;}
        const uint32_t flags=(b==0?CHUNK_START:0)|(b+1==blocks?CHUNK_END:0);
        if(b+1==blocks){for(int i=0;i<8;++i)o.cv[i]=cv[i];for(int i=0;i<16;++i)o.block[i]=words[i];
            o.counter=chunk;o.block_len=64;o.flags=flags;}
        else{uint32_t v[16];compress(cv,words,chunk,64,flags,v);for(int i=0;i<8;++i)cv[i]=v[i];}
    }return o;
}
__device__ Hash32 hash_column(const uint64_t* matrix,size_t rows,size_t cols,size_t col) {
    const size_t chunks=(rows+127)/128;Hash32 stack[16];int depth=0;HashOutput root_out{},single{};
    for(size_t c=0;c<chunks;++c){HashOutput co=chunk_output_column(matrix,rows,cols,col,c);if(chunks==1)single=co;
        Hash32 cv=chaining_value(co);size_t total=c;
        while(total&1){root_out=parent_output(stack[--depth],cv);cv=chaining_value(root_out);total>>=1;}
        stack[depth++]=cv;}
    if(chunks==1)return root_hash(single);Hash32 cv=stack[--depth];
    while(depth){root_out=parent_output(stack[--depth],cv);cv=chaining_value(root_out);}return root_hash(root_out);
}
__global__ void hash_columns_kernel(const uint64_t* matrix,Hash32* leaves,size_t rows,size_t cols) {
    const size_t col=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(col<cols)leaves[col]=hash_column(matrix,rows,cols,col);
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

extern "C" int volta_cuda_logup_fold4(void* raw,const Fp2* p0,const Fp2* p1,const Fp2* q0,const Fp2* q1,
    size_t pairs,Fp2 r,Fp2* o0,Fp2* o1,Fp2* o2,Fp2* o3) {
    Context* c=static_cast<Context*>(raw);if(!c||!p0||!p1||!q0||!q1||!o0||!o1||!o2||!o3||!pairs)return -1;
    const size_t ib=2*pairs*sizeof(Fp2),ob=pairs*sizeof(Fp2);for(int i=0;i<4;++i)if(ensure(c,i,ib)||ensure(c,4+i,ob))return -1;
    if(begin_timing(c))return -1;const Fp2* src[4]={p0,p1,q0,q1};for(int i=0;i<4;++i)CUDA_OR_RETURN(c,cudaMemcpyAsync(buf<Fp2>(c,i),src[i],ib,cudaMemcpyHostToDevice,c->stream));
    if(mark_timing(c,1))return -1;logup_fold<<<(pairs+BLOCK-1)/BLOCK,BLOCK,0,c->stream>>>(buf<Fp2>(c,0),buf<Fp2>(c,1),buf<Fp2>(c,2),buf<Fp2>(c,3),buf<Fp2>(c,4),buf<Fp2>(c,5),buf<Fp2>(c,6),buf<Fp2>(c,7),pairs,r);
    CUDA_OR_RETURN(c,cudaPeekAtLastError());if(mark_timing(c,2))return -1;Fp2* dst[4]={o0,o1,o2,o3};for(int i=0;i<4;++i)CUDA_OR_RETURN(c,cudaMemcpyAsync(dst[i],buf<Fp2>(c,4+i),ob,cudaMemcpyDeviceToHost,c->stream));
    return finish_timing(c,OP_LOGUP,4*ib,4*ob);
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
