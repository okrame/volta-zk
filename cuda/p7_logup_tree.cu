#include <cuda_runtime.h>
#include <omp.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;

struct alignas(16) Fp2 {
    uint64_t c0;
    uint64_t c1;
};

#define CUDA_CHECK(call)                                                                    \
    do {                                                                                    \
        cudaError_t err__ = (call);                                                         \
        if (err__ != cudaSuccess) {                                                         \
            std::cerr << #call << ": " << cudaGetErrorString(err__) << "\n";               \
            std::exit(2);                                                                   \
        }                                                                                   \
    } while (0)

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

__host__ __device__ inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    return Fp2{fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    return Fp2{
        fp_add(fp_mul(a.c0, b.c0), fp_mul(7, fp_mul(a.c1, b.c1))),
        fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
    };
}

__global__ void first_combine_kernel(
    const uint64_t* leaf_a, Fp2* out_p, Fp2* out_q, size_t pairs, uint64_t alpha1,
    uint64_t w7a1sq) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const uint64_t a = leaf_a[2 * i];
    const uint64_t b = leaf_a[2 * i + 1];
    const uint64_t sum = fp_add(a, b);
    out_p[i] = Fp2{sum, fp_add(alpha1, alpha1)};
    out_q[i] = Fp2{fp_add(fp_mul(a, b), w7a1sq), fp_mul(sum, alpha1)};
}

__global__ void general_combine_kernel(
    const Fp2* in_p, const Fp2* in_q, Fp2* out_p, Fp2* out_q, size_t pairs) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2 pa = in_p[2 * i];
    const Fp2 pb = in_p[2 * i + 1];
    const Fp2 qa = in_q[2 * i];
    const Fp2 qb = in_q[2 * i + 1];
    out_p[i] = fp2_add(fp2_mul(pa, qb), fp2_mul(pb, qa));
    out_q[i] = fp2_mul(qa, qb);
}

struct Buffers {
    Fp2* p0;
    Fp2* q0;
    Fp2* p1;
    Fp2* q1;
};

std::pair<Fp2*, Fp2*> launch_gpu_tree(
    const uint64_t* leaf, Buffers b, size_t n, uint64_t alpha1, uint64_t w7a1sq) {
    constexpr int block = 256;
    size_t len = n / 2;
    first_combine_kernel<<<(len + block - 1) / block, block>>>(
        leaf, b.p0, b.q0, len, alpha1, w7a1sq);
    CUDA_CHECK(cudaGetLastError());
    bool in_zero = true;
    while (len > 1) {
        const size_t pairs = len / 2;
        Fp2* in_p = in_zero ? b.p0 : b.p1;
        Fp2* in_q = in_zero ? b.q0 : b.q1;
        Fp2* out_p = in_zero ? b.p1 : b.p0;
        Fp2* out_q = in_zero ? b.q1 : b.q0;
        general_combine_kernel<<<(pairs + block - 1) / block, block>>>(
            in_p, in_q, out_p, out_q, pairs);
        CUDA_CHECK(cudaGetLastError());
        in_zero = !in_zero;
        len = pairs;
    }
    return in_zero ? std::make_pair(b.p0, b.q0) : std::make_pair(b.p1, b.q1);
}

struct HostBuffers {
    std::vector<Fp2> p0;
    std::vector<Fp2> q0;
    std::vector<Fp2> p1;
    std::vector<Fp2> q1;
};

std::pair<Fp2, Fp2> run_cpu_tree(
    const std::vector<uint64_t>& leaf, HostBuffers& b, uint64_t alpha1, uint64_t w7a1sq) {
    size_t len = leaf.size() / 2;
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = leaf[2 * i];
        const uint64_t c = leaf[2 * i + 1];
        const uint64_t sum = fp_add(a, c);
        b.p0[i] = Fp2{sum, fp_add(alpha1, alpha1)};
        b.q0[i] = Fp2{fp_add(fp_mul(a, c), w7a1sq), fp_mul(sum, alpha1)};
    }
    bool in_zero = true;
    while (len > 1) {
        const size_t pairs = len / 2;
        auto& in_p = in_zero ? b.p0 : b.p1;
        auto& in_q = in_zero ? b.q0 : b.q1;
        auto& out_p = in_zero ? b.p1 : b.p0;
        auto& out_q = in_zero ? b.q1 : b.q0;
#pragma omp parallel for schedule(static)
        for (size_t i = 0; i < pairs; ++i) {
            out_p[i] = fp2_add(
                fp2_mul(in_p[2 * i], in_q[2 * i + 1]),
                fp2_mul(in_p[2 * i + 1], in_q[2 * i]));
            out_q[i] = fp2_mul(in_q[2 * i], in_q[2 * i + 1]);
        }
        in_zero = !in_zero;
        len = pairs;
    }
    const auto& root_p = in_zero ? b.p0 : b.p1;
    const auto& root_q = in_zero ? b.q0 : b.q1;
    return {root_p[0], root_q[0]};
}

template <typename F>
double median_seconds(int reps, F&& f) {
    f();
    std::vector<double> samples;
    samples.reserve(reps);
    for (int rep = 0; rep < reps; ++rep) {
        const auto t0 = std::chrono::steady_clock::now();
        f();
        const auto t1 = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration<double>(t1 - t0).count());
    }
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

uint64_t hash_fp2(uint64_t h, Fp2 x) {
    h ^= x.c0;
    h *= 0x0000'0100'0000'01B3ULL;
    h ^= x.c1;
    h *= 0x0000'0100'0000'01B3ULL;
    return h;
}

bool equal_fp2(Fp2 a, Fp2 b) {
    return a.c0 == b.c0 && a.c1 == b.c1;
}

std::string hex64(uint64_t x) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << x;
    return out.str();
}

std::string json_escape(const char* s) {
    std::ostringstream out;
    for (; *s; ++s) {
        if (*s == '"' || *s == '\\') out << '\\';
        out << *s;
    }
    return out.str();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: " << argv[0] << " LOG2_N GPU_REPS CPU_REPS CPU_THREADS\n";
        return 2;
    }
    const int log2_n = std::stoi(argv[1]);
    const int gpu_reps = std::stoi(argv[2]);
    const int cpu_reps = std::stoi(argv[3]);
    const int cpu_threads = std::stoi(argv[4]);
    const size_t n = size_t{1} << log2_n;
    const size_t half = n / 2;
    omp_set_dynamic(0);
    omp_set_num_threads(cpu_threads);

    const uint64_t alpha0 = 0x1234'5678'9ABC'DEF0ULL;
    const uint64_t alpha1 = 0x0FED'CBA9'8765'4321ULL;
    const uint64_t w7a1sq = fp_mul(7, fp_mul(alpha1, alpha1));
    std::vector<uint64_t> leaf(n);
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < n; ++i) {
        const int16_t value = static_cast<int16_t>((i * 37 + 11) & 0xFFFF);
        const uint64_t x = value >= 0 ? static_cast<uint64_t>(value)
                                      : P - static_cast<uint64_t>(-static_cast<int64_t>(value));
        leaf[i] = fp_sub(alpha0, x);
    }

    HostBuffers host{
        std::vector<Fp2>(half),
        std::vector<Fp2>(half),
        std::vector<Fp2>(half),
        std::vector<Fp2>(half),
    };
    const auto cpu_root = run_cpu_tree(leaf, host, alpha1, w7a1sq);
    const double cpu_s = median_seconds(cpu_reps, [&] {
        run_cpu_tree(leaf, host, alpha1, w7a1sq);
    });

    uint64_t* d_leaf = nullptr;
    Buffers d{};
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_leaf), n * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d.p0), half * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d.q0), half * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d.p1), half * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d.q1), half * sizeof(Fp2)));
    CUDA_CHECK(cudaMemcpy(d_leaf, leaf.data(), n * sizeof(uint64_t), cudaMemcpyHostToDevice));

    Fp2 gpu_root[2]{};
    auto gpu_tree = [&] {
        const auto roots = launch_gpu_tree(d_leaf, d, n, alpha1, w7a1sq);
        CUDA_CHECK(cudaMemcpy(&gpu_root[0], roots.first, sizeof(Fp2), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(&gpu_root[1], roots.second, sizeof(Fp2), cudaMemcpyDeviceToHost));
    };
    const double gpu_s = median_seconds(gpu_reps, gpu_tree);

    // Differential validation of every internal p/q element, outside timing.
    std::vector<Fp2> expected_p(half), expected_q(half), gpu_p(half), gpu_q(half);
    constexpr int block = 256;
    size_t len = half;
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = leaf[2 * i];
        const uint64_t b = leaf[2 * i + 1];
        const uint64_t sum = fp_add(a, b);
        expected_p[i] = Fp2{sum, fp_add(alpha1, alpha1)};
        expected_q[i] = Fp2{fp_add(fp_mul(a, b), w7a1sq), fp_mul(sum, alpha1)};
    }
    first_combine_kernel<<<(len + block - 1) / block, block>>>(
        d_leaf, d.p0, d.q0, len, alpha1, w7a1sq);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaMemcpy(gpu_p.data(), d.p0, len * sizeof(Fp2), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(gpu_q.data(), d.q0, len * sizeof(Fp2), cudaMemcpyDeviceToHost));
    bool correct = true;
    uint64_t checksum = 0xCBF2'9CE4'8422'2325ULL;
    for (size_t i = 0; i < len; ++i) {
        correct = correct && equal_fp2(expected_p[i], gpu_p[i]) && equal_fp2(expected_q[i], gpu_q[i]);
        checksum = hash_fp2(hash_fp2(checksum, gpu_p[i]), gpu_q[i]);
    }
    bool in_zero = true;
    while (correct && len > 1) {
        const size_t pairs = len / 2;
        for (size_t i = 0; i < pairs; ++i) {
            expected_p[i] = fp2_add(
                fp2_mul(gpu_p[2 * i], gpu_q[2 * i + 1]),
                fp2_mul(gpu_p[2 * i + 1], gpu_q[2 * i]));
            expected_q[i] = fp2_mul(gpu_q[2 * i], gpu_q[2 * i + 1]);
        }
        Fp2* in_p = in_zero ? d.p0 : d.p1;
        Fp2* in_q = in_zero ? d.q0 : d.q1;
        Fp2* out_p = in_zero ? d.p1 : d.p0;
        Fp2* out_q = in_zero ? d.q1 : d.q0;
        general_combine_kernel<<<(pairs + block - 1) / block, block>>>(
            in_p, in_q, out_p, out_q, pairs);
        CUDA_CHECK(cudaGetLastError());
        CUDA_CHECK(cudaMemcpy(gpu_p.data(), out_p, pairs * sizeof(Fp2), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(gpu_q.data(), out_q, pairs * sizeof(Fp2), cudaMemcpyDeviceToHost));
        for (size_t i = 0; i < pairs; ++i) {
            correct = correct && equal_fp2(expected_p[i], gpu_p[i]) && equal_fp2(expected_q[i], gpu_q[i]);
            checksum = hash_fp2(hash_fp2(checksum, gpu_p[i]), gpu_q[i]);
        }
        in_zero = !in_zero;
        len = pairs;
    }
    correct = correct && equal_fp2(cpu_root.first, gpu_root[0]) && equal_fp2(cpu_root.second, gpu_root[1]);
    const double speedup = cpu_s / gpu_s;
    const bool timing_sane = gpu_s > 0.0 && speedup < 10000.0;
    const bool gate = correct && timing_sane && speedup >= 5.48;

    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    CUDA_CHECK(cudaFree(d_leaf));
    CUDA_CHECK(cudaFree(d.p0));
    CUDA_CHECK(cudaFree(d.q0));
    CUDA_CHECK(cudaFree(d.p1));
    CUDA_CHECK(cudaFree(d.q1));

    const uint64_t general_pairs = half - 1;
    std::cout << std::setprecision(12) << "{\n"
              << "  \"correctness\": " << (correct ? "true" : "false") << ",\n"
              << "  \"timing_sane\": " << (timing_sane ? "true" : "false") << ",\n"
              << "  \"gate_speedup_ge_5_48\": " << (gate ? "true" : "false") << ",\n"
              << "  \"cpu_s\": " << cpu_s << ", \"gpu_s\": " << gpu_s
              << ", \"gpu_cpu_speedup\": " << speedup << ",\n"
              << "  \"root_p\": {\"c0\": " << gpu_root[0].c0 << ", \"c1\": " << gpu_root[0].c1
              << "}, \"root_q\": {\"c0\": " << gpu_root[1].c0 << ", \"c1\": " << gpu_root[1].c1
              << "}, \"all_layers_checksum\": \"" << hex64(checksum) << "\",\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem << "},\n"
              << "  \"parameters\": {\"log2_n\": " << log2_n << ", \"n\": " << n
              << ", \"depth\": " << log2_n << ", \"gpu_reps\": " << gpu_reps
              << ", \"cpu_reps\": " << cpu_reps << ", \"cpu_threads\": " << cpu_threads
              << ", \"leaf_side\": \"ones\", \"completion_d2h_bytes\": 32},\n"
              << "  \"operation_counts\": {\"first_level_pairs\": " << half
              << ", \"first_level_base_mults\": " << 2 * half
              << ", \"general_pairs\": " << general_pairs
              << ", \"general_fp2_mults\": " << 3 * general_pairs << "}\n"
              << "}\n";
    return (correct && timing_sane) ? 0 : 1;
}
