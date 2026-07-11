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
#include <vector>

namespace {

constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;
constexpr int BLOCK = 256;

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

uint64_t fp_pow(uint64_t base, uint64_t exponent) {
    uint64_t acc = 1;
    while (exponent != 0) {
        if (exponent & 1) acc = fp_mul(acc, base);
        base = fp_mul(base, base);
        exponent >>= 1;
    }
    return acc;
}

__host__ __device__ inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    return Fp2{fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 mul_base(Fp2 a, uint64_t b) {
    return Fp2{fp_mul(a.c0, b), fp_mul(a.c1, b)};
}

uint64_t reverse_bits(uint64_t x, int bits) {
    x = ((x & 0x5555'5555'5555'5555ULL) << 1) | ((x >> 1) & 0x5555'5555'5555'5555ULL);
    x = ((x & 0x3333'3333'3333'3333ULL) << 2) | ((x >> 2) & 0x3333'3333'3333'3333ULL);
    x = ((x & 0x0F0F'0F0F'0F0F'0F0FULL) << 4) | ((x >> 4) & 0x0F0F'0F0F'0F0F'0F0FULL);
    x = ((x & 0x00FF'00FF'00FF'00FFULL) << 8) | ((x >> 8) & 0x00FF'00FF'00FF'00FFULL);
    x = ((x & 0x0000'FFFF'0000'FFFFULL) << 16) | ((x >> 16) & 0x0000'FFFF'0000'FFFFULL);
    x = (x << 32) | (x >> 32);
    return x >> (64 - bits);
}

__global__ void bit_reverse_kernel(
    const uint64_t* in, uint64_t* out, size_t rows, size_t n, int bits) {
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = rows * n;
    if (idx >= total) return;
    const size_t row = idx / n;
    const uint64_t j = idx - row * n;
    const uint64_t rev = __brevll(j) >> (64 - bits);
    out[row * n + rev] = in[idx];
}

__global__ void ntt_stage_kernel(
    uint64_t* values, const uint64_t* twiddles, size_t rows, size_t n, int len) {
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t per_row = n / 2;
    const size_t total = rows * per_row;
    if (idx >= total) return;
    const size_t row = idx / per_row;
    const size_t local = idx - row * per_row;
    const size_t half = len / 2;
    const size_t group = local / half;
    const size_t k = local - group * half;
    const size_t start = row * n + group * len;
    const size_t i0 = start + k;
    const size_t i1 = i0 + half;
    const uint64_t u = values[i0];
    const uint64_t v = fp_mul(values[i1], twiddles[k * (n / len)]);
    values[i0] = fp_add(u, v);
    values[i1] = fp_sub(u, v);
}

__global__ void combine_rows_kernel(
    const uint64_t* weights, const Fp2* q, const Fp2* c, Fp2* uq, Fp2* uc,
    size_t rows, size_t cols) {
    const size_t j = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (j >= cols) return;
    Fp2 aq{}, ac{};
    for (size_t i = 0; i < rows; ++i) {
        const uint64_t x = weights[i * cols + j];
        aq = fp2_add(aq, mul_base(q[i], x));
        ac = fp2_add(ac, mul_base(c[i], x));
    }
    uq[j] = aq;
    uc[j] = ac;
}

template <typename Reset, typename Run>
double median_seconds(int reps, Reset&& reset, Run&& run) {
    reset();
    run();
    std::vector<double> samples;
    samples.reserve(reps);
    for (int rep = 0; rep < reps; ++rep) {
        reset();
        const auto t0 = std::chrono::steady_clock::now();
        run();
        const auto t1 = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration<double>(t1 - t0).count());
    }
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

uint64_t hash_u64(uint64_t h, uint64_t x) {
    h ^= x;
    h *= 0x0000'0100'0000'01B3ULL;
    return h;
}

uint64_t checksum(const std::vector<uint64_t>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (uint64_t x : values) h = hash_u64(h, x);
    return h;
}

uint64_t checksum(const std::vector<Fp2>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (Fp2 x : values) h = hash_u64(hash_u64(h, x.c0), x.c1);
    return h;
}

bool equal_fp2_vectors(const std::vector<Fp2>& a, const std::vector<Fp2>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].c0 != b[i].c0 || a[i].c1 != b[i].c1) return false;
    }
    return true;
}

std::string hex64(uint64_t x) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << x;
    return out.str();
}

std::string hex64(uint64_t x) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << x;
    return out.str();
}

struct PassResult {
    double cpu_s;
    double gpu_s;
    double speedup;
    bool correct;
    bool timing_sane;
    uint64_t checksum;
};

PassResult run_ntt(
    size_t rows, int bits, size_t msg_len, int gpu_reps, int cpu_reps) {
    const size_t n = size_t{1} << bits;
    const size_t total = rows * n;
    std::vector<uint64_t> input(total), cpu(total), gpu(total), twiddles(n / 2);
#pragma omp parallel for schedule(static)
    for (size_t idx = 0; idx < total; ++idx) {
        const size_t j = idx % n;
        input[idx] = j < msg_len ? (idx * 0x9E37'79B9ULL + 17) % P : 0;
    }
    const uint64_t root = fp_pow(7, (P - 1) >> bits);
    twiddles[0] = 1;
    for (size_t i = 1; i < n / 2; ++i) twiddles[i] = fp_mul(twiddles[i - 1], root);

    auto cpu_run = [&] {
#pragma omp parallel for schedule(static)
        for (size_t row = 0; row < rows; ++row) {
            const size_t base = row * n;
            for (size_t j = 0; j < n; ++j) cpu[base + reverse_bits(j, bits)] = input[base + j];
            for (size_t len = 2; len <= n; len *= 2) {
                const size_t step = n / len;
                for (size_t start = 0; start < n; start += len) {
                    for (size_t k = 0; k < len / 2; ++k) {
                        const uint64_t u = cpu[base + start + k];
                        const uint64_t v = fp_mul(cpu[base + start + k + len / 2], twiddles[k * step]);
                        cpu[base + start + k] = fp_add(u, v);
                        cpu[base + start + k + len / 2] = fp_sub(u, v);
                    }
                }
            }
        }
    };
    const double cpu_s = median_seconds(cpu_reps, [] {}, cpu_run);

    uint64_t *d_input = nullptr, *d_output = nullptr, *d_twiddles = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_input), total * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_output), total * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_twiddles), (n / 2) * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(d_input, input.data(), total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(
        d_twiddles, twiddles.data(), (n / 2) * sizeof(uint64_t), cudaMemcpyHostToDevice));
    auto gpu_run = [&] {
        bit_reverse_kernel<<<(total + BLOCK - 1) / BLOCK, BLOCK>>>(d_input, d_output, rows, n, bits);
        CUDA_CHECK(cudaGetLastError());
        for (size_t len = 2; len <= n; len *= 2) {
            const size_t butterflies = rows * n / 2;
            ntt_stage_kernel<<<(butterflies + BLOCK - 1) / BLOCK, BLOCK>>>(
                d_output, d_twiddles, rows, n, static_cast<int>(len));
            CUDA_CHECK(cudaGetLastError());
        }
        uint64_t completion[2]{};
        CUDA_CHECK(cudaMemcpy(
            completion, d_output + total - 2, sizeof(completion), cudaMemcpyDeviceToHost));
    };
    const double gpu_s = median_seconds(gpu_reps, [] {}, gpu_run);
    CUDA_CHECK(cudaMemcpy(gpu.data(), d_output, total * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    const bool correct = cpu == gpu;
    CUDA_CHECK(cudaFree(d_input));
    CUDA_CHECK(cudaFree(d_output));
    CUDA_CHECK(cudaFree(d_twiddles));
    const double speedup = cpu_s / gpu_s;
    return PassResult{cpu_s, gpu_s, speedup, correct, gpu_s > 0 && speedup < 10000, checksum(gpu)};
}

PassResult run_combine(size_t rows, size_t cols, int gpu_reps, int cpu_reps) {
    const size_t total = rows * cols;
    std::vector<uint64_t> weights(total);
    std::vector<Fp2> q(rows), c(rows), cpu_q(cols), cpu_c(cols), gpu_q(cols), gpu_c(cols);
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < total; ++i) weights[i] = (i * 0x85EB'CA6BULL + 29) % P;
    for (size_t i = 0; i < rows; ++i) {
        q[i] = Fp2{(i * 37 + 11) % P, (i * 53 + 5) % P};
        c[i] = Fp2{(i * 71 + 7) % P, (i * 97 + 13) % P};
    }
    auto cpu_run = [&] {
#pragma omp parallel for schedule(static)
        for (size_t j = 0; j < cols; ++j) {
            Fp2 aq{}, ac{};
            for (size_t i = 0; i < rows; ++i) {
                const uint64_t x = weights[i * cols + j];
                aq = fp2_add(aq, mul_base(q[i], x));
                ac = fp2_add(ac, mul_base(c[i], x));
            }
            cpu_q[j] = aq;
            cpu_c[j] = ac;
        }
    };
    const double cpu_s = median_seconds(cpu_reps, [] {}, cpu_run);

    uint64_t* d_weights = nullptr;
    Fp2 *d_q = nullptr, *d_c = nullptr, *d_uq = nullptr, *d_uc = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_weights), total * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_q), rows * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_c), rows * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_uq), cols * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_uc), cols * sizeof(Fp2)));
    CUDA_CHECK(cudaMemcpy(d_weights, weights.data(), total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_q, q.data(), rows * sizeof(Fp2), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_c, c.data(), rows * sizeof(Fp2), cudaMemcpyHostToDevice));
    auto gpu_run = [&] {
        combine_rows_kernel<<<(cols + BLOCK - 1) / BLOCK, BLOCK>>>(
            d_weights, d_q, d_c, d_uq, d_uc, rows, cols);
        CUDA_CHECK(cudaGetLastError());
        Fp2 completion[2]{};
        CUDA_CHECK(cudaMemcpy(&completion[0], d_uq + cols - 1, sizeof(Fp2), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemcpy(&completion[1], d_uc + cols - 1, sizeof(Fp2), cudaMemcpyDeviceToHost));
    };
    const double gpu_s = median_seconds(gpu_reps, [] {}, gpu_run);
    CUDA_CHECK(cudaMemcpy(gpu_q.data(), d_uq, cols * sizeof(Fp2), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(gpu_c.data(), d_uc, cols * sizeof(Fp2), cudaMemcpyDeviceToHost));
    const bool correct = equal_fp2_vectors(cpu_q, gpu_q) && equal_fp2_vectors(cpu_c, gpu_c);
    CUDA_CHECK(cudaFree(d_weights));
    CUDA_CHECK(cudaFree(d_q));
    CUDA_CHECK(cudaFree(d_c));
    CUDA_CHECK(cudaFree(d_uq));
    CUDA_CHECK(cudaFree(d_uc));
    const double speedup = cpu_s / gpu_s;
    const uint64_t sum = checksum(gpu_q) ^ (checksum(gpu_c) * 0x9E37'79B9'7F4A'7C15ULL);
    return PassResult{cpu_s, gpu_s, speedup, correct, gpu_s > 0 && speedup < 10000, sum};
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
    if (argc != 8) {
        std::cerr << "usage: " << argv[0]
                  << " ROWS CODE_BITS MSG_LEN COLS GPU_REPS CPU_REPS CPU_THREADS\n";
        return 2;
    }
    const size_t rows = std::stoull(argv[1]);
    const int code_bits = std::stoi(argv[2]);
    const size_t msg_len = std::stoull(argv[3]);
    const size_t cols = std::stoull(argv[4]);
    const int gpu_reps = std::stoi(argv[5]);
    const int cpu_reps = std::stoi(argv[6]);
    const int cpu_threads = std::stoi(argv[7]);
    omp_set_dynamic(0);
    omp_set_num_threads(cpu_threads);

    const PassResult ntt = run_ntt(rows, code_bits, msg_len, gpu_reps, cpu_reps);
    const PassResult combine = run_combine(rows, cols, gpu_reps, cpu_reps);
    const bool correctness = ntt.correct && combine.correct;
    const bool timing_sane = ntt.timing_sane && combine.timing_sane;
    const bool gate = correctness && timing_sane && ntt.speedup >= 5.48 && combine.speedup >= 5.48;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    const size_t code_len = size_t{1} << code_bits;

    std::cout << std::setprecision(12) << "{\n"
              << "  \"correctness\": " << (correctness ? "true" : "false") << ",\n"
              << "  \"timing_sane\": " << (timing_sane ? "true" : "false") << ",\n"
              << "  \"gate_each_speedup_ge_5_48\": " << (gate ? "true" : "false") << ",\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem << "},\n"
              << "  \"parameters\": {\"rows\": " << rows << ", \"code_bits\": " << code_bits
              << ", \"code_len\": " << code_len << ", \"msg_len\": " << msg_len
              << ", \"cols\": " << cols << ", \"gpu_reps\": " << gpu_reps
              << ", \"cpu_reps\": " << cpu_reps << ", \"cpu_threads\": " << cpu_threads << "},\n"
              << "  \"ntt\": {\"cpu_s\": " << ntt.cpu_s << ", \"gpu_s\": " << ntt.gpu_s
              << ", \"gpu_cpu_speedup\": " << ntt.speedup << ", \"correct\": "
              << (ntt.correct ? "true" : "false") << ", \"checksum\": \"" << hex64(ntt.checksum)
              << "\", \"butterflies\": " << rows * (code_len / 2) * code_bits
              << ", \"resident_bytes\": " << rows * code_len * 8 << "},\n"
              << "  \"combine_rows\": {\"cpu_s\": " << combine.cpu_s << ", \"gpu_s\": "
              << combine.gpu_s << ", \"gpu_cpu_speedup\": " << combine.speedup
              << ", \"correct\": " << (combine.correct ? "true" : "false")
              << ", \"checksum\": \"" << hex64(combine.checksum)
              << "\", \"base_mul_equiv\": " << rows * cols * 4
              << ", \"weight_bytes\": " << rows * cols * 8 << "}\n"
              << "}\n";
    return (correctness && timing_sane) ? 0 : 1;
}
