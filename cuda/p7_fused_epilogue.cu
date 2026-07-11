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

__host__ __device__ inline uint64_t fp_from_i16(int16_t x) {
    return x >= 0 ? static_cast<uint64_t>(x) : P - static_cast<uint64_t>(-static_cast<int64_t>(x));
}

__host__ __device__ inline int16_t requant(int64_t acc, int shift) {
    int64_t rounded = (acc + (int64_t{1} << (shift - 1))) >> shift;
    if (rounded < -32768) rounded = -32768;
    if (rounded > 32767) rounded = 32767;
    return static_cast<int16_t>(rounded);
}

template <bool FUSED>
__global__ void gemm_requant_kernel(
    const int16_t* a,
    const int16_t* b,
    const uint64_t* masks,
    int16_t* out,
    uint64_t* corrections,
    int m,
    int k,
    int n,
    int shift) {
    const int j = blockIdx.x * blockDim.x + threadIdx.x;
    const int i = blockIdx.y * blockDim.y + threadIdx.y;
    if (i >= m || j >= n) return;
    int64_t acc = 0;
    for (int l = 0; l < k; ++l) {
        acc += static_cast<int64_t>(a[i * k + l]) * static_cast<int64_t>(b[l * n + j]);
    }
    const int idx = i * n + j;
    const int16_t y = requant(acc, shift);
    out[idx] = y;
    if constexpr (FUSED) corrections[idx] = fp_sub(fp_from_i16(y), masks[idx]);
}

template <typename F>
double cpu_median(int reps, F&& f) {
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

template <typename F>
double timed_gpu_launch(F&& launch, const int16_t* d_out, size_t output_elems) {
    int16_t completion[8]{};
    const auto t0 = std::chrono::steady_clock::now();
    launch();
    CUDA_CHECK(cudaMemcpy(
        completion, d_out + output_elems - 8, sizeof(completion), cudaMemcpyDeviceToHost));
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(t1 - t0).count();
}

struct PairedTiming {
    double native_s;
    double fused_s;
};

template <typename N, typename F>
PairedTiming gpu_abba(int warmups, int rounds, N&& native, F&& fused) {
    for (int i = 0; i < warmups; ++i) {
        native();
        fused();
    }
    std::vector<double> tn, tf;
    tn.reserve(2 * rounds);
    tf.reserve(2 * rounds);
    for (int i = 0; i < rounds; ++i) {
        tn.push_back(native());
        tf.push_back(fused());
        tf.push_back(fused());
        tn.push_back(native());
    }
    std::sort(tn.begin(), tn.end());
    std::sort(tf.begin(), tf.end());
    return PairedTiming{tn[tn.size() / 2], tf[tf.size() / 2]};
}

uint64_t checksum_i16(const std::vector<int16_t>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (int16_t x : values) {
        h ^= static_cast<uint16_t>(x);
        h *= 0x0000'0100'0000'01B3ULL;
    }
    return h;
}

uint64_t checksum_u64(const std::vector<uint64_t>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (uint64_t x : values) {
        h ^= x;
        h *= 0x0000'0100'0000'01B3ULL;
    }
    return h;
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

struct ShapeResult {
    int n;
    double cpu_native_s;
    double gpu_native_s;
    double gpu_fused_s;
    double rho;
    bool correct;
    uint64_t out_checksum;
    uint64_t corr_checksum;
};

ShapeResult run_shape(int m, int k, int n, int shift, int gpu_rounds, int cpu_reps) {
    const size_t a_len = static_cast<size_t>(m) * k;
    const size_t b_len = static_cast<size_t>(k) * n;
    const size_t out_len = static_cast<size_t>(m) * n;
    std::vector<int16_t> a(a_len), b(b_len), cpu_out(out_len), native_out(out_len),
        fused_out(out_len);
    std::vector<uint64_t> masks(out_len), cpu_corr(out_len), fused_corr(out_len);
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < a_len; ++i) a[i] = static_cast<int16_t>((i * 37 + 11) % 4001) - 2000;
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < b_len; ++i) b[i] = static_cast<int16_t>((i * 53 + 5) % 4001) - 2000;
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < out_len; ++i) masks[i] = (i * 0x9E37'79B9ULL + 17) % P;

    auto cpu_reference = [&] {
#pragma omp parallel for collapse(2) schedule(static)
        for (int i = 0; i < m; ++i) {
            for (int j = 0; j < n; ++j) {
                int64_t acc = 0;
                for (int l = 0; l < k; ++l) {
                    acc += static_cast<int64_t>(a[i * k + l]) *
                        static_cast<int64_t>(b[l * n + j]);
                }
                const size_t idx = static_cast<size_t>(i) * n + j;
                const int16_t y = requant(acc, shift);
                cpu_out[idx] = y;
                cpu_corr[idx] = fp_sub(fp_from_i16(y), masks[idx]);
            }
        }
    };
    const double cpu_native_s = cpu_median(cpu_reps, cpu_reference);

    int16_t *d_a = nullptr, *d_b = nullptr, *d_out = nullptr;
    uint64_t *d_masks = nullptr, *d_corr = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_a), a_len * sizeof(int16_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_b), b_len * sizeof(int16_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_out), out_len * sizeof(int16_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_masks), out_len * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_corr), out_len * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(d_a, a.data(), a_len * sizeof(int16_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_b, b.data(), b_len * sizeof(int16_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_masks, masks.data(), out_len * sizeof(uint64_t), cudaMemcpyHostToDevice));

    const dim3 block(16, 16);
    const dim3 grid((n + block.x - 1) / block.x, (m + block.y - 1) / block.y);
    auto native = [&] {
        return timed_gpu_launch(
            [&] {
                gemm_requant_kernel<false><<<grid, block>>>(
                    d_a, d_b, d_masks, d_out, d_corr, m, k, n, shift);
                CUDA_CHECK(cudaGetLastError());
            },
            d_out,
            out_len);
    };
    auto fused = [&] {
        return timed_gpu_launch(
            [&] {
                gemm_requant_kernel<true><<<grid, block>>>(
                    d_a, d_b, d_masks, d_out, d_corr, m, k, n, shift);
                CUDA_CHECK(cudaGetLastError());
            },
            d_out,
            out_len);
    };
    const PairedTiming timing = gpu_abba(2, gpu_rounds, native, fused);

    native();
    CUDA_CHECK(cudaMemcpy(native_out.data(), d_out, out_len * sizeof(int16_t), cudaMemcpyDeviceToHost));
    fused();
    CUDA_CHECK(cudaMemcpy(fused_out.data(), d_out, out_len * sizeof(int16_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(
        cudaMemcpy(fused_corr.data(), d_corr, out_len * sizeof(uint64_t), cudaMemcpyDeviceToHost));

    bool correct = native_out == cpu_out && fused_out == cpu_out && fused_corr == cpu_corr;
    for (size_t i = 0; correct && i < out_len; ++i) {
        correct = fp_add(fused_corr[i], masks[i]) == fp_from_i16(cpu_out[i]);
    }

    CUDA_CHECK(cudaFree(d_a));
    CUDA_CHECK(cudaFree(d_b));
    CUDA_CHECK(cudaFree(d_out));
    CUDA_CHECK(cudaFree(d_masks));
    CUDA_CHECK(cudaFree(d_corr));
    return ShapeResult{
        n,
        cpu_native_s,
        timing.native_s,
        timing.fused_s,
        timing.fused_s / timing.native_s,
        correct,
        checksum_i16(fused_out),
        checksum_u64(fused_corr),
    };
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 7) {
        std::cerr << "usage: " << argv[0]
                  << " M K SHIFT GPU_ROUNDS CPU_REPS CPU_THREADS\n";
        return 2;
    }
    const int m = std::stoi(argv[1]);
    const int k = std::stoi(argv[2]);
    const int shift = std::stoi(argv[3]);
    const int gpu_rounds = std::stoi(argv[4]);
    const int cpu_reps = std::stoi(argv[5]);
    const int cpu_threads = std::stoi(argv[6]);
    omp_set_dynamic(0);
    omp_set_num_threads(cpu_threads);

    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    std::vector<ShapeResult> rows;
    for (int n : {768, 2304, 3072}) rows.push_back(run_shape(m, k, n, shift, gpu_rounds, cpu_reps));

    const double ffn_down_native = rows[2].gpu_native_s;
    const double ffn_down_fused = ffn_down_native * rows[0].rho;
    const double layer_native = rows[1].gpu_native_s + rows[0].gpu_native_s +
        rows[2].gpu_native_s + ffn_down_native;
    const double layer_fused = rows[1].gpu_fused_s + rows[0].gpu_fused_s +
        rows[2].gpu_native_s + ffn_down_fused;
    const double weighted_rho = layer_fused / layer_native;
    bool correctness = true;
    bool timing_sane = true;
    for (const auto& row : rows) {
        correctness = correctness && row.correct;
        timing_sane = timing_sane && row.gpu_native_s > 0.0 && row.gpu_fused_s > 0.0;
    }
    const bool gate = correctness && timing_sane && weighted_rho <= 1.30;

    std::cout << std::setprecision(12) << "{\n"
              << "  \"correctness\": " << (correctness ? "true" : "false") << ",\n"
              << "  \"timing_sane\": " << (timing_sane ? "true" : "false") << ",\n"
              << "  \"gate_weighted_rho_le_1_30\": " << (gate ? "true" : "false") << ",\n"
              << "  \"weighted_rho_kernel\": " << weighted_rho << ",\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem << "},\n"
              << "  \"parameters\": {\"m\": " << m << ", \"k\": " << k
              << ", \"shift\": " << shift << ", \"gpu_rounds\": " << gpu_rounds
              << ", \"gpu_samples_per_variant\": " << 2 * gpu_rounds
              << ", \"cpu_reps\": " << cpu_reps << ", \"cpu_threads\": " << cpu_threads
              << ", \"resident_masks\": true, \"correction_bytes_per_output\": 8},\n"
              << "  \"shapes\": [\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& row = rows[i];
        const double macs = static_cast<double>(m) * k * row.n;
        std::cout << "    {\"m\": " << m << ", \"k\": " << k << ", \"n\": " << row.n
                  << ", \"cpu_native_s\": " << row.cpu_native_s
                  << ", \"gpu_native_s\": " << row.gpu_native_s
                  << ", \"gpu_fused_s\": " << row.gpu_fused_s << ", \"rho_kernel\": " << row.rho
                  << ", \"native_gpu_cpu_speedup\": " << row.cpu_native_s / row.gpu_native_s
                  << ", \"gpu_native_gmac_s\": " << macs / row.gpu_native_s / 1e9
                  << ", \"correction_bytes\": " << static_cast<uint64_t>(m) * row.n * 8
                  << ", \"correct\": " << (row.correct ? "true" : "false")
                  << ", \"output_checksum\": \"" << hex64(row.out_checksum)
                  << "\", \"correction_checksum\": \"" << hex64(row.corr_checksum) << "\"}"
                  << (i + 1 == rows.size() ? "\n" : ",\n");
    }
    std::cout << "  ]\n}\n";
    return (correctness && timing_sane) ? 0 : 1;
}
