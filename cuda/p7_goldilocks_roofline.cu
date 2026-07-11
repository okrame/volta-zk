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

// Mirrors volta-field exactly: 5 base-field multiplications per Fp2 multiply.
__host__ __device__ inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    const uint64_t c0 = fp_add(fp_mul(a.c0, b.c0), fp_mul(7, fp_mul(a.c1, b.c1)));
    const uint64_t c1 = fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0));
    return Fp2{c0, c1};
}

__global__ void stream_kernel(const Fp2* a, const Fp2* b, Fp2* out, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) out[i] = fp2_mul(a[i], b[i]);
}

__global__ void chain_kernel(const Fp2* a, const Fp2* b, Fp2* out, size_t n, int rounds) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n) return;
    Fp2 x = a[i];
    const Fp2 y = b[i];
    for (int j = 0; j < rounds; ++j) {
        const Fp2 bias{static_cast<uint64_t>(j + 1), static_cast<uint64_t>(2 * j + 3)};
        x = fp2_add(fp2_mul(x, y), bias);
    }
    out[i] = x;
}

template <typename F>
double cpu_median(int reps, F&& f) {
    f();  // pre-registered warmup
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
double gpu_median_ms(int reps, F&& launch) {
    launch();
    CUDA_CHECK(cudaDeviceSynchronize());  // pre-registered warmup
    cudaEvent_t start, stop;
    CUDA_CHECK(cudaEventCreate(&start));
    CUDA_CHECK(cudaEventCreate(&stop));
    std::vector<float> samples;
    samples.reserve(reps);
    for (int rep = 0; rep < reps; ++rep) {
        CUDA_CHECK(cudaEventRecord(start));
        launch();
        CUDA_CHECK(cudaEventRecord(stop));
        CUDA_CHECK(cudaEventSynchronize(stop));
        float ms = 0.0f;
        CUDA_CHECK(cudaEventElapsedTime(&ms, start, stop));
        samples.push_back(ms);
    }
    CUDA_CHECK(cudaEventDestroy(start));
    CUDA_CHECK(cudaEventDestroy(stop));
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

void fill_inputs(std::vector<Fp2>& a, std::vector<Fp2>& b) {
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < a.size(); ++i) {
        const uint64_t x = static_cast<uint64_t>(i);
        a[i] = Fp2{(x * 0x9E37'79B9ULL + 17) % P, (x * 0x85EB'CA6BULL + 29) % P};
        b[i] = Fp2{(x * 0xC2B2'AE35ULL + 31) % P, (x * 0x27D4'EB2FULL + 43) % P};
    }
}

bool equal_outputs(const std::vector<Fp2>& a, const std::vector<Fp2>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].c0 != b[i].c0 || a[i].c1 != b[i].c1) {
            std::cerr << "mismatch at " << i << ": cpu=(" << a[i].c0 << ',' << a[i].c1
                      << ") gpu=(" << b[i].c0 << ',' << b[i].c1 << ")\n";
            return false;
        }
    }
    return true;
}

uint64_t checksum(const std::vector<Fp2>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (const Fp2& x : values) {
        h ^= x.c0;
        h *= 0x0000'0100'0000'01B3ULL;
        h ^= x.c1;
        h *= 0x0000'0100'0000'01B3ULL;
    }
    return h;
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
    if (argc != 7) {
        std::cerr << "usage: " << argv[0]
                  << " STREAM_LOG2 CHAIN_LOG2 CHAIN_ROUNDS GPU_REPS CPU_REPS CPU_THREADS\n";
        return 2;
    }
    const int stream_log2 = std::stoi(argv[1]);
    const int chain_log2 = std::stoi(argv[2]);
    const int chain_rounds = std::stoi(argv[3]);
    const int gpu_reps = std::stoi(argv[4]);
    const int cpu_reps = std::stoi(argv[5]);
    const int cpu_threads = std::stoi(argv[6]);
    const size_t stream_n = size_t{1} << stream_log2;
    const size_t chain_n = size_t{1} << chain_log2;
    omp_set_dynamic(0);
    omp_set_num_threads(cpu_threads);

    int device = 0;
    CUDA_CHECK(cudaSetDevice(device));
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    int runtime_version = 0, driver_version = 0;
    CUDA_CHECK(cudaRuntimeGetVersion(&runtime_version));
    CUDA_CHECK(cudaDriverGetVersion(&driver_version));

    const int block = 256;

    std::vector<Fp2> stream_a(stream_n), stream_b(stream_n), stream_cpu(stream_n),
        stream_gpu(stream_n);
    fill_inputs(stream_a, stream_b);
    const double stream_cpu_s = cpu_median(cpu_reps, [&] {
#pragma omp parallel for schedule(static)
        for (size_t i = 0; i < stream_n; ++i) stream_cpu[i] = fp2_mul(stream_a[i], stream_b[i]);
    });
    Fp2 *d_a = nullptr, *d_b = nullptr, *d_out = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_a), stream_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_b), stream_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_out), stream_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMemcpy(d_a, stream_a.data(), stream_n * sizeof(Fp2), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_b, stream_b.data(), stream_n * sizeof(Fp2), cudaMemcpyHostToDevice));
    const double stream_gpu_s = gpu_median_ms(gpu_reps, [&] {
                                    stream_kernel<<<(stream_n + block - 1) / block, block>>>(
                                        d_a, d_b, d_out, stream_n);
                                    CUDA_CHECK(cudaGetLastError());
                                }) /
        1e3;
    CUDA_CHECK(
        cudaMemcpy(stream_gpu.data(), d_out, stream_n * sizeof(Fp2), cudaMemcpyDeviceToHost));
    const bool stream_ok = equal_outputs(stream_cpu, stream_gpu);
    const uint64_t stream_checksum = checksum(stream_gpu);
    CUDA_CHECK(cudaFree(d_a));
    CUDA_CHECK(cudaFree(d_b));
    CUDA_CHECK(cudaFree(d_out));

    // Release the 2^24 stream buffers before allocating the compute-chain set.
    std::vector<Fp2>().swap(stream_a);
    std::vector<Fp2>().swap(stream_b);
    std::vector<Fp2>().swap(stream_cpu);
    std::vector<Fp2>().swap(stream_gpu);

    std::vector<Fp2> chain_a(chain_n), chain_b(chain_n), chain_cpu(chain_n), chain_gpu(chain_n);
    fill_inputs(chain_a, chain_b);
    const double chain_cpu_s = cpu_median(cpu_reps, [&] {
#pragma omp parallel for schedule(static)
        for (size_t i = 0; i < chain_n; ++i) {
            Fp2 x = chain_a[i];
            const Fp2 y = chain_b[i];
            for (int j = 0; j < chain_rounds; ++j) {
                const Fp2 bias{static_cast<uint64_t>(j + 1), static_cast<uint64_t>(2 * j + 3)};
                x = fp2_add(fp2_mul(x, y), bias);
            }
            chain_cpu[i] = x;
        }
    });
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_a), chain_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_b), chain_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_out), chain_n * sizeof(Fp2)));
    CUDA_CHECK(cudaMemcpy(d_a, chain_a.data(), chain_n * sizeof(Fp2), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_b, chain_b.data(), chain_n * sizeof(Fp2), cudaMemcpyHostToDevice));
    const double chain_gpu_s = gpu_median_ms(gpu_reps, [&] {
                                   chain_kernel<<<(chain_n + block - 1) / block, block>>>(
                                       d_a, d_b, d_out, chain_n, chain_rounds);
                                   CUDA_CHECK(cudaGetLastError());
                               }) /
        1e3;
    CUDA_CHECK(cudaMemcpy(chain_gpu.data(), d_out, chain_n * sizeof(Fp2), cudaMemcpyDeviceToHost));
    const bool chain_ok = equal_outputs(chain_cpu, chain_gpu);
    const uint64_t chain_checksum = checksum(chain_gpu);
    CUDA_CHECK(cudaFree(d_a));
    CUDA_CHECK(cudaFree(d_b));
    CUDA_CHECK(cudaFree(d_out));

    const double stream_bytes = static_cast<double>(stream_n) * 3.0 * sizeof(Fp2);
    const double chain_ops = static_cast<double>(chain_n) * chain_rounds;
    std::ostringstream stream_hex, chain_hex;
    stream_hex << "0x" << std::hex << std::setw(16) << std::setfill('0') << stream_checksum;
    chain_hex << "0x" << std::hex << std::setw(16) << std::setfill('0') << chain_checksum;

    std::cout << std::setprecision(12) << "{\n"
              << "  \"correctness\": " << ((stream_ok && chain_ok) ? "true" : "false") << ",\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"clock_rate_khz\": " << prop.clockRate
              << ", \"memory_clock_rate_khz\": " << prop.memoryClockRate
              << ", \"memory_bus_width_bits\": " << prop.memoryBusWidth
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem
              << ", \"cuda_runtime_version\": " << runtime_version
              << ", \"cuda_driver_version\": " << driver_version << "},\n"
              << "  \"parameters\": {\"stream_log2\": " << stream_log2
              << ", \"chain_log2\": " << chain_log2 << ", \"chain_rounds\": " << chain_rounds
              << ", \"gpu_reps\": " << gpu_reps << ", \"cpu_reps\": " << cpu_reps
              << ", \"cpu_threads\": " << cpu_threads << ", \"fp_mul_per_fp2_mul\": 5},\n"
              << "  \"stream\": {\"cpu_s\": " << stream_cpu_s << ", \"gpu_s\": " << stream_gpu_s
              << ", \"gpu_cpu_speedup\": " << stream_cpu_s / stream_gpu_s
              << ", \"gpu_bandwidth_gb_s\": " << stream_bytes / stream_gpu_s / 1e9
              << ", \"gpu_fp2_mul_s\": " << static_cast<double>(stream_n) / stream_gpu_s
              << ", \"gpu_base_mul_equiv_s\": " << 5.0 * stream_n / stream_gpu_s
              << ", \"checksum\": \"" << stream_hex.str() << "\", \"matches_cpu\": "
              << (stream_ok ? "true" : "false") << "},\n"
              << "  \"chain\": {\"cpu_s\": " << chain_cpu_s << ", \"gpu_s\": " << chain_gpu_s
              << ", \"gpu_cpu_speedup\": " << chain_cpu_s / chain_gpu_s
              << ", \"gpu_fp2_mul_s\": " << chain_ops / chain_gpu_s
              << ", \"gpu_base_mul_equiv_s\": " << 5.0 * chain_ops / chain_gpu_s
              << ", \"checksum\": \"" << chain_hex.str() << "\", \"matches_cpu\": "
              << (chain_ok ? "true" : "false") << "}\n"
              << "}\n";
    return (stream_ok && chain_ok) ? 0 : 1;
}
