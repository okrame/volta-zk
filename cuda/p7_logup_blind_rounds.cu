#include <cuda_runtime.h>
#include <omp.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
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

struct RoundAcc {
    Fp2 pq0;
    Fp2 pq2;
    Fp2 qq0;
    Fp2 qq2;
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

__host__ __device__ inline Fp2 add(Fp2 a, Fp2 b) {
    return Fp2{fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 sub(Fp2 a, Fp2 b) {
    return Fp2{fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1)};
}

__host__ __device__ inline Fp2 mul(Fp2 a, Fp2 b) {
    return Fp2{
        fp_add(fp_mul(a.c0, b.c0), fp_mul(7, fp_mul(a.c1, b.c1))),
        fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
    };
}

__host__ __device__ inline Fp2 at2(Fp2 v0, Fp2 v1) {
    const Fp2 d = sub(v1, v0);
    return add(add(v0, d), d);
}

__host__ __device__ inline RoundAcc acc_add(RoundAcc a, RoundAcc b) {
    return RoundAcc{add(a.pq0, b.pq0), add(a.pq2, b.pq2), add(a.qq0, b.qq0),
                    add(a.qq2, b.qq2)};
}

__global__ void eval_kernel(
    const Fp2* p0, const Fp2* p1, const Fp2* q0, const Fp2* q1, const Fp2* s,
    RoundAcc* out, size_t pairs) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    const Fp2 a0 = p0[2 * i], a2 = at2(a0, p0[2 * i + 1]);
    const Fp2 b0 = p1[2 * i], b2 = at2(b0, p1[2 * i + 1]);
    const Fp2 c0 = q0[2 * i], c2 = at2(c0, q0[2 * i + 1]);
    const Fp2 d0 = q1[2 * i], d2 = at2(d0, q1[2 * i + 1]);
    const Fp2 si = s[i];
    out[i] = RoundAcc{
        mul(si, add(mul(a0, d0), mul(b0, c0))),
        mul(si, add(mul(a2, d2), mul(b2, c2))),
        mul(si, mul(c0, d0)),
        mul(si, mul(c2, d2)),
    };
}

__global__ void reduce_kernel(const RoundAcc* in, RoundAcc* out, size_t n) {
    __shared__ RoundAcc sh[BLOCK];
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const RoundAcc zero{};
    sh[threadIdx.x] = i < n ? in[i] : zero;
    __syncthreads();
    for (int stride = BLOCK / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride) sh[threadIdx.x] = acc_add(sh[threadIdx.x], sh[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) out[blockIdx.x] = sh[0];
}

__global__ void fold_kernel(
    const Fp2* p0, const Fp2* p1, const Fp2* q0, const Fp2* q1, Fp2* op0,
    Fp2* op1, Fp2* oq0, Fp2* oq1, size_t pairs, Fp2 r) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= pairs) return;
    op0[i] = add(p0[2 * i], mul(sub(p0[2 * i + 1], p0[2 * i]), r));
    op1[i] = add(p1[2 * i], mul(sub(p1[2 * i + 1], p1[2 * i]), r));
    oq0[i] = add(q0[2 * i], mul(sub(q0[2 * i + 1], q0[2 * i]), r));
    oq1[i] = add(q1[2 * i], mul(sub(q1[2 * i + 1], q1[2 * i]), r));
}

struct DeviceVec4 {
    Fp2* v[4];
};

struct HostVec4 {
    std::vector<Fp2> v[4];
};

struct BlindArtifacts {
    std::array<Fp2, 2> root_corrs{};
    std::vector<std::array<Fp2, 2>> round_corrs;
    std::array<Fp2, 4> split_corrs{};
    std::array<Fp2, 3> prod_corrs{};
};

struct BlindInputs {
    std::array<Fp2, 2> roots{};
    std::array<Fp2, 2> root_masks{};
    std::vector<std::array<Fp2, 2>> round_masks;
    std::array<Fp2, 4> split_masks{};
    std::array<Fp2, 3> prod_masks{};
    Fp2 lambda{};
    std::vector<Fp2> points;
};

BlindArtifacts blind_begin(const BlindInputs& in) {
    BlindArtifacts out;
    out.root_corrs = {
        sub(in.roots[0], in.root_masks[0]),
        sub(in.roots[1], in.root_masks[1]),
    };
    out.round_corrs.reserve(in.round_masks.size());
    return out;
}

void blind_round(
    BlindArtifacts& out, const BlindInputs& in, int round, RoundAcc acc, Fp2& cpref) {
    const Fp2 h0 = mul(cpref, add(mul(in.lambda, acc.pq0), acc.qq0));
    const Fp2 h2 = mul(cpref, add(mul(in.lambda, acc.pq2), acc.qq2));
    out.round_corrs.push_back({
        sub(h0, in.round_masks[round][0]),
        sub(h2, in.round_masks[round][1]),
    });
    const Fp2 pt = in.points[round];
    const Fp2 r = Fp2{static_cast<uint64_t>(101 + 2 * round),
                      static_cast<uint64_t>(211 + 3 * round)};
    const Fp2 pr = mul(pt, r);
    cpref = mul(cpref, sub(add(add(pr, pr), Fp2{1, 0}), add(pt, r)));
}

void blind_finish(
    BlindArtifacts& out, const BlindInputs& in, const std::array<Fp2, 4>& splits) {
    for (int i = 0; i < 4; ++i) out.split_corrs[i] = sub(splits[i], in.split_masks[i]);
    const std::array<Fp2, 3> products = {
        mul(splits[0], splits[3]),
        mul(splits[1], splits[2]),
        mul(splits[2], splits[3]),
    };
    for (int i = 0; i < 3; ++i) out.prod_corrs[i] = sub(products[i], in.prod_masks[i]);
}

RoundAcc* reduce_acc(RoundAcc* a0, RoundAcc* a1, size_t n) {
    RoundAcc* in = a0;
    RoundAcc* out = a1;
    while (n > 1) {
        const size_t blocks = (n + BLOCK - 1) / BLOCK;
        reduce_kernel<<<blocks, BLOCK>>>(in, out, n);
        CUDA_CHECK(cudaGetLastError());
        n = blocks;
        std::swap(in, out);
    }
    return in;
}

RoundAcc cpu_eval(const HostVec4& src, const std::vector<Fp2>& s, size_t pairs) {
    RoundAcc total{};
#pragma omp parallel
    {
        RoundAcc local{};
#pragma omp for schedule(static)
        for (size_t i = 0; i < pairs; ++i) {
            const Fp2 a0 = src.v[0][2 * i], a2 = at2(a0, src.v[0][2 * i + 1]);
            const Fp2 b0 = src.v[1][2 * i], b2 = at2(b0, src.v[1][2 * i + 1]);
            const Fp2 c0 = src.v[2][2 * i], c2 = at2(c0, src.v[2][2 * i + 1]);
            const Fp2 d0 = src.v[3][2 * i], d2 = at2(d0, src.v[3][2 * i + 1]);
            const Fp2 si = s[i];
            local = acc_add(local, RoundAcc{
                mul(si, add(mul(a0, d0), mul(b0, c0))),
                mul(si, add(mul(a2, d2), mul(b2, c2))),
                mul(si, mul(c0, d0)),
                mul(si, mul(c2, d2)),
            });
        }
#pragma omp critical
        total = acc_add(total, local);
    }
    return total;
}

void cpu_fold(const HostVec4& src, HostVec4& dst, size_t pairs, Fp2 r) {
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < pairs; ++i) {
        for (int col = 0; col < 4; ++col) {
            const Fp2 v0 = src.v[col][2 * i];
            dst.v[col][i] = add(v0, mul(sub(src.v[col][2 * i + 1], v0), r));
        }
    }
}

bool equal(Fp2 a, Fp2 b) {
    return a.c0 == b.c0 && a.c1 == b.c1;
}

bool equal(RoundAcc a, RoundAcc b) {
    return equal(a.pq0, b.pq0) && equal(a.pq2, b.pq2) && equal(a.qq0, b.qq0) &&
        equal(a.qq2, b.qq2);
}

bool equal(const BlindArtifacts& a, const BlindArtifacts& b) {
    if (a.round_corrs.size() != b.round_corrs.size()) return false;
    for (int i = 0; i < 2; ++i) if (!equal(a.root_corrs[i], b.root_corrs[i])) return false;
    for (size_t j = 0; j < a.round_corrs.size(); ++j) {
        for (int i = 0; i < 2; ++i) {
            if (!equal(a.round_corrs[j][i], b.round_corrs[j][i])) return false;
        }
    }
    for (int i = 0; i < 4; ++i) if (!equal(a.split_corrs[i], b.split_corrs[i])) return false;
    for (int i = 0; i < 3; ++i) if (!equal(a.prod_corrs[i], b.prod_corrs[i])) return false;
    return true;
}

uint64_t hash_fp2(uint64_t h, Fp2 x) {
    h ^= x.c0;
    h *= 0x0000'0100'0000'01B3ULL;
    h ^= x.c1;
    h *= 0x0000'0100'0000'01B3ULL;
    return h;
}

uint64_t hash_artifacts(uint64_t h, const BlindArtifacts& a) {
    for (Fp2 x : a.root_corrs) h = hash_fp2(h, x);
    for (const auto& row : a.round_corrs) for (Fp2 x : row) h = hash_fp2(h, x);
    for (Fp2 x : a.split_corrs) h = hash_fp2(h, x);
    for (Fp2 x : a.prod_corrs) h = hash_fp2(h, x);
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
    const size_t max_pairs = n / 2;
    omp_set_dynamic(0);
    omp_set_num_threads(cpu_threads);

    HostVec4 initial, h0, h1, gpu_copy;
    for (int col = 0; col < 4; ++col) {
        initial.v[col].resize(n);
        h0.v[col].resize(n);
        h1.v[col].resize(n);
        gpu_copy.v[col].resize(n);
#pragma omp parallel for schedule(static)
        for (size_t i = 0; i < n; ++i) {
            initial.v[col][i] = Fp2{
                (i * (0x9E37'79B9ULL + 2 * col) + 17 + col) % P,
                (i * (0x85EB'CA6BULL + 4 * col) + 29 + col) % P,
            };
        }
    }
    std::vector<Fp2> s(max_pairs), challenges(log2_n);
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < max_pairs; ++i) {
        s[i] = Fp2{(i * 0xC2B2'AE35ULL + 31) % P, (i * 0x27D4'EB2FULL + 43) % P};
    }
    for (int j = 0; j < log2_n; ++j) {
        challenges[j] = Fp2{static_cast<uint64_t>(101 + 2 * j), static_cast<uint64_t>(211 + 3 * j)};
    }
    BlindInputs blind_in;
    blind_in.roots = {Fp2{701, 907}, Fp2{1103, 1301}};
    blind_in.root_masks = {Fp2{1709, 1901}, Fp2{2203, 2503}};
    blind_in.lambda = Fp2{2707, 2903};
    blind_in.points.resize(log2_n);
    blind_in.round_masks.resize(log2_n);
    for (int j = 0; j < log2_n; ++j) {
        blind_in.points[j] = Fp2{static_cast<uint64_t>(3109 + 12 * j),
                                 static_cast<uint64_t>(3301 + 14 * j)};
        blind_in.round_masks[j] = {
            Fp2{static_cast<uint64_t>(3701 + 20 * j), static_cast<uint64_t>(3907 + 22 * j)},
            Fp2{static_cast<uint64_t>(4201 + 24 * j), static_cast<uint64_t>(4409 + 26 * j)},
        };
    }
    for (int i = 0; i < 4; ++i) {
        blind_in.split_masks[i] =
            Fp2{static_cast<uint64_t>(4703 + 30 * i), static_cast<uint64_t>(5003 + 32 * i)};
    }
    for (int i = 0; i < 3; ++i) {
        blind_in.prod_masks[i] =
            Fp2{static_cast<uint64_t>(5303 + 34 * i), static_cast<uint64_t>(5501 + 36 * i)};
    }

    DeviceVec4 d0{}, d1{};
    Fp2* d_s = nullptr;
    RoundAcc *d_acc0 = nullptr, *d_acc1 = nullptr;
    for (int col = 0; col < 4; ++col) {
        CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d0.v[col]), n * sizeof(Fp2)));
        CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d1.v[col]), n * sizeof(Fp2)));
    }
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_s), max_pairs * sizeof(Fp2)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_acc0), max_pairs * sizeof(RoundAcc)));
    CUDA_CHECK(cudaMalloc(
        reinterpret_cast<void**>(&d_acc1), ((max_pairs + BLOCK - 1) / BLOCK) * sizeof(RoundAcc)));
    CUDA_CHECK(cudaMemcpy(d_s, s.data(), max_pairs * sizeof(Fp2), cudaMemcpyHostToDevice));

    auto reset_gpu = [&] {
        for (int col = 0; col < 4; ++col) {
            CUDA_CHECK(cudaMemcpy(
                d0.v[col], initial.v[col].data(), n * sizeof(Fp2), cudaMemcpyHostToDevice));
        }
    };
    auto run_gpu = [&](bool blind) {
        BlindArtifacts artifacts = blind ? blind_begin(blind_in) : BlindArtifacts{};
        Fp2 cpref{1, 0};
        DeviceVec4* src = &d0;
        DeviceVec4* dst = &d1;
        size_t len = n;
        for (int round = 0; round < log2_n; ++round) {
            const size_t pairs = len / 2;
            eval_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(
                src->v[0], src->v[1], src->v[2], src->v[3], d_s, d_acc0, pairs);
            CUDA_CHECK(cudaGetLastError());
            RoundAcc* root = reduce_acc(d_acc0, d_acc1, pairs);
            RoundAcc message{};
            CUDA_CHECK(cudaMemcpy(&message, root, sizeof(message), cudaMemcpyDeviceToHost));
            if (blind) blind_round(artifacts, blind_in, round, message, cpref);
            fold_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(
                src->v[0], src->v[1], src->v[2], src->v[3], dst->v[0], dst->v[1],
                dst->v[2], dst->v[3], pairs, challenges[round]);
            CUDA_CHECK(cudaGetLastError());
            std::swap(src, dst);
            len = pairs;
        }
        std::array<Fp2, 4> splits{};
        for (int col = 0; col < 4; ++col) {
            CUDA_CHECK(cudaMemcpy(&splits[col], src->v[col], sizeof(Fp2), cudaMemcpyDeviceToHost));
        }
        if (blind) blind_finish(artifacts, blind_in, splits);
        return artifacts;
    };

    reset_gpu();
    run_gpu(false);
    reset_gpu();
    run_gpu(true);
    std::vector<double> gpu_clear_samples, gpu_blind_samples;
    auto sample_gpu = [&](bool blind) {
        reset_gpu();
        const auto t0 = std::chrono::steady_clock::now();
        run_gpu(blind);
        const auto t1 = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(t1 - t0).count();
    };
    for (int rep = 0; rep < gpu_reps; ++rep) {
        if (rep % 2 == 0) {
            gpu_clear_samples.push_back(sample_gpu(false));
            gpu_blind_samples.push_back(sample_gpu(true));
        } else {
            gpu_blind_samples.push_back(sample_gpu(true));
            gpu_clear_samples.push_back(sample_gpu(false));
        }
    }
    std::sort(gpu_clear_samples.begin(), gpu_clear_samples.end());
    std::sort(gpu_blind_samples.begin(), gpu_blind_samples.end());
    const double gpu_clear_s = gpu_clear_samples[gpu_clear_samples.size() / 2];
    const double gpu_s = gpu_blind_samples[gpu_blind_samples.size() / 2];

    auto reset_cpu = [&] {
        for (int col = 0; col < 4; ++col) {
            std::memcpy(h0.v[col].data(), initial.v[col].data(), n * sizeof(Fp2));
        }
    };
    auto run_cpu = [&](bool blind) {
        BlindArtifacts artifacts = blind ? blind_begin(blind_in) : BlindArtifacts{};
        Fp2 cpref{1, 0};
        HostVec4* src = &h0;
        HostVec4* dst = &h1;
        size_t len = n;
        for (int round = 0; round < log2_n; ++round) {
            const size_t pairs = len / 2;
            const RoundAcc message = cpu_eval(*src, s, pairs);
            if (blind) blind_round(artifacts, blind_in, round, message, cpref);
            cpu_fold(*src, *dst, pairs, challenges[round]);
            std::swap(src, dst);
            len = pairs;
        }
        std::array<Fp2, 4> splits{};
        for (int col = 0; col < 4; ++col) splits[col] = src->v[col][0];
        if (blind) blind_finish(artifacts, blind_in, splits);
        return artifacts;
    };
    reset_cpu();
    run_cpu(true);
    std::vector<double> cpu_samples;
    for (int rep = 0; rep < cpu_reps; ++rep) {
        reset_cpu();
        const auto t0 = std::chrono::steady_clock::now();
        run_cpu(true);
        const auto t1 = std::chrono::steady_clock::now();
        cpu_samples.push_back(std::chrono::duration<double>(t1 - t0).count());
    }
    std::sort(cpu_samples.begin(), cpu_samples.end());
    const double cpu_s = cpu_samples[cpu_samples.size() / 2];

    // Every-depth differential validation, excluded from timing.
    reset_cpu();
    reset_gpu();
    HostVec4* hsrc = &h0;
    HostVec4* hdst = &h1;
    DeviceVec4* dsrc = &d0;
    DeviceVec4* ddst = &d1;
    size_t len = n;
    bool correct = true;
    uint64_t checksum = 0xCBF2'9CE4'8422'2325ULL;
    BlindArtifacts cpu_artifacts = blind_begin(blind_in);
    BlindArtifacts gpu_artifacts = blind_begin(blind_in);
    Fp2 cpu_cpref{1, 0}, gpu_cpref{1, 0};
    for (int round = 0; round < log2_n && correct; ++round) {
        const size_t pairs = len / 2;
        const RoundAcc expected = cpu_eval(*hsrc, s, pairs);
        blind_round(cpu_artifacts, blind_in, round, expected, cpu_cpref);
        cpu_fold(*hsrc, *hdst, pairs, challenges[round]);
        eval_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(
            dsrc->v[0], dsrc->v[1], dsrc->v[2], dsrc->v[3], d_s, d_acc0, pairs);
        CUDA_CHECK(cudaGetLastError());
        RoundAcc* root = reduce_acc(d_acc0, d_acc1, pairs);
        RoundAcc got{};
        CUDA_CHECK(cudaMemcpy(&got, root, sizeof(got), cudaMemcpyDeviceToHost));
        correct = equal(expected, got);
        blind_round(gpu_artifacts, blind_in, round, got, gpu_cpref);
        for (Fp2 x : {got.pq0, got.pq2, got.qq0, got.qq2}) checksum = hash_fp2(checksum, x);
        fold_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(
            dsrc->v[0], dsrc->v[1], dsrc->v[2], dsrc->v[3], ddst->v[0], ddst->v[1],
            ddst->v[2], ddst->v[3], pairs, challenges[round]);
        CUDA_CHECK(cudaGetLastError());
        for (int col = 0; col < 4; ++col) {
            CUDA_CHECK(cudaMemcpy(
                gpu_copy.v[col].data(), ddst->v[col], pairs * sizeof(Fp2), cudaMemcpyDeviceToHost));
            for (size_t i = 0; i < pairs; ++i) {
                correct = correct && equal(hdst->v[col][i], gpu_copy.v[col][i]);
                checksum = hash_fp2(checksum, gpu_copy.v[col][i]);
            }
        }
        std::swap(hsrc, hdst);
        std::swap(dsrc, ddst);
        len = pairs;
    }

    std::array<Fp2, 4> cpu_splits{}, gpu_splits{};
    for (int col = 0; col < 4; ++col) {
        cpu_splits[col] = hsrc->v[col][0];
        CUDA_CHECK(cudaMemcpy(&gpu_splits[col], dsrc->v[col], sizeof(Fp2), cudaMemcpyDeviceToHost));
    }
    blind_finish(cpu_artifacts, blind_in, cpu_splits);
    blind_finish(gpu_artifacts, blind_in, gpu_splits);
    correct = correct && equal(cpu_artifacts, gpu_artifacts);
    checksum = hash_artifacts(checksum, gpu_artifacts);

    const double speedup = cpu_s / gpu_s;
    const double blind_over_clear = gpu_s / gpu_clear_s;
    const bool timing_sane = gpu_s > 0.0 && gpu_clear_s > 0.0 && speedup < 10000.0;
    const bool gate = correct && timing_sane && speedup >= 5.48 && blind_over_clear <= 1.05;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));

    for (int col = 0; col < 4; ++col) {
        CUDA_CHECK(cudaFree(d0.v[col]));
        CUDA_CHECK(cudaFree(d1.v[col]));
    }
    CUDA_CHECK(cudaFree(d_s));
    CUDA_CHECK(cudaFree(d_acc0));
    CUDA_CHECK(cudaFree(d_acc1));

    std::cout << std::setprecision(12) << "{\n"
              << "  \"correctness\": " << (correct ? "true" : "false") << ",\n"
              << "  \"blind_corrections_correct\": " << (correct ? "true" : "false") << ",\n"
              << "  \"timing_sane\": " << (timing_sane ? "true" : "false") << ",\n"
              << "  \"gate_speedup_ge_5_48_and_overhead_le_1_05\": "
              << (gate ? "true" : "false") << ",\n"
              << "  \"cpu_blind_s\": " << cpu_s << ", \"gpu_blind_s\": " << gpu_s
              << ", \"gpu_clear_s\": " << gpu_clear_s
              << ", \"gpu_cpu_speedup\": " << speedup
              << ", \"blind_over_clear\": " << blind_over_clear << ",\n"
              << "  \"all_rounds_checksum\": \"" << hex64(checksum) << "\",\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem << "},\n"
              << "  \"parameters\": {\"log2_n\": " << log2_n << ", \"n\": " << n
              << ", \"rounds\": " << log2_n << ", \"gpu_reps\": " << gpu_reps
              << ", \"cpu_reps\": " << cpu_reps << ", \"cpu_threads\": " << cpu_threads
              << ", \"round_message_d2h_bytes\": 64, \"fp2_mults_per_pair_eval\": 10"
              << ", \"fp2_mults_per_pair_fold\": 4, \"root_correction_bytes\": 32"
              << ", \"round_correction_bytes\": " << 32 * log2_n
              << ", \"split_correction_bytes\": 64, \"product_correction_bytes\": 48"
              << ", \"correction_bytes_total\": " << 32 + 32 * log2_n + 64 + 48
              << ", \"extra_transcript_rounds\": 0, \"resident_preexpanded_masks\": true}\n"
              << "}\n";
    return (correct && timing_sane) ? 0 : 1;
}
