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
constexpr int BLOCK = 128;
constexpr uint32_t CHUNK_START = 1;
constexpr uint32_t CHUNK_END = 2;
constexpr uint32_t PARENT = 4;
constexpr uint32_t ROOT = 8;

struct Hash32 {
    uint32_t w[8];
};

struct Output {
    uint32_t cv[8];
    uint32_t block[16];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;
};

__host__ __device__ constexpr uint32_t iv(int i) {
    constexpr uint32_t words[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };
    return words[i];
}

__host__ __device__ constexpr uint8_t perm(int i) {
    constexpr uint8_t indices[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    };
    return indices[i];
}

#define CUDA_CHECK(call)                                                                    \
    do {                                                                                    \
        cudaError_t err__ = (call);                                                         \
        if (err__ != cudaSuccess) {                                                         \
            std::cerr << #call << ": " << cudaGetErrorString(err__) << "\n";               \
            std::exit(2);                                                                   \
        }                                                                                   \
    } while (0)

__host__ __device__ inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__host__ __device__ inline void g(
    uint32_t s[16], int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr(s[d] ^ s[a], 16);
    s[c] += s[d];
    s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr(s[d] ^ s[a], 8);
    s[c] += s[d];
    s[b] = rotr(s[b] ^ s[c], 7);
}

__host__ __device__ void compress(
    const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
    uint32_t block_len, uint32_t flags, uint32_t out[16]) {
    uint32_t s[16], m[16], p[16];
    for (int i = 0; i < 8; ++i) s[i] = cv[i];
    for (int i = 0; i < 4; ++i) s[8 + i] = iv(i);
    s[12] = static_cast<uint32_t>(counter);
    s[13] = static_cast<uint32_t>(counter >> 32);
    s[14] = block_len;
    s[15] = flags;
    for (int i = 0; i < 16; ++i) m[i] = block[i];
    for (int round = 0; round < 7; ++round) {
        g(s, 0, 4, 8, 12, m[0], m[1]);
        g(s, 1, 5, 9, 13, m[2], m[3]);
        g(s, 2, 6, 10, 14, m[4], m[5]);
        g(s, 3, 7, 11, 15, m[6], m[7]);
        g(s, 0, 5, 10, 15, m[8], m[9]);
        g(s, 1, 6, 11, 12, m[10], m[11]);
        g(s, 2, 7, 8, 13, m[12], m[13]);
        g(s, 3, 4, 9, 14, m[14], m[15]);
        for (int i = 0; i < 16; ++i) p[i] = m[perm(i)];
        for (int i = 0; i < 16; ++i) m[i] = p[i];
    }
    for (int i = 0; i < 8; ++i) {
        out[i] = s[i] ^ s[i + 8];
        out[i + 8] = s[i + 8] ^ cv[i];
    }
}

__host__ __device__ Hash32 chaining_value(const Output& o) {
    uint32_t words[16];
    compress(o.cv, o.block, o.counter, o.block_len, o.flags, words);
    Hash32 h{};
    for (int i = 0; i < 8; ++i) h.w[i] = words[i];
    return h;
}

__host__ __device__ Hash32 root_hash(const Output& o) {
    uint32_t words[16];
    compress(o.cv, o.block, 0, o.block_len, o.flags | ROOT, words);
    Hash32 h{};
    for (int i = 0; i < 8; ++i) h.w[i] = words[i];
    return h;
}

__host__ __device__ Output parent_output(Hash32 left, Hash32 right) {
    Output o{};
    for (int i = 0; i < 8; ++i) {
        o.cv[i] = iv(i);
        o.block[i] = left.w[i];
        o.block[8 + i] = right.w[i];
    }
    o.block_len = 64;
    o.flags = PARENT;
    return o;
}

__host__ __device__ Output chunk_output_column(
    const uint64_t* matrix, size_t rows, size_t cols, size_t col, size_t chunk) {
    Output o{};
    uint32_t cv[8];
    for (int i = 0; i < 8; ++i) cv[i] = iv(i);
    const size_t row0 = chunk * 128;
    const size_t remaining = rows - row0;
    const int blocks = static_cast<int>((remaining < 128 ? remaining : 128) / 8);
    for (int block = 0; block < blocks; ++block) {
        uint32_t words[16];
        for (int i = 0; i < 8; ++i) {
            const uint64_t x = matrix[(row0 + block * 8 + i) * cols + col];
            words[2 * i] = static_cast<uint32_t>(x);
            words[2 * i + 1] = static_cast<uint32_t>(x >> 32);
        }
        uint32_t flags = (block == 0 ? CHUNK_START : 0) |
            (block + 1 == blocks ? CHUNK_END : 0);
        if (block + 1 == blocks) {
            for (int i = 0; i < 8; ++i) o.cv[i] = cv[i];
            for (int i = 0; i < 16; ++i) o.block[i] = words[i];
            o.counter = chunk;
            o.block_len = 64;
            o.flags = flags;
        } else {
            uint32_t out[16];
            compress(cv, words, chunk, 64, flags, out);
            for (int i = 0; i < 8; ++i) cv[i] = out[i];
        }
    }
    return o;
}

__host__ __device__ Hash32 hash_column(
    const uint64_t* matrix, size_t rows, size_t cols, size_t col) {
    const int chunks = static_cast<int>((rows + 127) / 128);
    Hash32 cvs[8];
    Output single{};
    for (int c = 0; c < chunks; ++c) {
        Output o = chunk_output_column(matrix, rows, cols, col, c);
        if (chunks == 1) single = o;
        cvs[c] = chaining_value(o);
    }
    if (chunks == 1) return root_hash(single);
    int count = chunks;
    while (count > 2) {
        for (int i = 0; i < count / 2; ++i) cvs[i] = chaining_value(parent_output(cvs[2 * i], cvs[2 * i + 1]));
        count /= 2;
    }
    return root_hash(parent_output(cvs[0], cvs[1]));
}

__host__ __device__ Hash32 hash_pair(Hash32 left, Hash32 right) {
    Output o{};
    for (int i = 0; i < 8; ++i) {
        o.cv[i] = iv(i);
        o.block[i] = left.w[i];
        o.block[8 + i] = right.w[i];
    }
    o.block_len = 64;
    o.flags = CHUNK_START | CHUNK_END;
    return root_hash(o);
}

__global__ void leaf_kernel(
    const uint64_t* matrix, Hash32* leaves, size_t rows, size_t cols) {
    const size_t col = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (col < cols) leaves[col] = hash_column(matrix, rows, cols, col);
}

__global__ void parent_kernel(const Hash32* in, Hash32* out, size_t pairs) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < pairs) out[i] = hash_pair(in[2 * i], in[2 * i + 1]);
}

bool equal(Hash32 a, Hash32 b) {
    for (int i = 0; i < 8; ++i) if (a.w[i] != b.w[i]) return false;
    return true;
}

std::string hex(Hash32 h) {
    std::ostringstream out;
    for (int i = 0; i < 8; ++i) {
        for (int b = 0; b < 4; ++b) out << std::hex << std::setw(2) << std::setfill('0')
            << ((h.w[i] >> (8 * b)) & 0xFF);
    }
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
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " ROWS COLS GPU_REPS\n";
        return 2;
    }
    const size_t rows = std::stoull(argv[1]);
    const size_t cols = std::stoull(argv[2]);
    const int gpu_reps = std::stoi(argv[3]);
    if (rows % 8 != 0 || rows > 1024 || !cols || (cols & (cols - 1))) return 2;
    const size_t total = rows * cols;
    std::vector<uint64_t> matrix(total);
#pragma omp parallel for schedule(static)
    for (size_t i = 0; i < total; ++i) matrix[i] = (i * 0x9E37'79B9ULL + 17) % P;

    uint64_t* d_matrix = nullptr;
    Hash32 *d0 = nullptr, *d1 = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d_matrix), total * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d0), cols * sizeof(Hash32)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&d1), cols * sizeof(Hash32)));
    CUDA_CHECK(cudaMemcpy(d_matrix, matrix.data(), total * sizeof(uint64_t), cudaMemcpyHostToDevice));
    Hash32 root{};
    auto run_gpu = [&] {
        leaf_kernel<<<(cols + BLOCK - 1) / BLOCK, BLOCK>>>(d_matrix, d0, rows, cols);
        CUDA_CHECK(cudaGetLastError());
        size_t len = cols;
        Hash32* in = d0;
        Hash32* out = d1;
        while (len > 1) {
            const size_t pairs = len / 2;
            parent_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(in, out, pairs);
            CUDA_CHECK(cudaGetLastError());
            std::swap(in, out);
            len = pairs;
        }
        CUDA_CHECK(cudaMemcpy(&root, in, sizeof(root), cudaMemcpyDeviceToHost));
    };
    run_gpu();
    std::vector<double> samples;
    for (int rep = 0; rep < gpu_reps; ++rep) {
        const auto t0 = std::chrono::steady_clock::now();
        run_gpu();
        const auto t1 = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration<double>(t1 - t0).count());
    }
    std::sort(samples.begin(), samples.end());
    const double gpu_s = samples[samples.size() / 2];

    // Independent host/device differential at every level (outside timing).
    std::vector<Hash32> host(cols), gpu(cols);
#pragma omp parallel for schedule(static)
    for (size_t j = 0; j < cols; ++j) host[j] = hash_column(matrix.data(), rows, cols, j);
    leaf_kernel<<<(cols + BLOCK - 1) / BLOCK, BLOCK>>>(d_matrix, d0, rows, cols);
    CUDA_CHECK(cudaMemcpy(gpu.data(), d0, cols * sizeof(Hash32), cudaMemcpyDeviceToHost));
    bool correct = true;
    for (size_t i = 0; i < cols; ++i) correct = correct && equal(host[i], gpu[i]);
    size_t len = cols;
    Hash32* in = d0;
    Hash32* out = d1;
    while (correct && len > 1) {
        const size_t pairs = len / 2;
        for (size_t i = 0; i < pairs; ++i) host[i] = hash_pair(host[2 * i], host[2 * i + 1]);
        parent_kernel<<<(pairs + BLOCK - 1) / BLOCK, BLOCK>>>(in, out, pairs);
        CUDA_CHECK(cudaMemcpy(gpu.data(), out, pairs * sizeof(Hash32), cudaMemcpyDeviceToHost));
        for (size_t i = 0; i < pairs; ++i) correct = correct && equal(host[i], gpu[i]);
        std::swap(in, out);
        len = pairs;
    }
    correct = correct && equal(root, host[0]);
    const bool timing_sane = gpu_s > 0.0 && gpu_s < 1.0;
    const bool gate = correct && timing_sane && gpu_s <= 0.075;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDeviceProperties(&prop, 0));
    CUDA_CHECK(cudaFree(d_matrix));
    CUDA_CHECK(cudaFree(d0));
    CUDA_CHECK(cudaFree(d1));

    std::cout << std::setprecision(12) << "{\n"
              << "  \"host_device_correctness\": " << (correct ? "true" : "false") << ",\n"
              << "  \"timing_sane\": " << (timing_sane ? "true" : "false") << ",\n"
              << "  \"gate_gpu_s_le_0_075\": " << (gate ? "true" : "false") << ",\n"
              << "  \"gpu_s\": " << gpu_s << ", \"root\": \"" << hex(root) << "\",\n"
              << "  \"parameters\": {\"rows\": " << rows << ", \"cols\": " << cols
              << ", \"leaf_bytes\": " << rows * 8 << ", \"gpu_reps\": " << gpu_reps
              << ", \"resident_matrix_bytes\": " << total * 8 << "},\n"
              << "  \"device\": {\"name\": \"" << json_escape(prop.name) << "\", \"cc\": \""
              << prop.major << '.' << prop.minor << "\", \"sm_count\": " << prop.multiProcessorCount
              << ", \"global_memory_bytes\": " << prop.totalGlobalMem << "}\n"
              << "}\n";
    return (correct && timing_sane) ? 0 : 1;
}
