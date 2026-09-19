#ifdef __CUDACC__
#include <cuda_runtime.h>
#endif

#include <algorithm>
#include <chrono>
#include <cmath>
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
constexpr uint64_t GENERATOR = 7;
constexpr uint64_t SEED = 0xC7'01'FF'70'25'02'00'01ULL;
constexpr size_t ARENA_BYTES = 6'442'450'944ULL;
constexpr int BLOCK = 256;

#ifdef __CUDACC__
#define HD __host__ __device__
#else
#define HD
#endif

HD inline uint64_t fp_add(uint64_t a, uint64_t b) {
    const uint64_t r0 = a + b;
    const bool carry = r0 < a;
    uint64_t r = carry ? r0 + EPSILON : r0;
    if (r >= P) r -= P;
    return r;
}

HD inline uint64_t fp_sub(uint64_t a, uint64_t b) {
    const uint64_t r = a - b;
    return a < b ? r - EPSILON : r;
}

HD inline uint64_t fp_mul(uint64_t a, uint64_t b) {
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

HD uint64_t fp_pow(uint64_t base, uint64_t exponent) {
    uint64_t out = 1;
    while (exponent) {
        if (exponent & 1) out = fp_mul(out, base);
        base = fp_mul(base, base);
        exponent >>= 1;
    }
    return out;
}

HD inline uint64_t splitmix64(uint64_t x) {
    x += 0x9E37'79B9'7F4A'7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58'476D'1CE4'E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D0'49BB'1331'11EBULL;
    return x ^ (x >> 31);
}

HD inline uint64_t canonical(uint64_t x) { return x >= P ? x - P : x; }

HD inline uint32_t bit_reverse(uint32_t x, int bits) {
    uint32_t out = 0;
    for (int i = 0; i < bits; ++i) {
        out = (out << 1) | (x & 1);
        x >>= 1;
    }
    return out;
}

uint64_t root_of_unity(size_t n) {
    if (!n || (n & (n - 1)) || n > (size_t{1} << 32)) {
        std::cerr << "FFT length exceeds Goldilocks two-adicity\n";
        std::exit(2);
    }
    return fp_pow(GENERATOR, (P - 1) / n);
}

void fill_host(std::vector<uint64_t>& values) {
    for (size_t i = 0; i < values.size(); ++i) values[i] = canonical(splitmix64(SEED + i));
}

void fft_radix2(std::vector<uint64_t>& values, uint64_t omega) {
    const size_t n = values.size();
    const int bits = static_cast<int>(std::log2(n));
    for (size_t i = 0; i < n; ++i) {
        const size_t j = bit_reverse(static_cast<uint32_t>(i), bits);
        if (i < j) std::swap(values[i], values[j]);
    }
    for (size_t len = 2; len <= n; len <<= 1) {
        const uint64_t step = fp_pow(omega, n / len);
        for (size_t base = 0; base < n; base += len) {
            uint64_t w = 1;
            for (size_t j = 0; j < len / 2; ++j) {
                const uint64_t a = values[base + j];
                const uint64_t b = fp_mul(w, values[base + j + len / 2]);
                values[base + j] = fp_add(a, b);
                values[base + j + len / 2] = fp_sub(a, b);
                w = fp_mul(w, step);
            }
        }
    }
}

std::vector<uint64_t> dft(const std::vector<uint64_t>& input, uint64_t omega) {
    std::vector<uint64_t> out(input.size());
    for (size_t k = 0; k < input.size(); ++k) {
        const uint64_t step = fp_pow(omega, k);
        uint64_t w = 1;
        for (uint64_t x : input) {
            out[k] = fp_add(out[k], fp_mul(x, w));
            w = fp_mul(w, step);
        }
    }
    return out;
}

void transpose(std::vector<uint64_t>& values, size_t m) {
    for (size_t row = 0; row < m; ++row)
        for (size_t column = row + 1; column < m; ++column)
            std::swap(values[row * m + column], values[column * m + row]);
}

void five_pass_fft(std::vector<uint64_t>& values, size_t m, uint64_t omega_n) {
    const size_t n = m * m;
    const uint64_t omega_m = fp_pow(omega_n, m);
    transpose(values, m);
    for (size_t row = 0; row < m; ++row) {
        std::vector<uint64_t> current(values.begin() + row * m, values.begin() + (row + 1) * m);
        fft_radix2(current, omega_m);
        std::copy(current.begin(), current.end(), values.begin() + row * m);
    }
    for (size_t row = 0; row < m; ++row) {
        values[row * m + row] = fp_mul(values[row * m + row], fp_pow(omega_n, row * row));
        for (size_t column = row + 1; column < m; ++column) {
            const uint64_t twiddle = fp_pow(omega_n, row * column);
            const uint64_t a = fp_mul(values[row * m + column], twiddle);
            const uint64_t b = fp_mul(values[column * m + row], twiddle);
            values[row * m + column] = b;
            values[column * m + row] = a;
        }
    }
    for (size_t row = 0; row < m; ++row) {
        std::vector<uint64_t> current(values.begin() + row * m, values.begin() + (row + 1) * m);
        fft_radix2(current, omega_m);
        std::copy(current.begin(), current.end(), values.begin() + row * m);
    }
    transpose(values, m);
    (void)n;
}

void odd_fft_parity_scattered(std::vector<uint64_t>& values, size_t m, uint64_t omega_n) {
    const size_t half = m * m;
    for (size_t parity = 0; parity < 2; ++parity) {
        std::vector<uint64_t> current(
            values.begin() + parity * half, values.begin() + (parity + 1) * half);
        five_pass_fft(current, m, fp_mul(omega_n, omega_n));
        std::copy(current.begin(), current.end(), values.begin() + parity * half);
    }
    for (size_t k = 0; k < half; ++k) {
        const uint64_t a = values[k];
        const uint64_t b = fp_mul(fp_pow(omega_n, k), values[half + k]);
        values[k] = fp_add(a, b);
        values[half + k] = fp_sub(a, b);
    }
}

uint64_t checksum(const std::vector<uint64_t>& values) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (uint64_t value : values) {
        h ^= value;
        h *= 0x0000'0100'0000'01B3ULL;
    }
    return h;
}

std::string hex64(uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

bool field_self_check() {
    for (uint64_t i = 0; i < 64; ++i) {
        const uint64_t a = canonical(splitmix64(SEED + 2 * i));
        const uint64_t b = canonical(splitmix64(SEED + 2 * i + 1));
        const uint64_t want = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(a) * b) % P);
        if (fp_mul(a, b) != want) return false;
    }
    return true;
}

bool index_self_check() {
    for (unsigned bits = 1; bits <= 11; ++bits) {
        const size_t m = size_t{1} << bits;
        for (unsigned stage = 1; stage <= bits; ++stage) {
            const size_t half = size_t{1} << (stage-1), len = half*2;
            for (size_t pair = 0; pair < m/2; ++pair) {
                const size_t offset = pair & (half-1);
                if (((pair >> (stage-1)) << stage) != (pair/half)*len ||
                    offset != pair % half ||
                    (offset << (2*bits-stage)) != offset*(m/len)*m) return false;
            }
        }
    }
    return true;
}

struct TileModelCheck {
    bool plain;
    bool twiddled;
    bool unique_coverage;
};

std::pair<std::vector<uint64_t>, bool> tiled_transpose_model(
    const std::vector<uint64_t>& input, size_t m, const std::vector<uint64_t>* twiddles) {
    std::vector<uint64_t> out = input;
    std::vector<uint8_t> writes(input.size());
    const size_t tiles = (m + 31) / 32;
    for (size_t tile_row = 0; tile_row < tiles; ++tile_row) {
        for (size_t tile_column = 0; tile_column <= tile_row; ++tile_column) {
            uint64_t a[32][32]{}, b[32][32]{};
            for (size_t row = 0; row < 32; ++row)
                for (size_t column = 0; column < 32; ++column) {
                    const size_t ar = tile_row * 32 + row, ac = tile_column * 32 + column;
                    const size_t br = tile_column * 32 + row, bc = tile_row * 32 + column;
                    if (ar < m && ac < m) a[row][column] = out[ar * m + ac];
                    if (br < m && bc < m) b[row][column] = out[br * m + bc];
                }
            for (size_t row = 0; row < 32; ++row)
                for (size_t column = 0; column < 32; ++column) {
                    const size_t ar = tile_row * 32 + row, ac = tile_column * 32 + column;
                    if (ar < m && ac < m) {
                        uint64_t value = tile_row == tile_column ? a[column][row] : b[column][row];
                        if (twiddles)
                            value = fp_mul(value, (*twiddles)[(tile_column * 32 + column) *
                                                              (tile_row * 32 + row)]);
                        out[ar * m + ac] = value;
                        ++writes[ar * m + ac];
                    }
                    if (tile_row != tile_column) {
                        const size_t br = tile_column * 32 + row, bc = tile_row * 32 + column;
                        if (br < m && bc < m) {
                            uint64_t value = a[column][row];
                            if (twiddles)
                                value = fp_mul(value, (*twiddles)[(tile_row * 32 + column) *
                                                                  (tile_column * 32 + row)]);
                            out[br * m + bc] = value;
                            ++writes[br * m + bc];
                        }
                    }
                }
        }
    }
    return {out, std::all_of(writes.begin(), writes.end(), [](uint8_t n) { return n == 1; })};
}

TileModelCheck tile_model_check() {
    constexpr size_t m = 64, n = m * m;
    std::vector<uint64_t> input(n), twiddles(n), plain_reference(n), twiddle_reference(n);
    fill_host(input);
    const uint64_t omega = root_of_unity(n);
    for (size_t i = 0; i < n; ++i) twiddles[i] = fp_pow(omega, i);
    for (size_t row = 0; row < m; ++row)
        for (size_t column = 0; column < m; ++column) {
            plain_reference[column * m + row] = input[row * m + column];
            twiddle_reference[column * m + row] =
                fp_mul(input[row * m + column], twiddles[row * column]);
        }
    const auto plain = tiled_transpose_model(input, m, nullptr);
    const auto twiddled = tiled_transpose_model(input, m, &twiddles);
    return {
        plain.first == plain_reference,
        twiddled.first == twiddle_reference,
        plain.second && twiddled.second,
    };
}

int host_check(int log2_m) {
    if (log2_m < 1 || log2_m > 4) return 2;
    const size_t m = size_t{1} << log2_m;
    const size_t n = m * m;
    const uint64_t omega = root_of_unity(n);
    std::vector<uint64_t> input(n);
    fill_host(input);
    auto radix = input;
    auto blocked = input;
    fft_radix2(radix, omega);
    five_pass_fft(blocked, m, omega);
    const auto direct = dft(input, omega);
    const bool root_ok = fp_pow(omega, n) == 1 && fp_pow(omega, n / 2) == P - 1;
    const bool radix_ok = radix == direct;
    const bool blocked_ok = blocked == direct;
    const bool field_ok = field_self_check() && index_self_check();
    const TileModelCheck tiles = tile_model_check();
    std::cout << "{\"schema\":\"volta-c71-fft-microbench-v1\",\"mode\":\"host-check\""
              << ",\"field\":{\"base_modulus\":" << P << ",\"generator\":" << GENERATOR
              << ",\"element_bytes\":8}"
              << ",\"input\":{\"generator\":\"splitmix64-v1\",\"seed\":\""
              << hex64(SEED) << "\",\"log2_m\":" << log2_m << ",\"length\":" << n << "}"
              << ",\"algorithm\":{\"passes\":5,\"layout\":\"natural-order\""
              << ",\"steps\":[\"transpose\",\"row-fft\",\"twiddle-transpose\",\"row-fft\",\"transpose\"]}"
              << ",\"correctness\":{\"field\":" << (field_ok ? "true" : "false")
              << ",\"primitive_root\":" << (root_ok ? "true" : "false")
              << ",\"radix2_vs_dft\":" << (radix_ok ? "true" : "false")
              << ",\"five_pass_vs_dft\":" << (blocked_ok ? "true" : "false")
              << ",\"tile_pair_plain_m64\":" << (tiles.plain ? "true" : "false")
              << ",\"tile_pair_twiddle_m64\":" << (tiles.twiddled ? "true" : "false")
              << ",\"tile_pair_unique_coverage_m64\":"
              << (tiles.unique_coverage ? "true" : "false") << "}"
              << ",\"checksum\":\"" << hex64(checksum(blocked)) << "\"}\n";
    return field_ok && root_ok && radix_ok && blocked_ok && tiles.plain && tiles.twiddled &&
                   tiles.unique_coverage
        ? 0
        : 1;
}

int host_check_odd(int log2_m) {
    if (log2_m < 1 || log2_m > 4) return 2;
    const size_t m = size_t{1} << log2_m, half = m * m, n = 2 * half;
    const uint64_t omega = root_of_unity(n);
    std::vector<uint64_t> input(n), scattered(n);
    fill_host(input);
    for (size_t i = 0; i < n; ++i) scattered[(i & 1) * half + i / 2] = input[i];
    odd_fft_parity_scattered(scattered, m, omega);
    const auto direct = dft(input, omega);
    const bool root_ok = fp_pow(omega, n) == 1 && fp_pow(omega, n / 2) == P - 1;
    const bool odd_ok = scattered == direct;
    std::cout << "{\"schema\":\"volta-c71-fft-microbench-v1\",\"mode\":\"host-check-odd\""
              << ",\"input\":{\"log2_m\":" << log2_m << ",\"length\":" << n << "}"
              << ",\"algorithm\":{\"square_passes\":5,\"merge_passes\":1"
              << ",\"layout\":\"parity-scattered-input/natural-order-output\"}"
              << ",\"correctness\":{\"primitive_root\":" << (root_ok ? "true" : "false")
              << ",\"odd_adapter_vs_dft\":" << (odd_ok ? "true" : "false") << "}"
              << ",\"merge\":{\"value_read_bytes\":" << 8 * n
              << ",\"value_write_bytes\":" << 8 * n
              << ",\"twiddle_read_bytes\":" << 4 * n
              << ",\"twiddle_table_bytes\":" << 8 * n
              << ",\"additional_twiddle_table_bytes_vs_square\":" << 4 * n
              << ",\"additional_twiddle_initialization_write_bytes\":" << 4 * n
              << ",\"field_multiplications\":" << n / 2
              << ",\"field_additions\":" << n / 2
              << ",\"field_subtractions\":" << n / 2 << "}"
              << ",\"whole_fft\":{\"value_read_write_bytes\":" << 12 * 8 * n
              << ",\"twiddle_read_bytes\":" << 4 * n * (2 * log2_m + 3)
              << ",\"butterflies\":" << n * (2 * log2_m + 1) / 2
              << ",\"square_cross_multiplications\":" << n << "}"
              << ",\"checksum\":\"" << hex64(checksum(scattered)) << "\"}\n";
    return root_ok && odd_ok ? 0 : 1;
}

#ifdef __CUDACC__

#define CUDA_CHECK(call)                                                                    \
    do {                                                                                    \
        const cudaError_t error__ = (call);                                                 \
        if (error__ != cudaSuccess) {                                                       \
            std::cerr << #call << ": " << cudaGetErrorString(error__) << "\n";             \
            std::exit(2);                                                                   \
        }                                                                                   \
    } while (0)

__global__ void init_kernel(uint64_t* values, size_t count) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < count) values[i] = canonical(splitmix64(SEED + i));
}

__global__ void twiddle_init_kernel(uint64_t* twiddles, size_t n, uint64_t omega) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) twiddles[i] = fp_pow(omega, i);
}

template <bool APPLY_TWIDDLE>
__global__ void tiled_transpose_kernel(
    uint64_t* values, const uint64_t* twiddles, size_t m, size_t twiddle_stride) {
    __shared__ uint64_t tile_a[32][33];
    __shared__ uint64_t tile_b[32][33];
    const size_t tile_column = blockIdx.x, tile_row = blockIdx.y;
    if (tile_row < tile_column) return;
    const size_t local_column = threadIdx.x;
    const size_t n = m * m, base = static_cast<size_t>(blockIdx.z) * n;
    for (size_t lane = threadIdx.y; lane < 32; lane += blockDim.y) {
        const size_t row_a = tile_row * 32 + lane;
        const size_t column_a = tile_column * 32 + local_column;
        const size_t row_b = tile_column * 32 + lane;
        const size_t column_b = tile_row * 32 + local_column;
        tile_a[lane][local_column] = row_a < m && column_a < m
            ? values[base + row_a * m + column_a]
            : 0;
        tile_b[lane][local_column] = row_b < m && column_b < m
            ? values[base + row_b * m + column_b]
            : 0;
    }
    __syncthreads();
    for (size_t lane = threadIdx.y; lane < 32; lane += blockDim.y) {
        const size_t row_a = tile_row * 32 + lane;
        const size_t column_a = tile_column * 32 + local_column;
        if (row_a < m && column_a < m) {
            uint64_t value = tile_b[local_column][lane];
            if (tile_row == tile_column) value = tile_a[local_column][lane];
            if (APPLY_TWIDDLE) {
                const size_t source_row = tile_column * 32 + local_column;
                const size_t source_column = tile_row * 32 + lane;
                value = fp_mul(value, twiddles[twiddle_stride * source_row * source_column]);
            }
            values[base + row_a * m + column_a] = value;
        }
        if (tile_row != tile_column) {
            const size_t row_b = tile_column * 32 + lane;
            const size_t column_b = tile_row * 32 + local_column;
            if (row_b < m && column_b < m) {
                uint64_t value = tile_a[local_column][lane];
                if (APPLY_TWIDDLE) {
                    const size_t source_row = tile_row * 32 + local_column;
                    const size_t source_column = tile_column * 32 + lane;
                    value = fp_mul(value, twiddles[twiddle_stride * source_row * source_column]);
                }
                values[base + row_b * m + column_b] = value;
            }
        }
    }
}

__global__ void row_fft_kernel(
    uint64_t* values, const uint64_t* twiddles, size_t m, int log2_m, size_t rows,
    size_t twiddle_stride) {
    extern __shared__ uint64_t shared[];
    const size_t row = blockIdx.x;
    if (row >= rows) return;
    uint64_t* data = values + row * m;
    for (size_t i = threadIdx.x; i < m; i += blockDim.x)
        shared[__brev(static_cast<uint32_t>(i)) >> (32-log2_m)] = data[i];
    __syncthreads();
    for (int stage = 1; stage <= log2_m; ++stage) {
        const size_t half = size_t{1} << (stage-1);
        for (size_t pair = threadIdx.x; pair < m / 2; pair += blockDim.x) {
            const size_t base = (pair >> (stage-1)) << stage;
            const size_t offset = pair & (half-1);
            const uint64_t w = twiddles[twiddle_stride * (offset << (2*log2_m-stage))];
            const uint64_t a = shared[base + offset];
            const uint64_t b = fp_mul(w, shared[base + offset + half]);
            shared[base + offset] = fp_add(a, b);
            shared[base + offset + half] = fp_sub(a, b);
        }
        __syncthreads();
    }
    for (size_t i = threadIdx.x; i < m; i += blockDim.x) data[i] = shared[i];
}

void launch_five_pass(
    uint64_t* values, const uint64_t* twiddles, size_t m, int log2_m, size_t batch,
    size_t twiddle_stride = 1) {
    const size_t tiles = (m + 31) / 32;
    const dim3 grid(tiles, tiles, batch), threads(32, 8);
    tiled_transpose_kernel<false><<<grid, threads>>>(values, nullptr, m, twiddle_stride);
    CUDA_CHECK(cudaGetLastError());
    row_fft_kernel<<<batch * m, BLOCK, m * sizeof(uint64_t)>>>(
        values, twiddles, m, log2_m, batch * m, twiddle_stride);
    CUDA_CHECK(cudaGetLastError());
    tiled_transpose_kernel<true><<<grid, threads>>>(values, twiddles, m, twiddle_stride);
    CUDA_CHECK(cudaGetLastError());
    row_fft_kernel<<<batch * m, BLOCK, m * sizeof(uint64_t)>>>(
        values, twiddles, m, log2_m, batch * m, twiddle_stride);
    CUDA_CHECK(cudaGetLastError());
    tiled_transpose_kernel<false><<<grid, threads>>>(values, nullptr, m, twiddle_stride);
    CUDA_CHECK(cudaGetLastError());
}

__global__ void odd_init_kernel(uint64_t* values, size_t n, size_t count) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= count) return;
    const size_t local = i % n, base = i - local, half = n / 2;
    values[base + (local & 1) * half + local / 2] = canonical(splitmix64(SEED + i));
}

__global__ void radix2_merge_kernel(
    uint64_t* values, const uint64_t* twiddles, size_t half, size_t butterflies) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= butterflies) return;
    const size_t k = i % half, base = 2 * (i - k);
    const uint64_t a = values[base + k];
    const uint64_t b = fp_mul(twiddles[k], values[base + half + k]);
    values[base + k] = fp_add(a, b);
    values[base + half + k] = fp_sub(a, b);
}

void launch_odd_fft(
    uint64_t* values, const uint64_t* twiddles, size_t m, int log2_m, size_t batch) {
    const size_t half = m * m, butterflies = batch * half;
    launch_five_pass(values, twiddles, m, log2_m, 2 * batch, 2);
    radix2_merge_kernel<<<(butterflies + BLOCK - 1) / BLOCK, BLOCK>>>(
        values, twiddles, half, butterflies);
    CUDA_CHECK(cudaGetLastError());
}

template <typename Launch>
double median_ms(int reps, Launch launch) {
    cudaEvent_t begin, end;
    CUDA_CHECK(cudaEventCreate(&begin));
    CUDA_CHECK(cudaEventCreate(&end));
    launch();
    CUDA_CHECK(cudaDeviceSynchronize());
    std::vector<float> samples;
    for (int rep = 0; rep < reps; ++rep) {
        CUDA_CHECK(cudaEventRecord(begin));
        launch();
        CUDA_CHECK(cudaEventRecord(end));
        CUDA_CHECK(cudaEventSynchronize(end));
        float elapsed = 0;
        CUDA_CHECK(cudaEventElapsedTime(&elapsed, begin, end));
        samples.push_back(elapsed);
    }
    CUDA_CHECK(cudaEventDestroy(begin));
    CUDA_CHECK(cudaEventDestroy(end));
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

bool gpu_correctness() {
    // Exercise off-diagonal tile pairs as well as diagonal tiles before timing.
    constexpr int log2_m = 6;
    constexpr size_t m = 1 << log2_m, n = m * m, batch = 2;
    const uint64_t omega = root_of_unity(n);
    std::vector<uint64_t> input(batch * n), want(batch * n), got(batch * n), twiddle(n);
    fill_host(input);
    for (size_t b = 0; b < batch; ++b) {
        std::vector<uint64_t> current(input.begin() + b * n, input.begin() + (b + 1) * n);
        fft_radix2(current, omega);
        std::copy(current.begin(), current.end(), want.begin() + b * n);
    }
    for (size_t i = 0; i < n; ++i) twiddle[i] = fp_pow(omega, i);
    uint64_t *device_values = nullptr, *device_twiddles = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_values), input.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_twiddles), twiddle.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(device_values, input.data(), input.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(device_twiddles, twiddle.data(), twiddle.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
    launch_five_pass(device_values, device_twiddles, m, log2_m, batch);
    CUDA_CHECK(cudaMemcpy(got.data(), device_values, got.size() * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    const bool even_ok = got == want;
    CUDA_CHECK(cudaFree(device_twiddles));
    CUDA_CHECK(cudaFree(device_values));

    constexpr size_t odd_n = 2 * n;
    const uint64_t odd_omega = root_of_unity(odd_n);
    input.resize(odd_n);
    want.resize(odd_n);
    got.resize(odd_n);
    twiddle.resize(odd_n);
    fill_host(input);
    std::vector<uint64_t> scattered(odd_n);
    for (size_t i = 0; i < odd_n; ++i) scattered[(i & 1) * n + i / 2] = input[i];
    want = input;
    fft_radix2(want, odd_omega);
    for (size_t i = 0; i < odd_n; ++i) twiddle[i] = fp_pow(odd_omega, i);
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_values), odd_n * sizeof(uint64_t)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_twiddles), odd_n * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(
        device_values, scattered.data(), odd_n * sizeof(uint64_t), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(
        device_twiddles, twiddle.data(), odd_n * sizeof(uint64_t), cudaMemcpyHostToDevice));
    launch_odd_fft(device_values, device_twiddles, m, log2_m, 1);
    CUDA_CHECK(cudaMemcpy(
        got.data(), device_values, odd_n * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(device_twiddles));
    CUDA_CHECK(cudaFree(device_values));
    return even_ok && got == want;
}

std::string escape(const char* text) {
    std::ostringstream out;
    for (; *text; ++text) {
        if (*text == '"' || *text == '\\') out << '\\';
        out << *text;
    }
    return out.str();
}

int gpu_bench(int log2_m, size_t batch, int reps, bool odd) {
    if (log2_m < 1 || log2_m > 12 || batch < 1 || batch > 1024 || reps < 1 || reps > 99)
        return 2;
    if (!gpu_correctness()) {
        std::cerr << "small CPU/GPU FFT correctness check failed\n";
        return 1;
    }
    const size_t m = size_t{1} << log2_m, square = m * m, n = square * (odd ? 2 : 1);
    const size_t count = batch * n;
    const size_t values_bytes = count * sizeof(uint64_t), twiddle_bytes = n * sizeof(uint64_t);
    const size_t requested = values_bytes + twiddle_bytes;
    constexpr size_t reserve = size_t{256} << 20;
    if (requested + reserve > ARENA_BYTES) {
        std::cerr << "requested FFT buffers plus reserve exceed the C7.1 arena\n";
        return 2;
    }
    size_t free_before = 0, total = 0;
    CUDA_CHECK(cudaMemGetInfo(&free_before, &total));
    if (requested + reserve > free_before) {
        std::cerr << "need " << requested << " device bytes plus reserve, have " << free_before << "\n";
        return 2;
    }
    uint64_t *values = nullptr, *twiddles = nullptr;
    const auto allocation_start = std::chrono::steady_clock::now();
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&values), values_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&twiddles), twiddle_bytes));
    const double allocation_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - allocation_start).count();
    size_t free_after = 0;
    CUDA_CHECK(cudaMemGetInfo(&free_after, &total));
    const uint64_t omega = root_of_unity(n);
    const double initialize_ms = median_ms(reps, [&] {
        if (odd)
            odd_init_kernel<<<(count + BLOCK - 1) / BLOCK, BLOCK>>>(values, n, count);
        else
            init_kernel<<<(count + BLOCK - 1) / BLOCK, BLOCK>>>(values, count);
        CUDA_CHECK(cudaGetLastError());
    });
    const double twiddle_initialize_ms = median_ms(reps, [&] {
        twiddle_init_kernel<<<(n + BLOCK - 1) / BLOCK, BLOCK>>>(twiddles, n, omega);
        CUDA_CHECK(cudaGetLastError());
    });
    const double fft_ms = median_ms(reps, [&] {
        if (odd)
            launch_odd_fft(values, twiddles, m, log2_m, batch);
        else
            launch_five_pass(values, twiddles, m, log2_m, batch);
    });
    std::vector<uint64_t> sample(4);
    CUDA_CHECK(cudaMemcpy(sample.data(), values, 2 * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(sample.data() + 2, values + count - 2, 2 * sizeof(uint64_t), cudaMemcpyDeviceToHost));
    int device = 0, runtime = 0, driver = 0;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDevice(&device));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    CUDA_CHECK(cudaRuntimeGetVersion(&runtime));
    CUDA_CHECK(cudaDriverGetVersion(&driver));
    CUDA_CHECK(cudaFree(twiddles));
    CUDA_CHECK(cudaFree(values));
    std::cout << std::setprecision(12)
              << "{\"schema\":\"volta-c71-fft-microbench-v1\",\"mode\":\""
              << (odd ? "cuda-odd" : "cuda") << "\""
              << ",\"field\":{\"base_modulus\":" << P << ",\"generator\":" << GENERATOR
              << ",\"element_bytes\":8}"
              << ",\"input\":{\"generator\":\"splitmix64-v1\",\"seed\":\""
              << hex64(SEED) << "\",\"log2_m\":" << log2_m << ",\"m\":" << m
              << ",\"length\":" << n << ",\"batch\":" << batch << "}"
              << ",\"algorithm\":{\"passes\":" << (odd ? 6 : 5)
              << ",\"layout\":\"" << (odd ? "parity-scattered-input/natural-order-output" : "natural-order") << "\""
              << ",\"steps\":[\"transpose\",\"row-fft\",\"twiddle-transpose\",\"row-fft\",\"transpose\""
              << (odd ? ",\"radix2-merge\"]}" : "]}")
              << ",\"device\":{\"name\":\"" << escape(prop.name) << "\",\"total_bytes\":" << total
              << ",\"free_before_bytes\":" << free_before << ",\"free_after_alloc_bytes\":" << free_after
              << ",\"runtime_version\":" << runtime << ",\"driver_version\":" << driver << "}"
              << ",\"allocation\":{\"values_bytes\":" << values_bytes
              << ",\"twiddle_bytes\":" << twiddle_bytes << ",\"requested_peak_bytes\":" << requested
              << ",\"transpose_static_shared_bytes_per_block\":16896"
              << ",\"row_fft_dynamic_shared_bytes_per_block\":" << m * sizeof(uint64_t)
              << ",\"observed_free_delta_bytes\":" << free_before - free_after
              << ",\"allocation_ms\":" << allocation_ms << "}"
              << ",\"timing_ms\":{\"initialize\":" << initialize_ms
              << ",\"twiddle_initialize\":" << twiddle_initialize_ms
              << (odd ? ",\"fft\":" : ",\"five_pass_fft\":") << fft_ms << "}"
              << ",\"logical_global_traffic_bytes\":"
              << (odd ? 12 * values_bytes : 10 * values_bytes)
              << ",\"logical_global_traffic_scope\":\"value-array-only; twiddle reads in work\""
              << ",\"odd_merge\":{\"value_read_bytes\":" << (odd ? 8 * count : 0)
              << ",\"value_write_bytes\":" << (odd ? 8 * count : 0)
              << ",\"twiddle_read_bytes\":" << (odd ? 4 * count : 0)
              << ",\"field_multiplications\":" << (odd ? count / 2 : 0)
              << ",\"field_additions\":" << (odd ? count / 2 : 0)
              << ",\"field_subtractions\":" << (odd ? count / 2 : 0) << "}"
              << ",\"work\":{\"twiddle_read_bytes\":"
              << 4 * count * (2 * log2_m + 2 + (odd ? 1 : 0))
              << ",\"butterflies\":" << count * (2 * log2_m + (odd ? 1 : 0)) / 2
              << ",\"square_cross_multiplications\":" << count
              << ",\"twiddle_table_bytes\":" << twiddle_bytes
              << ",\"additional_twiddle_table_bytes_vs_square\":"
              << (odd ? 4 * count / batch : 0)
              << ",\"additional_twiddle_initialization_write_bytes_vs_square\":"
              << (odd ? 4 * count / batch : 0) << "}"
              << ",\"rates\":{\"field_elements_per_second\":"
              << count / (fft_ms / 1000.0) << "}"
              << ",\"correctness\":{\"small_cpu_gpu_natural_order\":true}"
              << ",\"sample_checksum\":\"" << hex64(checksum(sample)) << "\"}\n";
    return 0;
}

#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--host-check")
        return host_check(std::stoi(argv[2]));
    if (argc == 3 && std::string(argv[1]) == "--host-check-odd")
        return host_check_odd(std::stoi(argv[2]));
#ifdef __CUDACC__
    if (argc == 5 && std::string(argv[1]) == "--gpu")
        return gpu_bench(std::stoi(argv[2]), std::stoull(argv[3]), std::stoi(argv[4]), false);
    if (argc == 5 && std::string(argv[1]) == "--gpu-odd")
        return gpu_bench(std::stoi(argv[2]), std::stoull(argv[3]), std::stoi(argv[4]), true);
#endif
    std::cerr << "usage: " << argv[0] << " --host-check[-odd] LOG2_M";
#ifdef __CUDACC__
    std::cerr << " | --gpu[-odd] LOG2_M BATCH REPS";
#endif
    std::cerr << "\n";
    return 2;
}
