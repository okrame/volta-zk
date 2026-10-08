// Existing C7.1 five-pass FFT, in place, natural-order output.
// Includer provides the original canonical fp_add/fp_sub/fp_mul and P.
#pragma once
#ifdef __CUDACC__
#define C71_FFT_HD __host__ __device__
#else
#define C71_FFT_HD
#endif
namespace c71_fft {
C71_FFT_HD inline uint64_t fp_pow(uint64_t base, uint64_t exponent) {
    uint64_t out = 1;
    while (exponent) {
        if (exponent & 1) out = fp_mul(out, base);
        base = fp_mul(base, base);
        exponent >>= 1;
    }
    return out;
}

inline uint32_t bit_reverse(uint32_t x, int bits) {
    uint32_t out=0;
    for(int i=0;i<bits;++i) { out=(out<<1)|(x&1); x>>=1; }
    return out;
}
inline void fft_radix2(std::vector<uint64_t>& values, uint64_t omega) {
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

inline std::vector<uint64_t> dft(const std::vector<uint64_t>& input, uint64_t omega) {
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

inline void transpose(std::vector<uint64_t>& values, size_t m) {
    for (size_t row = 0; row < m; ++row)
        for (size_t column = row + 1; column < m; ++column)
            std::swap(values[row * m + column], values[column * m + row]);
}

inline void five_pass_fft(std::vector<uint64_t>& values, size_t m, uint64_t omega_n) {
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

#ifdef __CUDACC__
template <bool APPLY_TWIDDLE, bool NORMALIZE = false>
__global__ void tiled_transpose_kernel(
    uint64_t* values, const uint64_t* twiddles, size_t m, size_t twiddle_stride,
    uint64_t scale = 1) {
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
            if constexpr (NORMALIZE) value = fp_mul(value, scale);
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
                if constexpr (NORMALIZE) value = fp_mul(value, scale);
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

inline cudaError_t launch_five_pass(
    cudaStream_t stream, uint64_t* values, const uint64_t* twiddles, size_t m, int log2_m, size_t batch,
    size_t twiddle_stride = 1, bool inverse = false, unsigned* attempted = nullptr) {
    const size_t tiles = (m + 31) / 32;
    const dim3 grid(tiles, tiles, batch), threads(32, 8);
    if(attempted) ++*attempted;
    tiled_transpose_kernel<false><<<grid, threads, 0, stream>>>(values, nullptr, m, twiddle_stride);
    if (const auto error=cudaGetLastError(); error!=cudaSuccess) return error;
    if(attempted) ++*attempted;
    row_fft_kernel<<<batch * m, 256, m * sizeof(uint64_t), stream>>>(
        values, twiddles, m, log2_m, batch * m, twiddle_stride);
    if (const auto error=cudaGetLastError(); error!=cudaSuccess) return error;
    if(attempted) ++*attempted;
    tiled_transpose_kernel<true><<<grid, threads, 0, stream>>>(values, twiddles, m, twiddle_stride);
    if (const auto error=cudaGetLastError(); error!=cudaSuccess) return error;
    if(attempted) ++*attempted;
    row_fft_kernel<<<batch * m, 256, m * sizeof(uint64_t), stream>>>(
        values, twiddles, m, log2_m, batch * m, twiddle_stride);
    if (const auto error=cudaGetLastError(); error!=cudaSuccess) return error;
    if(attempted) ++*attempted;
    if (inverse)
        tiled_transpose_kernel<false, true><<<grid, threads, 0, stream>>>(
            values, nullptr, m, twiddle_stride, fp_pow(m * m, P - 2));
    else
        tiled_transpose_kernel<false><<<grid, threads, 0, stream>>>(values, nullptr, m, twiddle_stride);
    if (const auto error=cudaGetLastError(); error!=cudaSuccess) return error;
    return cudaSuccess;
}

#endif
}
#undef C71_FFT_HD
