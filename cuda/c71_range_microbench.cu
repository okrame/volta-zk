#ifdef __CUDACC__
#include <cuda_runtime.h>
#endif

#include <algorithm>
#include <array>
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
constexpr uint64_t SEED = 0xC7'01'35'11'25'02'00'01ULL;
constexpr int BLOCK = 256;
constexpr size_t ARENA_BYTES = 6'442'450'944ULL;

#ifdef __CUDACC__
#define HD __host__ __device__
#else
#define HD
#endif

struct Fp3 {
    uint64_t c0, c1, c2;
};

struct Coeff4 {
    Fp3 c[4];
};

static_assert(sizeof(Fp3) == 24, "C7 Fp3 must use three canonical u64 limbs");
static_assert(sizeof(Coeff4) == 96, "four cubic coefficients must occupy 96 bytes");

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

HD inline Fp3 add(Fp3 a, Fp3 b) {
    return {fp_add(a.c0, b.c0), fp_add(a.c1, b.c1), fp_add(a.c2, b.c2)};
}

HD inline Fp3 sub(Fp3 a, Fp3 b) {
    return {fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1), fp_sub(a.c2, b.c2)};
}

// Mirrors volta-field: Fp3 = Fp[u]/(u^3 - 2), not the Fp2 x^2 - 7 field.
HD inline Fp3 mul(Fp3 a, Fp3 b) {
    const uint64_t c0 = fp_add(
        fp_mul(a.c0, b.c0),
        fp_mul(2, fp_add(fp_mul(a.c1, b.c2), fp_mul(a.c2, b.c1))));
    const uint64_t c1 = fp_add(
        fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
        fp_mul(2, fp_mul(a.c2, b.c2)));
    const uint64_t c2 = fp_add(
        fp_add(fp_mul(a.c0, b.c2), fp_mul(a.c1, b.c1)), fp_mul(a.c2, b.c0));
    return {c0, c1, c2};
}

// Cost-screen alternative; the timed baseline below still uses mul().
HD inline Fp3 mul6(Fp3 a, Fp3 b) {
    const uint64_t p0 = fp_mul(a.c0, b.c0), p1 = fp_mul(a.c1, b.c1);
    const uint64_t p2 = fp_mul(a.c2, b.c2);
    const uint64_t p01 = fp_sub(fp_sub(fp_mul(fp_add(a.c0, a.c1), fp_add(b.c0, b.c1)), p0), p1);
    const uint64_t p02 = fp_sub(fp_sub(fp_mul(fp_add(a.c0, a.c2), fp_add(b.c0, b.c2)), p0), p2);
    const uint64_t p12 = fp_sub(fp_sub(fp_mul(fp_add(a.c1, a.c2), fp_add(b.c1, b.c2)), p1), p2);
    return {fp_add(p0, fp_add(p12, p12)), fp_add(p01, fp_add(p2, p2)), fp_add(p02, p1)};
}

// Integer bias maps W to uint16; alpha is shifted by the SAME public bias.
// A uses its uint8 value with zero bias. No secret-indexed lookup table.
HD inline void leaf_pair(uint16_t x, uint16_t y, Fp3 alpha, Fp3 alpha2,
                         Fp3& numerator, Fp3& denominator) {
    const uint64_t sum = uint64_t(x)+y, product = uint64_t(x)*y;
    numerator = sub(add(alpha, alpha), {sum, 0, 0});
    denominator = add(sub(alpha2, {fp_mul(alpha.c0, sum), fp_mul(alpha.c1, sum),
                                   fp_mul(alpha.c2, sum)}), {product, 0, 0});
}

HD inline Fp3 fold(Fp3 a, Fp3 b, Fp3 r) {
    return add(a, mul(sub(b, a), r));
}

HD inline Coeff4 coeff_add(Coeff4 a, Coeff4 b) {
    for (int i = 0; i < 4; ++i) a.c[i] = add(a.c[i], b.c[i]);
    return a;
}

HD inline Coeff4 cubic_coeff_direct(
    const Fp3 child[4][2], const Fp3 equality[2], Fp3 lambda) {
    Fp3 a[4], d[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = child[i][0];
        d[i] = sub(child[i][1], a[i]);
    }
    Fp3 v[3]{};
    const int xs[3] = {0, 2, 1};
    const int ys[3] = {3, 1, 3};
    for (int term = 0; term < 3; ++term) {
        const Fp3 scale = term < 2 ? lambda : Fp3{1, 0, 0};
        const int x = xs[term], y = ys[term];
        v[0] = add(v[0], mul(scale, mul(a[x], a[y])));
        v[1] = add(v[1], mul(scale, add(mul(d[x], a[y]), mul(a[x], d[y]))));
        v[2] = add(v[2], mul(scale, mul(d[x], d[y])));
    }
    const Fp3 de = sub(equality[1], equality[0]);
    Coeff4 out{};
    for (int i = 0; i < 3; ++i) {
        out.c[i] = add(out.c[i], mul(equality[0], v[i]));
        out.c[i + 1] = add(out.c[i + 1], mul(de, v[i]));
    }
    return out;
}

// Same polynomial as cubic_coeff_direct, factored as
// (lambda*A+B)*D + (lambda*C)*B before multiplying by the equality line.
// Per pair this uses 4 + 8 + 6 = 18 general Fp3 multiplications.
HD inline Coeff4 cubic_coeff_factored(
    const Fp3 child[4][2], const Fp3 equality[2], Fp3 lambda) {
    Fp3 a[4], d[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = child[i][0];
        d[i] = sub(child[i][1], a[i]);
    }
    const Fp3 u0 = add(mul(lambda, a[0]), a[1]);
    const Fp3 du = add(mul(lambda, d[0]), d[1]);
    const Fp3 v0 = mul(lambda, a[2]);
    const Fp3 dv = mul(lambda, d[2]);
    const Fp3 v[3] = {
        add(mul(u0, a[3]), mul(v0, a[1])),
        add(add(mul(du, a[3]), mul(u0, d[3])),
            add(mul(dv, a[1]), mul(v0, d[1]))),
        add(mul(du, d[3]), mul(dv, d[1])),
    };
    const Fp3 de = sub(equality[1], equality[0]);
    Coeff4 out{};
    for (int i = 0; i < 3; ++i) {
        out.c[i] = add(out.c[i], mul(equality[0], v[i]));
        out.c[i + 1] = add(out.c[i + 1], mul(de, v[i]));
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

HD inline Fp3 synthetic(size_t lane, size_t index) {
    const uint64_t base = SEED ^ (uint64_t{lane} << 56) ^ static_cast<uint64_t>(index);
    return {canonical(splitmix64(base)), canonical(splitmix64(base + 1)),
            canonical(splitmix64(base + 2))};
}

void fill_host(std::vector<Fp3>& values, size_t n) {
    for (size_t lane = 0; lane < 5; ++lane)
        for (size_t i = 0; i < n; ++i) values[lane * n + i] = synthetic(lane, i);
}

std::vector<Fp3> merge_cpu(const std::vector<Fp3>& src, size_t n) {
    std::vector<Fp3> out(n);
    const Fp3* p = src.data();
    const Fp3* q = p + n;
    for (size_t i = 0; i < n / 2; ++i) {
        const Fp3 a = p[2 * i], b = q[2 * i], c = p[2 * i + 1], d = q[2 * i + 1];
        out[i] = add(mul(a, d), mul(c, b));
        out[n / 2 + i] = mul(b, d);
    }
    return out;
}

Coeff4 coeff_cpu(const std::vector<Fp3>& src, size_t n, Fp3 lambda, bool factored) {
    Coeff4 total{};
    for (size_t i = 0; i < n / 2; ++i) {
        Fp3 child[4][2];
        for (int j = 0; j < 4; ++j) {
            child[j][0] = src[j * n + 2 * i];
            child[j][1] = src[j * n + 2 * i + 1];
        }
        const Fp3 equality[2] = {src[4 * n + 2 * i], src[4 * n + 2 * i + 1]};
        total = coeff_add(total, factored ? cubic_coeff_factored(child, equality, lambda)
                                          : cubic_coeff_direct(child, equality, lambda));
    }
    return total;
}

std::vector<Fp3> fold_cpu(const std::vector<Fp3>& src, size_t n, Fp3 r) {
    std::vector<Fp3> out(5 * n / 2);
    for (size_t lane = 0; lane < 5; ++lane)
        for (size_t i = 0; i < n / 2; ++i)
            out[lane * (n / 2) + i] = fold(src[lane * n + 2 * i], src[lane * n + 2 * i + 1], r);
    return out;
}

std::vector<Fp3> gram_cpu(const std::vector<Fp3>& src, size_t n, int width, Fp3 lambda) {
    const size_t buckets = n / width;
    std::vector<Fp3> out(width * width);
    for (size_t bucket = 0; bucket < buckets; ++bucket) {
        const Fp3 eq = src[4 * n + bucket];
        for (int u = 0; u < width; ++u) {
            const size_t ui = bucket * width + u;
            const Fp3 ue = mul(eq, add(mul(lambda, src[ui]), src[n + ui]));
            const Fp3 ve = mul(eq, mul(lambda, src[2 * n + ui]));
            for (int v = 0; v < width; ++v) {
                const size_t vi = bucket * width + v;
                out[u * width + v] = add(
                    out[u * width + v],
                    add(mul(ue, src[3 * n + vi]), mul(ve, src[n + vi])));
            }
        }
    }
    return out;
}

std::vector<Fp3> gram_cpu_direct(
    const std::vector<Fp3>& src, size_t n, int width, Fp3 lambda) {
    const size_t buckets = n / width;
    std::vector<Fp3> out(width * width);
    for (size_t bucket = 0; bucket < buckets; ++bucket) {
        const Fp3 eq = src[4 * n + bucket];
        for (int u = 0; u < width; ++u) {
            const size_t ui = bucket * width + u;
            for (int v = 0; v < width; ++v) {
                const size_t vi = bucket * width + v;
                const Fp3 direct = add(
                    add(mul(mul(lambda, src[ui]), src[3 * n + vi]),
                        mul(mul(lambda, src[2 * n + ui]), src[n + vi])),
                    mul(src[n + ui], src[3 * n + vi]));
                out[u * width + v] = add(out[u * width + v], mul(eq, direct));
            }
        }
    }
    return out;
}

uint64_t hash_word(uint64_t h, uint64_t x) {
    h ^= x;
    return h * 0x0000'0100'0000'01B3ULL;
}

uint64_t checksum(const Fp3* values, size_t n) {
    uint64_t h = 0xCBF2'9CE4'8422'2325ULL;
    for (size_t i = 0; i < n; ++i) {
        h = hash_word(h, values[i].c0);
        h = hash_word(h, values[i].c1);
        h = hash_word(h, values[i].c2);
    }
    return h;
}

std::string hex64(uint64_t x) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << x;
    return out.str();
}

bool equal(const std::vector<Fp3>& a, const std::vector<Fp3>& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](Fp3 x, Fp3 y) {
        return x.c0 == y.c0 && x.c1 == y.c1 && x.c2 == y.c2;
    });
}

bool equal(Coeff4 a, Coeff4 b) {
    for (int i = 0; i < 4; ++i)
        if (a.c[i].c0 != b.c[i].c0 || a.c[i].c1 != b.c[i].c1 || a.c[i].c2 != b.c[i].c2)
            return false;
    return true;
}

bool equal(Fp3 a, Fp3 b) { return a.c0 == b.c0 && a.c1 == b.c1 && a.c2 == b.c2; }

bool specialization_check() {
    for (size_t i = 0; i < 64; ++i) {
        const Fp3 a = synthetic(0, i), b = synthetic(1, i);
        if (!equal(mul6(a, b), mul(a, b))) return false;
        for (uint16_t x : {uint16_t(0), uint16_t(255), uint16_t(32767), uint16_t(65535)}) {
            const uint16_t y = uint16_t(i*1031);
            Fp3 p, q;
            leaf_pair(x, y, a, mul(a, a), p, q);
            const Fp3 u = sub(a, {x, 0, 0}), v = sub(a, {y, 0, 0});
            if (!equal(p, add(u, v)) || !equal(q, mul(u, v))) return false;
        }
    }
    return true;
}

bool merge_identity_check(const std::vector<Fp3>& src, const std::vector<Fp3>& merged, size_t n) {
    for (size_t i = 0; i < n / 2; ++i) {
        const Fp3 p0 = src[2 * i], q0 = src[n + 2 * i];
        const Fp3 p1 = src[2 * i + 1], q1 = src[n + 2 * i + 1];
        const Fp3 numerator = add(mul(p0, q1), mul(p1, q0));
        const Fp3 denominator = mul(q0, q1);
        if (!equal(merged[i], numerator) || !equal(merged[n / 2 + i], denominator) ||
            !equal(mul(merged[i], denominator),
                   mul(numerator, merged[n / 2 + i])))
            return false;
    }
    return true;
}

bool fold_linearity_check(
    const std::vector<Fp3>& src, const std::vector<Fp3>& folded, size_t n, Fp3 r) {
    const Fp3 one_minus_r = sub(Fp3{1, 0, 0}, r);
    for (size_t lane = 0; lane < 5; ++lane)
        for (size_t i = 0; i < n / 2; ++i) {
            const Fp3 want = add(mul(one_minus_r, src[lane * n + 2 * i]),
                                 mul(r, src[lane * n + 2 * i + 1]));
            if (!equal(folded[lane * (n / 2) + i], want)) return false;
        }
    return true;
}

bool field_self_check() {
    const Fp3 u{0, 1, 0};
    const Fp3 u3 = mul(mul(u, u), u);
    const Fp3 a{P - 1, P - 2, P - 3}, b{17, 19, 23}, c{29, 31, 37};
    const Fp3 lhs = mul(a, add(b, c)), rhs = add(mul(a, b), mul(a, c));
    if (u3.c0 != 2 || u3.c1 != 0 || u3.c2 != 0 || lhs.c0 != rhs.c0 ||
        lhs.c1 != rhs.c1 || lhs.c2 != rhs.c2)
        return false;
    for (uint64_t i = 0; i < 64; ++i) {
        const uint64_t x = canonical(splitmix64(SEED + 2 * i));
        const uint64_t y = canonical(splitmix64(SEED + 2 * i + 1));
        const uint64_t want = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(x) * y) % P);
        if (fp_mul(x, y) != want) return false;
    }
    return true;
}

int host_check(int log2_n, int gram_width) {
    if (log2_n < 5 || log2_n > 20 ||
        (gram_width != 8 && gram_width != 16 && gram_width != 32) ||
        (size_t{1} << log2_n) < static_cast<size_t>(gram_width))
        return 2;
    const size_t n = size_t{1} << log2_n;
    const Fp3 lambda{101, 211, 307}, r{401, 503, 607};
    std::vector<Fp3> src(5 * n);
    fill_host(src, n);
    const auto merged = merge_cpu(src, n);
    const auto coeff = coeff_cpu(src, n, lambda, false);
    const auto coeff_factored = coeff_cpu(src, n, lambda, true);
    const auto folded = fold_cpu(src, n, r);
    const auto gram = gram_cpu(src, n, gram_width, lambda);
    const auto gram_direct = gram_cpu_direct(src, n, gram_width, lambda);
    const bool merge_ok = merge_identity_check(src, merged, n);
    const bool coeff_ok = equal(coeff, coeff_factored);
    const bool fold_ok = fold_linearity_check(src, folded, n, r);
    const bool gram_ok = equal(gram, gram_direct);
    const bool field_ok = field_self_check() && specialization_check();
    const bool ok = field_ok && merge_ok && coeff_ok && fold_ok && gram_ok;
    std::cout << "{\"schema\":\"volta-c71-range-microbench-v1\",\"mode\":\"host-check\""
              << ",\"field\":{\"base_modulus\":" << P
              << ",\"extension\":\"Fp[u]/(u^3-2)\",\"fp3_bytes\":24}"
              << ",\"input\":{\"generator\":\"splitmix64-v1\",\"seed\":\""
              << hex64(SEED) << "\",\"log2_n\":" << log2_n
              << ",\"gram_width\":" << gram_width << "}"
              << ",\"operation_model\":{\"cubic_direct_oracle_fp3_mul_per_pair\":27"
              << ",\"cubic_factored_kernel_fp3_mul_per_pair\":18}"
              << ",\"correctness\":{\"field\":" << (field_ok ? "true" : "false")
              << ",\"merge\":" << (merge_ok ? "true" : "false")
              << ",\"cubic_coeff\":" << (coeff_ok ? "true" : "false")
              << ",\"fold\":" << (fold_ok ? "true" : "false")
              << ",\"gram\":" << (gram_ok ? "true" : "false") << "}"
              << ",\"checksums\":{\"merge\":\"" << hex64(checksum(merged.data(), merged.size()))
              << "\",\"cubic_coeff\":\"" << hex64(checksum(coeff.c, 4))
              << "\",\"fold\":\"" << hex64(checksum(folded.data(), folded.size()))
              << "\",\"gram\":\"" << hex64(checksum(gram.data(), gram.size())) << "\"}}\n";
    return ok ? 0 : 1;
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

__global__ void init_kernel(Fp3* values, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= 5 * n) return;
    values[i] = synthetic(i / n, i % n);
}

__global__ void merge_kernel(const Fp3* src, Fp3* dst, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n / 2) return;
    const Fp3* p = src;
    const Fp3* q = src + n;
    const Fp3 a = p[2 * i], b = q[2 * i], c = p[2 * i + 1], d = q[2 * i + 1];
    dst[i] = add(mul(a, d), mul(c, b));
    dst[n / 2 + i] = mul(b, d);
}

// Compile-only cost probes; never launched by the benchmark driver.
__global__ void cost_merge6_kernel(const Fp3* src, Fp3* dst, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n / 2) return;
    const Fp3 a = src[2*i], b = src[n+2*i], c = src[2*i+1], d = src[n+2*i+1];
    dst[i] = add(mul6(a, d), mul6(c, b));
    dst[n/2+i] = mul6(b, d);
}

__global__ void cost_leaf_pair_kernel(const uint16_t* src, Fp3* dst, size_t n,
                                      Fp3 alpha, Fp3 alpha2) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= n/2) return;
    leaf_pair(src[2*i], src[2*i+1], alpha, alpha2, dst[i], dst[n/2+i]);
}

__global__ void cost_fp_mul_kernel(const uint64_t* a, const uint64_t* b,
                                    uint64_t* out, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) out[i] = fp_mul(a[i], b[i]);
}

__global__ void cost_fp3_mul6_kernel(const Fp3* a, const Fp3* b, Fp3* out, size_t n) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i < n) out[i] = mul6(a[i], b[i]);
}

__global__ void coeff_kernel(const Fp3* src, Coeff4* out, size_t n, Fp3 lambda) {
    __shared__ Coeff4 shared[BLOCK];
    const size_t pair = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    Coeff4 value{};
    if (pair < n / 2) {
        Fp3 child[4][2];
        for (int j = 0; j < 4; ++j) {
            child[j][0] = src[j * n + 2 * pair];
            child[j][1] = src[j * n + 2 * pair + 1];
        }
        const Fp3 equality[2] = {src[4 * n + 2 * pair], src[4 * n + 2 * pair + 1]};
        value = cubic_coeff_factored(child, equality, lambda);
    }
    shared[threadIdx.x] = value;
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride)
            shared[threadIdx.x] = coeff_add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) out[blockIdx.x] = shared[0];
}

__global__ void reduce_kernel(const Coeff4* in, Coeff4* out, size_t n) {
    __shared__ Coeff4 shared[BLOCK];
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    shared[threadIdx.x] = i < n ? in[i] : Coeff4{};
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride)
            shared[threadIdx.x] = coeff_add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) out[blockIdx.x] = shared[0];
}

__global__ void fold_kernel(const Fp3* src, Fp3* dst, size_t n, Fp3 r) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (i >= 5 * n / 2) return;
    const size_t lane = i / (n / 2), j = i % (n / 2);
    dst[i] = fold(src[lane * n + 2 * j], src[lane * n + 2 * j + 1], r);
}

__global__ void gram_init_kernel(Fp3* values, size_t n, size_t buckets) {
    const size_t i = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t total = 4 * n + buckets;
    if (i >= total) return;
    const size_t lane = i < 4 * n ? i / n : 4;
    const size_t index = i < 4 * n ? i % n : i - 4 * n;
    values[i] = synthetic(lane, index);
}

__global__ void gram_bucket_kernel(
    const Fp3* src, Fp3* out, size_t n, size_t buckets, int width, Fp3 lambda) {
    __shared__ Fp3 ue[32];
    __shared__ Fp3 ve[32];
    const size_t bucket = blockIdx.x;
    const int cell = threadIdx.x;
    if (bucket >= buckets || cell >= width * width) return;
    if (cell < width) {
        const size_t i = bucket * width + cell;
        const Fp3 eq = src[4 * n + bucket];
        ue[cell] = mul(eq, add(mul(lambda, src[i]), src[n + i]));
        ve[cell] = mul(eq, mul(lambda, src[2 * n + i]));
    }
    __syncthreads();
    const int u = cell / width, v = cell % width;
    const size_t vi = bucket * width + v;
    out[bucket * width * width + cell] =
        add(mul(ue[u], src[3 * n + vi]), mul(ve[u], src[n + vi]));
}

__global__ void gram_reduce_kernel(
    const Fp3* in, Fp3* out, size_t matrices, int cells) {
    __shared__ Fp3 shared[BLOCK];
    const size_t group = blockIdx.x;
    const int cell = blockIdx.y;
    const size_t matrix = group * BLOCK + threadIdx.x;
    shared[threadIdx.x] = matrix < matrices ? in[matrix * cells + cell] : Fp3{};
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride)
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) out[group * cells + cell] = shared[0];
}

Coeff4* launch_coeff(const Fp3* src, Coeff4* a, Coeff4* b, size_t n) {
    size_t count = (n / 2 + BLOCK - 1) / BLOCK;
    coeff_kernel<<<count, BLOCK>>>(src, a, n, Fp3{101, 211, 307});
    CUDA_CHECK(cudaGetLastError());
    Coeff4* in = a;
    Coeff4* out = b;
    while (count > 1) {
        const size_t blocks = (count + BLOCK - 1) / BLOCK;
        reduce_kernel<<<blocks, BLOCK>>>(in, out, count);
        CUDA_CHECK(cudaGetLastError());
        count = blocks;
        std::swap(in, out);
    }
    return in;
}

Fp3* launch_gram(
    const Fp3* src, Fp3* a, Fp3* b, size_t n, size_t buckets, int width) {
    const int cells = width * width;
    gram_bucket_kernel<<<buckets, cells>>>(src, a, n, buckets, width, Fp3{101, 211, 307});
    CUDA_CHECK(cudaGetLastError());
    size_t matrices = buckets;
    Fp3* in = a;
    Fp3* out = b;
    while (matrices > 1) {
        const size_t groups = (matrices + BLOCK - 1) / BLOCK;
        gram_reduce_kernel<<<dim3(groups, cells), BLOCK>>>(in, out, matrices, cells);
        CUDA_CHECK(cudaGetLastError());
        matrices = groups;
        std::swap(in, out);
    }
    return in;
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

bool gpu_correctness(int gram_width) {
    const size_t n = 1 << 10;
    std::vector<Fp3> host(5 * n), got;
    fill_host(host, n);
    const auto want_merge = merge_cpu(host, n);
    const auto want_fold = fold_cpu(host, n, Fp3{401, 503, 607});
    const Coeff4 want_coeff = coeff_cpu(host, n, Fp3{101, 211, 307}, false);
    const auto want_gram = gram_cpu(host, n, gram_width, Fp3{101, 211, 307});
    Fp3 *src = nullptr, *dst = nullptr;
    Coeff4 *a = nullptr, *b = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&src), 5 * n * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&dst), 5 * n / 2 * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&a), 2 * sizeof(Coeff4)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&b), sizeof(Coeff4)));
    CUDA_CHECK(cudaMemcpy(src, host.data(), 5 * n * sizeof(Fp3), cudaMemcpyHostToDevice));
    merge_kernel<<<(n / 2 + BLOCK - 1) / BLOCK, BLOCK>>>(src, dst, n);
    got.resize(n);
    CUDA_CHECK(cudaMemcpy(got.data(), dst, n * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const bool merge_ok = equal(got, want_merge);
    fold_kernel<<<(5 * n / 2 + BLOCK - 1) / BLOCK, BLOCK>>>(src, dst, n, Fp3{401, 503, 607});
    got.resize(5 * n / 2);
    CUDA_CHECK(cudaMemcpy(got.data(), dst, got.size() * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const bool fold_ok = equal(got, want_fold);
    Coeff4* result = launch_coeff(src, a, b, n);
    Coeff4 got_coeff{};
    CUDA_CHECK(cudaMemcpy(&got_coeff, result, sizeof(Coeff4), cudaMemcpyDeviceToHost));
    const bool coeff_ok = equal(got_coeff, want_coeff);
    const size_t buckets = n / gram_width;
    const int cells = gram_width * gram_width;
    Fp3 *gram_src = nullptr, *gram_a = nullptr, *gram_b = nullptr;
    std::vector<Fp3> compact(4 * n + buckets), got_gram(cells);
    for (int lane = 0; lane < 4; ++lane)
        std::copy_n(host.data() + lane * n, n, compact.data() + lane * n);
    std::copy_n(host.data() + 4 * n, buckets, compact.data() + 4 * n);
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_src), compact.size() * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_a), buckets * cells * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_b),
                          ((buckets + BLOCK - 1) / BLOCK) * cells * sizeof(Fp3)));
    CUDA_CHECK(cudaMemcpy(
        gram_src, compact.data(), compact.size() * sizeof(Fp3), cudaMemcpyHostToDevice));
    Fp3* gram_result = launch_gram(gram_src, gram_a, gram_b, n, buckets, gram_width);
    CUDA_CHECK(cudaMemcpy(
        got_gram.data(), gram_result, cells * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const bool gram_ok = equal(got_gram, want_gram);
    CUDA_CHECK(cudaFree(gram_b));
    CUDA_CHECK(cudaFree(gram_a));
    CUDA_CHECK(cudaFree(gram_src));
    CUDA_CHECK(cudaFree(b));
    CUDA_CHECK(cudaFree(a));
    CUDA_CHECK(cudaFree(dst));
    CUDA_CHECK(cudaFree(src));
    return field_self_check() && merge_ok && coeff_ok && fold_ok && gram_ok;
}

std::string escape(const char* text) {
    std::ostringstream out;
    for (; *text; ++text) {
        if (*text == '"' || *text == '\\') out << '\\';
        out << *text;
    }
    return out.str();
}

int gpu_bench(int log2_n, int reps, int gram_log2_n, int gram_width) {
    if (log2_n < 10 || log2_n > 25 || gram_log2_n < 10 || gram_log2_n > 25 ||
        reps < 1 || reps > 99 ||
        (gram_width != 8 && gram_width != 16 && gram_width != 32))
        return 2;
    const size_t n = size_t{1} << log2_n;
    const size_t blocks0 = (n / 2 + BLOCK - 1) / BLOCK;
    const size_t blocks1 = (blocks0 + BLOCK - 1) / BLOCK;
    const size_t src_bytes = 5 * n * sizeof(Fp3);
    const size_t dst_bytes = 5 * n / 2 * sizeof(Fp3);
    const size_t partial_bytes = (blocks0 + blocks1) * sizeof(Coeff4);
    const size_t requested = src_bytes + dst_bytes + partial_bytes;
    const size_t gram_n = size_t{1} << gram_log2_n;
    const size_t gram_buckets = gram_n / gram_width;
    const size_t gram_cells = gram_width * gram_width;
    const size_t gram_groups = (gram_buckets + BLOCK - 1) / BLOCK;
    const size_t gram_src_bytes = (4 * gram_n + gram_buckets) * sizeof(Fp3);
    const size_t gram_private_bytes = gram_buckets * gram_cells * sizeof(Fp3);
    const size_t gram_partial_bytes = gram_groups * gram_cells * sizeof(Fp3);
    const size_t gram_requested = gram_src_bytes + gram_private_bytes + gram_partial_bytes;
    if (std::max(requested, gram_requested) > ARENA_BYTES) {
        std::cerr << "requested buffers exceed the C7.1 arena\n";
        return 2;
    }
    const bool correct = gpu_correctness(gram_width);
    if (!correct) {
        std::cerr << "small CPU/GPU correctness check failed\n";
        return 1;
    }
    size_t free_before = 0, total = 0;
    CUDA_CHECK(cudaMemGetInfo(&free_before, &total));
    constexpr size_t reserve = size_t{256} << 20;
    if (std::max(requested, gram_requested) + reserve > free_before) {
        std::cerr << "need " << std::max(requested, gram_requested)
                  << " device bytes plus reserve, have " << free_before << "\n";
        return 2;
    }
    Fp3 *src = nullptr, *dst = nullptr;
    Coeff4 *partial0 = nullptr, *partial1 = nullptr;
    const auto allocation_start = std::chrono::steady_clock::now();
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&src), src_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&dst), dst_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial0), blocks0 * sizeof(Coeff4)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial1), blocks1 * sizeof(Coeff4)));
    const double allocation_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - allocation_start).count();
    size_t free_after = 0;
    CUDA_CHECK(cudaMemGetInfo(&free_after, &total));
    const double init_ms = median_ms(reps, [&] {
        init_kernel<<<(5 * n + BLOCK - 1) / BLOCK, BLOCK>>>(src, n);
        CUDA_CHECK(cudaGetLastError());
    });
    const double merge_ms = median_ms(reps, [&] {
        merge_kernel<<<(n / 2 + BLOCK - 1) / BLOCK, BLOCK>>>(src, dst, n);
        CUDA_CHECK(cudaGetLastError());
    });
    Coeff4* coeff_result = nullptr;
    const double coeff_ms = median_ms(reps, [&] {
        coeff_result = launch_coeff(src, partial0, partial1, n);
    });
    const double fold_ms = median_ms(reps, [&] {
        fold_kernel<<<(5 * n / 2 + BLOCK - 1) / BLOCK, BLOCK>>>(
            src, dst, n, Fp3{401, 503, 607});
        CUDA_CHECK(cudaGetLastError());
    });
    Coeff4 coeff{};
    std::array<Fp3, 4> samples{};
    CUDA_CHECK(cudaMemcpy(&coeff, coeff_result, sizeof(Coeff4), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(samples.data(), dst, 2 * sizeof(Fp3), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(samples.data() + 2, dst + 5 * n / 2 - 2, 2 * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const uint64_t output_checksum = hash_word(checksum(coeff.c, 4), checksum(samples.data(), 4));
    int device = 0, runtime = 0, driver = 0;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDevice(&device));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    CUDA_CHECK(cudaRuntimeGetVersion(&runtime));
    CUDA_CHECK(cudaDriverGetVersion(&driver));
    CUDA_CHECK(cudaFree(partial1));
    CUDA_CHECK(cudaFree(partial0));
    CUDA_CHECK(cudaFree(dst));
    CUDA_CHECK(cudaFree(src));
    Fp3 *gram_src = nullptr, *gram_a = nullptr, *gram_b = nullptr;
    const auto gram_allocation_start = std::chrono::steady_clock::now();
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_src), gram_src_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_a), gram_private_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&gram_b), gram_partial_bytes));
    const double gram_allocation_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - gram_allocation_start).count();
    size_t gram_free_after = 0;
    CUDA_CHECK(cudaMemGetInfo(&gram_free_after, &total));
    const double gram_init_ms = median_ms(reps, [&] {
        gram_init_kernel<<<(4 * gram_n + gram_buckets + BLOCK - 1) / BLOCK, BLOCK>>>(
            gram_src, gram_n, gram_buckets);
        CUDA_CHECK(cudaGetLastError());
    });
    Fp3* gram_result = nullptr;
    const double gram_ms = median_ms(reps, [&] {
        gram_result = launch_gram(
            gram_src, gram_a, gram_b, gram_n, gram_buckets, gram_width);
    });
    std::vector<Fp3> gram_host(gram_cells);
    CUDA_CHECK(cudaMemcpy(
        gram_host.data(), gram_result, gram_cells * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const uint64_t gram_checksum = checksum(gram_host.data(), gram_host.size());
    CUDA_CHECK(cudaFree(gram_b));
    CUDA_CHECK(cudaFree(gram_a));
    CUDA_CHECK(cudaFree(gram_src));
    std::cout << std::setprecision(12)
              << "{\"schema\":\"volta-c71-range-microbench-v1\",\"mode\":\"cuda\""
              << ",\"field\":{\"base_modulus\":" << P
              << ",\"extension\":\"Fp[u]/(u^3-2)\",\"fp3_bytes\":24}"
              << ",\"input\":{\"generator\":\"splitmix64-v1\",\"seed\":\""
              << hex64(SEED) << "\",\"log2_n\":" << log2_n
              << ",\"gram_log2_n\":" << gram_log2_n
              << ",\"gram_width\":" << gram_width << "}"
              << ",\"operation_model\":{\"cubic_direct_oracle_fp3_mul_per_pair\":27"
              << ",\"cubic_factored_kernel_fp3_mul_per_pair\":18}"
              << ",\"device\":{\"name\":\"" << escape(prop.name) << "\",\"total_bytes\":"
              << total << ",\"free_before_bytes\":" << free_before
              << ",\"free_after_alloc_bytes\":" << free_after << ",\"runtime_version\":"
              << runtime << ",\"driver_version\":" << driver << "}"
              << ",\"allocation\":{\"source_bytes\":" << src_bytes
              << ",\"fold_destination_bytes\":" << dst_bytes
              << ",\"reduction_partial_bytes\":" << partial_bytes
              << ",\"range_requested_peak_bytes\":" << requested
              << ",\"gram_source_bytes\":" << gram_src_bytes
              << ",\"gram_private_matrix_bytes\":" << gram_private_bytes
              << ",\"gram_reduction_partial_bytes\":" << gram_partial_bytes
              << ",\"gram_requested_peak_bytes\":" << gram_requested
              << ",\"requested_peak_bytes\":" << std::max(requested, gram_requested)
              << ",\"observed_free_delta_bytes\":" << free_before - free_after
              << ",\"gram_observed_free_delta_bytes\":" << free_before - gram_free_after
              << ",\"allocation_ms\":" << allocation_ms
              << ",\"gram_allocation_ms\":" << gram_allocation_ms << "}"
              << ",\"timing_ms\":{\"initialize\":" << init_ms << ",\"merge\":" << merge_ms
              << ",\"cubic_coeff_and_reduce\":" << coeff_ms << ",\"fold_five_arrays\":"
              << fold_ms << ",\"gram_initialize\":" << gram_init_ms
              << ",\"gram_private_matrices_and_reduce\":" << gram_ms
              << "},\"rates\":{\"rational_merges_per_second\":"
              << (n / 2) / (merge_ms / 1000.0) << ",\"cubic_buckets_per_second\":"
              << (n / 2) / (coeff_ms / 1000.0) << ",\"folded_fp3_values_per_second\":"
              << (5 * n / 2) / (fold_ms / 1000.0)
              << ",\"gram_outer_cells_per_second\":"
              << (gram_buckets * gram_cells) / (gram_ms / 1000.0) << "}"
              << ",\"correctness\":{\"small_cpu_gpu_reference\":"
              << (correct ? "true" : "false") << "},\"output_checksum\":\""
              << hex64(output_checksum) << "\",\"gram_checksum\":\""
              << hex64(gram_checksum) << "\"}\n";
    return correct ? 0 : 1;
}

#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--host-check")
        return host_check(std::stoi(argv[2]), std::stoi(argv[3]));
#ifdef __CUDACC__
    if (argc == 6 && std::string(argv[1]) == "--gpu")
        return gpu_bench(
            std::stoi(argv[2]), std::stoi(argv[3]), std::stoi(argv[4]), std::stoi(argv[5]));
#endif
    std::cerr << "usage: " << argv[0] << " --host-check LOG2_N GRAM_WIDTH";
#ifdef __CUDACC__
    std::cerr << " | --gpu LOG2_N REPS GRAM_LOG2_N GRAM_WIDTH";
#endif
    std::cerr << "\n";
    return 2;
}
