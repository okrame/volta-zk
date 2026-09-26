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

constexpr uint64_t SEED = 0xC7'01'35'11'25'02'00'01ULL;
constexpr int BLOCK = 256;
constexpr size_t ARENA_BYTES = 6'442'450'944ULL;

#ifdef __CUDACC__
#define HD __host__ __device__
#else
#define HD
#endif

#include "c71_fp3.cuh"

struct Coeff4 {
    Fp3 c[4];
};

static_assert(sizeof(Coeff4) == 96, "four cubic coefficients must occupy 96 bytes");

// Diagonal public node contraction. Inputs are features of ORIGINAL bytes
// (or their multilinear folds), never features of an already folded byte.
// One lane per launch, feature-major pair buffers. The public zero-byte
// baseline is restored analytically by the caller, outside this sum.
HD Coeff4 byte_contract_pair(const Fp3* lo, const Fp3* hi, const Fp3* weighted_lo,
                            const Fp3* weighted_hi, unsigned rank, size_t stride, Fp3 baseline,
                            Fp3 suffix_eq) {
    Fp3 v[3]={sub(Fp3{},baseline),Fp3{},Fp3{}};
    for(unsigned j=0;j<rank;++j) {
        const Fp3 a=lo[j*stride], delta=sub(hi[j*stride],a);
        const Fp3 da=weighted_lo[j*stride], dd=sub(weighted_hi[j*stride],da);
        const Fp3 cross=mul6(da,delta);
        v[0]=add(v[0],mul6(da,a));
        v[1]=add(v[1],add(cross,cross));
        v[2]=add(v[2],mul6(dd,delta));
    }
    Coeff4 out{};
    for(unsigned j=0;j<3;++j) out.c[j]=mul6(suffix_eq,v[j]);
    return out; // fourth entry stays zero for the shared reduction ABI.
}

// Apply the current-axis selector ONCE after reducing all supported pairs.
HD Coeff4 byte_contract_selector(Coeff4 quadratic, Fp3 e0, Fp3 e1) {
    Coeff4 out{};
    const Fp3 de=sub(e1,e0);
    for(unsigned j=0;j<3;++j) {
        out.c[j]=add(out.c[j],mul6(e0,quadratic.c[j]));
        out.c[j+1]=add(out.c[j+1],mul6(de,quadratic.c[j]));
    }
    return out;
}

// GKR arithmetic probe, one gate/cell pair after source folding. The gate
// operation is public; specialization removes Copy's quadratic products.
// Standalone cost only: a fused producer must be recounted, never charged
// these load/address instructions once per inlined field multiplication.
template<int Op> HD Coeff4 gkr_gate(Fp3 x0, Fp3 x1, Fp3 y0, Fp3 y1, Fp3 weight) {
    const Fp3 dx=sub(x1,x0);
    Coeff4 out{};
    if constexpr (Op == 2) {
        out.c[0]=mul6(weight,x0);
        out.c[1]=mul6(weight,dx);
    } else {
        const Fp3 dy=sub(y1,y0);
        Fp3 f[]={mul6(x0,y0),add(mul6(x0,dy),mul6(dx,y0)),mul6(dx,dy)};
        if constexpr (Op == 1) {
            f[0]=sub(add(x0,y0),add(f[0],f[0]));
            f[1]=sub(add(dx,dy),add(f[1],f[1]));
            f[2]=sub(Fp3{},add(f[2],f[2]));
        }
        for(int j=0;j<3;++j) out.c[j]=mul6(weight,f[j]);
    }
    return out;
}

template<int Op> HD Coeff4 gkr_pair(Fp3 x0, Fp3 x1, Fp3 y0, Fp3 y1,
                                  Fp3 s0, Fp3 s1, Fp3 weight) {
    const Coeff4 u=gkr_gate<Op>(x0,x1,y0,y1,weight);
    const Fp3 b=sub(s1,s0);
    Coeff4 out{};
    for(int j=0;j<(Op==2 ? 2 : 3);++j) {
        out.c[j]=add(out.c[j],mul6(s0,u.c[j]));
        out.c[j+1]=add(out.c[j+1],mul6(b,u.c[j]));
    }
    return out;
}

enum : uint8_t { GKR_AND = 0, GKR_XOR = 1, GKR_COPY = 2 };

struct MainGate {
    uint32_t x;
    uint32_t y;
    uint8_t op;
    uint8_t reserved[3];
};

struct MainProgram {
    uint32_t first_gate;
    uint32_t gate_count;
};

struct MainCell {
    uint32_t program;
    uint32_t pair;
};

// Exact source_cell_round gate accumulation for one public program/cell pair.
// The selector is applied once after every gate polynomial has been summed.
HD inline Coeff4 main_cell_coefficients(
    const Fp3* lo, const Fp3* hi, const MainGate* gates,
    const Fp3* weights, size_t gate_count, Fp3 selector_lo, Fp3 selector_hi) {
    Fp3 u[3]{};
    for (size_t i = 0; i < gate_count; ++i) {
        const MainGate gate = gates[i];
        Coeff4 contribution{};
        if (gate.op == GKR_COPY) {
            contribution = gkr_gate<2>(
                lo[gate.x], hi[gate.x], Fp3{}, Fp3{}, weights[i]);
        } else if (gate.op == GKR_XOR) {
            contribution = gkr_gate<1>(
                lo[gate.x], hi[gate.x], lo[gate.y], hi[gate.y], weights[i]);
        } else {
            contribution = gkr_gate<0>(
                lo[gate.x], hi[gate.x], lo[gate.y], hi[gate.y], weights[i]);
        }
        for (int j = 0; j < 3; ++j) u[j] = add(u[j], contribution.c[j]);
    }
    const Fp3 selector_delta = sub(selector_hi, selector_lo);
    Coeff4 out{};
    for (int j = 0; j < 3; ++j) {
        out.c[j] = add(out.c[j], mul6(selector_lo, u[j]));
        out.c[j + 1] = add(out.c[j + 1], mul6(selector_delta, u[j]));
    }
    return out;
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
template<bool Six> HD inline Fp3 coefficient_product(Fp3 a, Fp3 b) {
    return Six ? mul6(a, b) : mul(a, b);
}
template<bool Six = false> HD inline Coeff4 cubic_coeff_factored(
    const Fp3 child[4][2], const Fp3 equality[2], Fp3 lambda) {
    Fp3 a[4], d[4];
    for (int i = 0; i < 4; ++i) {
        a[i] = child[i][0];
        d[i] = sub(child[i][1], a[i]);
    }
    const Fp3 u0 = add(coefficient_product<Six>(lambda, a[0]), a[1]);
    const Fp3 du = add(coefficient_product<Six>(lambda, d[0]), d[1]);
    const Fp3 v0 = coefficient_product<Six>(lambda, a[2]);
    const Fp3 dv = coefficient_product<Six>(lambda, d[2]);
    const Fp3 v[3] = {
        add(coefficient_product<Six>(u0, a[3]), coefficient_product<Six>(v0, a[1])),
        add(add(coefficient_product<Six>(du, a[3]), coefficient_product<Six>(u0, d[3])),
            add(coefficient_product<Six>(dv, a[1]), coefficient_product<Six>(v0, d[1]))),
        add(coefficient_product<Six>(du, d[3]), coefficient_product<Six>(dv, d[1])),
    };
    const Fp3 de = sub(equality[1], equality[0]);
    Coeff4 out{};
    for (int i = 0; i < 3; ++i) {
        out.c[i] = add(out.c[i], coefficient_product<Six>(equality[0], v[i]));
        out.c[i + 1] = add(out.c[i + 1], coefficient_product<Six>(de, v[i]));
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

Coeff4 coeff_cpu(const std::vector<Fp3>& src, size_t n, Fp3 lambda, bool factored, bool six = false) {
    Coeff4 total{};
    for (size_t i = 0; i < n / 2; ++i) {
        Fp3 child[4][2];
        for (int j = 0; j < 4; ++j) {
            child[j][0] = src[j * n + 2 * i];
            child[j][1] = src[j * n + 2 * i + 1];
        }
        const Fp3 equality[2] = {src[4 * n + 2 * i], src[4 * n + 2 * i + 1]};
        total = coeff_add(total, factored ? (six ? cubic_coeff_factored<true>(child, equality, lambda)
                                            : cubic_coeff_factored(child, equality, lambda))
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

std::string escape(const char* text);

bool pipelined_round_cpu_check() {
    constexpr size_t previous_n = 64;
    const Fp3 lambda{101,211,307}, r_prev{401,503,607};
    std::vector<Fp3> previous(5*previous_n);
    fill_host(previous,previous_n);
    std::vector<Fp3> separate(5*previous_n/2);
    const size_t half=previous_n/2;
    for(int lane=0;lane<5;++lane)
        for(size_t i=0;i<half;++i)
            separate[lane*half+i]=fold(previous[lane*previous_n+i],
                                       previous[lane*previous_n+i+half],r_prev);
    Coeff4 want{};
    const size_t current_n=previous_n/2, current_half=current_n/2;
    for(size_t pair=0;pair<current_half;++pair){
        Fp3 child[4][2];
        for(int j=0;j<4;++j){
            child[j][0]=separate[j*current_n+pair];
            child[j][1]=separate[j*current_n+pair+current_half];
        }
        Fp3 eq[2]={separate[4*current_n+pair],separate[4*current_n+pair+current_half]};
        want=coeff_add(want,cubic_coeff_factored(child,eq,lambda));
    }
    std::vector<Fp3> fused(5*previous_n/2);
    Coeff4 sum{};
    for(size_t pair=0;pair<previous_n/4;++pair){
        Fp3 child[4][2];
        const size_t quarter=previous_n/4, half=previous_n/2;
        for(int j=0;j<4;++j){
            const Fp3* lane=previous.data()+j*previous_n;
            child[j][0]=fold(lane[pair],lane[pair+half],r_prev);
            child[j][1]=fold(lane[pair+quarter],lane[pair+half+quarter],r_prev);
            fused[j*half+pair]=child[j][0];
            fused[j*half+pair+quarter]=child[j][1];
        }
        const Fp3* lane=previous.data()+4*previous_n;
        Fp3 eq[2]={fold(lane[pair],lane[pair+half],r_prev),
                   fold(lane[pair+quarter],lane[pair+half+quarter],r_prev)};
        fused[4*half+pair]=eq[0];
        fused[4*half+pair+quarter]=eq[1];
        sum=coeff_add(sum,cubic_coeff_factored(child,eq,lambda));
    }
    // Adjacent pairing is the old standalone harness convention, not the
    // protocol's MSB convention. Ensure this fixture distinguishes them.
    const auto adjacent = fold_cpu(previous, previous_n, r_prev);
    return equal(fused,separate) && equal(sum,want) && !equal(adjacent,separate);
}

bool gkr_pair_check() {
    for (size_t i=0;i<64;++i) {
        const Fp3 x0=synthetic(0,i), x1=synthetic(1,i), y0=synthetic(2,i), y1=synthetic(3,i);
        const Fp3 s0=synthetic(4,i), s1=synthetic(5,i), w=synthetic(6,i);
        const Coeff4 coefficients[]={gkr_pair<0>(x0,x1,y0,y1,s0,s1,w),
            gkr_pair<1>(x0,x1,y0,y1,s0,s1,w),gkr_pair<2>(x0,x1,y0,y1,s0,s1,w)};
        for (Fp3 r : {Fp3{},Fp3{1,0,0},synthetic(7,i),Fp3{P-1,P-2,P-3}}) {
            const Fp3 x=add(x0,mul(r,sub(x1,x0))), y=add(y0,mul(r,sub(y1,y0)));
            const Fp3 selector=mul(w,add(s0,mul(r,sub(s1,s0))));
            const Fp3 xy=mul(x,y);
            const Fp3 values[]={xy,sub(add(x,y),add(xy,xy)),x};
            for (int op=0;op<3;++op) {
                Fp3 value{};
                for (int j=3;j>=0;--j) value=add(mul(value,r),coefficients[op].c[j]);
                if(!equal(value,mul(selector,values[op]))) return false;
            }
        }
    }
    return true;
}

bool main_cell_check() {
    constexpr size_t width = 16;
    const MainGate gates[] = {
        {0, 3, GKR_AND, {}}, {5, 7, GKR_XOR, {}}, {2, 0, GKR_COPY, {}},
        {11, 4, GKR_AND, {}}, {15, 6, GKR_XOR, {}}, {9, 0, GKR_COPY, {}},
    };
    Fp3 lo[width], hi[width], weights[std::size(gates)];
    for (size_t i = 0; i < width; ++i) {
        lo[i] = synthetic(20, i);
        hi[i] = synthetic(21, i);
    }
    for (size_t i = 0; i < std::size(gates); ++i) weights[i] = synthetic(22, i);
    const Fp3 selector_lo = synthetic(23, 0), selector_hi = synthetic(23, 1);
    const Coeff4 coefficients = main_cell_coefficients(
        lo, hi, gates, weights, std::size(gates), selector_lo, selector_hi);
    for (Fp3 r : {Fp3{}, Fp3{1,0,0}, synthetic(24, 0), Fp3{P-1,P-2,P-3}}) {
        Fp3 polynomial{};
        for (int j = 3; j >= 0; --j) polynomial = add(mul(polynomial, r), coefficients.c[j]);
        Fp3 gates_at_r{};
        for (size_t i = 0; i < std::size(gates); ++i) {
            const MainGate gate = gates[i];
            const Fp3 x = fold(lo[gate.x], hi[gate.x], r);
            Fp3 value = x;
            if (gate.op != GKR_COPY) {
                const Fp3 y = fold(lo[gate.y], hi[gate.y], r);
                const Fp3 xy = mul(x, y);
                value = gate.op == GKR_XOR ? sub(add(x, y), add(xy, xy)) : xy;
            }
            gates_at_r = add(gates_at_r, mul(weights[i], value));
        }
        const Fp3 selector = fold(selector_lo, selector_hi, r);
        if (!equal(polynomial, mul(selector, gates_at_r))) return false;
    }
    return true;
}

bool specialization_check() {
    if (!gkr_pair_check()) return false;
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

bool byte_contract_check() {
    std::vector<Fp3> data(5*32);
    fill_host(data,32);
    for(unsigned rank: {0u,2u,3u,4u,5u,8u,9u,16u,17u}) {
        const Fp3 *a=data.data(), *b=a+32, *d=b+32;
        const Fp3 baseline{P-1,19,31}, e0{P-2,37,41}, e1{43,P-3,47};
        Fp3 da[17], db[17];
        for(unsigned j=0;j<rank;++j) { da[j]=mul(d[j],a[j]); db[j]=mul(d[j],b[j]); }
        const Fp3 weight{67,71,73};
        const Coeff4 c=byte_contract_selector(
            byte_contract_pair(a,b,da,db,rank,1,baseline,weight),e0,e1);
        for(Fp3 t: {Fp3{},Fp3{1,0,0},Fp3{2,0,0},Fp3{3,0,0},Fp3{53,59,61}}) {
            Fp3 want=sub(Fp3{},baseline);
            for(unsigned j=0;j<rank;++j) {
                const Fp3 value=add(a[j],mul(t,sub(b[j],a[j])));
                want=add(want,mul(d[j],mul(value,value)));
            }
            want=mul(weight,mul(add(e0,mul(t,sub(e1,e0))),want));
            Fp3 got{};
            for(int j=3;j>=0;--j) got=add(c.c[j],mul(got,t));
            if(!equal(got,want)) return false;
        }
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
    const bool coeff_ok = equal(coeff, coeff_factored) && equal(coeff, coeff_cpu(src, n, lambda, true, true));
    const bool fold_ok = fold_linearity_check(src, folded, n, r);
    const bool gram_ok = equal(gram, gram_direct);
    const bool field_ok = field_self_check() && specialization_check();
    const bool contraction_ok = byte_contract_check();
    const bool main_cell_ok = main_cell_check();
    const bool fused_ok = pipelined_round_cpu_check();
    const bool ok =
        field_ok && contraction_ok && merge_ok && coeff_ok && fold_ok && gram_ok && fused_ok && main_cell_ok;
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
              << ",\"main_cell_coeff\":" << (main_cell_ok ? "true" : "false")
              << ",\"byte_contract_coeff\":" << (contraction_ok ? "true" : "false")
              << ",\"fold\":" << (fold_ok ? "true" : "false")
              << ",\"previous_fold_current_coeff\":" << (fused_ok ? "true" : "false")
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

// Three weighted gate-polynomial probes for the selector-factored schedule.
// The selector is applied once after summing every gate of a public program.
extern "C" __global__ void c71_gkr_and_gate(const Fp3* in, Coeff4* out, size_t n) {
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<n) out[i]=gkr_gate<0>(in[5*i],in[5*i+1],in[5*i+2],in[5*i+3],in[5*i+4]);
}
extern "C" __global__ void c71_gkr_xor_gate(const Fp3* in, Coeff4* out, size_t n) {
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<n) out[i]=gkr_gate<1>(in[5*i],in[5*i+1],in[5*i+2],in[5*i+3],in[5*i+4]);
}
extern "C" __global__ void c71_gkr_copy_gate(const Fp3* in, Coeff4* out, size_t n) {
    const size_t i=static_cast<size_t>(blockIdx.x)*blockDim.x+threadIdx.x;
    if(i<n) out[i]=gkr_gate<2>(in[5*i],in[5*i+1],Fp3{},Fp3{},in[5*i+4]);
}

// One thread per public (program, supported cell-pair). Rows are wire-major:
// row[pair * width + wire]. Gate descriptors and weights are public and
// contiguous inside each program. Unsupported pairs are absent from `cells`.
extern "C" __global__ void c71_gkr_main_cell_fused(
    const Fp3* lo, const Fp3* hi, size_t width,
    const MainGate* gates, const Fp3* weights, const MainProgram* programs,
    const MainCell* cells, const Fp3* selector_lo, const Fp3* selector_hi,
    Coeff4* partials, size_t cell_count) {
    __shared__ Coeff4 shared[BLOCK];
    const size_t item = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    Coeff4 value{};
    if (item < cell_count) {
        const MainCell cell = cells[item];
        const MainProgram program = programs[cell.program];
        const size_t row = size_t{cell.pair} * width;
        value = main_cell_coefficients(
            lo + row, hi + row, gates + program.first_gate,
            weights + program.first_gate, program.gate_count,
            selector_lo[item], selector_hi[item]);
    }
    shared[threadIdx.x] = value;
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride)
            shared[threadIdx.x] = coeff_add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) partials[blockIdx.x] = shared[0];
}

// Same arithmetic as the native contracted byte endpoint, followed by the
// existing block/cross-block reduction. No domain-sized coefficient output.
extern "C" __global__ void c71_byte_contract_coeff(
    const Fp3* lo, const Fp3* hi, const Fp3* weighted_lo, const Fp3* weighted_hi, unsigned rank,
    const Fp3* suffix_eq, Fp3 baseline, Coeff4* partials, size_t pairs) {
    __shared__ Coeff4 shared[BLOCK];
    const size_t i=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    Coeff4 value{};
    if(i<pairs)
        value=byte_contract_pair(lo+i,hi+i,weighted_lo+i,weighted_hi+i,rank,pairs,baseline,suffix_eq[i]);
    shared[threadIdx.x]=value;
    __syncthreads();
    for(int stride=BLOCK/2;stride;stride>>=1) {
        if(threadIdx.x<stride)
            shared[threadIdx.x]=coeff_add(shared[threadIdx.x],shared[threadIdx.x+stride]);
        __syncthreads();
    }
    if(threadIdx.x==0) partials[blockIdx.x]=shared[0];
}

// Best-case scalar byte-tree probe: 18 general Fp3 products, six base
// products each. Batch output is reduced separately; no full-domain buffer.
extern "C" __global__ void c71_byte_coeff6(const Fp3* src, Coeff4* out, size_t n, Fp3 lambda) {
    const size_t pair=size_t(blockIdx.x)*blockDim.x+threadIdx.x;
    if(pair>=n/2) return;
    Fp3 child[4][2];
    for(unsigned j=0;j<4;++j) {
        child[j][0]=src[j*n+2*pair];
        child[j][1]=src[j*n+2*pair+1];
    }
    const Fp3 equality[2]={src[4*n+2*pair],src[4*n+2*pair+1]};
    out[pair]=cubic_coeff_factored<true>(child,equality,lambda);
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

// Representative pipelined MSB round for a materialized sourcewise tree.
// r_prev was sampled only after the preceding coefficients were recorded.
// This folds the preceding coordinate, then computes the current cubic from
// the two resulting endpoints. It never consumes the current round challenge.
__global__ void previous_fold_current_coeff_kernel(
    const Fp3* previous, Fp3* current, Coeff4* partials,
    size_t previous_n, Fp3 lambda, Fp3 r_prev) {
    __shared__ Coeff4 shared[BLOCK];
    const size_t pair = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    Coeff4 value{};
    if (pair < previous_n / 4) {
        Fp3 child[4][2];
        const size_t quarter = previous_n / 4, half = previous_n / 2;
        for (int j = 0; j < 4; ++j) {
            const Fp3* lane = previous + j * previous_n;
            child[j][0] = fold(lane[pair], lane[pair + half], r_prev);
            child[j][1] = fold(lane[pair + quarter], lane[pair + half + quarter], r_prev);
            current[j * half + pair] = child[j][0];
            current[j * half + pair + quarter] = child[j][1];
        }
        const Fp3* eq_lane = previous + 4 * previous_n;
        Fp3 equality[2] = {
            fold(eq_lane[pair], eq_lane[pair + half], r_prev),
            fold(eq_lane[pair + quarter], eq_lane[pair + half + quarter], r_prev),
        };
        current[4 * half + pair] = equality[0];
        current[4 * half + pair + quarter] = equality[1];
        value = cubic_coeff_factored(child, equality, lambda);
    }
    shared[threadIdx.x] = value;
    __syncthreads();
    for (int stride = BLOCK / 2; stride; stride >>= 1) {
        if (threadIdx.x < stride)
            shared[threadIdx.x] = coeff_add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        __syncthreads();
    }
    if (threadIdx.x == 0) partials[blockIdx.x] = shared[0];
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

Coeff4* launch_previous_fold_current_coeff(
    const Fp3* previous, Fp3* current, Coeff4* a, Coeff4* b,
    size_t previous_n, Fp3 lambda, Fp3 r_prev) {
    size_t count = (previous_n / 4 + BLOCK - 1) / BLOCK;
    previous_fold_current_coeff_kernel<<<count, BLOCK>>>(
        previous, current, a, previous_n, lambda, r_prev);
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

size_t coefficient_reduction_additions(size_t pairs) {
    size_t additions = 0;
    size_t count = (pairs + BLOCK - 1) / BLOCK;
    for (;;) {
        additions += count * (BLOCK - 1) * 4;
        if (count == 1) return additions;
        count = (count + BLOCK - 1) / BLOCK;
    }
}

size_t coefficient_reduction_traffic(size_t pairs) {
    size_t count = (pairs + BLOCK - 1) / BLOCK;
    size_t bytes = count * sizeof(Coeff4); // Initial block partial writes.
    while (count > 1) {
        const size_t blocks = (count + BLOCK - 1) / BLOCK;
        bytes += (count + blocks) * sizeof(Coeff4);
        count = blocks;
    }
    return bytes;
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

void previous_fold_current_coeff_reference(
    const std::vector<Fp3>& previous, size_t previous_n, Fp3 lambda, Fp3 r_prev,
    std::vector<Fp3>& current, Coeff4& coefficient) {
    const size_t quarter = previous_n / 4, half = previous_n / 2;
    current.assign(5 * half, Fp3{});
    coefficient = Coeff4{};
    for (size_t pair = 0; pair < quarter; ++pair) {
        Fp3 child[4][2];
        for (int lane_index = 0; lane_index < 4; ++lane_index) {
            const Fp3* lane = previous.data() + lane_index * previous_n;
            child[lane_index][0] = fold(lane[pair], lane[pair + half], r_prev);
            child[lane_index][1] =
                fold(lane[pair + quarter], lane[pair + half + quarter], r_prev);
            current[lane_index * half + pair] = child[lane_index][0];
            current[lane_index * half + pair + quarter] = child[lane_index][1];
        }
        const Fp3* equality_lane = previous.data() + 4 * previous_n;
        Fp3 equality[2] = {
            fold(equality_lane[pair], equality_lane[pair + half], r_prev),
            fold(equality_lane[pair + quarter],
                 equality_lane[pair + half + quarter], r_prev),
        };
        current[4 * half + pair] = equality[0];
        current[4 * half + pair + quarter] = equality[1];
        coefficient = coeff_add(coefficient, cubic_coeff_factored(child, equality, lambda));
    }
}

bool fused_gkr_gpu_correctness() {
    // Four block partials force the cross-block reduction through its real path.
    constexpr size_t n = 1 << 12;
    const Fp3 lambda{101, 211, 307}, r_prev{401, 503, 607};
    std::vector<Fp3> previous(5 * n), want_current, got_current(5 * n / 2);
    fill_host(previous, n);
    Coeff4 want_coefficient{}, got_coefficient{};
    previous_fold_current_coeff_reference(
        previous, n, lambda, r_prev, want_current, want_coefficient);
    Fp3 *device_previous = nullptr, *device_current = nullptr;
    Coeff4 *partial0 = nullptr, *partial1 = nullptr;
    const size_t blocks0 = (n / 4 + BLOCK - 1) / BLOCK;
    const size_t blocks1 = std::max<size_t>(1, (blocks0 + BLOCK - 1) / BLOCK);
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_previous), previous.size() * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&device_current), got_current.size() * sizeof(Fp3)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial0), blocks0 * sizeof(Coeff4)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial1), blocks1 * sizeof(Coeff4)));
    CUDA_CHECK(cudaMemcpy(device_previous, previous.data(), previous.size() * sizeof(Fp3),
                          cudaMemcpyHostToDevice));
    Coeff4* result = launch_previous_fold_current_coeff(
        device_previous, device_current, partial0, partial1, n, lambda, r_prev);
    CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(got_current.data(), device_current, got_current.size() * sizeof(Fp3),
                          cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(&got_coefficient, result, sizeof(Coeff4), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaFree(partial1));
    CUDA_CHECK(cudaFree(partial0));
    CUDA_CHECK(cudaFree(device_current));
    CUDA_CHECK(cudaFree(device_previous));
    return equal(got_current, want_current) && equal(got_coefficient, want_coefficient);
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

int fused_gkr_bench(int log2_n, int reps) {
    if (log2_n < 10 || log2_n > 25 || reps < 1 || reps > 99) return 2;
    const size_t n = size_t{1} << log2_n;
    const size_t pairs = n / 4;
    const size_t blocks0 = (pairs + BLOCK - 1) / BLOCK;
    const size_t blocks1 = std::max<size_t>(1, (blocks0 + BLOCK - 1) / BLOCK);
    const size_t source_bytes = 5 * n * sizeof(Fp3);
    const size_t current_bytes = 5 * n / 2 * sizeof(Fp3);
    const size_t partial_bytes = (blocks0 + blocks1) * sizeof(Coeff4);
    const size_t requested = source_bytes + current_bytes + partial_bytes;
    if (requested > ARENA_BYTES) {
        std::cerr << "fused GKR buffers exceed the C7.1 arena\n";
        return 2;
    }
    if (!pipelined_round_cpu_check() || !fused_gkr_gpu_correctness()) {
        std::cerr << "fused GKR CPU/GPU reference differs\n";
        return 1;
    }
    size_t free_before = 0, total = 0;
    CUDA_CHECK(cudaMemGetInfo(&free_before, &total));
    constexpr size_t reserve = size_t{256} << 20;
    if (requested + reserve > free_before) {
        std::cerr << "need " << requested << " device bytes plus reserve, have "
                  << free_before << "\n";
        return 2;
    }
    Fp3 *previous = nullptr, *current = nullptr;
    Coeff4 *partial0 = nullptr, *partial1 = nullptr;
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&previous), source_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&current), current_bytes));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial0), blocks0 * sizeof(Coeff4)));
    CUDA_CHECK(cudaMalloc(reinterpret_cast<void**>(&partial1), blocks1 * sizeof(Coeff4)));
    init_kernel<<<(5 * n + BLOCK - 1) / BLOCK, BLOCK>>>(previous, n);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    Coeff4* result = nullptr;
    const double elapsed_ms = median_ms(reps, [&] {
        result = launch_previous_fold_current_coeff(
            previous, current, partial0, partial1, n,
            Fp3{101, 211, 307}, Fp3{401, 503, 607});
    });
    Coeff4 coefficient{};
    std::array<Fp3, 4> samples{};
    CUDA_CHECK(cudaMemcpy(&coefficient, result, sizeof(Coeff4), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(samples.data(), current, 2 * sizeof(Fp3), cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(samples.data() + 2, current + 5 * n / 2 - 2,
                          2 * sizeof(Fp3), cudaMemcpyDeviceToHost));
    const uint64_t checksum_value =
        hash_word(checksum(coefficient.c, 4), checksum(samples.data(), samples.size()));
    int device = 0, runtime = 0, driver = 0;
    cudaDeviceProp prop{};
    CUDA_CHECK(cudaGetDevice(&device));
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    CUDA_CHECK(cudaRuntimeGetVersion(&runtime));
    CUDA_CHECK(cudaDriverGetVersion(&driver));
    CUDA_CHECK(cudaFree(partial1));
    CUDA_CHECK(cudaFree(partial0));
    CUDA_CHECK(cudaFree(current));
    CUDA_CHECK(cudaFree(previous));
    const size_t primary_traffic = source_bytes + current_bytes;
    const size_t reduction_traffic = coefficient_reduction_traffic(pairs);
    std::cout << std::setprecision(12)
              << "{\"schema\":\"volta-c71-fused-gkr-v1\",\"mode\":\"cuda\""
              << ",\"scope\":\"previous-MSB-fold-plus-current-coefficient-and-full-reduction\""
              << ",\"input\":{\"generator\":\"splitmix64-v1\",\"seed\":\""
              << hex64(SEED) << "\",\"log2_previous_n\":" << log2_n
              << ",\"pairs\":" << pairs << ",\"reps\":" << reps << "}"
              << ",\"device\":{\"name\":\"" << escape(prop.name)
              << "\",\"runtime_version\":" << runtime
              << ",\"driver_version\":" << driver << "}"
              << ",\"allocation\":{\"source_bytes\":" << source_bytes
              << ",\"current_bytes\":" << current_bytes
              << ",\"partial_bytes\":" << partial_bytes
              << ",\"requested_peak_bytes\":" << requested << "}"
              << ",\"source_work\":{\"fp3_mul_per_pair\":28"
              << ",\"fp3_add_per_pair_before_reduction\":23"
              << ",\"fp3_sub_per_pair\":15"
              << ",\"reduction_fp3_additions\":"
              << coefficient_reduction_additions(pairs) << "}"
              << ",\"logical_global_traffic\":{\"primary_bytes\":" << primary_traffic
              << ",\"reduction_bytes\":" << reduction_traffic
              << ",\"total_bytes\":" << primary_traffic + reduction_traffic
              << ",\"separate_primary_bytes\":" << source_bytes + 2 * current_bytes << "}"
              << ",\"timing_ms\":{\"fused_kernel_and_full_reduction\":" << elapsed_ms << "}"
              << ",\"rate\":{\"pairs_per_second\":"
              << pairs / (elapsed_ms / 1000.0) << "}"
              << ",\"correctness\":{\"small_independent_cpu_gpu_reference\":true"
              << ",\"adjacent_ordering_rejected\":true}"
              << ",\"runtime_claim\":\"component measurement only; no prover upper\""
              << ",\"output_checksum\":\"" << hex64(checksum_value) << "\"}\n";
    return 0;
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
    if (argc == 4 && std::string(argv[1]) == "--fused-gkr")
        return fused_gkr_bench(std::stoi(argv[2]), std::stoi(argv[3]));
    if (argc == 6 && std::string(argv[1]) == "--gpu")
        return gpu_bench(
            std::stoi(argv[2]), std::stoi(argv[3]), std::stoi(argv[4]), std::stoi(argv[5]));
#endif
    std::cerr << "usage: " << argv[0] << " --host-check LOG2_N GRAM_WIDTH";
#ifdef __CUDACC__
    std::cerr << " | --fused-gkr LOG2_PREVIOUS_N REPS"
              << " | --gpu LOG2_N REPS GRAM_LOG2_N GRAM_WIDTH";
#endif
    std::cerr << "\n";
    return 2;
}
