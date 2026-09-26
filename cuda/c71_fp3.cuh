// Shared original Goldilocks/Fp3 arithmetic; includer defines HD.
#pragma once
constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;

struct Fp3 {
    uint64_t c0, c1, c2;
};

static_assert(sizeof(Fp3) == 24, "C7 Fp3 must use three canonical u64 limbs");

// Canonical operands have a+b <= 2p-2. Select (a+b mod 2^64)-p
// iff carry OR no borrow from subtracting p. PTX CC carries are explicit;
// the host branch is the same integer identity, checked against u128 mod p.
HD inline uint64_t fp_add(uint64_t a, uint64_t b) {
#ifdef __CUDA_ARCH__
    uint64_t out;
    asm("{ .reg .u64 t,s; .reg .u32 carry,borrow; .reg .pred take;\n"
        "add.cc.u64 t,%1,%2; addc.u32 carry,0,0;\n"
        "sub.cc.u64 s,t,%3; subc.u32 borrow,0,0;\n"
        "not.b32 borrow,borrow; or.b32 carry,carry,borrow;\n"
        "setp.ne.u32 take,carry,0; selp.u64 %0,s,t,take; }"
        : "=l"(out): "l"(a),"l"(b),"l"(P));
    return out;
#else
    const uint64_t t=a+b, c=t<a;
    return (c || t>=P) ? t-P : t;
#endif
}

HD inline uint64_t fp_sub(uint64_t a, uint64_t b) {
#ifdef __CUDA_ARCH__
    uint64_t out;
    asm("{ .reg .u64 t,correction; .reg .u32 borrow;\n"
        "sub.cc.u64 t,%1,%2; subc.u32 borrow,0,0;\n"
        "cvt.u64.u32 correction,borrow; sub.u64 %0,t,correction; }"
        : "=l"(out): "l"(a),"l"(b));
    return out;
#else
    const uint64_t t=a-b;
    return t-(a<b ? EPSILON:0);
#endif
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
    // t may be noncanonical, but t + t1 <= 2p-2. The same carry-aware
    // addition therefore returns the unique canonical residue.
    const uint64_t t = fp_sub(lo, hi >> 32);
    return fp_add(t, (hi & EPSILON) * EPSILON);
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

