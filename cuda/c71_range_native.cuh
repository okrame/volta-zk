// Private range arithmetic in the ORIGINAL Fp3 representation. No FS or MACs.
// The host check uses the same local algebra, never emulates GPU execution.
#pragma once
#include <cstdint>
#include <cstddef>
#ifdef __CUDACC__
#define C71_RANGE_HD __host__ __device__
#else
#define C71_RANGE_HD
#endif
#define HD C71_RANGE_HD
#include "c71_fp3.cuh"
#undef HD

namespace c71_range {
struct Pair { Fp3 p, q; };
struct Children { Fp3 v[4]; };
struct Cubic { Fp3 c[4]; };
static_assert(sizeof(Pair)==48 && sizeof(Children)==96 && sizeof(Cubic)==96);

C71_RANGE_HD inline Fp3 integer(int64_t x) {
    return {x<0 ? P-uint64_t(-x) : uint64_t(x),0,0};
}
C71_RANGE_HD inline Pair merge(Pair a, Pair b) {
    return {add(mul6(a.p,b.q),mul6(b.p,a.q)),mul6(a.q,b.q)};
}
C71_RANGE_HD inline Pair leaf_pair(int64_t x, int64_t y, Fp3 alpha) {
    const Fp3 a=sub(alpha,integer(x)), b=sub(alpha,integer(y));
    return {add(a,b),mul6(a,b)};
}
C71_RANGE_HD inline Fp3 equality(const Fp3* point, unsigned bits, size_t index) {
    Fp3 value{1,0,0};
    for(unsigned j=0;j<bits;++j)
        value=mul6(value,(index>>(bits-1-j))&1 ? point[j] : sub(Fp3{1,0,0},point[j]));
    return value;
}
C71_RANGE_HD inline Fp3 fold(Fp3 a, Fp3 b, Fp3 r) { return add(a,mul6(r,sub(b,a))); }
C71_RANGE_HD inline Children fold(Children a, Children b, Fp3 r) {
    for(unsigned j=0;j<4;++j) a.v[j]=fold(a.v[j],b.v[j],r);
    return a;
}
C71_RANGE_HD inline Cubic sum(Cubic a, Cubic b) {
    for(unsigned j=0;j<4;++j) a.c[j]=add(a.c[j],b.c[j]);
    return a;
}
C71_RANGE_HD inline Cubic coefficients(Children a, Children b, Fp3 lambda, Fp3 e0, Fp3 e1) {
    Children d{};
    for(unsigned j=0;j<4;++j) d.v[j]=sub(b.v[j],a.v[j]);
    Fp3 v[3]{};
    const unsigned xs[]={0,2,1}, ys[]={3,1,3};
    for(unsigned term=0;term<3;++term) {
        const unsigned x=xs[term],y=ys[term];
        const Fp3 c=term==2 ? Fp3{1,0,0}:lambda;
        v[0]=add(v[0],mul6(c,mul6(a.v[x],a.v[y])));
        v[1]=add(v[1],mul6(c,add(mul6(d.v[x],a.v[y]),mul6(a.v[x],d.v[y]))));
        v[2]=add(v[2],mul6(c,mul6(d.v[x],d.v[y])));
    }
    Cubic out{};
    const Fp3 de=sub(e1,e0);
    for(unsigned j=0;j<3;++j) {
        out.c[j]=add(out.c[j],mul6(e0,v[j]));
        out.c[j+1]=add(out.c[j+1],mul6(de,v[j]));
    }
    return out;
}
C71_RANGE_HD inline Fp3 gram(Children a, Children b, Fp3 lambda, Fp3 weight) {
    const Fp3 x=mul6(weight,add(mul6(lambda,a.v[0]),a.v[1]));
    const Fp3 y=mul6(mul6(weight,lambda),a.v[2]);
    return add(mul6(x,b.v[3]),mul6(y,b.v[1]));
}

// Maximum 35 original coordinates. Public geometry and only ALREADY emitted
// coins; no device function has access to the challenger/correlation stream.
struct Group {
    Fp3 alpha, lambda;
    Fp3 prefix[35], tail_point[35];
    uint64_t first_tail;
    uint32_t bottom, prefix_bits, width, tail_bits, buckets;
};
struct Round {
    Fp3 lambda, prefix_equality;
    Fp3 point[35];
    uint32_t bits;
};
static_assert(sizeof(Group)==1760 && sizeof(Round)==896);

// Checked BEFORE a launch. Selected windows contain whole groups. A nonzero
// return is the exact dynamic shared payload, including the small u bucket.
inline size_t group_shared_bytes(const Group& g,size_t tails) {
    if(g.bottom<1 || g.bottom>11 || g.prefix_bits>10 || g.width>5 ||
       g.bottom+g.prefix_bits+g.width>11 || g.tail_bits>35 || !tails ||
       tails>(uint64_t{1}<<g.tail_bits) || g.first_tail>(uint64_t{1}<<g.tail_bits)-tails ||
       (g.width && (!g.buckets || g.buckets>256))) return 0;
    const size_t pairs=g.bottom==1?0:(size_t{1}<<(g.bottom+g.prefix_bits+g.width-1));
    return pairs*sizeof(Pair)+(size_t{1}<<g.width)*sizeof(Children);
}
C71_RANGE_HD inline Cubic h_coefficients(const Fp3* h,unsigned half,Round r) {
    Fp3 v[3]{};
    for(unsigned z=0;z<half;++z) {
        const unsigned n=2*half;
        const Fp3 a=h[z*n+z], b=h[z*n+z+half], c=h[(z+half)*n+z], d=h[(z+half)*n+z+half];
        const Fp3 terms[]={a,sub(add(b,c),add(a,a)),add(sub(sub(d,b),c),a)};
        const Fp3 e=equality(r.point+1,r.bits-1,z);
        for(unsigned j=0;j<3;++j) v[j]=add(v[j],mul6(e,terms[j]));
    }
    const Fp3 e=mul6(r.prefix_equality,sub(Fp3{1,0,0},r.point[0]));
    const Fp3 de=mul6(r.prefix_equality,sub(add(r.point[0],r.point[0]),Fp3{1,0,0}));
    Cubic out{};
    for(unsigned j=0;j<3;++j) {
        out.c[j]=add(out.c[j],mul6(e,v[j]));
        out.c[j+1]=add(out.c[j+1],mul6(de,v[j]));
    }
    return out;
}
}
#undef C71_RANGE_HD
