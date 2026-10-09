// Original sourcewise product-sumcheck; MAC basis u^3=2, not PCS v^3=v+1.
#pragma once
#include "c71_pcs_source.cuh"
#ifdef __CUDACC__
#define C71_LINEAR_HD __host__ __device__
#else
#define C71_LINEAR_HD
#endif

namespace c71_linear {
struct Chunk { uint32_t shift, bits, first, reserved; };
struct Group { uint32_t bits, first, count, reserved; };
struct Interval {
    uint64_t index;
    uint32_t first, bits;
    Fp3 lower, upper;
};
struct Shape {
    uint64_t live;
    uint32_t dimension, remaining, chunks, groups, intervals, points;
};
struct Result { Fp3 values[5]; };
static_assert(sizeof(Chunk)==16 && sizeof(Group)==16 && sizeof(Interval)==64);
static_assert(sizeof(Shape)==32 && sizeof(Result)==120);
constexpr unsigned threads=256, max_blocks=8192;
constexpr size_t shared_bytes=threads*sizeof(Result);

inline bool valid(Shape s) {
    return s.dimension>=1 && s.dimension<=35 && s.remaining>=1 && s.remaining<=s.dimension &&
        s.live && s.live<=(uint64_t{1}<<s.dimension) && s.chunks<=5 && s.groups<=s.remaining &&
        s.intervals<=(uint32_t{1}<<20) && s.points<=(uint32_t{1}<<25) &&
        (s.groups==0)==(s.intervals==0);
}
C71_LINEAR_HD inline bool canonical(Fp3 x) { return x.c0<P && x.c1<P && x.c2<P; }
inline bool valid_packet(Shape s,const Chunk* chunks,const Fp3* tables,uint32_t table_count,
    const Group* groups,const Interval* intervals,const Fp3* points) {
    if(!valid(s) || table_count>1280 || (s.chunks && !chunks) || (table_count && !tables) ||
       (s.groups && !groups) || (s.intervals && !intervals) || (s.points && !points)) return false;
    unsigned prefix=s.dimension-s.remaining;
    uint32_t cursor=0;
    for(unsigned i=0;i<s.chunks;++i) {
        const auto c=chunks[i];
        if(c.reserved || c.bits<1 || c.bits>8 || c.bits>prefix || c.shift!=prefix-c.bits ||
           c.first!=cursor || (uint32_t{1}<<c.bits)>table_count-cursor) return false;
        cursor+=uint32_t{1}<<c.bits; prefix-=c.bits;
    }
    if(prefix || cursor!=table_count) return false;
    for(uint32_t i=0;i<table_count;++i) if(!canonical(tables[i])) return false;
    for(uint32_t i=0;i<s.points;++i) if(!canonical(points[i])) return false;
    cursor=0;
    for(uint32_t i=0;i<s.groups;++i) {
        const auto g=groups[i];
        if(g.reserved || g.bits>=s.remaining || (i && g.bits<=groups[i-1].bits) ||
           g.first!=cursor || !g.count || g.count>s.intervals-cursor) return false;
        for(uint32_t j=0;j<g.count;++j) {
            const auto interval=intervals[cursor+j];
            if(interval.bits!=g.bits || interval.first>s.points || interval.bits>s.points-interval.first ||
               interval.index>=(uint64_t{1}<<(s.remaining-1-g.bits)) ||
               (j && interval.index<intervals[cursor+j-1].index) ||
               !canonical(interval.lower) || !canonical(interval.upper)) return false;
        }
        cursor+=g.count;
    }
    return cursor==s.intervals;
}
C71_LINEAR_HD inline bool zero(Fp3 x) { return !(x.c0|x.c1|x.c2); }
C71_LINEAR_HD inline Fp3 base_mul(Fp3 x,uint64_t value) {
    return {fp_mul(x.c0,value),fp_mul(x.c1,value),fp_mul(x.c2,value)};
}
C71_LINEAR_HD inline Fp3 prefix_weight(uint64_t index,const Chunk* chunks,
    unsigned count,const Fp3* tables) {
    Fp3 value{1,0,0};
    for(unsigned i=0;i<count;++i) {
        const auto c=chunks[i];
        value=mul6(value,tables[c.first+((index>>c.shift)&((uint64_t{1}<<c.bits)-1))]);
    }
    return value;
}
C71_LINEAR_HD inline void public_weight(uint64_t suffix,const Group* groups,unsigned count,
    const Interval* intervals,const Fp3* points,Fp3& lower,Fp3& upper) {
    lower={}; upper={};
    for(unsigned group=0;group<count;++group) {
        const auto g=groups[group];
        const uint64_t index=suffix>>g.bits;
        uint32_t lo=0,hi=g.count;
        while(lo<hi) {
            const uint32_t mid=lo+(hi-lo)/2;
            if(intervals[g.first+mid].index<index) lo=mid+1; else hi=mid;
        }
        for(;lo<g.count && intervals[g.first+lo].index==index;++lo) {
            const auto interval=intervals[g.first+lo];
            const Fp3 equality=g.bits ? c71_range::equality(points+interval.first,g.bits,suffix) : Fp3{1,0,0};
            lower=add(lower,mul6(interval.lower,equality));
            upper=add(upper,mul6(interval.upper,equality));
        }
    }
}
C71_LINEAR_HD inline Result contribution(uint64_t index,uint64_t original,Shape shape,
    const Chunk* chunks,const Fp3* tables,const Group* groups,const Interval* intervals,
    const Fp3* points) {
    Result result{};
    const Fp3 value=base_mul(prefix_weight(index>>shape.remaining,chunks,shape.chunks,tables),original);
    if(zero(value)) return result;
    const uint64_t half=uint64_t{1}<<(shape.remaining-1), suffix=index&(half-1);
    Fp3 lower{},upper{};
    public_weight(suffix,groups,shape.groups,intervals,points,lower,upper);
    if(!(index&half)) {
        result.values[0]=mul6(value,lower);
        result.values[1]=mul6(value,sub(sub(upper,lower),lower));
        result.values[2]=mul6(value,sub(lower,upper));
        if(half==1) result.values[3]=value;
    } else {
        result.values[1]=mul6(value,lower);
        result.values[2]=mul6(value,sub(upper,lower));
        if(half==1) result.values[4]=value;
    }
    return result;
}
C71_LINEAR_HD inline Result sum(Result left,Result right) {
    for(unsigned i=0;i<5;++i) left.values[i]=add(left.values[i],right.values[i]);
    return left;
}
}
#undef C71_LINEAR_HD
