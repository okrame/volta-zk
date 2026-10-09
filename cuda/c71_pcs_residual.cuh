// Sourcewise PCS primitives ONLY: E=Fp[v]/(v^3-v-1), not MAC u^3=2.
// Preparatory component, without owner/caller integration or CUDA evidence.
#pragma once
#include "c71_pcs_source.cuh"
#ifdef __CUDACC__
#define C71_RESIDUAL_HD __host__ __device__
#else
#define C71_RESIDUAL_HD
#endif

namespace c71_pcs_residual {
struct E { uint64_t c0, c1, c2; };
struct Chunk { uint32_t shift, bits, first, reserved; };
struct EqShape { uint32_t bits, chunks, entries, reserved; };
struct Shape { uint64_t live; uint32_t dimension, remaining; EqShape equality; };
enum class Phase : uint32_t { singleton=0, retention=1, cosets=2, ood=3 };
struct CosetShape { uint64_t rows; uint32_t pad_rows, cosets, first_coset, reserved; };
struct PowerShape { uint32_t bits, low_bits, reserved0, reserved1; };
struct Planes { uint64_t* c0; uint64_t* c1; uint64_t* c2; };
struct ConstPlanes { const uint64_t* c0; const uint64_t* c1; const uint64_t* c2; };
// Owner constructs ONLY the fields of the selected phase. All others are null.
// Singleton: reduced points at 128 zero E; unused buckets remain zero.
// OOD: reduced points at one zero E. Retention: all three planes are zero,
// including the original public suffix. Cosets: ring[24*rows] is zero.
struct Output { Planes retained; uint64_t* ring; E* reduced; };
// Caller-owned payload: EQ <=5*16+1280*24 B; singleton 128*24 B;
// OOD 24 B plus split powers 24*(2^low_bits+2^(bits-low_bits));
// retention three planes 24*2^remaining B; cosets 24*rows*8 B,
// low 2*rows*8 B, high 2*ceil((2^(remaining-2)+pad_rows)/rows)*8 B,
// pads 4*pad_rows*24 B. Fold is out-of-place: old count*24 plus
// new (count>>rounds)*24 remain charged until successful owner retirement.
// FFT scratch/twiddle, Merkle/salts, replay and all host/device peers are
// additional; this component neither admits nor reserves a joint budget.
static_assert(sizeof(E)==24 && sizeof(Chunk)==16 && sizeof(EqShape)==16);
static_assert(sizeof(Shape)==32 && sizeof(CosetShape)==24 && sizeof(PowerShape)==16);
static_assert(sizeof(Planes)==24 && sizeof(ConstPlanes)==24 && sizeof(Output)==40);
constexpr unsigned threads=256, max_blocks=8192, singleton_capacity=128;
constexpr size_t singleton_shared_bytes=singleton_capacity*sizeof(E);
constexpr size_t ood_shared_bytes=threads*sizeof(E);

C71_RESIDUAL_HD inline bool canonical(E x) { return x.c0<P && x.c1<P && x.c2<P; }
C71_RESIDUAL_HD inline bool zero(E x) { return !(x.c0|x.c1|x.c2); }
C71_RESIDUAL_HD inline E add(E a,E b) {
    return {fp_add(a.c0,b.c0),fp_add(a.c1,b.c1),fp_add(a.c2,b.c2)};
}
C71_RESIDUAL_HD inline E sub(E a,E b) {
    return {fp_sub(a.c0,b.c0),fp_sub(a.c1,b.c1),fp_sub(a.c2,b.c2)};
}
C71_RESIDUAL_HD inline E base_mul(E a,uint64_t b) {
    return {fp_mul(a.c0,b),fp_mul(a.c1,b),fp_mul(a.c2,b)};
}
// Six Goldilocks products. Polynomial reduction is v^3=v+1,
// v^4=v^2+v; MAC mul/mul6 and MAC equality must NEVER be called here.
C71_RESIDUAL_HD inline E mul(E a,E b) {
    const uint64_t p0=fp_mul(a.c0,b.c0), p1=fp_mul(a.c1,b.c1), p2=fp_mul(a.c2,b.c2);
    const uint64_t p01=fp_sub(fp_sub(fp_mul(fp_add(a.c0,a.c1),fp_add(b.c0,b.c1)),p0),p1);
    const uint64_t p02=fp_sub(fp_sub(fp_mul(fp_add(a.c0,a.c2),fp_add(b.c0,b.c2)),p0),p2);
    const uint64_t p12=fp_sub(fp_sub(fp_mul(fp_add(a.c1,a.c2),fp_add(b.c1,b.c2)),p1),p2);
    return {fp_add(p0,p12),fp_add(fp_add(p01,p12),p2),fp_add(fp_add(p02,p1),p2)};
}
C71_RESIDUAL_HD inline E power(E a,uint64_t exponent) {
    E result{1,0,0};
    while(exponent) {
        if(exponent&1) result=mul(result,a);
        a=mul(a,a); exponent>>=1;
    }
    return result;
}
C71_RESIDUAL_HD inline E fold(E a,E b,E r) { return add(a,mul(r,sub(b,a))); }
C71_RESIDUAL_HD inline E fold2(E a,E b,E c,E d,E r0,E r1) {
    // Four consecutive quarters: MSB r0 combines (a,c) and (b,d),
    // then the next MSB r1 combines those two results.
    return fold(fold(a,c,r0),fold(b,d,r0),r1);
}
C71_RESIDUAL_HD inline E load(ConstPlanes p,uint64_t i) { return {p.c0[i],p.c1[i],p.c2[i]}; }
C71_RESIDUAL_HD inline void store(Planes p,uint64_t i,E value) {
    p.c0[i]=value.c0; p.c1[i]=value.c1; p.c2[i]=value.c2;
}
C71_RESIDUAL_HD inline uint64_t limb(E value,unsigned i) {
    return i==0 ? value.c0 : i==1 ? value.c1 : value.c2;
}
C71_RESIDUAL_HD inline E equality(const E* points,unsigned bits,uint64_t index) {
    E value{1,0,0};
    for(unsigned j=0;j<bits;++j)
        value=mul(value,(index>>(bits-1-j))&1 ? points[j] : sub(E{1,0,0},points[j]));
    return value;
}
C71_RESIDUAL_HD inline E lookup(uint64_t index,const Chunk* chunks,unsigned count,const E* tables) {
    E value{1,0,0};
    for(unsigned i=0;i<count;++i) {
        const auto c=chunks[i];
        value=mul(value,tables[c.first+((index>>c.shift)&((uint64_t{1}<<c.bits)-1))]);
    }
    return value;
}
C71_RESIDUAL_HD inline bool valid(EqShape e) {
    return e.bits<=35 && e.chunks<=5 && e.entries<=1280 && !e.reserved &&
        ((e.bits==0 && e.chunks==0 && e.entries==0) ||
         (e.bits && e.chunks && e.chunks<=e.bits && e.entries>=2*e.chunks));
}
// Host packet validation before upload. Exact ordered chunk coverage,
// canonical tables, and a bounded 5*256-entry allocation, including EQ(0/1).
inline bool valid_packet(EqShape e,const Chunk* chunks,const E* tables) {
    if(!valid(e) || (e.chunks && !chunks) || (e.entries && !tables)) return false;
    unsigned bits=e.bits;
    uint32_t cursor=0;
    for(unsigned i=0;i<e.chunks;++i) {
        const auto c=chunks[i];
        if(c.reserved || !c.bits || c.bits>8 || c.bits>bits || c.shift!=bits-c.bits ||
           c.first!=cursor || (uint32_t{1}<<c.bits)>e.entries-cursor) return false;
        cursor+=uint32_t{1}<<c.bits; bits-=c.bits;
    }
    if(bits || cursor!=e.entries) return false;
    for(uint32_t i=0;i<e.entries;++i) if(!canonical(tables[i])) return false;
    return true;
}
C71_RESIDUAL_HD inline bool valid(Shape s,Phase phase) {
    if(!s.dimension || s.dimension>35 || s.remaining>s.dimension || !s.live ||
       s.live>(uint64_t{1}<<s.dimension) || !valid(s.equality)) return false;
    switch(phase) {
    case Phase::singleton:
        // Native first-fold widths beyond 7 are explicitly unsupported.
        return s.dimension-s.remaining>=1 && s.dimension-s.remaining<=7 && s.equality.bits==s.remaining;
    case Phase::retention: case Phase::ood:
        return s.equality.bits==s.dimension-s.remaining;
    case Phase::cosets:
        return s.remaining>=2 && s.equality.bits==s.dimension-s.remaining;
    default: return false;
    }
}
C71_RESIDUAL_HD inline bool valid(CosetShape c,Shape s) {
    if(!valid(s,Phase::cosets) || c.reserved || !c71_pcs::power_two(c.rows) || c.rows<2 ||
       c.rows>(uint64_t{1}<<23) || !c.pad_rows || c.pad_rows>1536 ||
       !c71_pcs::power_two(c.cosets) || c.cosets<2 || c.cosets>4096 ||
       c.first_coset%2 || c.first_coset>c.cosets-2 || c.rows>(uint64_t{1}<<32)/c.cosets) return false;
    const uint64_t n=uint64_t{1}<<(s.remaining-2), height=c.rows*c.cosets;
    return height/16>=n && c.pad_rows<=height-n;
}
C71_RESIDUAL_HD inline bool valid(PowerShape p) {
    return p.bits<=35 && p.low_bits==(p.bits+1)/2 && !p.reserved0 && !p.reserved1;
}
C71_RESIDUAL_HD inline uint64_t low_count(PowerShape p) { return uint64_t{1}<<p.low_bits; }
C71_RESIDUAL_HD inline uint64_t high_count(PowerShape p) { return uint64_t{1}<<(p.bits-p.low_bits); }
C71_RESIDUAL_HD inline E power_lookup(uint64_t index,PowerShape p,const E* low,const E* high) {
    return mul(low[index&(low_count(p)-1)],high[index>>p.low_bits]);
}
C71_RESIDUAL_HD inline uint64_t folded_index(uint64_t index,Shape s) {
    return index&((uint64_t{1}<<s.remaining)-1);
}
C71_RESIDUAL_HD inline E original_contribution(uint64_t index,uint64_t base,Shape s,
    const Chunk* chunks,const E* tables) {
    return base_mul(lookup(index>>s.remaining,chunks,s.equality.chunks,tables),base);
}
C71_RESIDUAL_HD inline uint64_t high_rows(Shape s,CosetShape c) {
    const uint64_t n=uint64_t{1}<<(s.remaining-2);
    return (n+c.pad_rows+c.rows-1)/c.rows;
}
C71_RESIDUAL_HD inline uint64_t ring_index(unsigned column,unsigned component,unsigned lane,
    uint64_t row,CosetShape c) {
    return (uint64_t(column*3+component)*2+lane)*c.rows+row;
}
// Pad j occupies coefficient n+j, even in a reduced geometry with n<rows.
// Pending sums contain the original contributions before low powers/FFT.
C71_RESIDUAL_HD inline uint64_t padded(uint64_t value,const E* pads,const uint64_t* low,
    const uint64_t* high,Shape s,CosetShape c,unsigned column,unsigned component,uint64_t row,unsigned lane) {
    const uint64_t n=uint64_t{1}<<(s.remaining-2);
    for(uint64_t j=(row+c.rows-(n%c.rows))%c.rows;j<c.pad_rows;j+=c.rows)
        value=fp_add(value,fp_mul(limb(pads[uint64_t(column)*c.pad_rows+j],component),high[((n+j)/c.rows)*2+lane]));
    return fp_mul(value,low[uint64_t(lane)*c.rows+row]);
}
C71_RESIDUAL_HD inline bool weight_scalar(int16_t original,uint64_t& out) {
    if(original==INT16_MIN) return false; // original signed-W marker forbidden
    out=original<0 ? P-uint64_t(-int32_t(original)) : uint64_t(original);
    return true;
}
C71_RESIDUAL_HD inline bool valid_fold(uint64_t count,unsigned rounds,E r0,E r1) {
    return c71_pcs::power_two(count) && count<=(uint64_t{1}<<28) &&
        (rounds==1 || rounds==2) && count>=(uint64_t{1}<<rounds) && canonical(r0) &&
        (rounds==1 || canonical(r1));
}
// Used by fold kernels and, later, virtual-prefix query/round loaders.
C71_RESIDUAL_HD inline E folded_at(ConstPlanes values,uint64_t count,uint64_t index,
    unsigned rounds,E r0,E r1) {
    if(rounds==1) return fold(load(values,index),load(values,index+count/2),r0);
    const uint64_t quarter=count/4;
    return fold2(load(values,index),load(values,index+quarter),load(values,index+2*quarter),
        load(values,index+3*quarter),r0,r1);
}
inline bool valid_output(Phase phase,Output out) {
    const bool empty=!out.retained.c0 && !out.retained.c1 && !out.retained.c2;
    switch(phase) {
    case Phase::singleton: case Phase::ood: return empty && !out.ring && out.reduced;
    case Phase::retention:
        return out.retained.c0 && out.retained.c1 && out.retained.c2 && !out.ring && !out.reduced &&
            out.retained.c0!=out.retained.c1 && out.retained.c0!=out.retained.c2 && out.retained.c1!=out.retained.c2;
    case Phase::cosets: return empty && out.ring && !out.reduced;
    default: return false;
    }
}
inline bool empty(CosetShape c) {
    return !c.rows && !c.pad_rows && !c.cosets && !c.first_coset && !c.reserved;
}
inline bool empty(PowerShape p) { return !p.bits && !p.low_bits && !p.reserved0 && !p.reserved1; }
// Launcher pointer/phase guard only. The common owner must ALSO validate the
// host packet, byte spans, identities, aliases (including partial overlap),
// initialized input/pending output states, full coverage, and joint budget.
// Device lookup descriptors are immutable copies of that validated packet.
inline bool valid_arguments(Shape s,Phase phase,Output out,const Chunk* chunks,const E* tables,
    CosetShape c,const uint64_t* high,PowerShape p,const E* power_low,const E* power_high) {
    if(!valid(s,phase) || !valid_output(phase,out) ||
       ((s.equality.chunks!=0)!=(chunks!=nullptr)) || ((s.equality.entries!=0)!=(tables!=nullptr))) return false;
    switch(phase) {
    case Phase::singleton: case Phase::retention:
        return empty(c) && !high && empty(p) && !power_low && !power_high;
    case Phase::cosets:
        return valid(c,s) && high && empty(p) && !power_low && !power_high;
    case Phase::ood:
        return empty(c) && !high && valid(p) && p.bits==s.remaining && power_low && power_high && power_low!=power_high;
    default: return false;
    }
}
}
#undef C71_RESIDUAL_HD
