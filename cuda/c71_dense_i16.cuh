// Exact private integer GEMM. No rounding, field arithmetic, FS or MACs.
#pragma once
#include <cstddef>
#include <cstdint>
#ifdef __CUDACC__
#define C71_DENSE_HD __host__ __device__
#else
#define C71_DENSE_HD
#endif
namespace c71_dense {
constexpr unsigned max_k=21504, max_m=150, max_n=262144;
// Each of four signed-int8 sums fits int32, including zero K padding.
static_assert(uint64_t(max_k)*128*128 < uint64_t{1}<<31);
static_assert(uint64_t(max_k)*32767*32767 < uint64_t{1}<<47);
struct Shape { uint32_t m,n,k; };
struct Pointwise { int64_t a,b; uint32_t multiply; };
static_assert(sizeof(Pointwise)==24);
C71_DENSE_HD inline bool valid_pointwise(Pointwise op) {
    return op.multiply<=1 && op.a>=-(int64_t{1}<<30) && op.a<=(int64_t{1}<<30) &&
        op.b>=-(int64_t{1}<<30) && op.b<=(int64_t{1}<<30) &&
        (!op.multiply || (op.a==1 && op.b==1));
}
C71_DENSE_HD inline bool pointwise(int16_t x,int16_t y,Pointwise op,int64_t& out) {
    if(!valid_pointwise(op) || ((op.multiply || op.a) && x==INT16_MIN) ||
       ((op.multiply || op.b) && y==INT16_MIN)) return false;
    // Two bounded linear terms fit signed-48; gate fits signed-32.
    out=op.multiply?int64_t(x)*y:op.a*x+op.b*y;
    return true;
}
inline bool valid(Shape s,uint64_t a_words,uint64_t w_words,uint64_t out_values) {
    return s.m && s.m<=max_m && s.n && s.n<=max_n && s.k && s.k<=max_k &&
        uint64_t(s.m)*s.k<=a_words && uint64_t(s.n)*s.k<=w_words && uint64_t(s.m)*s.n<=out_values;
}
inline bool span(const void* p,uint64_t bytes,uintptr_t& end) {
    const auto start=reinterpret_cast<uintptr_t>(p);
    if(!p || bytes>UINTPTR_MAX-start) return false;
    end=start+bytes; return true;
}
inline bool overlaps(const void* a,uintptr_t ae,const void* b,uintptr_t be) {
    return reinterpret_cast<uintptr_t>(a)<be && reinterpret_cast<uintptr_t>(b)<ae;
}
inline bool valid_pointwise_buffers(const int16_t* x,const int16_t* y,
    int64_t* output,uint64_t count,Pointwise op,uint32_t* failed) {
    uintptr_t oe,fe;
    if(!valid_pointwise(op) || !count || count>uint64_t(max_m)*max_n ||
       reinterpret_cast<uintptr_t>(output)%8 || reinterpret_cast<uintptr_t>(failed)%4 ||
       !span(output,count*8,oe) || !span(failed,4,fe) || overlaps(output,oe,failed,fe)) return false;
    const int16_t* inputs[]={x,y}; const bool used[]={op.multiply || op.a,op.multiply || op.b};
    for(unsigned j=0;j<2;++j) {
        uintptr_t end;
        if(used[j] ? (reinterpret_cast<uintptr_t>(inputs[j])%2 || !span(inputs[j],count*2,end) ||
           overlaps(inputs[j],end,output,oe) || overlaps(inputs[j],end,failed,fe)) : inputs[j]!=nullptr) return false;
    }
    return true;
}
inline bool valid_buffers(const int16_t* x,uint64_t x_words,const int16_t* w,uint64_t w_words,
    int64_t* out,uint64_t out_values,uint32_t* failed,Shape s) {
    if(!valid(s,x_words,w_words,out_values) ||
       reinterpret_cast<uintptr_t>(x)%2 || reinterpret_cast<uintptr_t>(w)%2 ||
       reinterpret_cast<uintptr_t>(out)%8 || reinterpret_cast<uintptr_t>(failed)%4) return false;
    uintptr_t xe,we,oe,fe;
    return span(x,uint64_t(s.m)*s.k*2,xe) && span(w,uint64_t(s.n)*s.k*2,we) &&
       span(out,uint64_t(s.m)*s.n*8,oe) && span(failed,4,fe) &&
       !overlaps(x,xe,out,oe) && !overlaps(w,we,out,oe) && !overlaps(failed,fe,x,xe) &&
       !overlaps(failed,fe,w,we) && !overlaps(failed,fe,out,oe);
}
// Dense m16n8k32 s8 fragment coordinates (NOT the sparse MMA layout):
// https://docs.nvidia.com/cuda/parallel-thread-execution/index.html#warp-level-matrix-fragment-mma-16832
C71_DENSE_HD inline unsigned a_row(unsigned lane,unsigned reg) { return lane/4+8*(reg%2); }
C71_DENSE_HD inline unsigned a_k(unsigned lane,unsigned reg,unsigned byte) { return 4*(lane%4)+16*(reg/2)+byte; }
C71_DENSE_HD inline unsigned w_row(unsigned lane) { return lane/4; }
C71_DENSE_HD inline unsigned w_k(unsigned lane,unsigned reg,unsigned byte) { return 4*(lane%4)+16*reg+byte; }
C71_DENSE_HD inline unsigned out_row(unsigned lane,unsigned reg) { return lane/4+8*(reg/2); }
C71_DENSE_HD inline unsigned out_col(unsigned lane,unsigned reg) { return 2*(lane%4)+reg%2; }
C71_DENSE_HD inline int low(int16_t x) { return int(uint16_t(x)&255)-128; }
C71_DENSE_HD inline int high(int16_t x) { return (int(x)-low(x)-128)/256; }
C71_DENSE_HD inline void pack(int16_t x,unsigned byte,uint32_t& hi,uint32_t& lo) {
    hi|=uint32_t(uint8_t(high(x)))<<(8*byte);
    lo|=uint32_t(uint8_t(low(x)))<<(8*byte);
}
C71_DENSE_HD inline int64_t compose(int32_t hh,int32_t hl,int32_t lh,int32_t ll,
                                   int32_t sum_a,int32_t sum_w,unsigned padded_k) {
    // x=256*h+l+128. Correct in terms of ORIGINAL row sums; padded x=0
    // has (h,l)=(0,-128), so its ll contribution must also cancel.
    return 65536*int64_t(hh)+256*(int64_t(hl)+lh)+ll+
        128*(int64_t(sum_a)+sum_w)-16384*int64_t(padded_k);
}
// Same signed-48 / symmetric-i16 classes as c71_matrix::rne::integer.
// Magnitude arithmetic avoids implementation-defined negative shifts and
// C++ undefined signed left shifts. Publish only on success, never clamp.
C71_DENSE_HD inline bool quantize(int64_t raw,int32_t shift,int16_t& output) {
    if(raw<-(int64_t{1}<<47) || raw>=(int64_t{1}<<47)) return false;
    int64_t y=0;
    if(shift>=48) y=0;
    else if(shift<=-15) { if(raw) return false; }
    else if(shift<=0) y=raw*(int64_t{1}<<-shift);
    else {
        const uint64_t magnitude=uint64_t(raw<0?-raw:raw), d=uint64_t{1}<<shift;
        // The denominator is a power of two. Spell out integer shifts/masks
        // so nvcc need not lower generic division through reciprocal helpers.
        const uint64_t q=magnitude>>shift, r=magnitude&(d-1);
        const int64_t rounded=int64_t(q+(r>d-r || (r==d-r && (q&1))));
        y=raw<0?-rounded:rounded;
    }
    if(y<-32767 || y>32767) return false;
    output=int16_t(y); return true;
}
}
#undef C71_DENSE_HD
