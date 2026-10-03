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
}
#undef C71_DENSE_HD
