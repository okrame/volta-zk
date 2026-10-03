// Integer nonlinear producers. Public tables carry the calibrated semantics;
// this code only selects entries, rotates pairs, and preserves exact ties.
#pragma once
#include "c71_dense_i16.cuh"
#ifdef __CUDACC__
#define C71_NL_HD __host__ __device__
#else
#define C71_NL_HD
#endif
namespace c71_nonlinear {
struct Rope { uint32_t rows,heads,width,pairs; };
C71_NL_HD inline bool valid(Rope s) {
    return s.rows && s.rows<=150 && s.heads && s.heads<=32 &&
        s.width && s.width<=512 && !(s.width%2) && s.pairs && s.pairs<=s.width/2;
}
C71_NL_HD inline bool rotate(int16_t x,int16_t y,int32_t c,int32_t s,int64_t& a,int64_t& b) {
    if(x==INT16_MIN || y==INT16_MIN || c<-(1<<30) || c>(1<<30) || s<-(1<<30) || s>(1<<30)) return false;
    a=int64_t(c)*x-int64_t(s)*y; b=int64_t(s)*x+int64_t(c)*y; return true;
}
C71_NL_HD inline bool lookup(int16_t x,const int16_t* table,int16_t& y,uint32_t& index) {
    if(x==INT16_MIN) return false;
    index=uint32_t(int(x)+32767); y=table[index]; return y!=INT16_MIN;
}
C71_NL_HD inline bool slack(int16_t maximum,int16_t value,uint32_t index,uint32_t best,int16_t& out) {
    const int v=int(maximum)-value-int(index<best)-32768;
    if(maximum==INT16_MIN || value==INT16_MIN || v<INT16_MIN || v>INT16_MAX) return false;
    out=int16_t(v); return true;
}
}
#undef C71_NL_HD
