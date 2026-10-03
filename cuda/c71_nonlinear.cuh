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
using Wide=unsigned __int128;
struct Rms {
    uint32_t rows,heads,columns,weighted;
    uint64_t coefficients[6];
};
struct Attention { uint32_t rows,first,head,old,groups,lanes; };
inline Wide coefficient(const Rms& shape,unsigned index) {
    return Wide(shape.coefficients[2*index]) | (Wide(shape.coefficients[2*index+1])<<64);
}
inline bool valid(Rms shape) {
    if(!shape.rows || shape.rows>150 || !shape.heads || shape.heads>32 ||
       !shape.columns || shape.columns>5376 || shape.weighted>1) return false;
    const Wide maximum=~Wide{0}, numerator=coefficient(shape,0), epsilon=coefficient(shape,1), scale=coefficient(shape,2);
    const Wide top=Wide{4}<<(shape.weighted?62:30), statistic=(Wide{1}<<47)-1, boundary=Wide{131071}*131071;
    return numerator && epsilon && scale && numerator<=maximum/top &&
        scale<=(maximum-epsilon)/statistic && epsilon+scale*statistic<=maximum/boundary;
}
inline bool valid(Attention shape) {
    return shape.rows && shape.rows<=150 && shape.first<150 && shape.rows<=150-shape.first &&
        shape.head<32 && (shape.old==0 || shape.old==150 || shape.old==300) &&
        shape.groups && shape.groups<=32 && 32%shape.groups==0 && shape.lanes && shape.lanes<=512;
}
C71_NL_HD inline bool rms_round(Rms shape,int64_t product,uint64_t statistic,int16_t& output) {
    const uint64_t magnitude=product<0?uint64_t(-(product+1))+1:uint64_t(product);
    const uint64_t limit=shape.weighted?uint64_t(32767)*32767:32767;
    if(magnitude>limit || statistic>uint64_t(shape.columns)*32767*32767) return false;
    const Wide numerator=(Wide(shape.coefficients[0]) | (Wide(shape.coefficients[1])<<64))*magnitude*magnitude;
    const Wide denominator=(Wide(shape.coefficients[2]) | (Wide(shape.coefficients[3])<<64))+
        (Wide(shape.coefficients[4]) | (Wide(shape.coefficients[5])<<64))*statistic;
    if(4*numerator>=denominator*65535*65535) return false;
    uint32_t lower=0,upper=32768;
    while(upper-lower>1) {
        const uint32_t middle=(lower+upper)/2;
        if(denominator*middle*middle<=numerator) lower=middle; else upper=middle;
    }
    const Wide half=denominator*(2*lower+1)*(2*lower+1);
    const int32_t rounded=lower+uint32_t(4*numerator>half || (4*numerator==half && (lower&1)));
    output=int16_t(product<0?-rounded:rounded); return true;
}
C71_NL_HD inline int16_t probability(int32_t exponential,int64_t denominator) {
    const int64_t numerator=int64_t(exponential)*16384, quotient=numerator/denominator, remainder=numerator%denominator;
    return int16_t(quotient+(2*remainder>denominator || (2*remainder==denominator && (quotient&1))));
}
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
