// Original biased-byte tiles, not a second witness encoding.
#pragma once
#include "c71_dense_i16.cuh"
#ifdef __CUDACC__
#define C71_BYTE_HD __host__ __device__
#else
#define C71_BYTE_HD
#endif
namespace c71_byte {
struct Tile {
    uint64_t input_first, input_stride, rows, columns, original_first;
    uint64_t window_first, window_length;
    uint32_t byte_first, width, signed_width, dimension, suffix, bottom;
};
static_assert(sizeof(Tile)==80);
inline bool valid(Tile t,uint32_t kind,uint64_t input_count,uint64_t output_count) {
    if((kind!=1 && kind!=6) || (kind==1 ? t.signed_width!=2 : (t.signed_width!=4 && t.signed_width!=6)) ||
       !t.width || t.width>t.signed_width || t.byte_first>t.signed_width-t.width ||
       !t.rows || !t.columns || t.columns>t.input_stride || t.input_first>input_count ||
       t.columns>input_count-t.input_first ||
       t.rows-1>(input_count-t.input_first-t.columns)/t.input_stride ||
       !t.dimension || t.dimension>35 || t.bottom>t.dimension || t.suffix>t.dimension-t.bottom ||
       !t.window_length || t.window_length>(uint64_t{1}<<31) ||
       (t.window_length&(t.window_length-1)) || t.window_length<(uint64_t{1}<<t.bottom) ||
       t.window_first%t.window_length || t.window_length!=output_count) return false;
    const uint64_t domain=uint64_t{1}<<t.dimension;
    return t.window_first<=domain && t.window_length<=domain-t.window_first &&
        t.original_first<domain && t.rows<=(domain-t.original_first)/t.width/t.columns;
}
C71_BYTE_HD inline uint64_t ordered(uint64_t original,Tile t) {
    const uint64_t upper=original>>t.bottom;
    return ((((upper&((uint64_t{1}<<t.suffix)-1))<<(t.dimension-t.bottom-t.suffix)) |
             (upper>>t.suffix))<<t.bottom) | (original&((uint64_t{1}<<t.bottom)-1));
}
C71_BYTE_HD inline bool encode(int64_t value,unsigned signed_width,unsigned lane,uint8_t& byte) {
    const int64_t bound=int64_t{1}<<(8*signed_width-1);
    // The byte codec includes argmax's biased-u16 slack. Ordinary arithmetic
    // rejects INT16_MIN at its own boundary, not in this shared byte encoder.
    if(value < -bound || value>=bound) return false;
    byte=uint8_t(uint64_t(value)>>(8*lane)) ^ (lane+1==signed_width?128:0);
    return true;
}
}
#undef C71_BYTE_HD
