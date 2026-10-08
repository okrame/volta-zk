// Original resident A words -> biased bytes -> four exact base-field cosets.
#pragma once
#include "c71_pcs_weight.cuh"
#include "c71_byte_gather.cuh"
#ifdef __CUDACC__
#define C71_A_HD __host__ __device__
#else
#define C71_A_HD
#endif
namespace c71_pcs {
struct SourceTile {
    uint64_t input_first, input_stride, rows, columns, original_first;
    uint32_t byte_first, width, signed_width;
};
struct SourceShape {
    uint64_t message_rows, rows, live;
    uint32_t pad_rows, cosets, first_coset;
};
static_assert(sizeof(SourceTile)==56 && sizeof(SourceShape)==40);
C71_A_HD inline bool valid(SourceShape s) {
    return power_two(s.message_rows) && s.message_rows<=(uint64_t{1}<<27) &&
        power_two(s.rows) && s.rows>=4 && s.rows<=(uint64_t{1}<<20) && (s.rows&0x5555555555555555ULL) &&
        s.message_rows>=s.rows && s.message_rows/s.rows<=128 && s.live && s.live<=128*s.message_rows &&
        s.pad_rows && s.pad_rows<=1536 && power_two(s.cosets) && s.cosets>=4 && s.cosets<=4096 &&
        s.rows*s.cosets==16*s.message_rows && s.first_coset%4==0 && s.first_coset<=s.cosets-4;
}
inline bool valid(SourceTile t,unsigned kind,uint64_t words,uint64_t live) {
    return (kind==1 || kind==6) && (kind==1 ? t.signed_width==2 : (t.signed_width==4 || t.signed_width==6)) &&
        t.width && t.width<=t.signed_width && t.byte_first<=t.signed_width-t.width &&
        t.rows && t.columns && t.columns<=t.input_stride && t.input_first<=words &&
        t.columns<=words-t.input_first && t.rows-1<=(words-t.input_first-t.columns)/t.input_stride &&
        t.original_first<live && t.rows<=(live-t.original_first)/t.width/t.columns;
}
C71_A_HD inline uint64_t high_rows(SourceShape s) {
    return (s.message_rows+s.pad_rows+s.rows-1)/s.rows;
}
C71_A_HD inline uint64_t padded(uint64_t value,const uint64_t* pads,const uint64_t* low,
    const uint64_t* high,SourceShape s,unsigned column,uint64_t row,unsigned lane) {
    for(uint64_t j=row;j<s.pad_rows;j+=s.rows)
        value=fp_add(value,fp_mul(pads[uint64_t(column)*s.pad_rows+j],high[((s.message_rows+j)/s.rows)*4+lane]));
    return fp_mul(value,low[uint64_t(lane)*s.rows+row]);
}
}
#undef C71_A_HD
