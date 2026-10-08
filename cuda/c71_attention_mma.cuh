// Exact attention operands for the existing signed-int8 limb MMA. All
// coordinates are public; future KV/Pi cells are never loaded. No coins.
#pragma once
#include "c71_nonlinear.cuh"
#ifdef __CUDACC__
#define C71_ATTN_HD __host__ __device__
#else
#define C71_ATTN_HD
#endif
namespace c71_attention {
using Shape=c71_nonlinear::Attention;
constexpr uint64_t PAD=UINT64_MAX;
struct PiPointers { const int16_t* heads[32]; };
static_assert(sizeof(PiPointers)==256);
static_assert(uint64_t(512)*128*128<(uint64_t{1}<<31));
static_assert(uint64_t(512)*32767*32767<(uint64_t{1}<<47));
static_assert(uint64_t(450)*16384*32767<(uint64_t{1}<<47));

C71_ATTN_HD inline unsigned live(Shape s,unsigned row) { return s.old+s.first+row+1; }
C71_ATTN_HD inline unsigned tile_live(Shape s,unsigned row0) {
    return s.old+s.first+(row0+16<s.rows ? row0+16 : s.rows);
}
C71_ATTN_HD inline unsigned group(Shape s,unsigned head) { return head/(32/s.groups); }
C71_ATTN_HD inline unsigned padded(unsigned k) { return (k+31)&~31u; }
C71_ATTN_HD inline uint64_t qk_a_index(Shape s,unsigned row,unsigned k) {
    return row<s.rows && k<s.lanes ? (uint64_t(row)*32+s.head)*s.lanes+k : PAD;
}
C71_ATTN_HD inline uint64_t qk_b_index(Shape s,unsigned row0,unsigned key,unsigned k) {
    return key<tile_live(s,row0) && k<s.lanes
        ? (uint64_t(key)*s.groups+group(s,s.head))*s.lanes+k : PAD;
}
C71_ATTN_HD inline uint64_t pv_a_index(Shape s,unsigned row,unsigned key) {
    return row<s.rows && key<live(s,row) ? uint64_t(row)*(s.old+150)+key : PAD;
}
C71_ATTN_HD inline uint64_t pv_b_index(Shape s,unsigned head,unsigned row0,unsigned lane,unsigned key) {
    return lane<s.lanes && key<tile_live(s,row0)
        ? (uint64_t(key)*s.groups+group(s,head))*s.lanes+lane : PAD;
}
C71_ATTN_HD inline int16_t load(const int16_t* input,uint64_t index,bool& failed,bool pi=false) {
    if(index==PAD) return 0;
    const int16_t value=input[index];
    failed |= pi ? (value<0 || value>16384) : value==INT16_MIN;
    return value;
}
C71_ATTN_HD inline uint64_t output_index(Shape s,bool pv,unsigned head,unsigned row,unsigned column) {
    return pv ? (uint64_t(row)*32+head)*s.lanes+column : uint64_t(row)*(s.old+150)+column;
}
C71_ATTN_HD inline bool output_live(Shape s,bool pv,unsigned row,unsigned column) {
    return row<s.rows && column<(pv ? s.lanes : s.old+150);
}
C71_ATTN_HD inline int64_t output_value(Shape s,bool pv,unsigned row,unsigned column,int64_t value) {
    return pv || column<live(s,row) ? value : 0;
}
}
#undef C71_ATTN_HD

#ifdef __CUDACC__
// Candidate launchers have the original pointer ABI; common owner supplies
// typed spans, a sticky zero flag, and terminal fence/check before publication.
extern "C" cudaError_t c71_qk_mma_launch(cudaStream_t,const int16_t* query,const int16_t* keys,
    int64_t* output,c71_nonlinear::Attention,uint32_t* failed);
extern "C" cudaError_t c71_pv_mma_launch(cudaStream_t,const int16_t* const* probabilities,const int16_t* values,
    int64_t* output,c71_nonlinear::Attention,uint32_t* failed);
#endif
