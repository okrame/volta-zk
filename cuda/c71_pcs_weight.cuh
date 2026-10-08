// Original packed signed W -> canonical base-field coset coefficients.
// No alternate Fp3 representation, transcript, seed or MAC is introduced.
#pragma once
#include "c71_range_native.cuh"
#ifdef __CUDACC__
#define C71_W_HD __host__ __device__
#else
#define C71_W_HD
#endif
namespace c71_pcs {
struct WeightTile {
    uint64_t first, count, packed_first, packed_stride, columns;
};
static_assert(sizeof(WeightTile)==40);
struct WeightShape {
    uint64_t message_rows, rows;
    uint32_t pad_rows, cosets, first_coset, first_column, slots;
};
static_assert(sizeof(WeightShape)==40);
C71_W_HD inline bool power_two(uint64_t n) { return n && !(n&(n-1)); }
C71_W_HD inline bool valid(WeightShape s) {
    return power_two(s.message_rows) && s.message_rows<=(uint64_t{1}<<28) &&
        power_two(s.rows) && s.rows>=4 && s.rows<=(uint64_t{1}<<20) && (s.rows&0x5555555555555555ULL) &&
        s.message_rows>=s.rows && s.message_rows/s.rows<=256 &&
        s.pad_rows && s.pad_rows<=1536 && power_two(s.cosets) && s.cosets>=32 && s.cosets<=4096 &&
        s.first_coset%32==0 && s.first_coset<=s.cosets-32 &&
        s.first_column%4==0 && s.first_column<=124 && (s.slots==0 || s.slots==4);
}
C71_W_HD inline uint64_t high_rows(WeightShape s) {
    return (s.message_rows+s.pad_rows+s.rows-1)/s.rows;
}
C71_W_HD inline uint64_t power(uint64_t base,uint64_t exponent) {
    uint64_t result=1;
    while(exponent) {
        if(exponent&1) result=fp_mul(result,base);
        base=fp_mul(base,base); exponent>>=1;
    }
    return result;
}
C71_W_HD inline uint64_t packed_address(const WeightTile* tiles,uint64_t count,uint64_t index,uint64_t live) {
    if(index>=live) return UINT64_MAX; // the original public zero suffix
    uint64_t lo=0,hi=count;
    while(lo<hi) { const uint64_t mid=(lo+hi)/2; if(tiles[mid].first<=index) lo=mid+1; else hi=mid; }
    const auto t=tiles[lo-1];
    const uint64_t local=index-t.first;
    return t.packed_first+(local/t.columns)*t.packed_stride+local%t.columns;
}
// At most 256 original signed i16 products: |sum|<2^87. Two limbs
// retain the exact signed integer, with unsigned wrap defining subtraction.
// Reduction happens once per dot, not after every coefficient contribution.
struct SignedWide {
    uint64_t lo=0,hi=0;
    C71_W_HD void add(int16_t weight,uint64_t factor) {
        const uint64_t magnitude=weight<0 ? uint64_t(-int32_t(weight)) : uint64_t(weight);
        const uint64_t low=magnitude*factor;
#ifdef __CUDA_ARCH__
        const uint64_t high=__umul64hi(magnitude,factor);
#else
        const uint64_t high=uint64_t((static_cast<unsigned __int128>(magnitude)*factor)>>64);
#endif
        const uint64_t before=lo;
        if(weight<0) { lo-=low; hi-=high+(before<low); }
        else { lo+=low; hi+=high+(lo<before); }
    }
    C71_W_HD uint64_t residue() const {
        const uint64_t folded=fp_add(fp_sub(lo,hi>>32),(hi&EPSILON)*EPSILON);
        // Unsigned encoding adds 2^128 for negative sums; modulo p,
        // 2^128 == -2^32. Undo it using the proven signed bound above.
        return hi>>63 ? fp_add(folded,uint64_t{1}<<32) : folded;
    }
};
C71_W_HD inline uint64_t accumulate(const int16_t* weights,const WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,const uint64_t* low,
    const uint64_t* high,WeightShape s,unsigned column,uint64_t row,unsigned lane) {
    SignedWide sum{};
    for(uint64_t q=0;q<s.message_rows/s.rows;++q) {
        const uint64_t index=uint64_t(column)*s.message_rows+q*s.rows+row;
        if(index>=live) break; // original public suffix; later q cannot be live
        const uint64_t address=packed_address(tiles,tile_count,index,live);
        sum.add(weights[address],high[q*32+lane]);
    }
    uint64_t result=sum.residue();
    for(uint64_t j=row;j<s.pad_rows;j+=s.rows) {
        const uint64_t value=pads[uint64_t(column)*s.pad_rows+j];
        result=fp_add(result,fp_mul(value,high[((s.message_rows+j)/s.rows)*32+lane]));
    }
    return fp_mul(result,low[uint64_t(lane)*s.rows+row]);
}
}
#undef C71_W_HD
