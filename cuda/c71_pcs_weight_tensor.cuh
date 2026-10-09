// Exact Tensor Core accumulation selected by the owner/runner.
// Shares the original packed W, WeightShape, powers, pads and output ring.
#pragma once
#include "c71_pcs_weight.cuh"
#include "c71_dense_i16.cuh"
#ifdef __CUDACC__
#define C71_WT_HD __host__ __device__
#else
#define C71_WT_HD
#endif
namespace c71_pcs_tensor {
constexpr unsigned limbs=4, limb_bits=16, rows_per_column=4, mma_rows=16;
constexpr unsigned max_q=256, cosets=32, threads=128;
// Eight padding words avoid mapping every original row to the same starting
// shared bank under the dense A fragment's four-lane K partition.
constexpr unsigned shared_stride=max_q+8;
constexpr unsigned shared_bytes=mma_rows*shared_stride*sizeof(int16_t);
static_assert(shared_bytes==8448);
static_assert(limbs*limb_bits==64);
// Every INT8 accumulation prefix, including padded zero contributions, fits
// int32. Each reconstructed signed digit dot fits signed 39 bits; restoring
// the digit bias needs at most signed 40 bits. No saturating instruction.
static_assert(uint64_t(max_q)*128*128 < (uint64_t{1}<<31));
static_assert(uint64_t(max_q)*32767*32768 < (uint64_t{1}<<38));
static_assert(uint64_t(max_q)*32767*65535 < (uint64_t{1}<<39));

// value = sum_l (digit(value,l)+32768)*2^(16*l). The intermediate
// digit -32768 is valid here: only ORIGINAL signed W forbids INT16_MIN.
// dense_i16::pack/compose handle that digit exactly without RNE/clamping.
C71_WT_HD inline int16_t digit(uint64_t value,unsigned limb) {
    return int16_t(int32_t((value>>(limb_bits*limb))&65535u)-32768);
}

// Largest original q needed by any of the 16 public (column,row) pairs in
// one CTA. Skip entirely public zero groups; padded MMA K is zero data.
C71_WT_HD inline unsigned needed_q(c71_pcs::WeightShape s,uint64_t live,uint64_t row0) {
    const uint64_t first=uint64_t(s.first_column)*s.message_rows+row0;
    if(first>=live) return 0;
    const uint64_t needed=(live-1-first)/s.rows+1, bound=s.message_rows/s.rows;
    return unsigned(needed<bound?needed:bound);
}

// Restore an unsigned 16-bit digit dot from its biased signed MMA dot, then
// append it to the original SignedWide two's-complement encoding. Unsigned
// shifts/carry/subtraction avoid undefined signed shifts or signed overflow.
// Reduction remains ONCE after all four exact digit dots, as for ordinary W.
// |sum_W| <= 256*32767 < 2^23; |32768*sum_W| < 2^38;
// |unsigned_digit_dot| <= 256*32767*65535 < 2^39. Every partial
// recombination has magnitude <= 256*32767*(2^64-1) < 2^87, preserving
// SignedWide::residue's sign test and its original Goldilocks correction.
C71_WT_HD inline bool add_dot(c71_pcs::SignedWide& sum,int64_t signed_dot,
                             int32_t original_sum,unsigned limb) {
    if(limb>=limbs || signed_dot<=-(int64_t{1}<<38) || signed_dot>=(int64_t{1}<<38) ||
       original_sum<=-(int32_t{1}<<23) || original_sum>=(int32_t{1}<<23)) return false;
    const int64_t dot=signed_dot+32768*int64_t(original_sum);
    if(dot<=-(int64_t{1}<<39) || dot>=(int64_t{1}<<39)) return false;
    const uint64_t magnitude=dot<0?uint64_t(-(dot+1))+1:uint64_t(dot);
    const unsigned shift=limb_bits*limb;
    const uint64_t low=magnitude<<shift, high=shift?magnitude>>(64-shift):0;
    const uint64_t before=sum.lo;
    if(dot<0) { sum.lo-=low; sum.hi-=high+(before<low); }
    else { sum.lo+=low; sum.hi+=high+(sum.lo<before); }
    return true;
}
}
#undef C71_WT_HD
