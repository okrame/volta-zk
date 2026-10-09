// Base PCS remainder queries on the existing numeric owner. No extension/MAC
// basis conversion and no source/challenge interface.
#pragma once
#include "c71_pcs_weight.cuh"
namespace c71_pcs {
struct QueryBlock {
    uint64_t first, source_rows, message_rows, active;
    uint64_t byte_first, window_first, pad_first, pad_rows;
    uint32_t pad_only;
};
static_assert(sizeof(QueryBlock)==72);
#ifdef __CUDACC__
#define C71_QUERY_HD __host__ __device__
#else
#define C71_QUERY_HD
#endif
// Direct original W loader, separate from the byte-window/None-zero loader.
// The owner seals every signed W word (INT16_MIN forbidden), the original
// ordered WeightTile partition and canonical pads before this is submitted.
// No original pointer or challenge reaches a numeric producer.
C71_QUERY_HD inline uint64_t query_weight_active(uint64_t live,QueryBlock s) {
    const uint64_t left=live>s.byte_first ? live-s.byte_first : 0;
    return left<s.message_rows ? left : s.message_rows;
}
C71_QUERY_HD inline bool valid_query_weight_low(QueryBlock s,uint64_t capacity,uint64_t live,uint64_t pad_count) {
    if(!power_two(capacity) || capacity>(uint64_t{1}<<20) ||
       !power_two(s.message_rows) || s.message_rows>(uint64_t{1}<<28) ||
       !live || live>128*s.message_rows || s.pad_only>1 || s.window_first ||
       !s.pad_rows || s.pad_rows>1536 || s.byte_first%s.message_rows ||
       s.byte_first/s.message_rows>=128 || s.pad_first!=(s.byte_first/s.message_rows)*s.pad_rows ||
       s.pad_first>pad_count || s.pad_rows>pad_count-s.pad_first ||
       s.first%capacity || s.first>s.source_rows) return false;
    return s.pad_only ? (!s.active && s.source_rows==s.pad_rows) :
        (s.active==query_weight_active(live,s) &&
         (s.source_rows==s.active || s.source_rows==s.message_rows+s.pad_rows));
}
// Call only with the public geometry and sealed input contracts above.
// Guard the original logical index before packed_address or a W read. The
// public zero suffix and pad-only blocks therefore perform no W access.
C71_QUERY_HD inline uint64_t query_weight_low_at(const int16_t* weights,const WeightTile* tiles,
    uint64_t tile_count,uint64_t live,const uint64_t* pads,QueryBlock s,uint64_t j) {
    if(j>=s.source_rows) return 0;
    if(s.pad_only) return pads[s.pad_first+j];
    if(j<s.active) {
        const uint64_t index=s.byte_first+j;
        if(index>=live) return 0;
        const int32_t value=weights[packed_address(tiles,tile_count,index,live)];
        return value<0 ? P-uint64_t(-value) : uint64_t(value);
    }
    return j>=s.message_rows ? pads[s.pad_first+j-s.message_rows] : 0;
}
#undef C71_QUERY_HD
}
