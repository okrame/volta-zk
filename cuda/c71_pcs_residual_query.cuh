// Preparatory resident PCS query loader. PCS v^3=v+1; never MAC u^3=2.
// One original/retained visit produces all three base limbs together.
#pragma once
#include "c71_pcs_residual.cuh"
#include "c71_pcs_query.cuh"
#ifdef __CUDACC__
#define C71_QUERY_E_HD __host__ __device__
#else
#define C71_QUERY_E_HD
#endif

namespace c71_pcs_residual_query {
namespace pcs=c71_pcs_residual;
constexpr uint64_t max_capacity=uint64_t{1}<<20;
constexpr uint64_t max_message_rows=uint64_t{1}<<27;
constexpr unsigned threads=256;
constexpr unsigned coefficient_tile=32, prefix_tile=256, workers=8, max_blocks=8192;
constexpr uint64_t weight_shared_bytes=(threads+prefix_tile)*sizeof(pcs::E);
static_assert(threads==coefficient_tile*workers && weight_shared_bytes==12288);
struct WeightWork {uint64_t message_count,prefixes,coefficient_tiles,prefix_tiles,tasks;};

// These are the four E columns of a sourcewise extension, not the 128
// columns of the initial base commitment. A folded polynomial need not
// preserve its original public zero suffix: active is always the full n.
C71_QUERY_E_HD inline bool valid_shape(pcs::Shape s,bool retained) {
    if(!pcs::valid(s,pcs::Phase::cosets) || s.remaining>29) return false;
    return !retained || (s.dimension<=28 && s.live==(uint64_t{1}<<s.dimension) &&
        s.dimension-s.remaining<=2);
}
C71_QUERY_E_HD inline uint64_t message_rows(pcs::Shape s) {
    return uint64_t{1}<<(s.remaining-2);
}
C71_QUERY_E_HD inline bool valid_block(pcs::Shape s,uint64_t capacity,c71_pcs::QueryBlock b) {
    if(!valid_shape(s,false) || !c71_pcs::power_two(capacity) || capacity>max_capacity ||
       b.pad_only>1 || b.message_rows!=message_rows(s) || b.window_first ||
       !b.pad_rows || b.pad_rows>1536 || b.byte_first%b.message_rows ||
       b.byte_first>3*b.message_rows || b.pad_first!=(b.byte_first/b.message_rows)*b.pad_rows ||
       b.first%capacity) return false;
    if(b.pad_only) return !b.active && b.source_rows==b.pad_rows && b.first<=b.source_rows;
    return b.active==b.message_rows &&
        ((b.source_rows==0 && b.first==0) ||
         (b.source_rows==b.message_rows+b.pad_rows && b.first<=b.source_rows));
}
// Public geometry only. Bound prefixes by the first live coefficient before
// creating tasks: no original suffix read or pointless all-suffix CTAs.
// One thread owns a (worker,lane) partial for 32 prefixes; a CTA combines
// eight workers and adds each of its <=32 coefficient sums once per limb.
C71_QUERY_E_HD inline WeightWork weight_work(pcs::Shape s,uint64_t capacity,c71_pcs::QueryBlock b) {
    WeightWork result{};
    if(b.pad_only || !b.source_rows || b.first>=b.message_rows) return result;
    result.message_count=b.message_rows-b.first;
    if(result.message_count>capacity) result.message_count=capacity;
    const uint64_t local=b.byte_first+b.first,length=uint64_t{1}<<s.remaining;
    if(local>=s.live) return result;
    result.prefixes=(s.live-local-1)/length+1;
    result.coefficient_tiles=(result.message_count+coefficient_tile-1)/coefficient_tile;
    result.prefix_tiles=(result.prefixes+prefix_tile-1)/prefix_tile;
    result.tasks=result.coefficient_tiles*result.prefix_tiles;
    return result;
}
inline bool valid_arguments(pcs::Shape s,uint64_t capacity,c71_pcs::QueryBlock b,
    const pcs::Chunk* chunks,const pcs::E* tables,const pcs::E* pads,uint64_t pad_count,uint64_t* low) {
    return valid_block(s,capacity,b) && pads && low && pad_count==4*b.pad_rows &&
        static_cast<const void*>(pads)!=static_cast<const void*>(low) &&
        ((s.equality.chunks!=0)==(chunks!=nullptr)) && ((s.equality.entries!=0)==(tables!=nullptr));
}

// Host valid_packet + immutable upload is mandatory. Bounds are repeated
// for each accessed descriptor so malformed device descriptors cannot form
// an out-of-range shift/address before the terminal sticky flag is set.
C71_QUERY_E_HD inline bool checked_equality(uint64_t prefix,pcs::EqShape shape,
    const pcs::Chunk* chunks,const pcs::E* tables,pcs::E& value) {
    value={1,0,0};
    for(unsigned i=0;i<shape.chunks;++i) {
        const auto c=chunks[i];
        if(c.reserved || !c.bits || c.bits>8 || c.shift>=35 ||
           c.shift+c.bits>shape.bits || c.first>shape.entries ||
           (uint32_t{1}<<c.bits)>shape.entries-c.first) return false;
        const auto factor=tables[c.first+((prefix>>c.shift)&((uint64_t{1}<<c.bits)-1))];
        if(!pcs::canonical(factor)) return false;
        value=pcs::mul(value,factor);
    }
    return true;
}
C71_QUERY_E_HD inline bool pad_at(const pcs::E* pads,c71_pcs::QueryBlock b,uint64_t j,pcs::E& value) {
    value=pads[b.pad_first+(b.pad_only ? j : j-b.message_rows)];
    return pcs::canonical(value);
}

// Preconditions: valid_arguments and owner-validated ordered, full-cover
// packed mapping. input_words includes physical ragged row padding, whereas
// Shape.live counts original coefficients. Padding markers are never read.
// The original public suffix is skipped BEFORE packed_address/read, even
// when the EQ factor happens to be zero. Original -32768 is still forbidden.
C71_QUERY_E_HD inline bool weights_at(const int16_t* input,uint64_t input_words,
    const c71_pcs::WeightTile* tiles,uint64_t tile_count,pcs::Shape s,
    const pcs::Chunk* chunks,const pcs::E* tables,const pcs::E* pads,
    c71_pcs::QueryBlock b,uint64_t j,pcs::E& value) {
    value={};
    if(j>=b.source_rows) return true;
    if(b.pad_only || j>=b.message_rows) return pad_at(pads,b,j,value);
    const uint64_t length=uint64_t{1}<<s.remaining,local=b.byte_first+j;
    const uint64_t prefixes=uint64_t{1}<<(s.dimension-s.remaining);
    for(uint64_t p=0;p<prefixes;++p) {
        const uint64_t index=p*length+local;
        if(index>=s.live) break;
        const uint64_t address=c71_pcs::packed_address(tiles,tile_count,index,s.live);
        if(address>=input_words) return false;
        uint64_t original=0;
        if(!pcs::weight_scalar(input[address],original)) return false;
        pcs::E equality{};
        if(!checked_equality(p,s.equality,chunks,tables,equality)) return false;
        value=pcs::add(value,pcs::base_mul(equality,original));
    }
    return true;
}

// Retained physical planes are full and sealed. A virtual prefix has at
// most two MSB folds. All three source limbs are read and checked in this
// one pass, including zero-weight terms; no original A producer is called.
C71_QUERY_E_HD inline bool resident_at(pcs::ConstPlanes input,uint64_t input_count,
    pcs::Shape s,const pcs::Chunk* chunks,const pcs::E* tables,const pcs::E* pads,
    c71_pcs::QueryBlock b,uint64_t j,pcs::E& value) {
    value={};
    if(j>=b.source_rows) return true;
    if(b.pad_only || j>=b.message_rows) return pad_at(pads,b,j,value);
    const uint64_t length=uint64_t{1}<<s.remaining,local=b.byte_first+j;
    const uint64_t prefixes=uint64_t{1}<<(s.dimension-s.remaining);
    for(uint64_t p=0;p<prefixes;++p) {
        const uint64_t index=p*length+local;
        if(index>=input_count) return false;
        const pcs::E original=pcs::load(input,index);
        if(!pcs::canonical(original)) return false;
        pcs::E equality{};
        if(!checked_equality(p,s.equality,chunks,tables,equality)) return false;
        value=pcs::add(value,pcs::mul(original,equality));
    }
    return true;
}

// Output low[limb*capacity+i], 3*capacity words. Owner applies the existing
// Goldilocks remainder separately to those private views, without another
// source visit. Maximum low payload is 25,165,824 B (not a joint admission).
// EQ packet <=80+30,720 B, pads <=147,456 B; mapping, immutable W, retained
// 24*2^dimension planes, query factors/workspaces, Tree/open rows and all
// host/device peers are additional. No dynamic allocation. W uses two launches
// (initialize low/pads, then tiled prefix sums), or one for a pad/zero-only
// block; A retains its one-pass launcher unchanged. W shared scratch is
// 12,288 B/CTA: 256 cached EQ E + 256 worker partial E. The eight partials
// reduce exactly in Goldilocks before <=3 CAS field updates/coefficient/tile.
// No per-prefix global scratch, second W scan, or new A reconstruction.
// Launchers only enqueue on the owner's stream; one terminal flag/fence
// governs the whole query, and no failed/pending output may be published.
// Owner additionally checks kinds, identity, initialized/sealed leases,
// exact spans, partial aliases, packet coverage, lifetime and joint budget.
}
#undef C71_QUERY_E_HD
