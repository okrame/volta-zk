// Private B12 coins only. Numeric producers never receive this descriptor.
// Allocation, stream, failure lifetime and publication belong to the caller.
#pragma once
#include "c71_blake3.cuh"
#ifdef __CUDACC__
#define C71_SALT_HD __host__ __device__
#else
#define C71_SALT_HD
#endif
namespace c71_salts {
constexpr uint64_t CAP = uint64_t{1} << 40;
constexpr uint64_t MODULUS = 0xffffffff00000001ULL;
constexpr uint32_t MAX_CANDIDATES = uint32_t{1} << 24;
constexpr uint32_t SCAN_THREADS = 256;

struct Descriptor { c71_blake3::Output output; };
struct Chunk {
    uint64_t cursor, accepted, target;
    uint32_t candidates, capacity;
};
struct Geometry { uint64_t rows, origin; uint32_t cosets, cut; };
struct Progress {
    uint64_t cursor, accepted, logical_bytes, physical_blocks;
    uint32_t failed, complete;
};
static_assert(sizeof(Descriptor)==112 && sizeof(Chunk)==32);
static_assert(sizeof(Geometry)==24 && sizeof(Progress)==40);

C71_SALT_HD constexpr bool power_two(uint64_t x) { return x && !(x & (x-1)); }
C71_SALT_HD constexpr bool valid_capacity(uint32_t n) {
    return power_two(n) && n>=8 && n<=MAX_CANDIDATES;
}
C71_SALT_HD constexpr bool valid(Geometry g) {
    if (!power_two(g.rows) || g.rows>(uint64_t{1}<<23) || g.origin>CAP ||
        !power_two(g.cosets) || g.cosets>4096 || !power_two(g.cut) ||
        g.cut>g.rows*g.cosets) return false;
    // Preserve every original R20 geometry. The only larger geometry is
    // the S1 construction: cut4096, at least two cosets, height<=2^32.
    // Its owner must additionally enforce an explicit two-coset group.
    return g.rows<=(uint64_t{1}<<20) ||
        (g.cosets>=2 && g.cut==4096 && g.rows*g.cosets<=(uint64_t{1}<<32));
}
C71_SALT_HD constexpr bool valid_replay_span(uint64_t rows, uint64_t first, uint64_t count) {
    if (!power_two(rows) || rows>(uint64_t{1}<<23) || !count || count>65536) return false;
    const uint64_t height=(rows<=(uint64_t{1}<<20) ? 32 : 2)*rows;
    return first<=height && count<=height-first;
}
C71_SALT_HD constexpr bool valid(Chunk c, Geometry g) {
    return valid(g) && valid_capacity(c.capacity) && c.cursor<=CAP && c.cursor>=g.origin &&
        !((c.cursor-g.origin)&7) && c.accepted<=c.target && c.target<=4*g.rows*g.cosets &&
        c.accepted<=(c.cursor-g.origin)/8 && c.candidates<=c.capacity &&
        (c.candidates ? (c.accepted<c.target && c.candidates<=(CAP-c.cursor)/8)
                      : (c.accepted==c.target || CAP-c.cursor<8));
}

// Unlike root_hash, XOF output includes all sixteen little-endian u32 words.
C71_SALT_HD inline Descriptor descriptor(const uint8_t seed[32]) {
    constexpr char domain[] = "volta-zk/c71/b12/private-coins/v1";
    static_assert(sizeof(domain)==34);
    c71_blake3::Output first{};
    for(unsigned i=0;i<8;++i) first.cv[i]=c71_blake3::iv(i);
    for(unsigned i=0;i<64;++i) {
        const uint8_t byte=i<sizeof(domain) ? uint8_t(domain[i]) : seed[i-sizeof(domain)];
        first.block[i/4] |= uint32_t(byte) << (8*(i%4));
    }
    first.block_len=64; first.flags=c71_blake3::CHUNK_START;
    const auto cv=c71_blake3::chaining_value(first);
    Descriptor d{};
    for(unsigned i=0;i<8;++i) d.output.cv[i]=cv.w[i];
    d.output.block[0]=uint32_t(seed[30]) | (uint32_t(seed[31])<<8);
    d.output.block_len=2; d.output.flags=c71_blake3::CHUNK_END;
    return d;
}
C71_SALT_HD inline void xof_block(const Descriptor& d, uint64_t counter, uint32_t out[16]) {
    c71_blake3::compress(d.output.cv,d.output.block,counter,d.output.block_len,
        d.output.flags|c71_blake3::ROOT,out);
}
C71_SALT_HD inline uint64_t word(const uint32_t first[16], const uint32_t next[16], unsigned byte) {
    if(!(byte&3) && byte<=56)
        return uint64_t(first[byte/4]) | (uint64_t(first[byte/4+1])<<32);
    uint64_t value=0;
    for(unsigned i=0;i<8;++i) {
        const unsigned at=byte+i;
        const uint32_t x=at<64 ? first[at/4] : next[(at-64)/4];
        value |= uint64_t(uint8_t(x>>(8*(at%4)))) << (8*i);
    }
    return value;
}

// Masks refer to absolute XOF blocks. The initial partial block excludes
// earlier candidates, without treating them as rejected samples.
C71_SALT_HD constexpr uint32_t chunk_blocks(Chunk c) {
    return c.candidates ? uint32_t(((c.cursor&63)+8*uint64_t(c.candidates-1))/64+1) : 0;
}
C71_SALT_HD constexpr uint32_t block_sum_slots(Chunk c) {
    return (chunk_blocks(c)+SCAN_THREADS-1)/SCAN_THREADS;
}
C71_SALT_HD constexpr uint32_t group_sum_slots(Chunk c) {
    return (block_sum_slots(c)+SCAN_THREADS-1)/SCAN_THREADS;
}
C71_SALT_HD constexpr uint64_t candidate_offset(Chunk c, uint32_t block, unsigned lane) {
    return ((c.cursor/64)+block)*64+(c.cursor&7)+8*lane;
}
C71_SALT_HD constexpr bool included(Chunk c, uint64_t offset) {
    return offset>=c.cursor && offset-c.cursor<8*uint64_t(c.candidates);
}
C71_SALT_HD constexpr bool needs_next(Chunk c, uint32_t block) {
    return (c.cursor&7) && included(c,candidate_offset(c,block,7));
}
C71_SALT_HD inline uint8_t candidate_mask(Chunk c, uint32_t block,
    const uint32_t words[16], const uint32_t next[16]) {
    uint8_t mask=0;
    for(unsigned i=0;i<8;++i)
        if(included(c,candidate_offset(c,block,i)) && word(words,next,unsigned(c.cursor&7)+8*i)<MODULUS)
            mask |= uint8_t(1u<<i);
    return mask;
}
C71_SALT_HD inline uint8_t block_mask(const Descriptor& d, Chunk c, uint32_t block) {
    uint32_t words[16], next[16];
    xof_block(d,c.cursor/64+block,words);
    if(needs_next(c,block)) xof_block(d,c.cursor/64+block+1,next);
    return candidate_mask(c,block,words,next);
}
C71_SALT_HD inline unsigned popcount(uint8_t mask) {
    unsigned count=0;
    for(unsigned i=0;i<8;++i) count+=(mask>>i)&1;
    return count;
}
// rank is one-based. A boundary is AFTER the selected accepted candidate,
// before any rejection encountered while looking for the next accepted one.
// CAP+1 is an invalid rank, distinct from the valid terminal cursor CAP.
C71_SALT_HD inline uint64_t after_accepted(Chunk c, uint32_t block, uint8_t mask, unsigned rank) {
    if(!rank) return CAP+1;
    for(unsigned i=0;i<8;++i) if((mask>>i)&1) {
        if(--rank==0) return candidate_offset(c,block,i)+8;
    }
    return CAP+1;
}
C71_SALT_HD constexpr uint64_t physical_blocks(Chunk c) {
    if(!c.candidates) return 0;
    const unsigned first_cross=7-unsigned((c.cursor&63)/8);
    const uint64_t cross=(c.cursor&7) && c.candidates>first_cross
        ? 1+(uint64_t(c.candidates)-1-first_cross)/8 : 0;
    return chunk_blocks(c)+cross;
}

struct BlockCache { uint64_t counter=0; uint32_t words[16]{}; bool initialized=false; };
C71_SALT_HD inline bool candidate(const Descriptor& d, uint64_t offset,
    BlockCache& cache, uint64_t& value) {
    if(offset>CAP-8) return false;
    value=0;
    for(unsigned i=0;i<8;++i) {
        const uint64_t at=offset+i, counter=at/64;
        if(!cache.initialized || cache.counter!=counter) {
            xof_block(d,counter,cache.words); cache.counter=counter; cache.initialized=true;
        }
        value |= uint64_t(uint8_t(cache.words[(at%64)/4]>>(8*(at%4)))) << (8*i);
    }
    return true;
}
C71_SALT_HD inline bool sample4(const Descriptor& d, uint64_t& cursor,
    BlockCache& cache, uint64_t out[4]) {
    unsigned accepted=0;
    while(accepted<4) {
        uint64_t x;
        if(!candidate(d,cursor,cache,x)) return false;
        cursor+=8;
        if(x<MODULUS) out[accepted++]=x;
    }
    return true;
}

// One thread owns each row's cursor, even if a reduced band spans multiple
// cosets of that row. Output remains column-major in the original band.
C71_SALT_HD inline bool replay_row(const Descriptor& d, uint64_t& cursor, uint64_t rows,
    uint64_t first, uint64_t count, uint64_t row, uint64_t* salts, uint64_t& consumed) {
    const uint64_t start=cursor, first_row=first%rows;
    const uint64_t relative=(row+rows-first_row)%rows;
    BlockCache cache;
    for(uint64_t local=relative;local<count;local+=rows) {
        uint64_t out[4];
        if(!sample4(d,cursor,cache,out)) { consumed=cursor-start; return false; }
        for(unsigned i=0;i<4;++i) salts[uint64_t(i)*count+local]=out[i];
    }
    consumed=cursor-start; return true;
}
}
#undef C71_SALT_HD

#ifdef __CUDACC__
// Caller sizes scratch with chunk_blocks/block_sum_slots/group_sum_slots.
// Each call overwrites Progress: logical_bytes is cumulative from origin,
// physical_blocks counts this chunk's computed output blocks, including
// speculative output after the final sample. Neither launch fences.
extern "C" cudaError_t c71_pcs_salts_prescan_launch(cudaStream_t,
    const c71_salts::Descriptor*,c71_salts::Chunk,c71_salts::Geometry,
    uint8_t* masks,uint32_t* prefix,uint32_t* block_sums,uint32_t* group_sums,
    uint64_t* starts,uint64_t* offsets,c71_salts::Progress*,uint32_t* failed,unsigned* attempted);
extern "C" cudaError_t c71_pcs_salts_replay_launch(cudaStream_t,
    const c71_salts::Descriptor*,uint64_t* current,uint64_t rows,uint64_t first,uint64_t count,
    uint64_t* salts,uint64_t* consumed,uint32_t* failed);
#endif
