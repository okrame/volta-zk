// Exact C7.1 B12 hash encoding. No Fp3 conversion: inputs are canonical
// base limbs in native PCS order (PCS v^3-v-1, MAC u^3-2 are distinct).
#pragma once
#include "c71_blake3.cuh"
#ifdef __CUDACC__
#define C71_PCS_HD __host__ __device__
#else
#define C71_PCS_HD
#endif
namespace c71_pcs {
using c71_blake3::Hash32;
using c71_blake3::Output;
constexpr uint64_t MODULUS = 0xffffffff00000001ULL;
static_assert(sizeof(Hash32) == 32);

C71_PCS_HD inline void words(uint32_t* out, uint64_t value) {
    out[0] = uint32_t(value); out[1] = uint32_t(value >> 32);
}
C71_PCS_HD inline void domain(uint32_t* out, bool leaf) {
    const char* text = leaf ? "volta-zk/c71/b12/merkle/leaf/v1" : "volta-zk/c71/b12/merkle/node/v1";
    for (unsigned i=0; i<8; ++i) {
        out[i]=0;
        for (unsigned j=0; j<4; ++j) out[i] |= uint32_t(uint8_t(text[4*i+j])) << (8*j);
    }
}

// Canonical W has 128 columns. The first 32-byte domain + four columns
// make a full block. Pending four columns stay in the eight-column value
// ring; only this CV is retained per leaf. No generic BLAKE3 Hasher array.
C71_PCS_HD inline Hash32 leaf_start(const uint64_t* first, uint64_t stride, uint64_t row) {
    Output o{};
    for (unsigned j=0; j<8; ++j) o.cv[j]=c71_blake3::iv(j);
    domain(o.block,true);
    for (unsigned j=0; j<4; ++j) words(o.block+8+2*j,first[j*stride+row]);
    o.block_len=64; o.flags=c71_blake3::CHUNK_START;
    return c71_blake3::chaining_value(o);
}
C71_PCS_HD inline Hash32 leaf_step(Hash32 cv, const uint64_t* pending,
    const uint64_t* next, uint64_t stride, uint64_t row, unsigned first_column) {
    Output o{};
    for (unsigned j=0; j<8; ++j) o.cv[j]=cv.w[j];
    for (unsigned j=0; j<4; ++j) {
        words(o.block+2*j,pending[j*stride+row]);
        words(o.block+8+2*j,next[j*stride+row]);
    }
    o.block_len=64;
    // domain + columns 0..123 are exactly chunk zero (1024 bytes).
    o.flags=first_column==116 ? c71_blake3::CHUNK_END : 0;
    return c71_blake3::chaining_value(o);
}
C71_PCS_HD inline Hash32 leaf_finish(Hash32 first_chunk, const uint64_t* tail,
    const uint64_t* salts, uint64_t stride, uint64_t row, uint64_t salt_stride, uint64_t salt_row) {
    Output o{};
    for (unsigned j=0; j<8; ++j) o.cv[j]=c71_blake3::iv(j);
    for (unsigned j=0; j<4; ++j) {
        words(o.block+2*j,tail[j*stride+row]);
        words(o.block+8+2*j,salts[j*salt_stride+salt_row]);
    }
    o.counter=1; o.block_len=64;
    o.flags=c71_blake3::CHUNK_START | c71_blake3::CHUNK_END;
    return c71_blake3::root_hash(c71_blake3::parent_output(first_chunk,c71_blake3::chaining_value(o)));
}
// S1 has four PCS extension columns, each encoded limb 0,1,2 in the
// v^3=v+1 basis. Its leaf is domain32 + values96 + salt32, all in chunk
// zero. The final block has length 32: it must not be padded into the
// message or use the original 128-column leaf's second-chunk parent.
C71_PCS_HD inline Hash32 short_leaf(const uint64_t* values, uint64_t stride,
    uint64_t row, const uint64_t* salts, uint64_t salt_stride, uint64_t salt_row) {
    const Hash32 first=leaf_start(values,stride,row);
    const Hash32 second=leaf_step(first,values+4*stride,values+8*stride,stride,row,4);
    Output o{};
    for (unsigned j=0; j<8; ++j) o.cv[j]=second.w[j];
    for (unsigned j=0; j<4; ++j) words(o.block+2*j,salts[j*salt_stride+salt_row]);
    o.block_len=32; o.flags=c71_blake3::CHUNK_END;
    return c71_blake3::root_hash(o);
}
C71_PCS_HD constexpr bool valid_short_leaf_span(uint64_t rows, uint64_t first, uint64_t count) {
    return rows && !(rows&(rows-1)) && rows<=(uint64_t{1}<<23) &&
        count && count<=65536 && first<=2*rows && count<=2*rows-first;
}
C71_PCS_HD constexpr bool valid_short_pair_span(uint64_t rows, uint64_t first, uint64_t count) {
    // Even small reduced geometries must launch one lane at a time: an
    // unsynchronized same-CTA first/second leaf would race on states[row].
    return valid_short_leaf_span(rows,first,count) && count<=rows-first%rows;
}
// Canonicality is separate from span/owner validation. Input ring column
// stride is 2R; salts are column-major in this bounded replay band.
C71_PCS_HD inline bool canonical_short_leaf(const uint64_t* values, uint64_t stride,
    uint64_t row, const uint64_t* salts, uint64_t salt_stride, uint64_t salt_row) {
    for (unsigned j=0; j<12; ++j) if (values[j*stride+row]>=MODULUS) return false;
    for (unsigned j=0; j<4; ++j) if (salts[j*salt_stride+salt_row]>=MODULUS) return false;
    return true;
}
C71_PCS_HD inline Hash32 node(Hash32 left, Hash32 right) {
    Output o{};
    for (unsigned j=0; j<8; ++j) { o.cv[j]=c71_blake3::iv(j); o.block[8+j]=left.w[j]; }
    domain(o.block,false); o.block_len=64; o.flags=c71_blake3::CHUNK_START;
    const auto cv=c71_blake3::chaining_value(o);
    o=Output{};
    for (unsigned j=0; j<8; ++j) { o.cv[j]=cv.w[j]; o.block[j]=right.w[j]; }
    o.block_len=32; o.flags=c71_blake3::CHUNK_END;
    return c71_blake3::root_hash(o);
}
C71_PCS_HD inline Hash32 short_pair_finish(Hash32 first_leaf,Hash32 second_leaf) {
    return node(first_leaf,second_leaf);
}
// One independent frontier per natural row. Groups arrive consecutively;
// a set bit has already been written by the preceding groups. The final
// group consumes every level and leaves the full-coset root in roots[row].
C71_PCS_HD inline void merge_group(Hash32* frontier, Hash32* roots, uint64_t rows,
    uint64_t row, unsigned group, unsigned levels) {
    Hash32 current=roots[row];
    unsigned level=0;
    while ((group >> level)&1) {
        current=node(frontier[level*rows+row],current); ++level;
    }
    if (level==levels) roots[row]=current;
    else frontier[level*rows+row]=current;
}
}
#undef C71_PCS_HD

#ifdef __CUDACC__
// Owner supplies sealed 24R-word S1 ring and 2R-hash output, proves full
// span disjointness and initialization, and owns sticky flag/fence/lifetime.
// No allocation, FFT, node merge, fence or publication occurs here.
extern "C" cudaError_t c71_pcs_short_leaves_launch(cudaStream_t,
    const uint64_t* ring,const uint64_t* salts,c71_pcs::Hash32* output,
    uint64_t rows,uint64_t first,uint64_t count,uint32_t* failed);
// Two logical lanes, R physical states. All lane-zero bands precede every
// lane-one band on this stream. The owner proves that pending states have
// exact logical coverage; only completion at 2R publishes the R pair roots.
extern "C" cudaError_t c71_pcs_short_pairs_launch(cudaStream_t,
    const uint64_t* ring,const uint64_t* salts,c71_pcs::Hash32* states,
    uint64_t rows,uint64_t first,uint64_t count,uint32_t* failed);
#endif
