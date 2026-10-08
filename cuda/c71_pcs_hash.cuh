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
