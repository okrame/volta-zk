// Unkeyed BLAKE3 compression reused verbatim from p7_blake3_merkle.cu.
// Callers provide their own domains/encoding; P7's tree format is not C7.1.
#pragma once
#include <cstdint>
#ifdef __CUDACC__
#define C71_B3_HD __host__ __device__
#else
#define C71_B3_HD
#endif
namespace c71_blake3 {
constexpr uint32_t CHUNK_START = 1;
constexpr uint32_t CHUNK_END = 2;
constexpr uint32_t PARENT = 4;
constexpr uint32_t ROOT = 8;

struct Hash32 {
    uint32_t w[8];
};

struct Output {
    uint32_t cv[8];
    uint32_t block[16];
    uint64_t counter;
    uint32_t block_len;
    uint32_t flags;
};

C71_B3_HD constexpr uint32_t iv(int i) {
    constexpr uint32_t words[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };
    return words[i];
}

C71_B3_HD constexpr uint8_t perm(int i) {
    constexpr uint8_t indices[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    };
    return indices[i];
}

C71_B3_HD inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

C71_B3_HD inline void g(
    uint32_t s[16], int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr(s[d] ^ s[a], 16);
    s[c] += s[d];
    s[b] = rotr(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr(s[d] ^ s[a], 8);
    s[c] += s[d];
    s[b] = rotr(s[b] ^ s[c], 7);
}

C71_B3_HD inline void compress(
    const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
    uint32_t block_len, uint32_t flags, uint32_t out[16]) {
    uint32_t s[16], m[16], p[16];
    for (int i = 0; i < 8; ++i) s[i] = cv[i];
    for (int i = 0; i < 4; ++i) s[8 + i] = iv(i);
    s[12] = static_cast<uint32_t>(counter);
    s[13] = static_cast<uint32_t>(counter >> 32);
    s[14] = block_len;
    s[15] = flags;
    for (int i = 0; i < 16; ++i) m[i] = block[i];
    for (int round = 0; round < 7; ++round) {
        g(s, 0, 4, 8, 12, m[0], m[1]);
        g(s, 1, 5, 9, 13, m[2], m[3]);
        g(s, 2, 6, 10, 14, m[4], m[5]);
        g(s, 3, 7, 11, 15, m[6], m[7]);
        g(s, 0, 5, 10, 15, m[8], m[9]);
        g(s, 1, 6, 11, 12, m[10], m[11]);
        g(s, 2, 7, 8, 13, m[12], m[13]);
        g(s, 3, 4, 9, 14, m[14], m[15]);
        for (int i = 0; i < 16; ++i) p[i] = m[perm(i)];
        for (int i = 0; i < 16; ++i) m[i] = p[i];
    }
    for (int i = 0; i < 8; ++i) {
        out[i] = s[i] ^ s[i + 8];
        out[i + 8] = s[i + 8] ^ cv[i];
    }
}

C71_B3_HD inline Hash32 chaining_value(const Output& o) {
    uint32_t words[16];
    compress(o.cv, o.block, o.counter, o.block_len, o.flags, words);
    Hash32 h{};
    for (int i = 0; i < 8; ++i) h.w[i] = words[i];
    return h;
}

C71_B3_HD inline Hash32 root_hash(const Output& o) {
    uint32_t words[16];
    compress(o.cv, o.block, 0, o.block_len, o.flags | ROOT, words);
    Hash32 h{};
    for (int i = 0; i < 8; ++i) h.w[i] = words[i];
    return h;
}

C71_B3_HD inline Output parent_output(Hash32 left, Hash32 right) {
    Output o{};
    for (int i = 0; i < 8; ++i) {
        o.cv[i] = iv(i);
        o.block[i] = left.w[i];
        o.block[8 + i] = right.w[i];
    }
    o.block_len = 64;
    o.flags = PARENT;
    return o;
}

}
#undef C71_B3_HD
