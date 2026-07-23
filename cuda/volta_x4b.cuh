#pragma once

#include <cstddef>
#include <cstdint>

#if defined(__CUDACC__)
#define VOLTA_X4B_HD __host__ __device__
#define VOLTA_X4B_DEVICE __device__
#define VOLTA_X4B_GLOBAL __global__
#else
#define VOLTA_X4B_HD
#define VOLTA_X4B_DEVICE
#define VOLTA_X4B_GLOBAL
#endif

namespace volta_x4b {

constexpr uint64_t P = 0xFFFF'FFFF'0000'0001ULL;
constexpr uint64_t EPSILON = 0x0000'0000'FFFF'FFFFULL;
constexpr uint64_t FP2_NON_RESIDUE = 7;
constexpr uint64_t INVERSE_TWO = 0x7FFF'FFFF'8000'0001ULL;
constexpr uint64_t PRIMITIVE_ROOT_2_33_C0 = 0;
constexpr uint64_t PRIMITIVE_ROOT_2_33_C1 = 0x076d'e30b'51a3'f645ULL;

struct alignas(16) Fp2 {
    uint64_t c0;
    uint64_t c1;
};

struct Hash32 {
    uint32_t words[8];
};

/// Canonical X4c byte-gather request. Offsets are absolute byte offsets in
/// the one response arena. Requests are ordered by destination offset.
struct X4cGatherRequest {
    uint64_t source_offset_bytes;
    uint64_t destination_offset_bytes;
    uint64_t byte_len;
};

static_assert(sizeof(X4cGatherRequest) == 24, "X4c gather-request ABI mismatch");

enum : uint8_t {
    X4C_GATHER_CODEWORD_SYMBOL = 0,
    X4C_GATHER_CACHED_OUTER_DIGEST = 1,
    X4C_GATHER_REBUILT_OUTER_DIGEST = 2,
};

/// One exact operation from the frozen canonical gather plan. The batch is
/// ordered by round, then symbols, then the deduplicated frontier's
/// `(level,index)` order. It never expands the frontier into full paths.
struct X4cCanonicalGatherOperation {
    uint64_t codeword_offset_bytes;
    uint64_t cache_offset_bytes;
    uint64_t source_offset_bytes;
    uint64_t outer_len;
    uint64_t index;
    uint64_t destination_offset_bytes;
    Hash32 descriptor;
    uint32_t cohort_id;
    uint8_t source_kind;
    uint8_t level;
    uint8_t oracle_kind;
    uint8_t fold_round;
};

static_assert(
    sizeof(X4cCanonicalGatherOperation) == 88,
    "X4c canonical-gather operation ABI mismatch");

VOLTA_X4B_HD inline uint64_t fp_add(uint64_t a, uint64_t b) {
    const uint64_t r0 = a + b;
    const bool carry = r0 < a;
    uint64_t r = carry ? r0 + EPSILON : r0;
    if (r >= P) r -= P;
    return r;
}

VOLTA_X4B_HD inline uint64_t fp_sub(uint64_t a, uint64_t b) {
    const uint64_t r = a - b;
    return a < b ? r - EPSILON : r;
}

VOLTA_X4B_HD inline uint64_t fp_neg(uint64_t value) {
    return value == 0 ? 0 : P - value;
}

VOLTA_X4B_HD inline uint64_t fp_mul(uint64_t a, uint64_t b) {
#if defined(__CUDA_ARCH__)
    const uint64_t lo = a * b;
    const uint64_t hi = __umul64hi(a, b);
#else
    const unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
    const uint64_t lo = static_cast<uint64_t>(product);
    const uint64_t hi = static_cast<uint64_t>(product >> 64);
#endif
    const uint64_t hi_hi = hi >> 32;
    const uint64_t hi_lo = hi & EPSILON;
    const bool borrow = lo < hi_hi;
    uint64_t t = lo - hi_hi;
    if (borrow) t -= EPSILON;
    const uint64_t t1 = hi_lo * EPSILON;
    const uint64_t r0 = t + t1;
    const bool carry = r0 < t;
    uint64_t r = carry ? r0 + EPSILON : r0;
    if (r >= P) r -= P;
    return r;
}

VOLTA_X4B_HD inline uint64_t fp_pow(uint64_t base, uint64_t exponent) {
    uint64_t result = 1;
    while (exponent) {
        if (exponent & 1) result = fp_mul(result, base);
        base = fp_mul(base, base);
        exponent >>= 1;
    }
    return result;
}

VOLTA_X4B_HD inline uint64_t fp_inv(uint64_t value) {
    return fp_pow(value, P - 2);
}

VOLTA_X4B_HD inline Fp2 fp2_add(Fp2 a, Fp2 b) {
    return Fp2{fp_add(a.c0, b.c0), fp_add(a.c1, b.c1)};
}

VOLTA_X4B_HD inline Fp2 fp2_sub(Fp2 a, Fp2 b) {
    return Fp2{fp_sub(a.c0, b.c0), fp_sub(a.c1, b.c1)};
}

VOLTA_X4B_HD inline Fp2 fp2_mul(Fp2 a, Fp2 b) {
    return Fp2{
        fp_add(fp_mul(a.c0, b.c0), fp_mul(FP2_NON_RESIDUE, fp_mul(a.c1, b.c1))),
        fp_add(fp_mul(a.c0, b.c1), fp_mul(a.c1, b.c0)),
    };
}

VOLTA_X4B_HD inline Fp2 fp2_pow(Fp2 base, uint64_t exponent) {
    Fp2 result{1, 0};
    while (exponent) {
        if (exponent & 1) result = fp2_mul(result, base);
        base = fp2_mul(base, base);
        exponent >>= 1;
    }
    return result;
}

VOLTA_X4B_HD inline Fp2 fp2_inv(Fp2 value) {
    const uint64_t denominator =
        fp_sub(fp_mul(value.c0, value.c0),
               fp_mul(FP2_NON_RESIDUE, fp_mul(value.c1, value.c1)));
    const uint64_t inverse_denominator = fp_inv(denominator);
    return Fp2{
        fp_mul(value.c0, inverse_denominator),
        fp_mul(fp_neg(value.c1), inverse_denominator),
    };
}

VOLTA_X4B_HD inline Fp2 root_of_unity(uint32_t bits) {
    Fp2 root{PRIMITIVE_ROOT_2_33_C0, PRIMITIVE_ROOT_2_33_C1};
    for (uint32_t i = bits; i < 33; ++i) root = fp2_mul(root, root);
    return bits == 0 ? Fp2{1, 0} : root;
}

VOLTA_X4B_HD inline uint32_t power_of_two_log2(size_t value) {
    uint32_t bits = 0;
    while (value > 1) {
        value >>= 1;
        ++bits;
    }
    return bits;
}

/// Frozen X4c direct-fold equation. The input order is `omega^j`, so
/// `positive[j]` and `negative[j]` are the evaluations at `+x` and `-x`.
VOLTA_X4B_HD inline Fp2 direct_fold_symbol(
    Fp2 positive, Fp2 negative, Fp2 challenge, Fp2 inverse_x) {
    const Fp2 inverse_two{INVERSE_TWO, 0};
    const Fp2 even = fp2_mul(fp2_add(positive, negative), inverse_two);
    const Fp2 odd = fp2_mul(
        fp2_mul(fp2_sub(positive, negative), inverse_two), inverse_x);
    return fp2_add(even, fp2_mul(challenge, odd));
}

inline bool direct_fold_reference(
    const Fp2* input, size_t input_len, Fp2 challenge, Fp2* output) {
    if (!input || !output || input_len < 2 || (input_len & (input_len - 1)) ||
        input_len > (size_t{1} << 33))
        return false;
    const size_t half = input_len / 2;
    const Fp2 omega_inverse =
        fp2_inv(root_of_unity(power_of_two_log2(input_len)));
    Fp2 inverse_x{1, 0};
    for (size_t index = 0; index < half; ++index) {
        output[index] = direct_fold_symbol(
            input[index], input[index + half], challenge, inverse_x);
        inverse_x = fp2_mul(inverse_x, omega_inverse);
    }
    return true;
}

inline bool activation_add_reference(
    Fp2* destination, const Fp2* source, size_t count, Fp2 activation) {
    if (!destination || !source || !count) return false;
    for (size_t index = 0; index < count; ++index) {
        destination[index] =
            fp2_add(destination[index], fp2_mul(activation, source[index]));
    }
    return true;
}

constexpr size_t X4C_DIRECT_FOLD_RUN = 256;
constexpr size_t X4C_DIRECT_FOLD_BLOCK = 256;

constexpr uint32_t BLAKE3_CHUNK_START = 1;
constexpr uint32_t BLAKE3_CHUNK_END = 2;
constexpr uint32_t BLAKE3_ROOT = 8;
constexpr uint32_t BLAKE3_DERIVE_KEY_CONTEXT = 32;
constexpr uint32_t BLAKE3_DERIVE_KEY_MATERIAL = 64;

VOLTA_X4B_HD inline uint32_t iv(size_t index) {
    constexpr uint32_t values[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };
    return values[index];
}

VOLTA_X4B_HD inline uint8_t permutation(size_t index) {
    constexpr uint8_t values[16] = {
        2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
    };
    return values[index];
}

VOLTA_X4B_HD inline uint32_t rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

VOLTA_X4B_HD inline void blake3_g(
    uint32_t state[16], int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotate_right(state[d] ^ state[a], 16);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotate_right(state[d] ^ state[a], 8);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 7);
}

VOLTA_X4B_HD inline void blake3_compress(
    const uint32_t cv[8], const uint32_t block[16], uint64_t counter,
    uint32_t block_len, uint32_t flags, uint32_t output[16]) {
    uint32_t state[16];
    uint32_t message[16];
    uint32_t permuted[16];
    for (int i = 0; i < 8; ++i) state[i] = cv[i];
    for (int i = 0; i < 4; ++i) state[8 + i] = iv(i);
    state[12] = static_cast<uint32_t>(counter);
    state[13] = static_cast<uint32_t>(counter >> 32);
    state[14] = block_len;
    state[15] = flags;
    for (int i = 0; i < 16; ++i) message[i] = block[i];
    for (int round = 0; round < 7; ++round) {
        blake3_g(state, 0, 4, 8, 12, message[0], message[1]);
        blake3_g(state, 1, 5, 9, 13, message[2], message[3]);
        blake3_g(state, 2, 6, 10, 14, message[4], message[5]);
        blake3_g(state, 3, 7, 11, 15, message[6], message[7]);
        blake3_g(state, 0, 5, 10, 15, message[8], message[9]);
        blake3_g(state, 1, 6, 11, 12, message[10], message[11]);
        blake3_g(state, 2, 7, 8, 13, message[12], message[13]);
        blake3_g(state, 3, 4, 9, 14, message[14], message[15]);
        for (int i = 0; i < 16; ++i) permuted[i] = message[permutation(i)];
        for (int i = 0; i < 16; ++i) message[i] = permuted[i];
    }
    for (int i = 0; i < 8; ++i) {
        output[i] = state[i] ^ state[i + 8];
        output[i + 8] = state[i + 8] ^ cv[i];
    }
}

VOLTA_X4B_HD inline uint32_t load_u32_le(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
        (static_cast<uint32_t>(bytes[1]) << 8) |
        (static_cast<uint32_t>(bytes[2]) << 16) |
        (static_cast<uint32_t>(bytes[3]) << 24);
}

VOLTA_X4B_HD inline Hash32 blake3_small_hash(
    Hash32 key, uint32_t mode_flags, const uint8_t* bytes, size_t length) {
    uint32_t cv[8];
    for (int i = 0; i < 8; ++i) cv[i] = key.words[i];
    const size_t blocks = (length + 63) / 64;
    for (size_t block_index = 0; block_index < blocks; ++block_index) {
        uint32_t block[16]{};
        const size_t offset = block_index * 64;
        const size_t remaining = length - offset;
        const size_t block_len = remaining < 64 ? remaining : 64;
        for (size_t byte = 0; byte < block_len; byte += 4) {
            uint8_t word_bytes[4]{};
            const size_t take = block_len - byte < 4 ? block_len - byte : 4;
            for (size_t j = 0; j < take; ++j) word_bytes[j] = bytes[offset + byte + j];
            block[byte / 4] = load_u32_le(word_bytes);
        }
        uint32_t flags = mode_flags;
        if (block_index == 0) flags |= BLAKE3_CHUNK_START;
        if (block_index + 1 == blocks) flags |= BLAKE3_CHUNK_END;
        uint32_t output[16];
        if (block_index + 1 == blocks) {
            blake3_compress(cv, block, 0, static_cast<uint32_t>(block_len),
                            flags | BLAKE3_ROOT, output);
            Hash32 result{};
            for (int i = 0; i < 8; ++i) result.words[i] = output[i];
            return result;
        }
        blake3_compress(cv, block, 0, 64, flags, output);
        for (int i = 0; i < 8; ++i) cv[i] = output[i];
    }
    return Hash32{};
}

VOLTA_X4B_HD inline Hash32 blake3_context_key(const char* context, size_t length) {
    Hash32 iv_key{};
    for (int i = 0; i < 8; ++i) iv_key.words[i] = iv(i);
    return blake3_small_hash(iv_key, BLAKE3_DERIVE_KEY_CONTEXT,
                             reinterpret_cast<const uint8_t*>(context), length);
}

VOLTA_X4B_HD inline Hash32 blake3_derive_hash(
    Hash32 context_key, const uint8_t* bytes, size_t length) {
    return blake3_small_hash(context_key, BLAKE3_DERIVE_KEY_MATERIAL, bytes, length);
}

VOLTA_X4B_HD inline void write_u16(uint8_t* output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
}

VOLTA_X4B_HD inline void write_u32(uint8_t* output, uint32_t value) {
    for (int i = 0; i < 4; ++i) output[i] = static_cast<uint8_t>(value >> (8 * i));
}

VOLTA_X4B_HD inline void write_u64(uint8_t* output, uint64_t value) {
    for (int i = 0; i < 8; ++i) output[i] = static_cast<uint8_t>(value >> (8 * i));
}

VOLTA_X4B_HD inline void write_digest(uint8_t* output, Hash32 digest) {
    for (int i = 0; i < 8; ++i) write_u32(output + 4 * i, digest.words[i]);
}

VOLTA_X4B_HD inline void write_header(uint8_t* output, uint8_t kind, uint32_t body_len) {
    constexpr uint8_t magic[8] = {'V', 'O', 'L', 'T', 'A', 'X', '4', '4'};
    for (int i = 0; i < 8; ++i) output[i] = magic[i];
    write_u16(output + 8, 4);
    output[10] = kind;
    output[11] = 0;
    write_u32(output + 12, body_len);
}

VOLTA_X4B_HD inline Hash32 hash_inner_leaf(
    Hash32 leaf_key, uint32_t cohort_id, uint8_t oracle_kind, uint8_t fold_round,
    uint64_t outer_index, Hash32 descriptor, uint16_t slot, bool present, Fp2 symbol) {
    uint8_t frame[84]{};
    const uint32_t body_len = present ? 68 : 52;
    write_header(frame, 0x02, body_len);
    write_u32(frame + 16, cohort_id);
    frame[20] = 0;
    frame[21] = oracle_kind;
    frame[22] = fold_round;
    write_u64(frame + 23, outer_index);
    write_digest(frame + 31, descriptor);
    write_u16(frame + 63, slot);
    frame[65] = present ? 1 : 0;
    write_u16(frame + 66, present ? 1 : 0);
    if (present) {
        write_u64(frame + 68, symbol.c0);
        write_u64(frame + 76, symbol.c1);
    }
    return blake3_derive_hash(leaf_key, frame, 16 + body_len);
}

VOLTA_X4B_HD inline Hash32 hash_outer_leaf(
    Hash32 leaf_key, uint32_t cohort_id, uint8_t oracle_kind, uint8_t fold_round,
    uint64_t outer_index, Hash32 inner_root) {
    uint8_t frame[63]{};
    write_header(frame, 0x02, 47);
    write_u32(frame + 16, cohort_id);
    frame[20] = 1;
    frame[21] = oracle_kind;
    frame[22] = fold_round;
    write_u64(frame + 23, outer_index);
    write_digest(frame + 31, inner_root);
    return blake3_derive_hash(leaf_key, frame, sizeof(frame));
}

VOLTA_X4B_HD inline Hash32 hash_node(
    Hash32 node_key, uint32_t cohort_id, uint8_t tree_role, uint8_t oracle_kind,
    uint8_t fold_round, uint64_t outer_index, uint8_t level, uint64_t node_index,
    Hash32 left, Hash32 right) {
    uint8_t frame[104]{};
    write_header(frame, 0x03, 88);
    write_u32(frame + 16, cohort_id);
    frame[20] = tree_role;
    frame[21] = oracle_kind;
    frame[22] = fold_round;
    write_u64(frame + 23, outer_index);
    frame[31] = level;
    write_u64(frame + 32, node_index);
    write_digest(frame + 40, left);
    write_digest(frame + 72, right);
    return blake3_derive_hash(node_key, frame, sizeof(frame));
}

VOLTA_X4B_HD inline Hash32 one_slot_outer_leaf(
    const Fp2* codeword, const Hash32* keys, Hash32 descriptor,
    uint64_t coordinate, uint32_t cohort_id, uint8_t oracle_kind,
    uint8_t fold_round) {
    const Hash32 inner = hash_inner_leaf(
        keys[0], cohort_id, oracle_kind, fold_round, coordinate, descriptor,
        0, true, codeword[coordinate]);
    return hash_outer_leaf(
        keys[0], cohort_id, oracle_kind, fold_round, coordinate, inner);
}

/// Scalar reference for the deterministic level-major one-slot N4 cache.
/// Actual outer levels 0 and 1 are omitted; levels 2..=depth are written
/// left-to-right and the final digest is the root.
inline bool one_slot_n4_retained_reference(
    const Fp2* codeword, size_t outer_len, const Hash32* keys,
    Hash32 descriptor, uint32_t cohort_id, uint8_t oracle_kind,
    uint8_t fold_round, Hash32* retained) {
    if (!codeword || !keys || !retained || outer_len < 8 ||
        (outer_len & (outer_len - 1)) || outer_len > (size_t{1} << 33) ||
        oracle_kind != 2 || fold_round == 0)
        return false;
    const size_t level_two_count = outer_len / 4;
    for (size_t parent = 0; parent < level_two_count; ++parent) {
        const uint64_t coordinate = static_cast<uint64_t>(4 * parent);
        const Hash32 leaf0 = one_slot_outer_leaf(
            codeword, keys, descriptor, coordinate, cohort_id, oracle_kind,
            fold_round);
        const Hash32 leaf1 = one_slot_outer_leaf(
            codeword, keys, descriptor, coordinate + 1, cohort_id,
            oracle_kind, fold_round);
        const Hash32 leaf2 = one_slot_outer_leaf(
            codeword, keys, descriptor, coordinate + 2, cohort_id,
            oracle_kind, fold_round);
        const Hash32 leaf3 = one_slot_outer_leaf(
            codeword, keys, descriptor, coordinate + 3, cohort_id,
            oracle_kind, fold_round);
        const Hash32 left = hash_node(
            keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 1,
            2 * parent, leaf0, leaf1);
        const Hash32 right = hash_node(
            keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 1,
            2 * parent + 1, leaf2, leaf3);
        retained[parent] = hash_node(
            keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 2,
            parent, left, right);
    }
    size_t source_offset = 0;
    size_t source_count = level_two_count;
    size_t destination_offset = source_count;
    uint8_t level = 3;
    while (source_count > 1) {
        const size_t parent_count = source_count / 2;
        for (size_t parent = 0; parent < parent_count; ++parent) {
            retained[destination_offset + parent] = hash_node(
                keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX,
                level, parent, retained[source_offset + 2 * parent],
                retained[source_offset + 2 * parent + 1]);
        }
        source_offset = destination_offset;
        source_count = parent_count;
        destination_offset += parent_count;
        ++level;
    }
    return true;
}

VOLTA_X4B_HD inline bool rebuild_one_slot_outer_digest(
    const Fp2* codeword, uint64_t outer_len, const Hash32* keys,
    Hash32 descriptor, uint32_t cohort_id, uint8_t oracle_kind,
    uint8_t fold_round, uint8_t level, uint64_t index, Hash32* output) {
    if (!codeword || !keys || !output || level > 1 ||
        index >= (outer_len >> level))
        return false;
    if (level == 0) {
        *output = one_slot_outer_leaf(
            codeword, keys, descriptor, index, cohort_id, oracle_kind,
            fold_round);
        return true;
    }
    const uint64_t first_coordinate = 2 * index;
    const Hash32 left = one_slot_outer_leaf(
        codeword, keys, descriptor, first_coordinate, cohort_id, oracle_kind,
        fold_round);
    const Hash32 right = one_slot_outer_leaf(
        codeword, keys, descriptor, first_coordinate + 1, cohort_id,
        oracle_kind, fold_round);
    *output = hash_node(
        keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 1, index,
        left, right);
    return true;
}

VOLTA_X4B_HD inline uint64_t retained_level_digest_offset(
    uint64_t outer_len, uint8_t level) {
    return outer_len / 2 - (outer_len >> (level - 1));
}

#if defined(__CUDACC__)

VOLTA_X4B_GLOBAL void initialize_n4_keys(Hash32* keys) {
    if (blockIdx.x || threadIdx.x) return;
    keys[0] = blake3_context_key("volta-zk/x4/pcs-leaf/v4", 23);
    keys[1] = blake3_context_key("volta-zk/x4/pcs-node/v4", 23);
    keys[2] = blake3_context_key("volta-zk/x4/manifest-leaf/v4", 28);
    keys[3] = blake3_context_key("volta-zk/x4/manifest-node/v4", 28);
}

VOLTA_X4B_GLOBAL void generate_twiddles(Fp2* twiddles, size_t count, Fp2 root) {
    constexpr size_t RUN = 256;
    const size_t lane = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const size_t start = lane * RUN;
    if (start >= count) return;
    Fp2 value = fp2_pow(root, static_cast<uint64_t>(start));
    const size_t end = start + RUN < count ? start + RUN : count;
    for (size_t i = start; i < end; ++i) {
        twiddles[i] = value;
        value = fp2_mul(value, root);
    }
}

VOLTA_X4B_GLOBAL void context_probe(
    const uint8_t* payload, size_t length, const Hash32* keys, Hash32* output) {
    const size_t context = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (context < 4) output[context] = blake3_derive_hash(keys[context], payload, length);
}

VOLTA_X4B_GLOBAL void bit_reverse_fp2(
    const Fp2* input, Fp2* output, size_t n, int bits) {
    const size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < n) output[__brevll(index) >> (64 - bits)] = input[index];
}

VOLTA_X4B_GLOBAL void ntt_stage_fp2(
    Fp2* values, const Fp2* twiddles, size_t n, size_t len) {
    const size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index >= n / 2) return;
    const size_t half = len / 2;
    const size_t group = index / half;
    const size_t offset = index - group * half;
    const size_t left_index = group * len + offset;
    const size_t right_index = left_index + half;
    const Fp2 left = values[left_index];
    const Fp2 right = fp2_mul(values[right_index], twiddles[offset * (n / len)]);
    values[left_index] = fp2_add(left, right);
    values[right_index] = fp2_sub(left, right);
}

VOLTA_X4B_GLOBAL void inner_leaf_tile(
    const Fp2* symbols, const uint16_t* present_rank, const Hash32* descriptors,
    Hash32* output, const Hash32* keys, size_t coordinates, size_t structural_slots,
    uint64_t coordinate_start, uint32_t cohort_id, uint8_t oracle_kind,
    uint8_t fold_round) {
    const size_t flat = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (flat >= coordinates * structural_slots) return;
    const size_t coordinate = flat / structural_slots;
    const size_t slot = flat - coordinate * structural_slots;
    const uint16_t rank = present_rank[slot];
    const bool present = rank != UINT16_MAX;
    const Fp2 symbol = present ? symbols[static_cast<size_t>(rank) * coordinates + coordinate]
                               : Fp2{0, 0};
    output[flat] = hash_inner_leaf(
        keys[0], cohort_id, oracle_kind, fold_round, coordinate_start + coordinate,
        descriptors[slot], static_cast<uint16_t>(slot), present, symbol);
}

VOLTA_X4B_GLOBAL void inner_node_tile(
    const Hash32* input, Hash32* output, const Hash32* keys, size_t coordinates,
    size_t width, uint64_t coordinate_start, uint32_t cohort_id,
    uint8_t oracle_kind, uint8_t fold_round, uint8_t level) {
    const size_t parents = width / 2;
    const size_t flat = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (flat >= coordinates * parents) return;
    const size_t coordinate = flat / parents;
    const size_t node = flat - coordinate * parents;
    const size_t source = coordinate * width + 2 * node;
    output[flat] = hash_node(
        keys[1], cohort_id, 0, oracle_kind, fold_round, coordinate_start + coordinate,
        level, node, input[source], input[source + 1]);
}

VOLTA_X4B_GLOBAL void outer_leaf_tile(
    const Hash32* inner_roots, Hash32* output, const Hash32* keys,
    size_t coordinates, uint64_t coordinate_start, uint32_t cohort_id,
    uint8_t oracle_kind, uint8_t fold_round) {
    const size_t coordinate = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (coordinate < coordinates) {
        output[coordinate] = hash_outer_leaf(
            keys[0], cohort_id, oracle_kind, fold_round,
            coordinate_start + coordinate, inner_roots[coordinate]);
    }
}

VOLTA_X4B_GLOBAL void outer_node_tile(
    const Hash32* children, Hash32* output, const Hash32* keys, size_t parents,
    uint64_t node_start, uint32_t cohort_id, uint8_t oracle_kind,
    uint8_t fold_round, uint8_t level) {
    const size_t local = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (local < parents) {
        output[local] = hash_node(
            keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX,
            level, node_start + local, children[2 * local], children[2 * local + 1]);
    }
}

/// Coalesced direct fold. One block covers `BLOCK * RUN` consecutive output
/// coordinates. Thread zero derives the first inverse-x once, then fills the
/// lane bases by recurrence; every lane advances by `omega_inverse^BLOCK`.
/// There is no per-element exponentiation.
VOLTA_X4B_GLOBAL void direct_fold_fp2_run(
    const Fp2* positive, const Fp2* negative, Fp2* output,
    uint64_t output_start, size_t output_count, Fp2 challenge,
    Fp2 omega_inverse, Fp2 omega_inverse_block) {
    __shared__ Fp2 lane_inverse[X4C_DIRECT_FOLD_BLOCK];
    const size_t block_local_start =
        static_cast<size_t>(blockIdx.x) * blockDim.x * X4C_DIRECT_FOLD_RUN;
    if (threadIdx.x == 0) {
        Fp2 value = fp2_pow(
            omega_inverse, output_start + static_cast<uint64_t>(block_local_start));
        for (size_t lane = 0; lane < blockDim.x; ++lane) {
            lane_inverse[lane] = value;
            value = fp2_mul(value, omega_inverse);
        }
    }
    __syncthreads();

    size_t local = block_local_start + threadIdx.x;
    Fp2 inverse_x = lane_inverse[threadIdx.x];
    for (size_t run = 0; run < X4C_DIRECT_FOLD_RUN; ++run) {
        if (local < output_count) {
            output[local] = direct_fold_symbol(
                positive[local], negative[local], challenge, inverse_x);
        }
        local += blockDim.x;
        inverse_x = fp2_mul(inverse_x, omega_inverse_block);
    }
}

VOLTA_X4B_GLOBAL void activation_add_fp2(
    Fp2* destination, const Fp2* source, size_t count, Fp2 activation) {
    const size_t index =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < count) {
        destination[index] =
            fp2_add(destination[index], fp2_mul(activation, source[index]));
    }
}

/// Build actual outer level 2 directly from four codeword symbols, omitting
/// both outer leaves and level 1 from retained storage.
VOLTA_X4B_GLOBAL void one_slot_outer_level_two(
    const Fp2* codeword, Hash32* output, const Hash32* keys,
    Hash32 descriptor, size_t parents, uint32_t cohort_id,
    uint8_t oracle_kind, uint8_t fold_round) {
    const size_t parent =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (parent >= parents) return;
    const uint64_t coordinate = static_cast<uint64_t>(4 * parent);
    const Hash32 leaf0 = one_slot_outer_leaf(
        codeword, keys, descriptor, coordinate, cohort_id, oracle_kind,
        fold_round);
    const Hash32 leaf1 = one_slot_outer_leaf(
        codeword, keys, descriptor, coordinate + 1, cohort_id, oracle_kind,
        fold_round);
    const Hash32 leaf2 = one_slot_outer_leaf(
        codeword, keys, descriptor, coordinate + 2, cohort_id, oracle_kind,
        fold_round);
    const Hash32 leaf3 = one_slot_outer_leaf(
        codeword, keys, descriptor, coordinate + 3, cohort_id, oracle_kind,
        fold_round);
    const Hash32 left = hash_node(
        keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 1,
        2 * parent, leaf0, leaf1);
    const Hash32 right = hash_node(
        keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 1,
        2 * parent + 1, leaf2, leaf3);
    output[parent] = hash_node(
        keys[1], cohort_id, 1, oracle_kind, fold_round, UINT64_MAX, 2,
        parent, left, right);
}

VOLTA_X4B_GLOBAL void gather_fp2_samples(
    const Fp2* source, const uint64_t* indices, size_t count, Fp2* output) {
    const size_t index =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < count) output[index] = source[indices[index]];
}

VOLTA_X4B_GLOBAL void gather_bytes(
    uint8_t* arena, const X4cGatherRequest* requests, size_t request_count) {
    const size_t request_index = blockIdx.x;
    if (request_index >= request_count) return;
    const X4cGatherRequest request = requests[request_index];
    for (uint64_t byte = threadIdx.x; byte < request.byte_len; byte += blockDim.x) {
        arena[request.destination_offset_bytes + byte] =
            arena[request.source_offset_bytes + byte];
    }
}

/// Execute the exact canonical deduplicated gather plan. Missing outer levels
/// zero/one are rebuilt from the resident codeword; retained levels are copied
/// from the one-level-omitted cache.
VOLTA_X4B_GLOBAL void gather_canonical_operations(
    uint8_t* arena, const X4cCanonicalGatherOperation* operations,
    size_t operation_count, const Hash32* keys) {
    const size_t operation_index =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (operation_index >= operation_count) return;
    const X4cCanonicalGatherOperation operation = operations[operation_index];
    const Fp2* codeword = reinterpret_cast<const Fp2*>(
        arena + operation.codeword_offset_bytes);
    uint8_t* destination = arena + operation.destination_offset_bytes;
    if (operation.source_kind == X4C_GATHER_CODEWORD_SYMBOL) {
        const Fp2 symbol = codeword[operation.index];
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&symbol);
        for (size_t byte = 0; byte < sizeof(Fp2); ++byte) {
            destination[byte] = bytes[byte];
        }
    } else if (operation.source_kind == X4C_GATHER_CACHED_OUTER_DIGEST) {
        const Hash32 digest = *reinterpret_cast<const Hash32*>(
            arena + operation.source_offset_bytes);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&digest);
        for (size_t byte = 0; byte < sizeof(Hash32); ++byte) {
            destination[byte] = bytes[byte];
        }
    } else {
        Hash32 rebuilt{};
        (void)rebuild_one_slot_outer_digest(
            codeword, operation.outer_len, keys, operation.descriptor,
            operation.cohort_id, operation.oracle_kind, operation.fold_round,
            operation.level, operation.index, &rebuilt);
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&rebuilt);
        for (size_t byte = 0; byte < sizeof(Hash32); ++byte) {
            destination[byte] = bytes[byte];
        }
    }
}

#endif

}  // namespace volta_x4b
