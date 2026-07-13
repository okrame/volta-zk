#pragma once

#include <cstdint>

// Bit-exact device expansion for volta_field::FpStream, whose source of truth
// is rand_chacha 0.3.1's ChaCha8Rng.  The resident PCS uses this only for
// prover-secret row-pad and zero-knowledge-mask seeds.  Those seeds are not a
// shared verifier seed.  This primitive must never derive transcript
// challenges, Fiat-Shamir challenges, correlations, or any verifier-only
// secret (in particular Delta).

#if defined(__CUDACC__)
#define VOLTA_CHACHA8_HD __host__ __device__
#define VOLTA_CHACHA8_INLINE __forceinline__
#else
#define VOLTA_CHACHA8_HD
#define VOLTA_CHACHA8_INLINE inline
#endif

namespace volta {
namespace chacha8_fp {

constexpr std::uint64_t kGoldilocksModulus = UINT64_C(0xFFFFFFFF00000001);

struct Key {
    std::uint32_t words[8];
};

struct Fp2 {
    std::uint64_t c0;
    std::uint64_t c1;
};

VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE std::uint32_t load32_le(const std::uint8_t* src) {
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) |
           (static_cast<std::uint32_t>(src[3]) << 24);
}

VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE Key key_from_seed(const std::uint8_t seed[32]) {
    Key key{};
    for (int i = 0; i < 8; ++i) key.words[i] = load32_le(seed + 4 * i);
    return key;
}

VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE std::uint32_t rotl32(std::uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE void quarter_round(
    std::uint32_t& a,
    std::uint32_t& b,
    std::uint32_t& c,
    std::uint32_t& d) {
    a += b;
    d = rotl32(d ^ a, 16);
    c += d;
    b = rotl32(b ^ c, 12);
    a += b;
    d = rotl32(d ^ a, 8);
    c += d;
    b = rotl32(b ^ c, 7);
}

// rand_chacha uses the original ChaCha 64-bit-counter/64-bit-stream layout:
// constants | 256-bit seed | counter_lo, counter_hi, stream_lo, stream_hi.
VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE void block(
    const Key& key,
    std::uint64_t stream,
    std::uint64_t block_counter,
    std::uint32_t output[16]) {
    std::uint32_t initial[16] = {
        UINT32_C(0x61707865),
        UINT32_C(0x3320646E),
        UINT32_C(0x79622D32),
        UINT32_C(0x6B206574),
        key.words[0],
        key.words[1],
        key.words[2],
        key.words[3],
        key.words[4],
        key.words[5],
        key.words[6],
        key.words[7],
        static_cast<std::uint32_t>(block_counter),
        static_cast<std::uint32_t>(block_counter >> 32),
        static_cast<std::uint32_t>(stream),
        static_cast<std::uint32_t>(stream >> 32),
    };
    for (int i = 0; i < 16; ++i) output[i] = initial[i];

    // Four column+diagonal double-rounds are ChaCha8's eight rounds.
    for (int i = 0; i < 4; ++i) {
        quarter_round(output[0], output[4], output[8], output[12]);
        quarter_round(output[1], output[5], output[9], output[13]);
        quarter_round(output[2], output[6], output[10], output[14]);
        quarter_round(output[3], output[7], output[11], output[15]);
        quarter_round(output[0], output[5], output[10], output[15]);
        quarter_round(output[1], output[6], output[11], output[12]);
        quarter_round(output[2], output[7], output[8], output[13]);
        quarter_round(output[3], output[4], output[9], output[14]);
    }
    for (int i = 0; i < 16; ++i) output[i] += initial[i];
}

class Stream {
  public:
    VOLTA_CHACHA8_HD explicit Stream(const Key& key, std::uint64_t stream)
        : key_(key), stream_(stream), block_counter_(0), u64_index_(8), words_{} {}

    // Matches RngCore::next_u64 for BlockRng<u32>: adjacent u32 words in
    // little-endian order, low word first.
    VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE std::uint64_t next_u64() {
        if (u64_index_ == 8) refill();
        const std::uint32_t lo = words_[2 * u64_index_];
        const std::uint32_t hi = words_[2 * u64_index_ + 1];
        ++u64_index_;
        return static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32);
    }

    // Matches volta_field::FpStream::next_fp exactly. Values at or above P
    // are discarded rather than reduced, preserving uniform sampling.
    VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE std::uint64_t next_fp() {
        for (;;) {
            const std::uint64_t value = next_u64();
            if (value < kGoldilocksModulus) return value;
        }
    }

    // volta_field::FpStream::next_fp2 consumes two consecutive accepted Fp
    // values, first c0 and then c1.
    VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE Fp2 next_fp2() {
        return Fp2{next_fp(), next_fp()};
    }

  private:
    VOLTA_CHACHA8_HD VOLTA_CHACHA8_INLINE void refill() {
        block(key_, stream_, block_counter_, words_);
        ++block_counter_;
        u64_index_ = 0;
    }

    Key key_;
    std::uint64_t stream_;
    std::uint64_t block_counter_;
    std::uint32_t u64_index_;
    std::uint32_t words_[16];
};

}  // namespace chacha8_fp
}  // namespace volta

#undef VOLTA_CHACHA8_HD
#undef VOLTA_CHACHA8_INLINE
