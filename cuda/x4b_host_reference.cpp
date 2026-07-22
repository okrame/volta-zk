#include "volta_x4b.cuh"

#include <array>
#include <cstdio>
#include <vector>

using volta_x4b::Fp2;
using volta_x4b::Hash32;

namespace {

Hash32 digest_pattern(size_t slot) {
    uint8_t bytes[32];
    for (size_t i = 0; i < 32; ++i) bytes[i] = static_cast<uint8_t>(slot * 17 + i + 1);
    Hash32 digest{};
    for (size_t i = 0; i < 8; ++i) digest.words[i] = volta_x4b::load_u32_le(bytes + 4 * i);
    return digest;
}

uint64_t reverse_bits(uint64_t value) {
    value = ((value & 0x5555555555555555ULL) << 1) |
            ((value >> 1) & 0x5555555555555555ULL);
    value = ((value & 0x3333333333333333ULL) << 2) |
            ((value >> 2) & 0x3333333333333333ULL);
    value = ((value & 0x0f0f0f0f0f0f0f0fULL) << 4) |
            ((value >> 4) & 0x0f0f0f0f0f0f0f0fULL);
    value = ((value & 0x00ff00ff00ff00ffULL) << 8) |
            ((value >> 8) & 0x00ff00ff00ff00ffULL);
    value = ((value & 0x0000ffff0000ffffULL) << 16) |
            ((value >> 16) & 0x0000ffff0000ffffULL);
    return (value << 32) | (value >> 32);
}

void print_hash(const char* label, Hash32 digest) {
    uint8_t bytes[32];
    volta_x4b::write_digest(bytes, digest);
    std::printf("%s=", label);
    for (uint8_t byte : bytes) std::printf("%02x", byte);
    std::printf("\n");
}

Hash32 tree_root(
    size_t structural_slots, size_t present_slots, uint32_t cohort_id,
    uint8_t oracle_kind, uint8_t fold_round) {
    const size_t outer_len = 32;
    const Hash32 leaf_key = volta_x4b::blake3_context_key("volta-zk/x4/pcs-leaf/v4", 23);
    const Hash32 node_key = volta_x4b::blake3_context_key("volta-zk/x4/pcs-node/v4", 23);
    std::vector<Hash32> outer_leaves;
    outer_leaves.reserve(outer_len);
    for (size_t coordinate = 0; coordinate < outer_len; ++coordinate) {
        std::vector<Hash32> level;
        level.reserve(structural_slots);
        for (size_t slot = 0; slot < structural_slots; ++slot) {
            const bool present = slot < present_slots;
            const Fp2 symbol{
                static_cast<uint64_t>(slot * 257 + coordinate * 17 + 3),
                static_cast<uint64_t>(slot * 19 + coordinate * coordinate + 5),
            };
            level.push_back(volta_x4b::hash_inner_leaf(
                leaf_key, cohort_id, oracle_kind, fold_round, coordinate,
                present ? digest_pattern(slot) : Hash32{}, static_cast<uint16_t>(slot),
                present, symbol));
        }
        uint8_t inner_level = 1;
        while (level.size() > 1) {
            std::vector<Hash32> next;
            next.reserve(level.size() / 2);
            for (size_t node = 0; node < level.size() / 2; ++node) {
                next.push_back(volta_x4b::hash_node(
                    node_key, cohort_id, 0, oracle_kind, fold_round, coordinate,
                    inner_level, node, level[2 * node], level[2 * node + 1]));
            }
            level = std::move(next);
            ++inner_level;
        }
        outer_leaves.push_back(volta_x4b::hash_outer_leaf(
            leaf_key, cohort_id, oracle_kind, fold_round, coordinate, level[0]));
    }
    uint8_t outer_level = 1;
    while (outer_leaves.size() > 1) {
        std::vector<Hash32> next;
        next.reserve(outer_leaves.size() / 2);
        for (size_t node = 0; node < outer_leaves.size() / 2; ++node) {
            next.push_back(volta_x4b::hash_node(
                node_key, cohort_id, 1, oracle_kind, fold_round, UINT64_MAX,
                outer_level, node, outer_leaves[2 * node], outer_leaves[2 * node + 1]));
        }
        outer_leaves = std::move(next);
        ++outer_level;
    }
    return outer_leaves[0];
}

}  // namespace

int main() {
    uint8_t payload[104];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(i * 29 + 7);
    struct Context {
        const char* label;
        const char* value;
        size_t length;
    };
    const Context contexts[] = {
        {"derive_pcs_leaf", "volta-zk/x4/pcs-leaf/v4", 23},
        {"derive_pcs_node", "volta-zk/x4/pcs-node/v4", 23},
        {"derive_manifest_leaf", "volta-zk/x4/manifest-leaf/v4", 28},
        {"derive_manifest_node", "volta-zk/x4/manifest-node/v4", 28},
    };
    for (const Context& context : contexts) {
        print_hash(context.label, volta_x4b::blake3_derive_hash(
            volta_x4b::blake3_context_key(context.value, context.length), payload, sizeof(payload)));
    }

    const Fp2 root = volta_x4b::root_of_unity(33);
    std::printf("root_2_33=%016llx:%016llx\n",
                static_cast<unsigned long long>(root.c0),
                static_cast<unsigned long long>(root.c1));

    std::vector<Fp2> values(32, Fp2{0, 0});
    for (size_t i = 0; i < 11; ++i) {
        values[i] = Fp2{static_cast<uint64_t>(i * 17 + 3),
                        static_cast<uint64_t>(i * i + 5)};
    }
    const Fp2 ntt_root = volta_x4b::root_of_unity(5);
    for (size_t index = 0; index < values.size(); ++index) {
        const size_t reversed = reverse_bits(index) >> (64 - 5);
        if (index < reversed) std::swap(values[index], values[reversed]);
    }
    for (size_t len = 2; len <= values.size(); len *= 2) {
        const Fp2 step = volta_x4b::fp2_pow(ntt_root, values.size() / len);
        for (size_t start = 0; start < values.size(); start += len) {
            Fp2 twiddle{1, 0};
            for (size_t offset = 0; offset < len / 2; ++offset) {
                const Fp2 left = values[start + offset];
                const Fp2 right = volta_x4b::fp2_mul(values[start + offset + len / 2], twiddle);
                values[start + offset] = volta_x4b::fp2_add(left, right);
                values[start + offset + len / 2] = volta_x4b::fp2_sub(left, right);
                twiddle = volta_x4b::fp2_mul(twiddle, step);
            }
        }
    }
    for (size_t i = 0; i < values.size(); ++i) {
        std::printf("ntt_%02zu=%016llx:%016llx\n", i,
                    static_cast<unsigned long long>(values[i].c0),
                    static_cast<unsigned long long>(values[i].c1));
    }

    print_hash("root_m1_p1", tree_root(1, 1, 7, 0, 0));
    print_hash("root_m2_p1", tree_root(2, 1, 8, 1, 0));
    print_hash("root_m16_p13", tree_root(16, 13, 9, 0, 0));
    print_hash("root_m64_p49", tree_root(64, 49, 10, 1, 0));
    print_hash("root_fold", tree_root(1, 1, 11, 2, 3));
    return 0;
}
