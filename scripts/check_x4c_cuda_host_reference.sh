#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT

source_file="$scratch_dir/x4c_host_reference.cpp"
cat >"$source_file" <<'CPP'
#include "volta_x4b.cuh"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using volta_x4b::Fp2;
using volta_x4b::Hash32;

namespace {

[[noreturn]] void fail(const char* message) {
    std::fprintf(stderr, "X4C host-reference failure: %s\n", message);
    std::exit(1);
}

void require(bool condition, const char* message) {
    if (!condition) fail(message);
}

bool equal(Fp2 left, Fp2 right) {
    return left.c0 == right.c0 && left.c1 == right.c1;
}

bool equal(Hash32 left, Hash32 right) {
    return std::memcmp(&left, &right, sizeof(Hash32)) == 0;
}

Hash32 descriptor_pattern(size_t tag) {
    Hash32 result{};
    for (size_t word = 0; word < 8; ++word) {
        result.words[word] =
            static_cast<uint32_t>(0x1020'3040U + tag * 0x101U + word * 0x0102'0305U);
    }
    return result;
}

Fp2 symbol(size_t index) {
    return Fp2{
        static_cast<uint64_t>(index * 0x1'0000'01b3ULL + 17),
        static_cast<uint64_t>(index * index * 97 + index * 19 + 29),
    };
}

Fp2 scalar_fold_at(
    const std::vector<Fp2>& input, Fp2 challenge, size_t index) {
    const size_t half = input.size() / 2;
    const Fp2 positive = input[index];
    const Fp2 negative = input[index + half];
    const Fp2 inverse_two{volta_x4b::INVERSE_TWO, 0};
    const Fp2 omega = volta_x4b::root_of_unity(
        volta_x4b::power_of_two_log2(input.size()));
    const Fp2 x = volta_x4b::fp2_pow(omega, index);
    const Fp2 even =
        volta_x4b::fp2_mul(volta_x4b::fp2_add(positive, negative), inverse_two);
    const Fp2 odd = volta_x4b::fp2_mul(
        volta_x4b::fp2_mul(
            volta_x4b::fp2_sub(positive, negative), inverse_two),
        volta_x4b::fp2_inv(x));
    return volta_x4b::fp2_add(
        even, volta_x4b::fp2_mul(challenge, odd));
}

std::vector<Fp2> run_recurrence_fold(
    const std::vector<Fp2>& input, Fp2 challenge) {
    const size_t half = input.size() / 2;
    std::vector<Fp2> output(half);
    const Fp2 omega_inverse = volta_x4b::fp2_inv(
        volta_x4b::root_of_unity(
            volta_x4b::power_of_two_log2(input.size())));
    const Fp2 omega_inverse_block = volta_x4b::fp2_pow(
        omega_inverse, volta_x4b::X4C_DIRECT_FOLD_BLOCK);
    constexpr size_t block_span =
        volta_x4b::X4C_DIRECT_FOLD_BLOCK *
        volta_x4b::X4C_DIRECT_FOLD_RUN;
    for (size_t block_start = 0; block_start < half;
         block_start += block_span) {
        std::array<Fp2, volta_x4b::X4C_DIRECT_FOLD_BLOCK> lane_inverse{};
        Fp2 value = volta_x4b::fp2_pow(omega_inverse, block_start);
        for (Fp2& lane : lane_inverse) {
            lane = value;
            value = volta_x4b::fp2_mul(value, omega_inverse);
        }
        for (size_t lane = 0;
             lane < volta_x4b::X4C_DIRECT_FOLD_BLOCK; ++lane) {
            size_t local = block_start + lane;
            Fp2 inverse_x = lane_inverse[lane];
            for (size_t run = 0;
                 run < volta_x4b::X4C_DIRECT_FOLD_RUN; ++run) {
                if (local < half) {
                    output[local] = volta_x4b::direct_fold_symbol(
                        input[local], input[local + half], challenge,
                        inverse_x);
                }
                local += volta_x4b::X4C_DIRECT_FOLD_BLOCK;
                inverse_x =
                    volta_x4b::fp2_mul(inverse_x, omega_inverse_block);
            }
        }
    }
    return output;
}

void check_fold_length(size_t input_len) {
    std::vector<Fp2> input(input_len);
    for (size_t index = 0; index < input_len; ++index) {
        input[index] = symbol(index);
    }
    const std::array<Fp2, 4> challenges{{
        Fp2{0, 0},
        Fp2{1, 0},
        Fp2{3, 11},
        Fp2{volta_x4b::P - 1, volta_x4b::P - 2},
    }};
    const size_t half = input_len / 2;
    for (size_t challenge_ordinal = 0;
         challenge_ordinal < challenges.size(); ++challenge_ordinal) {
        const Fp2 challenge = challenges[challenge_ordinal];
        std::vector<Fp2> scalar(half);
        require(
            volta_x4b::direct_fold_reference(
                input.data(), input.size(), challenge, scalar.data()),
            "scalar direct-fold reference rejected valid geometry");
        const std::vector<Fp2> recurrence =
            run_recurrence_fold(input, challenge);
        for (size_t index = 0; index < half; ++index) {
            if (!equal(scalar[index], recurrence[index])) {
                fail("block/run recurrence differs from scalar fold");
            }
        }

        const std::array<size_t, 4> anchors{{
            0,
            half > 1 ? size_t{1} : size_t{0},
            half / 2,
            half - 1,
        }};
        for (size_t index : anchors) {
            require(
                equal(scalar[index], scalar_fold_at(input, challenge, index)),
                "direct-fold anchor differs from independent equation");
        }

    }
}

std::vector<std::vector<Hash32>> full_one_slot_tree(
    const std::vector<Fp2>& codeword, const Hash32 keys[2],
    Hash32 descriptor, uint32_t cohort_id, uint8_t fold_round) {
    std::vector<std::vector<Hash32>> levels;
    std::vector<Hash32> current(codeword.size());
    for (size_t coordinate = 0; coordinate < codeword.size(); ++coordinate) {
        current[coordinate] = volta_x4b::one_slot_outer_leaf(
            codeword.data(), keys, descriptor, coordinate, cohort_id, 2,
            fold_round);
    }
    levels.push_back(current);
    uint8_t level = 1;
    while (current.size() > 1) {
        std::vector<Hash32> next(current.size() / 2);
        for (size_t parent = 0; parent < next.size(); ++parent) {
            next[parent] = volta_x4b::hash_node(
                keys[1], cohort_id, 1, 2, fold_round, UINT64_MAX, level,
                parent, current[2 * parent], current[2 * parent + 1]);
        }
        current = next;
        levels.push_back(current);
        ++level;
    }
    return levels;
}

void check_one_slot_tree(size_t outer_len) {
    Hash32 keys[2] = {
        volta_x4b::blake3_context_key(
            "volta-zk/x4/pcs-leaf/v4", 23),
        volta_x4b::blake3_context_key(
            "volta-zk/x4/pcs-node/v4", 23),
    };
    const Hash32 descriptor = descriptor_pattern(outer_len);
    constexpr uint32_t cohort_id = 17;
    constexpr uint8_t fold_round = 3;
    std::vector<Fp2> codeword(outer_len);
    for (size_t index = 0; index < outer_len; ++index) {
        codeword[index] = symbol(index + outer_len);
    }
    std::vector<Hash32> retained(outer_len / 2 - 1);
    require(
        volta_x4b::one_slot_n4_retained_reference(
            codeword.data(), outer_len, keys, descriptor, cohort_id, 2,
            fold_round, retained.data()),
        "one-slot retained reference rejected valid geometry");
    const auto full = full_one_slot_tree(
        codeword, keys, descriptor, cohort_id, fold_round);
    for (uint8_t level = 2; level < full.size(); ++level) {
        const size_t offset = static_cast<size_t>(
            volta_x4b::retained_level_digest_offset(outer_len, level));
        for (size_t index = 0; index < full[level].size(); ++index) {
            require(
                equal(retained[offset + index], full[level][index]),
                "retained one-slot N4 level/root mismatch");
        }
    }
    require(
        equal(retained.back(), full.back()[0]),
        "retained one-slot N4 final digest is not the exact root");

    for (uint8_t level = 0; level <= 1; ++level) {
        for (size_t index : {size_t{0}, full[level].size() - 1}) {
            Hash32 rebuilt{};
            require(
                volta_x4b::rebuild_one_slot_outer_digest(
                    codeword.data(), outer_len, keys, descriptor, cohort_id,
                    2, fold_round, level, index, &rebuilt),
                "canonical frontier rebuild rejected valid operation");
            require(
                equal(rebuilt, full[level][index]),
                "canonical frontier rebuilt digest mismatch");
        }
    }
}

void check_canonical_operation_ordering() {
    using volta_x4b::x4c_canonical_operation_ordered_after;

    require(
        x4c_canonical_operation_ordered_after(true, 0, 100, true, 0, 101),
        "increasing canonical symbols were rejected");
    require(
        !x4c_canonical_operation_ordered_after(true, 0, 100, true, 0, 100),
        "duplicate canonical symbol was accepted");
    require(
        x4c_canonical_operation_ordered_after(true, 0, 100, false, 0, 1),
        "first frontier node was compared with the last symbol index");
    require(
        x4c_canonical_operation_ordered_after(false, 0, 7, false, 0, 8),
        "increasing same-level frontier was rejected");
    require(
        x4c_canonical_operation_ordered_after(false, 0, 8, false, 1, 0),
        "increasing frontier level was rejected");
    require(
        !x4c_canonical_operation_ordered_after(false, 1, 8, false, 1, 8),
        "duplicate frontier node was accepted");
    require(
        !x4c_canonical_operation_ordered_after(false, 1, 8, false, 0, 9),
        "decreasing frontier level was accepted");
    require(
        !x4c_canonical_operation_ordered_after(false, 1, 8, true, 0, 9),
        "symbol after frontier was accepted");
}

void check_activation_add() {
    std::vector<Fp2> destination(257);
    std::vector<Fp2> source(257);
    std::vector<Fp2> expected(257);
    const Fp2 activation{31, 37};
    for (size_t index = 0; index < source.size(); ++index) {
        destination[index] = symbol(index);
        source[index] = symbol(index + 1'000);
        expected[index] = volta_x4b::fp2_add(
            destination[index],
            volta_x4b::fp2_mul(activation, source[index]));
    }
    require(
        volta_x4b::activation_add_reference(
            destination.data(), source.data(), source.size(), activation),
        "activation-add reference rejected valid geometry");
    for (size_t index = 0; index < source.size(); ++index) {
        require(
            equal(destination[index], expected[index]),
            "activation-add reference mismatch");
    }
}

}  // namespace

int main() {
    static_assert(
        sizeof(volta_x4b::X4cGatherRequest) == 24,
        "X4c gather-request ABI changed");
    static_assert(
        sizeof(volta_x4b::X4cCanonicalGatherOperation) == 88,
        "X4c canonical-operation ABI changed");
    for (const uint8_t bits : {uint8_t{3}, uint8_t{8}, uint8_t{12},
                               uint8_t{16}, uint8_t{20}}) {
        const Fp2 root = volta_x4b::root_of_unity(bits);
        require(
            equal(
                volta_x4b::fp2_pow(root, uint64_t{1} << bits),
                Fp2{1, 0}),
            "root does not have the registered power-of-two order");
        require(
            !equal(
                volta_x4b::fp2_pow(root, uint64_t{1} << (bits - 1)),
                Fp2{1, 0}),
            "root has an unexpectedly smaller order");
        check_fold_length(size_t{1} << bits);
    }
    check_activation_add();
    check_canonical_operation_ordering();
    check_one_slot_tree(8);
    check_one_slot_tree(32);
    check_one_slot_tree(256);
    std::puts("X4C_CUDA_HOST_REFERENCE_OK");
    return 0;
}
CPP

g++ -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$repo_dir/cuda" \
    "$source_file" \
    -o "$scratch_dir/x4c_host_reference"

"$scratch_dir/x4c_host_reference"
