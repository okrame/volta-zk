#!/usr/bin/env python3
"""Executable C7 R0.8e analytic/readiness screen; every result is credit:false."""

from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction
from functools import lru_cache


GPT2 = {
    "name": "gpt2-124m-screen",
    "kind": "reference_workload_model",
    "weights": 124_000_000,
    "layers": 12,
    "d_model": 768,
    "query_heads": 12,
    "kv_heads": 12,
    "head_dim": 64,
}
GEMMA_ENVELOPE = {
    "name": "gemma-class-31b-envelope",
    "kind": "synthetic_screening_envelope_not_a_named_checkpoint",
    "screening_envelope": True,
    "named_checkpoint": False,
    "weights": 30_826_400_000,
    "layers": 46,
    "d_model": 4_608,
    "query_heads": 32,
    "kv_heads": 16,
    "head_dim": 128,
}

ACCEPTED_CONTEXT_TOKENS = 100
RESPONSE_TOKENS = 50
SUCCESSOR_CONTEXT_TOKENS = 150
R_MAX = 1 << 20
RESPONSE_BAD_EVENT_BUDGET_CAP = 64
RESPONSE_EVENT_BITS = 110
TERMINAL_CLAIM_SCREEN_CAP = 512

REFERENCE_N = 1 << 32
REFERENCE_WEIGHT_ALFC_BYTES = 4_014_000
REFERENCE_SECURITY_BITS = 100
TARGET_RESPONSE_EVENT_BITS = 110

ERA_INVERSE_RATE_NUMERATOR = 22
ERA_INVERSE_RATE_DENOMINATOR = 5
FIELD_SYMBOL_BYTES = 8
PACKED_WEIGHT_BYTES = 2
PERMUTATION_INDEX_BYTES = 4
MULTIPLIER_BYTES = 8
ILLUSTRATIVE_ERA_MERKLE_SYMBOLS_PER_LEAF = 64
DIGEST_ONLY_LEAF_CANDIDATES = (64, 128, 129, 141, 256)
LOGICAL_LEAF_SYMBOLS = 141
HASH_BYTES = 32
AUTHENTICATED_FP_SYMBOL_BYTES = 8
AUTHENTICATED_FP2_SYMBOL_BYTES = 16
LEAF_SALT_BITS = 256
LEAF_ORACLE_QUERY_SCREEN = 1 << 64
SELECTED_CHALLENGE_MODE = "fresh-honest-dv-post-prefix-interactive"
SELECTED_FIAT_SHAMIR_QUERY_BOUND = 0
FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN = 1 << 64
RLC_BAD_CHALLENGE_CAP = 512
GOLDILOCKS_MODULUS = (1 << 64) - (1 << 32) + 1

C7_RA_SCREEN_REPETITION = 4
C7_RA_SUCCESSOR_TRIE_DEPTH = 64
C7_POSEIDON_WIDTH = 16
C7_POSEIDON_RATE = 12
C7_POSEIDON_PERMUTATIONS_PER_LEAF = 14
C7_POSEIDON_SBOXES_PER_PERMUTATION = 8 * 16 + 22
C7_POSEIDON_SECRET_MULTIPLICATIONS_PER_SBOX = 4
C7_LEAF_SBOX_MULTIPLICATION_EQUIVALENTS = (
    C7_POSEIDON_PERMUTATIONS_PER_LEAF
    * C7_POSEIDON_SBOXES_PER_PERMUTATION
    * C7_POSEIDON_SECRET_MULTIPLICATIONS_PER_SBOX
)
C7_LEAF_PRIVATE_INPUT_CORRECTION_BYTES = (141 + 8) * 8
C7_LEAF_ROOT_METADATA_BYTES = 64  # private salt seed + public commitment nonce
C7_ROOT_MASK_SEED_BYTES = 32
ROOT_MASK_REJECTION_DRAW_CAP_CONTROLS = (5, 6)
ROOT_MASK_PRG_LIFETIME_RESERVE_BITS = 110
ROOT_MASK_BLAKE3_STATED_SECURITY_BITS = 128
ROOT_MASK_KMAC_STATED_SECURITY_BITS = 256
KMACXOF256_RATE_BYTES = 136
KMACXOF256_CAPACITY_BITS = 512
KMACXOF256_CHUNK_BYTES = 1 << 16
KMACXOF256_ADVERSARY_PERM_QUERY_CONTROL = 1 << 64
R08_PRIVACY_OTHER_TERM_TARGET_BITS = {
    "adaptive_RS_view_refinement": 110,
    "salt_PRF_multi_root": 110,
    "root_path_hiding_and_hash": 110,
    "multi_user_PCG_VOLE": 110,
    "multi_user_MAC": 110,
    "allocator_receipt_and_state": 120,
    "replay_fork_collision": 120,
    "selective_abort_and_timing": 110,
    "codec_transcript_refinement": None,
}

POLICY2_QUERY_CLASSES = (
    "unique_opened_leaves",
    "visible_masked_base_field_symbols",
    "merkle_sibling_digests",
)
POLICY2_AGGREGATE_CENSUS_CLASSES = POLICY2_QUERY_CLASSES + ("attempts",)

SETUP_TARGET_NUMERATOR = 2
SETUP_TARGET_DENOMINATOR = 1
SETUP_HARD_NUMERATOR = 21
SETUP_HARD_DENOMINATOR = 10
SETUP_EXPLORATORY_NUMERATOR = 3
SETUP_EXPLORATORY_DENOMINATOR = 1
GPT2_SETUP_WALL_TARGET_SECONDS = 15 * 60
GEMMA_SETUP_WALL_TARGET_SECONDS = 90 * 60
GPT2_SETUP_WALL_HARD_CAP_SECONDS = 990
GEMMA_SETUP_WALL_HARD_CAP_SECONDS = 5_940
ORIGINAL_QUERY_GROWTH_NUMERATOR = 105
ORIGINAL_QUERY_GROWTH_DENOMINATOR = 100
ACTIVE_QUERY_GROWTH_NUMERATOR = 130
ACTIVE_QUERY_GROWTH_DENOMINATOR = 100
WEIGHT_WIRE_TARGET_NUMERATOR = 105
WEIGHT_WIRE_TARGET_DENOMINATOR = 100
WEIGHT_WIRE_EXPLORATORY_MIN_NUMERATOR = 125
WEIGHT_WIRE_EXPLORATORY_MAX_NUMERATOR = 150
WEIGHT_WIRE_EXPLORATORY_DENOMINATOR = 100
STRICT_UD_SECURITY_BITS = 110
WHIR_DIRECT_SEND_VARIABLES = 6
WHIR_CONSTANT_FOLD_CONTROLS = tuple(range(1, 9))
WHIR_STARTING_LOG_INV_RATE_CONTROLS = (1, 2)
GOLDILOCKS_TWO_ADICITY = 32
GOLDILOCKS_FP2_CARDINALITY = GOLDILOCKS_MODULUS**2
GOLDILOCKS_FP3_NONCUBE = 2
R08_SELECTED_FP2_SCHEDULES = {
    "gpt2-124m-screen": (4, 5, 3, 3, 3, 3),
    "gemma-class-31b-envelope": (4, 4, 3, 3, 3, 4, 4, 4),
}
R08_PROVISIONAL_PRE_MASK_FP3_SCHEDULES = {
    "gpt2-124m-screen": (4, 5, 3, 3, 3, 3),
    "gemma-class-31b-envelope": (4, 3, 3, 3, 4, 4, 4, 4),
}
R08_SELECTED_FP3_SCHEDULES = {
    "gpt2-124m-screen": (4, 5, 3, 3, 3, 4),
    "gemma-class-31b-envelope": (4, 3, 3, 3, 4, 4, 4, 4),
}
C7_R08_CODEC_HEADER_BYTES = 16
C7_R08_FRAME_HEADER_BYTES = 16
C7_R08_MULTIPROOF_COUNT_BYTES = 4
C7_R08_QUERY_INDEX_BYTES = 4

ROOT_COUNT = 4
ROOT_NAMES = ("C_W", "C_B_e", "C_KV_e", "C_KV_e_plus_1")
WEIGHT_SEGMENTS_PER_LAYER = 8
GLOBAL_WEIGHT_SEGMENTS = 2
BOUNDARY_SEGMENTS = 4
PREDECESSOR_KV_SEGMENTS = 2
SUCCESSOR_KV_SEGMENTS = 2
FP_LIMBS_PER_FP2 = 2
FP_CORRECTION_BYTES = 8

COMPUTE_REFERENCE_BYTES = 6_000_000
BOUNDARY_REFERENCE_BYTES = 1_200_000
STATE_REFERENCE_BYTES = 2_000_000
MAC_SETTLEMENT_BYTES = 512
FIXED_FRAMING_BYTES = 65_536

GPT2_CERTIFICATE_LIMIT_BYTES = 30_000_000
LARGE_CERTIFICATE_LIMIT_BYTES = 100_000_000
MAX_LARGE_TO_GPT2_GROWTH = 3.0
EXPLORATORY_GPT2_CERTIFICATE_LIMIT_BYTES = 35_000_000
EXPLORATORY_LARGE_CERTIFICATE_LIMIT_BYTES = 115_000_000
EXPLORATORY_MAX_LARGE_TO_GPT2_GROWTH = 3.5


def ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def certified_bits(error_upper_bound: Fraction) -> float:
    """Return -log2(epsilon) without replacing the field size by a power of two."""
    return math.log2(error_upper_bound.denominator) - math.log2(
        error_upper_bound.numerator
    )


def strict_ud_query_count(security_bits: int, log_inv_rate: int) -> int:
    """Queries for (1-delta)^q < 2^-lambda, delta=(1-rate)/2."""
    miss_probability = (1.0 + 2.0 ** (-log_inv_rate)) / 2.0
    return math.ceil(-security_bits / math.log2(miss_probability))


def r08_selected_extension_strict_audit(
    model: dict[str, object],
    schedule: tuple[int, ...],
    extension_degree: int,
    num_variables: int | None = None,
) -> dict[str, object]:
    """Audit the inherited strict-UD gap bound on one selected schedule."""
    if extension_degree < 2:
        raise ValueError("selected extension degree must be at least two")
    variables = (
        (int(model["weights"]) - 1).bit_length()
        if num_variables is None
        else num_variables
    )
    remaining = variables
    log_inv_rate = 1
    q_open = 0
    fp_positions = 0
    total_gap_error = Fraction(0, 1)
    rounds = []
    for round_index, fold in enumerate(schedule):
        if fold <= 0 or fold > remaining:
            raise ValueError("invalid selected extension-field folding schedule")
        queries = strict_ud_query_count(STRICT_UD_SECURITY_BITS, log_inv_rate)
        limbs = 1 if round_index == 0 else extension_degree
        positions = queries * (1 << fold) * limbs
        per_challenge_error = Fraction(
            1 << (remaining + log_inv_rate), GOLDILOCKS_MODULUS**extension_degree
        )
        round_error = fold * per_challenge_error
        rounds.append(
            {
                "round": round_index,
                "remaining_variables_before_fold": remaining,
                "log_inv_rate_before_fold": log_inv_rate,
                "folding_factor": fold,
                "strict_ud_queries": queries,
                "Fp_limbs_per_opened_symbol": limbs,
                "unstacked_Fp_positions": positions,
                "gap_error_upper_bound": (
                    f"{round_error.numerator}/{round_error.denominator}"
                ),
                "certified_gap_bits": certified_bits(round_error),
            }
        )
        q_open += queries
        fp_positions += positions
        total_gap_error += round_error
        remaining -= fold
        log_inv_rate += fold - 1

    response_bits = certified_bits(total_gap_error)
    after_r_max_bits = response_bits - math.log2(R_MAX)
    bare_78_ratio = Fraction(1, 1 << 78) / total_gap_error
    reserve_84_ratio = Fraction(1, 1 << 84) / total_gap_error
    return {
        "model": model["name"],
        "field": f"Goldilocks_Fp{extension_degree}",
        "starting_rate": "1/2",
        "first_fold": 4,
        "schedule": list(schedule),
        "remaining_direct_send_variables": remaining,
        "q_open": q_open,
        "unstacked_Fp_positions": fp_positions,
        "rounds": rounds,
        "all_fold_gap_error_upper_bound": (
            f"{total_gap_error.numerator}/{total_gap_error.denominator}"
        ),
        "all_fold_certified_response_bits": response_bits,
        "deficit_to_110_bits": TARGET_RESPONSE_EVENT_BITS - response_bits,
        "after_R_max_2_pow_20_certified_bits": after_r_max_bits,
        "deficit_to_78_connection_bits_before_other_terms": 78 - after_r_max_bits,
        "bare_max_attempts_for_78_bits_before_other_terms": (
            bare_78_ratio.numerator // bare_78_ratio.denominator
        ),
        "max_attempts_for_84_bits_before_other_terms": (
            reserve_84_ratio.numerator // reserve_84_ratio.denominator
        ),
        "certifies_110_response_bits": response_bits >= TARGET_RESPONSE_EVENT_BITS,
        "certifies_78_after_R_max_before_other_terms": after_r_max_bits >= 78,
        "modest_110_to_104_or_98_relaxation_suffices": response_bits >= 98,
        "classification": "proved_upper_bound_audit_not_tight_attack",
        "credit": False,
    }


def r08_selected_fp2_strict_audit(
    model: dict[str, object], schedule: tuple[int, ...]
) -> dict[str, object]:
    return r08_selected_extension_strict_audit(model, schedule, 2)


def r08_fp3_field_and_terminal_screen() -> dict[str, object]:
    """Pin the carrier-independent Fp3 seam without claiming PCS refinement."""
    noncube_witness = pow(
        GOLDILOCKS_FP3_NONCUBE, (GOLDILOCKS_MODULUS - 1) // 3, GOLDILOCKS_MODULUS
    )
    return {
        "base_modulus": GOLDILOCKS_MODULUS,
        "construction": "Fp[u]/(u^3-2)",
        "irreducibility_check": {
            "p_mod_3": GOLDILOCKS_MODULUS % 3,
            "two_to_the_p_minus_1_over_3_mod_p": noncube_witness,
            "noncube": noncube_witness != 1,
            "reason": (
                "Fp_star_is_cyclic_and_3_divides_p_minus_1; two_is_not_a_cube; "
                "a_cubic_without_a_root_is_irreducible"
            ),
        },
        "canonical_element": "a0+a1*u+a2*u^2 with 0<=ai<p",
        "canonical_wire": "a0_le64 || a1_le64 || a2_le64",
        "wire_bytes": 3 * FIELD_SYMBOL_BYTES,
        "decode_rejects_noncanonical_limb_or_wrong_length": True,
        "multiplication": {
            "c0": "a0*b0 + 2*(a1*b2+a2*b1)",
            "c1": "a0*b1 + a1*b0 + 2*a2*b2",
            "c2": "a0*b2 + a1*b1 + a2*b0",
            "all_coordinates_reduced_mod_p": True,
            "kat": "(1,2,3)*(4,5,6)=(58,49,28)",
        },
        "terminal": {
            "shared_Delta_in_Fp3": True,
            "validity_equation": "k=m+Delta*x in Fp3",
            "independent_base_field_MACs_forbidden": True,
            "clear_terminal_evaluation_serialized": False,
            "provider_terminal_correction_limbs": 3,
            "provider_terminal_correction_bytes": 3 * FP_CORRECTION_BYTES,
            "single_nonzero_equation_error_bound": "1/|Fp3|",
            "single_nonzero_equation_bits": math.log2(GOLDILOCKS_MODULUS**3),
            "soundness_scope": (
                "uniform_honest_DV_Delta_fixed_after_the_bound_prefix"
            ),
            "malicious_DV_privacy_implied": False,
        },
        "concrete_rust_codec_implemented": True,
        "rust_codec_and_multiplication_KAT_pass": True,
        "rust_decode_wrong_length_and_noncanonical_limb_tests_pass": True,
        "carrier_independent_shared_Delta_adapter_implemented": True,
        "rust_shared_Delta_linearity_and_three_limb_mutation_tests_pass": True,
        "lean_three_coordinate_consequence_proved": True,
        "concrete_shared_Delta_adapter_refinement_proved": False,
        "implementation_scope": (
            "field_codec_KAT_and_terminal_MAC_equation_only; no_PCG_VOLE_PCS_or_prover"
        ),
        "credit": False,
    }


@lru_cache(maxsize=None)
def compact_merkle_max_siblings(leaves: int, opened: int) -> int:
    """Exact maximum frontier for the canonical compact full binary tree."""
    if leaves <= 0 or opened <= 0 or opened > leaves:
        raise ValueError("invalid compact Merkle opening geometry")
    if opened == leaves or leaves == 1:
        return 0
    if leaves & (leaves - 1) == 0:
        nodes = leaves
        present = opened
        siblings = 0
        while nodes > 1:
            siblings += min(present, nodes - present)
            nodes //= 2
            present = min(present, nodes)
        return siblings
    left = 1 << (leaves.bit_length() - 1)
    right = leaves - left
    best = -1
    for opened_left in range(max(0, opened - right), min(opened, left) + 1):
        opened_right = opened - opened_left
        if opened_left == 0:
            candidate = 1 + compact_merkle_max_siblings(right, opened_right)
        elif opened_right == 0:
            candidate = 1 + compact_merkle_max_siblings(left, opened_left)
        else:
            candidate = compact_merkle_max_siblings(
                left, opened_left
            ) + compact_merkle_max_siblings(right, opened_right)
        best = max(best, candidate)
    return best


def r08_fp3_opening_codec_screen(
    model: dict[str, object],
    schedule: tuple[int, ...],
    num_variables: int | None = None,
) -> dict[str, object]:
    """Compile the exact fail-closed g141 opening subcodec reservation caps."""
    audit = r08_selected_extension_strict_audit(
        model, schedule, 3, num_variables
    )
    rounds = []
    total = {
        "q_open": 0,
        "Z_atom": 0,
        "U_leaf": 0,
        "S_visible_Fp": 0,
        "H_sibling": 0,
        "payload_bytes": 0,
        "salt_bytes": 0,
        "multiproof_bytes": 0,
        "challenge_bytes": 0,
        "frame_header_bytes": 0,
    }
    for audit_round in audit["rounds"]:
        round_index = int(audit_round["round"])
        fold = int(audit_round["folding_factor"])
        queries = int(audit_round["strict_ud_queries"])
        limbs = int(audit_round["Fp_limbs_per_opened_symbol"])
        domain_exponent = int(audit_round["remaining_variables_before_fold"]) + int(
            audit_round["log_inv_rate_before_fold"]
        )
        oracle_fp_limbs = (1 << domain_exponent) * limbs
        leaf_count = ceil_div(oracle_fp_limbs, LOGICAL_LEAF_SYMBOLS)
        block_fp_limbs = (1 << fold) * limbs
        max_leaves_per_block = ceil_div(
            block_fp_limbs + LOGICAL_LEAF_SYMBOLS - 1,
            LOGICAL_LEAF_SYMBOLS,
        )
        unique_leaf_cap = min(leaf_count, queries * max_leaves_per_block)
        visible_fp_cap = unique_leaf_cap * LOGICAL_LEAF_SYMBOLS
        sibling_cap = compact_merkle_max_siblings(leaf_count, unique_leaf_cap)
        payload_bytes = visible_fp_cap * FIELD_SYMBOL_BYTES
        salt_bytes = unique_leaf_cap * (LEAF_SALT_BITS // 8)
        multiproof_bytes = (
            C7_R08_MULTIPROOF_COUNT_BYTES + sibling_cap * HASH_BYTES
        )
        challenge_bytes = (
            fold * 3 * FIELD_SYMBOL_BYTES
            + queries * C7_R08_QUERY_INDEX_BYTES
        )
        frame_header_bytes = 2 * C7_R08_FRAME_HEADER_BYTES
        row = {
            "round": round_index,
            "folding_factor": fold,
            "q_open": queries,
            "Fp_limbs_per_oracle_symbol": limbs,
            "Z_atom": int(audit_round["unstacked_Fp_positions"]),
            "oracle_Fp_limb_count": oracle_fp_limbs,
            "logical_leaf_count": leaf_count,
            "opened_block_Fp_limbs": block_fp_limbs,
            "maximum_logical_leaves_per_block": max_leaves_per_block,
            "U_leaf_reserved_cap": unique_leaf_cap,
            "S_visible_Fp_reserved_cap": visible_fp_cap,
            "H_sibling_reserved_cap": sibling_cap,
            "masked_payload_bytes": payload_bytes,
            "opened_salt_bytes": salt_bytes,
            "multiproof_bytes": multiproof_bytes,
            "interactive_challenge_bytes": challenge_bytes,
            "frame_header_bytes": frame_header_bytes,
            "leaf_indices_serialized_bytes": 0,
            "leaf_indices_reconstructed_from_u32_query_indices": True,
            "actual_accepted_counts_may_be_lower_but_reservation_never_refunds": True,
        }
        rounds.append(row)
        for key, value in (
            ("q_open", queries),
            ("Z_atom", row["Z_atom"]),
            ("U_leaf", unique_leaf_cap),
            ("S_visible_Fp", visible_fp_cap),
            ("H_sibling", sibling_cap),
            ("payload_bytes", payload_bytes),
            ("salt_bytes", salt_bytes),
            ("multiproof_bytes", multiproof_bytes),
            ("challenge_bytes", challenge_bytes),
            ("frame_header_bytes", frame_header_bytes),
        ):
            total[key] += value

    auxiliary_root_count = len(schedule) - 1
    auxiliary_root_bytes = auxiliary_root_count * (
        HASH_BYTES + C7_R08_FRAME_HEADER_BYTES
    )
    direct_send_bytes = (1 << int(audit["remaining_direct_send_variables"])) * (
        3 * FIELD_SYMBOL_BYTES
    )
    final_direct_frame_bytes = C7_R08_FRAME_HEADER_BYTES + direct_send_bytes
    terminal_adapter_bytes = C7_R08_FRAME_HEADER_BYTES + 3 * FP_CORRECTION_BYTES
    known_serialized_bytes = (
        C7_R08_CODEC_HEADER_BYTES
        + total["payload_bytes"]
        + total["salt_bytes"]
        + total["multiproof_bytes"]
        + total["challenge_bytes"]
        + total["frame_header_bytes"]
        + auxiliary_root_bytes
        + final_direct_frame_bytes
        + terminal_adapter_bytes
    )
    total.update(
        {
            "auxiliary_root_count": auxiliary_root_count,
            "auxiliary_root_and_frame_bytes": auxiliary_root_bytes,
            "final_direct_send_and_frame_bytes": final_direct_frame_bytes,
            "terminal_adapter_three_limb_and_frame_bytes": terminal_adapter_bytes,
            "codec_header_bytes": C7_R08_CODEC_HEADER_BYTES,
            "known_serialized_bytes": known_serialized_bytes,
        }
    )
    return {
        "model": model["name"],
        "field": "Goldilocks_Fp3",
        "schedule": list(schedule),
        "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
        "compact_tree_shape": (
            "recursive_largest_power_of_two_left_subtree_full_binary_2L_minus_1"
        ),
        "reservation_is_exact_conservative_cap": True,
        "deduplication_scope": "one_root_round_proof_only",
        "rounds": rounds,
        "totals": total,
        "unknown_fail_closed_bytes": [
            "strict_UD_non_oracle_sumcheck_and_OOD_messages",
            "omega_profile_and_authenticated_reservation_receipt",
            "plane_assignment_receipt",
            "root_hiding_randomness_capacity_metadata",
        ],
        "complete_codec_bytes_known": False,
        "compiled_four_axis_query_counts_known": True,
        "credit": False,
    }


def r08_fp3_setup_resource_screen(
    model: dict[str, object],
    bandwidth_bytes_per_second: float,
    total_coefficient_dimension: int | None = None,
) -> dict[str, object]:
    """Count the selected rate-1/2 packed-root setup without claiming an encoder."""
    weights = int(model["weights"])
    dimension = (
        1 << (weights - 1).bit_length()
        if total_coefficient_dimension is None
        else total_coefficient_dimension
    )
    assert dimension > 0 and dimension & (dimension - 1) == 0
    assert dimension >= weights
    variables = dimension.bit_length() - 1
    domain_symbols = 1 << (variables + 1)
    leaves = ceil_div(domain_symbols, LOGICAL_LEAF_SYMBOLS)
    tree_nodes = 2 * leaves - 1
    tree_bytes = tree_nodes * HASH_BYTES
    packed_bytes = weights * PACKED_WEIGHT_BYTES
    persistent_bytes = (
        packed_bytes
        + tree_bytes
        + C7_LEAF_ROOT_METADATA_BYTES
        + C7_ROOT_MASK_SEED_BYTES
    )
    setup_target_seconds = (
        GPT2_SETUP_WALL_TARGET_SECONDS
        if model["name"] == GPT2["name"]
        else GEMMA_SETUP_WALL_TARGET_SECONDS
    )
    setup_hard_seconds = (
        GPT2_SETUP_WALL_HARD_CAP_SECONDS
        if model["name"] == GPT2["name"]
        else GEMMA_SETUP_WALL_HARD_CAP_SECONDS
    )
    oracle_payload_hash_bytes = domain_symbols * FIELD_SYMBOL_BYTES
    derived_salt_hash_bytes = leaves * (LEAF_SALT_BITS // 8)
    counted_io_bytes = packed_bytes + tree_bytes
    bandwidth_floor_seconds = counted_io_bytes / bandwidth_bytes_per_second
    return {
        "model": model["name"],
        "field": "Goldilocks_Fp3_challenges_initial_oracle_over_Fp",
        "starting_rate": "1/2",
        "packed_weight_roots": 1,
        "packed_weight_bytes": packed_bytes,
        "initial_oracle_Fp_symbols": domain_symbols,
        "logical_g141_leaves": leaves,
        "compact_tree_nodes": tree_nodes,
        "compact_tree_bytes": tree_bytes,
        "root_salt_seed_and_nonce_bytes": C7_LEAF_ROOT_METADATA_BYTES,
        "private_root_mask_seed_bytes": C7_ROOT_MASK_SEED_BYTES,
        "persistent_bytes": persistent_bytes,
        "selected_RS_total_coefficient_dimension": dimension,
        "persistent_bytes_is_pre_mask_capacity_lower_bound": (
            total_coefficient_dimension is None
        ),
        "includes_selected_seeded_mask_capacity_geometry": (
            total_coefficient_dimension is not None
        ),
        "zk_randomness_capacity_symbols": dimension - weights,
        "zk_randomness_capacity_screen_ref": (
            "RS_t_query_root_capacity_screen"
        ),
        "zk_randomness_capacity_persistent_bytes": None,
        "complete_persistent_setup_bytes_known": False,
        "persistent_amplification_over_packed_i16": persistent_bytes
        / packed_bytes,
        "within_2x_target": (
            persistent_bytes * SETUP_TARGET_DENOMINATOR
            <= packed_bytes * SETUP_TARGET_NUMERATOR
        ),
        "within_2_1x_baseline_tolerance": (
            persistent_bytes * SETUP_HARD_DENOMINATOR
            <= packed_bytes * SETUP_HARD_NUMERATOR
        ),
        "within_3x_exploratory_disk_cap": (
            persistent_bytes * SETUP_EXPLORATORY_DENOMINATOR
            <= packed_bytes * SETUP_EXPLORATORY_NUMERATOR
        ),
        "setup_wall_target_seconds": setup_target_seconds,
        "setup_wall_hard_cap_seconds": setup_hard_seconds,
        "measured_setup_wall_seconds": None,
        "setup_wall_gate_pass": False,
        "setup_wall_status": "not_measured_fail_closed",
        "minimum_counted_IO": {
            "packed_read_bytes": packed_bytes,
            "persistent_tree_write_bytes": tree_bytes,
            "temporary_disk_write_bytes_target": 0,
            "temporary_disk_read_bytes_target": 0,
            "total_read_plus_write_bytes": counted_io_bytes,
            "bandwidth_floor_seconds_at_selected_rate": bandwidth_floor_seconds,
        },
        "hash_stream": {
            "oracle_payload_bytes": oracle_payload_hash_bytes,
            "derived_salt_bytes_absorbed": derived_salt_hash_bytes,
            "per_leaf_context_bytes": None,
            "complete_hash_input_bytes_known": False,
        },
        "required_rates_at_target": {
            "initial_oracle_Fp_symbols_per_second": domain_symbols
            / setup_target_seconds,
            "counted_IO_bytes_per_second": counted_io_bytes
            / setup_target_seconds,
            "oracle_payload_hash_bytes_per_second": oracle_payload_hash_bytes
            / setup_target_seconds,
        },
        "streaming_memory_target": (
            "configured_chunk_plus_at_most_140_Fp_carry_plus_O(log(leaves))_digests"
        ),
        "streaming_tree_builder_possible_if_ordered_symbols_exist": True,
        "ordered_RS_symbol_generator_one_source_scan_proved": False,
        "packed_source_scan_target": 1,
        "full_codeword_materialization_allowed": False,
        "model_sized_temporary_allowed": False,
        "setup_resource_gate_pass": False,
        "refresh": {
            "counter_domain": "distinct_from_setup",
            "budget_transfer_from_setup_allowed": False,
            "target_seconds": setup_target_seconds,
            "hard_cap_seconds": setup_hard_seconds,
            "test_authorized_or_required_in_R08": False,
            "measured_seconds": None,
            "status": "registered_not_tested_not_credited",
        },
        "credit": False,
    }


def r08_rs_t_query_capacity_screen(
    model: dict[str, object],
    visible_fp_per_attempt: int,
    initial_visible_fp_per_attempt: int,
) -> dict[str, object]:
    """Bound root life from the exact RS t-query randomness dimension."""
    weights = int(model["weights"])
    packed_bytes = weights * PACKED_WEIGHT_BYTES
    base_dimension = 1 << (weights - 1).bit_length()
    setup_target_seconds = (
        GPT2_SETUP_WALL_TARGET_SECONDS
        if model["name"] == GPT2["name"]
        else GEMMA_SETUP_WALL_TARGET_SECONDS
    )

    def geometry(dimension: int) -> dict[str, int]:
        domain_symbols = 2 * dimension
        leaves = ceil_div(domain_symbols, LOGICAL_LEAF_SYMBOLS)
        tree_bytes = (2 * leaves - 1) * HASH_BYTES
        return {
            "RS_total_coefficient_dimension": dimension,
            "rate_half_oracle_Fp_symbols": domain_symbols,
            "logical_g141_leaves": leaves,
            "compact_tree_bytes": tree_bytes,
            "persistent_bytes_excluding_mask_coefficients": (
                packed_bytes
                + tree_bytes
                + C7_LEAF_ROOT_METADATA_BYTES
                + C7_ROOT_MASK_SEED_BYTES
            ),
        }

    setup_caps = {
        "target_2_00x": packed_bytes * SETUP_TARGET_NUMERATOR
        // SETUP_TARGET_DENOMINATOR,
        "baseline_tolerance_2_10x": packed_bytes * SETUP_HARD_NUMERATOR
        // SETUP_HARD_DENOMINATOR,
        "exploratory_3_00x": packed_bytes * SETUP_EXPLORATORY_NUMERATOR
        // SETUP_EXPLORATORY_DENOMINATOR,
    }
    geometry_only_tiers = {}
    explicit_uniform_tiers = {}
    for tier, cap in setup_caps.items():
        dimension = base_dimension
        best_geometry = None
        best_uniform = None
        while geometry(dimension)[
            "persistent_bytes_excluding_mask_coefficients"
        ] <= cap:
            row = geometry(dimension)
            randomness_capacity = dimension - weights
            best_geometry = {
                **row,
                "setup_cap_bytes": cap,
                "random_Fp_coefficient_capacity": randomness_capacity,
                "maximum_full_attempts_at_reserved_visible_Fp_charge": (
                    randomness_capacity // visible_fp_per_attempt
                ),
                "required_oracle_Fp_symbols_per_second_at_setup_target": (
                    row["rate_half_oracle_Fp_symbols"] / setup_target_seconds
                ),
                "required_oracle_payload_bytes_per_second_at_setup_target": (
                    row["rate_half_oracle_Fp_symbols"]
                    * FIELD_SYMBOL_BYTES
                    / setup_target_seconds
                ),
            }
            uniform_capacity = min(
                randomness_capacity,
                (
                    cap
                    - row["persistent_bytes_excluding_mask_coefficients"]
                )
                // FIELD_SYMBOL_BYTES,
            )
            if uniform_capacity >= 0 and (
                best_uniform is None
                or uniform_capacity
                > best_uniform["random_Fp_coefficient_capacity"]
            ):
                best_uniform = {
                    **row,
                    "setup_cap_bytes": cap,
                    "random_Fp_coefficient_capacity": uniform_capacity,
                    "explicit_random_coefficient_bytes": (
                        uniform_capacity * FIELD_SYMBOL_BYTES
                    ),
                    "total_persistent_bytes": (
                        row["persistent_bytes_excluding_mask_coefficients"]
                        + uniform_capacity * FIELD_SYMBOL_BYTES
                    ),
                    "maximum_full_attempts_at_reserved_visible_Fp_charge": (
                        uniform_capacity // visible_fp_per_attempt
                    ),
                }
            dimension *= 2
        assert best_geometry is not None
        assert best_uniform is not None
        geometry_only_tiers[tier] = best_geometry
        explicit_uniform_tiers[tier] = best_uniform

    fixed_geometry = geometry(base_dimension)
    fixed_capacity = base_dimension - weights
    rmax_charge = visible_fp_per_attempt * R_MAX
    rmax_dimension = 1 << (weights + rmax_charge - 1).bit_length()
    rmax_geometry = geometry(rmax_dimension)
    rmax_geometry_bytes = rmax_geometry[
        "persistent_bytes_excluding_mask_coefficients"
    ]
    initial_rmax_charge = initial_visible_fp_per_attempt * R_MAX
    initial_rmax_dimension = 1 << (
        weights + initial_rmax_charge - 1
    ).bit_length()
    initial_rmax_geometry = geometry(initial_rmax_dimension)
    initial_rmax_geometry_bytes = initial_rmax_geometry[
        "persistent_bytes_excluding_mask_coefficients"
    ]
    return {
        "model": model["name"],
        "theorem_carrier": (
            "2026/391 Proposition 3.19: RS[F,L,ell] has perfect t-query "
            "ZK with message length ell-t and randomness length t"
        ),
        "paper_query_unit": "one distinct codeword alphabet location",
        "paper_scope": "fixed-set honest-verifier zero knowledge",
        "C7_charge_unit": "visible masked base-field symbol occurrence",
        "C7_charge_is_conservative_scalar_upper_bound": True,
        "C7_charge_to_paper_query_refinement_proved": False,
        "interleaving_warning": (
            "Claim 3.23 preserves t alphabet queries while each answer contains "
            "2^k base symbols; the g141 load map must prove the conversion"
        ),
        "reserved_visible_Fp_charge_per_attempt": visible_fp_per_attempt,
        "charge_scope": "compiled_weight_opening_leaf_payloads_only",
        "full_weight_attempt_and_lifecycle_charge_compiled": False,
        "initial_oracle_visible_Fp_charge_per_attempt": (
            initial_visible_fp_per_attempt
        ),
        "initial_interleaving_lanes": 1 << 4,
        "initial_dense_layout_randomness_lower_bound": (
            "16*max_c(load_c)>=sum_c(load_c)=visible_Fp; each RS lane needs "
            "randomness length at least its queried-location load"
        ),
        "initial_RS_mask_rank_argument": {
            "message_evaluation_rank": (
                "q for q distinct nonzero domain points and q<=message_dimension"
            ),
            "mask_evaluation_rank_upper_bound": "min(q,randomness_length)",
            "perfect_privacy_requires": "im(G_message)<=im(G_mask)",
            "consequence": "randomness_length>=q in every interleaving lane",
            "multiplicative_nonzero_evaluation_domain_required": True,
            "lean_proved": False,
        },
        "base_RS_total_coefficient_dimension": base_dimension,
        "canonical_weight_message_Fp_coefficients": weights,
        "zero_tree_growth_randomness_headroom_Fp_coefficients": fixed_capacity,
        "zero_tree_growth_maximum_full_attempts": (
            fixed_capacity // visible_fp_per_attempt
        ),
        "fixed_geometry": fixed_geometry,
        "setup_caps_bytes": setup_caps,
        "geometry_only_capacity_by_setup_tier": geometry_only_tiers,
        "geometry_only_warning": (
            "omits persistence of t uniform coefficients; admission needs either "
            "counted explicit storage or a computational PRG/PCG refinement plus "
            "a random-access one-scan schedule"
        ),
        "explicit_uniform_coefficient_persistence_control_by_setup_tier": (
            explicit_uniform_tiers
        ),
        "single_root_for_R_max_control": {
            "attempts": R_MAX,
            "required_random_Fp_coefficients": rmax_charge,
            **rmax_geometry,
            "persistent_amplification_excluding_mask_coefficients": (
                rmax_geometry_bytes / packed_bytes
            ),
            "explicit_uniform_random_coefficient_bytes": (
                rmax_charge * FIELD_SYMBOL_BYTES
            ),
            "total_persistent_amplification_with_explicit_coefficients": (
                (rmax_geometry_bytes + rmax_charge * FIELD_SYMBOL_BYTES)
                / packed_bytes
            ),
            "within_exploratory_3x": (
                rmax_geometry_bytes
                <= setup_caps["exploratory_3_00x"]
            ),
            "disposition": (
                "provisional_full_opening_charge_control_pending_cross_round_"
                "load_refinement"
            ),
        },
        "initial_oracle_only_R_max_lower_bound_control": {
            "attempts": R_MAX,
            "required_random_Fp_coefficients_lower_bound": initial_rmax_charge,
            **initial_rmax_geometry,
            "persistent_amplification_excluding_mask_coefficients": (
                initial_rmax_geometry_bytes / packed_bytes
            ),
            "within_exploratory_3x": (
                initial_rmax_geometry_bytes
                <= setup_caps["exploratory_3_00x"]
            ),
            "disposition": (
                "NO_GO_same_root_for_full_connection_horizon_even_if_all_"
                "later_round_leakage_is_free"
            ),
        },
        "R_root_is_distinct_from_R_max": True,
        "root_rotation_is_required_before_R_max": True,
        "refresh_test_authorized_or_required_in_R08": False,
        "stateful_malicious_DV_privacy_completed_by_this_screen": False,
        "numeric_Q_root_admitted": False,
        "reason_numeric_Q_root_not_admitted": (
            "the full codec load map, adaptive multi-session refinement, lifecycle "
            "charges and mask persistence/generation construction remain missing"
        ),
        "credit": False,
    }


def r08_root_mask_prg_policy_screen(
    model: dict[str, object], capacity: dict[str, object]
) -> dict[str, object]:
    """Register the selected computational root-mask line and its baseline."""
    maximum_coefficients = int(
        capacity["geometry_only_capacity_by_setup_tier"][
            "exploratory_3_00x"
        ]["random_Fp_coefficient_capacity"]
    )
    rejection_numerator = (1 << 64) - GOLDILOCKS_MODULUS
    draw_cap_rows = {}
    for draw_cap in ROOT_MASK_REJECTION_DRAW_CAP_CONTROLS:
        failure = Fraction(
            maximum_coefficients * rejection_numerator**draw_cap,
            (1 << 64) ** draw_cap,
        )
        draw_cap_rows[str(draw_cap)] = {
            "draws_per_coefficient_cap": draw_cap,
            "maximum_addressed_64_bit_words": (
                maximum_coefficients * draw_cap
            ),
            "root_generation_failure_upper_bound": (
                f"{failure.numerator}/{failure.denominator}"
            ),
            "root_generation_failure_certified_bits": certified_bits(failure),
        }

    selected_draw_cap = 6
    selected_failure = draw_cap_rows[str(selected_draw_cap)]
    blake3_loss_headroom_bits = (
        ROOT_MASK_BLAKE3_STATED_SECURITY_BITS
        - ROOT_MASK_PRG_LIFETIME_RESERVE_BITS
    )
    linear_loss_word_ceiling = 1 << blake3_loss_headroom_bits
    conservative_attempt_charge = int(
        capacity["reserved_visible_Fp_charge_per_attempt"]
    )
    return {
        "model": model["name"],
        "selected_policy": "computational_seeded_root_mask",
        "baseline_policy": "persisted_uniform_Fp_coefficients",
        "baseline_remains_reference_not_main_line": True,
        "setup_once_per_root_epoch": True,
        "response_reseeding_allowed": False,
        "bounded_root_reuse_required": True,
        "refresh_expected_rare_but_not_a_security_assumption": True,
        "root_mask_seed_bits": C7_ROOT_MASK_SEED_BYTES * 8,
        "root_mask_seed_bytes": C7_ROOT_MASK_SEED_BYTES,
        "fresh_uniform_private_seed_per_disclosed_candidate_root": True,
        "seed_reuse_across_root_epochs_allowed": False,
        "seed_serialized_in_certificate": False,
        "seed_must_remain_provider_private_at_rest": True,
        "generator_suite_id": None,
        "generator_primitive_selected": False,
        "candidate_order": [
            "keyed_BLAKE3_XOF",
            "KMACXOF256",
            "reduce_attempts_per_root_and_recompute",
        ],
        "primary_candidate_selected": "keyed_BLAKE3_XOF",
        "fallback_candidate": "KMACXOF256",
        "connection_target_bits": 78,
        "connection_target_reduction_allowed_to_admit_PRG": False,
        "candidate_promotion_rule": (
            "admit keyed BLAKE3-XOF only if its concrete multi-root advantage "
            "passes 2^-110 at the exact Q_mask_words; otherwise promote "
            "KMACXOF256 or reduce the attempt budget per root and recompute"
        ),
        "blake3_xof_candidate_screen": {
            "mode": "keyed_hash with 256-bit root seed and seekable XOF output",
            "candidate_only_not_admitted": True,
            "stated_general_security_target_bits": (
                ROOT_MASK_BLAKE3_STATED_SECURITY_BITS
            ),
            "stated_key_bits": 256,
            "key_bits_are_not_credited_as_security_bits": True,
            "component_reserve_bits": ROOT_MASK_PRG_LIFETIME_RESERVE_BITS,
            "maximum_composable_loss_bits_if_128_bit_target_is_applicable": (
                blake3_loss_headroom_bits
            ),
            "maximum_composable_loss_factor_if_128_bit_target_is_applicable": (
                1 << blake3_loss_headroom_bits
            ),
            "linear_in_Q_proof_form_control": {
                "maximum_words_for_110_bits": linear_loss_word_ceiling,
                "conservative_visible_Fp_charge_per_attempt": (
                    conservative_attempt_charge
                ),
                "conservative_one_attempt_passes": (
                    conservative_attempt_charge <= linear_loss_word_ceiling
                ),
                "terminal_verdict": False,
                "reason_not_terminal": (
                    "C7 visible-Fp charge to the theorem's generator-query loss "
                    "has not been refined"
                ),
            },
            "minimum_first_draw_words_at_exploratory_geometry": (
                maximum_coefficients
            ),
            "minimum_first_draw_words_log2": math.log2(maximum_coefficients),
            "maximum_six_draw_words_at_exploratory_geometry": int(
                selected_failure["maximum_addressed_64_bit_words"]
            ),
            "logical_codec_candidate": {
                "suite": "C7-RM-B3XOF-v1",
                "key": "private 32-byte root seed",
                "absorbed_prefix": (
                    "suite||model_id||epoch_id||layout_digest||field_id||rate||k0"
                ),
                "word_byte_offset": "8*(6*coefficient_index+draw_index)",
                "word_encoding": "little-endian u64",
                "draw_index_range": "0..5",
                "one_XOF_stream_per_candidate_root": True,
                "maximum_output_position_exclusive_bytes": (
                    int(selected_failure["maximum_addressed_64_bit_words"])
                    * 8
                ),
                "within_BLAKE3_2^64_minus_1_output_byte_limit": (
                    int(selected_failure["maximum_addressed_64_bit_words"])
                    * 8
                    <= (1 << 64) - 1
                ),
                "CPU_SIMT_bytes_must_match": True,
                "implemented": False,
            },
            "exact_Q_mask_words_numeric": None,
            "exact_multi_root_advantage_theorem_available": False,
            "passes_component_reserve": False,
            "reason": (
                "the official 128-bit security target and 256-bit key do not "
                "instantiate Adv_RootMaskPRG_multi(K_model,{Q_mask_words})"
            ),
        },
        "kmacxof256_fallback_screen": {
            "candidate_only_not_admitted": True,
            "nist_role": "KMAC is standardized as a PRF-capable SHA-3-derived function",
            "logical_codec_suite": "C7-RM-KMACXOF256-v1",
            "addressed_parallel_codec_selected": True,
            "conditional_ideal_permutation_control_compiled": True,
            "exact_multi_root_advantage_theorem_available": False,
            "setup_wall_gate_must_still_pass": True,
            "passes_component_reserve": False,
        },
        "Q_mask_words_definition": (
            "total addressed 64-bit generator words consumed by every candidate "
            "root setup, including rejection draws and failed seeds; visible PCS "
            "q may replace this only under a proved tighter leakage reduction"
        ),
        "coefficient_derivation": {
            "address": (
                "domain(model,epoch,layout,field,rate,k0,coefficient_index,draw_index)"
            ),
            "mapping": (
                "first little-endian u64 below p among fixed addressed draws"
            ),
            "selected_draw_cap": selected_draw_cap,
            "failure_action": (
                "abort before root disclosure; burn seed and candidate epoch slot"
            ),
            "fixed_addresses_support_random_access_and_CPU_SIMT_equivalence": True,
            "canonical_rejection_is_exactly_uniform_conditioned_on_success": True,
        },
        "maximum_random_Fp_coefficients_under_exploratory_setup_geometry": (
            maximum_coefficients
        ),
        "expected_64_bit_words_at_maximum_capacity": (
            maximum_coefficients * (1 << 64) / GOLDILOCKS_MODULUS
        ),
        "draw_cap_controls": draw_cap_rows,
        "selected_draw_cap_failure_bits": selected_failure[
            "root_generation_failure_certified_bits"
        ],
        "privacy_hybrid": {
            "real": "addressed coefficients from the private per-root seed",
            "ideal": "independent uniform Fp coefficients for every root epoch",
            "then_apply": (
                "ideal RS t-query privacy plus C7-OnlineMDVViewRefine and "
                "bounded root counters"
            ),
            "bound": (
                "Adv_RootMaskPRG_multi(K_model,{Q_mask_words[omega]}) + "
                "K_seed_attempts*epsilon_rejection <= 2^-110"
            ),
            "included_in_model_lifetime_78_bit_budget": True,
            "component_reserve_bits": ROOT_MASK_PRG_LIFETIME_RESERVE_BITS,
            "Adv_RootMaskPRG_multi_numeric": None,
            "K_model_numeric": None,
            "K_seed_attempts_numeric": None,
            "passes_component_reserve": False,
        },
        "separate_from_salt_PRF_and_VOLE_PCG": True,
        "existing_repository_generator_disposition": {
            "volta_field_FpStream_ChaCha8": {
                "status": "REJECT_PRODUCTION_C7_ROOT_MASK",
                "reason": (
                    "the implementation labels itself a mock-PCG stand-in, uses "
                    "a sequential unbounded rejection loop, and has no C7 multi-root "
                    "advantage theorem"
                ),
            },
            "volta_pcg_Aes128Mmo_GGM": {
                "status": "QUARANTINE",
                "reason": (
                    "the registered fixed-key 16-byte primitive is scoped only to "
                    "WYKW GGM node expansion, not the selected 256-bit addressed "
                    "root-mask function, and has no C7 Q_mask_words bound"
                ),
            },
            "volta_pcg_Blake3_GGM": {
                "status": "QUARANTINE",
                "reason": (
                    "the existing path is an explicit non-default 16-byte GGM-node "
                    "control, not a selected root-mask suite or multi-root reduction"
                ),
            },
        },
        "random_access_mask_coefficients_solve_RS_one_scan_generator": False,
        "refresh_test_authorized_or_required_in_R08": False,
        "credit": False,
    }


def r08_concrete_root_profile_proposal(
    model: dict[str, object],
    capacity: dict[str, object],
    r_root: int,
) -> dict[str, object]:
    """Compile one conservative, owner-unselected root-lifetime proposal."""
    assert r_root > 0 and r_root & (r_root - 1) == 0
    charge = int(capacity["reserved_visible_Fp_charge_per_attempt"])
    lifecycle_reserve_attempt_equivalents = r_root // 8
    response_attempt_charge = r_root * charge
    lifecycle_reserve_charge = lifecycle_reserve_attempt_equivalents * charge
    q_root = response_attempt_charge + lifecycle_reserve_charge
    tier_order = (
        "target_2_00x",
        "baseline_tolerance_2_10x",
        "exploratory_3_00x",
    )
    selected_tier = next(
        tier
        for tier in tier_order
        if q_root
        <= int(
            capacity["geometry_only_capacity_by_setup_tier"][tier][
                "random_Fp_coefficient_capacity"
            ]
        )
    )
    tier = capacity["geometry_only_capacity_by_setup_tier"][selected_tier]
    seed_attempt_cap = 2
    draw_cap = 6
    q_mask_words_per_seed = q_root * draw_cap
    q_mask_words_all_seed_attempts = q_mask_words_per_seed * seed_attempt_cap
    linear_control_bits = (
        ROOT_MASK_BLAKE3_STATED_SECURITY_BITS
        - math.log2(q_mask_words_all_seed_attempts)
    )
    rejection_failure = Fraction(
        seed_attempt_cap
        * q_root
        * ((1 << 64) - GOLDILOCKS_MODULUS) ** draw_cap,
        (1 << 64) ** draw_cap,
    )
    capacity_coefficients = int(tier["random_Fp_coefficient_capacity"])
    return {
        "profile_id": f"C7-R08-{model['name']}-Rroot-{r_root}-proposal-v1",
        "model": model["name"],
        "owner_selected": True,
        "owner_selected_as_fallback_variant": True,
        "owner_selected_as_mainline": False,
        "screening_only": True,
        "R_root_proposed": r_root,
        "R_root_scope": (
            "all accepted responses, failed attempts, retries and selective aborts"
        ),
        "post_hoc_refund_or_observed_average_allowed": False,
        "reserved_visible_Fp_charge_per_attempt_control": charge,
        "response_attempt_charge": response_attempt_charge,
        "lifecycle_reserve_attempt_equivalents": (
            lifecycle_reserve_attempt_equivalents
        ),
        "lifecycle_reserve_fraction_of_attempt_charge": "1/8",
        "lifecycle_reserve_charge": lifecycle_reserve_charge,
        "Q_root_scalar_cap_proposed": q_root,
        "Q_root_plane_vector_and_lifecycle_breakdown_complete": False,
        "selected_setup_tier": selected_tier,
        "RS_total_coefficient_dimension": int(
            tier["RS_total_coefficient_dimension"]
        ),
        "random_Fp_coefficient_capacity": capacity_coefficients,
        "unused_randomness_capacity_after_Q_root": capacity_coefficients - q_root,
        "persistent_bytes_excluding_mask_coefficients": int(
            tier["persistent_bytes_excluding_mask_coefficients"]
        ),
        "setup_cap_bytes": int(tier["setup_cap_bytes"]),
        "K_seed_attempts_per_root_epoch_cap": seed_attempt_cap,
        "seed_failure_policy": (
            "each failed setup seed is burned and charged; after two failures "
            "the root epoch fails closed before disclosure"
        ),
        "draws_per_coefficient_cap": draw_cap,
        "Q_mask_words_per_seed_cap": q_mask_words_per_seed,
        "Q_mask_words_all_seed_attempts_cap": q_mask_words_all_seed_attempts,
        "maximum_preregistered_Q_mask_words_compiled": True,
        "root_generation_rejection_failure_upper_bound": (
            f"{rejection_failure.numerator}/{rejection_failure.denominator}"
        ),
        "root_generation_rejection_failure_certified_bits": certified_bits(
            rejection_failure
        ),
        "BLAKE3_linear_in_Q_control_bits": linear_control_bits,
        "BLAKE3_linear_in_Q_control_passes_110": (
            linear_control_bits >= ROOT_MASK_PRG_LIFETIME_RESERVE_BITS
        ),
        "BLAKE3_exact_multi_root_advantage_passes_110": False,
        "reason_exact_gate_false": (
            "the full plane/lifecycle query map and a primitive-specific "
            "multi-root BLAKE3-XOF theorem remain missing"
        ),
        "connection_target_bits": 78,
        "connection_target_reduction_allowed": False,
        "profile_admitted": False,
        "credit": False,
    }


def r08_blake3_fallback_privacy_variant(
    profile: dict[str, object],
) -> dict[str, object]:
    """Compose the authorized fallback, leaving every unknown term fail-closed."""
    r_root = int(profile["R_root_proposed"])
    k_model = ceil_div(R_MAX, r_root)
    seed_attempts_per_root = int(profile["K_seed_attempts_per_root_epoch_cap"])
    k_seed_attempts = k_model * seed_attempts_per_root
    q_mask_words = (
        k_model * int(profile["Q_mask_words_all_seed_attempts_cap"])
    )
    blake3_linear_control = Fraction(
        q_mask_words, 1 << ROOT_MASK_BLAKE3_STATED_SECURITY_BITS
    )
    rejection = Fraction(
        k_seed_attempts
        * int(profile["Q_root_scalar_cap_proposed"])
        * ((1 << 64) - GOLDILOCKS_MODULUS) ** 6,
        (1 << 64) ** 6,
    )
    known_mask_sum = blake3_linear_control + rejection
    fallback_budget = Fraction(1, 1 << 78)
    remaining_other_terms_budget = fallback_budget - known_mask_sum
    other_terms = {
        "adaptive_RS_view_refinement": None,
        "salt_PRF_multi_root": None,
        "root_path_hiding_and_hash": None,
        "multi_user_PCG_VOLE": None,
        "multi_user_MAC": None,
        "allocator_receipt_and_state": None,
        "replay_fork_collision": None,
        "selective_abort_and_timing": None,
        "codec_transcript_refinement": None,
    }
    other_target_fractions = {
        name: (Fraction(0, 1) if bits is None else Fraction(1, 1 << bits))
        for name, bits in R08_PRIVACY_OTHER_TERM_TARGET_BITS.items()
    }
    other_target_sum = sum(other_target_fractions.values(), Fraction(0, 1))
    allocated_complete_sum = known_mask_sum + other_target_sum
    return {
        "variant_id": f"{profile['profile_id']}-blake3-full78-fallback-v1",
        "owner_authorized_fallback": True,
        "mainline_PRG_component_target_bits": 110,
        "mainline_target_unchanged": True,
        "fallback_complete_privacy_target_bits": 78,
        "model_global_attempt_horizon": R_MAX,
        "model_global_attempt_horizon_owner_confirmed": True,
        "model_global_attempt_horizon_scope": (
            "all connections, accepted responses, failures, retries and "
            "selective aborts using this model-privacy variant"
        ),
        "model_must_retire_variant_at_global_horizon": True,
        "R_root": r_root,
        "K_model": k_model,
        "K_seed_attempts": k_seed_attempts,
        "Q_mask_words_model_max": q_mask_words,
        "all_root_and_seed_failures_included": True,
        "blake3_specific_multi_root_theorem_found": False,
        "blake3_linear_128_control_is_named_hypothesis_not_theorem": True,
        "conditional_Adv_BLAKE3_multi_exact": (
            f"{blake3_linear_control.numerator}/{blake3_linear_control.denominator}"
        ),
        "conditional_Adv_BLAKE3_multi_bits": certified_bits(
            blake3_linear_control
        ),
        "rejection_error_exact": f"{rejection.numerator}/{rejection.denominator}",
        "rejection_error_bits": certified_bits(rejection),
        "known_mask_terms_sum_exact": (
            f"{known_mask_sum.numerator}/{known_mask_sum.denominator}"
        ),
        "known_mask_terms_sum_bits": certified_bits(known_mask_sum),
        "known_mask_terms_pass_mainline_110": (
            known_mask_sum <= Fraction(1, 1 << 110)
        ),
        "known_mask_terms_pass_fallback_78": known_mask_sum <= fallback_budget,
        "maximum_other_privacy_terms_sum_exact": (
            f"{remaining_other_terms_budget.numerator}/"
            f"{remaining_other_terms_budget.denominator}"
        ),
        "maximum_other_privacy_terms_sum_bits": certified_bits(
            remaining_other_terms_budget
        ),
        "other_privacy_terms": other_terms,
        "other_privacy_term_target_bits": R08_PRIVACY_OTHER_TERM_TARGET_BITS,
        "other_privacy_term_target_epsilon_exact": {
            name: f"{epsilon.numerator}/{epsilon.denominator}"
            for name, epsilon in other_target_fractions.items()
        },
        "allocated_complete_privacy_epsilon_exact": (
            f"{allocated_complete_sum.numerator}/{allocated_complete_sum.denominator}"
        ),
        "allocated_complete_privacy_bits": certified_bits(
            allocated_complete_sum
        ),
        "allocated_complete_privacy_passes_78": (
            allocated_complete_sum <= fallback_budget
        ),
        "allocation_pass_is_not_theorem_discharge": True,
        "all_privacy_terms_numeric": all(
            term is not None for term in other_terms.values()
        ),
        "complete_privacy_formula": (
            "Adv_BLAKE3_multi + epsilon_rejection + "
            "epsilon_adaptive_RS_view + Adv_saltPRF_multi + "
            "Adv_root_path_hash + Adv_multi_user_PCG_VOLE + "
            "Adv_multi_user_MAC + epsilon_allocator_state + "
            "epsilon_replay_fork_collision + epsilon_abort_timing + "
            "epsilon_codec_transcript"
        ),
        "complete_privacy_epsilon_exact": None,
        "complete_privacy_passes_78": False,
        "reason_complete_gate_false": (
            "the BLAKE3 term is only a named linear control and every listed "
            "non-mask achieved advantage remains unknown; numeric target "
            "allocations are not theorem discharge"
        ),
        "promote_if_complete_gate_fails": [
            "KMACXOF256",
            "reduce_R_root_and_recompute_all_terms",
        ],
        "variant_admitted": False,
        "credit": False,
    }


def r08_kmacxof256_mainline_screen(
    profile: dict[str, object],
) -> dict[str, object]:
    """Count the minimal chunk-addressed KMAC alternative, without credit."""
    assert len(b"VOLTA-ZK/C7/root-mask/v1") == 24
    assert KMACXOF256_CHUNK_BYTES % 8 == 0
    r_root = int(profile["R_root_proposed"])
    k_model = ceil_div(R_MAX, r_root)
    seed_attempts_per_root = int(profile["K_seed_attempts_per_root_epoch_cap"])
    k_seed_attempts = k_model * seed_attempts_per_root
    q_root = int(profile["Q_root_scalar_cap_proposed"])
    words_per_seed = q_root * 6
    bytes_per_seed = words_per_seed * 8
    full_chunks, tail_bytes = divmod(bytes_per_seed, KMACXOF256_CHUNK_BYTES)
    chunks_per_seed = full_chunks + (1 if tail_bytes else 0)
    full_chunk_squeeze_blocks = ceil_div(
        KMACXOF256_CHUNK_BYTES, KMACXOF256_RATE_BYTES
    )
    squeeze_blocks_per_seed = (
        full_chunks * full_chunk_squeeze_blocks
        + (ceil_div(tail_bytes, KMACXOF256_RATE_BYTES) if tail_bytes else 0)
    )
    # Each independent chunk has one cSHAKE prefix block and one key bytepad
    # block.  Its final message/padding permutation is also its first squeeze.
    permutations_per_seed = squeeze_blocks_per_seed + 2 * chunks_per_seed
    honest_model_permutations = permutations_per_seed * k_seed_attempts
    total_permutation_query_control = (
        honest_model_permutations + KMACXOF256_ADVERSARY_PERM_QUERY_CONTROL
    )
    sponge_indifferentiability_control = Fraction(
        total_permutation_query_control
        * (total_permutation_query_control + 1),
        1 << (KMACXOF256_CAPACITY_BITS + 1),
    )
    key_guess_control = Fraction(
        k_seed_attempts * KMACXOF256_ADVERSARY_PERM_QUERY_CONTROL,
        1 << ROOT_MASK_KMAC_STATED_SECURITY_BITS,
    )
    seed_collision = Fraction(
        k_seed_attempts * (k_seed_attempts - 1),
        1 << (ROOT_MASK_KMAC_STATED_SECURITY_BITS + 1),
    )
    rejection = Fraction(
        k_seed_attempts
        * q_root
        * ((1 << 64) - GOLDILOCKS_MODULUS) ** 6,
        (1 << 64) ** 6,
    )
    conditional_sum = (
        sponge_indifferentiability_control
        + key_guess_control
        + seed_collision
        + rejection
    )
    other_target_fractions = {
        name: (Fraction(0, 1) if bits is None else Fraction(1, 1 << bits))
        for name, bits in R08_PRIVACY_OTHER_TERM_TARGET_BITS.items()
    }
    other_target_sum = sum(other_target_fractions.values(), Fraction(0, 1))
    conditional_full_privacy_sum = conditional_sum + other_target_sum
    absorbed_padded_bytes_per_seed = (
        chunks_per_seed * 3 * KMACXOF256_RATE_BYTES
    )
    squeezed_internal_bytes_per_seed = (
        squeeze_blocks_per_seed * KMACXOF256_RATE_BYTES
    )
    descriptor_fields = {
        "magic_C7RMKX01": 8,
        "model_id": 32,
        "epoch_id_le64": 8,
        "root_slot_le64": 8,
        "layout_and_root_profile_digest": 32,
        "field_id_Goldilocks_Fp3_u3_minus_2_0x03": 1,
        "rate_numerator_0x01": 1,
        "rate_denominator_0x02": 1,
        "k0_0x04": 1,
        "logical_leaf_symbols_le16_141": 2,
        "draw_cap_0x06": 1,
        "Q_root_coefficients_le64": 8,
        "seed_attempt_index": 1,
    }
    assert sum(descriptor_fields.values()) == 104
    setup_target_seconds = (
        GPT2_SETUP_WALL_TARGET_SECONDS
        if profile["model"] == GPT2["name"]
        else GEMMA_SETUP_WALL_TARGET_SECONDS
    )
    setup_hard_cap_seconds = (
        GPT2_SETUP_WALL_HARD_CAP_SECONDS
        if profile["model"] == GPT2["name"]
        else GEMMA_SETUP_WALL_HARD_CAP_SECONDS
    )
    return {
        "model": profile["model"],
        "candidate": "KMACXOF256",
        "role": "mainline_110_bit_alternative_not_promoted",
        "model_global_attempt_horizon": R_MAX,
        "model_global_attempt_horizon_owner_confirmed": True,
        "R_root": r_root,
        "K_model": k_model,
        "K_seed_attempts": k_seed_attempts,
        "Q_mask_words_model_max": words_per_seed * k_seed_attempts,
        "standard": {
            "NIST_SP_800_185": "https://doi.org/10.6028/NIST.SP.800-185",
            "KMAC_may_be_used_as_PRF": True,
            "stated_security_strength_bits": ROOT_MASK_KMAC_STATED_SECURITY_BITS,
            "Keccak_rate_bits": KMACXOF256_RATE_BYTES * 8,
            "Keccak_capacity_bits": KMACXOF256_CAPACITY_BITS,
            "standard_supplies_C7_exact_multi_key_theorem": False,
        },
        "logical_codec_candidate": {
            "suite": "C7-RM-KMACXOF256-v1",
            "key": "private uniform 32-byte candidate-root seed",
            "customization_ASCII": "VOLTA-ZK/C7/root-mask/v1",
            "customization_bytes": 24,
            "SP800_185_KMACXOF_suffix": "right_encode(0)",
            "descriptor_fields_and_bytes": descriptor_fields,
            "descriptor_bytes": 104,
            "chunk_index_encoding": "le64 appended to descriptor",
            "KMAC_input_bytes_per_chunk": 112,
            "chunk_output_bytes": KMACXOF256_CHUNK_BYTES,
            "last_chunk_is_exact_prefix_without_serialized_padding": True,
            "word_mapping": (
                "offset=8*(6*coefficient_index+draw_index); "
                "chunk=floor(offset/65536); local=offset mod 65536; le64"
            ),
            "chunk_output_length_bits": (
                "8*min(65536,total_generator_bytes-65536*chunk_index)"
            ),
            "independent_KMACXOF256_call_per_chunk": True,
            "fixed_chunk_calls_allow_parallel_CPU_SIMT_evaluation": True,
            "canonical_emission_order_is_increasing_chunk_then_word": True,
            "CPU_SIMT_bytes_must_match": True,
            "persistent_generated_mask_or_codeword_bytes": 0,
            "certificate_bytes_added_by_generator_choice": 0,
            "visible_PCS_query_count_added_by_generator_choice": 0,
            "model_sized_scratch_allowed": False,
            "second_packed_weight_scan_allowed": False,
            "online_BatchOpen_mask_contribution_schedule_proved": False,
            "online_mask_regeneration_bytes_per_attempt": None,
            "setup_work_may_pay_online_regeneration": False,
            "implemented": False,
        },
        "per_candidate_seed_resource_control": {
            "logical_output_words": words_per_seed,
            "logical_output_bytes": bytes_per_seed,
            "chunks": chunks_per_seed,
            "last_chunk_logical_bytes": (
                tail_bytes if tail_bytes else KMACXOF256_CHUNK_BYTES
            ),
            "squeeze_rate_blocks": squeeze_blocks_per_seed,
            "Keccak_f1600_permutations": permutations_per_seed,
            "absorbed_padded_bytes": absorbed_padded_bytes_per_seed,
            "unserialized_squeeze_tail_bytes": (
                squeezed_internal_bytes_per_seed - bytes_per_seed
            ),
            "working_bytes_per_worker_upper_bound": (
                KMACXOF256_CHUNK_BYTES + 200 + 112
            ),
        },
        "per_root_two_seed_setup_cap": {
            "logical_generator_bytes": bytes_per_seed * seed_attempts_per_root,
            "Keccak_f1600_permutations": (
                permutations_per_seed * seed_attempts_per_root
            ),
            "minimum_logical_generator_Bps_for_setup_target": (
                bytes_per_seed * seed_attempts_per_root / setup_target_seconds
            ),
            "minimum_logical_generator_Bps_for_setup_hard_cap": (
                bytes_per_seed * seed_attempts_per_root / setup_hard_cap_seconds
            ),
            "minimum_Keccak_f1600_permutations_per_second_for_setup_target": (
                permutations_per_seed
                * seed_attempts_per_root
                / setup_target_seconds
            ),
            "setup_target_seconds": setup_target_seconds,
            "setup_hard_cap_seconds": setup_hard_cap_seconds,
            "setup_wall_measured": False,
        },
        "conditional_ideal_permutation_control": {
            "adversary_Keccak_permutation_queries_screen": (
                KMACXOF256_ADVERSARY_PERM_QUERY_CONTROL
            ),
            "adversary_query_screen_selected_as_security_definition": False,
            "honest_model_Keccak_permutations": honest_model_permutations,
            "total_permutation_query_control": total_permutation_query_control,
            "sponge_term_formula": "N*(N+1)/2^513",
            "sponge_term_bits": certified_bits(
                sponge_indifferentiability_control
            ),
            "multi_key_guess_control_bits": certified_bits(key_guess_control),
            "seed_collision_bits": certified_bits(seed_collision),
            "rejection_bits": certified_bits(rejection),
            "conditional_sum_exact": (
                f"{conditional_sum.numerator}/{conditional_sum.denominator}"
            ),
            "conditional_sum_bits": certified_bits(conditional_sum),
            "conditional_sum_passes_110": (
                conditional_sum <= Fraction(1, 1 << 110)
            ),
            "conditional_only_not_security_credit": True,
        },
        "conditional_full_privacy_allocation": {
            "other_privacy_term_target_bits": R08_PRIVACY_OTHER_TERM_TARGET_BITS,
            "complete_epsilon_exact": (
                f"{conditional_full_privacy_sum.numerator}/"
                f"{conditional_full_privacy_sum.denominator}"
            ),
            "complete_bits": certified_bits(conditional_full_privacy_sum),
            "complete_allocation_passes_78": (
                conditional_full_privacy_sum <= Fraction(1, 1 << 78)
            ),
            "allocation_pass_is_not_theorem_discharge": True,
        },
        "exact_multi_key_KMAC_to_Keccak_reduction_instantiated": False,
        "fixed_Keccak_f1600_assumption_numeric": False,
        "passes_component_reserve": False,
        "reason_gate_false": (
            "SP 800-185 supplies the construction/PRF role, while C7 still "
            "needs an exact adaptive multi-key reduction including adversarial "
            "permutation work; the displayed bound is an ideal-permutation control"
        ),
        "setup_wall_gate_must_still_pass": True,
        "candidate_promoted": False,
        "credit": False,
    }


def r08_online_rs_batch_open_screen(
    model: dict[str, object],
    profile: dict[str, object],
    setup: dict[str, object],
    codec: dict[str, object],
) -> dict[str, object]:
    """Bounded screen of the missing online selected-RS opening circuit."""
    weights = int(model["weights"])
    q_root = int(profile["Q_root_scalar_cap_proposed"])
    dimension = int(profile["RS_total_coefficient_dimension"])
    codeword_symbols = 2 * dimension
    codeword_bytes = codeword_symbols * FIELD_SYMBOL_BYTES
    packed_bytes = weights * PACKED_WEIGHT_BYTES
    stored_total = int(setup["persistent_bytes"]) + codeword_bytes
    initial_visible = int(codec["rounds"][0]["S_visible_Fp_reserved_cap"])
    dense_source_coefficients = weights + q_root
    dense_fma_control = dense_source_coefficients * initial_visible
    return {
        "model": model["name"],
        "scope": (
            "initial packed-weight RS oracle only; failure here is sufficient "
            "to reject the complete response opener"
        ),
        "required_contract": {
            "work": "O(N + poly(q,log N)) with source-linear constant independent of q",
            "packed_source_scans": 1,
            "bounded_memory": True,
            "full_codeword_or_model_sized_scratch": False,
            "second_scan": False,
            "CPU_SIMT_transcript_difference": False,
        },
        "selected_geometry": {
            "weight_Fp_coefficients": weights,
            "root_randomness_Fp_coefficients": q_root,
            "RS_total_coefficient_dimension": dimension,
            "rate_half_codeword_Fp_symbols": codeword_symbols,
            "initial_visible_Fp_reserved_cap": initial_visible,
        },
        "rows": {
            "independent_dense_evaluation": {
                "source_coefficients": dense_source_coefficients,
                "opened_outputs_control": initial_visible,
                "dense_FMA_control": dense_fma_control,
                "classification": "qN_control_not_lower_bound_on_shared_circuits",
                "pass": False,
                "reason": (
                    "direct Horner/dot evaluation repeats the dense source for "
                    "each opened symbol and violates the q-independent source term"
                ),
            },
            "persist_complete_rate_half_codeword": {
                "codeword_bytes": codeword_bytes,
                "persistent_bytes_with_existing_tree": stored_total,
                "persistent_amplification_over_packed_i16": (
                    stored_total / packed_bytes
                ),
                "selected_setup_tier_cap_bytes": int(profile["setup_cap_bytes"]),
                "exploratory_3x_cap_bytes": 3 * packed_bytes,
                "pass": False,
                "reason": (
                    "payload persistence exceeds the selected setup tier and "
                    "the 3x exploratory anti-X4d ceiling"
                ),
            },
            "online_full_codeword_materialization": {
                "minimum_full_payload_scratch_bytes": codeword_bytes,
                "model_sized_scratch": True,
                "pass": False,
                "reason": (
                    "materialization violates bounded memory even before its "
                    "encoder operations and temporary I/O are counted"
                ),
            },
            "pruned_or_subset_shared_transform": {
                "best_registered_standard_shape": "O(N*log(q)) or model-linear frontier",
                "exact_C7_operation_schedule_derived": False,
                "one_pass_bounded_memory_schedule_derived": False,
                "pass": False,
                "reason": (
                    "the bounded repository/paper screen contains no schedule "
                    "whose source-linear coefficient is independent of q; this "
                    "is a missing construction, not a universal lower bound"
                ),
            },
            "seeded_mask_only": {
                "BLAKE3_or_KMAC_changes_RS_linear_map": False,
                "generator_random_access_solves_shared_RS_evaluation": False,
                "pass": False,
                "reason": (
                    "addressed coefficients remove persistent mask storage but "
                    "do not evaluate their dense RS contribution at queried points"
                ),
            },
        },
        "complete_row_exists": False,
        "RS_control_online_gate_pass": False,
        "disposition": (
            "NO_GO_current_strict_UD_RS_realization_under_one_scan_bounded_"
            "memory_and_3x_setup_gates"
        ),
        "escape_requires_owner_design_change": (
            "a concrete different code-switch/shared circuit with exact bytes and "
            "O(N+poly(q,log N)), or relaxation of a recorded hard resource gate"
        ),
        "prover_or_SIMT_implementation_authorized": False,
        "credit": False,
    }


def r08_new_carrier_tournament() -> dict[str, object]:
    """Owner-authorized admission boundary; no old negative screen is rerun."""
    return {
        "state": "OPEN_DUAL_TRACK_NO_ENTRANT_ADMITTED",
        "owner_choice": "1.A",
        "tracks": {
            "published_constructions": {
                "role": "baseline_and_controls_only",
                "admission_rule": "exact_and_independently_verifiable_costs_only",
                "implementation_authorized": False,
                "credit": False,
            },
            "C7_codesigned_circuit": {
                "role": "main_research_line",
                "pre_CPU_screen_requires": [
                    "complete algebraic relation and codec",
                    "exact query, byte, memory, setup and work census",
                    "soundness and privacy bridge to MAC, KV cache and malicious verifier",
                    "one packed scan in O(N+poly(q,log N))",
                ],
                "pre_CPU_screen_pass": False,
                "tiny_CPU_prototype_authorized": False,
                "carrier_independent_policy2_reference_implemented": True,
                "tiny_non_PCS_conformance_test_implemented": True,
                "credit_by_design": False,
            },
        },
        "strict_ud_RS_role": "algebraic_and_security_control_baseline_only",
        "strict_ud_RS_prover_implementation_authorized": False,
        "admission_requires_one_complete_row": [
            "source-linear constant independent of q",
            "one monotone packed scan and bounded working memory",
            "no complete codeword or model-sized scratch",
            "exact logical-g141 query/load and certificate-byte codec",
            "all four query-growth axes <=1.30",
            "complete certificate <=35/115 MB and <=3.5x",
            "persistent setup <=3x and wall <=990/5940 seconds",
            "policy-2 t-query privacy and dishonest-prover soundness bridge",
            "canonical Fp3 wire and unchanged interactive Q_FS=0 transcript",
        ],
        "excluded_without_rescreen": {
            "pure_fold_width": "R0.7 exhausted; width alone creates no shared evaluation circuit",
            "cross_round_joint_sampling": "bounded screen found no actual visible-Fp sharing",
            "ERA_to_BaseFold": "fails q growth and setup floor before C7 privacy/terminal work",
            "SwitchFold_QAFold_BrakeFold": (
                "no exact one-scan bounded-memory Goldilocks schedule; auxiliary full encodings"
            ),
            "current_strict_UD_RS": (
                "direct qN, or complete-codeword persistence/materialization beyond setup/memory"
            ),
            "TensorSwitch_Titan": "sqrt-weight proof law exceeds the scaling exponent",
            "ITC_univariate_compiler": "does not supply the required multilinear opening relation",
            "constrained_code_HVZK_2026_391": (
                "privacy compiler only; does not supply the missing shared base-code evaluation"
            ),
        },
        "entrants": [],
        "main_research_candidate_not_admitted": "C7-SPBT-v0",
        "candidate_lineage": (
            "C7-SPBT-v0 replaces the unsound logistic operator bridge while "
            "retaining C7-DV-SPQ-v0 as its quarantined secret-point terminal"
        ),
        "bounded_codesigned_rows": r08b_codesigned_construction_screen(),
        "selected_carrier": None,
        "complete_row_exists": False,
        "prover_or_SIMT_implementation_authorized": False,
        "credit": False,
    }


def r08b_codesigned_construction_screen() -> dict[str, object]:
    """Exact local eliminations plus the carrier-independent tiny seam."""
    rate_half_persisted_parity_amplification = 1 + FIELD_SYMBOL_BYTES / PACKED_WEIGHT_BYTES
    return {
        "state": "NO_CARRIER_ROW_COMPLETE_REFERENCE_SEAM_READY",
        "policy2_reference_seam": {
            "root_mask_suite": "C7-RM-B3XOF-v1",
            "root_mask_descriptor_bytes": 90,
            "root_mask_draw_cap": 6,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "salt_bytes": 32,
            "leaf_digest_bytes": 32,
            "single_leaf_opening_fixed_bytes": 1296,
            "single_leaf_opening_formula": "1296 + 32*tree_depth",
            "tiny_two_leaf_opening_bytes": 1328,
            "q_attempt_and_q_response_separate": True,
            "abort_consumption_nonrefundable": True,
            "Fp3_terminal_shared_Delta_tested": True,
            "in_memory_KV_CAS_replay_fork_tested": True,
            "durable_allocator_or_PCS": False,
            "credit": False,
        },
        "structured_coset_block": {
            "online_work": "N + B*log2(B) for one X^B-c residue block",
            "online_memory": "B_Fp",
            "packed_source_passes": 1,
            "query_independent_source_constant": True,
            "soundness_obstruction": (
                "one random coset is one worst-case hit: a delta-density error "
                "may occupy only a delta fraction of cosets"
            ),
            "independent_cosets_cost": "t*N + poly(t*B,logN)",
            "disposition": "NO_GO_query_miss_amplification_reintroduces_tN",
            "credit": False,
        },
        "persisted_rate_half_field_parity": {
            "canonical_packed_bytes_per_source": PACKED_WEIGHT_BYTES,
            "minimum_parity_Fp_bytes_per_source": FIELD_SYMBOL_BYTES,
            "amplification_before_tree": rate_half_persisted_parity_amplification,
            "exploratory_setup_cap": SETUP_EXPLORATORY_NUMERATOR
            / SETUP_EXPLORATORY_DENOMINATOR,
            "general_floor": "1 + 4*(1/rate-1)",
            "rate_needed_before_tree_for_3x": "rate >= 2/3",
            "disposition": "NO_GO_fixed_rate_half_is_5x_before_tree",
            "credit": False,
        },
        "bounded_tail_causal_streaming_encoder": {
            "scope": (
                "linear causal encoders emitting in packed-source order with "
                "only bounded delayed tail"
            ),
            "distance_bound": "last nonzero input affects only the delayed tail",
            "disposition": "NO_GO_constant_relative_distance_requires_linear_tail_or_noncausal_setup",
            "not_a_general_linear_circuit_lower_bound": True,
            "credit": False,
        },
        "complete_relation_codec": False,
        "exact_full_resource_census": False,
        "stateful_soundness_privacy_bridge": False,
        "one_scan_BatchOpenBlocks_proof": False,
        "pre_CPU_screen_pass": False,
        "credit": False,
    }


def r08c_secret_point_dv_carrier_screen() -> dict[str, object]:
    """Fail-closed specification for the co-designed secret-point carrier."""
    field_size = GOLDILOCKS_MODULUS**3
    profiles = {}
    for model, coefficient_bound, attempts in (
        (GPT2, 1 << 28, 512),
        (GEMMA_ENVELOPE, 1 << 35, 8192),
    ):
        degree_bound = coefficient_bound - 1
        root_error = Fraction(attempts * degree_bound, field_size)
        profiles[str(model["name"])] = {
            "coefficient_bound": coefficient_bound,
            "degree_bound": degree_bound,
            "R_root_control": attempts,
            "adaptive_first_false_accept_bound": (
                f"{root_error.numerator}/{root_error.denominator}"
            ),
            "certified_bits_if_secret_view_hypothesis_holds": certified_bits(
                root_error
            ),
        }
    all_roots_error = Fraction(
        ROOT_COUNT * R_MAX * ((1 << 35) - 1), field_size
    )
    optimistic_group_auth_bytes_per_weight = 32
    return {
        "state": "MAIN_RESEARCH_CANDIDATE_NOT_ADMITTED",
        "candidate_id": "C7-DV-SPQ-v0",
        "role": "codesigned_designated_verifier_secret_point_quotient_carrier",
        "ideal_relation": {
            "commitment_state": (
                "root-scoped secret shares of A=F(tau), never a clear evaluation"
            ),
            "univariate_identity": "F(tau)-v=(tau-r)*Q(tau)",
            "synthetic_division": [
                "q[d-1]=f[d]",
                "q[i-1]=f[i]+r*q[i] for i=d-1..1",
                "v=f[0]+r*q[0]",
            ],
            "packed_scan_direction": "one manifest-fixed reverse sequential scan",
            "packed_source_bytes_read": "2*N",
            "clear_F_tau_Q_tau_or_v": False,
            "terminal_values": "connection-scoped shared-Delta Fp3 MAC only",
        },
        "algebraic_screen": {
            "field": "Goldilocks_Fp3",
            "field_cardinality_bits": math.log2(field_size),
            "per_root_profiles": profiles,
            "all_roots_R_max_error_bound": (
                f"{all_roots_error.numerator}/{all_roots_error.denominator}"
            ),
            "all_roots_R_max_certified_bits_if_hypotheses_hold": certified_bits(
                all_roots_error
            ),
            "hypotheses": [
                "the false identity is fixed before access to tau-dependent output",
                "the malicious view leaks no tau predicate beyond terminal accept/reject",
                "every failed attempt and selective abort consumes the root counter",
                "one response-wide RLC leaves one nonzero terminal identity",
            ],
            "security_credit": False,
        },
        "required_new_apis": {
            "EnrollSecretPoint": (
                "bind the root polynomial and create persistent secret shares of F(tau) "
                "without revealing tau, F(tau), or weights"
            ),
            "ImportRootShareIntoMac": (
                "transfer the persistent share into a fresh connection MAC domain"
            ),
            "OpenQuotientIntoMac": (
                "authenticate Q(tau) from the fixed quotient in sublinear wire "
                "without revealing tau, Q(tau), or v"
            ),
        },
        "hard_open_obligations": {
            "operator_transcript_bridge": (
                "R0.8d scalarizes packed eq claims exactly on the logistic curve, "
                "but that curve is unsound in the current public sequential GKR transcript"
            ),
            "same_F_enrollment_binding": (
                "the root token and every later quotient must use the same packed F"
            ),
            "succinct_malicious_OpenQuotientIntoMac": (
                "known VOLE/OLE inner-product realizations expose linear corrections"
            ),
            "stateful_malicious_DV_privacy": (
                "cover collusion, retries, selective abort, share import, replay and forks"
            ),
            "exact_resource_codec": (
                "count setup traffic/time/temp data and every online byte/operation"
            ),
        },
        "published_and_natural_backend_controls": {
            "algebraic_PRF_authenticator": {
                "persistent_authenticator": "at_least_one_group_element_per_coefficient",
                "optimistic_group_element_bytes": optimistic_group_auth_bytes_per_weight,
                "packed_plus_authenticator_amplification": (
                    1
                    + optimistic_group_auth_bytes_per_weight
                    / PACKED_WEIGHT_BYTES
                ),
                "disposition": "NO_GO_setup_and_full_group_work",
            },
            "silent_VOLE_or_NIIP_inner_product": {
                "known_communication": "linear_in_vector_length",
                "silent_OLE_control": "2*N+o(N) field elements",
                "Fp3_wire_control_bytes": "48*N+o(N)",
                "disposition": "NO_GO_online_certificate",
            },
            "Merkle_commit_quotient_then_query": {
                "disposition": "NO_GO_second_scan_or_model_sized_tree_scratch",
            },
            "public_power_group_commitment": {
                "disposition": "NO_GO_N_point_setup_and_full_large_field_MSM",
            },
            "finite_hidden_credential_pool": {
                "credential_storage_is_not_the_blocker": True,
                "blocker": (
                    "pre-revealed challenge pools are unsound; hidden batch credential "
                    "construction still lacks near-linear setup"
                ),
                "disposition": "QUARANTINE",
            },
            "structured_coset_residue": {
                "disposition": (
                    "NO_GO_commit-order_or_tN_amplification; preserves_R08b_reason"
                ),
            },
        },
        "safe_future_online_boundary": {
            "root_activation": [
                "setup transcript and immutable artifact manifest verified before activation",
                "setup target/hard wall remains 900/990 or 5400/5940 seconds",
                "persistent setup remains inside the registered exploratory 3x ceiling",
                "failed setup creates no active root and no reusable privacy budget",
            ],
            "attempt": [
                "reserve q_attempt and the secret-point attempt before dependent output",
                "online process has read-only root/model access",
                "one manifest-fixed monotone packed scan and no source reopen",
                "abort burns all reserved correlations, masks and root counters",
                "promotion follows terminal MAC acceptance atomically",
            ],
            "online_only_prover_authorized_now": False,
        },
        "complete_relation_codec": False,
        "exact_full_resource_census": False,
        "stateful_soundness_privacy_bridge": False,
        "one_scan_OpenQuotientIntoMac_proof": False,
        "pre_CPU_screen_pass": False,
        "selected_carrier": False,
        "prover_or_SIMT_implementation_authorized": False,
        "credit": False,
    }


def r08d_eq_to_secret_point_bridge_screen() -> dict[str, object]:
    """Exact bridge identity plus the fail-closed public-sumcheck composition screen."""
    p = GOLDILOCKS_MODULUS
    t = 7
    n = 6
    points = []
    denominator = 1
    power = t
    for _ in range(n):
        factor = (1 + power) % p
        assert factor != 0
        points.append(power * pow(factor, p - 2, p) % p)
        denominator = denominator * factor % p
        power = power * power % p

    eq_weights = []
    for j in range(1 << n):
        eq_weight = 1
        for k, point in enumerate(points):
            eq_weight = eq_weight * (point if (j >> k) & 1 else 1 - point) % p
        assert eq_weight * denominator % p == pow(t, j, p)
        eq_weights.append(eq_weight)
    weights = [((17 * j + 3) % 257) for j in range(1 << n)]
    mle_value = sum(w * q for w, q in zip(weights, eq_weights)) % p
    univariate_value = sum(w * pow(t, j, p) for j, w in enumerate(weights)) % p
    assert mle_value == univariate_value * pow(denominator, p - 2, p) % p

    # If r_1 is revealed before r_0, the two possible r_0 values come from ±t.
    # Their monic vanishing quadratic has h(0)+h(1)=1, so any false gap can
    # be erased with a legal degree-two sumcheck message.
    s_plus = t * pow(1 + t, p - 2, p) % p
    s_minus = (-t) * pow(1 - t, p - 2, p) % p

    def attack_poly(x: int) -> int:
        return (x - s_plus) * (x - s_minus) % p

    assert attack_poly(s_plus) == 0
    assert attack_poly(s_minus) == 0
    assert (attack_poly(0) + attack_poly(1)) % p == 1

    # A generic independent MLE point is not on the scalar curve already for n=2.
    arbitrary_r0 = 2
    arbitrary_r1 = 3
    odds0 = arbitrary_r0 * pow(1 - arbitrary_r0, p - 2, p) % p
    odds1 = arbitrary_r1 * pow(1 - arbitrary_r1, p - 2, p) % p
    assert odds1 != odds0 * odds0 % p

    profiles = {}
    for model in (GPT2, GEMMA_ENVELOPE):
        segments = terminal_segments(model)
        profiles[str(model["name"])] = {
            "illustrative_weight_segment_points": segments["weight"],
            "illustrative_all_plane_segment_points": segments["total"],
            "screen_cap": TERMINAL_CLAIM_SCREEN_CAP,
            "inside_screen_cap": segments["total"] <= TERMINAL_CLAIM_SCREEN_CAP,
            "packed_source_bytes_one_reverse_scan": 2 * int(model["weights"]),
            "ideal_combined_two_party_Fp3_token_payload_lower_bound_bytes": (
                2 * 3 * FIELD_SYMBOL_BYTES * segments["weight"]
            ),
            "compiled_manifest": False,
        }

    return {
        "state": "ALGEBRAIC_BRIDGE_PASS_PUBLIC_SEQUENTIAL_TRANSCRIPT_NO_GO",
        "candidate_composition": "C7-DV-SPQ-v0+LogisticEqCurve+public_blind_GKR",
        "exact_bridge": {
            "curve": "r_k(t)=t^(2^k)/(1+t^(2^k))",
            "denominator": "D_n(t)=product_k(1+t^(2^k))",
            "identity": "eq(r(t),j)=t^j/D_n(t)",
            "segment_claim": "MLE(W_i,r_i(t_i))=F_i(t_i)/D_i(t_i)",
            "packed_claim": "sum_i beta_i*F_i(t_i)/D_i(t_i)",
            "padding": "canonical padded coefficients are zero",
            "nondegenerate_domain": "reject t with any 1+t^(2^k)=0 before activation",
            "arbitrary_point_condition": (
                "for nondegenerate r, scalarization exists iff "
                "r_k/(1-r_k)=t^(2^k) for every k"
            ),
            "small_exact_modular_self_check": True,
            "generic_independent_r_counterexample": True,
            "materialized_Mobius_transform_or_L": False,
            "conditional_source_work": "N+O(J*log(max padded_len))",
            "conditional_packed_passes": 1,
            "conditional_scan_direction": "manifest-fixed reverse",
            "profiles": profiles,
            "credit": False,
        },
        "transcript_attack": {
            "current_protocol_challenges": "public and sequential",
            "current_Lean_soundness_sample_space": "independent uniform F^n",
            "curve_sample_space": "at most |F| correlated vectors",
            "low_to_high": (
                "r_0 reveals t=r_0/(1-r_0), so every later challenge is predictable"
            ),
            "high_to_low": (
                "conditioned on r_k, adjacent r_(k-1) has the two values induced by ±t^(2^(k-1))"
            ),
            "degree_two_gap_eraser": (
                "h(X)=delta*(X-s_plus)*(X-s_minus), with h(0)+h(1)=delta "
                "and h(s_plus)=h(s_minus)=0"
            ),
            "any_coordinate_order": (
                "an ascent after a previously revealed lower power is deterministic; "
                "avoiding all ascents forces consecutive descending order and the two-root attack"
            ),
            "false_gap_can_be_carried_then_erased": True,
            "small_exact_modular_attack_check": True,
            "existing_sumcheck_soundness_theorem_applies": False,
            "disposition": "NO_GO_for_current_public_sequential_blind_GKR_composition",
        },
        "bounded_escape_screen": {
            "independent_round_challenges": {
                "soundness_shape": "retains existing theorem",
                "secret_point_scalarization": False,
                "disposition": "CONTROL_not_a_univariate_SPQ_bridge",
            },
            "projective_monomial_sumcheck": {
                "benefit": "removes D_i and makes packed truth-table values monomial coefficients",
                "blocker": "the same correlated public challenge attack remains",
                "disposition": "NO_GO_as_transcript_escape",
            },
            "all_variable_univariate_skip": {
                "benefit": "one independent scalar challenge",
                "round_polynomial_degree": "Theta(N)",
                "blocker": "linear message/oracle or another PCS, violating the wire/recursion gate",
                "disposition": "NO_GO",
            },
            "bounded_univariate_skip": {
                "benefit": "only fuses a bounded number of coordinates",
                "blocker": "leaves multiple independent scalars and a multivariate terminal",
                "disposition": "CONTROL_not_a_univariate_SPQ_bridge",
            },
            "secret_or_encrypted_sumcheck_challenges": {
                "blocker": (
                    "the current blind-GKR prover needs public challenges to form later messages; "
                    "no bounded-wire secure folding refinement is supplied"
                ),
                "disposition": "QUARANTINE_new_operator_protocol_required",
            },
            "complete_escape_row_exists": False,
        },
        "functional_basis_bridge_conditional_pass": True,
        "public_GKR_composition_pass": False,
        "complete_relation_codec": False,
        "exact_full_resource_census": False,
        "stateful_soundness_privacy_bridge": False,
        "one_scan_OpenQuotientIntoMac_proof": False,
        "pre_CPU_screen_pass": False,
        "selected_carrier": False,
        "prover_or_SIMT_implementation_authorized": False,
        "credit": False,
    }


def r08e_secret_point_butterfly_transform_screen() -> dict[str, object]:
    """Check the exact reduction and fail closed on its delayed-opening gap."""
    p = GOLDILOCKS_MODULUS
    size = 1 << 6
    weights = [((19 * index + 7) % 263) for index in range(size)]
    challenges = [3, 5, 11, 17, 29, 43]
    levels: list[list[int]] = []
    folded = weights
    for challenge in challenges:
        next_fold = []
        complement = []
        for index in range(0, len(folded), 2):
            even = folded[index]
            odd = folded[index + 1]
            next_fold.append((even + challenge * (odd - even)) % p)
            complement.append((even - odd) % p)
        levels.append(complement)
        folded = next_fold
    terminal = folded[0]
    assert sum(len(level) for level in levels) + 1 == size

    def evaluate(coefficients: list[int], point: int) -> int:
        value = 0
        for coefficient in reversed(coefficients):
            value = (value * point + coefficient) % p
        return value

    tau = 47
    lhs = evaluate(weights, tau)
    rhs = 0
    prefix = 1
    tau_power = tau
    for challenge, complement in zip(challenges, levels):
        selector = (challenge - (1 - challenge) * tau_power) % p
        rhs = (
            rhs
            + prefix
            * selector
            * evaluate(complement, tau_power * tau_power % p)
        ) % p
        prefix = prefix * (1 + tau_power) % p
        tau_power = tau_power * tau_power % p
    rhs = (rhs + prefix * terminal) % p
    assert lhs == rhs

    recovered = [terminal]
    for challenge, complement in reversed(list(zip(challenges, levels))):
        parent = []
        for child, difference in zip(recovered, complement):
            even = (child + challenge * difference) % p
            odd = (child - (1 - challenge) * difference) % p
            parent.extend((even, odd))
        recovered = parent
    assert recovered == weights

    field_size = p**3
    profiles = {}
    for model, coefficient_bound, q_open in (
        (GPT2, 1 << 28, 831),
        (GEMMA_ENVELOPE, 1 << 35, 1055),
    ):
        weight_count = int(model["weights"])
        packed_bytes = PACKED_WEIGHT_BYTES * weight_count
        segment_count = terminal_segments(model)["total"]
        # For minimally power-of-two-padded nonempty segments,
        # N <= M_total < 2N. Z_1 is base-field-valued; every later Z and y
        # is Fp3, so the canonical dense transform uses exactly 16*M_total B.
        dense_aux_min_bytes = 16 * weight_count
        dense_aux_strict_upper_bytes = 32 * weight_count
        minimum_logical_fp_symbols = 2 * weight_count
        minimum_logical_leaves = ceil_div(
            minimum_logical_fp_symbols, LOGICAL_LEAF_SYMBOLS
        )
        raw_query_hit_upper = min(
            Fraction(1), Fraction(q_open, minimum_logical_leaves)
        )
        raw_query_miss_lower = 1 - raw_query_hit_upper
        response_error = Fraction(
            (coefficient_bound - 1) + (segment_count - 1), field_size
        )
        connection_error = R_MAX * response_error
        profiles[str(model["name"])] = {
            "packed_weight_scalars": weight_count,
            "packed_source_bytes_one_scan": packed_bytes,
            "illustrative_all_plane_segments": segment_count,
            "conservative_max_segment_coefficient_bound": coefficient_bound,
            "transform_butterflies": "M_total-J, hence <2*N-J",
            "transform_output_coefficients": "M_total with N<=M_total<2*N",
            "canonical_dense_auxiliary_bytes": {
                "formula": "16*M_total",
                "why": "M_total/2 Fp limbs at Z_1 plus M_total/2 Fp3 values",
                "minimum": dense_aux_min_bytes,
                "strict_upper_bound": dense_aux_strict_upper_bytes,
                "minimum_additional_bytes_over_packed_source": (
                    dense_aux_min_bytes / packed_bytes
                ),
                "minimum_packed_plus_retained_aux_amplification": (
                    (packed_bytes + dense_aux_min_bytes) / packed_bytes
                ),
            },
            "optimistic_two_party_orbit_token_control": {
                "combined_Fp3_bytes_minimum": 48 * weight_count,
                "packed_plus_tokens_amplification_minimum": (
                    (packed_bytes + 48 * weight_count) / packed_bytes
                ),
            },
            "raw_transform_merkle_sampling_control": {
                "q_open_control": q_open,
                "minimum_logical_g141_leaves": minimum_logical_leaves,
                "single_bad_leaf_hit_probability_upper": (
                    f"{raw_query_hit_upper.numerator}/{raw_query_hit_upper.denominator}"
                ),
                "single_bad_leaf_miss_probability_lower": (
                    f"{raw_query_miss_lower.numerator}/{raw_query_miss_lower.denominator}"
                ),
                "miss_certified_bits_upper": certified_bits(
                    raw_query_miss_lower
                ),
            },
            "conditional_fixed_before_beta_tau_soundness": {
                "per_response_error_bound": (
                    f"{response_error.numerator}/{response_error.denominator}"
                ),
                "per_response_certified_bits": certified_bits(response_error),
                "R_max_connection_error_bound": (
                    f"{connection_error.numerator}/{connection_error.denominator}"
                ),
                "R_max_connection_certified_bits": certified_bits(
                    connection_error
                ),
                "passes_110_bit_component_reserve": (
                    certified_bits(connection_error) >= 110
                ),
            },
            "compiled_segment_manifest": False,
        }

    return {
        "state": "EXACT_REDUCTION_PASS_DELAYED_OPENING_REALIZATION_NO_GO",
        "candidate_id": "C7-SPBT-v0",
        "role": "secret_point_butterfly_transform_reduction_for_independent_GKR_points",
        "architecture_summary": (
            "one causal response proof; session VOLE-MAC boundaries and weight "
            "evaluations; one response-wide PCS-to-MAC opening; append-only "
            "authenticated KV transition"
        ),
        "exact_relation": {
            "fold": "Y_(l+1)[i]=(1-r_l)*P_l[2i]+r_l*P_l[2i+1]",
            "complement": "Z_(l+1)[i]=P_l[2i]-P_l[2i+1]",
            "inverse": [
                "P_l[2i]=Y_(l+1)[i]+r_l*Z_(l+1)[i]",
                "P_l[2i+1]=Y_(l+1)[i]-(1-r_l)*Z_(l+1)[i]",
            ],
            "level_identity": (
                "P_l(X)=(1+X)Y_(l+1)(X^2)+"
                "(r_l-(1-r_l)X)Z_(l+1)(X^2)"
            ),
            "unrolled_identity": (
                "P_0(X)=D_n(X)*y+sum_l D_l(X)*c_l(X)*"
                "Z_(l+1)(X^(2^(l+1)))"
            ),
            "D_l": "product_(h<l)(1+X^(2^h))",
            "c_l": "r_l-(1-r_l)X^(2^l)",
            "degree_bound": "strictly less than M",
            "output_coefficients": "sum_l M/2^(l+1)+1=M",
            "pair_matrix_determinant": "-1 for every r_l",
            "bijection": "W <-> (Z_1,...,Z_n,y)",
            "final_y": "MLE(W,r) with ordinary independent GKR challenges",
            "small_exact_modular_identity_and_inverse_check": True,
        },
        "transcript": [
            "fix C_W, response relation, independent GKR challenges r and authenticated claims",
            "one packed scan emits the canonical tagged complement stream and fixes C_Z,e",
            "sample tau after all transform commitments are fixed and derive every query vector",
            "sample response-wide beta after every root, claim, handle and query vector is fixed",
            "open the C_W and C_Z,e structured linear evaluations directly into the shared-Delta Fp3 MAC",
            "settle every residual and y-v in one terminal RLC, then atomically promote or burn",
        ],
        "conditional_soundness": {
            "tau_term": "at most (M_max-1)/|Fp3| for every false residual evaluating to zero",
            "beta_term": "at most (J-1)/|Fp3| for scalar RLC cancellation after tau",
            "profiles": profiles,
            "dishonest_prover_bridge_complete": False,
            "credit": False,
        },
        "one_scan_transform_schedule": {
            "source_reads": 1,
            "source_bytes": "2*N",
            "source_order": "canonical monotone packed order with virtual zero padding",
            "algorithm": "binary carry stack; emit tagged Z_l coefficients in increasing local index",
            "Fp3_pending_values": "at most one per level",
            "commitment_frontier": "one g141 leaf buffer plus O(log N) hashes",
            "butterflies": "M_total-J < 2*N-J",
            "multiplications": "one extension-scalar multiply per butterfly",
            "add_subtracts": "two per butterfly",
            "response_auxiliary_hash_input": "16*M_total bytes in the typed dense codec",
            "second_source_scan": False,
            "model_sized_scratch_if_stream_is_discarded": False,
            "conditional_transform_only_pass": True,
            "complete_delayed_opening_pass": False,
        },
        "commit_challenge_open_triangle": {
            "tau_before_C_Z": {
                "attack": "one scalar identity leaves M transform coefficients adaptable",
                "disposition": "NO_GO_unsound",
            },
            "tau_after_C_Z_retain_transform": {
                "cost": "16*M_total response-local bytes; at least 9x packed including source",
                "disposition": "NO_GO_model_sized_scratch",
            },
            "tau_after_C_Z_recompute": {
                "cost": "a second packed source scan",
                "disposition": "NO_GO_second_scan",
            },
            "hidden_tau_during_stream": {
                "missing_primitive": (
                    "malicious private streaming inner product/OPE into MAC "
                    "with sublinear wire and no per-coefficient correction"
                ),
                "disposition": "OPEN_PRIMITIVE_NOT_A_COMPLETE_ROW",
            },
            "exact_tau_independent_sketch": {
                "observation": (
                    "supporting exact evaluation at M distinct later points is injective "
                    "on degree-<M polynomials"
                ),
                "scope": "information-theoretic sketches only; not a PCS lower bound",
                "disposition": "NO_GO_sublinear_exact_plain_sketch",
            },
        },
        "policy2_privacy": {
            "transform_is_invertible": True,
            "unmasked_transform_disclosure_equivalent_to_weight_disclosure": True,
            "C_Z_lifecycle": "fresh attempt-bound response commitment inside C_B,e",
            "visible_unit": "one g141 leaf is 141 masked Fp symbols; Fp3 occupies three",
            "all_failed_attempts_and_selective_aborts_burn": True,
            "terminal_transform_and_weight_evaluations_cleartext": False,
            "required_theorem": (
                "adaptive hiding for roots and masked transform leaves plus same-W binding, "
                "global Q_root accounting and malicious-DV view simulation"
            ),
            "policy2_query_vector_compiled": False,
            "stateful_privacy_theorem_complete": False,
        },
        "bounded_controls": {
            "raw_Merkle_local_checks": {
                "reason": "the invertible rate-1 transform has no distance; one bad leaf can change the claim",
                "disposition": "NO_GO_query_miss_is_near_one",
            },
            "rate_half_code_wrapper": {
                "reason": "restores the already rejected full codeword/setup or online materialization",
                "disposition": "NO_GO_current_realization",
            },
            "preprocessed_secret_point_orbit": {
                "reason": "the square-root/sign orbit doubles per level and contains Theta(M) Fp3 tokens",
                "disposition": "NO_GO_at_least_25x_packed_for_two_party_tokens",
            },
            "finite_public_tau_pool": {
                "reason": "110-bit challenge entropy requires an infeasible pool and reuse adds privacy leakage",
                "disposition": "NO_GO",
            },
            "all_round_symbolic_sumcheck_commitment": {
                "reason": (
                    "one scalar keeps the R0.8d correlated-challenge attack as a polynomial identity; "
                    "causal degree-two prefix tables grow as 3^round"
                ),
                "disposition": "NO_GO_without_another_PCS",
            },
            "coefficient_extraction_convolution": {
                "reason": (
                    "exact middle-coefficient relation materializes linear convolution remainders "
                    "for each matmul/token or needs persistent FFT transforms"
                ),
                "disposition": "NO_GO_response_scratch_or_setup",
            },
            "published_group_or_fold_controls": {
                "reason": (
                    "KZG-style reductions require group setup/MSMs; foldable-code PCS restores "
                    "a complete encoded oracle; known space-efficient PCS assumes multi-pass input"
                ),
                "disposition": "CONTROL_not_C7_admission",
            },
        },
        "persistent_setup": {
            "transform_algebra_requires_new_persistent_oracle": False,
            "discarded_stream_path_setup_amplification": "unchanged in principle",
            "retained_dense_transform_or_orbit_within_3x": False,
            "setup_wall_test_authorized": False,
            "refresh_test_authorized": False,
        },
        "proof_codec": {
            "one_fresh_transform_root_digest_lower_bound_bytes": HASH_BYTES,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "challenge_mode": SELECTED_CHALLENGE_MODE,
            "Q_FS": SELECTED_FIAT_SHAMIR_QUERY_BOUND,
            "delayed_opening_queries_paths_and_MAC_frames_compiled": False,
            "complete_certificate_bytes_known": False,
        },
        "algebraic_relation_complete": True,
        "exact_full_resource_census": False,
        "stateful_soundness_privacy_bridge": False,
        "one_scan_transform_only_proof": True,
        "one_scan_complete_opening_proof": False,
        "pre_CPU_screen_pass": False,
        "selected_carrier": False,
        "prover_or_SIMT_implementation_authorized": False,
        "credit": False,
    }


def constant_fold_schedule(num_variables: int, factor: int) -> list[int]:
    """Mirror the retained WHIR control's clamp-to-direct-send schedule."""
    remaining = num_variables
    schedule = []
    while True:
        folded = min(factor, remaining)
        schedule.append(folded)
        remaining -= folded
        if remaining <= WHIR_DIRECT_SEND_VARIABLES:
            return schedule


def pareto_schedules(candidates: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keep one deterministic representative for each undominated (q, Fp) pair."""
    unique: dict[tuple[int, int], dict[str, object]] = {}
    for candidate in candidates:
        key = (int(candidate["q_open"]), int(candidate["Fp_positions"]))
        incumbent = unique.get(key)
        if incumbent is None or tuple(candidate["schedule"]) < tuple(
            incumbent["schedule"]
        ):
            unique[key] = candidate
    frontier = []
    best_fp: int | None = None
    for candidate in sorted(
        unique.values(),
        key=lambda item: (
            int(item["q_open"]),
            int(item["Fp_positions"]),
            tuple(item["schedule"]),
        ),
    ):
        fp_positions = int(candidate["Fp_positions"])
        if best_fp is None or fp_positions < best_fp:
            frontier.append(candidate)
            best_fp = fp_positions
    return frontier


def variable_fold_pareto_frontier(
    num_variables: int, extension_limbs: int
) -> list[dict[str, object]]:
    """Enumerate every tail after the selected k0=4, pruning exact Pareto states."""
    first_fold = 4
    first_queries = strict_ud_query_count(STRICT_UD_SECURITY_BITS, 1)
    states: dict[tuple[int, int], list[dict[str, object]]] = {
        (num_variables - first_fold, first_fold): [
            {
                "schedule": [first_fold],
                "q_open": first_queries,
                "Fp_positions": first_queries * (1 << first_fold),
            }
        ]
    }
    accepted = []
    while states:
        next_states: dict[tuple[int, int], list[dict[str, object]]] = {}
        for (remaining, log_inv_rate), candidates in states.items():
            if remaining <= WHIR_DIRECT_SEND_VARIABLES:
                accepted.extend(candidates)
                continue
            queries = strict_ud_query_count(
                STRICT_UD_SECURITY_BITS, log_inv_rate
            )
            for candidate in candidates:
                for fold in range(1, remaining + 1):
                    child = {
                        "schedule": [*candidate["schedule"], fold],
                        "q_open": int(candidate["q_open"]) + queries,
                        "Fp_positions": int(candidate["Fp_positions"])
                        + queries * (1 << fold) * extension_limbs,
                    }
                    key = (remaining - fold, log_inv_rate + fold - 1)
                    next_states.setdefault(key, []).append(child)
        states = {
            key: pareto_schedules(candidates)
            for key, candidates in next_states.items()
        }
    return pareto_schedules(accepted)


def variable_fold_pair_screen(extension_limbs: int) -> dict[str, object]:
    """Show whether fold-width choice alone can meet both 1.05 growth gates."""
    small = variable_fold_pareto_frontier(
        (int(GPT2["weights"]) - 1).bit_length(), extension_limbs
    )
    large = variable_fold_pareto_frontier(
        (int(GEMMA_ENVELOPE["weights"]) - 1).bit_length(), extension_limbs
    )
    paired = []
    for small_row in small:
        for large_row in large:
            q_growth = Fraction(
                int(large_row["q_open"]), int(small_row["q_open"])
            )
            fp_growth = Fraction(
                int(large_row["Fp_positions"]),
                int(small_row["Fp_positions"]),
            )
            paired.append(
                (
                    max(q_growth, fp_growth),
                    q_growth,
                    fp_growth,
                    tuple(small_row["schedule"]),
                    tuple(large_row["schedule"]),
                    small_row,
                    large_row,
                )
            )
    best = min(paired, key=lambda item: item[:5])
    score, q_growth, fp_growth, _, _, small_best, large_best = best
    original_gate = Fraction(
        ORIGINAL_QUERY_GROWTH_NUMERATOR,
        ORIGINAL_QUERY_GROWTH_DENOMINATOR,
    )
    active_gate = Fraction(
        ACTIVE_QUERY_GROWTH_NUMERATOR, ACTIVE_QUERY_GROWTH_DENOMINATOR
    )
    any_pair_passes = any(
        q <= original_gate and fp <= original_gate for _, q, fp, *_ in paired
    )
    any_pair_passes_active = any(
        q <= active_gate and fp <= active_gate for _, q, fp, *_ in paired
    )
    required_q_factor = original_gate / q_growth
    required_fp_factor = original_gate / fp_growth
    required_uniform_factor = original_gate / score
    active_q_limit = (
        int(small_best["q_open"]) * ACTIVE_QUERY_GROWTH_NUMERATOR
        // ACTIVE_QUERY_GROWTH_DENOMINATOR
    )
    active_fp_limit = (
        int(small_best["Fp_positions"]) * ACTIVE_QUERY_GROWTH_NUMERATOR
        // ACTIVE_QUERY_GROWTH_DENOMINATOR
    )
    return {
        "scope": (
            "all_integer_tail_fold_widths_after_rate1_k0_4_under_registered_"
            f"strict_ud_query_formula_direct_send_6_and_Fp{extension_limbs}_unstacking"
        ),
        "extension_degree": extension_limbs,
        "pareto_no_dummy_padding": True,
        "gpt2_frontier_size": len(small),
        "gemma_31b_frontier_size": len(large),
        "any_pareto_pair_passes_q_and_Fp_1_05": any_pair_passes,
        "any_pareto_pair_passes_q_and_Fp_active_1_30": (
            any_pair_passes_active
        ),
        "best_minimax_pair": {
            "gpt2": small_best,
            "gemma_31b": large_best,
            "q_growth": float(q_growth),
            "Fp_growth": float(fp_growth),
            "max_growth": float(score),
            "required_large_q_factor_for_1_05": float(required_q_factor),
            "required_large_q_reduction_percent_for_1_05": float(
                100 * (1 - required_q_factor)
            ),
            "required_large_Fp_factor_for_1_05": float(required_fp_factor),
            "required_large_Fp_reduction_percent_for_1_05": float(
                100 * (1 - required_fp_factor)
            ),
            "required_uniform_common_factor_for_both_1_05": float(
                required_uniform_factor
            ),
            "required_uniform_common_reduction_percent_for_both_1_05": float(
                100 * (1 - required_uniform_factor)
            ),
            "axis_gaps_are_nonfungible": True,
            "Fp_positions_semantics": (
                "unstacked_Fp_position_formula_control_not_compiled_"
                "S_visible_Fp_leaf_payload"
            ),
            "owner_1_30_query_axis_gate": {
                "passes_q_and_unstacked_Fp_controls": (
                    q_growth <= active_gate and fp_growth <= active_gate
                ),
                "q_limit_for_selected_gpt2_denominator": active_q_limit,
                "q_headroom_draws": active_q_limit
                - int(large_best["q_open"]),
                "Fp_position_limit_for_selected_gpt2_denominator": (
                    active_fp_limit
                ),
                "Fp_position_headroom": active_fp_limit
                - int(large_best["Fp_positions"]),
                "does_not_compile_Z_atom_U_leaf_or_S_visible_Fp": True,
                "complete_row_pass": False,
            },
        },
        "q_min_endpoints": {
            "gpt2": min(small, key=lambda row: int(row["q_open"])),
            "gemma_31b": min(large, key=lambda row: int(row["q_open"])),
        },
        "Fp_min_endpoints": {
            "gpt2": min(small, key=lambda row: int(row["Fp_positions"])),
            "gemma_31b": min(large, key=lambda row: int(row["Fp_positions"])),
        },
        "disposition": (
            "pure_fold_width_choice_rejected_under_original_1_05; owner_1_30_"
            "fallback_retains_best_formula_pair_but_not_a_complete_codec_row"
        ),
        "not_a_universal_WHIR_lower_bound": True,
        "credit": False,
    }


def r07_bounded_closure_screens() -> dict[str, object]:
    """Record only the two owner-authorized post-Pareto bounded screens."""
    joint_small_fp = 19_104 - 1_130
    joint_large_fp = 24_128 - 1_576
    era_small_q = 2_370
    era_large_q = 3_602
    era_small_fp = 68_612
    era_large_fp = 71_076
    return {
        "scope": [
            "cross_round_joint_sampling_with_actual_visible_Fp_derivation",
            "genuinely_different_code_switch",
        ],
        "pure_fold_width_search_reopened": False,
        "cross_round_joint_sampling": {
            "candidate": (
                "iid path seeds with balanced quotient projections; an "
                "adjacent folded coordinate may be derived from the prior "
                "opened fiber and omitted from the later payload"
            ),
            "required_soundness_relation": (
                "all round roots fixed before path seeds; balanced projections; "
                "a fixed discrepancy set B_i of density delta_i for every "
                "failed extraction; miss <= sum_i(1-delta_i)^t_i plus gap, "
                "binding and MAC terms"
            ),
            "required_privacy_relation": (
                "for every adaptive abort prefix T, im(A_T*G_W) subseteq "
                "im(A_T*G_R), with every revealed or derived coordinate "
                "charged to the global root budget"
            ),
            "q_open": {"gpt2": 831, "gemma_31b": 1_054},
            "q_growth": 1_054 / 831,
            "maximum_adjacent_Fp_derivation": {
                "saved": {"gpt2": 1_130, "gemma_31b": 1_576},
                "remaining": {
                    "gpt2": joint_small_fp,
                    "gemma_31b": joint_large_fp,
                },
                "growth": joint_large_fp / joint_small_fp,
            },
            "why_q_does_not_shrink": (
                "each round/root fiber remains a distinct authenticated oracle "
                "opening; counting one shared seed as one PCS query hides work"
            ),
            "why_soundness_is_new": (
                "published WHIR samples links before the next root; delaying "
                "all samples needs a new strict-UD/RBR extractor and transcript"
            ),
            "why_resources_remain_open": (
                "distinct roots do not share Merkle paths, and sequential fold "
                "challenges give no one-scan bounded-memory root schedule"
            ),
            "missing_hypotheses": [
                "BalancedJointPath",
                "DelayedJointWHIRStrictUD_RBR",
                "JointFoldAdaptiveRSZK_image_criterion",
                "derivation_aware_g141_leaf_codec_and_exact_census",
                "one_scan_bounded_memory_root_open_schedule",
            ],
            "passes_original_1_05_q_and_Fp_controls": False,
            "disposition": "NO_GO",
            "not_a_universal_impossibility": True,
            "credit": False,
        },
        "different_code_switch": {
            "era_to_basefold_exact_formula_control": {
                "q_open": {"gpt2": era_small_q, "gemma_31b": era_large_q},
                "q_growth": era_large_q / era_small_q,
                "unstacked_Fp": {
                    "gpt2": era_small_fp,
                    "gemma_31b": era_large_fp,
                },
                "unstacked_Fp_growth": era_large_fp / era_small_fp,
                "optimistic_setup_amplification_floor": 1
                + 140.8 / 141
                + 66 / 141,
                "minimum_materialized_25_stack_bytes_over_packed": 6.25,
                "passes_active_1_30_q_gate": False,
                "passes_setup_hard_2_10": False,
            },
            "switchfold_qafold_brakefold": (
                "NO_GO: no exact e27/e35 C7 census; per-level auxiliary/carry "
                "roots, full encodings, O(N log N) WHT path, unbounded measured "
                "memory, clear evaluations and no policy-2 terminal/privacy bridge"
            ),
            "hvzk_codeswitch_2026_391": {
                "alphabet_width_asymptotic_growth_control": 35 / 27,
                "disposition": (
                    "NO_GO: below 1.30 only asymptotically before constants; "
                    "no exact leaf/path/setup/opener row and HVZK is not "
                    "adaptive stateful malicious-DV privacy"
                ),
            },
            "ligesis": (
                "NO_GO: full RS and secondary PCS/setup with no exact paired "
                "census or stateful hiding theorem"
            ),
            "itc3": (
                "NO_GO: univariate compiler; multilinear linear-time "
                "adaptation is not supplied"
            ),
            "complete_row_found_under_original_1_05": False,
            "complete_row_found_under_active_1_30": False,
            "disposition": "NO_GO",
            "credit": False,
        },
        "selected_carrier_original_1_05_disposition": "NO_GO",
        "owner_1_30_fallback": {
            "active": True,
            "applies_componentwise_to": [
                "logical_pcs_samples",
                "zk_alphabet_query_atoms",
                "unique_opened_leaves",
                "visible_masked_base_field_symbols",
            ],
            "retained_formula_candidate": (
                "Fp2_best_pure_fold_pair_831_19104_to_1054_24128"
            ),
            "known_q_and_unstacked_Fp_controls_pass": True,
            "unknown_cells": ["Z_atom", "U_leaf", "S_visible_Fp"],
            "complete_row_pass": False,
            "does_not_change_weight_wire_1_05": True,
            "does_not_change_setup_proof_security_or_resource_gates": True,
            "Fp3_closes_only_algebraic_axis": True,
            "credit": False,
        },
        "credit": False,
    }


def rs_whir_constant_fold_control(
    model: dict[str, object], starting_log_inv_rate: int, factor: int
) -> dict[str, object]:
    """Formula control only: it deliberately omits the concrete C7 codec."""
    weights = int(model["weights"])
    variables = (weights - 1).bit_length()
    padded_message_symbols = 1 << variables
    schedule = constant_fold_schedule(variables, factor)
    log_inv_rate = starting_log_inv_rate
    remaining_variables = variables
    rounds = []
    q_open = 0
    unstacked_fp_positions_control = 0
    fold_challenge_count = 0
    fold_gap_error_upper = Fraction(0, 1)
    for round_index, fold in enumerate(schedule):
        queries = strict_ud_query_count(STRICT_UD_SECURITY_BITS, log_inv_rate)
        fp_limbs_control = 1 if round_index == 0 else FP_LIMBS_PER_FP2
        fp_positions = queries * (1 << fold) * fp_limbs_control
        bad_value_count_upper_bound = 1 << (
            remaining_variables + log_inv_rate
        )
        challenge_gap_error_upper = Fraction(
            bad_value_count_upper_bound, GOLDILOCKS_FP2_CARDINALITY
        )
        certified_challenge_bits = certified_bits(challenge_gap_error_upper)
        round_gap_error_upper = fold * challenge_gap_error_upper
        rounds.append(
            {
                "round": round_index,
                "folding_factor": fold,
                "log_inv_rate_before_fold": log_inv_rate,
                "strict_ud_queries": queries,
                "fp_limbs_control": fp_limbs_control,
                "unstacked_fp_positions_control": fp_positions,
                "fold_challenge_count": fold,
                "strict_UD_bad_value_count_upper_bound_per_challenge": (
                    bad_value_count_upper_bound
                ),
                "strict_UD_per_challenge_gap_error_upper_bound": (
                    f"{challenge_gap_error_upper.numerator}/"
                    f"{challenge_gap_error_upper.denominator}"
                ),
                "strict_UD_per_challenge_certified_bits_Fp2_control": (
                    certified_challenge_bits
                ),
                "strict_UD_round_gap_error_upper_bound": (
                    f"{round_gap_error_upper.numerator}/"
                    f"{round_gap_error_upper.denominator}"
                ),
            }
        )
        q_open += queries
        unstacked_fp_positions_control += fp_positions
        fold_challenge_count += fold
        fold_gap_error_upper += round_gap_error_upper
        remaining_variables -= fold
        log_inv_rate += fold - 1

    domain_exponent = variables + starting_log_inv_rate
    domain_symbols = 1 << domain_exponent
    leaves = ceil_div(domain_symbols, LOGICAL_LEAF_SYMBOLS)
    tree_bytes = (2 * leaves - 1) * HASH_BYTES
    packed_bytes = weights * PACKED_WEIGHT_BYTES
    static_floor = packed_bytes + tree_bytes
    rotation_floor = packed_bytes + 2 * tree_bytes
    first_fold = schedule[0]
    folded_domain_exponent = domain_exponent - first_fold
    starting_gap_error_upper = Fraction(
        1 << domain_exponent, GOLDILOCKS_FP2_CARDINALITY
    )
    certified_gap_bits = certified_bits(starting_gap_error_upper)
    certified_lifetime_bits = certified_gap_bits - math.log2(R_MAX)
    certified_all_fold_bits = certified_bits(fold_gap_error_upper)
    return {
        "role": "theorem_carrier_formula_control",
        "model": model["name"],
        "security_bits": STRICT_UD_SECURITY_BITS,
        "security_bits_scope": "per_proximity_phase_before_round_union_and_algebraic_terms",
        "round_union_security_included": False,
        "starting_log_inv_rate": starting_log_inv_rate,
        "constant_folding_factor": factor,
        "num_variables": variables,
        "padded_message_symbols": padded_message_symbols,
        "zk_randomness_symbols_reserved": 0,
        "unused_padded_message_symbols": padded_message_symbols - weights,
        "zk_randomness_row_capacity_compiled": False,
        "domain_growth_for_zk_randomness_derived": False,
        "folding_schedule": schedule,
        "round_count_including_final_proximity_phase": len(schedule),
        "fold_challenge_count": fold_challenge_count,
        "rounds": rounds,
        "q_open_formula_control": q_open,
        "unstacked_fp_positions_formula_control": unstacked_fp_positions_control,
        "zk_auxiliary_atoms_included": False,
        "logical_leaf_indices_compiled": False,
        "U_leaf": None,
        "S_visible_Fp": None,
        "H_sibling": None,
        "initial_domain_exponent": domain_exponent,
        "initial_domain_symbols": domain_symbols,
        "first_fold_width_Fp_symbols": 1 << first_fold,
        "logical_g141_flat_stream_no_row_alignment_padding": True,
        "maximum_g141_leaves_touched_by_one_first_fold_row": ceil_div(
            (1 << first_fold) + LOGICAL_LEAF_SYMBOLS - 1,
            LOGICAL_LEAF_SYMBOLS,
        ),
        "exact_g141_leaf_union_compiled": False,
        "post_first_fold_domain_exponent": folded_domain_exponent,
        "retained_goldilocks_folded_domain_supported": (
            folded_domain_exponent <= GOLDILOCKS_TWO_ADICITY
        ),
        "published_goldilocks_initial_domain_scope_supported": (
            domain_exponent <= GOLDILOCKS_TWO_ADICITY
        ),
        "retained_domain_rule_proven_for_C7": False,
        "strict_UD_starting_gap_error_upper_bound": (
            f"{starting_gap_error_upper.numerator}/"
            f"{starting_gap_error_upper.denominator}"
        ),
        "strict_UD_starting_gap_certified_bits_Fp2_control": certified_gap_bits,
        "strict_UD_after_R_max_union_certified_bits_control": certified_lifetime_bits,
        "strict_UD_inherited_bound_certifies_110_per_response": (
            certified_gap_bits >= TARGET_RESPONSE_EVENT_BITS
        ),
        "strict_UD_inherited_bound_certifies_78_after_R_max_before_other_terms": (
            certified_lifetime_bits >= 78
        ),
        "strict_UD_all_fold_gap_error_upper_bound": (
            f"{fold_gap_error_upper.numerator}/{fold_gap_error_upper.denominator}"
        ),
        "strict_UD_all_fold_union_certified_bits_Fp2_control": (
            certified_all_fold_bits
        ),
        "strict_UD_all_fold_after_R_max_certified_bits_control": (
            certified_all_fold_bits - math.log2(R_MAX)
        ),
        "strict_UD_inherited_all_fold_bound_certifies_78_after_R_max": (
            certified_all_fold_bits - math.log2(R_MAX) >= 78
        ),
        "security_amplification_selected": False,
        "interactive_pow_bridge_counted": False,
        "static_digest_only_floor_bytes": static_floor,
        "static_digest_only_floor_amplification": static_floor / packed_bytes,
        "dual_root_rotation_floor_bytes": rotation_floor,
        "dual_root_rotation_floor_amplification": rotation_floor / packed_bytes,
        "static_setup_target_pass": static_floor * SETUP_TARGET_DENOMINATOR
        <= packed_bytes * SETUP_TARGET_NUMERATOR,
        "static_setup_hard_pass": static_floor * SETUP_HARD_DENOMINATOR
        <= packed_bytes * SETUP_HARD_NUMERATOR,
        "rotation_setup_hard_pass": rotation_floor * SETUP_HARD_DENOMINATOR
        <= packed_bytes * SETUP_HARD_NUMERATOR,
        "online_mdv_view_refine_proved": False,
        "one_scan_opener_proved": False,
        "admitted": False,
        "provenance": {
            "query_formula": "derived_from_strict_UD_delta_and_retained_WHIR_schedule",
            "domain_rule": "retained_WHIR_post_first_fold_guard_not_C7_admitted",
            "published_domain_scope": "WHIR_Goldilocks_benchmarks_omit_initial_exponent_above_32",
            "strict_UD_proximity_gap": "exact_bad_value_count_over_Goldilocks_p_squared",
            "digest_floor": "flat_g141_stream_accounting_identity",
            "codec_leaf_path_wire": "unknown_fail_closed",
        },
        "credit": False,
    }


def r07_carrier_pareto_screen() -> dict[str, object]:
    rows = []
    for starting_rate in WHIR_STARTING_LOG_INV_RATE_CONTROLS:
        for factor in WHIR_CONSTANT_FOLD_CONTROLS:
            rows.append(
                {
                    "candidate_id": f"strict-ud-r{starting_rate}-k{factor}",
                    "gpt2": rs_whir_constant_fold_control(
                        GPT2, starting_rate, factor
                    ),
                    "gemma_31b": rs_whir_constant_fold_control(
                        GEMMA_ENVELOPE, starting_rate, factor
                    ),
                }
            )
    for row in rows:
        small = row["gpt2"]
        large = row["gemma_31b"]
        row["paired_formula_control_growth"] = {
            "q_open": large["q_open_formula_control"]
            / small["q_open_formula_control"],
            "unstacked_fp_positions": large[
                "unstacked_fp_positions_formula_control"
            ]
            / small["unstacked_fp_positions_formula_control"],
            "q_open_within_1_05": 100 * large["q_open_formula_control"]
            <= 105 * small["q_open_formula_control"],
            "unstacked_fp_positions_within_1_05": 100
            * large["unstacked_fp_positions_formula_control"]
            <= 105 * small["unstacked_fp_positions_formula_control"],
        }

    reference_rows = [
        {
            "candidate_id": "ligerito-published-2^30-control",
            "role": "theorem_carrier_reference_not_C7_codec",
            "published_instance_symbols": 1 << 30,
            "published_security_bits": 100,
            "published_queries_per_round": 148,
            "published_proof_bytes": 420 * 1024,
            "published_prover_seconds": 80,
            "published_allocated_bytes": 31 * (1 << 30),
            "challenge_mode": "Fiat_Shamir_not_selected_C7_mode",
            "complete_C7_census": False,
            "one_scan_bounded_memory_opener": False,
            "admitted": False,
            "rejection_reason": (
                "matrix/full-codeword memory and Merkle-dominant log^2(N)/loglog(N) "
                "communication do not instantiate the C7 codec or resource gates"
            ),
            "credit": False,
        },
        {
            "candidate_id": "era-r4-published-2^32-control",
            "role": "byte_and_prover_control_only",
            "published_instance_symbols": 1 << 32,
            "published_security_bits": 100,
            "published_field_elements": 72_418,
            "published_hashes": 53_011,
            "published_proof_bytes": REFERENCE_WEIGHT_ALFC_BYTES,
            "complete_C7_census": False,
            "one_scan_bounded_memory_opener": False,
            "admitted": False,
            "rejection_reason": (
                "O(lambda*log(N)) queries, P1/P2/multiplier or N-scale "
                "intermediates, no adaptive privacy theorem, and about 3x "
                "digest-only dual-root rotation at r=4"
            ),
            "credit": False,
        },
    ]
    large_rate1_domain_exponent = (
        int(GEMMA_ENVELOPE["weights"]) - 1
    ).bit_length() + 1
    large_rate1_starting_gap_error = Fraction(
        1 << large_rate1_domain_exponent, GOLDILOCKS_FP2_CARDINALITY
    )
    large_rate1_gap_bits = certified_bits(large_rate1_starting_gap_error)
    minimum_extension_degree = 1
    while GOLDILOCKS_MODULUS**minimum_extension_degree < (
        1 << (TARGET_RESPONSE_EVENT_BITS + large_rate1_domain_exponent)
    ):
        minimum_extension_degree += 1
    large_rate1_k4 = next(
        row
        for row in rows
        if row["candidate_id"] == "strict-ud-r1-k4"
    )["gemma_31b"]
    fp2_positions = large_rate1_k4["unstacked_fp_positions_formula_control"]
    fp3_positions = sum(
        round_row["strict_ud_queries"]
        * (1 << round_row["folding_factor"])
        * (1 if round_row["round"] == 0 else 3)
        for round_row in large_rate1_k4["rounds"]
    )
    single_run_gap_error = Fraction(
        large_rate1_k4["strict_UD_all_fold_gap_error_upper_bound"]
    )
    minimum_repetitions = 1
    while single_run_gap_error**minimum_repetitions > Fraction(
        1, 1 << TARGET_RESPONSE_EVENT_BITS
    ):
        minimum_repetitions += 1
    repeated_gap_error = single_run_gap_error**minimum_repetitions
    fp3_gap_error = sum(
        (
            Fraction(
                round_row["strict_UD_bad_value_count_upper_bound_per_challenge"],
                GOLDILOCKS_MODULUS**minimum_extension_degree,
            )
            * round_row["fold_challenge_count"]
        )
        for round_row in large_rate1_k4["rounds"]
    )
    conditional_pow_bits = [
        max(
            0,
            math.ceil(
                TARGET_RESPONSE_EVENT_BITS
                + math.log2(round_row["fold_challenge_count"])
                - round_row[
                    "strict_UD_per_challenge_certified_bits_Fp2_control"
                ]
            ),
        )
        for round_row in large_rate1_k4["rounds"]
    ]

    return {
        "owner_selected_role": (
            "RS_t_query_ZK_plus_strict_unique_decoding_WHIR_or_Ligerito_"
            "with_public_salted_BLAKE3"
        ),
        "era_r4_role": "byte_and_prover_control_only",
        "numeric_Q_root_R_root_K_model_D_model_selected": False,
        "selection_rule": (
            "discard invalid rows first; compare the remaining non-fungible "
            "query, wire, setup, rotation, work, memory, verifier, security "
            "and service-life axes without a scalar score"
        ),
        "required_row_schema": [
            "q_open_by_plane_root_round",
            "Z_atom_after_Fp_unstacking",
            "U_leaf",
            "S_visible_Fp",
            "H_sibling",
            "certificate_bytes_GPT2_31B_and_growth",
            "setup_persistent_temp_IO_time_and_rotation",
            "online_passes_IO_work_and_RSS",
            "verifier_work",
            "knowledge_soundness_and_model_lifetime_privacy",
            "q_init_q_rotate_in_out_and_lifecycle_reserve",
            "R_root_K_model_D_model_service_horizon",
        ],
        "constant_schedule_formula_controls": rows,
        "variable_tail_fold_pareto_controls": {
            "Fp2": variable_fold_pair_screen(2),
            "Fp3": variable_fold_pair_screen(3),
        },
        "bounded_closure_screens": r07_bounded_closure_screens(),
        "published_reference_rows": reference_rows,
        "formula_controls_are_complete_census": False,
        "goldilocks_31b_has_retained_field_valid_controls": any(
            row["gemma_31b"]["retained_goldilocks_folded_domain_supported"]
            for row in rows
        ),
        "goldilocks_31b_minimum_first_fold_by_starting_log_inv_rate": {
            str(rate): max(
                0,
                (int(GEMMA_ENVELOPE["weights"]) - 1).bit_length()
                + rate
                - GOLDILOCKS_TWO_ADICITY,
            )
            for rate in WHIR_STARTING_LOG_INV_RATE_CONTROLS
        },
        "published_goldilocks_benchmark_scope_covers_31b": False,
        "retained_interleaved_domain_rule_is_C7_admitted": False,
        "all_31b_controls_lack_unamplified_Fp2_lifetime_certificate": all(
            not row["gemma_31b"][
                "strict_UD_inherited_all_fold_bound_certifies_78_after_R_max"
            ]
            for row in rows
        ),
        "security_amplification_options_unselected": [
            "proved_independent_algebraic_repetition",
            "explicit_interactive_pow_theorem_and_cost",
        ],
        "owner_selected_security_closure_path": [
            "one_bounded_tighter_strict_UD_all_fold_audit",
            "automatic_Goldilocks_Fp3_direct_three_Fp_limb_fallback",
            "two_independent_Fp2_folds_only_if_Fp3_fails_a_non_security_gate",
        ],
        "owner_selected_first_compiler_envelope": {
            "candidate_id": "rate1-k0-4-owner1_30-Fp2-query-axis-candidate",
            "constant_fold_control_reference": "strict-ud-r1-k4",
            "starting_rate": "1/2",
            "first_fold": 4,
            "tail_schedule_selected_for_formula_query_axes": True,
            "gpt2_tail_schedule": [5, 3, 3, 3, 3],
            "gemma_31b_tail_schedule": [4, 3, 3, 3, 4, 4, 4],
            "pure_fold_width_tail_rejected": True,
            "query_sharing_codec_selected": False,
            "bounded_alternative_screens_complete": True,
            "original_1_05_carrier_disposition": "NO_GO",
            "owner_1_30_query_growth_fallback_active": True,
            "next_required_work": (
                "compile_exact_Z_atom_U_leaf_S_visible_Fp_paths_bytes_setup_"
                "one_scan_and_security_without_relaxing_other_gates"
            ),
            "constant_k4_control_query_gates_pass": False,
            "weight_roots": 1,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "packing": "flat_dense_rows_may_straddle_leaves",
            "admitted": False,
        },
        "security_amplifier_formula_controls": {
            "baseline_31b_rate_1_over_2_starting_certified_bits": (
                large_rate1_gap_bits
            ),
            "baseline_31b_rate_1_over_2_all_fold_certified_bits": (
                large_rate1_k4[
                    "strict_UD_all_fold_union_certified_bits_Fp2_control"
                ]
            ),
            "target_per_registered_event_bits": TARGET_RESPONSE_EVENT_BITS,
            "tighter_analysis": {
                "additional_certified_bits_needed_at_starting_challenge": (
                    TARGET_RESPONSE_EVENT_BITS - large_rate1_gap_bits
                ),
                "additional_certified_bits_needed_for_all_fold_target": (
                    TARGET_RESPONSE_EVENT_BITS
                    - large_rate1_k4[
                        "strict_UD_all_fold_union_certified_bits_Fp2_control"
                    ]
                ),
                "tight_attack_or_impossibility_known": False,
                "selected": False,
                "bounded_audit_selected": True,
                "pass_condition": (
                    "schedule_parametric_all_fold_bound_and_eventual_31b_"
                    "rate1_k0_4_envelope_schedule_at_least_110_bits_without_"
                    "conjectural_or_list_decoding_assumptions"
                ),
            },
            "independent_repetition": {
                "conditional_minimum_repetitions": minimum_repetitions,
                "condition": (
                    "independent_complete_experiments_with_AND_acceptance_"
                    "giving_epsilon_all_folds_to_the_repetition_power"
                ),
                "conditional_all_fold_error_upper_bound": (
                    f"{repeated_gap_error.numerator}/{repeated_gap_error.denominator}"
                ),
                "conditional_all_fold_certified_bits": certified_bits(
                    repeated_gap_error
                ),
                "conditional_after_R_max_certified_bits": certified_bits(
                    repeated_gap_error
                )
                - math.log2(R_MAX),
                "conservative_unstacked_Fp_positions": 2 * fp2_positions,
                "conservative_payload_bytes": 2 * fp2_positions * FIELD_SYMBOL_BYTES,
                "shared_root_one_scan_and_privacy_savings_proved": False,
                "selected": False,
            },
            "larger_extension": {
                "minimum_Goldilocks_extension_degree_control": minimum_extension_degree,
                "starting_challenge_certified_bits_control": (
                    certified_bits(
                        Fraction(
                            1 << large_rate1_domain_exponent,
                            GOLDILOCKS_MODULUS**minimum_extension_degree,
                        )
                    )
                ),
                "all_fold_error_upper_bound_control": (
                    f"{fp3_gap_error.numerator}/{fp3_gap_error.denominator}"
                ),
                "all_fold_union_certified_bits_control": certified_bits(
                    fp3_gap_error
                ),
                "after_R_max_certified_bits_control": certified_bits(fp3_gap_error)
                - math.log2(R_MAX),
                "visible_limb_multiplier_vs_Fp2": minimum_extension_degree / 2,
                "unstacked_Fp_positions_control": fp3_positions,
                "payload_bytes_control": fp3_positions * FIELD_SYMBOL_BYTES,
                "payload_growth_vs_Fp2": fp3_positions / fp2_positions,
                "bridge_and_codec_proved": False,
                "selected": False,
                "selected_if_bounded_audit_fails": True,
                "terminal_adapter": "direct_three_canonical_Fp_limbs",
            },
            "interactive_pow": {
                "statistical_amplification_under_Q_FS_0": False,
                "conditional_pow_bits_by_phase": conditional_pow_bits,
                "conditional_expected_hash_trials": sum(
                    round_row["fold_challenge_count"] * (1 << pow_bits)
                    for round_row, pow_bits in zip(
                        large_rate1_k4["rounds"], conditional_pow_bits
                    )
                ),
                "conditional_serial_grind_synchronizations": large_rate1_k4[
                    "fold_challenge_count"
                ],
                "interactive_computational_soundness_theorem_proved": False,
                "selected": False,
            },
            "credit": False,
        },
        "any_row_admitted": False,
        "credit": False,
    }


def byte_result(value: int, classification: str, formula: str) -> dict[str, object]:
    return {
        "bytes": value,
        "classification": classification,
        "formula": formula,
        "credit": False,
    }


def time_result(value: float, formula: str) -> dict[str, object]:
    return {
        "seconds": value,
        "classification": "bandwidth_lower_bound_not_a_measurement",
        "formula": formula,
        "credit": False,
    }


def log_squared_scale(reference_bytes: int, size: int, reference_size: int) -> int:
    if size == reference_size:
        return reference_bytes
    return math.ceil(reference_bytes * (math.log2(size) / math.log2(reference_size)) ** 2)


def weight_alfc_bytes(weight_count: int) -> int:
    return math.ceil(
        REFERENCE_WEIGHT_ALFC_BYTES
        * TARGET_RESPONSE_EVENT_BITS
        / REFERENCE_SECURITY_BITS
        * (math.log2(weight_count) / math.log2(REFERENCE_N)) ** 2
    )


def terminal_segments(model: dict[str, object]) -> dict[str, int]:
    weights = WEIGHT_SEGMENTS_PER_LAYER * int(model["layers"]) + GLOBAL_WEIGHT_SEGMENTS
    total = (
        weights
        + BOUNDARY_SEGMENTS
        + PREDECESSOR_KV_SEGMENTS
        + SUCCESSOR_KV_SEGMENTS
    )
    return {
        "weight": weights,
        "boundary": BOUNDARY_SEGMENTS,
        "predecessor_kv": PREDECESSOR_KV_SEGMENTS,
        "successor_kv": SUCCESSOR_KV_SEGMENTS,
        "total": total,
        "terminal_claims_per_segment": 1,
        "compiled_manifest": False,
    }


def certificate_components(model: dict[str, object]) -> dict[str, dict[str, object]]:
    layers = int(model["layers"])
    width = int(model["d_model"])
    kv_heads = int(model["kv_heads"])
    head_dim = int(model["head_dim"])
    weights = int(model["weights"])
    compute_cells = layers * RESPONSE_TOKENS * width * width
    boundary_cells = layers * RESPONSE_TOKENS * width
    state_cells = 2 * layers * kv_heads * head_dim * SUCCESSOR_CONTEXT_TOKENS
    gpt_compute_cells = (
        int(GPT2["layers"]) * RESPONSE_TOKENS * int(GPT2["d_model"]) ** 2
    )
    gpt_boundary_cells = int(GPT2["layers"]) * RESPONSE_TOKENS * int(GPT2["d_model"])
    gpt_state_cells = (
        2
        * int(GPT2["layers"])
        * int(GPT2["kv_heads"])
        * int(GPT2["head_dim"])
        * SUCCESSOR_CONTEXT_TOKENS
    )
    segments = terminal_segments(model)["total"]

    return {
        "B_compute": byte_result(
            log_squared_scale(COMPUTE_REFERENCE_BYTES, compute_cells, gpt_compute_cells),
            "target_allocation_not_backend_evidence",
            "ceil(6,000,000*(log2(layers*response_tokens*d_model^2)/"
            "log2(gpt2_reference_compute_cells))^2)",
        ),
        "B_boundary_commitments": byte_result(
            log_squared_scale(
                BOUNDARY_REFERENCE_BYTES, boundary_cells, gpt_boundary_cells
            ),
            "target_allocation_not_backend_evidence",
            "ceil(1,200,000*(log2(layers*response_tokens*d_model)/"
            "log2(gpt2_reference_boundary_cells))^2)",
        ),
        "B_state": byte_result(
            log_squared_scale(STATE_REFERENCE_BYTES, state_cells, gpt_state_cells),
            "target_allocation_not_backend_evidence",
            "ceil(2,000,000*(log2(2*layers*kv_heads*head_dim*successor_tokens)/"
            "log2(gpt2_reference_kv_cells))^2)",
        ),
        "B_weight_ALFC": byte_result(
            weight_alfc_bytes(weights),
            "ERA_2^32_calibration_transposed_to_target_ALFC_no_protocol_credit",
            "ceil(4,014,000*(110/100)*(log2(weight_count)/32)^2)",
        ),
        "B_MAC": byte_result(
            MAC_SETTLEMENT_BYTES
            + segments * FP_LIMBS_PER_FP2 * FP_CORRECTION_BYTES,
            "target_allocation_not_backend_evidence",
            "512 + terminal_segments*2_Fp_limbs*8_bytes",
        ),
        "B_framing": byte_result(
            FIXED_FRAMING_BYTES + ROOT_COUNT * HASH_BYTES + 8 * segments,
            "target_allocation_not_codec_evidence",
            "65,536 + root_count*32 + terminal_segments*8",
        ),
    }


def illustrative_era_setup_and_refresh(
    model: dict[str, object], bandwidth_bytes_per_second: float
) -> dict[str, object]:
    weights = int(model["weights"])
    setup_wall_target = (
        GPT2_SETUP_WALL_TARGET_SECONDS
        if model["name"] == GPT2["name"]
        else GEMMA_SETUP_WALL_TARGET_SECONDS
    )
    setup_wall_hard_cap = (
        GPT2_SETUP_WALL_HARD_CAP_SECONDS
        if model["name"] == GPT2["name"]
        else GEMMA_SETUP_WALL_HARD_CAP_SECONDS
    )
    assert weights * ERA_INVERSE_RATE_NUMERATOR % ERA_INVERSE_RATE_DENOMINATOR == 0
    oracle_symbols = (
        weights * ERA_INVERSE_RATE_NUMERATOR // ERA_INVERSE_RATE_DENOMINATOR
    )
    packed = weights * PACKED_WEIGHT_BYTES
    oracle = oracle_symbols * FIELD_SYMBOL_BYTES
    p1 = weights * PERMUTATION_INDEX_BYTES
    p2 = weights * PERMUTATION_INDEX_BYTES
    multiplier = weights * MULTIPLIER_BYTES
    leaves = ceil_div(oracle_symbols, ILLUSTRATIVE_ERA_MERKLE_SYMBOLS_PER_LEAF)
    merkle_nodes = 2 * leaves - 1
    merkle = merkle_nodes * HASH_BYTES
    digest_only_screen = packed + merkle
    persistent_oracle = oracle + merkle
    setup_disk = packed + persistent_oracle + p1 + p2 + multiplier
    setup_target = packed * SETUP_TARGET_NUMERATOR // SETUP_TARGET_DENOMINATOR
    setup_hard = packed * SETUP_HARD_NUMERATOR // SETUP_HARD_DENOMINATOR
    setup_exploratory = (
        packed
        * SETUP_EXPLORATORY_NUMERATOR
        // SETUP_EXPLORATORY_DENOMINATOR
    )
    leaf_screens: dict[str, object] = {}
    for symbols_per_leaf in DIGEST_ONLY_LEAF_CANDIDATES:
        candidate_leaves = ceil_div(oracle_symbols, symbols_per_leaf)
        candidate_nodes = 2 * candidate_leaves - 1
        candidate_tree = candidate_nodes * HASH_BYTES
        candidate_total = packed + candidate_tree
        leaf_screens[str(symbols_per_leaf)] = {
            "symbols_per_leaf": symbols_per_leaf,
            "leaf_count": candidate_leaves,
            "maximum_path_depth": math.ceil(math.log2(candidate_leaves)),
            "tree_bytes": candidate_tree,
            "total_persistent_bytes": candidate_total,
            "target_metadata_headroom_bytes": setup_target - candidate_total,
            "hard_ceiling_metadata_headroom_bytes": setup_hard - candidate_total,
            "exploratory_ceiling_metadata_headroom_bytes": (
                setup_exploratory - candidate_total
            ),
            "amplification_over_packed_i16": candidate_total / packed,
            "private_payload_bytes_per_unique_leaf": {
                "Fp": symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES,
                "Fp2": symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES,
            },
            "within_2x_target": candidate_total <= setup_target,
            "within_2_1x_hard_ceiling": candidate_total <= setup_hard,
            "within_3x_exploratory_ceiling": (
                candidate_total <= setup_exploratory
            ),
            "classification": (
                "within_target_floor_only"
                if candidate_total <= setup_target
                else "within_baseline_tolerance_floor_only"
                if candidate_total <= setup_hard
                else "within_exploratory_3x_floor_only"
                if candidate_total <= setup_exploratory
                else "reject"
            ),
            "credit": False,
        }

    preprocessing_read = packed
    preprocessing_write = persistent_oracle + p1 + p2 + multiplier
    preprocessing_io = preprocessing_read + preprocessing_write
    refresh_read = packed + p1 + p2 + multiplier
    refresh_write = persistent_oracle
    refresh_io = refresh_read + refresh_write
    consumable_profile = persistent_oracle

    return {
        "packed_i16": byte_result(
            packed, "accounting_identity", "weight_count*2"
        ),
        "era_oracle": {
            "symbols": oracle_symbols,
            "inverse_rate": 4.4,
            **byte_result(
                oracle,
                "accounting_identity_given_ERA_rate",
                "weight_count*(22/5)*8",
            ),
        },
        "P1": byte_result(
            p1, "illustrative_artifact_layout", "weight_count*4"
        ),
        "P2": byte_result(
            p2, "illustrative_artifact_layout", "weight_count*4"
        ),
        "multiplier": byte_result(
            multiplier, "illustrative_artifact_layout", "weight_count*8"
        ),
        "merkle": {
            "symbols_per_leaf": ILLUSTRATIVE_ERA_MERKLE_SYMBOLS_PER_LEAF,
            "leaf_count": leaves,
            "compact_binary_tree_nodes": merkle_nodes,
            "maximum_path_depth": math.ceil(math.log2(leaves)),
            **byte_result(
                merkle,
                "target_compact_Merkle_layout",
                "(2*ceil(era_oracle_symbols/64)-1)*32",
            ),
        },
        "persistent_oracle": byte_result(
            persistent_oracle,
            "illustrative_artifact_layout",
            "era_oracle_bytes + compact_Merkle_tree_bytes",
        ),
        "digest_only_candidate_floor_screen": {
            **byte_result(
                digest_only_screen,
                "illustrative_packed_plus_digest_tree_not_a_derived_candidate",
                "packed_i16 + compact_Merkle_tree",
            ),
            "amplification_over_packed_i16": digest_only_screen / packed,
        },
        "owner_setup_envelope": {
            "target_multiplier": "2/1",
            "baseline_tolerance_multiplier": "21/10",
            "exploratory_ceiling_multiplier": "3/1",
            "target_bytes": setup_target,
            "baseline_tolerance_bytes": setup_hard,
            "exploratory_persistent_disk_cap_bytes": setup_exploratory,
            "setup_wall_target_seconds": setup_wall_target,
            "setup_wall_hard_cap_seconds": setup_wall_hard_cap,
            "refresh_wall_target_seconds": setup_wall_target,
            "refresh_wall_hard_cap_seconds": setup_wall_hard_cap,
            "refresh_counter_is_separate": True,
            "refresh_budget_transfer_allowed": False,
            "refresh_tested_in_R08": False,
            "absolute_time_caps_must_be_preregistered_before_measurement": True,
            "all_absolute_caps_selected": True,
            "exploratory_setup_gate_pass": False,
            "selected_logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "selected_leaf_status": (
                "logical_format_selected_floor_screen_only_no_codec_or_setup_credit"
            ),
            "simt_may_change_logical_leaf_symbols": False,
            "asymptotic_minimum_symbols_per_leaf": {
                "2x_target": 141,
                "2_1x_hard": 128,
                "smallest_power_of_two_meeting_target": 256,
                "formula": "A_setup ~= 1 + 140.8/g",
            },
            "leaf_screens": leaf_screens,
            "compiled_candidate_manifest_complete": False,
            "credit": False,
        },
        "illustrative_era_artifact_volume_sum": byte_result(
            setup_disk,
            "illustrative_artifact_volume_not_derived_setup",
            "packed_i16 + ERA_oracle + P1 + P2 + multiplier + Merkle_tree",
        ),
        "setup_amplification_over_packed_i16": setup_disk / packed,
        "anti_x4d_structural_gate": {
            "passes": False,
            "reasons": [
                "persistent expanded field/code oracle",
                "model-linear P1/P2/multiplier planes",
                "model-sized preprocessing writes",
            ],
            "numeric_setup_ceiling_registered": True,
            "credit": False,
        },
        "ideal_fused_artifact_io_screen": {
            "bytes_read": byte_result(
                preprocessing_read, "analytic_lower_bound", "packed_i16_bytes"
            ),
            "bytes_written": byte_result(
                preprocessing_write,
                "analytic_lower_bound",
                "ERA_oracle + P1 + P2 + multiplier + Merkle_tree",
            ),
            "total_io": byte_result(
                preprocessing_io,
                "analytic_lower_bound",
                "preprocessing_bytes_read + preprocessing_bytes_written",
            ),
            "bandwidth_roofline": time_result(
                preprocessing_io / bandwidth_bytes_per_second,
                "minimum_fused_preprocessing_io/selected_bandwidth",
            ),
            "non_fused_merklization_additional_read": byte_result(
                oracle,
                "excluded_from_fused_lower_bound",
                "one additional ERA_oracle read",
            ),
        },
        "hypothetical_full_reencode_sensitivity": {
            "bytes_read": byte_result(
                refresh_read,
                "hypothetical_reencode_screen",
                "packed_i16 + P1 + P2 + multiplier",
            ),
            "bytes_written": byte_result(
                refresh_write,
                "hypothetical_reencode_screen",
                "fresh ERA_oracle + fresh compact Merkle tree",
            ),
            "total_io": byte_result(
                refresh_io,
                "hypothetical_reencode_screen",
                "refresh_bytes_read + refresh_bytes_written",
            ),
            "bandwidth_roofline": time_result(
                refresh_io / bandwidth_bytes_per_second,
                "refresh_total_io/selected_bandwidth",
            ),
            "consumable_profile": byte_result(
                consumable_profile,
                "target_pool_screen",
                "fresh ERA_oracle + fresh compact Merkle tree",
            ),
            "R_max_pool": byte_result(
                consumable_profile * R_MAX,
                "impractical_pool_sensitivity_not_a_selected_policy",
                "consumable_profile_bytes*2^20",
            ),
        },
        "assumptions": [
            "Merkle nodes use a compact 2L-1 binary tree; no power-of-two leaf padding.",
            "P1/P2 use four-byte segment-local indices; every canonical shard is below 2^32 entries.",
            "The fused preprocessing floor hashes leaves while writing the oracle; a non-fused build rereads the oracle.",
            "Refresh is reported separately from the certificate timer and the one-scan online target.",
            "No preprocessing theorem is claimed to remove the fresh online linear-functional scan.",
        ],
    }


def online_scan(model: dict[str, object], chunk_bytes: int, bandwidth: float) -> dict[str, object]:
    scan_bytes = 2 * int(model["weights"])
    return {
        "sequential_passes": 1,
        "bytes_read": byte_result(
            scan_bytes,
            "packed_source_target_not_backend_schedule",
            "weight_count*2 packed_i16 bytes",
        ),
        "bytes_written": byte_result(
            0,
            "L_and_source_scan_spill_target_only",
            "no spill and no materialized functional",
        ),
        "materialized_L": byte_result(
            0,
            "packed_source_target_not_backend_schedule",
            "eq weights generated and consumed in stream order",
        ),
        "resident_expanded_Fp_or_Fp2_weight_wrapper": byte_result(
            0,
            "packed_source_target_not_backend_schedule",
            "packed i16 conversion is chunk-local",
        ),
        "configured_working_chunk": byte_result(
            chunk_bytes, "configurable_memory_ceiling", "--chunk-mb*1,000,000"
        ),
        "chunk_count": ceil_div(scan_bytes, chunk_bytes),
        "bandwidth_roofline": time_result(
            scan_bytes / bandwidth, "online_scan_bytes/selected_bandwidth"
        ),
        "assumption": "one terminal functional per canonical segment; no K*N coefficient construction",
        "credit": False,
    }


def c7_policy3_ra_leaf_screen(model: dict[str, object]) -> dict[str, object]:
    """Count the executable one-stage RA/LeafCom screen, not an admitted PCS."""
    weights = int(model["weights"])
    packed = weights * PACKED_WEIGHT_BYTES
    packed_leaves = ceil_div(weights, LOGICAL_LEAF_SYMBOLS)
    code_symbols = weights * C7_RA_SCREEN_REPETITION
    leaves = ceil_div(code_symbols, LOGICAL_LEAF_SYMBOLS)
    tree_nodes = 2 * leaves - 1
    tree_bytes = tree_nodes * HASH_BYTES
    ligesis_c7_tree_bytes = tree_nodes * 56
    ligesis_c7_persistent = packed + ligesis_c7_tree_bytes
    persistent = packed + tree_bytes + C7_LEAF_ROOT_METADATA_BYTES
    setup_target = packed * SETUP_TARGET_NUMERATOR // SETUP_TARGET_DENOMINATOR
    setup_hard = packed * SETUP_HARD_NUMERATOR // SETUP_HARD_DENOMINATOR
    setup_exploratory = (
        packed
        * SETUP_EXPLORATORY_NUMERATOR
        // SETUP_EXPLORATORY_DENOMINATOR
    )
    permutations = leaves * C7_POSEIDON_PERMUTATIONS_PER_LEAF
    sboxes = permutations * C7_POSEIDON_SBOXES_PER_PERMUTATION
    secret_multiplications = leaves * C7_LEAF_SBOX_MULTIPLICATION_EQUIVALENTS
    return {
        "status": "EXECUTABLE_ONLINE_SCREEN_ONLY_NOT_A_PCS",
        "code": {
            "shape": "one-stage repeat-permute-diagonal-accumulate",
            "repetition": C7_RA_SCREEN_REPETITION,
            "code_symbols": code_symbols,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "leaf_count": leaves,
            "online_cost_identity": (
                "r*N source occurrences, 64*r*N successor-trie steps, "
                "r*N Fp multiplications, at most r*N range adds, and "
                "141*U query-prefix additions"
            ),
            "online_memory_identity": "O(64*141*U) trie nodes plus 141*U Fp outputs",
            "packed_source_passes": 1,
            "packed_source_bytes_read": packed,
            "model_linear_scratch_write_bytes": 0,
            "complete_codeword_bytes": 0,
            "source_coefficient_independent_of_queries": True,
            "cpu_reference_implemented": True,
            "cpu_reference_module": "volta_pcs::c7_ra_batch_open_screen",
            "distance_gate_passed": False,
            "distance_reason": (
                "no accepted constant-relative-distance theorem for this "
                "one-stage Goldilocks construction; binary RA evidence does "
                "not transfer, and accepted nonbinary linear-distance results "
                "require multiple accumulators"
            ),
            "setup_generation_gate_passed": False,
            "setup_generation_reason": (
                "a random interleaver needs a model-sized reorder/scatter or "
                "nonmonotone source reads to emit the committed accumulator "
                "oracle in leaf order"
            ),
            "c7_cpu_reference_pass": False,
            "credit": False,
        },
        "leaf_commitment": {
            "implementation": "Poseidon2 Goldilocks width-16/rate-12 salted leaf",
            "implementation_module": "volta_pcs::c7_policy3_leaf",
            "payload_symbols": LOGICAL_LEAF_SYMBOLS,
            "salt_bits": LEAF_SALT_BITS,
            "digest_bytes": HASH_BYTES,
            "permutations_per_leaf": C7_POSEIDON_PERMUTATIONS_PER_LEAF,
            "sboxes_per_permutation": C7_POSEIDON_SBOXES_PER_PERMUTATION,
            "secret_multiplications_per_leaf": (
                C7_POSEIDON_PERMUTATIONS_PER_LEAF
                * C7_POSEIDON_SBOXES_PER_PERMUTATION
                * C7_POSEIDON_SECRET_MULTIPLICATIONS_PER_SBOX
            ),
            "private_input_correction_bytes_per_opened_leaf": (
                C7_LEAF_PRIVATE_INPUT_CORRECTION_BYTES
            ),
            "root_salt_seed_and_commitment_nonce_bytes": C7_LEAF_ROOT_METADATA_BYTES,
            "private_checker_implemented": False,
            "private_checker_required_shape": (
                "all queried Poseidon traces in fresh C_B,e plus one shared "
                "randomized zerocheck and authenticated terminal links"
            ),
            "malicious_dv_hiding_or_binding_proved": False,
            "credit": False,
        },
        "alternative_leaf_controls": {
            "blake3": {
                "setup_control": "conventional_fast_hash",
                "private_bit_carry_checker_implemented": False,
                "hiding_or_malicious_dv_theorem": False,
                "credit": False,
            },
            "ligesis_c7": {
                "digest_bytes": 56,
                "compact_tree_bytes": ligesis_c7_tree_bytes,
                "packed_plus_tree_bytes": ligesis_c7_persistent,
                "amplification_over_packed_i16": ligesis_c7_persistent / packed,
                "preprocessing_table_multiplier_excluded_from_floor": 32,
                "cited_property": "SIS_collision_resistance_for_bounded_binary_inputs_not_hiding",
                "within_hard_ceiling": ligesis_c7_persistent <= setup_hard,
                "within_exploratory_3x_ceiling": (
                    ligesis_c7_persistent <= setup_exploratory
                ),
                "credit": False,
            },
        },
        "setup": {
            "packed_i16_bytes": packed,
            "compact_tree_nodes": tree_nodes,
            "compact_tree_bytes": tree_bytes,
            "minimal_persistent_bytes": persistent,
            "amplification_over_packed_i16": persistent / packed,
            "target_bytes": setup_target,
            "baseline_tolerance_bytes": setup_hard,
            "exploratory_persistent_disk_cap_bytes": setup_exploratory,
            "storage_within_target": persistent <= setup_target,
            "storage_within_baseline_tolerance": persistent <= setup_hard,
            "storage_within_exploratory_ceiling": (
                persistent <= setup_exploratory
            ),
            "poseidon_permutations": permutations,
            "poseidon_sboxes": sboxes,
            "poseidon_sbox_multiplication_equivalents": secret_multiplications,
            "salt_key_derivations_in_current_one_shot_helper": leaves,
            "salt_keyed_hash_calls": leaves,
            "cached_root_salt_key_implementation_exists": False,
            "internal_tree_hash_compressions": leaves - 1,
            "tree_hash_io_bytes": None,
            "poseidon_work_is_lower_bound_excluding_salt_kdf_prf_tree_hash_and_root_ordering": True,
            "packed_root_leaf_count_control": packed_leaves,
            "packed_root_sbox_multiplication_equivalents_per_response_control": (
                packed_leaves * C7_LEAF_SBOX_MULTIPLICATION_EQUIVALENTS
            ),
            "streaming_root_schedule_exists": False,
            "setup_gate_passed": False,
            "credit": False,
        },
        "terminal_disposition": (
            "reject as C7 backend: the online block algorithm is executable, "
            "but distance, streaming root construction, private checker, "
            "codec refinement and malicious-DV theorem do not compose"
        ),
        "credit": False,
    }


def challenge_mode_comparison() -> dict[str, object]:
    extension_field_size = GOLDILOCKS_MODULUS**3
    interactive = Fraction(RLC_BAD_CHALLENGE_CAP, extension_field_size)
    fs_direct = Fraction(
        FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN * RLC_BAD_CHALLENGE_CAP,
        extension_field_size,
    )
    fs_pair = Fraction(
        FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN * RLC_BAD_CHALLENGE_CAP**2,
        extension_field_size**2,
    )

    def probability(value: Fraction) -> dict[str, object]:
        return {
            "exact": f"{value.numerator}/{value.denominator}",
            "effective_bits": math.log2(value.denominator) - math.log2(value.numerator),
        }

    return {
        "scope": (
            "one fixed-prefix RLC bad set; connection composition and every "
            "other event remain separate"
        ),
        "challenge_field_size": extension_field_size,
        "bad_challenge_cap_T": RLC_BAD_CHALLENGE_CAP,
        "interactive_selected": {
            "formula": "T/|Fp3|",
            **probability(interactive),
            "explicit_challenge_bytes_per_draw": 3 * FIELD_SYMBOL_BYTES,
            "grinding_queries": 0,
            "requirements": [
                "prefix fixed before the draw",
                "fresh uniform honest-DV randomness",
                "canonical serialized challenge and durable attempt binding",
            ],
            "selected": True,
            "credit": False,
        },
        "fiat_shamir_direct_control": {
            "formula": "Q_FS*T/|Fp3|",
            "Q_FS": FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN,
            **probability(fs_direct),
            "selected": False,
            "credit": False,
        },
        "fiat_shamir_two_challenge_amplified": {
            "formula": "Q_FS*T^2/|Fp3|^2",
            "Q_FS": FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN,
            **probability(fs_pair),
            "explicit_challenge_bytes": 0,
            "extra_response_handle_path_settlement_bytes": None,
            "extra_field_and_hash_work": None,
            "extra_packed_source_passes": None,
            "requirements": [
                "one paired RO invocation on one frozen prefix and grinding nonce",
                "paired output expands with domain separation into two independent challenges",
                "canonical rejection sampling into Fp3",
                "both challenges check the same complete relation",
                "no state restoration or cross-attempt transcript reuse",
                "Q_FS counts paired trials over the entire declared grinding scope",
                "separately queryable challenge oracles require a new joint grinding bound",
                "all duplicate/shared responses, paths, MACs and scans are compiled and counted",
            ],
            "selected": False,
            "proof_size_gate_passed": False,
            "credit": False,
        },
        "privacy_note": (
            "challenge mode changes soundness and wire/work accounting; it "
            "does not replace the malicious-DV privacy theorem"
        ),
        "credit": False,
    }


def policy2_query_accounting() -> dict[str, object]:
    """Register distinct policy-2 limits without inventing backend counts."""
    empty_query_census = {
        query_class: None for query_class in POLICY2_QUERY_CLASSES
    }
    empty_aggregate_census = {
        query_class: None for query_class in POLICY2_AGGREGATE_CENSUS_CLASSES
    }
    active_query_growth_tolerance = Fraction(
        ACTIVE_QUERY_GROWTH_NUMERATOR, ACTIVE_QUERY_GROWTH_DENOMINATOR
    )
    original_query_growth_tolerance = Fraction(
        ORIGINAL_QUERY_GROWTH_NUMERATOR,
        ORIGINAL_QUERY_GROWTH_DENOMINATOR,
    )
    era_like_target_t_over_n = Fraction(1, 704)
    era_like_hard_t_over_n = Fraction(13, 128)

    def appended_symbol_screen(weight_count: int) -> dict[str, object]:
        target_extra = weight_count * era_like_target_t_over_n.numerator // (
            era_like_target_t_over_n.denominator
        )
        hard_extra = weight_count * era_like_hard_t_over_n.numerator // (
            era_like_hard_t_over_n.denominator
        )
        return {
            "target_extra_symbols_floor": target_extra,
            "hard_extra_symbols_floor": hard_extra,
            "hypothetical_attempts_at_830_same_units": {
                "target": target_extra // 830,
                "hard": hard_extra // 830,
            },
        }

    return {
        "status": "R08_FP3_SEEDED_MASK_SELECTED_FULL_CODEC_UNADMITTED",
        "privacy_statement": (
            "only root-bound masked PCS responses within the durable global "
            "budget are visible; the terminal evaluation remains VOLE-authenticated"
        ),
        "authoritative_attempt_census": {
            "q_attempt": dict(empty_aggregate_census),
            "q_response": dict(empty_aggregate_census),
            "plane_tags": ["weight", "boundary", "kv_predecessor", "kv_successor"],
            "q_attempt_by_plane": {
                plane: dict(empty_query_census)
                for plane in ("weight", "boundary", "kv_predecessor", "kv_successor")
            },
            "q_response_by_plane": {
                plane: dict(empty_query_census)
                for plane in ("weight", "boundary", "kv_predecessor", "kv_successor")
            },
            "A_attempt": None,
            "logical_pcs_samples_q_open_by_plane_root_round": None,
            "zk_alphabet_query_atoms_by_plane_root_round": None,
            "flat_vectors_are_wire_aggregates_not_privacy_substitutes": True,
            "q_attempt_is_reserved_maximum": True,
            "q_response_is_actual_accepted_response_census": True,
            "q_response_componentwise_at_most_q_attempt": None,
            "entries_tagged_by_commitment_plane": False,
            "aborted_prefix_exposure_counted_separately": True,
            "base_field_symbol_rule": (
                "Fp2 counts as two Fp symbols; a whole 141-symbol leaf counts "
                "all 141 symbols; no packed alphabet query counts as one until unstacked"
            ),
            "cross_attempt_deduplication_allowed": False,
            "credit": False,
        },
        "weight_epoch_lifecycle_census": {
            "q_init": dict(empty_aggregate_census),
            "q_rotate_in": dict(empty_aggregate_census),
            "q_rotate_out": dict(empty_aggregate_census),
            "every_disclosed_candidate_root_counted": True,
            "abort_retry_burns_full_lifecycle_reservation": True,
            "zero_visible_charge_requires_authenticated_only_codec_theorem": True,
            "codec_theorem_proved": False,
            "credit": False,
        },
        "root_privacy_budget": {
            "privacy_unit": "visible masked base-field symbol occurrence",
            "privacy_unit_status": (
                "conservative_provisional_screen_pending_joint_theorem"
            ),
            "attempt_plane_charge_vector": {
                "u_W": None,
                "u_B": None,
                "u_KV_predecessor": None,
                "u_KV_successor": None,
            },
            "weight_epoch_lifecycle_charge_vector": {
                "u_init": None,
                "u_rotate_in": None,
                "u_rotate_out": None,
            },
            "Q_root_privacy_units": None,
            "R_root_attempts": None,
            "A_init_attempts": None,
            "A_rotate_in_attempts": None,
            "A_rotate_out_attempts": None,
            "positive_q_attempt_required": True,
            "positive_weight_charge_u_W_required": True,
            "at_least_one_complete_attempt_capacity_required": True,
            "numeric_preconditions_instantiated": False,
            "model_lifetime_privacy_target_bits": 78,
            "model_lifetime_advantage_ceiling": "2^-78",
            "model_lifetime_bound_signature": (
                "Adv_priv_model_lifetime(K_model,D_model,Q_root,u_init,"
                "u_rotate_in,u_rotate_out,Q_B,Q_KV,Q_hide,Q_PRF)"
            ),
            "model_lifetime_bound_derived": False,
            "numeric_caps_deferred_until_complete_pareto": True,
            "fixed_consumption_formula": (
                "u_init+A_rotate_in*u_rotate_in+A_rotate_out*u_rotate_out+"
                "R_root*u_W <= Q_root"
            ),
            "service_admission_preserves_lifecycle_reserve": True,
            "zero_lifecycle_charge_theorem_proved": False,
            "fixed_consumption_on_accept_abort_retry_crash": True,
            "unused_reservation_refunded": False,
            "positive_privacy_headroom_required": True,
            "headroom_fraction_selected": None,
            "credit": False,
        },
        "allocator_cardinality_relations": {
            "weight": (
                "u_init[omega]+sum_response u_W+sum_rotate_in u_rotate_in+"
                "sum_rotate_out u_rotate_out <= Q_root[omega]"
            ),
            "boundary": "u_B[a] <= Q_B[a]",
            "kv": (
                "u_create[s] + sum_reserved_predecessor_use_charges[s] <= Q_KV[s]"
            ),
            "attempts": "|A_model| <= sum_omega R_root[omega]",
            "epochs": "|Omega_disclosed_candidates| <= K_model",
            "rotations": "accepted+aborted+failed disclosed candidates <= K_model-1",
            "boundary_roots": "|B_created| <= |A_model|",
            "kv_roots": "|KV_created| <= 1+|A_model|",
            "mac_domains": (
                "|domains_init union domains_response union "
                "domains_rotate_in union domains_rotate_out| <= D_model"
            ),
            "mac_domain_scope_includes_failed_and_aborted_lifecycle": True,
            "numeric_instantiation": False,
            "credit": False,
        },
        "global_counter": {
            "authority": "model_owner_provider_not_designated_verifier",
            "authority_owner_selected": True,
            "privacy_theorem_conditioned_on_honest_linearizable_allocator": True,
            "corrupt_or_forkable_allocator_in_privacy_scope": False,
            "malicious_verifier_can_mint_or_rollback_receipts": False,
            "scope": (
                "one complete ordered weight-oracle epoch across accepted responses, "
                "failures, retries, selective aborts, setup/rotation attempts, "
                "disclosed candidates, connections and colluding designated verifiers"
            ),
            "plane_state_scope": (
                "weight high-water plus boundary-attempt and every-created-KV-root "
                "maps under one plane-tagged reservation/assignment state machine"
            ),
            "atomic_reservation_before_first_witness_dependent_answer": True,
            "public_root_is_baseline_view_element": True,
            "cross_world_root_replacement_charged_to_hiding": True,
            "reservation_extension_after_first_answer_allowed": False,
            "remaining_budget_below_q_attempt_rejects_before_answer": True,
            "durable_hash_chained_or_equivalent_journal_required": True,
            "local_hash_chain_alone_prevents_rollback_or_fork": False,
            "shared_allocator_or_monotonic_anchor_required": True,
            "globally_consistent_multi_replica_reservation_proved": False,
            "complete_weight_oracle_epoch_schema_compiled": False,
            "authenticated_reservation_receipt_codec_instantiated": False,
            "receipt_bound_into_canonical_transcript_proved": False,
            "receipt_authenticates_receipt_free_request_binding": True,
            "receipt_free_binding_includes_connection_nonce_mac_domain_charge": True,
            "reserved_session_binding_is_request_binding_plus_receipt": True,
            "receipt_lifecycle": "Reserved->InFlight->Burned|Accepted",
            "linearizable_single_session_receipt_state_machine_proved": False,
            "first_reply_cached_before_receipt_or_seed_commitment_emission": True,
            "exact_duplicate_returns_only_cached_byte_identical_reply": True,
            "divergent_replay_rejects_before_new_witness_dependent_bytes": True,
            "durable_transcript_state_and_reply_cache_instantiated": False,
            "durable_weight_budget_high_water_map_instantiated": False,
            "durable_boundary_budget_map_instantiated": False,
            "durable_kv_budget_map_instantiated": False,
            "nonrefundable_new_root_assignment_slots_instantiated": False,
            "plane_assignment_receipt_codec_instantiated": False,
            "plane_assignment_cas_before_root_disclosure_proved": False,
            "post_first_reply_charge_extension_allowed": False,
            "persistent_state_plane_record_bytes": None,
            "model_lifetime_allocator_storage_bytes": None,
            "authenticated_state_ledger_compaction_proved": False,
            "rate_limits_or_user_quotas_are_security_counters": False,
            "rate_limits_or_user_quotas_are_dos_mitigations": True,
            "credit": False,
        },
        "root_rotation": {
            "rotation_authorized": False,
            "same_weight_root_epoch_cap_K_model": None,
            "cross_root_adaptive_composition_theorem_proved": False,
            "fresh_independent_encoding_randomness_required": True,
            "stop_admit_before_cutover_required": True,
            "outstanding_receipts_resolved_or_burned_before_cutover": False,
            "same_W_bridge_knowledge_soundness_proved": False,
            "same_W_bridge_malicious_dv_privacy_proved": False,
            "typed_init_and_rotate_query_charges_instantiated": False,
            "bridge_zero_visible_query_theorem_proved": False,
            "old_and_new_root_reservations_before_first_bridge_byte": True,
            "failed_or_aborted_candidate_root_sealed": True,
            "failed_or_aborted_disclosed_candidate_consumes_K_model": True,
            "rotation_retry_uses_fresh_candidate_and_fresh_reservations": True,
            "setup_storage_refresh_and_atomic_cutover_compiled": False,
            "only_weight_epoch_counter_is_fresh_after_rotation": True,
            "state_plane_ledger_carried_byte_identically_required": True,
            "state_plane_ledger_carry_forward_proved": False,
            "warning": "a new root does not reset privacy or setup accounting for free",
            "credit": False,
        },
        "cryptographic_work_bounds": {
            "Q_CR_collision_binding": None,
            "Q_hide_adaptive_root_path": None,
            "Q_salt_PRF": None,
            "Q_root_mask_PRG_words_by_epoch": None,
            "Adv_RootMaskPRG_multi": None,
            "root_mask_PRG_component_reserve_bits": (
                ROOT_MASK_PRG_LIFETIME_RESERVE_BITS
            ),
            "root_mask_PRG_is_distinct_from_salt_PRF_and_VOLE_PCG": True,
            "historical_Q_leaf_is_not_an_active_substitute": True,
            "all_active_bounds_derived_across_K_model": False,
            "credit": False,
        },
        "response_and_state_plane_privacy": {
            "weight_Q_root_does_not_pay_for_boundary_or_kv": True,
            "Q_B_per_attempt": None,
            "Q_KV_per_created_state_root": None,
            "census_tagged_by_commitment_plane": False,
            "boundary_root_charged_once_per_attempt": True,
            "every_proposed_successor_root_charged_before_disclosure": True,
            "aborted_or_rejected_successor_root_sealed": True,
            "accepted_successor_keeps_same_counter_on_predecessor_reuse": True,
            "genesis_InitKVState_before_first_disclosure_required": True,
            "genesis_InitKVState_codec_and_theorems_proved": False,
            "kv_budget_maps_are_outside_weight_epoch_ledger": True,
            "boundary_and_successor_charges_reserved_before_first_reply": True,
            "new_roots_assigned_to_preburned_slots_before_disclosure": True,
            "authenticated_only_zero_visible_query_claim_proved": False,
            "per_plane_hiding_prf_and_path_bounds_derived": False,
            "credit": False,
        },
        "multiuser_mac_composition": {
            "D_model_key_domains": None,
            "D_model_scope": [
                "weight_or_KV_setup_or_init_validation",
                "W_dependent_response_attempts",
                "W_dependent_rotate_in_bridges",
                "W_dependent_rotate_out_bridges",
                "failed_or_aborted_lifecycle_attempts",
            ],
            "J_d_scope": (
                "all_correlations_reserved_or_consumed_in_scoped_phases_"
                "including_burned_suffixes"
            ),
            "zero_lifecycle_domain_requires_zero_vole_mac_codec_theorem": True,
            "zero_lifecycle_domain_theorem_proved": False,
            "one_Delta_and_fixed_key_tape_per_domain": True,
            "malicious_verifier_may_correlate_Delta_and_keys_across_domains": True,
            "fresh_domain_separated_provider_coins_and_masks_required": True,
            "existing_lean_theorem_covers_one_domain_only": True,
            "soundness_bound_shape": (
                "sum_domain(epsilon_MAC_domain)+"
                "epsilon_MultiUserMacCompose(D_model)"
            ),
            "multiuser_vole_mac_theorem_proved": False,
            "allocator_privacy_trust": "honest_model_owner_provider",
            "allocator_privacy_integrity_proved": False,
            "dishonest_prover_receipt_unforgeability_proved": False,
            "generic_receipt_hypothesis_disallowed": True,
            "credit": False,
        },
        "paired_history_privacy_game": {
            "common_public_request_required": True,
            "equal_public_prompt_output_abort_and_shape_leakage_required": True,
            "branch_specific_predecessors_must_both_be_valid": True,
            "roots_excluded_from_equal_leakage_and_replaced_by_hiding_hybrid": True,
            "equal_predicate_is_witness_independent_base_frame_only": True,
            "branch_derived_closure_includes": [
                "roots_and_paths",
                "root_budget_id",
                "receipt_and_authentication",
                "predecessor_certificate_digest",
                "transcript_and_journal_heads",
            ],
            "branch_derived_view_closure_reduction_proved": False,
            "operational_game_formalized": False,
            "credit": False,
        },
        "online_mdv_view_refinement": {
            "theorem_name": "C7-OnlineMDVViewRefine",
            "statement": (
                "every legal adaptive byte-prefix view factors through the "
                "bounded adaptive RS oracle plus the authenticated-terminal simulator"
            ),
            "published_2026_391_fixed_set_t_query_zk_error": 0,
            "published_2026_391_composition_is_nonadaptive_hvzk": True,
            "published_result_implies_stateful_malicious_dv": False,
            "codec_load_map_from_visible_Fp_to_each_correlated_RS_component_required": True,
            "capacity_definition": (
                "CapFp(r)=max q such that every legal prefix T with "
                "S_visible_Fp(T)<=q has load[r,c,T]<=t[r,c] for every component c"
            ),
            "paper_t_is_visible_Fp_capacity_without_codec_proof": False,
            "proof_complete": False,
            "hard_stop": True,
            "credit": False,
        },
        "model_lifetime_privacy_bound": {
            "formula": (
                "sum_disclosed_candidate_omega eps_RV_W + sum_attempt eps_RV_B + "
                "sum_state eps_RV_KV + Adv_MultiUserVOLE_MDV + "
                "Adv_RootMaskPRG_multi + K_seed_attempts*eps_rejection + "
                "sum_domain Adv_PCG + sum_attempt(eps_terminal_codec+eps_timing) + "
                "sum_all_rotation_attempts eps_RotateSameW_priv + "
                "eps_branch_derived_closure + eps_state_codec_carry"
            ),
            "eps_RV_formula": (
                "eps_OnlineMDVViewRefine + zeta_RS_adapt + Adv_SaltPRF + "
                "Adv_BLAKE3_RootPathHide"
            ),
            "root_mask_privacy_is_computational": True,
            "root_mask_PRG_advantage_included_once_model_wide": True,
            "allocator_failure_term": (
                "zero only under the selected AllocOK trust boundary; otherwise Pr[not AllocOK]"
            ),
            "receipt_EUF_is_soundness_not_privacy": True,
            "Q_CR_is_soundness_not_privacy": True,
            "admission_rhs_at_most": "2^-78",
            "derived": False,
            "credit": False,
        },
        "dishonest_prover_soundness_bound": {
            "formula": (
                "Adv_CR_BLAKE3 + sum_descriptor(eps_geometry_position + "
                "eps_strictUD_RBRKS + eps_setup_binding + "
                "eps_masked_oracle_to_same_witness) + "
                "sum_rotation(eps_RotateSameW_KS+eps_atomic_cutover) + "
                "Adv_MultiUserMAC + sum_attempt(eps_RLC_operator + "
                "eps_Fp2_terminal + eps_PCG) + Adv_EUF_Receipt + "
                "eps_InitKVStateSound + eps_plane_assignment + eps_replay_fork"
            ),
            "strict_unique_decoding_only": True,
            "list_decoding_or_conjectural_assumption_allowed": False,
            "derived": False,
            "credit": False,
        },
        "separate_gates": {
            "proof_size": (
                "105% is the weight-wire target; a preselected 125-150% "
                "exploratory cap is usable only when the complete certificate "
                "also passes 35/115 MB and 3.5x"
            ),
            "privacy": (
                "weight Q_root and response/state Q_B/Q_KV are separately "
                "derived from their exact masking/ZK theorems"
            ),
            "setup": (
                "2.00x/2.10x remain target/baseline; an exploratory ceiling "
                "near 3x also requires preregistered absolute disk, setup-wall "
                "and refresh-wall caps"
            ),
            "prover": "each attempt must retain one packed scan and bounded memory",
            "single_minimum_across_these_gates_valid": False,
            "credit": False,
        },
        "model_scaling_gate": {
            "rule": (
                "after unstacking to fixed 141-symbol leaves and Fp limbs, "
                "logical PCS samples, ZK-alphabet query atoms, unique leaves "
                "and visible-symbol caps may each grow by at most the owner-"
                "authorized 30% hard tolerance from GPT-2 to 31B; this does "
                "not transfer slack to the independent 105% weight-wire target "
                "or its conditional 125-150% exploratory band"
            ),
            "constrained_counts": [
                "logical_pcs_samples",
                "zk_alphabet_query_atoms",
                "unique_opened_leaves",
                "visible_masked_base_field_symbols",
            ],
            "gpt2": None,
            "gemma_31b": None,
            "original_preferred_growth_ratio": float(
                original_query_growth_tolerance
            ),
            "original_1_05_disposition": "NO_GO_after_two_bounded_screens",
            "max_normalized_query_count_growth_ratio": float(
                active_query_growth_tolerance
            ),
            "equivalent_max_query_exponent": math.log(
                float(active_query_growth_tolerance)
            )
            / math.log(float(GEMMA_ENVELOPE["weights"]) / float(GPT2["weights"])),
            "known_Fp2_formula_controls": {
                "logical_pcs_samples_growth": 1_054 / 831,
                "unstacked_Fp_position_growth": 24_128 / 19_104,
                "both_within_active_1_30": True,
                "not_Z_atom_U_leaf_or_S_visible_Fp": True,
            },
            "passes": False,
            "merkle_paths_may_grow_only_if_complete_proof_bytes_still_pass": True,
            "credit": False,
        },
        "candidate_query_laws": {
            "whir_unique_decoding": {
                "published_label": "O(lambda) grouped queries for suitable parameters",
                "disposition": "selected_theorem_carrier_only_unstack_grouped_alphabet_and_leaf_alignment",
            },
            "constrained_code_hvzk_2026_391": {
                "published_label": "O(lambda) queries over an N-dependent alphabet",
                "disposition": "census_only_hvzk_is_not_stateful_malicious_dv_privacy",
            },
            "ligerito": {
                "published_label": "log^2(N)/loglog(N) proof law and level schedule",
                "disposition": "fails_constant_normalized_query_gate_until_exact_counter_refutes",
            },
            "era_codeswitch": {
                "published_label": "O(lambda*log(N)) field-element queries",
                "disposition": "fails_constant_normalized_query_gate_as_published",
            },
        },
        "public_hash_choice": {
            "blake3_leaf_and_tree_eligible": True,
            "blake3_selected_as_public_leaf_and_tree_function": True,
            "blake3_selected_as_concrete_binding_primitive": True,
            "blake3_selection_does_not_supply_root_hiding": True,
            "private_hash_checker_required": False,
            "canonical_domain_position_length_binding_required": True,
            "collision_and_position_binding_proved": False,
            "randomized_encoding_root_hiding_proved": False,
            "leaf_digest_serialized_when_recomputable": False,
            "opened_salt_bytes_per_unique_leaf": LEAF_SALT_BITS // 8,
            "poseidon2_policy3_control_selected": False,
            "terminal_evaluation_serialized_clear": False,
            "credit": False,
        },
        "anti_x4d_setup_privacy_screen": {
            "scope": (
                "illustrative c0=4.4 append-t-symbol randomized encoding; "
                "not a selected backend or Q_root unit"
            ),
            "formula": "A_setup ~= 1 + 32*c_eff/141, c_eff=c0*(1+t/N)",
            "c0": 4.4,
            "max_c_eff_target_2_00": 4.40625,
            "max_c_eff_hard_2_10": 4.846875,
            "max_t_over_n_target": (
                f"{era_like_target_t_over_n.numerator}/"
                f"{era_like_target_t_over_n.denominator}"
            ),
            "max_t_over_n_hard": (
                f"{era_like_hard_t_over_n.numerator}/"
                f"{era_like_hard_t_over_n.denominator}"
            ),
            "models": {
                str(GPT2["name"]): appended_symbol_screen(int(GPT2["weights"])),
                str(GEMMA_ENVELOPE["name"]): appended_symbol_screen(
                    int(GEMMA_ENVELOPE["weights"])
                ),
            },
            "counts_metadata_or_persistent_payload_oracle": False,
            "credit": False,
        },
        "credit": False,
    }


def model_report(
    model: dict[str, object], chunk_bytes: int, bandwidth: float
) -> dict[str, object]:
    components = certificate_components(model)
    total = sum(int(component["bytes"]) for component in components.values())
    weight_target = int(components["B_weight_ALFC"]["bytes"])
    weight_target_105 = (
        weight_target * WEIGHT_WIRE_TARGET_NUMERATOR
        // WEIGHT_WIRE_TARGET_DENOMINATOR
    )
    weight_exploratory_min = (
        weight_target * WEIGHT_WIRE_EXPLORATORY_MIN_NUMERATOR
        // WEIGHT_WIRE_EXPLORATORY_DENOMINATOR
    )
    weight_exploratory_max = (
        weight_target * WEIGHT_WIRE_EXPLORATORY_MAX_NUMERATOR
        // WEIGHT_WIRE_EXPLORATORY_DENOMINATOR
    )
    weight_target_reserve = weight_target_105 - weight_target
    payload_only_leaf_bounds = {}
    for symbols_per_leaf in DIGEST_ONLY_LEAF_CANDIDATES:
        payload_only_leaf_bounds[str(symbols_per_leaf)] = {
            "Fp": {
                "registered_component_allocation": weight_target
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "target_105_percent": weight_target_105
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "exploratory_125_percent": weight_exploratory_min
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "exploratory_150_percent": weight_exploratory_max
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "target_reserve_only": weight_target_reserve
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
            },
            "Fp2": {
                "registered_component_allocation": weight_target
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "target_105_percent": weight_target_105
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "exploratory_125_percent": weight_exploratory_min
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "exploratory_150_percent": weight_exploratory_max
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "target_reserve_only": weight_target_reserve
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
            },
        }
    total_at_weight_target_105 = total - weight_target + weight_target_105
    total_at_weight_exploratory_min = (
        total - weight_target + weight_exploratory_min
    )
    total_at_weight_exploratory_max = (
        total - weight_target + weight_exploratory_max
    )
    segments = terminal_segments(model)
    compute_cells = (
        int(model["layers"]) * RESPONSE_TOKENS * int(model["d_model"]) ** 2
    )
    boundary_cells = int(model["layers"]) * RESPONSE_TOKENS * int(model["d_model"])
    kv_cells = (
        2
        * int(model["layers"])
        * int(model["kv_heads"])
        * int(model["head_dim"])
        * SUCCESSOR_CONTEXT_TOKENS
    )
    return {
        "model": model,
        "workload_proxies": {
            "compute_cells": compute_cells,
            "boundary_cells": boundary_cells,
            "successor_K_and_V_cells": kv_cells,
        },
        "terminal_segments": segments,
        "certificate": {
            "components": components,
            "total": byte_result(
                total,
                "sum_of_allocation_caps_not_a_compiled_certificate",
                "B_compute+B_boundary_commitments+B_state+B_weight_ALFC+B_MAC+B_framing",
            ),
            "compiled_certificate_bytes_counted": False,
            "plane_budget_control_wire": {
                "compiled_plane_assignment_receipt_and_auth_bytes": None,
                "assigned_once_to_boundary_state_or_framing": False,
                "status": "unknown_fail_closed",
                "credit": False,
            },
            "weight_oracle_query_wire_envelope": {
                "included_in_B_weight_ALFC_not_additive": True,
                "registered_component_allocation_bytes": weight_target,
                "target_ceiling_105_percent_bytes": weight_target_105,
                "target_reserve_over_allocation_bytes": weight_target_reserve,
                "exploratory_hard_band_percent": [125, 150],
                "exploratory_hard_band_bytes": {
                    "minimum_125_percent": weight_exploratory_min,
                    "maximum_150_percent": weight_exploratory_max,
                },
                "selected_exploratory_hard_percent": None,
                "selection_must_precede_compiled_measurement": True,
                "exploratory_hard_requires_complete_certificate_caps": {
                    "gpt2_bytes": EXPLORATORY_GPT2_CERTIFICATE_LIMIT_BYTES,
                    "gemma_31b_bytes": EXPLORATORY_LARGE_CERTIFICATE_LIMIT_BYTES,
                    "large_to_gpt2_growth": EXPLORATORY_MAX_LARGE_TO_GPT2_GROWTH,
                },
                "compiled_weight_oracle_query_bytes": None,
                "compiled_weight_oracle_interactive_challenge_bytes": None,
                "compiled_omega_profile_receipt_and_auth_bytes": None,
                "challenge_messages_are_serialized": True,
                "response_wide_beta_gamma_counted_elsewhere_exactly_once": True,
                "fiat_shamir_transform_selected": False,
                "status": "unknown_fail_closed",
                "payload_only_unique_leaf_upper_bounds": payload_only_leaf_bounds,
                "upper_bound_warning": (
                    "reserves zero bytes for opened salts, digests, multiproofs, "
                    "masked IOP messages, omega/profile/reservation authentication, "
                    "terminal authentication or framing"
                ),
                "credit": False,
            },
            "total_if_weight_envelope_uses_target_105": byte_result(
                total_at_weight_target_105,
                "allocation_sensitivity_not_a_compiled_certificate",
                "certificate_allocation-B_weight_ALFC+105pct_target",
            ),
            "total_if_weight_envelope_uses_exploratory_125": byte_result(
                total_at_weight_exploratory_min,
                "allocation_sensitivity_not_a_compiled_certificate",
                "certificate_allocation-B_weight_ALFC+125pct_exploratory",
            ),
            "total_if_weight_envelope_uses_exploratory_150": byte_result(
                total_at_weight_exploratory_max,
                "allocation_sensitivity_not_a_compiled_certificate",
                "certificate_allocation-B_weight_ALFC+150pct_exploratory",
            ),
            "unknown_components_fail_closed": [
                "operator_protocol",
                "masked_oracle_query_compiler_and_privacy_theorem",
                "concrete_codec",
            ],
            "credit": False,
        },
        "source_functional_scan_target": online_scan(
            model, chunk_bytes, bandwidth
        ),
        "illustrative_era_artifact_volume_screen": illustrative_era_setup_and_refresh(
            model, bandwidth
        ),
        "policy3_one_stage_ra_poseidon_screen": c7_policy3_ra_leaf_screen(model),
        "credit": False,
    }


def growth_screen() -> dict[str, object]:
    small = int(GPT2["weights"])
    large = int(GEMMA_ENVELOPE["weights"])
    ratio = large / small
    laws = {
        "log_N": (math.log(large) / math.log(small), "ln(N)"),
        "log2_N_over_loglog_N": (
            (math.log2(large) ** 2 / math.log2(math.log2(large)))
            / (math.log2(small) ** 2 / math.log2(math.log2(small))),
            "log2(N)^2/log2(log2(N))",
        ),
        "log2_N": ((math.log(large) / math.log(small)) ** 2, "ln(N)^2"),
        "N_to_1_over_4": (ratio**0.25, "N^(1/4)"),
        "sqrt_N": (math.sqrt(ratio), "N^(1/2)"),
        "N": (ratio, "N"),
    }
    return {
        "weight_ratio_R": ratio,
        "exponent_threshold_for_3x": math.log(3) / math.log(ratio),
        "exponent_threshold_for_3_5x": math.log(3.5) / math.log(ratio),
        "exponent_threshold_for_6x": math.log(6) / math.log(ratio),
        "laws": {
            name: {
                "formula": formula,
                "growth": growth,
                "within_3x": growth <= 3,
                "within_6x": growth <= 6,
                "credit": False,
            }
            for name, (growth, formula) in laws.items()
        },
        "credit": False,
    }


def security_screen() -> dict[str, object]:
    response_epsilon = Fraction(
        RESPONSE_BAD_EVENT_BUDGET_CAP, 1 << RESPONSE_EVENT_BITS
    )
    hash_epsilon = Fraction(1, 1 << 128)
    pcg_epsilon = Fraction(1, 1 << 128)
    state_epsilon = Fraction(1, 1 << 120)
    framing_epsilon = Fraction(1, 1 << 128)
    connection_epsilon = (
        R_MAX * response_epsilon
        + hash_epsilon
        + pcg_epsilon
        + state_epsilon
        + framing_epsilon
    )
    connection_bits = math.log2(connection_epsilon.denominator) - math.log2(
        connection_epsilon.numerator
    )
    gpt2_rate1_domain_exponent = (int(GPT2["weights"]) - 1).bit_length() + 1
    large_rate1_domain_exponent = (
        int(GEMMA_ENVELOPE["weights"]) - 1
    ).bit_length() + 1
    gpt2_gap_error = Fraction(
        1 << gpt2_rate1_domain_exponent, GOLDILOCKS_FP2_CARDINALITY
    )
    large_gap_error = Fraction(
        1 << large_rate1_domain_exponent, GOLDILOCKS_FP2_CARDINALITY
    )
    gpt2_gap_bits = certified_bits(gpt2_gap_error)
    large_gap_bits = certified_bits(large_gap_error)
    largest_static_leaf_count = ceil_div(
        int(GEMMA_ENVELOPE["weights"]) * ERA_INVERSE_RATE_NUMERATOR
        // ERA_INVERSE_RATE_DENOMINATOR,
        LOGICAL_LEAF_SYMBOLS,
    )
    leaf_hit = Fraction(
        2 * largest_static_leaf_count * LEAF_ORACLE_QUERY_SCREEN,
        1 << LEAF_SALT_BITS,
    )
    leaf_hit_bits = math.log2(leaf_hit.denominator) - math.log2(
        leaf_hit.numerator
    )
    leaf_hit_192 = Fraction(
        2 * largest_static_leaf_count * LEAF_ORACLE_QUERY_SCREEN,
        1 << 192,
    )
    leaf_hit_192_bits = math.log2(leaf_hit_192.denominator) - math.log2(
        leaf_hit_192.numerator
    )
    return {
        "R_max": R_MAX,
        "R_max_scope": "accepted responses + failed attempts + retries + selective aborts",
        "shared_Delta_connection_scoped": True,
        "challenge_field": (
            "selected Goldilocks Fp3 with one shared Delta and canonical three-limb "
            "encoding; Lean proves coordinate linearity, while the concrete Rust "
            "codec/shared-Delta adapter refinement remains open"
        ),
        "one_time_correlations_and_masks_burn_on_abort": True,
        "malicious_verifier_key_schedule": {
            "lean_model": "Delta and total Nat-to-F key tape fixed upfront; challenges and chi adaptive",
            "connection_key_tape_seed_or_domain_fixed_before_responses": True,
            "attempt_interval_reserved_before_witness_dependent_bytes": True,
            "attempt_interval_count": None,
            "attempt_interval_count_source": "J_cap(concrete codec, public shape)",
            "lazy_indexed_expansion_allowed": True,
            "unused_suffix_burned_on_every_outcome": True,
            "adaptive_post_correction_keys_allowed": False,
            "real_pcg_vole_refinement_proved": False,
            "credit": False,
        },
        "sampling_commit_private_open_schedule": {
            "order": [
                "client_entropy_commit",
                "provider_seed_commit",
                "client_entropy_open",
                "response_tokens_roots_and_first_messages",
                "relation_proves_private_provider_seed_opening_and_coin_use",
            ],
            "public_commitment_count": 2,
            "public_opening_count": 1,
            "provider_seed_opening_serialized": False,
            "fixed_payload_bytes_before_framing": 96,
            "framing_bytes": None,
            "reconciled_into_B_framing": False,
            "hash_collision_binding_proved": False,
            "client_entropy_hiding_until_provider_commit_proved": False,
            "provider_seed_hiding_from_verifier_proved": False,
            "credit": False,
        },
        "response_bad_event_budget_cap": RESPONSE_BAD_EVENT_BUDGET_CAP,
        "event_registry_complete": False,
        "bits_per_bad_event": RESPONSE_EVENT_BITS,
        "epsilon_response_exact": (
            f"{response_epsilon.numerator}/{response_epsilon.denominator}"
        ),
        "response_composed_bits": math.log2(response_epsilon.denominator)
        - math.log2(response_epsilon.numerator),
        "other_terms": {
            "hash": "2^-128 allocation; not yet derived from a concrete commitment",
            "PCG": "2^-128",
            "state_replay_collision": "2^-120",
            "framing": "2^-128",
        },
        "formula": "R_max*(64*2^-110) + 2^-128 + 2^-128 + 2^-120 + 2^-128",
        "epsilon_connection_exact": (
            f"{connection_epsilon.numerator}/{connection_epsilon.denominator}"
        ),
        "connection_security_bits": connection_bits,
        "target_bits": 78,
        "conditional_budget_fits_78": connection_bits >= 78,
        "current_protocol_security_gate_pass": False,
        "classification": (
            "conditional_union_budget_arithmetic_not_a_security_proof"
        ),
        "strict_ud_algebraic_screen": {
            "scope": "rate_1_over_2_starting_proximity_gap_formula_control",
            "Goldilocks_modulus": GOLDILOCKS_MODULUS,
            "Fp2_cardinality": GOLDILOCKS_FP2_CARDINALITY,
            "Fp2_cardinality_bit_length_informational_only": (
                GOLDILOCKS_FP2_CARDINALITY.bit_length()
            ),
            "error_upper_bound": "epsilon_gap <= 2^(D+rate)/p^2",
            "starting_error_upper_bound_exact": {
                str(GPT2["name"]): (
                    f"{gpt2_gap_error.numerator}/{gpt2_gap_error.denominator}"
                ),
                str(GEMMA_ENVELOPE["name"]): (
                    f"{large_gap_error.numerator}/{large_gap_error.denominator}"
                ),
            },
            "certified_per_starting_challenge_bits_lower_bound": {
                str(GPT2["name"]): gpt2_gap_bits,
                str(GEMMA_ENVELOPE["name"]): large_gap_bits,
            },
            "certified_after_R_max_bits_lower_bound_before_other_terms": {
                str(GPT2["name"]): gpt2_gap_bits - math.log2(R_MAX),
                str(GEMMA_ENVELOPE["name"]): large_gap_bits
                - math.log2(R_MAX),
            },
            "bare_per_attempt_bits_for_78_after_R_max": 78 + math.log2(R_MAX),
            "registered_per_attempt_reserve_bits": TARGET_RESPONSE_EVENT_BITS,
            "additional_certified_bits_needed_for_large_registered_reserve": (
                TARGET_RESPONSE_EVENT_BITS - large_gap_bits
            ),
            "inherited_unamplified_Fp2_bound_admission_pass": False,
            "tighter_analysis_or_amplifier_selected": False,
            "tight_attack_or_impossibility_proved": False,
            "retained_fiat_shamir_pow_available_under_Q_FS_0": False,
            "credit": False,
        },
        "leaf_commitment_hiding_screen": {
            "status": "historical_policy3_screen_not_active_policy2_budget",
            "salt_bits": LEAF_SALT_BITS,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "largest_static_weight_leaf_count_screen": largest_static_leaf_count,
            "adversarial_leaf_oracle_queries_screen": LEAF_ORACLE_QUERY_SCREEN,
            "formula": "2*L_static*Q_leaf/2^salt_bits",
            "hit_probability_exact": f"{leaf_hit.numerator}/{leaf_hit.denominator}",
            "effective_bits": leaf_hit_bits,
            "salt_192_effective_bits_same_screen": leaf_hit_192_bits,
            "salt_192_disposition": "reject",
            "Q_leaf_is_not_R_max": True,
            "connection_wide_leaf_count_complete": False,
            "concrete_leaf_function_implemented": True,
            "concrete_arithmetizable_commitment_selected": False,
            "binding_error_derived": False,
            "credit": False,
        },
        "challenge_generation": {
            "mode_selected": True,
            "selected_mode": SELECTED_CHALLENGE_MODE,
            "mode_definition": (
                "fresh honest-DV challenges after their committed prefixes; "
                "serialize them in the durable transcript"
            ),
            "fiat_shamir_status": (
                "quarantined_not_used_by_selected_protocol"
            ),
            "adversarial_fiat_shamir_query_bound": (
                SELECTED_FIAT_SHAMIR_QUERY_BOUND
            ),
            "rho_beta_gamma_serialized": True,
            "honest_dv_randomness_fresh_per_committed_prefix": True,
            "honest_dv_entropy_delivery_instantiated": False,
            "interactive_transcript_binding_proved": False,
            "abort_burns_reserved_attempt": True,
            "warning": (
                "a roughly 128-bit Fp2 challenge loses log2(Q_FS) bits "
                "under a direct ROM grinding bound; this is why FS is not selected"
            ),
            "credit": False,
        },
        "credit": False,
    }


def build_report(chunk_bytes: int, bandwidth_bytes_per_second: float) -> dict[str, object]:
    small = model_report(GPT2, chunk_bytes, bandwidth_bytes_per_second)
    large = model_report(GEMMA_ENVELOPE, chunk_bytes, bandwidth_bytes_per_second)
    fp3_field_and_terminal = r08_fp3_field_and_terminal_screen()

    # First close the root-capacity fixed point from the pre-mask codec.  GPT-2
    # crosses from 2^27 to 2^28 coefficients once its selected Q_root is added;
    # Gemma remains at 2^35.  The final codec below must reproduce these roots.
    small_provisional_codec = r08_fp3_opening_codec_screen(
        GPT2,
        R08_PROVISIONAL_PRE_MASK_FP3_SCHEDULES[str(GPT2["name"])],
    )
    large_provisional_codec = r08_fp3_opening_codec_screen(
        GEMMA_ENVELOPE,
        R08_PROVISIONAL_PRE_MASK_FP3_SCHEDULES[
            str(GEMMA_ENVELOPE["name"])
        ],
    )
    small_provisional_capacity = r08_rs_t_query_capacity_screen(
        GPT2,
        int(small_provisional_codec["totals"]["S_visible_Fp"]),
        int(small_provisional_codec["rounds"][0]["S_visible_Fp_reserved_cap"]),
    )
    large_provisional_capacity = r08_rs_t_query_capacity_screen(
        GEMMA_ENVELOPE,
        int(large_provisional_codec["totals"]["S_visible_Fp"]),
        int(large_provisional_codec["rounds"][0]["S_visible_Fp_reserved_cap"]),
    )
    small_provisional_profile = r08_concrete_root_profile_proposal(
        GPT2, small_provisional_capacity, 1 << 9
    )
    large_provisional_profile = r08_concrete_root_profile_proposal(
        GEMMA_ENVELOPE, large_provisional_capacity, 1 << 13
    )
    small_selected_dimension = int(
        small_provisional_profile["RS_total_coefficient_dimension"]
    )
    large_selected_dimension = int(
        large_provisional_profile["RS_total_coefficient_dimension"]
    )
    small_selected_variables = small_selected_dimension.bit_length() - 1
    large_selected_variables = large_selected_dimension.bit_length() - 1

    small_fp3_audit = r08_selected_extension_strict_audit(
        GPT2,
        R08_SELECTED_FP3_SCHEDULES[str(GPT2["name"])],
        3,
        small_selected_variables,
    )
    large_fp3_audit = r08_selected_extension_strict_audit(
        GEMMA_ENVELOPE,
        R08_SELECTED_FP3_SCHEDULES[str(GEMMA_ENVELOPE["name"])],
        3,
        large_selected_variables,
    )
    small_fp3_codec = r08_fp3_opening_codec_screen(
        GPT2,
        R08_SELECTED_FP3_SCHEDULES[str(GPT2["name"])],
        small_selected_variables,
    )
    large_fp3_codec = r08_fp3_opening_codec_screen(
        GEMMA_ENVELOPE,
        R08_SELECTED_FP3_SCHEDULES[str(GEMMA_ENVELOPE["name"])],
        large_selected_variables,
    )
    small_fp3_totals = small_fp3_codec["totals"]
    large_fp3_totals = large_fp3_codec["totals"]
    small_t_query_capacity = r08_rs_t_query_capacity_screen(
        GPT2,
        int(small_fp3_totals["S_visible_Fp"]),
        int(small_fp3_codec["rounds"][0]["S_visible_Fp_reserved_cap"]),
    )
    large_t_query_capacity = r08_rs_t_query_capacity_screen(
        GEMMA_ENVELOPE,
        int(large_fp3_totals["S_visible_Fp"]),
        int(large_fp3_codec["rounds"][0]["S_visible_Fp_reserved_cap"]),
    )
    small_root_mask_prg = r08_root_mask_prg_policy_screen(
        GPT2, small_t_query_capacity
    )
    large_root_mask_prg = r08_root_mask_prg_policy_screen(
        GEMMA_ENVELOPE, large_t_query_capacity
    )
    small_root_profile = r08_concrete_root_profile_proposal(
        GPT2, small_t_query_capacity, 1 << 9
    )
    large_root_profile = r08_concrete_root_profile_proposal(
        GEMMA_ENVELOPE, large_t_query_capacity, 1 << 13
    )
    assert (
        int(small_root_profile["RS_total_coefficient_dimension"])
        == small_selected_dimension
    )
    assert (
        int(large_root_profile["RS_total_coefficient_dimension"])
        == large_selected_dimension
    )
    small_fp3_setup = r08_fp3_setup_resource_screen(
        GPT2, bandwidth_bytes_per_second, small_selected_dimension
    )
    large_fp3_setup = r08_fp3_setup_resource_screen(
        GEMMA_ENVELOPE, bandwidth_bytes_per_second, large_selected_dimension
    )
    small_online_rs_open = r08_online_rs_batch_open_screen(
        GPT2, small_root_profile, small_fp3_setup, small_fp3_codec
    )
    large_online_rs_open = r08_online_rs_batch_open_screen(
        GEMMA_ENVELOPE, large_root_profile, large_fp3_setup, large_fp3_codec
    )
    small_blake3_fallback = r08_blake3_fallback_privacy_variant(
        small_root_profile
    )
    large_blake3_fallback = r08_blake3_fallback_privacy_variant(
        large_root_profile
    )
    small_kmac_mainline = r08_kmacxof256_mainline_screen(
        small_root_profile
    )
    large_kmac_mainline = r08_kmacxof256_mainline_screen(
        large_root_profile
    )
    fp3_opening_growth = {
        key: large_fp3_totals[key] / small_fp3_totals[key]
        for key in ("q_open", "Z_atom", "U_leaf", "S_visible_Fp")
    }
    fp3_known_bytes = {
        str(GPT2["name"]): small_fp3_totals["known_serialized_bytes"],
        str(GEMMA_ENVELOPE["name"]): large_fp3_totals["known_serialized_bytes"],
    }
    small_total = int(small["certificate"]["total"]["bytes"])
    large_total = int(large["certificate"]["total"]["bytes"])
    certificate_growth = large_total / small_total
    return {
        "schema": "volta-c7-stateful-alfc-r08-screen-v27",
        "design": "C7 stateful authenticated linear-functional commitment",
        "screening_only": True,
        "credit": False,
        "authorization": {
            "r07_carrier_and_pareto_checkpoint_authorized": True,
            "r08_codec_security_bytes_resources_design_authorized": True,
            "batch_open_blocks_cpu_reference_authorized_now": False,
            "batch_open_blocks_cpu_reference_pre_authorized_after_checkpoint": False,
            "batch_open_blocks_cpu_reference_requires_backend_checkpoint": True,
            "tiny_cpu_screen_completed": True,
            "optimized_simt_kernel_authorized": False,
            "simt_requires_c7_cpu_reference_pass": True,
            "large_prover_or_e2e_execution_authorized": False,
            "pod_contact_or_execution_authorized": False,
            "pod_preparation_only": True,
            "c7_cpu_reference_pass": False,
            "c7_pod_ready": False,
            "former_selected_RS_realization_no_go": True,
            "owner_design_decision_required_before_more_implementation": False,
            "new_shared_carrier_tournament_authorized": True,
            "strict_ud_RS_demoted_to_control_baseline": True,
            "strict_ud_RS_prover_authorized": False,
            "carrier_independent_Fp3_codec_KAT_MAC_adapter_authorized": True,
            "carrier_independent_Fp3_seam_implemented": True,
            "carrier_independent_policy2_reference_authorized": True,
            "tiny_non_PCS_conformance_test_implemented": True,
            "published_carriers_baseline_controls_only": True,
            "C7_codesigned_circuit_main_research_line": True,
            "C7_secret_point_quotient_research_authorized": True,
            "C7_secret_point_butterfly_reduction_screened": True,
            "C7_secret_point_butterfly_carrier_admitted": False,
            "C7_codesigned_pre_CPU_screen_pass": False,
            "tiny_CPU_prototype_authorized_now": False,
        },
        "privacy_policy": {
            "active": 2,
            "last_tested": 3,
            "active_status": "spbt_reduction_pass_delayed_opening_no_go",
            "last_tested_policy3_terminal_shape": (
                "digest-only salted leaf commitment with public Merkle paths "
                "and attempt-local VOLE-private leaf/PCS checks"
            ),
            "policy_3_candidate_exhaustion_documented": True,
            "terminal_catalog": {
                "published_clear_query_pcs_hvzk": "reject_no_clear_policy",
                "one_stage_ra": "reject_distance_and_ordered_root_setup",
                "raa_two_stage_era": "reject_N_intermediate_or_qN",
                "full_dense_root_and_dot": "reject_full_nonlinear_per_response_circuit_and_no_one_pass_schedule",
                "poseidon2_leaf": "reject_composed_backend_setup_and_checker_missing",
                "blake3_leaf": "reject_private_checker_and_byte_census_missing",
                "ligesis_subset_sum": "reject_collision_resistance_only_no_hiding_and_c7_tree_floor_2.5887x",
                "linear_leaf": "reject_constructed_collisions",
                "group_lattice_leaf": "reject_non_native_or_msm_setup_gates",
                "preprocessing_evaluation_binding": "reject_missing_strong_binding_knowledge_soundness",
            },
            "policy_2_status": "active_design_only",
            "policy_2_activation_authorized": True,
            "policy_2_root_mask_main_line": "computational_per_root_seed_PRG_PCG",
            "policy_2_root_mask_baseline": "persisted_uniform_Fp_coefficients",
            "policy_2_root_mask_primary_candidate": "keyed_BLAKE3_XOF",
            "policy_2_root_mask_fallback_candidate": "KMACXOF256",
            "policy_2_PRG_failure_may_not_reduce_78bit_target": True,
            "policy_2_privacy_declared_computational": True,
            "policy_2_Adv_root_mask_PRG_in_78_bit_budget": True,
            "policy_2_root_wide_query_horizon_schema_registered": True,
            "policy_2_root_wide_query_horizon_instantiated": False,
            "policy_2_concrete_root_profile_proposals_compiled": True,
            "policy_2_concrete_root_profile_owner_selected_for_fallback": True,
            "policy_2_concrete_root_profile_owner_selected_for_mainline": False,
            "policy_2_blake3_full78_fallback_owner_authorized": True,
            "policy_2_blake3_full78_fallback_admitted": False,
            "policy_2_model_global_2_pow_20_horizon_owner_confirmed": True,
            "policy_2_kmacxof256_mainline_screen_compiled": True,
            "policy_2_kmacxof256_mainline_promoted": False,
            "policy_2_kmac_64KiB_v1_codec_owner_frozen": True,
            "policy_2_complete_privacy_target_allocation_owner_approved": True,
            "policy_2_candidate_order_owner_reconfirmed": (
                "BLAKE3_primary_KMAC_unpromoted_control"
            ),
            "policy_2_exact_numeric_caps_derived": False,
            "numeric_caps_deferred_until_complete_pareto": True,
            "selected_theorem_carrier": None,
            "strict_ud_RS_role": "algebraic_and_security_control_baseline_only",
            "selected_public_leaf_tree_function": "salted_BLAKE3",
            "era_r4_role": "byte_and_prover_control_only",
            "policy_2_query_accounting_ref": "top-level policy2_query_accounting",
        },
        "admission_gates": {
            "candidate_setup_manifest_complete": False,
            "setup_disk_time_traffic_refresh_derived": False,
            "peak_resident_or_mapped_setup_bytes_counted": False,
            "numeric_setup_ceiling_registered": True,
            "weight_query_wire_envelope_registered": True,
            "proof_wire_105_is_target_not_immediate_hard_stop": True,
            "proof_wire_exploratory_125_to_150_band_registered": True,
            "proof_wire_exploratory_exact_cap_selected": False,
            "proof_wire_exploratory_total_35_115MB_3_5x_caps_registered": True,
            "setup_exploratory_3x_ceiling_registered": True,
            "setup_exploratory_absolute_disk_caps_registered": True,
            "setup_wall_targets_15m_90m_registered": True,
            "setup_exploratory_absolute_time_and_refresh_caps_selected": True,
            "logical_leaf_geometry_selected": True,
            "anti_x4d_setup_gate_pass": False,
            "active_public_leaf_function_implemented": True,
            "historical_policy3_poseidon2_leaf_implemented": True,
            "concrete_leaf_commitment_selected": True,
            "public_blake3_leaf_tree_function_selected": True,
            "leaf_commitment_adaptive_hiding_proved": False,
            "policy3_private_leaf_checker_required": False,
            "only_budgeted_masked_query_payloads_codec_proved": False,
            "terminal_evaluation_remains_authenticated": True,
            "malicious_dv_connection_privacy_theorem_complete": False,
            "policy2_model_lifetime_privacy_78bit_proved": False,
            "policy2_root_mask_seed_policy_selected": True,
            "policy2_root_mask_primary_candidate_selected": True,
            "policy2_root_mask_generator_primitive_selected": False,
            "policy2_root_mask_PRG_advantage_numeric": False,
            "policy2_rs_t_query_dimension_screen_complete": True,
            "policy2_same_root_for_Rmax_disposition": "NO_GO",
            "policy2_rs_t_query_numeric_Q_root_admitted": False,
            "policy2_concrete_R_root_profile_proposals_compiled": True,
            "policy2_concrete_R_root_profile_owner_selected_for_fallback": True,
            "policy2_concrete_R_root_profile_owner_selected_for_mainline": False,
            "policy2_blake3_full78_fallback_owner_authorized": True,
            "policy2_blake3_full78_fallback_complete_sum_pass": False,
            "policy2_model_global_2_pow_20_horizon_owner_confirmed": True,
            "policy2_kmacxof256_mainline_screen_compiled": True,
            "policy2_kmacxof256_mainline_promoted": False,
            "policy2_RS_control_online_opening_screen_complete": True,
            "policy2_RS_control_online_opening_screen_pass": False,
            "new_shared_carrier_tournament_authorized": True,
            "new_shared_carrier_tournament_complete_row_exists": False,
            "strict_ud_RS_prover_implementation_authorized": False,
            "carrier_independent_Fp3_codec_KAT_pass": True,
            "carrier_independent_Fp3_MAC_adapter_test_pass": True,
            "carrier_independent_Fp3_PCS_refinement_proved": False,
            "policy2_epoch_and_receipt_transcript_binding_proved": False,
            "policy2_single_session_receipt_state_machine_proved": False,
            "policy2_plane_charge_vector_and_durable_maps_instantiated": False,
            "policy2_no_extension_plane_assignment_cas_proved": False,
            "policy2_genesis_kv_budget_initialization_proved": False,
            "policy2_state_budget_carry_across_weight_rotation_proved": False,
            "policy2_init_rotation_query_reservations_instantiated": False,
            "policy2_disclosed_candidate_epoch_accounting_instantiated": False,
            "policy2_multiuser_vole_mac_composition_proved": False,
            "policy2_lifecycle_mac_domain_census_instantiated": False,
            "policy2_same_W_rotation_bridge_complete": False,
            "policy2_paired_history_game_formalized": False,
            "policy2_branch_derived_view_closure_proved": False,
            "policy2_boundary_and_kv_plane_privacy_horizons_derived": False,
            "policy2_allocator_privacy_integrity_proved": False,
            "policy2_receipt_unforgeability_proved": False,
            "policy2_distinct_hash_work_bounds_derived": False,
            "policy2_online_mdv_view_refine_proved": False,
            "challenge_generation_and_grinding_policy_selected": True,
            "retained_interleaved_goldilocks_domain_rule_admitted": False,
            "algebraic_security_amplifier_selected": True,
            "algebraic_security_closure_path_selected": True,
            "fp3_direct_three_limb_fallback_selected": True,
            "first_compiler_envelope_selected": (
                "rate1-k0-4-owner1_30-Fp3-flat-g141-one-root"
            ),
            "strict_ud_algebraic_110bit_per_response_derived": True,
            "strict_ud_algebraic_gap_after_Rmax_78bit_derived": True,
            "full_connection_78bit_security_derived": False,
            "honest_dv_entropy_delivery_instantiated": False,
            "interactive_challenge_transcript_binding_proved": False,
            "pure_fold_width_tail_screen_pass": False,
            "bounded_joint_sampling_screen_complete": True,
            "bounded_joint_sampling_screen_pass": False,
            "bounded_different_code_switch_screen_complete": True,
            "bounded_different_code_switch_screen_pass": False,
            "selected_carrier_original_1_05_disposition": "NO_GO",
            "owner_1_30_query_growth_fallback_active": True,
            "owner_1_30_known_q_and_unstacked_Fp_controls_pass": True,
            "owner_1_30_complete_four_axis_query_gate_pass": True,
            "joint_sampler_visible_Fp_sharing_selected": False,
            "different_code_switch_selected": False,
            "one_pass_batch_open_blocks_proved": False,
            "cpu_batch_open_blocks_reference_pass": False,
            "simt_bit_exact_equivalence_pass": False,
            "query_schedule_compiled": False,
            "opening_query_schedule_compiled": True,
            "query_counter_schema": {
                "aggregate": list(POLICY2_AGGREGATE_CENSUS_CLASSES),
                "per_plane": list(POLICY2_QUERY_CLASSES),
                "attempt_counter": "A_attempt",
                "logical_pcs_samples_q_open_by_plane_root_round": (
                    "r08_owner_decisions_and_security_codec_screen."
                    "Fp3_g141_opening_codec_screen.rounds"
                ),
                "zk_alphabet_query_atoms_by_plane_root_round": (
                    "same_round_rows_Z_atom"
                ),
            },
            "exact_query_counts_by_root_and_round": {
                str(GPT2["name"]): small_fp3_codec["rounds"],
                str(GEMMA_ENVELOPE["name"]): large_fp3_codec["rounds"],
            },
            "adversarial_leaf_oracle_query_bound": LEAF_ORACLE_QUERY_SCREEN,
            "adversarial_leaf_oracle_query_bound_kind": (
                "owner_selected_analytic_screen_not_a_concrete_theorem_cap"
            ),
            "adversarial_fiat_shamir_query_bound": (
                SELECTED_FIAT_SHAMIR_QUERY_BOUND
            ),
            "serialized_query_and_challenge_bytes_by_model": {
                str(GPT2["name"]): small_fp3_codec["totals"][
                    "known_serialized_bytes"
                ],
                str(GEMMA_ENVELOPE["name"]): large_fp3_codec["totals"][
                    "known_serialized_bytes"
                ],
            },
            "query_bytes_reconciled_into_certificate_total": False,
            "compiled_tier_a_certificate_gate_pass": False,
        },
        "batch_open_blocks_admission": {
            "state": "R08_STRICT_UD_RS_CONTROL_REALIZATION_NO_GO",
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "complexity_target": "O(N + poly(q, log N))",
            "generator_incidence_obstruction": {
                "orientation": "G in F^(k*n), Enc(m)=mG, minimum distance d",
                "row_weight_lower_bound": "wt(e_j*G) >= d",
                "nonzero_incidence_lower_bound": "nnz(G) >= k*d",
                "uniform_output_coordinate_expected_support": "nnz(G)/n >= k*d/n",
                "uniform_logical_leaf_expected_direct_incidences": (
                    "U_leaf*k*d/ceil(n/141) = U_leaf*141*k*(d/n_phys)"
                ),
                "constant_relative_distance_consequence": "Omega(U_leaf*k)",
                "weighted_query_screen": {
                    "definition": (
                        "delta_mu=min_(m!=0) Pr_(i~mu)[(mG)_i!=0]"
                    ),
                    "expected_direct_support": "E_mu wt(G[:,i]) >= k*delta_mu",
                    "edge_cases": {
                        "delta_mu=0": "no finite independent query count",
                        "delta_mu=1": "one query",
                    },
                    "formula_domain": "0 < delta_mu < 1",
                    "independent_query_lower_bound": (
                        "ceil(lambda*ln(2)/-ln(1-delta_mu))"
                    ),
                    "warning": (
                        "bias toward sparse outputs may lower detection; derive "
                        "delta_mu, and if it falls charge the increased query/proof "
                        "bytes; richer IOPs need a compiled census"
                    ),
                },
                "disposition": "reject_direct_sparse_coordinate_accumulation",
                "scope": (
                    "direct coefficient application only; not a lower bound "
                    "against a structured shared linear circuit"
                ),
            },
            "only_surviving_algorithm_shape": None,
            "RS_control_bounded_online_screen": {
                str(GPT2["name"]): small_online_rs_open,
                str(GEMMA_ENVELOPE["name"]): large_online_rs_open,
            },
            "no_complete_row_reason": (
                "direct evaluation is qN; complete-codeword persistence and "
                "materialization fail setup/memory; no pruned/shared circuit "
                "with O(N+poly(q,log N)) and exact bytes was found"
            ),
            "not_a_universal_lower_bound": True,
            "cpu_reference_contract": {
                "algorithm_selected": False,
                "reference_implemented": True,
                "reference_kind": "one-stage_RA_negative_screen_not_a_PCS",
                "cost_identity_required": (
                    "C(N,q,h)=c_source*N+P(q,h), h=ceil(log2(N)), "
                    "c_source independent of q"
                ),
                "memory_identity_required": (
                    "M(N,q,h)<=chunk+M_fixed+P_M(q,h)"
                ),
                "empirical_sweep_alone_sufficient": False,
                "packed_source_passes": 1,
                "packed_source_bytes_read": "2*N",
                "source_offsets": "strictly_monotone",
                "backward_seeks_or_reopens": 0,
                "model_linear_scratch_write_bytes": 0,
                "complete_codeword_bytes": 0,
                "expanded_weight_bytes": 0,
                "working_memory": (
                    "configured_chunk + at_most_140_symbol_carry + poly(q,log N)"
                ),
                "disk_output": "poly(q,log N) only; no source/codeword spill",
                "required_output": [
                    "exact root-bound masked PCS payload occurrences serialized under plane budgets",
                    "opened leaf salts and canonical query/leaf indices",
                    "public digests/root and exact multiproof checks",
                    "terminal evaluation only as opaque authenticated handles/corrections",
                    "source, operation, disk and memory counters",
                ],
                "hard_fail": [
                    "second packed-source pass or reread",
                    "qN or N*log(q) source-dependent work",
                    "complete codeword or model-sized scratch",
                    "resident expanded extension-field source wrapper",
                    "unreconciled operation, I/O, memory or certificate bytes",
                ],
            },
            "c7_cpu_reference_pass": False,
            "credit": False,
        },
        "new_carrier_tournament": r08_new_carrier_tournament(),
        "secret_point_dv_carrier_screen": r08c_secret_point_dv_carrier_screen(),
        "eq_to_secret_point_bridge_screen": r08d_eq_to_secret_point_bridge_screen(),
        "secret_point_butterfly_transform_screen": (
            r08e_secret_point_butterfly_transform_screen()
        ),
        "simt_path": {
            "state": "BLOCKED_BEFORE_CPU_REFERENCE_PASS",
            "stage_order": [
                "S0 analytic incidence/structure gate",
                "S1 CPU BatchOpenBlocks reference",
                "S2 C7_CPU_REFERENCE_PASS checkpoint",
                "S3 SIMT implementation of admitted phases only",
                "S4 byte-exact CPU/SIMT conformance",
                "S5 scaled local integration preflight",
            ],
            "optimized_kernel_or_scaffold_exists": False,
            "allowed_phases": [
                "streaming setup",
                "public leaf hash/Merkle",
                "PCG/VOLE",
                "MAC",
                "Fp/Fp2/Fp3 selected-extension arithmetic",
                "leaf checks",
                "reductions",
            ],
            "forbidden": [
                "complete codeword",
                "model-sized scratch",
                "second packed scan",
                "qN source work",
                "unaccounted bytes",
                "transcript or correlation-order change",
            ],
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "gpu_padding": {
                "temporary_zero_only": True,
                "persistent_bytes": 0,
                "certificate_bytes": 0,
                "leaf_commitment_hash_input_bytes": 0,
                "transcript_bytes": 0,
                "physical_width_selected": False,
                "bytes_operations_zeroing_and_peak_vram_must_be_measured": True,
            },
            "required_metrics": [
                "pass/read/reopen/seek counts and packed bytes",
                "source-dependent and query-only operations",
                "Fp/Fp2/Fp3, hash, AES, VOLE, MAC, leaf and reduction operations",
                "host disk reads/writes, scratch and fsync",
                "H2D/D2H/explicit-D2D/device-generated/device-zeroed bytes",
                "RSS/VmHWM, VRAM and pinned-memory peaks",
                "kernel launches and synchronizations by reason and wall time",
                "padding, output, certificate and transcript bytes",
            ],
            "metric_scopes": [
                "streaming_setup",
                "response_batch_open_blocks",
            ],
            "packed_source_h2d_passes_per_scope": 1,
            "cross_scope_netting_allowed": False,
            "byte_exact_cpu_simt_required": [
                "packed input interpretation and canonical query plan",
                "root-bound masked logical leaves, opened salts and canonical indices",
                "exact finite-fixture PCG/VOLE values and consumption",
                "leaf digests, root and multiproof",
                "opaque handles, corrections and correlation schedule digest",
                "transcript after every frame and challenge sequence",
                "all selected Fp2/Fp3 limbs, terminal settlement and certificate bytes",
                "CPU verifier result and atomic journal transition",
            ],
            "production_internal_value_record": (
                "domain-separated digests and counters only; no leaves, salts "
                "or PCG/VOLE secrets"
            ),
            "simt_bit_exact_equivalence_pass": False,
            "credit": False,
        },
        "pod_readiness": {
            "state": "C7_R08E_SPBT_REDUCTION_PASS_DELAYED_OPENING_NO_GO",
            "handoff_spec": "docs/c7-r03-prover-pod-handoff.md",
            "handoff_preparation_authorized": True,
            "required_before_C7_POD_READY": {
                "concrete_crypto_and_composed_security_pass": False,
                "canonical_compiler_and_query_census_pass": False,
                "cpu_batch_open_blocks_reference_pass": False,
                "one_pass_bounded_memory_schedule_pass": False,
                "setup_manifest_within_owner_envelope": False,
                "compiled_certificate_within_owner_envelope": False,
                "bounded_masked_query_codec_and_real_finite_pcg_pass": False,
                "two_response_tiny_scaled_serialized_chain_pass": False,
                "reload_full_verifier_and_mutations_pass": False,
                "abort_burn_and_atomic_promotion_pass": False,
                "clean_checkpoint_and_ledger_transition": False,
            },
            "conditional_before_C7_POD_READY": {
                "simt_selected": False,
                "simt_bit_exact_equivalence_if_selected": False,
            },
            "all_required_gates_pass": False,
            "pod_contact_requires_later_explicit_owner_GO": True,
            "credit": False,
        },
        "workload": {
            "accepted_context_tokens": ACCEPTED_CONTEXT_TOKENS,
            "response_tokens": RESPONSE_TOKENS,
            "successor_context_tokens": SUCCESSOR_CONTEXT_TOKENS,
            "same_workload_for_both_models": True,
        },
        "illustrative_ALFC_schedule_screen": {
            "logical_openings_per_response": 1,
            "terminal_MAC_settlements_per_response": 1,
            "roots": list(ROOT_NAMES),
            "root_count": ROOT_COUNT,
            "root_bytes_in_certificate": byte_result(
                ROOT_COUNT * HASH_BYTES,
                "accounting_identity",
                "4 roots*32 bytes",
            ),
            "weight_segments": "8 per layer + 2 global",
            "boundary_segments": BOUNDARY_SEGMENTS,
            "predecessor_KV_segments": PREDECESSOR_KV_SEGMENTS,
            "successor_KV_segments": SUCCESSOR_KV_SEGMENTS,
            "terminal_claim_multiplicity_per_segment": 1,
            "terminal_claim_screen_cap": TERMINAL_CLAIM_SCREEN_CAP,
            "connection_handle_screen_cap": R_MAX * TERMINAL_CLAIM_SCREEN_CAP,
            "compiled_layout_manifest": False,
            "codec_enforces_screen_cap": False,
            "hard_stop": "If any segment retains K unrelated points, replace O(N) by O(K*N); this screen no longer applies.",
            "credit": False,
        },
        "formula_labels": {
            "evidence_calibration": "Only the 4,014,000-byte ERA N=2^32, 100-bit point is imported evidence.",
            "target_allocation": "B_compute, B_boundary_commitments, B_state, B_MAC and B_framing are explicit design envelopes, not backend evidence.",
            "weight_transposition_assumption": "The ERA point remains a historical allocation calibration; no policy-2 backend or query count is selected.",
            "serialized_query_wire_ledger": "B_query_wire is the weight-oracle sub-ledger inside B_weight_ALFC; q_attempt/q_response leaf, symbol, path and attempt counters remain distinct and the compiled census is unknown.",
            "all_results": "Every byte, time and memory quantity is credit:false.",
        },
        "parameters": {
            "ERA_inverse_rate": 4.4,
            "field_symbol_bytes": FIELD_SYMBOL_BYTES,
            "packed_weight_bytes": PACKED_WEIGHT_BYTES,
            "P1_bytes_per_source_weight": PERMUTATION_INDEX_BYTES,
            "P2_bytes_per_source_weight": PERMUTATION_INDEX_BYTES,
            "multiplier_bytes_per_source_weight": MULTIPLIER_BYTES,
            "illustrative_ERA_Merkle_symbols_per_leaf": (
                ILLUSTRATIVE_ERA_MERKLE_SYMBOLS_PER_LEAF
            ),
            "digest_only_leaf_candidates": list(DIGEST_ONLY_LEAF_CANDIDATES),
            "selected_logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "setup_target_multiplier": 2.0,
            "setup_baseline_tolerance_multiplier": 2.1,
            "setup_exploratory_ceiling_multiplier": 3.0,
            "setup_wall_target_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_TARGET_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_TARGET_SECONDS,
            },
            "setup_wall_hard_cap_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_HARD_CAP_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_HARD_CAP_SECONDS,
            },
            "weight_wire_target_percent": 105,
            "weight_wire_exploratory_hard_band_percent": [125, 150],
            "leaf_salt_bits_screen": LEAF_SALT_BITS,
            "leaf_oracle_query_screen": LEAF_ORACLE_QUERY_SCREEN,
            "selected_challenge_mode": SELECTED_CHALLENGE_MODE,
            "selected_fiat_shamir_query_bound": (
                SELECTED_FIAT_SHAMIR_QUERY_BOUND
            ),
            "selected_bandwidth_GB_per_second": bandwidth_bytes_per_second / 1_000_000_000,
            "configured_chunk_MB": chunk_bytes / 1_000_000,
        },
        "growth": growth_screen(),
        "models": {str(GPT2["name"]): small, str(GEMMA_ENVELOPE["name"]): large},
        "certificate_comparison": {
            "gpt2_total": byte_result(
                small_total,
                "sum_of_allocation_caps",
                "sum of all six GPT-2 allocation components",
            ),
            "large_total": byte_result(
                large_total,
                "sum_of_allocation_caps",
                "sum of all six large-model allocation components",
            ),
            "large_to_gpt2_growth": certificate_growth,
            "allocation_partition_within_Tier_A": {
                "gpt2_at_most_30MB": small_total <= GPT2_CERTIFICATE_LIMIT_BYTES,
                "large_at_most_100MB": large_total <= LARGE_CERTIFICATE_LIMIT_BYTES,
                "large_at_most_3x_gpt2": certificate_growth
                <= MAX_LARGE_TO_GPT2_GROWTH,
            },
            "allocation_partition_within_exploratory_total_caps": {
                "gpt2_at_most_35MB": (
                    small_total <= EXPLORATORY_GPT2_CERTIFICATE_LIMIT_BYTES
                ),
                "large_at_most_115MB": (
                    large_total <= EXPLORATORY_LARGE_CERTIFICATE_LIMIT_BYTES
                ),
                "large_at_most_3_5x_gpt2": (
                    certificate_growth
                    <= EXPLORATORY_MAX_LARGE_TO_GPT2_GROWTH
                ),
            },
            "credit": False,
        },
        "r07_owner_exploratory_relaxations": {
            "proof_wire": {
                "target_percent": 105,
                "exploratory_hard_band_percent": [125, 150],
                "selected_hard_percent": None,
                "selection_must_precede_compiled_measurement": True,
                "conditional_complete_certificate_caps": {
                    "gpt2_bytes": EXPLORATORY_GPT2_CERTIFICATE_LIMIT_BYTES,
                    "gemma_31b_bytes": EXPLORATORY_LARGE_CERTIFICATE_LIMIT_BYTES,
                    "large_to_gpt2_growth": (
                        EXPLORATORY_MAX_LARGE_TO_GPT2_GROWTH
                    ),
                },
                "complete_compiled_gate_pass": False,
            },
            "setup": {
                "target_multiplier": 2.0,
                "baseline_tolerance_multiplier": 2.1,
                "exploratory_ceiling_multiplier": 3.0,
                "absolute_persistent_disk_caps_bytes": {
                    str(GPT2["name"]): (
                        int(GPT2["weights"])
                        * PACKED_WEIGHT_BYTES
                        * SETUP_EXPLORATORY_NUMERATOR
                        // SETUP_EXPLORATORY_DENOMINATOR
                    ),
                    str(GEMMA_ENVELOPE["name"]): (
                        int(GEMMA_ENVELOPE["weights"])
                        * PACKED_WEIGHT_BYTES
                        * SETUP_EXPLORATORY_NUMERATOR
                        // SETUP_EXPLORATORY_DENOMINATOR
                    ),
                },
                "setup_wall_targets_seconds": {
                    str(GPT2["name"]): GPT2_SETUP_WALL_TARGET_SECONDS,
                    str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_TARGET_SECONDS,
                },
                "setup_wall_tolerance_caps_seconds": {
                    str(GPT2["name"]): GPT2_SETUP_WALL_HARD_CAP_SECONDS,
                    str(GEMMA_ENVELOPE["name"]): (
                        GEMMA_SETUP_WALL_HARD_CAP_SECONDS
                    ),
                },
                "refresh_wall_targets_seconds": {
                    str(GPT2["name"]): GPT2_SETUP_WALL_TARGET_SECONDS,
                    str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_TARGET_SECONDS,
                },
                "refresh_wall_hard_caps_seconds": {
                    str(GPT2["name"]): GPT2_SETUP_WALL_HARD_CAP_SECONDS,
                    str(GEMMA_ENVELOPE["name"]): (
                        GEMMA_SETUP_WALL_HARD_CAP_SECONDS
                    ),
                },
                "refresh_counters_independent_from_setup": True,
                "refresh_budget_transfer_allowed": False,
                "refresh_test_authorized_or_required_in_R08": False,
                "refresh_status": "registered_not_tested_not_credited",
                "time_caps_must_be_preregistered_before_measurement": True,
                "all_absolute_caps_selected": True,
                "complete_compiled_gate_pass": False,
            },
            "no_tolerance_transfer": True,
            "credit": False,
        },
        "r08_owner_decisions_and_security_codec_screen": {
            "fixed_carrier": (
                "RS_t_query_ZK_plus_strict_UD_WHIR_or_Ligerito"
            ),
            "starting_rate": "1/2",
            "first_fold": 4,
            "packed_weight_roots": 1,
            "logical_leaf_symbols": LOGICAL_LEAF_SYMBOLS,
            "challenge_mode": SELECTED_CHALLENGE_MODE,
            "Q_FS": SELECTED_FIAT_SHAMIR_QUERY_BOUND,
            "owner_confirmations": {
                "KMACXOF256_64KiB_chunk_and_v1_descriptor_frozen": True,
                "complete_privacy_target_allocation_approved": True,
                "BLAKE3_remains_primary_for_performance_and_parallelism": True,
                "KMACXOF256_remains_unpromoted_high_margin_control": True,
            },
            "future_Fiat_Shamir_rule": {
                "changes_current_interactive_protocol": False,
                "current_Q_FS": 0,
                "root_mask_PRG_and_transcript_hash_are_distinct_roles": True,
                "KMACXOF256_preferred_if_security_margin_has_priority": True,
                "BLAKE3_preferred_if_performance_parallelism_has_priority": True,
                "BLAKE3_requires_tightly_preregistered_Q_FS": True,
                "full_ROM_multi_target_proof_byte_budget_required_before_selection": True,
                "future_primitive_selected_now": False,
            },
            "setup_wall_targets_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_TARGET_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_TARGET_SECONDS,
            },
            "setup_wall_tolerance_caps_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_HARD_CAP_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_HARD_CAP_SECONDS,
            },
            "refresh_wall_targets_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_TARGET_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_TARGET_SECONDS,
            },
            "refresh_wall_hard_caps_seconds": {
                str(GPT2["name"]): GPT2_SETUP_WALL_HARD_CAP_SECONDS,
                str(GEMMA_ENVELOPE["name"]): GEMMA_SETUP_WALL_HARD_CAP_SECONDS,
            },
            "refresh_counters_independent_from_setup": True,
            "refresh_budget_transfer_allowed": False,
            "refresh_test_authorized_or_required_in_R08": False,
            "refresh_status": "registered_not_tested_not_credited",
            "Fp2_strict_schedule_audit": {
                str(GPT2["name"]): r08_selected_fp2_strict_audit(
                    GPT2, R08_SELECTED_FP2_SCHEDULES[str(GPT2["name"])]
                ),
                str(GEMMA_ENVELOPE["name"]): r08_selected_fp2_strict_audit(
                    GEMMA_ENVELOPE,
                    R08_SELECTED_FP2_SCHEDULES[str(GEMMA_ENVELOPE["name"])],
                ),
            },
            "security_disposition": (
                "Fp2_fails; owner_selects_direct_Fp3_and_retains_78_bit_"
                "connection_target"
            ),
            "selected_codec_field": "Goldilocks_Fp3",
            "selected_terminal_base_field_limbs": 3,
            "connection_target_bits": 78,
            "Fp3_field_and_terminal_screen": fp3_field_and_terminal,
            "Fp3_strict_schedule_audit": {
                str(GPT2["name"]): small_fp3_audit,
                str(GEMMA_ENVELOPE["name"]): large_fp3_audit,
            },
            "Fp3_g141_opening_codec_screen": {
                str(GPT2["name"]): small_fp3_codec,
                str(GEMMA_ENVELOPE["name"]): large_fp3_codec,
            },
            "root_profile_codec_fixed_point": {
                str(GPT2["name"]): {
                    "pre_mask_schedule": list(
                        R08_PROVISIONAL_PRE_MASK_FP3_SCHEDULES[
                            str(GPT2["name"])
                        ]
                    ),
                    "pre_mask_num_variables": (
                        int(GPT2["weights"]) - 1
                    ).bit_length(),
                    "selected_schedule": list(
                        R08_SELECTED_FP3_SCHEDULES[str(GPT2["name"])]
                    ),
                    "selected_num_variables": small_selected_variables,
                    "selected_RS_total_coefficient_dimension": (
                        small_selected_dimension
                    ),
                    "crossed_power_of_two_boundary": True,
                    "final_profile_reproduces_selected_dimension": True,
                },
                str(GEMMA_ENVELOPE["name"]): {
                    "pre_mask_schedule": list(
                        R08_PROVISIONAL_PRE_MASK_FP3_SCHEDULES[
                            str(GEMMA_ENVELOPE["name"])
                        ]
                    ),
                    "pre_mask_num_variables": (
                        int(GEMMA_ENVELOPE["weights"]) - 1
                    ).bit_length(),
                    "selected_schedule": list(
                        R08_SELECTED_FP3_SCHEDULES[
                            str(GEMMA_ENVELOPE["name"])
                        ]
                    ),
                    "selected_num_variables": large_selected_variables,
                    "selected_RS_total_coefficient_dimension": (
                        large_selected_dimension
                    ),
                    "crossed_power_of_two_boundary": False,
                    "final_profile_reproduces_selected_dimension": True,
                },
                "fixed_point_closed": True,
                "credit": False,
            },
            "Fp3_g141_opening_comparison": {
                "four_axis_large_to_gpt2_growth": fp3_opening_growth,
                "all_four_axes_within_1_30": all(
                    growth <= ACTIVE_QUERY_GROWTH_NUMERATOR
                    / ACTIVE_QUERY_GROWTH_DENOMINATOR
                    for growth in fp3_opening_growth.values()
                ),
                "known_serialized_bytes": fp3_known_bytes,
                "known_serialized_large_to_gpt2_growth": (
                    fp3_known_bytes[str(GEMMA_ENVELOPE["name"])]
                    / fp3_known_bytes[str(GPT2["name"])]
                ),
                "known_bytes_within_weight_wire_105_percent_targets": {
                    str(GPT2["name"]): (
                        fp3_known_bytes[str(GPT2["name"])]
                        <= small["certificate"]["weight_oracle_query_wire_envelope"][
                            "target_ceiling_105_percent_bytes"
                        ]
                    ),
                    str(GEMMA_ENVELOPE["name"]): (
                        fp3_known_bytes[str(GEMMA_ENVELOPE["name"])]
                        <= large["certificate"]["weight_oracle_query_wire_envelope"][
                            "target_ceiling_105_percent_bytes"
                        ]
                    ),
                },
                "full_weight_wire_gate_pass": False,
                "reason": "unknown_fail_closed_bytes_are_not_yet_serialized",
                "credit": False,
            },
            "Fp3_setup_resource_screen": {
                str(GPT2["name"]): small_fp3_setup,
                str(GEMMA_ENVELOPE["name"]): large_fp3_setup,
            },
            "RS_t_query_root_capacity_screen": {
                str(GPT2["name"]): small_t_query_capacity,
                str(GEMMA_ENVELOPE["name"]): large_t_query_capacity,
            },
            "root_mask_PRG_policy_screen": {
                str(GPT2["name"]): small_root_mask_prg,
                str(GEMMA_ENVELOPE["name"]): large_root_mask_prg,
            },
            "concrete_root_profile_proposal_screen": {
                str(GPT2["name"]): small_root_profile,
                str(GEMMA_ENVELOPE["name"]): large_root_profile,
            },
            "blake3_full78_fallback_privacy_screen": {
                str(GPT2["name"]): small_blake3_fallback,
                str(GEMMA_ENVELOPE["name"]): large_blake3_fallback,
            },
            "kmacxof256_mainline_security_codec_resource_screen": {
                str(GPT2["name"]): small_kmac_mainline,
                str(GEMMA_ENVELOPE["name"]): large_kmac_mainline,
            },
            "online_RS_BatchOpenBlocks_bounded_screen": {
                str(GPT2["name"]): small_online_rs_open,
                str(GEMMA_ENVELOPE["name"]): large_online_rs_open,
            },
            "credit": False,
        },
        "sensitivity": {
            "weight_count": "B_weight_ALFC follows log2(weight_count)^2; setup, refresh and online bytes are linear in weight_count.",
            "layer_count_and_response_tokens": "B_compute uses log2(layers*response_tokens*d_model^2)^2.",
            "boundary_shape": "B_boundary_commitments uses log2(layers*response_tokens*d_model)^2.",
            "KV_length": "B_state uses log2(2*layers*kv_heads*head_dim*successor_context_tokens)^2.",
            "root_count": "B_framing adds exactly 32 bytes per root.",
            "terminal_segments": "B_MAC adds 16 bytes and B_framing adds 8 bytes per segment; multiplicity must remain one.",
            "warning": "Batching only the weight dimension does not control layer/token/KV/root growth.",
            "credit": False,
        },
        "security": security_screen(),
        "policy2_query_accounting": policy2_query_accounting(),
        "r07_carrier_pareto_screen": r07_carrier_pareto_screen(),
        "interactive_vs_fiat_shamir": challenge_mode_comparison(),
        "self_check": {"status": "pending", "credit": False},
    }


def self_check(report: dict[str, object]) -> None:
    assert report["schema"] == "volta-c7-stateful-alfc-r08-screen-v27"
    models = report["models"]
    small = models[str(GPT2["name"])]
    large = models[str(GEMMA_ENVELOPE["name"])]
    small_artifacts = small["illustrative_era_artifact_volume_screen"]
    large_artifacts = large["illustrative_era_artifact_volume_screen"]
    assert ACCEPTED_CONTEXT_TOKENS + RESPONSE_TOKENS == SUCCESSOR_CONTEXT_TOKENS
    assert int(GEMMA_ENVELOPE["weights"]) / int(GPT2["weights"]) == 248.6
    assert terminal_segments(GPT2)["total"] == 106
    assert terminal_segments(GEMMA_ENVELOPE)["total"] == 378
    assert weight_alfc_bytes(REFERENCE_N) == 4_415_400
    assert (
        small_artifacts["illustrative_era_artifact_volume_sum"]["bytes"]
        == 7_142_399_968
    )
    assert (
        small_artifacts["digest_only_candidate_floor_screen"]["bytes"]
        == 793_599_968
    )
    assert (
        large_artifacts["illustrative_era_artifact_volume_sum"]["bytes"]
        == 1_775_600_639_968
    )
    small_setup = small_artifacts["owner_setup_envelope"]
    large_setup = large_artifacts["owner_setup_envelope"]
    assert small_setup["target_bytes"] == 496_000_000
    assert small_setup["baseline_tolerance_bytes"] == 520_800_000
    assert small_setup["exploratory_persistent_disk_cap_bytes"] == 744_000_000
    assert large_setup["target_bytes"] == 123_305_600_000
    assert large_setup["baseline_tolerance_bytes"] == 129_470_880_000
    assert large_setup["exploratory_persistent_disk_cap_bytes"] == (
        184_958_400_000
    )
    assert small_setup["setup_wall_target_seconds"] == 900
    assert large_setup["setup_wall_target_seconds"] == 5_400
    assert small_setup["setup_wall_hard_cap_seconds"] == 990
    assert large_setup["setup_wall_hard_cap_seconds"] == 5_940
    assert small_setup["refresh_wall_target_seconds"] == 900
    assert small_setup["refresh_wall_hard_cap_seconds"] == 990
    assert small_setup["refresh_counter_is_separate"]
    assert not small_setup["refresh_budget_transfer_allowed"]
    assert not small_setup["refresh_tested_in_R08"]
    assert small_setup["all_absolute_caps_selected"]
    assert not small_setup["exploratory_setup_gate_pass"]
    assert small_setup["leaf_screens"]["64"]["classification"] == "reject"
    assert small_setup["leaf_screens"]["128"]["classification"] == (
        "within_baseline_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["256"]["classification"] == (
        "within_target_floor_only"
    )
    assert small_setup["leaf_screens"]["129"]["classification"] == (
        "within_baseline_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["141"]["classification"] == (
        "within_target_floor_only"
    )
    assert small_setup["selected_logical_leaf_symbols"] == 141
    assert large_setup["selected_logical_leaf_symbols"] == 141
    assert not small_setup["simt_may_change_logical_leaf_symbols"]
    assert small_setup["leaf_screens"]["141"]["total_persistent_bytes"] == (
        495_648_224
    )
    assert large_setup["leaf_screens"]["141"]["total_persistent_bytes"] == (
        123_218_149_216
    )
    assert large_setup["leaf_screens"]["128"]["classification"] == (
        "within_baseline_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["128"][
        "hard_ceiling_metadata_headroom_bytes"
    ] == 32
    assert large_setup["leaf_screens"]["128"][
        "hard_ceiling_metadata_headroom_bytes"
    ] == 32
    assert not small_artifacts["anti_x4d_structural_gate"]["passes"]
    assert not large_artifacts["anti_x4d_structural_gate"]["passes"]
    small_ra = small["policy3_one_stage_ra_poseidon_screen"]
    large_ra = large["policy3_one_stage_ra_poseidon_screen"]
    assert small_ra["code"]["cpu_reference_implemented"]
    assert small_ra["code"]["packed_source_bytes_read"] == 248_000_000
    assert small_ra["setup"]["compact_tree_bytes"] == 225_134_752
    assert small_ra["setup"]["minimal_persistent_bytes"] == 473_134_816
    assert small_ra["setup"]["poseidon_sbox_multiplication_equivalents"] == 29_548_940_400
    assert small_ra["setup"][
        "packed_root_sbox_multiplication_equivalents_per_response_control"
    ] == 7_387_237_200
    assert large_ra["setup"]["compact_tree_bytes"] == 55_968_499_296
    assert large_ra["setup"]["minimal_persistent_bytes"] == 117_621_299_360
    assert large_ra["setup"]["poseidon_sbox_multiplication_equivalents"] == 7_345_865_536_800
    assert large_ra["setup"][
        "packed_root_sbox_multiplication_equivalents_per_response_control"
    ] == 1_836_466_388_400
    assert small_ra["alternative_leaf_controls"]["ligesis_c7"][
        "packed_plus_tree_bytes"
    ] == 641_985_816
    assert large_ra["alternative_leaf_controls"]["ligesis_c7"][
        "packed_plus_tree_bytes"
    ] == 159_597_673_768
    assert not small_ra["alternative_leaf_controls"]["ligesis_c7"][
        "within_hard_ceiling"
    ]
    assert not large_ra["alternative_leaf_controls"]["ligesis_c7"][
        "within_hard_ceiling"
    ]
    assert small_ra["setup"]["storage_within_target"]
    assert large_ra["setup"]["storage_within_target"]
    assert not small_ra["code"]["distance_gate_passed"]
    assert not small_ra["code"]["setup_generation_gate_passed"]
    assert not small_ra["setup"]["setup_gate_passed"]
    assert (
        small["source_functional_scan_target"]["bytes_read"]["bytes"]
        == 248_000_000
    )
    assert (
        large["source_functional_scan_target"]["bytes_read"]["bytes"]
        == 61_652_800_000
    )
    assert small["source_functional_scan_target"]["materialized_L"]["bytes"] == 0
    schedule = report["illustrative_ALFC_schedule_screen"]
    assert schedule["root_bytes_in_certificate"]["bytes"] == 128
    assert schedule["terminal_claim_screen_cap"] == 512
    assert schedule["connection_handle_screen_cap"] == 1 << 29
    assert not schedule["compiled_layout_manifest"]
    assert not schedule["codec_enforces_screen_cap"]
    assert report["growth"]["exponent_threshold_for_3x"] < 0.200
    assert 0.227 < report["growth"]["exponent_threshold_for_3_5x"] < 0.228
    assert report["growth"]["exponent_threshold_for_6x"] < 0.326
    assert 1.55 < report["growth"]["laws"]["log2_N_over_loglog_N"]["growth"] < 1.57
    assert report["security"]["epsilon_connection_exact"] == (
        "17592186044675/340282366920938463463374607431768211456"
    )
    assert report["security"]["connection_security_bits"] >= 78
    assert all(
        report["certificate_comparison"][
            "allocation_partition_within_Tier_A"
        ].values()
    )
    assert all(
        report["certificate_comparison"][
            "allocation_partition_within_exploratory_total_caps"
        ].values()
    )
    relaxations = report["r07_owner_exploratory_relaxations"]
    assert relaxations["proof_wire"]["target_percent"] == 105
    assert relaxations["proof_wire"]["exploratory_hard_band_percent"] == [
        125,
        150,
    ]
    assert relaxations["proof_wire"]["selected_hard_percent"] is None
    assert not relaxations["proof_wire"]["complete_compiled_gate_pass"]
    assert relaxations["setup"]["exploratory_ceiling_multiplier"] == 3.0
    assert relaxations["setup"]["absolute_persistent_disk_caps_bytes"] == {
        "gpt2-124m-screen": 744_000_000,
        "gemma-class-31b-envelope": 184_958_400_000,
    }
    assert relaxations["setup"]["setup_wall_targets_seconds"] == {
        "gpt2-124m-screen": 900,
        "gemma-class-31b-envelope": 5_400,
    }
    assert relaxations["setup"]["setup_wall_tolerance_caps_seconds"] == {
        "gpt2-124m-screen": 990,
        "gemma-class-31b-envelope": 5_940,
    }
    assert relaxations["setup"]["refresh_wall_targets_seconds"] == {
        "gpt2-124m-screen": 900,
        "gemma-class-31b-envelope": 5_400,
    }
    assert relaxations["setup"]["refresh_wall_hard_caps_seconds"] == {
        "gpt2-124m-screen": 990,
        "gemma-class-31b-envelope": 5_940,
    }
    assert relaxations["setup"]["refresh_counters_independent_from_setup"]
    assert not relaxations["setup"]["refresh_budget_transfer_allowed"]
    assert not relaxations["setup"]["refresh_test_authorized_or_required_in_R08"]
    assert relaxations["setup"]["all_absolute_caps_selected"]
    assert not relaxations["setup"]["complete_compiled_gate_pass"]
    assert relaxations["no_tolerance_transfer"]
    r08 = report["r08_owner_decisions_and_security_codec_screen"]
    assert r08["starting_rate"] == "1/2"
    assert r08["first_fold"] == 4
    assert r08["packed_weight_roots"] == 1
    assert r08["logical_leaf_symbols"] == 141
    assert r08["Q_FS"] == 0
    assert r08["owner_confirmations"] == {
        "KMACXOF256_64KiB_chunk_and_v1_descriptor_frozen": True,
        "complete_privacy_target_allocation_approved": True,
        "BLAKE3_remains_primary_for_performance_and_parallelism": True,
        "KMACXOF256_remains_unpromoted_high_margin_control": True,
    }
    future_fs = r08["future_Fiat_Shamir_rule"]
    assert not future_fs["changes_current_interactive_protocol"]
    assert future_fs["current_Q_FS"] == 0
    assert future_fs["root_mask_PRG_and_transcript_hash_are_distinct_roles"]
    assert future_fs["BLAKE3_requires_tightly_preregistered_Q_FS"]
    assert not future_fs["future_primitive_selected_now"]
    assert r08["setup_wall_targets_seconds"] == {
        "gpt2-124m-screen": 900,
        "gemma-class-31b-envelope": 5_400,
    }
    assert r08["setup_wall_tolerance_caps_seconds"] == {
        "gpt2-124m-screen": 990,
        "gemma-class-31b-envelope": 5_940,
    }
    assert r08["refresh_counters_independent_from_setup"]
    assert not r08["refresh_budget_transfer_allowed"]
    assert not r08["refresh_test_authorized_or_required_in_R08"]
    assert r08["selected_codec_field"] == "Goldilocks_Fp3"
    assert r08["selected_terminal_base_field_limbs"] == 3
    assert r08["connection_target_bits"] == 78
    fp3_field = r08["Fp3_field_and_terminal_screen"]
    assert fp3_field["construction"] == "Fp[u]/(u^3-2)"
    assert fp3_field["irreducibility_check"][
        "two_to_the_p_minus_1_over_3_mod_p"
    ] == (1 << 32) - 1
    assert fp3_field["irreducibility_check"]["noncube"]
    assert fp3_field["wire_bytes"] == 24
    assert fp3_field["terminal"]["shared_Delta_in_Fp3"]
    assert fp3_field["terminal"]["independent_base_field_MACs_forbidden"]
    assert not fp3_field["terminal"]["clear_terminal_evaluation_serialized"]
    assert fp3_field["terminal"]["provider_terminal_correction_bytes"] == 24
    assert not fp3_field["terminal"]["malicious_DV_privacy_implied"]
    assert fp3_field["concrete_rust_codec_implemented"]
    assert fp3_field["rust_codec_and_multiplication_KAT_pass"]
    assert fp3_field["rust_decode_wrong_length_and_noncanonical_limb_tests_pass"]
    assert fp3_field["carrier_independent_shared_Delta_adapter_implemented"]
    assert fp3_field[
        "rust_shared_Delta_linearity_and_three_limb_mutation_tests_pass"
    ]
    assert fp3_field["lean_three_coordinate_consequence_proved"]
    assert not fp3_field["concrete_shared_Delta_adapter_refinement_proved"]
    fp2_audit = r08["Fp2_strict_schedule_audit"]
    assert fp2_audit["gpt2-124m-screen"]["q_open"] == 831
    assert fp2_audit["gpt2-124m-screen"]["unstacked_Fp_positions"] == 19_104
    large_fp2_audit = fp2_audit["gemma-class-31b-envelope"]
    assert large_fp2_audit["q_open"] == 1_054
    assert large_fp2_audit["unstacked_Fp_positions"] == 24_128
    assert 89.087 < large_fp2_audit["all_fold_certified_response_bits"] < 89.088
    assert 69.087 < large_fp2_audit[
        "after_R_max_2_pow_20_certified_bits"
    ] < 69.088
    assert large_fp2_audit[
        "bare_max_attempts_for_78_bits_before_other_terms"
    ] == 2_175
    assert large_fp2_audit["max_attempts_for_84_bits_before_other_terms"] == 33
    assert not large_fp2_audit["certifies_110_response_bits"]
    assert not large_fp2_audit["certifies_78_after_R_max_before_other_terms"]
    assert not large_fp2_audit["modest_110_to_104_or_98_relaxation_suffices"]
    fp3_audit = r08["Fp3_strict_schedule_audit"]
    small_fp3_audit = fp3_audit["gpt2-124m-screen"]
    large_fp3_audit = fp3_audit["gemma-class-31b-envelope"]
    assert small_fp3_audit["schedule"] == [4, 5, 3, 3, 3, 4]
    assert small_fp3_audit["unstacked_Fp_positions"] == 29_192
    assert 160.01 < small_fp3_audit["all_fold_certified_response_bits"] < 160.02
    assert large_fp3_audit["q_open"] == 1_055
    assert large_fp3_audit["unstacked_Fp_positions"] == 33_848
    assert 153.17 < large_fp3_audit["all_fold_certified_response_bits"] < 153.18
    assert 133.17 < large_fp3_audit[
        "after_R_max_2_pow_20_certified_bits"
    ] < 133.18
    assert large_fp3_audit["certifies_110_response_bits"]
    assert large_fp3_audit["certifies_78_after_R_max_before_other_terms"]
    fp3_codec = r08["Fp3_g141_opening_codec_screen"]
    assert fp3_codec["gpt2-124m-screen"]["totals"]["q_open"] == 831
    assert fp3_codec["gemma-class-31b-envelope"]["totals"]["q_open"] == 1_055
    assert not fp3_codec["gpt2-124m-screen"]["complete_codec_bytes_known"]
    assert compact_merkle_max_siblings(3, 1) == 2
    assert compact_merkle_max_siblings(3, 2) == 1
    assert compact_merkle_max_siblings(8, 1) == 3
    fixed_point = r08["root_profile_codec_fixed_point"]
    assert fixed_point["fixed_point_closed"]
    assert fixed_point["gpt2-124m-screen"]["pre_mask_num_variables"] == 27
    assert fixed_point["gpt2-124m-screen"]["selected_num_variables"] == 28
    assert fixed_point["gpt2-124m-screen"]["crossed_power_of_two_boundary"]
    assert fixed_point["gemma-class-31b-envelope"]["selected_num_variables"] == 35
    assert not fixed_point["gemma-class-31b-envelope"][
        "crossed_power_of_two_boundary"
    ]
    assert fp3_codec["gpt2-124m-screen"]["totals"] == {
        "q_open": 831,
        "Z_atom": 29_192,
        "U_leaf": 1_662,
        "S_visible_Fp": 234_342,
        "H_sibling": 20_997,
        "payload_bytes": 1_874_736,
        "salt_bytes": 53_184,
        "multiproof_bytes": 671_928,
        "challenge_bytes": 3_852,
        "frame_header_bytes": 192,
        "auxiliary_root_count": 5,
        "auxiliary_root_and_frame_bytes": 240,
        "final_direct_send_and_frame_bytes": 1_552,
        "terminal_adapter_three_limb_and_frame_bytes": 40,
        "codec_header_bytes": 16,
        "known_serialized_bytes": 2_605_740,
    }
    large_codec_totals = fp3_codec["gemma-class-31b-envelope"]["totals"]
    assert large_codec_totals["Z_atom"] == 33_848
    assert large_codec_totals["U_leaf"] == 2_110
    assert large_codec_totals["S_visible_Fp"] == 297_510
    assert large_codec_totals["H_sibling"] == 39_843
    assert large_codec_totals["known_serialized_bytes"] == 3_729_724
    assert large_codec_totals["q_open"] * 100 <= 130 * 831
    assert large_codec_totals["Z_atom"] * 100 <= 130 * 29_192
    assert large_codec_totals["U_leaf"] * 100 <= 130 * 1_662
    assert large_codec_totals["S_visible_Fp"] * 100 <= 130 * 234_342
    fp3_comparison = r08["Fp3_g141_opening_comparison"]
    assert fp3_comparison["all_four_axes_within_1_30"]
    assert fp3_comparison["known_serialized_bytes"] == {
        "gpt2-124m-screen": 2_605_740,
        "gemma-class-31b-envelope": 3_729_724,
    }
    assert all(
        fp3_comparison["known_bytes_within_weight_wire_105_percent_targets"].values()
    )
    assert not fp3_comparison["full_weight_wire_gate_pass"]
    fp3_setup = r08["Fp3_setup_resource_screen"]
    small_fp3_setup = fp3_setup["gpt2-124m-screen"]
    large_fp3_setup = fp3_setup["gemma-class-31b-envelope"]
    assert small_fp3_setup["persistent_bytes"] == 491_686_208
    assert large_fp3_setup["persistent_bytes"] == 92_844_619_328
    assert not small_fp3_setup["persistent_bytes_is_pre_mask_capacity_lower_bound"]
    assert small_fp3_setup["includes_selected_seeded_mask_capacity_geometry"]
    assert small_fp3_setup["zk_randomness_capacity_symbols"] == 144_435_456
    assert not small_fp3_setup["complete_persistent_setup_bytes_known"]
    assert small_fp3_setup["within_2x_target"]
    assert large_fp3_setup["within_2x_target"]
    assert small_fp3_setup["setup_wall_target_seconds"] == 900
    assert small_fp3_setup["setup_wall_hard_cap_seconds"] == 990
    assert large_fp3_setup["setup_wall_target_seconds"] == 5_400
    assert large_fp3_setup["setup_wall_hard_cap_seconds"] == 5_940
    assert not small_fp3_setup["ordered_RS_symbol_generator_one_source_scan_proved"]
    assert not small_fp3_setup["setup_resource_gate_pass"]
    assert not small_fp3_setup["refresh"]["test_authorized_or_required_in_R08"]
    t_query_capacity = r08["RS_t_query_root_capacity_screen"]
    small_t_query = t_query_capacity["gpt2-124m-screen"]
    large_t_query = t_query_capacity["gemma-class-31b-envelope"]
    assert small_t_query["zero_tree_growth_randomness_headroom_Fp_coefficients"] == 10_217_728
    assert large_t_query["zero_tree_growth_randomness_headroom_Fp_coefficients"] == 3_533_338_368
    assert small_t_query["zero_tree_growth_maximum_full_attempts"] == 43
    assert large_t_query["zero_tree_growth_maximum_full_attempts"] == 11_876
    assert small_t_query["geometry_only_capacity_by_setup_tier"][
        "target_2_00x"
    ]["maximum_full_attempts_at_reserved_visible_Fp_charge"] == 616
    assert large_t_query["geometry_only_capacity_by_setup_tier"][
        "baseline_tolerance_2_10x"
    ]["maximum_full_attempts_at_reserved_visible_Fp_charge"] == 127_367
    assert small_t_query[
        "explicit_uniform_coefficient_persistence_control_by_setup_tier"
    ]["exploratory_3_00x"][
        "maximum_full_attempts_at_reserved_visible_Fp_charge"
    ] == 134
    assert large_t_query[
        "explicit_uniform_coefficient_persistence_control_by_setup_tier"
    ]["exploratory_3_00x"][
        "maximum_full_attempts_at_reserved_visible_Fp_charge"
    ] == 25_596
    assert small_t_query["single_root_for_R_max_control"][
        "persistent_bytes_excluding_mask_coefficients"
    ] == 249_782_553_920
    assert large_t_query["single_root_for_R_max_control"][
        "persistent_bytes_excluding_mask_coefficients"
    ] == 560_721_907_712
    assert small_t_query["initial_oracle_visible_Fp_charge_per_attempt"] == 75_012
    assert large_t_query["initial_oracle_visible_Fp_charge_per_attempt"] == 75_012
    assert small_t_query["initial_oracle_only_R_max_lower_bound_control"][
        "persistent_bytes_excluding_mask_coefficients"
    ] == 125_015_276_992
    assert large_t_query["initial_oracle_only_R_max_lower_bound_control"][
        "persistent_bytes_excluding_mask_coefficients"
    ] == 186_420_076_992
    assert not large_t_query[
        "initial_oracle_only_R_max_lower_bound_control"
    ]["within_exploratory_3x"]
    assert not small_t_query["single_root_for_R_max_control"][
        "within_exploratory_3x"
    ]
    assert not large_t_query["C7_charge_to_paper_query_refinement_proved"]
    assert not large_t_query["numeric_Q_root_admitted"]
    assert not large_t_query["refresh_test_authorized_or_required_in_R08"]
    root_mask_prg = r08["root_mask_PRG_policy_screen"]
    small_prg = root_mask_prg["gpt2-124m-screen"]
    large_prg = root_mask_prg["gemma-class-31b-envelope"]
    assert small_prg["selected_policy"] == "computational_seeded_root_mask"
    assert small_prg["baseline_policy"] == (
        "persisted_uniform_Fp_coefficients"
    )
    assert small_prg["root_mask_seed_bytes"] == 32
    assert small_prg["primary_candidate_selected"] == "keyed_BLAKE3_XOF"
    assert small_prg["fallback_candidate"] == "KMACXOF256"
    assert not small_prg["connection_target_reduction_allowed_to_admit_PRG"]
    blake3_screen = large_prg["blake3_xof_candidate_screen"]
    assert blake3_screen[
        "maximum_composable_loss_bits_if_128_bit_target_is_applicable"
    ] == 18
    assert blake3_screen[
        "maximum_composable_loss_factor_if_128_bit_target_is_applicable"
    ] == 262_144
    assert large_prg["blake3_xof_candidate_screen"][
        "linear_in_Q_proof_form_control"
    ]["conservative_visible_Fp_charge_per_attempt"] == 297_510
    assert not large_prg["blake3_xof_candidate_screen"][
        "linear_in_Q_proof_form_control"
    ]["conservative_one_attempt_passes"]
    assert small_prg["blake3_xof_candidate_screen"][
        "linear_in_Q_proof_form_control"
    ]["conservative_visible_Fp_charge_per_attempt"] == 234_342
    assert small_prg["blake3_xof_candidate_screen"][
        "linear_in_Q_proof_form_control"
    ]["conservative_one_attempt_passes"]
    assert 35 < blake3_screen["minimum_first_draw_words_log2"] < 36
    assert blake3_screen["logical_codec_candidate"][
        "maximum_output_position_exclusive_bytes"
    ] == 1_818_867_683_328
    assert blake3_screen["logical_codec_candidate"][
        "within_BLAKE3_2^64_minus_1_output_byte_limit"
    ]
    assert not blake3_screen["logical_codec_candidate"]["implemented"]
    assert not blake3_screen["passes_component_reserve"]
    assert not large_prg["kmacxof256_fallback_screen"][
        "passes_component_reserve"
    ]
    assert large_prg["kmacxof256_fallback_screen"][
        "addressed_parallel_codec_selected"
    ]
    assert small_prg["coefficient_derivation"]["selected_draw_cap"] == 6
    assert 163.37 < small_prg["selected_draw_cap_failure_bits"] < 163.39
    assert 156.85 < large_prg["selected_draw_cap_failure_bits"] < 156.87
    assert large_prg["draw_cap_controls"]["6"][
        "maximum_addressed_64_bit_words"
    ] == 227_358_460_416
    assert large_prg["privacy_hybrid"][
        "included_in_model_lifetime_78_bit_budget"
    ]
    assert not large_prg["privacy_hybrid"]["passes_component_reserve"]
    assert not large_prg["generator_primitive_selected"]
    generator_disposition = large_prg[
        "existing_repository_generator_disposition"
    ]
    assert generator_disposition["volta_field_FpStream_ChaCha8"][
        "status"
    ] == "REJECT_PRODUCTION_C7_ROOT_MASK"
    assert generator_disposition["volta_pcg_Aes128Mmo_GGM"][
        "status"
    ] == "QUARANTINE"
    assert generator_disposition["volta_pcg_Blake3_GGM"][
        "status"
    ] == "QUARANTINE"
    assert not large_prg["refresh_test_authorized_or_required_in_R08"]
    root_profiles = r08["concrete_root_profile_proposal_screen"]
    small_root_profile = root_profiles["gpt2-124m-screen"]
    large_root_profile = root_profiles["gemma-class-31b-envelope"]
    assert small_root_profile["R_root_proposed"] == 512
    assert small_root_profile["Q_root_scalar_cap_proposed"] == 134_980_992
    assert small_root_profile["Q_mask_words_all_seed_attempts_cap"] == 1_619_771_904
    assert small_root_profile["unused_randomness_capacity_after_Q_root"] == 9_454_464
    assert small_root_profile["selected_setup_tier"] == "target_2_00x"
    assert large_root_profile["R_root_proposed"] == 8_192
    assert large_root_profile["Q_root_scalar_cap_proposed"] == 2_741_852_160
    assert large_root_profile["Q_mask_words_all_seed_attempts_cap"] == 32_902_225_920
    assert large_root_profile["unused_randomness_capacity_after_Q_root"] == 791_486_208
    assert large_root_profile["selected_setup_tier"] == "target_2_00x"
    assert not small_root_profile["BLAKE3_linear_in_Q_control_passes_110"]
    assert not large_root_profile["BLAKE3_linear_in_Q_control_passes_110"]
    assert small_root_profile["owner_selected"]
    assert large_root_profile["owner_selected"]
    assert small_root_profile["owner_selected_as_fallback_variant"]
    assert large_root_profile["owner_selected_as_fallback_variant"]
    assert not small_root_profile["owner_selected_as_mainline"]
    assert not large_root_profile["owner_selected_as_mainline"]
    assert not small_root_profile["profile_admitted"]
    assert not large_root_profile["profile_admitted"]
    fallbacks = r08["blake3_full78_fallback_privacy_screen"]
    small_fallback = fallbacks["gpt2-124m-screen"]
    large_fallback = fallbacks["gemma-class-31b-envelope"]
    assert small_fallback["K_model"] == 2_048
    assert large_fallback["K_model"] == 128
    assert small_fallback["model_global_attempt_horizon_owner_confirmed"]
    assert large_fallback["model_global_attempt_horizon_owner_confirmed"]
    assert small_fallback["K_seed_attempts"] == 4_096
    assert large_fallback["K_seed_attempts"] == 256
    assert small_fallback["Q_mask_words_model_max"] == 3_317_292_859_392
    assert large_fallback["Q_mask_words_model_max"] == 4_211_484_917_760
    assert 86.40 < small_fallback["conditional_Adv_BLAKE3_multi_bits"] < 86.41
    assert 86.06 < large_fallback["conditional_Adv_BLAKE3_multi_bits"] < 86.07
    assert not small_fallback["known_mask_terms_pass_mainline_110"]
    assert not large_fallback["known_mask_terms_pass_mainline_110"]
    assert small_fallback["known_mask_terms_pass_fallback_78"]
    assert large_fallback["known_mask_terms_pass_fallback_78"]
    assert small_fallback["allocated_complete_privacy_passes_78"]
    assert large_fallback["allocated_complete_privacy_passes_78"]
    assert 86.40 < small_fallback["allocated_complete_privacy_bits"] < 86.41
    assert 86.06 < large_fallback["allocated_complete_privacy_bits"] < 86.07
    assert small_fallback["allocation_pass_is_not_theorem_discharge"]
    assert 78 < small_fallback[
        "maximum_other_privacy_terms_sum_bits"
    ] < 78.01
    assert 78 < large_fallback[
        "maximum_other_privacy_terms_sum_bits"
    ] < 78.01
    assert not small_fallback["all_privacy_terms_numeric"]
    assert not large_fallback["all_privacy_terms_numeric"]
    assert not small_fallback["complete_privacy_passes_78"]
    assert not large_fallback["complete_privacy_passes_78"]
    assert not small_fallback["variant_admitted"]
    assert not large_fallback["variant_admitted"]
    kmac = r08["kmacxof256_mainline_security_codec_resource_screen"]
    small_kmac = kmac["gpt2-124m-screen"]
    large_kmac = kmac["gemma-class-31b-envelope"]
    assert small_kmac["model_global_attempt_horizon_owner_confirmed"]
    assert large_kmac["model_global_attempt_horizon_owner_confirmed"]
    assert small_kmac["Q_mask_words_model_max"] == 3_317_292_859_392
    assert large_kmac["Q_mask_words_model_max"] == 4_211_484_917_760
    assert small_kmac["logical_codec_candidate"]["descriptor_bytes"] == 104
    assert small_kmac["logical_codec_candidate"]["KMAC_input_bytes_per_chunk"] == 112
    assert small_kmac["logical_codec_candidate"]["chunk_output_bytes"] == 65_536
    assert small_kmac["logical_codec_candidate"][
        "certificate_bytes_added_by_generator_choice"
    ] == 0
    assert small_kmac["logical_codec_candidate"][
        "visible_PCS_query_count_added_by_generator_choice"
    ] == 0
    assert small_kmac["logical_codec_candidate"][
        "fixed_chunk_calls_allow_parallel_CPU_SIMT_evaluation"
    ]
    assert not small_kmac["logical_codec_candidate"]["implemented"]
    assert not small_kmac["logical_codec_candidate"][
        "online_BatchOpen_mask_contribution_schedule_proved"
    ]
    assert small_kmac["logical_codec_candidate"][
        "online_mask_regeneration_bytes_per_attempt"
    ] is None
    small_kmac_resource = small_kmac["per_candidate_seed_resource_control"]
    large_kmac_resource = large_kmac["per_candidate_seed_resource_control"]
    assert small_kmac_resource["logical_output_bytes"] == 6_479_087_616
    assert small_kmac_resource["chunks"] == 98_864
    assert small_kmac_resource["Keccak_f1600_permutations"] == 47_849_710
    assert large_kmac_resource["logical_output_bytes"] == 131_608_903_680
    assert large_kmac_resource["chunks"] == 2_008_193
    assert large_kmac_resource["Keccak_f1600_permutations"] == 971_965_171
    assert small_kmac["conditional_ideal_permutation_control"][
        "conditional_sum_passes_110"
    ]
    assert large_kmac["conditional_ideal_permutation_control"][
        "conditional_sum_passes_110"
    ]
    assert small_kmac["conditional_full_privacy_allocation"][
        "complete_allocation_passes_78"
    ]
    assert large_kmac["conditional_full_privacy_allocation"][
        "complete_allocation_passes_78"
    ]
    assert 107 < small_kmac["conditional_full_privacy_allocation"][
        "complete_bits"
    ] < 108
    assert 107 < large_kmac["conditional_full_privacy_allocation"][
        "complete_bits"
    ] < 108
    assert not small_kmac["exact_multi_key_KMAC_to_Keccak_reduction_instantiated"]
    assert not large_kmac["fixed_Keccak_f1600_assumption_numeric"]
    assert not small_kmac["passes_component_reserve"]
    assert not large_kmac["candidate_promoted"]
    assert not report["security"]["event_registry_complete"]
    assert report["security"]["conditional_budget_fits_78"]
    assert not report["security"]["current_protocol_security_gate_pass"]
    algebraic = report["security"]["strict_ud_algebraic_screen"]
    assert 99.999999999 < algebraic[
        "certified_per_starting_challenge_bits_lower_bound"
    ][
        str(GPT2["name"])
    ] < 100
    assert 91.999999999 < algebraic[
        "certified_per_starting_challenge_bits_lower_bound"
    ][
        str(GEMMA_ENVELOPE["name"])
    ] < 92
    assert 71.999999999 < algebraic[
        "certified_after_R_max_bits_lower_bound_before_other_terms"
    ][
        str(GEMMA_ENVELOPE["name"])
    ] < 72
    assert 18 < algebraic[
        "additional_certified_bits_needed_for_large_registered_reserve"
    ] < 18.000000001
    assert algebraic["Fp2_cardinality_bit_length_informational_only"] == 128
    assert not algebraic["inherited_unamplified_Fp2_bound_admission_pass"]
    key_schedule = report["security"]["malicious_verifier_key_schedule"]
    assert key_schedule["connection_key_tape_seed_or_domain_fixed_before_responses"]
    assert key_schedule["attempt_interval_reserved_before_witness_dependent_bytes"]
    assert key_schedule["attempt_interval_count"] is None
    assert not key_schedule["adaptive_post_correction_keys_allowed"]
    assert not key_schedule["real_pcg_vole_refinement_proved"]
    sampling = report["security"]["sampling_commit_private_open_schedule"]
    assert sampling["fixed_payload_bytes_before_framing"] == 96
    assert not sampling["provider_seed_opening_serialized"]
    assert not sampling["reconciled_into_B_framing"]
    policy = report["privacy_policy"]
    assert policy["active"] == 2
    assert policy["last_tested"] == 3
    assert policy["active_status"] == "spbt_reduction_pass_delayed_opening_no_go"
    assert policy["policy_3_candidate_exhaustion_documented"]
    assert len(policy["terminal_catalog"]) == 10
    assert policy["policy_2_status"] == "active_design_only"
    assert policy["policy_2_activation_authorized"]
    assert policy["policy_2_root_wide_query_horizon_schema_registered"]
    assert policy["policy_2_concrete_root_profile_proposals_compiled"]
    assert policy[
        "policy_2_concrete_root_profile_owner_selected_for_fallback"
    ]
    assert not policy[
        "policy_2_concrete_root_profile_owner_selected_for_mainline"
    ]
    assert policy["policy_2_blake3_full78_fallback_owner_authorized"]
    assert not policy["policy_2_blake3_full78_fallback_admitted"]
    assert policy["policy_2_model_global_2_pow_20_horizon_owner_confirmed"]
    assert policy["policy_2_kmacxof256_mainline_screen_compiled"]
    assert not policy["policy_2_kmacxof256_mainline_promoted"]
    assert policy["policy_2_root_mask_main_line"] == (
        "computational_per_root_seed_PRG_PCG"
    )
    assert policy["policy_2_root_mask_baseline"] == (
        "persisted_uniform_Fp_coefficients"
    )
    assert policy["policy_2_root_mask_primary_candidate"] == "keyed_BLAKE3_XOF"
    assert policy["policy_2_root_mask_fallback_candidate"] == "KMACXOF256"
    assert policy["policy_2_PRG_failure_may_not_reduce_78bit_target"]
    assert policy["policy_2_privacy_declared_computational"]
    assert policy["policy_2_Adv_root_mask_PRG_in_78_bit_budget"]
    assert not policy["policy_2_root_wide_query_horizon_instantiated"]
    assert not policy["policy_2_exact_numeric_caps_derived"]
    assert policy["numeric_caps_deferred_until_complete_pareto"]
    assert policy["selected_public_leaf_tree_function"] == "salted_BLAKE3"
    assert policy["era_r4_role"] == "byte_and_prover_control_only"
    authorization = report["authorization"]
    assert authorization["r07_carrier_and_pareto_checkpoint_authorized"]
    assert authorization["tiny_cpu_screen_completed"]
    assert not authorization["batch_open_blocks_cpu_reference_authorized_now"]
    assert not authorization[
        "batch_open_blocks_cpu_reference_pre_authorized_after_checkpoint"
    ]
    assert authorization["batch_open_blocks_cpu_reference_requires_backend_checkpoint"]
    assert not authorization["optimized_simt_kernel_authorized"]
    assert authorization["simt_requires_c7_cpu_reference_pass"]
    assert not authorization["large_prover_or_e2e_execution_authorized"]
    assert not authorization["pod_contact_or_execution_authorized"]
    assert not authorization["c7_cpu_reference_pass"]
    assert not authorization["c7_pod_ready"]
    assert authorization["former_selected_RS_realization_no_go"]
    assert not authorization[
        "owner_design_decision_required_before_more_implementation"
    ]
    assert authorization["new_shared_carrier_tournament_authorized"]
    assert authorization["strict_ud_RS_demoted_to_control_baseline"]
    assert not authorization["strict_ud_RS_prover_authorized"]
    assert authorization[
        "carrier_independent_Fp3_codec_KAT_MAC_adapter_authorized"
    ]
    assert authorization["carrier_independent_Fp3_seam_implemented"]
    assert authorization["carrier_independent_policy2_reference_authorized"]
    assert authorization["tiny_non_PCS_conformance_test_implemented"]
    assert authorization["published_carriers_baseline_controls_only"]
    assert authorization["C7_codesigned_circuit_main_research_line"]
    assert authorization["C7_secret_point_quotient_research_authorized"]
    assert not authorization["C7_codesigned_pre_CPU_screen_pass"]
    assert not authorization["tiny_CPU_prototype_authorized_now"]
    gates = report["admission_gates"]
    assert gates["numeric_setup_ceiling_registered"]
    assert gates["weight_query_wire_envelope_registered"]
    assert gates["proof_wire_105_is_target_not_immediate_hard_stop"]
    assert gates["proof_wire_exploratory_125_to_150_band_registered"]
    assert not gates["proof_wire_exploratory_exact_cap_selected"]
    assert gates[
        "proof_wire_exploratory_total_35_115MB_3_5x_caps_registered"
    ]
    assert gates["setup_exploratory_3x_ceiling_registered"]
    assert gates["setup_exploratory_absolute_disk_caps_registered"]
    assert gates[
        "setup_exploratory_absolute_time_and_refresh_caps_selected"
    ]
    assert gates["logical_leaf_geometry_selected"]
    assert not gates["anti_x4d_setup_gate_pass"]
    assert gates["active_public_leaf_function_implemented"]
    assert gates["historical_policy3_poseidon2_leaf_implemented"]
    assert not gates["leaf_commitment_adaptive_hiding_proved"]
    assert gates["concrete_leaf_commitment_selected"]
    assert not gates["policy3_private_leaf_checker_required"]
    assert not gates["only_budgeted_masked_query_payloads_codec_proved"]
    assert gates["terminal_evaluation_remains_authenticated"]
    assert not gates["malicious_dv_connection_privacy_theorem_complete"]
    assert not gates["policy2_model_lifetime_privacy_78bit_proved"]
    assert gates["policy2_root_mask_seed_policy_selected"]
    assert gates["policy2_root_mask_primary_candidate_selected"]
    assert not gates["policy2_root_mask_generator_primitive_selected"]
    assert not gates["policy2_root_mask_PRG_advantage_numeric"]
    assert gates["policy2_concrete_R_root_profile_proposals_compiled"]
    assert gates[
        "policy2_concrete_R_root_profile_owner_selected_for_fallback"
    ]
    assert not gates[
        "policy2_concrete_R_root_profile_owner_selected_for_mainline"
    ]
    assert gates["policy2_blake3_full78_fallback_owner_authorized"]
    assert not gates["policy2_blake3_full78_fallback_complete_sum_pass"]
    assert gates["policy2_model_global_2_pow_20_horizon_owner_confirmed"]
    assert gates["policy2_kmacxof256_mainline_screen_compiled"]
    assert not gates["policy2_kmacxof256_mainline_promoted"]
    assert not gates["policy2_epoch_and_receipt_transcript_binding_proved"]
    assert not gates["policy2_single_session_receipt_state_machine_proved"]
    assert not gates["policy2_plane_charge_vector_and_durable_maps_instantiated"]
    assert not gates["policy2_no_extension_plane_assignment_cas_proved"]
    assert not gates["policy2_genesis_kv_budget_initialization_proved"]
    assert not gates["policy2_state_budget_carry_across_weight_rotation_proved"]
    assert not gates["policy2_init_rotation_query_reservations_instantiated"]
    assert not gates["policy2_disclosed_candidate_epoch_accounting_instantiated"]
    assert not gates["policy2_multiuser_vole_mac_composition_proved"]
    assert not gates["policy2_lifecycle_mac_domain_census_instantiated"]
    assert not gates["policy2_same_W_rotation_bridge_complete"]
    assert not gates["policy2_paired_history_game_formalized"]
    assert not gates["policy2_branch_derived_view_closure_proved"]
    assert not gates["policy2_boundary_and_kv_plane_privacy_horizons_derived"]
    assert not gates["policy2_allocator_privacy_integrity_proved"]
    assert not gates["policy2_receipt_unforgeability_proved"]
    assert not gates["policy2_distinct_hash_work_bounds_derived"]
    assert gates["challenge_generation_and_grinding_policy_selected"]
    assert not gates["retained_interleaved_goldilocks_domain_rule_admitted"]
    assert gates["algebraic_security_amplifier_selected"]
    assert gates["algebraic_security_closure_path_selected"]
    assert gates["fp3_direct_three_limb_fallback_selected"]
    assert gates["first_compiler_envelope_selected"] == (
        "rate1-k0-4-owner1_30-Fp3-flat-g141-one-root"
    )
    assert gates["strict_ud_algebraic_110bit_per_response_derived"]
    assert gates["strict_ud_algebraic_gap_after_Rmax_78bit_derived"]
    assert not gates["full_connection_78bit_security_derived"]
    assert not gates["honest_dv_entropy_delivery_instantiated"]
    assert not gates["interactive_challenge_transcript_binding_proved"]
    assert not gates["pure_fold_width_tail_screen_pass"]
    assert gates["bounded_joint_sampling_screen_complete"]
    assert not gates["bounded_joint_sampling_screen_pass"]
    assert gates["bounded_different_code_switch_screen_complete"]
    assert not gates["bounded_different_code_switch_screen_pass"]
    assert gates["selected_carrier_original_1_05_disposition"] == "NO_GO"
    assert gates["owner_1_30_query_growth_fallback_active"]
    assert gates["owner_1_30_known_q_and_unstacked_Fp_controls_pass"]
    assert gates["owner_1_30_complete_four_axis_query_gate_pass"]
    assert not gates["joint_sampler_visible_Fp_sharing_selected"]
    assert not gates["different_code_switch_selected"]
    assert not gates["one_pass_batch_open_blocks_proved"]
    assert not gates["cpu_batch_open_blocks_reference_pass"]
    assert not gates["simt_bit_exact_equivalence_pass"]
    assert not gates["query_schedule_compiled"]
    assert gates["opening_query_schedule_compiled"]
    assert gates["query_counter_schema"]["aggregate"] == list(
        POLICY2_AGGREGATE_CENSUS_CLASSES
    )
    assert gates["query_counter_schema"]["per_plane"] == list(
        POLICY2_QUERY_CLASSES
    )
    assert gates["query_counter_schema"][
        "logical_pcs_samples_q_open_by_plane_root_round"
    ].endswith("Fp3_g141_opening_codec_screen.rounds")
    assert gates["adversarial_leaf_oracle_query_bound"] == 1 << 64
    assert gates["adversarial_leaf_oracle_query_bound_kind"] == (
        "owner_selected_analytic_screen_not_a_concrete_theorem_cap"
    )
    assert gates["adversarial_fiat_shamir_query_bound"] == 0
    assert len(gates["exact_query_counts_by_root_and_round"][
        "gpt2-124m-screen"
    ]) == 6
    assert len(gates["exact_query_counts_by_root_and_round"][
        "gemma-class-31b-envelope"
    ]) == 8
    assert gates["serialized_query_and_challenge_bytes_by_model"] == {
        "gpt2-124m-screen": 2_605_740,
        "gemma-class-31b-envelope": 3_729_724,
    }
    assert not gates["query_bytes_reconciled_into_certificate_total"]
    assert not gates["compiled_tier_a_certificate_gate_pass"]
    small_query = small["certificate"]["weight_oracle_query_wire_envelope"]
    large_query = large["certificate"]["weight_oracle_query_wire_envelope"]
    assert small_query["registered_component_allocation_bytes"] == 3_116_843
    assert small_query["target_ceiling_105_percent_bytes"] == 3_272_685
    assert small_query["target_reserve_over_allocation_bytes"] == 155_842
    assert small_query["exploratory_hard_band_bytes"] == {
        "minimum_125_percent": 3_896_053,
        "maximum_150_percent": 4_675_264,
    }
    assert small_query["selected_exploratory_hard_percent"] is None
    assert small_query["compiled_weight_oracle_interactive_challenge_bytes"] is None
    assert small_query["compiled_omega_profile_receipt_and_auth_bytes"] is None
    assert small["certificate"]["plane_budget_control_wire"][
        "compiled_plane_assignment_receipt_and_auth_bytes"
    ] is None
    assert small_query[
        "response_wide_beta_gamma_counted_elsewhere_exactly_once"
    ]
    assert large_query["registered_component_allocation_bytes"] == 5_234_948
    assert large_query["target_ceiling_105_percent_bytes"] == 5_496_695
    assert large_query["target_reserve_over_allocation_bytes"] == 261_747
    assert large_query["exploratory_hard_band_bytes"] == {
        "minimum_125_percent": 6_543_685,
        "maximum_150_percent": 7_852_422,
    }
    assert small["certificate"][
        "total_if_weight_envelope_uses_target_105"
    ]["bytes"] == 12_541_405
    assert large["certificate"][
        "total_if_weight_envelope_uses_target_105"
    ]["bytes"] == 19_474_047
    assert small["certificate"][
        "total_if_weight_envelope_uses_exploratory_125"
    ]["bytes"] == 13_164_773
    assert large["certificate"][
        "total_if_weight_envelope_uses_exploratory_125"
    ]["bytes"] == 20_521_037
    assert small["certificate"][
        "total_if_weight_envelope_uses_exploratory_150"
    ]["bytes"] == 13_943_984
    assert large["certificate"][
        "total_if_weight_envelope_uses_exploratory_150"
    ]["bytes"] == 21_829_774
    leaf_hide = report["security"]["leaf_commitment_hiding_screen"]
    assert leaf_hide["salt_bits"] == 256
    assert leaf_hide["logical_leaf_symbols"] == 141
    assert leaf_hide["largest_static_weight_leaf_count_screen"] == 961_958_582
    assert leaf_hide["effective_bits"] > 161
    assert leaf_hide["salt_192_effective_bits_same_screen"] < 98
    assert leaf_hide["concrete_leaf_function_implemented"]
    assert not leaf_hide["concrete_arithmetizable_commitment_selected"]
    challenge = report["security"]["challenge_generation"]
    assert challenge["mode_selected"]
    assert challenge["selected_mode"] == SELECTED_CHALLENGE_MODE
    assert challenge["adversarial_fiat_shamir_query_bound"] == 0
    assert challenge["rho_beta_gamma_serialized"]
    assert not challenge["honest_dv_entropy_delivery_instantiated"]
    assert not challenge["interactive_transcript_binding_proved"]
    challenge_comparison = report["interactive_vs_fiat_shamir"]
    assert 182.9 < challenge_comparison["interactive_selected"]["effective_bits"] < 183.1
    assert 118.9 < challenge_comparison["fiat_shamir_direct_control"]["effective_bits"] < 119.1
    assert 301.9 < challenge_comparison["fiat_shamir_two_challenge_amplified"]["effective_bits"] < 302.1
    assert not challenge_comparison["fiat_shamir_two_challenge_amplified"][
        "proof_size_gate_passed"
    ]
    batch_open = report["batch_open_blocks_admission"]
    assert batch_open["state"] == "R08_STRICT_UD_RS_CONTROL_REALIZATION_NO_GO"
    assert batch_open["logical_leaf_symbols"] == 141
    assert batch_open["generator_incidence_obstruction"][
        "nonzero_incidence_lower_bound"
    ] == "nnz(G) >= k*d"
    assert batch_open["cpu_reference_contract"]["reference_implemented"]
    assert "opened leaf salts and canonical query/leaf indices" in batch_open[
        "cpu_reference_contract"
    ]["required_output"]
    assert batch_open["cpu_reference_contract"]["packed_source_passes"] == 1
    online_screens = batch_open["RS_control_bounded_online_screen"]
    assert online_screens["gpt2-124m-screen"]["rows"][
        "persist_complete_rate_half_codeword"
    ]["codeword_bytes"] == 4_294_967_296
    assert online_screens["gpt2-124m-screen"]["rows"][
        "persist_complete_rate_half_codeword"
    ]["persistent_bytes_with_existing_tree"] == 4_786_653_504
    assert online_screens["gemma-class-31b-envelope"]["rows"][
        "persist_complete_rate_half_codeword"
    ]["persistent_bytes_with_existing_tree"] == 642_600_433_216
    for online in online_screens.values():
        assert not online["complete_row_exists"]
        assert not online["RS_control_online_gate_pass"]
        assert not online["prover_or_SIMT_implementation_authorized"]
    assert not batch_open["c7_cpu_reference_pass"]
    tournament = report["new_carrier_tournament"]
    assert tournament["state"] == "OPEN_DUAL_TRACK_NO_ENTRANT_ADMITTED"
    assert tournament["tracks"]["published_constructions"]["role"] == (
        "baseline_and_controls_only"
    )
    codesigned = tournament["tracks"]["C7_codesigned_circuit"]
    assert codesigned["role"] == "main_research_line"
    assert len(codesigned["pre_CPU_screen_requires"]) == 4
    assert not codesigned["pre_CPU_screen_pass"]
    assert not codesigned["tiny_CPU_prototype_authorized"]
    assert codesigned["carrier_independent_policy2_reference_implemented"]
    assert codesigned["tiny_non_PCS_conformance_test_implemented"]
    assert not codesigned["credit_by_design"]
    assert tournament["strict_ud_RS_role"] == (
        "algebraic_and_security_control_baseline_only"
    )
    assert not tournament["strict_ud_RS_prover_implementation_authorized"]
    assert not tournament["entrants"]
    assert tournament["main_research_candidate_not_admitted"] == "C7-SPBT-v0"
    bounded_rows = tournament["bounded_codesigned_rows"]
    assert bounded_rows["state"] == "NO_CARRIER_ROW_COMPLETE_REFERENCE_SEAM_READY"
    seam = bounded_rows["policy2_reference_seam"]
    assert seam["root_mask_descriptor_bytes"] == 90
    assert seam["tiny_two_leaf_opening_bytes"] == 1328
    assert seam["q_attempt_and_q_response_separate"]
    assert seam["abort_consumption_nonrefundable"]
    assert not seam["durable_allocator_or_PCS"]
    assert bounded_rows["persisted_rate_half_field_parity"][
        "amplification_before_tree"
    ] == 5
    assert bounded_rows["structured_coset_block"]["packed_source_passes"] == 1
    assert not bounded_rows["complete_relation_codec"]
    assert not bounded_rows["exact_full_resource_census"]
    assert not bounded_rows["stateful_soundness_privacy_bridge"]
    assert not bounded_rows["one_scan_BatchOpenBlocks_proof"]
    assert not bounded_rows["pre_CPU_screen_pass"]
    assert tournament["selected_carrier"] is None
    assert not tournament["complete_row_exists"]
    assert not tournament["prover_or_SIMT_implementation_authorized"]
    secret_point = report["secret_point_dv_carrier_screen"]
    assert secret_point["state"] == "MAIN_RESEARCH_CANDIDATE_NOT_ADMITTED"
    assert secret_point["candidate_id"] == "C7-DV-SPQ-v0"
    assert secret_point["algebraic_screen"][
        "all_roots_R_max_certified_bits_if_hypotheses_hold"
    ] > 110
    assert secret_point["published_and_natural_backend_controls"][
        "algebraic_PRF_authenticator"
    ]["packed_plus_authenticator_amplification"] == 17
    assert not secret_point["complete_relation_codec"]
    assert not secret_point["exact_full_resource_census"]
    assert not secret_point["stateful_soundness_privacy_bridge"]
    assert not secret_point["one_scan_OpenQuotientIntoMac_proof"]
    assert not secret_point["pre_CPU_screen_pass"]
    assert not secret_point["selected_carrier"]
    assert not secret_point["prover_or_SIMT_implementation_authorized"]
    bridge = report["eq_to_secret_point_bridge_screen"]
    assert bridge["state"] == (
        "ALGEBRAIC_BRIDGE_PASS_PUBLIC_SEQUENTIAL_TRANSCRIPT_NO_GO"
    )
    assert bridge["exact_bridge"]["small_exact_modular_self_check"]
    assert bridge["exact_bridge"]["generic_independent_r_counterexample"]
    assert bridge["exact_bridge"]["conditional_packed_passes"] == 1
    assert all(
        profile["inside_screen_cap"]
        and not profile["compiled_manifest"]
        for profile in bridge["exact_bridge"]["profiles"].values()
    )
    assert bridge["transcript_attack"]["small_exact_modular_attack_check"]
    assert bridge["transcript_attack"]["false_gap_can_be_carried_then_erased"]
    assert not bridge["transcript_attack"][
        "existing_sumcheck_soundness_theorem_applies"
    ]
    assert not bridge["bounded_escape_screen"]["complete_escape_row_exists"]
    assert bridge["functional_basis_bridge_conditional_pass"]
    assert not bridge["public_GKR_composition_pass"]
    assert not bridge["complete_relation_codec"]
    assert not bridge["exact_full_resource_census"]
    assert not bridge["stateful_soundness_privacy_bridge"]
    assert not bridge["one_scan_OpenQuotientIntoMac_proof"]
    assert not bridge["pre_CPU_screen_pass"]
    assert not bridge["selected_carrier"]
    assert not bridge["prover_or_SIMT_implementation_authorized"]
    butterfly = report["secret_point_butterfly_transform_screen"]
    assert butterfly["state"] == (
        "EXACT_REDUCTION_PASS_DELAYED_OPENING_REALIZATION_NO_GO"
    )
    assert butterfly["candidate_id"] == "C7-SPBT-v0"
    relation = butterfly["exact_relation"]
    assert relation["small_exact_modular_identity_and_inverse_check"]
    assert relation["pair_matrix_determinant"] == "-1 for every r_l"
    assert relation["output_coefficients"] == "sum_l M/2^(l+1)+1=M"
    transcript = butterfly["transcript"]
    tau_phase = next(
        i for i, phase in enumerate(transcript) if phase.startswith("sample tau")
    )
    beta_phase = next(
        i
        for i, phase in enumerate(transcript)
        if phase.startswith("sample response-wide beta")
    )
    assert tau_phase < beta_phase
    assert butterfly["one_scan_transform_schedule"]["source_reads"] == 1
    assert butterfly["one_scan_transform_schedule"]["conditional_transform_only_pass"]
    assert not butterfly["one_scan_transform_schedule"]["complete_delayed_opening_pass"]
    assert butterfly["commit_challenge_open_triangle"]["tau_before_C_Z"][
        "disposition"
    ] == "NO_GO_unsound"
    assert butterfly["commit_challenge_open_triangle"]["tau_after_C_Z_recompute"][
        "disposition"
    ] == "NO_GO_second_scan"
    assert butterfly["policy2_privacy"]["transform_is_invertible"]
    assert not butterfly["policy2_privacy"]["policy2_query_vector_compiled"]
    for profile in butterfly["conditional_soundness"]["profiles"].values():
        assert profile["canonical_dense_auxiliary_bytes"][
            "minimum_packed_plus_retained_aux_amplification"
        ] == 9
        assert profile["optimistic_two_party_orbit_token_control"][
            "packed_plus_tokens_amplification_minimum"
        ] == 25
        assert profile["raw_transform_merkle_sampling_control"][
            "miss_certified_bits_upper"
        ] < 1
        assert profile["conditional_fixed_before_beta_tau_soundness"][
            "passes_110_bit_component_reserve"
        ]
        assert not profile["compiled_segment_manifest"]
    assert butterfly["algebraic_relation_complete"]
    assert butterfly["one_scan_transform_only_proof"]
    assert not butterfly["exact_full_resource_census"]
    assert not butterfly["stateful_soundness_privacy_bridge"]
    assert not butterfly["one_scan_complete_opening_proof"]
    assert not butterfly["pre_CPU_screen_pass"]
    assert not butterfly["selected_carrier"]
    assert not butterfly["prover_or_SIMT_implementation_authorized"]
    simt = report["simt_path"]
    assert simt["state"] == "BLOCKED_BEFORE_CPU_REFERENCE_PASS"
    assert simt["logical_leaf_symbols"] == 141
    assert not simt["optimized_kernel_or_scaffold_exists"]
    assert simt["gpu_padding"]["persistent_bytes"] == 0
    assert simt["gpu_padding"]["certificate_bytes"] == 0
    assert simt["packed_source_h2d_passes_per_scope"] == 1
    assert not simt["simt_bit_exact_equivalence_pass"]
    assert (
        "root-bound masked logical leaves, opened salts and canonical indices"
        in simt["byte_exact_cpu_simt_required"]
    )
    policy2 = report["policy2_query_accounting"]
    assert policy2["status"] == (
        "R08_FP3_SEEDED_MASK_SELECTED_FULL_CODEC_UNADMITTED"
    )
    assert list(policy2["authoritative_attempt_census"]["q_attempt"]) == list(
        POLICY2_AGGREGATE_CENSUS_CLASSES
    )
    assert set(policy2["authoritative_attempt_census"]["q_attempt_by_plane"]) == {
        "weight",
        "boundary",
        "kv_predecessor",
        "kv_successor",
    }
    assert all(
        list(census) == list(POLICY2_QUERY_CLASSES)
        for census in policy2["authoritative_attempt_census"][
            "q_attempt_by_plane"
        ].values()
    )
    assert policy2["authoritative_attempt_census"][
        "logical_pcs_samples_q_open_by_plane_root_round"
    ] is None
    assert all(
        value is None
        for value in policy2["root_privacy_budget"][
            "attempt_plane_charge_vector"
        ].values()
    )
    assert all(
        value is None
        for value in policy2["root_privacy_budget"][
            "weight_epoch_lifecycle_charge_vector"
        ].values()
    )
    assert all(
        all(value is None for value in census.values())
        for key, census in policy2["weight_epoch_lifecycle_census"].items()
        if key.startswith("q_")
    )
    assert policy2["root_privacy_budget"]["fixed_consumption_formula"] == (
        "u_init+A_rotate_in*u_rotate_in+A_rotate_out*u_rotate_out+"
        "R_root*u_W <= Q_root"
    )
    assert policy2["root_privacy_budget"]["privacy_unit_status"] == (
        "conservative_provisional_screen_pending_joint_theorem"
    )
    assert policy2["root_privacy_budget"]["positive_q_attempt_required"]
    assert policy2["root_privacy_budget"][
        "at_least_one_complete_attempt_capacity_required"
    ]
    assert not policy2["root_privacy_budget"][
        "numeric_preconditions_instantiated"
    ]
    assert policy2["root_privacy_budget"][
        "fixed_consumption_on_accept_abort_retry_crash"
    ]
    assert policy2["root_privacy_budget"][
        "model_lifetime_privacy_target_bits"
    ] == 78
    assert not policy2["root_privacy_budget"]["model_lifetime_bound_derived"]
    assert not policy2["root_privacy_budget"]["unused_reservation_refunded"]
    assert not policy2["root_privacy_budget"][
        "zero_lifecycle_charge_theorem_proved"
    ]
    assert not policy2["allocator_cardinality_relations"]["numeric_instantiation"]
    assert policy2["allocator_cardinality_relations"][
        "mac_domain_scope_includes_failed_and_aborted_lifecycle"
    ]
    assert policy2["global_counter"][
        "public_root_is_baseline_view_element"
    ]
    assert policy2["global_counter"][
        "cross_world_root_replacement_charged_to_hiding"
    ]
    assert not policy2["global_counter"][
        "rate_limits_or_user_quotas_are_security_counters"
    ]
    assert not policy2["global_counter"][
        "malicious_verifier_can_mint_or_rollback_receipts"
    ]
    assert not policy2["global_counter"][
        "complete_weight_oracle_epoch_schema_compiled"
    ]
    assert not policy2["global_counter"][
        "authenticated_reservation_receipt_codec_instantiated"
    ]
    assert policy2["global_counter"]["receipt_lifecycle"] == (
        "Reserved->InFlight->Burned|Accepted"
    )
    assert policy2["global_counter"][
        "receipt_authenticates_receipt_free_request_binding"
    ]
    assert policy2["global_counter"][
        "first_reply_cached_before_receipt_or_seed_commitment_emission"
    ]
    assert not policy2["global_counter"][
        "linearizable_single_session_receipt_state_machine_proved"
    ]
    assert not policy2["global_counter"][
        "durable_transcript_state_and_reply_cache_instantiated"
    ]
    assert not policy2["global_counter"][
        "durable_boundary_budget_map_instantiated"
    ]
    assert not policy2["global_counter"]["durable_kv_budget_map_instantiated"]
    assert not policy2["global_counter"][
        "plane_assignment_receipt_codec_instantiated"
    ]
    assert not policy2["global_counter"][
        "plane_assignment_cas_before_root_disclosure_proved"
    ]
    assert not policy2["global_counter"][
        "post_first_reply_charge_extension_allowed"
    ]
    assert policy2["global_counter"]["persistent_state_plane_record_bytes"] is None
    assert policy2["global_counter"][
        "model_lifetime_allocator_storage_bytes"
    ] is None
    assert not policy2["root_rotation"][
        "outstanding_receipts_resolved_or_burned_before_cutover"
    ]
    assert not policy2["root_rotation"][
        "same_W_bridge_knowledge_soundness_proved"
    ]
    assert not policy2["root_rotation"][
        "same_W_bridge_malicious_dv_privacy_proved"
    ]
    assert policy2["root_rotation"][
        "only_weight_epoch_counter_is_fresh_after_rotation"
    ]
    assert not policy2["root_rotation"][
        "state_plane_ledger_carry_forward_proved"
    ]
    assert all(
        value is None
        for key, value in policy2["cryptographic_work_bounds"].items()
        if key.startswith("Q_")
    )
    assert not policy2["multiuser_mac_composition"][
        "multiuser_vole_mac_theorem_proved"
    ]
    assert policy2["multiuser_mac_composition"]["D_model_scope"] == [
        "weight_or_KV_setup_or_init_validation",
        "W_dependent_response_attempts",
        "W_dependent_rotate_in_bridges",
        "W_dependent_rotate_out_bridges",
        "failed_or_aborted_lifecycle_attempts",
    ]
    assert policy2["multiuser_mac_composition"][
        "zero_lifecycle_domain_requires_zero_vole_mac_codec_theorem"
    ]
    assert not policy2["multiuser_mac_composition"][
        "zero_lifecycle_domain_theorem_proved"
    ]
    assert not policy2["multiuser_mac_composition"][
        "allocator_privacy_integrity_proved"
    ]
    assert not policy2["multiuser_mac_composition"][
        "dishonest_prover_receipt_unforgeability_proved"
    ]
    assert not policy2["paired_history_privacy_game"][
        "operational_game_formalized"
    ]
    assert not policy2["paired_history_privacy_game"][
        "branch_derived_view_closure_reduction_proved"
    ]
    assert not policy2["response_and_state_plane_privacy"][
        "per_plane_hiding_prf_and_path_bounds_derived"
    ]
    assert policy2["response_and_state_plane_privacy"][
        "every_proposed_successor_root_charged_before_disclosure"
    ]
    assert policy2["response_and_state_plane_privacy"][
        "aborted_or_rejected_successor_root_sealed"
    ]
    assert policy2["response_and_state_plane_privacy"][
        "genesis_InitKVState_before_first_disclosure_required"
    ]
    assert not policy2["response_and_state_plane_privacy"][
        "genesis_InitKVState_codec_and_theorems_proved"
    ]
    assert not policy2["separate_gates"]["single_minimum_across_these_gates_valid"]
    assert not policy2["model_scaling_gate"]["passes"]
    assert policy2["model_scaling_gate"][
        "max_normalized_query_count_growth_ratio"
    ] == 1.30
    assert policy2["model_scaling_gate"][
        "original_preferred_growth_ratio"
    ] == 1.05
    assert policy2["model_scaling_gate"]["constrained_counts"] == [
        "logical_pcs_samples",
        "zk_alphabet_query_atoms",
        "unique_opened_leaves",
        "visible_masked_base_field_symbols",
    ]
    assert 0.047 < policy2["model_scaling_gate"][
        "equivalent_max_query_exponent"
    ] < 0.048
    assert policy2["public_hash_choice"]["blake3_leaf_and_tree_eligible"]
    assert not policy2["public_hash_choice"]["private_hash_checker_required"]
    assert policy2["public_hash_choice"][
        "blake3_selected_as_concrete_binding_primitive"
    ]
    assert policy2["public_hash_choice"][
        "blake3_selection_does_not_supply_root_hiding"
    ]
    assert policy2["public_hash_choice"]["opened_salt_bytes_per_unique_leaf"] == 32
    setup_privacy = policy2["anti_x4d_setup_privacy_screen"]
    assert setup_privacy["max_t_over_n_target"] == "1/704"
    assert setup_privacy["max_t_over_n_hard"] == "13/128"
    assert setup_privacy["models"]["gpt2-124m-screen"][
        "target_extra_symbols_floor"
    ] == 176_136
    assert setup_privacy["models"]["gemma-class-31b-envelope"][
        "target_extra_symbols_floor"
    ] == 43_787_500
    assert not policy2["root_rotation"]["rotation_authorized"]
    assert not policy2["root_rotation"][
        "typed_init_and_rotate_query_charges_instantiated"
    ]
    assert policy2["root_rotation"][
        "failed_or_aborted_disclosed_candidate_consumes_K_model"
    ]
    pareto = report["r07_carrier_pareto_screen"]
    assert len(pareto["constant_schedule_formula_controls"]) == 16
    variable_tail = pareto["variable_tail_fold_pareto_controls"]
    fp2_tail = variable_tail["Fp2"]
    fp3_tail = variable_tail["Fp3"]
    assert fp2_tail["gpt2_frontier_size"] == 22
    assert fp2_tail["gemma_31b_frontier_size"] == 34
    assert not fp2_tail["any_pareto_pair_passes_q_and_Fp_1_05"]
    assert fp2_tail["any_pareto_pair_passes_q_and_Fp_active_1_30"]
    assert fp2_tail["best_minimax_pair"]["gpt2"] == {
        "schedule": [4, 5, 3, 3, 3, 3],
        "q_open": 831,
        "Fp_positions": 19_104,
    }
    assert fp2_tail["best_minimax_pair"]["gemma_31b"] == {
        "schedule": [4, 4, 3, 3, 3, 4, 4, 4],
        "q_open": 1_054,
        "Fp_positions": 24_128,
    }
    assert 17.2 < fp2_tail["best_minimax_pair"][
        "required_large_q_reduction_percent_for_1_05"
    ] < 17.3
    assert 16.8 < fp2_tail["best_minimax_pair"][
        "required_large_Fp_reduction_percent_for_1_05"
    ] < 16.9
    assert fp2_tail["best_minimax_pair"]["axis_gaps_are_nonfungible"]
    assert fp2_tail["best_minimax_pair"]["owner_1_30_query_axis_gate"][
        "passes_q_and_unstacked_Fp_controls"
    ]
    assert fp2_tail["best_minimax_pair"]["owner_1_30_query_axis_gate"][
        "q_headroom_draws"
    ] == 26
    assert fp2_tail["best_minimax_pair"]["owner_1_30_query_axis_gate"][
        "Fp_position_headroom"
    ] == 707
    assert not fp2_tail["best_minimax_pair"]["owner_1_30_query_axis_gate"][
        "complete_row_pass"
    ]
    assert fp2_tail["best_minimax_pair"][
        "required_uniform_common_reduction_percent_for_both_1_05"
    ] == max(
        fp2_tail["best_minimax_pair"][
            "required_large_q_reduction_percent_for_1_05"
        ],
        fp2_tail["best_minimax_pair"][
            "required_large_Fp_reduction_percent_for_1_05"
        ],
    )
    assert not fp3_tail["any_pareto_pair_passes_q_and_Fp_1_05"]
    assert fp3_tail["any_pareto_pair_passes_q_and_Fp_active_1_30"]
    assert fp3_tail["best_minimax_pair"]["gpt2"] == {
        "schedule": [4, 5, 3, 3, 3, 3],
        "q_open": 831,
        "Fp_positions": 26_528,
    }
    assert fp3_tail["best_minimax_pair"]["gemma_31b"] == {
        "schedule": [4, 3, 3, 3, 4, 4, 4, 4],
        "q_open": 1_055,
        "Fp_positions": 33_848,
    }
    assert 17.2 < fp3_tail["best_minimax_pair"][
        "required_large_q_reduction_percent_for_1_05"
    ] < 17.4
    assert 17.7 < fp3_tail["best_minimax_pair"][
        "required_large_Fp_reduction_percent_for_1_05"
    ] < 17.8
    assert fp3_tail["best_minimax_pair"]["axis_gaps_are_nonfungible"]
    assert fp3_tail["best_minimax_pair"][
        "required_uniform_common_reduction_percent_for_both_1_05"
    ] == max(
        fp3_tail["best_minimax_pair"][
            "required_large_q_reduction_percent_for_1_05"
        ],
        fp3_tail["best_minimax_pair"][
            "required_large_Fp_reduction_percent_for_1_05"
        ],
    )
    bounded = pareto["bounded_closure_screens"]
    assert not bounded["pure_fold_width_search_reopened"]
    joint = bounded["cross_round_joint_sampling"]
    assert joint["q_open"] == {"gpt2": 831, "gemma_31b": 1_054}
    assert joint["maximum_adjacent_Fp_derivation"]["remaining"] == {
        "gpt2": 17_974,
        "gemma_31b": 22_552,
    }
    assert 1.254 < joint["maximum_adjacent_Fp_derivation"]["growth"] < 1.255
    assert not joint["passes_original_1_05_q_and_Fp_controls"]
    assert joint["disposition"] == "NO_GO"
    code_switch = bounded["different_code_switch"]
    era_switch = code_switch["era_to_basefold_exact_formula_control"]
    assert era_switch["q_open"] == {"gpt2": 2_370, "gemma_31b": 3_602}
    assert 1.519 < era_switch["q_growth"] < 1.520
    assert era_switch["unstacked_Fp"] == {
        "gpt2": 68_612,
        "gemma_31b": 71_076,
    }
    assert 1.035 < era_switch["unstacked_Fp_growth"] < 1.037
    assert era_switch["optimistic_setup_amplification_floor"] > 2.10
    assert not era_switch["passes_active_1_30_q_gate"]
    assert not code_switch["complete_row_found_under_active_1_30"]
    assert code_switch["disposition"] == "NO_GO"
    fallback = bounded["owner_1_30_fallback"]
    assert fallback["active"]
    assert fallback["known_q_and_unstacked_Fp_controls_pass"]
    assert not fallback["complete_row_pass"]
    assert bounded["selected_carrier_original_1_05_disposition"] == "NO_GO"
    assert len(pareto["published_reference_rows"]) == 2
    assert all(not row["admitted"] for row in pareto["published_reference_rows"])
    assert pareto["published_reference_rows"][1]["published_field_elements"] == (
        72_418
    )
    assert pareto["goldilocks_31b_has_retained_field_valid_controls"]
    assert pareto[
        "goldilocks_31b_minimum_first_fold_by_starting_log_inv_rate"
    ] == {"1": 4, "2": 5}
    assert not pareto["published_goldilocks_benchmark_scope_covers_31b"]
    assert not pareto["retained_interleaved_domain_rule_is_C7_admitted"]
    assert pareto[
        "all_31b_controls_lack_unamplified_Fp2_lifetime_certificate"
    ]
    assert pareto["owner_selected_security_closure_path"] == [
        "one_bounded_tighter_strict_UD_all_fold_audit",
        "automatic_Goldilocks_Fp3_direct_three_Fp_limb_fallback",
        "two_independent_Fp2_folds_only_if_Fp3_fails_a_non_security_gate",
    ]
    assert pareto["owner_selected_first_compiler_envelope"]["candidate_id"] == (
        "rate1-k0-4-owner1_30-Fp2-query-axis-candidate"
    )
    assert pareto["owner_selected_first_compiler_envelope"][
        "tail_schedule_selected_for_formula_query_axes"
    ]
    assert pareto["owner_selected_first_compiler_envelope"][
        "gpt2_tail_schedule"
    ] == [5, 3, 3, 3, 3]
    assert pareto["owner_selected_first_compiler_envelope"][
        "gemma_31b_tail_schedule"
    ] == [4, 3, 3, 3, 4, 4, 4]
    assert pareto["owner_selected_first_compiler_envelope"][
        "pure_fold_width_tail_rejected"
    ]
    assert not pareto["owner_selected_first_compiler_envelope"][
        "constant_k4_control_query_gates_pass"
    ]
    assert not pareto["owner_selected_first_compiler_envelope"]["admitted"]
    amplifiers = pareto["security_amplifier_formula_controls"]
    assert not amplifiers["tighter_analysis"][
        "tight_attack_or_impossibility_known"
    ]
    assert amplifiers["tighter_analysis"]["bounded_audit_selected"]
    assert amplifiers["independent_repetition"][
        "conditional_minimum_repetitions"
    ] == 2
    assert 178.0 < amplifiers["independent_repetition"][
        "conditional_all_fold_certified_bits"
    ] < 178.1
    assert 158.0 < amplifiers["independent_repetition"][
        "conditional_after_R_max_certified_bits"
    ] < 158.1
    assert amplifiers["larger_extension"][
        "minimum_Goldilocks_extension_degree_control"
    ] == 3
    assert amplifiers["larger_extension"][
        "visible_limb_multiplier_vs_Fp2"
    ] == 1.5
    assert amplifiers["larger_extension"]["unstacked_Fp_positions_control"] == 42_080
    assert 1.42 < amplifiers["larger_extension"]["payload_growth_vs_Fp2"] < 1.44
    assert amplifiers["larger_extension"]["selected_if_bounded_audit_fails"]
    assert amplifiers["larger_extension"]["terminal_adapter"] == (
        "direct_three_canonical_Fp_limbs"
    )
    assert not amplifiers["interactive_pow"][
        "statistical_amplification_under_Q_FS_0"
    ]
    assert amplifiers["interactive_pow"]["conditional_pow_bits_by_phase"] == [
        21,
        20,
        19,
        18,
        17,
        16,
        15,
        14,
    ]
    assert amplifiers["interactive_pow"][
        "conditional_expected_hash_trials"
    ] == 16_711_680
    assert not pareto["any_row_admitted"]
    rate1_k4 = next(
        row
        for row in pareto["constant_schedule_formula_controls"]
        if row["candidate_id"] == "strict-ud-r1-k4"
    )
    assert rate1_k4["gpt2"]["initial_domain_exponent"] == 28
    assert rate1_k4["gemma_31b"]["initial_domain_exponent"] == 36
    assert rate1_k4["gemma_31b"]["post_first_fold_domain_exponent"] == 32
    assert rate1_k4["gemma_31b"][
        "maximum_g141_leaves_touched_by_one_first_fold_row"
    ] == 2
    assert not rate1_k4["gemma_31b"]["exact_g141_leaf_union_compiled"]
    assert rate1_k4["gemma_31b"][
        "retained_goldilocks_folded_domain_supported"
    ]
    assert not rate1_k4["gemma_31b"][
        "published_goldilocks_initial_domain_scope_supported"
    ]
    assert 99.999999999 < rate1_k4["gpt2"][
        "strict_UD_starting_gap_certified_bits_Fp2_control"
    ] < 100
    assert 91.999999999 < rate1_k4["gemma_31b"][
        "strict_UD_starting_gap_certified_bits_Fp2_control"
    ] < 92
    assert 71.999999999 < rate1_k4["gemma_31b"][
        "strict_UD_after_R_max_union_certified_bits_control"
    ] < 72
    assert not rate1_k4["gemma_31b"][
        "strict_UD_inherited_bound_certifies_78_after_R_max_before_other_terms"
    ]
    assert rate1_k4["gemma_31b"]["fold_challenge_count"] == 32
    assert 89.0 < rate1_k4["gemma_31b"][
        "strict_UD_all_fold_union_certified_bits_Fp2_control"
    ] < 89.1
    assert 69.0 < rate1_k4["gemma_31b"][
        "strict_UD_all_fold_after_R_max_certified_bits_control"
    ] < 69.1
    assert rate1_k4["gemma_31b"][
        "strict_UD_all_fold_gap_error_upper_bound"
    ] == (
        "547608330240/340282366762482138490186164457219031041"
    )
    assert rate1_k4["gpt2"]["unused_padded_message_symbols"] == 10_217_728
    assert rate1_k4["gemma_31b"]["unused_padded_message_symbols"] == (
        3_533_338_368
    )
    assert not rate1_k4["gemma_31b"]["zk_randomness_row_capacity_compiled"]
    assert not rate1_k4["gpt2"]["round_union_security_included"]
    assert rate1_k4["gpt2"]["q_open_formula_control"] == 832
    assert rate1_k4["gemma_31b"]["q_open_formula_control"] == 1054
    assert rate1_k4["gpt2"]["static_digest_only_floor_bytes"] == 369_843_040
    assert rate1_k4["gemma_31b"]["static_digest_only_floor_bytes"] == 92_844_619_232
    assert not rate1_k4["paired_formula_control_growth"]["q_open_within_1_05"]
    assert not rate1_k4["paired_formula_control_growth"][
        "unstacked_fp_positions_within_1_05"
    ]
    rate1_k2 = next(
        row
        for row in pareto["constant_schedule_formula_controls"]
        if row["candidate_id"] == "strict-ud-r1-k2"
    )
    assert not rate1_k2["gemma_31b"][
        "retained_goldilocks_folded_domain_supported"
    ]
    rate2_k5 = next(
        row
        for row in pareto["constant_schedule_formula_controls"]
        if row["candidate_id"] == "strict-ud-r2-k5"
    )
    assert rate2_k5["gemma_31b"]["post_first_fold_domain_exponent"] == 32
    assert rate2_k5["gemma_31b"][
        "retained_goldilocks_folded_domain_supported"
    ]
    assert not policy2["online_mdv_view_refinement"]["proof_complete"]
    assert not policy2["online_mdv_view_refinement"][
        "paper_t_is_visible_Fp_capacity_without_codec_proof"
    ]
    assert not policy2["model_lifetime_privacy_bound"]["derived"]
    assert policy2["dishonest_prover_soundness_bound"][
        "strict_unique_decoding_only"
    ]
    readiness = report["pod_readiness"]
    assert readiness["state"] == (
        "C7_R08E_SPBT_REDUCTION_PASS_DELAYED_OPENING_NO_GO"
    )
    assert not readiness["all_required_gates_pass"]
    assert not any(readiness["required_before_C7_POD_READY"].values())
    assert not readiness["conditional_before_C7_POD_READY"]["simt_selected"]
    assert not readiness["conditional_before_C7_POD_READY"][
        "simt_bit_exact_equivalence_if_selected"
    ]
    assert all(
        not component["credit"]
        for model in (small, large)
        for component in model["certificate"]["components"].values()
    )
    report["self_check"]["status"] = "pass"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chunk-mb",
        type=float,
        default=256.0,
        help="decimal MB for the bounded streaming chunk (default: 256)",
    )
    parser.add_argument(
        "--bandwidth-gbps",
        type=float,
        default=3.2,
        help="decimal GB/s for I/O rooflines (default: 3.2)",
    )
    args = parser.parse_args()
    if (
        not math.isfinite(args.chunk_mb)
        or not math.isfinite(args.bandwidth_gbps)
        or args.chunk_mb <= 0
        or args.bandwidth_gbps <= 0
    ):
        parser.error("--chunk-mb and --bandwidth-gbps must be finite and positive")
    chunk_bytes = round(args.chunk_mb * 1_000_000)
    if chunk_bytes < 1:
        parser.error("--chunk-mb rounds to less than one byte")
    report = build_report(chunk_bytes, args.bandwidth_gbps * 1_000_000_000)
    self_check(report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
